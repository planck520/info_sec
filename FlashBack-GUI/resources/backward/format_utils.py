# -*- coding: utf-8 -*-
"""Utilities to understand printf-style variadic calls.

- Resolve constant format strings from Hex-Rays cexpr.
- Parse format string to determine which varargs are actually consumed.
"""
from __future__ import annotations

import re
from typing import List, Optional

try:
    import idaapi  # type: ignore
    import idc     # type: ignore
except Exception:
    idaapi = idc = None  # type: ignore

# Broadly cover most printf directives, including positional args and * width/precision
_FMT_RE = re.compile(
    r"%"
    r"(?:(?P<pos>\d+)\$)?"                               # %2$...
    r"(?P<flags>[-+#0 'I]*)"                             # flags
    r"(?:(?P<width>\*(?:(?P<wpos>\d+)\$)?|\d+))?"        # width or * / *n$
    r"(?:(?:\.(?P<prec>\*(?:(?P<ppos>\d+)\$)?|\d+)))?"   # .precision or .* / .*n$
    r"(?P<len>hh|h|ll|l|j|z|t|L)?"                      # length
    r"(?P<conv>[diuoxXfFeEgGaAcspn%]|\[[^\]]*\])"       # conversion, including character sets %[...]
)

def _try_get_cstr_from_expr(expr) -> Optional[str]:
    """Best-effort extraction of a constant string literal from a cexpr."""
    import logging
    _LOGGER = logging.getLogger(__name__)

    if idaapi is None or idc is None:
        _LOGGER.debug(f"[DEBUG _try_get_cstr] idaapi or idc is None")
        return None

    try:
        expr_op = getattr(expr, "op", None)
        cot_obj = getattr(idaapi, "cot_obj", -1)
        cot_ptr = getattr(idaapi, "cot_ptr", -1)
        cot_cast = getattr(idaapi, "cot_cast", -1)
        cot_ref = getattr(idaapi, "cot_ref", -1)
        cot_str = getattr(idaapi, "cot_str", -1)

        # ============ DEBUG: expression type check ============
        _LOGGER.info(f"[DEBUG _try_get_cstr] expr.op={expr_op}")
        _LOGGER.info(f"  cot_obj={cot_obj}, cot_ptr={cot_ptr}, cot_cast={cot_cast}, cot_ref={cot_ref}, cot_str={cot_str}")
        # ==========================================

        # Recursive helper
        def try_extract_ea(e):
            """Try to extract the address of a string literal from an expression."""
            e_op = getattr(e, "op", None)

            # Case 1: cot_obj - direct object reference
            if e_op == cot_obj:
                ea = getattr(e, "obj_ea", idaapi.BADADDR)
                ea_str = f"0x{ea:x}" if ea != idaapi.BADADDR else "BADADDR"
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_obj: obj_ea={ea_str}")
                return ea

            # Case 2: cot_ptr - pointer dereference (*x)
            elif e_op == cot_ptr:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_ptr: dereferencing pointer")
                sub_expr = getattr(e, "x", None)
                if sub_expr:
                    return try_extract_ea(sub_expr)

            # Case 3: cot_ref - address-of (&x)
            elif e_op == cot_ref:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_ref: taking address")
                sub_expr = getattr(e, "x", None)
                if sub_expr:
                    return try_extract_ea(sub_expr)

            # Case 4: cot_cast - type cast
            elif e_op == cot_cast:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_cast: type cast")
                sub_expr = getattr(e, "x", None)
                if sub_expr:
                    return try_extract_ea(sub_expr)

            # Case 5: cot_str - string literal (some IDA versions)
            elif e_op == cot_str:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_str: string constant")
                ea = getattr(e, "obj_ea", idaapi.BADADDR)
                if ea == idaapi.BADADDR:
                    # Some versions may use the string field
                    string_val = getattr(e, "string", None)
                    if string_val:
                        _LOGGER.info(f"[DEBUG _try_get_cstr] Got string from cot_str.string: {repr(string_val)}")
                        return string_val  # Return the string directly
                return ea

            # Fallback: try a generic way to recover the address
            _LOGGER.warning(f"[DEBUG _try_get_cstr] Unknown expression type: {e_op}, trying fallback methods")

            # Try to read obj_ea, which may belong to an unknown object type
            ea = getattr(e, "obj_ea", None)
            if ea is not None and ea != idaapi.BADADDR:
                ea_str = f"0x{ea:x}" if ea != idaapi.BADADDR else "BADADDR"
                _LOGGER.info(f"[DEBUG _try_get_cstr] Fallback: found obj_ea={ea_str}")
                return ea

            # Try to read the string field, which may already hold the string
            string_val = getattr(e, "string", None)
            if string_val:
                _LOGGER.info(f"[DEBUG _try_get_cstr] Fallback: found string field: {repr(string_val)}")
                return string_val

            # Try the child expression x recursively
            sub_expr = getattr(e, "x", None)
            if sub_expr:
                _LOGGER.info(f"[DEBUG _try_get_cstr] Fallback: trying sub-expression e.x")
                return try_extract_ea(sub_expr)

            _LOGGER.warning(f"[DEBUG _try_get_cstr] All methods failed for expression type {e_op}")
            return idaapi.BADADDR

        # Try to extract the address
        result_ea = try_extract_ea(expr)

        # If a string was returned directly (the cot_str case)
        if isinstance(result_ea, str):
            _LOGGER.info(f"[DEBUG _try_get_cstr] Successfully parsed (direct string): {repr(result_ea)}")
            return result_ea

        # If a valid address was recovered, try to read the string
        if result_ea != idaapi.BADADDR:
            bs = idc.get_strlit_contents(result_ea, -1, -1)
            _LOGGER.info(f"[DEBUG _try_get_cstr] get_strlit_contents result: {repr(bs)}")

            if bs is not None:
                try:
                    result = bytes(bs).decode("utf-8", errors="ignore")
                    _LOGGER.info(f"[DEBUG _try_get_cstr] Successfully parsed: {repr(result)}")
                    return result
                except Exception as e:
                    _LOGGER.warning(f"[DEBUG _try_get_cstr] Decode failed: {e}")
                    return str(bs)
            else:
                _LOGGER.warning(f"[DEBUG _try_get_cstr] get_strlit_contents returned None")
        else:
            _LOGGER.warning(f"[DEBUG _try_get_cstr] Failed to extract EA")

    except Exception as e:
        _LOGGER.error(f"[DEBUG _try_get_cstr] Exception: {e}", exc_info=True)
        return None

    _LOGGER.warning(f"[DEBUG _try_get_cstr] Returning None (failed to parse)")
    return None

def try_get_cstr_from_cexpr(expr) -> Optional[str]:
    return _try_get_cstr_from_expr(expr)

def parse_printf_used_positions(fmt: str) -> List[int]:
    """Return the vararg positions consumed by the format string (1-based, relative to va_start)."""
    positions: List[int] = []
    next_pos = 1
    for m in _FMT_RE.finditer(fmt):
        conv = m.group("conv")
        if conv == "%":
            continue  # Handle '%%'

        # A width * consumes one argument
        width = m.group("width")
        if width and width.startswith("*"):
            wpos = m.group("wpos")
            if wpos:
                positions.append(int(wpos))
            else:
                positions.append(next_pos)
                next_pos += 1

        # A precision * also consumes one argument
        prec = m.group("prec")
        if prec and prec.startswith("*"):
            ppos = m.group("ppos")
            if ppos:
                positions.append(int(ppos))
            else:
                positions.append(next_pos)
                next_pos += 1

        # The main conversion itself consumes one argument
        pos = m.group("pos")
        if pos:
            positions.append(int(pos))
        else:
            positions.append(next_pos)
            next_pos += 1

    # Deduplicate while preserving first-seen order
    seen = set()
    uniq: List[int] = []
    for p in positions:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq

def get_referenced_vararg_indices(cfunc, call_expr, fmt_idx: int, va_start_idx: int) -> List[int]:
    """
    For a given call, return the vararg positions actually referenced by the
    format string (1-based, relative to va_start). If parsing fails, return
    an empty list so the caller can fall back to the conservative select-all strategy.
    """
    if fmt_idx >= call_expr.a.size():
        return []
    fmt_expr = call_expr.a[fmt_idx]
    s = _try_get_cstr_from_expr(fmt_expr)
    if not s:
        return []
    return parse_printf_used_positions(s)

def parse_printf_positions_filtered(fmt: str,
                                    allow_conversions={"s", "n"},
                                    include_width_star_for_s: bool = True):
    """
    Return only the vararg positions consumed by the conversions we care about
    (1-based, relative to va_start).
    - allow_conversions: only consider these conversions (default {"s", "n"})
    - include_width_star_for_s: if True, count the width * in %*s as well
    """
    if not fmt:
        return []

    positions = []
    next_pos = 1
    for m in _FMT_RE.finditer(fmt):
        conv = m.group("conv")
        if conv == "%":
            continue  # '%%' does not consume a vararg

        # Width-star argument: count it only when conv == "s" and requested; otherwise just advance next_pos
        width = m.group("width")
        if width and width.startswith("*"):
            wpos = m.group("wpos")
            if conv == "s" and include_width_star_for_s:
                if wpos:               # Positional parameter *N$
                    positions.append(int(wpos))
                else:                  # Sequential parameter *
                    positions.append(next_pos)
                    next_pos += 1
            else:
                # Irrelevant conversions still consume one vararg: only advance next_pos for non-positional arguments
                if not wpos:
                    next_pos += 1

        # Precision * matters less for overflow risk, so just advance next_pos to keep indexing correct
        prec = m.group("prec")
        if prec and prec.startswith("*"):
            ppos = m.group("ppos")
            if not ppos:
                next_pos += 1

        pos = m.group("pos")  # Present when N$ positional arguments are used

        # Check whether the conversion is dangerous
        is_dangerous = False
        if conv in allow_conversions:
            is_dangerous = True
        elif conv.startswith("[") and conv.endswith("]") and "s" in allow_conversions:
            # Character-set formats %[...] are as risky as %s and may trigger buffer overflows
            is_dangerous = True

        if is_dangerous:
            # Relevant conversion: record its position
            if pos:
                positions.append(int(pos))
            else:
                positions.append(next_pos)
                next_pos += 1
        else:
            # Irrelevant conversion: do not record it, but advance next_pos because it still consumes a vararg
            if not pos:
                next_pos += 1

    # Deduplicate while preserving order
    seen, out = set(), []
    for p in positions:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out
