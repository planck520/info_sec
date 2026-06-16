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

# 粗覆盖大多数 printf 指令（含位置参数与 * 的 width/precision）
_FMT_RE = re.compile(
    r"%"
    r"(?:(?P<pos>\d+)\$)?"                               # %2$...
    r"(?P<flags>[-+#0 'I]*)"                             # flags
    r"(?:(?P<width>\*(?:(?P<wpos>\d+)\$)?|\d+))?"        # width 或 * / *n$
    r"(?:(?:\.(?P<prec>\*(?:(?P<ppos>\d+)\$)?|\d+)))?"   # .precision 或 .* / .*n$
    r"(?P<len>hh|h|ll|l|j|z|t|L)?"                      # length
    r"(?P<conv>[diuoxXfFeEgGaAcspn%]|\[[^\]]*\])"       # 转换，包括字符集 %[...]
)

def _try_get_cstr_from_expr(expr) -> Optional[str]:
    """从 cexpr 尽力解析常量字符串字面量。"""
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

        # ============ DEBUG: 表达式类型检查 ============
        _LOGGER.info(f"[DEBUG _try_get_cstr] expr.op={expr_op}")
        _LOGGER.info(f"  cot_obj={cot_obj}, cot_ptr={cot_ptr}, cot_cast={cot_cast}, cot_ref={cot_ref}, cot_str={cot_str}")
        # ==========================================

        # 递归处理函数
        def try_extract_ea(e):
            """尝试从表达式中提取字符串常量的地址"""
            e_op = getattr(e, "op", None)

            # Case 1: cot_obj - 直接对象引用
            if e_op == cot_obj:
                ea = getattr(e, "obj_ea", idaapi.BADADDR)
                ea_str = f"0x{ea:x}" if ea != idaapi.BADADDR else "BADADDR"
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_obj: obj_ea={ea_str}")
                return ea

            # Case 2: cot_ptr - 指针解引用 (*x)
            elif e_op == cot_ptr:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_ptr: dereferencing pointer")
                sub_expr = getattr(e, "x", None)
                if sub_expr:
                    return try_extract_ea(sub_expr)

            # Case 3: cot_ref - 取址 (&x)
            elif e_op == cot_ref:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_ref: taking address")
                sub_expr = getattr(e, "x", None)
                if sub_expr:
                    return try_extract_ea(sub_expr)

            # Case 4: cot_cast - 类型转换
            elif e_op == cot_cast:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_cast: type cast")
                sub_expr = getattr(e, "x", None)
                if sub_expr:
                    return try_extract_ea(sub_expr)

            # Case 5: cot_str - 字符串常量（某些IDA版本）
            elif e_op == cot_str:
                _LOGGER.info(f"[DEBUG _try_get_cstr] cot_str: string constant")
                ea = getattr(e, "obj_ea", idaapi.BADADDR)
                if ea == idaapi.BADADDR:
                    # 有些版本可能使用 string 字段
                    string_val = getattr(e, "string", None)
                    if string_val:
                        _LOGGER.info(f"[DEBUG _try_get_cstr] Got string from cot_str.string: {repr(string_val)}")
                        return string_val  # 直接返回字符串
                return ea

            # Fallback: 尝试通用方法获取地址
            _LOGGER.warning(f"[DEBUG _try_get_cstr] Unknown expression type: {e_op}, trying fallback methods")

            # 尝试获取 obj_ea（可能是未知的对象类型）
            ea = getattr(e, "obj_ea", None)
            if ea is not None and ea != idaapi.BADADDR:
                ea_str = f"0x{ea:x}" if ea != idaapi.BADADDR else "BADADDR"
                _LOGGER.info(f"[DEBUG _try_get_cstr] Fallback: found obj_ea={ea_str}")
                return ea

            # 尝试获取 string 字段（可能直接包含字符串）
            string_val = getattr(e, "string", None)
            if string_val:
                _LOGGER.info(f"[DEBUG _try_get_cstr] Fallback: found string field: {repr(string_val)}")
                return string_val

            # 尝试递归子表达式 x
            sub_expr = getattr(e, "x", None)
            if sub_expr:
                _LOGGER.info(f"[DEBUG _try_get_cstr] Fallback: trying sub-expression e.x")
                return try_extract_ea(sub_expr)

            _LOGGER.warning(f"[DEBUG _try_get_cstr] All methods failed for expression type {e_op}")
            return idaapi.BADADDR

        # 尝试提取地址
        result_ea = try_extract_ea(expr)

        # 如果直接得到了字符串（cot_str 情况）
        if isinstance(result_ea, str):
            _LOGGER.info(f"[DEBUG _try_get_cstr] Successfully parsed (direct string): {repr(result_ea)}")
            return result_ea

        # 如果得到了有效地址，尝试读取字符串
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
    """返回被格式串消费的**变参位置**（1-based，相对 va_start）。"""
    positions: List[int] = []
    next_pos = 1
    for m in _FMT_RE.finditer(fmt):
        conv = m.group("conv")
        if conv == "%":
            continue  # 处理 '%%'

        # width 的星号会消耗一个参数
        width = m.group("width")
        if width and width.startswith("*"):
            wpos = m.group("wpos")
            if wpos:
                positions.append(int(wpos))
            else:
                positions.append(next_pos)
                next_pos += 1

        # precision 的星号也会消耗一个参数
        prec = m.group("prec")
        if prec and prec.startswith("*"):
            ppos = m.group("ppos")
            if ppos:
                positions.append(int(ppos))
            else:
                positions.append(next_pos)
                next_pos += 1

        # 主转换本身消耗一个参数
        pos = m.group("pos")
        if pos:
            positions.append(int(pos))
        else:
            positions.append(next_pos)
            next_pos += 1

    # 去重但保持首次出现顺序
    seen = set()
    uniq: List[int] = []
    for p in positions:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq

def get_referenced_vararg_indices(cfunc, call_expr, fmt_idx: int, va_start_idx: int) -> List[int]:
    """
    给定一次调用，返回格式串实际引用到的**变参位置**（1-based，相对 va_start）。
    若解析失败，返回空列表以便上层走“保守全选”策略。
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
    只返回会被关心的转换符消耗到的变参位置（相对 va_start 的 1-based）。
    - allow_conversions: 仅考虑这些转换符（默认 {'s','n'}）
    - include_width_star_for_s: 若为 True，遇到 %*s 时把 width 的 * 也计入（同样是 vararg）
    """
    if not fmt:
        return []

    positions = []
    next_pos = 1
    for m in _FMT_RE.finditer(fmt):
        conv = m.group("conv")
        if conv == "%":
            continue  # '%%' 不消耗变参

        # width 星号参数（只在 conv=='s' 且需要时计入；否则只推进 next_pos）
        width = m.group("width")
        if width and width.startswith("*"):
            wpos = m.group("wpos")
            if conv == "s" and include_width_star_for_s:
                if wpos:               # 位置参数 *N$
                    positions.append(int(wpos))
                else:                  # 顺序参数 *
                    positions.append(next_pos)
                    next_pos += 1
            else:
                # 不关心的转换，但依然消耗一个 vararg：只推进 next_pos（非位置参数时）
                if not wpos:
                    next_pos += 1

        # precision 的 '*' 对溢出风险关系不大，这里统一只推进 next_pos，保持索引正确
        prec = m.group("prec")
        if prec and prec.startswith("*"):
            ppos = m.group("ppos")
            if not ppos:
                next_pos += 1

        pos = m.group("pos")  # 若存在 N$ 位置参数

        # 检查是否为危险的格式符
        is_dangerous = False
        if conv in allow_conversions:
            is_dangerous = True
        elif conv.startswith("[") and conv.endswith("]") and "s" in allow_conversions:
            # 字符集格式符 %[...] 和 %s 一样危险，可能导致缓冲区溢出
            is_dangerous = True

        if is_dangerous:
            # 关心的转换：记录其位置
            if pos:
                positions.append(int(pos))
            else:
                positions.append(next_pos)
                next_pos += 1
        else:
            # 不关心的转换：不记录，但如果不是位置参数则推进 next_pos（因为也消耗一个 vararg）
            if not pos:
                next_pos += 1

    # 去重并保序
    seen, out = set(), []
    for p in positions:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out
