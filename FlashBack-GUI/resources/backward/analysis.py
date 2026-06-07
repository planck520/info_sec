# -*- coding: utf-8 -*-
"""Core backward data-flow analysis routines.

These helpers are IDA/Hex-Rays specific and are invoked by cli.Analyzer.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union, Any
import re

try:
    import idaapi  # type: ignore
    import ida_hexrays  # type: ignore
    import idc  # type: ignore
    import idautils  # type: ignore
    import ida_funcs  # type: ignore
except Exception:  # pragma: no cover - only available inside IDA
    idaapi = ida_hexrays = idc = idautils = ida_funcs = None  # type: ignore

from backward.constants import ASSIGN_OPS
from backward.visitors import CallVisitor, collect_vars_from_expr
from backward.format_utils import (
    get_referenced_vararg_indices,
    parse_printf_positions_filtered,
    try_get_cstr_from_cexpr,
)
from backward.propagator_handler import handle_propagator_assignments



# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def _expr_parent_insn_ea(cfunc, e) -> int:
    """Return the EA of the nearest parent cinsn for an expression, or BADADDR on failure."""
    try:
        item = cfunc.body.find_parent_of(e)
        while item:
            if item.is_insn():
                return item.cinsn.ea
            item = cfunc.body.find_parent_of(item.it)
    except Exception:
        pass
    return idaapi.BADADDR


def _check_strlen_safe_pattern(cfunc, var_idx: int, call_ea: int, sink_func: str, len_idx: Optional[int]) -> bool:
    """Check whether a CWE-120 sink matches the strlen-based safe pattern.

    Pattern 1: strlen + malloc
        v2 = strlen(v1);
        v3 = malloc(v2 + 1);
        strcpy(v3, v1);

    Pattern 2: strlen + len argument
        v3 = strlen(hostname);
        strncpy(cfg->hostname, hostname, v3);

    Returns:
        True if the pattern is safe and should be filtered; otherwise False.
    """
    import logging
    _LOGGER = logging.getLogger(__name__)

    # Only check CWE-120-related functions
    CWE120_SINKS = {
        "strcpy", "strcat", "strncpy", "strncat", "memcpy", "memmove",
        "wcscpy", "wcscat", "wmemcpy", "wmemmove", "stpcpy", "sprintf",
        "snprintf", "vsnprintf", "bcopy", "memccpy", "strlcpy", "strlcat",
        "sscsnf"
    }

    if sink_func not in CWE120_SINKS:
        return False

    # Get the variable name and function name
    func_name = ida_funcs.get_func_name(cfunc.entry_ea) or "unknown"
    try:
        lvar = cfunc.lvars[var_idx]
        var_name = lvar.name
    except Exception:
        return False

    # Look backward for strlen calls
    class StrlenFinder(idaapi.ctree_visitor_t):
        def __init__(self, target_var_idx: int, limit_ea: int):
            super().__init__(idaapi.CV_FAST)
            self.target_idx = target_var_idx
            self.limit_ea = limit_ea
            self.strlen_found = False
            self.strlen_result_var = None

        def visit_expr(self, e):
            ea = getattr(e, "ea", idaapi.BADADDR) or _expr_parent_insn_ea(cfunc, e)
            # Only inspect statements from the function entry up to the sink call site (inclusive)
            if ea == idaapi.BADADDR or ea > self.limit_ea:
                return 0

            # Look for: result_var = strlen(target_var)
            if e.op == idaapi.cot_asg:
                lhs = getattr(e, "x", None)
                rhs = getattr(e, "y", None)

                if rhs and rhs.op == idaapi.cot_call:
                    callee = rhs.x
                    if callee.op == idaapi.cot_obj:
                        func_name = idaapi.get_func_name(callee.obj_ea) or ""
                        if func_name == "strlen" and rhs.a.size() > 0:
                            arg = rhs.a[0]
                            if arg.op == idaapi.cot_var and arg.v.idx == self.target_idx:
                                # Found strlen(target_var)
                                if lhs and lhs.op == idaapi.cot_var:
                                    self.strlen_found = True
                                    self.strlen_result_var = lhs.v.idx
                                    return 1  # Stop searching
            return 0

    finder = StrlenFinder(var_idx, call_ea)
    try:
        finder.apply_to(cfunc.body, None)
    except Exception:
        return False

    if not finder.strlen_found or finder.strlen_result_var is None:
        return False

    strlen_var_idx = finder.strlen_result_var

    # Pattern 2: check whether the strlen result is used as the len argument
    if len_idx is not None:
        # Find the call site and check whether len_idx uses strlen_var
        class LenChecker(idaapi.ctree_visitor_t):
            def __init__(self, strlen_idx: int, tgt_ea: int, tgt_len_idx: int):
                super().__init__(idaapi.CV_FAST)
                self.strlen_idx = strlen_idx
                self.target_ea = tgt_ea
                self.len_param_idx = tgt_len_idx
                self.len_matches = False

            def visit_expr(self, e):
                if e.op == idaapi.cot_call:
                    ea = getattr(e, "ea", idaapi.BADADDR)
                    if ea == self.target_ea and self.len_param_idx < e.a.size():
                        len_arg = e.a[self.len_param_idx]
                        if len_arg.op == idaapi.cot_var and len_arg.v.idx == self.strlen_idx:
                            self.len_matches = True
                            return 1
                return 0

        len_checker = LenChecker(strlen_var_idx, call_ea, len_idx)
        try:
            len_checker.apply_to(cfunc.body, None)
        except Exception:
            pass

        if len_checker.len_matches:
            _LOGGER.info(f"[CWE-120] ✓ Safe pattern (strlen+len): {sink_func} in {func_name} at 0x{call_ea:x}")
            return True

    # Pattern 1: check whether the strlen result flows into malloc
    class MallocChecker(idaapi.ctree_visitor_t):
        def __init__(self, strlen_idx: int, limit_ea: int):
            super().__init__(idaapi.CV_FAST)
            self.strlen_idx = strlen_idx
            self.limit_ea = limit_ea
            self.malloc_vars = set()

        def visit_expr(self, e):
            # Check malloc/calloc/realloc calls
            if e.op == idaapi.cot_call:
                callee = e.x
                if callee.op == idaapi.cot_obj:
                    func_name = idaapi.get_func_name(callee.obj_ea) or ""
                    if func_name in ("malloc", "calloc", "realloc"):
                        # Check whether malloc's first argument (size) contains the strlen variable
                        if e.a.size() > 0:
                            size_arg = e.a[0]
                            if self._contains_var(size_arg, self.strlen_idx):
                                # This is a valid malloc; find the variable that receives its return value
                                parent_item = cfunc.body.find_parent_of(e)
                                while parent_item:
                                    if hasattr(parent_item, 'cexpr') and parent_item.cexpr.op == idaapi.cot_asg:
                                        lhs = parent_item.cexpr.x
                                        if lhs.op == idaapi.cot_var:
                                            self.malloc_vars.add(lhs.v.idx)
                                            break
                                    parent_item = cfunc.body.find_parent_of(parent_item.it) if hasattr(parent_item, 'it') else None
            return 0

        def _contains_var(self, expr, var_idx: int) -> bool:
            """Recursively check whether the expression contains the target variable."""
            class VarChecker(idaapi.ctree_visitor_t):
                def __init__(self, target_idx: int):
                    super().__init__(idaapi.CV_FAST)
                    self.target_idx = target_idx
                    self.found = False

                def visit_expr(self, e):
                    if e.op == idaapi.cot_var and e.v.idx == self.target_idx:
                        self.found = True
                        return 1
                    return 0

            checker = VarChecker(var_idx)
            try:
                checker.apply_to(expr, None)
            except Exception:
                pass
            return checker.found

    malloc_checker = MallocChecker(strlen_var_idx, call_ea)
    try:
        malloc_checker.apply_to(cfunc.body, None)
    except Exception:
        return False

    # Check whether the sink destination argument (usually argument 0) comes from malloc
    if malloc_checker.malloc_vars:
        class SinkDstChecker(idaapi.ctree_visitor_t):
            def __init__(self, malloc_set: set, tgt_ea: int):
                super().__init__(idaapi.CV_FAST)
                self.malloc_set = malloc_set
                self.target_ea = tgt_ea
                self.dst_is_malloc = False

            def visit_expr(self, e):
                if e.op == idaapi.cot_call:
                    ea = getattr(e, "ea", idaapi.BADADDR)
                    if ea == self.target_ea and e.a.size() > 0:
                        dst_arg = e.a[0]
                        if dst_arg.op == idaapi.cot_var and dst_arg.v.idx in self.malloc_set:
                            self.dst_is_malloc = True
                            return 1
                return 0

        dst_checker = SinkDstChecker(malloc_checker.malloc_vars, call_ea)
        try:
            dst_checker.apply_to(cfunc.body, None)
        except Exception:
            pass

        if dst_checker.dst_is_malloc:
            _LOGGER.info(f"[CWE-120] ✓ Safe pattern (strlen+malloc): {sink_func} in {func_name} at 0x{call_ea:x}")
            return True

    return False


def _decompile_func_by_ea(func_ea: int):
    """Safely decompile a function by its entry EA, returning None on failure."""
    try:
        return ida_hexrays.decompile(func_ea)
    except Exception:
        return None


def _find_call_expr_by_ea(cfunc, target_name: str, target_ea: int):
    """Find the call expression for a target function in cfunc by exact EA. Return (cexpr_t, ea) or None."""
    visitor = CallVisitor(cfunc, target_name)
    visitor.apply_to(cfunc.body, None)
    for ce, ea in visitor.calls:
        if ea == target_ea:
            return ce, ea
    return None


def _cexpr_to_text(cfunc, e) -> str:
    """Render any cexpr as a single-line string for context reporting."""
    try:
        qp = ida_hexrays.qstring_printer_t(cfunc, False)
        e._print(0, qp)
        s = qp.s.strip()
        if "\n" in s:
            s = s.split("\n", 1)[0]
        return s
    except Exception:
        return ""


# === Structured condition scan: whether the call appears in an if/else/loop/switch condition or branch ===
def _node_contains_call(node, target_ea: int, target_text: str, cfunc) -> bool:
    """Check whether a subtree contains the target call, preferably by EA and otherwise by single-line text."""
    class _Finder(idaapi.ctree_visitor_t):
        def __init__(self, tgt_ea, tgt_txt):
            super().__init__(idaapi.CV_FAST)
            self.tgt_ea = tgt_ea
            self.tgt_txt = tgt_txt
            self.found = False
        def visit_expr(self, e):
            if e.op == idaapi.cot_call:
                ea = getattr(e, "ea", idaapi.BADADDR)
                if ea == self.tgt_ea and ea != idaapi.BADADDR:
                    self.found = True
                    return 1  # stop
                # Some versions/scenarios may expose BADADDR here, so fall back to text matching
                if self.tgt_txt:
                    try:
                        qp = ida_hexrays.qstring_printer_t(cfunc, False)
                        e._print(0, qp)
                        line = qp.s.strip().split("\n", 1)[0]
                        if line == self.tgt_txt:
                            self.found = True
                            return 1
                    except Exception:
                        pass
            return 0
        def visit_insn(self, i):
            return 0
    f = _Finder(target_ea, target_text)
    try:
        f.apply_to(node, None)
    except Exception:
        return False
    return f.found

def _is_callsite_in_condition(cfunc, call_expr) -> bool:
    """Scan the whole function structure and return True if the target call appears in an if/else/loop/switch condition or branch body."""
    tgt_ea = getattr(call_expr, "ea", idaapi.BADADDR)
    # Use the target call's single-line text as the fallback match key
    try:
        qp = ida_hexrays.qstring_printer_t(cfunc, False)
        call_expr._print(0, qp)
        tgt_txt = qp.s.strip().split("\n", 1)[0]
    except Exception:
        tgt_txt = ""

    class _CondScanner(idaapi.ctree_visitor_t):
        def __init__(self, ea, txt):
            super().__init__(idaapi.CV_FAST)
            self.ea = ea
            self.txt = txt
            self.hit = False

        def visit_insn(self, i):
            if self.hit:
                return 1
            op = i.op

            # if (...) {ithen} else {ielse}
            if op == getattr(idaapi, "cit_if", -1):
                ci = i.cif
                try:
                    if ci.expr and _node_contains_call(ci.expr, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass
                try:
                    if ci.ithen and _node_contains_call(ci.ithen, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass
                try:
                    if ci.ielse and _node_contains_call(ci.ielse, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass

            # while (expr) body
            elif op == getattr(idaapi, "cit_while", -1):
                cw = i.cwhile
                try:
                    if cw.expr and _node_contains_call(cw.expr, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass
                try:
                    if cw.body and _node_contains_call(cw.body, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass

            # do {body} while (expr)
            elif op == getattr(idaapi, "cit_do", -1):
                cd = i.cdo
                try:
                    if cd.body and _node_contains_call(cd.body, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass
                try:
                    if cd.expr and _node_contains_call(cd.expr, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass

            # for (init; expr; step) body
            elif op == getattr(idaapi, "cit_for", -1):
                cf = i.cfor
                for child in ("init", "expr", "step", "body"):
                    try:
                        node = getattr(cf, child)
                        if node and _node_contains_call(node, self.ea, self.txt, cfunc):
                            self.hit = True; return 1
                    except Exception:
                        pass

            # switch (expr) {body}
            elif op == getattr(idaapi, "cit_switch", -1):
                cs = i.cswitch
                try:
                    if cs.expr and _node_contains_call(cs.expr, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass
                try:
                    if cs.body and _node_contains_call(cs.body, self.ea, self.txt, cfunc):
                        self.hit = True; return 1
                except Exception:
                    pass

            return 0  # Keep scanning

    scanner = _CondScanner(tgt_ea, tgt_txt)
    try:
        scanner.apply_to(cfunc.body, None)
    except Exception:
        return False
    return scanner.hit

def _cond_tag(cfunc, call_expr) -> str:
    """Return "needs_check" or "certain"."""
    return "needs_check" if _is_callsite_in_condition(cfunc, call_expr) else "certain"


# ----------------------------------------------------------------------
# Basic traversal and collection
# ----------------------------------------------------------------------
def find_var_assignments(
    cfunc,
    lvar_idx: int,
    cwe_sources: Dict[Union[int, str], Set[str]],
    limit_ea: Optional[int] = None,
    propagators: Optional[dict] = None,
) -> List[dict]:
    """Trace assignments to a local variable and places where it is passed as an argument."""
    import logging
    _LOGGER = logging.getLogger(__name__)

    # _LOGGER.info(f"[DEBUG find_var_assignments] >>> ENTER lvar_idx={lvar_idx}")
    results: List[dict] = []

    class _AssignVisitor(idaapi.ctree_visitor_t):  # type: ignore[misc]
        def __init__(self, target_idx: int) -> None:
            super().__init__(idaapi.CV_FAST)
            self.target_idx = target_idx

        def visit_expr(self, e) -> int:  # type: ignore[override]
            # 1) Assignment / compound assignment / initialization
            if e.op in ASSIGN_OPS:
                lhs = getattr(e, "x", None)
                rhs = getattr(e, "y", None)
                if lhs is not None and lhs.op == idaapi.cot_var and lhs.v.idx == self.target_idx:
                    ea = getattr(e, "ea", idaapi.BADADDR) or _expr_parent_insn_ea(cfunc, e)
                    if ea == idaapi.BADADDR or (limit_ea is not None and not (ea < limit_ea)):
                        return 0

                    # If the assignment RHS is a propagator call (for example snprintf/GetValue/cJSON_*)
                    if propagators and rhs is not None and rhs.op == idaapi.cot_call:
                        try:
                            prop_results = handle_propagator_assignments(cfunc, rhs, ea, propagators)
                        except Exception:
                            prop_results = []
                        if prop_results:
                            results.extend(prop_results)
                            return 0

                    results.append({"type": "assign", "ea": ea, "expr": rhs})

            # 2) Call site: the variable is passed into a position we care about
            elif e.op == idaapi.cot_call:
                callee = e.x
                func_name = ""
                if callee.op == idaapi.cot_obj:
                    func_name = idaapi.get_func_name(callee.obj_ea) or ""

                for i, arg in enumerate(e.a):
                    if isinstance(i, int) and i in cwe_sources and func_name in cwe_sources[i]:
                        if arg.op == idaapi.cot_var and arg.v.idx == self.target_idx:
                            ea = getattr(e, "ea", idaapi.BADADDR) or _expr_parent_insn_ea(cfunc, e)
                            if ea == idaapi.BADADDR or (limit_ea is not None and not (ea < limit_ea)):
                                return 0
                            results.append({
                                "type": "arg", "ea": ea, "expr": e, "arg_index": i
                            })
            return 0

    # _LOGGER.info(f"[DEBUG find_var_assignments] Starting AST traversal for lvar_idx={lvar_idx}")
    _AssignVisitor(lvar_idx).apply_to(cfunc.body, None)
    results.sort(key=lambda x: x["ea"], reverse=True)
    # _LOGGER.info(f"[DEBUG find_var_assignments] <<< EXIT lvar_idx={lvar_idx}, found {len(results)} assignments")
    return results


def extract_vars_from_expr(expr) -> List[int]:
    """Return the list of local-variable indices that appear in the expression tree."""
    vars_found: List[int] = []

    class _VarVisitor(idaapi.ctree_visitor_t):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__(idaapi.CV_FAST)

        def visit_expr(self, e) -> int:  # type: ignore[override]
            if e.op == idaapi.cot_var:
                vars_found.append(e.v.idx)
            return 0

    _VarVisitor().apply_to(expr, None)
    return vars_found


def _iter_lvars(cfunc):
    """Safely iterate over cfunc.lvars across different bindings."""
    try:
        n = len(cfunc.lvars)
        for i in range(n):
            yield i, cfunc.lvars[i]
    except Exception:
        try:
            n = cfunc.lvars.size()
            for i in range(n):
                yield i, cfunc.lvars[i]
        except Exception:
            return


def _build_arg_ordinal_map(cfunc):
    """Build a mapping from local-variable index to parameter ordinal."""
    arg_ord_map = {}
    try:
        args = list(getattr(cfunc, "arguments", [])) or []
    except Exception:
        args = []
    if args:
        for idx, lv in _iter_lvars(cfunc):
            try:
                ord_ = args.index(lv)
                arg_ord_map[idx] = ord_
            except ValueError:
                pass
    return arg_ord_map


# ----------------------------------------------------------------------
# Core backward tracing
# ----------------------------------------------------------------------
def trace_var_sources(
    cfunc,
    var_idx: int,
    cwe_sources: Dict[Union[int, str], Set[str]],
    call_ea: Optional[int] = None,
    arg_size: int = 0,
    depth: int = 0,
    var_sources: Optional[Set[int]] = None,
    path_stack: Optional[Set[int]] = None,
    arg_ord_map: Optional[dict] = None,
    propagators: Optional[dict] = None,
):
    """Trace the origin of a local variable. Return (sources, func_name, ea, taint_source)."""
    import logging
    _LOGGER = logging.getLogger(__name__)

    # _LOGGER.info(f"[DEBUG trace_var_sources] >>> ENTER var_idx={var_idx}, depth={depth}")

    if var_sources is None:
        var_sources = set()
    if path_stack is None:
        path_stack = set()

    if var_idx in path_stack:
        # _LOGGER.info(f"[DEBUG trace_var_sources] <<< EXIT (circular) var_idx={var_idx}")
        return var_sources, None, None, None

    path_stack.add(var_idx)
    # _LOGGER.info(f"[DEBUG trace_var_sources] Calling find_var_assignments for var_idx={var_idx}")
    assigns = find_var_assignments(
        cfunc, var_idx, cwe_sources, limit_ea=call_ea, propagators=propagators
    )
    # _LOGGER.info(f"[DEBUG trace_var_sources] find_var_assignments returned {len(assigns)} items")
    if not assigns:
        if arg_ord_map and var_idx in arg_ord_map:
            var_sources.add(arg_ord_map[var_idx])
        return var_sources, None, None, None

    for item in assigns:
        if item["type"] == "assign":
            ea = item["ea"]
            rhs = item["expr"]

            # RHS is a call return: treat it as a ret source
            if rhs is not None and rhs.op == idaapi.cot_call and rhs.x.op == idaapi.cot_obj:
                func_name = idaapi.get_func_name(rhs.x.obj_ea)
                if func_name in cwe_sources.get("ret", set()):
                    return var_sources, func_name, ea, "ret"

            elif rhs is not None and rhs.op == idaapi.cot_cast:
                target_expr = rhs.x
                if target_expr.op == idaapi.cot_call and target_expr.x.op == idaapi.cot_obj:
                    func_name = idaapi.get_func_name(target_expr.x.obj_ea)
                    if func_name in cwe_sources.get("ret", set()):
                        return var_sources, func_name, ea, "ret"
                elif target_expr.op in (idaapi.cot_ptr, idaapi.cot_memptr, idaapi.cot_memref):
                    sub = target_expr.x
                    if sub.op == idaapi.cot_call and sub.x.op == idaapi.cot_obj:
                        func_name = idaapi.get_func_name(sub.x.obj_ea)
                        if func_name in cwe_sources.get("ret", set()):
                            return var_sources, func_name, ea, "ret"

            # Otherwise recurse into variables referenced by the RHS subtree
            sub_vars = extract_vars_from_expr(rhs) if rhs is not None else []
            # _LOGGER.info(f"[DEBUG trace_var_sources] RHS has {len(sub_vars)} sub-variables to trace")
            for sub_idx in sub_vars:
                # _LOGGER.info(f"[DEBUG trace_var_sources] Recursing into sub_idx={sub_idx} (depth={depth+1})")
                sources, func_name, fea, taint_source = trace_var_sources(
                    cfunc,
                    sub_idx,
                    cwe_sources,
                    call_ea=ea,
                    arg_size=arg_size,
                    depth=depth + 1,
                    var_sources=var_sources,
                    path_stack=path_stack,  # Share path_stack instead of copying it
                    arg_ord_map=arg_ord_map,
                    propagators=propagators,
                )
                # _LOGGER.info(f"[DEBUG trace_var_sources] Returned from sub_idx={sub_idx}, func_name={func_name}")
                if func_name:
                    # _LOGGER.info(f"[DEBUG trace_var_sources] <<< EXIT (found source) var_idx={var_idx}")
                    return sources, func_name, fea, taint_source

        elif item["type"] == "arg":
            ea = item["ea"]
            taint_source = item["arg_index"]
            func_name = idaapi.get_func_name(item["expr"].x.obj_ea)
            return var_sources, func_name, ea, taint_source

        elif item["type"] == "propagator":
            # Assignment-style propagator: continue tracing variables in its input expr
            ea = item["ea"]
            expr = item["expr"]
            prop_vars = extract_vars_from_expr(expr)
            # _LOGGER.info(f"[DEBUG trace_var_sources] Propagator has {len(prop_vars)} variables to trace")
            for sub_idx in prop_vars:
                # _LOGGER.info(f"[DEBUG trace_var_sources] Recursing into propagator sub_idx={sub_idx} (depth={depth+1})")
                sources, src_func, src_ea, taint_source = trace_var_sources(
                    cfunc,
                    sub_idx,
                    cwe_sources,
                    call_ea=ea,
                    arg_size=arg_size,
                    depth=depth + 1,
                    var_sources=var_sources,
                    path_stack=path_stack,  # Share path_stack instead of copying it
                    arg_ord_map=arg_ord_map,
                    propagators=propagators,
                )
                # _LOGGER.info(f"[DEBUG trace_var_sources] Returned from propagator sub_idx={sub_idx}, src_func={src_func}")
                if src_func:
                    # _LOGGER.info(f"[DEBUG trace_var_sources] <<< EXIT (found source via propagator) var_idx={var_idx}")
                    return sources, src_func, src_ea, taint_source

    # _LOGGER.info(f"[DEBUG trace_var_sources] <<< EXIT (no source found) var_idx={var_idx}")
    return var_sources, None, None, None


# ----------------------------------------------------------------------
# Move one layer upward: trace a callee parameter back to its caller
# ----------------------------------------------------------------------
def analyze_arg_xrefs(
    caller_func_address: int,
    callee_func_name: str,
    arg_index: int,
    cwe_sources,
    format_funcs: Optional[dict] = None,
    vuln_type: Optional[str] = None,
    len_idx: Optional[int] = None,
    propagators: Optional[dict] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Enumerate all caller-side call sites to callee and prepare to trace arg_index."""
    import logging
    _LOGGER = logging.getLogger(__name__)

    func_name = idc.get_func_name(caller_func_address)
    try:
        cfunc = ida_hexrays.decompile(caller_func_address)
    except Exception:
        return None
    if not cfunc:
        return None

    arg_ord_map = _build_arg_ordinal_map(cfunc)
    visitor = CallVisitor(cfunc, callee_func_name)
    visitor.apply_to(cfunc.body, None)

    # Variadic / format handling
    is_variadic = False
    fmt_idx = None
    va_start_idx = None
    if format_funcs and callee_func_name in format_funcs:
        conf = format_funcs.get(callee_func_name, {})
        fmt_idx = conf.get("fmt")
        va_start_idx = conf.get("va_start")
        is_variadic = isinstance(fmt_idx, int) and isinstance(va_start_idx, int)

    results: List[Dict[str, Any]] = []

    # Propagator configuration, for example {"GetValue": {"input":0, "output":1}}
    prop_conf = (propagators or {}).get(callee_func_name)

    import logging
    _LOGGER = logging.getLogger(__name__)

    # ============ DEBUG: function entry info ============
    # _LOGGER.info(f"[DEBUG analyze_arg_xrefs] Analyzing {callee_func_name} in {func_name}")
    _LOGGER.info(f"  arg_index={arg_index}, vuln_type={vuln_type}, len_idx={len_idx}")
    _LOGGER.info(f"  is_variadic={is_variadic}, fmt_idx={fmt_idx}, va_start_idx={va_start_idx}")
    # _LOGGER.info(f"  Found {len(visitor.calls)} call sites")
    # ==========================================

    for call_expr, _ in visitor.calls:
        call_ea = call_expr.ea
        tag_here = _cond_tag(cfunc, call_expr)  # Condition label for this call site

        base_ctx = {
            "callee": callee_func_name,
            "caller": func_name,
            "call_ea": call_ea,
            "call_line": _cexpr_to_text(cfunc, call_expr),
            "cond_tag": tag_here,
        }

        # ============ DEBUG: call-site info ============
        # _LOGGER.info(f"[DEBUG call_site] Processing call at 0x{call_ea:x}")
        _LOGGER.info(f"  call_line: {_cexpr_to_text(cfunc, call_expr)}")
        _LOGGER.info(f"  arg count: {call_expr.a.size()}")
        # ==========================================

        _LOGGER.debug(f"[analyze_arg_xrefs] Processing {callee_func_name} in {func_name} at 0x{call_ea:x}, vuln_type={vuln_type}")

        # Compute the absolute argument indices that must be checked at this call site
        indices_to_check: List[int] = []

        # ============ DEBUG: branch condition ============
        # _LOGGER.info(f"[DEBUG branch] Checking condition: is_variadic and arg_index == fmt_idx")
        _LOGGER.info(f"  is_variadic={is_variadic}, arg_index={arg_index}, fmt_idx={fmt_idx}")
        _LOGGER.info(f"  Condition result: {is_variadic and arg_index == fmt_idx}")
        # ==========================================

        if is_variadic and arg_index == fmt_idx and call_expr.a.size() > va_start_idx:
            if vuln_type == "CWE-134":
                indices_to_check = [fmt_idx]
            elif vuln_type == "CWE-78":
                # For command injection in format functions, check all variable arguments
                indices_to_check = list(range(va_start_idx, call_expr.a.size()))
            elif vuln_type == "CWE-120":
                if len_idx is not None and len_idx < call_expr.a.size():
                    len_expr = call_expr.a[len_idx]
                    if len_expr.op == idaapi.cot_num or (
                        len_expr.op == idaapi.cot_cast and len_expr.x.op == idaapi.cot_num
                    ):
                        results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                        continue
                s = try_get_cstr_from_cexpr(call_expr.a[fmt_idx])
                if s:
                    used_positions = parse_printf_positions_filtered(
                        s, {"s", "n"}, include_width_star_for_s=True
                    )
                    indices_to_check = [
                        va_start_idx + (p - 1)
                        for p in used_positions
                        if va_start_idx + (p - 1) < call_expr.a.size()
                    ]
                    if not indices_to_check:
                        results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                        continue
                else:
                    indices_to_check = [fmt_idx]
            else:
                indices_to_check = [fmt_idx]
        else:
                    # ============ DEBUG: entering the else branch ============
            # _LOGGER.info(f"[DEBUG branch] Entered ELSE branch (not is_variadic or arg_index != fmt_idx)")
            # ==========================================

            # For non-variadic functions, check if there's a length parameter that's a constant
            if len_idx is not None and len_idx < call_expr.a.size() and vuln_type == "CWE-120":
                len_expr = call_expr.a[len_idx]
                if len_expr.op == idaapi.cot_num or (
                    len_expr.op == idaapi.cot_cast and len_expr.x.op == idaapi.cot_num
                ):
                    # Length is a constant, skip this call for CWE-120
                    # _LOGGER.info(f"[DEBUG filter] Filtered: len_idx is constant")
                    results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                    continue

            # Special handling for scanf family functions that are configured as format functions
            # but we're checking a different parameter (e.g., checking arg 0 while fmt is at arg 1)
                # ============ DEBUG: scanf special-case condition ============
            # _LOGGER.info(f"[DEBUG scanf_filter] Checking scanf filter condition:")
            _LOGGER.info(f"  is_variadic={is_variadic}")
            _LOGGER.info(f"  fmt_idx={fmt_idx}, arg_index={arg_index}")
            _LOGGER.info(f"  fmt_idx != arg_index: {fmt_idx != arg_index if fmt_idx is not None else 'N/A'}")
            _LOGGER.info(f"  vuln_type={vuln_type}")
            scanf_filter_cond = (is_variadic and fmt_idx is not None and fmt_idx != arg_index and
                                 fmt_idx < call_expr.a.size() and vuln_type == "CWE-120")
            _LOGGER.info(f"  Final condition result: {scanf_filter_cond}")
            # ==========================================

            if (is_variadic and fmt_idx is not None and fmt_idx != arg_index and
                fmt_idx < call_expr.a.size() and vuln_type == "CWE-120"):
                    # ============ DEBUG: entering the scanf filtering branch ============
                # _LOGGER.info(f"[DEBUG scanf_filter] Entered scanf filter branch")
                _LOGGER.info(f"  Trying to parse format string at arg index {fmt_idx}")
                # ==========================================

                s = try_get_cstr_from_cexpr(call_expr.a[fmt_idx])

                    # ============ DEBUG: format-string parse result ============
                # _LOGGER.info(f"[DEBUG scanf_filter] Format string parse result: {repr(s)}")
                # ==========================================

                if s:
                    # For scanf family functions like __isoc99_sscanf, only %s can cause buffer overflow
                    used_positions = parse_printf_positions_filtered(
                        s, {"s"}, include_width_star_for_s=True  # Only check %s for buffer overflow
                    )

                        # ============ DEBUG: %s position check ============
                    # _LOGGER.info(f"[DEBUG scanf_filter] Format string: {s}")
                    # _LOGGER.info(f"[DEBUG scanf_filter] Used positions with %s: {used_positions}")
                    # ==========================================

                    if not used_positions:
                        # No %s format specifiers found, skip this call for CWE-120
                        # _LOGGER.info(f"[DEBUG filter] Filtered: No %s in format string '{s}'")
                        results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                        continue
                else:
                    # ============ DEBUG: format-string parsing failed ============
                    _LOGGER.warning(f"[DEBUG scanf_filter] Format string parse FAILED - filter skipped!")
                    _LOGGER.warning(f"  This may cause false positive!")
                    # ==========================================

            if arg_index < call_expr.a.size():
                indices_to_check = [arg_index]
            else:
                results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                continue



                # ---------- GetValue(key, dst) -> jump to SetValue(key, val) and trace val ----------
        if handle_propagator_assignments and prop_conf and isinstance(prop_conf, dict) and callee_func_name not in {"snprintf", "vsnprintf"}:
            prop_input = prop_conf.get("input")
            if isinstance(prop_input, int) and arg_index == int(prop_input):
                base_ctx.update({
                    "getvalue_key": None,
                    "getvalue_call_line": _cexpr_to_text(cfunc, call_expr),
                    "setvalue_sites": [],
                })
                    # Record the key string
                try:
                    key_expr = call_expr.a[prop_input]
                    base_ctx["getvalue_key"] = try_get_cstr_from_cexpr(key_expr)
                except Exception:
                    pass

                try:
                    prop_hits = handle_propagator_assignments(cfunc, call_expr, call_ea, propagators)
                except Exception:
                    prop_hits = []

                for ph in prop_hits:
                    if ph.get("type") != "propagator":
                        continue
                    set_ea = ph.get("ea")
                    set_func_name = ph.get("func_name")
                    # SetValue defaults to parameter 1 for the value argument

                    if not isinstance(set_ea, int) or not set_func_name:
                        continue

                    host_func = ida_funcs.get_func(set_ea)
                    if not host_func:
                        continue
                    host_name = idc.get_func_name(host_func.start_ea) or ""
                    host_cfunc = _decompile_func_by_ea(host_func.start_ea)
                    if not host_cfunc:
                        continue

                    found = _find_call_expr_by_ea(host_cfunc, set_func_name, set_ea)
                    if not found:
                        continue
                    set_call_expr, _ = found
                    if set_arg_idx >= set_call_expr.a.size():
                        continue

                    # Host call-site label

                    # Collect SetValue-site context
                    site_ctx = {
                        "setvalue_func": set_func_name,
                        "setvalue_host": host_name,
                        "setvalue_func_ea": host_func.start_ea,
                        "setvalue_call_ea": set_ea,
                        "setvalue_call_line": _cexpr_to_text(host_cfunc, set_call_expr),
                        "setvalue_key": try_get_cstr_from_cexpr(set_call_expr.a[0]) if set_call_expr.a.size() > 0 else None,
                        "setvalue_val_abs_idx": set_arg_idx,
                        "setvalue_val_line": _cexpr_to_text(host_cfunc, set_call_expr.a[set_arg_idx]),
                        "setvalue_cond_tag": host_tag,
                    }
                    base_ctx.setdefault("setvalue_sites", []).append(site_ctx)

                    # Trace the val argument inside the function that contains SetValue
                    host_arg_map = _build_arg_ordinal_map(host_cfunc)
                    arg_expr2 = set_call_expr.a[set_arg_idx]

                    _lvars2, _gvars2, lvar_exprs2 = collect_vars_from_expr(host_cfunc, arg_expr2)

                    local_next2: Set[int] = set()
                    source_payload2: Optional[Dict[str, Any]] = None

                    for lvidx2 in lvar_exprs2:
                        sources2, fname2, fea2, tsrc2 = trace_var_sources(
                            cfunc=host_cfunc,
                            var_idx=lvidx2,
                            cwe_sources=cwe_sources,
                            call_ea=set_ea,
                            arg_size=set_call_expr.a.size(),
                            depth=0,
                            var_sources=set(),
                            path_stack=set(),
                            arg_ord_map=host_arg_map,
                            propagators=propagators,
                        )
                        local_next2.update(sources2)
                        if fname2 and source_payload2 is None:
                        # Record jump-node metadata and labels in the source payload
                            source_payload2 = {
                                "func": fname2,
                                "ea": fea2,
                                "taint": tsrc2,
                                "abs_idx": set_arg_idx,
                                "jump_to_func": host_name,
                                "jump_func_ea": host_func.start_ea,
                                "jump_call_ea": set_ea,
                                "jump_cond_tag": host_tag,
                                # Caller label
                            }

                            # Hand the result to the upper layer as a jump edge, including both labels
                    jump_edges = []
                    for nx in local_next2:
                        jump_edges.append({
                            "next_idx": nx,
                            "abs_idx": set_arg_idx,
                            "jump_to_func": host_name,
                            "jump_func_ea": host_func.start_ea,
                            "jump_call_ea": set_ea,
                            # Caller label
                            # Host label
                        })

                    results.append({
                        "call_ea": call_ea,
                        "edges": jump_edges,
                        "source": source_payload2,
                        "context": dict(base_ctx),
                        "cond_tag": tag_here,
                    })

                # This call site is fully handled once the propagator rule matches
                continue
        # -------------------------------------------------------------------

        # Regular path: trace the expressions referenced by indices_to_check
        edges: List[Dict[str, int]] = []
        source_payload: Optional[Dict[str, Any]] = None

        # CWE-120: before tracing, check whether the current function matches a safe pattern
        if vuln_type == "CWE-120" and indices_to_check:
            # Check the first argument that needs inspection
            first_idx = indices_to_check[0]
            if first_idx < call_expr.a.size():
                arg_expr = call_expr.a[first_idx]
                _lvars_pre, _gvars_pre, lvar_exprs_pre = collect_vars_from_expr(cfunc, arg_expr)

                # Check whether any variable matches the safe pattern
                has_safe_pattern = False
                for lvar_idx_pre in lvar_exprs_pre:
                    if _check_strlen_safe_pattern(cfunc, lvar_idx_pre, call_ea, callee_func_name, len_idx):
                        has_safe_pattern = True
                        break

                if has_safe_pattern:
                    # Skip this call site and emit no path
                    continue

        for abs_idx in indices_to_check:
            # _LOGGER.info(f"[DEBUG loop] Processing abs_idx={abs_idx} in indices_to_check={indices_to_check}")
            arg_expr = call_expr.a[abs_idx]
            _lvars, _gvars, lvar_exprs = collect_vars_from_expr(cfunc, arg_expr)
            # _LOGGER.info(f"[DEBUG loop] Found {len(lvar_exprs)} lvar_exprs to trace")

            local_next: Set[int] = set()
            for lvar_idx in lvar_exprs:
                # _LOGGER.info(f"[DEBUG trace_var_sources] Calling trace_var_sources for lvar_idx={lvar_idx}")
                sources, func_name2, ea, taint_source = trace_var_sources(
                    cfunc=cfunc,
                    var_idx=lvar_idx,
                    cwe_sources=cwe_sources,
                    call_ea=call_ea,
                    arg_size=call_expr.a.size(),
                    depth=0,
                    var_sources=set(),
                    path_stack=set(),
                    arg_ord_map=arg_ord_map,
                    propagators=propagators,
                )
                local_next.update(sources)
                if func_name2 and source_payload is None:
                    source_payload = {
                        "func": func_name2,
                        "ea": ea,
                        "taint": taint_source,
                        "abs_idx": abs_idx,
                        "cond_tag": tag_here,  # Caller label
                    }

            for nx in local_next:
                edges.append({"next_idx": nx, "abs_idx": abs_idx, "cond_tag": tag_here})

        results.append({
            "call_ea": call_ea, "edges": edges, "source": source_payload, "context": base_ctx, "cond_tag": tag_here
        })

    # ============ DEBUG: analyze_arg_xrefs return value ============
    # _LOGGER.info(f"[DEBUG analyze_arg_xrefs] Returning {len(results)} results for {callee_func_name} in {func_name}")
    for i, r in enumerate(results):
        edges_count = len(r.get("edges", []))
        has_source = r.get("source") is not None
        # _LOGGER.info(f"  Result {i}: call_ea=0x{r['call_ea']:x}, edges={edges_count}, has_source={has_source}")
    # ==========================================

    return results if results else None


def analyze_func_xrefs(func_name: str) -> Set[int]:
    """Return the set of unique caller entry EAs that reference `func_name`."""
    callee_ea = idc.get_name_ea(idaapi.BADADDR, func_name)
    if callee_ea == idaapi.BADADDR:
        return set()
    if not ida_hexrays.init_hexrays_plugin():
        return set()

    caller_funcs_address: Set[int] = set()
    for xref in idautils.XrefsTo(callee_ea, 0):
        caller_func = ida_funcs.get_func(xref.frm)
        if not caller_func:
            continue
        caller_funcs_address.add(caller_func.start_ea)
    return caller_funcs_address


# ----------------------------------------------------------------------
# Multi-hop backward tracing: build complete paths
# ----------------------------------------------------------------------
def trace_data_flow(
    start_func: str,
    arg_index: int,
    cwe_sources,
    call_ea: Optional[int] = None,
    func_ea: Union[str, int] = "sink",
    path: Optional[List[tuple]] = None,
    visited: Optional[Set[tuple]] = None,
    cache_get=None,
    cache_set=None,
    trace_path_counter=None,
    format_funcs: Optional[dict] = None,
    display_index: Optional[int] = None,
    vuln_type: Optional[str] = None,
    len_idx: Optional[int] = None,
    propagators: Optional[dict] = None,
    max_depth: int = 10,
    max_paths: int = 10000,
    root_label: Optional[str] = None,
):
    """Trace upward from (start_func, arg_index) and return a list of paths.
       Each path is a list of node tuples of the form
       (func, arg_index, call_ea, func_ea, label), where label is one of
       {"needs_check", "certain", "sink", "source"}.
    """
    import logging
    _LOGGER = logging.getLogger(__name__)

    if path is None:
        path = []
    if visited is None:
        visited = set()

    # ============ Create a dedicated counter for each sink function ============
    # Create an independent counter when this is a new sink root (func_ea == "sink" and path is empty)
    is_sink_root = (func_ea == "sink" and len(path) == 0)
    if is_sink_root and trace_path_counter is None:
        trace_path_counter = [0]
        _LOGGER.info(f"[LIMIT] Created a dedicated path counter for sink function {start_func} (max_paths={max_paths})")
    elif is_sink_root and trace_path_counter is not None:
        # If an external counter was supplied (shared mode), log a hint
        _LOGGER.info(f"[LIMIT] Sink function {start_func} is using the shared path counter (current count: {trace_path_counter[0]})")
    # ==========================================

    # ============ Priority 1: check the path-count limit ============
    if trace_path_counter is not None and trace_path_counter[0] >= max_paths:
        _LOGGER.warning(f"[LIMIT] Reached the path limit {max_paths}; stop generating more paths (start_func={start_func})")
        return []
    # ==========================================

    # ============ DEBUG: trace_data_flow entry ============
    depth = len(path)
    call_ea_str = f"0x{call_ea:x}" if call_ea else "None"
    # _LOGGER.info(f"[DEBUG trace_data_flow] ===== ENTER =====")
    # _LOGGER.info(f"  start_func={start_func}, arg_index={arg_index}")
    # _LOGGER.info(f"  call_ea={call_ea_str}, func_ea={func_ea}")
    # _LOGGER.info(f"  depth={depth}, vuln_type={vuln_type}")
    # ==========================================

    if len(path) > max_depth:
        # _LOGGER.info(f"[DEBUG trace_data_flow] Max depth exceeded ({len(path)} > {max_depth}), returning empty")
        return []

    # Current node (the root is the sink)
    label_here = root_label if root_label is not None else ("sink" if func_ea == "sink" else "certain")
    node = (
        start_func,
        display_index if display_index is not None else arg_index,
        call_ea,
        func_ea,
        label_here,
    )
    if node in visited:
        # _LOGGER.info(f"[DEBUG trace_data_flow] Node already visited: {start_func}, returning empty")
        return []

    # Cache key: drop call_ea for better reuse so different call sites in the same function can share results
    cache_key = (start_func, arg_index, vuln_type)
    if cache_get is not None:
        cached = cache_get(cache_key)
        if cached is not None:
            # _LOGGER.info(f"[DEBUG trace_data_flow] Cache hit for {start_func}, returning {len(cached)} cached results")
            return cached

    visited.add(node)
    path = path + [node]
    results: List[List[tuple]] = []

    caller_addrs = analyze_func_xrefs(start_func)
    # _LOGGER.info(f"[DEBUG trace_data_flow] Found {len(caller_addrs)} callers for {start_func}")

    if not caller_addrs:
        # _LOGGER.info(f"[DEBUG trace_data_flow] No callers found for {start_func}, path ends here (leaf node)")
        results.append(path)
        if trace_path_counter is not None:
            trace_path_counter[0] += 1
        if cache_set is not None:
            cache_set(cache_key, results)
        return results

    for addr in caller_addrs:
        caller_name = idc.get_func_name(addr)
        # _LOGGER.info(f"[DEBUG trace_data_flow] Processing caller: {caller_name} at 0x{addr:x}")

        call_infos = analyze_arg_xrefs(
            addr,
            start_func,
            arg_index,
            cwe_sources,
            format_funcs=format_funcs,
            vuln_type=vuln_type,
            len_idx=len_idx,
            propagators=propagators,
        )
        if not call_infos:
            # _LOGGER.info(f"[DEBUG trace_data_flow] No call_infos returned from {caller_name}, skipping")
            continue

        # _LOGGER.info(f"[DEBUG trace_data_flow] Got {len(call_infos)} call_infos from {caller_name}")

        for info in call_infos:
            this_call_ea = info["call_ea"]
            src = info.get("source")
            edges = info.get("edges", [])
            info_cond = info.get("cond_tag", "certain")

            # ============ DEBUG: processing one call_info ============
            # _LOGGER.info(f"[DEBUG trace_data_flow] Processing call_info at 0x{this_call_ea:x}")
            # _LOGGER.info(f"  has_source={src is not None}, edges_count={len(edges)}")
            # ==========================================

            # Source hit: explicitly include the caller node; insert the host node too for GetValue -> SetValue
            if src:
                caller_node = (
                    caller_name,
                    src.get("abs_idx", arg_index),
                    this_call_ea,
                    addr,
                    info_cond,  # Caller label
                )
                prefix_nodes = [caller_node]

                if "jump_to_func" in src:
                    host_node = (
                        src["jump_to_func"],
                        src.get("abs_idx", arg_index),
                        src.get("jump_call_ea"),
                        src.get("jump_func_ea", "propagator"),
                        src.get("jump_cond_tag", "certain"),  # Host label
                    )
                    prefix_nodes.append(host_node)

                path_to_func = path + prefix_nodes + [
                    (src["func"], src["taint"], src["ea"], "source", "source")
                ]
                results.append(path_to_func)
                if trace_path_counter is not None:
                    trace_path_counter[0] += 1

            # No source hit: keep propagating along the edges
            # _LOGGER.info(f"[DEBUG trace_data_flow] Processing {len(edges)} edges from call at 0x{this_call_ea:x}")
            for edge_idx, edge in enumerate(edges):
                next_idx = edge["next_idx"]
                abs_idx = edge["abs_idx"]
                caller_tag = edge.get("cond_tag", info_cond)
                # _LOGGER.info(f"[DEBUG trace_data_flow] Edge {edge_idx}: next_idx={next_idx}, abs_idx={abs_idx}")


                # Propagator jump edge: insert caller first, then let the next layer add the host automatically
                if "jump_to_func" in edge:
                    # _LOGGER.info(f"[DEBUG trace_data_flow] Recursing via JUMP to {edge['jump_to_func']}")
                    caller_node = (caller_name, abs_idx, this_call_ea, addr, caller_tag)
                    prefix = path + [caller_node]
                    sub_paths = trace_data_flow(
                        start_func=edge["jump_to_func"],
                        arg_index=next_idx,
                        cwe_sources=cwe_sources,
                        call_ea=edge.get("jump_call_ea"),
                        func_ea=edge.get("jump_func_ea", "propagator"),
                        path=prefix,  # The prefix already contains the caller
                        visited=visited,
                        cache_get=cache_get,
                        cache_set=cache_set,
                        trace_path_counter=trace_path_counter,
                        format_funcs=format_funcs,
                        display_index=abs_idx,
                        vuln_type=vuln_type,
                        len_idx=len_idx,
                        propagators=propagators,
                        max_depth=max_depth,
                        max_paths=max_paths,
                    )
                    # Let the first node in the next layer represent the host (with label)
                    # The next layer treats its root as a sink node, and we want the host node to stay visible,
                    # so do not insert it again here; keep the same strategy as the source branch above.
                    # _LOGGER.info(f"[DEBUG trace_data_flow] Returned {len(sub_paths)} sub_paths from JUMP to {edge['jump_to_func']}")
                    # ============ Priority 3: check the path count before extending ============
                    if trace_path_counter is not None and trace_path_counter[0] + len(sub_paths) > max_paths:
                        remaining = max_paths - trace_path_counter[0]
                        if remaining > 0:
                            _LOGGER.warning(f"[LIMIT] Path count is near the limit; only append the remaining {remaining} paths")
                            results.extend(sub_paths[:remaining])
                        _LOGGER.warning(f"[LIMIT] Reached the path limit {max_paths}; stop appending more paths")
                        return results
                    # ==========================================
                    results.extend(sub_paths)
                else:
                    # Regular case: recurse into the caller
                    # _LOGGER.info(f"[DEBUG trace_data_flow] Recursing NORMALLY to caller {caller_name}")
                    caller_node = (caller_name, abs_idx, this_call_ea, addr, caller_tag)
                    sub_paths = trace_data_flow(
                        start_func=caller_name,
                        arg_index=next_idx,
                        cwe_sources=cwe_sources,
                        call_ea=this_call_ea,
                        func_ea=addr,
                        path=path,  # Do not insert the caller early; the next layer will add it with the label
                        visited=visited,
                        cache_get=cache_get,
                        cache_set=cache_set,
                        trace_path_counter=trace_path_counter,
                        format_funcs=format_funcs,
                        display_index=abs_idx,
                        vuln_type=vuln_type,
                        len_idx=len_idx,
                        propagators=propagators,
                        max_depth=max_depth,
                        max_paths=max_paths,
                        root_label=caller_tag,     # Force the next-layer root label to be "needs_check" or "certain"
                    )
                    # _LOGGER.info(f"[DEBUG trace_data_flow] Returned {len(sub_paths)} sub_paths from NORMAL recursion to {caller_name}")
                    # ============ Priority 3: check the path count before extending ============
                    if trace_path_counter is not None and trace_path_counter[0] + len(sub_paths) > max_paths:
                        remaining = max_paths - trace_path_counter[0]
                        if remaining > 0:
                            _LOGGER.warning(f"[LIMIT] Path count is near the limit; only append the remaining {remaining} paths")
                            results.extend(sub_paths[:remaining])
                        _LOGGER.warning(f"[LIMIT] Reached the path limit {max_paths}; stop appending more paths")
                        return results
                    # ==========================================
                    results.extend(sub_paths)

            # Leaf: no edges and no source hit
            if not src and not edges:
                # _LOGGER.info(f"[DEBUG trace_data_flow] No source and no edges at 0x{this_call_ea:x}, path ends here (filtered or leaf)")
                results.append(path)
                if trace_path_counter is not None:
                    trace_path_counter[0] += 1

    if cache_set is not None:
        cache_set(cache_key, results)

    # ============ DEBUG: trace_data_flow return ============
    # _LOGGER.info(f"[DEBUG trace_data_flow] ===== EXIT =====")
    # _LOGGER.info(f"  start_func={start_func}, returning {len(results)} paths")
    # ==========================================

    return results
