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
# 小工具
# ----------------------------------------------------------------------
def _expr_parent_insn_ea(cfunc, e) -> int:
    """找到表达式最近的父 cinsn 的 EA；失败返回 BADADDR。"""
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
    """检查 CWE-120 sink 是否符合 strlen 安全模式。

    模式 1: strlen + malloc
        v2 = strlen(v1);
        v3 = malloc(v2 + 1);
        strcpy(v3, v1);

    模式 2: strlen + len 参数
        v3 = strlen(hostname);
        strncpy(cfg->hostname, hostname, v3);

    Returns:
        True 如果符合安全模式（应该过滤），False 否则
    """
    import logging
    _LOGGER = logging.getLogger(__name__)

    # 只检查 CWE-120 相关函数
    CWE120_SINKS = {
        "strcpy", "strcat", "strncpy", "strncat", "memcpy", "memmove",
        "wcscpy", "wcscat", "wmemcpy", "wmemmove", "stpcpy", "sprintf",
        "snprintf", "vsnprintf", "bcopy", "memccpy", "strlcpy", "strlcat",
        "sscsnf"
    }

    if sink_func not in CWE120_SINKS:
        return False

    # 获取变量名和函数名
    func_name = ida_funcs.get_func_name(cfunc.entry_ea) or "unknown"
    try:
        lvar = cfunc.lvars[var_idx]
        var_name = lvar.name
    except Exception:
        return False

    # 向上查找 strlen 调用
    class StrlenFinder(idaapi.ctree_visitor_t):
        def __init__(self, target_var_idx: int, limit_ea: int):
            super().__init__(idaapi.CV_FAST)
            self.target_idx = target_var_idx
            self.limit_ea = limit_ea
            self.strlen_found = False
            self.strlen_result_var = None

        def visit_expr(self, e):
            ea = getattr(e, "ea", idaapi.BADADDR) or _expr_parent_insn_ea(cfunc, e)
            # 只检查从函数头到 sink 调用点（包含）之间的语句
            if ea == idaapi.BADADDR or ea > self.limit_ea:
                return 0

            # 查找: result_var = strlen(target_var)
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
                                # 找到 strlen(target_var)
                                if lhs and lhs.op == idaapi.cot_var:
                                    self.strlen_found = True
                                    self.strlen_result_var = lhs.v.idx
                                    return 1  # 停止搜索
            return 0

    finder = StrlenFinder(var_idx, call_ea)
    try:
        finder.apply_to(cfunc.body, None)
    except Exception:
        return False

    if not finder.strlen_found or finder.strlen_result_var is None:
        return False

    strlen_var_idx = finder.strlen_result_var

    # 模式 2: 检查 strlen 结果是否用作 len 参数
    if len_idx is not None:
        # 查找调用点，检查 len_idx 参数是否是 strlen_var
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

    # 模式 1: 检查 strlen 结果是否用于 malloc
    class MallocChecker(idaapi.ctree_visitor_t):
        def __init__(self, strlen_idx: int, limit_ea: int):
            super().__init__(idaapi.CV_FAST)
            self.strlen_idx = strlen_idx
            self.limit_ea = limit_ea
            self.malloc_vars = set()

        def visit_expr(self, e):
            # 检查 malloc/calloc/realloc 调用
            if e.op == idaapi.cot_call:
                callee = e.x
                if callee.op == idaapi.cot_obj:
                    func_name = idaapi.get_func_name(callee.obj_ea) or ""
                    if func_name in ("malloc", "calloc", "realloc"):
                        # 检查 malloc 的第一个参数（size 参数）是否包含 strlen 变量
                        if e.a.size() > 0:
                            size_arg = e.a[0]
                            if self._contains_var(size_arg, self.strlen_idx):
                                # 这是一个有效的 malloc，查找谁接收了它的返回值
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
            """递归检查表达式中是否包含指定变量"""
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

    # 检查 sink 的目标参数（通常是第 0 个）是否来自 malloc
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
    """安全反编译：根据函数起始 EA 反编译，失败返回 None。"""
    try:
        return ida_hexrays.decompile(func_ea)
    except Exception:
        return None


def _find_call_expr_by_ea(cfunc, target_name: str, target_ea: int):
    """在 cfunc 中按 EA 精确找到指定函数名的调用表达式。返回 (cexpr_t, ea) 或 None。"""
    visitor = CallVisitor(cfunc, target_name)
    visitor.apply_to(cfunc.body, None)
    for ce, ea in visitor.calls:
        if ea == target_ea:
            return ce, ea
    return None


def _cexpr_to_text(cfunc, e) -> str:
    """将任意 cexpr 打印为单行文本（用于上下文描述）。"""
    try:
        qp = ida_hexrays.qstring_printer_t(cfunc, False)
        e._print(0, qp)
        s = qp.s.strip()
        if "\n" in s:
            s = s.split("\n", 1)[0]
        return s
    except Exception:
        return ""


# === 条件检测（结构化扫描版）：调用是否位于 if/else/loop/switch 的条件或分支中 ===
def _node_contains_call(node, target_ea: int, target_text: str, cfunc) -> bool:
    """判断某子树 node 是否包含目标调用（优先按 EA，失败则按单行文本匹配）"""
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
                # 有些版本/场景 EA 可能为 BADADDR，退化用文本比较（同一语句会命中）
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
    """全函数扫描结构化语句：若目标调用出现在 if/else/loop/switch 的条件或分支体中则返回 True。"""
    tgt_ea = getattr(call_expr, "ea", idaapi.BADADDR)
    # 取目标调用的单行文本作兜底匹配
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

            return 0  # 继续扫描

    scanner = _CondScanner(tgt_ea, tgt_txt)
    try:
        scanner.apply_to(cfunc.body, None)
    except Exception:
        return False
    return scanner.hit

def _cond_tag(cfunc, call_expr) -> str:
    """返回 '需要检查' / '确定'。"""
    return "需要检查" if _is_callsite_in_condition(cfunc, call_expr) else "确定"


# ----------------------------------------------------------------------
# 基础遍历与收集
# ----------------------------------------------------------------------
def find_var_assignments(
    cfunc,
    lvar_idx: int,
    cwe_sources: Dict[Union[int, str], Set[str]],
    limit_ea: Optional[int] = None,
    propagators: Optional[dict] = None,
) -> List[dict]:
    """回溯某局部变量的赋值/作为参数传递的使用点。"""
    results: List[dict] = []

    class _AssignVisitor(idaapi.ctree_visitor_t):  # type: ignore[misc]
        def __init__(self, target_idx: int) -> None:
            super().__init__(idaapi.CV_FAST)
            self.target_idx = target_idx

        def visit_expr(self, e) -> int:  # type: ignore[override]
            # 1) 赋值/复合赋值/初始化
            if e.op in ASSIGN_OPS:
                lhs = getattr(e, "x", None)
                rhs = getattr(e, "y", None)
                if lhs is not None and lhs.op == idaapi.cot_var and lhs.v.idx == self.target_idx:
                    ea = getattr(e, "ea", idaapi.BADADDR) or _expr_parent_insn_ea(cfunc, e)
                    if ea == idaapi.BADADDR or (limit_ea is not None and not (ea < limit_ea)):
                        return 0

                    # 赋值右值若为 propagator 调用（如 snprintf/GetValue/cJSON_*）
                    if propagators and rhs is not None and rhs.op == idaapi.cot_call:
                        try:
                            prop_results = handle_propagator_assignments(cfunc, rhs, ea, propagators)
                        except Exception:
                            prop_results = []
                        if prop_results:
                            results.extend(prop_results)
                            return 0

                    results.append({"type": "assign", "ea": ea, "expr": rhs})

            # 2) 调用处：变量作参数传递到我们关注的位置
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

    _AssignVisitor(lvar_idx).apply_to(cfunc.body, None)
    results.sort(key=lambda x: x["ea"], reverse=True)
    return results


def extract_vars_from_expr(expr) -> List[int]:
    """返回表达式树中出现的局部变量 idx 列表。"""
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
    """兼容不同绑定：安全遍历 cfunc.lvars。"""
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
    """构建 局部变量 idx -> 形参序号 ordinal 的映射。"""
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
# 核心回溯
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
    """回溯局部变量的来源。返回 (sources, func_name, ea, taint_source)。"""
    if var_sources is None:
        var_sources = set()
    if path_stack is None:
        path_stack = set()

    if var_idx in path_stack:
        return var_sources, None, None, None

    path_stack.add(var_idx)
    assigns = find_var_assignments(
        cfunc, var_idx, cwe_sources, limit_ea=call_ea, propagators=propagators
    )
    if not assigns:
        if arg_ord_map and var_idx in arg_ord_map:
            var_sources.add(arg_ord_map[var_idx])
        return var_sources, None, None, None

    for item in assigns:
        if item["type"] == "assign":
            ea = item["ea"]
            rhs = item["expr"]

            # 右值为调用返回：ret 源
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

            # 否则递归 RHS 子树中的变量
            for sub_idx in extract_vars_from_expr(rhs) if rhs is not None else []:
                sources, func_name, fea, taint_source = trace_var_sources(
                    cfunc,
                    sub_idx,
                    cwe_sources,
                    call_ea=ea,
                    arg_size=arg_size,
                    depth=depth + 1,
                    var_sources=var_sources,
                    path_stack=set(path_stack),
                    arg_ord_map=arg_ord_map,
                    propagators=propagators,
                )
                if func_name:
                    return sources, func_name, fea, taint_source

        elif item["type"] == "arg":
            ea = item["ea"]
            taint_source = item["arg_index"]
            func_name = idaapi.get_func_name(item["expr"].x.obj_ea)
            return var_sources, func_name, ea, taint_source

        elif item["type"] == "propagator":
            # 赋值型 propagator：把其“输入 expr”中的变量继续回溯
            ea = item["ea"]
            expr = item["expr"]
            for sub_idx in extract_vars_from_expr(expr):
                sources, src_func, src_ea, taint_source = trace_var_sources(
                    cfunc,
                    sub_idx,
                    cwe_sources,
                    call_ea=ea,
                    arg_size=arg_size,
                    depth=depth + 1,
                    var_sources=var_sources,
                    path_stack=set(path_stack),
                    arg_ord_map=arg_ord_map,
                    propagators=propagators,
                )
                if src_func:
                    return sources, src_func, src_ea, taint_source

    return var_sources, None, None, None


# ----------------------------------------------------------------------
# 向上 1 层：从 callee 的某形参回溯到它的 caller
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
    """在 caller 中枚举所有对 callee 的调用点，针对 arg_index 做回溯准备。"""
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

    # 变参/格式化
    is_variadic = False
    fmt_idx = None
    va_start_idx = None
    if format_funcs and callee_func_name in format_funcs:
        conf = format_funcs.get(callee_func_name, {})
        fmt_idx = conf.get("fmt")
        va_start_idx = conf.get("va_start")
        is_variadic = isinstance(fmt_idx, int) and isinstance(va_start_idx, int)

    results: List[Dict[str, Any]] = []

    # 传播器配置（例如 {"GetValue": {"input":0, "output":1}})
    prop_conf = (propagators or {}).get(callee_func_name)

    import logging
    _LOGGER = logging.getLogger(__name__)

    # ============ DEBUG: 函数入口信息 ============
    _LOGGER.info(f"[DEBUG analyze_arg_xrefs] Analyzing {callee_func_name} in {func_name}")
    _LOGGER.info(f"  arg_index={arg_index}, vuln_type={vuln_type}, len_idx={len_idx}")
    _LOGGER.info(f"  is_variadic={is_variadic}, fmt_idx={fmt_idx}, va_start_idx={va_start_idx}")
    _LOGGER.info(f"  Found {len(visitor.calls)} call sites")
    # ==========================================

    for call_expr, _ in visitor.calls:
        call_ea = call_expr.ea
        tag_here = _cond_tag(cfunc, call_expr)  # ★ 本调用点的条件标签

        base_ctx = {
            "callee": callee_func_name,
            "caller": func_name,
            "call_ea": call_ea,
            "call_line": _cexpr_to_text(cfunc, call_expr),
            "cond_tag": tag_here,
        }

        # ============ DEBUG: 调用点信息 ============
        _LOGGER.info(f"[DEBUG call_site] Processing call at 0x{call_ea:x}")
        _LOGGER.info(f"  call_line: {_cexpr_to_text(cfunc, call_expr)}")
        _LOGGER.info(f"  arg count: {call_expr.a.size()}")
        # ==========================================

        _LOGGER.debug(f"[analyze_arg_xrefs] Processing {callee_func_name} in {func_name} at 0x{call_ea:x}, vuln_type={vuln_type}")

        # 计算本 callsite 需要检查的"实参绝对下标"
        indices_to_check: List[int] = []

        # ============ DEBUG: 条件判断 ============
        _LOGGER.info(f"[DEBUG branch] Checking condition: is_variadic and arg_index == fmt_idx")
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
            # ============ DEBUG: 进入 else 分支 ============
            _LOGGER.info(f"[DEBUG branch] Entered ELSE branch (not is_variadic or arg_index != fmt_idx)")
            # ==========================================

            # For non-variadic functions, check if there's a length parameter that's a constant
            if len_idx is not None and len_idx < call_expr.a.size() and vuln_type == "CWE-120":
                len_expr = call_expr.a[len_idx]
                if len_expr.op == idaapi.cot_num or (
                    len_expr.op == idaapi.cot_cast and len_expr.x.op == idaapi.cot_num
                ):
                    # Length is a constant, skip this call for CWE-120
                    _LOGGER.info(f"[DEBUG filter] Filtered: len_idx is constant")
                    results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                    continue

            # Special handling for scanf family functions that are configured as format functions
            # but we're checking a different parameter (e.g., checking arg 0 while fmt is at arg 1)
            # ============ DEBUG: scanf 特殊处理条件 ============
            _LOGGER.info(f"[DEBUG scanf_filter] Checking scanf filter condition:")
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
                # ============ DEBUG: 进入 scanf 过滤分支 ============
                _LOGGER.info(f"[DEBUG scanf_filter] Entered scanf filter branch")
                _LOGGER.info(f"  Trying to parse format string at arg index {fmt_idx}")
                # ==========================================

                s = try_get_cstr_from_cexpr(call_expr.a[fmt_idx])

                # ============ DEBUG: 格式字符串解析结果 ============
                _LOGGER.info(f"[DEBUG scanf_filter] Format string parse result: {repr(s)}")
                # ==========================================

                if s:
                    # For scanf family functions like __isoc99_sscanf, only %s can cause buffer overflow
                    used_positions = parse_printf_positions_filtered(
                        s, {"s"}, include_width_star_for_s=True  # Only check %s for buffer overflow
                    )

                    # ============ DEBUG: %s 位置检查 ============
                    _LOGGER.info(f"[DEBUG scanf_filter] Format string: {s}")
                    _LOGGER.info(f"[DEBUG scanf_filter] Used positions with %s: {used_positions}")
                    # ==========================================

                    if not used_positions:
                        # No %s format specifiers found, skip this call for CWE-120
                        _LOGGER.info(f"[DEBUG filter] Filtered: No %s in format string '{s}'")
                        results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                        continue
                else:
                    # ============ DEBUG: 格式字符串解析失败 ============
                    _LOGGER.warning(f"[DEBUG scanf_filter] Format string parse FAILED - filter skipped!")
                    _LOGGER.warning(f"  This may cause false positive!")
                    # ==========================================

            if arg_index < call_expr.a.size():
                indices_to_check = [arg_index]
            else:
                results.append({"call_ea": call_ea, "edges": [], "source": None, "context": base_ctx})
                continue



        # ---------- GetValue(key, dst) → 跳到 SetValue(key, val) 并对 val 回溯 ----------
        if handle_propagator_assignments and prop_conf and isinstance(prop_conf, dict) and callee_func_name not in {"snprintf", "vsnprintf"}:
            prop_input = prop_conf.get("input")
            if isinstance(prop_input, int) and arg_index == int(prop_input):
                base_ctx.update({
                    "getvalue_key": None,
                    "getvalue_call_line": _cexpr_to_text(cfunc, call_expr),
                    "setvalue_sites": [],
                })
                # 记录 key 字符串
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
                    set_arg_idx = int(ph.get("input_idx", 1))  # SetValue 的 value 形参默认 1

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

                    host_tag = _cond_tag(host_cfunc, set_call_expr)  # ★ host 调用点标签

                    # 收集 SetValue 现场上下文
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

                    # 在 SetValue 所在函数中，回溯其 val 实参
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
                            # 在 source payload 里放入“跳转节点”信息与标签
                            source_payload2 = {
                                "func": fname2,
                                "ea": fea2,
                                "taint": tsrc2,
                                "abs_idx": set_arg_idx,
                                "jump_to_func": host_name,
                                "jump_func_ea": host_func.start_ea,
                                "jump_call_ea": set_ea,
                                "jump_cond_tag": host_tag,
                                "cond_tag": tag_here,  # caller 的标签
                            }

                    # 以“跳转边”的形式交给上层（边里也带上两个标签）
                    jump_edges = []
                    for nx in local_next2:
                        jump_edges.append({
                            "next_idx": nx,
                            "abs_idx": set_arg_idx,
                            "jump_to_func": host_name,
                            "jump_func_ea": host_func.start_ea,
                            "jump_call_ea": set_ea,
                            "cond_tag": tag_here,         # caller 的标签
                            "jump_cond_tag": host_tag,    # host 的标签
                        })

                    results.append({
                        "call_ea": call_ea,
                        "edges": jump_edges,
                        "source": source_payload2,
                        "context": dict(base_ctx),
                        "cond_tag": tag_here,
                    })

                # 命中 propagator 后，这个 callsite 已处理完毕
                continue
        # -------------------------------------------------------------------

        # 常规路径：对 indices_to_check 中的表达式回溯
        edges: List[Dict[str, int]] = []
        source_payload: Optional[Dict[str, Any]] = None

        # CWE-120: 在开始回溯前，检查当前函数是否有安全模式
        if vuln_type == "CWE-120" and indices_to_check:
            # 检查第一个需要检查的参数
            first_idx = indices_to_check[0]
            if first_idx < call_expr.a.size():
                arg_expr = call_expr.a[first_idx]
                _lvars_pre, _gvars_pre, lvar_exprs_pre = collect_vars_from_expr(cfunc, arg_expr)

                # 检查任意一个变量是否符合安全模式
                has_safe_pattern = False
                for lvar_idx_pre in lvar_exprs_pre:
                    if _check_strlen_safe_pattern(cfunc, lvar_idx_pre, call_ea, callee_func_name, len_idx):
                        has_safe_pattern = True
                        break

                if has_safe_pattern:
                    # 跳过这个调用点，不生成任何路径
                    continue

        for abs_idx in indices_to_check:
            arg_expr = call_expr.a[abs_idx]
            _lvars, _gvars, lvar_exprs = collect_vars_from_expr(cfunc, arg_expr)

            local_next: Set[int] = set()
            for lvar_idx in lvar_exprs:
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
                        "cond_tag": tag_here,  # caller 标签
                    }

            for nx in local_next:
                edges.append({"next_idx": nx, "abs_idx": abs_idx, "cond_tag": tag_here})

        results.append({
            "call_ea": call_ea, "edges": edges, "source": source_payload, "context": base_ctx, "cond_tag": tag_here
        })

    # ============ DEBUG: analyze_arg_xrefs 返回结果 ============
    _LOGGER.info(f"[DEBUG analyze_arg_xrefs] Returning {len(results)} results for {callee_func_name} in {func_name}")
    for i, r in enumerate(results):
        edges_count = len(r.get("edges", []))
        has_source = r.get("source") is not None
        _LOGGER.info(f"  Result {i}: call_ea=0x{r['call_ea']:x}, edges={edges_count}, has_source={has_source}")
    # ==========================================

    return results if results else None


def analyze_func_xrefs(func_name: str) -> Set[int]:
    """返回引用 `func_name` 的唯一 caller 函数起始 EA 集合。"""
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
# 多层回溯：构建完整路径
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
    max_depth: int = 15,
    root_label: Optional[str] = None,
):
    """从 (start_func, arg_index) 开始向上传播，返回若干条路径（每条路径是**节点元组列表**）。
       节点元组形如：(func, arg_index, call_ea, func_ea, label)。
       label ∈ {"需要检查","确定","sink","source"}。
    """
    import logging
    _LOGGER = logging.getLogger(__name__)

    if path is None:
        path = []
    if visited is None:
        visited = set()

    # ============ DEBUG: trace_data_flow 入口 ============
    depth = len(path)
    call_ea_str = f"0x{call_ea:x}" if call_ea else "None"
    _LOGGER.info(f"[DEBUG trace_data_flow] ===== ENTER =====")
    _LOGGER.info(f"  start_func={start_func}, arg_index={arg_index}")
    _LOGGER.info(f"  call_ea={call_ea_str}, func_ea={func_ea}")
    _LOGGER.info(f"  depth={depth}, vuln_type={vuln_type}")
    # ==========================================

    if len(path) > max_depth:
        _LOGGER.info(f"[DEBUG trace_data_flow] Max depth exceeded ({len(path)} > {max_depth}), returning empty")
        return []

    # 当前节点（root 为 sink）
    label_here = root_label if root_label is not None else ("sink" if func_ea == "sink" else "确定")
    node = (
        start_func,
        display_index if display_index is not None else arg_index,
        call_ea,
        func_ea,
        label_here,
    )
    if node in visited:
        _LOGGER.info(f"[DEBUG trace_data_flow] Node already visited: {start_func}, returning empty")
        return []

    # 缓存键包含 call_ea，避免不同调用点串扰
    cache_key = (start_func, arg_index, call_ea, vuln_type)
    if cache_get is not None:
        cached = cache_get(cache_key)
        if cached is not None:
            _LOGGER.info(f"[DEBUG trace_data_flow] Cache hit for {start_func}, returning {len(cached)} cached results")
            return cached

    visited.add(node)
    path = path + [node]
    results: List[List[tuple]] = []

    caller_addrs = analyze_func_xrefs(start_func)
    _LOGGER.info(f"[DEBUG trace_data_flow] Found {len(caller_addrs)} callers for {start_func}")

    if not caller_addrs:
        _LOGGER.info(f"[DEBUG trace_data_flow] No callers found for {start_func}, path ends here (leaf node)")
        results.append(path)
        if trace_path_counter is not None:
            trace_path_counter[0] += 1
        if cache_set is not None:
            cache_set(cache_key, results)
        return results

    for addr in caller_addrs:
        caller_name = idc.get_func_name(addr)
        _LOGGER.info(f"[DEBUG trace_data_flow] Processing caller: {caller_name} at 0x{addr:x}")

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
            _LOGGER.info(f"[DEBUG trace_data_flow] No call_infos returned from {caller_name}, skipping")
            continue

        _LOGGER.info(f"[DEBUG trace_data_flow] Got {len(call_infos)} call_infos from {caller_name}")

        for info in call_infos:
            this_call_ea = info["call_ea"]
            src = info.get("source")
            edges = info.get("edges", [])
            info_cond = info.get("cond_tag", "确定")

            # ============ DEBUG: 处理单个 call_info ============
            _LOGGER.info(f"[DEBUG trace_data_flow] Processing call_info at 0x{this_call_ea:x}")
            _LOGGER.info(f"  has_source={src is not None}, edges_count={len(edges)}")
            # ==========================================

            # 命中源：路径需要显式包含 caller 节点；若来自 GetValue→SetValue，还需插入 host 节点
            if src:
                caller_node = (
                    caller_name,
                    src.get("abs_idx", arg_index),
                    this_call_ea,
                    addr,
                    info_cond,  # caller 标签
                )
                prefix_nodes = [caller_node]

                if "jump_to_func" in src:
                    host_node = (
                        src["jump_to_func"],
                        src.get("abs_idx", arg_index),
                        src.get("jump_call_ea"),
                        src.get("jump_func_ea", "propagator"),
                        src.get("jump_cond_tag", "确定"),  # host 标签
                    )
                    prefix_nodes.append(host_node)

                path_to_func = path + prefix_nodes + [
                    (src["func"], src["taint"], src["ea"], "source", "source")
                ]
                results.append(path_to_func)
                if trace_path_counter is not None:
                    trace_path_counter[0] += 1

            # 未命中源：沿"边"继续传播
            for edge in edges:
                next_idx = edge["next_idx"]
                abs_idx = edge["abs_idx"]
                caller_tag = edge.get("cond_tag", info_cond)


                # propagator 跳转边：路径里先插入 caller，再让下一层自动添加 host
                if "jump_to_func" in edge:
                    caller_node = (caller_name, abs_idx, this_call_ea, addr, caller_tag)
                    prefix = path + [caller_node]
                    sub_paths = trace_data_flow(
                        start_func=edge["jump_to_func"],
                        arg_index=next_idx,
                        cwe_sources=cwe_sources,
                        call_ea=edge.get("jump_call_ea"),
                        func_ea=edge.get("jump_func_ea", "propagator"),
                        path=prefix,  # 前缀已包含 caller
                        visited=visited.copy(),
                        cache_get=cache_get,
                        cache_set=cache_set,
                        trace_path_counter=trace_path_counter,
                        format_funcs=format_funcs,
                        display_index=abs_idx,
                        vuln_type=vuln_type,
                        len_idx=len_idx,
                        propagators=propagators,
                        max_depth=max_depth,
                    )
                    # 在下一层的第一个节点补上 host（含标签）
                    # 由于下一层的 root 会被当成“sink”加入，我们希望 host 节点可视化出现，
                    # 故这里不额外插入，维持与上面 src 分支一致的策略。
                    results.extend(sub_paths)
                else:
                    # 常规：递归到 caller
                    caller_node = (caller_name, abs_idx, this_call_ea, addr, caller_tag)
                    sub_paths = trace_data_flow(
                        start_func=caller_name,
                        arg_index=next_idx,
                        cwe_sources=cwe_sources,
                        call_ea=this_call_ea,
                        func_ea=addr,
                        path=path,  # 不提前插 caller，下一层会自动添加（并携带标签）
                        visited=visited.copy(),
                        cache_get=cache_get,
                        cache_set=cache_set,
                        trace_path_counter=trace_path_counter,
                        format_funcs=format_funcs,
                        display_index=abs_idx,
                        vuln_type=vuln_type,
                        len_idx=len_idx,
                        propagators=propagators,
                        max_depth=max_depth,
                        root_label=caller_tag,     # ★ 把“需要检查/确定”强制给下一层根
                    )
                    results.extend(sub_paths)

            # 没有边也没命中源：落叶
            if not src and not edges:
                _LOGGER.info(f"[DEBUG trace_data_flow] No source and no edges at 0x{this_call_ea:x}, path ends here (filtered or leaf)")
                results.append(path)
                if trace_path_counter is not None:
                    trace_path_counter[0] += 1

    if cache_set is not None:
        cache_set(cache_key, results)

    # ============ DEBUG: trace_data_flow 返回 ============
    _LOGGER.info(f"[DEBUG trace_data_flow] ===== EXIT =====")
    _LOGGER.info(f"  start_func={start_func}, returning {len(results)} paths")
    # ==========================================

    return results
