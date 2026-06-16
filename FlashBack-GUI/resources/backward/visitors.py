# -*- coding: utf-8 -*-
"""Hex-Rays ctree visitors used by the backward analysis.

All visitors are kept small & focused. Each class includes concise docstrings
and avoids global state, following Google Python Style.
"""
from __future__ import annotations

from typing import List, Optional, Set, Tuple

try:
    import ida_hexrays  # type: ignore
    import idaapi  # type: ignore
    import ida_lines  # type: ignore
    import ida_funcs  # type: ignore
    import idc  # type: ignore
except Exception:  # pragma: no cover - only available inside IDA
    ida_hexrays = idaapi = ida_lines = ida_funcs = idc = None  # type: ignore


class CallVisitor(idaapi.ctree_visitor_t):  # type: ignore[misc]
    """Collect call-sites to a target function within a cfunc body.

    Attributes:
        calls: List of tuples (call_expr, call_ea).
        cfunc: The current decompiled function object.
        target_func_name: Callee name to match.
    """

    def __init__(self, cfunc, target_func_name: str) -> None:
        super().__init__(idaapi.CV_FAST)
        self.calls: List[Tuple[object, int]] = []
        self.cfunc = cfunc
        self.target_func_name = target_func_name

    def visit_expr(self, expr) -> int:  # type: ignore[override]
        import logging
        _LOGGER = logging.getLogger(__name__)

        if expr.op == idaapi.cot_call:
            callee = expr.x
            if callee.op == idaapi.cot_obj:
                func_name = idaapi.get_func_name(callee.obj_ea)
                # ============ DEBUG: 发现调用 ============
                _LOGGER.debug(f"[DEBUG CallVisitor] Found call to {func_name} (looking for {self.target_func_name})")
                # ==========================================
                if func_name == self.target_func_name:
                    _LOGGER.info(f"[DEBUG CallVisitor] MATCHED! Added call to {func_name} at 0x{expr.ea:x}")
                    self.calls.append((expr, expr.ea))
        elif expr.op == idaapi.cot_cast:
            target_expr = expr.x
            if target_expr.op == idaapi.cot_call and target_expr.x.op == idaapi.cot_obj:
                func_name = idaapi.get_func_name(target_expr.x.obj_ea)
                _LOGGER.debug(f"[DEBUG CallVisitor] Found casted call to {func_name} (looking for {self.target_func_name})")
                if func_name == self.target_func_name:
                    _LOGGER.info(f"[DEBUG CallVisitor] MATCHED! Added casted call to {func_name} at 0x{target_expr.ea:x}")
                    self.calls.append((target_expr, target_expr.ea))
            elif target_expr.op in (idaapi.cot_ptr, idaapi.cot_memptr, idaapi.cot_memref):
                sub = target_expr.x
                if sub.op == idaapi.cot_call and sub.x.op == idaapi.cot_obj:
                    func_name = idaapi.get_func_name(sub.x.obj_ea)
                    _LOGGER.debug(f"[DEBUG CallVisitor] Found ptr/memptr call to {func_name} (looking for {self.target_func_name})")
                    if func_name == self.target_func_name:
                        _LOGGER.info(f"[DEBUG CallVisitor] MATCHED! Added ptr/memptr call to {func_name} at 0x{sub.ea:x}")
                        self.calls.append((sub, sub.ea))
        return 0


class LocalVarXrefs:
    """Find & pretty-print xrefs of a given local variable in a cfunc.

    Methods here are primarily used for debugging/inspection purposes.
    """

    def __init__(self, cfunc, lvar_idx: int) -> None:
        self.cfunc = cfunc
        self.lvar_idx = lvar_idx

    def get_xrefs(self) -> List[int]:
        """Return EAs of statements that reference the target local."""

        class _XrefVisitor(idaapi.ctree_visitor_t):  # type: ignore[misc]
            def __init__(self, cfunc, target_idx: int) -> None:
                super().__init__(idaapi.CV_FAST)
                self.target_idx = target_idx
                self.cfunc = cfunc
                self.visited_eas: Set[int] = set()

            def visit_expr(self, e) -> int:  # type: ignore[override]
                if e.op == idaapi.cot_var and e.v.idx == self.target_idx:
                    item = self.cfunc.body.find_parent_of(e)
                    while item:
                        if item.is_insn():
                            ea = item.cinsn.ea
                            if ea != idaapi.BADADDR:
                                self.visited_eas.add(ea)
                            break
                        item = self.cfunc.body.find_parent_of(item.it)
                return 0

        visitor = _XrefVisitor(self.cfunc, self.lvar_idx)
        visitor.apply_to(self.cfunc.body, None)
        return sorted(visitor.visited_eas)

    def get_decompiled_line(self, ea: int) -> str:
        if ea not in self.cfunc.eamap:
            return "<未知语句>"
        lines: List[str] = []
        for stmt in self.cfunc.eamap[ea]:
            qp = ida_hexrays.qstring_printer_t(self.cfunc, False)
            stmt._print(0, qp)
            lines.append(qp.s.split("\n")[0])
        return "\n".join(lines)

    def run(self) -> None:
        xrefs = self.get_xrefs()
        print(f"\n局部变量 ID #{self.lvar_idx} 在函数 {ida_funcs.get_func_name(self.cfunc.entry_ea)} 中的引用：")
        for ea in xrefs:
            line = self.get_decompiled_line(ea)
            print(f"  [0x{ea:X}] {line}")


class VarCollector(idaapi.ctree_visitor_t):  # type: ignore[misc]
    """Collect local & global variable references in an expression tree."""

    def __init__(self, cfunc) -> None:
        super().__init__(idaapi.CV_FAST)
        self.cfunc = cfunc
        self.lvar_ids: Set[int] = set()
        self.gvars: Set[int] = set()
        self.lvars = []

    def visit_expr(self, expr) -> int:  # type: ignore[override]
        if expr.op == idaapi.cot_var:
            self.lvar_ids.add(expr.v.idx)
            self.lvars.append(expr)
        elif expr.op == idaapi.cot_obj:
            ea = expr.obj_ea
            flags = idaapi.get_flags(ea)
            if idaapi.is_data(flags):
                segname = idc.get_segm_name(ea) or ""
                if segname.lower() != "extern":
                    self.gvars.add(ea)
        return 0


def collect_vars_from_expr(cfunc, root_expr):
    """Collect variable info from an expression.

    Returns:
        Tuple[List[str], List[str], Set[int]]: (local var names, global var names,
            local var indices encountered)
    """
    vc = VarCollector(cfunc)
    vc.apply_to(root_expr, None)

    lvar_names = [cfunc.lvars[idx].name for idx in vc.lvar_ids]
    gvar_names = [idaapi.get_name(ea) for ea in vc.gvars]
    lvar_exprs = vc.lvar_ids
    return lvar_names, gvar_names, lvar_exprs