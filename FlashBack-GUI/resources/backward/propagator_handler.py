# -*- coding: utf-8 -*-
"""Utilities for handling propagators in backward taint analysis.

This module processes propagator functions defined in config.json, handling specific propagation rules
for functions like snprintf, GetValue, and cJSON_*.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Union, Any
import logging
try:
    import idaapi  # type: ignore
    import ida_hexrays  # type: ignore
    import idc  # type: ignore
    import idautils  # type: ignore
    import ida_funcs  # type: ignore
except Exception:  # pragma: no cover - only available inside IDA
    idaapi = ida_hexrays = idc = idautils = ida_funcs = None  # type: ignore

from backward.format_utils import try_get_cstr_from_cexpr, parse_printf_positions_filtered
from backward.visitors import CallVisitor

_LOGGER = logging.getLogger(__name__)

def handle_propagator_assignments(
    cfunc,
    rhs: Any,
    ea: int,
    propagators: Dict[str, dict]
) -> List[dict]:
    results: List[dict] = []
    if not propagators or rhs.op != idaapi.cot_call:
        return results

    callee = rhs.x
    if callee.op != idaapi.cot_obj:
        return results

    func_name = idaapi.get_func_name(callee.obj_ea) or ""
    if func_name not in propagators:
        return results

    prop = propagators[func_name]
    input_idx = prop.get("input")
    output_idx = prop.get("output")
    if input_idx is None or output_idx is None:
        _LOGGER.warning("Invalid propagator config for %s: input=%s, output=%s", func_name, input_idx, output_idx)
        return results

    _LOGGER.debug("Processing propagator %s at ea 0x%x, input_idx=%d", func_name, ea, input_idx)

    # 处理 snprintf/vsnprintf
    if func_name in ("snprintf", "vsnprintf") and input_idx < rhs.a.size():
        fmt_expr = rhs.a[input_idx]
        fmt_str = try_get_cstr_from_cexpr(fmt_expr)
        if fmt_str:
            used_positions = parse_printf_positions_filtered(fmt_str, {"s", "n"}, include_width_star_for_s=True)
            for pos in used_positions:
                vararg_idx = input_idx + pos
                if vararg_idx < rhs.a.size():
                    results.append({
                        "type": "propagator",
                        "ea": ea,
                        "expr": rhs.a[vararg_idx],
                        "func_name": func_name,
                        "input_idx": vararg_idx
                    })
        return results

    # 处理 GetValue（支持 propagator 和 sink 场景）
    elif func_name == "GetValue" and input_idx < rhs.a.size():
        input_expr = rhs.a[input_idx]
        string_ea = input_expr.obj_ea if input_expr.op == idaapi.cot_obj else idaapi.BADADDR
        if string_ea == idaapi.BADADDR:
            _LOGGER.debug("No valid string EA for GetValue input at ea 0x%x", ea)
            return results

        input_str = try_get_cstr_from_cexpr(input_expr)
        if not input_str:
            _LOGGER.debug("Failed to extract string from GetValue input at ea 0x%x", ea)
            return results

        setvalue_func_ea = idc.get_name_ea(idaapi.BADADDR, "SetValue")
        if setvalue_func_ea == idaapi.BADADDR:
            _LOGGER.debug("SetValue function not found")
            return results

        # 使用字符串的 xrefs 查找所有 SetValue 调用
        for xref in idautils.XrefsTo(string_ea, 0):
            caller_func = ida_funcs.get_func(xref.frm)
            if not caller_func:
                continue
            caller_ea = xref.frm  # 字符串引用的精确地址
            # if input_str == "lan.ip":
            #     print(hex(caller_ea),hex(caller_func.start_ea),hex(cfunc.entry_ea),hex(ea))
            # 在当前函数中排除 GetValue 调用点之后的 SetValue
            # if caller_func.start_ea == cfunc.entry_ea and caller_ea >= ea:
            #     _LOGGER.debug("Skipping SetValue at ea 0x%x in current function (after GetValue ea 0x%x)", caller_ea, ea)
            #     continue
            try:
                caller_cfunc = ida_hexrays.decompile(caller_func.start_ea)
                # if input_str == "lan.ip":
                #     print(hex(caller_ea),hex(caller_func.start_ea),hex(cfunc.entry_ea),hex(ea))
                visitor = CallVisitor(caller_cfunc, "SetValue")
                visitor.apply_to(caller_cfunc.body, None)
                for call_expr, call_ea in visitor.calls:
                    
                    if caller_func.start_ea == cfunc.entry_ea and call_ea >= ea:
                        _LOGGER.debug("Skipping SetValue at ea 0x%x in current function (after GetValue ea 0x%x)", caller_ea, ea)
                        continue
                    # if input_str == "iptv.city.vlan":
                    #     print(hex(caller_ea),hex(caller_func.start_ea),hex(cfunc.entry_ea),hex(call_ea),hex(ea))
                    #     output_str = try_get_cstr_from_cexpr(call_expr.a[0])
                    #     print("  SetValue output:",output_str)
                    # if call_ea != caller_ea:  # 确保匹配 xref 的调用点
                    #     continue
                    if call_expr.a and call_expr.a[0].op == idaapi.cot_obj and call_expr.a[0].obj_ea == string_ea:
                        # if input_str =
                        
                        if len(call_expr.a) > 1:
                            results.append({
                                "type": "propagator",
                                "ea": call_ea,
                                "expr": call_expr.a[1],  # 从 SetValue 参数 1 传播
                                "func_name": "SetValue",
                                "input_idx": 1
                            })
                        # 不 break，继续收集所有匹配的 SetValue 调用
            except Exception as e:
                _LOGGER.debug("Failed to decompile function at 0x%x for SetValue xref: %s", caller_func.start_ea, str(e))
                continue
        return results

    # 处理 cJSON_GetObjectItem/cJSON_Parse
    elif func_name in ("cJSON_GetObjectItem", "cJSON_Parse") and input_idx < rhs.a.size():
        results.append({
            "type": "propagator",
            "ea": ea,
            "expr": rhs.a[input_idx],
            "func_name": func_name,
            "input_idx": input_idx
        })
        return results

    return results