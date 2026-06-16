# -*- coding: utf-8 -*-
"""CLI entry for backward taint tracing (Hex-Rays based).

修复：在 IDA 以 `-S <...>/backward/cli.py` 直接执行时，`__package__` 为空，
相对导入会失败（"attempted relative import with no known parent package"）。
这里在顶层做一次 *自举*：将工程根目录加入 `sys.path`，然后使用**绝对导入**。

用法（示例）：
    ida64.exe -A -S"D:/your-project/backward/cli.py \
               --sinks D:/cfg/sinks.json \
               --sources D:/cfg/sources.json \
               --output D:/out/result.json"
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Dict, List, Optional, Set, Tuple, Union

# --- Bootstrap: ensure `backward` package is importable when run via IDA -S ---
_HERE = os.path.abspath(os.path.dirname(__file__))
_PROJ_ROOT = os.path.dirname(_HERE)  # parent of "backward"
if _PROJ_ROOT not in sys.path:
    sys.path.insert(0, _PROJ_ROOT)

try:
    import idaapi  # type: ignore
    import ida_hexrays  # type: ignore
    import idc  # type: ignore
    import ida_lines  # type: ignore
except Exception:  # 在非 IDA 环境下导入会失败，这里仅为类型提示
    idaapi = ida_hexrays = idc = ida_lines = None  # type: ignore

# 改为**绝对导入**，避免相对导入在脚本模式下失败
from backward.analysis import trace_data_flow
from backward.cache import TinyCache
from backward.io_utils import load_config_from_json, load_sinks_from_json

_LOGGER = logging.getLogger(__name__)


class Analyzer:
    """Coordinator that runs backward traces for all sinks.

    Attributes:
        cwe_sources: Source declaration mapping.
        cache: Result cache across recursion.

    Note: 每个sink函数会创建独立的路径计数器（上限10000条）
    """

    # def __init__(self, cwe_sources: Dict[Union[int, str], Set[str]], format_funcs: dict, propagators: dict, max_cache_size: int, max_paths: int = 10000, max_depth: int = 10) -> None:
    def __init__(self, cwe_sources: Dict[Union[int, str], Set[str]], format_funcs: dict, propagators: dict, max_cache_size: int, max_depth: int = 10) -> None:
        self.cwe_sources = cwe_sources
        self.format_funcs = format_funcs or {}
        self.propagators = propagators or {}  # 新增：支持 propagators
        self.cache = TinyCache(max_size=max_cache_size)
        # 不再使用全局计数器，每个sink函数独立计数
        # self.trace_count = [0]
        # self.max_paths = max_paths  # 新增：最大路径数限制
        self.max_depth = max_depth  # 新增：最大深度限制

    def process_single_sink(self, cwe_name: str, sink_func: str, param_idx: int, len_idx: Optional[int] = None) -> List[dict]:
        # 传递 None 让 trace_data_flow 为每个sink函数创建独立的路径计数器
        results = trace_data_flow(
            start_func=sink_func,
            arg_index=param_idx,
            cwe_sources=self.cwe_sources,
            cache_get=self.cache.get,
            cache_set=self.cache.set,
            trace_path_counter=None,  # 改为 None，每个sink独立计数
            format_funcs=self.format_funcs,
            vuln_type=cwe_name,
            len_idx=len_idx,  # 新增：传递 len_idx
            propagators=self.propagators,  # 新增：传递 propagators
            max_depth=self.max_depth,  # 新增：传递最大深度
            # max_paths=self.max_paths,  # 新增：传递最大路径数
        )

        filtered = [p for p in results if p and p[-1][3] == "source"]  # 更新过滤逻辑，确保路径有效
        if not filtered:
            return []

        paths_info = []
        for path in filtered:
            source_func = None
            for hop in path:
                func_name, _, _, func_ea, *_rest = hop   # ★ 兼容 4/5 元素
                if func_ea == "source":
                    source_func = func_name
            paths_info.append({
                "vuln_type": cwe_name,
                "sink_func": sink_func,
                "source_func": source_func,
                "param_idx": param_idx,  # 新增：记录参数索引
                "len_idx": len_idx,  # 新增：记录 len 参数索引（如果存在）
                "path": [
                    {
                        "func": func_name,
                        "arg_index": arg_idx,
                        "call_ea": hex(ea) if isinstance(ea, int) else str(ea),
                        "func_ea": func_ea if isinstance(func_ea, str) else hex(func_ea),
                        "label": (rest[0] if rest else None)  # ★ 新增：需要检查/确定/sink/source
                    }
                    for (func_name, arg_idx, ea, func_ea, *rest) in path
                ],
            })
        return paths_info
    
    def run_all(self, sinks_data) -> List[dict]:
        sink_param_map: Dict[str, List[Tuple[str, int, Optional[int]]]] = {}
        for sink in sinks_data:
            cwe_name = sink.get("cwe", "")
            sink_func = sink.get("func", "")
            if not cwe_name or not sink_func:  # 验证必填字段
                _LOGGER.warning("Invalid sink entry: missing cwe or func: %s", sink)
                continue
            param_indices = sink.get("params", [])
            len_idx = sink.get("len")  # 获取 len 字段
            if isinstance(len_idx, list):
                len_idx = len_idx[0] if len_idx else None  # 取第一个 len（若存在）
            elif not isinstance(len_idx, (int, type(None))):
                _LOGGER.warning("Invalid len field in sink %s: %s", sink_func, len_idx)
                len_idx = None
            for param_idx in param_indices:
                sink_param_map.setdefault(cwe_name, []).append((sink_func, param_idx, len_idx))

        json_results: List[dict] = []
        for cwe_name, sink_funcs in sink_param_map.items():
            for sink_func, param_idx, len_idx in sink_funcs:
                _LOGGER.debug(
                    "Processing sink %s(param_idx=%d, len_idx=%s) for CWE %s",
                    sink_func, param_idx, len_idx, cwe_name
                )
                res = self.process_single_sink(cwe_name, sink_func, param_idx, len_idx)
                if res:
                    json_results.extend(res)
                    _LOGGER.debug("Found %d paths for sink %s in CWE %s", len(res), sink_func, cwe_name)
        return json_results

    
def _dedup_paths(paths: List[dict]) -> List[dict]:
    seen = set()
    out = []
    for item in paths:
        # 以 path 的关键四元组序列作为去重键
        key = tuple((hop["func"], hop["arg_index"], hop["call_ea"], hop["func_ea"]) for hop in item["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _dedup_paths_by_sink_callsite(paths: List[dict]) -> List[dict]:
    """基于 sink_func 和最后一个 hop 的 call_ea 进行去重。

    对于 sink_func 相同且 path 倒数第一个元素的 call_ea 相同的路径，
    只保留第一条路径。

    Args:
        paths: 待去重的路径列表

    Returns:
        去重后的路径列表
    """
    seen = set()
    out = []
    for item in paths:
        path = item.get("path", [])
        if not path:
            out.append(item)
            continue

        # 获取 path 倒数第一个元素的 call_ea 和 sink_func
        last_hop = path[-1]
        last_call_ea = last_hop.get("call_ea", "")
        sink_func = item.get("sink_func", "")

        # 使用 (sink_func, last_call_ea) 作为去重键
        key = (sink_func, last_call_ea)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _check_reaches_main(func_ea: int, visited: Optional[Set[int]] = None, max_depth: int = 50) -> bool:
    """从指定函数向上追溯调用链，检查是否能到达main函数。

    Args:
        func_ea: 起始函数的地址
        visited: 已访问过的函数集合（避免循环）
        max_depth: 最大递归深度

    Returns:
        True 如果能到达main函数，False 否则
    """
    if visited is None:
        visited = set()

    if max_depth <= 0:
        return False

    if func_ea in visited:
        return False

    visited.add(func_ea)

    # 获取函数名
    try:
        import ida_funcs
        import idautils
        import ida_name

        func_name = ida_funcs.get_func_name(func_ea)

        # 检查是否是main函数
        if func_name and func_name in ("main", "_main", "start", "_start"):
            return True

        # 获取所有调用当前函数的地方
        callers = set()
        for xref in idautils.XrefsTo(func_ea, 0):
            # 接受多种类型的引用：
            # - fl_CN/fl_CF: 直接调用
            # - fl_JN/fl_JF: 跳转
            # - dr_O/dr_R/dr_W: 数据引用（用于间接调用、GOT表、函数指针等）
            if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF,
                            idaapi.dr_O, idaapi.dr_R, idaapi.dr_W):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    callers.add(caller_func.start_ea)

        # 递归检查所有调用者
        for caller_ea in callers:
            if _check_reaches_main(caller_ea, visited, max_depth - 1):
                return True

        return False
    except Exception:
        return False


def _filter_tenda_paths_without_main(paths: List[dict]) -> List[dict]:
    """Tenda固件专用：过滤掉不经过main函数的路径。

    对于每条路径，找到倒数第二个函数（调用source的函数），
    从该函数向上追溯xref，如果无法到达main函数，则过滤掉。

    Args:
        paths: 路径列表

    Returns:
        过滤后的路径列表
    """
    out = []
    filtered_count = 0

    for item in paths:
        path = item.get("path", [])
        if len(path) < 2:
            # 路径太短，保留
            out.append(item)
            continue

        # 找到倒数第二个函数（调用source的函数）
        head_func = path[-2]
        func_ea_str = head_func.get("func_ea", "")

        # 解析函数地址
        try:
            if isinstance(func_ea_str, str):
                if func_ea_str.lower().startswith("0x"):
                    func_ea = int(func_ea_str, 16)
                elif func_ea_str == "source" or func_ea_str == "sink":
                    # 特殊标记，保留
                    out.append(item)
                    continue
                else:
                    func_ea = int(func_ea_str)
            else:
                func_ea = int(func_ea_str)
        except (ValueError, TypeError):
            # 无法解析地址，保留
            out.append(item)
            continue

        # 检查是否能到达main
        if _check_reaches_main(func_ea):
            out.append(item)
        else:
            filtered_count += 1
            func_name = head_func.get("func", "unknown")
            _LOGGER.info(f"[Tenda] Filtered path: head function {func_name} at {func_ea_str} does not reach main")

    if filtered_count > 0:
        print(f"[*] Tenda固件过滤：移除 {filtered_count} 条未经过main函数的路径")

    return out

def _ensure_ida_available() -> None:
    if idaapi is None or ida_hexrays is None or idc is None:
        print("[!] 本脚本需在 IDA Pro 的 Python 环境中运行 (import idaapi 失败)")
        sys.exit(2)


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Backward taint tracing (Hex-Rays)")
    p.add_argument("--config", required=True, help="Config JSON path (contains sinks, sources, format_funcs, etc.)")
    p.add_argument("--output", required=True, help="Output JSON path")
    p.add_argument("--max-cache-size", type=int, default=10000, help="Cache capacity (default: 10000)")
    p.add_argument("--max-paths", type=int, default=10000, help="Maximum number of paths to generate (default: 10000)")
    p.add_argument("--max-depth", type=int, default=10, help="Maximum recursion depth for path tracing (default: 10)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logger level")
    return p

# === 追加：导出路径对应的反编译代码（含逐 hop 的调用行） ===
def _parse_hex_or_none(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.lower().startswith("0x"):
            try:
                return int(s, 16)
            except Exception:
                return None
    return None

def _decompile_func_text(func_ea: int) -> str:
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        lines = cfunc.get_pseudocode()
        body = "\n".join(idaapi.tag_remove(l.line) for l in lines)
        fn = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        header = f"/* Function: {fn} @ 0x{func_ea:X} */\n"
        return header + body + "\n"
    except Exception as e:
        return f"/* decompile failed @ 0x{func_ea:X}: {e} */\n"

def _print_cexpr_one_line(cfunc, item) -> str:
    try:
        qp = ida_hexrays.qstring_printer_t(cfunc, False)
        item._print(0, qp)
        return idaapi.tag_remove(qp.s).strip().split("\n", 1)[0]
    except Exception:
        return ""

def get_decompiled_line_from_address(ea: int) -> str:
    """
    给定调用点 EA，返回该调用在反编译里的单行代码文本。
    优先基于 cexpr.ea 精确匹配；失败时用 eamap 中的节点回退；再失败返回占位说明。
    """
    if not ida_hexrays.init_hexrays_plugin():
        return "<hex-rays not available>"

    func = idaapi.get_func(ea)
    if not func:
        return f"<no function for 0x{ea:X}>"

    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        return f"<decompile failed for 0x{ea:X}: {e}>"

    # 1) 先在 ctree 里找 cot_call 且 e.ea == ea 的表达式
    class _CallFinder(idaapi.ctree_visitor_t):
        def __init__(self, tgt_ea):
            super().__init__(idaapi.CV_FAST)
            self.tgt = tgt_ea
            self.hit = None
        def visit_expr(self, e):
            if e.op == idaapi.cot_call and getattr(e, "ea", idaapi.BADADDR) == self.tgt:
                self.hit = e
                return 1  # stop
            return 0

    finder = _CallFinder(ea)
    try:
        finder.apply_to(cfunc.body, None)
    except Exception:
        pass

    def _one_line_from_node(node) -> str:
        try:
            qp = ida_hexrays.qstring_printer_t(cfunc, False)
            node._print(0, qp)
            s = ida_lines.tag_remove(qp.s).strip()
            return s.split("\n", 1)[0]
        except Exception:
            return ""

    if finder.hit is not None:
        line = _one_line_from_node(finder.hit)
        if line:
            return line

    # 2) eamap 回退：拿该 EA 关联的反编译节点，优先取调用表达式
    try:
        if hasattr(cfunc, "eamap") and ea in cfunc.eamap:
            # 优先挑出 cot_call 的节点
            call_nodes = [n for n in cfunc.eamap[ea] if getattr(n, "op", None) == idaapi.cot_call]
            nodes = call_nodes or list(cfunc.eamap[ea])
            for n in nodes:
                line = _one_line_from_node(n)
                if line:
                    return line
    except Exception:
        pass

    # 3) 再退化：遍历表达式，拿到 EA 相同的任意节点
    class _AnyByEA(idaapi.ctree_visitor_t):
        def __init__(self, tgt_ea):
            super().__init__(idaapi.CV_FAST)
            self.tgt = tgt_ea
            self.line = None
        def visit_expr(self, e):
            if getattr(e, "ea", idaapi.BADADDR) == self.tgt:
                self.line = _one_line_from_node(e)
                return 1
            return 0
    any_f = _AnyByEA(ea)
    try:
        any_f.apply_to(cfunc.body, None)
    except Exception:
        pass
    if any_f.line:
        return any_f.line

    return f"<no exact call found for 0x{ea:X}>"

def _host_func_ea_for_hop(path: list, i: int) -> int | None:
    """
    推断第 i 个 hop 的调用发生在哪个函数里（用于取调用行）：
    - 若本 hop 的 func_ea 是整数 → 调用发生在该函数中。
    - 若本 hop func_ea 为 'source'（源头），通常调用发生在上一个 hop 的函数中。
    - 若为 'sink' 或无法判断 → None。
    """
    fea_raw = path[i].get("func_ea")
    fea = _parse_hex_or_none(fea_raw)
    if isinstance(fea, int):
        return fea
    if (isinstance(fea_raw, str) and fea_raw == "source") and i > 0:
        # 源头的调用发生在上一个函数里
        prev_fea = _parse_hex_or_none(path[i-1].get("func_ea"))
        if isinstance(prev_fea, int):
            return prev_fea
    return None

def _write_paths_c_files(results: list, out_dir: str) -> None:
    """
    给每条路径写一个 <index>.c：
    - 文件头部输出 Hops 列表，并在每个 hop 下面输出“具体调用行”（如果能定位）。
    - 文件主体按出现顺序去重，输出该路径涉及的所有函数的反编译代码。
    """
    import os
    os.makedirs(out_dir, exist_ok=True)

    path_idx = 0
    for item in results:
        path = item.get("path") or []
        if not path:
            continue
        path_idx += 1

        # === 头部：Hops + 调用行 ===
        banner = [
            "/* =====================================================",
            f" *  Path {path_idx}",
            f" *  vuln_type = {item.get('vuln_type')}",
            f" *  sink_func = {item.get('sink_func')}",
            f" *  source_func = {item.get('source_func')}",
            " *  Hops:",
        ]

        for i, hop in enumerate(path):
            func = hop.get("func")
            argi = hop.get("arg_index")
            call_ea_raw = hop.get("call_ea")
            fea_raw = hop.get("func_ea")
            label = hop.get("label")

            banner.append(f" *    - {func} (arg={argi}, call_ea={call_ea_raw}, func_ea={fea_raw}, label={label})")

            # 尝试打印该 hop 的“具体调用行”
            cea = _parse_hex_or_none(call_ea_raw)
            if isinstance(cea, int):
                call_line = get_decompiled_line_from_address(cea)
                # 追加一行显示调用文本
                banner.append(f" *        call: {call_line}")

        banner.append(" * ===================================================== */\n")

        # === 主体：该路径涉及的所有函数反编译 ===
        ordered_eas = []
        seen = set()
        for hop in path:
            fea = _parse_hex_or_none(hop.get("func_ea"))
            if isinstance(fea, int) and fea not in seen:
                seen.add(fea)
                ordered_eas.append(fea)

        chunks = ["\n".join(banner)]
        for ea in ordered_eas:
            chunks.append(_decompile_func_text(ea))

        out_c = os.path.join(out_dir, f"{path_idx}.c")
        try:
            with open(out_c, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n\n".join(chunks))
        except Exception as e:
            print(f"[!] 写入 {out_c} 失败: {e}")


def main(argv: Optional[List[str]] = None) -> int:
    _ensure_ida_available()

    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_argparser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level))

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays Decompiler 不可用！")
        return 3

    start_time = time.time()
    # 使用综合加载函数
    sinks, cwe_sources, format_funcs, propagators = load_config_from_json(args.config)
    analyzer = Analyzer(
        cwe_sources=cwe_sources,
        format_funcs=format_funcs,
        propagators=propagators,
        max_cache_size=args.max_cache_size,
        # max_paths=args.max_paths,
        max_depth=args.max_depth
    )

    results = analyzer.run_all(sinks)
    # 第一轮去重：完整路径去重
    results = _dedup_paths(results)
    # 第二轮去重：基于 sink_func 和最后一个 call_ea 去重
    results = _dedup_paths_by_sink_callsite(results)

    # Tenda固件特殊过滤：检查路径是否经过main函数
    binary_path = idc.get_input_file_path() if idc else ""
    if "Tenda" in binary_path or "tenda" in binary_path:
        print("[*] 检测到Tenda固件，启用main函数过滤...")
        results = _filter_tenda_paths_without_main(results)

    # CWE-120 安全模式已在回溯过程中自动过滤
    print("[*] CWE-120 安全模式（strlen+malloc/len）已在分析时自动过滤")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # === 追加：为每条路径输出一份 <index>.c 到与 JSON 同目录 ===
    # _write_paths_c_files(results, out_dir=os.path.dirname(args.output))
    
    stats = analyzer.cache.stats()
    elapsed = time.time() - start_time

    print()
    print("=" * 60)
    print("=== 分析完成 ===")
    print("=" * 60)
    print(f"总耗时：{elapsed:.2f} 秒")
    print(f"路径计数模式：每个sink函数独立计数（上限10000条/sink）")
    print(f"最终输出路径数量：{len(results)} 条")
    print(f"(CWE-120 安全模式已在分析时自动过滤)")
    print()
    print("=== Cache Stats ===")
    print(f"Hits      : {stats['hits']}")
    print(f"Misses    : {stats['misses']}")
    print(f"Hit Rate  : {stats['hit_rate']:.2f}%")
    print(f"Cache Size: {stats['current_size']} / {stats['max_size']}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())