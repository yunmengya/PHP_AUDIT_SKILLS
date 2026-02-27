#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from common import (
    build_output_root,
    detect_sinks,
    detect_sources_in_lines,
    detect_validations,
    extract_function_block,
    extract_params_from_signature,
    find_class_files,
    pick_class_file,
    read_text,
    REQUEST_KEYWORDS,
    SOURCE_PATTERNS,
    write_json,
    write_text,
)


def load_routes(routes_json: str) -> List[Dict]:
    with open(routes_json, "r", encoding="utf-8") as f:
        return json.load(f)


def load_call_graph(out_root: str) -> Tuple[Dict[str, Dict], Dict[str, Dict[int, List[Dict]]]]:
    graph_path = os.path.join(out_root, "route_tracer", "call_graph.json")
    if not os.path.exists(graph_path):
        return {}, {}
    try:
        with open(graph_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}, {}

    nodes = {n.get("id"): n for n in data.get("nodes", []) if n.get("id")}
    callsite_map: Dict[str, Dict[int, List[Dict]]] = {}
    for edge in data.get("edges", []):
        cs = edge.get("callsite", {})
        fpath = cs.get("file")
        line = cs.get("line")
        if not fpath or not line:
            continue
        callsite_map.setdefault(fpath, {}).setdefault(int(line), []).append(edge)
    return nodes, callsite_map


def extract_function_blocks(text: str) -> List[Tuple[str, str, int, str]]:
    functions = []
    pattern = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{", re.I)
    for m in pattern.finditer(text):
        name = m.group(1)
        sig = m.group(2)
        start = m.end() - 1
        depth = 0
        i = start
        end = None
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if end is None:
            continue
        body = text[start + 1 : end]
        body_start_line = text[: start + 1].count("\\n") + 1
        functions.append((name, sig, body_start_line, body))
    return functions


def build_function_summaries(text: str, file_path: str) -> Dict[str, Dict]:
    summaries: Dict[str, Dict] = {}
    for name, sig, start_line, body in extract_function_blocks(text):
        params = extract_params_from_signature(sig)
        lines = body.splitlines()
        sinks = detect_sinks(lines, start_line, file_path)
        returns: Set[str] = set()
        param_sinks: Dict[str, List[Dict]] = {}
        for idx, line in enumerate(lines, start=start_line):
            if "return" in line:
                for p in params:
                    if f"${p}" in line:
                        returns.add(p)
            for sink in sinks:
                if sink["line"] != idx:
                    continue
                for p in params:
                    if f"${p}" in line:
                        param_sinks.setdefault(p, []).append(sink)
        summaries[name] = {
            "params": params,
            "returns": returns,
            "param_sinks": param_sinks,
        }
    return summaries


def parse_assignment(line: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);\s*$", line)
    if not m:
        return None
    return m.group(1), m.group(2)


def parse_concat_assignment(line: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\=\s*(.+);\s*$", line)
    if not m:
        return None
    return m.group(1), m.group(2)


def line_has_sanitizer(line: str) -> bool:
    sanitizer_patterns = [
        r"\bintval\s*\(",
        r"\bfloatval\s*\(",
        r"\bfilter_var\s*\(",
        r"\bctype_\w+\s*\(",
        r"\bpreg_match\s*\(",
        r"\baddslashes\s*\(",
        r"\bmysqli_real_escape_string\s*\(",
        r"\bPDO::quote\s*\(",
        r"\bhtmlspecialchars\s*\(",
        r"\bhtmlentities\s*\(",
        r"\bstrip_tags\s*\(",
        r"\bescapeshellarg\s*\(",
        r"\bescapeshellcmd\s*\(",
        r"\bValidator::make\s*\(",
        r"\brequest\s*\(\)\s*->\s*validate\s*\(",
        r"\$request\s*->\s*validate\s*\(",
        r"\bvalidate\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,",
        r"\be\s*\(",
        r"\btwig_escape_filter\s*\(",
    ]
    return any(re.search(p, line, re.I) for p in sanitizer_patterns)


_SUPERGLOBAL_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[", re.I)


def line_has_direct_source(line: str) -> bool:
    if _SUPERGLOBAL_RE.search(line):
        return True
    for pattern in SOURCE_PATTERNS:
        if pattern.search(line):
            return True
    lower = line.lower()
    return any(k in lower for k in REQUEST_KEYWORDS)


def extract_call_args(expr: str, func: str) -> List[str]:
    m = re.search(rf"{re.escape(func)}\s*\(", expr)
    if not m:
        return []
    i = m.end()
    depth = 1
    buf = []
    while i < len(expr):
        c = expr[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        buf.append(c)
        i += 1
    args_str = "".join(buf)
    args = []
    current = []
    depth = 0
    for ch in args_str:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


def extract_call_args_from_raw(expr: str, raw: str) -> List[str]:
    if not raw:
        return []
    name = raw
    if "->" in name:
        name = name.split("->")[-1]
    elif "::" in name:
        name = name.split("::")[-1]
    name = name.strip()
    if not name:
        return []
    return extract_call_args(expr, name)


def arg_is_tainted(arg: str, tainted_vars: Set[str]) -> bool:
    if "$" in arg:
        if any(f"${v}" in arg for v in tainted_vars):
            return True
    if "$_" in arg:
        return True
    if "request()" in arg or "$request" in arg:
        return True
    if "php://input" in arg:
        return True
    return False


def analyze_taint(
    lines: List[str],
    start_line: int,
    sources: List[Dict],
    summaries: Dict[str, Dict],
    file_path: str,
    callsite_map: Optional[Dict[int, List[Dict]]] = None,
    call_graph_nodes: Optional[Dict[str, Dict]] = None,
) -> Tuple[List[Dict], List[Dict]]:
    taint_events: List[Dict] = []
    sinks: List[Dict] = []
    tainted_vars: Set[str] = set()
    sanitized_vars: Set[str] = set()

    for src in sources:
        if src.get("param"):
            tainted_vars.add(src["param"])

    for idx, line in enumerate(lines, start=start_line):
        line_stripped = line.strip()
        line_tainted_vars = [v for v in tainted_vars if f"${v}" in line_stripped]
        direct_source = line_has_direct_source(line_stripped)
        line_tainted = bool(line_tainted_vars) or direct_source

        if direct_source:
            taint_events.append({"file": file_path, "line": idx, "code": line_stripped, "vars": ["_direct"]})

        assign = parse_assignment(line_stripped)
        concat = parse_concat_assignment(line_stripped)

        if assign:
            lhs, rhs = assign
            rhs_has_source = "$_" in rhs or "request()" in rhs or "$request" in rhs or "php://input" in rhs
            rhs_has_taint = any(f"${v}" in rhs for v in tainted_vars)
            if rhs_has_source or rhs_has_taint:
                tainted_vars.add(lhs)
                taint_events.append({"file": file_path, "line": idx, "code": line_stripped, "vars": [lhs]})
            if line_has_sanitizer(rhs):
                sanitized_vars.add(lhs)

            # Propagate through known function summaries
            for func, summary in summaries.items():
                if re.search(rf"\b{re.escape(func)}\s*\(", rhs):
                    args = extract_call_args(rhs, func)
                    params = summary.get("params", [])
                    tainted_params = set()
                    for idx_arg, arg in enumerate(args):
                        if any(f"${v}" in arg for v in tainted_vars):
                            if idx_arg < len(params):
                                tainted_params.add(params[idx_arg])
                    # Propagate taint if function returns a tainted param
                    if lhs and summary.get("returns"):
                        if any(p in summary.get("returns") for p in tainted_params):
                            tainted_vars.add(lhs)
                            taint_events.append({"file": file_path, "line": idx, "code": line_stripped, "vars": [lhs]})
                    # Interprocedural sinks: param-driven
                    for p, sink_list in summary.get("param_sinks", {}).items():
                        if p in tainted_params:
                            for s in sink_list:
                                inter = dict(s)
                                inter["via"] = func
                                inter["interprocedural"] = True
                                sinks.append(inter)

            # Propagate through call graph summaries (cross-file)
            if callsite_map and call_graph_nodes:
                edges = callsite_map.get(idx, [])
                for edge in edges:
                    callee_id = edge.get("callee")
                    node = call_graph_nodes.get(callee_id)
                    if not node:
                        continue
                    args = extract_call_args_from_raw(line_stripped, edge.get("raw", ""))
                    params = node.get("params", [])
                    tainted_params = set()
                    for idx_arg, arg in enumerate(args):
                        if arg_is_tainted(arg, tainted_vars):
                            if idx_arg < len(params):
                                tainted_params.add(params[idx_arg])
                    summary = node.get("summary", {})
                    if lhs and summary.get("returns"):
                        if any(p in summary.get("returns") for p in tainted_params):
                            tainted_vars.add(lhs)
                            taint_events.append({"file": file_path, "line": idx, "code": line_stripped, "vars": [lhs]})
                    for p, sink_types in summary.get("param_sinks", {}).items():
                        if p in tainted_params:
                            for sink_type in sink_types:
                                sinks.append({
                                    "file": file_path,
                                    "line": idx,
                                    "code": line_stripped,
                                    "type": sink_type,
                                    "via": callee_id,
                                    "interprocedural": True,
                                })

        if concat:
            lhs, rhs = concat
            if any(f"${v}" in rhs for v in tainted_vars):
                tainted_vars.add(lhs)
                taint_events.append({"file": file_path, "line": idx, "code": line_stripped, "vars": [lhs]})

        if line_tainted_vars:
            taint_events.append({"file": file_path, "line": idx, "code": line_stripped, "vars": line_tainted_vars})

        # Interprocedural sinks at callsites without assignment
        if not assign and callsite_map and call_graph_nodes:
            edges = callsite_map.get(idx, [])
            for edge in edges:
                callee_id = edge.get("callee")
                node = call_graph_nodes.get(callee_id)
                if not node:
                    continue
                args = extract_call_args_from_raw(line_stripped, edge.get("raw", ""))
                params = node.get("params", [])
                tainted_params = set()
                for idx_arg, arg in enumerate(args):
                    if arg_is_tainted(arg, tainted_vars):
                        if idx_arg < len(params):
                            tainted_params.add(params[idx_arg])
                summary = node.get("summary", {})
                for p, sink_types in summary.get("param_sinks", {}).items():
                    if p in tainted_params:
                        for sink_type in sink_types:
                            sinks.append({
                                "file": file_path,
                                "line": idx,
                                "code": line_stripped,
                                "type": sink_type,
                                "via": callee_id,
                                "interprocedural": True,
                            })

        # Detect sinks on this line if tainted
        line_sinks = detect_sinks([line_stripped], idx, file_path)
        if line_sinks and line_tainted:
            for s in line_sinks:
                s["tainted"] = True
                if line_tainted_vars and any(v in sanitized_vars for v in line_tainted_vars):
                    s["sanitized"] = True
                sinks.append(s)

    return taint_events, sinks


def trace_route(
    route: Dict,
    class_index: Dict[str, List[str]],
    call_graph_nodes: Dict[str, Dict],
    callsite_by_file: Dict[str, Dict[int, List[Dict]]],
) -> Optional[Dict]:
    controller = route.get("controller")
    action = route.get("action")
    controller_file = route.get("controller_file")
    if not controller_file:
        controller_file = pick_class_file(class_index, controller)
    if not controller_file or not action:
        return trace_entry_file(route, controller_file, call_graph_nodes, callsite_by_file)

    text = read_text(controller_file)
    body, body_start_line = extract_function_block(text, action)
    if body is None:
        return trace_entry_file(route, controller_file, call_graph_nodes, callsite_by_file)

    lines = body.splitlines()
    summaries = build_function_summaries(text, controller_file)
    sources = detect_sources_in_lines(lines, controller_file, body_start_line)
    # add path params as sources with line 0
    for p in route.get("params", []):
        if p.get("source") == "path":
            sources.append({
                "file": controller_file,
                "line": 0,
                "param": p.get("name"),
                "kind": "PATH",
            })

    validations = detect_validations(lines, body_start_line)
    callsite_map = callsite_by_file.get(controller_file, {}) if callsite_by_file else {}
    taint, sinks = analyze_taint(
        lines,
        body_start_line,
        sources,
        summaries,
        controller_file,
        callsite_map=callsite_map,
        call_graph_nodes=call_graph_nodes,
    )

    controllability = "none"
    if sources and sinks:
        controllability = "conditional" if validations else "fully"
    elif sources and not sinks:
        controllability = "conditional"

    primary_source = sources[0] if sources else None

    trace = {
        "route": {
            "method": route.get("method"),
            "path": route.get("path"),
            "controller": controller,
            "action": action,
        },
        "source": primary_source,
        "sources": sources,
        "taint": taint,
        "sink": sinks[0] if sinks else None,
        "sinks": sinks,
        "validation": validations,
        "controllability": controllability,
        "call_graph_used": bool(call_graph_nodes),
        "entry_fallback": False,
    }
    return trace


def trace_entry_file(
    route: Dict,
    controller_file: Optional[str],
    call_graph_nodes: Dict[str, Dict],
    callsite_by_file: Dict[str, Dict[int, List[Dict]]],
) -> Optional[Dict]:
    if not controller_file:
        return None
    text = read_text(controller_file)
    lines = text.splitlines()
    sources = detect_sources_in_lines(lines, controller_file, 1)
    validations = detect_validations(lines, 1)
    summaries = build_function_summaries(text, controller_file)
    callsite_map = callsite_by_file.get(controller_file, {}) if callsite_by_file else {}
    taint, sinks = analyze_taint(
        lines,
        1,
        sources,
        summaries,
        controller_file,
        callsite_map=callsite_map,
        call_graph_nodes=call_graph_nodes,
    )

    controllability = "none"
    if sources and sinks:
        controllability = "conditional" if validations else "fully"
    elif sources and not sinks:
        controllability = "conditional"

    primary_source = sources[0] if sources else None

    trace = {
        "route": {
            "method": route.get("method"),
            "path": route.get("path"),
            "controller": route.get("controller"),
            "action": route.get("action"),
        },
        "source": primary_source,
        "sources": sources,
        "taint": taint,
        "sink": sinks[0] if sinks else None,
        "sinks": sinks,
        "validation": validations,
        "controllability": controllability,
        "call_graph_used": bool(call_graph_nodes),
        "entry_fallback": True,
        "entry_file": controller_file,
    }
    return trace


def write_trace(route: Dict, trace: Dict, out_root: str) -> None:
    route_name = sanitize_route_name(route)
    route_root = os.path.join(out_root, "route_tracer", route_name)
    os.makedirs(route_root, exist_ok=True)
    write_json(os.path.join(route_root, "trace.json"), trace)
    write_text(os.path.join(route_root, "trace.md"), render_trace_md(trace))
    write_json(os.path.join(route_root, "sinks.json"), trace.get("sinks", []))


def render_trace_md(trace: Dict) -> str:
    route = trace.get("route", {})
    lines = [
        f"# Trace for {route.get('method')} {route.get('path')}",
        "",
        "## Source",
        json_block(trace.get("source")),
        "",
        "## Sink",
        json_block(trace.get("sink")),
        "",
        "## Taint",
    ]
    for t in trace.get("taint", []):
        lines.append(f"- {t.get('file')}:{t.get('line')} {t.get('code')}")
    lines.append("")
    lines.append("## Validation")
    for v in trace.get("validation", []):
        lines.append(f"- {v.get('line')}: {v.get('code')}")
    lines.append("")
    lines.append(f"## Controllability: {trace.get('controllability')}")
    lines.append("")
    lines.append(f"## Call Graph Used: {trace.get('call_graph_used')}")
    if trace.get("entry_fallback"):
        lines.append("")
        lines.append(f"## Entry Fallback: {trace.get('entry_file')}")
    return "\n".join(lines) + "\n"


def json_block(obj) -> str:
    if not obj:
        return "(none)"
    return "```json\n" + json.dumps(obj, ensure_ascii=False, indent=2) + "\n```"


def sanitize_route_name(route: Dict) -> str:
    path = route.get("path") or "root"
    method = route.get("method") or "ANY"
    safe = re_sub(r"[^A-Za-z0-9_]+", "_", path.strip("/") or "root")
    return f"{method}_{safe}"


def re_sub(pattern: str, repl: str, text: str) -> str:
    import re

    return re.sub(pattern, repl, text)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    routes_json = os.path.join(out_root, "route_mapper", "routes.json")
    if not os.path.exists(routes_json):
        raise SystemExit("routes.json not found. Run route_mapper first.")

    routes = load_routes(routes_json)
    class_index = find_class_files(project_root)
    call_graph_nodes, callsite_by_file = load_call_graph(out_root)

    count = 0
    for route in routes:
        trace = trace_route(route, class_index, call_graph_nodes, callsite_by_file)
        if not trace:
            continue
        write_trace(route, trace, out_root)
        count += 1

    print(f"Wrote {count} traces to {out_root}")


if __name__ == "__main__":
    main()
