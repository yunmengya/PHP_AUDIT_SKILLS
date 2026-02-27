#!/usr/bin/env python3
import argparse
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from common import (
    Progress,
    build_output_root,
    detect_sinks,
    extract_params_from_signature,
    read_text,
    write_json,
    write_text,
    walk_php_files,
)


try:
    from tree_sitter_languages import get_parser
except Exception:  # pragma: no cover
    get_parser = None


def ensure_parser():
    if get_parser is None:
        return None
    return get_parser("php")


KEYWORD_CALLS = {
    "if",
    "for",
    "foreach",
    "while",
    "switch",
    "catch",
    "isset",
    "empty",
    "echo",
    "print",
    "return",
    "require",
    "include",
    "include_once",
    "require_once",
    "array",
}


_PARSER_LOCAL = threading.local()


def get_thread_parser():
    parser = getattr(_PARSER_LOCAL, "parser", None)
    if parser is None:
        parser = ensure_parser()
        _PARSER_LOCAL.parser = parser
    return parser


def find_namespace(text: str) -> str:
    m = re.search(r"\bnamespace\s+([A-Za-z0-9_\\]+)\s*;", text)
    return m.group(1) if m else ""


def parse_use_aliases(text: str) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for m in re.finditer(r"\buse\s+([^;]+);", text):
        clause = m.group(1)
        # ignore group use like: use Foo\{Bar, Baz as Q}
        if "{" in clause:
            continue
        parts = clause.split(" as ") if " as " in clause else clause.split(" AS ")
        full = parts[0].strip()
        alias = parts[1].strip() if len(parts) > 1 else full.split("\\")[-1]
        aliases[alias] = full
    return aliases


def resolve_class(name: str, namespace: str, aliases: Dict[str, str]) -> str:
    if not name:
        return ""
    if "\\" in name:
        return name.strip("\\")
    if name in aliases:
        return aliases[name]
    return f"{namespace}\\{name}" if namespace else name


def node_text(text: str, node) -> str:
    return text[node.start_byte : node.end_byte]


def extract_params_from_node(text: str, node) -> List[str]:
    params = []
    for child in node.named_children:
        if child.type == "formal_parameters":
            for p in child.named_children:
                if p.type in ("simple_parameter", "variadic_parameter"):
                    var = p.child_by_field_name("name")
                    if var:
                        name = node_text(text, var).lstrip("$")
                        params.append(name)
    if not params:
        # fallback regex on text of parameter list
        m = re.search(r"\((.*)\)", node_text(text, node))
        if m:
            params.extend(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", m.group(1)))
    return params


def extract_function_body(text: str, node) -> Tuple[str, int]:
    body = node.child_by_field_name("body")
    if body is None:
        return "", node.start_point[0] + 1
    body_text = node_text(text, body)
    body_start_line = body.start_point[0] + 1
    return body_text, body_start_line


def summarize_function(text: str, file_path: str, node, params: List[str]) -> Dict:
    body_text, body_start_line = extract_function_body(text, node)
    lines = body_text.splitlines()
    sinks = detect_sinks(lines, body_start_line, file_path)

    returns = []
    param_sinks: Dict[str, List[str]] = {}
    for idx, line in enumerate(lines, start=body_start_line):
        if "return" in line:
            for p in params:
                if f"${p}" in line:
                    if p not in returns:
                        returns.append(p)
        for sink in sinks:
            if sink["line"] != idx:
                continue
            for p in params:
                if f"${p}" in line:
                    param_sinks.setdefault(p, []).append(sink["type"])
    return {"returns": returns, "param_sinks": param_sinks}


def find_variable_new_map(text: str, namespace: str, aliases: Dict[str, str]) -> Dict[str, str]:
    var_map: Dict[str, str] = {}
    for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+([A-Za-z_][A-Za-z0-9_\\]*)", text):
        var = m.group(1)
        cls = resolve_class(m.group(2), namespace, aliases)
        var_map[var] = cls
    return var_map


def collect_nodes_and_edges(path: str, text: str, parser) -> Tuple[List[Dict], List[Dict]]:
    tree = parser.parse(bytes(text, "utf-8"))
    root = tree.root_node

    namespace = find_namespace(text)
    aliases = parse_use_aliases(text)
    var_map = find_variable_new_map(text, namespace, aliases)

    nodes: List[Dict] = []
    edges: List[Dict] = []

    class_stack: List[Optional[str]] = []
    func_stack: List[Optional[str]] = []

    def current_class() -> Optional[str]:
        return class_stack[-1] if class_stack else None

    def current_func() -> Optional[str]:
        return func_stack[-1] if func_stack else None

    def make_func_id(ns: str, func: str) -> str:
        return f"{ns}\\{func}" if ns else func

    def make_method_id(ns: str, cls: str, method: str) -> str:
        cls_full = resolve_class(cls, ns, aliases)
        return f"{cls_full}::{method}"

    def register_node(node, node_type: str, name: str, cls: Optional[str]) -> str:
        params = extract_params_from_node(text, node)
        summary = summarize_function(text, path, node, params)
        node_id = make_method_id(namespace, cls, name) if node_type == "method" else make_func_id(namespace, name)
        nodes.append({
            "id": node_id,
            "type": node_type,
            "name": name,
            "class": cls,
            "namespace": namespace,
            "file": path,
            "line": node.start_point[0] + 1,
            "params": params,
            "summary": summary,
        })
        return node_id

    def record_edge(caller: str, callee: str, line: int, raw: str, unresolved: bool = False):
        edges.append({
            "caller": caller,
            "callee": callee,
            "callsite": {"file": path, "line": line},
            "unresolved": unresolved,
            "raw": raw,
        })

    def walk(node):
        # class
        if node.type in ("class_declaration", "interface_declaration", "trait_declaration"):
            name_node = node.child_by_field_name("name")
            cls_name = node_text(text, name_node) if name_node else ""
            class_stack.append(cls_name)
            for child in node.named_children:
                walk(child)
            class_stack.pop()
            return

        # function
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            func_name = node_text(text, name_node) if name_node else ""
            func_id = register_node(node, "function", func_name, None)
            func_stack.append(func_id)
            for child in node.named_children:
                walk(child)
            func_stack.pop()
            return

        # method
        if node.type == "method_declaration":
            name_node = node.child_by_field_name("name")
            method_name = node_text(text, name_node) if name_node else ""
            cls = current_class() or ""
            method_id = register_node(node, "method", method_name, cls)
            func_stack.append(method_id)
            for child in node.named_children:
                walk(child)
            func_stack.pop()
            return

        # call expressions
        if node.type in ("function_call_expression", "function_call"):
            name_node = node.child_by_field_name("function") or node.child_by_field_name("name")
            func_name = node_text(text, name_node) if name_node else ""
            caller = current_func()
            if caller:
                callee = make_func_id(namespace, func_name)
                record_edge(caller, callee, node.start_point[0] + 1, func_name, False)
            return

        if node.type in ("method_call_expression", "member_call_expression"):
            obj = node.child_by_field_name("object")
            name_node = node.child_by_field_name("name")
            method_name = node_text(text, name_node) if name_node else ""
            obj_text = node_text(text, obj) if obj else ""
            caller = current_func()
            if caller:
                if obj_text == "$this" and current_class():
                    callee = make_method_id(namespace, current_class() or "", method_name)
                    record_edge(caller, callee, node.start_point[0] + 1, f"{obj_text}->{method_name}", False)
                elif obj_text.startswith("$") and obj_text[1:] in var_map:
                    cls = var_map[obj_text[1:]]
                    callee = f"{cls}::{method_name}"
                    record_edge(caller, callee, node.start_point[0] + 1, f"{obj_text}->{method_name}", False)
                else:
                    record_edge(caller, method_name, node.start_point[0] + 1, f"{obj_text}->{method_name}", True)
            return

        if node.type in ("scoped_call_expression", "scoped_method_call_expression"):
            scope = node.child_by_field_name("scope")
            name_node = node.child_by_field_name("name")
            cls_name = node_text(text, scope) if scope else ""
            method_name = node_text(text, name_node) if name_node else ""
            caller = current_func()
            if caller:
                cls = resolve_class(cls_name, namespace, aliases)
                callee = f"{cls}::{method_name}"
                record_edge(caller, callee, node.start_point[0] + 1, f"{cls_name}::{method_name}", False)
            return

        for child in node.named_children:
            walk(child)

    walk(root)
    return nodes, edges


def normalize_threads(threads: int) -> int:
    if threads is None or threads <= 0:
        return max(os.cpu_count() or 4, 1)
    return max(threads, 1)


def _match_block(text: str, brace_pos: int) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    if brace_pos < 0:
        return None, None, None
    depth = 0
    i = brace_pos
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
        return None, None, None
    body = text[brace_pos + 1 : end]
    body_start_line = text[: brace_pos + 1].count("\n") + 1
    return body, body_start_line, end


def _extract_methods_from_class(text: str, cls_name: str, namespace: str, file_path: str, class_start: int) -> List[Dict]:
    # find class body
    brace_pos = text.find("{", class_start)
    body, body_start_line, body_end = _match_block(text, brace_pos)
    if body is None:
        return []
    methods: List[Dict] = []
    for m in re.finditer(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{", body, re.I):
        name = m.group(1)
        sig = m.group(2)
        params = extract_params_from_signature(sig)
        local_brace = body.find("{", m.end() - 1)
        method_body, method_start_line, _ = _match_block(body, local_brace)
        if method_body is None:
            continue
        # compute summary
        lines = method_body.splitlines()
        sinks = detect_sinks(lines, method_start_line, file_path)
        returns = []
        param_sinks: Dict[str, List[str]] = {}
        for idx, line in enumerate(lines, start=method_start_line):
            if "return" in line:
                for p in params:
                    if f"${p}" in line and p not in returns:
                        returns.append(p)
            for sink in sinks:
                if sink["line"] != idx:
                    continue
                for p in params:
                    if f"${p}" in line:
                        param_sinks.setdefault(p, []).append(sink["type"])
        node_id = f"{namespace}\\{cls_name}::{name}" if namespace else f"{cls_name}::{name}"
        methods.append({
            "id": node_id,
            "type": "method",
            "name": name,
            "class": cls_name,
            "namespace": namespace,
            "file": file_path,
            "line": body[: m.start()].count("\n") + body_start_line,
            "params": params,
            "summary": {"returns": returns, "param_sinks": param_sinks},
            "_body": method_body,
            "_body_start": method_start_line,
        })
    return methods


def _extract_functions(text: str, namespace: str, file_path: str, class_ranges: List[Tuple[int, int]]) -> List[Dict]:
    functions: List[Dict] = []
    for m in re.finditer(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{", text, re.I):
        if any(start <= m.start() <= end for start, end in class_ranges):
            continue
        name = m.group(1)
        sig = m.group(2)
        params = extract_params_from_signature(sig)
        brace_pos = text.find("{", m.end() - 1)
        body, body_start_line, _ = _match_block(text, brace_pos)
        if body is None:
            continue
        lines = body.splitlines()
        sinks = detect_sinks(lines, body_start_line, file_path)
        returns = []
        param_sinks: Dict[str, List[str]] = {}
        for idx, line in enumerate(lines, start=body_start_line):
            if "return" in line:
                for p in params:
                    if f"${p}" in line and p not in returns:
                        returns.append(p)
            for sink in sinks:
                if sink["line"] != idx:
                    continue
                for p in params:
                    if f"${p}" in line:
                        param_sinks.setdefault(p, []).append(sink["type"])
        node_id = f"{namespace}\\{name}" if namespace else name
        functions.append({
            "id": node_id,
            "type": "function",
            "name": name,
            "class": None,
            "namespace": namespace,
            "file": file_path,
            "line": text[: m.start()].count("\n") + 1,
            "params": params,
            "summary": {"returns": returns, "param_sinks": param_sinks},
            "_body": body,
            "_body_start": body_start_line,
        })
    return functions


def build_call_graph_regex(project_root: str) -> Dict:
    nodes: List[Dict] = []
    edges: List[Dict] = []
    files = list(walk_php_files(project_root))
    for path in files:
        try:
            text = read_text(path)
        except Exception:
            continue
        namespace = find_namespace(text)

        class_ranges: List[Tuple[int, int]] = []
        for m in re.finditer(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b", text):
            cls_name = m.group(1)
            body, _, end = _match_block(text, text.find("{", m.end()))
            if body is None or end is None:
                continue
            class_ranges.append((m.start(), end))
            nodes.extend(_extract_methods_from_class(text, cls_name, namespace, path, m.start()))

        nodes.extend(_extract_functions(text, namespace, path, class_ranges))

        # build simple edges from function bodies
        func_map = {n["id"]: n for n in nodes if n.get("file") == path}
        method_index: Dict[str, str] = {}
        func_index: Dict[str, str] = {}
        for n in nodes:
            if n.get("file") != path:
                continue
            if n.get("type") == "function":
                func_index[n["name"]] = n["id"]
            if n.get("type") == "method":
                method_index[f"{n.get('class')}::{n.get('name')}"] = n["id"]

        for n in list(func_map.values()):
            body = n.pop("_body", "")
            body_start = n.pop("_body_start", None)
            if not body or not body_start:
                continue
            for idx, line in enumerate(body.splitlines(), start=body_start):
                if "function" in line:
                    continue
                # method calls
                m_this = re.search(r"\$this->([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
                if m_this and n.get("class"):
                    callee = method_index.get(f"{n.get('class')}::{m_this.group(1)}")
                    edges.append({
                        "caller": n["id"],
                        "callee": callee or f"{n.get('class')}::{m_this.group(1)}",
                        "callsite": {"file": path, "line": idx},
                        "unresolved": callee is None,
                        "raw": f"$this->{m_this.group(1)}",
                    })
                m_static = re.search(r"([A-Za-z_][A-Za-z0-9_\\\\]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
                if m_static:
                    cls_name = m_static.group(1)
                    base_cls = cls_name.split("\\\\")[-1]
                    key = f"{base_cls}::{m_static.group(2)}"
                    callee = method_index.get(key)
                    edges.append({
                        "caller": n["id"],
                        "callee": callee or f"{cls_name}::{m_static.group(2)}",
                        "callsite": {"file": path, "line": idx},
                        "unresolved": callee is None,
                        "raw": f"{cls_name}::{m_static.group(2)}",
                    })
                # function calls
                for m_call in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line):
                    name = m_call.group(1)
                    if name.lower() in KEYWORD_CALLS:
                        continue
                    callee = func_index.get(name)
                    if not callee:
                        continue
                    edges.append({
                        "caller": n["id"],
                        "callee": callee,
                        "callsite": {"file": path, "line": idx},
                        "unresolved": False,
                        "raw": name,
                    })

    graph = {"nodes": nodes, "edges": edges, "degraded": True, "reason": "regex_fallback"}
    return graph


def build_call_graph(project_root: str, out_root: str, threads: int = 0, progress: bool = False) -> Dict:
    threads = normalize_threads(threads)
    nodes: List[Dict] = []
    edges: List[Dict] = []

    if get_parser is None:
        print("[WARN] tree_sitter_languages not installed; using regex fallback call graph.")
        return build_call_graph_regex(project_root)

    files = list(walk_php_files(project_root))
    prog = Progress(len(files), label="call_graph", enabled=progress)

    def worker(path: str) -> Tuple[List[Dict], List[Dict]]:
        try:
            text = read_text(path)
        except Exception:
            return [], []
        parser = get_thread_parser()
        if parser is None:
            return [], []
        return collect_nodes_and_edges(path, text, parser)

    if threads <= 1 or len(files) <= 1:
        for path in files:
            n, e = worker(path)
            nodes.extend(n)
            edges.extend(e)
            prog.update()
    else:
        with ThreadPoolExecutor(max_workers=min(threads, len(files))) as ex:
            futures = {ex.submit(worker, p): p for p in files}
            for fut in as_completed(futures):
                try:
                    n, e = fut.result()
                    nodes.extend(n)
                    edges.extend(e)
                except Exception:
                    pass
                prog.update()

    # dedupe nodes by id
    uniq_nodes: Dict[str, Dict] = {}
    for n in nodes:
        uniq_nodes[n["id"]] = n

    graph = {
        "nodes": list(uniq_nodes.values()),
        "edges": edges,
    }
    return graph


def write_outputs(graph: Dict, out_root: str) -> None:
    route_root = os.path.join(out_root, "route_tracer")
    os.makedirs(route_root, exist_ok=True)

    json_path = os.path.join(route_root, "call_graph.json")
    write_json(json_path, graph)

    # Summary MD
    node_count = len(graph.get("nodes", []))
    edge_count = len(graph.get("edges", []))
    unresolved = [e for e in graph.get("edges", []) if e.get("unresolved")]
    # top-10 callees
    freq: Dict[str, int] = {}
    for e in graph.get("edges", []):
        callee = e.get("callee") or ""
        freq[callee] = freq.get(callee, 0) + 1
    top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]

    lines = ["# Call Graph Summary", "", f"Nodes: {node_count}", f"Edges: {edge_count}", f"Unresolved: {len(unresolved)}", ""]
    lines.append("## Top Callees")
    for name, count in top:
        lines.append(f"- {name}: {count}")
    write_text(os.path.join(route_root, "call_graph.md"), "\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--threads", type=int, default=0, help="Worker threads (0=auto)")
    ap.add_argument("--progress", dest="progress", action="store_true", default=True, help="Show progress bar (default: on)")
    ap.add_argument("--no-progress", dest="progress", action="store_false", help="Disable progress bar")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    graph = build_call_graph(project_root, out_root, threads=args.threads, progress=args.progress)
    write_outputs(graph, out_root)
    print(f"Wrote call graph to {out_root}")


if __name__ == "__main__":
    main()
