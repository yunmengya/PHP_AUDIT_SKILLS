#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

from common import build_output_root, read_text, write_json, walk_php_files, detect_sources_in_lines, detect_validations, detect_sinks


SCRIPT_DIR = os.path.dirname(__file__)
CONFIG_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "_config"))


def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def load_policy() -> Dict:
    cfg = os.path.join(CONFIG_DIR, "ai_audit_policy.json")
    if not os.path.exists(cfg):
        return {}
    return load_json(cfg, {}) or {}


def list_traces(out_root: str) -> List[Tuple[str, Dict]]:
    tracer_root = os.path.join(out_root, "route_tracer")
    traces: List[Tuple[str, Dict]] = []
    if not os.path.isdir(tracer_root):
        return traces
    for name in sorted(os.listdir(tracer_root)):
        trace_path = os.path.join(tracer_root, name, "trace.json")
        if not os.path.exists(trace_path):
            continue
        trace = load_json(trace_path, None)
        if isinstance(trace, dict):
            traces.append((name, trace))
    return traces


def find_route(routes: List[Dict], trace_route: Dict) -> Optional[Dict]:
    if not trace_route:
        return None
    for r in routes:
        if (
            r.get("path") == trace_route.get("path")
            and r.get("controller") == trace_route.get("controller")
            and r.get("action") == trace_route.get("action")
        ):
            return r
    for r in routes:
        if r.get("path") == trace_route.get("path"):
            return r
    return None


def load_call_graph(out_root: str) -> Tuple[Dict[str, Dict], List[Dict]]:
    path = os.path.join(out_root, "route_tracer", "call_graph.json")
    data = load_json(path, {})
    nodes = {n.get("id"): n for n in data.get("nodes", []) if n.get("id")}
    edges = data.get("edges", []) if isinstance(data.get("edges"), list) else []
    return nodes, edges


def call_graph_complete(out_root: str) -> bool:
    path = os.path.join(out_root, "route_tracer", "call_graph.json")
    if not os.path.exists(path):
        return False
    data = load_json(path, {})
    if isinstance(data, dict) and data.get("degraded"):
        return False
    nodes = data.get("nodes") or []
    return len(nodes) > 0


def extract_block_by_line(text: str, line_no: int) -> Tuple[str, Optional[int]]:
    if not text:
        return "", None
    lines = text.splitlines()
    if line_no < 1:
        return "", None
    idx = min(line_no - 1, len(lines) - 1)
    func_line = None
    for i in range(idx, -1, -1):
        if re.search(r"\bfunction\b", lines[i]):
            func_line = i
            break
    if func_line is None:
        return "", None
    # locate the first '{' after the function line
    offset = sum(len(l) + 1 for l in lines[:func_line])
    brace_pos = text.find("{", offset)
    if brace_pos == -1:
        return "", None
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
        return "", None
    body = text[brace_pos + 1 : end]
    body_start_line = text[: brace_pos + 1].count("\n") + 1
    return body, body_start_line


def get_line(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].rstrip()
    return ""


def _entry_id_from_path(project_root: str, path: str) -> str:
    rel = os.path.relpath(path, project_root)
    safe = rel.replace(os.sep, "_").replace(":", "_")
    return safe


def select_entry_files(project_root: str, policy: Dict) -> List[str]:
    files = walk_php_files(project_root)
    if not files:
        return []

    def score(p: str) -> Tuple[int, str]:
        rel = os.path.relpath(p, project_root)
        parts = rel.split(os.sep)
        s = 0
        if parts and parts[0].lower() in ("public", "web", "www", "htdocs"):
            s -= 3
        if len(parts) == 1:
            s -= 2
        return (s, rel)

    files.sort(key=score)
    max_files = int(policy.get("max_entry_files", 80))
    if max_files > 0:
        files = files[:max_files]
    return files


def build_fallback_trace(project_root: str, path: str) -> Dict:
    text = read_text(path)
    lines = text.splitlines()
    sources = detect_sources_in_lines(lines, path, 1)
    validations = detect_validations(lines, 1)
    sinks = detect_sinks(lines, 1, path)
    taint = []
    for src in sources:
        line_no = src.get("line") or 0
        code = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        taint.append({"file": path, "line": line_no, "code": code, "vars": []})

    controllability = "none"
    if sources and sinks:
        controllability = "conditional" if validations else "fully"
    elif sources and not sinks:
        controllability = "conditional"

    rel = os.path.relpath(path, project_root)
    trace = {
        "route": {
            "method": "ANY",
            "path": "/" + rel.replace(os.sep, "/"),
            "controller": os.path.basename(path),
            "action": "",
        },
        "source": sources[0] if sources else None,
        "sources": sources,
        "taint": taint,
        "sink": sinks[0] if sinks else None,
        "sinks": sinks,
        "validation": validations,
        "controllability": controllability,
        "call_graph_used": False,
        "entry_fallback": True,
        "entry_file": path,
    }
    return trace


def build_context(
    entry_id: str,
    trace: Dict,
    route_info: Optional[Dict],
    controller_file: Optional[str],
    nodes: Dict[str, Dict],
    edges: List[Dict],
) -> Dict:
    route = trace.get("route") or {}
    action = route.get("action") or (route_info or {}).get("action")
    controller = route.get("controller") or (route_info or {}).get("controller")

    start_nodes: List[str] = []
    if controller_file and action:
        for node_id, node in nodes.items():
            if node.get("file") == controller_file and node.get("name") == action:
                start_nodes.append(node_id)
        if not start_nodes and controller:
            for node_id, node in nodes.items():
                if node.get("name") == action:
                    cls = node.get("class") or ""
                    if cls == controller or node_id.endswith(f"{controller}::{action}"):
                        start_nodes.append(node_id)
    if not start_nodes and controller_file:
        for node_id, node in nodes.items():
            if node.get("file") == controller_file:
                start_nodes.append(node_id)

    edges_by_caller: Dict[str, List[Dict]] = {}
    for e in edges:
        caller = e.get("caller")
        if not caller:
            continue
        edges_by_caller.setdefault(caller, []).append(e)

    reachable: List[str] = []
    sub_edges: List[Dict] = []
    unresolved_edges: List[Dict] = []

    if start_nodes:
        visited = set(start_nodes)
        queue = list(start_nodes)
        while queue:
            caller = queue.pop(0)
            reachable.append(caller)
            for e in edges_by_caller.get(caller, []):
                callee = e.get("callee")
                if e.get("unresolved") or callee not in nodes:
                    unresolved_edges.append(e)
                    continue
                sub_edges.append(e)
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)
    else:
        reachable = list(nodes.keys())
        sub_edges = list(edges)
        for e in edges:
            if e.get("unresolved") or e.get("callee") not in nodes:
                unresolved_edges.append(e)

    file_cache: Dict[str, str] = {}
    def read_file(path: str) -> str:
        if path not in file_cache:
            try:
                file_cache[path] = read_text(path)
            except Exception:
                file_cache[path] = ""
        return file_cache[path]

    functions: List[Dict] = []
    file_paths = set()
    for node_id in reachable:
        node = nodes.get(node_id) or {}
        fpath = node.get("file") or ""
        if fpath:
            file_paths.add(fpath)
        text = read_file(fpath) if fpath else ""
        body, body_start = extract_block_by_line(text, int(node.get("line") or 1)) if text else ("", None)
        functions.append({
            "id": node_id,
            "name": node.get("name"),
            "class": node.get("class"),
            "file": fpath,
            "line": node.get("line"),
            "body": body,
            "body_start_line": body_start,
        })

    # include files from trace sources/sinks/taint/validation
    for key in ("source", "sink"):
        obj = trace.get(key) or {}
        if obj.get("file"):
            file_paths.add(obj.get("file"))
    for item in trace.get("sources") or []:
        if item.get("file"):
            file_paths.add(item.get("file"))
    for item in trace.get("sinks") or []:
        if item.get("file"):
            file_paths.add(item.get("file"))
    for item in trace.get("taint") or []:
        if item.get("file"):
            file_paths.add(item.get("file"))
    for item in trace.get("validation") or []:
        if isinstance(item, dict) and item.get("file"):
            file_paths.add(item.get("file"))

    files: List[Dict] = []
    for path in sorted(file_paths):
        files.append({"path": path, "content": read_file(path)})

    unresolved_calls: List[Dict] = []
    for e in unresolved_edges:
        cs = e.get("callsite") or {}
        fpath = cs.get("file")
        line = cs.get("line")
        code = ""
        if fpath and line:
            text = read_file(fpath)
            code = get_line(text, int(line))
        unresolved_calls.append({
            "file": fpath,
            "line": line,
            "code": code,
            "raw": e.get("raw"),
        })

    sub_nodes = [nodes[nid] for nid in reachable if nid in nodes]

    context = {
        "entry_id": entry_id,
        "project": trace.get("project"),
        "route": route,
        "trace": trace,
        "call_graph": {
            "nodes": sub_nodes,
            "edges": sub_edges,
            "unresolved_calls": unresolved_calls,
        },
        "functions": functions,
        "files": files,
        "meta": {
            "controller_file": controller_file,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
    }
    return context


def build_compact_context(context: Dict) -> Dict:
    trace = context.get("trace") or {}
    return {
        "entry_id": context.get("entry_id"),
        "route": context.get("route"),
        "trace": {
            "source": trace.get("source"),
            "sources": trace.get("sources"),
            "sink": trace.get("sink"),
            "sinks": trace.get("sinks"),
            "taint": trace.get("taint"),
            "validation": trace.get("validation"),
            "controllability": trace.get("controllability"),
        },
        "functions": [
            {
                "id": f.get("id"),
                "name": f.get("name"),
                "class": f.get("class"),
                "file": f.get("file"),
                "line": f.get("line"),
            }
            for f in (context.get("functions") or [])
        ],
        "call_graph": {
            "node_count": len((context.get("call_graph") or {}).get("nodes") or []),
            "edge_count": len((context.get("call_graph") or {}).get("edges") or []),
        },
        "meta": context.get("meta"),
    }


def load_ai_results(out_root: str) -> Tuple[List[Dict], str]:
    path = os.path.join(out_root, "mcp_raw", "ai-audit-mcp.json")
    if not os.path.exists(path):
        return [], "missing"
    data = load_json(path, None)
    if data is None:
        return [], "invalid"
    if isinstance(data, list):
        return data, "ok"
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data.get("results"), "ok"
        if isinstance(data.get("findings"), list):
            return data.get("findings"), "ok"
    return [], "invalid"


def severity_from_sink(sink_type: str) -> str:
    st = (sink_type or "").lower()
    if st in {"sql", "rce", "ssrf", "xxe", "include", "file", "deserialize", "ssti"}:
        return "high"
    if st in {"xss", "csrf", "auth", "authz", "permission", "access", "var_override"}:
        return "medium"
    return "medium"


def default_poc(sink_type: str, route: Dict) -> Dict:
    st = (sink_type or "").lower()
    payloads = {
        "sql": "1' OR 1=1 -- ",
        "xss": "<svg onload=alert(1)>",
        "ssrf": "http://127.0.0.1/",
        "xxe": "<!DOCTYPE xxe [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>",
        "file": "../../../../etc/passwd",
        "include": "../../../../etc/passwd",
        "rce": "; id;",
        "deserialize": "O:8:\"Exploit\":0:{}",
        "csrf": "(CSRF payload)",
        "auth": "(auth bypass payload)",
        "authz": "(authz bypass payload)",
    }
    payload = payloads.get(st, "(payload)")
    return {
        "method": (route or {}).get("method") or "ANY",
        "path": (route or {}).get("path") or "",
        "params": {"payload": payload},
        "notes": "仅模板，不执行",
    }


def validate_ai_finding(item: Dict) -> List[str]:
    required = [
        "id",
        "title",
        "route",
        "sink",
        "source",
        "taint",
        "validation",
        "controllability",
        "confidence",
        "notes",
        "poc",
    ]
    errors: List[str] = []
    for k in required:
        if k not in item or item.get(k) in (None, ""):
            errors.append(f"missing:{k}")

    sink = item.get("sink") or {}
    if not isinstance(sink, dict):
        errors.append("sink:not_object")
    else:
        if not sink.get("type"):
            errors.append("sink:missing_type")
        if not sink.get("file"):
            errors.append("sink:missing_file")

    route = item.get("route")
    if not isinstance(route, dict):
        errors.append("route:not_object")

    taint = item.get("taint")
    if not isinstance(taint, list):
        errors.append("taint:not_list")

    validation = item.get("validation")
    if not isinstance(validation, list):
        errors.append("validation:not_list")

    controllability = item.get("controllability")
    if controllability not in ("fully", "conditional", "none"):
        errors.append("controllability:invalid")

    return errors


def normalize_ai_finding(item: Dict) -> Dict:
    sink = item.get("sink") or {}
    route = item.get("route") or {}
    severity = item.get("severity") or severity_from_sink(sink.get("type"))
    poc = item.get("poc")
    if not poc:
        poc = default_poc(sink.get("type"), route)
    return {
        "id": str(item.get("id")),
        "title": item.get("title"),
        "severity": severity,
        "confidence": item.get("confidence"),
        "route": route,
        "source": item.get("source"),
        "taint": item.get("taint") or [],
        "sink": sink,
        "validation": item.get("validation") or [],
        "controllability": item.get("controllability"),
        "poc": poc,
        "notes": item.get("notes"),
        "exploitability": item.get("exploitability") or "待验证",
        "ai_table": item.get("ai_table") if isinstance(item.get("ai_table"), dict) else None,
        "ai_consensus": item.get("ai_consensus"),
        "consensus_score": item.get("consensus_score"),
        "context_id": item.get("context_id"),
    }


def evidence_score(item: Dict) -> int:
    score = 0
    if item.get("source"):
        score += 1
    if isinstance(item.get("taint"), list) and item.get("taint"):
        score += 1
    sink = item.get("sink") or {}
    if sink.get("file") and sink.get("line"):
        score += 1
    if isinstance(item.get("validation"), list):
        score += 1
    if item.get("controllability") in ("fully", "conditional", "none"):
        score += 1
    return score


def poc_quality(item: Dict) -> str:
    route = item.get("route") or {}
    method = (route.get("method") or "").upper()
    path = route.get("path") or ""
    poc = item.get("poc")
    if isinstance(poc, dict):
        pm = (poc.get("method") or "").upper()
        pp = poc.get("path") or ""
        if method and path and pm == method and pp == path:
            return "ok"
        return "weak"
    if isinstance(poc, str):
        if path and path in poc:
            return "ok"
    return "weak"


def module_for_finding(item: Dict) -> Tuple[str, bool]:
    sink = item.get("sink") or {}
    sink_type = (sink.get("type") or "").lower()
    fid = (item.get("id") or "").upper()
    title = (item.get("title") or "").lower()

    if sink_type in {"auth", "authz", "authorization", "access", "permission"} or fid.startswith("AUTH") or "auth" in title:
        return "auth_audit", True
    if sink_type in {"csrf"} or fid.startswith("CSRF") or "csrf" in title:
        return "csrf_audit", False
    if sink_type in {"sql"}:
        return "sql_audit", False
    if sink_type in {"rce"}:
        return "rce_audit", False
    if sink_type in {"file", "include"}:
        return "file_audit", False
    if sink_type in {"ssrf", "xxe"}:
        return "ssrf_xxe_audit", False
    if sink_type in {"xss", "ssti"}:
        return "xss_ssti_audit", False
    if sink_type in {"deserialize", "serialization", "phar"} or fid.startswith("SER"):
        return "serialize_audit", False
    if sink_type in {"var_override", "variable_override"} or fid.startswith("VAR"):
        return "var_override_audit", False
    return "file_audit", False


def run_ai_mcp(project_root: str, out_root: str) -> None:
    cfg = os.path.join(SCRIPT_DIR, "mcp_config.json")
    if not os.path.exists(cfg):
        cfg = os.path.join(SCRIPT_DIR, "mcp_config.example.json")
    py = sys.executable or "python3"
    cmd = [py, os.path.join(SCRIPT_DIR, "mcp_adapter.py"), "--project", project_root, "--out", out_root, "--tool", "ai-audit-mcp", "--config", cfg]
    subprocess.run(cmd, cwd=project_root, capture_output=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    routes_path = os.path.join(out_root, "route_mapper", "routes.json")
    routes = load_json(routes_path, []) if os.path.exists(routes_path) else []

    nodes, edges = load_call_graph(out_root)
    traces = list_traces(out_root)
    policy = load_policy()
    require_call_graph = bool(policy.get("require_call_graph", False))
    use_compact = bool(policy.get("use_compact_context", False))
    entry_mode = "routes"

    if not traces:
        entry_mode = "fallback"
        entry_files = select_entry_files(project_root, policy)
        traces = [(_entry_id_from_path(project_root, p), build_fallback_trace(project_root, p)) for p in entry_files]

    ctx_root = os.path.join(out_root, "ai_audit", "ai_audit_context")
    os.makedirs(ctx_root, exist_ok=True)

    for entry_id, trace in traces:
        route = trace.get("route") or {}
        route_info = find_route(routes, route)
        controller_file = trace.get("entry_file") or (route_info or {}).get("controller_file")
        ctx = build_context(entry_id, trace, route_info, controller_file, nodes, edges)
        ctx_dir = os.path.join(ctx_root, entry_id)
        os.makedirs(ctx_dir, exist_ok=True)
        write_json(os.path.join(ctx_dir, "context.json"), ctx)
        if use_compact:
            compact = build_compact_context(ctx)
            write_json(os.path.join(ctx_dir, "context_compact.json"), compact)

    # auto-run ai-audit-mcp if missing
    ai_raw_path = os.path.join(out_root, "mcp_raw", "ai-audit-mcp.json")
    if not os.path.exists(ai_raw_path):
        run_ai_mcp(project_root, out_root)

    ai_results, status = load_ai_results(out_root)
    ai_dir = os.path.join(out_root, "ai_audit")
    os.makedirs(ai_dir, exist_ok=True)

    invalid: List[Dict] = []
    normalized: List[Dict] = []
    for item in ai_results:
        if not isinstance(item, dict):
            invalid.append({"id": None, "errors": ["item:not_object"]})
            continue
        errors = validate_ai_finding(item)
        if errors:
            invalid.append({"id": item.get("id"), "errors": errors})
            continue
        normalized.append(normalize_ai_finding(item))

    context_incomplete = require_call_graph and not call_graph_complete(out_root)

    # Write raw AI results
    write_json(os.path.join(ai_dir, "ai_findings.json"), {"results": ai_results})

    # Split into modules
    module_findings: Dict[str, List[Dict]] = {}
    auth_findings: List[Dict] = []
    for item in normalized:
        item["evidence_score"] = evidence_score(item)
        item["context_incomplete"] = context_incomplete
        item["poc_quality"] = poc_quality(item)
        module, is_auth = module_for_finding(item)
        if is_auth:
            auth_findings.append(item)
        else:
            module_findings.setdefault(module, []).append(item)

    # Write module findings
    for module, items in module_findings.items():
        mod_dir = os.path.join(out_root, module)
        os.makedirs(mod_dir, exist_ok=True)
        write_json(os.path.join(mod_dir, "findings.json"), items)

    if auth_findings:
        auth_dir = os.path.join(out_root, "auth_audit")
        os.makedirs(auth_dir, exist_ok=True)
        write_json(os.path.join(auth_dir, "auth_evidence.json"), auth_findings)

    # Write aggregated findings
    write_json(os.path.join(ai_dir, "findings.json"), normalized)

    ok_flag = status == "ok" and len(normalized) > 0 and len(invalid) == 0
    if require_call_graph and context_incomplete:
        ok_flag = False
    report = {
        "status": status,
        "total": len(ai_results),
        "valid": len(normalized),
        "invalid": len(invalid),
        "errors": invalid,
        "context_entries": len(traces),
        "used_ai": bool(ai_results),
        "context_incomplete": context_incomplete,
        "entry_mode": entry_mode,
        "ok": ok_flag,
    }
    write_json(os.path.join(ai_dir, "ai_audit_report.json"), report)

    if status != "ok" or not normalized or invalid:
        print("AI audit missing/invalid. Fallback will be triggered by audit_cli.")
    else:
        print(f"AI audit complete. Findings: {len(normalized)}")


if __name__ == "__main__":
    main()
