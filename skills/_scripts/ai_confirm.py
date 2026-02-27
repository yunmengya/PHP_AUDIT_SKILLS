#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import time
from urllib.parse import quote
from typing import Dict, List, Optional, Set, Tuple

from audit_helpers import stable_id
from common import build_output_root, read_text, write_json

POLICY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "_config", "ai_audit_policy.json"))


ALLOWED_EXPLOITABILITY = {"已确认", "高可能", "待验证"}
HIGH_RISK_SINKS = {"sql", "rce", "deserialize", "file", "ssrf", "xxe"}

REQUIRED_TABLE_FIELDS = [
    "title_label",
    "severity_label",
    "reachability",
    "impact",
    "complexity",
    "exploitability",
    "location",
    "trigger",
    "input_source",
    "output_mode",
    "evidence",
]

WORDLIST_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "wordlists"))
_WORDLIST_CACHE: Dict[str, List[str]] = {}


def _load_wordlist(name: str) -> List[str]:
    if name in _WORDLIST_CACHE:
        return _WORDLIST_CACHE[name]
    path = os.path.join(WORDLIST_DIR, name)
    if not os.path.exists(path):
        _WORDLIST_CACHE[name] = []
        return []
    lines: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#") or line.startswith("//"):
                    continue
                lines.append(line)
    except Exception:
        lines = []
    _WORDLIST_CACHE[name] = lines
    return lines


def load_policy() -> Dict:
    if not os.path.exists(POLICY_PATH):
        return {}
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _pick_payload(key: str, default: str) -> Tuple[str, str]:
    lines = _load_wordlist(f"{key}.txt")
    if lines:
        return lines[0], "wordlist"
    return default, "template"


def _extract_param(input_source: str, route_path: str = "") -> Tuple[str, bool]:
    if input_source:
        m = re.search(r"\$_(GET|POST|REQUEST)\[['\"]([^'\"]+)['\"]\]", input_source)
        if m:
            return m.group(2), False
        m = re.search(r"\b(GET|POST|REQUEST)\s*:\s*([A-Za-z0-9_\-]+)\b", input_source, re.I)
        if m:
            return m.group(2), False
        m = re.search(r"\b(query|body|param|params)\.([A-Za-z0-9_\-]+)\b", input_source, re.I)
        if m:
            return m.group(2), False
        m = re.search(r"\b(input|param|request|get|post)\(\s*['\"]([^'\"]+)['\"]", input_source, re.I)
        if m:
            return m.group(2), False
        m = re.search(r"\bRequest::(input|param|get|post)\(\s*['\"]([^'\"]+)['\"]", input_source, re.I)
        if m:
            return m.group(2), False
        m = re.search(r":\s*([A-Za-z0-9_\-\[\]'\"]+)", input_source)
        if m:
            param = m.group(1).strip().strip("\"'[]")
            if param:
                return param, False

    if route_path:
        m = re.search(r"\{([A-Za-z0-9_\-]+)(?:\?|:[^}]+)?\}", route_path)
        if m:
            return m.group(1), True
        m = re.search(r"/:([A-Za-z0-9_\-]+)\??", route_path)
        if m:
            return m.group(1), True
        m = re.search(r"<([A-Za-z0-9_\-]+)(?::[^>]+)?>", route_path)
        if m:
            return m.group(1), True

    return "param", False


def _apply_path_param(path: str, param: str, payload: str) -> str:
    if not path:
        return "/path"
    encoded = quote(payload, safe="")
    patterns = [
        (rf"\{{{re.escape(param)}\}}", encoded),
        (rf"\{{{re.escape(param)}\?\}}", encoded),
        (rf"\{{{re.escape(param)}:[^}}]+\\}}", encoded),
        (rf":{re.escape(param)}\\??(?=/|$)", encoded),
        (rf"<{re.escape(param)}>", encoded),
        (rf"<{re.escape(param)}:[^>]+>", encoded),
    ]
    for pat, rep in patterns:
        if re.search(pat, path):
            return re.sub(pat, rep, path)
    return path


def _build_curl(method: str, path: str, param: str, payload: str, in_path: bool = False) -> str:
    method = (method or "GET").upper()
    path = path or "/path"
    payload = payload.replace("\"", "\\\"")
    if in_path:
        path = _apply_path_param(path, param, payload)
        target = f"http://target{path}"
        if method in {"POST", "PUT", "PATCH"}:
            return f"curl -X {method} \"{target}\""
        return f"curl \"{target}\""
    target = f"http://target{path}"
    if method in {"POST", "PUT", "PATCH"}:
        return f"curl -X {method} \"{target}\" -d \"{param}={payload}\""
    return f"curl \"{target}?{param}={payload}\""


def _template_poc(f: Dict, ai_table: Dict) -> Tuple[str, str]:
    sink = f.get("sink") or {}
    sink_type = str(sink.get("type") or "").lower()
    route = f.get("route") or {}
    method = (route.get("method") or "GET").upper()
    path = route.get("path") or ""
    input_source = ai_table.get("input_source") or ""
    param, in_path = _extract_param(input_source, path)

    if "sql" in sink_type:
        payload, source = _pick_payload("sql", "' OR 1=1 -- -")
        return _build_curl(method, path, param, payload, in_path=in_path), source
    if "xss" in sink_type or "ssti" in sink_type:
        payload, source = _pick_payload("xss", "<svg onload=alert(1)>")
        return _build_curl(method, path, param, payload, in_path=in_path), source
    if "ssrf" in sink_type:
        payload, source = _pick_payload("ssrf", "http://127.0.0.1/")
        return _build_curl(method, path, param, payload, in_path=in_path), source
    if "xxe" in sink_type:
        xml, source = _pick_payload(
            "xxe",
            "<?xml version=\"1.0\"?>\n"
            "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
            "<root>&xxe;</root>",
        )
        path = path or "/path"
        return (
            f"curl -X POST \"http://target{path}\" -H \"Content-Type: application/xml\" --data-binary '{xml}'",
            source,
        )
    if "file" in sink_type:
        payload, source = _pick_payload("file", "../../../../../etc/passwd")
        return _build_curl(method, path, param, payload, in_path=in_path), source
    if "rce" in sink_type or "cmd" in sink_type:
        payload, source = _pick_payload("rce", "; id; #")
        return _build_curl(method, path, param, payload, in_path=in_path), source
    if "deserialize" in sink_type:
        payload, source = _pick_payload("deserialize", "O:8:\"Exploit\":0:{}")
        return _build_curl(method, path, param, payload, in_path=in_path), source
    if "csrf" in sink_type:
        payload, source = _pick_payload("csrf", "")
        path = path or "/path"
        if payload:
            return payload, source
        return (
            f"<form action=\"http://target{path}\" method=\"POST\">\n"
            f"  <input name=\"{param}\" value=\"test\" />\n"
            "  <input type=\"submit\" />\n"
            "</form>",
            "template",
        )
    return _build_curl(method, path, param, "test", in_path=in_path), "template"


def _evidence_summary(f: Dict, ai_table: Dict) -> str:
    source = f.get("source") or ai_table.get("input_source") or "-"
    sink = f.get("sink") or {}
    sink_name = sink.get("function") or sink.get("type") or "-"
    route = f.get("route") or {}
    route_str = ""
    if isinstance(route, dict):
        method = route.get("method") or ""
        path = route.get("path") or ""
        route_str = f"{method} {path}".strip()
    summary = f"{source} -> {sink_name}"
    if route_str:
        summary = f"{summary} @ {route_str}"
    return summary


def load_routes(out_root: str) -> List[Dict]:
    path = os.path.join(out_root, "route_mapper", "routes.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def method_match(route_method: str, target_method: str) -> bool:
    if not route_method or route_method == "ANY":
        return True
    if not target_method:
        return True
    parts = [p.strip().upper() for p in str(route_method).split("|")]
    return target_method.upper() in parts


def find_controller_file(route: Dict, routes: List[Dict]) -> Optional[str]:
    if not route:
        return None
    r_path = route.get("path")
    r_method = route.get("method")
    r_action = route.get("action")
    r_ctrl = route.get("controller")
    for r in routes:
        if r_path and r.get("path") != r_path:
            continue
        if r_action and r.get("action") != r_action:
            continue
        if r_ctrl and r.get("controller") != r_ctrl:
            continue
        if not method_match(r.get("method"), r_method):
            continue
        if r.get("controller_file"):
            return r.get("controller_file")
    return None


def load_call_graph(out_root: str) -> Tuple[Dict[str, Dict], List[Dict]]:
    path = os.path.join(out_root, "route_tracer", "call_graph.json")
    if not os.path.exists(path):
        return {}, []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}, []
    nodes = {n.get("id"): n for n in (data.get("nodes") or []) if n.get("id")}
    edges = data.get("edges") or []
    return nodes, edges


def load_traces(out_root: str) -> Tuple[Dict[Tuple[str, int], List[Dict]], Dict[Tuple[str, str, str, str], List[Dict]], List[Dict]]:
    sink_map: Dict[Tuple[str, int], List[Dict]] = {}
    route_map: Dict[Tuple[str, str, str, str], List[Dict]] = {}
    traces: List[Dict] = []
    trace_root = os.path.join(out_root, "route_tracer")
    if not os.path.isdir(trace_root):
        return sink_map, route_map, traces
    for root, _, files in os.walk(trace_root):
        for f in files:
            if f != "trace.json":
                continue
            path = os.path.join(root, f)
            try:
                data = json.load(open(path, "r", encoding="utf-8"))
            except Exception:
                continue
            traces.append(data)
            sinks = data.get("sinks", []) or ([] if data.get("sink") is None else [data.get("sink")])
            for s in sinks:
                if not s:
                    continue
                sfile = s.get("file")
                sline = s.get("line")
                if sfile and sline:
                    sink_map.setdefault((sfile, int(sline)), []).append(data)
            route = data.get("route") or {}
            key = (
                route.get("method") or "",
                route.get("path") or "",
                route.get("controller") or "",
                route.get("action") or "",
            )
            if any(key):
                route_map.setdefault(key, []).append(data)
    return sink_map, route_map, traces


def pick_trace(finding: Dict, sink_map: Dict, route_map: Dict) -> Optional[Dict]:
    sink = finding.get("sink") or {}
    sfile = sink.get("file")
    sline = sink.get("line")
    if sfile and sline:
        hits = sink_map.get((sfile, int(sline)))
        if hits:
            return hits[0]
    route = finding.get("route") or {}
    key = (
        route.get("method") or "",
        route.get("path") or "",
        route.get("controller") or "",
        route.get("action") or "",
    )
    if any(key):
        hits = route_map.get(key)
        if hits:
            return hits[0]
    return None


def ensure_id(f: Dict, prefix: str = "FIND") -> str:
    fid = f.get("id")
    if fid:
        return fid
    sink = f.get("sink") or {}
    fid = stable_id(prefix, sink.get("file"), sink.get("line"), f.get("title") or "")
    f["id"] = fid
    return fid


def load_findings_by_file(out_root: str) -> Dict[str, List[Dict]]:
    files: Dict[str, List[Dict]] = {}
    for root, _, names in os.walk(out_root):
        for n in names:
            if n not in ("findings.json", "auth_evidence.json"):
                continue
            path = os.path.join(root, n)
            try:
                data = json.load(open(path, "r", encoding="utf-8"))
            except Exception:
                continue
            if isinstance(data, list):
                files[path] = data
    return files


def extract_function_block_by_line(text: str, name: str, target_line: Optional[int]) -> Optional[Tuple[int, int, str]]:
    pattern = re.compile(rf"function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{", re.I)
    candidates: List[Tuple[int, int]] = []
    for m in pattern.finditer(text):
        start = m.start()
        start_line = text[:start].count("\\n") + 1
        candidates.append((start_line, m.start()))
    if not candidates:
        return None
    if target_line:
        start_line, start_pos = min(candidates, key=lambda x: abs(x[0] - target_line))
    else:
        start_line, start_pos = candidates[0]
    body_start = text.find("{", start_pos)
    if body_start == -1:
        return None
    depth = 0
    i = body_start
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
        return None
    block = text[start_pos : end + 1]
    end_line = text[: end + 1].count("\\n") + 1
    return start_line, end_line, block


def extract_snippet(text: str, line: int, span: int = 12) -> str:
    lines = text.splitlines()
    if line <= 0:
        return ""
    start = max(1, line - span)
    end = min(len(lines), line + span)
    return "\\n".join(lines[start - 1 : end])


def find_entry_nodes(
    finding: Dict,
    trace: Optional[Dict],
    routes: List[Dict],
    nodes_by_id: Dict[str, Dict],
) -> Tuple[List[str], Optional[str]]:
    route = trace.get("route") if trace else finding.get("route")
    controller_file = find_controller_file(route or {}, routes)
    action = (route or {}).get("action")
    sink = finding.get("sink") or {}
    sink_file = sink.get("file")
    sink_line = sink.get("line")
    if not controller_file and trace and trace.get("entry_file"):
        controller_file = trace.get("entry_file")

    entry_nodes = []
    if controller_file and action:
        for node in nodes_by_id.values():
            if node.get("file") == controller_file and node.get("name") == action:
                entry_nodes.append(node.get("id"))

    if not entry_nodes and controller_file and sink_line:
        candidates = [n for n in nodes_by_id.values() if n.get("file") == controller_file and n.get("line")]
        if candidates:
            chosen = min(candidates, key=lambda n: abs(int(n.get("line")) - int(sink_line)))
            entry_nodes.append(chosen.get("id"))

    if not entry_nodes and sink_file and sink_line:
        candidates = [n for n in nodes_by_id.values() if n.get("file") == sink_file and n.get("line")]
        if candidates:
            chosen = min(candidates, key=lambda n: abs(int(n.get("line")) - int(sink_line)))
            entry_nodes.append(chosen.get("id"))

    return [e for e in entry_nodes if e], controller_file or sink_file


def build_subgraph(entry_ids: List[str], nodes_by_id: Dict[str, Dict], edges: List[Dict]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    if not entry_ids or not nodes_by_id:
        return [], [], []
    adj: Dict[str, List[Dict]] = {}
    for e in edges:
        caller = e.get("caller")
        if not caller:
            continue
        adj.setdefault(caller, []).append(e)

    visited: Set[str] = set(entry_ids)
    queue: List[str] = list(entry_ids)
    sub_edges: List[Dict] = []
    unresolved: List[Dict] = []

    while queue:
        cur = queue.pop(0)
        for e in adj.get(cur, []):
            sub_edges.append(e)
            callee = e.get("callee")
            if callee in nodes_by_id and callee not in visited:
                visited.add(callee)
                queue.append(callee)
            if e.get("unresolved") or callee not in nodes_by_id:
                unresolved.append(e)

    sub_nodes = [nodes_by_id[i] for i in visited if i in nodes_by_id]
    return sub_nodes, sub_edges, unresolved


def build_context(
    out_root: str,
    finding: Dict,
    trace: Optional[Dict],
    routes: List[Dict],
    nodes_by_id: Dict[str, Dict],
    edges: List[Dict],
) -> Dict:
    entry_ids, entry_file = find_entry_nodes(finding, trace, routes, nodes_by_id)
    sub_nodes, sub_edges, unresolved = build_subgraph(entry_ids, nodes_by_id, edges)

    files_needed: Set[str] = set()
    if entry_file:
        files_needed.add(entry_file)
    sink = finding.get("sink") or {}
    if sink.get("file"):
        files_needed.add(sink.get("file"))
    for n in sub_nodes:
        if n.get("file"):
            files_needed.add(n.get("file"))
    for e in unresolved:
        cs = e.get("callsite") or {}
        if cs.get("file"):
            files_needed.add(cs.get("file"))

    file_cache: Dict[str, str] = {}
    for path in sorted(files_needed):
        try:
            file_cache[path] = read_text(path)
        except Exception:
            file_cache[path] = ""

    functions: List[Dict] = []
    for n in sub_nodes:
        path = n.get("file")
        name = n.get("name")
        if not path or not name:
            continue
        text = file_cache.get(path, "")
        block = extract_function_block_by_line(text, name, n.get("line"))
        if block:
            start_line, end_line, func_text = block
        else:
            start_line, end_line, func_text = None, None, ""
        functions.append({
            "id": n.get("id"),
            "name": name,
            "file": path,
            "line": n.get("line"),
            "start_line": start_line,
            "end_line": end_line,
            "text": func_text,
            "snippet": extract_snippet(text, int(n.get("line") or 0)) if not func_text else "",
        })

    unresolved_calls: List[Dict] = []
    for e in unresolved:
        cs = e.get("callsite") or {}
        code_line = ""
        if cs.get("file") and cs.get("line"):
            text = file_cache.get(cs.get("file"), "")
            lines = text.splitlines()
            if 0 < int(cs.get("line")) <= len(lines):
                code_line = lines[int(cs.get("line")) - 1]
        unresolved_calls.append({
            "caller": e.get("caller"),
            "callee": e.get("callee"),
            "callsite": cs,
            "code": code_line,
        })

    context = {
        "finding": finding,
        "trace": trace,
        "call_graph": {
            "entry_nodes": entry_ids,
            "nodes": sub_nodes,
            "edges": sub_edges,
            "unresolved_calls": unresolved_calls,
        },
        "functions": functions,
        "files": file_cache,
    }
    return context


def normalize_exploitability(value: str) -> str:
    if value in ALLOWED_EXPLOITABILITY:
        return value
    if not value:
        return "待验证"
    value = str(value).strip()
    if value in ALLOWED_EXPLOITABILITY:
        return value
    return "待验证"


def validate_ai_result(ai: Dict) -> List[str]:
    issues: List[str] = []
    if not ai.get("id"):
        issues.append("missing:id")
    for k in REQUIRED_TABLE_FIELDS:
        if k not in ai or ai.get(k) in (None, ""):
            issues.append(f"missing:{k}")
    for key in ("reachability", "impact", "complexity"):
        val = ai.get(key)
        if not isinstance(val, dict):
            issues.append(f"{key}:not_object")
            continue
        if "score" not in val:
            issues.append(f"{key}:missing_score")
        if "desc" not in val or not str(val.get("desc") or "").strip():
            issues.append(f"{key}:missing_desc")
    exp = ai.get("exploitability")
    if exp and exp not in ALLOWED_EXPLOITABILITY:
        issues.append("exploitability:invalid")
    evidence = ai.get("evidence")
    if not isinstance(evidence, list) or len(evidence) == 0:
        issues.append("evidence:empty")
    else:
        for idx, ev in enumerate(evidence):
            if not isinstance(ev, dict):
                issues.append(f"evidence:{idx}:not_object")
                continue
            if not ev.get("file"):
                issues.append(f"evidence:{idx}:missing_file")
            if not ev.get("line"):
                issues.append(f"evidence:{idx}:missing_line")
    if ai.get("confidence") is None:
        issues.append("missing:confidence")
    if not ai.get("rationale"):
        issues.append("missing:rationale")
    return issues


def gate_confirm(finding: Dict, trace: Optional[Dict]) -> Tuple[bool, List[str]]:
    issues = []
    source = finding.get("source") or (trace.get("source") if trace else None)
    validation = finding.get("validation")
    if validation is None and trace:
        validation = trace.get("validation")
    controllability = finding.get("controllability") or (trace.get("controllability") if trace else None)
    sink = finding.get("sink") or {}
    sink_type = sink.get("type") or sink.get("function") or ""

    if not source:
        issues.append("missing:source")
    if validation:
        issues.append("validation:present")
    if controllability != "fully":
        issues.append("controllability:not_fully")
    if sink_type not in HIGH_RISK_SINKS:
        issues.append("sink:not_high_risk")

    return len(issues) == 0, issues


def load_ai_results(out_root: str) -> List[Dict]:
    path = os.path.join(out_root, "mcp_raw", "ai-confirm-mcp.json")
    if not os.path.exists(path):
        raise SystemExit("ai-confirm-mcp.json not found. Run AI skill first.")
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"ai-confirm-mcp.json parse error: {exc}")
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    if isinstance(data, list):
        return data
    raise SystemExit("ai-confirm-mcp.json invalid format: expected list or {results: []}")


def hash_context(context: Dict) -> str:
    raw = json.dumps(context, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    routes = load_routes(out_root)
    nodes_by_id, edges = load_call_graph(out_root)
    sink_map, route_map, _ = load_traces(out_root)
    findings_by_file = load_findings_by_file(out_root)

    # Build contexts for all findings
    ctx_root = os.path.join(out_root, "ai_context")
    os.makedirs(ctx_root, exist_ok=True)
    context_hashes: Dict[str, str] = {}
    policy = load_policy()
    min_evidence = int(policy.get("evidence_score_min", 0))

    all_findings: List[Tuple[str, Dict]] = []
    for path, items in findings_by_file.items():
        for f in items:
            fid = ensure_id(f, "AI")
            all_findings.append((path, f))
            trace = pick_trace(f, sink_map, route_map)
            context = build_context(out_root, f, trace, routes, nodes_by_id, edges)
            ctx_dir = os.path.join(ctx_root, fid)
            os.makedirs(ctx_dir, exist_ok=True)
            ctx_path = os.path.join(ctx_dir, "context.json")
            write_json(ctx_path, context)
            context_hashes[fid] = hash_context(context)

    # Load AI results (must exist)
    ai_results = load_ai_results(out_root)
    ai_map = {str(r.get("id")): r for r in ai_results if r.get("id")}

    missing: List[str] = []
    invalid: List[Dict] = []
    downgraded: List[Dict] = []
    updated_files: Set[str] = set()

    for src_path, f in all_findings:
        fid = ensure_id(f, "AI")
        ai = ai_map.get(fid)
        if not ai:
            missing.append(fid)
            continue
        errors = validate_ai_result(ai)
        if errors:
            invalid.append({"id": fid, "errors": errors})
            continue

        ai_table = {
            "title_label": ai.get("title_label"),
            "severity_label": ai.get("severity_label"),
            "reachability": ai.get("reachability"),
            "impact": ai.get("impact"),
            "complexity": ai.get("complexity"),
            "exploitability": normalize_exploitability(ai.get("exploitability")),
            "location": ai.get("location"),
            "trigger": ai.get("trigger"),
            "input_source": ai.get("input_source"),
            "output_mode": ai.get("output_mode"),
            "evidence": ai.get("evidence"),
        }
        ai_table["evidence_summary"] = _evidence_summary(f, ai_table)
        evidence_score = int(f.get("evidence_score") or 0)
        context_incomplete = bool(f.get("context_incomplete"))
        ai_consensus = f.get("ai_consensus") or "unknown"
        poc_quality = f.get("poc_quality") or "weak"
        ai_table["evidence_score"] = evidence_score
        ai_table["context_incomplete"] = context_incomplete
        ai_table["ai_consensus"] = ai_consensus
        ai_table["poc_quality"] = poc_quality
        ai_poc = (ai.get("poc") or "").strip()
        if ai_poc:
            ai_table["poc"] = ai_poc
            ai_table["poc_source"] = "ai"
        else:
            poc, poc_source = _template_poc(f, ai_table)
            ai_table["poc"] = poc
            ai_table["poc_source"] = poc_source

        exploitability = ai_table["exploitability"]
        trace = pick_trace(f, sink_map, route_map)
        ok, issues = gate_confirm(f, trace)
        constraints = list(ai.get("constraints") or [])
        downgrade_reasons: List[str] = []
        if exploitability == "已确认" and not ok:
            downgrade_reasons.extend([f"gate:{i}" for i in issues])
        if exploitability == "已确认" and min_evidence and evidence_score < min_evidence:
            downgrade_reasons.append(f"evidence_score<{min_evidence}")
        if exploitability == "已确认" and context_incomplete:
            downgrade_reasons.append("context_incomplete")
        if exploitability == "已确认" and ai_consensus == "low":
            downgrade_reasons.append("consensus_low")

        if exploitability == "已确认" and downgrade_reasons:
            exploitability = "高可能"
            constraints.extend(downgrade_reasons)
            downgraded.append({"id": fid, "reasons": downgrade_reasons})
            ai_table["exploitability"] = exploitability

        f["ai_table"] = ai_table
        f["exploitability"] = exploitability
        f["reachability"] = ai_table["reachability"]
        f["impact"] = ai_table["impact"]
        f["complexity"] = ai_table["complexity"]
        f["ai_confirm"] = {
            "provider": "skill",
            "confidence": ai.get("confidence"),
            "rationale": ai.get("rationale"),
            "constraints": constraints,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "input_hash": context_hashes.get(fid),
        }
        updated_files.add(src_path)

    for path in updated_files:
        write_json(path, findings_by_file[path])

    report = {
        "total": len(all_findings),
        "updated": len(updated_files),
        "missing": missing,
        "invalid": invalid,
        "downgraded": downgraded,
    }
    write_json(os.path.join(out_root, "ai_confirm.json"), report)

    if missing or invalid:
        raise SystemExit(f"AI confirmation missing/invalid for {len(missing)} missing, {len(invalid)} invalid.")
    print(f"AI confirmation complete. Findings: {len(all_findings)}")


if __name__ == "__main__":
    main()
