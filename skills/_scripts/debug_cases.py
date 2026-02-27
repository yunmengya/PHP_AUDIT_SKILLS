#!/usr/bin/env python3
import argparse
import json
import os
import re
from typing import Any, Dict, List, Tuple

from common import build_output_root, write_json, write_text
from audit_helpers import markdown_table


MODULE_VULN_TYPE = {
    "sql_audit": "sql_injection",
    "rce_audit": "command_exec",
    "file_audit": "file",
    "ssrf_xxe_audit": "ssrf_xxe",
    "xss_ssti_audit": "xss_ssti",
    "csrf_audit": "csrf",
    "var_override_audit": "variable_override",
    "serialize_audit": "deserialization",
    "auth_audit": "authz",
    "vuln_report": "dependency",
}

WORDLIST_BY_SINK = {
    "sql": "sql.txt",
    "sql_injection": "sql.txt",
    "rce": "rce.txt",
    "command_exec": "rce.txt",
    "file": "file.txt",
    "ssrf": "ssrf.txt",
    "xxe": "xxe.txt",
    "ssrf_xxe": "ssrf.txt",
    "xss": "xss.txt",
    "ssti": "xss.txt",
    "xss_ssti": "xss.txt",
    "deserialize": "deserialize.txt",
    "deserialization": "deserialize.txt",
    "csrf": "csrf.txt",
}

BUCKET_PRIORITY = ["GET", "POST", "BODY", "COOKIE", "HEADER"]
METHOD_CHOICES = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}


def load_findings(out_root: str) -> List[Tuple[Dict[str, Any], str]]:
    items: List[Tuple[Dict[str, Any], str]] = []
    for root, _, files in os.walk(out_root):
        for name in files:
            if name not in ("findings.json", "auth_evidence.json"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            if isinstance(data, list):
                for it in data:
                    if isinstance(it, dict):
                        items.append((it, path))
    return items


def module_from_source(source_path: str, out_root: str) -> str:
    rel = os.path.relpath(source_path, out_root)
    parts = rel.split(os.sep)
    return parts[0] if parts else "unknown"


def rel_path(path: str, project_root: str) -> str:
    if not path:
        return "-"
    try:
        abs_path = os.path.abspath(path)
        project_abs = os.path.abspath(project_root)
        if abs_path.startswith(project_abs + os.sep) or abs_path == project_abs:
            return os.path.relpath(abs_path, project_abs)
        if os.path.isabs(path):
            return path.lstrip(os.sep)
    except Exception:
        pass
    return path


def build_trace_chain(finding: Dict[str, Any], project_root: str) -> List[Dict[str, Any]]:
    chain: List[Dict[str, Any]] = []
    source = finding.get("source") or {}
    if isinstance(source, dict) and source.get("file"):
        chain.append(
            {
                "file": rel_path(str(source.get("file")), project_root),
                "line": source.get("line"),
                "code": source.get("code") or "source",
            }
        )

    taint = finding.get("taint")
    if isinstance(taint, list):
        for node in taint:
            if not isinstance(node, dict):
                continue
            if not node.get("file"):
                continue
            chain.append(
                {
                    "file": rel_path(str(node.get("file")), project_root),
                    "line": node.get("line"),
                    "code": node.get("code") or "taint",
                }
            )

    sink = finding.get("sink") or {}
    if isinstance(sink, dict) and sink.get("file"):
        chain.append(
            {
                "file": rel_path(str(sink.get("file")), project_root),
                "line": sink.get("line"),
                "code": sink.get("code") or "sink",
            }
        )
    return chain


def build_entry(finding: Dict[str, Any]) -> str:
    route = finding.get("route") or {}
    if isinstance(route, dict) and (route.get("method") or route.get("path")):
        return f"{route.get('method', '')} {route.get('path', '')}".strip()
    return str(finding.get("entry") or "-")


def normalize_method(value: str, input_map: Dict[str, Any]) -> str:
    if value:
        raw = str(value).split("|")[0].strip().upper()
        if raw in METHOD_CHOICES:
            if raw == "ANY":
                return "GET"
            return raw
    if isinstance(input_map.get("POST"), dict) and input_map.get("POST"):
        return "POST"
    if isinstance(input_map.get("BODY"), dict) and input_map.get("BODY"):
        return "POST"
    return "GET"


def normalize_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "/"
    if text.startswith("http://") or text.startswith("https://"):
        return text
    if text.startswith("/"):
        return text
    return "/" + text


def build_route_method_path(finding: Dict[str, Any], input_map: Dict[str, Any]) -> Tuple[str, str]:
    route = finding.get("route") or {}
    if not isinstance(route, dict):
        return normalize_method("", input_map), "/"
    method = normalize_method(str(route.get("method") or ""), input_map)
    path = normalize_path(str(route.get("path") or ""))
    return method, path


def normalize_bucket(value: str) -> str:
    v = str(value or "").strip().upper()
    if v in BUCKET_PRIORITY:
        return v
    if v in ("REQUEST", "PARAM", "QUERY"):
        return "GET"
    if v in ("FORM",):
        return "POST"
    return "GET"


def first_key(bucket: Any, default_key: str = "payload") -> str:
    if isinstance(bucket, dict) and bucket:
        return str(next(iter(bucket.keys())))
    return default_key


def build_input_map(finding: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    poc = finding.get("poc") or {}
    if isinstance(poc, dict):
        params = poc.get("params")
        if isinstance(params, dict) and params:
            return {"GET": params}
        body = poc.get("body")
        if isinstance(body, dict) and body:
            return {"POST": body}

    source = finding.get("source") or {}
    param = source.get("param") if isinstance(source, dict) else None
    if param:
        kind = normalize_bucket(str(source.get("kind") or "GET"))
        return {kind: {str(param): "__INPUT__"}}
    return {}


def build_input_value(input_map: Dict[str, Dict[str, Any]]) -> str:
    for bucket_name in BUCKET_PRIORITY:
        bucket = input_map.get(bucket_name) or {}
        if isinstance(bucket, dict) and bucket:
            first = next(iter(bucket.keys()))
            return str(bucket.get(first))
    return ""


def sink_type_of(module: str, finding: Dict[str, Any]) -> str:
    sink = finding.get("sink") or {}
    if isinstance(sink, dict) and sink.get("type"):
        return str(sink.get("type")).strip().lower()
    return MODULE_VULN_TYPE.get(module, module)


def _extract_bucket_param_from_input_source(text: str) -> Tuple[str, str]:
    src = str(text or "")
    if not src:
        return "", ""

    m = re.search(r"\$_(GET|POST|COOKIE|REQUEST|SERVER)\[['\"]([^'\"]+)['\"]\]", src, re.I)
    if m:
        bucket = normalize_bucket(m.group(1))
        param = str(m.group(2)).strip()
        if bucket == "SERVER":
            bucket = "HEADER"
        if param:
            return bucket, param

    m = re.search(r"\b(GET|POST|BODY|COOKIE|HEADER|REQUEST)\s*:\s*([A-Za-z0-9_\-]+)", src, re.I)
    if m:
        return normalize_bucket(m.group(1)), str(m.group(2)).strip()

    m = re.search(r"\b(query|body|param|params)\.([A-Za-z0-9_\-]+)", src, re.I)
    if m:
        bucket = "GET" if m.group(1).lower() in ("query", "param", "params") else "BODY"
        return bucket, str(m.group(2)).strip()

    m = re.search(r"\b(input|param|get|post)\(\s*['\"]([^'\"]+)['\"]", src, re.I)
    if m:
        fn = str(m.group(1)).lower()
        bucket = "POST" if fn == "post" else "GET"
        return bucket, str(m.group(2)).strip()

    m = re.search(r":\s*([A-Za-z0-9_\-]+)", src)
    if m:
        return "GET", str(m.group(1)).strip()

    return "", ""


def _candidate_key(candidate: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    return (
        str(candidate.get("method") or "GET").upper(),
        normalize_path(str(candidate.get("path") or "/")),
        normalize_bucket(str(candidate.get("bucket") or "GET")),
        str(candidate.get("param") or "payload"),
        str(candidate.get("content_type") or "").lower(),
    )


def _bucket_priority_score(bucket: str) -> int:
    b = normalize_bucket(bucket)
    if b in BUCKET_PRIORITY:
        return len(BUCKET_PRIORITY) - BUCKET_PRIORITY.index(b)
    return 0


def _append_candidate(
    result: List[Dict[str, Any]],
    seen: Dict[Tuple[str, str, str, str, str], int],
    method: str,
    path: str,
    bucket: str,
    param: str,
    content_type: str,
    score: int,
    reason: str,
    source: str,
) -> None:
    cand = {
        "method": normalize_method(method, {}),
        "path": normalize_path(path),
        "bucket": normalize_bucket(bucket),
        "param": str(param or "payload"),
        "content_type": str(content_type or "").strip(),
        "score": int(score),
        "reason": str(reason),
        "source": str(source),
    }
    key = _candidate_key(cand)
    idx = seen.get(key)
    if idx is None:
        seen[key] = len(result)
        result.append(cand)
        return

    current = result[idx]
    if cand["score"] > int(current.get("score") or 0):
        result[idx] = cand
    elif cand["reason"] and cand["reason"] not in str(current.get("reason") or ""):
        result[idx]["reason"] = f"{current.get('reason')} | {cand['reason']}".strip(" |")


def build_request_plan(
    finding: Dict[str, Any],
    module: str,
    route_method: str,
    route_path: str,
    input_map: Dict[str, Any],
    sink_type: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], int, List[str], str]:
    candidates: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, str, str, str, str], int] = {}
    planning_source = "rules"

    source = finding.get("source") or {}
    source_kind = normalize_bucket(str(source.get("kind") or "GET")) if isinstance(source, dict) else "GET"
    source_param = str(source.get("param") or "").strip() if isinstance(source, dict) else ""

    default_method = normalize_method(route_method, input_map)
    default_path = normalize_path(route_path)

    if source_param:
        _append_candidate(
            candidates,
            seen,
            default_method,
            default_path,
            source_kind,
            source_param,
            "",
            95 + _bucket_priority_score(source_kind),
            "source.kind/source.param",
            "rules",
        )

    for bucket_name in BUCKET_PRIORITY:
        bucket = input_map.get(bucket_name)
        if not isinstance(bucket, dict) or not bucket:
            continue
        for key in bucket.keys():
            _append_candidate(
                candidates,
                seen,
                default_method,
                default_path,
                bucket_name,
                str(key),
                "application/json" if bucket_name == "BODY" else "",
                85 + _bucket_priority_score(bucket_name),
                f"input_map.{bucket_name}",
                "rules",
            )

    raw_poc = finding.get("poc")
    if isinstance(raw_poc, dict):
        poc_method = normalize_method(str(raw_poc.get("method") or default_method), input_map)
        poc_path = normalize_path(str(raw_poc.get("path") or default_path))
        params = raw_poc.get("params")
        if isinstance(params, dict) and params:
            key = str(next(iter(params.keys())))
            _append_candidate(
                candidates,
                seen,
                poc_method,
                poc_path,
                "GET",
                key,
                "",
                88,
                "finding.poc.params",
                "rules",
            )
        body = raw_poc.get("body")
        if isinstance(body, dict) and body:
            key = str(next(iter(body.keys())))
            _append_candidate(
                candidates,
                seen,
                poc_method,
                poc_path,
                "BODY",
                key,
                "application/json",
                88,
                "finding.poc.body",
                "rules",
            )

    if not candidates:
        _append_candidate(
            candidates,
            seen,
            default_method,
            default_path,
            "GET",
            "payload",
            "",
            70,
            "fallback_default",
            "rules",
        )

    ai_table = finding.get("ai_table") or {}
    if isinstance(ai_table, dict) and ai_table:
        planning_source = "rules+ai_artifacts"
        ai_bucket, ai_param = _extract_bucket_param_from_input_source(str(ai_table.get("input_source") or ""))
        if ai_bucket and ai_param:
            _append_candidate(
                candidates,
                seen,
                default_method,
                default_path,
                ai_bucket,
                ai_param,
                "",
                110 + _bucket_priority_score(ai_bucket),
                "ai_table.input_source",
                "ai_artifact",
            )

        ai_poc = ai_table.get("poc")
        if isinstance(ai_poc, dict):
            poc_method = normalize_method(str(ai_poc.get("method") or default_method), input_map)
            poc_path = normalize_path(str(ai_poc.get("path") or default_path))
            params = ai_poc.get("params") if isinstance(ai_poc.get("params"), dict) else {}
            body = ai_poc.get("body") if isinstance(ai_poc.get("body"), dict) else {}
            if params:
                _append_candidate(
                    candidates,
                    seen,
                    poc_method,
                    poc_path,
                    "GET",
                    str(next(iter(params.keys()))),
                    "",
                    112,
                    "ai_table.poc.params",
                    "ai_artifact",
                )
            if body:
                _append_candidate(
                    candidates,
                    seen,
                    poc_method,
                    poc_path,
                    "BODY",
                    str(next(iter(body.keys()))),
                    "application/json",
                    112,
                    "ai_table.poc.body",
                    "ai_artifact",
                )
        elif isinstance(ai_poc, str) and ai_poc:
            m = re.search(r"\bcurl\b.*?\s-X\s+([A-Za-z]+)", ai_poc, re.I)
            ai_method = normalize_method(m.group(1) if m else default_method, input_map)
            url_match = re.search(r"https?://[^\s'\"]+", ai_poc)
            ai_path = default_path
            if url_match:
                url = url_match.group(0)
                path_start = url.find("/", url.find("//") + 2)
                ai_path = normalize_path(url[path_start:] if path_start != -1 else "/")
            _append_candidate(
                candidates,
                seen,
                ai_method,
                ai_path,
                source_kind,
                source_param or "payload",
                "",
                105,
                "ai_table.poc_string",
                "ai_artifact",
            )

    candidates.sort(
        key=lambda c: (
            int(c.get("score") or 0),
            _bucket_priority_score(str(c.get("bucket") or "GET")),
            str(c.get("method") or "GET"),
        ),
        reverse=True,
    )

    best = candidates[0] if candidates else {
        "method": default_method,
        "path": default_path,
        "bucket": "GET",
        "param": "payload",
        "content_type": "",
        "score": 0,
        "reason": "fallback_default",
        "source": "rules",
    }

    planning_score = int(best.get("score") or 0)
    planning_reasons: List[str] = []
    for cand in candidates[:3]:
        reason = str(cand.get("reason") or "").strip()
        if reason and reason not in planning_reasons:
            planning_reasons.append(reason)

    if sink_type and sink_type in WORDLIST_BY_SINK:
        planning_reasons.append(f"wordlist:{WORDLIST_BY_SINK[sink_type]}")

    return candidates, best, planning_score, planning_reasons, planning_source


def ensure_slice_template(path: str, case_id: str) -> None:
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = f"""<?php
// Debug slice template for {case_id}
// 说明：补充必要的 include/require，然后把进入 sink 前的最终变量赋值给 $final_value

$inputMap = json_decode(getenv('DEBUG_INPUT_JSON') ?: '{{}}', true);
$_GET = $inputMap['GET'] ?? [];
$_POST = $inputMap['POST'] ?? [];
$_COOKIE = $inputMap['COOKIE'] ?? [];
$_SERVER = array_merge($_SERVER, $inputMap['HEADER'] ?? []);

$input_value = '';
foreach (['GET','POST','COOKIE','HEADER','BODY'] as $k) {{
    if (!empty($inputMap[$k]) && is_array($inputMap[$k])) {{
        $firstKey = array_key_first($inputMap[$k]);
        $input_value = (string)($inputMap[$k][$firstKey] ?? '');
        break;
    }}
}}

// TODO: 在这里调用目标代码
$final_value = '__TODO__';

$result = [
    'status' => 'pending',
    'input' => $input_value,
    'final_value' => $final_value,
    'transform_chain' => [],
    'notes' => 'TODO: 填写 final_value 并补充 transform_chain'
];

echo json_encode($result, JSON_UNESCAPED_UNICODE);
"""
    write_text(path, content)


def render_poc_plan_md(cases: List[Dict[str, Any]]) -> str:
    rows: List[List[str]] = []
    for case in cases:
        best = case.get("best_request") or {}
        rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("vuln_type") or "-"),
                str(best.get("method") or "-"),
                str(best.get("path") or "-"),
                str(best.get("bucket") or "-"),
                str(best.get("param") or "-"),
                str(case.get("planning_source") or "-"),
                str(case.get("planning_score") or "-"),
                " | ".join(case.get("planning_reasons") or []) or "-",
            ]
        )
    return (
        "# Debug 请求规划\n\n"
        + markdown_table(
            ["编号", "漏洞类型", "方法", "路径", "注入桶", "参数", "来源", "分数", "原因"],
            rows,
        )
        + "\n"
    )


def generate_cases(project_root: str, out_root: str) -> str:
    cases: List[Dict[str, Any]] = []

    for finding, source_path in load_findings(out_root):
        case_id = str(finding.get("id") or "UNSET")
        module = module_from_source(source_path, out_root)
        vuln_type = MODULE_VULN_TYPE.get(module, module)

        input_map = build_input_map(finding)
        route_method, route_path = build_route_method_path(finding, input_map)
        sink_type = sink_type_of(module, finding)

        request_candidates, best_request, planning_score, planning_reasons, planning_source = build_request_plan(
            finding,
            module,
            route_method,
            route_path,
            input_map,
            sink_type,
        )

        sink = finding.get("sink") or {}
        sink_rel = sink.copy() if isinstance(sink, dict) else {}
        if isinstance(sink_rel, dict) and sink_rel.get("file"):
            sink_rel["file"] = rel_path(str(sink_rel.get("file")), project_root)

        trace_chain = build_trace_chain(finding, project_root)
        source_path_rel = "unknown:0"
        if isinstance(sink_rel, dict) and sink_rel.get("file") and sink_rel.get("line"):
            source_path_rel = f"{sink_rel.get('file')}:{sink_rel.get('line')}"
        elif trace_chain:
            tail = trace_chain[-1]
            if tail.get("file") and tail.get("line"):
                source_path_rel = f"{tail.get('file')}:{tail.get('line')}"

        if not trace_chain:
            trace_chain = [{"file": "unknown", "line": 0, "code": "unknown"}]

        case: Dict[str, Any] = {
            "case_id": case_id,
            "module": module,
            "vuln_type": vuln_type,
            "sink_type": sink_type,
            "entry": build_entry(finding),
            "route_method": route_method,
            "route_path": route_path,
            "raw_poc": finding.get("poc"),
            "input": build_input_value(input_map),
            "input_map": input_map,
            "sink": sink_rel,
            "trace_chain": trace_chain,
            "source_path": source_path_rel,
            "request_candidates": request_candidates,
            "best_request": best_request,
            "planning_score": planning_score,
            "planning_reasons": planning_reasons,
            "planning_source": planning_source,
            "debug_script": os.path.join(out_root, "debug_verify", "slices", f"{case_id}.php"),
        }
        cases.append(case)

    debug_dir = os.path.join(out_root, "debug_verify")
    os.makedirs(debug_dir, exist_ok=True)

    cases_path = os.path.join(debug_dir, "debug_cases.json")
    poc_plan_path = os.path.join(debug_dir, "poc_plan.json")
    poc_plan_md_path = os.path.join(debug_dir, "poc_plan.md")

    write_json(cases_path, cases)
    write_json(
        poc_plan_path,
        [
            {
                "case_id": case.get("case_id"),
                "vuln_type": case.get("vuln_type"),
                "best_request": case.get("best_request"),
                "request_candidates": case.get("request_candidates"),
                "planning_score": case.get("planning_score"),
                "planning_reasons": case.get("planning_reasons"),
                "planning_source": case.get("planning_source"),
            }
            for case in cases
        ],
    )
    write_text(poc_plan_md_path, render_poc_plan_md(cases))

    for case in cases:
        ensure_slice_template(str(case.get("debug_script")), str(case.get("case_id")))

    return cases_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="PHP project root")
    parser.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = parser.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    cases_path = generate_cases(project_root, out_root)
    print(f"debug_cases.json written: {cases_path}")


if __name__ == "__main__":
    main()
