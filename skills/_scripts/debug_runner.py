#!/usr/bin/env python3
import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from common import build_output_root, write_json, write_text
from audit_helpers import markdown_table
from debug_cases import generate_cases, WORDLIST_BY_SINK, BUCKET_PRIORITY
from auto_slice import generate_slice_for_case

RULES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "php-audit-common", "references", "debug_change_rules.yml")
)
WORDLIST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wordlists"))
CURL_EXEC_TIMEOUT_SEC = 15
HTTP_SERVER_START_TIMEOUT_SEC = 5

RESULT_VALUES = {"confirmed", "conditional", "rejected", "skipped"}
CHANGE_VALUES = {"no_change", "weak_change", "strong_change", "unknown"}

CATEGORY_RULES = {
    "sql_audit": "input_limit",
    "rce_audit": "input_limit",
    "file_audit": "input_limit",
    "var_override_audit": "input_limit",
    "serialize_audit": "input_limit",
    "xss_ssti_audit": "output_encoding",
    "ssrf_xxe_audit": "url_restriction",
    "csrf_audit": "input_limit",
    "auth_audit": "auth_logic",
    "vuln_report": "dependency",
}


def running_in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    cgroup_path = "/proc/1/cgroup"
    if os.path.exists(cgroup_path):
        try:
            with open(cgroup_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read().lower()
            return ("docker" in text) or ("containerd" in text) or ("kubepods" in text)
        except Exception:
            return False
    return False


def ensure_running_in_container() -> None:
    if running_in_container():
        return
    raise SystemExit("Use skills/docker/run_debug.sh")


def tail_text(text: str, max_chars: int = 2000, max_lines: int = 20) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    tail = "\n".join(lines[-max_lines:])
    if len(tail) > max_chars:
        tail = tail[-max_chars:]
    return tail


def load_change_rules(path: str) -> Dict[str, List[str]]:
    rules = {"weak_change": [], "strong_change": []}
    if not os.path.exists(path):
        return rules
    current = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.endswith(":"):
                    key = line[:-1].strip()
                    current = key if key in rules else None
                    continue
                if line.startswith("-") and current:
                    value = line[1:].strip()
                    if value:
                        rules[current].append(value)
    except Exception:
        return rules
    return rules


def classify_change(
    input_val: str,
    final_val: str,
    transform_chain: List[str],
    rules: Dict[str, List[str]],
    explicit: str = "",
) -> str:
    if explicit in CHANGE_VALUES:
        return explicit
    if input_val == final_val:
        return "no_change"
    if transform_chain:
        for item in transform_chain:
            if item in rules.get("strong_change", []):
                return "strong_change"
        for item in transform_chain:
            if item in rules.get("weak_change", []):
                return "weak_change"
    return "weak_change"


def decide_result(category: str, change_type: str) -> str:
    if change_type == "unknown":
        return "skipped"
    if category in ("input_limit", "output_encoding", "url_restriction"):
        if change_type == "no_change":
            return "confirmed"
        if change_type == "weak_change":
            return "conditional"
        return "rejected"
    if category == "auth_logic":
        if change_type == "strong_change":
            return "rejected"
        if change_type == "no_change":
            return "conditional"
        return "conditional"
    if category == "dependency":
        return "conditional"
    return "conditional"


def parse_debug_output(stdout: str) -> Tuple[Dict[str, Any], str]:
    last_json: Optional[Dict[str, Any]] = None
    for line in stdout.splitlines()[::-1]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
            except Exception:
                continue
            if isinstance(parsed, dict):
                last_json = parsed
                break
    if not last_json:
        return {}, "no_json_output"
    return last_json, ""


def run_php_script(script_path: str, input_map: Dict[str, Any]) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    meta: Dict[str, Any] = {
        "return_code": None,
        "duration_ms": 0,
        "stdout_tail": "",
        "stderr_tail": "",
    }
    start = time.perf_counter()

    if not os.path.exists(script_path):
        meta["duration_ms"] = int((time.perf_counter() - start) * 1000)
        return {}, "script_missing", meta

    php = shutil.which("php")
    if not php:
        meta["duration_ms"] = int((time.perf_counter() - start) * 1000)
        return {}, "php_not_found", meta

    env = os.environ.copy()
    env["DEBUG_INPUT_JSON"] = json.dumps(input_map or {}, ensure_ascii=False)

    try:
        proc = subprocess.run([php, script_path], capture_output=True, text=True, env=env)
    except Exception:
        meta["duration_ms"] = int((time.perf_counter() - start) * 1000)
        return {}, "exec_failed", meta

    meta["return_code"] = proc.returncode
    meta["duration_ms"] = int((time.perf_counter() - start) * 1000)
    meta["stdout_tail"] = tail_text(proc.stdout or "")
    meta["stderr_tail"] = tail_text(proc.stderr or "")

    if proc.returncode != 0:
        return {}, "exec_failed", meta

    data, err = parse_debug_output(proc.stdout)
    if err:
        return {}, err, meta
    return data, "", meta


def php_quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def wait_tcp_ready(host: str, port: int, timeout_sec: int, proc: subprocess.Popen) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            s.close()
            time.sleep(0.1)
    return False


def pick_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def build_slice_router_php(slice_path: str) -> str:
    slice_q = php_quote(slice_path)
    return f"""<?php
header('Content-Type: application/json; charset=utf-8');

$headers = [];
foreach ($_SERVER as $k => $v) {{
    if (strpos($k, 'HTTP_') === 0) {{
        $name = str_replace('_', '-', substr($k, 5));
        $headers[$name] = $v;
    }}
}}

$rawBody = file_get_contents('php://input');
$bodyMap = [];
$decoded = json_decode($rawBody, true);
if (is_array($decoded)) {{
    $bodyMap = $decoded;
}} elseif (!empty($_POST)) {{
    $bodyMap = $_POST;
}} elseif (is_string($rawBody) && strlen($rawBody) > 0) {{
    $bodyMap = ['payload' => $rawBody];
}}

$inputMap = [
    'GET' => $_GET ?? [],
    'POST' => $_POST ?? [],
    'COOKIE' => $_COOKIE ?? [],
    'HEADER' => $headers,
];
if (!empty($bodyMap)) {{
    $inputMap['BODY'] = $bodyMap;
}}

putenv('DEBUG_INPUT_JSON=' . json_encode($inputMap, JSON_UNESCAPED_UNICODE));
require '{slice_q}';
"""


def start_case_http_server(case: Dict[str, Any], out_root: str) -> Tuple[Optional[Dict[str, Any]], str]:
    slice_path = str(case.get("debug_script") or "")
    if not slice_path or not os.path.exists(slice_path):
        return None, "script_missing"

    php = shutil.which("php")
    curl = shutil.which("curl")
    if not php:
        return None, "php_not_found"
    if not curl:
        return None, "curl_not_found"

    runtime_root = os.path.join(out_root, "debug_verify", "http_runtime")
    os.makedirs(runtime_root, exist_ok=True)

    case_id = str(case.get("case_id") or "case")
    work_dir = tempfile.mkdtemp(prefix=f"{case_id}_", dir=runtime_root)
    router_path = os.path.join(work_dir, "router.php")
    write_text(router_path, build_slice_router_php(slice_path))

    port = pick_free_port()
    proc = subprocess.Popen(
        [php, "-S", f"127.0.0.1:{port}", router_path],
        cwd=work_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if not wait_tcp_ready("127.0.0.1", port, HTTP_SERVER_START_TIMEOUT_SEC, proc):
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return None, "http_server_start_failed"

    return {
        "mode": "curl_http",
        "host": "127.0.0.1",
        "port": port,
        "base_url": f"http://127.0.0.1:{port}",
        "process": proc,
        "work_dir": work_dir,
        "router_path": router_path,
    }, ""


def stop_case_http_server(server: Optional[Dict[str, Any]]) -> None:
    if not isinstance(server, dict):
        return
    proc = server.get("process")
    if not isinstance(proc, subprocess.Popen):
        return
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=1)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def extract_http_status(raw: str) -> Optional[int]:
    status = None
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line.startswith("HTTP/"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[1].isdigit():
            status = int(parts[1])
    return status


def split_http_response(raw: str) -> Tuple[str, str]:
    text = raw or ""
    marker = "\r\n\r\n"
    idx = text.rfind(marker)
    if idx != -1:
        return text[:idx], text[idx + len(marker) :]
    marker = "\n\n"
    idx = text.rfind(marker)
    if idx != -1:
        return text[:idx], text[idx + len(marker) :]
    return "", text


def extract_http_body(raw: str) -> str:
    _, body = split_http_response(raw)
    return body


def ensure_cases(out_root: str, project_root: str) -> str:
    return generate_cases(project_root, out_root)


def compact_cell(value: Any, max_len: int = 160) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\n", "\\n")
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def render_md(rows: List[Dict[str, Any]]) -> str:
    table_rows: List[List[str]] = []
    change_map = {
        "no_change": "无变化",
        "weak_change": "弱变化",
        "strong_change": "强变化",
        "unknown": "未知",
    }
    result_map = {
        "confirmed": "成立",
        "conditional": "条件成立",
        "rejected": "不成立",
        "skipped": "跳过",
    }
    for row in rows:
        change_raw = str(row.get("change_type") or "-")
        change_cn = change_map.get(change_raw, "未知")
        change_label = f"{change_cn}({change_raw})" if change_raw not in ("-", "") else "-"

        result_raw = str(row.get("result") or "-")
        result_cn = result_map.get(result_raw, "未知")
        result_label = f"{result_cn}({result_raw})" if result_raw not in ("-", "") else "-"

        table_rows.append(
            [
                str(row.get("case_id") or "-"),
                str(row.get("vuln_type") or "-"),
                result_label,
                change_label,
                str(row.get("attempt_count") or 0),
                str(row.get("payload_source") or "-"),
                str(row.get("request_source") or "-"),
                compact_cell(row.get("payload_used") or "-", max_len=80),
                compact_cell(row.get("poc_cmd") or "-", max_len=120),
                compact_cell(row.get("notes") or "-"),
            ]
        )

    return (
        "# Debug 验证证据\n\n"
        + markdown_table(
            ["编号", "漏洞类型", "判定", "变化", "尝试数", "Payload来源", "请求来源", "Payload", "PoC", "备注"],
            table_rows,
        )
        + "\n"
    )


def render_process_md(rows: List[Dict[str, Any]]) -> str:
    table_rows: List[List[str]] = []
    for row in rows:
        dynamic_reasons = row.get("dynamic_reasons")
        if isinstance(dynamic_reasons, list) and dynamic_reasons:
            dynamic_text = " | ".join([str(x) for x in dynamic_reasons if str(x).strip()])
        else:
            dynamic_text = "-"
        table_rows.append(
            [
                str(row.get("case_id") or "-"),
                str(row.get("status") or "-"),
                str(row.get("return_code") if row.get("return_code") is not None else "-"),
                str(row.get("http_status") if row.get("http_status") is not None else "-"),
                str(row.get("execution_mode") or "-"),
                str(row.get("duration_ms") if row.get("duration_ms") is not None else "-"),
                "Y" if row.get("sink_probe_hit") else "N",
                "Y" if row.get("taint_var_reached_sink") else "N",
                str(row.get("request_attempt_count") or 0),
                str(row.get("dictionary_attempt_count") or 0),
                str(row.get("ai_attempt_count") or 0),
                str(row.get("ai_realtime_status") or "-"),
                str(row.get("matched_attempt_index") or "-"),
                compact_cell(row.get("trace_case_file") or "-", max_len=120),
                compact_cell(row.get("error_reason") or "-"),
                compact_cell(dynamic_text, max_len=120),
                compact_cell(row.get("curl_cmd") or "-", max_len=120),
                compact_cell(row.get("request_preview") or "-", max_len=160),
                compact_cell(row.get("response_header_preview") or "-", max_len=160),
                compact_cell(row.get("response_body_preview") or "-", max_len=160),
                compact_cell(row.get("stdout_tail") or "-"),
                compact_cell(row.get("stderr_tail") or "-"),
            ]
        )

    return (
        "# Debug 过程记录\n\n"
        + markdown_table(
            [
                "编号",
                "状态",
                "返回码",
                "HTTP码",
                "执行模式",
                "耗时(ms)",
                "Sink命中",
                "Taint达Sink",
                "总尝试",
                "字典尝试",
                "AI尝试",
                "AI状态",
                "命中序号",
                "Trace文件",
                "错误",
                "动态原因",
                "curl命令",
                "请求预览",
                "响应头预览",
                "响应体预览",
                "stdout尾部",
                "stderr尾部",
            ],
            table_rows,
        )
        + "\n"
    )


def summarize_transform_steps(steps: Any, max_steps: int = 5) -> str:
    if not isinstance(steps, list) or not steps:
        return "-"
    out: List[str] = []
    for step in steps[:max_steps]:
        if not isinstance(step, dict):
            continue
        idx = step.get("step")
        expr = str(step.get("expr") or "").strip()
        op = str(step.get("op") or "").strip()
        before = compact_cell(step.get("before") or "", max_len=40)
        after = compact_cell(step.get("after") or "", max_len=40)
        out.append(f"#{idx}:{op}:{expr}:{before}->{after}")
    return " | ".join(out) if out else "-"


def build_transform_diffs(steps: Any, max_steps: int = 20) -> List[Dict[str, Any]]:
    if not isinstance(steps, list) or not steps:
        return []
    rows: List[Dict[str, Any]] = []
    for step in steps[:max_steps]:
        if not isinstance(step, dict):
            continue
        before = str(step.get("before") or "")
        after = str(step.get("after") or "")
        rows.append(
            {
                "step": int(step.get("step") or 0),
                "expr": str(step.get("expr") or ""),
                "op": str(step.get("op") or ""),
                "changed": before != after,
                "before": before,
                "after": after,
            }
        )
    return rows


def summarize_call_stack(stack: Any, max_frames: int = 4) -> str:
    if not isinstance(stack, list) or not stack:
        return "-"
    out: List[str] = []
    for frame in stack[:max_frames]:
        if not isinstance(frame, dict):
            continue
        cls = str(frame.get("class") or "")
        fn = str(frame.get("function") or "")
        line = frame.get("line")
        target = f"{cls}{frame.get('type') or ''}{fn}" if cls else fn
        if not target:
            target = "unknown"
        out.append(f"{target}@{line if line is not None else '?'}")
    return " -> ".join(out) if out else "-"


def render_func_trace_md(rows: List[Dict[str, Any]]) -> str:
    table_rows: List[List[str]] = []
    detail_blocks: List[str] = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("case_id") or "-"),
                str(row.get("result") or "-"),
                str(row.get("execution_mode") or "-"),
                "Y" if row.get("sink_probe_hit") else "N",
                "Y" if row.get("taint_var_reached_sink") else "N",
                str(row.get("transform_step_count") or 0),
                compact_cell(row.get("before_sink") or "-", max_len=80),
                compact_cell(row.get("after_sink") or "-", max_len=80),
                compact_cell(row.get("transform_summary") or "-", max_len=180),
                compact_cell(row.get("call_stack_summary") or "-", max_len=180),
            ]
        )
        case_id = str(row.get("case_id") or "-")
        sink_frame = row.get("sink_keyframe") if isinstance(row.get("sink_keyframe"), dict) else {}
        diffs = row.get("transform_diffs") if isinstance(row.get("transform_diffs"), list) else []

        step_lines: List[str] = []
        for diff in diffs[:12]:
            if not isinstance(diff, dict):
                continue
            marker = "CHANGED" if diff.get("changed") else "SAME"
            step_lines.append(
                f"{diff.get('step')}. [{marker}] {diff.get('op')} | {diff.get('expr')}\n"
                f"   before: {compact_cell(diff.get('before') or '', max_len=120)}\n"
                f"   after : {compact_cell(diff.get('after') or '', max_len=120)}"
            )
        if not step_lines:
            step_lines.append("no transform steps")

        detail_blocks.append(
            "\n".join(
                [
                    f"## {case_id}",
                    f"- Result: {row.get('result') or '-'}",
                    f"- Sink Probe Hit: {bool(row.get('sink_probe_hit'))}",
                    f"- Taint Reached Sink: {bool(row.get('taint_var_reached_sink'))}",
                    f"- Trace File: {row.get('trace_case_file') or '-'}",
                    "",
                    "Sink Keyframe:",
                    f"- Before: {compact_cell(sink_frame.get('before') or '', max_len=180)}",
                    f"- After: {compact_cell(sink_frame.get('after') or '', max_len=180)}",
                    f"- Input: {compact_cell(sink_frame.get('input') or '', max_len=120)}",
                    "",
                    "Transform Diffs:",
                    *step_lines,
                ]
            )
        )
    return (
        "# Debug 函数追踪\n\n"
        + markdown_table(
            ["编号", "结果", "执行模式", "Sink命中", "Taint达Sink", "变换步数", "Sink前", "Sink后", "变换摘要", "调用栈摘要"],
            table_rows,
        )
        + "\n\n"
        + "\n\n".join(detail_blocks)
        + "\n"
    )


def render_poc_md(rows: List[Dict[str, Any]]) -> str:
    table_rows: List[List[str]] = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("case_id") or "-"),
                str(row.get("vuln_type") or "-"),
                str(row.get("route_method") or "-"),
                str(row.get("route_path") or "-"),
                str(row.get("payload_source") or "-"),
                str(row.get("request_source") or "-"),
                str(row.get("matched_result") or "-"),
                compact_cell(row.get("poc_cmd") or "-", max_len=220),
            ]
        )

    return (
        "# Debug PoC 命令\n\n"
        + markdown_table(
            ["编号", "漏洞类型", "方法", "路径", "Payload来源", "请求来源", "结果", "PoC命令"],
            table_rows,
        )
        + "\n"
    )


def write_empty_outputs(debug_dir: str) -> None:
    evidence_rows: List[Dict[str, Any]] = []
    process_rows: List[Dict[str, Any]] = []
    poc_rows: List[Dict[str, Any]] = []
    func_trace_rows: List[Dict[str, Any]] = []
    write_json(os.path.join(debug_dir, "debug_evidence.json"), evidence_rows)
    write_text(os.path.join(debug_dir, "debug_evidence.md"), render_md(evidence_rows))
    write_json(os.path.join(debug_dir, "debug_process.json"), process_rows)
    write_text(os.path.join(debug_dir, "debug_process.md"), render_process_md(process_rows))
    write_json(os.path.join(debug_dir, "debug_poc.json"), poc_rows)
    write_text(os.path.join(debug_dir, "debug_poc.md"), render_poc_md(poc_rows))
    write_json(os.path.join(debug_dir, "debug_func_trace.json"), func_trace_rows)
    write_text(os.path.join(debug_dir, "debug_func_trace.md"), render_func_trace_md(func_trace_rows))


def normalize_bucket(value: str) -> str:
    v = str(value or "").strip().upper()
    if v in BUCKET_PRIORITY:
        return v
    if v in ("REQUEST", "PARAM", "QUERY"):
        return "GET"
    if v == "FORM":
        return "POST"
    return "GET"


def normalize_method(value: str, input_map: Dict[str, Any]) -> str:
    raw = str(value or "").split("|")[0].strip().upper()
    if raw in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return raw
    if raw == "ANY":
        return "GET"

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


def deep_clone_input_map(input_map: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return json.loads(json.dumps(input_map or {}, ensure_ascii=False))
    except Exception:
        if isinstance(input_map, dict):
            return dict(input_map)
        return {}


def ensure_bucket_dict(input_map: Dict[str, Any], bucket: str) -> Dict[str, Any]:
    existing = input_map.get(bucket)
    if isinstance(existing, dict):
        return existing
    input_map[bucket] = {}
    return input_map[bucket]


def pick_first_param(bucket: Any, default: str = "payload") -> str:
    if isinstance(bucket, dict) and bucket:
        return str(next(iter(bucket.keys())))
    return default


def normalize_request_candidate(case: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    input_map = case.get("input_map") if isinstance(case.get("input_map"), dict) else {}
    best = case.get("best_request") if isinstance(case.get("best_request"), dict) else {}

    method = normalize_method(
        str(candidate.get("method") or best.get("method") or case.get("route_method") or "GET"),
        input_map,
    )
    path = normalize_path(str(candidate.get("path") or best.get("path") or case.get("route_path") or "/"))
    bucket = normalize_bucket(str(candidate.get("bucket") or best.get("bucket") or "GET"))
    param = str(candidate.get("param") or best.get("param") or "").strip()

    if not param:
        bucket_data = input_map.get(bucket)
        param = pick_first_param(bucket_data, "payload")

    content_type = str(candidate.get("content_type") or best.get("content_type") or "").strip()

    return {
        "method": method,
        "path": path,
        "bucket": bucket,
        "param": param,
        "content_type": content_type,
        "reason": str(candidate.get("reason") or best.get("reason") or ""),
        "source": str(candidate.get("source") or best.get("source") or "rules"),
    }


def load_wordlist_lines(path: str) -> List[str]:
    lines: List[str] = []
    if not os.path.exists(path):
        return lines
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
        return []
    return lines


def resolve_wordlist_name(case: Dict[str, Any]) -> str:
    sink_type = str(case.get("sink_type") or "").lower()
    vuln_type = str(case.get("vuln_type") or "").lower()

    if sink_type in WORDLIST_BY_SINK:
        return WORDLIST_BY_SINK[sink_type]
    if vuln_type in WORDLIST_BY_SINK:
        return WORDLIST_BY_SINK[vuln_type]

    if "sql" in sink_type or "sql" in vuln_type:
        return "sql.txt"
    if "rce" in sink_type or "command" in vuln_type:
        return "rce.txt"
    if "file" in sink_type or "file" in vuln_type:
        return "file.txt"
    if "ssrf" in sink_type or "ssrf" in vuln_type:
        return "ssrf.txt"
    if "xxe" in sink_type or "xxe" in vuln_type:
        return "xxe.txt"
    if "xss" in sink_type or "xss" in vuln_type or "ssti" in sink_type or "ssti" in vuln_type:
        return "xss.txt"
    if "deserialize" in sink_type or "deserial" in vuln_type:
        return "deserialize.txt"
    if "csrf" in sink_type or "csrf" in vuln_type:
        return "csrf.txt"
    return "sql.txt"


def dictionary_payloads_for_case(case: Dict[str, Any], max_payloads: int = 30) -> Tuple[List[str], str]:
    wordlist_name = resolve_wordlist_name(case)
    path = os.path.join(WORDLIST_DIR, wordlist_name)
    lines = load_wordlist_lines(path)
    if not lines:
        return ["payload"], "wordlist:fallback"
    return lines[:max_payloads], f"wordlist:{wordlist_name}"


def inject_payload(input_map: Dict[str, Any], bucket: str, param: str, payload: str) -> Dict[str, Any]:
    next_map = deep_clone_input_map(input_map)
    target_bucket = normalize_bucket(bucket)
    if target_bucket not in BUCKET_PRIORITY:
        target_bucket = "GET"
    if not param:
        param = "payload"

    bucket_data = ensure_bucket_dict(next_map, target_bucket)
    bucket_data[param] = payload
    next_map[target_bucket] = bucket_data

    # Fallback rule required by policy: if all buckets empty, create GET.payload.
    if not any(isinstance(next_map.get(name), dict) and next_map.get(name) for name in BUCKET_PRIORITY):
        next_map["GET"] = {"payload": payload}

    return next_map


def compact_map_for_context(input_map: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for bucket in BUCKET_PRIORITY:
        value = input_map.get(bucket)
        if isinstance(value, dict) and value:
            keys = list(value.keys())[:5]
            out[bucket] = {k: value[k] for k in keys}
    return out


def build_ai_request_context(cases: List[Dict[str, Any]], debug_dir: str) -> str:
    rows: List[Dict[str, Any]] = []
    for case in cases:
        payloads, payload_source = dictionary_payloads_for_case(case, max_payloads=8)
        rows.append(
            {
                "case_id": case.get("case_id"),
                "vuln_type": case.get("vuln_type"),
                "sink_type": case.get("sink_type"),
                "source_path": case.get("source_path"),
                "entry": case.get("entry"),
                "route_method": case.get("route_method"),
                "route_path": case.get("route_path"),
                "input_map": compact_map_for_context(case.get("input_map") if isinstance(case.get("input_map"), dict) else {}),
                "best_request": case.get("best_request") or {},
                "request_candidates": (case.get("request_candidates") or [])[:10],
                "payload_source": payload_source,
                "payload_hints": payloads,
            }
        )

    context = {
        "cases": rows,
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "case_count": len(rows),
            "strategy": "dictionary_first_then_ai",
        },
    }
    path = os.path.join(debug_dir, "ai_request_context.json")
    write_json(path, context)
    return path


def load_ai_suggestions(path: Optional[str]) -> Dict[str, List[Dict[str, Any]]]:
    if not path:
        return {}
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    if not isinstance(data, dict):
        return {}

    items = data.get("results")
    if not isinstance(items, list):
        return {}

    out: Dict[str, List[Dict[str, Any]]] = {}
    for row in items:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id") or "").strip()
        if not case_id:
            continue
        candidates = row.get("candidates")
        if not isinstance(candidates, list):
            continue

        parsed: List[Dict[str, Any]] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            parsed.append(
                {
                    "method": str(candidate.get("method") or "GET"),
                    "path": str(candidate.get("path") or "/"),
                    "bucket": str(candidate.get("bucket") or "GET"),
                    "param": str(candidate.get("param") or "payload"),
                    "content_type": str(candidate.get("content_type") or ""),
                    "payload": str(candidate.get("payload") or "").strip(),
                    "reason": str(candidate.get("reason") or "ai_realtime"),
                    "confidence": candidate.get("confidence"),
                }
            )

        if parsed:
            out[case_id] = parsed
    return out


def analyze_attempt_evidence(
    sink_type: str,
    attempt: Dict[str, Any],
    baseline_return_code: Optional[int],
    baseline_stdout: str,
    baseline_stderr: str,
) -> Dict[str, int]:
    text = "\n".join(
        [
            str(attempt.get("stdout_tail") or ""),
            str(attempt.get("stderr_tail") or ""),
            str(attempt.get("final_value") or ""),
            str(attempt.get("notes") or ""),
        ]
    ).lower()

    sink_keywords = {
        "sql": ["sql", "syntax", "mysql", "pdo", "query"],
        "rce": ["exec", "system", "command", "shell"],
        "file": ["file", "path", "read", "open"],
        "ssrf": ["http", "curl", "socket", "url"],
        "xxe": ["xml", "entity", "doctype", "xxe"],
        "xss": ["script", "alert", "html", "xss"],
        "deserialize": ["unserialize", "object", "class", "magic"],
        "csrf": ["csrf", "token", "forbidden", "origin"],
    }

    key = "sql"
    sink_l = sink_type.lower()
    for k in sink_keywords.keys():
        if k in sink_l:
            key = k
            break

    keyword_hits = 0
    for kw in sink_keywords.get(key, []):
        if kw in text:
            keyword_hits += 1

    rc = attempt.get("http_status")
    if rc is None:
        rc = attempt.get("return_code")
    status_code_diff = 1 if baseline_return_code is not None and rc != baseline_return_code else 0

    response_diff = 0
    if baseline_stdout and str(attempt.get("stdout_tail") or "") != baseline_stdout:
        response_diff += 1
    if baseline_stderr and str(attempt.get("stderr_tail") or "") != baseline_stderr:
        response_diff += 1

    return {
        "status_code_diff_score": status_code_diff,
        "response_diff_score": response_diff,
        "keyword_match_score": keyword_hits,
    }


def pick_injection_target(case: Dict[str, Any], candidate: Dict[str, Any], input_map: Dict[str, Any]) -> Tuple[str, str]:
    bucket = normalize_bucket(str(candidate.get("bucket") or ""))
    param = str(candidate.get("param") or "").strip()

    if param:
        return bucket, param

    if isinstance(input_map.get(bucket), dict) and input_map.get(bucket):
        return bucket, pick_first_param(input_map.get(bucket), "payload")

    for fallback_bucket in BUCKET_PRIORITY:
        bucket_data = input_map.get(fallback_bucket)
        if isinstance(bucket_data, dict) and bucket_data:
            return fallback_bucket, pick_first_param(bucket_data, "payload")

    return "GET", "payload"


def request_candidates_for_case(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = case.get("request_candidates") if isinstance(case.get("request_candidates"), list) else []
    parsed: List[Dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            parsed.append(normalize_request_candidate(case, row))

    if not parsed:
        parsed.append(normalize_request_candidate(case, {}))

    # Dedupe while keeping order.
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for row in parsed:
        key = (
            row.get("method"),
            row.get("path"),
            row.get("bucket"),
            row.get("param"),
            row.get("content_type"),
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(row)
    return uniq


def build_attempt_input(
    case: Dict[str, Any],
    candidate: Dict[str, Any],
    payload: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    base_input = case.get("input_map") if isinstance(case.get("input_map"), dict) else {}
    bucket, param = pick_injection_target(case, candidate, base_input)
    injected = inject_payload(base_input, bucket, param, payload)

    cand = dict(candidate)
    cand["bucket"] = bucket
    cand["param"] = param
    return injected, cand


def build_poc_command(method: str, path: str, input_map: Dict[str, Any], content_type: str = "") -> str:
    method_norm = normalize_method(method, input_map)
    path_norm = normalize_path(path)

    if path_norm.startswith("http://") or path_norm.startswith("https://"):
        url = path_norm
    else:
        url = f"http://target{path_norm}"

    params = input_map.get("GET") if isinstance(input_map.get("GET"), dict) else {}
    query = urllib.parse.urlencode(params, doseq=True)
    if query:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query}"

    parts: List[str] = ["curl", "-i", "-sS", "-X", method_norm, shlex.quote(url)]

    headers: Dict[str, str] = {}
    header_bucket = input_map.get("HEADER")
    if isinstance(header_bucket, dict):
        for key, value in header_bucket.items():
            headers[str(key)] = str(value)

    cookie_bucket = input_map.get("COOKIE")
    if isinstance(cookie_bucket, dict) and cookie_bucket:
        headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookie_bucket.items()])

    for hk, hv in headers.items():
        parts.extend(["-H", shlex.quote(f"{hk}: {hv}")])

    body_obj = input_map.get("POST") if isinstance(input_map.get("POST"), dict) else {}
    body_raw = input_map.get("BODY")

    if method_norm not in ("GET", "HEAD"):
        if isinstance(body_obj, dict) and body_obj:
            parts.extend(["-H", shlex.quote("Content-Type: application/json")])
            parts.extend(["--data-raw", shlex.quote(json.dumps(body_obj, ensure_ascii=False))])
        elif isinstance(body_raw, dict) and body_raw:
            ctype = content_type or "application/json"
            parts.extend(["-H", shlex.quote(f"Content-Type: {ctype}")])
            parts.extend(["--data-raw", shlex.quote(json.dumps(body_raw, ensure_ascii=False))])
        elif isinstance(body_raw, str) and body_raw.strip():
            ctype = content_type or "text/plain"
            parts.extend(["-H", shlex.quote(f"Content-Type: {ctype}")])
            parts.extend(["--data-raw", shlex.quote(body_raw)])

    return " ".join(parts)


def build_runtime_url(path: str, input_map: Dict[str, Any], base_url: str) -> str:
    path_norm = normalize_path(path)
    if path_norm.startswith("http://") or path_norm.startswith("https://"):
        parsed = urllib.parse.urlsplit(path_norm)
        path_only = parsed.path or "/"
        if parsed.query:
            path_only = f"{path_only}?{parsed.query}"
    else:
        path_only = path_norm

    if not path_only.startswith("/"):
        path_only = "/" + path_only
    url = f"{base_url}{path_only}"

    params = input_map.get("GET") if isinstance(input_map.get("GET"), dict) else {}
    query = urllib.parse.urlencode(params, doseq=True)
    if query:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query}"
    return url


def build_curl_args(
    method: str,
    path: str,
    input_map: Dict[str, Any],
    content_type: str,
    base_url: str,
) -> List[str]:
    method_norm = normalize_method(method, input_map)
    url = build_runtime_url(path, input_map, base_url)
    args: List[str] = ["curl", "-sS", "-i", "-X", method_norm, url]

    headers: Dict[str, str] = {}
    header_bucket = input_map.get("HEADER")
    if isinstance(header_bucket, dict):
        for key, value in header_bucket.items():
            headers[str(key)] = str(value)

    cookie_bucket = input_map.get("COOKIE")
    if isinstance(cookie_bucket, dict) and cookie_bucket:
        headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookie_bucket.items()])

    for hk, hv in headers.items():
        args.extend(["-H", f"{hk}: {hv}"])

    body_obj = input_map.get("POST") if isinstance(input_map.get("POST"), dict) else {}
    body_raw = input_map.get("BODY")

    if method_norm not in ("GET", "HEAD"):
        if isinstance(body_obj, dict) and body_obj:
            args.extend(["-H", "Content-Type: application/json"])
            args.extend(["--data-raw", json.dumps(body_obj, ensure_ascii=False)])
        elif isinstance(body_raw, dict) and body_raw:
            ctype = content_type or "application/json"
            args.extend(["-H", f"Content-Type: {ctype}"])
            args.extend(["--data-raw", json.dumps(body_raw, ensure_ascii=False)])
        elif isinstance(body_raw, str) and body_raw.strip():
            ctype = content_type or "text/plain"
            args.extend(["-H", f"Content-Type: {ctype}"])
            args.extend(["--data-raw", body_raw])

    return args


def run_curl_request(
    server: Dict[str, Any],
    method: str,
    path: str,
    input_map: Dict[str, Any],
    content_type: str,
) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    meta: Dict[str, Any] = {
        "return_code": None,
        "duration_ms": 0,
        "stdout_tail": "",
        "stderr_tail": "",
        "http_status": None,
        "execution_mode": "curl_http",
        "curl_cmd": "",
        "request_preview": "",
        "response_header_preview": "",
        "response_body_preview": "",
    }

    curl = shutil.which("curl")
    if not curl:
        return {}, "curl_missing", meta

    base_url = str(server.get("base_url") or "http://127.0.0.1:18080")
    args = build_curl_args(method, path, input_map, content_type, base_url)
    runtime_url = build_runtime_url(path, input_map, base_url)
    if args and args[0] != curl:
        args[0] = curl

    meta["curl_cmd"] = " ".join([shlex.quote(x) for x in args])
    meta["request_preview"] = tail_text(
        json.dumps(
            {
                "method": normalize_method(method, input_map),
                "url": runtime_url,
                "input_map": compact_map_for_context(input_map if isinstance(input_map, dict) else {}),
            },
            ensure_ascii=False,
        ),
        max_chars=1200,
        max_lines=30,
    )
    start = time.perf_counter()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=CURL_EXEC_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        meta["duration_ms"] = int((time.perf_counter() - start) * 1000)
        return {}, "curl_timeout", meta
    except Exception:
        meta["duration_ms"] = int((time.perf_counter() - start) * 1000)
        return {}, "curl_exec_failed", meta

    meta["duration_ms"] = int((time.perf_counter() - start) * 1000)
    meta["return_code"] = proc.returncode
    meta["stdout_tail"] = tail_text(proc.stdout or "")
    meta["stderr_tail"] = tail_text(proc.stderr or "")
    meta["http_status"] = extract_http_status(proc.stdout or "")
    response_headers, response_body = split_http_response(proc.stdout or "")
    meta["response_header_preview"] = tail_text(response_headers, max_chars=1200, max_lines=30)
    meta["response_body_preview"] = tail_text(response_body, max_chars=1200, max_lines=30)

    if proc.returncode != 0:
        return {}, "curl_exec_failed", meta

    body = response_body
    data, err = parse_debug_output(body)
    if err:
        data, err = parse_debug_output(proc.stdout or "")
    if err:
        return {}, err, meta
    return data, "", meta


def fallback_poc_from_case(case: Dict[str, Any]) -> Tuple[str, str, str, str]:
    raw_poc = case.get("raw_poc")
    input_map = case.get("input_map") if isinstance(case.get("input_map"), dict) else {}
    route_method = str(case.get("route_method") or "GET")
    route_path = str(case.get("route_path") or "/")

    if isinstance(raw_poc, str) and raw_poc.strip():
        return raw_poc.strip(), "raw_string", normalize_method(route_method, input_map), normalize_path(route_path)

    if isinstance(raw_poc, dict):
        cmd = raw_poc.get("cmd")
        if isinstance(cmd, str) and cmd.strip():
            method = normalize_method(str(raw_poc.get("method") or route_method), input_map)
            path = normalize_path(str(raw_poc.get("path") or route_path))
            return cmd.strip(), "raw_struct_cmd", method, path

    method = normalize_method(route_method, input_map)
    path = normalize_path(route_path)
    cmd = build_poc_command(method, path, input_map)
    if not cmd:
        cmd = "curl -i -sS -X GET 'http://target/'"
    return cmd, "route_input_map", method, path


def execute_attempt(
    case: Dict[str, Any],
    category: str,
    candidate: Dict[str, Any],
    payload: str,
    payload_source: str,
    request_source: str,
    rules: Dict[str, List[str]],
    base_notes: str,
    server: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    input_map, normalized_candidate = build_attempt_input(case, candidate, payload)
    input_val = str(case.get("input") or "")

    if isinstance(server, dict) and server.get("mode") == "curl_http":
        output, err, proc_meta = run_curl_request(
            server,
            str(normalized_candidate.get("method") or case.get("route_method") or "GET"),
            str(normalized_candidate.get("path") or case.get("route_path") or "/"),
            input_map,
            str(normalized_candidate.get("content_type") or ""),
        )
    else:
        output, err, proc_meta = (
            {},
            "http_server_unavailable",
            {
                "return_code": None,
                "duration_ms": 0,
                "stdout_tail": "",
                "stderr_tail": "",
                "http_status": None,
                "execution_mode": "curl_http",
                "curl_cmd": "",
                "request_preview": "",
                "response_header_preview": "",
                "response_body_preview": "",
            },
        )
    status = output.get("status") if isinstance(output, dict) else ""
    transform_chain = output.get("transform_chain") if isinstance(output, dict) else []
    transform_steps = output.get("transform_steps") if isinstance(output, dict) else []
    call_stack = output.get("call_stack") if isinstance(output, dict) else []
    var_snapshot = output.get("var_snapshot") if isinstance(output, dict) else {}
    sink_probe_hit = bool(output.get("sink_probe_hit")) if isinstance(output, dict) else False
    taint_var_reached_sink = bool(output.get("taint_var_reached_sink")) if isinstance(output, dict) else False
    change_type = output.get("change_type") if isinstance(output, dict) else ""

    if isinstance(output, dict) and output.get("input") not in (None, ""):
        input_val = str(output.get("input"))

    notes = base_notes
    if err or status != "done" or output.get("final_value") == "__TODO__":
        notes = (notes + "; " if notes else "") + f"debug_skip:{err or 'pending'}"
        change_type = "unknown"
        result = "skipped"
        final_val = output.get("final_value") if isinstance(output, dict) else "-"
    else:
        final_val = output.get("final_value")
        if final_val is None:
            final_val = "-"
        if not isinstance(transform_chain, list):
            transform_chain = []
        change_type = classify_change(str(input_val), str(final_val), transform_chain, rules, str(change_type))
        result = decide_result(category, change_type)

    if result not in RESULT_VALUES:
        result = "conditional"
    if change_type not in CHANGE_VALUES:
        change_type = "unknown"

    if err in {"script_missing", "php_not_found", "exec_failed", "curl_missing", "curl_timeout", "curl_exec_failed", "http_server_unavailable"}:
        process_status = "error"
    elif err or status != "done" or output.get("final_value") == "__TODO__":
        process_status = "skipped"
    else:
        process_status = "ok"

    attempt = {
        "case_id": case.get("case_id"),
        "result": result,
        "change_type": change_type,
        "process_status": process_status,
        "error_reason": err,
        "notes": notes or "-",
        "input": input_val,
        "final_value": final_val,
        "transform_chain": transform_chain if isinstance(transform_chain, list) else [],
        "transform_steps": transform_steps if isinstance(transform_steps, list) else [],
        "call_stack": call_stack if isinstance(call_stack, list) else [],
        "var_snapshot": var_snapshot if isinstance(var_snapshot, dict) else {},
        "sink_probe_hit": sink_probe_hit,
        "taint_var_reached_sink": taint_var_reached_sink,
        "return_code": proc_meta.get("return_code"),
        "duration_ms": proc_meta.get("duration_ms"),
        "stdout_tail": proc_meta.get("stdout_tail") or "",
        "stderr_tail": proc_meta.get("stderr_tail") or "",
        "http_status": proc_meta.get("http_status"),
        "execution_mode": proc_meta.get("execution_mode") or ("curl_http" if isinstance(server, dict) else "slice_cli"),
        "curl_cmd": proc_meta.get("curl_cmd") or "",
        "request_preview": proc_meta.get("request_preview") or "",
        "response_header_preview": proc_meta.get("response_header_preview") or "",
        "response_body_preview": proc_meta.get("response_body_preview") or "",
        "request_candidate": normalized_candidate,
        "request_source": request_source,
        "payload_used": payload,
        "payload_source": payload_source,
        "input_map": input_map,
    }
    return attempt


def _attempt_status_code(attempt: Dict[str, Any]) -> Optional[int]:
    code = attempt.get("http_status")
    if isinstance(code, int):
        return code
    code = attempt.get("return_code")
    if isinstance(code, int):
        return code
    return None


def _response_changed_vs_baseline(attempt: Dict[str, Any], baseline_attempt: Optional[Dict[str, Any]]) -> bool:
    if not baseline_attempt:
        return False
    cur_code = _attempt_status_code(attempt)
    base_code = _attempt_status_code(baseline_attempt)
    if cur_code is not None and base_code is not None and cur_code != base_code:
        return True
    if str(attempt.get("response_body_preview") or "") != str(baseline_attempt.get("response_body_preview") or ""):
        return True
    if str(attempt.get("response_header_preview") or "") != str(baseline_attempt.get("response_header_preview") or ""):
        return True
    if str(attempt.get("stdout_tail") or "") != str(baseline_attempt.get("stdout_tail") or ""):
        return True
    if str(attempt.get("stderr_tail") or "") != str(baseline_attempt.get("stderr_tail") or ""):
        return True
    return False


def apply_runtime_refinement(
    case: Dict[str, Any],
    attempt: Dict[str, Any],
    baseline_attempt: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    _ = case
    reasons: List[str] = []
    sink_probe_hit = bool(attempt.get("sink_probe_hit"))
    taint_reached = bool(attempt.get("taint_var_reached_sink"))
    response_changed = _response_changed_vs_baseline(attempt, baseline_attempt)
    original_result = str(attempt.get("result") or "skipped")
    process_status = str(attempt.get("process_status") or "skipped")

    if sink_probe_hit:
        reasons.append("sink_probe_hit")
    if taint_reached:
        reasons.append("taint_reached_sink")
    if response_changed:
        reasons.append("response_changed_vs_baseline")

    refined = original_result
    if process_status not in {"error", "skipped"}:
        if sink_probe_hit and taint_reached:
            if refined != "confirmed":
                refined = "confirmed"
                reasons.append(f"promote:{original_result}->confirmed")
        elif sink_probe_hit or taint_reached:
            if refined in {"rejected", "skipped"}:
                refined = "conditional"
                reasons.append(f"promote:{original_result}->conditional")
        elif response_changed and refined == "rejected":
            refined = "conditional"
            reasons.append("promote:response_delta")

        if refined == "confirmed" and not (sink_probe_hit or taint_reached):
            refined = "conditional"
            reasons.append("demote:missing_sink_signal")

    if refined not in RESULT_VALUES:
        refined = "conditional"

    attempt["result_before_runtime"] = original_result
    attempt["result"] = refined
    attempt["dynamic_reasons"] = reasons
    attempt["response_changed"] = response_changed
    attempt["runtime_signal_score"] = (
        (40 if sink_probe_hit else 0)
        + (60 if taint_reached else 0)
        + (20 if response_changed else 0)
    )
    return attempt


def choose_best_attempt(attempts: List[Dict[str, Any]], sink_type: str) -> Tuple[Optional[Dict[str, Any]], Optional[int]]:
    if not attempts:
        return None, None

    baseline_return_code = attempts[0].get("return_code")
    baseline_stdout = str(attempts[0].get("stdout_tail") or "")
    baseline_stderr = str(attempts[0].get("stderr_tail") or "")

    ranked: List[Tuple[int, int]] = []
    for idx, attempt in enumerate(attempts):
        result = str(attempt.get("result") or "skipped")
        result_score = {
            "confirmed": 400,
            "conditional": 300,
            "rejected": 150,
            "skipped": 50,
        }.get(result, 0)

        change_type = str(attempt.get("change_type") or "unknown")
        change_score = {
            "no_change": 80,
            "weak_change": 60,
            "strong_change": 20,
            "unknown": 0,
        }.get(change_type, 0)

        details = analyze_attempt_evidence(
            sink_type,
            attempt,
            baseline_return_code=baseline_return_code if isinstance(baseline_return_code, int) else None,
            baseline_stdout=baseline_stdout,
            baseline_stderr=baseline_stderr,
        )
        status_code_diff = int(details.get("status_code_diff_score") or 0)
        response_diff = int(details.get("response_diff_score") or 0)
        keyword_match = int(details.get("keyword_match_score") or 0)
        runtime_signal_score = int(attempt.get("runtime_signal_score") or 0)
        sink_probe_bonus = 25 if attempt.get("sink_probe_hit") else 0
        taint_bonus = 35 if attempt.get("taint_var_reached_sink") else 0

        total = (
            result_score
            + change_score
            + status_code_diff * 10
            + response_diff * 8
            + keyword_match * 4
            + runtime_signal_score
            + sink_probe_bonus
            + taint_bonus
        )
        attempt["status_code_diff_score"] = status_code_diff
        attempt["response_diff_score"] = response_diff
        attempt["keyword_match_score"] = keyword_match
        attempt["sink_probe_bonus"] = sink_probe_bonus
        attempt["taint_bonus"] = taint_bonus
        attempt["evidence_score"] = total
        ranked.append((total, idx))

    ranked.sort(key=lambda item: item[0], reverse=True)
    best_score, best_idx = ranked[0]
    _ = best_score
    return attempts[best_idx], best_idx


def build_case_report_rows(
    case: Dict[str, Any],
    selected: Dict[str, Any],
    matched_index: int,
    attempt_count: int,
    dictionary_count: int,
    ai_count: int,
    ai_status: str,
    stop_reason: str,
    trace_case_file: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    candidate = selected.get("request_candidate") or {}
    method = str(candidate.get("method") or case.get("route_method") or "GET")
    path = str(candidate.get("path") or case.get("route_path") or "/")
    content_type = str(candidate.get("content_type") or "")

    poc_cmd = build_poc_command(method, path, selected.get("input_map") if isinstance(selected.get("input_map"), dict) else {}, content_type)
    poc_source = str(selected.get("request_source") or "rules")
    if not poc_cmd:
        poc_cmd, poc_source, method, path = fallback_poc_from_case(case)

    evidence_row = {
        "case_id": case.get("case_id"),
        "module": case.get("module"),
        "vuln_type": case.get("vuln_type"),
        "entry": case.get("entry"),
        "input": selected.get("input"),
        "final_value": selected.get("final_value"),
        "sink": case.get("sink") or {},
        "result": selected.get("result"),
        "notes": selected.get("notes") or "-",
        "change_type": selected.get("change_type"),
        "trace_chain": case.get("trace_chain") or [],
        "source_path": case.get("source_path") or "-",
        "route_method": method,
        "route_path": path,
        "poc_cmd": poc_cmd,
        "poc_source": poc_source,
        "payload_used": selected.get("payload_used") or "",
        "payload_source": selected.get("payload_source") or "",
        "request_source": selected.get("request_source") or case.get("planning_source") or "rules",
        "attempt_count": attempt_count,
        "stop_reason": stop_reason,
        "planning_source": case.get("planning_source") or "rules",
        "planning_score": case.get("planning_score") or 0,
        "matched_attempt_index": matched_index,
        "evidence_score": selected.get("evidence_score") or 0,
        "execution_mode": selected.get("execution_mode") or "slice_cli",
        "http_status": selected.get("http_status"),
        "transform_steps": selected.get("transform_steps") if isinstance(selected.get("transform_steps"), list) else [],
        "call_stack": selected.get("call_stack") if isinstance(selected.get("call_stack"), list) else [],
        "var_snapshot": selected.get("var_snapshot") if isinstance(selected.get("var_snapshot"), dict) else {},
        "sink_probe_hit": bool(selected.get("sink_probe_hit")),
        "taint_var_reached_sink": bool(selected.get("taint_var_reached_sink")),
        "dynamic_reasons": selected.get("dynamic_reasons") if isinstance(selected.get("dynamic_reasons"), list) else [],
        "response_header_preview": selected.get("response_header_preview") or "",
        "response_body_preview": selected.get("response_body_preview") or "",
        "trace_case_file": trace_case_file,
    }

    process_row = {
        "case_id": case.get("case_id"),
        "debug_script": case.get("debug_script"),
        "status": selected.get("process_status") or "skipped",
        "return_code": selected.get("return_code"),
        "http_status": selected.get("http_status"),
        "execution_mode": selected.get("execution_mode") or "slice_cli",
        "duration_ms": selected.get("duration_ms"),
        "stdout_tail": selected.get("stdout_tail") or "",
        "stderr_tail": selected.get("stderr_tail") or "",
        "error_reason": selected.get("error_reason") or "",
        "curl_cmd": selected.get("curl_cmd") or "",
        "request_preview": selected.get("request_preview") or "",
        "response_header_preview": selected.get("response_header_preview") or "",
        "response_body_preview": selected.get("response_body_preview") or "",
        "sink_probe_hit": bool(selected.get("sink_probe_hit")),
        "taint_var_reached_sink": bool(selected.get("taint_var_reached_sink")),
        "dynamic_reasons": selected.get("dynamic_reasons") if isinstance(selected.get("dynamic_reasons"), list) else [],
        "request_attempt_count": attempt_count,
        "dictionary_attempt_count": dictionary_count,
        "ai_attempt_count": ai_count,
        "ai_realtime_status": ai_status,
        "matched_attempt_index": matched_index,
        "trace_case_file": trace_case_file,
    }

    poc_row = {
        "case_id": case.get("case_id"),
        "module": case.get("module"),
        "vuln_type": case.get("vuln_type"),
        "entry": case.get("entry"),
        "route_method": method,
        "route_path": path,
        "poc_source": poc_source,
        "poc_cmd": poc_cmd,
        "payload_used": selected.get("payload_used") or "",
        "payload_source": selected.get("payload_source") or "",
        "request_source": selected.get("request_source") or case.get("planning_source") or "rules",
        "matched_result": selected.get("result") or "skipped",
        "execution_mode": selected.get("execution_mode") or "slice_cli",
        "sink_probe_hit": bool(selected.get("sink_probe_hit")),
        "taint_var_reached_sink": bool(selected.get("taint_var_reached_sink")),
        "trace_case_file": trace_case_file,
    }

    var_snapshot = selected.get("var_snapshot") if isinstance(selected.get("var_snapshot"), dict) else {}
    func_trace_row = {
        "case_id": case.get("case_id"),
        "result": selected.get("result") or "skipped",
        "execution_mode": selected.get("execution_mode") or "slice_cli",
        "matched_attempt_index": matched_index,
        "attempt_count": attempt_count,
        "sink_probe_hit": bool(selected.get("sink_probe_hit")),
        "taint_var_reached_sink": bool(selected.get("taint_var_reached_sink")),
        "transform_steps": selected.get("transform_steps") if isinstance(selected.get("transform_steps"), list) else [],
        "transform_step_count": len(selected.get("transform_steps") or []),
        "transform_summary": summarize_transform_steps(selected.get("transform_steps")),
        "call_stack": selected.get("call_stack") if isinstance(selected.get("call_stack"), list) else [],
        "call_stack_summary": summarize_call_stack(selected.get("call_stack")),
        "before_sink": var_snapshot.get("before_sink") if isinstance(var_snapshot, dict) else "",
        "after_sink": var_snapshot.get("after_sink") if isinstance(var_snapshot, dict) else "",
        "sink_keyframe": {
            "before": var_snapshot.get("before_sink") if isinstance(var_snapshot, dict) else "",
            "after": var_snapshot.get("after_sink") if isinstance(var_snapshot, dict) else "",
            "input": selected.get("input") or "",
        },
        "transform_diffs": build_transform_diffs(selected.get("transform_steps")),
        "dynamic_reasons": selected.get("dynamic_reasons") if isinstance(selected.get("dynamic_reasons"), list) else [],
        "trace_case_file": trace_case_file,
    }

    # Required traceability back to evidence row.
    evidence_row["poc_cmd"] = poc_row["poc_cmd"]
    evidence_row["poc_source"] = poc_row["poc_source"]

    return evidence_row, process_row, poc_row, func_trace_row


def write_trace_case_file(
    trace_case_dir: str,
    case: Dict[str, Any],
    selected: Dict[str, Any],
    attempts: List[Dict[str, Any]],
    matched_index: int,
    stop_reason: str,
) -> str:
    case_id = str(case.get("case_id") or "case")
    os.makedirs(trace_case_dir, exist_ok=True)
    path = os.path.join(trace_case_dir, f"{case_id}.json")

    attempt_rows: List[Dict[str, Any]] = []
    for idx, attempt in enumerate(attempts, start=1):
        row = {
            "attempt_index": idx,
            "result": attempt.get("result"),
            "result_before_runtime": attempt.get("result_before_runtime"),
            "change_type": attempt.get("change_type"),
            "process_status": attempt.get("process_status"),
            "payload_used": attempt.get("payload_used"),
            "payload_source": attempt.get("payload_source"),
            "request_source": attempt.get("request_source"),
            "request_candidate": attempt.get("request_candidate"),
            "execution_mode": attempt.get("execution_mode"),
            "http_status": attempt.get("http_status"),
            "return_code": attempt.get("return_code"),
            "sink_probe_hit": bool(attempt.get("sink_probe_hit")),
            "taint_var_reached_sink": bool(attempt.get("taint_var_reached_sink")),
            "dynamic_reasons": attempt.get("dynamic_reasons") if isinstance(attempt.get("dynamic_reasons"), list) else [],
            "transform_chain": attempt.get("transform_chain") if isinstance(attempt.get("transform_chain"), list) else [],
            "transform_steps": attempt.get("transform_steps") if isinstance(attempt.get("transform_steps"), list) else [],
            "call_stack": attempt.get("call_stack") if isinstance(attempt.get("call_stack"), list) else [],
            "var_snapshot": attempt.get("var_snapshot") if isinstance(attempt.get("var_snapshot"), dict) else {},
            "request_preview": attempt.get("request_preview") or "",
            "response_header_preview": attempt.get("response_header_preview") or "",
            "response_body_preview": attempt.get("response_body_preview") or "",
            "curl_cmd": attempt.get("curl_cmd") or "",
            "stdout_tail": attempt.get("stdout_tail") or "",
            "stderr_tail": attempt.get("stderr_tail") or "",
            "evidence_score": attempt.get("evidence_score"),
            "runtime_signal_score": attempt.get("runtime_signal_score"),
        }
        attempt_rows.append(row)

    selected_row = {
        "matched_attempt_index": matched_index,
        "stop_reason": stop_reason,
        "result": selected.get("result"),
        "result_before_runtime": selected.get("result_before_runtime"),
        "sink_probe_hit": bool(selected.get("sink_probe_hit")),
        "taint_var_reached_sink": bool(selected.get("taint_var_reached_sink")),
        "dynamic_reasons": selected.get("dynamic_reasons") if isinstance(selected.get("dynamic_reasons"), list) else [],
        "request_candidate": selected.get("request_candidate"),
        "payload_used": selected.get("payload_used"),
        "transform_steps": selected.get("transform_steps") if isinstance(selected.get("transform_steps"), list) else [],
        "call_stack": selected.get("call_stack") if isinstance(selected.get("call_stack"), list) else [],
        "var_snapshot": selected.get("var_snapshot") if isinstance(selected.get("var_snapshot"), dict) else {},
        "curl_cmd": selected.get("curl_cmd") or "",
        "request_preview": selected.get("request_preview") or "",
        "response_header_preview": selected.get("response_header_preview") or "",
        "response_body_preview": selected.get("response_body_preview") or "",
    }

    payload = {
        "case_id": case_id,
        "module": case.get("module"),
        "vuln_type": case.get("vuln_type"),
        "entry": case.get("entry"),
        "planning_source": case.get("planning_source"),
        "selected": selected_row,
        "attempts": attempt_rows,
    }
    write_json(path, payload)
    return path


def execute_case(
    case: Dict[str, Any],
    rules: Dict[str, List[str]],
    ai_suggestions_map: Dict[str, List[Dict[str, Any]]],
    ai_realtime_enabled: bool,
    ai_budget: int,
    ai_runtime_status: str,
    project_root: str,
    out_root: str,
    trace_verbose: bool = False,
    trace_case_dir: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    case_id = str(case.get("case_id") or "")
    module = str(case.get("module") or "")
    category = CATEGORY_RULES.get(module, "input_limit")

    notes = str(case.get("notes") or "")
    try:
        auto_note = generate_slice_for_case(case, project_root, out_root)
    except Exception as exc:
        auto_note = f"auto_slice_error:{exc.__class__.__name__}"
    if auto_note:
        notes = (notes + "; " if notes else "") + auto_note

    server, server_err = start_case_http_server(case, out_root)
    if server_err:
        notes = (notes + "; " if notes else "") + f"server_error:{server_err}"

    request_candidates = request_candidates_for_case(case)
    dictionary_payloads, dictionary_payload_source = dictionary_payloads_for_case(case)

    attempts: List[Dict[str, Any]] = []
    baseline_attempt: Optional[Dict[str, Any]] = None
    dictionary_count = 0
    ai_count = 0
    stop_reason = "exhausted"

    def finalize(
        selected_attempt: Dict[str, Any],
        matched_idx: int,
        ai_status_value: str,
        stop_reason_value: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        trace_file = ""
        if trace_verbose:
            trace_root = trace_case_dir or os.path.join(out_root, "debug_verify", "trace_cases")
            try:
                trace_file = write_trace_case_file(
                    trace_root,
                    case,
                    selected_attempt,
                    attempts,
                    matched_idx,
                    stop_reason_value,
                )
            except Exception as exc:
                reasons = selected_attempt.get("dynamic_reasons")
                if not isinstance(reasons, list):
                    reasons = []
                reasons.append(f"trace_write_failed:{exc.__class__.__name__}")
                selected_attempt["dynamic_reasons"] = reasons
        return build_case_report_rows(
            case,
            selected_attempt,
            matched_idx,
            len(attempts),
            dictionary_count,
            ai_count,
            ai_status_value,
            stop_reason_value,
            trace_case_file=trace_file,
        )

    try:
        # 1) Dictionary first: payload outer loop, request candidate inner loop.
        for payload in dictionary_payloads:
            for req in request_candidates:
                dictionary_count += 1
                attempt = execute_attempt(
                    case,
                    category,
                    req,
                    payload,
                    dictionary_payload_source,
                    str(case.get("planning_source") or "rules"),
                    rules,
                    notes,
                    server,
                )
                attempt = apply_runtime_refinement(case, attempt, baseline_attempt)
                attempts.append(attempt)
                if baseline_attempt is None:
                    baseline_attempt = attempt
                if attempt.get("result") in {"confirmed", "conditional"}:
                    stop_reason = f"dictionary_{attempt.get('result')}"
                    selected = attempt
                    matched_idx = len(attempts)
                    ai_status = "disabled" if not ai_realtime_enabled else "not_needed"
                    return finalize(selected, matched_idx, ai_status, stop_reason)

        # 2) AI supplement after dictionary exhaustion.
        ai_status = "disabled"
        if ai_realtime_enabled:
            if ai_runtime_status == "failed":
                ai_status = "failed"
            else:
                ai_status = "ok"
                ai_candidates = ai_suggestions_map.get(case_id) or []
                dedupe = set()
                capped = ai_candidates[: max(ai_budget, 0)]

                for raw in capped:
                    if ai_count >= ai_budget:
                        break

                    req = normalize_request_candidate(case, raw if isinstance(raw, dict) else {})
                    payload = str(raw.get("payload") or "").strip() if isinstance(raw, dict) else ""
                    if not payload:
                        # Keep flow resilient when AI omitted payload.
                        payload = dictionary_payloads[0] if dictionary_payloads else "payload"

                    dedupe_key = (
                        req.get("method"),
                        req.get("path"),
                        req.get("bucket"),
                        req.get("param"),
                        req.get("content_type"),
                        payload,
                    )
                    if dedupe_key in dedupe:
                        continue
                    dedupe.add(dedupe_key)

                    ai_count += 1
                    attempt = execute_attempt(
                        case,
                        category,
                        req,
                        payload,
                        "ai_realtime",
                        "ai_realtime",
                        rules,
                        notes,
                        server,
                    )
                    attempt = apply_runtime_refinement(case, attempt, baseline_attempt)
                    attempts.append(attempt)
                    if baseline_attempt is None:
                        baseline_attempt = attempt

                    if attempt.get("result") in {"confirmed", "conditional"}:
                        stop_reason = f"ai_{attempt.get('result')}"
                        selected = attempt
                        matched_idx = len(attempts)
                        return finalize(selected, matched_idx, ai_status, stop_reason)

                if ai_count == 0:
                    ai_status = "no_candidates"

        # 3) No hit: choose strongest evidence candidate.
        selected, selected_idx = choose_best_attempt(attempts, str(case.get("sink_type") or case.get("vuln_type") or ""))

        if not selected:
            selected = {
                "result": "skipped",
                "result_before_runtime": "skipped",
                "change_type": "unknown",
                "process_status": "skipped",
                "error_reason": "no_attempts",
                "notes": notes or "-",
                "input": case.get("input") or "",
                "final_value": "-",
                "transform_chain": [],
                "transform_steps": [],
                "call_stack": [],
                "var_snapshot": {},
                "sink_probe_hit": False,
                "taint_var_reached_sink": False,
                "dynamic_reasons": [],
                "return_code": None,
                "duration_ms": 0,
                "stdout_tail": "",
                "stderr_tail": "",
                "http_status": None,
                "execution_mode": "curl_http" if isinstance(server, dict) else "slice_cli",
                "curl_cmd": "",
                "request_preview": "",
                "response_header_preview": "",
                "response_body_preview": "",
                "request_candidate": normalize_request_candidate(case, {}),
                "request_source": str(case.get("planning_source") or "rules"),
                "payload_used": "",
                "payload_source": dictionary_payload_source,
                "input_map": case.get("input_map") if isinstance(case.get("input_map"), dict) else {},
                "runtime_signal_score": 0,
                "evidence_score": 0,
            }
            selected_idx = 0

        stop_reason = "exhausted_no_match"
        matched_index = (selected_idx + 1) if selected_idx is not None else 1

        return finalize(selected, matched_index, ai_status, stop_reason)
    finally:
        stop_case_http_server(server)


def main() -> None:
    ensure_running_in_container()

    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="PHP project root")
    parser.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    parser.add_argument("--cases", default=None, help="debug_cases.json path (optional)")

    parser.add_argument("--prepare-ai-context-only", action="store_true", help="Only generate ai_request_context.json then exit")
    parser.add_argument("--ai-realtime", dest="ai_realtime", action="store_true", default=True, help="Enable AI realtime supplement")
    parser.add_argument("--disable-ai-realtime", dest="ai_realtime", action="store_false", help="Disable AI realtime supplement")
    parser.add_argument("--ai-suggestions", default=None, help="Path to ai realtime suggestions json")
    parser.add_argument("--ai-runtime-status", default="", help="Host runtime status for ai realtime")
    parser.add_argument("--ai-model", default="", help="AI model hint (metadata only)")
    parser.add_argument("--ai-rounds", type=int, default=2, help="AI rounds")
    parser.add_argument("--ai-candidates-per-round", type=int, default=5, help="AI candidates per round")
    parser.add_argument("--ai-timeout", type=int, default=30, help="AI timeout seconds")
    parser.add_argument("--trace-verbose", action="store_true", help="Write per-case verbose trace json")

    args = parser.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    debug_dir = os.path.join(out_root, "debug_verify")
    os.makedirs(debug_dir, exist_ok=True)
    trace_case_dir = os.path.join(debug_dir, "trace_cases")

    if args.cases:
        cases_path = os.path.abspath(args.cases)
    else:
        cases_path = ensure_cases(out_root, project_root)

    if not os.path.exists(cases_path):
        write_empty_outputs(debug_dir)
        context_path = build_ai_request_context([], debug_dir)
        print(f"No debug cases found. Context: {context_path}")
        return

    with open(cases_path, "r", encoding="utf-8") as f:
        cases = json.load(f) or []

    if not isinstance(cases, list) or not cases:
        write_empty_outputs(debug_dir)
        context_path = build_ai_request_context([], debug_dir)
        print(f"No debug cases found. Context: {context_path}")
        return

    context_path = build_ai_request_context(cases, debug_dir)
    if args.prepare_ai_context_only:
        print(f"ai_request_context.json written: {context_path}")
        return

    rules = load_change_rules(RULES_PATH)
    ai_budget = max(0, int(args.ai_rounds or 0) * int(args.ai_candidates_per_round or 0))
    ai_suggestions_map = load_ai_suggestions(args.ai_suggestions)
    ai_runtime_status = str(args.ai_runtime_status or "").strip().lower()

    evidence_rows: List[Dict[str, Any]] = []
    process_rows: List[Dict[str, Any]] = []
    poc_rows: List[Dict[str, Any]] = []
    func_trace_rows: List[Dict[str, Any]] = []

    for case in cases:
        evidence_row, process_row, poc_row, func_trace_row = execute_case(
            case,
            rules,
            ai_suggestions_map=ai_suggestions_map,
            ai_realtime_enabled=bool(args.ai_realtime),
            ai_budget=ai_budget,
            ai_runtime_status=ai_runtime_status,
            project_root=project_root,
            out_root=out_root,
            trace_verbose=bool(args.trace_verbose),
            trace_case_dir=trace_case_dir,
        )
        evidence_rows.append(evidence_row)
        process_rows.append(process_row)
        poc_rows.append(poc_row)
        func_trace_rows.append(func_trace_row)

    write_json(os.path.join(debug_dir, "debug_evidence.json"), evidence_rows)
    write_text(os.path.join(debug_dir, "debug_evidence.md"), render_md(evidence_rows))
    write_json(os.path.join(debug_dir, "debug_process.json"), process_rows)
    write_text(os.path.join(debug_dir, "debug_process.md"), render_process_md(process_rows))
    write_json(os.path.join(debug_dir, "debug_poc.json"), poc_rows)
    write_text(os.path.join(debug_dir, "debug_poc.md"), render_poc_md(poc_rows))
    write_json(os.path.join(debug_dir, "debug_func_trace.json"), func_trace_rows)
    write_text(os.path.join(debug_dir, "debug_func_trace.md"), render_func_trace_md(func_trace_rows))

    print(f"debug_evidence.json written: {os.path.join(debug_dir, 'debug_evidence.json')}")
    print(f"debug_process.json written: {os.path.join(debug_dir, 'debug_process.json')}")
    print(f"debug_poc.json written: {os.path.join(debug_dir, 'debug_poc.json')}")
    print(f"debug_func_trace.json written: {os.path.join(debug_dir, 'debug_func_trace.json')}")


if __name__ == "__main__":
    main()
