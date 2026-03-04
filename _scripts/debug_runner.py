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
TARGET_URL = "http://target"  # Default target URL, can be overridden by --target-url
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

FRAMEWORK_PROFILE_JSON = "framework_profile.json"
FRAMEWORK_BOOT_TIMEOUT_SEC = 8
FRAMEWORK_HEALTHCHECK_TIMEOUT_SEC = 5

FRAMEWORK_PACKAGE_MAP = {
    "laravel/framework": "laravel",
    "symfony/framework-bundle": "symfony",
    "topthink/framework": "thinkphp",
    "yiisoft/yii2": "yii",
    "codeigniter4/framework": "codeigniter",
    "codeigniter/framework": "codeigniter",
    "slim/slim": "slim",
    "cakephp/cakephp": "cakephp",
    "hyperf/framework": "hyperf",
    "laravel/lumen-framework": "lumen",
}

FRAMEWORK_PRIORITY = [
    "laravel/framework",
    "laravel/lumen-framework",
    "symfony/framework-bundle",
    "topthink/framework",
    "yiisoft/yii2",
    "codeigniter4/framework",
    "codeigniter/framework",
    "slim/slim",
    "cakephp/cakephp",
    "hyperf/framework",
]

FRAMEWORK_DOCROOT_HINTS = {
    "laravel": ["public", "."],
    "lumen": ["public", "."],
    "symfony": ["public", "."],
    "thinkphp": ["public", "."],
    "yii": ["web", "public", "."],
    "codeigniter": ["public", "."],
    "slim": ["public", "."],
    "cakephp": ["webroot", "public", "."],
    "hyperf": ["public", "."],
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


def load_json_dict(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def collect_lock_versions(lock_data: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(lock_data, dict):
        return out
    for key in ("packages", "packages-dev"):
        rows = lock_data.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip().lower()
            version = str(row.get("version") or "").strip()
            if name and version and name not in out:
                out[name] = version
    return out


def collect_require_versions(composer_data: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(composer_data, dict):
        return out
    for key in ("require", "require-dev"):
        rows = composer_data.get(key)
        if not isinstance(rows, dict):
            continue
        for pkg, ver in rows.items():
            name = str(pkg or "").strip().lower()
            if not name:
                continue
            out[name] = str(ver or "").strip()
    return out


def detect_framework_by_files(project_root: str) -> Tuple[str, str]:
    markers = [
        ("laravel", [os.path.join(project_root, "artisan"), os.path.join(project_root, "bootstrap", "app.php")]),
        ("symfony", [os.path.join(project_root, "bin", "console"), os.path.join(project_root, "config", "bundles.php")]),
        ("thinkphp", [os.path.join(project_root, "think"), os.path.join(project_root, "app")]),
        ("yii", [os.path.join(project_root, "yii"), os.path.join(project_root, "config")]),
        ("codeigniter", [os.path.join(project_root, "system"), os.path.join(project_root, "application")]),
        ("slim", [os.path.join(project_root, "public", "index.php"), os.path.join(project_root, "vendor", "autoload.php")]),
        ("cakephp", [os.path.join(project_root, "bin", "cake"), os.path.join(project_root, "config")]),
        ("hyperf", [os.path.join(project_root, "bin", "hyperf.php"), os.path.join(project_root, "config", "autoload")]),
    ]
    for framework_name, paths in markers:
        if all(os.path.exists(p) for p in paths):
            return framework_name, "filesystem"
    return "", "none"


def resolve_framework_docroot(project_root: str, framework_name: str) -> Tuple[str, str]:
    hints = FRAMEWORK_DOCROOT_HINTS.get(framework_name, ["public", "web", "webroot", "."])
    for rel in hints:
        abs_dir = project_root if rel == "." else os.path.join(project_root, rel)
        if os.path.isdir(abs_dir) and os.path.isfile(os.path.join(abs_dir, "index.php")):
            return rel, abs_dir
    for rel in ("public", "web", "webroot", "."):
        abs_dir = project_root if rel == "." else os.path.join(project_root, rel)
        if os.path.isdir(abs_dir) and os.path.isfile(os.path.join(abs_dir, "index.php")):
            return rel, abs_dir
    return "", ""


def detect_framework_profile(project_root: str) -> Dict[str, Any]:
    composer_path = os.path.join(project_root, "composer.json")
    lock_path = os.path.join(project_root, "composer.lock")
    composer_data = load_json_dict(composer_path)
    lock_data = load_json_dict(lock_path)
    lock_versions = collect_lock_versions(lock_data)
    require_versions = collect_require_versions(composer_data)

    framework_pkg = ""
    framework_name = ""
    framework_version = ""
    detected_from = "none"

    for pkg in FRAMEWORK_PRIORITY:
        if pkg in lock_versions:
            framework_pkg = pkg
            framework_name = FRAMEWORK_PACKAGE_MAP.get(pkg, "")
            framework_version = lock_versions.get(pkg, "")
            detected_from = "composer.lock"
            break
        if pkg in require_versions:
            framework_pkg = pkg
            framework_name = FRAMEWORK_PACKAGE_MAP.get(pkg, "")
            framework_version = require_versions.get(pkg, "")
            detected_from = "composer.json"
            break

    if not framework_name:
        framework_name, detected_from = detect_framework_by_files(project_root)

    doc_root_rel = ""
    doc_root_abs = ""
    if framework_name:
        doc_root_rel, doc_root_abs = resolve_framework_docroot(project_root, framework_name)

    mode = "framework" if framework_name else "snippet"
    doc_root_exists = bool(doc_root_abs and os.path.isdir(doc_root_abs))
    index_exists = bool(doc_root_abs and os.path.isfile(os.path.join(doc_root_abs, "index.php")))
    boot_supported = bool(mode == "framework" and doc_root_exists and index_exists and framework_name != "hyperf")

    return {
        "mode": mode,
        "framework_name": framework_name or "",
        "framework_package": framework_pkg or "",
        "framework_version": framework_version or "",
        "detected_from": detected_from,
        "composer_json_exists": bool(os.path.exists(composer_path)),
        "composer_lock_exists": bool(os.path.exists(lock_path)),
        "doc_root": doc_root_rel,
        "doc_root_abs": doc_root_abs,
        "doc_root_exists": doc_root_exists,
        "index_exists": index_exists,
        "boot_supported": boot_supported,
        "boot_strategy": "php_builtin_server" if framework_name else "slice_http_server",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def load_framework_profile(profile_path: str, project_root: str) -> Dict[str, Any]:
    if profile_path:
        data = load_json_dict(profile_path)
        if isinstance(data, dict) and data:
            out = dict(data)
            out.setdefault("project_root", project_root)
            return out
    profile = detect_framework_profile(project_root)
    profile["project_root"] = project_root
    return profile


def write_framework_profile(profile: Dict[str, Any], debug_dir: str, out_root: str) -> str:
    profile = dict(profile or {})
    profile.setdefault("generated_at", time.strftime("%Y-%m-%dT%H:%M:%S"))
    debug_path = os.path.join(debug_dir, FRAMEWORK_PROFILE_JSON)
    meta_dir = os.path.join(out_root, "_meta")
    os.makedirs(meta_dir, exist_ok=True)
    meta_path = os.path.join(meta_dir, FRAMEWORK_PROFILE_JSON)
    write_json(debug_path, profile)
    write_json(meta_path, profile)
    return debug_path


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


def build_framework_router_php(doc_root: str) -> str:
    doc_q = php_quote(doc_root)
    return f"""<?php
$docRoot = '{doc_q}';
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$path = realpath($docRoot . $uri);

if ($uri && $uri !== '/' && $path && strpos($path, $docRoot) === 0 && is_file($path)) {{
    return false;
}}

$indexFile = $docRoot . DIRECTORY_SEPARATOR . 'index.php';
if (!is_file($indexFile)) {{
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "framework_index_missing";
    exit(0);
}}

require $indexFile;
"""


def start_framework_http_server(profile: Dict[str, Any], out_root: str) -> Tuple[Optional[Dict[str, Any]], str]:
    if str(profile.get("mode") or "") != "framework":
        return None, "not_framework_mode"

    if not bool(profile.get("boot_supported")):
        return None, "framework_boot_not_supported"

    php = shutil.which("php")
    curl = shutil.which("curl")
    if not php:
        return None, "php_not_found"
    if not curl:
        return None, "curl_not_found"

    doc_root = str(profile.get("doc_root_abs") or "")
    if not doc_root or not os.path.isdir(doc_root):
        return None, "framework_doc_root_missing"
    if not os.path.isfile(os.path.join(doc_root, "index.php")):
        return None, "framework_index_missing"

    runtime_root = os.path.join(out_root, "debug_verify", "http_runtime")
    os.makedirs(runtime_root, exist_ok=True)
    work_dir = tempfile.mkdtemp(prefix="framework_", dir=runtime_root)

    router_path = os.path.join(work_dir, "router.php")
    write_text(router_path, build_framework_router_php(doc_root))

    port = pick_free_port()
    proc = subprocess.Popen(
        [php, "-S", f"127.0.0.1:{port}", "-t", doc_root, router_path],
        cwd=work_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if not wait_tcp_ready("127.0.0.1", port, FRAMEWORK_BOOT_TIMEOUT_SEC, proc):
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return None, "framework_http_server_start_failed"

    base_url = f"http://127.0.0.1:{port}"
    try:
        check = subprocess.run(
            [curl, "-sS", "-i", "--max-time", str(FRAMEWORK_HEALTHCHECK_TIMEOUT_SEC), f"{base_url}/"],
            capture_output=True,
            text=True,
            timeout=FRAMEWORK_HEALTHCHECK_TIMEOUT_SEC + 1,
        )
    except Exception:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return None, "framework_healthcheck_exec_failed"

    if check.returncode != 0:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return None, "framework_healthcheck_failed"

    status = extract_http_status(check.stdout or "")
    if status is None or status >= 500:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return None, "framework_healthcheck_bad_status"

    return {
        "mode": "framework_http",
        "host": "127.0.0.1",
        "port": port,
        "base_url": base_url,
        "process": proc,
        "work_dir": work_dir,
        "router_path": router_path,
        "framework_name": str(profile.get("framework_name") or ""),
        "framework_version": str(profile.get("framework_version") or ""),
    }, ""


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
                str(row.get("skip_reason") or "-"),
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
        "# 动态调试验证证据\n\n"
        + markdown_table(
            ["编号", "漏洞类型", "判定", "跳过分类", "变化", "尝试数", "Payload来源", "请求来源", "Payload", "PoC", "备注"],
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
                str(row.get("skip_reason") or "-"),
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
        "# 动态调试过程记录\n\n"
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
                "跳过分类",
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
            marker = "有变化" if diff.get("changed") else "无变化"
            step_lines.append(
                f"{diff.get('step')}. [{marker}] {diff.get('op')} | {diff.get('expr')}\n"
                f"   before: {compact_cell(diff.get('before') or '', max_len=120)}\n"
                f"   after : {compact_cell(diff.get('after') or '', max_len=120)}"
            )
        if not step_lines:
            step_lines.append("无变换步骤")

        detail_blocks.append(
            "\n".join(
                [
                    f"## {case_id}",
                    f"- 结果: {row.get('result') or '-'}",
                    f"- Sink探针命中: {bool(row.get('sink_probe_hit'))}",
                    f"- 污点到达Sink: {bool(row.get('taint_var_reached_sink'))}",
                    f"- 追踪文件: {row.get('trace_case_file') or '-'}",
                    "",
                    "Sink关键帧:",
                    f"- 变更前: {compact_cell(sink_frame.get('before') or '', max_len=180)}",
                    f"- 变更后: {compact_cell(sink_frame.get('after') or '', max_len=180)}",
                    f"- 输入: {compact_cell(sink_frame.get('input') or '', max_len=120)}",
                    "",
                    "变换差异:",
                    *step_lines,
                ]
            )
        )
    return (
        "# 动态调试函数追踪\n\n"
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
        "# 动态调试 PoC 命令\n\n"
        + markdown_table(
            ["编号", "漏洞类型", "方法", "路径", "Payload来源", "请求来源", "结果", "PoC命令"],
            table_rows,
        )
        + "\n"
    )


DEBUG_JSON_NAMES = {
    "evidence": "动态调试证据.json",
    "process": "动态调试过程.json",
    "poc": "动态调试PoC.json",
    "func_trace": "函数追踪证据.json",
}

DEBUG_MD_NAMES = {
    "evidence": "动态调试证据.md",
    "process": "动态调试过程.md",
    "poc": "动态调试PoC.md",
    "func_trace": "函数追踪证据.md",
}

DEBUG_RUNTIME_JSON = "动态运行元信息.json"
DEBUG_RUNTIME_MD = "动态运行元信息.md"


def write_debug_outputs(
    debug_dir: str,
    evidence_rows: List[Dict[str, Any]],
    process_rows: List[Dict[str, Any]],
    poc_rows: List[Dict[str, Any]],
    func_trace_rows: List[Dict[str, Any]],
) -> None:
    json_payloads = {
        DEBUG_JSON_NAMES["evidence"]: evidence_rows,
        DEBUG_JSON_NAMES["process"]: process_rows,
        DEBUG_JSON_NAMES["poc"]: poc_rows,
        DEBUG_JSON_NAMES["func_trace"]: func_trace_rows,
    }
    md_payloads = {
        DEBUG_MD_NAMES["evidence"]: render_md(evidence_rows),
        DEBUG_MD_NAMES["process"]: render_process_md(process_rows),
        DEBUG_MD_NAMES["poc"]: render_poc_md(poc_rows),
        DEBUG_MD_NAMES["func_trace"]: render_func_trace_md(func_trace_rows),
    }

    for name, payload in json_payloads.items():
        write_json(os.path.join(debug_dir, name), payload)

    for name, payload in md_payloads.items():
        write_text(os.path.join(debug_dir, name), payload)


def write_empty_outputs(debug_dir: str) -> None:
    evidence_rows: List[Dict[str, Any]] = []
    process_rows: List[Dict[str, Any]] = []
    poc_rows: List[Dict[str, Any]] = []
    func_trace_rows: List[Dict[str, Any]] = []
    write_debug_outputs(debug_dir, evidence_rows, process_rows, poc_rows, func_trace_rows)


def summarize_result_counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    stats = {"total": 0, "confirmed": 0, "conditional": 0, "rejected": 0, "skipped": 0}
    for row in rows:
        result = str(row.get("result") or "").strip().lower()
        if result not in {"confirmed", "conditional", "rejected", "skipped"}:
            continue
        stats["total"] += 1
        stats[result] += 1
    return stats


def render_runtime_meta_md(meta: Dict[str, Any]) -> str:
    stats = meta.get("result_stats") if isinstance(meta.get("result_stats"), dict) else {}
    lines = [
        "# 动态运行元信息",
        "",
        f"- 本次运行ID：`{meta.get('run_id') or '-'}`",
        f"- Docker执行：`{'是' if meta.get('executed_in_container') else '否'}`",
        f"- 生成时间：{meta.get('generated_at') or '-'}",
        f"- 用例总数：{meta.get('case_count') or 0}",
        f"- 框架模式：`{meta.get('framework_mode') or '-'}`",
        f"- 框架启动状态：`{meta.get('framework_boot_status') or '-'}`",
        "",
        "## 结果统计",
        "| 指标 | 数值 |",
        "|---|---|",
        f"| 总数 | {stats.get('total', 0)} |",
        f"| 已确认 | {stats.get('confirmed', 0)} |",
        f"| 有条件成立 | {stats.get('conditional', 0)} |",
        f"| 已排除 | {stats.get('rejected', 0)} |",
        f"| 已跳过 | {stats.get('skipped', 0)} |",
        "",
    ]
    return "\n".join(lines)


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


def read_slice_code_for_context(case: Dict[str, Any], max_chars: int = 5000) -> str:
    path = str(case.get("debug_script") or "").strip()
    if not path:
        return ""
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return ""
    if len(text) > max_chars:
        return text[:max_chars]
    return text


def ai_seed_payloads_for_case(case: Dict[str, Any], max_payloads: int = 8) -> List[str]:
    sink_type = str(case.get("sink_type") or case.get("vuln_type") or "").lower()
    base = "test"
    payloads: List[str] = []
    if "sql" in sink_type:
        base = "' OR 1=1 -- -"
        payloads = [
            base,
            urllib.parse.quote(base, safe=""),
            "1'/**/OR/**/'1'='1",
            "1%27%20OR%201=1--%20-",
        ]
    elif "rce" in sink_type:
        base = ";id;"
        payloads = [
            base,
            urllib.parse.quote(base, safe=""),
            "%3Bid%3B",
            "|id",
        ]
    elif "file" in sink_type:
        base = "../../../../etc/passwd"
        payloads = [
            base,
            urllib.parse.quote(base, safe=""),
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..//..//..//..//etc/passwd",
        ]
    elif "ssrf" in sink_type:
        base = "http://127.0.0.1:80/"
        payloads = [
            base,
            "http://localhost/",
            "http://2130706433/",
            urllib.parse.quote(base, safe=":/"),
        ]
    elif "xxe" in sink_type:
        base = "<!DOCTYPE r [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><r>&xxe;</r>"
        payloads = [
            base,
            urllib.parse.quote(base, safe=""),
            "<?xml version='1.0'?><!DOCTYPE a [<!ENTITY b SYSTEM 'file:///etc/hosts'>]><a>&b;</a>",
        ]
    elif "xss" in sink_type or "ssti" in sink_type:
        base = "<svg/onload=alert(1)>"
        payloads = [
            base,
            urllib.parse.quote(base, safe=""),
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "{{7*7}}",
        ]
    elif "deserialize" in sink_type:
        base = 'O:8:"Exploit":0:{}'
        payloads = [
            base,
            urllib.parse.quote(base, safe=""),
            "a:1:{i:0;O:8:\"Exploit\":0:{}}",
        ]
    else:
        payloads = [base, urllib.parse.quote(base, safe="")]
    uniq: List[str] = []
    seen = set()
    for p in payloads:
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(key)
    return uniq[: max_payloads if max_payloads > 0 else 1]


def build_ai_request_context(cases: List[Dict[str, Any]], debug_dir: str, ai_only_bypass: bool = False) -> str:
    rows: List[Dict[str, Any]] = []
    for case in cases:
        if ai_only_bypass:
            payloads = ai_seed_payloads_for_case(case, max_payloads=8)
            payload_source = "ai_seed"
        else:
            payloads, payload_source = dictionary_payloads_for_case(case, max_payloads=8)
        slice_file = str(case.get("debug_script") or "")
        slice_code = read_slice_code_for_context(case)
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
                "slice_file": slice_file,
                "slice_code": slice_code,
            }
        )

    context = {
        "cases": rows,
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "case_count": len(rows),
            "strategy": "ai_only_iterative_bypass" if ai_only_bypass else "dictionary_first_then_ai",
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
        url = f"{TARGET_URL}{path_norm}"

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
    runtime_mode = str(server.get("mode") or "curl_http") if isinstance(server, dict) else "curl_http"
    meta: Dict[str, Any] = {
        "return_code": None,
        "duration_ms": 0,
        "stdout_tail": "",
        "stderr_tail": "",
        "http_status": None,
        "execution_mode": runtime_mode,
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
        if runtime_mode == "framework_http":
            fallback_body = tail_text(response_body or proc.stdout or "", max_chars=800, max_lines=20)
            fallback_input = ""
            post_bucket = input_map.get("POST") if isinstance(input_map.get("POST"), dict) else {}
            body_bucket = input_map.get("BODY") if isinstance(input_map.get("BODY"), dict) else {}
            if isinstance(post_bucket, dict) and post_bucket:
                fallback_input = str(next(iter(post_bucket.values())))
            elif isinstance(body_bucket, dict) and body_bucket:
                fallback_input = str(next(iter(body_bucket.values())))
            elif isinstance(input_map.get("GET"), dict) and input_map.get("GET"):
                fallback_input = str(next(iter(input_map.get("GET").values())))

            fallback_output = {
                "status": "done",
                "input": fallback_input,
                "final_value": fallback_body,
                "transform_chain": [],
                "transform_steps": [],
                "call_stack": [],
                "var_snapshot": {},
                "sink_probe_hit": False,
                "taint_var_reached_sink": False,
                "change_type": "weak_change" if fallback_body else "unknown",
                "framework_fallback_no_json": True,
            }
            return fallback_output, "", meta
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
        cmd = f"curl -i -sS -X GET '{TARGET_URL}/'"
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

    if isinstance(server, dict) and server.get("mode") in {"curl_http", "framework_http"} and server.get("base_url"):
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
                "execution_mode": str(server.get("mode") or "curl_http") if isinstance(server, dict) else "slice_cli",
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
    framework_fallback_no_json = bool(output.get("framework_fallback_no_json")) if isinstance(output, dict) else False

    notes = base_notes
    if isinstance(output, dict) and output.get("input") not in (None, ""):
        input_val = str(output.get("input"))

    if framework_fallback_no_json:
        notes = (notes + "; " if notes else "") + "framework_fallback:no_json_output"

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
        "execution_mode": proc_meta.get("execution_mode") or (str(server.get("mode") or "curl_http") if isinstance(server, dict) else "slice_cli"),
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


def is_auth_required_signal(selected: Dict[str, Any]) -> bool:
    status = selected.get("http_status")
    if isinstance(status, int) and status in {401, 403}:
        return True
    reasons = selected.get("dynamic_reasons")
    if isinstance(reasons, list):
        for reason in reasons:
            text = str(reason or "").lower()
            if any(k in text for k in ("auth", "login", "forbidden", "unauthorized", "permission")):
                return True
    combined = "\n".join(
        [
            str(selected.get("response_header_preview") or ""),
            str(selected.get("response_body_preview") or ""),
            str(selected.get("stderr_tail") or ""),
            str(selected.get("stdout_tail") or ""),
            str(selected.get("notes") or ""),
        ]
    ).lower()
    auth_keywords = [
        "unauthorized",
        "forbidden",
        "login required",
        "authentication",
        "auth required",
        "permission denied",
        "access denied",
        "请登录",
        "未登录",
        "无权限",
        "权限不足",
    ]
    return any(k in combined for k in auth_keywords)


def classify_skip_reason(
    selected: Dict[str, Any],
    attempt_count: int,
    framework_profile: Optional[Dict[str, Any]] = None,
) -> str:
    result = str(selected.get("result") or "").strip().lower()
    if result != "skipped":
        return ""

    error_reason = str(selected.get("error_reason") or "").strip().lower()
    process_status = str(selected.get("process_status") or "").strip().lower()
    profile = framework_profile if isinstance(framework_profile, dict) else {}
    boot_status = str(profile.get("boot_status") or "").strip().lower()

    if error_reason == "curl_timeout" or "timeout" in error_reason:
        return "timeout"
    if is_auth_required_signal(selected):
        return "auth_required"

    precheck_errors = {
        "no_attempts",
        "script_missing",
        "php_not_found",
        "curl_missing",
        "http_server_unavailable",
        "framework_boot_not_supported",
        "framework_doc_root_missing",
        "framework_index_missing",
        "framework_http_server_start_failed",
        "framework_healthcheck_exec_failed",
        "framework_healthcheck_failed",
        "framework_healthcheck_bad_status",
    }
    if error_reason in precheck_errors:
        return "precheck_skip"
    if attempt_count <= 0 and process_status in {"error", "skipped"}:
        return "precheck_skip"
    if boot_status == "failed" and process_status in {"error", "skipped"}:
        return "precheck_skip"

    return "runtime_skip"


def build_case_report_rows(
    case: Dict[str, Any],
    selected: Dict[str, Any],
    matched_index: int,
    attempt_count: int,
    dictionary_count: int,
    ai_count: int,
    ai_status: str,
    stop_reason: str,
    until_confirmed: bool,
    trace_case_file: str = "",
    framework_profile: Optional[Dict[str, Any]] = None,
    runtime_mode: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    candidate = selected.get("request_candidate") or {}
    method = str(candidate.get("method") or case.get("route_method") or "GET")
    path = str(candidate.get("path") or case.get("route_path") or "/")
    content_type = str(candidate.get("content_type") or "")

    poc_cmd = build_poc_command(method, path, selected.get("input_map") if isinstance(selected.get("input_map"), dict) else {}, content_type)
    poc_source = str(selected.get("request_source") or "rules")
    if not poc_cmd:
        poc_cmd, poc_source, method, path = fallback_poc_from_case(case)
    selected_result = str(selected.get("result") or "skipped")
    confirmation_target = "confirmed" if until_confirmed else "confirmed_or_conditional"
    if until_confirmed:
        confirmation_met = selected_result == "confirmed"
    else:
        confirmation_met = selected_result in {"confirmed", "conditional"}

    profile = framework_profile if isinstance(framework_profile, dict) else {}
    framework_mode = str(profile.get("mode") or "snippet")
    framework_name = str(profile.get("framework_name") or "")
    framework_version = str(profile.get("framework_version") or "")
    framework_boot_status = str(profile.get("boot_status") or "")
    framework_boot_error = str(profile.get("boot_error") or "")
    runtime_mode_value = runtime_mode or str(profile.get("runtime_mode") or framework_mode or "snippet")
    skip_reason = classify_skip_reason(selected, attempt_count, framework_profile=profile)

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
        "confirmation_target": confirmation_target,
        "confirmation_met": confirmation_met,
        "poc_cmd": poc_cmd,
        "poc_source": poc_source,
        "payload_used": selected.get("payload_used") or "",
        "payload_source": selected.get("payload_source") or "",
        "request_source": selected.get("request_source") or case.get("planning_source") or "rules",
        "attempt_count": attempt_count,
        "dictionary_attempt_count": dictionary_count,
        "ai_attempt_count": ai_count,
        "ai_realtime_status": ai_status,
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
        "framework_mode": framework_mode,
        "framework_name": framework_name,
        "framework_version": framework_version,
        "framework_boot_status": framework_boot_status,
        "framework_boot_error": framework_boot_error,
        "runtime_mode": runtime_mode_value,
        "skip_reason": skip_reason,
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
        "confirmation_target": confirmation_target,
        "confirmation_met": confirmation_met,
        "matched_attempt_index": matched_index,
        "trace_case_file": trace_case_file,
        "framework_mode": framework_mode,
        "framework_name": framework_name,
        "framework_version": framework_version,
        "framework_boot_status": framework_boot_status,
        "framework_boot_error": framework_boot_error,
        "runtime_mode": runtime_mode_value,
        "skip_reason": skip_reason,
    }

    poc_row = {
        "case_id": case.get("case_id"),
        "module": case.get("module"),
        "vuln_type": case.get("vuln_type"),
        "entry": case.get("entry"),
        "route_method": method,
        "route_path": path,
        "confirmation_target": confirmation_target,
        "confirmation_met": confirmation_met,
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
        "framework_mode": framework_mode,
        "framework_name": framework_name,
        "framework_version": framework_version,
        "framework_boot_status": framework_boot_status,
        "framework_boot_error": framework_boot_error,
        "runtime_mode": runtime_mode_value,
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
        "framework_mode": framework_mode,
        "framework_name": framework_name,
        "framework_version": framework_version,
        "framework_boot_status": framework_boot_status,
        "framework_boot_error": framework_boot_error,
        "runtime_mode": runtime_mode_value,
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


def build_ai_fallback_candidates(
    case: Dict[str, Any],
    request_candidates: List[Dict[str, Any]],
    ai_budget: int,
) -> List[Dict[str, Any]]:
    limit = ai_budget if ai_budget > 0 else 8
    seed_payloads = ai_seed_payloads_for_case(case, max_payloads=max(1, limit))
    reqs = request_candidates if request_candidates else [normalize_request_candidate(case, {})]
    fallback: List[Dict[str, Any]] = []
    if not reqs:
        return fallback
    for idx, payload in enumerate(seed_payloads):
        req = reqs[idx % len(reqs)]
        fallback.append(
            {
                "method": req.get("method"),
                "path": req.get("path"),
                "bucket": req.get("bucket"),
                "param": req.get("param"),
                "content_type": req.get("content_type"),
                "payload": payload,
                "reason": "ai_seed_bypass",
                "confidence": 0.35,
            }
        )
        if len(fallback) >= limit:
            break
    return fallback


def execute_case(
    case: Dict[str, Any],
    rules: Dict[str, List[str]],
    ai_suggestions_map: Dict[str, List[Dict[str, Any]]],
    ai_realtime_enabled: bool,
    ai_budget: int,
    ai_runtime_status: str,
    ai_force_all: bool,
    until_confirmed: bool,
    ai_only_bypass: bool,
    project_root: str,
    out_root: str,
    trace_verbose: bool = False,
    trace_case_dir: str = "",
    framework_profile: Optional[Dict[str, Any]] = None,
    runtime_mode: str = "snippet",
    shared_server: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    case_id = str(case.get("case_id") or "")
    module = str(case.get("module") or "")
    category = CATEGORY_RULES.get(module, "input_limit")

    notes = str(case.get("notes") or "")
    profile = framework_profile if isinstance(framework_profile, dict) else {}
    if str(profile.get("framework_name") or "").strip():
        notes = (notes + "; " if notes else "") + (
            f"framework:{profile.get('framework_name')}@{profile.get('framework_version') or 'unknown'}"
        )
    try:
        auto_note = generate_slice_for_case(case, project_root, out_root)
    except Exception as exc:
        auto_note = f"auto_slice_error:{exc.__class__.__name__}"
    if auto_note:
        notes = (notes + "; " if notes else "") + auto_note

    server = shared_server if isinstance(shared_server, dict) else None
    server_err = ""
    server_owned = False
    if not isinstance(server, dict):
        server_owned = True
        server, server_err = start_case_http_server(case, out_root)
        if server_err:
            notes = (notes + "; " if notes else "") + f"server_error:{server_err}"
    else:
        notes = (notes + "; " if notes else "") + f"runtime_mode:{runtime_mode or 'framework'}"

    request_candidates = request_candidates_for_case(case)
    if ai_only_bypass:
        dictionary_payloads = []
        dictionary_payload_source = "ai_only_bypass"
    else:
        dictionary_payloads, dictionary_payload_source = dictionary_payloads_for_case(case)

    attempts: List[Dict[str, Any]] = []
    baseline_attempt: Optional[Dict[str, Any]] = None
    dictionary_count = 0
    ai_count = 0
    stop_reason = "exhausted"
    dictionary_selected: Optional[Dict[str, Any]] = None
    dictionary_selected_idx = 0
    target_results = {"confirmed"} if until_confirmed else {"confirmed", "conditional"}
    effective_ai_budget = ai_budget
    if ai_only_bypass and effective_ai_budget <= 0:
        effective_ai_budget = 8

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
            until_confirmed=until_confirmed,
            trace_case_file=trace_file,
            framework_profile=profile,
            runtime_mode=runtime_mode,
        )

    try:
        # 1) Dictionary first (default mode only): payload outer loop, request candidate inner loop.
        if not ai_only_bypass:
            dictionary_hit = False
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
                    if attempt.get("result") in target_results:
                        if not ai_force_all:
                            stop_reason = f"dictionary_{attempt.get('result')}"
                            selected = attempt
                            matched_idx = len(attempts)
                            ai_status = "disabled" if not ai_realtime_enabled else "not_needed"
                            return finalize(selected, matched_idx, ai_status, stop_reason)
                        dictionary_selected = attempt
                        dictionary_selected_idx = len(attempts)
                        dictionary_hit = True
                        break
                if dictionary_hit:
                    break

        # 2) AI loop.
        ai_status = "disabled"
        if ai_realtime_enabled:
            if ai_runtime_status == "failed" and not ai_only_bypass:
                ai_status = "failed"
            else:
                ai_status = "ok" if ai_runtime_status != "failed" else "failed_seed"
                ai_candidates = ai_suggestions_map.get(case_id) or []
                if ai_only_bypass and not ai_candidates:
                    ai_candidates = build_ai_fallback_candidates(case, request_candidates, effective_ai_budget)
                    if ai_status == "ok":
                        ai_status = "seed_only"
                dedupe = set()
                capped = ai_candidates[: max(effective_ai_budget, 0)]

                for raw in capped:
                    if ai_count >= effective_ai_budget:
                        break

                    req = normalize_request_candidate(case, raw if isinstance(raw, dict) else {})
                    payload = str(raw.get("payload") or "").strip() if isinstance(raw, dict) else ""
                    if not payload:
                        # Keep flow resilient when AI omitted payload.
                        if ai_only_bypass:
                            seed_payloads = ai_seed_payloads_for_case(case, max_payloads=max(1, effective_ai_budget or 1))
                            payload = seed_payloads[0] if seed_payloads else "payload"
                        else:
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

                    if attempt.get("result") in target_results:
                        stop_reason = f"ai_{attempt.get('result')}"
                        selected = attempt
                        matched_idx = len(attempts)
                        return finalize(selected, matched_idx, ai_status, stop_reason)

                if ai_count == 0:
                    ai_status = "no_candidates"

        if dictionary_selected is not None:
            matched_result = str(dictionary_selected.get("result") or "confirmed")
            if not ai_realtime_enabled:
                stop_reason = f"dictionary_{matched_result}_ai_disabled"
            elif ai_status == "failed":
                stop_reason = f"dictionary_{matched_result}_ai_failed"
            elif ai_status == "no_candidates":
                stop_reason = f"dictionary_{matched_result}_ai_no_candidates"
            else:
                stop_reason = f"dictionary_{matched_result}_ai_exhausted"
            return finalize(dictionary_selected, dictionary_selected_idx, ai_status, stop_reason)

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
                "execution_mode": str(server.get("mode") or "curl_http") if isinstance(server, dict) else "slice_cli",
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

        if ai_only_bypass:
            if ai_count == 0:
                if ai_status == "no_candidates":
                    stop_reason = "ai_no_candidates"
                elif ai_status == "disabled":
                    stop_reason = "ai_disabled"
                else:
                    stop_reason = "ai_no_attempt"
            elif until_confirmed and str(selected.get("result") or "") != "confirmed":
                stop_reason = "ai_target_confirmed_not_reached"
            else:
                stop_reason = "ai_exhausted_no_match"
        elif until_confirmed and str(selected.get("result") or "") != "confirmed":
            stop_reason = "target_confirmed_not_reached"
        else:
            stop_reason = "exhausted_no_match"
        matched_index = (selected_idx + 1) if selected_idx is not None else 1

        return finalize(selected, matched_index, ai_status, stop_reason)
    finally:
        if server_owned:
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
    parser.add_argument("--ai-force-all", action="store_true", help="Force AI pass for every case even when dictionary already matches")
    parser.add_argument("--until-confirmed", dest="until_confirmed", action="store_true", help="Keep trying until result becomes confirmed (within budget)")
    parser.add_argument("--allow-conditional-stop", dest="until_confirmed", action="store_false", help="Allow conditional as early stop target")
    parser.add_argument("--ai-only-bypass", action="store_true", help="Use AI iterative bypass only (skip dictionary loop)")
    parser.set_defaults(until_confirmed=False)
    parser.add_argument("--trace-verbose", action="store_true", help="Write per-case verbose trace json")
    parser.add_argument("--target-url", default="http://target", help="Target URL for dynamic verification (default: http://target)")
    parser.add_argument("--framework-profile", default="", help="Optional framework profile json generated by audit_cli")

    args = parser.parse_args()
    global TARGET_URL
    TARGET_URL = args.target_url.rstrip("/")

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)
    run_id = str(os.environ.get("AUDIT_RUN_ID") or "").strip()
    if not run_id:
        run_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
    run_started_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    debug_dir = os.path.join(out_root, "debug_verify")
    os.makedirs(debug_dir, exist_ok=True)
    trace_case_dir = os.path.join(debug_dir, "trace_cases")

    framework_profile = load_framework_profile(str(args.framework_profile or "").strip(), project_root)
    framework_profile.setdefault("project_root", project_root)
    if str(framework_profile.get("mode") or "") == "framework":
        framework_profile.setdefault("boot_status", "pending")
        framework_profile.setdefault("runtime_mode", "framework_pending")
    else:
        framework_profile["boot_status"] = "not_required"
        framework_profile["runtime_mode"] = "snippet"
    write_framework_profile(framework_profile, debug_dir, out_root)

    if args.cases:
        cases_path = os.path.abspath(args.cases)
    else:
        cases_path = ensure_cases(out_root, project_root)

    if not os.path.exists(cases_path):
        write_empty_outputs(debug_dir)
        empty_meta = {
            "run_id": run_id,
            "generated_at": run_started_at,
            "executed_in_container": bool(running_in_container()),
            "case_count": 0,
            "framework_mode": str(framework_profile.get("runtime_mode") or framework_profile.get("mode") or "-"),
            "framework_boot_status": str(framework_profile.get("boot_status") or "-"),
            "result_stats": summarize_result_counts([]),
        }
        write_json(os.path.join(debug_dir, DEBUG_RUNTIME_JSON), empty_meta)
        write_text(os.path.join(debug_dir, DEBUG_RUNTIME_MD), render_runtime_meta_md(empty_meta))
        context_path = build_ai_request_context([], debug_dir, ai_only_bypass=bool(args.ai_only_bypass))
        print(f"No debug cases found. Context: {context_path}; framework_profile: {os.path.join(debug_dir, FRAMEWORK_PROFILE_JSON)}")
        return

    with open(cases_path, "r", encoding="utf-8") as f:
        cases = json.load(f) or []

    if not isinstance(cases, list) or not cases:
        write_empty_outputs(debug_dir)
        empty_meta = {
            "run_id": run_id,
            "generated_at": run_started_at,
            "executed_in_container": bool(running_in_container()),
            "case_count": 0,
            "framework_mode": str(framework_profile.get("runtime_mode") or framework_profile.get("mode") or "-"),
            "framework_boot_status": str(framework_profile.get("boot_status") or "-"),
            "result_stats": summarize_result_counts([]),
        }
        write_json(os.path.join(debug_dir, DEBUG_RUNTIME_JSON), empty_meta)
        write_text(os.path.join(debug_dir, DEBUG_RUNTIME_MD), render_runtime_meta_md(empty_meta))
        context_path = build_ai_request_context([], debug_dir, ai_only_bypass=bool(args.ai_only_bypass))
        print(f"No debug cases found. Context: {context_path}; framework_profile: {os.path.join(debug_dir, FRAMEWORK_PROFILE_JSON)}")
        return

    for case in cases:
        try:
            _ = generate_slice_for_case(case, project_root, out_root)
        except Exception:
            continue

    context_path = build_ai_request_context(cases, debug_dir, ai_only_bypass=bool(args.ai_only_bypass))
    if args.prepare_ai_context_only:
        print(f"ai_request_context.json written: {context_path}; framework_profile: {os.path.join(debug_dir, FRAMEWORK_PROFILE_JSON)}")
        return

    rules = load_change_rules(RULES_PATH)
    ai_budget = max(0, int(args.ai_rounds or 0) * int(args.ai_candidates_per_round or 0))
    ai_suggestions_map = load_ai_suggestions(args.ai_suggestions)
    ai_runtime_status = str(args.ai_runtime_status or "").strip().lower()

    shared_server: Optional[Dict[str, Any]] = None
    framework_runtime_mode = "snippet"
    if str(framework_profile.get("mode") or "") == "framework":
        shared_server, boot_err = start_framework_http_server(framework_profile, out_root)
        if isinstance(shared_server, dict):
            framework_profile["boot_status"] = "ok"
            framework_profile["boot_error"] = ""
            framework_profile["runtime_mode"] = "framework_http"
            framework_profile["runtime_base_url"] = str(shared_server.get("base_url") or "")
            framework_runtime_mode = "framework_http"
        else:
            framework_profile["boot_status"] = "failed"
            framework_profile["boot_error"] = str(boot_err or "framework_boot_failed")
            framework_profile["runtime_mode"] = "snippet_fallback"
            framework_runtime_mode = "snippet_fallback"
    write_framework_profile(framework_profile, debug_dir, out_root)

    evidence_rows: List[Dict[str, Any]] = []
    process_rows: List[Dict[str, Any]] = []
    poc_rows: List[Dict[str, Any]] = []
    func_trace_rows: List[Dict[str, Any]] = []

    try:
        for case in cases:
            evidence_row, process_row, poc_row, func_trace_row = execute_case(
                case,
                rules,
                ai_suggestions_map=ai_suggestions_map,
                ai_realtime_enabled=bool(args.ai_realtime),
                ai_budget=ai_budget,
                ai_runtime_status=ai_runtime_status,
                ai_force_all=bool(args.ai_force_all),
                until_confirmed=bool(args.until_confirmed),
                ai_only_bypass=bool(args.ai_only_bypass),
                project_root=project_root,
                out_root=out_root,
                trace_verbose=bool(args.trace_verbose),
                trace_case_dir=trace_case_dir,
                framework_profile=framework_profile,
                runtime_mode=framework_runtime_mode,
                shared_server=shared_server,
            )
            evidence_rows.append(evidence_row)
            process_rows.append(process_row)
            poc_rows.append(poc_row)
            func_trace_rows.append(func_trace_row)
    finally:
        stop_case_http_server(shared_server)

    write_debug_outputs(debug_dir, evidence_rows, process_rows, poc_rows, func_trace_rows)
    runtime_meta = {
        "run_id": run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "executed_in_container": bool(running_in_container()),
        "case_count": len(cases),
        "framework_mode": framework_runtime_mode,
        "framework_boot_status": str(framework_profile.get("boot_status") or "-"),
        "ai_only_bypass": bool(args.ai_only_bypass),
        "ai_realtime": bool(args.ai_realtime),
        "ai_runtime_status": ai_runtime_status or ("disabled" if not args.ai_realtime else "unknown"),
        "until_confirmed": bool(args.until_confirmed),
        "result_stats": summarize_result_counts(evidence_rows),
    }
    write_json(os.path.join(debug_dir, DEBUG_RUNTIME_JSON), runtime_meta)
    write_text(os.path.join(debug_dir, DEBUG_RUNTIME_MD), render_runtime_meta_md(runtime_meta))

    print(f"动态调试证据.json written: {os.path.join(debug_dir, DEBUG_JSON_NAMES['evidence'])}")
    print(f"动态调试过程.json written: {os.path.join(debug_dir, DEBUG_JSON_NAMES['process'])}")
    print(f"动态调试PoC.json written: {os.path.join(debug_dir, DEBUG_JSON_NAMES['poc'])}")
    print(f"函数追踪证据.json written: {os.path.join(debug_dir, DEBUG_JSON_NAMES['func_trace'])}")


if __name__ == "__main__":
    main()
