#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple

from common import build_output_root, write_json, write_text
from audit_helpers import markdown_table


MODULE_LABELS = {
    "sql_audit": "SQL 注入",
    "auth_audit": "鉴权/访问控制",
    "vuln_report": "依赖漏洞",
    "file_audit": "文件风险",
    "rce_audit": "命令执行",
    "ssrf_xxe_audit": "SSRF/XXE",
    "xss_ssti_audit": "XSS/SSTI",
    "csrf_audit": "CSRF",
    "var_override_audit": "变量覆盖",
    "serialize_audit": "反序列化",
}

MODULE_ORDER = [
    "sql_audit",
    "auth_audit",
    "vuln_report",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
]

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_CN = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

RESULT_CN = {
    "confirmed": "已确认",
    "conditional": "条件成立",
    "rejected": "已排除",
    "skipped": "已跳过",
}

RESULT_ALIAS_TEXT = {
    "confirmed": "已确认可利用",
    "conditional": "条件成立",
    "rejected": "已排除",
    "skipped": "已跳过",
}

HUMAN_TERM_LABELS = {
    "sink_probe_hit": "危险函数探针命中",
    "taint_var_reached_sink": "用户输入到达危险函数",
}

DOMAIN_CN_LABELS = {
    "sql": "SQL 注入",
    "rce": "命令执行",
    "file": "文件风险",
    "ssrf": "SSRF/XXE",
    "xss": "XSS/SSTI",
    "deserialize": "反序列化",
    "csrf": "CSRF",
    "auth": "鉴权/访问控制",
    "generic": "其他漏洞",
}

CN_REPORT_MD = "总报告.md"
CN_REPORT_APPENDIX_MD = "总报告_技术附录.md"
CN_REPORT_JSON = "总报告.json"
CN_REPORT_ALIAS_MD = "最终报告.md"
CN_REPORT_ALIAS_APPENDIX_MD = "最终报告_技术附录.md"
CN_REPORT_ALIAS_JSON = "最终报告.json"

PRIMARY_STATIC_MD = "最终静态审计结果.md"
PRIMARY_DYNAMIC_MD = "动态debug审计报告.md"
PRIMARY_AI_VERIFY_MD = "AI深入验证最终报告.md"

ARCHIVE_ROOT = "归档"
ARCHIVE_STAGE_DIR = os.path.join(ARCHIVE_ROOT, "阶段报告")
ARCHIVE_DEBUG_DIR = os.path.join(ARCHIVE_ROOT, "调试证据")
ARCHIVE_BURP_DIR = os.path.join(ARCHIVE_ROOT, "Burp模板")
ARCHIVE_QUALITY_DIR = os.path.join(ARCHIVE_ROOT, "质量门禁")
ARCHIVE_BINDING_DIR = os.path.join(ARCHIVE_ROOT, "结论绑定")
BINDING_MATRIX_MD = "静态_动态_AI_结论对照表.md"

DEBUG_EVIDENCE_JSON = "动态调试证据.json"
DEBUG_PROCESS_JSON = "动态调试过程.json"
DEBUG_POC_JSON = "动态调试PoC.json"
DEBUG_FUNC_TRACE_JSON = "函数追踪证据.json"

RESULT_CN_PLAIN = {
    "confirmed": "已确认",
    "conditional": "有条件成立",
    "rejected": "已排除",
    "skipped": "已跳过",
}

AUTH_HINT_KEYWORDS = (
    "auth",
    "jwt",
    "token",
    "login",
    "session",
    "permission",
    "role",
    "guard",
    "middleware",
)


def file_sha256(path: str) -> str:
    if not path or not os.path.exists(path):
        return "-"
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "-"


def wordlists_version() -> str:
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wordlists"))
    path = os.path.join(base, "sources.json")
    if not os.path.exists(path):
        return "-"
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return "sources.json"
    parts: List[str] = []
    for entry in data.get("sources", []):
        if isinstance(entry, str):
            parts.append(entry)
            continue
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("repo") or "source"
            commit = entry.get("commit") or entry.get("tag") or ""
            parts.append(f"{name}@{commit}" if commit else str(name))
    return "; ".join(parts) if parts else "sources.json"


def build_meta_rows(out_root: str) -> List[List[str]]:
    ai_findings = os.path.join(out_root, "ai_audit", "ai_findings.json")
    ai_confirm = os.path.join(out_root, "ai_confirm.json")
    script_final = os.path.join(os.path.dirname(__file__), "final_report.py")
    script_ai_audit = os.path.join(os.path.dirname(__file__), "ai_audit.py")
    return [
        ["输出目录", "审计输出根目录"],
        ["生成时间", time.strftime("%Y-%m-%d %H:%M:%S")],
        ["AI初审结果哈希", file_sha256(ai_findings)],
        ["AI复核结果哈希", file_sha256(ai_confirm)],
        ["字典版本", wordlists_version()],
        ["AI缓存哈希", file_sha256(os.path.join(out_root, "ai_audit", "ai_cache.json"))],
        ["final_report.py", file_sha256(script_final)],
        ["ai_audit.py", file_sha256(script_ai_audit)],
    ]


def _load_json(path: str, default: Any) -> Any:
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def load_findings(out_root: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    findings: List[Dict[str, Any]] = []
    sources: List[str] = []
    for root, _, files in os.walk(out_root):
        for f in files:
            if f not in ("findings.json", "auth_evidence.json"):
                continue
            path = os.path.join(root, f)
            data = _load_json(path, None)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        row = dict(item)
                        row["_source"] = os.path.relpath(path, out_root)
                        findings.append(row)
                sources.append(path)
            elif isinstance(data, dict) and isinstance(data.get("results"), list):
                for item in data.get("results") or []:
                    if isinstance(item, dict):
                        row = dict(item)
                        row["_source"] = os.path.relpath(path, out_root)
                        findings.append(row)
                sources.append(path)
    return findings, sources


def load_debug_evidence(out_root: str) -> List[Dict[str, Any]]:
    path = os.path.join(out_root, "debug_verify", DEBUG_EVIDENCE_JSON)
    data = _load_json(path, None)
    if isinstance(data, list):
        return data
    return []


def load_debug_process(out_root: str) -> List[Dict[str, Any]]:
    path = os.path.join(out_root, "debug_verify", DEBUG_PROCESS_JSON)
    data = _load_json(path, None)
    if isinstance(data, list):
        return data
    return []


def load_debug_func_trace(out_root: str) -> List[Dict[str, Any]]:
    path = os.path.join(out_root, "debug_verify", DEBUG_FUNC_TRACE_JSON)
    data = _load_json(path, None)
    if isinstance(data, list):
        return data
    return []


def load_route_auth_map(out_root: str) -> Dict[str, Dict[str, Any]]:
    path = os.path.join(out_root, "route_mapper", "routes.json")
    data = _load_json(path, None)
    if not isinstance(data, list):
        return {}

    mapping: Dict[str, Dict[str, Any]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "ANY").split("|")[0].strip().upper() or "ANY"
        route_path = str(item.get("path") or "").strip() or "/"
        middlewares = item.get("middlewares") if isinstance(item.get("middlewares"), list) else []
        mw_text = " ".join([str(m).lower() for m in middlewares])
        has_auth_hint = any(k in mw_text for k in AUTH_HINT_KEYWORDS)
        auth_required = bool(has_auth_hint)
        key = f"{method} {route_path}"
        mapping[key] = {
            "auth_required": auth_required,
            "middlewares": middlewares,
        }
        if method == "ANY":
            any_key = f"GET {route_path}"
            mapping.setdefault(any_key, mapping[key])
    return mapping


def dedup_key(f: Dict[str, Any]) -> str:
    sink = f.get("sink") or {}
    route = f.get("route") or {}
    path = route.get("path") if isinstance(route, dict) else str(route)
    key = f"{sink.get('file','')}:{sink.get('line','')}:{sink.get('type','')}:{path}:{f.get('title','')}"
    if key.strip(":") == "":
        fid = f.get("id") or ""
        base = json.dumps(f, ensure_ascii=False, sort_keys=True)
        return str(fid) or hashlib.md5(base.encode("utf-8")).hexdigest()
    return key


def deduplicate(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    uniq: Dict[str, Dict[str, Any]] = {}
    dups: List[Dict[str, Any]] = []
    for f in findings:
        key = dedup_key(f)
        if key in uniq:
            dups.append({"key": key, "id": f.get("id"), "source": f.get("_source")})
            continue
        uniq[key] = f
    return list(uniq.values()), dups


def module_from_source(f: Dict[str, Any]) -> str:
    src = str(f.get("_source") or "")
    if not src:
        return "unknown"
    parts = src.split(os.sep)
    return parts[0] if parts else "unknown"


def normalize_severity(raw: str) -> str:
    s = str(raw or "").lower()
    cvss = re.search(r"cvss\s*([0-9]+\.?[0-9]*)", s)
    if cvss:
        try:
            score = float(cvss.group(1))
            if score >= 9:
                return "critical"
            if score >= 7:
                return "high"
            if score >= 4:
                return "medium"
            return "low"
        except Exception:
            pass
    if "critical" in s or "严重" in s or "致命" in s or "危急" in s:
        return "critical"
    if "high" in s or "高危" in s:
        return "high"
    if "medium" in s or "中危" in s:
        return "medium"
    if "low" in s or "低危" in s:
        return "low"
    return "low"


def severity_rank(level: str) -> int:
    mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return mapping.get(str(level or "").lower(), 0)


def normalize_result(raw: str) -> str:
    v = str(raw or "").strip().lower()
    if v in ("confirmed", "conditional", "rejected", "skipped"):
        return v
    return "skipped"


def result_rank(result: str) -> int:
    mapping = {"confirmed": 3, "conditional": 2, "rejected": 1, "skipped": 0}
    return mapping.get(normalize_result(result), 0)


def static_conclusion_text(case: Dict[str, Any]) -> str:
    severity = str(SEVERITY_CN.get(str(case.get("severity") or "low"), case.get("severity") or "low"))
    vuln_type = str(case.get("vuln_type") or "其他")
    return f"{severity} {vuln_type}"


def dynamic_supported(status: str) -> bool:
    normalized = normalize_result(status)
    return normalized in ("confirmed", "conditional")


def dynamic_supported_text(status: str) -> str:
    normalized = normalize_result(status)
    if normalized in ("confirmed", "conditional"):
        return "支持"
    if normalized == "rejected":
        return "不支持"
    return "未验证"


def parse_entry_method_path(entry: Any) -> Tuple[str, str]:
    raw = str(entry or "").strip()
    if not raw:
        return "GET", "/"
    parts = raw.split(None, 1)
    method = str(parts[0] if parts else "GET").upper()
    path = str(parts[1] if len(parts) > 1 else "/").strip() or "/"
    return method, path


def resolve_case_burp_template(case: Dict[str, Any], burp_templates: List[str]) -> str:
    if not burp_templates:
        return "-"
    if len(burp_templates) == 1:
        return burp_templates[0]

    case_id = str(case.get("case_id") or "").lower()
    method, path = parse_entry_method_path(case.get("entry"))
    method = method.lower()
    path_tokens = [t for t in re.split(r"[^a-z0-9]+", path.lower()) if t]

    best_rel = ""
    best_score = -1
    for rel in burp_templates:
        name = os.path.basename(str(rel)).lower()
        score = 0
        if case_id and case_id in name:
            score += 10
        if method and method != "any" and method in name:
            score += 3
        for tk in path_tokens[:6]:
            if len(tk) < 2:
                continue
            if tk in name:
                score += 1
        if score > best_score:
            best_score = score
            best_rel = rel

    if best_score <= 0:
        return burp_templates[0]
    return best_rel


def build_dynamic_reason(
    dynamic_status: str,
    sink_probe_hit: bool,
    taint_var_reached_sink: bool,
    dynamic_reasons: List[Any],
    http_status: Any,
) -> str:
    normalized = normalize_result(dynamic_status)
    reason_text = "；".join(
        [str(x).strip() for x in dynamic_reasons[:2] if str(x).strip()]
    )
    if normalized in ("confirmed", "conditional"):
        if sink_probe_hit and taint_var_reached_sink:
            base = "动态请求命中危险函数，且用户输入到达危险函数。"
        elif sink_probe_hit:
            base = "动态请求命中危险函数。"
        elif taint_var_reached_sink:
            base = "动态请求中用户输入到达危险函数。"
        else:
            base = "动态调试出现可利用信号。"
    elif normalized == "rejected":
        base = "动态调试未形成可利用证据，当前判定为已排除。"
    else:
        base = "动态调试未完成或证据不足，当前状态为已跳过。"

    status_text = ""
    if http_status is not None and str(http_status).strip():
        status_text = f"HTTP 状态 {http_status}。"

    parts = [base]
    if status_text:
        parts.append(status_text)
    if reason_text:
        parts.append(reason_text)
    return "".join(parts)


def build_evidence_refs(trace_case_file: str, burp_template_ref: str = "") -> List[str]:
    refs = [
        f"debug_verify/{DEBUG_EVIDENCE_JSON}",
        f"debug_verify/{DEBUG_PROCESS_JSON}",
        f"debug_verify/{DEBUG_POC_JSON}",
        f"debug_verify/{DEBUG_FUNC_TRACE_JSON}",
    ]
    trace = str(trace_case_file or "").strip()
    if trace and trace != "-":
        refs.append(trace)
    burp_ref = str(burp_template_ref or "").strip()
    if burp_ref and burp_ref != "-":
        refs.append(burp_ref)
    return refs


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, str) and not value.strip():
            return default
        return int(float(value))
    except Exception:
        return default


def compact_text(value: Any, max_len: int = 120) -> str:
    text = str(value if value is not None else "").replace("\n", "\\n")
    if not text:
        return "-"
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def safe_code_text(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("```", "'''")


def to_json_text(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False, indent=2)


def bool_text(value: Any) -> str:
    return "是" if bool(value) else "否"


def yes_no(value: bool) -> str:
    return "是" if value else "否"


def go_no_go_text(value: str) -> str:
    mapping = {
        "No-Go": "禁止上线",
        "Conditional-Go": "有条件上线",
        "Go": "可上线",
    }
    return mapping.get(str(value), str(value))


def run_status_text(value: Any) -> str:
    mapping = {
        "ok": "成功",
        "error": "失败",
        "failed": "失败",
        "skipped": "跳过",
    }
    raw = str(value or "-").strip()
    return mapping.get(raw, raw)


def ai_status_text(value: Any) -> str:
    mapping = {
        "ok": "成功",
        "failed": "失败",
        "error": "失败",
        "timeout": "超时",
        "disabled": "已关闭",
        "not_needed": "未触发",
        "skipped": "跳过",
        "-": "-",
        "": "-",
    }
    raw = str(value or "-")
    return mapping.get(raw, raw)


def stop_reason_text(value: Any) -> str:
    mapping = {
        "confirmed": "已确认",
        "conditional": "条件成立",
        "rejected": "已排除",
        "exhausted": "已穷尽",
        "skipped": "已跳过",
    }
    raw = str(value or "-").strip()
    if raw in mapping:
        return mapping[raw]
    if raw.endswith("_confirmed"):
        return "已确认"
    if raw.endswith("_conditional"):
        return "条件成立"
    if raw.endswith("_rejected"):
        return "已排除"
    if raw.endswith("_exhausted"):
        return "已穷尽"
    if raw.endswith("_skipped"):
        return "已跳过"
    return raw


def normalize_artifact_path(path: str, out_root: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "-"
    if raw.startswith("/work/out/"):
        return os.path.join(out_root, raw[len("/work/out/") :])
    if raw == "/work/out":
        return out_root
    if raw.startswith("debug_verify/"):
        return os.path.join(out_root, raw)
    return raw


def resolve_trace_case(path: str, out_root: str) -> Dict[str, Any]:
    normalized = normalize_artifact_path(path, out_root)
    if normalized == "-":
        return {}
    for candidate in [normalized, str(path or "")]:
        if candidate and os.path.exists(candidate):
            data = _load_json(candidate, {})
            if isinstance(data, dict):
                return data
    return {}


def _path_under_root(raw: str, root: str) -> str:
    if not root:
        return ""
    if not os.path.isabs(raw):
        return ""
    root_abs = os.path.abspath(root)
    raw_abs = os.path.abspath(raw)
    if raw_abs == root_abs:
        return "."
    prefix = root_abs + os.sep
    if raw_abs.startswith(prefix):
        return raw_abs[len(prefix) :]
    return ""


def _infer_rel_from_suffix(raw: str, root: str) -> str:
    if not root:
        return ""
    if not os.path.isabs(raw):
        return ""
    root_abs = os.path.abspath(root)
    if not os.path.isdir(root_abs):
        return ""
    normalized = raw.replace("\\", "/").strip("/")
    parts = [p for p in normalized.split("/") if p]
    if not parts:
        return ""
    for i in range(len(parts)):
        suffix = os.path.join(*parts[i:])
        candidate = os.path.join(root_abs, suffix)
        if os.path.exists(candidate):
            return suffix.replace("\\", "/")
    return ""


def normalize_path_for_report(path: str, project_root: str, out_root: str = "") -> str:
    raw = str(path or "").strip()
    if not raw:
        return "-"

    suffix = ""
    raw_core = raw
    m = re.match(r"^(.*?)(:\d+(?::\d+)?)$", raw)
    if m:
        prefix = m.group(1)
        if prefix.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", prefix):
            raw_core = prefix
            suffix = m.group(2)

    # Container mount path to project-relative display.
    if raw_core.startswith("/work/project"):
        rel = raw_core[len("/work/project") :].lstrip("/")
        norm = rel if rel else "."
        return norm + suffix

    # Container mount path to out-relative display.
    if raw_core.startswith("/work/out"):
        rel = raw_core[len("/work/out") :].lstrip("/")
        norm = rel if rel else "."
        return norm + suffix

    # Host absolute path under project/out roots -> relative path.
    for root in [project_root, out_root]:
        rel = _path_under_root(raw_core, root)
        if rel:
            return rel + suffix

    # Mounted project fallback: find a matching suffix that exists under project root.
    rel_suffix = _infer_rel_from_suffix(raw_core, project_root)
    if rel_suffix:
        return rel_suffix + suffix

    # Fallback: if file contains the project basename segment, strip to that point.
    proj_name = os.path.basename(os.path.abspath(project_root).rstrip(os.sep))
    if proj_name:
        normalized = raw_core.replace("\\", "/")
        marker = f"/{proj_name}/"
        idx = normalized.rfind(marker)
        if idx >= 0:
            tail = normalized[idx + len(marker) :]
            norm = tail if tail else "."
            return norm + suffix
        if normalized.endswith(f"/{proj_name}"):
            return "." + suffix

    return raw


def normalize_embedded_path(value: str, project_root: str, out_root: str) -> str:
    raw = str(value or "")
    if not raw:
        return raw
    proj_abs = os.path.abspath(project_root) if project_root else ""
    out_abs = os.path.abspath(out_root) if out_root else ""
    if raw.startswith("/work/project") or raw.startswith("/work/out"):
        return normalize_path_for_report(raw, project_root, out_root)
    if proj_abs and (raw == proj_abs or raw.startswith(proj_abs + os.sep)):
        return normalize_path_for_report(raw, project_root, out_root)
    if out_abs and (raw == out_abs or raw.startswith(out_abs + os.sep)):
        return normalize_path_for_report(raw, project_root, out_root)
    if raw.startswith("/Users/"):
        return normalize_path_for_report(raw, project_root, out_root)
    return raw


def normalize_paths_in_value(value: Any, project_root: str, out_root: str) -> Any:
    if isinstance(value, dict):
        row: Dict[str, Any] = {}
        for k, v in value.items():
            key = str(k).lower()
            if isinstance(v, str):
                if key == "file" or key.endswith("_file") or "path" in key:
                    row[k] = normalize_path_for_report(v, project_root, out_root)
                else:
                    row[k] = normalize_embedded_path(v, project_root, out_root)
            else:
                row[k] = normalize_paths_in_value(v, project_root, out_root)
        return row
    if isinstance(value, list):
        return [normalize_paths_in_value(x, project_root, out_root) for x in value]
    if isinstance(value, str):
        return normalize_embedded_path(value, project_root, out_root)
    return value


def finding_location(f: Dict[str, Any], project_root: str, out_root: str) -> str:
    sink = f.get("sink") if isinstance(f.get("sink"), dict) else {}
    file_path = str(sink.get("file") or "").strip()
    line = sink.get("line")
    norm_file = normalize_path_for_report(file_path, project_root, out_root)
    if file_path and line:
        return f"{norm_file}:{line}"
    if file_path:
        return norm_file
    return "-"


def finding_entry(f: Dict[str, Any], debug_row: Dict[str, Any]) -> str:
    route = f.get("route") if isinstance(f.get("route"), dict) else {}
    if route:
        method = str(route.get("method") or "GET").upper()
        path = str(route.get("path") or "/")
        return f"{method} {path}"
    if debug_row:
        method = str(debug_row.get("route_method") or "").strip().upper()
        path = str(debug_row.get("route_path") or "").strip()
        if method or path:
            return f"{method or 'GET'} {path or '/'}"
    if f.get("entry"):
        return str(f.get("entry"))
    return "-"


def finding_vuln_type(f: Dict[str, Any], module: str, debug_row: Dict[str, Any]) -> str:
    if debug_row.get("vuln_type"):
        return str(debug_row.get("vuln_type"))
    sink = f.get("sink") if isinstance(f.get("sink"), dict) else {}
    if sink.get("type"):
        return str(sink.get("type"))
    if f.get("vuln_type"):
        return str(f.get("vuln_type"))
    return MODULE_LABELS.get(module, module)


def detect_domain(vuln_type: str) -> str:
    v = str(vuln_type or "").lower()
    if "sql" in v:
        return "sql"
    if "command" in v or "rce" in v or "exec" in v:
        return "rce"
    if "file" in v:
        return "file"
    if "ssrf" in v or "xxe" in v:
        return "ssrf"
    if "xss" in v or "ssti" in v:
        return "xss"
    if "serial" in v or "deserial" in v:
        return "deserialize"
    if "csrf" in v:
        return "csrf"
    if "auth" in v:
        return "auth"
    return "generic"


def impact_pack(vuln_type: str) -> Tuple[str, str, str]:
    domain = detect_domain(vuln_type)
    if domain == "sql":
        return (
            "数据库读取/修改风险，可能导致数据泄露或篡改。",
            "应用直接拼接可控参数到 SQL 语句。",
            "敏感数据泄露、越权读取、批量数据破坏。",
        )
    if domain == "rce":
        return (
            "命令执行风险，可能导致主机控制权受损。",
            "可控参数进入 system/exec/shell 等执行路径。",
            "远程执行任意命令、横向移动、数据破坏。",
        )
    if domain == "file":
        return (
            "文件读写/包含风险，可能导致敏感文件泄露。",
            "路径参数未做白名单和规范化限制。",
            "配置泄露、源码泄露、任意文件读取/覆盖。",
        )
    if domain == "ssrf":
        return (
            "服务端请求伪造风险，可能访问内网敏感接口。",
            "URL 或 XML 输入可控且未限制目标与协议。",
            "内网探测、云元数据泄露、内部服务攻击。",
        )
    if domain == "xss":
        return (
            "前端脚本注入风险，可能窃取会话或执行恶意脚本。",
            "输出缺少上下文相关编码/模板转义。",
            "会话劫持、页面篡改、用户账号风险。",
        )
    if domain == "deserialize":
        return (
            "反序列化对象注入风险，可能触发危险魔术方法。",
            "不可信输入进入 unserialize 或等效入口。",
            "代码执行、文件操作、逻辑绕过。",
        )
    if domain == "csrf":
        return (
            "跨站请求伪造风险，可能被动触发敏感操作。",
            "状态变更接口未校验 CSRF Token。",
            "用户账户被恶意代操作。",
        )
    if domain == "auth":
        return (
            "鉴权/授权校验不足，存在越权访问风险。",
            "关键操作缺少身份或权限二次确认。",
            "低权限用户访问高权限数据/功能。",
        )
    return (
        "存在安全缺陷，需结合业务上下文评估。",
        "输入校验或关键控制面不足。",
        "可能导致数据泄露、篡改或业务中断。",
    )


def remediation_pack(vuln_type: str) -> Tuple[str, str, str]:
    domain = detect_domain(vuln_type)
    if domain == "sql":
        return (
            "统一改为参数化查询（PDO prepared statements），禁止拼接 SQL。",
            "数据库账号最小权限，读写分离并限制危险语句。",
            "新增 SQL 注入回归用例（正常/恶意 payload）并复跑 debug。",
        )
    if domain == "rce":
        return (
            "删除或替换 shell 执行路径，必要时严格命令白名单。",
            "关闭危险函数（如可行）并收紧容器权限。",
            "为命令输入构造攻击样例回归并验证 result=rejected。",
        )
    if domain == "file":
        return (
            "路径参数做 canonicalize 后白名单校验，禁止相对路径穿越。",
            "将可访问目录限定到安全根目录并只读化。",
            "新增目录穿越与非法扩展名测试并复跑 debug。",
        )
    if domain == "ssrf":
        return (
            "对目标 URL 做协议/域名/IP 白名单校验，禁用内网地址。",
            "HTTP 客户端增加 DNS 重绑定与跳转限制。",
            "新增内网/云元数据 payload 回归并验证拦截。",
        )
    if domain == "xss":
        return (
            "所有输出按上下文做转义（HTML/属性/JS）。",
            "开启模板自动转义并禁止不安全直出接口。",
            "新增 XSS payload 页面回归与编码断言。",
        )
    if domain == "deserialize":
        return (
            "避免反序列化不可信数据，优先 JSON + schema。",
            "若必须反序列化，限制允许类并做完整性签名校验。",
            "新增 gadget 链测试并确保无法触发危险路径。",
        )
    if domain == "csrf":
        return (
            "状态变更接口统一校验 CSRF Token 与 Origin/Referer。",
            "Cookie 设为 SameSite=Lax/Strict，必要时二次确认。",
            "新增跨站请求模拟测试并验证失败。",
        )
    if domain == "auth":
        return (
            "在控制器和服务层双重校验身份与资源权限。",
            "对高危操作增加审计日志和最小权限模型。",
            "新增越权回归测试（水平/垂直越权）。",
        )
    return (
        "补充输入校验与边界控制，收敛攻击面。",
        "增强运行时防护与最小权限配置。",
        "补齐针对该缺陷类型的自动化回归用例。",
    )


def build_case_rows(
    findings: List[Dict[str, Any]],
    project_root: str,
    out_root: str,
    debug_evidence: List[Dict[str, Any]],
    debug_process: List[Dict[str, Any]],
    debug_func_trace: List[Dict[str, Any]],
    burp_templates: Optional[List[str]] = None,
    route_auth_map: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    debug_map = {str(d.get("case_id")): d for d in debug_evidence if isinstance(d, dict) and d.get("case_id")}
    process_map = {str(d.get("case_id")): d for d in debug_process if isinstance(d, dict) and d.get("case_id")}
    trace_map = {str(d.get("case_id")): d for d in debug_func_trace if isinstance(d, dict) and d.get("case_id")}

    rows: List[Dict[str, Any]] = []
    for f in findings:
        case_id = str(f.get("id") or "")
        if not case_id:
            case_id = hashlib.md5(json.dumps(f, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:10]

        module = module_from_source(f)
        sink_obj = f.get("sink") if isinstance(f.get("sink"), dict) else {}
        route_obj = f.get("route") if isinstance(f.get("route"), dict) else {}
        debug_row = debug_map.get(case_id, {})
        process_row = process_map.get(case_id, {})
        trace_row = trace_map.get(case_id, {})

        ai_table = f.get("ai_table") if isinstance(f.get("ai_table"), dict) else {}
        severity_raw = (
            ai_table.get("severity_label")
            or f.get("combined_severity")
            or f.get("severity")
            or "medium"
        )
        severity = normalize_severity(str(severity_raw))
        result = normalize_result(str(debug_row.get("result") or "skipped"))

        evidence_score = safe_int(debug_row.get("evidence_score"), default=safe_int(f.get("evidence_score"), 0))
        entry = finding_entry(f, debug_row)
        location = finding_location(f, project_root, out_root)
        vuln_type = finding_vuln_type(f, module, debug_row)

        poc_cmd = str(debug_row.get("poc_cmd") or "").strip()
        if not poc_cmd:
            raw_poc = f.get("poc")
            if isinstance(raw_poc, str) and raw_poc.strip():
                poc_cmd = raw_poc.strip()
            elif isinstance(raw_poc, dict):
                cmd = raw_poc.get("cmd")
                if isinstance(cmd, str) and cmd.strip():
                    poc_cmd = cmd.strip()
        if not poc_cmd:
            poc_cmd = "curl -i -sS -X GET 'http://target/'"

        trace_case_file_raw = str(
            process_row.get("trace_case_file")
            or debug_row.get("trace_case_file")
            or trace_row.get("trace_case_file")
            or ""
        )
        trace_case_file = normalize_artifact_path(trace_case_file_raw, out_root)
        trace_case_data = resolve_trace_case(trace_case_file_raw, out_root)
        selected_trace = trace_case_data.get("selected") if isinstance(trace_case_data.get("selected"), dict) else {}
        attempt_rounds = trace_case_data.get("attempts") if isinstance(trace_case_data.get("attempts"), list) else []
        attempt_rounds = normalize_paths_in_value(attempt_rounds, project_root, out_root)
        if str(result or "skipped") == "skipped":
            result = normalize_result(str(selected_trace.get("result") or result))

        transform_steps = trace_row.get("transform_steps")
        if not isinstance(transform_steps, list):
            transform_steps = selected_trace.get("transform_steps") if isinstance(selected_trace.get("transform_steps"), list) else []
        transform_steps = normalize_paths_in_value(transform_steps, project_root, out_root)

        call_stack = trace_row.get("call_stack")
        if not isinstance(call_stack, list):
            call_stack = selected_trace.get("call_stack") if isinstance(selected_trace.get("call_stack"), list) else []
        call_stack = normalize_paths_in_value(call_stack, project_root, out_root)

        var_snapshot = selected_trace.get("var_snapshot") if isinstance(selected_trace.get("var_snapshot"), dict) else {}
        before_sink = str(trace_row.get("before_sink") or var_snapshot.get("before_sink") or "")
        after_sink = str(trace_row.get("after_sink") or var_snapshot.get("after_sink") or "")

        call_stack_summary = str(trace_row.get("call_stack_summary") or "")
        if not call_stack_summary and call_stack:
            frames: List[str] = []
            for frame in call_stack[:4]:
                if not isinstance(frame, dict):
                    continue
                cls = str(frame.get("class") or "")
                fn = str(frame.get("function") or "")
                tp = str(frame.get("type") or "")
                line = frame.get("line")
                label = f"{cls}{tp}{fn}" if cls else fn
                if not label:
                    label = "unknown"
                frames.append(f"{label}@{line if line is not None else '?'}")
            call_stack_summary = " -> ".join(frames)

        dynamic_status = normalize_result(result)
        dynamic_is_supported = dynamic_supported(dynamic_status)
        auth_requirement, auth_requirement_text = resolve_auth_requirement(
            module=module,
            title=str(f.get("title") or ""),
            entry=entry,
            route_obj=route_obj,
            route_auth_map=route_auth_map or {},
        )
        verify_status = verify_status_text(dynamic_status)
        exploit_conclusion = direct_exploit_text(dynamic_status, auth_requirement)
        vuln_code = extract_vuln_code_snippet(sink_obj, transform_steps)
        burp_template_ref = resolve_case_burp_template(
            {
                "case_id": case_id,
                "entry": entry,
            },
            burp_templates or [],
        )
        burp_file_name = burp_payload_filename(
            case_id=case_id,
            vuln_type=vuln_type,
            title=str(f.get("title") or ""),
            burp_template_ref=burp_template_ref,
        )
        evidence_refs = build_evidence_refs(
            normalize_path_for_report(trace_case_file, project_root, out_root),
            burp_template_ref,
        )
        dynamic_reason = build_dynamic_reason(
            dynamic_status=dynamic_status,
            sink_probe_hit=bool(
                process_row.get("sink_probe_hit")
                or debug_row.get("sink_probe_hit")
                or trace_row.get("sink_probe_hit")
            ),
            taint_var_reached_sink=bool(
                process_row.get("taint_var_reached_sink")
                or debug_row.get("taint_var_reached_sink")
                or trace_row.get("taint_var_reached_sink")
            ),
            dynamic_reasons=process_row.get("dynamic_reasons")
            if isinstance(process_row.get("dynamic_reasons"), list)
            else (debug_row.get("dynamic_reasons") if isinstance(debug_row.get("dynamic_reasons"), list) else []),
            http_status=process_row.get("http_status")
            if process_row.get("http_status") is not None
            else debug_row.get("http_status"),
        )

        rows.append(
            {
                "case_id": case_id,
                "title": str(f.get("title") or case_id),
                "module": module,
                "category_label": MODULE_LABELS.get(module, module),
                "vuln_type": vuln_type,
                "severity": severity,
                "severity_raw": str(severity_raw),
                "result": result,
                "evidence_score": evidence_score,
                "entry": entry,
                "location": location,
                "bucket": str((debug_row.get("request_candidate") or {}).get("bucket") or "GET"),
                "param": str((debug_row.get("request_candidate") or {}).get("param") or "payload"),
                "payload_used": str(debug_row.get("payload_used") or ""),
                "payload_source": str(debug_row.get("payload_source") or ""),
                "request_source": str(debug_row.get("request_source") or ""),
                "poc_cmd": poc_cmd,
                "poc_short": compact_text(poc_cmd, 100),
                "verify_status": verify_status,
                "auth_requirement": auth_requirement,
                "auth_requirement_text": auth_requirement_text,
                "exploit_conclusion": exploit_conclusion,
                "vuln_code": vuln_code,
                "vuln_code_short": compact_text(vuln_code, 120) if vuln_code else "-",
                "execution_mode": str(process_row.get("execution_mode") or debug_row.get("execution_mode") or "-"),
                "http_status": process_row.get("http_status") if process_row.get("http_status") is not None else debug_row.get("http_status"),
                "sink_probe_hit": bool(process_row.get("sink_probe_hit") or debug_row.get("sink_probe_hit") or trace_row.get("sink_probe_hit")),
                "taint_var_reached_sink": bool(
                    process_row.get("taint_var_reached_sink")
                    or debug_row.get("taint_var_reached_sink")
                    or trace_row.get("taint_var_reached_sink")
                ),
                "dynamic_reasons": process_row.get("dynamic_reasons")
                if isinstance(process_row.get("dynamic_reasons"), list)
                else (debug_row.get("dynamic_reasons") if isinstance(debug_row.get("dynamic_reasons"), list) else []),
                "stop_reason": str(debug_row.get("stop_reason") or selected_trace.get("stop_reason") or "-"),
                "matched_attempt_index": debug_row.get("matched_attempt_index")
                if debug_row.get("matched_attempt_index") is not None
                else selected_trace.get("matched_attempt_index"),
                "attempt_count": safe_int(debug_row.get("attempt_count"), 0),
                "attempt_rounds": attempt_rounds,
                "ai_status": str(process_row.get("ai_realtime_status") or "-"),
                "status": str(process_row.get("status") or "skipped"),
                "trace_case_file": normalize_path_for_report(trace_case_file, project_root, out_root),
                "request_preview": str(process_row.get("request_preview") or ""),
                "response_header_preview": str(process_row.get("response_header_preview") or ""),
                "response_body_preview": str(process_row.get("response_body_preview") or ""),
                "transform_steps": transform_steps,
                "call_stack": call_stack,
                "before_sink": before_sink,
                "after_sink": after_sink,
                "call_stack_summary": call_stack_summary or "-",
                "dynamic_status": dynamic_status,
                "dynamic_supported": dynamic_is_supported,
                "dynamic_support_text": dynamic_supported_text(dynamic_status),
                "dynamic_reason": dynamic_reason,
                "evidence_refs": evidence_refs,
                "burp_template_ref": burp_template_ref,
                "burp_payload_file": burp_file_name,
                "static_conclusion": static_conclusion_text(
                    {
                        "severity": severity,
                        "vuln_type": vuln_type,
                    }
                ),
            }
        )
    return rows


def summarize_cases(case_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(case_rows)
    confirmed = sum(1 for c in case_rows if c.get("result") == "confirmed")
    conditional = sum(1 for c in case_rows if c.get("result") == "conditional")
    critical_high = sum(1 for c in case_rows if c.get("severity") in ("critical", "high"))
    p0 = sum(
        1
        for c in case_rows
        if c.get("result") in ("confirmed", "conditional")
        and c.get("severity") in ("critical", "high")
    )

    exploitable = confirmed > 0 or conditional > 0
    max_sev_rank = max([severity_rank(str(c.get("severity") or "info")) for c in case_rows] or [0])
    max_severity = "info"
    for level in ["critical", "high", "medium", "low", "info"]:
        if severity_rank(level) == max_sev_rank:
            max_severity = level
            break

    confirmed_high = sum(
        1
        for c in case_rows
        if c.get("result") == "confirmed" and c.get("severity") in ("critical", "high")
    )
    if confirmed_high > 0:
        go_no_go = "No-Go"
    elif exploitable:
        go_no_go = "Conditional-Go"
    else:
        go_no_go = "Go"

    return {
        "total": total,
        "confirmed": confirmed,
        "conditional": conditional,
        "critical_high": critical_high,
        "p0": p0,
        "exploitable": exploitable,
        "max_severity": max_severity,
        "go_no_go": go_no_go,
    }


def overall_risk(summary: Dict[str, Any]) -> str:
    if not summary.get("total"):
        return "无明显风险"
    max_severity = str(summary.get("max_severity") or "info")
    if max_severity in ("critical", "high"):
        return "高风险"
    if summary.get("exploitable"):
        return "中风险"
    return "低风险"


def top_risks(case_rows: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    def _score(row: Dict[str, Any]) -> Tuple[int, int, int]:
        return (
            severity_rank(str(row.get("severity"))),
            result_rank(str(row.get("result"))),
            safe_int(row.get("evidence_score"), 0),
        )

    rows = sorted(case_rows, key=_score, reverse=True)
    return rows[:limit]


def risk_overview_rows(case_rows: List[Dict[str, Any]]) -> List[List[str]]:
    buckets: Dict[str, Dict[str, int]] = {}
    for c in case_rows:
        label = str(c.get("category_label") or "其他")
        sev = str(c.get("severity") or "low")
        if label not in buckets:
            buckets[label] = {k: 0 for k in SEVERITY_ORDER}
            buckets[label]["total"] = 0
        if sev not in buckets[label]:
            sev = "low"
        buckets[label][sev] += 1
        buckets[label]["total"] += 1

    rows: List[List[str]] = []
    total = {k: 0 for k in SEVERITY_ORDER}
    total["total"] = 0
    for module in MODULE_ORDER:
        label = MODULE_LABELS.get(module, module)
        default_counts = {k: 0 for k in SEVERITY_ORDER}
        default_counts["total"] = 0
        row_counts = buckets.get(label, default_counts)
        rows.append(
            [
                label,
                str(row_counts["critical"]) if row_counts["critical"] else "-",
                str(row_counts["high"]) if row_counts["high"] else "-",
                str(row_counts["medium"]) if row_counts["medium"] else "-",
                str(row_counts["low"]) if row_counts["low"] else "-",
                str(row_counts["total"]),
            ]
        )
        for k in SEVERITY_ORDER:
            total[k] += row_counts[k]
        total["total"] += row_counts["total"]

    existing = {r[0] for r in rows}
    for label, counts in buckets.items():
        if label in existing:
            continue
        rows.append(
            [
                label,
                str(counts["critical"]) if counts["critical"] else "-",
                str(counts["high"]) if counts["high"] else "-",
                str(counts["medium"]) if counts["medium"] else "-",
                str(counts["low"]) if counts["low"] else "-",
                str(counts["total"]),
            ]
        )
        for k in SEVERITY_ORDER:
            total[k] += counts[k]
        total["total"] += counts["total"]

    rows.append(
        [
            "合计",
            str(total["critical"]) if total["critical"] else "-",
            str(total["high"]) if total["high"] else "-",
            str(total["medium"]) if total["medium"] else "-",
            str(total["low"]) if total["low"] else "-",
            str(total["total"]),
        ]
    )
    return rows


def core_issues(case_rows: List[Dict[str, Any]]) -> List[str]:
    counts: Dict[str, int] = {}
    for c in case_rows:
        module = str(c.get("module") or "unknown")
        counts[module] = counts.get(module, 0) + 1
    issues: List[str] = []
    if counts.get("rce_audit", 0) > 0:
        issues.append("收敛命令执行入口并启用参数白名单。")
    if counts.get("sql_audit", 0) > 0:
        issues.append("统一改造为参数化查询，禁止拼接 SQL。")
    if counts.get("file_audit", 0) > 0:
        issues.append("文件路径参数执行 canonicalize + 白名单。")
    if counts.get("ssrf_xxe_audit", 0) > 0:
        issues.append("出站请求做协议/域名/IP 白名单限制。")
    if counts.get("xss_ssti_audit", 0) > 0:
        issues.append("统一启用上下文输出编码和模板自动转义。")
    if counts.get("serialize_audit", 0) > 0:
        issues.append("避免反序列化不可信数据，改 JSON + schema。")
    if counts.get("auth_audit", 0) > 0:
        issues.append("关键操作增加身份与资源权限双重校验。")
    if counts.get("csrf_audit", 0) > 0:
        issues.append("状态变更接口统一引入 CSRF Token 验证。")
    if not issues:
        issues.append("未识别到高优先级系统性问题，建议继续保持回归扫描。")
    return issues


def escape_summary(text: str) -> str:
    return str(text).replace("\n", " ").strip()


def appendix_anchor_id(case_id: Any) -> str:
    base = re.sub(r"[^A-Za-z0-9_-]+", "-", str(case_id or "case")).strip("-").lower()
    return f"case-{base or 'case'}"


def case_group_key(case: Dict[str, Any]) -> str:
    vuln_type = str(case.get("vuln_type") or "-")
    location = str(case.get("location") or "-")
    entry = str(case.get("entry") or "-")
    return f"{vuln_type}|{location}|{entry}"


def case_priority_tuple(case: Dict[str, Any]) -> Tuple[int, int, int]:
    return (
        result_rank(str(case.get("result") or "")),
        severity_rank(str(case.get("severity") or "")),
        safe_int(case.get("evidence_score"), 0),
    )


def build_main_cases(case_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for case in case_rows:
        key = case_group_key(case)
        grouped.setdefault(key, []).append(case)

    out: List[Dict[str, Any]] = []
    for key, items in grouped.items():
        ordered = sorted(items, key=case_priority_tuple, reverse=True)
        rep = dict(ordered[0])
        rep["group_key"] = key
        rep["group_count"] = len(items)
        rep["group_case_ids"] = [str(i.get("case_id") or "-") for i in ordered]
        rep["appendix_anchor"] = appendix_anchor_id(rep.get("case_id"))
        out.append(rep)

    out.sort(key=case_priority_tuple, reverse=True)
    return out


def result_alias_text(result: str) -> str:
    normalized = normalize_result(result)
    return RESULT_ALIAS_TEXT.get(normalized, RESULT_CN.get(normalized, normalized))


def human_vuln_name(vuln_type: str) -> str:
    return DOMAIN_CN_LABELS.get(detect_domain(vuln_type), str(vuln_type or "其他漏洞"))


def safe_slug_text(text: str, max_len: int = 40) -> str:
    raw = str(text or "").strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    if not slug:
        return "payload"
    return slug[:max_len].rstrip("_") or "payload"


def parse_method_path_from_entry(entry: str) -> Tuple[str, str]:
    raw = str(entry or "").strip()
    if not raw:
        return "", ""
    parts = raw.split()
    if len(parts) >= 2:
        method = parts[0].strip().upper()
        path = parts[1].strip()
        if path:
            if not path.startswith("/") and not path.startswith("http://") and not path.startswith("https://"):
                path = "/" + path
            return method, path
    return "", ""


def resolve_auth_requirement(
    module: str,
    title: str,
    entry: str,
    route_obj: Dict[str, Any],
    route_auth_map: Dict[str, Dict[str, Any]],
) -> Tuple[str, str]:
    method = str(route_obj.get("method") or "").split("|")[0].strip().upper()
    route_path = str(route_obj.get("path") or "").strip()
    if not route_path:
        method, route_path = parse_method_path_from_entry(entry)
    if route_path and not route_path.startswith("/") and not route_path.startswith("http://") and not route_path.startswith("https://"):
        route_path = "/" + route_path

    keys: List[str] = []
    if method and route_path:
        keys.append(f"{method} {route_path}")
    if route_path:
        keys.append(f"ANY {route_path}")
        keys.append(f"GET {route_path}")

    for key in keys:
        route_row = route_auth_map.get(key)
        if not isinstance(route_row, dict):
            continue
        if route_row.get("auth_required"):
            return "need_auth", "✅ 需登录"
        return "no_auth", "❌ 无需"

    lower_title = str(title or "").lower()
    if module == "auth_audit" or "authorization" in lower_title or "鉴权" in str(title or ""):
        return "no_auth", "❌ 无需"
    return "unknown", "⚪ 待确认"


def verify_status_text(status: str) -> str:
    normalized = normalize_result(status)
    mapping = {
        "confirmed": "✅ 已确认存在",
        "conditional": "⚠️ 有条件成立",
        "rejected": "❎ 已排除",
        "skipped": "⏭️ 已跳过",
    }
    return mapping.get(normalized, "⏭️ 已跳过")


def direct_exploit_text(status: str, auth_requirement: str) -> str:
    normalized = normalize_result(status)
    if normalized == "confirmed":
        if auth_requirement == "no_auth":
            return "无需认证，可直接利用"
        if auth_requirement == "need_auth":
            return "需要认证后可利用"
        return "已确认可利用，认证条件待确认"
    if normalized == "conditional":
        if auth_requirement == "no_auth":
            return "无需认证，满足条件后可利用"
        if auth_requirement == "need_auth":
            return "需要认证且满足条件后可利用"
        return "有条件成立，需补充认证条件验证"
    if normalized == "rejected":
        return "未复现可利用路径，当前已排除"
    return "未完成动态验证，暂不下利用结论"


def extract_vuln_code_snippet(
    sink_obj: Dict[str, Any],
    transform_steps: List[Dict[str, Any]],
) -> str:
    if isinstance(sink_obj, dict):
        sink_code = str(sink_obj.get("code") or "").strip()
        if sink_code:
            return sink_code
    for step in transform_steps:
        if not isinstance(step, dict):
            continue
        expr = str(step.get("expr") or "").strip()
        if expr:
            return expr
    return ""


def burp_payload_filename(case_id: str, vuln_type: str, title: str, burp_template_ref: str) -> str:
    base = os.path.basename(str(burp_template_ref or "").strip())
    if base and base != "-" and base.lower() not in {"any_root.txt", "get_root.txt", "post_root.txt"}:
        return base
    suffix = safe_slug_text(title or vuln_type)
    return f"{case_id}_{suffix}.txt"


def to_human_case(case: Dict[str, Any]) -> Dict[str, Any]:
    vuln_type = str(case.get("vuln_type") or "")
    impact, precondition, _ = impact_pack(vuln_type)
    fix_code, fix_config, fix_test = remediation_pack(vuln_type)
    result = normalize_result(str(case.get("dynamic_status") or case.get("result") or "skipped"))
    dynamic_reason = str(case.get("dynamic_reason") or "").strip()
    if not dynamic_reason:
        dynamic_reasons = case.get("dynamic_reasons") if isinstance(case.get("dynamic_reasons"), list) else []
        dynamic_reason = "、".join([str(x) for x in dynamic_reasons[:2] if str(x).strip()]) or "无明显动态信号"
    http_status = str(case.get("http_status") if case.get("http_status") is not None else "-")

    return {
        "case_id": str(case.get("case_id") or "-"),
        "vuln_name": human_vuln_name(vuln_type),
        "severity_text": SEVERITY_CN.get(str(case.get("severity") or "low"), str(case.get("severity") or "low")),
        "result_alias": result_alias_text(result),
        "verify_status": str(case.get("verify_status") or verify_status_text(result)),
        "auth_requirement_text": str(case.get("auth_requirement_text") or "⚪ 待确认"),
        "exploit_conclusion": str(case.get("exploit_conclusion") or direct_exploit_text(result, str(case.get("auth_requirement") or "unknown"))),
        "vuln_code_short": compact_text(case.get("vuln_code") or "-", max_len=180),
        "location": str(case.get("location") or "-"),
        "entry": str(case.get("entry") or "-"),
        "trigger": precondition,
        "impact": impact,
        "poc_cmd_short": compact_text(case.get("poc_cmd") or "-", max_len=180),
        "http_status": http_status,
        "dynamic_reason": dynamic_reason,
        "dynamic_supported_text": str(case.get("dynamic_support_text") or dynamic_supported_text(result)),
        "fix_code": fix_code,
        "fix_config": fix_config,
        "retest": f"修复后应为已排除。{fix_test}",
        "group_count": safe_int(case.get("group_count"), 1),
        "burp_template_ref": str(case.get("burp_template_ref") or "-"),
    }


def render_human_case(case: Dict[str, Any]) -> List[str]:
    h = to_human_case(case)
    lines: List[str] = []
    lines.append(
        f"### [{h['case_id']}] {h['vuln_name']} | {h['severity_text']} | {h['result_alias']}"
    )
    lines.append(f"- 验证状态：{h['verify_status']}")
    lines.append(f"- 危险等级：{h['severity_text']}")
    lines.append(f"- 认证需求：{h['auth_requirement_text']}")
    lines.append(f"- 利用结论：{h['exploit_conclusion']}")
    lines.append(f"- 发生位置：`{h['location']}`")
    lines.append(f"- 请求入口：`{h['entry']}`")
    lines.append(f"- 漏洞代码：`{h['vuln_code_short']}`")
    lines.append(f"- Burp 模版：`{h['burp_template_ref']}`")
    lines.append(f"- 触发条件：{h['trigger']}")
    lines.append(f"- 实际影响：{h['impact']}")
    if h["group_count"] > 1:
        lines.append(f"- 同类重复：{h['group_count']} 条（详见附录）")
    lines.append(
        f"- {HUMAN_TERM_LABELS['sink_probe_hit']}：{bool_text(case.get('sink_probe_hit'))}"
    )
    lines.append(
        f"- {HUMAN_TERM_LABELS['taint_var_reached_sink']}：{bool_text(case.get('taint_var_reached_sink'))}"
    )
    lines.append("复现步骤：")
    lines.append(f"1. 执行命令：`{h['poc_cmd_short']}`")
    lines.append(f"2. 观察现象：HTTP `{h['http_status']}`；{h['dynamic_reason']}")
    lines.append(f"3. 判定标准：{h['result_alias']}")
    lines.append(f"- 静态结论是否被动态证据支持：**{h['dynamic_supported_text']}**")
    lines.append("修复建议：")
    lines.append(f"1. {h['fix_code']}")
    lines.append(f"2. {h['fix_config']}")
    lines.append(f"- 复测标准：{h['retest']}")
    lines.append(
        f"- 技术附录：[`查看 {h['case_id']} 详细证据`]({CN_REPORT_APPENDIX_MD}#{case.get('appendix_anchor')})"
    )
    lines.append("")
    return lines


def remediation_rows_human(case_rows: List[Dict[str, Any]]) -> List[List[str]]:
    rows: List[List[str]] = []
    for case in case_rows:
        severity = str(case.get("severity") or "low")
        result = normalize_result(str(case.get("result") or "skipped"))
        if result in ("confirmed", "conditional") and severity in ("critical", "high"):
            priority = "P0"
            due = "24h"
        elif result in ("confirmed", "conditional"):
            priority = "P1"
            due = "72h"
        else:
            priority = "P2"
            due = "7d"
        fix_code, fix_config, _ = remediation_pack(str(case.get("vuln_type") or ""))
        action = compact_text(f"{fix_code}；{fix_config}", max_len=72)
        rows.append(
            [
                priority,
                str(case.get("case_id") or "-"),
                action,
                "应用研发负责人",
                due,
                "复测结果=已排除",
            ]
        )
    if not rows:
        rows.append(["P2", "-", "无待修项", "-", "-", "-"])
    return rows


def normalize_debug_value(value: Any, max_len: int = 100) -> str:
    raw = str(value if value is not None else "").strip()
    if raw in ("", "null", "None", "NULL"):
        return "空值"
    if raw in ("[]", "{}", "array()", "Array()"):
        return "空集合"
    return compact_text(raw, max_len=max_len)


def op_level_text(op: str) -> str:
    mapping = {
        "strong_change": "强变化",
        "weak_change": "轻微变化",
        "no_change": "无变化",
        "unknown": "未知",
        "-": "-",
        "": "-",
    }
    return mapping.get(str(op or "").strip(), str(op or "-"))


def read_color_mode() -> str:
    raw = str(os.environ.get("REPORT_COLOR_MODE", "auto") or "").strip().lower()
    if raw in ("auto", "on", "off"):
        return raw
    return "auto"


def classify_step_level(step: Dict[str, Any]) -> str:
    expr = str(step.get("expr") or "").lower()
    op = str(step.get("op") or "").strip().lower()

    dangerous_tokens = [
        "shell_exec",
        "system(",
        "exec(",
        "passthru(",
        "proc_open(",
        "popen(",
        "unserialize",
        "select ",
        "insert ",
        "update ",
        "delete ",
        " where ",
        " from ",
        "$sql",
        "sql",
    ]
    if op == "strong_change" or any(token in expr for token in dangerous_tokens):
        return "high"
    if op == "weak_change" or bool(step.get("changed")):
        return "medium"
    return "info"


def level_label(level: str) -> str:
    mapping = {
        "high": "高危",
        "medium": "中危",
        "info": "信息",
    }
    return mapping.get(str(level or "").strip().lower(), "信息")


def level_badge(level: str, color_mode: str) -> str:
    label = level_label(level)
    if color_mode == "off":
        return f"[{label}]"

    colors = {
        "high": "#d73a49",
        "medium": "#f39c12",
        "info": "#22863a",
    }
    color = colors.get(str(level or "").strip().lower(), colors["info"])
    return f"<span style=\"color:{color}\"><strong>{label}</strong></span> [{label}]"


def step_human_note(step: Dict[str, Any]) -> str:
    expr = str(step.get("expr") or "").lower()
    changed = bool(step.get("changed"))
    after = str(step.get("after") or "").lower()
    if ("select" in expr and ("where" in expr or "from" in expr)) or "sql" in expr:
        return "SQL 语句受输入影响，需重点排查注入风险。"
    if any(k in expr for k in ["shell_exec", "system(", "exec(", "passthru", "proc_open", "popen("]):
        return "命令执行参数发生变化，需确认是否可控。"
    if any(k in expr for k in ["include", "require", "file_get_contents", "fopen", "readfile", "unlink", "copy("]):
        return "文件路径或文件操作参数发生变化，需校验白名单。"
    if any(k in expr for k in ["curl", "request", "http", "wget"]) or "http://" in after or "https://" in after:
        return "外部请求目标可能可控，需排查 SSRF 风险。"
    if "unserialize" in expr:
        return "反序列化输入发生变化，需确认来源可信。"
    if changed:
        return "变量值发生变化，需继续看是否进入危险函数。"
    return "本步骤未见关键值变化。"


def parse_transform_steps(case: Dict[str, Any], max_steps: int = 0) -> List[Dict[str, Any]]:
    steps_raw = case.get("transform_steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        return []

    parsed_steps: List[Dict[str, Any]] = []
    for idx, item in enumerate(steps_raw, 1):
        if not isinstance(item, dict):
            continue
        parsed_steps.append(
            {
                "order": safe_int(item.get("step"), idx),
                "line": item.get("line"),
                "expr": str(item.get("expr") or item.get("function") or "trace_step"),
                "changed": bool(item.get("changed")),
                "before": compact_text(item.get("before"), max_len=100),
                "after": compact_text(item.get("after"), max_len=100),
                "op": str(item.get("op") or "-"),
            }
        )

    parsed_steps.sort(key=lambda x: (safe_int(x.get("order"), 0), safe_int(x.get("line"), 0)))
    if max_steps > 0:
        parsed_steps = parsed_steps[:max_steps]
    return parsed_steps


def render_debug_change_overview_table(case: Dict[str, Any], color_mode: str) -> str:
    parsed_steps = parse_transform_steps(case, max_steps=80)
    if not parsed_steps:
        return "（无步骤变更）"

    rows: List[List[str]] = []
    for step in parsed_steps:
        level = classify_step_level(step)
        rows.append(
            [
                str(step.get("order")),
                str(step.get("line") if step.get("line") not in (None, "") else "?"),
                compact_text(step.get("expr"), max_len=96),
                normalize_debug_value(step.get("before"), max_len=80),
                normalize_debug_value(step.get("after"), max_len=80),
                op_level_text(str(step.get("op") or "-")),
                step_human_note(step),
                level_badge(level, color_mode),
            ]
    )
    return markdown_table(["步骤", "行号", "代码片段", "变化前", "变化后", "变化级别", "人话说明", "风险标识"], rows)


def request_brief_from_preview(preview: Any) -> str:
    raw = str(preview or "").strip()
    if not raw:
        return "-"
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            method = str(data.get("method") or "GET").upper()
            url = str(data.get("url") or "")
            if url:
                return f"{method} {url}"
            return method
    except Exception:
        pass
    first = raw.splitlines()[0] if raw else "-"
    return compact_text(first, max_len=140)


def response_header_brief(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "-"
    first = raw.splitlines()[0] if raw.splitlines() else raw
    return compact_text(first, max_len=120)


def dynamic_result_rows(case: Dict[str, Any]) -> List[List[str]]:
    reasons = case.get("dynamic_reasons") if isinstance(case.get("dynamic_reasons"), list) else []
    reasons_text = "；".join([compact_text(x, 60) for x in reasons[:3]]) if reasons else "-"
    evidence_refs = case.get("evidence_refs") if isinstance(case.get("evidence_refs"), list) else []
    evidence_ref_text = "；".join([str(x) for x in evidence_refs[:3]]) if evidence_refs else "-"
    return [
        ["case_id", str(case.get("case_id") or "-")],
        ["静态结论", str(case.get("static_conclusion") or static_conclusion_text(case))],
        ["调试结论", RESULT_CN.get(str(case.get("result") or "skipped"), str(case.get("result") or "-"))],
        ["验证状态", str(case.get("verify_status") or verify_status_text(str(case.get("result") or "skipped")))],
        ["认证需求", str(case.get("auth_requirement_text") or "⚪ 待确认")],
        ["利用结论", str(case.get("exploit_conclusion") or "-")],
        ["危险等级", SEVERITY_CN.get(str(case.get("severity") or "low"), str(case.get("severity") or "low"))],
        ["动态状态", RESULT_CN.get(str(case.get("dynamic_status") or "skipped"), str(case.get("dynamic_status") or "-"))],
        ["是否支持静态结论", str(case.get("dynamic_support_text") or dynamic_supported_text(str(case.get("dynamic_status") or "skipped")))],
        ["运行状态", run_status_text(case.get("status"))],
        ["HTTP状态", str(case.get("http_status") if case.get("http_status") is not None else "-")],
        [HUMAN_TERM_LABELS["sink_probe_hit"], bool_text(case.get("sink_probe_hit"))],
        [HUMAN_TERM_LABELS["taint_var_reached_sink"], bool_text(case.get("taint_var_reached_sink"))],
        ["执行模式", str(case.get("execution_mode") or "-")],
        ["尝试次数", str(case.get("attempt_count") if case.get("attempt_count") is not None else "-")],
        ["停止原因", stop_reason_text(case.get("stop_reason"))],
        ["请求来源", str(case.get("request_source") or "-")],
        ["Payload来源", str(case.get("payload_source") or "-")],
        ["Payload", compact_text(case.get("payload_used") or "-", 120)],
        ["请求摘要", request_brief_from_preview(case.get("request_preview"))],
        ["响应摘要", response_header_brief(case.get("response_header_preview"))],
        ["绑定说明", compact_text(case.get("dynamic_reason") or "-", 160)],
        ["漏洞代码", compact_text(case.get("vuln_code") or "-", 160)],
        ["证据引用", compact_text(evidence_ref_text, 160)],
        ["Burp 模版", str(case.get("burp_template_ref") or "-")],
        ["动态说明", reasons_text],
    ]


def compact_case_for_report(case: Dict[str, Any]) -> Dict[str, Any]:
    keep_keys = [
        "case_id",
        "title",
        "module",
        "category_label",
        "vuln_type",
        "severity",
        "severity_raw",
        "result",
        "evidence_score",
        "entry",
        "location",
        "bucket",
        "param",
        "payload_used",
        "payload_source",
        "request_source",
        "poc_cmd",
        "poc_short",
        "verify_status",
        "auth_requirement",
        "auth_requirement_text",
        "exploit_conclusion",
        "vuln_code",
        "vuln_code_short",
        "execution_mode",
        "http_status",
        "sink_probe_hit",
        "taint_var_reached_sink",
        "dynamic_reasons",
        "stop_reason",
        "matched_attempt_index",
        "attempt_count",
        "attempt_rounds",
        "ai_status",
        "status",
        "trace_case_file",
        "dynamic_status",
        "dynamic_supported",
        "dynamic_support_text",
        "dynamic_reason",
        "evidence_refs",
        "burp_template_ref",
        "burp_payload_file",
        "static_conclusion",
        "group_key",
        "group_count",
        "group_case_ids",
        "appendix_anchor",
    ]
    out: Dict[str, Any] = {}
    for key in keep_keys:
        if key in case:
            out[key] = case.get(key)
    return out


def resolve_case_slice_path(case: Dict[str, Any], out_root: str) -> str:
    candidates: List[str] = []

    trace_case_file = str(case.get("trace_case_file") or "").strip()
    if trace_case_file and trace_case_file != "-":
        candidates.append(trace_case_file)
        candidates.append(normalize_artifact_path(trace_case_file, out_root))

    steps = case.get("transform_steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            file_path = str(step.get("file") or "").strip()
            if file_path:
                candidates.append(file_path)

    case_id = str(case.get("case_id") or "").strip()
    if case_id:
        candidates.append(os.path.join(out_root, "debug_verify", "slices", f"{case_id}.php"))
        candidates.append(os.path.join("debug_verify", "slices", f"{case_id}.php"))
        candidates.append(f"/work/out/debug_verify/slices/{case_id}.php")

    seen: set = set()
    for raw in candidates:
        if not raw:
            continue
        normalized = normalize_artifact_path(raw, out_root)
        to_try = [normalized, raw]
        if not os.path.isabs(raw):
            to_try.append(os.path.join(out_root, raw))
        for path in to_try:
            if not path:
                continue
            if path in seen:
                continue
            seen.add(path)
            if os.path.isfile(path):
                return path
    return ""


def render_slice_code_with_inline_changes(case: Dict[str, Any], out_root: str) -> str:
    slice_path = resolve_case_slice_path(case, out_root)
    if not slice_path:
        return "（未找到切片代码）"

    try:
        with open(slice_path, "r", encoding="utf-8", errors="ignore") as f:
            code_lines = f.read().splitlines()
    except Exception:
        return "（切片代码读取失败）"

    change_map: Dict[int, List[str]] = {}
    steps = case.get("transform_steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            line_no = safe_int(step.get("line"), 0)
            if line_no <= 0:
                continue
            target_line = line_no
            if 1 <= line_no <= len(code_lines):
                this_line = code_lines[line_no - 1]
                if "__debug_track(" in this_line and line_no > 1:
                    prev_line = code_lines[line_no - 2] if line_no - 2 >= 0 else ""
                    # In auto_slice output, __debug_track usually follows $__debug_after_*;
                    # annotate the actual business line instead of helper lines.
                    if str(prev_line).lstrip().startswith("$__debug_after_") and line_no > 2:
                        target_line = line_no - 2
                    else:
                        target_line = line_no - 1
            before = normalize_debug_value(step.get("before"), max_len=120)
            after = normalize_debug_value(step.get("after"), max_len=120)
            op_text = op_level_text(str(step.get("op") or "-"))
            fn = str(step.get("function") or "").strip()
            fn_part = f"{fn}/" if fn else ""
            level = classify_step_level(step)
            note = f"-> [{level_label(level)}] {before} => {after} [{fn_part}{op_text}]"
            change_map.setdefault(target_line, []).append(note)

    rendered: List[str] = []
    for idx, code in enumerate(code_lines, 1):
        suffixes = change_map.get(idx) or []
        if suffixes:
            rendered.append(f"{idx:>4}  {code}    {suffixes[0]}")
            for extra in suffixes[1:]:
                rendered.append(f"      {extra}")
        else:
            rendered.append(f"{idx:>4}  {code}")

    overflow_lines = sorted([line for line in change_map.keys() if line > len(code_lines)])
    if overflow_lines:
        rendered.append("")
        rendered.append("      # 以下变化行号未在切片代码中找到")
        for line in overflow_lines:
            for note in change_map.get(line, []):
                rendered.append(f"      line {line}: {note}")

    return "\n".join(rendered)


def collect_burp_template_files(out_root: str) -> List[str]:
    roots = [
        os.path.join(out_root, "route_mapper", "burp_templates"),
        os.path.join(out_root, "debug_verify", "burp_templates"),
    ]
    files: List[str] = []
    seen: set = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, out_root).replace("\\", "/")
            if rel in seen:
                continue
            seen.add(rel)
            files.append(rel)
    return files


def ensure_archive_layout(out_root: str) -> Dict[str, str]:
    paths = {
        "root": os.path.join(out_root, ARCHIVE_ROOT),
        "stage": os.path.join(out_root, ARCHIVE_STAGE_DIR),
        "debug": os.path.join(out_root, ARCHIVE_DEBUG_DIR),
        "burp": os.path.join(out_root, ARCHIVE_BURP_DIR),
        "quality": os.path.join(out_root, ARCHIVE_QUALITY_DIR),
        "binding": os.path.join(out_root, ARCHIVE_BINDING_DIR),
    }
    for p in paths.values():
        os.makedirs(p, exist_ok=True)
    return paths


def copy_file_if_exists(src: str, dst: str) -> None:
    if not src or not os.path.isfile(src):
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    try:
        shutil.copy2(src, dst)
    except Exception:
        return


def copy_tree_if_exists(src_dir: str, dst_dir: str) -> None:
    if not src_dir or not os.path.isdir(src_dir):
        return
    os.makedirs(dst_dir, exist_ok=True)
    for root, _, files in os.walk(src_dir):
        rel = os.path.relpath(root, src_dir)
        target_root = dst_dir if rel == "." else os.path.join(dst_dir, rel)
        os.makedirs(target_root, exist_ok=True)
        for name in files:
            src = os.path.join(root, name)
            dst = os.path.join(target_root, name)
            copy_file_if_exists(src, dst)


def remove_file_if_exists(path: str) -> None:
    if not path or not os.path.isfile(path):
        return
    try:
        os.remove(path)
    except Exception:
        return


def read_text_file(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def status_cn_plain(value: Any) -> str:
    key = normalize_result(str(value or "skipped"))
    return RESULT_CN_PLAIN.get(key, "已跳过")


def load_ai_deep_summary(out_root: str) -> Dict[str, Any]:
    path = os.path.join(out_root, "ai_deep_audit", "ai_deep_audit_summary.json")
    if not os.path.isfile(path):
        return {}
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def request_source_cn(value: Any) -> str:
    raw = str(value or "").strip().lower()
    mapping = {
        "rules": "规则字典",
        "route_candidates": "路由候选",
        "route_hint": "路由推断",
        "fallback": "兜底生成",
        "ai_realtime": "AI实时补全",
        "ai_artifacts": "AI产物",
        "manual": "人工指定",
    }
    return mapping.get(raw, str(value or "-") or "-")


def payload_source_cn(value: Any) -> str:
    raw = str(value or "").strip().lower()
    mapping = {
        "dictionary": "字典",
        "wordlist": "字典",
        "rules": "规则",
        "route_input_map": "路由输入",
        "ai_realtime": "AI实时补全",
        "ai_artifacts": "AI产物",
        "manual": "人工指定",
    }
    return mapping.get(raw, str(value or "-") or "-")


def build_round_signal_text(round_row: Dict[str, Any]) -> str:
    signals: List[str] = []
    status_code = round_row.get("http_status")
    if status_code not in (None, ""):
        signals.append(f"HTTP {status_code}")
    if round_row.get("sink_probe_hit"):
        signals.append("命中危险函数探针")
    if round_row.get("taint_var_reached_sink"):
        signals.append("用户输入到达危险函数")
    dynamic_reasons = round_row.get("dynamic_reasons")
    if isinstance(dynamic_reasons, list):
        for reason in dynamic_reasons[:2]:
            text = str(reason).strip()
            if text:
                signals.append(text)
    if not signals:
        return "无明显动态信号"
    return "；".join(signals[:3])


def build_case_round_rows(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    rounds_raw = case.get("attempt_rounds") if isinstance(case.get("attempt_rounds"), list) else []
    rows: List[Dict[str, Any]] = []
    for idx, item in enumerate(rounds_raw, start=1):
        if not isinstance(item, dict):
            continue
        result_key = normalize_result(str(item.get("result") or "skipped"))
        request_preview = item.get("request_preview")
        request_brief = request_brief_from_preview(request_preview)
        row = {
            "round_index": safe_int(item.get("attempt_index"), idx),
            "payload_source": payload_source_cn(item.get("payload_source")),
            "request_source": request_source_cn(item.get("request_source")),
            "request_brief": request_brief,
            "signal_text": build_round_signal_text(item),
            "round_result": status_cn_plain(result_key),
        }
        rows.append(row)

    if rows:
        rows.sort(key=lambda x: safe_int(x.get("round_index"), 0))
        return rows

    fallback_result = status_cn_plain(case.get("result"))
    return [
        {
            "round_index": 1,
            "payload_source": payload_source_cn(case.get("payload_source")),
            "request_source": request_source_cn(case.get("request_source")),
            "request_brief": request_brief_from_preview(case.get("request_preview")),
            "signal_text": compact_text(case.get("dynamic_reason") or "无明显动态信号", max_len=140),
            "round_result": fallback_result,
        }
    ]


def render_static_md(
    main_cases: List[Dict[str, Any]],
    all_cases: List[Dict[str, Any]],
    project_root: str,
    out_root: str,
) -> str:
    summary_main = summarize_cases(main_cases)
    summary_raw = summarize_cases(all_cases)
    lines: List[str] = []
    lines.append(f"# {os.path.basename(project_root)} 最终静态审计结果")
    lines.append("")
    lines.append(f"> 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"> 项目路径：`{project_root}`")
    lines.append(f"> 输出目录：`{out_root}`")
    lines.append("")
    lines.append("## 一、静态结果总览")
    lines.append("")
    lines.append(
        markdown_table(
            ["指标", "值"],
            [
                ["原始命中", str(summary_raw.get("total", 0))],
                ["去重后命中", str(summary_main.get("total", 0))],
                ["严重/高危", str(summary_main.get("critical_high", 0))],
                ["最高风险", str(SEVERITY_CN.get(str(summary_main.get("max_severity") or "low"), summary_main.get("max_severity") or "low"))],
            ],
        )
    )
    lines.append("")
    lines.append(markdown_table(["类别", "严重", "高危", "中危", "低危", "总计"], risk_overview_rows(main_cases)))
    lines.append("")
    lines.append("## 二、静态漏洞清单（去重后）")
    lines.append("")
    rows: List[List[str]] = []
    for case in main_cases:
        rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("vuln_type") or "-"),
                str(SEVERITY_CN.get(str(case.get("severity") or "low"), case.get("severity") or "low")),
                f"`{case.get('entry') or '-'}`",
                f"`{case.get('location') or '-'}`",
                str(case.get("static_conclusion") or static_conclusion_text(case)),
            ]
        )
    if not rows:
        rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append(markdown_table(["案例ID", "漏洞类型", "严重度", "入口", "位置", "静态结论"], rows))
    lines.append("")
    lines.append("## 三、关联报告")
    lines.append("")
    lines.append(f"- 动态调试审计报告：`{PRIMARY_DYNAMIC_MD}`")
    lines.append(f"- AI 深入验证最终报告：`{PRIMARY_AI_VERIFY_MD}`")
    lines.append(f"- 静态/动态/AI 绑定矩阵：`{ARCHIVE_BINDING_DIR}/{BINDING_MATRIX_MD}`")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_dynamic_md(
    all_cases: List[Dict[str, Any]],
    project_root: str,
    out_root: str,
) -> str:
    ordered = sorted(all_cases, key=case_priority_tuple, reverse=True)
    lines: List[str] = []
    lines.append(f"# {os.path.basename(project_root)} 动态debug审计报告")
    lines.append("")
    lines.append(f"> 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"> 输出目录：`{out_root}`")
    lines.append("")
    counts = {"confirmed": 0, "conditional": 0, "rejected": 0, "skipped": 0}
    for case in ordered:
        key = normalize_result(str(case.get("result") or "skipped"))
        counts[key] = counts.get(key, 0) + 1
    lines.append("## 一、动态调试结果总览")
    lines.append("")
    lines.append(
        markdown_table(
            ["状态", "数量"],
            [
                ["已确认", str(counts["confirmed"])],
                ["有条件成立", str(counts["conditional"])],
                ["已排除", str(counts["rejected"])],
                ["已跳过", str(counts["skipped"])],
            ],
        )
    )
    lines.append("")
    top_rows: List[List[str]] = []
    for case in ordered:
        top_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("vuln_type") or "-"),
                status_cn_plain(case.get("result")),
                str(case.get("http_status") if case.get("http_status") is not None else "-"),
                bool_text(case.get("sink_probe_hit")),
                bool_text(case.get("taint_var_reached_sink")),
                str(case.get("attempt_count") if case.get("attempt_count") is not None else "-"),
                str(case.get("request_source") or "-"),
                str(case.get("payload_source") or "-"),
            ]
        )
    if not top_rows:
        top_rows.append(["-", "-", "-", "-", "-", "-", "-", "-", "-"])
    lines.append(
        markdown_table(
            ["案例ID", "漏洞类型", "状态", "HTTP", "探针命中", "到达危险函数", "尝试次数", "请求来源", "Payload来源"],
            top_rows,
        )
    )
    lines.append("")
    lines.append("## 二、动态调试明细（逐条）")
    lines.append("")
    if not ordered:
        lines.append("（无动态调试结果）")
        lines.append("")
    for idx, case in enumerate(ordered, 1):
        ref, payload = burp_template_payload(case, out_root)
        status_text = str(case.get("verify_status") or verify_status_text(str(case.get("result") or "skipped")))
        risk_text = SEVERITY_CN.get(str(case.get("severity") or "low"), str(case.get("severity") or "low"))
        auth_text = str(case.get("auth_requirement_text") or "⚪ 待确认")
        if "需登录" in auth_text:
            risk_text = f"{risk_text}（需认证）"
        evidence_parts: List[str] = []
        evidence_parts.append(f"危险函数探针命中={bool_text(case.get('sink_probe_hit'))}")
        evidence_parts.append(f"用户输入到达危险函数={bool_text(case.get('taint_var_reached_sink'))}")
        if case.get("http_status") is not None:
            evidence_parts.append(f"HTTP状态={case.get('http_status')}")
        if case.get("attempt_count") is not None:
            evidence_parts.append(f"尝试次数={case.get('attempt_count')}")
        evidence_text = "；".join([str(x) for x in evidence_parts if str(x).strip()]) or "-"
        lines.append(f"### {idx}) {case.get('case_id') or '-'} - {case.get('vuln_type') or '-'}")
        lines.append("")
        lines.append(
            markdown_table(
                ["项目", "结论"],
                [
                    ["状态", f"**{status_text}**"],
                    ["风险等级", risk_text],
                    ["认证需求", auth_text],
                    ["接口", f"`{case.get('entry') or '-'}`"],
                    ["执行模式", str(case.get("execution_mode") or "-")],
                    ["验证PoC", f"`{compact_text(case.get('poc_cmd') or '-', 180)}`"],
                    ["关键证据", evidence_text],
                    ["说明", compact_text(case.get("dynamic_reason") or "-", 180)],
                ],
            )
        )
        lines.append("")
        lines.append("#### 动态调试过程（逐轮）")
        lines.append("")
        round_rows = build_case_round_rows(case)
        round_table_rows: List[List[str]] = []
        for row in round_rows:
            round_table_rows.append(
                [
                    f"第{row.get('round_index')}轮",
                    str(row.get("payload_source") or "-"),
                    str(row.get("request_source") or "-"),
                    compact_text(row.get("request_brief") or "-", 110),
                    compact_text(row.get("signal_text") or "-", 140),
                    str(row.get("round_result") or "-"),
                ]
            )
        lines.append(
            markdown_table(
                ["轮次", "Payload来源", "请求来源", "请求摘要", "关键响应信号", "本轮结论"],
                round_table_rows if round_table_rows else [["-", "-", "-", "-", "-", "-"]],
            )
        )
        first_status = str(round_table_rows[0][5]) if round_table_rows else status_cn_plain(case.get("result"))
        final_status = status_cn_plain(case.get("result"))
        lines.append("")
        if first_status != final_status:
            lines.append(f"**状态变化：** {first_status} -> {final_status}")
        else:
            lines.append(f"**状态变化：** {final_status}（单轮判定）")
        lines.append("")
        lines.append("#### Burp复现模版")
        lines.append("")
        lines.append(f"- Burp模版路径：`{ref}`")
        lines.append("")
        lines.append("```http")
        lines.append(safe_code_text(payload))
        lines.append("```")
        lines.append("")
    lines.append("## 三、证据索引")
    lines.append("")
    lines.append(f"- `debug_verify/{DEBUG_EVIDENCE_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_PROCESS_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_POC_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_FUNC_TRACE_JSON}`")
    lines.append("")
    return "\n".join(lines) + "\n"


def burp_template_payload(case: Dict[str, Any], out_root: str) -> Tuple[str, str]:
    ref = str(case.get("burp_template_ref") or "").strip()
    if not ref or ref == "-":
        return "-", "（未找到 Burp 复现模版）"
    full = os.path.join(out_root, ref)
    content = read_text_file(full).strip()
    if not content:
        return ref, "（Burp 复现模版为空或读取失败）"
    return ref, content


def render_binding_matrix_md(cases: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append("# 静态_动态_AI_结论对照表")
    lines.append("")
    rows: List[List[str]] = []
    for case in cases:
        dynamic_cn = status_cn_plain(case.get("dynamic_status") or case.get("result"))
        ai_cn = status_cn_plain(case.get("result"))
        support = str(case.get("dynamic_support_text") or dynamic_supported_text(str(case.get("dynamic_status") or "skipped")))
        consistent = "是" if dynamic_cn == ai_cn else "否"
        note = "三方一致" if consistent == "是" else "存在差异，需复核"
        rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("static_conclusion") or static_conclusion_text(case)),
                dynamic_cn,
                ai_cn,
                consistent,
                note if support == "支持" else f"{note}（{support}）",
            ]
        )
    if not rows:
        rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append(markdown_table(["案例编号", "静态结论", "动态结论", "AI最终结论", "是否一致", "说明"], rows))
    lines.append("")
    return "\n".join(lines) + "\n"


def render_ai_verify_md(
    main_cases: List[Dict[str, Any]],
    project_root: str,
    out_root: str,
) -> str:
    deep_summary = load_ai_deep_summary(out_root)
    focus_results = {"confirmed", "conditional"}
    focus_cases = [case for case in main_cases if normalize_result(str(case.get("result") or "skipped")) in focus_results]
    hidden_cases = len(main_cases) - len(focus_cases)
    target_statuses = deep_summary.get("target_statuses") if isinstance(deep_summary.get("target_statuses"), list) else []
    target_text = "、".join([status_cn_plain(x) for x in target_statuses]) if target_statuses else "有条件成立"

    lines: List[str] = []
    lines.append(f"# {os.path.basename(project_root)} AI深入验证最终报告")
    lines.append("")
    lines.append(f"> 项目：`{os.path.basename(project_root)}`")
    lines.append(f"> 时间：`{time.strftime('%Y-%m-%d %H:%M:%S')}`")
    lines.append("> 执行环境：`Docker + 真实请求(curl) + AI深度验证`")
    lines.append(f"> 输出目录：`{out_root}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 一、验证结果")
    lines.append("")
    counts = {"confirmed": 0, "conditional": 0}
    for case in focus_cases:
        key = normalize_result(str(case.get("result") or "skipped"))
        if key in counts:
            counts[key] += 1
    lines.append(
        markdown_table(
            ["指标", "值"],
            [
                ["目标状态", target_text],
                ["目标案例数", str(deep_summary.get("target_case_count") or len(focus_cases))],
                ["本轮选中数", str(deep_summary.get("selected_case_count") or len(focus_cases))],
                ["实际尝试数", str(deep_summary.get("attempted_case_count") or len(focus_cases))],
                ["升级为已确认", str(deep_summary.get("promoted_to_confirmed_count") or 0)],
                ["重点案例数", str(len(focus_cases))],
                ["已确认", str(counts["confirmed"])],
                ["有条件成立", str(counts["conditional"])],
            ],
        )
    )
    if hidden_cases > 0:
        lines.append("")
        lines.append(f"- 说明：`已排除/已跳过` 共 `{hidden_cases}` 条，已归档，不在本报告展开。")
    lines.append("")
    summary_rows: List[List[str]] = []
    for case in focus_cases:
        status_text = str(case.get("verify_status") or verify_status_text(str(case.get("result") or "skipped")))
        summary_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("vuln_type") or "-"),
                status_text,
                "Docker + PHP片段 + curl",
                f"`{case.get('entry') or '-'}`",
                str(case.get("auth_requirement_text") or "⚪ 待确认"),
            ]
        )
    if not summary_rows:
        summary_rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append(markdown_table(["漏洞名称", "类型", "状态", "验证方式", "接口", "认证需求"], summary_rows))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 二、验证过程")
    lines.append("")
    if not focus_cases:
        lines.append("（无可用验证过程）")
        lines.append("")
    for idx, case in enumerate(focus_cases, 1):
        ref, payload = burp_template_payload(case, out_root)
        status_text = str(case.get("verify_status") or verify_status_text(str(case.get("result") or "skipped")))
        risk_text = SEVERITY_CN.get(str(case.get("severity") or "low"), str(case.get("severity") or "low"))
        auth_text = str(case.get("auth_requirement_text") or "⚪ 待确认")
        if "需登录" in auth_text:
            risk_text = f"{risk_text}（需认证）"
        evidence_parts: List[str] = []
        evidence_parts.append(f"危险函数探针命中={bool_text(case.get('sink_probe_hit'))}")
        evidence_parts.append(f"用户输入到达危险函数={bool_text(case.get('taint_var_reached_sink'))}")
        if case.get("http_status") is not None:
            evidence_parts.append(f"HTTP状态={case.get('http_status')}")
        if case.get("attempt_count") is not None:
            evidence_parts.append(f"尝试次数={case.get('attempt_count')}")
        evidence_text = "；".join([str(x) for x in evidence_parts if str(x).strip()]) or "-"
        verify_method = "Docker + PHP片段 + curl + AI多轮验证"
        lines.append(f"### {idx}) {case.get('case_id') or '-'} - {case.get('vuln_type') or '-'}")
        lines.append("")
        lines.append(
            markdown_table(
                ["项目", "结论"],
                [
                    ["状态", f"**{status_text}**"],
                    ["风险等级", risk_text],
                    ["认证需求", auth_text],
                    ["接口", f"`{case.get('entry') or '-'}`"],
                    ["验证方式", verify_method],
                    ["验证PoC", f"`{compact_text(case.get('poc_cmd') or '-', 180)}`"],
                    ["关键证据", evidence_text],
                    ["说明", compact_text(case.get("dynamic_reason") or "-", 180)],
                ],
            )
        )
        lines.append("")
        lines.append("#### 动态调试过程（逐轮）")
        lines.append("")
        round_rows = build_case_round_rows(case)
        round_table_rows: List[List[str]] = []
        for row in round_rows:
            round_table_rows.append(
                [
                    f"第{row.get('round_index')}轮",
                    str(row.get("payload_source") or "-"),
                    str(row.get("request_source") or "-"),
                    compact_text(row.get("request_brief") or "-", 110),
                    compact_text(row.get("signal_text") or "-", 140),
                    str(row.get("round_result") or "-"),
                ]
            )
        lines.append(
            markdown_table(
                ["轮次", "Payload来源", "请求来源", "请求摘要", "关键响应信号", "本轮结论"],
                round_table_rows if round_table_rows else [["-", "-", "-", "-", "-", "-"]],
            )
        )
        first_status = str(round_table_rows[0][5]) if round_table_rows else status_cn_plain(case.get("result"))
        final_status = status_cn_plain(case.get("result"))
        if first_status != final_status:
            lines.append("")
            lines.append(f"**状态变化：** {first_status} -> {final_status}")
        else:
            lines.append("")
            lines.append(f"**状态变化：** {final_status}（单轮判定）")
        lines.append("")
        lines.append("#### Burp复现模版")
        lines.append("")
        lines.append(f"- Burp模版路径：`{ref}`")
        lines.append("")
        lines.append("```http")
        lines.append(safe_code_text(payload))
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 三、结论对照（静态 / 动态 / AI）")
    lines.append("")
    matrix_rows: List[List[str]] = []
    for case in focus_cases:
        dynamic_cn = status_cn_plain(case.get("dynamic_status") or case.get("result"))
        ai_cn = status_cn_plain(case.get("result"))
        consistent = "是" if dynamic_cn == ai_cn else "否"
        note = "三方一致" if consistent == "是" else "需人工复核"
        matrix_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("static_conclusion") or static_conclusion_text(case)),
                dynamic_cn,
                ai_cn,
                consistent,
                note,
            ]
        )
    if not matrix_rows:
        matrix_rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append(markdown_table(["案例编号", "静态结论", "动态结论", "AI最终结论", "是否一致", "说明"], matrix_rows))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 四、证据索引")
    lines.append("")
    lines.append(f"- `debug_verify/{DEBUG_EVIDENCE_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_PROCESS_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_POC_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_FUNC_TRACE_JSON}`")
    lines.append("- `route_mapper/burp_templates/`")
    lines.append("- `debug_verify/trace_cases/`")
    lines.append(f"- `{ARCHIVE_BINDING_DIR}/{BINDING_MATRIX_MD}`")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_md(
    main_cases: List[Dict[str, Any]],
    all_cases: List[Dict[str, Any]],
    out_root: str,
    project_root: str,
) -> str:
    summary_raw = summarize_cases(all_cases)
    summary_main = summarize_cases(main_cases)
    top5 = top_risks(main_cases, limit=5)
    issues = core_issues(main_cases)
    burp_templates = collect_burp_template_files(out_root)

    lines: List[str] = []
    lines.append(f"# {os.path.basename(project_root)} 安全审计报告（研发版）")
    lines.append("")
    lines.append(f"> 报告版本: 2.0")
    lines.append(f"> 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"> 项目路径: `{project_root}`")
    lines.append(f"> 输出路径: `{out_root}`")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 0. 一句话结论")
    lines.append("")
    lines.append(
        f"- 共发现 `{summary_raw['total']}` 条命中，主文去重后为 `{summary_main['total']}` 类。"
    )
    lines.append(
        f"- 最高风险为 **{SEVERITY_CN.get(summary_main['max_severity'], summary_main['max_severity'])}**，上线建议 **{go_no_go_text(summary_main['go_no_go'])}**。"
    )
    lines.append("- 判定口径：`已确认可利用`、`条件成立`、`已排除`。")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 1. 今天先做什么（24h动作）")
    lines.append("")
    action_rows: List[List[str]] = []
    for idx, row in enumerate(top5, 1):
        fix_code, _, _ = remediation_pack(str(row.get("vuln_type") or ""))
        action_rows.append(
            [
                str(idx),
                str(row.get("case_id") or "-"),
                f"`{row.get('location') or '-'}`",
                compact_text(fix_code, max_len=40),
                "24h" if row.get("severity") in ("critical", "high") else "72h",
            ]
        )
    if not action_rows:
        action_rows.append(["-", "-", "-", "-", "-"])
    lines.append(markdown_table(["序号", "问题ID", "位置", "先做什么", "时限"], action_rows))
    if issues:
        lines.append("")
        lines.append(f"- 今日首要动作：{issues[0]}")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 2. 风险总览（去重后）")
    lines.append("")
    lines.append(
        markdown_table(
            ["指标", "数值"],
            [
                ["原始命中数", str(summary_raw["total"])],
                ["去重后问题数", str(summary_main["total"])],
                ["已确认可利用", str(summary_main["confirmed"])],
                ["条件成立", str(summary_main["conditional"])],
                ["严重/高危", str(summary_main["critical_high"])],
            ],
        )
    )
    lines.append("")
    lines.append(markdown_table(["类别", "严重", "高危", "中危", "低危", "总计"], risk_overview_rows(main_cases)))
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 3. 漏洞详情（人话版）")
    lines.append("")
    if main_cases:
        for case in main_cases:
            lines.extend(render_human_case(case))
    else:
        lines.append("（无漏洞）")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 4. 静态与动态结果总览")
    lines.append("")
    binding_rows: List[List[str]] = []
    for case in main_cases[:30]:
        evidence_refs = case.get("evidence_refs") if isinstance(case.get("evidence_refs"), list) else []
        evidence_hint = "；".join([str(x) for x in evidence_refs[:2]]) if evidence_refs else "-"
        binding_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("static_conclusion") or static_conclusion_text(case)),
                str(RESULT_CN.get(str(case.get("dynamic_status") or "skipped"), case.get("dynamic_status") or "skipped")),
                str(case.get("dynamic_support_text") or dynamic_supported_text(str(case.get("dynamic_status") or "skipped"))),
                compact_text(case.get("dynamic_reason") or "-", max_len=72),
                compact_text(evidence_hint, max_len=90),
            ]
        )
    if not binding_rows:
        binding_rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append("### 4.1 静态-动态证据支持矩阵")
    lines.append("")
    lines.append(
        markdown_table(
            ["ID", "静态结论", "动态状态", "是否支持", "动态说明", "证据引用"],
            binding_rows,
        )
    )
    lines.append("")

    static_rows: List[List[str]] = []
    for case in main_cases[:20]:
        static_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("vuln_type") or "-"),
                str(SEVERITY_CN.get(str(case.get("severity") or "low"), case.get("severity") or "low")),
                f"`{case.get('location') or '-'}`",
                f"`{case.get('entry') or '-'}`",
                str(RESULT_CN.get(str(case.get("result") or "skipped"), case.get("result") or "skipped")),
            ]
        )
    if not static_rows:
        static_rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append("### 4.2 静态结果（去重后）")
    lines.append("")
    lines.append(markdown_table(["ID", "类型", "严重度", "位置", "入口", "判定"], static_rows))
    lines.append("")

    dynamic_rows: List[List[str]] = []
    for case in main_cases[:20]:
        dynamic_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(RESULT_CN.get(str(case.get("result") or "skipped"), case.get("result") or "skipped")),
                str(case.get("http_status") if case.get("http_status") is not None else "-"),
                bool_text(case.get("sink_probe_hit")),
                bool_text(case.get("taint_var_reached_sink")),
                str(case.get("attempt_count") if case.get("attempt_count") is not None else "-"),
                str(case.get("request_source") or "-"),
                str(case.get("payload_source") or "-"),
            ]
    )
    if not dynamic_rows:
        dynamic_rows.append(["-", "-", "-", "-", "-", "-", "-", "-"])
    lines.append("### 4.3 动态调试结果（去重代表）")
    lines.append("")
    lines.append(
        markdown_table(
            ["ID", "调试结论", "HTTP", "探针命中", "到达危险函数", "尝试次数", "请求来源", "Payload来源"],
            dynamic_rows,
        )
    )
    lines.append("")

    poc_rows: List[List[str]] = []
    for case in main_cases[:20]:
        poc_rows.append(
            [
                str(case.get("case_id") or "-"),
                compact_text(case.get("poc_cmd") or "-", max_len=120),
            ]
    )
    if not poc_rows:
        poc_rows.append(["-", "-"])
    lines.append("### 4.4 PoC 命令")
    lines.append("")
    lines.append(markdown_table(["ID", "PoC"], poc_rows))
    lines.append("")

    lines.append("### 4.5 Burp 模版")
    lines.append("")
    if burp_templates:
        burp_rows = [[str(i + 1), f"`{rel}`"] for i, rel in enumerate(burp_templates)]
        lines.append(markdown_table(["序号", "模板文件"], burp_rows))
    else:
        lines.append("（无 Burp 模版）")
    lines.append("")

    lines.append("### 4.6 可利用验证清单（便于导入 Burp）")
    lines.append("")
    exploit_rows: List[List[str]] = []
    for case in main_cases[:50]:
        exploit_rows.append(
            [
                str(case.get("burp_payload_file") or "-"),
                str(human_vuln_name(str(case.get("vuln_type") or "-"))),
                str(case.get("auth_requirement_text") or "⚪ 待确认"),
                str(case.get("verify_status") or verify_status_text(str(case.get("result") or "skipped"))),
                str(SEVERITY_CN.get(str(case.get("severity") or "low"), str(case.get("severity") or "low"))),
                compact_text(case.get("exploit_conclusion") or "-", max_len=60),
            ]
        )
    if not exploit_rows:
        exploit_rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append(
        markdown_table(
            ["文件名", "漏洞", "认证需求", "验证状态", "危险等级", "利用说明"],
            exploit_rows,
        )
    )
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 5. 附录入口")
    lines.append("")
    lines.append(f"- 详细技术附录：`{CN_REPORT_APPENDIX_MD}`")
    lines.append("- 动态变化已提供颜色标识与表格总览；若客户端不支持颜色，请按 `[高危]/[中危]/[信息]` 标签阅读。")
    lines.append("- 证据索引：")
    lines.append(f"- `debug_verify/{DEBUG_EVIDENCE_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_PROCESS_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_FUNC_TRACE_JSON}`")
    lines.append(f"- `debug_verify/trace_cases/`")
    lines.append(f"- `route_mapper/burp_templates/`")
    if burp_templates:
        preview = ", ".join([f"`{x}`" for x in burp_templates[:5]])
        lines.append(f"- Burp 模版文件：{preview}")
        if len(burp_templates) > 5:
            lines.append(f"- 其余 {len(burp_templates) - 5} 个见附录 `E. Burp 模版`")
    else:
        lines.append("- Burp 模版文件：`无`")
    lines.append(f"- `{CN_REPORT_JSON}`")
    lines.append("")
    lines.append("## 元信息")
    lines.append("")
    lines.append(markdown_table(["项目", "值"], build_meta_rows(out_root)))
    lines.append("")
    return "\n".join(lines) + "\n"


def render_appendix_md(
    all_cases: List[Dict[str, Any]],
    out_root: str,
    project_root: str,
) -> str:
    ordered = sorted(all_cases, key=case_priority_tuple, reverse=True)
    color_mode = read_color_mode()
    burp_templates = collect_burp_template_files(out_root)
    lines: List[str] = []
    lines.append(f"# {os.path.basename(project_root)} 技术附录（原始细节）")
    lines.append("")
    lines.append(f"> 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## A. 原始命中清单（未去重）")
    lines.append("")
    raw_rows: List[List[str]] = []
    for case in ordered:
        raw_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("vuln_type") or "-"),
                str(SEVERITY_CN.get(str(case.get("severity") or "low"), case.get("severity") or "low")),
                str(RESULT_CN.get(str(case.get("result") or "skipped"), case.get("result") or "skipped")),
                f"`{case.get('entry') or '-'}`",
                f"`{case.get('location') or '-'}`",
                str(case.get("evidence_score") or 0),
                f"`{case_group_key(case)}`",
            ]
        )
    if not raw_rows:
        raw_rows.append(["-", "-", "-", "-", "-", "-", "-", "-"])
    lines.append(
        markdown_table(
            ["案例ID", "类型", "严重度", "判定", "入口", "位置", "证据分", "归并键"],
            raw_rows,
        )
    )
    lines.append("")

    lines.append("## B. 动态调试过程与结果（按案例ID）")
    lines.append("")
    if not ordered:
        lines.append("（无动态调试结果）")
        lines.append("")
    for case in ordered:
        case_id = str(case.get("case_id") or "-")
        anchor = appendix_anchor_id(case_id)
        slice_path = resolve_case_slice_path(case, out_root)
        slice_display = normalize_path_for_report(slice_path, project_root, out_root) if slice_path else "-"
        lines.append(f"<a id=\"{anchor}\"></a>")
        lines.append(f"### [{case_id}] 动态调试摘要")
        lines.append(f"- 漏洞类型：`{case.get('vuln_type') or '-'}`")
        lines.append(f"- 入口：`{case.get('entry') or '-'}`")
        lines.append(f"- 位置：`{case.get('location') or '-'}`")
        lines.append(f"- 追踪文件：`{case.get('trace_case_file') or '-'}`")
        lines.append(f"- 切片代码：`{slice_display}`")
        lines.append("")
        lines.append(markdown_table(["项", "值"], dynamic_result_rows(case)))
        lines.append("")
        lines.append("### 动态变化总览（颜色+表格）")
        lines.append("")
        lines.append(render_debug_change_overview_table(case, color_mode))
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>完整切片代码 + 行旁调试变化（->）</summary>")
        lines.append("")
        lines.append("```php")
        lines.append(safe_code_text(render_slice_code_with_inline_changes(case, out_root)))
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>请求预览（可选）</summary>")
        lines.append("")
        lines.append("```json")
        lines.append(safe_code_text(case.get("request_preview") or ""))
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>响应头预览（可选）</summary>")
        lines.append("")
        lines.append("```http")
        lines.append(safe_code_text(case.get("response_header_preview") or ""))
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("## C. 可利用验证清单")
    lines.append("")
    exploit_rows: List[List[str]] = []
    for case in ordered:
        exploit_rows.append(
            [
                str(case.get("burp_payload_file") or "-"),
                str(human_vuln_name(str(case.get("vuln_type") or "-"))),
                str(case.get("auth_requirement_text") or "⚪ 待确认"),
                str(case.get("verify_status") or verify_status_text(str(case.get("result") or "skipped"))),
                str(SEVERITY_CN.get(str(case.get("severity") or "low"), str(case.get("severity") or "low"))),
                compact_text(case.get("exploit_conclusion") or "-", max_len=72),
            ]
        )
    if not exploit_rows:
        exploit_rows.append(["-", "-", "-", "-", "-", "-"])
    lines.append(
        markdown_table(
            ["文件名", "漏洞", "认证需求", "验证状态", "危险等级", "利用说明"],
            exploit_rows,
        )
    )
    lines.append("")

    lines.append("## D. PoC命令全集")
    lines.append("")
    poc_rows: List[List[str]] = []
    for case in ordered:
        poc_rows.append(
            [
                str(case.get("case_id") or "-"),
                str(case.get("vuln_type") or "-"),
                str(case.get("entry") or "-"),
                compact_text(case.get("poc_cmd") or "-", max_len=220),
            ]
        )
    if not poc_rows:
        poc_rows.append(["-", "-", "-", "-"])
    lines.append(markdown_table(["案例ID", "类型", "入口", "PoC命令"], poc_rows))
    lines.append("")

    lines.append("## E. Burp 模版")
    lines.append("")
    if not burp_templates:
        lines.append("（无 Burp 模版）")
        lines.append("")
    else:
        rows: List[List[str]] = []
        for idx, rel in enumerate(burp_templates, 1):
            rows.append([str(idx), f"`{rel}`"])
        lines.append(markdown_table(["序号", "模板文件"], rows))
        lines.append("")
        for rel in burp_templates:
            full = os.path.join(out_root, rel)
            raw = ""
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read()
            except Exception:
                raw = "（读取失败）"
            lines.append("<details>")
            lines.append(f"<summary>{rel}</summary>")
            lines.append("")
            lines.append("```http")
            lines.append(safe_code_text(raw.strip()))
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    lines.append("## F. 证据文件索引")
    lines.append("")
    lines.append(f"- `{CN_REPORT_MD}`")
    lines.append(f"- `{CN_REPORT_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_EVIDENCE_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_PROCESS_JSON}`")
    lines.append(f"- `debug_verify/{DEBUG_FUNC_TRACE_JSON}`")
    lines.append(f"- `debug_verify/trace_cases/`")
    lines.append(f"- `route_mapper/burp_templates/`")
    lines.append(f"- `证据校验.md`")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_cn_report_text(report_text: str) -> str:
    text = str(report_text or "")
    text = text.replace("final_report_appendix.md", CN_REPORT_APPENDIX_MD)
    text = text.replace("final_report.json", CN_REPORT_JSON)
    text = text.replace("debug_verify/debug_evidence.json", f"debug_verify/{DEBUG_EVIDENCE_JSON}")
    text = text.replace("debug_verify/debug_process.json", f"debug_verify/{DEBUG_PROCESS_JSON}")
    text = text.replace("debug_verify/debug_poc.json", f"debug_verify/{DEBUG_POC_JSON}")
    text = text.replace("debug_verify/debug_func_trace.json", f"debug_verify/{DEBUG_FUNC_TRACE_JSON}")
    return text


def build_cn_appendix_text(appendix_text: str) -> str:
    text = str(appendix_text or "")
    text = text.replace("final_report.md", CN_REPORT_MD)
    text = text.replace("final_report.json", CN_REPORT_JSON)
    text = text.replace("debug_verify/debug_evidence.json", f"debug_verify/{DEBUG_EVIDENCE_JSON}")
    text = text.replace("debug_verify/debug_process.json", f"debug_verify/{DEBUG_PROCESS_JSON}")
    text = text.replace("debug_verify/debug_poc.json", f"debug_verify/{DEBUG_POC_JSON}")
    text = text.replace("debug_verify/debug_func_trace.json", f"debug_verify/{DEBUG_FUNC_TRACE_JSON}")
    return text


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)
    archive_paths = ensure_archive_layout(out_root)

    findings, sources = load_findings(out_root)
    deduped, duplicates = deduplicate(findings)
    debug_evidence = load_debug_evidence(out_root)
    debug_process = load_debug_process(out_root)
    debug_func_trace = load_debug_func_trace(out_root)
    route_auth_map = load_route_auth_map(out_root)
    burp_templates = collect_burp_template_files(out_root)

    all_case_rows = build_case_rows(
        findings,
        project_root=project_root,
        out_root=out_root,
        debug_evidence=debug_evidence,
        debug_process=debug_process,
        debug_func_trace=debug_func_trace,
        burp_templates=burp_templates,
        route_auth_map=route_auth_map,
    )
    main_cases = build_main_cases(all_case_rows)
    report_main_cases = [compact_case_for_report(case) for case in main_cases]
    binding_matrix = [
        {
            "case_id": str(case.get("case_id") or "-"),
            "static_conclusion": str(case.get("static_conclusion") or static_conclusion_text(case)),
            "dynamic_status": str(case.get("dynamic_status") or normalize_result(case.get("result"))),
            "dynamic_supported": bool(case.get("dynamic_supported")),
            "dynamic_support_text": str(
                case.get("dynamic_support_text")
                or dynamic_supported_text(str(case.get("dynamic_status") or case.get("result") or "skipped"))
            ),
            "dynamic_reason": str(case.get("dynamic_reason") or "-"),
            "poc_cmd": str(case.get("poc_cmd") or "-"),
            "verify_status": str(case.get("verify_status") or verify_status_text(str(case.get("result") or "skipped"))),
            "auth_requirement_text": str(case.get("auth_requirement_text") or "⚪ 待确认"),
            "exploit_conclusion": str(case.get("exploit_conclusion") or "-"),
            "burp_payload_file": str(case.get("burp_payload_file") or "-"),
            "vuln_code": str(case.get("vuln_code") or "-"),
            "evidence_refs": case.get("evidence_refs") if isinstance(case.get("evidence_refs"), list) else [],
            "burp_template_ref": str(case.get("burp_template_ref") or "-"),
        }
        for case in main_cases
    ]
    summary = summarize_cases(main_cases)
    summary_raw = summarize_cases(all_case_rows)

    report = {
        "summary": summary,
        "summary_raw": summary_raw,
        "overall_risk": overall_risk(summary),
        "findings_raw_total": len(findings),
        "findings_total": len(deduped),
        "cases_total": len(report_main_cases),
        "cases_total_raw": len(all_case_rows),
        "findings": deduped,
        "duplicates": duplicates,
        "sources": sources,
        "main_cases": report_main_cases,
        "binding_matrix": binding_matrix,
        "debug_evidence_path": os.path.join("debug_verify", DEBUG_EVIDENCE_JSON),
        "debug_process_path": os.path.join("debug_verify", DEBUG_PROCESS_JSON),
        "debug_func_trace_path": os.path.join("debug_verify", DEBUG_FUNC_TRACE_JSON),
        "trace_cases_dir": os.path.join("debug_verify", "trace_cases"),
        "burp_templates_dir": os.path.join("route_mapper", "burp_templates"),
        "artifacts": {
            "static_main_md_path": PRIMARY_STATIC_MD,
            "dynamic_main_md_path": PRIMARY_DYNAMIC_MD,
            "ai_verify_main_md_path": PRIMARY_AI_VERIFY_MD,
            "legacy_report_md_path": os.path.join(ARCHIVE_BINDING_DIR, CN_REPORT_MD),
            "legacy_report_appendix_md_path": os.path.join(ARCHIVE_BINDING_DIR, CN_REPORT_APPENDIX_MD),
            "legacy_report_json_path": os.path.join(ARCHIVE_BINDING_DIR, CN_REPORT_JSON),
            "legacy_report_alias_md_path": os.path.join(ARCHIVE_BINDING_DIR, CN_REPORT_ALIAS_MD),
            "legacy_report_alias_appendix_md_path": os.path.join(ARCHIVE_BINDING_DIR, CN_REPORT_ALIAS_APPENDIX_MD),
            "legacy_report_alias_json_path": os.path.join(ARCHIVE_BINDING_DIR, CN_REPORT_ALIAS_JSON),
            "binding_matrix_md_path": os.path.join(ARCHIVE_BINDING_DIR, BINDING_MATRIX_MD),
            "debug_evidence_path": os.path.join("debug_verify", DEBUG_EVIDENCE_JSON),
            "debug_process_path": os.path.join("debug_verify", DEBUG_PROCESS_JSON),
            "debug_func_trace_path": os.path.join("debug_verify", DEBUG_FUNC_TRACE_JSON),
            "trace_cases_dir": os.path.join("debug_verify", "trace_cases"),
            "burp_templates_dir": os.path.join("route_mapper", "burp_templates"),
        },
    }

    report_json_path = os.path.join(archive_paths["binding"], CN_REPORT_JSON)
    report_alias_json_path = os.path.join(archive_paths["binding"], CN_REPORT_ALIAS_JSON)
    write_json(report_json_path, report)
    write_json(report_alias_json_path, report)

    report_text = render_md(main_cases, all_case_rows, out_root, project_root)
    report_path = os.path.join(archive_paths["binding"], CN_REPORT_MD)
    report_alias_path = os.path.join(archive_paths["binding"], CN_REPORT_ALIAS_MD)
    appendix_text = render_appendix_md(all_case_rows, out_root, project_root)
    appendix_path = os.path.join(archive_paths["binding"], CN_REPORT_APPENDIX_MD)
    appendix_alias_path = os.path.join(archive_paths["binding"], CN_REPORT_ALIAS_APPENDIX_MD)

    report_cn_text = build_cn_report_text(report_text)
    appendix_cn_text = build_cn_appendix_text(appendix_text)

    write_text(report_path, report_cn_text)
    write_text(appendix_path, appendix_cn_text)
    write_text(report_alias_path, report_cn_text)
    write_text(appendix_alias_path, appendix_cn_text)

    static_path = os.path.join(out_root, PRIMARY_STATIC_MD)
    dynamic_path = os.path.join(out_root, PRIMARY_DYNAMIC_MD)
    ai_verify_path = os.path.join(out_root, PRIMARY_AI_VERIFY_MD)
    write_text(static_path, render_static_md(main_cases, all_case_rows, project_root, out_root))
    write_text(dynamic_path, render_dynamic_md(all_case_rows, project_root, out_root))
    write_text(ai_verify_path, render_ai_verify_md(main_cases, project_root, out_root))

    binding_matrix_path = os.path.join(archive_paths["binding"], BINDING_MATRIX_MD)
    write_text(binding_matrix_path, render_binding_matrix_md(main_cases))

    # Archive stage reports for phased handoff usage.
    stage_candidates = [
        os.path.join(out_root, "_meta", "phase1_map.md"),
        os.path.join(out_root, "_meta", "phase2_risk_map.md"),
        os.path.join(out_root, "_meta", "phase3_trace_log.md"),
        os.path.join(out_root, "_meta", "phase4_attack_chain.md"),
        os.path.join(out_root, "_meta", "phase5_report_index.md"),
        os.path.join(out_root, "审计流水线状态.md"),
        os.path.join(out_root, "agent_task_manifest.md"),
        os.path.join(out_root, "phase_gate_0.md"),
        os.path.join(out_root, "phase_gate_1.md"),
        os.path.join(out_root, "phase_gate_2.md"),
        os.path.join(out_root, "phase_gate_3.md"),
        os.path.join(out_root, "phase_gate_4.md"),
        os.path.join(out_root, "phase_gate_5.md"),
        os.path.join(out_root, "phase_gate_6.md"),
    ]
    for src in stage_candidates:
        if not os.path.isfile(src):
            continue
        dst = os.path.join(archive_paths["stage"], os.path.basename(src))
        copy_file_if_exists(src, dst)

    # Keep only three main reports at out root; phase/gate markdown files are archived.
    root_aux_md_candidates = [
        os.path.join(out_root, "审计流水线状态.md"),
        os.path.join(out_root, "agent_task_manifest.md"),
        os.path.join(out_root, "phase_gate_0.md"),
        os.path.join(out_root, "phase_gate_1.md"),
        os.path.join(out_root, "phase_gate_2.md"),
        os.path.join(out_root, "phase_gate_3.md"),
        os.path.join(out_root, "phase_gate_4.md"),
        os.path.join(out_root, "phase_gate_5.md"),
        os.path.join(out_root, "phase_gate_6.md"),
    ]
    for src in root_aux_md_candidates:
        remove_file_if_exists(src)

    # Archive dynamic evidence files for security-team review.
    debug_candidates = [
        os.path.join(out_root, "debug_verify", "动态调试证据.md"),
        os.path.join(out_root, "debug_verify", DEBUG_EVIDENCE_JSON),
        os.path.join(out_root, "debug_verify", "动态调试过程.md"),
        os.path.join(out_root, "debug_verify", DEBUG_PROCESS_JSON),
        os.path.join(out_root, "debug_verify", "动态调试PoC.md"),
        os.path.join(out_root, "debug_verify", DEBUG_POC_JSON),
        os.path.join(out_root, "debug_verify", "函数追踪证据.md"),
        os.path.join(out_root, "debug_verify", DEBUG_FUNC_TRACE_JSON),
    ]
    for src in debug_candidates:
        if not os.path.exists(src):
            continue
        dst = os.path.join(archive_paths["debug"], os.path.basename(src))
        copy_file_if_exists(src, dst)

    trace_cases_src = os.path.join(out_root, "debug_verify", "trace_cases")
    trace_cases_dst = os.path.join(archive_paths["debug"], "trace_cases")
    copy_tree_if_exists(trace_cases_src, trace_cases_dst)

    # Archive Burp templates from both static and dynamic stages.
    copy_tree_if_exists(
        os.path.join(out_root, "route_mapper", "burp_templates"),
        os.path.join(archive_paths["burp"], "route_mapper"),
    )
    copy_tree_if_exists(
        os.path.join(out_root, "debug_verify", "burp_templates"),
        os.path.join(archive_paths["burp"], "debug_verify"),
    )

    print(f"静态主报告路径: {static_path}")
    print(f"动态主报告路径: {dynamic_path}")
    print(f"AI深验主报告路径: {ai_verify_path}")
    print(f"归档主报告路径: {report_path}")
    print(f"归档技术附录路径: {appendix_path}")
    print(f"归档主报告JSON路径: {report_json_path}")
    print(f"归档绑定矩阵路径: {binding_matrix_path}")


if __name__ == "__main__":
    main()
