#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Set

sys.path.insert(0, os.path.dirname(__file__))

from common import build_output_root, walk_php_files, write_text
from audit_helpers import markdown_table

SCRIPT_DIR = os.path.dirname(__file__)


def resolve_python() -> str:
    env_py = os.environ.get("SKILLS_PYTHON")
    if env_py and os.path.exists(env_py):
        return env_py
    venv_py = os.path.join(os.path.dirname(SCRIPT_DIR), ".venv", "bin", "python3")
    if os.path.exists(venv_py):
        return venv_py
    return sys.executable or "python3"


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
    raise SystemExit("Use skills/docker/run_audit.sh")

PIPELINE_ORDER = [
    "route_mapper",
    "call_graph",
    "route_tracer",
    "ai_audit",
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "vuln_scanner",
    "mcp_adapter",
    "severity_enrich",
    "ai_confirm",
    "debug_verify",
    "report_refresh",
    "phase_attack_chain",
    "phase_report_index",
    "final_report",
    "evidence_check",
]

DEFAULT_MODULES = [
    "route_mapper",
    "call_graph",
    "route_tracer",
    "ai_audit",
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "mcp_adapter",
    "severity_enrich",
    "ai_confirm",
    "debug_verify",
    "report_refresh",
    "phase_attack_chain",
    "phase_report_index",
    "final_report",
    "evidence_check",
]

DEPS = {
    "route_tracer": ["route_mapper"],
    "call_graph": ["route_tracer"],
    "ai_audit": ["route_mapper", "route_tracer", "call_graph"],
    "sql_audit": ["route_tracer"],
    "auth_audit": ["route_mapper"],
    "file_audit": ["route_tracer"],
    "rce_audit": ["route_tracer"],
    "ssrf_xxe_audit": ["route_tracer"],
    "xss_ssti_audit": ["route_tracer"],
    "csrf_audit": ["route_tracer"],
    "var_override_audit": ["route_tracer"],
    "serialize_audit": ["route_tracer"],
    "ai_confirm": ["severity_enrich", "route_tracer", "call_graph"],
}

RULE_AUDIT_MODULES = [
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "vuln_scanner",
]


def hash_strings(items: List[str]) -> str:
    h = hashlib.sha256()
    for s in items:
        h.update(s.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def hash_paths(paths: List[str]) -> str:
    entries: List[str] = []
    for p in paths:
        if not p:
            continue
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                    except Exception:
                        continue
                    entries.append(f"{fp}:{st.st_mtime_ns}:{st.st_size}")
        elif os.path.exists(p):
            try:
                st = os.stat(p)
                entries.append(f"{p}:{st.st_mtime_ns}:{st.st_size}")
            except Exception:
                entries.append(f"{p}:error")
        else:
            entries.append(f"{p}:missing")
    entries.sort()
    return hash_strings(entries)


def project_signature(project_root: str) -> str:
    php_files = walk_php_files(project_root)
    extra = []
    for name in ["composer.lock", "composer.json"]:
        p = os.path.join(project_root, name)
        if os.path.exists(p):
            extra.append(p)
    route_configs = []
    for p in [
        os.path.join(project_root, "config", "routes.yaml"),
        os.path.join(project_root, "config", "routes.yml"),
    ]:
        if os.path.exists(p):
            route_configs.append(p)
    routes_dir = os.path.join(project_root, "config", "routes")
    if os.path.isdir(routes_dir):
        for root, _, files in os.walk(routes_dir):
            for f in files:
                if f.endswith(".yml") or f.endswith(".yaml"):
                    route_configs.append(os.path.join(root, f))
    return hash_paths(php_files + extra + route_configs)


def list_findings_files(out_root: str) -> List[str]:
    files = []
    for root, _, names in os.walk(out_root):
        for n in names:
            if n == "findings.json" or n == "auth_evidence.json":
                files.append(os.path.join(root, n))
    return files


def load_meta(out_root: str) -> Dict:
    path = os.path.join(out_root, "meta.json")
    if not os.path.exists(path):
        return {"stages": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "stages" in data:
                return data
    except Exception:
        pass
    return {"stages": {}}


def ai_audit_ok(out_root: str) -> bool:
    path = os.path.join(out_root, "ai_audit", "ai_audit_report.json")
    if not os.path.exists(path):
        return False
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return False
    return bool(data.get("ok"))


def save_meta(out_root: str, meta: Dict) -> None:
    path = os.path.join(out_root, "meta.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


REPORT_DIRS = {
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "vuln_report",
}

STAGE_DIR_SKIP = {
    "ai_audit_context",
    "ai_context",
    "mcp_raw",
    "http_runtime",
    "slices",
    "trace_cases",
    "burp_templates",
}

REPORT_EXTENSIONS = {".md", ".json", ".html"}

ROUTE_TRACER_REPORT_NAMES = {"trace.json", "trace.md", "sinks.json", "call_graph.json", "call_graph.md"}

MODULE_DIR_CN_MAP = {
    "sql_audit": "SQL注入审计",
    "auth_audit": "鉴权审计",
    "file_audit": "文件风险审计",
    "rce_audit": "命令执行审计",
    "ssrf_xxe_audit": "SSRF_XXE审计",
    "xss_ssti_audit": "XSS_SSTI审计",
    "csrf_audit": "CSRF审计",
    "var_override_audit": "变量覆盖审计",
    "serialize_audit": "反序列化审计",
    "vuln_report": "依赖漏洞审计",
    "route_mapper": "路由映射",
    "route_tracer": "路由追踪",
    "debug_verify": "动态调试",
    "mcp_raw": "AI原始结果",
    "mcp_parsed": "AI解析结果",
    "_meta": "阶段元信息",
}

REPORT_BUNDLE_DIR = "报告汇总"

FILE_CN_MAP = {
    "final_report.md": "总报告.md",
    "final_report_appendix.md": "总报告_技术附录.md",
    "final_report.json": "总报告.json",
    "总报告.md": "总报告.md",
    "总报告_技术附录.md": "总报告_技术附录.md",
    "总报告.json": "总报告.json",
    "evidence_check.md": "证据校验.md",
    "evidence_check.json": "证据校验.json",
    "debug_cases.json": "动态调试用例.json",
    "debug_evidence.md": "动态调试证据.md",
    "debug_evidence.json": "动态调试证据.json",
    "debug_process.md": "动态调试过程.md",
    "debug_process.json": "动态调试过程.json",
    "debug_poc.md": "动态调试PoC.md",
    "debug_poc.json": "动态调试PoC.json",
    "debug_func_trace.md": "函数追踪证据.md",
    "debug_func_trace.json": "函数追踪证据.json",
    "poc_plan.md": "PoC计划.md",
    "poc_plan.json": "PoC计划.json",
    "routes.md": "路由映射.md",
    "routes.json": "路由映射.json",
    "trace.md": "路由追踪.md",
    "trace.json": "路由追踪.json",
    "sinks.json": "危险函数汇总.json",
    "summary.json": "MCP结果汇总.json",
    "meta.json": "执行元信息.json",
    "phase1_map.md": "阶段1_映射.md",
    "phase2_risk_map.md": "阶段2_风险映射.md",
    "phase3_trace_log.md": "阶段3_追踪日志.md",
    "phase4_attack_chain.md": "阶段4_攻击链.md",
    "phase5_report_index.md": "阶段5_报告索引.md",
}


def is_report_file(path: str) -> bool:
    name = os.path.basename(path)
    if name in {"meta.json"}:
        return False
    ext = os.path.splitext(name)[1].lower()
    return ext in REPORT_EXTENSIONS


def latest_matching_md(dir_path: str, pattern: str) -> Optional[str]:
    candidates: List[str] = []
    for n in os.listdir(dir_path):
        p = os.path.join(dir_path, n)
        if not os.path.isfile(p):
            continue
        if not n.endswith(".md"):
            continue
        if pattern in n:
            candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    return candidates[0]


def collect_reports_from_dir(dir_path: str) -> List[str]:
    if not os.path.isdir(dir_path):
        return []
    base = os.path.basename(dir_path.rstrip("/"))
    reports: List[str] = []
    if base == "route_tracer":
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in STAGE_DIR_SKIP]
            for n in files:
                if n in ROUTE_TRACER_REPORT_NAMES:
                    reports.append(os.path.join(root, n))
        return reports

    if base in REPORT_DIRS:
        fixed_names = ["findings.json", "findings.md", "index.html"]
        if base == "auth_audit":
            fixed_names = [
                "auth_evidence.json",
                "auth_findings.md",
                "auth_routes.md",
                "index.html",
            ]
            for marker in ["_auth_audit_", "_auth_mapping_", "_auth_README_"]:
                latest = latest_matching_md(dir_path, marker)
                if latest:
                    reports.append(latest)
        elif base == "vuln_report":
            fixed_names = ["composer_audit.json", "composer_audit.md"]
        else:
            latest = latest_matching_md(dir_path, f"_{base}_")
            if latest:
                reports.append(latest)

        for n in fixed_names:
            p = os.path.join(dir_path, n)
            if os.path.isfile(p):
                reports.append(p)
        return reports

    for n in os.listdir(dir_path):
        p = os.path.join(dir_path, n)
        if os.path.isfile(p) and is_report_file(p):
            reports.append(p)
    return reports


def collect_report_paths(out_root: str, selected_stages: List[str]) -> List[str]:
    report_paths: List[str] = []
    for stage in selected_stages:
        outputs = stage_outputs(out_root, stage)
        for output in outputs:
            if os.path.isfile(output) and is_report_file(output):
                report_paths.append(output)
                continue
            if os.path.isdir(output):
                report_paths.extend(collect_reports_from_dir(output))

    unique = sorted(set(report_paths))
    final_md = os.path.join(out_root, "final_report.md")
    final_list = [p for p in unique if p != final_md]
    if os.path.exists(final_md):
        final_list.append(final_md)
    return final_list


def remap_to_host_out(path: str, out_root: str, host_out_root: Optional[str]) -> str:
    if not host_out_root:
        return path
    out_abs = os.path.abspath(out_root)
    host_abs = os.path.abspath(host_out_root)
    path_abs = os.path.abspath(path)
    if path_abs == out_abs:
        return host_abs
    prefix = out_abs + os.sep
    if path_abs.startswith(prefix):
        rel = path_abs[len(prefix) :]
        return os.path.join(host_abs, rel)
    return path


def print_report_paths(out_root: str, selected_stages: List[str], host_out_root: Optional[str]) -> None:
    report_paths = collect_report_paths(out_root, selected_stages)
    if not report_paths:
        print("[REPORTS] No report files found.")
        return
    print("[REPORTS] Generated report files:")
    for p in report_paths:
        shown = remap_to_host_out(p, out_root, host_out_root)
        print(f"- {shown}")


def _safe_filename(name: str) -> str:
    out = str(name or "").replace("/", "_").replace("\\", "_")
    out = " ".join(out.split())
    return out.strip() or "未命名结果"


def _ensure_unique_name(name: str, used: Set[str]) -> str:
    base = _safe_filename(name)
    stem, ext = os.path.splitext(base)
    if base not in used:
        used.add(base)
        return base
    i = 2
    while True:
        candidate = f"{stem}_{i}{ext}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        i += 1


def _module_label_from_relpath(rel_path: str) -> str:
    rel_norm = str(rel_path or "").replace("\\", "/")
    first = rel_norm.split("/", 1)[0] if rel_norm else ""
    return MODULE_DIR_CN_MAP.get(first, "审计结果")


def _cn_alias_name(rel_path: str, seq: int) -> str:
    rel_norm = str(rel_path or "").replace("\\", "/")
    base = os.path.basename(rel_norm)
    parent = os.path.basename(os.path.dirname(rel_norm))
    ext = os.path.splitext(base)[1].lower()

    direct = FILE_CN_MAP.get(base)
    if direct:
        return direct

    module_label = _module_label_from_relpath(rel_norm)

    if base == "findings.md":
        return f"{module_label}_发现.md"
    if base == "findings.json":
        return f"{module_label}_发现.json"
    if base == "index.html":
        return f"{module_label}_详情页.html"

    if base.startswith("out_") and base.endswith(".md"):
        return f"{module_label}_执行日志.md"

    if parent == "trace_cases" and base.endswith(".json"):
        case_stem = os.path.splitext(base)[0]
        return f"案例追踪_{case_stem}.json"

    if base.endswith(".html") and "-" in base:
        case_stem = os.path.splitext(base)[0]
        return f"漏洞详情_{case_stem}.html"

    if base.endswith(".json") and "-" in base:
        case_stem = os.path.splitext(base)[0]
        return f"漏洞数据_{case_stem}.json"

    if ext == ".md":
        return f"结果报告_{seq:03d}.md"
    if ext == ".json":
        return f"结果数据_{seq:03d}.json"
    if ext == ".html":
        return f"结果页面_{seq:03d}.html"
    return f"结果文件_{seq:03d}{ext or ''}"


def build_chinese_named_results(out_root: str, selected_stages: List[str]) -> List[str]:
    report_paths = collect_report_paths(out_root, selected_stages)
    if not report_paths:
        return []

    rel_existing = set(
        os.path.relpath(p, out_root).replace("\\", "/")
        for p in report_paths
        if os.path.isfile(p)
    )
    cn_prefer_en = {
        "总报告.md": "final_report.md",
        "总报告_技术附录.md": "final_report_appendix.md",
        "总报告.json": "final_report.json",
    }

    cn_dir = os.path.join(out_root, REPORT_BUNDLE_DIR)
    os.makedirs(cn_dir, exist_ok=True)

    used: Set[str] = set()
    mapping_rows: List[List[str]] = []
    generated: List[str] = []

    for idx, src in enumerate(report_paths, 1):
        if not os.path.isfile(src):
            continue
        rel = os.path.relpath(src, out_root).replace("\\", "/")
        base = os.path.basename(rel)
        preferred_en = cn_prefer_en.get(base)
        if preferred_en and preferred_en in rel_existing:
            # Skip duplicated Chinese-source alias if English canonical source exists.
            continue
        cn_name = _ensure_unique_name(_cn_alias_name(rel, idx), used)
        dst = os.path.join(cn_dir, cn_name)
        try:
            shutil.copy2(src, dst)
        except Exception:
            continue
        generated.append(dst)
        mapping_rows.append([f"`{cn_name}`", f"`{rel}`"])

    index_path = os.path.join(cn_dir, "文件对照表.md")
    lines = ["# 报告汇总文件对照表", ""]
    if mapping_rows:
        lines.append(markdown_table(["中文文件名", "原始文件"], mapping_rows))
    else:
        lines.append("（无可用文件）")
    lines.append("")
    write_text(index_path, "\n".join(lines))
    generated.append(index_path)
    return generated


def print_chinese_report_paths(paths: List[str], out_root: str, host_out_root: Optional[str]) -> None:
    if not paths:
        return
    unique = sorted(set(paths))
    bundle_dir = remap_to_host_out(os.path.join(out_root, REPORT_BUNDLE_DIR), out_root, host_out_root)
    print(f"[REPORTS-CN] 报告汇总目录: {bundle_dir}")
    print("[REPORTS-CN] 报告汇总文件:")
    for p in unique:
        shown = remap_to_host_out(p, out_root, host_out_root)
        print(f"- {shown}")


def stage_outputs(out_root: str, stage: str) -> List[str]:
    if stage == "route_mapper":
        return [
            os.path.join(out_root, "route_mapper", "routes.json"),
            os.path.join(out_root, "route_mapper", "routes.md"),
            os.path.join(out_root, "route_mapper", "burp_templates"),
        ]
    if stage == "call_graph":
        return [
            os.path.join(out_root, "route_tracer", "call_graph.json"),
            os.path.join(out_root, "route_tracer", "call_graph.md"),
        ]
    if stage == "route_tracer":
        return [os.path.join(out_root, "route_tracer")]
    if stage == "ai_audit":
        return [
            os.path.join(out_root, "ai_audit", "ai_findings.json"),
            os.path.join(out_root, "ai_audit", "findings.json"),
            os.path.join(out_root, "ai_audit", "ai_audit_report.json"),
            os.path.join(out_root, "ai_audit", "ai_audit_context"),
        ]
    if stage == "sql_audit":
        return [os.path.join(out_root, "sql_audit")]
    if stage == "auth_audit":
        return [os.path.join(out_root, "auth_audit")]
    if stage == "file_audit":
        return [os.path.join(out_root, "file_audit")]
    if stage == "rce_audit":
        return [os.path.join(out_root, "rce_audit")]
    if stage == "ssrf_xxe_audit":
        return [os.path.join(out_root, "ssrf_xxe_audit")]
    if stage == "xss_ssti_audit":
        return [os.path.join(out_root, "xss_ssti_audit")]
    if stage == "csrf_audit":
        return [os.path.join(out_root, "csrf_audit")]
    if stage == "var_override_audit":
        return [os.path.join(out_root, "var_override_audit")]
    if stage == "serialize_audit":
        return [os.path.join(out_root, "serialize_audit")]
    if stage == "vuln_scanner":
        return [os.path.join(out_root, "vuln_report")]
    if stage == "mcp_adapter":
        return [os.path.join(out_root, "mcp_parsed", "summary.json")]
    if stage == "severity_enrich":
        return list_findings_files(out_root)
    if stage == "ai_confirm":
        return [os.path.join(out_root, "ai_confirm.json"), os.path.join(out_root, "ai_context")]
    if stage == "report_refresh":
        return [os.path.join(out_root, "sql_audit"), os.path.join(out_root, "file_audit"), os.path.join(out_root, "rce_audit"), os.path.join(out_root, "ssrf_xxe_audit"), os.path.join(out_root, "xss_ssti_audit"), os.path.join(out_root, "csrf_audit"), os.path.join(out_root, "var_override_audit"), os.path.join(out_root, "serialize_audit"), os.path.join(out_root, "auth_audit")]
    if stage == "debug_verify":
        return [
            os.path.join(out_root, "debug_verify", "debug_cases.json"),
            os.path.join(out_root, "debug_verify", "poc_plan.json"),
            os.path.join(out_root, "debug_verify", "poc_plan.md"),
            os.path.join(out_root, "debug_verify", "debug_evidence.json"),
            os.path.join(out_root, "debug_verify", "debug_evidence.md"),
            os.path.join(out_root, "debug_verify", "debug_process.json"),
            os.path.join(out_root, "debug_verify", "debug_process.md"),
            os.path.join(out_root, "debug_verify", "debug_poc.json"),
            os.path.join(out_root, "debug_verify", "debug_poc.md"),
            os.path.join(out_root, "debug_verify", "debug_func_trace.json"),
            os.path.join(out_root, "debug_verify", "debug_func_trace.md"),
        ]
    if stage == "phase_attack_chain":
        return [os.path.join(out_root, "_meta", "phase4_attack_chain.md")]
    if stage == "final_report":
        return [
            os.path.join(out_root, "final_report.json"),
            os.path.join(out_root, "final_report_appendix.md"),
            os.path.join(out_root, "final_report.md"),
            os.path.join(out_root, "总报告.json"),
            os.path.join(out_root, "总报告_技术附录.md"),
            os.path.join(out_root, "总报告.md"),
        ]
    if stage == "phase_report_index":
        return [
            os.path.join(out_root, "_meta", "phase1_map.md"),
            os.path.join(out_root, "_meta", "phase2_risk_map.md"),
            os.path.join(out_root, "_meta", "phase3_trace_log.md"),
            os.path.join(out_root, "_meta", "phase4_attack_chain.md"),
            os.path.join(out_root, "_meta", "phase5_report_index.md"),
        ]
    if stage == "evidence_check":
        return [
            os.path.join(out_root, "evidence_check.json"),
            os.path.join(out_root, "evidence_check.md"),
        ]
    return []


def outputs_exist(outputs: List[str]) -> bool:
    for p in outputs:
        if os.path.isdir(p):
            if not os.path.exists(p):
                return False
            base = os.path.basename(p.rstrip("/"))
            if base in REPORT_DIRS:
                if not _module_outputs_complete(p, base):
                    return False
        else:
            if not os.path.exists(p):
                return False
    return True


def _module_outputs_complete(dir_path: str, module: str) -> bool:
    # Must have findings/auth evidence and a module report
    if module == "auth_audit":
        required = ["auth_evidence.json"]
        files = os.listdir(dir_path) if os.path.isdir(dir_path) else []
        if not all(os.path.exists(os.path.join(dir_path, r)) for r in required):
            return False
        has_reports = (
            any(f.endswith(".md") and "_auth_audit_" in f for f in files)
            and any(f.endswith(".md") and "_auth_mapping_" in f for f in files)
            and any(f.endswith(".md") and "_auth_README_" in f for f in files)
        )
        return has_reports
    if module == "vuln_report":
        if not os.path.exists(os.path.join(dir_path, "composer_audit.json")):
            return False
        if not os.path.exists(os.path.join(dir_path, "composer_audit.md")):
            return False
        return True

    findings = os.path.join(dir_path, "findings.json")
    if not os.path.exists(findings):
        return False
    files = os.listdir(dir_path) if os.path.isdir(dir_path) else []
    return any(f.endswith(".md") and f"_{module}_" in f for f in files)


def stage_input_hash(stage: str, project_sig: str, out_root: str, config_path: str, quick_mode: bool = False) -> str:
    parts = [project_sig]
    common = os.path.join(SCRIPT_DIR, "common.py")
    audit_helpers = os.path.join(SCRIPT_DIR, "audit_helpers.py")

    if stage == "route_mapper":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "route_mapper.py"), common]))
    elif stage == "call_graph":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "call_graph.py"), common]))
    elif stage == "route_tracer":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "route_tracer.py"), common]))
        parts.append(hash_paths([os.path.join(out_root, "route_mapper", "routes.json")]))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer", "call_graph.json")]))
    elif stage == "ai_audit":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "ai_audit.py"), common]))
        parts.append(hash_paths([os.path.join(out_root, "route_mapper", "routes.json")]))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer")]))
        parts.append(hash_paths([os.path.join(out_root, "mcp_raw", "ai-audit-mcp.json")]))
    elif stage in {
        "sql_audit",
        "auth_audit",
        "file_audit",
        "rce_audit",
        "ssrf_xxe_audit",
        "xss_ssti_audit",
        "csrf_audit",
        "var_override_audit",
        "serialize_audit",
    }:
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, f"{stage}.py"), common, audit_helpers]))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer")]))
    elif stage == "vuln_scanner":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "vuln_scanner.py")]))
    elif stage == "mcp_adapter":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "mcp_adapter.py"), config_path]))
    elif stage == "severity_enrich":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "severity_enricher.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "ai_confirm":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "ai_confirm.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer"), os.path.join(out_root, "route_mapper", "routes.json")]))
    elif stage == "debug_verify":
        parts.append(
            hash_paths(
                [
                    os.path.join(SCRIPT_DIR, "debug_cases.py"),
                    os.path.join(SCRIPT_DIR, "debug_runner.py"),
                    os.path.join(SCRIPT_DIR, "auto_slice.py"),
                    os.path.join(SCRIPT_DIR, "mcp_config.debug.json"),
                    os.path.join(SCRIPT_DIR, "..", "ai-confirm-mcp", "scripts", "ai_confirm_mcp.py"),
                ]
            )
        )
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "..", "php-audit-common", "references", "debug_change_rules.yml")]))
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "..", "wordlists")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "report_refresh":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "report_refresh.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "phase_attack_chain":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "phase_attack_chain.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "phase_report_index":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "phase_report_index.py")]))
        parts.append(hash_paths([os.path.join(out_root, "_meta")]))
    elif stage == "final_report":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "final_report.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
        parts.append(hash_paths([
            os.path.join(out_root, "debug_verify", "debug_evidence.json"),
            os.path.join(out_root, "debug_verify", "debug_evidence.md"),
            os.path.join(out_root, "debug_verify", "debug_func_trace.json"),
            os.path.join(out_root, "debug_verify", "debug_func_trace.md"),
        ]))
    elif stage == "evidence_check":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "evidence_check.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
        parts.append(hash_paths([os.path.join(out_root, "_meta")]))
        parts.append(hash_paths([
            os.path.join(out_root, "debug_verify", "debug_evidence.json"),
            os.path.join(out_root, "debug_verify", "debug_evidence.md"),
            os.path.join(out_root, "debug_verify", "debug_func_trace.json"),
            os.path.join(out_root, "debug_verify", "debug_func_trace.md"),
            os.path.join(out_root, "final_report.md"),
            os.path.join(out_root, "final_report_appendix.md"),
        ]))
    else:
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, f"{stage}.py")]))

    if quick_mode and stage in RULE_AUDIT_MODULES:
        parts.append("rule_audit_quick_mode=1")

    return hash_strings(parts)


def build_cmd(stage: str, project_root: str, out_root: str, config_path: str, threads: int, progress: bool) -> List[str]:
    py = resolve_python()
    if stage == "route_mapper":
        cmd = [py, os.path.join(SCRIPT_DIR, "route_mapper.py"), "--project", project_root, "--out", out_root]
        if threads is not None:
            cmd.extend(["--threads", str(threads)])
        cmd.append("--progress" if progress else "--no-progress")
        return cmd
    if stage == "call_graph":
        cmd = [py, os.path.join(SCRIPT_DIR, "call_graph.py"), "--project", project_root, "--out", out_root]
        if threads is not None:
            cmd.extend(["--threads", str(threads)])
        cmd.append("--progress" if progress else "--no-progress")
        return cmd
    if stage == "route_tracer":
        return [py, os.path.join(SCRIPT_DIR, "route_tracer.py"), "--project", project_root, "--out", out_root]
    if stage == "ai_audit":
        return [py, os.path.join(SCRIPT_DIR, "ai_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "sql_audit":
        return [py, os.path.join(SCRIPT_DIR, "sql_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "auth_audit":
        return [py, os.path.join(SCRIPT_DIR, "auth_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "file_audit":
        return [py, os.path.join(SCRIPT_DIR, "file_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "rce_audit":
        return [py, os.path.join(SCRIPT_DIR, "rce_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "ssrf_xxe_audit":
        return [py, os.path.join(SCRIPT_DIR, "ssrf_xxe_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "xss_ssti_audit":
        return [py, os.path.join(SCRIPT_DIR, "xss_ssti_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "csrf_audit":
        return [py, os.path.join(SCRIPT_DIR, "csrf_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "var_override_audit":
        return [py, os.path.join(SCRIPT_DIR, "var_override_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "serialize_audit":
        return [py, os.path.join(SCRIPT_DIR, "serialize_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "vuln_scanner":
        return [py, os.path.join(SCRIPT_DIR, "vuln_scanner.py"), "--project", project_root, "--out", out_root]
    if stage == "mcp_adapter":
        cmd = [py, os.path.join(SCRIPT_DIR, "mcp_adapter.py"), "--project", project_root, "--out", out_root, "--all"]
        if config_path and os.path.exists(config_path):
            cmd.extend(["--config", config_path])
        return cmd
    if stage == "severity_enrich":
        return [py, os.path.join(SCRIPT_DIR, "severity_enricher.py"), "--project", project_root, "--out", out_root]
    if stage == "ai_confirm":
        return [py, os.path.join(SCRIPT_DIR, "ai_confirm.py"), "--project", project_root, "--out", out_root]
    if stage == "debug_verify":
        return [py, os.path.join(SCRIPT_DIR, "debug_runner.py"), "--project", project_root, "--out", out_root]
    if stage == "report_refresh":
        return [py, os.path.join(SCRIPT_DIR, "report_refresh.py"), "--project", project_root, "--out", out_root]
    if stage == "phase_attack_chain":
        return [py, os.path.join(SCRIPT_DIR, "phase_attack_chain.py"), "--project", project_root, "--out", out_root]
    if stage == "final_report":
        return [py, os.path.join(SCRIPT_DIR, "final_report.py"), "--project", project_root, "--out", out_root]
    if stage == "phase_report_index":
        return [py, os.path.join(SCRIPT_DIR, "phase_report_index.py"), "--project", project_root, "--out", out_root]
    if stage == "evidence_check":
        cmd = [py, os.path.join(SCRIPT_DIR, "evidence_check.py"), "--project", project_root, "--out", out_root]
        if os.environ.get("EVIDENCE_STRICT") == "1":
            cmd.append("--strict")
        return cmd
    raise SystemExit(f"Unknown stage: {stage}")


def build_stage_env(stage: str, ai_ok: bool) -> Dict[str, str]:
    env = os.environ.copy()
    if ai_ok and stage in RULE_AUDIT_MODULES:
        env["RULE_AUDIT_QUICK"] = "1"
        env.setdefault("RULE_AUDIT_QUICK_REASON", "ai_audit_ok")
    else:
        env.pop("RULE_AUDIT_QUICK", None)
        env.pop("RULE_AUDIT_QUICK_REASON", None)
    return env


def expand_dependencies(selected: Set[str]) -> Set[str]:
    expanded = set(selected)
    changed = True
    while changed:
        changed = False
        for s in list(expanded):
            for dep in DEPS.get(s, []):
                if dep not in expanded:
                    expanded.add(dep)
                    changed = True
    return expanded


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--modules", default=None, help="Comma-separated module list or 'all'")
    ap.add_argument("--skip-mcp", action="store_true", help="Skip mcp_adapter stage")
    ap.add_argument("--no-cache", action="store_true", help="Disable cache")
    ap.add_argument("--force", action="store_true", help="Force re-run all stages")
    ap.add_argument("--config", default=None, help="mcp_config.json path")
    ap.add_argument("--evidence-strict", action="store_true", help="Fail if evidence_check finds issues")
    ap.add_argument("--threads", type=int, default=0, help="Worker threads for file scans (0=auto)")
    ap.add_argument("--progress", dest="progress", action="store_true", default=True, help="Show progress bars for file scans (default: on)")
    ap.add_argument("--no-progress", dest="progress", action="store_false", help="Disable progress bars")
    args = ap.parse_args()

    ensure_running_in_container()
    print("[INFO] Running inside docker container.")

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)
    host_out_root = os.environ.get("SKILLS_HOST_OUT")

    modules_provided = args.modules is not None
    if not modules_provided or args.modules == "all":
        selected = set(DEFAULT_MODULES)
    else:
        selected = set([m.strip() for m in args.modules.split(",") if m.strip()])

    if args.skip_mcp:
        selected.discard("mcp_adapter")
        if not modules_provided:
            selected.add("vuln_scanner")

    selected = expand_dependencies(selected)
    if args.skip_mcp:
        selected.discard("mcp_adapter")

    if args.config:
        config_path = args.config
    else:
        default_cfg = os.path.join(SCRIPT_DIR, "mcp_config.json")
        example_cfg = os.path.join(SCRIPT_DIR, "mcp_config.example.json")
        config_path = default_cfg if os.path.exists(default_cfg) else example_cfg

    project_sig = project_signature(project_root)
    meta = load_meta(out_root)

    if args.evidence_strict:
        os.environ["EVIDENCE_STRICT"] = "1"

    ai_ok = False
    selected_stages = [s for s in PIPELINE_ORDER if s in selected]
    for stage in PIPELINE_ORDER:
        if stage not in selected:
            continue

        quick_mode = ai_ok and stage in RULE_AUDIT_MODULES
        if quick_mode:
            print(f"[INFO] {stage} running in quick mode (ai_audit ok)")

        outputs = stage_outputs(out_root, stage)
        input_hash = stage_input_hash(stage, project_sig, out_root, config_path, quick_mode=quick_mode)
        previous = meta.get("stages", {}).get(stage)
        cache_hit = (
            previous
            and previous.get("input_hash") == input_hash
            and outputs_exist(outputs)
        )

        if args.force or args.no_cache:
            cache_hit = False

        if cache_hit:
            print(f"[SKIP] {stage} (cache)")
            if stage == "ai_audit":
                ai_ok = ai_audit_ok(out_root)
                if ai_ok:
                    print("[INFO] ai_audit ok; rule modules will run in quick mode.")
            continue

        cmd = build_cmd(stage, project_root, out_root, config_path, args.threads, args.progress)
        print(f"[RUN] {stage}: {' '.join(cmd)}")
        proc = subprocess.run(cmd, cwd=project_root, capture_output=False, env=build_stage_env(stage, ai_ok))
        if proc.returncode != 0:
            raise SystemExit(f"Stage failed: {stage}")

        if stage == "ai_audit":
            ai_ok = ai_audit_ok(out_root)
            if ai_ok:
                print("[INFO] ai_audit ok; rule modules will run in quick mode.")

        meta.setdefault("stages", {})[stage] = {
            "input_hash": input_hash,
            "outputs": outputs,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        save_meta(out_root, meta)

    shown_out_root = remap_to_host_out(out_root, out_root, host_out_root)
    print(f"Audit complete. Output: {shown_out_root}")
    print_report_paths(out_root, selected_stages, host_out_root)
    cn_paths = build_chinese_named_results(out_root, selected_stages)
    print_chinese_report_paths(cn_paths, out_root, host_out_root)


if __name__ == "__main__":
    main()
