#!/usr/bin/env python3
import argparse
import json
import os
import time
from typing import Dict, List

from common import build_output_root, write_text, write_json
from audit_helpers import write_module_report, write_module_html, load_findings
from sql_audit import render_sql_report, project_name_from_out


def refresh_sql(out_root: str) -> None:
    sql_dir = os.path.join(out_root, "sql_audit")
    findings_path = os.path.join(sql_dir, "findings.json")
    if not os.path.exists(findings_path):
        return
    findings = load_findings(findings_path)
    attach_debug(findings, load_debug_map(out_root))
    ts = time.strftime("%Y%m%d_%H%M%S")
    report_name = f"{project_name_from_out(out_root)}_sql_audit_{ts}.md"
    content = render_sql_report(findings, out_root, ts)
    write_text(os.path.join(sql_dir, report_name), content)
    write_module_html(sql_dir, "sql_audit", "SQL 注入审计报告", findings)


def refresh_generic(out_root: str, module: str, title: str) -> None:
    mod_dir = os.path.join(out_root, module)
    findings_path = os.path.join(mod_dir, "findings.json")
    if not os.path.exists(findings_path):
        return
    findings = load_findings(findings_path)
    attach_debug(findings, load_debug_map(out_root))
    write_module_report(mod_dir, module, title, findings)


def refresh_auth(out_root: str) -> None:
    auth_dir = os.path.join(out_root, "auth_audit")
    evidence_path = os.path.join(auth_dir, "auth_evidence.json")
    if not os.path.exists(evidence_path):
        return
    try:
        findings = json.load(open(evidence_path, "r", encoding="utf-8"))
    except Exception:
        findings = []
    attach_debug(findings, load_debug_map(out_root))

    ts = time.strftime("%Y%m%d_%H%M%S")
    project = project_name_from_out(out_root)

    # mapping from findings only
    mapping_name = f"{project}_auth_mapping_{ts}.md"
    m_lines = [
        f"# {project} - 鉴权映射表",
        "",
        f"生成时间：{ts}",
        "",
        "| Method | Path | Controller | Action | Auth Keywords | Ownership Check | Middlewares |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        route = f.get("route") or {}
        m_lines.append(
            f"| {route.get('method','')} | {route.get('path','')} | {route.get('controller','')} | {route.get('action','')} | - | - | - |"
        )
    write_text(os.path.join(auth_dir, mapping_name), "\n".join(m_lines) + "\n")

    # main report
    report_name = f"{project}_auth_audit_{ts}.md"
    r_lines = [
        f"# {project} - 鉴权审计报告",
        "",
        f"生成时间：{ts}",
        f"总风险数：{len(findings)}",
        "",
        "## 风险摘要",
    ]
    for f in findings:
        route = f.get("route") or {}
        r_lines.append(f"- {route.get('method','')} {route.get('path','')} -> {f.get('title')}")
    r_lines.append("")
    r_lines.append("## 详细风险")
    for f in findings:
        route = f.get("route") or {}
        r_lines.append(f"### {f.get('id')} {f.get('title')}")
        r_lines.append(f"- 路由：{route.get('method')} {route.get('path')}")
        r_lines.append(f"- 独立等级：{f.get('independent_severity') or f.get('severity')}")
        r_lines.append(f"- 组合等级：{f.get('combined_severity') or f.get('severity')}")
        r_lines.append(f"- 置信度：{f.get('confidence')}")
        r_lines.append(f"- 可控性：{f.get('controllability')}")
        r_lines.append("")
    write_text(os.path.join(auth_dir, report_name), "\n".join(r_lines) + "\n")

    # README
    readme_name = f"{project}_auth_README_{ts}.md"
    rd_lines = [
        f"# {project} - 鉴权审计说明",
        "",
        "本目录包含三份对外交付文件：",
        f"- {report_name}：主报告（漏洞分析与风险摘要）",
        f"- {mapping_name}：路由→鉴权机制映射表",
        f"- {readme_name}：本说明文件",
        "",
        "说明：",
        "- 主报告不重复完整路由清单",
        "- 映射表不包含漏洞分析或 PoC",
    ]
    write_text(os.path.join(auth_dir, readme_name), "\n".join(rd_lines) + "\n")
    write_module_html(auth_dir, "auth_audit", "鉴权审计报告", findings)


def _severity_from_advisory(item: Dict) -> str:
    sev = (item.get("severity") or "medium").lower()
    if sev in {"critical", "high", "medium", "low"}:
        return sev
    return "medium"


def refresh_vuln_report(out_root: str) -> None:
    vuln_dir = os.path.join(out_root, "vuln_report")
    audit_path = os.path.join(vuln_dir, "composer_audit.json")
    if not os.path.exists(audit_path):
        return
    try:
        data = json.load(open(audit_path, "r", encoding="utf-8"))
    except Exception:
        return

    advisories = data.get("advisories") if isinstance(data, dict) else {}
    findings: List[Dict] = []
    seq = 1
    if isinstance(advisories, dict):
        for pkg, items in advisories.items():
            for item in items or []:
                fid = f"VULN-{seq:03d}"
                title = item.get("title") or "Dependency Advisory"
                severity = _severity_from_advisory(item)
                cvss = item.get("cvss") or item.get("cvss_score") or item.get("cvssScore")
                findings.append({
                    "id": fid,
                    "title": f"{pkg} - {title}",
                    "severity": severity,
                    "independent_severity": severity,
                    "combined_severity": severity,
                    "confidence": "high",
                    "route": None,
                    "source": {"package": pkg},
                    "taint": [],
                    "sink": {"file": "composer.lock", "line": 0, "function": pkg, "type": "dependency"},
                    "validation": [],
                    "controllability": "conditional",
                    "poc": {"notes": "依赖漏洞，需结合组件使用场景确认"},
                    "notes": item.get("link") or item.get("cve") or "Dependency advisory",
                    "cvss_score": cvss,
                })
                seq += 1

    os.makedirs(vuln_dir, exist_ok=True)
    attach_debug(findings, load_debug_map(out_root))
    write_json(os.path.join(vuln_dir, "findings.json"), findings)
    write_module_report(vuln_dir, "vuln_report", "依赖漏洞审计报告", findings)


def load_debug_map(out_root: str) -> Dict[str, Dict]:
    path = os.path.join(out_root, "debug_verify", "debug_evidence.json")
    if not os.path.exists(path):
        return {}
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return {}
    mapping = {}
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("case_id"):
                mapping[item["case_id"]] = item
    return mapping


def attach_debug(findings: List[Dict], debug_map: Dict[str, Dict]) -> None:
    if not findings or not debug_map:
        return
    for f in findings:
        fid = f.get("id")
        if fid and fid in debug_map:
            f["debug_evidence"] = debug_map[fid]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    out_root = build_output_root(os.path.abspath(args.project), args.out)

    refresh_sql(out_root)
    refresh_auth(out_root)
    refresh_generic(out_root, "file_audit", "文件类漏洞审计报告")
    refresh_generic(out_root, "rce_audit", "命令/代码执行审计报告")
    refresh_generic(out_root, "ssrf_xxe_audit", "SSRF/XXE 审计报告")
    refresh_generic(out_root, "xss_ssti_audit", "XSS/SSTI 审计报告")
    refresh_generic(out_root, "csrf_audit", "CSRF 漏洞审计报告")
    refresh_generic(out_root, "var_override_audit", "变量覆盖审计报告")
    refresh_generic(out_root, "serialize_audit", "反序列化审计报告")
    refresh_vuln_report(out_root)

    print("Reports refreshed")


if __name__ == "__main__":
    main()
