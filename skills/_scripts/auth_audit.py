#!/usr/bin/env python3
import argparse
import json
import os
import re
import time

from audit_helpers import (
    apply_rule_audit_quick_filter,
    build_output_root,
    compact_text,
    markdown_table,
    project_name_from_out,
    stable_id,
    write_module_html,
)
from common import read_text

AUTH_KEYWORDS = [
    "auth",
    "middleware",
    "gate",
    "policy",
    "permission",
    "role",
    "guard",
    "jwt",
    "isadmin",
    "checkpermission",
    "tenant_id",
    "user_id",
]

OWNERSHIP_FIELDS = [
    "user_id",
    "owner_id",
    "uid",
    "created_by",
    "author_id",
    "tenant_id",
    "org_id",
    "company_id",
    "account_id",
]

AUTH_ID_PATTERNS = [
    re.compile(r"Auth::id\s*\(", re.I),
    re.compile(r"auth\s*\(\)\s*->\s*id\s*\(", re.I),
    re.compile(r"\$user->id", re.I),
    re.compile(r"\$this->user->id", re.I),
    re.compile(r"request\s*\(\)\s*->\s*user\s*\(\)\s*->\s*id\s*\(", re.I),
]


def load_routes(routes_json: str):
    with open(routes_json, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_auth_keywords(text: str):
    lower = text.lower()
    hits = [k for k in AUTH_KEYWORDS if k in lower]
    return hits


def detect_ownership_checks(text: str):
    checks = []
    auth_vars = set()
    for idx, line in enumerate(text.splitlines(), start=1):
        for p in AUTH_ID_PATTERNS:
            if p.search(line):
                m = re.search(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*.+", line)
                if m:
                    auth_vars.add(m.group(1))
        line_lower = line.lower()
        if any(field in line_lower for field in OWNERSHIP_FIELDS):
            if any(p.search(line) for p in AUTH_ID_PATTERNS):
                checks.append({"line": idx, "code": line.strip(), "kind": "direct"})
                continue
            for v in auth_vars:
                if f"${v}" in line:
                    checks.append({"line": idx, "code": line.strip(), "kind": "via_var"})
                    break
    return checks


def extract_method_body(text: str, action: str):
    pattern = re.compile(rf"function\s+{re.escape(action)}\s*\([^)]*\)\s*\{{", re.I)
    m = pattern.search(text)
    if not m:
        return ""
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
        return ""
    return text[start + 1 : end]


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
    auth_routes = []
    findings = []

    for r in routes:
        controller_file = r.get("controller_file")
        action = r.get("action")
        if not controller_file or not action:
            continue
        text = read_text(controller_file)
        body = extract_method_body(text, action)
        hits = detect_auth_keywords(body)
        ownership_checks = detect_ownership_checks(body)
        middlewares = [m.lower() for m in (r.get("middlewares") or [])]
        mw_hits = [m for m in middlewares if any(k in m for k in AUTH_KEYWORDS)]
        hits = list(dict.fromkeys(hits + mw_hits))
        auth_routes.append({
            "method": r.get("method"),
            "path": r.get("path"),
            "controller": r.get("controller"),
            "action": action,
            "auth_keywords": hits,
            "ownership_checks": ownership_checks,
            "middlewares": r.get("middlewares") or [],
        })
        if not hits and not ownership_checks:
            fid = stable_id("AUTH", controller_file, 0, r.get("path") or "")
            findings.append({
                "id": fid,
                "title": "Possible Missing Authorization",
                "severity": "medium",
                "independent_severity": "medium",
                "combined_severity": "medium",
                "confidence": "low",
                "route": {
                    "method": r.get("method"),
                    "path": r.get("path"),
                    "controller": r.get("controller"),
                    "action": action,
                },
                "source": None,
                "taint": [],
                "sink": {"file": controller_file, "line": 0, "function": action, "code": ""},
                "validation": [],
                "controllability": "conditional",
                "poc": {"method": r.get("method"), "path": r.get("path"), "notes": "仅模板，不执行"},
                "notes": "No auth keyword or ownership check found in handler body.",
            })

    findings = apply_rule_audit_quick_filter(findings, "auth_audit")

    out_dir = os.path.join(out_root, "auth_audit")
    os.makedirs(out_dir, exist_ok=True)

    # auth_routes.md
    lines = ["# Auth Routes", ""]
    route_rows = []
    for r in auth_routes:
        own = "yes" if r.get("ownership_checks") else "no"
        middlewares = ", ".join(r.get("middlewares") or []) or "none"
        route_rows.append(
            [
                r.get("method") or "-",
                r.get("path") or "-",
                r.get("controller") or "-",
                r.get("action") or "-",
                f"{', '.join(r.get('auth_keywords') or []) or 'none'} / ownership:{own}",
                middlewares,
            ]
        )
    lines.append(
        markdown_table(
            ["Method", "Path", "Controller", "Action", "Auth Keywords", "Middlewares"],
            [[compact_text(c) for c in row] for row in route_rows],
        )
    )
    with open(os.path.join(out_dir, "auth_routes.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # auth_findings.md
    f_lines = ["# Auth Findings", "", f"Total: {len(findings)}", ""]
    f_rows = []
    for fnd in findings:
        route = fnd.get("route") or {}
        f_rows.append([
            fnd.get("id") or "-",
            route.get("method") or "-",
            route.get("path") or "-",
            fnd.get("title") or "-",
        ])
    f_lines.append(
        markdown_table(
            ["ID", "Method", "Path", "Title"],
            [[compact_text(c) for c in row] for row in f_rows],
        )
    )
    with open(os.path.join(out_dir, "auth_findings.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(f_lines) + "\n")

    # auth_evidence.json
    with open(os.path.join(out_dir, "auth_evidence.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    # ---- external 3-file delivery ----
    ts = time.strftime("%Y%m%d_%H%M%S")
    project_name = project_name_from_out(out_root)

    # mapping file (routes -> auth mechanisms)
    mapping_name = f"{project_name}_auth_mapping_{ts}.md"
    m_lines = [
        f"# {project_name} - 鉴权映射表",
        "",
        f"生成时间：{ts}",
        "",
    ]
    m_rows = []
    for r in auth_routes:
        own = "yes" if r.get("ownership_checks") else "no"
        middlewares = ", ".join(r.get("middlewares") or []) or "none"
        m_rows.append(
            [
                r.get("method") or "-",
                r.get("path") or "-",
                r.get("controller") or "-",
                r.get("action") or "-",
                ", ".join(r.get("auth_keywords") or []) or "none",
                own,
                middlewares,
            ]
        )
    m_lines.append(
        markdown_table(
            ["Method", "Path", "Controller", "Action", "Auth Keywords", "Ownership", "Middlewares"],
            [[compact_text(c) for c in row] for row in m_rows],
        )
    )
    with open(os.path.join(out_dir, mapping_name), "w", encoding="utf-8") as f:
        f.write("\n".join(m_lines) + "\n")

    # main report (findings only, no full route list)
    report_name = f"{project_name}_auth_audit_{ts}.md"
    r_lines = [
        f"# {project_name} - 鉴权审计报告",
        "",
        f"生成时间：{ts}",
        f"总风险数：{len(findings)}",
        "",
        "## 风险摘要",
    ]
    summary_rows = []
    for fnd in findings:
        route = fnd.get("route") or {}
        summary_rows.append([
            fnd.get("id") or "-",
            route.get("method") or "-",
            route.get("path") or "-",
            fnd.get("title") or "-",
        ])
    r_lines.append(
        markdown_table(
            ["ID", "Method", "Path", "Title"],
            [[compact_text(c) for c in row] for row in summary_rows],
        )
    )
    r_lines.append("")
    r_lines.append("## 详细风险表")
    detail_rows = []
    for fnd in findings:
        route = fnd.get("route") or {}
        ai_info = fnd.get("ai_confirm") or {}
        ai_table = fnd.get("ai_table") if isinstance(fnd.get("ai_table"), dict) else None
        evidence_summary = ai_table.get("evidence_summary") if ai_table else None
        detail_rows.append([
            fnd.get("id") or "-",
            fnd.get("title") or "-",
            f"{route.get('method','')} {route.get('path','')}".strip() or "-",
            fnd.get("independent_severity") or fnd.get("severity") or "-",
            fnd.get("combined_severity") or fnd.get("severity") or "-",
            fnd.get("confidence") or "-",
            fnd.get("controllability") or "-",
            fnd.get("exploitability") or "-",
            ai_info.get("rationale") or "-",
            evidence_summary or "-",
            fnd.get("notes") or "-",
        ])
    r_lines.append(
        markdown_table(
            ["ID", "标题", "路由", "独立等级", "组合等级", "置信度", "可控性", "可利用性", "AI理由", "证据摘要", "证据"],
            [[compact_text(c) for c in row] for row in detail_rows],
        )
    )
    r_lines.append("")
    with open(os.path.join(out_dir, report_name), "w", encoding="utf-8") as f:
        f.write("\n".join(r_lines) + "\n")

    # README
    readme_name = f"{project_name}_auth_README_{ts}.md"
    rd_lines = [
        f"# {project_name} - 鉴权审计说明",
        "",
        "本目录包含三份对外交付文件：",
        markdown_table(
            ["文件", "说明"],
            [
                [report_name, "主报告（漏洞分析与风险摘要）"],
                [mapping_name, "路由→鉴权机制映射表"],
                [readme_name, "本说明文件"],
            ],
        ),
        "",
        "说明：",
        markdown_table(
            ["条目", "内容"],
            [
                ["1", "主报告不重复完整路由清单"],
                ["2", "映射表不包含漏洞分析或 PoC"],
            ],
        ),
    ]
    with open(os.path.join(out_dir, readme_name), "w", encoding="utf-8") as f:
        f.write("\n".join(rd_lines) + "\n")

    write_module_html(out_dir, "auth_audit", "鉴权审计报告", findings)

    print(f"Wrote {len(findings)} findings to {out_dir}")


if __name__ == "__main__":
    main()
