#!/usr/bin/env python3
import argparse
import json
import os
import re

from audit_helpers import apply_rule_audit_quick_filter, build_output_root, stable_id, write_findings, write_module_report
from common import read_text


CSRF_KEYWORDS = [
    "csrf",
    "csrf_token",
    "_token",
    "verifycsrf",
    "verifycsrftoken",
    "x-csrf",
]

STATE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}




def middleware_has_csrf(middlewares):
    if not middlewares:
        return False
    lower = [m.lower() for m in middlewares]
    return any(k in m for m in lower for k in CSRF_KEYWORDS)

def load_routes(routes_json: str):
    with open(routes_json, "r", encoding="utf-8") as f:
        return json.load(f)


def method_has_csrf_guard(code: str) -> bool:
    lower = code.lower()
    return any(k in lower for k in CSRF_KEYWORDS)


def scan_csrf(project_root: str, out_root: str):
    routes_json = os.path.join(out_root, "route_mapper", "routes.json")
    if not os.path.exists(routes_json):
        return []

    routes = load_routes(routes_json)
    findings = []
    for r in routes:
        method = (r.get("method") or "").upper()
        if not any(m in method for m in STATE_METHODS):
            continue
        controller_file = r.get("controller_file")
        action = r.get("action")
        if not controller_file or not action:
            continue
        text = read_text(controller_file)
        # naive slice: just search for function block
        pattern = re.compile(rf"function\s+{re.escape(action)}\s*\([^)]*\)\s*\{{", re.I)
        m = pattern.search(text)
        if not m:
            continue
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
            continue
        body = text[start + 1 : end]
        if method_has_csrf_guard(body):
            continue
        if middleware_has_csrf(r.get("middlewares") or []):
            continue
        fid = stable_id("CSRF", controller_file, m.start(), r.get("path") or "")
        findings.append({
            "id": fid,
            "title": "Possible CSRF Missing Protection",
            "severity": "medium",
            "independent_severity": "medium",
            "combined_severity": "medium",
            "confidence": "low",
            "route": {
                "method": r.get("method"),
                "path": r.get("path"),
                "controller": r.get("controller"),
                "action": r.get("action"),
            },
            "source": None,
            "taint": [],
            "sink": {"file": controller_file, "line": 0, "function": action, "code": ""},
            "validation": [],
            "controllability": "conditional",
            "poc": {"method": method, "path": r.get("path"), "notes": "仅模板，不执行"},
            "notes": "No CSRF guard keywords found in handler.",
        })
    return findings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    out_dir = os.path.join(out_root, "csrf_audit")

    findings = scan_csrf(project_root, out_root)
    findings = apply_rule_audit_quick_filter(findings, "csrf_audit")
    write_findings(out_dir, "CSRF Audit Findings", findings)
    write_module_report(out_dir, "csrf_audit", "CSRF 漏洞审计报告", findings)
    print(f"Wrote {len(findings)} findings to {out_dir}")


if __name__ == "__main__":
    main()
