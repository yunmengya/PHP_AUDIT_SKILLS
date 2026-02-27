#!/usr/bin/env python3
import argparse
import os
import re

from audit_helpers import apply_rule_audit_quick_filter, build_output_root, stable_id, write_findings, write_module_report
from common import read_text, walk_php_files


def scan_var_override(project_root: str):
    findings = []
    patterns = [
        re.compile(r"\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)[^)]*\)", re.I),
        re.compile(r"\bparse_str\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)[^)]*\)", re.I),
        re.compile(r"\$\$[A-Za-z_]", re.I),
        re.compile(r"\$\{\$[A-Za-z_][A-Za-z0-9_]*\}", re.I),
    ]

    for path in walk_php_files(project_root):
        text = read_text(path)
        for idx, line in enumerate(text.splitlines(), start=1):
            for rx in patterns:
                if rx.search(line):
                    fid = stable_id("VAR", path, idx, rx.pattern)
                    findings.append({
                        "id": fid,
                        "title": "Possible Variable Override",
                        "severity": "medium",
                        "independent_severity": "medium",
                        "combined_severity": "medium",
                        "confidence": "medium",
                        "route": None,
                        "source": None,
                        "taint": [{"file": path, "line": idx, "code": line.strip()}],
                        "sink": {"file": path, "line": idx, "function": "var_override", "code": line.strip()},
                        "validation": [],
                        "controllability": "conditional",
                        "poc": {"notes": "仅模板，不执行"},
                        "notes": f"Matched pattern: {rx.pattern}",
                    })
                    break
    return findings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    out_dir = os.path.join(out_root, "var_override_audit")

    findings = scan_var_override(project_root)
    findings = apply_rule_audit_quick_filter(findings, "var_override_audit")
    write_findings(out_dir, "Var Override Audit Findings", findings)
    write_module_report(out_dir, "var_override_audit", "变量覆盖审计报告", findings)
    print(f"Wrote {len(findings)} findings to {out_dir}")


if __name__ == "__main__":
    main()
