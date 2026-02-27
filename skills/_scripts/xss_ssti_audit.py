#!/usr/bin/env python3
import argparse
import os

from audit_helpers import (
    apply_rule_audit_quick_filter,
    build_output_root,
    extract_findings_from_traces,
    load_findings,
    load_traces,
    merge_findings,
    write_module_report,
    write_findings,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)

    traces = load_traces(out_root)
    new_findings = extract_findings_from_traces(traces, ["xss", "ssti"], "Possible XSS/SSTI", "XSS")
    new_findings = apply_rule_audit_quick_filter(new_findings, "xss_ssti_audit")

    out_dir = os.path.join(out_root, "xss_ssti_audit")
    existing = load_findings(os.path.join(out_dir, "findings.json"))
    merged = merge_findings(existing, new_findings)

    write_findings(out_dir, "XSS/SSTI Audit Findings", merged)
    write_module_report(out_dir, "xss_ssti_audit", "XSS/SSTI 漏洞审计报告", merged)
    print(f"Wrote {len(merged)} findings to {out_dir}")


if __name__ == "__main__":
    main()
