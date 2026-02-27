#!/usr/bin/env python3
import argparse
import os
from typing import List

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
from common import detect_path_filters, read_text


def _window(lines: List[str], line_no: int, radius: int = 6):
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    return lines[start - 1 : end], start


def enrich_findings(findings: List[dict]) -> List[dict]:
    for f in findings:
        sink = f.get("sink") or {}
        path = sink.get("file")
        line = sink.get("line") or 0
        if not path or not os.path.exists(path):
            continue
        try:
            text = read_text(path)
        except Exception:
            continue
        lines = text.splitlines()
        window, start_line = _window(lines, line)
        filters = detect_path_filters(window, start_line)
        if filters:
            f["path_filters"] = filters
            if f.get("controllability") == "fully":
                f["controllability"] = "conditional"
            if f.get("confidence") == "high":
                f["confidence"] = "medium"
    return findings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)

    traces = load_traces(out_root)
    new_findings = extract_findings_from_traces(traces, ["file", "include"], "Possible File Operation Risk", "FILE")
    new_findings = enrich_findings(new_findings)
    new_findings = apply_rule_audit_quick_filter(new_findings, "file_audit")

    out_dir = os.path.join(out_root, "file_audit")
    existing = load_findings(os.path.join(out_dir, "findings.json"))
    merged = merge_findings(existing, new_findings)

    write_findings(out_dir, "File Audit Findings", merged)
    write_module_report(out_dir, "file_audit", "文件类漏洞审计报告", merged)
    print(f"Wrote {len(merged)} findings to {out_dir}")


if __name__ == "__main__":
    main()
