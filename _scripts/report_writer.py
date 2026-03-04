#!/usr/bin/env python3
import argparse
import json
import os
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(__file__))

from common import build_output_root, write_json, write_text


def load_findings(out_root: str) -> List[Dict]:
    findings = []
    for root, _, files in os.walk(out_root):
        for f in files:
            if f == "findings.json" or f == "auth_evidence.json":
                path = os.path.join(root, f)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                        if isinstance(data, list):
                            findings.extend(data)
                        elif isinstance(data, dict) and "results" in data:
                            findings.extend(data.get("results") or [])
                except Exception:
                    continue
    return findings


def summarize(findings: List[Dict]) -> Dict:
    summary = {"total": len(findings), "severity": {"high": 0, "medium": 0, "low": 0, "info": 0}}
    for f in findings:
        sev = f.get("severity", "info")
        if sev not in summary["severity"]:
            sev = "info"
        summary["severity"][sev] += 1
    return summary


def render_md(summary: Dict, findings: List[Dict]) -> str:
    lines = ["# Audit Summary", "", f"Total Findings: {summary['total']}", ""]
    lines.append("## Severity Breakdown")
    for k, v in summary["severity"].items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("## Findings List")
    for f in findings:
        title = f.get("title", "Finding")
        fid = f.get("id", "")
        sev = f.get("severity", "info")
        route = f.get("route") or {}
        path = route.get("path") if isinstance(route, dict) else None
        lines.append(f"- {fid} {title} ({sev}) {path or ''}")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    findings = load_findings(out_root)
    summary = summarize(findings)

    write_json(os.path.join(out_root, "report_summary.json"), summary)
    write_text(os.path.join(out_root, "report_summary.md"), render_md(summary, findings))
    print(f"Wrote summary for {len(findings)} findings to {out_root}")


if __name__ == "__main__":
    main()
