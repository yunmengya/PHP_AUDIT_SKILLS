#!/usr/bin/env python3
import argparse
import json
import os
from typing import Dict, List


def build_output_root(project_root: str, out_dir: str) -> str:
    if out_dir:
        return out_dir
    base = os.path.basename(project_root.rstrip("/"))
    return os.path.join(os.path.dirname(project_root), f"{base}_audit")


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

    raw_dir = os.path.join(out_root, "mcp_raw")
    parsed_dir = os.path.join(out_root, "mcp_parsed")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)

    with open(os.path.join(raw_dir, "report-writer-mcp.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    with open(os.path.join(parsed_dir, "report-writer-mcp.json"), "w", encoding="utf-8") as f:
        json.dump({"tool": "report-writer-mcp", "status": "ok", "results": summary}, f, ensure_ascii=False, indent=2)

    with open(os.path.join(out_root, "report_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_root, "report_summary.md"), "w", encoding="utf-8") as f:
        f.write(render_md(summary, findings))

    print(f"Wrote summary for {len(findings)} findings to {out_root}")


if __name__ == "__main__":
    main()
