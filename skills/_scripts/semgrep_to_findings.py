#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from typing import Dict, List

from common import build_output_root, write_json, write_text


def load_semgrep_results(path: str) -> List[Dict]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    if isinstance(data, dict) and "results" in data:
        return data.get("results") or []
    if isinstance(data, list):
        return data
    return []


def classify_finding(check_id: str) -> str:
    check_id = check_id.lower()
    if "sqli" in check_id or "sql" in check_id:
        return "sql"
    if "rce" in check_id or "command" in check_id or "exec" in check_id:
        return "rce"
    if "ssrf" in check_id:
        return "ssrf"
    if "xss" in check_id:
        return "xss"
    if "deserialize" in check_id or "unserialize" in check_id:
        return "serialize"
    if "file" in check_id or "include" in check_id or "path" in check_id:
        return "file"
    return "other"


def stable_id(check_id: str, path: str, line: int, index: int) -> str:
    base = f"{check_id}|{path or ''}|{line or 0}|{index}"
    digest = hashlib.md5(base.encode("utf-8")).hexdigest()[:8]
    return f"SG-{digest}"


def severity_from_semgrep(result: Dict) -> str:
    sev = (result.get("extra") or {}).get("severity") or result.get("severity") or "INFO"
    sev = str(sev).lower()
    if sev in ("critical", "high"):
        return "high"
    if sev in ("medium", "warning"):
        return "medium"
    if sev in ("low", "info"):
        return "low"
    return "info"


def build_trace(result: Dict) -> List[Dict]:
    trace = []
    path = result.get("path")
    start = result.get("start") or {}
    end = result.get("end") or {}
    line = start.get("line") or result.get("line") or 0
    code = result.get("extra", {}).get("lines") or result.get("code") or ""
    trace.append({"file": path, "line": line, "code": code})

    dataflow = (result.get("extra") or {}).get("dataflow") or {}
    trace_steps = dataflow.get("trace") or dataflow.get("taint_trace")
    if isinstance(trace_steps, list):
        for step in trace_steps:
            loc = step.get("location") or {}
            sline = (loc.get("start") or {}).get("line") or loc.get("line")
            fpath = loc.get("path") or path
            svalue = step.get("value") or step.get("content") or ""
            trace.append({"file": fpath, "line": sline or 0, "code": svalue})
    return trace


def build_poc(result: Dict) -> Dict:
    path = result.get("path") or "/"
    return {"method": "GET", "path": f"/{os.path.basename(path)}", "params": {"id": "1' OR 1=1 -- "}, "notes": "仅模板，不执行"}


def to_findings(results: List[Dict]) -> List[Dict]:
    findings = []
    for idx, r in enumerate(results, start=1):
        check_id = r.get("check_id") or r.get("rule_id") or f"semgrep-{idx}"
        category = classify_finding(check_id)
        severity = severity_from_semgrep(r)
        extra = r.get("extra") or {}
        message = extra.get("message") or r.get("message") or check_id
        trace = build_trace(r)
        path = r.get("path")
        line = (r.get("start") or {}).get("line") or r.get("line") or 0

        finding = {
            "id": stable_id(check_id, path, line, idx),
            "title": message,
            "severity": severity,
            "independent_severity": severity,
            "combined_severity": severity,
            "confidence": "medium",
            "route": None,
            "source": None,
            "taint": trace,
            "sink": {
                "file": path,
                "line": line,
                "function": check_id,
                "code": extra.get("lines") or "",
            },
            "validation": [],
            "controllability": "conditional",
            "poc": build_poc(r),
            "notes": f"Semgrep result mapped to findings ({category}).",
            "category": category,
            "origin": "semgrep",
        }
        findings.append(finding)
    return findings


def merge_findings(existing: List[Dict], incoming: List[Dict]) -> List[Dict]:
    merged: Dict[str, Dict] = {}
    for f in existing:
        fid = f.get("id")
        if fid:
            merged[fid] = f
    for f in incoming:
        fid = f.get("id")
        if fid:
            merged[fid] = f
        else:
            merged[f"tmp-{len(merged)+1}"] = f
    return list(merged.values())


def write_findings(findings: List[Dict], out_root: str) -> None:
    out_dir = os.path.join(out_root, "semgrep_audit")
    os.makedirs(out_dir, exist_ok=True)
    write_json(os.path.join(out_dir, "findings.json"), findings)
    lines = ["# Semgrep Findings", "", f"Total: {len(findings)}", ""]
    for f in findings:
        lines.append(f"## {f['id']} {f['title']}")
        lines.append(f"- Severity: {f['severity']}")
        lines.append(f"- Category: {f.get('category')}")
        sink = f.get("sink") or {}
        lines.append(f"- Sink: {sink.get('file')}:{sink.get('line')}")
        lines.append("")
    write_text(os.path.join(out_dir, "findings.md"), "\n".join(lines) + "\n")


def write_split_findings(findings: List[Dict], out_root: str) -> None:
    category_dirs = {
        "sql": "sql_audit",
        "rce": "rce_audit",
        "file": "file_audit",
        "ssrf": "ssrf_xxe_audit",
        "xss": "xss_ssti_audit",
        "serialize": "serialize_audit",
        "other": "semgrep_audit",
    }

    grouped: Dict[str, List[Dict]] = {}
    for f in findings:
        cat = f.get("category") or "other"
        grouped.setdefault(cat, []).append(f)

    for cat, items in grouped.items():
        target = category_dirs.get(cat, "semgrep_audit")
        out_dir = os.path.join(out_root, target)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "findings.json")

        existing = []
        if os.path.exists(out_path):
            try:
                with open(out_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        existing = data
            except Exception:
                existing = []

        merged = merge_findings(existing, items)
        write_json(out_path, merged)

        md_lines = [f"# {target} Findings", "", f"Total: {len(merged)}", ""]
        for f in merged:
            md_lines.append(f"## {f.get('id')} {f.get('title')}")
            md_lines.append(f"- Severity: {f.get('severity')}")
            md_lines.append(f"- Category: {f.get('category')}")
            sink = f.get("sink") or {}
            md_lines.append(f"- Sink: {sink.get('file')}:{sink.get('line')}")
            md_lines.append("")
        write_text(os.path.join(out_dir, "findings.md"), "\n".join(md_lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--semgrep-json", default=None, help="Path to semgrep-mcp.json")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    semgrep_json = args.semgrep_json or os.path.join(out_root, "mcp_parsed", "semgrep-mcp.json")
    results = load_semgrep_results(semgrep_json)

    findings = to_findings(results)
    write_findings(findings, out_root)
    write_split_findings(findings, out_root)
    print(f"Wrote {len(findings)} findings to {out_root}")


if __name__ == "__main__":
    main()
