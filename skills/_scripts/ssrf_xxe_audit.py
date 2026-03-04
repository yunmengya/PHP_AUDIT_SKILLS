#!/usr/bin/env python3
import argparse
import os
import re
from typing import List

from audit_helpers import (
    apply_rule_audit_quick_filter,
    build_output_root,
    extract_findings_from_traces,
    load_findings,
    load_traces,
    merge_findings,
    stable_id,
    write_module_report,
    write_findings,
)
from common import backfill_findings_source, detect_sinks, detect_sources_in_lines, detect_url_filters, detect_xml_filters, read_text, walk_php_files


def _window(lines: List[str], line_no: int, radius: int = 6):
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    return lines[start - 1 : end], start


def _is_network_like_sink(code: str) -> bool:
    if not code:
        return False
    if re.search(r"\b(curl_[A-Za-z0-9_]+|CURLOPT_URL|file_get_contents|fopen|fsockopen|stream_socket_client|get_headers)\b", code, re.I):
        return True
    if re.search(r"(https?://|ftp://|gopher://|dict://)", code, re.I):
        return True
    if re.search(r"\b(url|uri|host|domain|ip|socket|http)\b", code, re.I):
        return True
    return False


def _nearest_source(sources: List[dict], sink_line: int, radius: int = 30):
    candidates = [s for s in sources if abs((s.get("line") or 0) - sink_line) <= radius]
    if not candidates:
        return None
    candidates.sort(key=lambda s: abs((s.get("line") or 0) - sink_line))
    return candidates[0]


def fallback_scan_findings(project_root: str, sink_types: List[str]) -> List[dict]:
    if not sink_types:
        return []
    type_set = set(sink_types)
    findings: List[dict] = []
    seen = set()

    for path in walk_php_files(project_root):
        try:
            text = read_text(path)
        except Exception:
            continue
        lines = text.splitlines()
        sinks = detect_sinks(lines, 1, path)
        sources = detect_sources_in_lines(lines, path, 1)

        for sink in sinks:
            sink_type = sink.get("type")
            if sink_type not in type_set:
                continue
            if sink_type == "ssrf" and not _is_network_like_sink(sink.get("code") or ""):
                continue

            line_no = sink.get("line") or 0
            source = _nearest_source(sources, line_no)
            window, start_line = _window(lines, line_no)
            filters = detect_url_filters(window, start_line) if sink_type == "ssrf" else detect_xml_filters(window, start_line)

            controllability = "fully" if source and not filters else "conditional"
            confidence = "medium" if source else "low"
            if filters and confidence == "medium":
                confidence = "low"
            severity = "high" if controllability == "fully" else "medium"

            title = "可能存在 SSRF" if sink_type == "ssrf" else "可能存在 XXE"
            prefix = "SSRF" if sink_type == "ssrf" else "XXE"
            fid = stable_id(prefix, path, line_no, sink.get("code") or "")
            dedupe_key = (fid, sink_type, path, line_no)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            finding = {
                "id": fid,
                "title": title,
                "severity": severity,
                "independent_severity": severity,
                "combined_severity": severity,
                "confidence": confidence,
                "route": None,
                "source": source,
                "taint": [],
                "sink": sink,
                "validation": filters,
                "controllability": controllability,
                "poc": None,
                "notes": "trace 缺失兜底扫描（source->sink 轻量追踪）",
                "trace_fallback": True,
            }
            if sink_type == "ssrf" and filters:
                finding["url_filters"] = filters
            if sink_type == "xxe" and filters:
                finding["xml_filters"] = filters
            findings.append(finding)
    return findings


def enrich_findings(findings: List[dict]) -> List[dict]:
    for f in findings:
        sink = f.get("sink") or {}
        sink_type = sink.get("type")
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
        if sink_type == "ssrf":
            filters = detect_url_filters(window, start_line)
            if filters:
                f["url_filters"] = filters
                if f.get("controllability") == "fully":
                    f["controllability"] = "conditional"
                if f.get("confidence") == "high":
                    f["confidence"] = "medium"
        if sink_type == "xxe":
            filters = detect_xml_filters(window, start_line)
            if filters:
                f["xml_filters"] = filters
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
    ssrf_findings = extract_findings_from_traces(traces, ["ssrf"], "可能存在 SSRF", "SSRF")
    xxe_findings = extract_findings_from_traces(traces, ["xxe"], "可能存在 XXE", "XXE")
    new_findings = ssrf_findings + xxe_findings

    missing_types = []
    if not any((f.get("sink") or {}).get("type") == "ssrf" for f in new_findings):
        missing_types.append("ssrf")
    if not any((f.get("sink") or {}).get("type") == "xxe" for f in new_findings):
        missing_types.append("xxe")
    if missing_types:
        new_findings.extend(fallback_scan_findings(project_root, missing_types))

    new_findings = enrich_findings(new_findings)
    new_findings = backfill_findings_source(new_findings)
    new_findings = apply_rule_audit_quick_filter(new_findings, "ssrf_xxe_audit")

    out_dir = os.path.join(out_root, "ssrf_xxe_audit")
    existing = load_findings(os.path.join(out_dir, "findings.json"))
    merged = merge_findings(existing, new_findings)

    write_findings(out_dir, "SSRF/XXE 风险发现", merged)
    write_module_report(out_dir, "ssrf_xxe_audit", "SSRF/XXE 漏洞审计报告", merged)
    print(f"Wrote {len(merged)} findings to {out_dir}")


if __name__ == "__main__":
    main()
