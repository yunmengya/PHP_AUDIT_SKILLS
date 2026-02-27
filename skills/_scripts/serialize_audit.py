#!/usr/bin/env python3
import argparse
import os
from typing import Dict, List

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
from common import (
    detect_deserialize_triggers,
    find_pop_candidates,
    read_text,
    walk_php_files,
)


def scan_triggers(project_root: str) -> List[Dict]:
    triggers: List[Dict] = []
    for path in walk_php_files(project_root):
        try:
            text = read_text(path)
        except Exception:
            continue
        triggers.extend(detect_deserialize_triggers(text.splitlines(), 1, path))
    return triggers


def enrich_findings(findings: List[Dict], triggers: List[Dict], pop_candidates: List[Dict]) -> List[Dict]:
    phar_triggers = [t for t in triggers if t.get("type") == "phar"]
    deserialize_triggers = [t for t in triggers if t.get("type") == "deserialize"]
    for f in findings:
        f["phar_trigger_count"] = len(phar_triggers)
        f["deserialize_trigger_count"] = len(deserialize_triggers)
        f["pop_candidates_count"] = len(pop_candidates)
        if phar_triggers:
            f["phar_triggers_sample"] = phar_triggers[:20]
        if pop_candidates:
            f["pop_candidates_sample"] = pop_candidates[:20]
    return findings


def findings_from_triggers(triggers: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    seq = 1
    for t in triggers[:50]:
        findings.append({
            "id": f"SER-TRIG-{seq:03d}",
            "title": "Deserialization Trigger",
            "severity": "medium",
            "independent_severity": "medium",
            "combined_severity": "medium",
            "confidence": "low",
            "route": None,
            "source": None,
            "taint": [],
            "sink": {
                "file": t.get("file"),
                "line": t.get("line"),
                "function": t.get("type"),
                "code": t.get("code"),
                "type": "deserialize",
            },
            "validation": [],
            "controllability": "conditional",
            "poc": None,
            "notes": "Trigger-only scan without route_tracer evidence.",
        })
        seq += 1
    return findings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)

    traces = load_traces(out_root)
    new_findings = extract_findings_from_traces(traces, ["deserialize"], "Possible Deserialization", "SER")

    triggers = scan_triggers(project_root)
    pop_candidates = find_pop_candidates(project_root)
    if new_findings:
        new_findings = enrich_findings(new_findings, triggers, pop_candidates)
    else:
        new_findings = findings_from_triggers(triggers)

    new_findings = apply_rule_audit_quick_filter(new_findings, "serialize_audit")

    out_dir = os.path.join(out_root, "serialize_audit")
    existing = load_findings(os.path.join(out_dir, "findings.json"))
    merged = merge_findings(existing, new_findings)

    write_findings(out_dir, "Serialize Audit Findings", merged)
    write_module_report(out_dir, "serialize_audit", "反序列化审计报告", merged)
    print(f"Wrote {len(merged)} findings to {out_dir}")


if __name__ == "__main__":
    main()
