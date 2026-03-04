#!/usr/bin/env python3
import argparse
import json
import os
from typing import Dict, List

from common import build_output_root, write_json


def load_findings_files(out_root: str) -> List[str]:
    paths = []
    for root, _, files in os.walk(out_root):
        for f in files:
            if f == "findings.json" or f == "auth_evidence.json":
                paths.append(os.path.join(root, f))
    return paths


def bump(sev: str) -> str:
    sev = (sev or "info").lower()
    if sev in ("info", "low", "l"):
        return "medium"
    if sev in ("medium", "m"):
        return "high"
    return "high"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    out_root = build_output_root(os.path.abspath(args.project), args.out)
    paths = load_findings_files(out_root)

    auth_weak = False
    for p in paths:
        if os.path.basename(os.path.dirname(p)) == "auth_audit":
            try:
                data = json.load(open(p, "r", encoding="utf-8"))
                if isinstance(data, list) and data:
                    auth_weak = True
                    break
            except Exception:
                continue

    for p in paths:
        module = os.path.basename(os.path.dirname(p))
        try:
            data = json.load(open(p, "r", encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, list):
            continue

        changed = False
        for f in data:
            base = f.get("independent_severity") or f.get("severity") or "info"
            f["independent_severity"] = base
            combined = f.get("combined_severity") or base
            if auth_weak and module not in ("auth_audit", "csrf_audit"):
                combined = bump(combined)
            f["combined_severity"] = combined
            changed = True

        if changed:
            write_json(p, data)

    print("Severity enrichment complete")


if __name__ == "__main__":
    main()
