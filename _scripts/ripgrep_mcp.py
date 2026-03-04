#!/usr/bin/env python3
import argparse
import json
import os
import re
from typing import Dict, List, Optional

from common import build_output_root, read_text, walk_php_files, write_json, write_text


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


def get_context(file_path: str, line_no: int, context: int) -> Dict:
    text = read_text(file_path)
    lines = text.splitlines()
    idx = max(line_no - 1, 0)
    start = max(idx - context, 0)
    end = min(idx + context + 1, len(lines))
    before = lines[start:idx]
    line = lines[idx] if 0 <= idx < len(lines) else ""
    after = lines[idx + 1 : end]
    return {"before": before, "line": line, "after": after}


def from_semgrep(results: List[Dict], project_root: str, context: int) -> List[Dict]:
    contexts = []
    for r in results:
        path = r.get("path")
        if not path:
            continue
        if not os.path.isabs(path):
            path = os.path.join(project_root, path)
        line = (r.get("start") or {}).get("line") or r.get("line")
        if not line:
            continue
        ctx = get_context(path, int(line), context)
        contexts.append({
            "file": path,
            "line": int(line),
            "match": ctx["line"].strip(),
            "before": ctx["before"],
            "after": ctx["after"],
            "rule_id": r.get("check_id") or r.get("rule_id") or "",
        })
    return contexts


def from_patterns(project_root: str, patterns: List[str], context: int) -> List[Dict]:
    regexes = [re.compile(p, re.I) for p in patterns]
    contexts = []
    for path in walk_php_files(project_root):
        text = read_text(path)
        for idx, line in enumerate(text.splitlines(), start=1):
            for rx in regexes:
                if rx.search(line):
                    ctx = get_context(path, idx, context)
                    contexts.append({
                        "file": path,
                        "line": idx,
                        "match": ctx["line"].strip(),
                        "before": ctx["before"],
                        "after": ctx["after"],
                        "pattern": rx.pattern,
                    })
                    break
    return contexts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--context", type=int, default=3, help="Context lines")
    ap.add_argument("--pattern", action="append", default=[], help="Regex pattern (repeatable)")
    ap.add_argument("--semgrep-json", default=None, help="Semgrep JSON path")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    raw_dir = os.path.join(out_root, "mcp_raw")
    parsed_dir = os.path.join(out_root, "mcp_parsed")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)

    semgrep_json = args.semgrep_json
    if not semgrep_json:
        semgrep_json = os.path.join(out_root, "mcp_raw", "semgrep-mcp.json")
        if not os.path.exists(semgrep_json):
            semgrep_json = None

    contexts: List[Dict]
    if semgrep_json:
        results = load_semgrep_results(semgrep_json)
        contexts = from_semgrep(results, project_root, args.context)
    else:
        if not args.pattern:
            raise SystemExit("No semgrep json found and no --pattern provided.")
        contexts = from_patterns(project_root, args.pattern, args.context)

    raw_txt = os.path.join(raw_dir, "ripgrep-mcp.txt")
    with open(raw_txt, "w", encoding="utf-8") as f:
        for c in contexts:
            f.write(f"{c.get('file')}:{c.get('line')}:{c.get('match')}\n")

    raw_json = os.path.join(raw_dir, "ripgrep-mcp.json")
    write_json(raw_json, {"results": contexts})

    parsed_json = os.path.join(parsed_dir, "ripgrep-mcp.json")
    write_json(parsed_json, {"tool": "ripgrep-mcp", "status": "ok", "results": contexts})

    print(f"Wrote {len(contexts)} contexts to {out_root}")


if __name__ == "__main__":
    main()
