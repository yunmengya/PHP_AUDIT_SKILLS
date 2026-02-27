#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from typing import Dict, List


def load_rulesets(path: str) -> List[str]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    configs = data.get("configs", [])
    if not isinstance(configs, list):
        return []

    base_dir = os.path.dirname(os.path.abspath(path))
    resolved: List[str] = []
    for cfg in configs:
        if not isinstance(cfg, str):
            continue
        # Registry configs like r/all or p/trailofbits should stay as-is
        if cfg.startswith("r/") or cfg.startswith("p/"):
            resolved.append(cfg)
            continue
        # Allow absolute paths
        if os.path.isabs(cfg):
            resolved.append(cfg)
            continue
        # Resolve relative paths against ruleset directory
        resolved.append(os.path.join(base_dir, cfg))
    return resolved


def ensure_semgrep(bin_path: str) -> str:
    if bin_path:
        return bin_path

    # Prefer shared tools under skills/_tools if present
    skills_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    tools_bin = os.path.join(skills_root, "_tools", "semgrep")
    if os.path.exists(tools_bin):
        return tools_bin

    # Prefer local venv inside this skill if present
    skill_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    local_bin = os.path.join(skill_root, ".venv", "bin", "semgrep")
    if os.path.exists(local_bin):
        return local_bin

    found = shutil.which("semgrep")
    if not found:
        raise SystemExit("semgrep not found in PATH or local venv. Install official semgrep CLI first.")
    return found


def run_semgrep(
    semgrep_bin: str,
    project_root: str,
    out_root: str,
    configs: List[str],
    extra_args: List[str],
) -> Dict:
    raw_dir = os.path.join(out_root, "mcp_raw")
    parsed_dir = os.path.join(out_root, "mcp_parsed")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)

    raw_path = os.path.join(raw_dir, "semgrep-mcp.json")
    cmd = [semgrep_bin, "scan", "--json", "--json-output", raw_path]

    for cfg in configs:
        cmd.extend(["--config", cfg])

    if not configs:
        cmd.extend(["--config", "r/all"])

    # Exclude noisy directories by default
    cmd.extend(["--exclude", "vendor", "--exclude", "node_modules", "--exclude", "storage", "--exclude", "runtime", "--exclude", "cache"])

    cmd.extend(extra_args)
    cmd.append(project_root)

    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode not in (0, 1):
        # 1 can indicate findings; treat as ok
        err = proc.stderr.strip() or proc.stdout.strip()
        result = {"tool": "semgrep-mcp", "status": "error", "error": err}
        with open(os.path.join(parsed_dir, "semgrep-mcp.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return result

    if not os.path.exists(raw_path):
        # fallback to stdout if json-output wasn't written
        data = {"raw": proc.stdout}
    else:
        with open(raw_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                data = json.load(f)
            except Exception:
                data = {"raw": f.read()}

    results = data.get("results") if isinstance(data, dict) else data
    result = {"tool": "semgrep-mcp", "status": "ok", "results": results}

    with open(os.path.join(parsed_dir, "semgrep-mcp.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--ruleset", default=None, help="Path to rulesets.json")
    ap.add_argument("--config", action="append", default=[], help="Extra semgrep --config (can be repeated)")
    ap.add_argument("--semgrep-bin", default=None, help="Path to semgrep binary")
    ap.add_argument("--extra-arg", action="append", default=[], help="Extra semgrep CLI arg (repeatable)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    if not os.path.isdir(project_root):
        raise SystemExit("Project root not found.")

    base = os.path.basename(project_root.rstrip("/"))
    out_root = os.path.abspath(args.out) if args.out else os.path.join(os.path.dirname(project_root), f"{base}_audit")

    semgrep_bin = ensure_semgrep(args.semgrep_bin)

    configs = []
    if args.ruleset:
        configs.extend(load_rulesets(args.ruleset))
    configs.extend(args.config or [])

    run_semgrep(semgrep_bin, project_root, out_root, configs, args.extra_arg or [])


if __name__ == "__main__":
    main()
