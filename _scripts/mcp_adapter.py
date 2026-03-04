#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(__file__))

from common import build_output_root, write_json, write_text

DEFAULT_TOOLS = [
    "semgrep-mcp",
    "ripgrep-mcp",
    "composer-audit-mcp",
    "report-writer-mcp",
    "ai-confirm-mcp",
]

SCRIPT_DIR = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))


def resolve_python() -> str:
    env_py = os.environ.get("SKILLS_PYTHON")
    if env_py and os.path.exists(env_py):
        return env_py
    venv_py = os.path.join(os.path.dirname(SCRIPT_DIR), ".venv", "bin", "python3")
    if os.path.exists(venv_py):
        return venv_py
    found = shutil.which("python3")
    if found:
        return found
    return sys.executable or "python3"


def load_config(path: Optional[str]) -> Dict:
    if not path:
        return {}
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {"_config_error": str(exc)}


def format_command(template: str, project: str, out_root: str) -> str:
    return template.format(
        project=project,
        out=out_root,
        repo_root=REPO_ROOT,
        script_dir=SCRIPT_DIR,
        skills_root=os.path.join(REPO_ROOT, "skills"),
        python=resolve_python(),
    )


def run_command(cmd: str, cwd: str, timeout_sec: int = 0) -> subprocess.CompletedProcess:
    kwargs: Dict[str, Any] = {
        "cwd": cwd,
        "shell": True,
        "capture_output": True,
        "text": True,
    }
    if timeout_sec > 0:
        kwargs["timeout"] = timeout_sec
    return subprocess.run(cmd, **kwargs)


def parse_output(raw: str, fmt: str):
    if fmt == "json":
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw}
    return {"raw": raw}


def normalize_result(tool: str, data) -> Dict:
    # Best-effort normalization: accept list or dict
    if isinstance(data, list):
        return {"tool": tool, "status": "ok", "results": data, "confidence": "high"}
    if isinstance(data, dict):
        # common keys: results/findings
        if "results" in data:
            return {"tool": tool, "status": "ok", "results": data.get("results"), "confidence": "high"}
        if "findings" in data:
            return {"tool": tool, "status": "ok", "results": data.get("findings"), "confidence": "high"}
    return {"tool": tool, "status": "ok", "results": data, "confidence": "high"}


def degrade_result(tool: str, status: str, error: str) -> Dict:
    return {
        "tool": tool,
        "status": status,
        "results": [],
        "error": error,
        "confidence": "low",
        "degraded": True,
    }


def _coerce_int(raw: Any, default: int) -> int:
    try:
        val = int(raw)
    except Exception:
        return default
    return val if val >= 0 else default


def _coerce_float(raw: Any, default: float) -> float:
    try:
        val = float(raw)
    except Exception:
        return default
    return val if val >= 0 else default


def _resolve_tool_runtime(tool_cfg: Dict[str, Any]) -> Dict[str, Any]:
    retries = _coerce_int(
        tool_cfg.get("retries", os.environ.get("MCP_ADAPTER_RETRIES", "2")),
        2,
    )
    retry_delay_sec = _coerce_float(
        tool_cfg.get("retry_delay_sec", os.environ.get("MCP_ADAPTER_RETRY_DELAY_SEC", "1.5")),
        1.5,
    )
    timeout_sec = _coerce_int(
        tool_cfg.get("timeout_sec", os.environ.get("MCP_ADAPTER_TIMEOUT_SEC", "180")),
        180,
    )
    return {
        "retries": retries,
        "retry_delay_sec": retry_delay_sec,
        "timeout_sec": timeout_sec,
    }


def _format_output_path(output_path: str, project: str, out_root: str) -> str:
    try:
        return output_path.format(project=project, out=out_root)
    except Exception:
        return output_path


def run_tool(tool: str, project: str, out_root: str, config: Dict) -> Dict:
    tool_cfg = config.get("tools", {}).get(tool, {})
    raw_dir = os.path.join(out_root, "mcp_raw")
    parsed_dir = os.path.join(out_root, "mcp_parsed")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)

    # If no command configured, fall back to reading existing output_path if provided
    cmd = tool_cfg.get("command")
    output_format = tool_cfg.get("output_format", "json")
    output_path = tool_cfg.get("output_path")
    runtime = _resolve_tool_runtime(tool_cfg)

    if cmd:
        formatted = format_command(cmd, project, out_root)
        attempts = []
        proc = None
        raw = ""
        for attempt in range(1, int(runtime["retries"]) + 2):
            attempt_row: Dict[str, Any] = {"attempt": attempt}
            try:
                proc = run_command(formatted, project, timeout_sec=int(runtime["timeout_sec"]))
                raw = proc.stdout or proc.stderr or ""
                attempt_row["return_code"] = int(proc.returncode)
                attempt_row["output"] = (raw or "").strip()[:2000]
            except subprocess.TimeoutExpired as exc:
                proc = None
                raw = (exc.stdout or exc.stderr or f"timeout after {runtime['timeout_sec']}s") if isinstance(exc, subprocess.TimeoutExpired) else ""
                attempt_row["return_code"] = 124
                attempt_row["output"] = str(raw).strip()[:2000]
            except Exception as exc:
                proc = None
                raw = str(exc)
                attempt_row["return_code"] = 125
                attempt_row["output"] = str(exc)[:2000]
            attempts.append(attempt_row)
            if proc is not None and proc.returncode == 0:
                break
            if attempt <= int(runtime["retries"]):
                time.sleep(float(runtime["retry_delay_sec"]))

        raw_file = os.path.join(raw_dir, f"{tool}.out")
        write_text(raw_file, "\n\n".join([f"[attempt {a.get('attempt')}] rc={a.get('return_code')}\n{a.get('output') or ''}" for a in attempts]))

        if proc is None or proc.returncode != 0:
            detail = raw.strip() or "tool command failed"
            result = degrade_result(tool, "error", detail)
            result["attempts"] = attempts
            result["retry_exhausted"] = True
            write_json(os.path.join(parsed_dir, f"{tool}.json"), result)
            return result

        # If command already wrote output file, use it. Otherwise parse stdout.
        resolved_output_path = _format_output_path(str(output_path or ""), project, out_root) if output_path else ""
        if resolved_output_path and os.path.exists(resolved_output_path):
            try:
                with open(resolved_output_path, "r", encoding="utf-8") as f:
                    data = f.read()
            except Exception:
                data = raw
            data_parsed = parse_output(data, output_format)
        else:
            data_parsed = parse_output(raw, output_format)

        result = normalize_result(tool, data_parsed)
        result["attempts"] = attempts
        result["retry_exhausted"] = False
        write_json(os.path.join(parsed_dir, f"{tool}.json"), result)
        return result

    # No command: try to read output_path if exists, else mark missing
    if output_path:
        resolved = _format_output_path(str(output_path), project, out_root)
        if os.path.exists(resolved):
            with open(resolved, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            data_parsed = parse_output(data, output_format)
            result = normalize_result(tool, data_parsed)
            write_json(os.path.join(parsed_dir, f"{tool}.json"), result)
            return result

    result = degrade_result(tool, "missing", "No command configured and no output file found.")
    write_json(os.path.join(parsed_dir, f"{tool}.json"), result)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--config", default=None, help="Path to mcp_config.json")
    ap.add_argument("--tool", default=None, help="Run a single tool")
    ap.add_argument("--all", action="store_true", help="Run all tools")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    config = load_config(args.config)
    config_error = str(config.get("_config_error") or "").strip() if isinstance(config, dict) else ""
    tools = []
    if args.all:
        tools = DEFAULT_TOOLS
    elif args.tool:
        tools = [args.tool]
    else:
        raise SystemExit("Specify --tool or --all")

    results = []
    for tool in tools:
        try:
            results.append(run_tool(tool, project_root, out_root, config))
        except Exception as exc:
            degraded = degrade_result(tool, "error", f"unexpected_error: {exc}")
            degraded["retry_exhausted"] = False
            write_json(os.path.join(out_root, "mcp_parsed", f"{tool}.json"), degraded)
            results.append(degraded)

    summary = {
        "tools": results,
        "degraded_tools": [r.get("tool") for r in results if r.get("degraded")],
        "config_error": config_error,
    }
    write_json(os.path.join(out_root, "mcp_parsed", "summary.json"), summary)
    print(f"MCP run complete. {len(results)} tools processed.")


if __name__ == "__main__":
    main()
