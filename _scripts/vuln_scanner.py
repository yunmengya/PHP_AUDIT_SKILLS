#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys


SCRIPT_DIR = os.path.dirname(__file__)


def resolve_python() -> str:
    env_py = os.environ.get("SKILLS_PYTHON")
    if env_py and os.path.exists(env_py):
        return env_py
    venv_py = os.path.join(os.path.dirname(SCRIPT_DIR), ".venv", "bin", "python3")
    if os.path.exists(venv_py):
        return venv_py
    return sys.executable or "python3"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    script = os.path.abspath(
        os.path.join(SCRIPT_DIR, "..", "composer-audit-mcp", "scripts", "composer_audit_mcp.py")
    )
    cmd = [resolve_python(), script, "--project", project_root]
    if args.out:
        cmd.extend(["--out", args.out])
    subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
