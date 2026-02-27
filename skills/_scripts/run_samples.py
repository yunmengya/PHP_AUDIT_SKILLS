#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from typing import List
import re

SCRIPT_DIR = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SAMPLES_DIR = os.path.join(ROOT, "_samples")

TESTS = [
    {
        "name": "safe_app",
        "modules": [
            "route_mapper",
            "route_tracer",
            "sql_audit",
            "rce_audit",
            "file_audit",
            "ssrf_xxe_audit",
            "xss_ssti_audit",
            "serialize_audit",
            "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index",
            "final_report",
            "evidence_check",
        ],
        "expect": {
            "sql_audit": "==0",
            "rce_audit": "==0",
            "file_audit": "==0",
            "ssrf_xxe_audit": "==0",
            "xss_ssti_audit": "==0",
            "serialize_audit": "==0",
        },
    },
    {
        "name": "vuln_app",
        "modules": [
            "route_mapper",
            "route_tracer",
            "sql_audit",
            "rce_audit",
            "file_audit",
            "ssrf_xxe_audit",
            "xss_ssti_audit",
            "serialize_audit",
            "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index",
            "final_report",
            "evidence_check",
        ],
        "expect": {
            "sql_audit": ">0",
            "rce_audit": ">0",
            "file_audit": ">0",
            "ssrf_xxe_audit": ">0",
            "xss_ssti_audit": ">0",
            "serialize_audit": ">0",
        },
    },
    {
        "name": "sql_app",
        "modules": ["route_mapper", "route_tracer", "sql_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"sql_audit": "==3"},
    },
    {
        "name": "rce_app",
        "modules": ["route_mapper", "route_tracer", "rce_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"rce_audit": "==3"},
    },
    {
        "name": "file_app",
        "modules": ["route_mapper", "route_tracer", "file_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"file_audit": "==3"},
    },
    {
        "name": "ssrf_xxe_app",
        "modules": ["route_mapper", "route_tracer", "ssrf_xxe_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"ssrf_xxe_audit": "==3"},
    },
    {
        "name": "xss_ssti_app",
        "modules": ["route_mapper", "route_tracer", "xss_ssti_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"xss_ssti_audit": "==3"},
    },
    {
        "name": "serialize_app",
        "modules": ["route_mapper", "route_tracer", "serialize_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"serialize_audit": "==3"},
    },
    {
        "name": "var_override_app",
        "modules": ["var_override_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"var_override_audit": "==4"},
    },
    {
        "name": "csrf_app",
        "modules": ["route_mapper", "csrf_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"csrf_audit": "==3"},
    },
    {
        "name": "auth_app",
        "modules": ["route_mapper", "auth_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"auth_audit": "==2"},
    },

    {
        "name": "chain_app",
        "modules": ["route_mapper", "route_tracer", "sql_audit", "auth_audit", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {"sql_audit": ">0", "auth_audit": ">0"},
    },
    {
        "name": "phase_meta_sample",
        "modules": ["route_mapper", "severity_enrich", "debug_verify", "report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "expect": {},
    },
]


def run_cli(project_root: str, modules: List[str]) -> str:
    repo_root = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
    docker_audit = os.path.join(repo_root, "skills", "docker", "run_audit.sh")
    cmd = [
        docker_audit,
        project_root,
        "--skip-mcp",
        "--no-cache",
        "--modules",
        ",".join(modules),
        "--evidence-strict",
    ]
    print(f"[RUN] {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    if proc.returncode != 0:
        raise SystemExit(f"skills/docker run_audit failed for {project_root}")
    combined = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    matches = re.findall(r"Audit complete\.\s*Output:\s*(.+)", combined)
    if not matches:
        raise SystemExit(f"{project_root}: unable to parse output path from run_audit.sh")
    return matches[-1].strip()


def count_findings(out_root: str, module: str) -> int:
    if module == "auth_audit":
        path = os.path.join(out_root, module, "auth_evidence.json")
    else:
        path = os.path.join(out_root, module, "findings.json")
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict) and "results" in data:
            return len(data.get("results") or [])
    except Exception:
        return 0
    return 0


def has_sql_report(out_root: str) -> bool:
    sql_dir = os.path.join(out_root, "sql_audit")
    if not os.path.isdir(sql_dir):
        return False
    for f in os.listdir(sql_dir):
        if f.endswith(".md") and "_sql_audit_" in f:
            return True
    return False


def has_auth_reports(out_root: str) -> bool:
    auth_dir = os.path.join(out_root, "auth_audit")
    if not os.path.isdir(auth_dir):
        return False
    files = os.listdir(auth_dir)
    return (
        any(f.endswith(".md") and "_auth_audit_" in f for f in files)
        and any(f.endswith(".md") and "_auth_mapping_" in f for f in files)
        and any(f.endswith(".md") and "_auth_README_" in f for f in files)
    )


def has_vuln_trigger(out_root: str) -> bool:
    md = os.path.join(out_root, "vuln_report", "composer_audit.md")
    if not os.path.exists(md):
        return False
    try:
        text = open(md, "r", encoding="utf-8").read()
        return "触发点分析" in text
    except Exception:
        return False


def has_phase_meta(out_root: str) -> bool:
    meta_dir = os.path.join(out_root, "_meta")
    required = [
        "phase1_map.md",
        "phase2_risk_map.md",
        "phase3_trace_log.md",
        "phase4_attack_chain.md",
        "phase5_report_index.md",
    ]
    if not os.path.isdir(meta_dir):
        return False
    return all(os.path.exists(os.path.join(meta_dir, name)) for name in required)


def check_expectations(project_root: str, out_root: str, expect: dict, modules: List[str]) -> None:
    for module, rule in expect.items():
        count = count_findings(out_root, module)
        m = re.match(r"(==|>=|<=|>|<)\s*(\d+)", rule)
        if not m:
            raise SystemExit(f"{project_root}: invalid rule '{rule}' for {module}")
        op, num = m.group(1), int(m.group(2))
        if op == "==":
            ok = count == num
        elif op == ">":
            ok = count > num
        elif op == "<":
            ok = count < num
        elif op == ">=":
            ok = count >= num
        else:
            ok = count <= num
        if not ok:
            raise SystemExit(f"{project_root}: expected {module} {rule}, got {count}")
    final_report = os.path.join(out_root, "final_report.json")
    if not os.path.exists(final_report):
        raise SystemExit(f"{project_root}: final_report.json missing")
    evidence = os.path.join(out_root, "evidence_check.json")
    if not os.path.exists(evidence):
        raise SystemExit(f"{project_root}: evidence_check.json missing")

    # extra checks when modules executed
    if "sql_audit" in modules and not has_sql_report(out_root):
        raise SystemExit(f"{project_root}: sql_audit report missing")
    if "auth_audit" in modules and not has_auth_reports(out_root):
        raise SystemExit(f"{project_root}: auth_audit 3-file reports missing")
    if "vuln_scanner" in modules and not has_vuln_trigger(out_root):
        raise SystemExit(f"{project_root}: vuln trigger analysis missing")
    if "final_report" in modules and not has_phase_meta(out_root):
        raise SystemExit(f"{project_root}: phase meta outputs missing")


def main() -> None:
    for t in TESTS:
        name = t["name"]
        project_root = os.path.join(SAMPLES_DIR, name)
        if not os.path.isdir(project_root):
            raise SystemExit(f"Sample missing: {project_root}")
        out_root = run_cli(project_root, t["modules"])
        check_expectations(project_root, out_root, t["expect"], t["modules"])
        print(f"[OK] {name}")
    print("All samples passed.")


if __name__ == "__main__":
    main()
