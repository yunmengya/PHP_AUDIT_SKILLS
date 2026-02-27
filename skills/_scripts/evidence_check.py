#!/usr/bin/env python3
import argparse
import json
import os
import re
from typing import Dict, List, Tuple

from common import build_output_root, write_json, write_text

POLICY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "_config", "ai_audit_policy.json"))

REQUIRED_FIELDS = [
    "id",
    "title",
    "severity",
    "confidence",
    "sink",
    "validation",
    "controllability",
    "poc",
    "exploitability",
]

AI_TABLE_FIELDS = [
    "title_label",
    "severity_label",
    "reachability",
    "impact",
    "complexity",
    "exploitability",
    "location",
    "trigger",
    "input_source",
    "output_mode",
    "evidence",
]


def load_policy() -> Dict:
    if not os.path.exists(POLICY_PATH):
        return {}
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def load_findings(out_root: str) -> List[Tuple[Dict, str]]:
    items: List[Tuple[Dict, str]] = []
    for root, _, files in os.walk(out_root):
        for f in files:
            if f == "findings.json" or f == "auth_evidence.json":
                path = os.path.join(root, f)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if isinstance(data, list):
                        for it in data:
                            items.append((it, path))
                except Exception:
                    continue
    return items


def is_policy_finding(f: Dict, source_path: str) -> bool:
    fid = (f.get("id") or "").upper()
    title = (f.get("title") or "").lower()
    if "auth_audit" in source_path or "csrf_audit" in source_path:
        return True
    if fid.startswith("AUTH") or fid.startswith("CSRF"):
        return True
    if "authorization" in title or "csrf" in title:
        return True
    return False


def is_var_override(f: Dict, source_path: str) -> bool:
    fid = (f.get("id") or "").upper()
    if "var_override_audit" in source_path:
        return True
    return fid.startswith("VAR")


def is_trigger_only(f: Dict) -> bool:
    fid = (f.get("id") or "").upper()
    return fid.startswith("SER-TRIG")


def validate_finding(f: Dict, source_path: str, require_ai: bool) -> List[str]:
    issues = []
    policy = load_policy()
    min_evidence = int(policy.get("evidence_score_min", 0))
    for k in REQUIRED_FIELDS:
        if k == "exploitability" and not require_ai:
            continue
        if k not in f or f.get(k) in (None, ""):
            issues.append(f"missing:{k}")

    sink = f.get("sink") or {}
    if not sink.get("file"):
        issues.append("sink:file")
    if not (is_policy_finding(f, source_path) or is_var_override(f, source_path) or is_trigger_only(f)):
        if not sink.get("line"):
            issues.append("sink:line")

    controllability = f.get("controllability")
    if controllability not in ("fully", "conditional", "none"):
        issues.append("controllability:invalid")

    severity = (f.get("severity") or "").lower()
    if severity and severity not in ("high", "medium", "low", "info"):
        issues.append("severity:invalid")

    # Evidence chain completeness
    if not (is_policy_finding(f, source_path) or is_var_override(f, source_path) or is_trigger_only(f)):
        if f.get("source") in (None, ""):
            issues.append("missing:source")
        taint = f.get("taint")
        if not isinstance(taint, list) or len(taint) == 0:
            issues.append("missing:taint")

    if require_ai:
        ai_table = f.get("ai_table")
        if not isinstance(ai_table, dict):
            issues.append("missing:ai_table")
            return issues
        for k in AI_TABLE_FIELDS:
            if k not in ai_table or ai_table.get(k) in (None, ""):
                issues.append(f"ai_table:missing:{k}")
        for key in ("reachability", "impact", "complexity"):
            val = ai_table.get(key)
            if not isinstance(val, dict):
                issues.append(f"ai_table:{key}:not_object")
                continue
            if "score" not in val:
                issues.append(f"ai_table:{key}:missing_score")
            if not str(val.get("desc") or "").strip():
                issues.append(f"ai_table:{key}:missing_desc")
        evidence = ai_table.get("evidence")
        if not isinstance(evidence, list) or len(evidence) == 0:
            issues.append("ai_table:evidence:empty")
        else:
            for idx, ev in enumerate(evidence):
                if not isinstance(ev, dict):
                    issues.append(f"ai_table:evidence:{idx}:not_object")
                    continue
                if not ev.get("file"):
                    issues.append(f"ai_table:evidence:{idx}:missing_file")
                if not ev.get("line"):
                    issues.append(f"ai_table:evidence:{idx}:missing_line")

    if require_ai:
        ev_score = f.get("evidence_score")
        if ev_score is None:
            issues.append("missing:evidence_score")
        else:
            try:
                ev_score_int = int(ev_score)
            except Exception:
                ev_score_int = -1
                issues.append("invalid:evidence_score")
            if min_evidence and ev_score_int >= 0 and ev_score_int < min_evidence and f.get("exploitability") == "已确认":
                issues.append("exploitability:evidence_score_low")

        if f.get("context_incomplete") and f.get("exploitability") == "已确认":
            issues.append("exploitability:context_incomplete")

        if (f.get("ai_consensus") or "").lower() == "low" and f.get("exploitability") == "已确认":
            issues.append("exploitability:consensus_low")

    return issues


def render_md(summary: Dict, issues: List[Dict]) -> str:
    lines = [
        "# Evidence Chain Check",
        "",
        f"Total Findings: {summary['total']}",
        f"Complete: {summary['complete']}",
        f"Incomplete: {summary['incomplete']}",
        "",
        "## Issues",
    ]
    for it in issues:
        lines.append(f"- {it['id']} {it['title']} ({it['source']}) -> {', '.join(it['issues'])}")
    return "\n".join(lines) + "\n"


DEBUG_REQUIRED_FIELDS = [
    "case_id",
    "vuln_type",
    "entry",
    "input",
    "final_value",
    "sink",
    "result",
    "notes",
    "change_type",
    "trace_chain",
    "source_path",
]

DYNAMIC_STATUS_VALUES = {"confirmed", "conditional", "rejected", "skipped"}

DEFAULT_DEBUG_SKIPPED_RATIO_MAX = 0.40


def debug_skipped_ratio_max() -> float:
    raw = os.environ.get("DEBUG_SKIPPED_RATIO_MAX", "").strip()
    if not raw:
        return DEFAULT_DEBUG_SKIPPED_RATIO_MAX
    try:
        value = float(raw)
    except Exception:
        return DEFAULT_DEBUG_SKIPPED_RATIO_MAX
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def appendix_anchor_id(case_id: str) -> str:
    base = re.sub(r"[^A-Za-z0-9_-]+", "-", str(case_id or "case")).strip("-").lower()
    return f"case-{base or 'case'}"


def normalize_severity(raw: str) -> str:
    s = str(raw or "").strip().lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    if "严重" in s or "critical" in s:
        return "critical"
    if "高危" in s or "high" in s:
        return "high"
    if "中危" in s or "medium" in s:
        return "medium"
    if "低危" in s or "low" in s:
        return "low"
    return "low"


def extra_output_checks(out_root: str, finding_ids: List[str]) -> List[Dict]:
    issues: List[Dict] = []
    skipped_ratio_limit = debug_skipped_ratio_max()
    module_reports = [
        "file_audit",
        "rce_audit",
        "ssrf_xxe_audit",
        "xss_ssti_audit",
        "csrf_audit",
        "var_override_audit",
        "serialize_audit",
    ]
    # SQL report existence
    sql_dir = os.path.join(out_root, "sql_audit")
    if os.path.exists(os.path.join(sql_dir, "findings.json")):
        has_report = False
        if os.path.isdir(sql_dir):
            for f in os.listdir(sql_dir):
                if f.endswith(".md") and "_sql_audit_" in f:
                    has_report = True
                    break
        if not has_report:
            issues.append({"id": "SQL-REPORT", "title": "Missing SQL audit report", "source": "sql_audit", "issues": ["report:missing"]})

    # Auth three-file delivery existence
    auth_dir = os.path.join(out_root, "auth_audit")
    if os.path.exists(os.path.join(auth_dir, "auth_evidence.json")):
        files = os.listdir(auth_dir) if os.path.isdir(auth_dir) else []
        ok = (
            any(f.endswith(".md") and "_auth_audit_" in f for f in files)
            and any(f.endswith(".md") and "_auth_mapping_" in f for f in files)
            and any(f.endswith(".md") and "_auth_README_" in f for f in files)
        )
        if not ok:
            issues.append({"id": "AUTH-REPORT", "title": "Missing auth 3-file reports", "source": "auth_audit", "issues": ["auth:three_files_missing"]})

    # Vuln trigger analysis existence
    vuln_md = os.path.join(out_root, "vuln_report", "composer_audit.md")
    if os.path.exists(vuln_md):
        try:
            text = open(vuln_md, "r", encoding="utf-8").read()
            if "触发点分析" not in text:
                issues.append({"id": "VULN-TRIGGER", "title": "Missing vuln trigger analysis", "source": "vuln_report", "issues": ["trigger:missing"]})
        except Exception:
            issues.append({"id": "VULN-TRIGGER", "title": "Missing vuln trigger analysis", "source": "vuln_report", "issues": ["trigger:missing"]})
    # Generic module report existence
    for module in module_reports:
        mod_dir = os.path.join(out_root, module)
        findings = os.path.join(mod_dir, "findings.json")
        if not os.path.exists(findings):
            continue
        if not os.path.isdir(mod_dir):
            issues.append({"id": f"{module.upper()}-REPORT", "title": "Missing module report dir", "source": module, "issues": ["report:dir_missing"]})
            continue
        has_report = any(
            f.endswith(".md") and f"_{module}_" in f
            for f in os.listdir(mod_dir)
        )
        if not has_report:
            issues.append({"id": f"{module.upper()}-REPORT", "title": "Missing module report", "source": module, "issues": ["report:missing"]})

    # Debug evidence outputs
    debug_dir = os.path.join(out_root, "debug_verify")
    debug_json = os.path.join(debug_dir, "debug_evidence.json")
    debug_md = os.path.join(debug_dir, "debug_evidence.md")
    if finding_ids and not os.path.exists(debug_json):
        issues.append({"id": "DEBUG-EVIDENCE", "title": "Missing debug_evidence.json", "source": "debug_verify", "issues": ["debug_evidence:missing_json"]})
    if finding_ids and not os.path.exists(debug_md):
        issues.append({"id": "DEBUG-EVIDENCE", "title": "Missing debug_evidence.md", "source": "debug_verify", "issues": ["debug_evidence:missing_md"]})
    if os.path.exists(debug_json):
        try:
            data = json.load(open(debug_json, "r", encoding="utf-8"))
        except Exception:
            data = []
            issues.append({"id": "DEBUG-EVIDENCE", "title": "Unreadable debug_evidence.json", "source": "debug_verify", "issues": ["debug_evidence:unreadable"]})
        if isinstance(data, list):
            total_cases = len(data)
            skipped_cases = sum(
                1 for entry in data
                if isinstance(entry, dict) and str(entry.get("result") or "") == "skipped"
            )
            if total_cases > 0:
                skipped_ratio = skipped_cases / total_cases
                if skipped_ratio > skipped_ratio_limit:
                    issues.append({
                        "id": "DEBUG-EVIDENCE",
                        "title": "Debug skipped ratio too high",
                        "source": "debug_verify",
                        "issues": [
                            f"debug_evidence:skipped_ratio_high:{skipped_cases}/{total_cases}>{skipped_ratio_limit:.2f}"
                        ],
                    })

            case_ids = set()
            for entry in data:
                if not isinstance(entry, dict):
                    issues.append({"id": "DEBUG-EVIDENCE", "title": "Invalid debug_evidence entry", "source": "debug_verify", "issues": ["debug_evidence:entry_not_object"]})
                    continue
                for k in DEBUG_REQUIRED_FIELDS:
                    if k not in entry:
                        issues.append({"id": entry.get("case_id") or "DEBUG-EVIDENCE", "title": "Missing debug field", "source": "debug_verify", "issues": [f"debug_evidence:missing:{k}"]})
                case_id = entry.get("case_id")
                if case_id:
                    case_ids.add(case_id)
                change_type = entry.get("change_type")
                result = entry.get("result")
                if result not in ("confirmed", "conditional", "rejected", "skipped"):
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Invalid debug result", "source": "debug_verify", "issues": ["debug_evidence:result_invalid"]})
                if change_type not in ("no_change", "weak_change", "strong_change", "unknown"):
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Invalid change_type", "source": "debug_verify", "issues": ["debug_evidence:change_type_invalid"]})
                if result != "skipped" and change_type == "unknown":
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Unknown change_type", "source": "debug_verify", "issues": ["debug_evidence:change_type_unknown"]})
                trace_chain = entry.get("trace_chain")
                if not isinstance(trace_chain, list) or len(trace_chain) == 0:
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Missing trace_chain", "source": "debug_verify", "issues": ["debug_evidence:trace_chain_missing"]})
                source_path = str(entry.get("source_path") or "")
                if source_path.startswith(os.sep):
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Absolute source_path", "source": "debug_verify", "issues": ["debug_evidence:source_path_absolute"]})
                if ":" not in source_path:
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Invalid source_path", "source": "debug_verify", "issues": ["debug_evidence:source_path_invalid"]})
            for fid in finding_ids:
                if fid not in case_ids:
                    issues.append({"id": fid, "title": "Missing debug evidence for finding", "source": "debug_verify", "issues": ["debug_evidence:case_missing"]})

    # final_report and appendix checks
    final_json = os.path.join(out_root, "final_report.json")
    final_md = os.path.join(out_root, "final_report.md")
    appendix_md = os.path.join(out_root, "final_report_appendix.md")
    if finding_ids and not os.path.exists(final_json):
        issues.append(
            {
                "id": "FINAL-REPORT",
                "title": "missing final_report.json",
                "source": "final_report.json",
                "issues": ["final_report:missing_json"],
            }
        )
    if os.path.exists(final_json):
        try:
            report_json = json.load(open(final_json, "r", encoding="utf-8"))
        except Exception:
            report_json = {}
            issues.append(
                {
                    "id": "FINAL-REPORT",
                    "title": "final_report.json unreadable",
                    "source": "final_report.json",
                    "issues": ["final_report:json_unreadable"],
                }
            )
        if isinstance(report_json, dict):
            main_cases = report_json.get("main_cases")
            if finding_ids and not isinstance(main_cases, list):
                issues.append(
                    {
                        "id": "FINAL-REPORT",
                        "title": "final_report main_cases missing",
                        "source": "final_report.json",
                        "issues": ["final_report:main_cases_missing"],
                    }
                )
            if isinstance(main_cases, list):
                for case in main_cases:
                    if not isinstance(case, dict):
                        continue
                    case_id = str(case.get("case_id") or "FINAL-REPORT")
                    severity = normalize_severity(str(case.get("severity") or "low"))
                    dynamic_status = str(case.get("dynamic_status") or "").strip().lower()
                    has_dynamic_supported = isinstance(case.get("dynamic_supported"), bool)
                    dynamic_reason = str(case.get("dynamic_reason") or "").strip()
                    refs = case.get("evidence_refs")

                    if dynamic_status and dynamic_status not in DYNAMIC_STATUS_VALUES:
                        issues.append(
                            {
                                "id": case_id,
                                "title": "Invalid dynamic_status",
                                "source": "final_report.json",
                                "issues": [f"final_report:dynamic_status_invalid:{dynamic_status}"],
                            }
                        )

                    if severity in ("critical", "high"):
                        if not dynamic_status:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing dynamic_status",
                                    "source": "final_report.json",
                                    "issues": ["final_report:high_missing_dynamic_status"],
                                }
                            )
                        elif dynamic_status not in DYNAMIC_STATUS_VALUES:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case dynamic_status invalid",
                                    "source": "final_report.json",
                                    "issues": ["final_report:high_dynamic_status_invalid"],
                                }
                            )

                        if not has_dynamic_supported:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing dynamic_supported",
                                    "source": "final_report.json",
                                    "issues": ["final_report:high_missing_dynamic_supported"],
                                }
                            )
                        if not dynamic_reason:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing dynamic_reason",
                                    "source": "final_report.json",
                                    "issues": ["final_report:high_missing_dynamic_reason"],
                                }
                            )
                        if not isinstance(refs, list) or len(refs) == 0:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing evidence_refs",
                                    "source": "final_report.json",
                                    "issues": ["final_report:high_missing_evidence_refs"],
                                }
                            )

    if finding_ids and os.path.exists(final_md):
        try:
            text = open(final_md, "r", encoding="utf-8").read()
            if "debug_evidence" not in text:
                issues.append({"id": "FINAL-REPORT", "title": "final_report missing debug_evidence reference", "source": "final_report.md", "issues": ["final_report:missing_debug_reference"]})
            if not re.search(r"^##\s+\d+\.\s+附录入口\s*$", text, flags=re.MULTILINE):
                issues.append({"id": "FINAL-REPORT", "title": "final_report missing appendix section", "source": "final_report.md", "issues": ["final_report:missing_appendix_section"]})
            if "静态-动态证据支持矩阵" not in text:
                issues.append(
                    {
                        "id": "FINAL-REPORT",
                        "title": "final_report missing static-dynamic matrix",
                        "source": "final_report.md",
                        "issues": ["final_report:missing_static_dynamic_matrix"],
                    }
                )

            case_ids = []
            for line in text.splitlines():
                if not line.startswith("### ["):
                    continue
                close_idx = line.find("]")
                if close_idx <= 4:
                    continue
                case_id = line[4:close_idx].strip()
                if case_id:
                    case_ids.append(case_id)
            for case_id in case_ids:
                anchor = appendix_anchor_id(case_id)
                ref = f"final_report_appendix.md#{anchor}"
                if ref not in text:
                    issues.append({
                        "id": case_id,
                        "title": "final_report case missing appendix anchor link",
                        "source": "final_report.md",
                        "issues": [f"final_report:missing_appendix_anchor:{anchor}"],
                    })
        except Exception:
            issues.append({"id": "FINAL-REPORT", "title": "final_report unreadable", "source": "final_report.md", "issues": ["final_report:unreadable"]})

    if os.path.exists(appendix_md):
        try:
            with open(appendix_md, "r", encoding="utf-8") as f:
                _ = f.read(1)
        except Exception:
            issues.append({"id": "FINAL-REPORT-APPENDIX", "title": "final_report_appendix unreadable", "source": "final_report_appendix.md", "issues": ["final_report_appendix:unreadable"]})
    elif finding_ids:
        issues.append({"id": "FINAL-REPORT-APPENDIX", "title": "missing final_report_appendix.md", "source": "final_report_appendix.md", "issues": ["final_report_appendix:missing"]})

    # Phase meta outputs
    meta_dir = os.path.join(out_root, "_meta")
    required_meta = [
        "phase1_map.md",
        "phase2_risk_map.md",
        "phase3_trace_log.md",
        "phase4_attack_chain.md",
        "phase5_report_index.md",
    ]
    if not os.path.isdir(meta_dir):
        issues.append({"id": "META-OUTPUT", "title": "Missing phase meta directory", "source": "_meta", "issues": ["meta:dir_missing"]})
    else:
        for name in required_meta:
            if not os.path.exists(os.path.join(meta_dir, name)):
                issues.append({"id": "META-OUTPUT", "title": "Missing phase meta file", "source": "_meta", "issues": [f"meta:file_missing:{name}"]})
        phase5 = os.path.join(meta_dir, "phase5_report_index.md")
        if os.path.exists(phase5):
            try:
                text = open(phase5, "r", encoding="utf-8").read()
                missing = []
                for key in ("Q1", "Q2", "Q3"):
                    if key not in text:
                        missing.append(key)
                if "结论" not in text:
                    missing.append("结论")
                if missing:
                    issues.append({"id": "META-TERMINATION", "title": "Missing termination decisions", "source": "_meta/phase5_report_index.md", "issues": [f"meta:termination_missing:{','.join(missing)}"]})
            except Exception:
                issues.append({"id": "META-TERMINATION", "title": "Missing termination decisions", "source": "_meta/phase5_report_index.md", "issues": ["meta:termination_unreadable"]})
    return issues


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero if any issues found")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    require_ai = os.path.exists(os.path.join(out_root, "ai_confirm.json"))

    entries = load_findings(out_root)
    issues = []
    complete = 0
    finding_ids = []
    for f, source_path in entries:
        errs = validate_finding(f, source_path, require_ai)
        if errs:
            issues.append({
                "id": f.get("id"),
                "title": f.get("title"),
                "source": os.path.relpath(source_path, out_root),
                "issues": errs,
            })
        else:
            complete += 1
        if f.get("id"):
            finding_ids.append(f.get("id"))

    # output completeness checks
    issues.extend(extra_output_checks(out_root, finding_ids))

    summary = {
        "total": len(entries),
        "complete": complete,
        "incomplete": len(issues),
    }
    report = {"summary": summary, "issues": issues}

    write_json(os.path.join(out_root, "evidence_check.json"), report)
    write_text(os.path.join(out_root, "evidence_check.md"), render_md(summary, issues))

    if args.strict and issues:
        raise SystemExit("Evidence check failed")
    print(f"Evidence check complete. Issues: {len(issues)}")


if __name__ == "__main__":
    main()
