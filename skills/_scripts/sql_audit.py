#!/usr/bin/env python3
import argparse
import json
import os
import sys
import re
import time
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from common import (
    SQL_SINK_PATTERNS,
    SQL_VALIDATION_PATTERNS,
    build_output_root,
    read_text,
    walk_php_files,
    write_json,
    write_text,
)
from audit_helpers import apply_rule_audit_quick_filter, compact_text, markdown_table, write_module_html

# ORM/Prepared statement safe patterns (reduce false positives)
SAFE_SQL_PATTERNS = [
    r"->\s*prepare\s*\(",
    r"->\s*bindParam\s*\(",
    r"->\s*bindValue\s*\(",
    r"->\s*execute\s*\(",
    r"\bDB::table\s*\(",
    r"->\s*where\s*\(",
    r"->\s*whereIn\s*\(",
    r"->\s*whereNull\s*\(",
    r"->\s*whereNotNull\s*\(",
]


def is_sql_sink_line(line: str) -> bool:
    for rule in SQL_SINK_PATTERNS:
        if rule["regex"].search(line):
            return True
    return False


def has_sql_validation(line: str) -> bool:
    return any(p.search(line) for p in SQL_VALIDATION_PATTERNS)


def is_safe_sql_usage(line: str) -> bool:
    return any(re.search(p, line, re.I) for p in SAFE_SQL_PATTERNS)


def load_traces(trace_root: str) -> List[Dict]:
    traces = []
    for root, _, files in os.walk(trace_root):
        for f in files:
            if f == "trace.json":
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8") as fh:
                    try:
                        traces.append(json.load(fh))
                    except Exception:
                        continue
    return traces


def findings_from_traces(traces: List[Dict]) -> List[Dict]:
    findings = []
    seq = 1
    for trace in traces:
        sinks = trace.get("sinks", []) or ([] if trace.get("sink") is None else [trace.get("sink")])
        sql_sinks = [s for s in sinks if s and s.get("type") == "sql"]
        if not sql_sinks:
            continue
        src = trace.get("source")
        validation = trace.get("validation", [])
        controllability = trace.get("controllability") or "conditional"
        confidence = "high" if src and not validation else "medium"
        severity = "high" if controllability == "fully" else "medium"
        poc = build_poc(trace)
        for s in sql_sinks:
            if is_safe_sql_usage(s.get("code", "")):
                # Reduce false positives when sinks are safe ORM/prepared usages
                continue
            findings.append({
                "id": f"SQLI-{seq:03d}",
                "title": "Possible SQL Injection",
                "severity": severity,
                "independent_severity": severity,
                "combined_severity": severity,
                "confidence": confidence,
                "route": trace.get("route"),
                "source": src,
                "taint": trace.get("taint", []),
                "sink": s,
                "validation": validation,
                "controllability": controllability,
                "poc": poc,
                "notes": "Derived from route_tracer output.",
            })
            seq += 1
    return findings


def fallback_findings(project_root: str) -> List[Dict]:
    findings = []
    seq = 1
    for path in walk_php_files(project_root):
        text = read_text(path)
        for idx, line in enumerate(text.splitlines(), start=1):
            if is_sql_sink_line(line):
                if is_safe_sql_usage(line):
                    continue
                findings.append({
                    "id": f"SQLI-{seq:03d}",
                    "title": "Possible SQL Injection",
                    "severity": "medium",
                    "independent_severity": "medium",
                    "combined_severity": "medium",
                    "confidence": "low",
                    "route": None,
                    "source": None,
                    "taint": [],
                    "sink": {"file": path, "line": idx, "function": "sql", "code": line.strip()},
                    "validation": [],
                    "controllability": "conditional",
                    "poc": None,
                    "notes": "Fallback scan without route_tracer evidence.",
                })
                seq += 1
    return findings


def build_poc(trace: Dict) -> Dict:
    route = trace.get("route", {})
    path = route.get("path") or "/"
    method = (route.get("method") or "GET").split("|")[0]
    source = trace.get("source") or {}
    param = source.get("param") or "id"
    payload = "1' OR 1=1 -- "
    if method in ("GET", "ANY"):
        return {"method": "GET", "path": path, "params": {param: payload}, "notes": "仅模板，不执行"}
    return {"method": method, "path": path, "body": {param: payload}, "notes": "仅模板，不执行"}

def project_name_from_out(out_root: str) -> str:
    base = os.path.basename(out_root.rstrip("/"))
    m = re.match(r"(.+?)_audit(?:_\\d{8}_\\d{6})?$", base)
    if m:
        return m.group(1)
    return base or "project"


def mapping_row(f: Dict) -> Tuple[str, str, str, str, str, str, str, str]:
    sink = f.get("sink") or {}
    route = f.get("route") or {}
    loc = f"{sink.get('file')}:{sink.get('line')}"
    func = sink.get("function") or "sql"
    framework = route.get("framework") or "unknown"
    code = sink.get("code", "")
    if is_safe_sql_usage(code):
        param_status = "参数化/安全"
    elif has_sql_validation(code):
        param_status = "过滤/转义"
    else:
        param_status = "动态拼接"
    controllability = f.get("controllability") or "conditional"
    indep = f.get("independent_severity") or f.get("severity") or "info"
    combo = f.get("combined_severity") or f.get("severity") or "info"
    return f.get("id", "-"), loc, func, framework, param_status, controllability, indep, combo


def render_sql_report(findings: List[Dict], out_root: str, ts: str) -> str:
    project_name = project_name_from_out(out_root)
    lines = [
        f"# {project_name} - SQL 注入审计报告",
        "",
        f"生成时间：{ts}",
        f"输出目录：{out_root}",
        "",
    ]
    lines.append("## SQL 操作映射表")
    map_rows: List[List[str]] = []
    for f in findings:
        rid, loc, func, fw, ps, ctrl, indep, combo = mapping_row(f)
        map_rows.append([rid, loc, func, fw, ps, ctrl, indep, combo])
    lines.append(
        markdown_table(
            ["序号", "位置(文件:行)", "方法/函数", "框架", "参数化状态", "可控性", "独立等级", "组合等级"],
            map_rows,
        )
    )
    lines.append("")

    lines.append("## 风险详情表")
    detail_rows: List[List[str]] = []
    for f in findings:
        rid = f.get("id", "-")
        title = f.get("title", "Finding")
        indep = f.get("independent_severity") or f.get("severity", "info")
        combo = f.get("combined_severity") or f.get("severity", "info")
        conf = f.get("confidence", "medium")
        route = f.get("route") or {}
        route_str = f"{route.get('method','')} {route.get('path','')}".strip()
        sink = f.get("sink") or {}
        ai_info = f.get("ai_confirm") or {}
        notes = f.get("notes") or ""
        debug = f.get("debug_evidence") or {}
        debug_result = debug.get("result") or "-"
        debug_change = debug.get("change_type") or "-"
        evidence_summary = None
        ai_table = f.get("ai_table") if isinstance(f.get("ai_table"), dict) else None
        if ai_table:
            evidence_summary = ai_table.get("evidence_summary")
        detail_rows.append([
            compact_text(rid),
            compact_text(title),
            compact_text(f"{sink.get('file','-')}:{sink.get('line','-')}"),
            compact_text(indep),
            compact_text(combo),
            compact_text(conf),
            compact_text(f.get("exploitability") or "-"),
            compact_text(f.get("controllability") or "conditional"),
            compact_text(route_str or "-"),
            compact_text(f"{sink.get('function') or sink.get('type') or '-'}"),
            compact_text(debug_result),
            compact_text(debug_change),
            compact_text(ai_info.get("rationale") or "-"),
            compact_text(evidence_summary or "-"),
            compact_text(notes or "-"),
        ])
    lines.append(
        markdown_table(
            ["ID", "标题", "位置", "独立等级", "组合等级", "置信度", "可利用性", "可控性", "路由/入口", "Sink", "Debug结论", "变化类型", "AI理由", "证据摘要", "备注"],
            detail_rows,
        )
    )
    lines.append("")

    lines.append("## 证据链表")
    evidence_rows: List[List[str]] = []
    for f in findings:
        evidence_rows.append([
            compact_text(f.get("id") or "-"),
            compact_text(f.get("source")),
            compact_text(f.get("taint")),
            compact_text(f.get("validation")),
        ])
    lines.append(markdown_table(["ID", "Source", "Taint", "Validation"], evidence_rows))
    lines.append("")

    lines.append("## PoC 表")
    poc_rows: List[List[str]] = []
    for f in findings:
        ai_table = f.get("ai_table") or {}
        poc = ai_table.get("poc") or f.get("poc")
        poc_source = ai_table.get("poc_source") or ("template" if poc else "-")
        if poc_source == "template":
            poc_source = "template(需人工校验)"
        poc_rows.append([compact_text(f.get("id") or "-"), compact_text(poc_source), compact_text(poc)])
    lines.append(markdown_table(["ID", "PoC来源", "PoC"], poc_rows))
    lines.append("")

    lines.append("## 修复建议")
    rec_rows = [
        ["1", "使用预编译/参数绑定"],
        ["2", "对 ORDER BY / 列名 / 表名采用白名单"],
        ["3", "统一输入校验与类型约束"],
    ]
    lines.append(markdown_table(["序号", "建议"], rec_rows))
    lines.append("")

    lines.append("## 结论")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    ctrl_counts = {"fully": 0, "conditional": 0, "none": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
        ctrl = f.get("controllability") or "conditional"
        if ctrl in ctrl_counts:
            ctrl_counts[ctrl] += 1
    conclusion_rows = [
        ["高危数量", str(counts["high"])],
        ["中危数量", str(counts["medium"])],
        ["低危数量", str(counts["low"])],
        ["可控性统计", f"fully={ctrl_counts['fully']}, conditional={ctrl_counts['conditional']}, none={ctrl_counts['none']}"],
    ]
    lines.append(markdown_table(["指标", "数值"], conclusion_rows))
    lines.append("")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_findings(findings: List[Dict], out_root: str) -> None:
    out_dir = os.path.join(out_root, "sql_audit")
    os.makedirs(out_dir, exist_ok=True)
    write_json(os.path.join(out_dir, "findings.json"), findings)
    lines = ["# SQL Audit Findings", "", f"Total: {len(findings)}", ""]
    for f in findings:
        route = f.get("route") or {}
        lines.append(f"## {f['id']} {f['title']}")
        lines.append(f"- Severity: {f['severity']}")
        lines.append(f"- Independent: {f.get('independent_severity') or f.get('severity')}")
        lines.append(f"- Combined: {f.get('combined_severity') or f.get('severity')}")
        lines.append(f"- Confidence: {f['confidence']}")
        if route:
            lines.append(f"- Route: {route.get('method')} {route.get('path')}")
        sink = f.get("sink") or {}
        if sink:
            lines.append(f"- Sink: {sink.get('file')}:{sink.get('line')}")
        lines.append("")
    write_text(os.path.join(out_dir, "findings.md"), "\n".join(lines) + "\n")

    # comprehensive report
    ts = time.strftime("%Y%m%d_%H%M%S")
    project_name = project_name_from_out(out_root)
    report_name = f"{project_name}_sql_audit_{ts}.md"
    write_text(os.path.join(out_dir, report_name), render_sql_report(findings, out_root, ts))
    write_module_html(out_dir, "sql_audit", "SQL 注入审计报告", findings)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    trace_root = os.path.join(out_root, "route_tracer")

    findings: List[Dict]
    if os.path.isdir(trace_root):
        traces = load_traces(trace_root)
        findings = findings_from_traces(traces)
    else:
        findings = []

    if not findings:
        findings = fallback_findings(project_root)

    findings = apply_rule_audit_quick_filter(findings, "sql_audit")

    write_findings(findings, out_root)
    print(f"Wrote {len(findings)} findings to {out_root}")


if __name__ == "__main__":
    main()
