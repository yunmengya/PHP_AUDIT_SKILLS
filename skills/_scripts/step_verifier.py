#!/usr/bin/env python3
import argparse
import glob
import json
import os
import time
from typing import Any, Dict, List, Tuple

from common import build_output_root, write_json, write_text

ARCHIVE_ROOT_DIR = "归档"
ARCHIVE_QUALITY_DIR = os.path.join(ARCHIVE_ROOT_DIR, "质量门禁")
STEP_GATE_DIR = os.path.join(ARCHIVE_QUALITY_DIR, "步骤门禁")

PHASE_NAME = {
    0: "预检与编排",
    1: "信息收集",
    2: "调用链追踪",
    3: "交叉分析",
    4: "静态漏洞分析",
    5: "动态验证与漏洞确认",
    6: "AI深入审计",
    7: "报告汇总与交付",
}

STATUS_PASS = "PASS"
STATUS_BLOCK = "BLOCK"
HARD_BLOCKING_EVIDENCE_PREFIXES = (
    "run_context:",
    "stage_required:",
    "debug_runtime:not_in_container",
    "ai_deep_audit:not_in_container",
    "ai_deep_audit:stage_status:",
    "ai_deep_audit:missing_summary_json",
    "ai_deep_audit:summary_unreadable",
    "ai_deep_audit:missing_report_md",
    "ai_deep_audit:missing_target_statuses",
    "ai_deep_audit:ai_only_bypass_required",
    "ai_deep_audit:target_selection_incomplete",
    "ai_deep_audit:target_execution_incomplete",
    "debug_evidence:missing_json",
    "debug_evidence:missing_md",
    "debug_evidence:unreadable",
    "debug_evidence:entry_not_object",
    "debug_evidence:missing:",
    "debug_evidence:trace_chain_missing",
    "debug_evidence:source_path_invalid",
    "debug_evidence:source_path_absolute",
    "debug_evidence:case_missing",
    "final_report:high_missing_dynamic_status",
    "final_report:high_dynamic_status_invalid",
    "final_report:high_missing_dynamic_supported",
    "final_report:high_missing_dynamic_reason",
    "final_report:high_missing_evidence_refs",
    "debug_evidence:strict_dynamic_skipped",
    "debug_evidence:strict_confirmed_required:",
    "debug_evidence:strict_ai_status_invalid:",
    "debug_evidence:strict_ai_attempt_missing",
    "debug_evidence:skipped_ratio_high:",
)


def _load_json(path: str) -> Any:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _exists_non_empty(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    try:
        return os.path.getsize(path) > 0
    except Exception:
        return False


def _stage_status(out_root: str) -> Dict[str, str]:
    run_ctx = _load_json(os.path.join(out_root, "_meta", "run_context.json"))
    stages = {}
    if isinstance(run_ctx, dict):
        rows = run_ctx.get("stages")
        if isinstance(rows, dict):
            for k, v in rows.items():
                if isinstance(v, dict):
                    stages[str(k)] = str(v.get("status") or "")
    return stages


def _stage_enabled(stage_map: Dict[str, str], stage: str) -> bool:
    return stage in stage_map


def _count_route_trace_coverage(out_root: str) -> Tuple[int, int, float]:
    routes = _load_json(os.path.join(out_root, "route_mapper", "routes.json"))
    route_count = len(routes) if isinstance(routes, list) else 0
    trace_files = glob.glob(os.path.join(out_root, "route_tracer", "**", "trace.json"), recursive=True)
    trace_count = len(trace_files)
    if route_count <= 0:
        return route_count, trace_count, 1.0
    return route_count, trace_count, float(trace_count) / float(route_count)


def _collect_findings(out_root: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for root, _, files in os.walk(out_root):
        for name in files:
            if name not in {"findings.json", "auth_evidence.json"}:
                continue
            path = os.path.join(root, name)
            data = _load_json(path)
            if isinstance(data, list):
                for row in data:
                    if isinstance(row, dict):
                        findings.append(row)
    return findings


def _count_high_critical(findings: List[Dict[str, Any]]) -> int:
    count = 0
    for row in findings:
        sev = str(row.get("severity") or "").strip().lower()
        if sev in {"high", "critical"}:
            count += 1
    return count


def _module_has_markdown(module_dir: str) -> bool:
    if not os.path.isdir(module_dir):
        return False
    for name in os.listdir(module_dir):
        if name.endswith(".md"):
            return True
    return False


def _check_path(checks: List[Dict[str, str]], path: str, title: str) -> None:
    if _exists_non_empty(path):
        checks.append({"check": title, "status": STATUS_PASS, "detail": path})
    else:
        checks.append({"check": title, "status": STATUS_BLOCK, "detail": f"missing: {path}"})


def _is_hard_blocking_evidence_issue(issue_item: Dict[str, Any]) -> bool:
    if not isinstance(issue_item, dict):
        return False
    issue_rows = issue_item.get("issues")
    if not isinstance(issue_rows, list) or not issue_rows:
        return False
    for row in issue_rows:
        text = str(row or "")
        if any(text.startswith(prefix) for prefix in HARD_BLOCKING_EVIDENCE_PREFIXES):
            return True
    return False


def _count_blocking_issues(ec_report: Dict[str, Any]) -> Tuple[int, int]:
    if not isinstance(ec_report, dict):
        return 0, 0
    rows = ec_report.get("issues")
    if not isinstance(rows, list):
        return 0, 0
    blocking = 0
    non_blocking = 0
    for row in rows:
        if _is_hard_blocking_evidence_issue(row):
            blocking += 1
        else:
            non_blocking += 1
    return blocking, non_blocking


def verify_phase(out_root: str, phase_id: int) -> Tuple[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    stage_map = _stage_status(out_root)

    if phase_id == 0:
        run_ctx = _load_json(os.path.join(out_root, "_meta", "run_context.json"))
        if isinstance(run_ctx, dict) and bool(run_ctx.get("executed_in_container")):
            checks.append({"check": "Docker执行环境", "status": STATUS_PASS, "detail": "executed_in_container=true"})
        else:
            checks.append({"check": "Docker执行环境", "status": STATUS_BLOCK, "detail": "run_context missing or not container"})
        _check_path(checks, os.path.join(out_root, "agent_task_manifest.md"), "任务编排清单")

    elif phase_id == 1:
        _check_path(checks, os.path.join(out_root, "route_mapper", "routes.json"), "路由JSON")
        _check_path(checks, os.path.join(out_root, "route_mapper", "routes.md"), "路由Markdown")
        if _stage_enabled(stage_map, "auth_audit"):
            _check_path(checks, os.path.join(out_root, "auth_audit", "auth_evidence.json"), "鉴权证据")
        if _stage_enabled(stage_map, "vuln_scanner"):
            _check_path(checks, os.path.join(out_root, "vuln_report", "composer_audit.json"), "依赖扫描JSON")
            _check_path(checks, os.path.join(out_root, "vuln_report", "composer_audit.md"), "依赖扫描Markdown")

    elif phase_id == 2:
        _check_path(checks, os.path.join(out_root, "route_tracer", "call_graph.json"), "调用图JSON")
        trace_files = glob.glob(os.path.join(out_root, "route_tracer", "**", "trace.json"), recursive=True)
        sink_files = glob.glob(os.path.join(out_root, "route_tracer", "**", "sinks.json"), recursive=True)
        if trace_files:
            checks.append({"check": "路由追踪JSON", "status": STATUS_PASS, "detail": f"count={len(trace_files)}"})
        else:
            checks.append({"check": "路由追踪JSON", "status": STATUS_BLOCK, "detail": "missing route_tracer/**/trace.json"})
        if sink_files:
            checks.append({"check": "危险函数汇总", "status": STATUS_PASS, "detail": f"count={len(sink_files)}"})
        else:
            checks.append({"check": "危险函数汇总", "status": STATUS_BLOCK, "detail": "missing route_tracer/**/sinks.json"})
        route_count, trace_count, ratio = _count_route_trace_coverage(out_root)
        if ratio >= 0.90:
            checks.append({
                "check": "追踪覆盖率",
                "status": STATUS_PASS,
                "detail": f"{trace_count}/{route_count} = {ratio:.2%}",
            })
        else:
            checks.append({
                "check": "追踪覆盖率",
                "status": STATUS_BLOCK,
                "detail": f"{trace_count}/{route_count} = {ratio:.2%} < 90%",
            })

    elif phase_id == 3:
        if _stage_enabled(stage_map, "ai_confirm"):
            _check_path(checks, os.path.join(out_root, "ai_confirm.json"), "AI确认结果")
        findings = _collect_findings(out_root)
        checks.append({"check": "静态发现可读", "status": STATUS_PASS, "detail": f"findings={len(findings)}"})

    elif phase_id == 4:
        modules = [
            "sql_audit",
            "rce_audit",
            "file_audit",
            "ssrf_xxe_audit",
            "xss_ssti_audit",
            "csrf_audit",
            "var_override_audit",
            "serialize_audit",
        ]
        active = 0
        for m in modules:
            if not _stage_enabled(stage_map, m):
                continue
            active += 1
            dir_path = os.path.join(out_root, m)
            fp = os.path.join(dir_path, "findings.json")
            if _exists_non_empty(fp) and _module_has_markdown(dir_path):
                checks.append({"check": f"{m}产物完整", "status": STATUS_PASS, "detail": "findings+md"})
            else:
                checks.append({"check": f"{m}产物完整", "status": STATUS_BLOCK, "detail": "missing findings.json or module md"})
        if active == 0:
            checks.append({"check": "静态漏洞模块命中", "status": STATUS_BLOCK, "detail": "no static vulnerability modules enabled"})

    elif phase_id == 5:
        runtime = _load_json(os.path.join(out_root, "debug_verify", "动态运行元信息.json"))
        if isinstance(runtime, dict) and bool(runtime.get("executed_in_container")):
            checks.append({"check": "动态阶段Docker执行", "status": STATUS_PASS, "detail": "executed_in_container=true"})
        else:
            checks.append({"check": "动态阶段Docker执行", "status": STATUS_BLOCK, "detail": "missing or invalid 动态运行元信息.json"})
        for name in ["动态调试证据.md", "动态调试过程.md", "动态调试PoC.md", "函数追踪证据.md"]:
            _check_path(checks, os.path.join(out_root, "debug_verify", name), name)
        debug_cases = _load_json(os.path.join(out_root, "debug_verify", "debug_cases.json"))
        case_count = len(debug_cases) if isinstance(debug_cases, list) else 0
        evidence = _load_json(os.path.join(out_root, "debug_verify", "动态调试证据.json"))
        evidence_count = len(evidence) if isinstance(evidence, list) else 0
        if case_count <= evidence_count:
            checks.append({"check": "动态case覆盖", "status": STATUS_PASS, "detail": f"cases={case_count}, evidence={evidence_count}"})
        else:
            checks.append({"check": "动态case覆盖", "status": STATUS_BLOCK, "detail": f"cases={case_count}, evidence={evidence_count}"})

        high_count = _count_high_critical(_collect_findings(out_root))
        if high_count <= case_count:
            checks.append({"check": "高危漏洞动态测试覆盖", "status": STATUS_PASS, "detail": f"high/critical={high_count}, debug_cases={case_count}"})
        else:
            checks.append({"check": "高危漏洞动态测试覆盖", "status": STATUS_BLOCK, "detail": f"high/critical={high_count}, debug_cases={case_count}"})

    elif phase_id == 6:
        summary = _load_json(os.path.join(out_root, "ai_deep_audit", "ai_deep_audit_summary.json"))
        _check_path(checks, os.path.join(out_root, "ai_deep_audit", "AI深入审计阶段报告.md"), "AI深入审计阶段报告")
        if isinstance(summary, dict) and bool(summary.get("executed_in_container")):
            checks.append({"check": "AI深审Docker执行", "status": STATUS_PASS, "detail": "executed_in_container=true"})
        else:
            checks.append({"check": "AI深审Docker执行", "status": STATUS_BLOCK, "detail": "missing or invalid ai_deep_audit_summary.json"})
        if isinstance(summary, dict):
            ai_only = bool(summary.get("ai_only_bypass"))
            target_statuses = summary.get("target_statuses")
            target_count = int(summary.get("target_case_count") or 0)
            selected_count = int(summary.get("selected_case_count") or 0)
            attempted_count = int(summary.get("attempted_case_count") or 0)

            if ai_only:
                checks.append({"check": "AI-only绕过模式", "status": STATUS_PASS, "detail": "ai_only_bypass=true"})
            else:
                checks.append({"check": "AI-only绕过模式", "status": STATUS_BLOCK, "detail": "ai_only_bypass=false"})

            if isinstance(target_statuses, list) and target_statuses:
                checks.append({"check": "深审目标状态", "status": STATUS_PASS, "detail": ",".join([str(x) for x in target_statuses])})
            else:
                checks.append({"check": "深审目标状态", "status": STATUS_BLOCK, "detail": "target_statuses missing"})

            if selected_count >= target_count:
                checks.append(
                    {
                        "check": "目标案例选取覆盖",
                        "status": STATUS_PASS,
                        "detail": f"selected={selected_count}, target={target_count}",
                    }
                )
            else:
                checks.append(
                    {
                        "check": "目标案例选取覆盖",
                        "status": STATUS_BLOCK,
                        "detail": f"selected={selected_count}, target={target_count}",
                    }
                )

            if attempted_count >= selected_count:
                checks.append(
                    {
                        "check": "目标案例执行覆盖",
                        "status": STATUS_PASS,
                        "detail": f"attempted={attempted_count}, selected={selected_count}",
                    }
                )
            else:
                checks.append(
                    {
                        "check": "目标案例执行覆盖",
                        "status": STATUS_BLOCK,
                        "detail": f"attempted={attempted_count}, selected={selected_count}",
                    }
                )
        else:
            checks.append({"check": "AI深审摘要结构", "status": STATUS_BLOCK, "detail": "summary json missing"})

    elif phase_id == 7:
        for name in ["最终静态审计结果.md", "动态debug审计报告.md", "AI深入验证最终报告.md"]:
            _check_path(checks, os.path.join(out_root, name), name)
        _check_path(checks, os.path.join(out_root, ARCHIVE_QUALITY_DIR, "证据校验.md"), "证据校验报告")
        _check_path(checks, os.path.join(out_root, ARCHIVE_QUALITY_DIR, "资源回收报告.md"), "资源回收报告")
        ec = _load_json(os.path.join(out_root, ARCHIVE_QUALITY_DIR, "证据校验.json"))
        blocking_count = 0
        non_blocking_count = 0
        total_issue_count = 0
        if isinstance(ec, dict):
            issues = ec.get("issues")
            if isinstance(issues, list):
                total_issue_count = len(issues)
            blocking_count, non_blocking_count = _count_blocking_issues(ec)
        if blocking_count == 0:
            checks.append(
                {
                    "check": "证据校验阻断项",
                    "status": STATUS_PASS,
                    "detail": f"blocking=0, warning={non_blocking_count}, total={total_issue_count}",
                }
            )
        else:
            checks.append(
                {
                    "check": "证据校验阻断项",
                    "status": STATUS_BLOCK,
                    "detail": f"blocking={blocking_count}, warning={non_blocking_count}, total={total_issue_count}",
                }
            )

    else:
        checks.append({"check": "阶段ID合法", "status": STATUS_BLOCK, "detail": f"unknown phase_id={phase_id}"})

    blocked = [c for c in checks if c.get("status") == STATUS_BLOCK]
    return (STATUS_BLOCK if blocked else STATUS_PASS), checks


def render_md(phase_id: int, verdict: str, checks: List[Dict[str, str]], out_root: str) -> str:
    phase_name = PHASE_NAME.get(phase_id, f"阶段{phase_id}")
    lines: List[str] = [
        f"# 阶段{phase_id}质检报告（agent-verifier）",
        "",
        f"- 阶段名称：{phase_name}",
        f"- 验收结论：{verdict}",
        f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 输出目录：`{out_root}`",
        "",
        "| 检查项 | 结果 | 说明 |",
        "| --- | --- | --- |",
    ]
    for row in checks:
        lines.append(f"| {row.get('check', '-')} | {row.get('status', '-')} | {row.get('detail', '-')} |")

    blocked = [c for c in checks if c.get("status") == STATUS_BLOCK]
    lines.append("")
    if blocked:
        lines.append("## 阻断原因")
        lines.append("")
        for idx, row in enumerate(blocked, 1):
            lines.append(f"{idx}. {row.get('check', '-')}：{row.get('detail', '-')}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--phase-id", type=int, required=True)
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(os.path.join(out_root, STEP_GATE_DIR), exist_ok=True)

    verdict, checks = verify_phase(out_root, int(args.phase_id))
    md_path = os.path.join(out_root, STEP_GATE_DIR, f"phase_{int(args.phase_id)}_verifier.md")
    json_path = os.path.join(out_root, STEP_GATE_DIR, f"phase_{int(args.phase_id)}_verifier.json")

    md = render_md(int(args.phase_id), verdict, checks, out_root)
    write_text(md_path, md)
    write_json(json_path, {
        "phase_id": int(args.phase_id),
        "phase_name": PHASE_NAME.get(int(args.phase_id), f"阶段{int(args.phase_id)}"),
        "verdict": verdict,
        "checks": checks,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    })

    print(f"[VERIFIER] phase={int(args.phase_id)} verdict={verdict} report={md_path}")
    if verdict == STATUS_PASS:
        return
    raise SystemExit(2)


if __name__ == "__main__":
    main()
