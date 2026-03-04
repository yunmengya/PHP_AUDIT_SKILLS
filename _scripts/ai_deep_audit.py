#!/usr/bin/env python3
import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from common import build_output_root, write_json, write_text
from audit_helpers import markdown_table
from debug_cases import generate_cases


RESULT_VALUES = {"confirmed", "conditional", "rejected", "skipped"}
FINDING_FILES = {"findings.json", "auth_evidence.json"}
DEFAULT_TARGET_STATUSES = ("conditional",)


def shell_join(parts: List[str]) -> str:
    # Python 3.7 does not provide shlex.join; keep command logging compatible.
    join_fn = getattr(shlex, "join", None)
    if callable(join_fn):
        return join_fn(parts)
    return " ".join(shlex.quote(str(p)) for p in parts)


def running_in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    cgroup_path = "/proc/1/cgroup"
    if os.path.exists(cgroup_path):
        try:
            with open(cgroup_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read().lower()
            return ("docker" in text) or ("containerd" in text) or ("kubepods" in text)
        except Exception:
            return False
    return False


def ensure_running_in_container() -> None:
    if running_in_container():
        return
    raise SystemExit("Use skills/docker/run_audit.sh")


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except Exception:
        return default
    return val if val >= 0 else default


def env_text(name: str, default: str) -> str:
    raw = os.environ.get(name, "").strip()
    return raw if raw else default


def resolve_default_model() -> str:
    return (
        os.environ.get("AI_DEEP_MODEL")
        or os.environ.get("AI_CONFIRM_MODEL")
        or os.environ.get("AI_AUDIT_MODEL")
        or "sonnet"
    )


def load_json_list(path: str) -> List[Dict[str, Any]]:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
    except Exception:
        return []
    return []


def parse_target_statuses(raw: str) -> List[str]:
    values = [str(x).strip().lower() for x in str(raw or "").split(",")]
    parsed = [x for x in values if x in RESULT_VALUES]
    if not parsed:
        return list(DEFAULT_TARGET_STATUSES)
    dedupe: List[str] = []
    seen = set()
    for s in parsed:
        if s in seen:
            continue
        seen.add(s)
        dedupe.append(s)
    return dedupe


def normalize_severity(raw: str) -> str:
    s = str(raw or "").strip().lower()
    if s in {"critical", "high", "medium", "low"}:
        return s
    if "严重" in s:
        return "critical"
    if "高" in s:
        return "high"
    if "中" in s:
        return "medium"
    return "low"


def severity_weight(sev: str) -> int:
    mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return mapping.get(normalize_severity(sev), 1)


def result_weight(result: str) -> int:
    # unresolved first
    mapping = {"conditional": 0, "skipped": 1, "rejected": 2, "confirmed": 3}
    return mapping.get(str(result or "").strip().lower(), 1)


def load_finding_meta(out_root: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for root, _, files in os.walk(out_root):
        for name in files:
            if name not in FINDING_FILES:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            if not isinstance(data, list):
                continue
            module = os.path.basename(os.path.dirname(path))
            for row in data:
                if not isinstance(row, dict):
                    continue
                case_id = str(row.get("id") or "").strip()
                if not case_id:
                    continue
                sink = row.get("sink") if isinstance(row.get("sink"), dict) else {}
                location = "-"
                sink_file = str(sink.get("file") or "").strip()
                sink_line = sink.get("line")
                if sink_file and sink_line:
                    location = f"{sink_file}:{sink_line}"
                elif sink_file:
                    location = sink_file
                out[case_id] = {
                    "severity": normalize_severity(str(row.get("severity") or "low")),
                    "title": str(row.get("title") or ""),
                    "module": module,
                    "location": location,
                }
    return out


def load_previous_dynamic_result(out_root: str) -> Dict[str, str]:
    path = os.path.join(out_root, "debug_verify", "动态调试证据.json")
    rows = load_json_list(path)
    out: Dict[str, str] = {}
    for row in rows:
        case_id = str(row.get("case_id") or "").strip()
        if not case_id:
            continue
        result = str(row.get("result") or "").strip().lower()
        if result in RESULT_VALUES:
            out[case_id] = result
    return out


def ensure_cases(project_root: str, out_root: str) -> List[Dict[str, Any]]:
    path = os.path.join(out_root, "debug_verify", "debug_cases.json")
    rows = load_json_list(path)
    if rows:
        return rows
    generated = generate_cases(project_root, out_root)
    return load_json_list(generated)


def prioritize_cases(
    cases: List[Dict[str, Any]],
    finding_meta: Dict[str, Dict[str, Any]],
    previous_dynamic: Dict[str, str],
) -> List[Dict[str, Any]]:
    def case_key(case: Dict[str, Any]) -> Tuple[int, int, str]:
        case_id = str(case.get("case_id") or "")
        meta = finding_meta.get(case_id) or {}
        prev_result = previous_dynamic.get(case_id, "skipped")
        sev = str(meta.get("severity") or "low")
        return (
            result_weight(prev_result),
            -severity_weight(sev),
            case_id,
        )

    return sorted(cases, key=case_key)


def summarize_debug_results(out_root: str) -> Dict[str, int]:
    path = os.path.join(out_root, "debug_verify", "动态调试证据.json")
    rows = load_json_list(path)
    stats = {"total": 0, "confirmed": 0, "conditional": 0, "rejected": 0, "skipped": 0}
    for row in rows:
        result = str(row.get("result") or "").strip().lower()
        if result not in RESULT_VALUES:
            continue
        stats["total"] += 1
        stats[result] += 1
    return stats


def load_debug_result_map(out_root: str) -> Dict[str, str]:
    path = os.path.join(out_root, "debug_verify", "动态调试证据.json")
    rows = load_json_list(path)
    out: Dict[str, str] = {}
    for row in rows:
        case_id = str(row.get("case_id") or "").strip()
        if not case_id:
            continue
        result = str(row.get("result") or "").strip().lower()
        if result in RESULT_VALUES:
            out[case_id] = result
    return out


def summarize_selected_results(selected_cases: List[Dict[str, Any]], result_map: Dict[str, str]) -> Dict[str, int]:
    stats = {"total": len(selected_cases), "confirmed": 0, "conditional": 0, "rejected": 0, "skipped": 0}
    for case in selected_cases:
        case_id = str(case.get("case_id") or "").strip()
        result = result_map.get(case_id, "skipped")
        if result in stats:
            stats[result] += 1
    return stats


def merge_case_rows(base_rows: List[Dict[str, Any]], update_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ordered_ids: List[str] = []
    merged_map: Dict[str, Dict[str, Any]] = {}
    leftovers: List[Dict[str, Any]] = []

    for row in base_rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id") or "").strip()
        if not case_id:
            leftovers.append(row)
            continue
        if case_id not in merged_map:
            ordered_ids.append(case_id)
        merged_map[case_id] = row

    for row in update_rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id") or "").strip()
        if not case_id:
            leftovers.append(row)
            continue
        if case_id not in merged_map:
            ordered_ids.append(case_id)
        merged_map[case_id] = row

    merged: List[Dict[str, Any]] = []
    for case_id in ordered_ids:
        row = merged_map.get(case_id)
        if isinstance(row, dict):
            merged.append(row)
    merged.extend(leftovers)
    return merged


def merge_debug_outputs(out_root: str, previous_rows: Dict[str, List[Dict[str, Any]]]) -> None:
    targets = {
        "evidence": os.path.join(out_root, "debug_verify", "动态调试证据.json"),
        "process": os.path.join(out_root, "debug_verify", "动态调试过程.json"),
        "poc": os.path.join(out_root, "debug_verify", "动态调试PoC.json"),
        "func_trace": os.path.join(out_root, "debug_verify", "函数追踪证据.json"),
    }
    for key, path in targets.items():
        base_rows = previous_rows.get(key) or []
        update_rows = load_json_list(path)
        merged_rows = merge_case_rows(base_rows, update_rows)
        write_json(path, merged_rows)


def render_summary_md(summary: Dict[str, Any]) -> str:
    selected_rows = summary.get("selected_case_rows") if isinstance(summary.get("selected_case_rows"), list) else []
    result_stats = summary.get("result_stats") if isinstance(summary.get("result_stats"), dict) else {}
    output_paths = summary.get("output_paths") if isinstance(summary.get("output_paths"), dict) else {}
    ai_config = summary.get("ai_config") if isinstance(summary.get("ai_config"), dict) else {}
    target_statuses = summary.get("target_statuses") if isinstance(summary.get("target_statuses"), list) else []
    target_statuses_text = "、".join([str(x) for x in target_statuses]) if target_statuses else "conditional"

    lines = [
        "# AI 深入审计阶段报告",
        "",
        f"- 生成时间：{summary.get('generated_at') or '-'}",
        f"- 本次运行ID：`{summary.get('run_id') or '-'}`",
        f"- 阶段状态：{summary.get('stage_status') or '-'}",
        f"- 运行耗时：{summary.get('duration_ms') or 0} ms",
        f"- 目标项目：`{summary.get('project_root') or '-'}`",
        f"- Docker执行：`{'是' if summary.get('executed_in_container') else '否'}`",
        "",
        "## 一、执行策略",
        "- 审计方式：基于已有漏洞报告 + 对应源码定位做二次深审。",
        "- 验证方式：Docker 内真实请求验证（curl），并记录动态调试证据。",
        f"- 目标状态：`{target_statuses_text}`（默认仅 `conditional`）。",
        "- 执行策略：仅 AI 绕过循环（不使用字典 payload）。",
        "- 目标规则：多轮验证后输出客观状态（已确认/有条件成立/已排除/已跳过）。",
        "",
        "## 二、AI 深审配置",
        f"- 模型：`{ai_config.get('ai_model') or '-'}`",
        f"- 预算：`{ai_config.get('ai_rounds') or 0} x {ai_config.get('ai_candidates_per_round') or 0}`",
        f"- 单轮超时：`{ai_config.get('ai_timeout') or 0}s`",
        f"- AI实时补全：`{'开启' if ai_config.get('ai_realtime') else '关闭'}`",
        f"- 强制AI尝试：`{'开启' if ai_config.get('ai_force_all') else '关闭'}`",
        f"- AI-only绕过：`{'开启' if summary.get('ai_only_bypass') else '关闭'}`",
        f"- 目标收敛：`{'直到已确认' if ai_config.get('until_confirmed') else '允许有条件成立'}`",
        f"- 建议集状态：`{summary.get('ai_suggestions_status') or '-'}`",
        "",
        "## 三、深审用例清单（按优先级）",
    ]

    if selected_rows:
        lines.append(
            markdown_table(
                ["case_id", "上轮动态状态", "严重度", "模块", "位置", "标题"],
                selected_rows,
            )
        )
    else:
        lines.append("（无可执行用例）")

    lines += [
        "",
        "## 四、执行结果统计",
        "| 指标 | 数值 |",
        "|---|---|",
        f"| 目标状态总数 | {summary.get('target_case_count', 0)} |",
        f"| 本轮选中数 | {summary.get('selected_case_count', 0)} |",
        f"| 实际尝试数 | {summary.get('attempted_case_count', 0)} |",
        f"| 升级为已确认 | {summary.get('promoted_to_confirmed_count', 0)} |",
        f"| 深审结果总数 | {result_stats.get('total', 0)} |",
        f"| 已确认 | {result_stats.get('confirmed', 0)} |",
        f"| 有条件成立 | {result_stats.get('conditional', 0)} |",
        "",
        "## 五、结果文件",
        f"- 深审摘要（JSON）：`{output_paths.get('summary_json') or '-'}`",
        f"- 深审用例（JSON）：`{output_paths.get('selected_cases_json') or '-'}`",
        f"- 动态证据（JSON）：`{output_paths.get('debug_evidence_json') or '-'}`",
        f"- 动态过程（MD）：`{output_paths.get('debug_process_md') or '-'}`",
        f"- AI 报告（MD）：`{output_paths.get('ai_verify_md') or '-'}`",
        "",
        "## 六、执行命令",
        "```bash",
        str(summary.get("executed_cmd") or "-"),
        "```",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ensure_running_in_container()

    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--ai-model", default=resolve_default_model(), help="AI model")
    ap.add_argument("--ai-rounds", type=int, default=env_int("AI_DEEP_ROUNDS", 2), help="AI rounds")
    ap.add_argument(
        "--ai-candidates-per-round",
        type=int,
        default=env_int("AI_DEEP_CANDIDATES_PER_ROUND", 5),
        help="AI candidates per round",
    )
    ap.add_argument("--ai-timeout", type=int, default=env_int("AI_DEEP_TIMEOUT", 30), help="AI timeout seconds")
    ap.add_argument("--max-cases", type=int, default=env_int("AI_DEEP_MAX_CASES", 0), help="Limit deep-audit case count")
    ap.add_argument(
        "--target-statuses",
        default=env_text("AI_DEEP_TARGET_STATUSES", ",".join(DEFAULT_TARGET_STATUSES)),
        help="Comma-separated dynamic statuses to target (default: conditional)",
    )
    ap.add_argument("--trace-verbose", action="store_true", help="Write trace cases")
    ap.add_argument("--ai-realtime", dest="ai_realtime", action="store_true", default=env_bool("AI_DEEP_REALTIME", True))
    ap.add_argument("--disable-ai-realtime", dest="ai_realtime", action="store_false")
    ap.add_argument("--ai-force-all", dest="ai_force_all", action="store_true", default=env_bool("AI_DEEP_FORCE_ALL", True))
    ap.add_argument("--disable-ai-force-all", dest="ai_force_all", action="store_false")
    ap.add_argument(
        "--until-confirmed",
        dest="until_confirmed",
        action="store_true",
        default=env_bool("AI_DEEP_UNTIL_CONFIRMED", True),
    )
    ap.add_argument("--allow-conditional-stop", dest="until_confirmed", action="store_false")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    deep_dir = os.path.join(out_root, "ai_deep_audit")
    os.makedirs(deep_dir, exist_ok=True)

    started = time.time()
    cases = ensure_cases(project_root, out_root)
    finding_meta = load_finding_meta(out_root)
    previous_dynamic = load_previous_dynamic_result(out_root)
    target_statuses = parse_target_statuses(args.target_statuses)
    ordered_cases = prioritize_cases(cases, finding_meta, previous_dynamic)
    target_cases = [
        case for case in ordered_cases
        if previous_dynamic.get(str(case.get("case_id") or "").strip(), "skipped") in target_statuses
    ]
    target_case_count = len(target_cases)

    if args.max_cases and args.max_cases > 0:
        target_cases = target_cases[: int(args.max_cases)]

    selected_case_rows: List[List[str]] = []
    for case in target_cases:
        case_id = str(case.get("case_id") or "")
        meta = finding_meta.get(case_id) or {}
        prev_result = previous_dynamic.get(case_id, "未执行")
        selected_case_rows.append(
            [
                case_id or "-",
                prev_result,
                str(meta.get("severity") or "low"),
                str(case.get("module") or str(meta.get("module") or "-")),
                str(meta.get("location") or str(case.get("source_path") or "-")),
                str(meta.get("title") or "-"),
            ]
        )

    selected_cases_path = os.path.join(deep_dir, "ai_deep_cases.json")
    write_json(selected_cases_path, target_cases)
    previous_debug_rows = {
        "evidence": load_json_list(os.path.join(out_root, "debug_verify", "动态调试证据.json")),
        "process": load_json_list(os.path.join(out_root, "debug_verify", "动态调试过程.json")),
        "poc": load_json_list(os.path.join(out_root, "debug_verify", "动态调试PoC.json")),
        "func_trace": load_json_list(os.path.join(out_root, "debug_verify", "函数追踪证据.json")),
    }

    suggestions_path = os.path.join(out_root, "mcp_raw", "ai-confirm-mcp-debug.json")
    if args.ai_realtime and os.path.exists(suggestions_path):
        ai_suggestions_status = "ok"
    elif args.ai_realtime:
        ai_suggestions_status = "failed"
    else:
        ai_suggestions_status = "disabled"

    debug_cmd = [
        sys.executable or "python3",
        os.path.join(os.path.dirname(__file__), "debug_runner.py"),
        "--project",
        project_root,
        "--out",
        out_root,
        "--cases",
        selected_cases_path,
        "--ai-model",
        str(args.ai_model or "sonnet"),
        "--ai-rounds",
        str(max(0, int(args.ai_rounds))),
        "--ai-candidates-per-round",
        str(max(0, int(args.ai_candidates_per_round))),
        "--ai-timeout",
        str(max(1, int(args.ai_timeout))),
        "--ai-only-bypass",
    ]
    if args.trace_verbose:
        debug_cmd.append("--trace-verbose")
    if args.ai_force_all:
        debug_cmd.append("--ai-force-all")
    if args.until_confirmed:
        debug_cmd.append("--until-confirmed")
    else:
        debug_cmd.append("--allow-conditional-stop")
    if args.ai_realtime:
        debug_cmd.extend(["--ai-realtime", "--ai-runtime-status", ai_suggestions_status])
        if ai_suggestions_status == "ok":
            debug_cmd.extend(["--ai-suggestions", suggestions_path])
    else:
        debug_cmd.extend(["--disable-ai-realtime", "--ai-runtime-status", "disabled"])

    proc = subprocess.run(debug_cmd, cwd=project_root, capture_output=False)
    rc = int(proc.returncode)
    merge_debug_outputs(out_root, previous_debug_rows)

    _ = summarize_debug_results(out_root)
    current_dynamic = load_debug_result_map(out_root)
    result_stats = summarize_selected_results(target_cases, current_dynamic)
    selected_case_ids = {str(case.get("case_id") or "").strip() for case in target_cases if str(case.get("case_id") or "").strip()}
    attempted_case_count = sum(1 for cid in selected_case_ids if cid in current_dynamic)
    promoted_to_confirmed_count = 0
    for cid in selected_case_ids:
        prev = previous_dynamic.get(cid, "skipped")
        now = current_dynamic.get(cid, "skipped")
        if prev != "confirmed" and now == "confirmed":
            promoted_to_confirmed_count += 1
    duration_ms = int((time.time() - started) * 1000)

    summary_json_path = os.path.join(deep_dir, "ai_deep_audit_summary.json")
    summary_md_path = os.path.join(deep_dir, "AI深入审计阶段报告.md")
    run_id = str(os.environ.get("AUDIT_RUN_ID") or "").strip()
    if not run_id:
        run_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
    summary: Dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "run_id": run_id,
        "project_root": project_root,
        "out_root": out_root,
        "executed_in_container": bool(running_in_container()),
        "stage_status": "done" if rc == 0 else "failed",
        "duration_ms": duration_ms,
        "target_statuses": target_statuses,
        "target_case_count": target_case_count,
        "selected_case_count": len(target_cases),
        "attempted_case_count": attempted_case_count,
        "promoted_to_confirmed_count": promoted_to_confirmed_count,
        "ai_only_bypass": True,
        "selected_case_rows": selected_case_rows,
        "result_stats": result_stats,
        "executed_cmd": shell_join(debug_cmd),
        "return_code": rc,
        "ai_suggestions_status": ai_suggestions_status,
        "ai_config": {
            "ai_model": str(args.ai_model or "sonnet"),
            "ai_rounds": max(0, int(args.ai_rounds)),
            "ai_candidates_per_round": max(0, int(args.ai_candidates_per_round)),
            "ai_timeout": max(1, int(args.ai_timeout)),
            "ai_realtime": bool(args.ai_realtime),
            "ai_force_all": bool(args.ai_force_all),
            "until_confirmed": bool(args.until_confirmed),
            "target_statuses": target_statuses,
            "ai_only_bypass": True,
        },
        "output_paths": {
            "summary_json": summary_json_path,
            "selected_cases_json": selected_cases_path,
            "debug_evidence_json": os.path.join(out_root, "debug_verify", "动态调试证据.json"),
            "debug_process_md": os.path.join(out_root, "debug_verify", "动态调试过程.md"),
            "ai_verify_md": os.path.join(out_root, "AI深入验证最终报告.md"),
        },
    }
    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_summary_md(summary))

    print(f"ai_deep_audit_summary.json written: {summary_json_path}")
    print(f"AI深入审计阶段报告.md written: {summary_md_path}")

    if rc != 0:
        raise SystemExit(rc)


if __name__ == "__main__":
    main()
