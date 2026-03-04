#!/usr/bin/env python3
import argparse
import json
import os
import re
from typing import Dict, List, Tuple

from common import build_output_root, write_json, write_text

POLICY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "_config", "ai_audit_policy.json"))
EVIDENCE_CHECK_JSON_CN = "证据校验.json"
EVIDENCE_CHECK_MD_CN = "证据校验.md"
PRIMARY_STATIC_MD = "最终静态审计结果.md"
PRIMARY_DYNAMIC_MD = "动态debug审计报告.md"
PRIMARY_AI_VERIFY_MD = "AI深入验证最终报告.md"
ARCHIVE_ROOT_DIR = "归档"
ARCHIVE_STAGE_DIR = os.path.join(ARCHIVE_ROOT_DIR, "阶段报告")
ARCHIVE_DEBUG_DIR = os.path.join(ARCHIVE_ROOT_DIR, "调试证据")
ARCHIVE_BURP_DIR = os.path.join(ARCHIVE_ROOT_DIR, "Burp模板")
ARCHIVE_QUALITY_DIR = os.path.join(ARCHIVE_ROOT_DIR, "质量门禁")
ARCHIVE_BINDING_DIR = os.path.join(ARCHIVE_ROOT_DIR, "结论绑定")
STEP_GATE_DIR = os.path.join(ARCHIVE_QUALITY_DIR, "步骤门禁")
AI_DEEP_DIR = "ai_deep_audit"
AI_DEEP_SUMMARY_JSON = "ai_deep_audit_summary.json"
AI_DEEP_STAGE_MD = "AI深入审计阶段报告.md"
RUN_CONTEXT_PATH = os.path.join("_meta", "run_context.json")
DEBUG_RUNTIME_JSON = os.path.join("debug_verify", "动态运行元信息.json")

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


def has_ai_enrichment(f: Dict) -> bool:
    if not isinstance(f, dict):
        return False
    if isinstance(f.get("ai_table"), dict):
        return True
    if str(f.get("exploitability") or "").strip():
        return True
    return False


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


def pick_existing_path(candidates: List[str]) -> str:
    for p in candidates:
        if os.path.exists(p):
            return p
    return candidates[0] if candidates else ""


def exists_any(candidates: List[str]) -> bool:
    return any(os.path.exists(p) for p in candidates)


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


def is_fallback_finding(f: Dict) -> bool:
    notes = str((f or {}).get("notes") or "").lower()
    if "兜底扫描" in notes:
        return True
    if "fallback" in notes:
        return True
    return False


def validate_finding(f: Dict, source_path: str, require_ai: bool) -> List[str]:
    issues = []
    policy = load_policy()
    min_evidence = int(policy.get("evidence_score_min", 0))
    ai_enriched = has_ai_enrichment(f)
    trigger_only = is_trigger_only(f)
    fallback_finding = is_fallback_finding(f)
    for k in REQUIRED_FIELDS:
        # exploitability is required only when AI enrichment exists for this finding.
        if k == "exploitability" and not ai_enriched:
            continue
        # Trigger-only or fallback findings may not have actionable PoC strings yet.
        if k == "poc" and (trigger_only or fallback_finding):
            continue
        if k not in f or f.get(k) in (None, ""):
            issues.append(f"missing:{k}")

    sink = f.get("sink") or {}
    if not sink.get("file"):
        issues.append("sink:file")
    if not (is_policy_finding(f, source_path) or is_var_override(f, source_path) or trigger_only):
        if not sink.get("line"):
            issues.append("sink:line")

    controllability = f.get("controllability")
    if controllability not in ("fully", "conditional", "none"):
        issues.append("controllability:invalid")

    severity = (f.get("severity") or "").lower()
    if severity and severity not in ("high", "medium", "low", "info"):
        issues.append("severity:invalid")

    # Evidence chain completeness
    if not (is_policy_finding(f, source_path) or is_var_override(f, source_path) or trigger_only or fallback_finding):
        if f.get("source") in (None, ""):
            issues.append("missing:source")
        taint = f.get("taint")
        if not isinstance(taint, list) or len(taint) == 0:
            issues.append("missing:taint")

    if ai_enriched:
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

    if ai_enriched:
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
    def human_issue_title(raw: str) -> str:
        text = str(raw or "").strip()
        if not text:
            return "未命名问题"
        exact = {
            "Missing auth 3-file reports": "缺少鉴权三件套报告",
            "Missing vuln trigger analysis": "缺少依赖漏洞触发点分析",
            "Missing module report dir": "缺少模块报告目录",
            "Missing module report": "缺少模块报告",
            "Debug skipped ratio too high": "动态调试跳过比例过高",
            "Debug skipped ratio warning": "动态调试跳过比例预警",
            "Invalid debug_evidence entry": "动态调试证据条目格式无效",
            "Missing debug field": "动态调试证据缺少字段",
            "Invalid debug result": "动态调试结果值无效",
            "Invalid change_type": "动态变化类型无效",
            "Unknown change_type": "动态变化类型未知",
            "Missing trace_chain": "缺少调用链追踪",
            "Absolute source_path": "source_path 不应为绝对路径",
            "Invalid source_path": "source_path 格式无效",
            "Missing debug evidence for finding": "漏洞缺少动态调试证据",
            "Strict dynamic verification not completed": "严格动态验证未完成",
            "Strict AI realtime status invalid": "严格AI实时验证状态不合规",
            "Strict AI attempts missing": "严格AI验证缺少实际尝试",
            "Strict confirmed target not reached": "严格模式未达到已确认状态",
            "final_report main_cases missing": "主报告缺少 main_cases 字段",
            "Invalid dynamic_status": "dynamic_status 值无效",
            "High/Critical case missing dynamic_status": "高危案例缺少 dynamic_status",
            "High/Critical case dynamic_status invalid": "高危案例 dynamic_status 无效",
            "High/Critical case missing dynamic_supported": "高危案例缺少 dynamic_supported",
            "High/Critical case missing dynamic_reason": "高危案例缺少 dynamic_reason",
            "High/Critical case missing evidence_refs": "高危案例缺少 evidence_refs",
            "final_report missing debug evidence reference": "主报告缺少动态证据引用",
            "final_report missing appendix section": "主报告缺少附录入口章节",
            "final_report missing static-dynamic matrix": "主报告缺少静态-动态支持矩阵",
            "final_report case missing appendix anchor link": "主报告案例缺少附录锚点链接",
            "final_report unreadable": "主报告无法读取",
            "final_report_appendix unreadable": "技术附录无法读取",
            "Missing phase meta directory": "缺少阶段元信息目录",
            "Missing phase meta file": "缺少阶段元信息文件",
            "Missing termination decisions": "缺少终止决策信息",
            "Missing static main report": "缺少最终静态审计结果主报告",
            "Missing dynamic main report": "缺少动态debug审计主报告",
            "Missing AI verify main report": "缺少AI深入验证最终报告",
            "AI verify report missing section": "AI深验报告缺少必需章节",
            "AI verify report has final decision section": "AI深验报告不应包含最终判定章节",
            "AI verify report has request sample section": "AI深验报告不应包含请求样例章节",
            "AI verify report missing project-conclusion table": "AI深验报告缺少项目/结论表",
            "AI verify report missing round process table": "AI深验报告缺少逐轮调试过程表",
            "AI verify report missing Burp code block": "AI深验报告缺少Burp复现代码块",
            "AI verify report matrix status not Chinese": "AI深验报告结论对照状态非中文",
            "AI verify report should hide rejected/skipped details": "AI深验报告验证过程不应展示已排除/已跳过明细",
            "Missing AI deep audit summary": "缺少AI深入审计阶段摘要",
            "Missing AI deep audit report": "缺少AI深入审计阶段报告",
            "AI deep audit stage not completed": "AI深入审计阶段未完成",
            "AI deep audit missing target statuses": "AI深入审计缺少目标状态配置",
            "AI deep audit not in ai-only bypass mode": "AI深入审计未启用AI-only绕过模式",
            "AI deep audit target selection incomplete": "AI深入审计目标案例选取不完整",
            "AI deep audit target execution incomplete": "AI深入审计目标案例执行不完整",
            "Missing run context": "缺少本次运行上下文",
            "Run context unreadable": "本次运行上下文不可读",
            "Required stage not executed": "必需阶段未执行完成",
            "Missing debug runtime metadata": "缺少动态运行元信息",
            "Debug runtime metadata unreadable": "动态运行元信息不可读",
            "Run ID mismatch": "运行ID不一致",
            "Stage not running in docker": "阶段未在Docker内执行",
            "Missing archive directory": "缺少归档目录",
            "Missing step verifier gate": "缺少步骤质检门禁文件",
            "Unreadable step verifier gate": "步骤质检门禁文件不可读",
            "Step verifier gate blocked": "步骤质检未通过",
        }
        if text in exact:
            return exact[text]
        # 通用词替换，兼容旧文案
        text = text.replace("Missing ", "缺少")
        text = text.replace("missing ", "缺少")
        text = text.replace("Invalid ", "无效的")
        text = text.replace("Unreadable ", "无法读取")
        text = text.replace("final_report", "主报告")
        text = text.replace("debug_evidence", "动态调试证据")
        return text

    lines = [
        "# 证据链校验报告",
        "",
        f"发现总数：{summary['total']}",
        f"通过数量：{summary['complete']}",
        f"问题数量：{summary['incomplete']}",
        "",
        "## 问题列表",
    ]
    if not issues:
        lines.append("- 无")
    for it in issues:
        lines.append(f"- {it['id']} {human_issue_title(it.get('title'))}（{it['source']}） -> {', '.join(it['issues'])}")
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
STATUS_CN_VALUES = {"已确认", "有条件成立", "已排除", "已跳过"}

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


def safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def debug_case_attempt_count(entry: Dict) -> int:
    if not isinstance(entry, dict):
        return 0
    for key in ("attempt_count", "request_attempt_count"):
        if key in entry:
            return max(0, safe_int(entry.get(key), 0))
    return 0


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


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
    strict_dynamic_verify_all = env_flag("STRICT_DYNAMIC_VERIFY_ALL", False)
    strict_ai_realtime = env_flag("STRICT_AI_REALTIME", False)
    strict_ai_require_attempt = env_flag("STRICT_AI_REQUIRE_ATTEMPT", False)
    strict_require_confirmed = env_flag("STRICT_REQUIRE_CONFIRMED", False)
    strict_block_skipped_ratio = env_flag("STRICT_BLOCK_DEBUG_SKIPPED_RATIO", False)
    module_reports = [
        "file_audit",
        "rce_audit",
        "ssrf_xxe_audit",
        "xss_ssti_audit",
        "csrf_audit",
        "var_override_audit",
        "serialize_audit",
    ]

    # New main report contract
    main_reports = [
        os.path.join(out_root, PRIMARY_STATIC_MD),
        os.path.join(out_root, PRIMARY_DYNAMIC_MD),
        os.path.join(out_root, PRIMARY_AI_VERIFY_MD),
    ]
    if not os.path.exists(main_reports[0]):
        issues.append({"id": "MAIN-STATIC", "title": "Missing static main report", "source": PRIMARY_STATIC_MD, "issues": ["main_report:missing_static"]})
    if not os.path.exists(main_reports[1]):
        issues.append({"id": "MAIN-DYNAMIC", "title": "Missing dynamic main report", "source": PRIMARY_DYNAMIC_MD, "issues": ["main_report:missing_dynamic"]})
    if not os.path.exists(main_reports[2]):
        issues.append({"id": "MAIN-AI", "title": "Missing AI verify main report", "source": PRIMARY_AI_VERIFY_MD, "issues": ["main_report:missing_ai_verify"]})

    # Archive structure contract
    archive_dirs = [
        ARCHIVE_STAGE_DIR,
        ARCHIVE_DEBUG_DIR,
        ARCHIVE_BURP_DIR,
        ARCHIVE_QUALITY_DIR,
        ARCHIVE_BINDING_DIR,
        STEP_GATE_DIR,
    ]
    for rel in archive_dirs:
        abs_dir = os.path.join(out_root, rel)
        if not os.path.isdir(abs_dir):
            issues.append({"id": "ARCHIVE-DIR", "title": "Missing archive directory", "source": rel, "issues": [f"archive:missing:{rel}"]})

    run_context_data: Dict[str, Any] = {}
    run_id_expected = ""
    run_context_file = os.path.join(out_root, RUN_CONTEXT_PATH)
    if not os.path.exists(run_context_file):
        issues.append(
            {
                "id": "RUN-CONTEXT",
                "title": "Missing run context",
                "source": RUN_CONTEXT_PATH,
                "issues": ["run_context:missing"],
            }
        )
    else:
        try:
            run_context_data = json.load(open(run_context_file, "r", encoding="utf-8"))
            if not isinstance(run_context_data, dict):
                run_context_data = {}
        except Exception:
            run_context_data = {}
            issues.append(
                {
                    "id": "RUN-CONTEXT",
                    "title": "Run context unreadable",
                    "source": RUN_CONTEXT_PATH,
                    "issues": ["run_context:unreadable"],
                }
            )
    if run_context_data:
        run_id_expected = str(run_context_data.get("run_id") or "").strip()
        if not bool(run_context_data.get("executed_in_container")):
            issues.append(
                {
                    "id": "RUN-CONTEXT",
                    "title": "Stage not running in docker",
                    "source": RUN_CONTEXT_PATH,
                    "issues": ["run_context:not_in_container"],
                }
            )
        stage_map = run_context_data.get("stages") if isinstance(run_context_data.get("stages"), dict) else {}
        for required_stage in ("debug_verify", "ai_deep_audit"):
            stage_row = stage_map.get(required_stage) if isinstance(stage_map.get(required_stage), dict) else {}
            status = str(stage_row.get("status") or "").strip().lower()
            if status != "done":
                issues.append(
                    {
                        "id": required_stage,
                        "title": "Required stage not executed",
                        "source": RUN_CONTEXT_PATH,
                        "issues": [f"run_context:stage_not_done:{required_stage}:{status or 'missing'}"],
                    }
                )

    for pid in range(7):
        gate_rel = os.path.join(STEP_GATE_DIR, f"phase_{pid}_verifier.md")
        gate_abs = os.path.join(out_root, gate_rel)
        if not os.path.exists(gate_abs):
            issues.append(
                {
                    "id": f"STEP-GATE-{pid}",
                    "title": "Missing step verifier gate",
                    "source": gate_rel,
                    "issues": [f"step_gate:missing:phase_{pid}"],
                }
            )
            continue
        try:
            text = open(gate_abs, "r", encoding="utf-8").read()
        except Exception:
            issues.append(
                {
                    "id": f"STEP-GATE-{pid}",
                    "title": "Unreadable step verifier gate",
                    "source": gate_rel,
                    "issues": [f"step_gate:unreadable:phase_{pid}"],
                }
            )
            continue
        if "验收结论：PASS" not in text:
            issues.append(
                {
                    "id": f"STEP-GATE-{pid}",
                    "title": "Step verifier gate blocked",
                    "source": gate_rel,
                    "issues": [f"step_gate:not_pass:phase_{pid}"],
                }
            )

    phase7_rel = os.path.join(STEP_GATE_DIR, "phase_7_verifier.md")
    phase7_abs = os.path.join(out_root, phase7_rel)
    if os.path.exists(phase7_abs):
        try:
            text7 = open(phase7_abs, "r", encoding="utf-8").read()
            if "验收结论：PASS" not in text7:
                issues.append(
                    {
                        "id": "STEP-GATE-7",
                        "title": "Step verifier gate blocked",
                        "source": phase7_rel,
                        "issues": ["step_gate:not_pass:phase_7"],
                    }
                )
        except Exception:
            issues.append(
                {
                    "id": "STEP-GATE-7",
                    "title": "Unreadable step verifier gate",
                    "source": phase7_rel,
                    "issues": ["step_gate:unreadable:phase_7"],
                }
            )

    debug_runtime_file = os.path.join(out_root, DEBUG_RUNTIME_JSON)
    debug_runtime_data: Dict[str, Any] = {}
    if not os.path.exists(debug_runtime_file):
        issues.append(
            {
                "id": "DEBUG-RUNTIME",
                "title": "Missing debug runtime metadata",
                "source": DEBUG_RUNTIME_JSON,
                "issues": ["debug_runtime:missing"],
            }
        )
    else:
        try:
            debug_runtime_data = json.load(open(debug_runtime_file, "r", encoding="utf-8"))
            if not isinstance(debug_runtime_data, dict):
                debug_runtime_data = {}
        except Exception:
            debug_runtime_data = {}
            issues.append(
                {
                    "id": "DEBUG-RUNTIME",
                    "title": "Debug runtime metadata unreadable",
                    "source": DEBUG_RUNTIME_JSON,
                    "issues": ["debug_runtime:unreadable"],
                }
            )
    if debug_runtime_data:
        if run_id_expected and str(debug_runtime_data.get("run_id") or "").strip() != run_id_expected:
            issues.append(
                {
                    "id": "DEBUG-RUNTIME",
                    "title": "Run ID mismatch",
                    "source": DEBUG_RUNTIME_JSON,
                    "issues": ["debug_runtime:run_id_mismatch"],
                }
            )
        if not bool(debug_runtime_data.get("executed_in_container")):
            issues.append(
                {
                    "id": "DEBUG-RUNTIME",
                    "title": "Stage not running in docker",
                    "source": DEBUG_RUNTIME_JSON,
                    "issues": ["debug_runtime:not_in_container"],
                }
            )

    # AI verify report format checks
    ai_verify_path = os.path.join(out_root, PRIMARY_AI_VERIFY_MD)
    if os.path.exists(ai_verify_path):
        try:
            ai_text = open(ai_verify_path, "r", encoding="utf-8").read()
        except Exception:
            ai_text = ""
            issues.append({"id": "MAIN-AI", "title": "AI verify report missing section", "source": PRIMARY_AI_VERIFY_MD, "issues": ["ai_verify:unreadable"]})
        if ai_text:
            required_sections = [
                "## 一、验证结果",
                "## 二、验证过程",
                "## 三、结论对照（静态 / 动态 / AI）",
                "## 四、证据索引",
            ]
            for sec in required_sections:
                if sec not in ai_text:
                    issues.append({"id": "MAIN-AI", "title": "AI verify report missing section", "source": PRIMARY_AI_VERIFY_MD, "issues": [f"ai_verify:missing_section:{sec}"]})
            if "最终判定" in ai_text:
                issues.append({"id": "MAIN-AI", "title": "AI verify report has final decision section", "source": PRIMARY_AI_VERIFY_MD, "issues": ["ai_verify:has_final_decision"]})
            if "请求样例" in ai_text:
                issues.append({"id": "MAIN-AI", "title": "AI verify report has request sample section", "source": PRIMARY_AI_VERIFY_MD, "issues": ["ai_verify:has_request_sample"]})
            has_real_process_case = bool(re.search(r"^###\s+\d+\)\s+", ai_text, flags=re.MULTILINE))
            if has_real_process_case and not re.search(r"^\|\s*项目\s*\|\s*结论\s*\|", ai_text, flags=re.MULTILINE):
                issues.append({"id": "MAIN-AI", "title": "AI verify report missing project-conclusion table", "source": PRIMARY_AI_VERIFY_MD, "issues": ["ai_verify:missing_project_conclusion_table"]})
            if has_real_process_case and "#### 动态调试过程（逐轮）" not in ai_text:
                issues.append({"id": "MAIN-AI", "title": "AI verify report missing round process table", "source": PRIMARY_AI_VERIFY_MD, "issues": ["ai_verify:missing_round_process_heading"]})
            if has_real_process_case and not re.search(r"^\|\s*轮次\s*\|\s*Payload来源\s*\|\s*请求来源\s*\|", ai_text, flags=re.MULTILINE):
                issues.append({"id": "MAIN-AI", "title": "AI verify report missing round process table", "source": PRIMARY_AI_VERIFY_MD, "issues": ["ai_verify:missing_round_process_table"]})
            if has_real_process_case and "```http" not in ai_text:
                issues.append({"id": "MAIN-AI", "title": "AI verify report missing Burp code block", "source": PRIMARY_AI_VERIFY_MD, "issues": ["ai_verify:missing_http_code_block"]})
            sec2_start = ai_text.find("## 二、验证过程")
            sec3_start = ai_text.find("## 三、结论对照（静态 / 动态 / AI）")
            if sec2_start >= 0 and sec3_start > sec2_start:
                sec2_text = ai_text[sec2_start:sec3_start]
                for line in sec2_text.splitlines():
                    if not line.startswith("|"):
                        continue
                    if "状态" not in line:
                        continue
                    if ("已排除" in line) or ("已跳过" in line):
                        issues.append(
                            {
                                "id": "MAIN-AI",
                                "title": "AI verify report should hide rejected/skipped details",
                                "source": PRIMARY_AI_VERIFY_MD,
                                "issues": ["ai_verify:has_rejected_or_skipped_detail"],
                            }
                        )
                        break

            in_matrix = False
            for line in ai_text.splitlines():
                if line.startswith("## 三、结论对照"):
                    in_matrix = True
                    continue
                if in_matrix and line.startswith("## "):
                    in_matrix = False
                if not in_matrix:
                    continue
                if not line.startswith("|"):
                    continue
                if "静态结论" in line or "---" in line:
                    continue
                cols = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cols) < 4:
                    continue
                case_id_val = cols[0]
                dynamic_val = cols[2]
                ai_val = cols[3]
                if case_id_val in {"", "-"} and dynamic_val in {"", "-"} and ai_val in {"", "-"}:
                    continue
                if dynamic_val not in STATUS_CN_VALUES or ai_val not in STATUS_CN_VALUES:
                    issues.append(
                        {
                            "id": "MAIN-AI",
                            "title": "AI verify report matrix status not Chinese",
                            "source": PRIMARY_AI_VERIFY_MD,
                            "issues": [f"ai_verify:matrix_status_not_cn:{dynamic_val}/{ai_val}"],
                        }
                    )
                    break

    # AI deep audit stage checks
    ai_deep_dir = os.path.join(out_root, AI_DEEP_DIR)
    ai_deep_summary = os.path.join(ai_deep_dir, AI_DEEP_SUMMARY_JSON)
    ai_deep_report = os.path.join(ai_deep_dir, AI_DEEP_STAGE_MD)
    ai_deep_data: Dict[str, Any] = {}
    if not os.path.exists(ai_deep_summary):
        issues.append(
            {
                "id": "AI-DEEP-AUDIT",
                "title": "Missing AI deep audit summary",
                "source": AI_DEEP_DIR,
                "issues": ["ai_deep_audit:missing_summary_json"],
            }
        )
    else:
        try:
            ai_deep_data = json.load(open(ai_deep_summary, "r", encoding="utf-8"))
        except Exception:
            ai_deep_data = {}
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "Missing AI deep audit summary",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": ["ai_deep_audit:summary_unreadable"],
                }
            )
        stage_status = str((ai_deep_data or {}).get("stage_status") or "").strip().lower()
        if stage_status and stage_status != "done":
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "AI deep audit stage not completed",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": [f"ai_deep_audit:stage_status:{stage_status}"],
                }
            )
        if run_id_expected and str((ai_deep_data or {}).get("run_id") or "").strip() != run_id_expected:
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "Run ID mismatch",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": ["ai_deep_audit:run_id_mismatch"],
                }
            )
        if not bool((ai_deep_data or {}).get("executed_in_container")):
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "Stage not running in docker",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": ["ai_deep_audit:not_in_container"],
                }
            )
        target_statuses = (ai_deep_data or {}).get("target_statuses")
        if not isinstance(target_statuses, list) or not target_statuses:
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "AI deep audit missing target statuses",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": ["ai_deep_audit:missing_target_statuses"],
                }
            )
        if not bool((ai_deep_data or {}).get("ai_only_bypass")):
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "AI deep audit not in ai-only bypass mode",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": ["ai_deep_audit:ai_only_bypass_required"],
                }
            )
        target_case_count = int((ai_deep_data or {}).get("target_case_count") or 0)
        selected_case_count = int((ai_deep_data or {}).get("selected_case_count") or 0)
        attempted_case_count = int((ai_deep_data or {}).get("attempted_case_count") or 0)
        if selected_case_count < target_case_count:
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "AI deep audit target selection incomplete",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": [f"ai_deep_audit:target_selection_incomplete:{selected_case_count}/{target_case_count}"],
                }
            )
        if attempted_case_count < selected_case_count:
            issues.append(
                {
                    "id": "AI-DEEP-AUDIT",
                    "title": "AI deep audit target execution incomplete",
                    "source": AI_DEEP_SUMMARY_JSON,
                    "issues": [f"ai_deep_audit:target_execution_incomplete:{attempted_case_count}/{selected_case_count}"],
                }
            )
    if not os.path.exists(ai_deep_report):
        issues.append(
            {
                "id": "AI-DEEP-AUDIT",
                "title": "Missing AI deep audit report",
                "source": AI_DEEP_DIR,
                "issues": ["ai_deep_audit:missing_report_md"],
            }
        )
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
    debug_json_candidates = [
        os.path.join(debug_dir, "动态调试证据.json"),
    ]
    debug_md_candidates = [
        os.path.join(debug_dir, "动态调试证据.md"),
    ]
    debug_json = pick_existing_path(debug_json_candidates)
    debug_md = pick_existing_path(debug_md_candidates)
    if finding_ids and not exists_any(debug_json_candidates):
        issues.append({"id": "DEBUG-EVIDENCE", "title": "Missing 动态调试证据.json", "source": "debug_verify", "issues": ["debug_evidence:missing_json"]})
    if finding_ids and not exists_any(debug_md_candidates):
        issues.append({"id": "DEBUG-EVIDENCE", "title": "Missing 动态调试证据.md", "source": "debug_verify", "issues": ["debug_evidence:missing_md"]})
    if os.path.exists(debug_json):
        try:
            data = json.load(open(debug_json, "r", encoding="utf-8"))
        except Exception:
            data = []
            issues.append({"id": "DEBUG-EVIDENCE", "title": "Unreadable 动态调试证据.json", "source": "debug_verify", "issues": ["debug_evidence:unreadable"]})
        if isinstance(data, list):
            data_rows = [entry for entry in data if isinstance(entry, dict)]
            executable_rows = [entry for entry in data_rows if debug_case_attempt_count(entry) > 0]
            ratio_rows = executable_rows if executable_rows else data_rows
            runtime_scope_rows: List[Dict] = []
            for entry in ratio_rows:
                result = str(entry.get("result") or "").strip().lower()
                skip_reason = str(entry.get("skip_reason") or "").strip().lower()
                if result == "skipped" and skip_reason in {"precheck_skip", "auth_required", "timeout"}:
                    continue
                runtime_scope_rows.append(entry)
            total_cases = len(runtime_scope_rows)
            skipped_cases = sum(
                1
                for entry in runtime_scope_rows
                if str(entry.get("result") or "").strip().lower() == "skipped"
                and str(entry.get("skip_reason") or "").strip().lower() == "runtime_skip"
            )
            if total_cases > 0:
                skipped_ratio = skipped_cases / total_cases
                if skipped_ratio > skipped_ratio_limit:
                    ratio_scope = "runtime_scope"
                    issue_title = "Debug skipped ratio too high" if strict_block_skipped_ratio else "Debug skipped ratio warning"
                    issue_code_prefix = "debug_evidence:skipped_ratio_high" if strict_block_skipped_ratio else "debug_evidence:skipped_ratio_warn"
                    issues.append({
                        "id": "DEBUG-EVIDENCE",
                        "title": issue_title,
                        "source": "debug_verify",
                        "issues": [
                            f"{issue_code_prefix}:{ratio_scope}:{skipped_cases}/{total_cases}>{skipped_ratio_limit:.2f}"
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
                skip_reason = str(entry.get("skip_reason") or "").strip().lower()
                if str(result) == "skipped":
                    if skip_reason not in {"precheck_skip", "runtime_skip", "timeout", "auth_required"}:
                        issues.append(
                            {
                                "id": case_id or "DEBUG-EVIDENCE",
                                "title": "Missing debug field",
                                "source": "debug_verify",
                                "issues": [f"debug_evidence:missing:skip_reason:{skip_reason or 'empty'}"],
                            }
                        )
                if strict_dynamic_verify_all and result == "skipped":
                    issues.append(
                        {
                            "id": case_id or "DEBUG-EVIDENCE",
                            "title": "Strict dynamic verification not completed",
                            "source": "debug_verify",
                            "issues": ["debug_evidence:strict_dynamic_skipped"],
                        }
                    )
                if strict_require_confirmed and result != "confirmed":
                    issues.append(
                        {
                            "id": case_id or "DEBUG-EVIDENCE",
                            "title": "Strict confirmed target not reached",
                            "source": "debug_verify",
                            "issues": [f"debug_evidence:strict_confirmed_required:{result or 'missing'}"],
                        }
                    )
                if change_type not in ("no_change", "weak_change", "strong_change", "unknown"):
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Invalid change_type", "source": "debug_verify", "issues": ["debug_evidence:change_type_invalid"]})
                if result != "skipped" and change_type == "unknown":
                    issues.append({"id": case_id or "DEBUG-EVIDENCE", "title": "Unknown change_type", "source": "debug_verify", "issues": ["debug_evidence:change_type_unknown"]})
                ai_status = str(entry.get("ai_realtime_status") or "").strip().lower()
                if strict_ai_realtime and ai_status != "ok":
                    issues.append(
                        {
                            "id": case_id or "DEBUG-EVIDENCE",
                            "title": "Strict AI realtime status invalid",
                            "source": "debug_verify",
                            "issues": [f"debug_evidence:strict_ai_status_invalid:{ai_status or 'missing'}"],
                        }
                    )
                if strict_ai_require_attempt:
                    try:
                        ai_attempt_count = int(entry.get("ai_attempt_count") or 0)
                    except Exception:
                        ai_attempt_count = 0
                    if ai_attempt_count <= 0:
                        issues.append(
                            {
                                "id": case_id or "DEBUG-EVIDENCE",
                                "title": "Strict AI attempts missing",
                                "source": "debug_verify",
                                "issues": ["debug_evidence:strict_ai_attempt_missing"],
                            }
                        )
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
    final_json_candidates = [
        os.path.join(out_root, ARCHIVE_BINDING_DIR, "总报告.json"),
        os.path.join(out_root, ARCHIVE_BINDING_DIR, "最终报告.json"),
        os.path.join(out_root, "总报告.json"),
        os.path.join(out_root, "最终报告.json"),
    ]
    final_md_candidates = [
        os.path.join(out_root, ARCHIVE_BINDING_DIR, "总报告.md"),
        os.path.join(out_root, ARCHIVE_BINDING_DIR, "最终报告.md"),
        os.path.join(out_root, "总报告.md"),
        os.path.join(out_root, "最终报告.md"),
    ]
    appendix_md_candidates = [
        os.path.join(out_root, ARCHIVE_BINDING_DIR, "总报告_技术附录.md"),
        os.path.join(out_root, ARCHIVE_BINDING_DIR, "最终报告_技术附录.md"),
        os.path.join(out_root, "总报告_技术附录.md"),
        os.path.join(out_root, "最终报告_技术附录.md"),
    ]
    final_json = pick_existing_path(final_json_candidates)
    final_md = pick_existing_path(final_md_candidates)
    appendix_md = pick_existing_path(appendix_md_candidates)

    if finding_ids and not exists_any(final_json_candidates):
        issues.append(
            {
                "id": "FINAL-REPORT",
                "title": "missing 总报告.json",
                "source": os.path.basename(final_json) or "总报告.json",
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
                    "title": "总报告.json unreadable",
                    "source": os.path.basename(final_json) or "总报告.json",
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
                        "source": os.path.basename(final_json) or "总报告.json",
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
                                "source": os.path.basename(final_json) or "总报告.json",
                                "issues": [f"final_report:dynamic_status_invalid:{dynamic_status}"],
                            }
                        )

                    if severity in ("critical", "high"):
                        if not dynamic_status:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing dynamic_status",
                                    "source": os.path.basename(final_json) or "总报告.json",
                                    "issues": ["final_report:high_missing_dynamic_status"],
                                }
                            )
                        elif dynamic_status not in DYNAMIC_STATUS_VALUES:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case dynamic_status invalid",
                                    "source": os.path.basename(final_json) or "总报告.json",
                                    "issues": ["final_report:high_dynamic_status_invalid"],
                                }
                            )

                        if not has_dynamic_supported:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing dynamic_supported",
                                    "source": os.path.basename(final_json) or "总报告.json",
                                    "issues": ["final_report:high_missing_dynamic_supported"],
                                }
                            )
                        if not dynamic_reason:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing dynamic_reason",
                                    "source": os.path.basename(final_json) or "总报告.json",
                                    "issues": ["final_report:high_missing_dynamic_reason"],
                                }
                            )
                        if not isinstance(refs, list) or len(refs) == 0:
                            issues.append(
                                {
                                    "id": case_id,
                                    "title": "High/Critical case missing evidence_refs",
                                    "source": os.path.basename(final_json) or "总报告.json",
                                    "issues": ["final_report:high_missing_evidence_refs"],
                                }
                            )

    if finding_ids and os.path.exists(final_md):
        try:
            text = open(final_md, "r", encoding="utf-8").read()
            if ("动态调试证据" not in text) and ("debug_evidence" not in text):
                issues.append({"id": "FINAL-REPORT", "title": "final_report missing debug evidence reference", "source": os.path.basename(final_md), "issues": ["final_report:missing_debug_reference"]})
            if not re.search(r"^##\s+\d+\.\s+附录入口\s*$", text, flags=re.MULTILINE):
                issues.append({"id": "FINAL-REPORT", "title": "final_report missing appendix section", "source": os.path.basename(final_md), "issues": ["final_report:missing_appendix_section"]})
            if "静态-动态证据支持矩阵" not in text:
                issues.append(
                    {
                        "id": "FINAL-REPORT",
                        "title": "final_report missing static-dynamic matrix",
                        "source": os.path.basename(final_md),
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
                ref = f"{os.path.basename(appendix_md)}#{anchor}"
                if ref not in text:
                    issues.append({
                        "id": case_id,
                        "title": "final_report case missing appendix anchor link",
                        "source": os.path.basename(final_md),
                        "issues": [f"final_report:missing_appendix_anchor:{anchor}"],
                    })
        except Exception:
            issues.append({"id": "FINAL-REPORT", "title": "final_report unreadable", "source": os.path.basename(final_md), "issues": ["final_report:unreadable"]})

    if os.path.exists(appendix_md):
        try:
            with open(appendix_md, "r", encoding="utf-8") as f:
                _ = f.read(1)
        except Exception:
            issues.append({"id": "FINAL-REPORT-APPENDIX", "title": "final_report_appendix unreadable", "source": os.path.basename(appendix_md), "issues": ["final_report_appendix:unreadable"]})
    elif finding_ids:
        issues.append({"id": "FINAL-REPORT-APPENDIX", "title": "missing 总报告_技术附录.md", "source": os.path.basename(appendix_md) or "总报告_技术附录.md", "issues": ["final_report_appendix:missing"]})

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
                for legacy_key, cn_key in (("Q1", "问题1"), ("Q2", "问题2"), ("Q3", "问题3")):
                    if legacy_key not in text and cn_key not in text:
                        missing.append(cn_key)
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

    entries = load_findings(out_root)
    # ai_confirm.json may exist even when no finding was actually enriched.
    # In that case we should not force AI-required fields on every finding.
    require_ai = False
    ai_confirm_path = os.path.join(out_root, "ai_confirm.json")
    if os.path.exists(ai_confirm_path):
        try:
            ai_meta = json.load(open(ai_confirm_path, "r", encoding="utf-8"))
        except Exception:
            ai_meta = {}
        updated = 0
        if isinstance(ai_meta, dict):
            try:
                updated = int(ai_meta.get("updated") or 0)
            except Exception:
                updated = 0
        if updated > 0:
            require_ai = True
        else:
            require_ai = any(has_ai_enrichment(f) for f, _ in entries)

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

    quality_dir = os.path.join(out_root, ARCHIVE_QUALITY_DIR)
    os.makedirs(quality_dir, exist_ok=True)
    write_json(os.path.join(quality_dir, EVIDENCE_CHECK_JSON_CN), report)
    write_text(os.path.join(quality_dir, EVIDENCE_CHECK_MD_CN), render_md(summary, issues))

    if args.strict and issues:
        raise SystemExit("证据校验失败")
    print(f"证据校验完成。问题数: {len(issues)}")


if __name__ == "__main__":
    main()
