#!/usr/bin/env python3
import atexit
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import re
import socket
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from common import build_output_root, walk_php_files, write_text
from audit_helpers import markdown_table

SCRIPT_DIR = os.path.dirname(__file__)


def resolve_python() -> str:
    env_py = os.environ.get("SKILLS_PYTHON")
    if env_py and os.path.exists(env_py):
        return env_py
    venv_py = os.path.join(os.path.dirname(SCRIPT_DIR), ".venv", "bin", "python3")
    if os.path.exists(venv_py):
        return venv_py
    return sys.executable or "python3"


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

PIPELINE_ORDER = [
    "route_mapper",
    "call_graph",
    "route_tracer",
    "ai_audit",
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "vuln_scanner",
    "mcp_adapter",
    "severity_enrich",
    "ai_confirm",
    "debug_verify",
    "ai_deep_audit",
    "report_refresh",
    "phase_attack_chain",
    "phase_report_index",
    "final_report",
    "evidence_check",
]

DEFAULT_MODULES = [
    "route_mapper",
    "call_graph",
    "route_tracer",
    "ai_audit",
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "mcp_adapter",
    "severity_enrich",
    "ai_confirm",
    "debug_verify",
    "ai_deep_audit",
    "report_refresh",
    "phase_attack_chain",
    "phase_report_index",
    "final_report",
    "evidence_check",
]

DEPS = {
    "call_graph": ["route_mapper"],
    "route_tracer": ["route_mapper", "call_graph"],
    "ai_audit": ["route_mapper", "route_tracer", "call_graph"],
    "sql_audit": ["route_tracer"],
    "auth_audit": ["route_mapper"],
    "file_audit": ["route_tracer"],
    "rce_audit": ["route_tracer"],
    "ssrf_xxe_audit": ["route_tracer"],
    "xss_ssti_audit": ["route_tracer"],
    "csrf_audit": ["route_tracer"],
    "var_override_audit": ["route_tracer"],
    "serialize_audit": ["route_tracer"],
    "ai_confirm": ["severity_enrich", "route_tracer", "call_graph"],
    "ai_deep_audit": ["debug_verify", "ai_confirm", "route_tracer"],
}

RULE_AUDIT_MODULES = [
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "vuln_scanner",
]

NON_CACHEABLE_STAGES = {"debug_verify", "ai_deep_audit"}
RUN_CONTEXT_JSON = "run_context.json"
RUN_LOCK_JSON = os.path.join("_meta", "run.lock")

FRAMEWORK_PACKAGE_MAP = {
    "laravel/framework": "laravel",
    "symfony/framework-bundle": "symfony",
    "topthink/framework": "thinkphp",
    "yiisoft/yii2": "yii",
    "codeigniter4/framework": "codeigniter",
    "codeigniter/framework": "codeigniter",
    "slim/slim": "slim",
    "cakephp/cakephp": "cakephp",
    "hyperf/framework": "hyperf",
    "laravel/lumen-framework": "lumen",
}

FRAMEWORK_PRIORITY = [
    "laravel/framework",
    "laravel/lumen-framework",
    "symfony/framework-bundle",
    "topthink/framework",
    "yiisoft/yii2",
    "codeigniter4/framework",
    "codeigniter/framework",
    "slim/slim",
    "cakephp/cakephp",
    "hyperf/framework",
]

FRAMEWORK_DOCROOT_HINTS = {
    "laravel": ["public", "."],
    "lumen": ["public", "."],
    "symfony": ["public", "."],
    "thinkphp": ["public", "."],
    "yii": ["web", "public", "."],
    "codeigniter": ["public", "."],
    "slim": ["public", "."],
    "cakephp": ["webroot", "public", "."],
    "hyperf": ["public", "."],
}

FRAMEWORK_PROFILE_JSON = "framework_profile.json"


STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"
STATUS_DISABLED = "disabled"

STATUS_CN = {
    STATUS_PENDING: "等待中",
    STATUS_RUNNING: "执行中",
    STATUS_DONE: "已完成",
    STATUS_SKIPPED: "已跳过",
    STATUS_FAILED: "失败",
    STATUS_DISABLED: "未启用",
}

STATUS_TAG = {
    STATUS_PENDING: "[WAIT]",
    STATUS_RUNNING: "[RUN ]",
    STATUS_DONE: "[DONE]",
    STATUS_SKIPPED: "[SKIP]",
    STATUS_FAILED: "[FAIL]",
    STATUS_DISABLED: "[OFF ]",
}

VERIFIER_AGENT = {
    "id": "agent-verifier",
    "name": "统一质检员",
    "task": "阶段达标验收（PASS/BLOCK）",
}

VERIFIER_PENDING = "pending"
VERIFIER_RUNNING = "running"
VERIFIER_PASS = "pass"
VERIFIER_BLOCK = "block"
VERIFIER_SKIPPED = "skipped"

VERIFIER_STATUS_CN = {
    VERIFIER_PENDING: "待执行",
    VERIFIER_RUNNING: "执行中",
    VERIFIER_PASS: "已通过",
    VERIFIER_BLOCK: "已阻断",
    VERIFIER_SKIPPED: "已跳过",
}

PIPELINE_STATUS_MD = "审计流水线状态.md"
AGENT_TASK_MANIFEST_MD = "agent_task_manifest.md"
PHASE_GATE_FILES = [f"phase_gate_{i}.md" for i in range(8)]
PIPELINE_EVENTS_JSONL = "pipeline_events.jsonl"
AGENT_RUNTIME_JSON = os.path.join("_meta", "agent_runtime.json")
AGENT_REAPER_EVENTS_JSONL = os.path.join("_meta", "agent_reaper_events.jsonl")
STEP_VERIFIER_DIR = os.path.join("归档", "质量门禁", "步骤门禁")

STAGE_CN = {
    "route_mapper": "路由映射",
    "call_graph": "调用图构建",
    "route_tracer": "调用链追踪",
    "ai_audit": "AI静态补强",
    "sql_audit": "SQL审计",
    "auth_audit": "鉴权审计",
    "file_audit": "文件审计",
    "rce_audit": "命令执行审计",
    "ssrf_xxe_audit": "SSRF/XXE审计",
    "xss_ssti_audit": "XSS/SSTI审计",
    "csrf_audit": "CSRF审计",
    "var_override_audit": "变量覆盖审计",
    "serialize_audit": "反序列化审计",
    "vuln_scanner": "依赖漏洞扫描",
    "mcp_adapter": "MCP采集",
    "severity_enrich": "严重度补强",
    "ai_confirm": "AI确认",
    "debug_verify": "动态调试验证",
    "ai_deep_audit": "AI深入审计验证",
    "report_refresh": "报告刷新",
    "phase_attack_chain": "攻击链报告",
    "phase_report_index": "阶段报告索引",
    "final_report": "最终报告生成",
    "evidence_check": "证据校验",
}

PIPELINE_PHASES = [
    {
        "id": 0,
        "name": "预检与编排",
        "stages": ["__phase0__"],
        "agents": [
            {
                "id": "env-agent",
                "name": "环境分析员",
                "task": "docker/python3/compose 可用性检查",
                "stages": ["__phase0__"],
            },
            {
                "id": "path-agent",
                "name": "路径编排员",
                "task": "计算输出目录 {base}/{项目}/{时间}",
                "stages": ["__phase0__"],
            },
            {
                "id": "coordinator-agent",
                "name": "总控编排员",
                "task": "生成任务编排清单 agent_task_manifest",
                "stages": ["__phase0__"],
            },
        ],
    },
    {
        "id": 1,
        "name": "信息收集",
        "stages": ["route_mapper", "auth_audit", "vuln_scanner", "mcp_adapter"],
        "agents": [
            {
                "id": "agent-1-route-discover",
                "name": "路由分析员",
                "task": "提取全量路由",
                "stages": ["route_mapper"],
            },
            {
                "id": "agent-1-route-param",
                "name": "参数分析员",
                "task": "提取方法与参数位",
                "stages": ["route_mapper"],
            },
            {
                "id": "agent-1-route-burp",
                "name": "Burp模板员",
                "task": "生成 Burp 模板索引",
                "stages": ["route_mapper"],
            },
            {
                "id": "agent-2-auth-audit",
                "name": "鉴权分析员",
                "task": "路由鉴权映射",
                "stages": ["auth_audit"],
            },
            {
                "id": "agent-3-vuln-scanner",
                "name": "组件扫描员",
                "task": "依赖/CVE 漏洞扫描",
                "stages": ["vuln_scanner", "mcp_adapter"],
            },
        ],
    },
    {
        "id": 2,
        "name": "调用链追踪",
        "stages": ["call_graph", "route_tracer"],
        "agents": [
            {
                "id": "agent-5-trace-dispatch",
                "name": "追踪分发员",
                "task": "按高危入口分发追踪任务",
                "stages": ["call_graph"],
            },
            {
                "id": "agent-5-trace-worker",
                "name": "调用链追踪员",
                "task": "逐条追踪 source -> sink",
                "stages": ["route_tracer"],
            },
            {
                "id": "agent-5-trace-merge",
                "name": "追踪汇总员",
                "task": "合并 trace/sinks/call_graph",
                "stages": ["route_tracer"],
            },
        ],
    },
    {
        "id": 3,
        "name": "交叉分析",
        "stages": ["ai_audit", "severity_enrich", "ai_confirm"],
        "agents": [
            {
                "id": "agent-4-risk-join",
                "name": "交叉分析员",
                "task": "关联入口/鉴权/风险证据",
                "stages": ["ai_audit"],
            },
            {
                "id": "agent-4-risk-priority",
                "name": "优先级分析员",
                "task": "生成高危优先级与确认建议",
                "stages": ["severity_enrich", "ai_confirm"],
            },
        ],
    },
    {
        "id": 4,
        "name": "静态漏洞分析",
        "stages": [
            "sql_audit",
            "rce_audit",
            "file_audit",
            "ssrf_xxe_audit",
            "xss_ssti_audit",
            "csrf_audit",
            "var_override_audit",
            "serialize_audit",
        ],
        "agents": [
            {"id": "agent-6a-sql", "name": "SQL审计员", "task": "SQL注入深度审计", "stages": ["sql_audit"]},
            {"id": "agent-6b-rce", "name": "RCE审计员", "task": "命令执行深度审计", "stages": ["rce_audit"]},
            {"id": "agent-6c-file", "name": "文件审计员", "task": "文件类风险审计", "stages": ["file_audit"]},
            {"id": "agent-6d-ssrf-xxe", "name": "SSRF/XXE审计员", "task": "SSRF/XXE深度审计", "stages": ["ssrf_xxe_audit"]},
            {"id": "agent-6e-xss-ssti", "name": "XSS/SSTI审计员", "task": "XSS/SSTI审计", "stages": ["xss_ssti_audit"]},
            {"id": "agent-6f-csrf", "name": "CSRF审计员", "task": "CSRF审计", "stages": ["csrf_audit"]},
            {"id": "agent-6g-var-override", "name": "变量覆盖审计员", "task": "变量覆盖审计", "stages": ["var_override_audit"]},
            {"id": "agent-6h-serialize", "name": "反序列化审计员", "task": "反序列化审计", "stages": ["serialize_audit"]},
        ],
    },
    {
        "id": 5,
        "name": "动态验证与漏洞确认",
        "stages": ["debug_verify"],
        "agents": [
            {"id": "agent-7a-framework-detect", "name": "框架识别员", "task": "识别框架类型与版本", "stages": ["debug_verify"]},
            {"id": "agent-7b-framework-boot", "name": "框架启动员", "task": "框架项目Docker启动与健康检查", "stages": ["debug_verify"]},
            {"id": "agent-7c-snippet-extract", "name": "片段提取员", "task": "无框架项目提取最小可执行片段", "stages": ["debug_verify"]},
            {"id": "agent-7d-debug-case", "name": "动态用例员", "task": "生成 debug cases", "stages": ["debug_verify"]},
            {"id": "agent-7e-payload-dict", "name": "字典注入员", "task": "字典优先注入尝试", "stages": ["debug_verify"]},
            {"id": "agent-7f-payload-ai", "name": "AI补全员", "task": "字典未命中时AI补全", "stages": ["debug_verify"]},
            {"id": "agent-7g-curl-exec", "name": "请求执行员", "task": "Docker内真实curl验证", "stages": ["debug_verify"]},
            {"id": "agent-7h-trace-evidence", "name": "证据追踪员", "task": "记录过程/结果/函数追踪", "stages": ["debug_verify"]},
            {"id": "agent-7i-burp-pack", "name": "Burp整理员", "task": "Burp模版与说明整理", "stages": ["debug_verify"]},
        ],
    },
    {
        "id": 6,
        "name": "AI深入审计",
        "stages": ["ai_deep_audit"],
        "agents": [
            {
                "id": "agent-8a-deep-select",
                "name": "深审选案员",
                "task": "基于已出报告与源码定位筛选深审case",
                "stages": ["ai_deep_audit"],
            },
            {
                "id": "agent-8b-deep-ai",
                "name": "深审AI验证员",
                "task": "多轮AI PoC补全与严格动态验证",
                "stages": ["ai_deep_audit"],
            },
            {
                "id": "agent-8c-deep-evidence",
                "name": "深审证据员",
                "task": "输出AI深审阶段报告与统计",
                "stages": ["ai_deep_audit"],
            },
        ],
    },
    {
        "id": 7,
        "name": "报告汇总与交付",
        "stages": ["report_refresh", "phase_attack_chain", "phase_report_index", "final_report", "evidence_check"],
        "agents": [
            {"id": "agent-9a-binding", "name": "绑定矩阵员", "task": "静态与动态结果绑定", "stages": ["report_refresh"]},
            {"id": "agent-9b-main-report", "name": "主报告员", "task": "生成总报告", "stages": ["final_report"]},
            {"id": "agent-9c-appendix", "name": "附录员", "task": "生成技术附录", "stages": ["final_report"]},
            {"id": "agent-9d-kpi", "name": "指标员", "task": "覆盖率/确认率统计", "stages": ["phase_report_index", "phase_attack_chain"]},
            {"id": "agent-9e-evidence", "name": "证据门禁员", "task": "证据校验与阻断项输出", "stages": ["evidence_check"]},
        ],
    },
]

STAGE_PHASE_ID: Dict[str, int] = {}
for _phase in PIPELINE_PHASES:
    _pid = int(_phase["id"])
    for _stage in _phase.get("stages", []):
        STAGE_PHASE_ID[str(_stage)] = _pid


def stage_phase_id(stage: str) -> int:
    return int(STAGE_PHASE_ID.get(stage, 999))


def is_final_status(status: str) -> bool:
    return status in {STATUS_DONE, STATUS_SKIPPED, STATUS_DISABLED}


def phase_prerequisites_done(stage: str, stage_status: Dict[str, str], selected_stages: Set[str]) -> bool:
    phase_id = stage_phase_id(stage)
    if phase_id <= 0:
        return True
    for prev_stage in selected_stages:
        if stage_phase_id(prev_stage) < phase_id:
            if not is_final_status(stage_status.get(prev_stage, STATUS_PENDING)):
                return False
    return True


def dependencies_done(stage: str, stage_status: Dict[str, str], selected_stages: Set[str]) -> bool:
    for dep in DEPS.get(stage, []):
        if dep not in selected_stages:
            continue
        dep_state = stage_status.get(dep, STATUS_PENDING)
        if dep_state == STATUS_FAILED:
            return False
        if not is_final_status(dep_state):
            return False
    return True


def agents_for_stage(stage: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for phase in PIPELINE_PHASES:
        for agent in phase.get("agents") or []:
            stages = [str(s) for s in (agent.get("stages") or [])]
            if stage in stages:
                out.append(
                    {
                        "id": str(agent.get("id") or "-"),
                        "name": str(agent.get("name") or "-"),
                        "task": str(agent.get("task") or "-"),
                    }
                )
    return out


def append_pipeline_event(
    out_root: str,
    event_type: str,
    stage: str = "",
    status: str = "",
    note: str = "",
    extra: Optional[Dict[str, object]] = None,
) -> None:
    payload: Dict[str, object] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "event_type": event_type,
        "stage": stage,
        "stage_cn": _stage_text(stage) if stage else "",
        "status": status,
        "status_cn": _status_text(status) if status else "",
        "note": note,
    }
    if extra:
        payload.update(extra)
    path = os.path.join(out_root, PIPELINE_EVENTS_JSONL)
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = str(os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    return value if value >= minimum else default


def init_agent_runtime(out_root: str) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "started_at": now_iso(),
        "updated_at": now_iso(),
        "finished_at": "",
        "config": {
            "autoclose_enabled": env_flag("AGENT_AUTOCLOSE", True),
            "idle_timeout_sec": env_int("AGENT_IDLE_TIMEOUT_SEC", 120, minimum=1),
            "heartbeat_sec": env_int("AGENT_HEARTBEAT_SEC", 5, minimum=1),
            "hard_timeout_sec": env_int("AGENT_HARD_TIMEOUT_SEC", 1800, minimum=30),
        },
        "summary": {
            "started": 0,
            "closed": 0,
            "failed": 0,
            "reaped": 0,
            "reap_errors": 0,
        },
        "agents": {},
    }
    write_agent_runtime(out_root, state)
    return state


def write_agent_runtime(out_root: str, state: Dict[str, Any]) -> None:
    path = os.path.join(out_root, AGENT_RUNTIME_JSON)
    payload = dict(state or {})
    payload["updated_at"] = now_iso()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        return


def append_agent_reaper_event(
    out_root: str,
    event_type: str,
    agent_id: str,
    stage: str,
    status: str,
    reason: str = "",
    extra: Optional[Dict[str, object]] = None,
) -> None:
    payload: Dict[str, object] = {
        "timestamp": now_iso(),
        "event_type": event_type,
        "agent_id": str(agent_id or "-"),
        "stage": stage,
        "stage_cn": _stage_text(stage) if stage else "",
        "status": status,
        "reason": reason,
    }
    if extra:
        payload.update(extra)
    path = os.path.join(out_root, AGENT_REAPER_EVENTS_JSONL)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        return


def _agent_row(state: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
    agents = state.setdefault("agents", {})
    row = agents.get(agent_id)
    if isinstance(row, dict):
        return row
    row = {
        "agent_id": agent_id,
        "name": "",
        "task": "",
        "status": "idle",
        "stage": "",
        "phase_id": 0,
        "group_index": 0,
        "run_count": 0,
        "started_at": "",
        "started_epoch": 0.0,
        "last_heartbeat_at": "",
        "last_heartbeat_epoch": 0.0,
        "closed_at": "",
        "close_reason": "",
        "return_code": None,
        "duration_ms": None,
    }
    agents[agent_id] = row
    return row


def agent_mark_running(
    out_root: str,
    state: Dict[str, Any],
    stage: str,
    phase_id: int,
    group_index: int,
    agents: List[Dict[str, str]],
) -> None:
    if not agents:
        return
    now_epoch = float(time.time())
    now_text = now_iso()
    summary = state.setdefault("summary", {})
    for agent in agents:
        agent_id = str(agent.get("id") or "-")
        row = _agent_row(state, agent_id)
        row["name"] = str(agent.get("name") or row.get("name") or "")
        row["task"] = str(agent.get("task") or row.get("task") or "")
        row["status"] = "running"
        row["stage"] = stage
        row["phase_id"] = int(phase_id)
        row["group_index"] = int(group_index)
        row["run_count"] = int(row.get("run_count") or 0) + 1
        row["last_heartbeat_at"] = now_text
        row["last_heartbeat_epoch"] = now_epoch
        row["closed_at"] = ""
        row["close_reason"] = ""
        row["return_code"] = None
        row["duration_ms"] = None
        row["started_at"] = now_text
        row["started_epoch"] = now_epoch
        summary["started"] = int(summary.get("started") or 0) + 1
        append_agent_reaper_event(
            out_root,
            event_type="agent_start",
            agent_id=agent_id,
            stage=stage,
            status="running",
            reason="stage_start",
            extra={"phase_id": phase_id, "group_index": group_index},
        )
    write_agent_runtime(out_root, state)


def agent_mark_final(
    out_root: str,
    state: Dict[str, Any],
    stage: str,
    phase_id: int,
    group_index: int,
    agent_ids: List[str],
    status: str,
    reason: str,
    return_code: Optional[int] = None,
    duration_ms: Optional[int] = None,
) -> None:
    if not agent_ids:
        return
    now_epoch = float(time.time())
    now_text = now_iso()
    normalized = "closed"
    if status == STATUS_FAILED:
        normalized = "failed"
    elif status == "reaped":
        normalized = "reaped"
    summary = state.setdefault("summary", {})
    for agent_id in agent_ids:
        aid = str(agent_id or "-")
        row = _agent_row(state, aid)
        prev_status = str(row.get("status") or "idle")
        row["status"] = normalized
        row["stage"] = stage or str(row.get("stage") or "")
        row["phase_id"] = int(phase_id or row.get("phase_id") or 0)
        row["group_index"] = int(group_index or row.get("group_index") or 0)
        row["last_heartbeat_at"] = now_text
        row["last_heartbeat_epoch"] = now_epoch
        row["closed_at"] = now_text
        row["close_reason"] = reason
        if return_code is not None:
            row["return_code"] = int(return_code)
        if duration_ms is not None:
            row["duration_ms"] = int(duration_ms)
        if prev_status == "running":
            if normalized == "failed":
                summary["failed"] = int(summary.get("failed") or 0) + 1
            elif normalized == "reaped":
                summary["reaped"] = int(summary.get("reaped") or 0) + 1
            else:
                summary["closed"] = int(summary.get("closed") or 0) + 1
        append_agent_reaper_event(
            out_root,
            event_type="agent_final",
            agent_id=aid,
            stage=stage,
            status=normalized,
            reason=reason,
            extra={
                "phase_id": phase_id,
                "group_index": group_index,
                "return_code": return_code,
                "duration_ms": duration_ms,
            },
        )
    write_agent_runtime(out_root, state)


def agent_runtime_counts(state: Optional[Dict[str, Any]]) -> Dict[str, int]:
    if not isinstance(state, dict):
        return {
            "running": 0,
            "closed": 0,
            "failed": 0,
            "reaped": 0,
            "closed_total": 0,
            "reap_errors": 0,
        }
    agents = state.get("agents")
    if not isinstance(agents, dict):
        agents = {}
    running = 0
    closed = 0
    failed = 0
    reaped = 0
    for row in agents.values():
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "idle")
        if status == "running":
            running += 1
        elif status == "closed":
            closed += 1
        elif status == "failed":
            failed += 1
        elif status == "reaped":
            reaped += 1
    summary = state.get("summary")
    reap_errors = 0
    if isinstance(summary, dict):
        reap_errors = int(summary.get("reap_errors") or 0)
    return {
        "running": running,
        "closed": closed,
        "failed": failed,
        "reaped": reaped,
        "closed_total": closed + failed + reaped,
        "reap_errors": reap_errors,
    }


def phase_agent_runtime_counts(state: Optional[Dict[str, Any]], phase: Dict[str, object]) -> Dict[str, int]:
    if not isinstance(state, dict):
        return {"running": 0, "closed_total": 0, "reap_errors": 0}
    phase_agents = phase.get("agents") or []
    if not isinstance(phase_agents, list):
        return {"running": 0, "closed_total": 0, "reap_errors": 0}
    include_ids = {str(a.get("id") or "-") for a in phase_agents if isinstance(a, dict)}
    if not include_ids:
        return {"running": 0, "closed_total": 0, "reap_errors": 0}
    agents = state.get("agents")
    if not isinstance(agents, dict):
        return {"running": 0, "closed_total": 0, "reap_errors": 0}
    running = 0
    closed_total = 0
    for aid, row in agents.items():
        if aid not in include_ids:
            continue
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "idle")
        if status == "running":
            running += 1
        if status in {"closed", "failed", "reaped"}:
            closed_total += 1
    return {
        "running": running,
        "closed_total": closed_total,
        "reap_errors": int(((state.get("summary") or {}).get("reap_errors") or 0)),
    }


def reap_stale_agents(
    out_root: str,
    state: Dict[str, Any],
    reason: str,
    force: bool = False,
    phase_id: int = 0,
) -> Dict[str, int]:
    config = state.get("config")
    if not isinstance(config, dict):
        config = {}
    if not bool(config.get("autoclose_enabled")) and not force:
        return {"reaped": 0, "running_before": 0, "running_after": 0}
    idle_timeout = int(config.get("idle_timeout_sec") or 120)
    hard_timeout = int(config.get("hard_timeout_sec") or 1800)
    now_epoch = float(time.time())
    now_text = now_iso()
    agents = state.get("agents")
    if not isinstance(agents, dict):
        return {"reaped": 0, "running_before": 0, "running_after": 0}
    running_before = 0
    reaped = 0
    summary = state.setdefault("summary", {})
    for aid, row in agents.items():
        if not isinstance(row, dict):
            continue
        if str(row.get("status") or "") != "running":
            continue
        running_before += 1
        last_hb = float(row.get("last_heartbeat_epoch") or 0.0)
        started_epoch = float(row.get("started_epoch") or last_hb or 0.0)
        idle_elapsed = now_epoch - last_hb if last_hb > 0 else 0.0
        hard_elapsed = now_epoch - started_epoch if started_epoch > 0 else 0.0
        should_reap = bool(force)
        if not should_reap and last_hb > 0 and idle_elapsed >= idle_timeout:
            should_reap = True
        if not should_reap and started_epoch > 0 and hard_elapsed >= hard_timeout:
            should_reap = True
        if not should_reap:
            continue
        row["status"] = "reaped"
        row["closed_at"] = now_text
        row["close_reason"] = reason
        row["last_heartbeat_at"] = now_text
        row["last_heartbeat_epoch"] = now_epoch
        if row.get("return_code") is None:
            row["return_code"] = -1
        reaped += 1
        summary["reaped"] = int(summary.get("reaped") or 0) + 1
        append_agent_reaper_event(
            out_root,
            event_type="agent_reap",
            agent_id=str(aid),
            stage=str(row.get("stage") or ""),
            status="reaped",
            reason=reason,
            extra={"phase_id": phase_id},
        )
    running_after = max(0, running_before - reaped)
    write_agent_runtime(out_root, state)
    return {"reaped": reaped, "running_before": running_before, "running_after": running_after}


def cleanup_before_gate(out_root: str, state: Dict[str, Any], phase_id: int) -> Dict[str, int]:
    return reap_stale_agents(
        out_root,
        state,
        reason=f"phase_gate_{phase_id}_cleanup",
        force=True,
        phase_id=phase_id,
    )


def final_cleanup(out_root: str, state: Dict[str, Any], failed_stage: str = "") -> Dict[str, int]:
    reason = "pipeline_failed" if failed_stage else "pipeline_done"
    stats = reap_stale_agents(out_root, state, reason=reason, force=True, phase_id=7)
    state["finished_at"] = now_iso()
    write_agent_runtime(out_root, state)
    return stats


def render_resource_cleanup_markdown(state: Dict[str, Any], failed_stage: str = "") -> str:
    config = state.get("config") if isinstance(state.get("config"), dict) else {}
    counts = agent_runtime_counts(state)
    decision = "已完成" if not failed_stage else "异常结束"
    rows: List[List[str]] = []
    agents = state.get("agents")
    if isinstance(agents, dict):
        for aid, row in sorted(agents.items(), key=lambda x: x[0]):
            if not isinstance(row, dict):
                continue
            status = str(row.get("status") or "idle")
            status_cn = {
                "idle": "未启动",
                "running": "运行中",
                "closed": "已关闭",
                "failed": "失败关闭",
                "reaped": "强制回收",
            }.get(status, status)
            rows.append(
                [
                    str(aid),
                    str(row.get("name") or "-"),
                    status_cn,
                    _stage_text(str(row.get("stage") or "")),
                    str(row.get("close_reason") or "-"),
                    str(row.get("started_at") or "-"),
                    str(row.get("closed_at") or "-"),
                ]
            )

    lines = [
        "# 资源回收报告",
        "",
        f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 运行结果：{decision}",
        f"- 自动关闭开关：{'开启' if bool(config.get('autoclose_enabled', True)) else '关闭'}",
        f"- 空闲超时：{int(config.get('idle_timeout_sec') or 120)} 秒",
        f"- 硬超时：{int(config.get('hard_timeout_sec') or 1800)} 秒",
        f"- Agent 启动次数：{int((state.get('summary') or {}).get('started') or 0)}",
        f"- 已关闭数量：{counts['closed_total']}",
        f"- 强制回收数量：{counts['reaped']}",
        f"- 回收异常数量：{counts['reap_errors']}",
    ]
    if failed_stage:
        lines.append(f"- 失败阶段：{failed_stage}")
    lines.append("")
    if rows:
        lines.append(markdown_table(["Agent ID", "角色", "状态", "最近阶段", "关闭原因", "启动时间", "关闭时间"], rows))
    else:
        lines.append("（无 agent 运行记录）")
    lines.append("")
    return "\n".join(lines)


def write_resource_cleanup_report(out_root: str, state: Dict[str, Any], failed_stage: str = "") -> str:
    quality_dir = os.path.join(out_root, ARCHIVE_QUALITY_DIR)
    os.makedirs(quality_dir, exist_ok=True)
    path = os.path.join(quality_dir, RESOURCE_CLEANUP_MD)
    write_text(path, render_resource_cleanup_markdown(state, failed_stage=failed_stage))
    return path


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def write_run_context(path: str, payload: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        return


def init_run_context(out_root: str, project_root: str) -> Tuple[str, str, Dict[str, Any]]:
    run_id = str(os.environ.get("AUDIT_RUN_ID") or "").strip()
    if not run_id:
        run_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
    path = os.path.join(out_root, "_meta", RUN_CONTEXT_JSON)
    payload: Dict[str, Any] = {
        "run_id": run_id,
        "project_root": project_root,
        "out_root": out_root,
        "started_at": now_iso(),
        "finished_at": "",
        "overall_status": "running",
        "executed_in_container": bool(running_in_container()),
        "host_name": socket.gethostname(),
        "stages": {},
    }
    write_run_context(path, payload)
    return run_id, path, payload


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def _read_json_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def acquire_run_lock(out_root: str, run_id: str) -> str:
    lock_path = os.path.join(out_root, RUN_LOCK_JSON)
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    stale_sec = 21600
    try:
        stale_sec = max(60, int(os.environ.get("AUDIT_RUN_LOCK_STALE_SEC", "21600")))
    except Exception:
        stale_sec = 21600
    now_epoch = time.time()
    host_name = socket.gethostname()
    payload = {
        "run_id": run_id,
        "pid": os.getpid(),
        "host": host_name,
        "started_at": now_iso(),
        "started_epoch": now_epoch,
        "out_root": out_root,
    }

    for _ in range(3):
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            existing = _read_json_file(lock_path)
            existing_pid = 0
            try:
                existing_pid = int(existing.get("pid") or 0)
            except Exception:
                existing_pid = 0
            existing_host = str(existing.get("host") or "")
            same_host = (not existing_host) or (existing_host == host_name)
            active = same_host and existing_pid > 0 and _pid_alive(existing_pid)
            if active:
                existing_run_id = str(existing.get("run_id") or "-")
                raise SystemExit(
                    f"Output directory is in use: {out_root} "
                    f"(run_id={existing_run_id}, pid={existing_pid})."
                )
            existing_epoch = float(existing.get("started_epoch") or 0.0)
            stale_by_age = bool(existing_epoch > 0 and (now_epoch - existing_epoch) >= stale_sec)
            stale_by_mtime = False
            try:
                stale_by_mtime = (now_epoch - os.path.getmtime(lock_path)) >= stale_sec
            except Exception:
                stale_by_mtime = False
            if stale_by_age or stale_by_mtime or not existing:
                try:
                    os.remove(lock_path)
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
                continue
            raise SystemExit(f"Output directory lock exists, please use a new output path: {out_root}")
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)

            def _release_lock() -> None:
                try:
                    current = _read_json_file(lock_path)
                    if not current or str(current.get("run_id") or "") == run_id:
                        os.remove(lock_path)
                except FileNotFoundError:
                    pass
                except Exception:
                    pass

            atexit.register(_release_lock)
            return lock_path
    raise SystemExit(f"Failed to acquire output lock for: {out_root}")


def mark_stage_context(
    run_context: Dict[str, Any],
    stage: str,
    status: str,
    phase_id: int = 0,
    cache_hit: Optional[bool] = None,
    return_code: Optional[int] = None,
    duration_ms: Optional[int] = None,
) -> None:
    stages = run_context.setdefault("stages", {})
    row = stages.get(stage)
    if not isinstance(row, dict):
        row = {}
        stages[stage] = row
    if "started_at" not in row:
        row["started_at"] = now_iso()
    row["updated_at"] = now_iso()
    row["status"] = status
    if phase_id > 0:
        row["phase_id"] = phase_id
    if cache_hit is not None:
        row["cache_hit"] = bool(cache_hit)
    if return_code is not None:
        row["return_code"] = int(return_code)
    if duration_ms is not None:
        row["duration_ms"] = int(duration_ms)
    if status in {STATUS_DONE, STATUS_FAILED, STATUS_SKIPPED, STATUS_DISABLED}:
        row["finished_at"] = now_iso()


def init_pipeline_stage_status(selected_stages: Set[str]) -> Dict[str, str]:
    status: Dict[str, str] = {}
    for stage in PIPELINE_ORDER:
        status[stage] = STATUS_PENDING if stage in selected_stages else STATUS_DISABLED
    status["__phase0__"] = STATUS_PENDING
    return status


def _derive_group_status(stage_values: List[str]) -> str:
    if not stage_values:
        return STATUS_DISABLED
    if all(v == STATUS_DISABLED for v in stage_values):
        return STATUS_DISABLED
    if any(v == STATUS_FAILED for v in stage_values):
        return STATUS_FAILED
    if any(v == STATUS_RUNNING for v in stage_values):
        return STATUS_RUNNING
    active = [v for v in stage_values if v != STATUS_DISABLED]
    if active and all(v == STATUS_SKIPPED for v in active):
        return STATUS_SKIPPED
    if active and all(v in {STATUS_DONE, STATUS_SKIPPED} for v in active):
        return STATUS_DONE
    if any(v in {STATUS_DONE, STATUS_SKIPPED} for v in active) and any(v == STATUS_PENDING for v in active):
        return STATUS_RUNNING
    if active and all(v == STATUS_PENDING for v in active):
        return STATUS_PENDING
    return STATUS_PENDING


def phase_status_map(stage_status: Dict[str, str]) -> Dict[int, str]:
    output: Dict[int, str] = {}
    for phase in PIPELINE_PHASES:
        states = [stage_status.get(s, STATUS_DISABLED) for s in phase["stages"]]
        output[int(phase["id"])] = _derive_group_status(states)
    return output


def agent_status(stage_status: Dict[str, str], stage_keys: List[str]) -> str:
    states = [stage_status.get(s, STATUS_DISABLED) for s in stage_keys]
    return _derive_group_status(states)


def _blocked_by_phase_text(phase_id: int, phase_states: Dict[int, str]) -> str:
    if phase_id <= 0:
        return ""
    prev = phase_states.get(phase_id - 1, STATUS_DISABLED)
    current = phase_states.get(phase_id, STATUS_DISABLED)
    if current != STATUS_PENDING:
        return ""
    if prev in {STATUS_DONE, STATUS_SKIPPED, STATUS_DISABLED}:
        return ""
    return f"blocked by #{phase_id - 1}"


def _blocked_phase_ids(phase_id: int, phase_states: Dict[int, str]) -> List[str]:
    if phase_id <= 1:
        return []
    blocked: List[str] = []
    for prev_id in range(1, phase_id):
        prev = phase_states.get(prev_id, STATUS_DISABLED)
        if prev not in {STATUS_DONE, STATUS_SKIPPED, STATUS_DISABLED}:
            blocked.append(f"#{prev_id}")
    return blocked


def _direct_blocker(phase_id: int, phase_states: Dict[int, str]) -> str:
    if phase_id <= 0:
        return ""
    prev_id = phase_id - 1
    prev = phase_states.get(prev_id, STATUS_DISABLED)
    if prev in {STATUS_DONE, STATUS_SKIPPED, STATUS_DISABLED}:
        return ""
    return f"#{prev_id}"


def _phase_runtime_text(phase_id: int, phase_name: str, phase_states: Dict[int, str], running_agents: int) -> str:
    pstatus = phase_states.get(phase_id, STATUS_DISABLED)
    if pstatus == STATUS_RUNNING:
        return f"阶段{phase_id}：{phase_name}（{'并行执行中' if running_agents > 1 else '执行中'}）"
    if pstatus == STATUS_PENDING:
        blocked = _direct_blocker(phase_id, phase_states)
        if blocked:
            return f"阶段{phase_id}：{phase_name}（等待中，blocked by {blocked}）"
        return f"阶段{phase_id}：{phase_name}（等待中）"
    return f"阶段{phase_id}：{phase_name}（{_status_text(pstatus)}）"


def _agent_runtime_icon(status: str) -> str:
    icons = {
        STATUS_RUNNING: "🔄",
        STATUS_DONE: "✅",
        STATUS_SKIPPED: "⏭",
        STATUS_PENDING: "⌛",
        STATUS_FAILED: "❌",
        STATUS_DISABLED: "□",
    }
    return icons.get(status, "□")


def _agent_display_id(agent_id: str) -> str:
    raw = str(agent_id or "-")
    m = re.match(r"agent-(\d+)", raw)
    if not m:
        return raw
    short = f"agent-{m.group(1)}"
    if short == raw:
        return raw
    return f"{short} ({raw})"


def _stage_text(stage: str) -> str:
    if stage == "__phase0__":
        return "预检编排"
    return STAGE_CN.get(stage, stage)


def _status_text(status: str) -> str:
    return STATUS_CN.get(status, status)


def _verifier_status_text(status: str) -> str:
    return VERIFIER_STATUS_CN.get(status, status)


def _verifier_runtime_icon(status: str) -> str:
    icons = {
        VERIFIER_RUNNING: "🔍",
        VERIFIER_PASS: "✅",
        VERIFIER_BLOCK: "❌",
        VERIFIER_PENDING: "⌛",
        VERIFIER_SKIPPED: "⏭",
    }
    return icons.get(status, "⌛")


def init_phase_verifier_state() -> Dict[int, Dict[str, str]]:
    state: Dict[int, Dict[str, str]] = {}
    for phase in PIPELINE_PHASES:
        pid = int(phase["id"])
        state[pid] = {
            "status": VERIFIER_PENDING,
            "note": "",
            "report_path": "",
            "updated_at": "",
        }
    return state


def set_phase_verifier_state(
    phase_verifier: Dict[int, Dict[str, str]],
    phase_id: int,
    status: str,
    note: str = "",
    report_path: str = "",
) -> None:
    row = phase_verifier.setdefault(
        int(phase_id),
        {"status": VERIFIER_PENDING, "note": "", "report_path": "", "updated_at": ""},
    )
    row["status"] = str(status)
    row["note"] = str(note or "")
    if report_path:
        row["report_path"] = str(report_path)
    row["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")


def render_pipeline_runtime_markdown(
    out_root: str,
    stage_status: Dict[str, str],
    current_stage: str,
    started_at: float,
    event_note: str = "",
    phase_verifier: Optional[Dict[int, Dict[str, str]]] = None,
) -> str:
    now = time.time()
    elapsed_sec = max(0, int(now - started_at))
    phase_states = phase_status_map(stage_status)

    current_stage_text = _stage_text(current_stage) if current_stage else "-"
    lines: List[str] = [
        "# 审计流水线状态",
        "",
        f"- 更新时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 运行时长：{elapsed_sec}s",
        f"- 当前阶段：`{current_stage_text}`",
        f"- 输出目录：`{out_root}`",
        f"- 质检Agent：`{VERIFIER_AGENT['id']}` ({VERIFIER_AGENT['name']})",
    ]
    if event_note:
        lines.append(f"- 最近事件：{event_note}")
    lines += [
        "",
        "## 顺序执行队列",
    ]
    for phase in sorted(PIPELINE_PHASES, key=lambda x: int(x["id"])):
        pid = int(phase["id"])
        pstatus = phase_states.get(pid, STATUS_DISABLED)
        icon = _agent_runtime_icon(pstatus)
        line = f"{icon} 阶段{pid}：{phase['name']}"
        vrow = (phase_verifier or {}).get(pid) if isinstance(phase_verifier, dict) else None
        vstatus = str((vrow or {}).get("status") or VERIFIER_PENDING)
        line = f"{line} | 质检:{_verifier_runtime_icon(vstatus)} {_verifier_status_text(vstatus)}"
        if pstatus == STATUS_PENDING:
            blocker = _direct_blocker(pid, phase_states)
            if blocker:
                line = f"{line}  > blocked by {blocker}"
        lines.append(line)
    lines.append("")
    return "\n".join(lines)


def render_agent_task_manifest(
    stage_status: Dict[str, str],
    phase_verifier: Optional[Dict[int, Dict[str, str]]] = None,
) -> str:
    rows: List[List[str]] = []
    for phase in PIPELINE_PHASES:
        pid = str(phase["id"])
        pname = str(phase["name"])
        for agent in phase.get("agents") or []:
            stage_keys = [str(s) for s in (agent.get("stages") or [])]
            mapped = ", ".join([_stage_text(s) for s in stage_keys]) if stage_keys else "-"
            rows.append(
                [
                    pid,
                    pname,
                    str(agent.get("id") or "-"),
                    str(agent.get("name") or "-"),
                    _status_text(agent_status(stage_status, stage_keys)),
                    mapped,
                    str(agent.get("task") or "-"),
                ]
            )
        vstatus = str(((phase_verifier or {}).get(int(phase["id"])) or {}).get("status") or VERIFIER_PENDING)
        rows.append(
            [
                pid,
                pname,
                str(VERIFIER_AGENT["id"]),
                str(VERIFIER_AGENT["name"]),
                _verifier_status_text(vstatus),
                "阶段门禁验收",
                str(VERIFIER_AGENT["task"]),
            ]
        )
    return "\n".join(
        [
            "# Agent 任务编排清单",
            "",
            markdown_table(
                ["阶段", "阶段名称", "Agent ID", "角色", "状态", "映射阶段", "任务"],
                rows,
            ),
            "",
        ]
    )


def render_phase_gate_markdown(
    phase: Dict[str, object],
    phase_states: Dict[int, str],
    stage_status: Dict[str, str],
    current_stage: str,
    agent_runtime: Optional[Dict[str, Any]] = None,
    phase_verifier: Optional[Dict[int, Dict[str, str]]] = None,
) -> str:
    pid = int(phase["id"])
    pname = str(phase["name"])
    pstatus = phase_states.get(pid, STATUS_DISABLED)
    blocked = _blocked_by_phase_text(pid, phase_states)
    if pstatus in {STATUS_DONE, STATUS_SKIPPED, STATUS_DISABLED}:
        decision = "通过"
    elif pstatus == STATUS_FAILED:
        decision = "阻断"
    elif pstatus == STATUS_RUNNING:
        decision = "执行中"
    else:
        decision = "等待中"

    runtime_counts = phase_agent_runtime_counts(agent_runtime, phase)
    vrow = (phase_verifier or {}).get(pid) if isinstance(phase_verifier, dict) else None
    vstatus = str((vrow or {}).get("status") or VERIFIER_PENDING)
    vnote = str((vrow or {}).get("note") or "")
    vreport = str((vrow or {}).get("report_path") or "")

    rows: List[List[str]] = []
    rows.append(
        [
            str(VERIFIER_AGENT["id"]),
            str(VERIFIER_AGENT["name"]),
            _verifier_status_text(vstatus),
            "阶段门禁验收",
            str(VERIFIER_AGENT["task"]),
        ]
    )
    for agent in phase.get("agents") or []:
        stage_keys = [str(s) for s in (agent.get("stages") or [])]
        rows.append(
            [
                str(agent.get("id") or "-"),
                str(agent.get("name") or "-"),
                _status_text(agent_status(stage_status, stage_keys)),
                ", ".join([_stage_text(s) for s in stage_keys]) if stage_keys else "-",
                str(agent.get("task") or "-"),
            ]
        )

    lines = [
        f"# Verifier Gate {pid}",
        "",
        f"- 阶段：阶段{pid} {pname}",
        f"- 阶段状态：{_status_text(pstatus)}",
        f"- 门禁结论：{decision}",
        f"- 当前执行阶段：{_stage_text(current_stage) if current_stage else '-'}",
        f"- 质检Agent：{VERIFIER_AGENT['id']} ({VERIFIER_AGENT['name']})",
        f"- 质检状态：{_verifier_status_text(vstatus)}",
        f"- 运行中Agent数：{runtime_counts['running']}",
        f"- 已关闭Agent数：{runtime_counts['closed_total']}",
        f"- 回收异常数：{runtime_counts['reap_errors']}",
        f"- 更新时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    if blocked:
        lines.append(f"- 阻塞信息：{blocked}")
    if vnote:
        lines.append(f"- 质检备注：{vnote}")
    if vreport:
        lines.append(f"- 质检报告：`{vreport}`")
    lines += [
        "",
        markdown_table(["Agent ID", "角色", "状态", "映射阶段", "任务"], rows),
        "",
    ]
    return "\n".join(lines)


def write_pipeline_runtime_files(
    out_root: str,
    stage_status: Dict[str, str],
    current_stage: str,
    started_at: float,
    event_note: str = "",
    agent_runtime: Optional[Dict[str, Any]] = None,
    phase_verifier: Optional[Dict[int, Dict[str, str]]] = None,
) -> None:
    status_md = render_pipeline_runtime_markdown(
        out_root,
        stage_status,
        current_stage,
        started_at,
        event_note=event_note,
        phase_verifier=phase_verifier,
    )
    write_text(os.path.join(out_root, PIPELINE_STATUS_MD), status_md)

    manifest_md = render_agent_task_manifest(stage_status, phase_verifier=phase_verifier)
    write_text(os.path.join(out_root, AGENT_TASK_MANIFEST_MD), manifest_md)

    phase_states = phase_status_map(stage_status)
    for phase in PIPELINE_PHASES:
        path = os.path.join(out_root, f"phase_gate_{int(phase['id'])}.md")
        gate_md = render_phase_gate_markdown(
            phase,
            phase_states,
            stage_status,
            current_stage,
            agent_runtime=agent_runtime,
            phase_verifier=phase_verifier,
        )
        write_text(path, gate_md)


def hash_strings(items: List[str]) -> str:
    h = hashlib.sha256()
    for s in items:
        h.update(s.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def hash_paths(paths: List[str]) -> str:
    entries: List[str] = []
    for p in paths:
        if not p:
            continue
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                    except Exception:
                        continue
                    entries.append(f"{fp}:{st.st_mtime_ns}:{st.st_size}")
        elif os.path.exists(p):
            try:
                st = os.stat(p)
                entries.append(f"{p}:{st.st_mtime_ns}:{st.st_size}")
            except Exception:
                entries.append(f"{p}:error")
        else:
            entries.append(f"{p}:missing")
    entries.sort()
    return hash_strings(entries)


def project_signature(project_root: str) -> str:
    php_files = walk_php_files(project_root)
    extra = []
    for name in ["composer.lock", "composer.json"]:
        p = os.path.join(project_root, name)
        if os.path.exists(p):
            extra.append(p)
    route_configs = []
    for p in [
        os.path.join(project_root, "config", "routes.yaml"),
        os.path.join(project_root, "config", "routes.yml"),
    ]:
        if os.path.exists(p):
            route_configs.append(p)
    routes_dir = os.path.join(project_root, "config", "routes")
    if os.path.isdir(routes_dir):
        for root, _, files in os.walk(routes_dir):
            for f in files:
                if f.endswith(".yml") or f.endswith(".yaml"):
                    route_configs.append(os.path.join(root, f))
    return hash_paths(php_files + extra + route_configs)


def _load_json_dict(path: str) -> Dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def _collect_lock_versions(lock_data: Dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(lock_data, dict):
        return out
    for key in ("packages", "packages-dev"):
        rows = lock_data.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip().lower()
            version = str(row.get("version") or "").strip()
            if name and version and name not in out:
                out[name] = version
    return out


def _collect_require_versions(composer_data: Dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(composer_data, dict):
        return out
    for key in ("require", "require-dev"):
        rows = composer_data.get(key)
        if not isinstance(rows, dict):
            continue
        for pkg, ver in rows.items():
            name = str(pkg or "").strip().lower()
            if not name:
                continue
            out[name] = str(ver or "").strip()
    return out


def _detect_framework_by_files(project_root: str) -> Tuple[str, str]:
    markers = [
        ("laravel", [os.path.join(project_root, "artisan"), os.path.join(project_root, "bootstrap", "app.php")]),
        ("symfony", [os.path.join(project_root, "bin", "console"), os.path.join(project_root, "config", "bundles.php")]),
        ("thinkphp", [os.path.join(project_root, "think"), os.path.join(project_root, "app")]),
        ("yii", [os.path.join(project_root, "yii"), os.path.join(project_root, "config")]),
        ("codeigniter", [os.path.join(project_root, "system"), os.path.join(project_root, "application")]),
        ("slim", [os.path.join(project_root, "public", "index.php"), os.path.join(project_root, "vendor", "autoload.php")]),
        ("cakephp", [os.path.join(project_root, "bin", "cake"), os.path.join(project_root, "config")]),
        ("hyperf", [os.path.join(project_root, "bin", "hyperf.php"), os.path.join(project_root, "config", "autoload")]),
    ]
    for framework_name, paths in markers:
        if all(os.path.exists(p) for p in paths):
            return framework_name, "filesystem"
    return "", "none"


def _resolve_doc_root(project_root: str, framework_name: str) -> Tuple[str, str]:
    hints = FRAMEWORK_DOCROOT_HINTS.get(framework_name, ["public", "web", "."])
    for rel in hints:
        abs_dir = project_root if rel == "." else os.path.join(project_root, rel)
        index_file = os.path.join(abs_dir, "index.php")
        if os.path.isdir(abs_dir) and os.path.isfile(index_file):
            return rel, abs_dir
    generic = ["public", "web", "webroot", "."]
    for rel in generic:
        abs_dir = project_root if rel == "." else os.path.join(project_root, rel)
        if os.path.isdir(abs_dir) and os.path.isfile(os.path.join(abs_dir, "index.php")):
            return rel, abs_dir
    return "", ""


def detect_framework_profile(project_root: str) -> Dict[str, Any]:
    composer_path = os.path.join(project_root, "composer.json")
    lock_path = os.path.join(project_root, "composer.lock")
    composer_data = _load_json_dict(composer_path)
    lock_data = _load_json_dict(lock_path)
    lock_versions = _collect_lock_versions(lock_data)
    require_versions = _collect_require_versions(composer_data)

    framework_pkg = ""
    framework_name = ""
    framework_version = ""
    detected_from = "none"

    for pkg in FRAMEWORK_PRIORITY:
        if pkg in lock_versions:
            framework_pkg = pkg
            framework_name = FRAMEWORK_PACKAGE_MAP.get(pkg, "")
            framework_version = lock_versions.get(pkg, "")
            detected_from = "composer.lock"
            break
        if pkg in require_versions:
            framework_pkg = pkg
            framework_name = FRAMEWORK_PACKAGE_MAP.get(pkg, "")
            framework_version = require_versions.get(pkg, "")
            detected_from = "composer.json"
            break

    if not framework_name:
        framework_name, detected_from = _detect_framework_by_files(project_root)

    doc_root_rel = ""
    doc_root_abs = ""
    if framework_name:
        doc_root_rel, doc_root_abs = _resolve_doc_root(project_root, framework_name)

    mode = "framework" if framework_name else "snippet"
    doc_root_exists = bool(doc_root_abs and os.path.isdir(doc_root_abs))
    index_exists = bool(doc_root_abs and os.path.isfile(os.path.join(doc_root_abs, "index.php")))
    boot_supported = bool(mode == "framework" and doc_root_exists and index_exists and framework_name != "hyperf")

    return {
        "mode": mode,
        "framework_name": framework_name or "",
        "framework_package": framework_pkg or "",
        "framework_version": framework_version or "",
        "detected_from": detected_from,
        "composer_json_exists": bool(os.path.exists(composer_path)),
        "composer_lock_exists": bool(os.path.exists(lock_path)),
        "doc_root": doc_root_rel,
        "doc_root_abs": doc_root_abs,
        "doc_root_exists": doc_root_exists,
        "index_exists": index_exists,
        "boot_supported": boot_supported,
        "boot_strategy": "php_builtin_server" if framework_name else "slice_http_server",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def write_framework_profile(out_root: str, profile: Dict[str, object]) -> str:
    meta_dir = os.path.join(out_root, "_meta")
    os.makedirs(meta_dir, exist_ok=True)
    path = os.path.join(meta_dir, FRAMEWORK_PROFILE_JSON)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profile or {}, f, ensure_ascii=False, indent=2)
    except Exception:
        return ""
    return path


def list_findings_files(out_root: str) -> List[str]:
    files = []
    for root, _, names in os.walk(out_root):
        for n in names:
            if n == "findings.json" or n == "auth_evidence.json":
                files.append(os.path.join(root, n))
    return files


def load_meta(out_root: str) -> Dict:
    path = os.path.join(out_root, "meta.json")
    if not os.path.exists(path):
        return {"stages": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "stages" in data:
                return data
    except Exception:
        pass
    return {"stages": {}}


def ai_audit_ok(out_root: str) -> bool:
    path = os.path.join(out_root, "ai_audit", "ai_audit_report.json")
    if not os.path.exists(path):
        return False
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return False
    return bool(data.get("ok"))


def save_meta(out_root: str, meta: Dict) -> None:
    path = os.path.join(out_root, "meta.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


REPORT_DIRS = {
    "sql_audit",
    "auth_audit",
    "file_audit",
    "rce_audit",
    "ssrf_xxe_audit",
    "xss_ssti_audit",
    "csrf_audit",
    "var_override_audit",
    "serialize_audit",
    "vuln_report",
}

STAGE_DIR_SKIP = {
    "ai_audit_context",
    "ai_context",
    "mcp_raw",
    "http_runtime",
    "slices",
    "trace_cases",
    "burp_templates",
}

REPORT_EXTENSIONS = {".md", ".json", ".html"}

ROUTE_TRACER_REPORT_NAMES = {"trace.json", "trace.md", "sinks.json", "call_graph.json", "call_graph.md"}

MODULE_DIR_CN_MAP = {
    "sql_audit": "SQL注入审计",
    "auth_audit": "鉴权审计",
    "file_audit": "文件风险审计",
    "rce_audit": "命令执行审计",
    "ssrf_xxe_audit": "SSRF_XXE审计",
    "xss_ssti_audit": "XSS_SSTI审计",
    "csrf_audit": "CSRF审计",
    "var_override_audit": "变量覆盖审计",
    "serialize_audit": "反序列化审计",
    "vuln_report": "依赖漏洞审计",
    "route_mapper": "路由映射",
    "route_tracer": "路由追踪",
    "debug_verify": "动态调试",
    "ai_deep_audit": "AI深入审计",
    "mcp_raw": "AI原始结果",
    "mcp_parsed": "AI解析结果",
    "_meta": "阶段元信息",
}

REPORT_BUNDLE_DIR = "报告汇总"
DEBUG_EVIDENCE_JSON_CN = "动态调试证据.json"
DEBUG_PROCESS_JSON_CN = "动态调试过程.json"
DEBUG_POC_JSON_CN = "动态调试PoC.json"
DEBUG_FUNC_TRACE_JSON_CN = "函数追踪证据.json"
PRIMARY_STATIC_MD = "最终静态审计结果.md"
PRIMARY_DYNAMIC_MD = "动态debug审计报告.md"
PRIMARY_AI_VERIFY_MD = "AI深入验证最终报告.md"
ARCHIVE_ROOT_DIR = "归档"
ARCHIVE_STAGE_DIR = os.path.join(ARCHIVE_ROOT_DIR, "阶段报告")
ARCHIVE_DEBUG_DIR = os.path.join(ARCHIVE_ROOT_DIR, "调试证据")
ARCHIVE_BURP_DIR = os.path.join(ARCHIVE_ROOT_DIR, "Burp模板")
ARCHIVE_QUALITY_DIR = os.path.join(ARCHIVE_ROOT_DIR, "质量门禁")
ARCHIVE_BINDING_DIR = os.path.join(ARCHIVE_ROOT_DIR, "结论绑定")
REPORT_JSON_CN = "总报告.json"
REPORT_MD_CN = "总报告.md"
REPORT_APPENDIX_MD_CN = "总报告_技术附录.md"
REPORT_JSON_CN_ALT = "最终报告.json"
REPORT_MD_CN_ALT = "最终报告.md"
REPORT_APPENDIX_MD_CN_ALT = "最终报告_技术附录.md"
RESOURCE_CLEANUP_MD = "资源回收报告.md"

FILE_CN_MAP = {
    PRIMARY_STATIC_MD: PRIMARY_STATIC_MD,
    PRIMARY_DYNAMIC_MD: PRIMARY_DYNAMIC_MD,
    PRIMARY_AI_VERIFY_MD: PRIMARY_AI_VERIFY_MD,
    "final_report.md": "总报告.md",
    "final_report_appendix.md": "总报告_技术附录.md",
    "final_report.json": "总报告.json",
    "最终报告.md": "最终报告.md",
    "最终报告_技术附录.md": "最终报告_技术附录.md",
    "最终报告.json": "最终报告.json",
    "总报告.md": "总报告.md",
    "总报告_技术附录.md": "总报告_技术附录.md",
    "总报告.json": "总报告.json",
    "evidence_check.md": "证据校验.md",
    "evidence_check.json": "证据校验.json",
    "证据校验.md": "证据校验.md",
    "证据校验.json": "证据校验.json",
    RESOURCE_CLEANUP_MD: RESOURCE_CLEANUP_MD,
    "debug_cases.json": "动态调试用例.json",
    "debug_evidence.md": "动态调试证据.md",
    "debug_evidence.json": "动态调试证据.json",
    "debug_process.md": "动态调试过程.md",
    "debug_process.json": "动态调试过程.json",
    "debug_poc.md": "动态调试PoC.md",
    "debug_poc.json": "动态调试PoC.json",
    "debug_func_trace.md": "函数追踪证据.md",
    "debug_func_trace.json": "函数追踪证据.json",
    "动态运行元信息.md": "动态运行元信息.md",
    "动态运行元信息.json": "动态运行元信息.json",
    "AI深入审计阶段报告.md": "AI深入审计阶段报告.md",
    "ai_deep_audit_summary.json": "AI深入审计摘要.json",
    "poc_plan.md": "PoC计划.md",
    "poc_plan.json": "PoC计划.json",
    "routes.md": "路由映射.md",
    "routes.json": "路由映射.json",
    "auth_findings.md": "鉴权风险发现.md",
    "auth_routes.md": "鉴权路由映射.md",
    "call_graph.md": "调用图摘要.md",
    "call_graph.json": "调用图摘要.json",
    "trace.md": "路由追踪.md",
    "trace.json": "路由追踪.json",
    "sinks.json": "危险函数汇总.json",
    "summary.json": "MCP结果汇总.json",
    "meta.json": "执行元信息.json",
    "phase1_map.md": "阶段1_映射.md",
    "phase2_risk_map.md": "阶段2_风险映射.md",
    "phase3_trace_log.md": "阶段3_追踪日志.md",
    "phase4_attack_chain.md": "阶段4_攻击链.md",
    "phase5_report_index.md": "阶段5_报告索引.md",
    "run_context.json": "本次运行上下文.json",
    "审计流水线状态.md": "审计流水线状态.md",
    "agent_task_manifest.md": "Agent任务编排清单.md",
    "phase_gate_0.md": "阶段门禁0.md",
    "phase_gate_1.md": "阶段门禁1.md",
    "phase_gate_2.md": "阶段门禁2.md",
    "phase_gate_3.md": "阶段门禁3.md",
    "phase_gate_4.md": "阶段门禁4.md",
    "phase_gate_5.md": "阶段门禁5.md",
    "phase_gate_6.md": "阶段门禁6.md",
    "phase_gate_7.md": "阶段门禁7.md",
    "静态_动态_AI_结论对照表.md": "静态_动态_AI_结论对照表.md",
}


def is_report_file(path: str) -> bool:
    name = os.path.basename(path)
    if name in {"meta.json"}:
        return False
    ext = os.path.splitext(name)[1].lower()
    return ext in REPORT_EXTENSIONS


def latest_matching_md(dir_path: str, pattern: str) -> Optional[str]:
    candidates: List[str] = []
    for n in os.listdir(dir_path):
        p = os.path.join(dir_path, n)
        if not os.path.isfile(p):
            continue
        if not n.endswith(".md"):
            continue
        if pattern in n:
            candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    return candidates[0]


def collect_reports_from_dir(dir_path: str) -> List[str]:
    if not os.path.isdir(dir_path):
        return []
    base = os.path.basename(dir_path.rstrip("/"))
    reports: List[str] = []
    if base == "route_tracer":
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in STAGE_DIR_SKIP]
            for n in files:
                if n in ROUTE_TRACER_REPORT_NAMES:
                    reports.append(os.path.join(root, n))
        return reports

    if base in REPORT_DIRS:
        fixed_names = ["findings.json", "findings.md", "index.html"]
        if base == "auth_audit":
            fixed_names = [
                "auth_evidence.json",
                "auth_findings.md",
                "auth_routes.md",
                "index.html",
            ]
            for marker in ["_auth_audit_", "_auth_mapping_", "_auth_README_"]:
                latest = latest_matching_md(dir_path, marker)
                if latest:
                    reports.append(latest)
        elif base == "vuln_report":
            fixed_names = ["composer_audit.json", "composer_audit.md"]
        else:
            latest = latest_matching_md(dir_path, f"_{base}_")
            if latest:
                reports.append(latest)

        for n in fixed_names:
            p = os.path.join(dir_path, n)
            if os.path.isfile(p):
                reports.append(p)
        return reports

    for n in os.listdir(dir_path):
        p = os.path.join(dir_path, n)
        if os.path.isfile(p) and is_report_file(p):
            reports.append(p)
    return reports


def collect_report_paths(out_root: str, selected_stages: List[str]) -> List[str]:
    report_paths: List[str] = []
    for stage in selected_stages:
        outputs = stage_outputs(out_root, stage)
        for output in outputs:
            if os.path.isfile(output) and is_report_file(output):
                report_paths.append(output)
                continue
            if os.path.isdir(output):
                report_paths.extend(collect_reports_from_dir(output))

    unique = sorted(set(report_paths))
    main_md_candidates = [
        os.path.join(out_root, PRIMARY_STATIC_MD),
        os.path.join(out_root, PRIMARY_DYNAMIC_MD),
        os.path.join(out_root, PRIMARY_AI_VERIFY_MD),
    ]
    final_md_candidates = main_md_candidates + [
        os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_MD_CN),
        os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_MD_CN_ALT),
    ]
    final_list = [p for p in unique if p not in final_md_candidates]
    for final_md in final_md_candidates:
        if os.path.exists(final_md):
            final_list.append(final_md)
    return final_list


def remap_to_host_out(path: str, out_root: str, host_out_root: Optional[str]) -> str:
    if not host_out_root:
        return path
    out_abs = os.path.abspath(out_root)
    host_abs = os.path.abspath(host_out_root)
    path_abs = os.path.abspath(path)
    if path_abs == out_abs:
        return host_abs
    prefix = out_abs + os.sep
    if path_abs.startswith(prefix):
        rel = path_abs[len(prefix) :]
        return os.path.join(host_abs, rel)
    return path


def print_report_paths(out_root: str, selected_stages: List[str], host_out_root: Optional[str]) -> None:
    # 对外仅展示中文报告清单，原始文件清单不再打印。
    _ = (out_root, selected_stages, host_out_root)
    return


def _safe_filename(name: str) -> str:
    out = str(name or "").replace("/", "_").replace("\\", "_")
    out = " ".join(out.split())
    return out.strip() or "未命名结果"


def _ensure_unique_name(name: str, used: Set[str]) -> str:
    base = _safe_filename(name)
    stem, ext = os.path.splitext(base)
    if base not in used:
        used.add(base)
        return base
    i = 2
    while True:
        candidate = f"{stem}_{i}{ext}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        i += 1


def _module_label_from_relpath(rel_path: str) -> str:
    rel_norm = str(rel_path or "").replace("\\", "/")
    first = rel_norm.split("/", 1)[0] if rel_norm else ""
    return MODULE_DIR_CN_MAP.get(first, "审计结果")


def _cn_alias_name(rel_path: str, seq: int) -> str:
    rel_norm = str(rel_path or "").replace("\\", "/")
    base = os.path.basename(rel_norm)
    parent = os.path.basename(os.path.dirname(rel_norm))
    ext = os.path.splitext(base)[1].lower()

    direct = FILE_CN_MAP.get(base)
    if direct:
        return direct

    module_label = _module_label_from_relpath(rel_norm)

    if base == "findings.md":
        return f"{module_label}_发现.md"
    if base == "findings.json":
        return f"{module_label}_发现.json"
    if base == "index.html":
        return f"{module_label}_详情页.html"

    if base.startswith("out_") and base.endswith(".md"):
        return f"{module_label}_执行日志.md"

    if parent == "trace_cases" and base.endswith(".json"):
        case_stem = os.path.splitext(base)[0]
        return f"案例追踪_{case_stem}.json"

    if base.endswith(".html") and "-" in base:
        case_stem = os.path.splitext(base)[0]
        return f"漏洞详情_{case_stem}.html"

    if base.endswith(".json") and "-" in base:
        case_stem = os.path.splitext(base)[0]
        return f"漏洞数据_{case_stem}.json"

    if ext == ".md":
        return f"结果报告_{seq:03d}.md"
    if ext == ".json":
        return f"结果数据_{seq:03d}.json"
    if ext == ".html":
        return f"结果页面_{seq:03d}.html"
    return f"结果文件_{seq:03d}{ext or ''}"


def build_chinese_named_results(out_root: str, selected_stages: List[str]) -> List[str]:
    report_paths = collect_report_paths(out_root, selected_stages)
    if not report_paths:
        return []

    cn_dir = os.path.join(out_root, REPORT_BUNDLE_DIR)
    os.makedirs(cn_dir, exist_ok=True)

    used: Set[str] = set()
    mapping_rows: List[List[str]] = []
    generated: List[str] = []

    for idx, src in enumerate(report_paths, 1):
        if not os.path.isfile(src):
            continue
        if os.path.splitext(src)[1].lower() != ".md":
            continue
        rel = os.path.relpath(src, out_root).replace("\\", "/")
        cn_name = _ensure_unique_name(_cn_alias_name(rel, idx), used)
        dst = os.path.join(cn_dir, cn_name)
        try:
            shutil.copy2(src, dst)
        except Exception:
            continue
        generated.append(dst)
        module_label = _module_label_from_relpath(rel)
        mapping_rows.append([f"`{cn_name}`", module_label, f"`{rel}`"])

    index_path = os.path.join(cn_dir, "文件对照表.md")
    lines = ["# 报告汇总文件对照表", ""]
    if mapping_rows:
        lines.append(markdown_table(["中文文件名", "所属模块", "源路径"], mapping_rows))
    else:
        lines.append("（无可用文件）")
    lines.append("")
    write_text(index_path, "\n".join(lines))
    generated.append(index_path)
    return generated


def print_chinese_report_paths(paths: List[str], out_root: str, host_out_root: Optional[str]) -> None:
    if not paths:
        return
    unique = sorted(set(paths))
    priority = [PRIMARY_STATIC_MD, PRIMARY_DYNAMIC_MD, PRIMARY_AI_VERIFY_MD]

    def sort_key(path: str) -> Tuple[int, str]:
        name = os.path.basename(path)
        if name in priority:
            return (priority.index(name), name)
        return (len(priority) + 1, name)

    unique = sorted(unique, key=sort_key)
    bundle_dir = remap_to_host_out(os.path.join(out_root, REPORT_BUNDLE_DIR), out_root, host_out_root)
    print(f"[REPORTS-CN] 报告汇总目录: {bundle_dir}")
    print("[REPORTS-CN] 报告汇总文件:")
    for p in unique:
        shown = remap_to_host_out(p, out_root, host_out_root)
        print(f"- {shown}")


def archive_runtime_markdowns(out_root: str) -> None:
    archive_stage_dir = os.path.join(out_root, ARCHIVE_STAGE_DIR)
    os.makedirs(archive_stage_dir, exist_ok=True)
    runtime_files = [PIPELINE_STATUS_MD, AGENT_TASK_MANIFEST_MD] + PHASE_GATE_FILES
    for name in runtime_files:
        src = os.path.join(out_root, name)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(archive_stage_dir, name)
        try:
            shutil.copy2(src, dst)
        except Exception:
            continue
        try:
            os.remove(src)
        except Exception:
            pass


def stage_outputs(out_root: str, stage: str) -> List[str]:
    if stage == "route_mapper":
        return [
            os.path.join(out_root, "route_mapper", "routes.json"),
            os.path.join(out_root, "route_mapper", "routes.md"),
            os.path.join(out_root, "route_mapper", "burp_templates"),
        ]
    if stage == "call_graph":
        return [
            os.path.join(out_root, "route_tracer", "call_graph.json"),
            os.path.join(out_root, "route_tracer", "call_graph.md"),
        ]
    if stage == "route_tracer":
        return [os.path.join(out_root, "route_tracer")]
    if stage == "ai_audit":
        return [
            os.path.join(out_root, "ai_audit", "ai_findings.json"),
            os.path.join(out_root, "ai_audit", "findings.json"),
            os.path.join(out_root, "ai_audit", "ai_audit_report.json"),
            os.path.join(out_root, "ai_audit", "ai_audit_context"),
        ]
    if stage == "sql_audit":
        return [os.path.join(out_root, "sql_audit")]
    if stage == "auth_audit":
        return [os.path.join(out_root, "auth_audit")]
    if stage == "file_audit":
        return [os.path.join(out_root, "file_audit")]
    if stage == "rce_audit":
        return [os.path.join(out_root, "rce_audit")]
    if stage == "ssrf_xxe_audit":
        return [os.path.join(out_root, "ssrf_xxe_audit")]
    if stage == "xss_ssti_audit":
        return [os.path.join(out_root, "xss_ssti_audit")]
    if stage == "csrf_audit":
        return [os.path.join(out_root, "csrf_audit")]
    if stage == "var_override_audit":
        return [os.path.join(out_root, "var_override_audit")]
    if stage == "serialize_audit":
        return [os.path.join(out_root, "serialize_audit")]
    if stage == "vuln_scanner":
        return [os.path.join(out_root, "vuln_report")]
    if stage == "mcp_adapter":
        return [os.path.join(out_root, "mcp_parsed", "summary.json")]
    if stage == "severity_enrich":
        return list_findings_files(out_root)
    if stage == "ai_confirm":
        return [os.path.join(out_root, "ai_confirm.json"), os.path.join(out_root, "ai_context")]
    if stage == "report_refresh":
        return [os.path.join(out_root, "sql_audit"), os.path.join(out_root, "file_audit"), os.path.join(out_root, "rce_audit"), os.path.join(out_root, "ssrf_xxe_audit"), os.path.join(out_root, "xss_ssti_audit"), os.path.join(out_root, "csrf_audit"), os.path.join(out_root, "var_override_audit"), os.path.join(out_root, "serialize_audit"), os.path.join(out_root, "auth_audit")]
    if stage == "debug_verify":
        return [
            os.path.join(out_root, "debug_verify", "debug_cases.json"),
            os.path.join(out_root, "debug_verify", "poc_plan.json"),
            os.path.join(out_root, "debug_verify", "poc_plan.md"),
            os.path.join(out_root, "debug_verify", DEBUG_EVIDENCE_JSON_CN),
            os.path.join(out_root, "debug_verify", "动态调试证据.md"),
            os.path.join(out_root, "debug_verify", DEBUG_PROCESS_JSON_CN),
            os.path.join(out_root, "debug_verify", "动态调试过程.md"),
            os.path.join(out_root, "debug_verify", DEBUG_POC_JSON_CN),
            os.path.join(out_root, "debug_verify", "动态调试PoC.md"),
            os.path.join(out_root, "debug_verify", DEBUG_FUNC_TRACE_JSON_CN),
            os.path.join(out_root, "debug_verify", "函数追踪证据.md"),
            os.path.join(out_root, "debug_verify", "动态运行元信息.json"),
            os.path.join(out_root, "debug_verify", "动态运行元信息.md"),
        ]
    if stage == "ai_deep_audit":
        return [
            os.path.join(out_root, "ai_deep_audit", "ai_deep_audit_summary.json"),
            os.path.join(out_root, "ai_deep_audit", "AI深入审计阶段报告.md"),
            os.path.join(out_root, "debug_verify", DEBUG_EVIDENCE_JSON_CN),
            os.path.join(out_root, "debug_verify", "动态调试证据.md"),
        ]
    if stage == "phase_attack_chain":
        return [os.path.join(out_root, "_meta", "phase4_attack_chain.md")]
    if stage == "final_report":
        return [
            os.path.join(out_root, PRIMARY_STATIC_MD),
            os.path.join(out_root, PRIMARY_DYNAMIC_MD),
            os.path.join(out_root, PRIMARY_AI_VERIFY_MD),
            os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_JSON_CN),
            os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_APPENDIX_MD_CN),
            os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_MD_CN),
            os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_JSON_CN_ALT),
            os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_APPENDIX_MD_CN_ALT),
            os.path.join(out_root, ARCHIVE_BINDING_DIR, REPORT_MD_CN_ALT),
            os.path.join(out_root, ARCHIVE_BINDING_DIR, "静态_动态_AI_结论对照表.md"),
            os.path.join(out_root, ARCHIVE_STAGE_DIR),
            os.path.join(out_root, ARCHIVE_DEBUG_DIR),
            os.path.join(out_root, ARCHIVE_BURP_DIR),
            os.path.join(out_root, ARCHIVE_QUALITY_DIR),
        ]
    if stage == "phase_report_index":
        return [
            os.path.join(out_root, "_meta", "phase1_map.md"),
            os.path.join(out_root, "_meta", "phase2_risk_map.md"),
            os.path.join(out_root, "_meta", "phase3_trace_log.md"),
            os.path.join(out_root, "_meta", "phase4_attack_chain.md"),
            os.path.join(out_root, "_meta", "phase5_report_index.md"),
            os.path.join(out_root, "_meta", RUN_CONTEXT_JSON),
            os.path.join(out_root, AGENT_RUNTIME_JSON),
            os.path.join(out_root, AGENT_REAPER_EVENTS_JSONL),
            os.path.join(out_root, STEP_VERIFIER_DIR),
            os.path.join(out_root, PIPELINE_STATUS_MD),
            os.path.join(out_root, AGENT_TASK_MANIFEST_MD),
            os.path.join(out_root, "phase_gate_0.md"),
            os.path.join(out_root, "phase_gate_1.md"),
            os.path.join(out_root, "phase_gate_2.md"),
            os.path.join(out_root, "phase_gate_3.md"),
            os.path.join(out_root, "phase_gate_4.md"),
            os.path.join(out_root, "phase_gate_5.md"),
            os.path.join(out_root, "phase_gate_6.md"),
            os.path.join(out_root, "phase_gate_7.md"),
        ]
    if stage == "evidence_check":
        return [
            os.path.join(out_root, ARCHIVE_QUALITY_DIR, "证据校验.json"),
            os.path.join(out_root, ARCHIVE_QUALITY_DIR, "证据校验.md"),
            os.path.join(out_root, ARCHIVE_QUALITY_DIR, RESOURCE_CLEANUP_MD),
            os.path.join(out_root, STEP_VERIFIER_DIR),
        ]
    return []


def outputs_exist(outputs: List[str]) -> bool:
    for p in outputs:
        if os.path.isdir(p):
            if not os.path.exists(p):
                return False
            base = os.path.basename(p.rstrip("/"))
            if base in REPORT_DIRS:
                if not _module_outputs_complete(p, base):
                    return False
        else:
            if not os.path.exists(p):
                return False
    return True


def _module_outputs_complete(dir_path: str, module: str) -> bool:
    # Must have findings/auth evidence and a module report
    if module == "auth_audit":
        required = ["auth_evidence.json"]
        files = os.listdir(dir_path) if os.path.isdir(dir_path) else []
        if not all(os.path.exists(os.path.join(dir_path, r)) for r in required):
            return False
        has_reports = (
            any(f.endswith(".md") and "_auth_audit_" in f for f in files)
            and any(f.endswith(".md") and "_auth_mapping_" in f for f in files)
            and any(f.endswith(".md") and "_auth_README_" in f for f in files)
        )
        return has_reports
    if module == "vuln_report":
        if not os.path.exists(os.path.join(dir_path, "composer_audit.json")):
            return False
        if not os.path.exists(os.path.join(dir_path, "composer_audit.md")):
            return False
        return True

    findings = os.path.join(dir_path, "findings.json")
    if not os.path.exists(findings):
        return False
    files = os.listdir(dir_path) if os.path.isdir(dir_path) else []
    return any(f.endswith(".md") and f"_{module}_" in f for f in files)


def stage_input_hash(stage: str, project_sig: str, out_root: str, config_path: str, quick_mode: bool = False) -> str:
    parts = [project_sig]
    common = os.path.join(SCRIPT_DIR, "common.py")
    audit_helpers = os.path.join(SCRIPT_DIR, "audit_helpers.py")

    if stage == "route_mapper":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "route_mapper.py"), common]))
    elif stage == "call_graph":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "call_graph.py"), common]))
    elif stage == "route_tracer":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "route_tracer.py"), common]))
        parts.append(hash_paths([os.path.join(out_root, "route_mapper", "routes.json")]))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer", "call_graph.json")]))
    elif stage == "ai_audit":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "ai_audit.py"), common]))
        parts.append(hash_paths([os.path.join(out_root, "route_mapper", "routes.json")]))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer")]))
        parts.append(hash_paths([os.path.join(out_root, "mcp_raw", "ai-audit-mcp.json")]))
    elif stage in {
        "sql_audit",
        "auth_audit",
        "file_audit",
        "rce_audit",
        "ssrf_xxe_audit",
        "xss_ssti_audit",
        "csrf_audit",
        "var_override_audit",
        "serialize_audit",
    }:
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, f"{stage}.py"), common, audit_helpers]))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer")]))
    elif stage == "vuln_scanner":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "vuln_scanner.py")]))
    elif stage == "mcp_adapter":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "mcp_adapter.py"), config_path]))
    elif stage == "severity_enrich":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "severity_enricher.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "ai_confirm":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "ai_confirm.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
        parts.append(hash_paths([os.path.join(out_root, "route_tracer"), os.path.join(out_root, "route_mapper", "routes.json")]))
    elif stage == "debug_verify":
        parts.append(
            hash_paths(
                [
                    os.path.join(SCRIPT_DIR, "debug_cases.py"),
                    os.path.join(SCRIPT_DIR, "debug_runner.py"),
                    os.path.join(SCRIPT_DIR, "auto_slice.py"),
                    os.path.join(SCRIPT_DIR, "mcp_config.debug.json"),
                    os.path.join(SCRIPT_DIR, "..", "ai-confirm-mcp", "scripts", "ai_confirm_mcp.py"),
                ]
            )
        )
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "..", "php-audit-common", "references", "debug_change_rules.yml")]))
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "..", "wordlists")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "ai_deep_audit":
        parts.append(
            hash_paths(
                [
                    os.path.join(SCRIPT_DIR, "ai_deep_audit.py"),
                    os.path.join(SCRIPT_DIR, "debug_runner.py"),
                    os.path.join(SCRIPT_DIR, "debug_cases.py"),
                ]
            )
        )
        parts.append(hash_paths([os.path.join(out_root, "debug_verify", "debug_cases.json")]))
        parts.append(hash_paths([os.path.join(out_root, "debug_verify", DEBUG_EVIDENCE_JSON_CN)]))
        parts.append(hash_paths([os.path.join(out_root, "mcp_raw", "ai-confirm-mcp-debug.json")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "report_refresh":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "report_refresh.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "phase_attack_chain":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "phase_attack_chain.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
    elif stage == "phase_report_index":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "phase_report_index.py")]))
        parts.append(hash_paths([os.path.join(out_root, "_meta")]))
    elif stage == "final_report":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "final_report.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
        parts.append(hash_paths([
            os.path.join(out_root, "debug_verify", DEBUG_EVIDENCE_JSON_CN),
            os.path.join(out_root, "debug_verify", "动态调试证据.md"),
            os.path.join(out_root, "debug_verify", DEBUG_FUNC_TRACE_JSON_CN),
            os.path.join(out_root, "debug_verify", "函数追踪证据.md"),
        ]))
    elif stage == "evidence_check":
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, "evidence_check.py")]))
        parts.append(hash_paths(list_findings_files(out_root)))
        parts.append(hash_paths([os.path.join(out_root, "_meta")]))
        parts.append(hash_paths([
            os.path.join(out_root, "debug_verify", DEBUG_EVIDENCE_JSON_CN),
            os.path.join(out_root, "debug_verify", "动态调试证据.md"),
            os.path.join(out_root, "debug_verify", DEBUG_FUNC_TRACE_JSON_CN),
            os.path.join(out_root, "debug_verify", "函数追踪证据.md"),
            os.path.join(out_root, REPORT_MD_CN),
            os.path.join(out_root, REPORT_APPENDIX_MD_CN),
        ]))
    else:
        parts.append(hash_paths([os.path.join(SCRIPT_DIR, f"{stage}.py")]))

    if quick_mode and stage in RULE_AUDIT_MODULES:
        parts.append("rule_audit_quick_mode=1")

    return hash_strings(parts)


def build_cmd(stage: str, project_root: str, out_root: str, config_path: str, threads: int, progress: bool) -> List[str]:
    py = resolve_python()
    if stage == "route_mapper":
        cmd = [py, os.path.join(SCRIPT_DIR, "route_mapper.py"), "--project", project_root, "--out", out_root]
        if threads is not None:
            cmd.extend(["--threads", str(threads)])
        cmd.append("--progress" if progress else "--no-progress")
        return cmd
    if stage == "call_graph":
        cmd = [py, os.path.join(SCRIPT_DIR, "call_graph.py"), "--project", project_root, "--out", out_root]
        if threads is not None:
            cmd.extend(["--threads", str(threads)])
        cmd.append("--progress" if progress else "--no-progress")
        return cmd
    if stage == "route_tracer":
        return [py, os.path.join(SCRIPT_DIR, "route_tracer.py"), "--project", project_root, "--out", out_root]
    if stage == "ai_audit":
        return [py, os.path.join(SCRIPT_DIR, "ai_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "sql_audit":
        return [py, os.path.join(SCRIPT_DIR, "sql_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "auth_audit":
        return [py, os.path.join(SCRIPT_DIR, "auth_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "file_audit":
        return [py, os.path.join(SCRIPT_DIR, "file_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "rce_audit":
        return [py, os.path.join(SCRIPT_DIR, "rce_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "ssrf_xxe_audit":
        return [py, os.path.join(SCRIPT_DIR, "ssrf_xxe_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "xss_ssti_audit":
        return [py, os.path.join(SCRIPT_DIR, "xss_ssti_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "csrf_audit":
        return [py, os.path.join(SCRIPT_DIR, "csrf_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "var_override_audit":
        return [py, os.path.join(SCRIPT_DIR, "var_override_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "serialize_audit":
        return [py, os.path.join(SCRIPT_DIR, "serialize_audit.py"), "--project", project_root, "--out", out_root]
    if stage == "vuln_scanner":
        return [py, os.path.join(SCRIPT_DIR, "vuln_scanner.py"), "--project", project_root, "--out", out_root]
    if stage == "mcp_adapter":
        cmd = [py, os.path.join(SCRIPT_DIR, "mcp_adapter.py"), "--project", project_root, "--out", out_root, "--all"]
        if config_path and os.path.exists(config_path):
            cmd.extend(["--config", config_path])
        return cmd
    if stage == "severity_enrich":
        return [py, os.path.join(SCRIPT_DIR, "severity_enricher.py"), "--project", project_root, "--out", out_root]
    if stage == "ai_confirm":
        return [py, os.path.join(SCRIPT_DIR, "ai_confirm.py"), "--project", project_root, "--out", out_root]
    if stage == "debug_verify":
        cmd = [py, os.path.join(SCRIPT_DIR, "debug_runner.py"), "--project", project_root, "--out", out_root]
        profile = detect_framework_profile(project_root)
        profile_path = write_framework_profile(out_root, profile)
        if profile_path:
            cmd.extend(["--framework-profile", profile_path])
        return cmd
    if stage == "ai_deep_audit":
        def _env_int(name: str, default: int) -> int:
            raw = os.environ.get(name, "").strip()
            if not raw:
                return default
            try:
                val = int(raw)
            except Exception:
                return default
            return val if val >= 0 else default

        def _env_bool(name: str, default: bool) -> bool:
            raw = os.environ.get(name, "").strip().lower()
            if not raw:
                return default
            return raw in {"1", "true", "yes", "on"}

        ai_model = (
            os.environ.get("AI_DEEP_MODEL")
            or os.environ.get("AI_CONFIRM_MODEL")
            or os.environ.get("AI_AUDIT_MODEL")
            or "sonnet"
        )
        ai_rounds = _env_int("AI_DEEP_ROUNDS", 2)
        ai_candidates = _env_int("AI_DEEP_CANDIDATES_PER_ROUND", 5)
        ai_timeout = _env_int("AI_DEEP_TIMEOUT", 30)
        ai_realtime = _env_bool("AI_DEEP_REALTIME", True)
        ai_force_all = _env_bool("AI_DEEP_FORCE_ALL", True)
        until_confirmed = _env_bool("AI_DEEP_UNTIL_CONFIRMED", True)
        trace_verbose = _env_bool("AI_DEEP_TRACE_VERBOSE", True)

        cmd = [
            py,
            os.path.join(SCRIPT_DIR, "ai_deep_audit.py"),
            "--project",
            project_root,
            "--out",
            out_root,
            "--ai-model",
            ai_model,
            "--ai-rounds",
            str(ai_rounds),
            "--ai-candidates-per-round",
            str(ai_candidates),
            "--ai-timeout",
            str(ai_timeout),
        ]
        if trace_verbose:
            cmd.append("--trace-verbose")
        if ai_realtime:
            cmd.append("--ai-realtime")
        else:
            cmd.append("--disable-ai-realtime")
        if ai_force_all:
            cmd.append("--ai-force-all")
        else:
            cmd.append("--disable-ai-force-all")
        if until_confirmed:
            cmd.append("--until-confirmed")
        else:
            cmd.append("--allow-conditional-stop")
        return cmd
    if stage == "report_refresh":
        return [py, os.path.join(SCRIPT_DIR, "report_refresh.py"), "--project", project_root, "--out", out_root]
    if stage == "phase_attack_chain":
        return [py, os.path.join(SCRIPT_DIR, "phase_attack_chain.py"), "--project", project_root, "--out", out_root]
    if stage == "final_report":
        return [py, os.path.join(SCRIPT_DIR, "final_report.py"), "--project", project_root, "--out", out_root]
    if stage == "phase_report_index":
        return [py, os.path.join(SCRIPT_DIR, "phase_report_index.py"), "--project", project_root, "--out", out_root]
    if stage == "evidence_check":
        cmd = [py, os.path.join(SCRIPT_DIR, "evidence_check.py"), "--project", project_root, "--out", out_root]
        if os.environ.get("EVIDENCE_STRICT") == "1":
            cmd.append("--strict")
        return cmd
    raise SystemExit(f"Unknown stage: {stage}")


def build_stage_env(stage: str, ai_ok: bool, run_id: str = "") -> Dict[str, str]:
    env = os.environ.copy()
    if ai_ok and stage in RULE_AUDIT_MODULES:
        env["RULE_AUDIT_QUICK"] = "1"
        env.setdefault("RULE_AUDIT_QUICK_REASON", "ai_audit_ok")
    else:
        env.pop("RULE_AUDIT_QUICK", None)
        env.pop("RULE_AUDIT_QUICK_REASON", None)
    if run_id:
        env["AUDIT_RUN_ID"] = run_id
    return env


def expand_dependencies(selected: Set[str]) -> Set[str]:
    expanded = set(selected)
    changed = True
    while changed:
        changed = False
        for s in list(expanded):
            for dep in DEPS.get(s, []):
                if dep not in expanded:
                    expanded.add(dep)
                    changed = True
    return expanded


def run_stage_command(stage: str, cmd: List[str], project_root: str, env: Dict[str, str]) -> Dict[str, object]:
    started = time.time()
    proc = subprocess.run(cmd, cwd=project_root, capture_output=False, env=env)
    elapsed_ms = int((time.time() - started) * 1000)
    return {
        "stage": stage,
        "return_code": int(proc.returncode),
        "duration_ms": elapsed_ms,
        "cmd": cmd,
    }


def run_phase_verifier_command(
    phase_id: int,
    project_root: str,
    out_root: str,
    env: Dict[str, str],
) -> Dict[str, object]:
    py = resolve_python()
    cmd = [
        py,
        os.path.join(SCRIPT_DIR, "step_verifier.py"),
        "--project",
        project_root,
        "--out",
        out_root,
        "--phase-id",
        str(int(phase_id)),
    ]
    started = time.time()
    proc = subprocess.run(cmd, cwd=project_root, capture_output=False, env=env)
    elapsed_ms = int((time.time() - started) * 1000)
    report_path = os.path.join(out_root, STEP_VERIFIER_DIR, f"phase_{int(phase_id)}_verifier.md")
    return {
        "phase_id": int(phase_id),
        "return_code": int(proc.returncode),
        "duration_ms": elapsed_ms,
        "cmd": cmd,
        "report_path": report_path,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root (default {project}_audit)")
    ap.add_argument("--modules", default=None, help="Comma-separated module list or 'all'")
    ap.add_argument("--skip-mcp", action="store_true", help="Skip mcp_adapter stage")
    ap.add_argument("--no-cache", action="store_true", help="Disable cache")
    ap.add_argument("--force", action="store_true", help="Force re-run all stages")
    ap.add_argument("--config", default=None, help="mcp_config.json path")
    ap.add_argument("--evidence-strict", action="store_true", help="Fail if evidence_check finds issues")
    ap.add_argument("--threads", type=int, default=0, help="Worker threads for file scans (0=auto)")
    ap.add_argument("--max-parallel-agents", type=int, default=4, help="Max parallel stage workers for multi-agent scheduling")
    ap.add_argument("--progress", dest="progress", action="store_true", default=True, help="Show progress bars for file scans (default: on)")
    ap.add_argument("--no-progress", dest="progress", action="store_false", help="Disable progress bars")
    args = ap.parse_args()

    ensure_running_in_container()
    print("[INFO] Running inside docker container.")

    project_root = os.path.abspath(args.project)
    out_root = build_output_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)
    host_out_root = os.environ.get("SKILLS_HOST_OUT")
    run_id_hint = str(os.environ.get("AUDIT_RUN_ID") or "").strip()
    if not run_id_hint:
        run_id_hint = f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
        os.environ["AUDIT_RUN_ID"] = run_id_hint
    acquire_run_lock(out_root, run_id_hint)
    run_id, run_context_path, run_context = init_run_context(out_root, project_root)
    allow_dynamic_stage_cache = env_flag("ALLOW_DYNAMIC_STAGE_CACHE", False)
    print(f"[INFO] Run ID: {run_id}")

    modules_provided = args.modules is not None
    if not modules_provided or args.modules == "all":
        selected = set(DEFAULT_MODULES)
    else:
        selected = set([m.strip() for m in args.modules.split(",") if m.strip()])

    if args.skip_mcp:
        selected.discard("mcp_adapter")
        if not modules_provided:
            selected.add("vuln_scanner")

    # Dynamic debug and AI deep audit are mandatory for this skill pipeline.
    selected.update({"debug_verify", "ai_deep_audit"})
    selected = expand_dependencies(selected)
    if args.skip_mcp:
        selected.discard("mcp_adapter")

    if args.config:
        config_path = args.config
    else:
        default_cfg = os.path.join(SCRIPT_DIR, "mcp_config.json")
        example_cfg = os.path.join(SCRIPT_DIR, "mcp_config.example.json")
        config_path = default_cfg if os.path.exists(default_cfg) else example_cfg

    project_sig = project_signature(project_root)
    meta = load_meta(out_root)

    if args.evidence_strict:
        os.environ["EVIDENCE_STRICT"] = "1"

    started_at = time.time()
    ai_ok = False
    selected_stages = [s for s in PIPELINE_ORDER if s in selected]
    selected_stage_set = set(selected_stages)
    stage_status = init_pipeline_stage_status(selected_stage_set)
    max_parallel_agents = max(1, int(args.max_parallel_agents or 1))
    agent_runtime = init_agent_runtime(out_root)
    phase_verifier = init_phase_verifier_state()
    phase0_agents = agents_for_stage("__phase0__")
    phase0_agent_ids = [str(a.get("id") or "-") for a in phase0_agents]
    failed_stage = ""

    stage_status["__phase0__"] = STATUS_RUNNING
    mark_stage_context(run_context, "__phase0__", STATUS_RUNNING, phase_id=0)
    agent_mark_running(
        out_root,
        agent_runtime,
        stage="__phase0__",
        phase_id=0,
        group_index=1,
        agents=phase0_agents,
    )
    write_run_context(run_context_path, run_context)
    append_pipeline_event(
        out_root,
        event_type="phase_start",
        stage="__phase0__",
        status=STATUS_RUNNING,
        note="阶段0预检与编排启动",
    )
    write_pipeline_runtime_files(
        out_root,
        stage_status,
        current_stage="__phase0__",
        started_at=started_at,
        event_note="阶段0预检与编排启动",
        agent_runtime=agent_runtime,
        phase_verifier=phase_verifier,
    )
    print(f"[PIPELINE] 状态面板: {remap_to_host_out(os.path.join(out_root, PIPELINE_STATUS_MD), out_root, host_out_root)}")

    stage_status["__phase0__"] = STATUS_DONE
    mark_stage_context(run_context, "__phase0__", STATUS_DONE, phase_id=0, return_code=0, duration_ms=0)
    agent_mark_final(
        out_root,
        agent_runtime,
        stage="__phase0__",
        phase_id=0,
        group_index=1,
        agent_ids=phase0_agent_ids,
        status=STATUS_DONE,
        reason="phase0_done",
        return_code=0,
        duration_ms=0,
    )
    write_run_context(run_context_path, run_context)
    append_pipeline_event(
        out_root,
        event_type="phase_done",
        stage="__phase0__",
        status=STATUS_DONE,
        note="阶段0预检与编排完成",
    )
    write_pipeline_runtime_files(
        out_root,
        stage_status,
        current_stage="__phase0__",
        started_at=started_at,
        event_note="阶段0预检与编排完成",
        agent_runtime=agent_runtime,
        phase_verifier=phase_verifier,
    )

    verifier_stage = "phase_verifier_0"
    set_phase_verifier_state(phase_verifier, 0, VERIFIER_RUNNING, note="agent-verifier 执行中")
    mark_stage_context(run_context, verifier_stage, STATUS_RUNNING, phase_id=0)
    agent_mark_running(
        out_root,
        agent_runtime,
        stage=verifier_stage,
        phase_id=0,
        group_index=99,
        agents=[VERIFIER_AGENT],
    )
    write_run_context(run_context_path, run_context)
    append_pipeline_event(
        out_root,
        event_type="verifier_start",
        stage=verifier_stage,
        status=STATUS_RUNNING,
        note="阶段0质检启动",
        extra={"phase_id": 0, "agent": VERIFIER_AGENT["id"]},
    )
    write_pipeline_runtime_files(
        out_root,
        stage_status,
        current_stage=verifier_stage,
        started_at=started_at,
        event_note="阶段0质检执行中: agent-verifier",
        agent_runtime=agent_runtime,
        phase_verifier=phase_verifier,
    )
    verifier_env = os.environ.copy()
    verifier_env["AUDIT_RUN_ID"] = run_id
    vres0 = run_phase_verifier_command(0, project_root, out_root, verifier_env)
    vrc0 = int(vres0.get("return_code", 1))
    vreport0 = str(vres0.get("report_path") or "")
    if vrc0 == 0:
        set_phase_verifier_state(phase_verifier, 0, VERIFIER_PASS, note="阶段0验收通过", report_path=vreport0)
        mark_stage_context(run_context, verifier_stage, STATUS_DONE, phase_id=0, return_code=0, duration_ms=int(vres0.get("duration_ms") or 0))
        agent_mark_final(
            out_root,
            agent_runtime,
            stage=verifier_stage,
            phase_id=0,
            group_index=99,
            agent_ids=[VERIFIER_AGENT["id"]],
            status=STATUS_DONE,
            reason="verifier_pass",
            return_code=0,
            duration_ms=int(vres0.get("duration_ms") or 0),
        )
        append_pipeline_event(
            out_root,
            event_type="verifier_pass",
            stage=verifier_stage,
            status=STATUS_DONE,
            note="阶段0质检通过",
            extra={"phase_id": 0, "report_path": vreport0},
        )
    else:
        set_phase_verifier_state(phase_verifier, 0, VERIFIER_BLOCK, note="阶段0验收阻断", report_path=vreport0)
        mark_stage_context(run_context, verifier_stage, STATUS_FAILED, phase_id=0, return_code=vrc0, duration_ms=int(vres0.get("duration_ms") or 0))
        agent_mark_final(
            out_root,
            agent_runtime,
            stage=verifier_stage,
            phase_id=0,
            group_index=99,
            agent_ids=[VERIFIER_AGENT["id"]],
            status=STATUS_FAILED,
            reason="verifier_block",
            return_code=vrc0,
            duration_ms=int(vres0.get("duration_ms") or 0),
        )
        append_pipeline_event(
            out_root,
            event_type="verifier_block",
            stage=verifier_stage,
            status=STATUS_FAILED,
            note="阶段0质检阻断",
            extra={"phase_id": 0, "report_path": vreport0},
        )
        failed_stage = verifier_stage
    write_run_context(run_context_path, run_context)
    write_pipeline_runtime_files(
        out_root,
        stage_status,
        current_stage=verifier_stage,
        started_at=started_at,
        event_note=f"阶段0质检{'通过' if vrc0 == 0 else '阻断'}",
        agent_runtime=agent_runtime,
        phase_verifier=phase_verifier,
    )

    phase_groups: Dict[int, List[List[str]]] = {
        1: [["route_mapper", "vuln_scanner", "mcp_adapter"], ["auth_audit"]],
        2: [["call_graph"], ["route_tracer"]],
        3: [["ai_audit"], ["severity_enrich"], ["ai_confirm"]],
        4: [[
            "sql_audit",
            "rce_audit",
            "file_audit",
            "ssrf_xxe_audit",
            "xss_ssti_audit",
            "csrf_audit",
            "var_override_audit",
            "serialize_audit",
        ]],
        5: [["debug_verify"]],
        6: [["ai_deep_audit"]],
        7: [["report_refresh", "phase_attack_chain", "phase_report_index"], ["final_report"], ["evidence_check"]],
    }

    pending: Set[str] = set(selected_stages)
    if failed_stage:
        pending = set()
    for phase in PIPELINE_PHASES:
        pid = int(phase["id"])
        if pid == 0:
            continue
        groups = phase_groups.get(pid, [])
        active_in_phase = [s for group in groups for s in group if s in pending]
        if not active_in_phase:
            continue

        append_pipeline_event(
            out_root,
            event_type="phase_start",
            stage=f"phase_{pid}",
            status=STATUS_RUNNING,
            note=f"阶段{pid}启动: {phase['name']}",
            extra={"phase_id": pid},
        )
        write_pipeline_runtime_files(
            out_root,
            stage_status,
            current_stage=active_in_phase[0],
            started_at=started_at,
            event_note=f"阶段{pid}启动: {phase['name']}",
            agent_runtime=agent_runtime,
            phase_verifier=phase_verifier,
        )

        phase_failed = False
        for group_idx, group in enumerate(groups, start=1):
            if failed_stage:
                phase_failed = True
                break
            group_active = [s for s in group if s in pending]
            if not group_active:
                continue

            runnable: List[Dict[str, object]] = []
            cached_or_skipped: List[str] = []

            for stage in group_active:
                stage_agents = agents_for_stage(stage)
                agent_ids = [str(a.get("id") or "-") for a in stage_agents]
                if not dependencies_done(stage, stage_status, selected_stage_set):
                    failed_stage = f"dependency_blocked:{stage}"
                    phase_failed = True
                    mark_stage_context(run_context, stage, STATUS_FAILED, phase_id=pid, return_code=1, duration_ms=0)
                    agent_mark_final(
                        out_root,
                        agent_runtime,
                        stage=stage,
                        phase_id=pid,
                        group_index=group_idx,
                        agent_ids=agent_ids,
                        status=STATUS_FAILED,
                        reason="dependency_blocked",
                        return_code=1,
                        duration_ms=0,
                    )
                    write_run_context(run_context_path, run_context)
                    append_pipeline_event(
                        out_root,
                        event_type="stage_blocked",
                        stage=stage,
                        status=STATUS_FAILED,
                        note=f"依赖未满足: {_stage_text(stage)}",
                        extra={"phase_id": pid, "group_index": group_idx},
                    )
                    break

                quick_mode = ai_ok and stage in RULE_AUDIT_MODULES
                if quick_mode:
                    print(f"[INFO] {stage} running in quick mode (ai_audit ok)")

                outputs = stage_outputs(out_root, stage)
                input_hash = stage_input_hash(stage, project_sig, out_root, config_path, quick_mode=quick_mode)
                previous = meta.get("stages", {}).get(stage)
                cache_hit = bool(
                    previous
                    and previous.get("input_hash") == input_hash
                    and outputs_exist(outputs)
                )
                if args.force or args.no_cache:
                    cache_hit = False
                if stage in NON_CACHEABLE_STAGES and not allow_dynamic_stage_cache:
                    cache_hit = False

                if cache_hit:
                    print(f"[SKIP] {stage} (cache)")
                    stage_status[stage] = STATUS_SKIPPED
                    pending.discard(stage)
                    cached_or_skipped.append(stage)
                    mark_stage_context(run_context, stage, STATUS_SKIPPED, phase_id=pid, cache_hit=True, return_code=0, duration_ms=0)
                    agent_mark_final(
                        out_root,
                        agent_runtime,
                        stage=stage,
                        phase_id=pid,
                        group_index=group_idx,
                        agent_ids=agent_ids,
                        status=STATUS_SKIPPED,
                        reason="cache_hit",
                        return_code=0,
                        duration_ms=0,
                    )
                    write_run_context(run_context_path, run_context)
                    append_pipeline_event(
                        out_root,
                        event_type="stage_skip_cache",
                        stage=stage,
                        status=STATUS_SKIPPED,
                        note=f"缓存命中: {_stage_text(stage)}",
                        extra={"agents": agent_ids, "phase_id": pid, "group_index": group_idx},
                    )
                    if stage == "ai_audit":
                        ai_ok = ai_audit_ok(out_root)
                        if ai_ok:
                            print("[INFO] ai_audit ok; rule modules will run in quick mode.")
                    continue

                cmd = build_cmd(stage, project_root, out_root, config_path, args.threads, args.progress)
                print(f"[RUN] {stage}: {' '.join(cmd)}")
                stage_status[stage] = STATUS_RUNNING
                mark_stage_context(run_context, stage, STATUS_RUNNING, phase_id=pid, cache_hit=False)
                agent_mark_running(
                    out_root,
                    agent_runtime,
                    stage=stage,
                    phase_id=pid,
                    group_index=group_idx,
                    agents=stage_agents,
                )
                write_run_context(run_context_path, run_context)
                runnable.append(
                    {
                        "stage": stage,
                        "cmd": cmd,
                        "env": build_stage_env(stage, ai_ok, run_id=run_id),
                        "outputs": outputs,
                        "input_hash": input_hash,
                        "agents": agent_ids,
                        "phase_id": pid,
                        "group_index": group_idx,
                    }
                )
                append_pipeline_event(
                    out_root,
                    event_type="stage_start",
                    stage=stage,
                    status=STATUS_RUNNING,
                    note=f"阶段开始: {_stage_text(stage)}",
                    extra={"agents": agent_ids, "cmd": cmd, "phase_id": pid, "group_index": group_idx},
                )

            if failed_stage:
                break

            if cached_or_skipped:
                write_pipeline_runtime_files(
                    out_root,
                    stage_status,
                    current_stage=cached_or_skipped[0],
                    started_at=started_at,
                    event_note=f"阶段缓存命中: {', '.join([_stage_text(s) for s in cached_or_skipped])}",
                    agent_runtime=agent_runtime,
                    phase_verifier=phase_verifier,
                )

            if not runnable:
                continue

            write_pipeline_runtime_files(
                out_root,
                stage_status,
                current_stage=str(runnable[0].get("stage") or ""),
                started_at=started_at,
                event_note=f"阶段{pid} 任务组{group_idx} 并行执行: {', '.join([_stage_text(str(x.get('stage') or '')) for x in runnable])}",
                agent_runtime=agent_runtime,
                phase_verifier=phase_verifier,
            )

            for idx in range(0, len(runnable), max_parallel_agents):
                batch = runnable[idx : idx + max_parallel_agents]
                worker_count = min(max_parallel_agents, len(batch))
                with ThreadPoolExecutor(max_workers=worker_count) as ex:
                    fut_map = {
                        ex.submit(
                            run_stage_command,
                            str(job["stage"]),
                            list(job["cmd"]),
                            project_root,
                            dict(job["env"]),
                        ): job
                        for job in batch
                    }

                    for fut in as_completed(fut_map):
                        job = fut_map[fut]
                        stage = str(job["stage"])
                        result = fut.result()
                        rc = int(result.get("return_code", 1))
                        duration_ms = int(result.get("duration_ms", 0))
                        pending.discard(stage)

                        if rc != 0:
                            stage_status[stage] = STATUS_FAILED
                            failed_stage = stage
                            phase_failed = True
                            mark_stage_context(
                                run_context,
                                stage,
                                STATUS_FAILED,
                                phase_id=int(job.get("phase_id") or 0),
                                return_code=rc,
                                duration_ms=duration_ms,
                            )
                            agent_mark_final(
                                out_root,
                                agent_runtime,
                                stage=stage,
                                phase_id=int(job.get("phase_id") or 0),
                                group_index=int(job.get("group_index") or 0),
                                agent_ids=[str(x) for x in (job.get("agents") or [])],
                                status=STATUS_FAILED,
                                reason="stage_failed",
                                return_code=rc,
                                duration_ms=duration_ms,
                            )
                            write_run_context(run_context_path, run_context)
                            append_pipeline_event(
                                out_root,
                                event_type="stage_fail",
                                stage=stage,
                                status=STATUS_FAILED,
                                note=f"阶段失败: {_stage_text(stage)}",
                                extra={
                                    "agents": job.get("agents"),
                                    "return_code": rc,
                                    "duration_ms": duration_ms,
                                    "phase_id": job.get("phase_id"),
                                    "group_index": job.get("group_index"),
                                },
                            )
                        else:
                            stage_status[stage] = STATUS_DONE
                            mark_stage_context(
                                run_context,
                                stage,
                                STATUS_DONE,
                                phase_id=int(job.get("phase_id") or 0),
                                return_code=rc,
                                duration_ms=duration_ms,
                            )
                            agent_mark_final(
                                out_root,
                                agent_runtime,
                                stage=stage,
                                phase_id=int(job.get("phase_id") or 0),
                                group_index=int(job.get("group_index") or 0),
                                agent_ids=[str(x) for x in (job.get("agents") or [])],
                                status=STATUS_DONE,
                                reason="stage_done",
                                return_code=rc,
                                duration_ms=duration_ms,
                            )
                            write_run_context(run_context_path, run_context)
                            meta.setdefault("stages", {})[stage] = {
                                "input_hash": job["input_hash"],
                                "outputs": job["outputs"],
                                "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            }
                            save_meta(out_root, meta)
                            append_pipeline_event(
                                out_root,
                                event_type="stage_done",
                                stage=stage,
                                status=STATUS_DONE,
                                note=f"阶段完成: {_stage_text(stage)}",
                                extra={
                                    "agents": job.get("agents"),
                                    "return_code": rc,
                                    "duration_ms": duration_ms,
                                    "phase_id": job.get("phase_id"),
                                    "group_index": job.get("group_index"),
                                },
                            )
                            if stage == "ai_audit":
                                ai_ok = ai_audit_ok(out_root)
                                if ai_ok:
                                    print("[INFO] ai_audit ok; rule modules will run in quick mode.")

                        write_pipeline_runtime_files(
                            out_root,
                            stage_status,
                            current_stage=stage,
                            started_at=started_at,
                            event_note=f"{_stage_text(stage)} {'失败' if rc != 0 else '完成'}",
                            agent_runtime=agent_runtime,
                            phase_verifier=phase_verifier,
                        )
                if failed_stage:
                    break

            if failed_stage:
                phase_failed = True
                break

        cleanup_stats = cleanup_before_gate(out_root, agent_runtime, pid)
        if int(cleanup_stats.get("reaped", 0)) > 0:
            append_pipeline_event(
                out_root,
                event_type="agent_reap",
                stage=f"phase_{pid}",
                status=STATUS_DONE,
                note=f"阶段门禁前回收残留Agent: {int(cleanup_stats.get('reaped', 0))}",
                extra={"phase_id": pid, "cleanup": cleanup_stats},
            )
        write_pipeline_runtime_files(
            out_root,
            stage_status,
            current_stage="",
            started_at=started_at,
            event_note=f"阶段{pid}门禁回收完成",
            agent_runtime=agent_runtime,
            phase_verifier=phase_verifier,
        )
        if not phase_failed:
            if pid == 7:
                # Phase-7 verifier requires the cleanup report path; pre-write a provisional copy here.
                write_resource_cleanup_report(out_root, agent_runtime, failed_stage="")
            verifier_stage = f"phase_verifier_{pid}"
            set_phase_verifier_state(phase_verifier, pid, VERIFIER_RUNNING, note="agent-verifier 执行中")
            mark_stage_context(run_context, verifier_stage, STATUS_RUNNING, phase_id=pid)
            agent_mark_running(
                out_root,
                agent_runtime,
                stage=verifier_stage,
                phase_id=pid,
                group_index=99,
                agents=[VERIFIER_AGENT],
            )
            write_run_context(run_context_path, run_context)
            append_pipeline_event(
                out_root,
                event_type="verifier_start",
                stage=verifier_stage,
                status=STATUS_RUNNING,
                note=f"阶段{pid}质检启动",
                extra={"phase_id": pid, "agent": VERIFIER_AGENT["id"]},
            )
            write_pipeline_runtime_files(
                out_root,
                stage_status,
                current_stage=verifier_stage,
                started_at=started_at,
                event_note=f"阶段{pid}质检执行中: agent-verifier",
                agent_runtime=agent_runtime,
                phase_verifier=phase_verifier,
            )
            verifier_env = os.environ.copy()
            verifier_env["AUDIT_RUN_ID"] = run_id
            vres = run_phase_verifier_command(pid, project_root, out_root, verifier_env)
            vrc = int(vres.get("return_code", 1))
            vreport = str(vres.get("report_path") or "")
            if vrc == 0:
                set_phase_verifier_state(phase_verifier, pid, VERIFIER_PASS, note=f"阶段{pid}验收通过", report_path=vreport)
                mark_stage_context(
                    run_context,
                    verifier_stage,
                    STATUS_DONE,
                    phase_id=pid,
                    return_code=0,
                    duration_ms=int(vres.get("duration_ms") or 0),
                )
                agent_mark_final(
                    out_root,
                    agent_runtime,
                    stage=verifier_stage,
                    phase_id=pid,
                    group_index=99,
                    agent_ids=[VERIFIER_AGENT["id"]],
                    status=STATUS_DONE,
                    reason="verifier_pass",
                    return_code=0,
                    duration_ms=int(vres.get("duration_ms") or 0),
                )
                append_pipeline_event(
                    out_root,
                    event_type="verifier_pass",
                    stage=verifier_stage,
                    status=STATUS_DONE,
                    note=f"阶段{pid}质检通过",
                    extra={"phase_id": pid, "report_path": vreport},
                )
            else:
                set_phase_verifier_state(phase_verifier, pid, VERIFIER_BLOCK, note=f"阶段{pid}验收阻断", report_path=vreport)
                mark_stage_context(
                    run_context,
                    verifier_stage,
                    STATUS_FAILED,
                    phase_id=pid,
                    return_code=vrc,
                    duration_ms=int(vres.get("duration_ms") or 0),
                )
                agent_mark_final(
                    out_root,
                    agent_runtime,
                    stage=verifier_stage,
                    phase_id=pid,
                    group_index=99,
                    agent_ids=[VERIFIER_AGENT["id"]],
                    status=STATUS_FAILED,
                    reason="verifier_block",
                    return_code=vrc,
                    duration_ms=int(vres.get("duration_ms") or 0),
                )
                append_pipeline_event(
                    out_root,
                    event_type="verifier_block",
                    stage=verifier_stage,
                    status=STATUS_FAILED,
                    note=f"阶段{pid}质检阻断",
                    extra={"phase_id": pid, "report_path": vreport},
                )
                failed_stage = verifier_stage
                phase_failed = True
            write_run_context(run_context_path, run_context)
            write_pipeline_runtime_files(
                out_root,
                stage_status,
                current_stage=verifier_stage,
                started_at=started_at,
                event_note=f"阶段{pid}质检{'通过' if vrc == 0 else '阻断'}",
                agent_runtime=agent_runtime,
                phase_verifier=phase_verifier,
            )
        phase_state = phase_status_map(stage_status).get(pid, STATUS_PENDING)
        if phase_failed or phase_state == STATUS_FAILED:
            append_pipeline_event(
                out_root,
                event_type="phase_fail",
                stage=f"phase_{pid}",
                status=STATUS_FAILED,
                note=f"阶段{pid}失败: {phase['name']}",
                extra={"phase_id": pid, "failed_stage": failed_stage},
            )
            break
        append_pipeline_event(
            out_root,
            event_type="phase_done",
            stage=f"phase_{pid}",
            status=STATUS_DONE,
            note=f"阶段{pid}完成: {phase['name']}",
            extra={"phase_id": pid},
        )

    if failed_stage:
        final_cleanup(out_root, agent_runtime, failed_stage=failed_stage)
        write_resource_cleanup_report(out_root, agent_runtime, failed_stage=failed_stage)
        run_context["overall_status"] = "failed"
        run_context["finished_at"] = now_iso()
        write_run_context(run_context_path, run_context)
        write_pipeline_runtime_files(
            out_root,
            stage_status,
            current_stage=failed_stage if failed_stage != "scheduler_deadlock" else "",
            started_at=started_at,
            event_note=f"流程中断: {failed_stage}",
            agent_runtime=agent_runtime,
            phase_verifier=phase_verifier,
        )
        raise SystemExit(f"Stage failed: {failed_stage}")

    final_cleanup(out_root, agent_runtime, failed_stage="")
    write_resource_cleanup_report(out_root, agent_runtime, failed_stage="")
    write_pipeline_runtime_files(
        out_root,
        stage_status,
        current_stage="",
        started_at=started_at,
        event_note="全流程执行完成",
        agent_runtime=agent_runtime,
        phase_verifier=phase_verifier,
    )
    run_context["overall_status"] = "done"
    run_context["finished_at"] = now_iso()
    write_run_context(run_context_path, run_context)
    if "final_report" in selected_stage_set:
        archive_runtime_markdowns(out_root)

    shown_out_root = remap_to_host_out(out_root, out_root, host_out_root)
    print(f"Audit complete. Output: {shown_out_root}")
    print_report_paths(out_root, selected_stages, host_out_root)
    cn_paths = build_chinese_named_results(out_root, selected_stages)
    print_chinese_report_paths(cn_paths, out_root, host_out_root)


if __name__ == "__main__":
    main()
