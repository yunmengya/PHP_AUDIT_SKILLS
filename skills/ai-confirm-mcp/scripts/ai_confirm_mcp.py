#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple


ALLOWED_BUCKETS = {"GET", "POST", "BODY", "COOKIE", "HEADER"}
ALLOWED_EXPLOITABILITY = {"已确认", "高可能", "待验证"}


def resolve_out_root(project_root: str, out_root: Optional[str]) -> str:
    if out_root:
        return os.path.abspath(out_root)
    return f"{os.path.abspath(project_root).rstrip('/')}_audit"


def load_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def pick_model(cli_model: str) -> str:
    if cli_model:
        return cli_model
    return os.environ.get("AI_CONFIRM_MODEL") or os.environ.get("AI_AUDIT_MODEL") or "sonnet"


def run_claude_json(prompt: str, schema: Dict[str, Any], model: str, timeout_sec: int) -> Tuple[Optional[Dict[str, Any]], str]:
    cmd = [
        "claude",
        "--print",
        "--output-format",
        "json",
        "--model",
        model,
        "--json-schema",
        json.dumps(schema, ensure_ascii=False),
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=max(1, int(timeout_sec)),
        )
    except FileNotFoundError:
        return None, "claude_not_found"
    except subprocess.TimeoutExpired:
        return None, f"claude_timeout:{timeout_sec}s"
    except Exception as exc:
        return None, f"claude_exec_error:{exc}"

    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout or "claude_failed").strip()

    stdout = (proc.stdout or "").strip()
    if not stdout:
        return None, "claude_empty_output"

    try:
        data = json.loads(stdout)
    except Exception:
        return None, "claude_invalid_json"

    if not isinstance(data, dict):
        return None, "claude_non_object"

    return data, ""


def claude_health_probe(model: str, timeout_sec: int) -> str:
    schema = {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
        },
        "required": ["ok"],
    }
    prompt = "仅返回 JSON: {\"ok\": true}"
    _, err = run_claude_json(prompt, schema, model, max(1, min(timeout_sec, 5)))
    return err


def normalize_bucket(value: str) -> str:
    v = str(value or "").strip().upper()
    if v in ALLOWED_BUCKETS:
        return v
    if v in ("REQUEST", "QUERY", "PARAM"):
        return "GET"
    if v in ("FORM",):
        return "POST"
    return "GET"


def normalize_method(value: str, fallback: str = "GET") -> str:
    v = str(value or "").strip().upper()
    if v in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return v
    if v == "ANY":
        return "GET"
    return fallback


def normalize_path(value: str, fallback: str = "/") -> str:
    p = str(value or "").strip()
    if not p:
        p = fallback
    if not p:
        p = "/"
    if p.startswith("http://") or p.startswith("https://"):
        return p
    if not p.startswith("/"):
        p = "/" + p
    return p


def to_float01(value: Any, default: float = 0.5) -> float:
    try:
        v = float(value)
    except Exception:
        return default
    if v < 0:
        return 0.0
    if v > 1:
        return 1.0
    return v


def debug_schema(max_candidates: int) -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "candidates": {
                "type": "array",
                "maxItems": max_candidates,
                "items": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string"},
                        "path": {"type": "string"},
                        "bucket": {"type": "string"},
                        "param": {"type": "string"},
                        "content_type": {"type": "string"},
                        "payload": {"type": "string"},
                        "reason": {"type": "string"},
                        "confidence": {"type": "number"},
                    },
                    "required": ["method", "path", "bucket", "param", "payload", "reason", "confidence"],
                },
            }
        },
        "required": ["candidates"],
    }


def build_debug_prompt(case: Dict[str, Any], round_index: int, per_round: int) -> str:
    return (
        "你是 PHP 漏洞调试 PoC 规划助手。\n"
        "请根据 case 上下文，生成可直接执行的请求候选（仅 JSON）。\n"
        "要求：\n"
        "1) 仅输出 candidates 数组（最多 {n} 条）。\n"
        "2) bucket 只能是 GET/POST/BODY/COOKIE/HEADER。\n"
        "3) payload 必须非空，尽量针对 sink 类型。\n"
        "4) path 必须是 URL path（如 /api/user）。\n"
        "5) 结果用于动态调试，不要解释文字。\n"
        "6) 尽量避免和历史候选重复。\n\n"
        "Round: {r}\n"
        "Case JSON:\n"
        "{ctx}\n"
    ).format(n=per_round, r=round_index, ctx=json.dumps(case, ensure_ascii=False))


def sanitize_debug_candidate(candidate: Dict[str, Any], case: Dict[str, Any], fallback_payload: str) -> Dict[str, Any]:
    best = case.get("best_request") if isinstance(case.get("best_request"), dict) else {}
    method = normalize_method(candidate.get("method"), normalize_method(best.get("method") or case.get("route_method") or "GET"))
    path = normalize_path(candidate.get("path"), normalize_path(best.get("path") or case.get("route_path") or "/"))
    bucket = normalize_bucket(candidate.get("bucket") or best.get("bucket") or "GET")
    param = str(candidate.get("param") or best.get("param") or "payload").strip() or "payload"
    content_type = str(candidate.get("content_type") or best.get("content_type") or "").strip()
    payload = str(candidate.get("payload") or "").strip() or fallback_payload
    reason = str(candidate.get("reason") or "ai_realtime").strip() or "ai_realtime"
    confidence = to_float01(candidate.get("confidence"), 0.5)
    return {
        "method": method,
        "path": path,
        "bucket": bucket,
        "param": param,
        "content_type": content_type,
        "payload": payload,
        "reason": reason,
        "confidence": confidence,
    }


def run_debug_suggest_mode(
    out_root: str,
    model: str,
    rounds: int,
    candidates_per_round: int,
    timeout_sec: int,
) -> Dict[str, Any]:
    context_path = os.path.join(out_root, "debug_verify", "ai_request_context.json")
    context = load_json(context_path, {})
    cases = context.get("cases") if isinstance(context, dict) else None
    if not isinstance(cases, list):
        cases = []

    max_budget = max(0, int(rounds)) * max(0, int(candidates_per_round))
    if max_budget <= 0:
        max_budget = 10

    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    started = time.time()

    probe_err = claude_health_probe(model, timeout_sec)
    if probe_err:
        for case in cases:
            if not isinstance(case, dict):
                continue
            case_id = str(case.get("case_id") or "").strip()
            if not case_id:
                continue
            results.append({"case_id": case_id, "candidates": []})
        output = {
            "results": results,
            "meta": {
                "mode": "debug-suggest",
                "model": model,
                "rounds": rounds,
                "candidates_per_round": candidates_per_round,
                "timeout_sec": timeout_sec,
                "duration_sec": round(time.time() - started, 3),
                "error_count": 1,
                "errors": [{"scope": "probe", "error": probe_err}],
            },
        }
        write_json(os.path.join(out_root, "mcp_raw", "ai-confirm-mcp-debug.json"), output)
        return output

    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id") or "")
        if not case_id:
            continue

        payload_hints = case.get("payload_hints") if isinstance(case.get("payload_hints"), list) else []
        fallback_payload = str(payload_hints[0]) if payload_hints else "payload"

        merged: List[Dict[str, Any]] = []
        seen = set()

        for round_index in range(1, max(1, rounds) + 1):
            if len(merged) >= max_budget:
                break

            schema = debug_schema(candidates_per_round)
            prompt = build_debug_prompt(case, round_index, candidates_per_round)
            data, err = run_claude_json(prompt, schema, model, timeout_sec)
            if err:
                errors.append({"case_id": case_id, "round": round_index, "error": err})
                continue

            candidates = data.get("candidates") if isinstance(data, dict) else None
            if not isinstance(candidates, list):
                errors.append({"case_id": case_id, "round": round_index, "error": "invalid_candidates"})
                continue

            for raw in candidates:
                if not isinstance(raw, dict):
                    continue
                candidate = sanitize_debug_candidate(raw, case, fallback_payload)
                key = (
                    candidate.get("method"),
                    candidate.get("path"),
                    candidate.get("bucket"),
                    candidate.get("param"),
                    candidate.get("content_type"),
                    candidate.get("payload"),
                )
                if key in seen:
                    continue
                seen.add(key)
                merged.append(candidate)
                if len(merged) >= max_budget:
                    break

        results.append({"case_id": case_id, "candidates": merged})

    duration = round(time.time() - started, 3)
    output = {
        "results": results,
        "meta": {
            "mode": "debug-suggest",
            "model": model,
            "rounds": rounds,
            "candidates_per_round": candidates_per_round,
            "timeout_sec": timeout_sec,
            "duration_sec": duration,
            "error_count": len(errors),
            "errors": errors,
        },
    }
    write_json(os.path.join(out_root, "mcp_raw", "ai-confirm-mcp-debug.json"), output)
    return output


def confirm_item_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "title_label": {"type": "string"},
            "severity_label": {"type": "string"},
            "reachability": {
                "type": "object",
                "properties": {
                    "score": {"type": "number"},
                    "desc": {"type": "string"},
                },
                "required": ["score", "desc"],
            },
            "impact": {
                "type": "object",
                "properties": {
                    "score": {"type": "number"},
                    "desc": {"type": "string"},
                },
                "required": ["score", "desc"],
            },
            "complexity": {
                "type": "object",
                "properties": {
                    "score": {"type": "number"},
                    "desc": {"type": "string"},
                },
                "required": ["score", "desc"],
            },
            "exploitability": {"type": "string"},
            "location": {"type": "string"},
            "trigger": {"type": "string"},
            "input_source": {"type": "string"},
            "output_mode": {"type": "string"},
            "evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string"},
                        "line": {"type": "number"},
                        "note": {"type": "string"},
                    },
                    "required": ["file", "line"],
                },
            },
            "poc": {"type": "string"},
            "confidence": {"type": "number"},
            "rationale": {"type": "string"},
        },
        "required": [
            "id",
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
            "confidence",
            "rationale",
        ],
    }


def build_confirm_prompt(context: Dict[str, Any]) -> str:
    return (
        "你是 PHP 漏洞可利用性确认助手。\n"
        "基于给定上下文输出一条严格 JSON（无额外文本）。\n"
        "exploitability 只能是：已确认/高可能/待验证。\n\n"
        "Context JSON:\n"
        f"{json.dumps(context, ensure_ascii=False)}\n"
    )


def fallback_confirm_row(context: Dict[str, Any]) -> Dict[str, Any]:
    finding = context.get("finding") if isinstance(context, dict) else {}
    finding = finding if isinstance(finding, dict) else {}
    fid = str(finding.get("id") or "AI-UNKNOWN")
    title = str(finding.get("title") or "Possible Vulnerability")
    severity = str(finding.get("combined_severity") or finding.get("severity") or "medium").upper()

    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
    route = finding.get("route") if isinstance(finding.get("route"), dict) else {}

    route_method = str(route.get("method") or "GET")
    route_path = str(route.get("path") or "/")
    source_kind = str(source.get("kind") or "GET")
    source_param = str(source.get("param") or "param")

    evidence = [
        {
            "file": str(sink.get("file") or source.get("file") or "unknown"),
            "line": int(sink.get("line") or source.get("line") or 0),
            "note": "sink",
        }
    ]

    poc = f"curl -i -sS -X {route_method if route_method != 'ANY' else 'GET'} \"http://target{route_path}?{source_param}=test\""
    return {
        "id": fid,
        "title_label": f"[{fid}] {title}",
        "severity_label": severity,
        "reachability": {"score": 2, "desc": "需结合路由和调用链验证"},
        "impact": {"score": 2, "desc": "可能影响数据与业务完整性"},
        "complexity": {"score": 1, "desc": "需要构造参数和上下文"},
        "exploitability": "待验证",
        "location": f"{sink.get('file') or source.get('file') or 'unknown'}:{sink.get('line') or source.get('line') or 0}",
        "trigger": str(sink.get("function") or sink.get("type") or "sink"),
        "input_source": f"{source_kind}: {source_param}",
        "output_mode": "unknown",
        "evidence": evidence,
        "poc": poc,
        "confidence": 0.5,
        "rationale": "使用模板兜底（LLM 不可用或响应不合法）。",
    }


def sanitize_confirm_row(row: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(fallback)
    out.update({k: v for k, v in row.items() if v not in (None, "")})

    exp = str(out.get("exploitability") or "待验证")
    if exp not in ALLOWED_EXPLOITABILITY:
        out["exploitability"] = "待验证"

    for key in ("reachability", "impact", "complexity"):
        val = out.get(key)
        if not isinstance(val, dict):
            out[key] = fallback[key]
            continue
        score = val.get("score")
        desc = str(val.get("desc") or "").strip()
        try:
            score_f = float(score)
        except Exception:
            score_f = float(fallback[key]["score"])
        if not desc:
            desc = fallback[key]["desc"]
        out[key] = {"score": score_f, "desc": desc}

    evidence = out.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        out["evidence"] = fallback["evidence"]
    else:
        normalized = []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            file = str(item.get("file") or "").strip()
            line = item.get("line")
            note = str(item.get("note") or "").strip()
            if not file:
                continue
            try:
                line_int = int(line)
            except Exception:
                line_int = 0
            normalized.append({"file": file, "line": line_int, "note": note})
        out["evidence"] = normalized or fallback["evidence"]

    out["confidence"] = to_float01(out.get("confidence"), 0.5)
    out["rationale"] = str(out.get("rationale") or fallback["rationale"]) or fallback["rationale"]
    return out


def run_confirm_mode(out_root: str, model: str, timeout_sec: int) -> Dict[str, Any]:
    ctx_root = os.path.join(out_root, "ai_context")
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    started = time.time()

    context_files: List[str] = []
    if os.path.isdir(ctx_root):
        for entry in sorted(os.listdir(ctx_root)):
            path = os.path.join(ctx_root, entry, "context.json")
            if os.path.exists(path):
                context_files.append(path)

    schema = confirm_item_schema()

    for path in context_files:
        context = load_json(path, {})
        fallback = fallback_confirm_row(context)
        prompt = build_confirm_prompt(context)
        data, err = run_claude_json(prompt, schema, model, timeout_sec)
        if err:
            errors.append({"context": path, "error": err})
            results.append(fallback)
            continue

        row = sanitize_confirm_row(data if isinstance(data, dict) else {}, fallback)
        results.append(row)

    duration = round(time.time() - started, 3)
    output = {
        "results": results,
        "meta": {
            "mode": "confirm",
            "model": model,
            "timeout_sec": timeout_sec,
            "duration_sec": duration,
            "error_count": len(errors),
            "errors": errors,
        },
    }
    write_json(os.path.join(out_root, "mcp_raw", "ai-confirm-mcp.json"), output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="PHP project root")
    parser.add_argument("--out", default=None, help="Audit output root")
    parser.add_argument("--mode", choices=["confirm", "debug-suggest"], default="confirm")
    parser.add_argument("--model", default="", help="AI model")
    parser.add_argument("--rounds", type=int, default=2, help="Rounds for debug-suggest")
    parser.add_argument("--candidates-per-round", type=int, default=5, help="Candidates per round for debug-suggest")
    parser.add_argument("--timeout", type=int, default=30, help="AI timeout seconds")
    args = parser.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = resolve_out_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    model = pick_model(args.model)
    timeout_sec = max(1, int(args.timeout or 30))

    if args.mode == "debug-suggest":
        output = run_debug_suggest_mode(
            out_root=out_root,
            model=model,
            rounds=max(1, int(args.rounds or 1)),
            candidates_per_round=max(1, int(args.candidates_per_round or 1)),
            timeout_sec=timeout_sec,
        )
    else:
        output = run_confirm_mode(out_root=out_root, model=model, timeout_sec=timeout_sec)

    print(json.dumps({"ok": True, "mode": args.mode, "meta": output.get("meta", {})}, ensure_ascii=False))


if __name__ == "__main__":
    main()
