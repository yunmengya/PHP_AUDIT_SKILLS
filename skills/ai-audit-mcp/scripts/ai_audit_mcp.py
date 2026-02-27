#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple


def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def resolve_out_root(project_root: str, out_root: str) -> str:
    if out_root:
        return out_root
    base = os.path.join("/tmp", "php_skills_audit")
    name = os.path.basename(project_root.rstrip("/")) or "project"
    ts = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(base, f"{name}_audit_{ts}")


def load_policy() -> Dict:
    cfg = os.path.join(os.path.dirname(__file__), "..", "..", "_config", "ai_audit_policy.json")
    cfg = os.path.abspath(cfg)
    if not os.path.exists(cfg):
        return {}
    return load_json(cfg, {}) or {}


def hash_text(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def load_cache(out_root: str) -> Dict:
    path = os.path.join(out_root, "ai_audit", "ai_cache.json")
    if not os.path.exists(path):
        return {"version": 1, "entries": {}}
    data = load_json(path, {}) or {}
    if data.get("version") != 1:
        return {"version": 1, "entries": {}}
    if not isinstance(data.get("entries"), dict):
        data["entries"] = {}
    return data


def save_cache(out_root: str, cache: Dict) -> None:
    path = os.path.join(out_root, "ai_audit", "ai_cache.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_json(path, cache)


def read_contexts(out_root: str) -> List[Tuple[str, str, str]]:
    ctx_root = os.path.join(out_root, "ai_audit", "ai_audit_context")
    if not os.path.isdir(ctx_root):
        return []
    items: List[Tuple[str, str, str]] = []
    for entry in sorted(os.listdir(ctx_root)):
        full_path = os.path.join(ctx_root, entry, "context.json")
        compact_path = os.path.join(ctx_root, entry, "context_compact.json")
        if os.path.exists(full_path):
            items.append((entry, full_path, compact_path))
    return items


def build_schema() -> str:
    schema = {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "title": {"type": "string"},
                        "route": {"type": "object"},
                        "sink": {"type": "object"},
                        "source": {"type": "object"},
                        "taint": {"type": "array"},
                        "validation": {"type": "array"},
                        "controllability": {"type": "string"},
                        "confidence": {},
                        "notes": {"type": "string"},
                        "poc": {},
                    },
                    "required": [
                        "id",
                        "title",
                        "route",
                        "sink",
                        "source",
                        "taint",
                        "validation",
                        "controllability",
                        "confidence",
                        "notes",
                        "poc",
                    ],
                },
            }
        },
        "required": ["results"],
    }
    return json.dumps(schema, ensure_ascii=False)


def build_prompt(context_text: str) -> str:
    return (
        "你是PHP代码安全审计专家。基于以下完整上下文JSON进行审计，输出JSON结果。\n"
        "要求：\n"
        "1. 仅基于提供的上下文，不能编造不存在的文件/路径。\n"
        "2. 每条发现必须给出完整证据链：source/taint/sink/validation/controllability。\n"
        "3. 必须输出poc（字符串或结构化对象均可）。\n"
        "4. 如果没有发现，返回 {\"results\": []}。\n\n"
        "上下文JSON如下：\n"
        + context_text
    )


def run_claude(prompt: str, model: str, schema: str) -> Dict:
    cmd = [
        "claude",
        "--print",
        "--output-format",
        "json",
        "--model",
        model,
        "--json-schema",
        schema,
    ]
    proc = subprocess.run(cmd, input=prompt, text=True, capture_output=True)
    if proc.returncode != 0:
        return {"error": proc.stderr or proc.stdout or "claude failed"}
    try:
        return json.loads(proc.stdout)
    except Exception:
        return {"error": "invalid json", "raw": proc.stdout}


def run_with_context(context_text: str, model: str, schema: str, runs: int) -> Tuple[List[List[Dict]], List[set], List[Dict]]:
    run_sets: List[set] = []
    run_results: List[List[Dict]] = []
    trace: List[Dict] = []
    for r in range(runs):
        resp = run_claude(build_prompt(context_text), model, schema)
        if not isinstance(resp, dict) or "results" not in resp:
            trace.append({"run": r + 1, "error": "invalid_response", "detail": resp})
            run_results.append([])
            run_sets.append(set())
            continue
        results = resp.get("results") or []
        if not isinstance(results, list):
            results = []
        run_results.append(results)
        run_sets.append({result_key(it) for it in results if isinstance(it, dict)})
        trace.append({"run": r + 1, "count": len(results)})
    return run_results, run_sets, trace


def result_key(item: Dict) -> str:
    sink = item.get("sink") or {}
    file = sink.get("file") or ""
    line = sink.get("line") or ""
    stype = sink.get("type") or ""
    title = item.get("title") or ""
    return f"{file}:{line}:{stype}:{title}"


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / float(len(a | b))


def consensus_score(sets: List[set]) -> float:
    if not sets:
        return 0.0
    if len(sets) == 1:
        return 1.0
    scores: List[float] = []
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            scores.append(jaccard(sets[i], sets[j]))
    return sum(scores) / len(scores) if scores else 0.0


def has_sinks_from_compact(compact_text: str) -> bool:
    try:
        data = json.loads(compact_text)
    except Exception:
        return False
    trace = data.get("trace") or {}
    sinks = trace.get("sinks") or []
    return bool(sinks)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="PHP project root")
    ap.add_argument("--out", default=None, help="Output root")
    ap.add_argument("--model", default=os.environ.get("AI_AUDIT_MODEL", "sonnet"))
    ap.add_argument("--workers", type=int, default=0, help="Parallel workers (0=auto)")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project)
    out_root = resolve_out_root(project_root, args.out)
    os.makedirs(out_root, exist_ok=True)

    policy = load_policy()
    runs = int(policy.get("consensus_runs", 1))
    threshold = float(policy.get("consensus_threshold", 0.7))

    contexts = read_contexts(out_root)
    schema = build_schema()

    all_results: List[Dict] = []
    trace: List[Dict] = []
    start_time = time.time()

    cache = load_cache(out_root)
    entries_cache = cache.get("entries", {})

    def process_entry(entry_id: str, ctx_path: str, compact_path: str) -> Tuple[str, Dict, List[Dict]]:
        try:
            context_text = open(ctx_path, "r", encoding="utf-8").read()
        except Exception:
            return entry_id, {"error": "read_failed"}, []

        ctx_hash = hash_text(context_text)
        cached = entries_cache.get(entry_id, {})
        if cached.get("hash") == ctx_hash and isinstance(cached.get("results"), list):
            return entry_id, {"cached": True, "hash": ctx_hash, "count": len(cached.get("results"))}, cached.get("results")

        compact_text = ""
        if policy.get("use_compact_context") and os.path.exists(compact_path):
            try:
                compact_text = open(compact_path, "r", encoding="utf-8").read()
            except Exception:
                compact_text = ""

        if compact_text:
            run_results, run_sets, run_trace = run_with_context(compact_text, args.model, schema, runs)
            if not has_sinks_from_compact(compact_text):
                # fallback to full context if compact has no sinks
                run_results, run_sets, run_trace = run_with_context(context_text, args.model, schema, runs)
        else:
            run_results, run_sets, run_trace = run_with_context(context_text, args.model, schema, runs)
        score = consensus_score(run_sets)
        consensus = "high" if score >= threshold else "low"
        merged = run_results[0] if run_results else []
        for it in merged:
            if isinstance(it, dict):
                it["context_id"] = entry_id
                it["ai_consensus"] = consensus
                it["consensus_score"] = round(score, 3)
        entry_trace = {"cached": False, "hash": ctx_hash, "runs": run_trace}
        return entry_id, entry_trace, merged

    workers = args.workers if args.workers and args.workers > 0 else min(8, os.cpu_count() or 4)
    if workers <= 1 or len(contexts) <= 1:
        for entry_id, ctx_path, compact_path in contexts:
            eid, entry_trace, merged = process_entry(entry_id, ctx_path, compact_path)
            trace.append({"entry_id": eid, **entry_trace})
            all_results.extend(merged)
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(contexts))) as ex:
            futures = {ex.submit(process_entry, entry_id, ctx_path, compact_path): entry_id for entry_id, ctx_path, compact_path in contexts}
            for fut in as_completed(futures):
                eid, entry_trace, merged = fut.result()
                trace.append({"entry_id": eid, **entry_trace})
                all_results.extend(merged)

    # update cache
    new_entries: Dict[str, Dict] = {}
    for item in all_results:
        if not isinstance(item, dict):
            continue
        cid = item.get("context_id")
        if not cid:
            continue
        new_entries.setdefault(cid, {"hash": entries_cache.get(cid, {}).get("hash"), "results": []})
        new_entries[cid]["results"].append(item)
    # keep cached hashes for entries we processed
    for entry in trace:
        eid = entry.get("entry_id")
        if not eid:
            continue
        h = entry.get("hash")
        if eid not in new_entries:
            new_entries[eid] = {"hash": h, "results": entries_cache.get(eid, {}).get("results", [])}
        else:
            new_entries[eid]["hash"] = h
    cache["entries"] = new_entries
    save_cache(out_root, cache)

    duration = round(time.time() - start_time, 2)
    output = {
        "results": all_results,
        "meta": {
            "model": args.model,
            "runs": runs,
            "consensus_threshold": threshold,
            "duration_sec": duration,
            "contexts": len(contexts),
            "workers": workers,
        },
        "trace": trace,
    }

    out_path = os.path.join(out_root, "mcp_raw", "ai-audit-mcp.json")
    write_json(out_path, output)
    print(f"ai-audit-mcp output: {out_path}")


if __name__ == "__main__":
    main()
