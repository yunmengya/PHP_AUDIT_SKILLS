## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-036d |
| Phase | 3 |
| Responsibility | Dynamically determine parallel worker count based on container resource usage |

# Concurrency Tuner

## Purpose

Dynamically determine how many Trace-Workers can run in parallel based on the
current CPU and memory utilisation of the target Docker container. This prevents
resource exhaustion that would cause unreliable traces or container crashes.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Container stats | Docker daemon (`docker stats php --no-stream`) | Yes | `CPUPerc`, `MemPerc` |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST respect target server capacity — concurrency level MUST NOT cause server crash or denial of service | FAIL — audit crashes target server, destroys test environment |

## Fill-in Procedure

### Step 1 — Query Container Resource Usage

| Field | Fill-in Value |
|-------|---------------|
| `container_name` | {php — target PHP container name} |
| `cpu_pct` | {numeric CPU percentage from docker stats} |
| `mem_pct` | {numeric memory percentage from docker stats} |

```bash
docker stats php --no-stream --format "{{.CPUPerc}} {{.MemPerc}}"
```

Parse the output into two numeric values: `cpu_pct` and `mem_pct` (strip the `%` suffix).

### Step 2 — Apply Concurrency Decision Table

| Field | Fill-in Value |
|-------|---------------|
| `cpu_pct` | {value from Step 1} |
| `mem_pct` | {value from Step 1} |
| `max_workers` | {1 / 2 / 3 — based on decision table below} |

| Condition | Max Workers | Rationale |
|-----------|-------------|-----------|
| `cpu_pct < 50` **and** `mem_pct < 60` | 3 | Ample headroom for parallel tracing |
| `cpu_pct < 80` **and** `mem_pct < 80` | 2 | Moderate load — two workers safe |
| Otherwise | 1 | High load — serial execution only |

### Step 3 — Timeout Configuration

| Field | Fill-in Value |
|-------|---------------|
| `per_route_timeout_s` | {30 — seconds before kill and mark failed} |
| `trace_size_cap_mb` | {50 — max trace file size in MB before truncation} |

Regardless of concurrency level, enforce the following per-task limits:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Per-route tracing timeout | 30 seconds | Kill and mark `failed` with reason `timeout` after this duration |
| Xdebug trace file size cap | 50 MB | If trace file exceeds this, truncate and mark `truncated` |

### Step 4 — Emit Concurrency Level

| Field | Fill-in Value |
|-------|---------------|
| `concurrency_level` | {integer: 1, 2, or 3} |
| `timeout_settings` | {per_route_timeout_s: 30, trace_size_cap_mb: 50} |

Return the chosen worker count to the Dispatcher's main loop so it can spawn
the appropriate number of Trace-Workers concurrently.

### Step 5 — Periodic Re-evaluation (Optional)

| Field | Fill-in Value |
|-------|---------------|
| `re_evaluate` | {true/false — re-query docker stats between batches} |
| `adjustment_direction` | {up / down / unchanged} |

Between dispatch batches, re-query `docker stats` and adjust the worker count
up or down. This is especially useful during long-running dispatch runs where
system load may change.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Concurrency level | (in-memory) | Integer: 1, 2, or 3 |
| Timeout settings | (in-memory) | `{ per_route_timeout_s: 30, trace_size_cap_mb: 50 }` |

## Examples

### ✅ GOOD — Complete concurrency decision

```json
{
  "cpu_pct": 35.2,
  "mem_pct": 42.8,
  "max_workers": 3,
  "per_route_timeout_s": 30,
  "trace_size_cap_mb": 50
}
```

CPU and memory both low, 3 workers selected, timeout settings included.

### ❌ BAD — Missing context

```json
{
  "max_workers": 3
}
```

Problems: No `cpu_pct`/`mem_pct` evidence for the decision, no timeout settings.

## Error Handling

| Error | Action |
|-------|--------|
| `docker stats` command fails | Default to 1 worker (serial) and log warning |
| Container `php` not found | Abort dispatch with `container_not_found` error |
| Non-numeric CPU/Memory values | Default to 1 worker and log warning |
