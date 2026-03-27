> **Skill ID**: S-036d | **Phase**: 3 | **Parent**: S-036 (Trace-Dispatcher)
> **Input**: Docker container resource stats
> **Output**: Concurrency level (1, 2, or 3 parallel workers)

# Concurrency Tuner

## Purpose

Dynamically determine how many Trace-Workers can run in parallel based on the
current CPU and memory utilisation of the target Docker container. This prevents
resource exhaustion that would cause unreliable traces or container crashes.

## Procedure

### 1. Query Container Resource Usage

```bash
# Retrieve CPU and memory percentages for the PHP container
docker stats php --no-stream --format "{{.CPUPerc}} {{.MemPerc}}"
```

Parse the output into two numeric values: `cpu_pct` and `mem_pct` (strip the
`%` suffix).

### 2. Apply Concurrency Decision Table

| Condition | Max Workers | Rationale |
|-----------|-------------|-----------|
| `cpu_pct < 50` **and** `mem_pct < 60` | 3 | Ample headroom for parallel tracing |
| `cpu_pct < 80` **and** `mem_pct < 80` | 2 | Moderate load — two workers safe |
| Otherwise | 1 | High load — serial execution only |

### 3. Timeout Configuration

Regardless of concurrency level, enforce the following per-task limits:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Per-route tracing timeout | 30 seconds | Kill and mark `failed` with reason `timeout` after this duration |
| Xdebug trace file size cap | 50 MB | If trace file exceeds this, truncate and mark `truncated` |

### 4. Emit Concurrency Level

Return the chosen worker count to the Dispatcher's main loop so it can spawn
the appropriate number of Trace-Workers concurrently.

### 5. Periodic Re-evaluation (Optional)

Between dispatch batches, re-query `docker stats` and adjust the worker count
up or down. This is especially useful during long-running dispatch runs where
system load may change.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Docker daemon | `docker stats php --no-stream` | Yes | `CPUPerc`, `MemPerc` |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Concurrency level | (in-memory) | Integer: 1, 2, or 3 |
| Timeout settings | (in-memory) | `{ per_route_timeout_s: 30, trace_size_cap_mb: 50 }` |

## Error Handling

| Error | Action |
|-------|--------|
| `docker stats` command fails | Default to 1 worker (serial) and log warning |
| Container `php` not found | Abort dispatch with `container_not_found` error |
| Non-numeric CPU/Memory values | Default to 1 worker and log warning |
