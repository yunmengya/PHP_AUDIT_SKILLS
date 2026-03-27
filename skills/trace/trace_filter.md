> **Skill ID**: S-037c | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: Raw Xdebug trace file + target sink function name
> **Output**: Filtered trace JSON (≤ 500 lines, sink-relevant chains only)

# Trace Filter

## Purpose

Process the raw Xdebug function trace to remove framework noise and retain only
the call chains relevant to the target sink function. This produces a compact,
analysable trace suitable for Phase 4 auditors.

## Procedure

### 1. Run `trace_filter.php`

```bash
docker cp tools/trace_filter.php php:/tmp/trace_filter.php
docker exec php php /tmp/trace_filter.php \
  /tmp/xdebug_traces/trace.*.xt \
  $SINK_FUNCTION
```

### 2. Trimming Rules

| Condition | Action |
|-----------|--------|
| Trace file > 10 MB | Automatically trim output to ≤ 500 lines |
| Sink-related call stacks | **Keep** — any call chain that includes or leads to the sink function |
| User-input propagation chains | **Keep** — chains originating from `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `php://input` |
| Filter / sanitisation functions | **Keep** — `htmlspecialchars`, `intval`, `addslashes`, `prepared statements`, `htmlentities`, `strip_tags`, etc. |
| Framework bootstrap | **Discard** — Composer autoload, Kernel boot, service provider registration |
| Autoload calls | **Discard** — `spl_autoload_call`, Composer class map lookups |
| Event dispatching internals | **Discard** — framework event loop plumbing |

### 3. Output Format

Produce a JSON structure:

```json
{
  "route_id": "route_005",
  "sink_function": "DB::raw",
  "filtered_line_count": 247,
  "call_chain": [
    "index.php",
    "Illuminate\\Foundation\\Http\\Kernel::handle",
    "App\\Http\\Controllers\\UserController::update",
    "Illuminate\\Support\\Facades\\DB::raw"
  ],
  "filters_encountered": ["intval"],
  "raw_trace_size_bytes": 5242880
}
```

### 4. Pass to Downstream

Hand the filtered trace to the Dynamic Binding Resolver (S-037d) for further
enrichment.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Request Executor (S-037b) | Container: `/tmp/xdebug_traces/trace.*.xt` | Yes | Raw Xdebug function trace |
| Task package | (from S-036e) | Yes | `sink_function` |
| Filter tool | `tools/trace_filter.php` | Yes | Filtering logic |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Filtered trace JSON | (in-memory / piped to S-037d) | Compact sink-relevant call chain |

## Error Handling

| Error | Action |
|-------|--------|
| Trace file is empty (0 bytes) | Mark `trace_empty`; signal fallback strategy (S-036f) |
| `trace_filter.php` not found | Copy from `tools/` directory and retry |
| Sink function not found in trace | Mark `route_missed`; verify URL/method/parameters and suggest retry |
| Filtered output still > 500 lines | Truncate to 500 lines centred on the sink call; log warning |
