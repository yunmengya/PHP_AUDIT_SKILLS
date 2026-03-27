## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-037c |
| Phase | 3 |
| Responsibility | Filter raw Xdebug traces to retain only sink-relevant call chains |

# Trace Filter

## Purpose

Process the raw Xdebug function trace to remove framework noise and retain only
the call chains relevant to the target sink function. This produces a compact,
analysable trace suitable for Phase 4 auditors.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Raw trace file | Request Executor S-037b (Container: `/tmp/xdebug_traces/trace.*.xt`) | Yes | Raw Xdebug function trace |
| Task package | From S-036e (in-memory) | Yes | `sink_function` |
| `trace_filter.php` | `tools/trace_filter.php` | Yes | Filtering logic |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST preserve all sinks with user-controllable input — filtering MUST NOT remove potentially exploitable paths | FAIL — exploitable sinks filtered out, missed vulnerabilities |

## Fill-in Procedure

### Step 1 — Run `trace_filter.php`

| Field | Fill-in Value |
|-------|---------------|
| `sink_function` | {target function name, e.g., DB::raw, exec, system} |
| `trace_file` | {/tmp/xdebug_traces/trace.*.xt} |
| `max_depth` | {500 lines default} |

```bash
docker cp tools/trace_filter.php php:/tmp/trace_filter.php
docker exec php php /tmp/trace_filter.php \
  /tmp/xdebug_traces/trace.*.xt \
  $SINK_FUNCTION
```

### Step 2 — Trimming Rules

| Field | Fill-in Value |
|-------|---------------|
| `trim_strategy` | {keep_sink_related / truncate_oldest} |
| `max_output_lines` | {500} |
| `size_threshold` | {10 MB — triggers auto-trim} |

| Condition | Action |
|-----------|--------|
| Trace file > 10 MB | Automatically trim output to ≤ 500 lines |
| Sink-related call stacks | **Keep** — any call chain that includes or leads to the sink function |
| User-input propagation chains | **Keep** — chains originating from `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `php://input` |
| Filter / sanitisation functions | **Keep** — `htmlspecialchars`, `intval`, `addslashes`, `prepared statements`, `htmlentities`, `strip_tags`, etc. |
| Framework bootstrap | **Discard** — Composer autoload, Kernel boot, service provider registration |
| Autoload calls | **Discard** — `spl_autoload_call`, Composer class map lookups |
| Event dispatching internals | **Discard** — framework event loop plumbing |

### Step 3 — Output Format

| Field | Fill-in Value |
|-------|---------------|
| `route_id` | {route identifier from task package} |
| `sink_function` | {target function name} |
| `filtered_line_count` | {number of lines after filtering} |
| `call_chain` | {ordered list of function calls from entry to sink} |
| `filters_encountered` | {list of sanitisation functions found in trace} |
| `raw_trace_size_bytes` | {original trace file size} |

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

### Step 4 — Pass to Downstream

| Field | Fill-in Value |
|-------|---------------|
| `downstream_consumer` | {Dynamic Binding Resolver S-037d} |

Hand the filtered trace to the Dynamic Binding Resolver (S-037d) for further enrichment.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Filtered trace JSON | (in-memory / piped to S-037d) | Compact sink-relevant call chain |

## Examples

### ✅ GOOD — Complete filtered trace

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

All fields present, call_chain ends at sink, filters documented.

### ❌ BAD — Incomplete filter result

```json
{
  "route_id": "route_005",
  "call_chain": ["index.php"]
}
```

Problems: Missing `sink_function`, `filtered_line_count`, `filters_encountered`, `raw_trace_size_bytes`. Call chain too short — no sink reached.

## Error Handling

| Error | Action |
|-------|--------|
| Trace file is empty (0 bytes) | Mark `trace_empty`; signal fallback strategy (S-036f) |
| `trace_filter.php` not found | Copy from `tools/` directory and retry |
| Sink function not found in trace | Mark `route_missed`; verify URL/method/parameters and suggest retry |
| Filtered output still > 500 lines | Truncate to 500 lines centred on the sink call; log warning |
