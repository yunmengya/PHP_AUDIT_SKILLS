## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-036c |
| Phase | 3 |
| Responsibility | Group trimmed route list by sink type for efficient batch dispatch |

# Sink Grouper

## Purpose

Group the trimmed route list by sink type so that routes sharing the same
vulnerability category are batched together. This enables downstream Phase 4
specialized auditors to process related traces in bulk and improves cache
locality during analysis.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Trimmed task list | Resource Downsampler S-036b (in-memory) | Yes | `sink_function`, `route_id`, `priority`, `source_count` |

## Fill-in Procedure

### Step 1 — Identify Sink Types

Read the `sink_function` field from each task entry and map it to a canonical sink category:

| Field | Fill-in Value |
|-------|---------------|
| `sink_function` | {target function name from task entry} |
| `sink_category` | {RCE / SQLi / File / SSRF / XXE / Deserialization / XSS / Other} |

Mapping reference:

| Sink Category | Example Sink Functions |
|---------------|----------------------|
| RCE | `exec`, `system`, `passthru`, `shell_exec`, `proc_open`, `popen`, `eval`, `assert`, `preg_replace` (with `e` modifier) |
| SQLi | `DB::raw`, `mysqli_query`, `PDO::query`, `pg_query`, `mysql_query` |
| File | `file_get_contents`, `file_put_contents`, `fopen`, `include`, `require`, `readfile`, `unlink`, `move_uploaded_file` |
| SSRF | `curl_exec`, `file_get_contents` (URL), `fsockopen`, `ftp_connect` |
| XXE | `simplexml_load_string`, `DOMDocument::loadXML`, `xml_parse` |
| Deserialization | `unserialize`, `yaml_parse` |
| XSS | `echo`, `print`, `printf` (when outputting user input without encoding) |
| Other | Any sink not matching the above categories |

### Step 2 — Build Groups

| Field | Fill-in Value |
|-------|---------------|
| `group_key` | {sink_category name} |
| `group_members` | {list of task entries matching this category} |

Create one group per sink category present in the trimmed list:

```
groups = {
  "RCE":  [task_003, task_017, ...],
  "SQLi": [task_001, task_005, ...],
  ...
}
```

### Step 3 — Ordering Within Groups

| Field | Fill-in Value |
|-------|---------------|
| `intra_group_sort` | {priority ascending, then source_count descending} |

Within each group, maintain the priority-then-source-count ordering established by S-036a.

### Step 4 — Group-Level Batch Sizing

| Field | Fill-in Value |
|-------|---------------|
| `batch_size` | {5–10 tasks per batch} |
| `small_group_threshold` | {≤ 5 — becomes a single batch} |

Split large groups into batches of 5–10 tasks for dispatch to individual Trace-Workers. Smaller groups (≤ 5) become a single batch.

### Step 5 — Emit Grouped Batches

| Field | Fill-in Value |
|-------|---------------|
| `output_format` | {dict of sink_category → list of batches} |
| `downstream_consumers` | {Task Packager S-036e, Concurrency Tuner S-036d} |

Pass the grouped and batched task list to the Task Packager (S-036e) and Concurrency Tuner (S-036d).

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Sink-grouped batches | (in-memory / piped to S-036d, S-036e) | Dict of `{sink_category: [[batch1], [batch2], ...]}` |

## Examples

### ✅ GOOD — Properly grouped and batched

```json
{
  "RCE": [
    [
      { "route_id": "route_003", "sink_function": "exec", "priority": "P0", "source_count": 5 },
      { "route_id": "route_017", "sink_function": "system", "priority": "P0", "source_count": 3 }
    ]
  ],
  "SQLi": [
    [
      { "route_id": "route_001", "sink_function": "DB::raw", "priority": "P0", "source_count": 6 },
      { "route_id": "route_005", "sink_function": "mysqli_query", "priority": "P1", "source_count": 4 }
    ]
  ]
}
```

Grouped by category, ordered within groups, batched ≤ 10 per batch.

### ❌ BAD — No grouping, missing category

```json
[
  { "route_id": "route_003", "sink_function": "exec" },
  { "route_id": "route_001", "sink_function": "DB::raw" }
]
```

Problems: Flat list instead of grouped dict, no sink_category assignment, missing `priority` and `source_count`.

## Error Handling

| Error | Action |
|-------|--------|
| `sink_function` field missing on an entry | Assign to `Other` group and log warning |
| Sink function not in any known category | Assign to `Other` group |
| Empty trimmed list | Return empty groups; upstream should have already handled this |
