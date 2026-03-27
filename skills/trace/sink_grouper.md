> **Skill ID**: S-036c | **Phase**: 3 | **Parent**: S-036 (Trace-Dispatcher)
> **Input**: Trimmed task list
> **Output**: Sink-type-grouped batches for efficient dispatch

# Sink Grouper

## Purpose

Group the trimmed route list by sink type so that routes sharing the same
vulnerability category are batched together. This enables downstream Phase 4
specialized auditors to process related traces in bulk and improves cache
locality during analysis.

## Procedure

### 1. Identify Sink Types

Read the `sink_function` field from each task entry and map it to a canonical
sink category:

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

### 2. Build Groups

Create one group per sink category present in the trimmed list:

```
groups = {
  "RCE":  [task_003, task_017, ...],
  "SQLi": [task_001, task_005, ...],
  ...
}
```

### 3. Ordering Within Groups

Within each group, maintain the priority-then-source-count ordering established
by S-036a.

### 4. Group-Level Batch Sizing

Split large groups into batches of 5–10 tasks for dispatch to individual
Trace-Workers. Smaller groups (≤ 5) become a single batch.

### 5. Emit Grouped Batches

Pass the grouped and batched task list to the Task Packager (S-036e) and
Concurrency Tuner (S-036d).

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Resource Downsampler (S-036b) | (in-memory) | Yes | `sink_function`, `route_id`, `priority`, `source_count` |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Sink-grouped batches | (in-memory / piped to S-036d, S-036e) | Dict of `{sink_category: [[batch1], [batch2], ...]}` |

## Error Handling

| Error | Action |
|-------|--------|
| `sink_function` field missing on an entry | Assign to `Other` group and log warning |
| Sink function not in any known category | Assign to `Other` group |
| Empty trimmed list | Return empty groups; upstream should have already handled this |
