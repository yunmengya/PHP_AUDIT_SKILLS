> **Skill ID**: S-036b | **Phase**: 3 | **Parent**: S-036 (Trace-Dispatcher)
> **Input**: Sorted task list + total route count
> **Output**: Trimmed task list with downsampled lower-priority routes

# Resource Downsampler

## Purpose

Automatically downsample lower-priority routes when the total number of routes
exceeds resource budgets, ensuring that high-priority routes are always fully
traced while keeping overall execution time bounded.

## Procedure

### 1. Count Total Routes

Compute `total_routes = len(sorted_task_list)`.

### 2. Apply Downsampling Rules

Use the following table to decide how many routes to retain per priority level:

| Total Routes | P0 | P1 | P2 | P3 |
|--------------|----|----|----|----|
| ≤ 50 | All | All | All | All |
| 51 – 100 | All | All | All | Sample 50 % |
| 101 – 200 | All | All | Sample 50 % | Sample 25 % |
| > 200 | All | All | Sample 30 % | Skip entirely |

### 3. Sampling Strategy

When sampling within a priority level:

1. **Sort** the level's entries by `source_count` descending.
2. **Retain** the top _N_ entries (where _N_ = ceiling of the percentage ×
   level count).
3. **Mark** discarded entries with `status: "skipped"` and
   `skip_reason: "downsampled"`.

> Rationale: Higher `source_count` implies greater taint confidence and
> therefore higher value for dynamic tracing.

### 4. Emit Trimmed List

Pass the retained entries to the Sink Grouper (S-036c). Separately, record
skipped entries so the dispatch summary can report them.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Task Priority Sorter (S-036a) | (in-memory) | Yes | Full sorted task list |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Trimmed task list | (in-memory / piped to S-036c) | Subset of routes to actually trace |
| Skipped entries | (in-memory) | Routes removed by downsampling, with `status: "skipped"` |

## Error Handling

| Error | Action |
|-------|--------|
| All routes skipped (e.g., everything is P3 and total > 200) | Emit warning; keep at least 5 P3 routes with highest `source_count` |
| Negative or zero `source_count` on all entries | Retain original order; do not downsample within that level |
