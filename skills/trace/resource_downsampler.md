## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-036b |
| Phase | 3 |
| Responsibility | Downsample lower-priority routes when total count exceeds resource budgets |

# Resource Downsampler

## Purpose

Automatically downsample lower-priority routes when the total number of routes
exceeds resource budgets, ensuring that high-priority routes are always fully
traced while keeping overall execution time bounded.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Sorted task list | Task Priority Sorter S-036a (in-memory) | Yes | Full sorted task list with `priority`, `source_count` |

## Fill-in Procedure

### Step 1 — Count Total Routes

| Field | Fill-in Value |
|-------|---------------|
| `total_routes` | {len(sorted_task_list)} |

Compute `total_routes = len(sorted_task_list)`.

### Step 2 — Apply Downsampling Rules

| Field | Fill-in Value |
|-------|---------------|
| `total_routes` | {computed total from Step 1} |
| `P0_action` | {All — always retain all P0 routes} |
| `P1_action` | {All — always retain all P1 routes} |
| `P2_action` | {All / Sample 50% / Sample 30% — based on total_routes} |
| `P3_action` | {All / Sample 50% / Sample 25% / Skip entirely — based on total_routes} |

Use the following table to decide how many routes to retain per priority level:

| Total Routes | P0 | P1 | P2 | P3 |
|--------------|----|----|----|----|
| ≤ 50 | All | All | All | All |
| 51 – 100 | All | All | All | Sample 50 % |
| 101 – 200 | All | All | Sample 50 % | Sample 25 % |
| > 200 | All | All | Sample 30 % | Skip entirely |

### Step 3 — Sampling Strategy

When sampling within a priority level:

| Field | Fill-in Value |
|-------|---------------|
| `sort_within_level` | {source_count descending} |
| `retain_count` | {ceiling(percentage × level_count)} |
| `discard_status` | {status: "skipped"} |
| `discard_reason` | {skip_reason: "downsampled"} |

1. **Sort** the level's entries by `source_count` descending.
2. **Retain** the top _N_ entries (where _N_ = ceiling of the percentage × level count).
3. **Mark** discarded entries with `status: "skipped"` and `skip_reason: "downsampled"`.

> Rationale: Higher `source_count` implies greater taint confidence and therefore higher value for dynamic tracing.

### Step 4 — Emit Trimmed List

| Field | Fill-in Value |
|-------|---------------|
| `retained_entries_destination` | {Sink Grouper S-036c} |
| `skipped_entries_destination` | {dispatch summary report} |

Pass the retained entries to the Sink Grouper (S-036c). Separately, record
skipped entries so the dispatch summary can report them.

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Trimmed task list | (in-memory / piped to S-036c) | Subset of routes to actually trace |
| Skipped entries | (in-memory) | Routes removed by downsampling, with `status: "skipped"` |

## Examples

### ✅ GOOD — Correctly downsampled (120 total routes)

```json
{
  "total_routes": 120,
  "retained": [
    { "route_id": "route_001", "priority": "P0", "source_count": 8, "status": "pending" },
    { "route_id": "route_002", "priority": "P1", "source_count": 5, "status": "pending" },
    { "route_id": "route_010", "priority": "P2", "source_count": 4, "status": "pending" }
  ],
  "skipped": [
    { "route_id": "route_050", "priority": "P3", "source_count": 1, "status": "skipped", "skip_reason": "downsampled" }
  ]
}
```

P0/P1 fully retained, P2 sampled 50%, P3 sampled 25%, skipped entries marked properly.

### ❌ BAD — Missing skip metadata

```json
{
  "retained": [
    { "route_id": "route_001", "priority": "P0" }
  ],
  "skipped": [
    { "route_id": "route_050" }
  ]
}
```

Problems: No `total_routes`, skipped entries missing `status`, `skip_reason`, `priority`, `source_count`.

## Error Handling

| Error | Action |
|-------|--------|
| All routes skipped (e.g., everything is P3 and total > 200) | Emit warning; keep at least 5 P3 routes with highest `source_count` |
| Negative or zero `source_count` on all entries | Retain original order; do not downsample within that level |
