> **Skill ID**: S-036a | **Phase**: 3 | **Parent**: S-036 (Trace-Dispatcher)
> **Input**: `priority_queue.json`
> **Output**: Sorted task list (P0→P3, secondary by `source_count` descending)

# Task Priority Sorter

## Purpose

Read the priority queue produced by Phase 2 and sort all candidate routes into a
deterministic execution order so that the highest-risk routes are traced first.

## Procedure

### 1. Load Priority Queue

Read `$WORK_DIR/priority_queue.json`.  Each entry contains at minimum:

| Field | Type | Description |
|-------|------|-------------|
| `route_id` | string | Unique route identifier |
| `sink_id` | string | Associated sink identifier |
| `priority` | string | One of `P0`, `P1`, `P2`, `P3` |
| `source_count` | integer | Number of distinct taint sources reaching this sink |
| `route_url` | string | URL path |
| `method` | string | HTTP method |

### 2. Primary Sort — Priority Level

Sort entries by priority in ascending severity order:

| Order | Priority | Meaning |
|-------|----------|---------|
| 1 | P0 | Critical — direct user-input-to-sink, no filter |
| 2 | P1 | High — user input reaches sink with weak/bypassable filter |
| 3 | P2 | Medium — user input reaches sink with partial filtering |
| 4 | P3 | Low — indirect flow or strong filtering present |

### 3. Secondary Sort — Source Count

Within each priority level, sort by `source_count` **descending** (higher
confidence / larger attack surface first).

### 4. Dependency-Aware Re-ordering (Optional Refinement)

After the base sort, apply the following adjustments without violating primary
priority order:

- **Auth endpoints first**: Move authentication / login routes toward the top
  within their priority band so credential acquisition strategies work early.
- **Public entry points first**: Anonymous-accessible routes have the largest
  attack surface — prefer them within the same priority level.
- **Data-write operations first**: `POST` / `PUT` / `DELETE` methods are
  promoted above `GET` within the same priority level (higher impact).

### 5. Emit Sorted List

Output the sorted array for downstream consumption by the Resource Downsampler
(S-036b).

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Phase 2 output | `$WORK_DIR/priority_queue.json` | Yes | `route_id`, `sink_id`, `priority`, `source_count`, `route_url`, `method` |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Sorted task list | (in-memory / piped to S-036b) | Array of route entries ordered P0→P3, then by `source_count` desc |

## Error Handling

| Error | Action |
|-------|--------|
| `priority_queue.json` missing or empty | Abort Phase 3 with `no_tasks` status |
| Entry missing `priority` field | Default to `P3` and log warning |
| Entry missing `source_count` | Default to `0` and log warning |
| Malformed JSON | Abort with `invalid_input` error |
