## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-036a |
| Phase | 3 |
| Responsibility | Sort candidate routes by priority level and source count for deterministic execution order |

# Task Priority Sorter

## Purpose

Read the priority queue produced by Phase 2 and sort all candidate routes into a
deterministic execution order so that the highest-risk routes are traced first.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `priority_queue.json` | Phase 2 output (`$WORK_DIR/priority_queue.json`) | Yes | `route_id`, `sink_id`, `priority`, `source_count`, `route_url`, `method` |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate or hallucinate file paths, function names, or call chains — only reference code verified to exist in the target source | FAIL — phantom traces create false attack targets in Phase-4 |
| CR-2 | Output MUST conform to the file's Output Contract schema — non-conformant output breaks downstream consumers | FAIL — downstream agents cannot parse trace results |
| CR-3 | MUST sort by severity potential (P0 > P1 > P2) — alphabetical or random order wastes high-value audit slots | FAIL — low-severity sinks processed first, P0 sinks may timeout |

| CR-DEG | Step 0 Degradation Check MUST be completed before any processing — empty table = QC FAIL | Degraded data treated as complete |
## Fill-in Procedure

### Step 0 — Upstream Degradation Check (MANDATORY)

Per `shared/degradation_check.md`, fill the degradation status table before any data processing:

| Upstream Phase | Flag Variable | Value | Affected Input Files |
|---------------|---------------|-------|---------------------|
| Phase-2 | PHASE2_DEGRADED | {true/false/not_set} | {files consumed from this phase} |

IF any Value = true → apply Degradation Enforcement Rules (cap verdicts at "suspected", add [DEGRADED INPUT] prefix).

### Step 1 — Load Priority Queue

Read `$WORK_DIR/priority_queue.json`. Each entry contains at minimum:

| Field | Fill-in Value |
|-------|---------------|
| `route_id` | {unique route identifier from queue} |
| `sink_id` | {associated sink identifier from queue} |
| `priority` | {P0 / P1 / P2 / P3} |
| `source_count` | {integer — number of distinct taint sources reaching this sink} |
| `route_url` | {URL path from queue} |
| `method` | {HTTP method from queue} |

### Step 2 — Primary Sort — Priority Level

Sort entries by priority in ascending severity order:

| Field | Fill-in Value |
|-------|---------------|
| `sort_key_primary` | {priority level: P0 → P1 → P2 → P3} |
| `sort_direction` | {ascending severity — P0 first} |

Priority level meanings:

| Order | Priority | Meaning |
|-------|----------|---------|
| 1 | P0 | Critical — direct user-input-to-sink, no filter |
| 2 | P1 | High — user input reaches sink with weak/bypassable filter |
| 3 | P2 | Medium — user input reaches sink with partial filtering |
| 4 | P3 | Low — indirect flow or strong filtering present |

### Step 3 — Secondary Sort — Source Count

Within each priority level, sort by `source_count` **descending** (higher confidence / larger attack surface first).

| Field | Fill-in Value |
|-------|---------------|
| `sort_key_secondary` | {source_count} |
| `sort_direction` | {descending — highest count first} |

### Step 4 — Dependency-Aware Re-ordering (Optional)

After the base sort, apply the following adjustments without violating primary priority order:

| Field | Fill-in Value |
|-------|---------------|
| `auth_endpoint_boost` | {true/false — move auth/login routes toward top within priority band} |
| `public_entry_boost` | {true/false — prefer anonymous-accessible routes within same priority} |
| `write_method_boost` | {true/false — promote POST/PUT/DELETE above GET within same priority} |

- **Auth endpoints first**: Move authentication / login routes toward the top
  within their priority band so credential acquisition strategies work early.
- **Public entry points first**: Anonymous-accessible routes have the largest
  attack surface — prefer them within the same priority level.
- **Data-write operations first**: `POST` / `PUT` / `DELETE` methods are
  promoted above `GET` within the same priority level (higher impact).

### Step 5 — Emit Sorted List

| Field | Fill-in Value |
|-------|---------------|
| `output_format` | {sorted array of route entries} |
| `downstream_consumer` | {Resource Downsampler S-036b} |

Output the sorted array for downstream consumption by the Resource Downsampler (S-036b).

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Sorted task list | (in-memory / piped to S-036b) | Array of route entries ordered P0→P3, then by `source_count` desc |

## Examples

### ✅ GOOD — Complete sorted output

```json
[
  { "route_id": "route_012", "sink_id": "sink_007", "priority": "P0", "source_count": 5, "route_url": "/api/admin/exec", "method": "POST" },
  { "route_id": "route_003", "sink_id": "sink_002", "priority": "P0", "source_count": 3, "route_url": "/api/user/login", "method": "POST" },
  { "route_id": "route_008", "sink_id": "sink_004", "priority": "P1", "source_count": 4, "route_url": "/api/data/export", "method": "GET" },
  { "route_id": "route_015", "sink_id": "sink_009", "priority": "P2", "source_count": 2, "route_url": "/api/config", "method": "PUT" }
]
```

All fields present, P0 before P1 before P2, higher `source_count` first within same priority.

### ❌ BAD — Missing fields / wrong order

```json
[
  { "route_id": "route_008", "priority": "P1" },
  { "route_id": "route_012", "priority": "P0", "source_count": 5 }
]
```

Problems: P1 sorted before P0; missing `sink_id`, `source_count`, `route_url`, `method` fields.

## Error Handling

| Error | Action |
|-------|--------|
| `priority_queue.json` missing or empty | Abort Phase 3 with `no_tasks` status |
| Entry missing `priority` field | Default to `P3` and log warning |
| Entry missing `source_count` | Default to `0` and log warning |
| Malformed JSON | Abort with `invalid_input` error |
