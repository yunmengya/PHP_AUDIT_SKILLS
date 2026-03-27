> **Skill ID**: S-030h | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: all parsed data from S-030a through S-030g
> **Output**: `route_map.json` + `auth_gap_report.json` (final validated outputs)

# Route Map Assembler

## Purpose

Merge all intermediate results from the route mapping pipeline (S-030a through S-030g) into the final `route_map.json` output. Apply all Critical Rules (CR-1 through CR-6) as a final validation pass. This is the terminal step that produces the deliverable consumed by downstream Phase-2 agents (context_extractor, risk_classifier) and Phase-3 deep analysis.

## Procedure

### Step 1: Load All Intermediate Results

Load the following files produced by prior sub-skills:

| File | Source Sub-Skill | Content |
|------|-----------------|---------|
| `validated_routes.json` | S-030b | Cross-validated HTTP routes |
| `route_params.json` | S-030c | Input sources per route |
| `hidden_routes.json` | S-030d | Hidden/undocumented endpoints |
| `cli_entries.json` | S-030e | CLI synthetic routes |
| `background_entries.json` | S-030f | CRON/Queue/Hook synthetic routes |
| `auth_gap_report.json` | S-030g | Auth gap analysis |

### Step 2: Merge Routes into Unified List

1. Start with all routes from `validated_routes.json`.
2. Append hidden routes from `hidden_routes.json` with `"hidden": true`.
3. Append CLI entries from `cli_entries.json`.
4. Append CRON/Queue/Hook entries from `background_entries.json`.
5. Assign sequential IDs: `route_001`, `route_002`, ..., `route_synth_001`, ...
6. Deduplicate: if a hidden route matches an existing validated route by `(method, path)`, merge metadata rather than creating a duplicate.

### Step 3: Enrich with Parameter Sources

For each route in the merged list:
1. Look up the route ID in `route_params.json`.
2. Populate the `input_sources` field with the parameter data from S-030c.
3. If no parameter data exists for a route, set `input_sources: []`.

### Step 4: Enrich with Auth Classification

For each route:
1. Look up the route in `auth_gap_report.json` classification.
2. Set `auth_level` based on the classification:
   - `public` → `"anonymous"`
   - `authenticated` → `"authenticated"`
   - `authorized` → `"authorized"`
   - `system` → `"system"`
   - `suspicious` → `"anonymous"` (with a flag for review)

### Step 5: Apply CR Validation Rules

Run final validation on every route entry:

| Rule | Check | Action on Violation |
|------|-------|-------------------|
| **CR-1** | Route has `file` + `line` fields with non-empty values | Delete route, log: "CR-1 violation: no provenance for {path}" |
| **CR-2** | If CLI route command was available, `validated_routes.json` has `cli_route_list != "not_available"` | Log warning if CLI was available but not executed |
| **CR-3** | `controller` + `action` exist in source code (`controller_verified: true`) | Delete route, log: "CR-3 violation: controller not found for {path}" |
| **CR-4** | `input_sources` is based on code analysis (not empty when controller has input handling) | Mark `input_sources` as `"unknown"` if not analyzed |
| **CR-5** | No `Route::resource` entries remain unexpanded | Check for any resource route markers; expand if found |
| **CR-6** | Hidden routes (`hidden: true`) have `discovery_source` field | Delete hidden route without `discovery_source`, log warning |

### Step 6: Generate Final route_map.json

Produce the final output in this schema:

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "framework": "laravel",
    "framework_version": "10.x",
    "total_routes": 93,
    "http_routes": 85,
    "hidden_routes": 3,
    "synthetic_routes": 5,
    "cli_route_list": "available",
    "cr_violations": []
  },
  "routes": [
    {
      "id": "route_001",
      "path": "/api/users/{id}",
      "method": "GET",
      "controller": "App\\Http\\Controllers\\UserController",
      "action": "show",
      "file": "app/Http/Controllers/UserController.php",
      "line": 45,
      "input_sources": ["route_param:id"],
      "middleware": ["auth:sanctum"],
      "auth_level": "authenticated",
      "hidden": false
    }
  ]
}
```

Each route entry fields:

| Field | Description | Required |
|-------|-------------|----------|
| `id` | `route_{NNN}` or `route_synth_{NNN}` | ✅ |
| `path` | Discovered URL path | ✅ |
| `method` | HTTP method (GET/POST/PUT/DELETE/ANY) or entry type | ✅ |
| `controller` | Fully qualified controller class | ✅ |
| `action` | Controller method name | ✅ |
| `file` | Source file path (relative to project root) | ✅ |
| `line` | Line number in source file | ✅ |
| `input_sources` | Array of parameter source labels | ✅ |
| `middleware` | Array of middleware names | ✅ |
| `auth_level` | `anonymous` / `authenticated` / `authorized` / `system` | ✅ |
| `hidden` | Boolean — whether endpoint is undocumented | ✅ |
| `discovery_source` | How hidden endpoint was found (only if `hidden: true`) | Conditional |
| `entry_type` | `CLI` / `CRON` / `QUEUE` / `HOOK` (only for synthetic routes) | Conditional |
| `synthetic_id` | `ENTRY_*:name` (only for synthetic routes) | Conditional |

### Step 7: Copy Final auth_gap_report.json

Copy `auth_gap_report.json` from S-030g as the final output. No modifications needed — it is already in its final form.

### Step 8: Summary Statistics

Print a summary to the console (user-facing output in Chinese):

```
━━━ 路由映射完成 ━━━
HTTP 路由: {N} 条
隐藏端点: {N} 条
合成入口: CLI={N} CRON={N} QUEUE={N} HOOK={N}
认证缺口: {N} 条 (高风险: {N})
CR 违规:  {N} 条 (已删除)
输出文件: $WORK_DIR/route_map.json
         $WORK_DIR/auth_gap_report.json
```

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | All HTTP route entries |
| route_params.json | `$WORK_DIR/route_params.json` | ✅ | Input sources per route |
| hidden_routes.json | `$WORK_DIR/hidden_routes.json` | ✅ | Hidden endpoint entries |
| cli_entries.json | `$WORK_DIR/cli_entries.json` | ✅ | CLI synthetic routes |
| background_entries.json | `$WORK_DIR/background_entries.json` | ✅ | CRON/Queue/Hook entries |
| auth_gap_report.json | `$WORK_DIR/auth_gap_report.json` | ✅ | Auth classification data |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | Framework metadata |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| route_map.json | `$WORK_DIR/route_map.json` | Final unified route map (schema: `schemas/route_map.schema.json`) |
| auth_gap_report.json | `$WORK_DIR/auth_gap_report.json` | Final auth gap analysis (schema: `schemas/auth_gap_report.schema.json`) |

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-1 | Every route MUST have `file` + `line` provenance. Violating entries are deleted. |
| CR-2 | CLI route command MUST have been attempted if framework supports it. |
| CR-3 | Controller + method MUST exist in source. Violating entries are deleted. |
| CR-4 | `input_sources` MUST be from code analysis. Unknown sources marked accordingly. |
| CR-5 | Resource routes MUST be fully expanded. Any unexpanded entries trigger re-expansion. |
| CR-6 | Hidden endpoints MUST have `discovery_source`. Violating entries are deleted. |

## Error Handling

| Error | Action |
|-------|--------|
| Intermediate file missing (e.g., `hidden_routes.json`) | Log warning, proceed without that data source; output will be partial but valid |
| All intermediate files missing | Output empty `route_map.json` with `"routes": []`, log critical error |
| CR validation deletes all routes | Output empty routes array, log critical: "All routes failed validation" |
| Duplicate route IDs after merge | Re-assign sequential IDs to resolve conflicts |
| JSON parse error on intermediate file | Log error with filename, skip that data source |
