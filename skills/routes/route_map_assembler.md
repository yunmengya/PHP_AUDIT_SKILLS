# Route Map Assembler

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030g |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Merge all intermediate route mapping results into the final unified `route_map.json` with CR validation |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| validated_routes.json | `$WORK_DIR/validated_routes.json` | ✅ | All HTTP route entries |
| route_params.json | `$WORK_DIR/route_params.json` | ✅ | Input sources per route |
| hidden_routes.json | `$WORK_DIR/hidden_routes.json` | ✅ | Hidden endpoint entries |
| cli_entries.json | `$WORK_DIR/cli_entries.json` | ✅ | CLI synthetic routes |
| background_entries.json | `$WORK_DIR/background_entries.json` | ✅ | CRON/Queue/Hook entries |
| auth_gap_report.json | `$WORK_DIR/auth_gap_report.json` | ✅ | Auth classification data |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | Framework metadata |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Every route MUST have `file` + `line` provenance with non-empty values | **Violating entries DELETED** |
| CR-2 | CLI route command MUST have been attempted if framework supports it | Log warning if skipped |
| CR-3 | Controller + method MUST exist in source code (`controller_verified: true`) | **Violating entries DELETED** |
| CR-4 | `input_sources` MUST be from code analysis, not guessed | Mark as `"unknown"` if not analyzed |
| CR-5 | Resource routes MUST be fully expanded — no `Route::resource` stubs | Re-expand if found |
| CR-6 | Hidden endpoints (`hidden: true`) MUST have `discovery_source` field | **Violating entries DELETED** |

## Fill-in Procedure

### Procedure A: Load All Intermediate Results

| Field | Fill-in Value |
|-------|--------------|
| validated_routes | {load `$WORK_DIR/validated_routes.json` — from route command executor} |
| route_params | {load `$WORK_DIR/route_params.json` — from parameter source extractor} |
| hidden_routes | {load `$WORK_DIR/hidden_routes.json` — from hidden endpoint discoverer} |
| cli_entries | {load `$WORK_DIR/cli_entries.json` — from CLI entry scanner} |
| background_entries | {load `$WORK_DIR/background_entries.json` — from CRON/queue/hook scanner} |
| auth_gap_report | {load `$WORK_DIR/auth_gap_report.json` — from auth gap analyzer} |
| environment_status | {load `$WORK_DIR/environment_status.json` — framework metadata} |

### Procedure B: Merge Routes into Unified List

| Field | Fill-in Value |
|-------|--------------|
| base_routes | {start with all routes from `validated_routes.json`} |
| append_hidden | {append hidden routes with `"hidden": true`} |
| append_cli | {append CLI entries from `cli_entries.json`} |
| append_background | {append CRON/Queue/Hook entries from `background_entries.json`} |
| id_assignment | {assign sequential IDs: `route_001`, `route_002`, ..., `route_synth_001`, ...} |
| deduplication | {if hidden route matches validated route by `(method, path)` → merge metadata, don't duplicate} |

### Procedure C: Enrich with Parameter Sources

For each route in merged list:

| Field | Fill-in Value |
|-------|--------------|
| route_id | {look up route ID in `route_params.json`} |
| input_sources | {populate from parameter data; if no data exists → set `input_sources: []`} |

### Procedure D: Enrich with Auth Classification

For each route:

| Field | Fill-in Value |
|-------|--------------|
| route_id | {look up route in `auth_gap_report.json`} |
| auth_level | {map classification: `public` → `anonymous`, `authenticated` → `authenticated`, `authorized` → `authorized`, `system` → `system`, `suspicious` → `anonymous` (flagged)} |

### Procedure E: Apply CR Validation Rules

For each route entry, apply all rules:

| CR | Check | Fill-in Action |
|----|-------|---------------|
| CR-1 | Route has `file` + `line` with non-empty values | {if missing → DELETE route, log: `"CR-1 violation: no provenance for {path}"`} |
| CR-2 | If CLI route command available, check `cli_route_list != "not_available"` | {FAIL — CLI routes missing from final map, coverage incomplete} |
| CR-3 | `controller_verified: true` | {if false → DELETE route, log: `"CR-3 violation: controller not found for {path}"`} |
| CR-4 | `input_sources` from code analysis | {if not analyzed → mark `input_sources` as `"unknown"`} |
| CR-5 | No unexpanded `Route::resource` entries | {if found → expand into individual routes} |
| CR-6 | Hidden routes have `discovery_source` | {if missing → DELETE hidden route, log warning} |

### Procedure F: Generate Final route_map.json

Fill in metadata:

| Field | Fill-in Value |
|-------|--------------|
| generated_at | {ISO 8601 timestamp} |
| framework | {from `environment_status.json`} |
| framework_version | {from `environment_status.json`} |
| total_routes | {count of all routes after CR validation} |
| http_routes | {count of standard HTTP routes} |
| hidden_routes | {count of hidden endpoints} |
| synthetic_routes | {count of CLI + CRON + Queue + Hook entries} |
| cli_route_list | {`available` / `unavailable` / `not_available`} |
| cr_violations | {array of logged CR violation messages} |

Each route entry MUST have these fields:

| Field | Description | Required |
|-------|-------------|----------|
| `id` | `route_{NNN}` or `route_synth_{NNN}` | ✅ |
| `path` | Discovered URL path | ✅ |
| `method` | HTTP method or entry type | ✅ |
| `controller` | Fully qualified controller class | ✅ |
| `action` | Controller method name | ✅ |
| `file` | Source file path (relative to project root) | ✅ |
| `line` | Line number in source file | ✅ |
| `input_sources` | Array of parameter source labels | ✅ |
| `middleware` | Array of middleware names | ✅ |
| `auth_level` | `anonymous` / `authenticated` / `authorized` / `system` | ✅ |
| `hidden` | Boolean — whether endpoint is undocumented | ✅ |
| `discovery_source` | How hidden endpoint was found (only if `hidden: true`) | Conditional |
| `entry_type` | `CLI` / `CRON` / `QUEUE` / `HOOK` (only for synthetic) | Conditional |
| `synthetic_id` | `ENTRY_*:name` (only for synthetic) | Conditional |

### Procedure G: Copy Final auth_gap_report.json

| Field | Fill-in Value |
|-------|--------------|
| action | {copy `auth_gap_report.json` from Procedure A as final output — no modifications needed} |

### Procedure H: Summary Statistics (Console Output)

Print user-facing summary (in Chinese):

```
━━━ 路由映射完成 ━━━
HTTP 路由: {N} 条
隐藏端点: {N} 条
Synthetic entries: CLI={N} CRON={N} QUEUE={N} HOOK={N}
认证缺口: {N} 条 (高风险: {N})
CR 违规:  {N} 条 (已删除)
输出文件: $WORK_DIR/route_map.json
         $WORK_DIR/auth_gap_report.json
```

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| route_map.json | `$WORK_DIR/原始数据/route_map.json` | `schemas/route_map.schema.json` | Final unified route map |
| auth_gap_report.json | `$WORK_DIR/原始数据/auth_gap_report.json` | `schemas/auth_gap_report.schema.json` | Final auth gap analysis |

### Output Schema (route_map.json)

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

## Examples

### ✅ GOOD: Properly Merged Route with Full Enrichment
```json
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
```
All required fields present. Provenance verified (CR-1). Controller verified (CR-3). Input sources from code analysis (CR-4). Auth level from middleware analysis. ✅

### ❌ BAD: CR-1 Violation Kept in Output
```json
{
  "id": "route_055",
  "path": "/api/internal/health",
  "method": "GET",
  "controller": "App\\Http\\Controllers\\HealthController",
  "action": "check",
  "input_sources": [],
  "middleware": [],
  "auth_level": "anonymous",
  "hidden": false
}
```
Missing `file` and `line` fields — violates **CR-1**. This entry should have been DELETED during Procedure E validation, not kept in the output. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Intermediate file missing (e.g., `hidden_routes.json`) | Log warning, proceed without that data source; output will be partial but valid |
| All intermediate files missing | Output empty `route_map.json` with `"routes": []`, log critical error |
| CR validation deletes all routes | Output empty routes array, log critical: "All routes failed validation" |
| Duplicate route IDs after merge | Re-assign sequential IDs to resolve conflicts |
| JSON parse error on intermediate file | Log error with filename, skip that data source |
