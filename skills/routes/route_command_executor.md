# Route Command Executor

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030h |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Execute framework route-listing commands in Docker and cross-validate against statically parsed routes |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| raw_routes.json | `$WORK_DIR/raw_routes.json` | ✅ | Parsed route entries from S-030a |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework`, `docker_container` |
| Docker container | Running container | ⚠️ Optional | CLI route command execution |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-2 | If the framework supports a route-listing command, it MUST be executed. Skipping without attempting is a violation. | Missing routes that only exist at runtime — incomplete route map |
| CR-1 | CLI-only routes still need provenance. Attempt to locate their source file via controller class resolution. | Entry deleted by assembler if provenance not found |

## Fill-in Procedure

### Procedure A: Identify Available Route Commands

| Field | Fill-in Value |
|-------|--------------|
| framework | {read from `environment_status.json`} |
| command | {select from table below; if no command available → skip to Procedure D} |
| format_flag | {JSON format flag for the command} |

**Framework route command reference:**

| Framework | Command | Format Flag |
|-----------|---------|-------------|
| Laravel | `php artisan route:list` | `--json` |
| Symfony | `php bin/console debug:router` | `--format=json` |
| WordPress | `wp-cli route list` | `--format=json` |
| ThinkPHP | — (no built-in command) | N/A |
| Yii2 | — (no built-in command) | N/A |
| CakePHP | `bin/cake routes` | — (parse text output) |
| CodeIgniter | — (no built-in command) | N/A |
| Drupal | `drush route:list` | `--format=json` |
| Native PHP | — (not applicable) | N/A |

### Procedure B: Execute Route Command in Docker

| Field | Fill-in Value |
|-------|--------------|
| container_name | {from `environment_status.json` or inspect `docker-compose.yml`} |
| exec_command | {`docker exec {container} {command} {format_flag} 2>/dev/null`} |
| exit_code | {capture exit code — 0 = success, non-zero = failure} |
| cli_route_list | {`available` if success, `unavailable` if failure} |
| cli_error | {error message if command failed, `null` if success} |
| parsed_output | {parse JSON or text output into normalized route list} |

### Procedure C: Cross-Validate Against Parsed Routes

| Field | Fill-in Value |
|-------|--------------|
| match_key | {`(method, path)` tuple} |
| matched_routes | {routes found in BOTH CLI output AND `raw_routes.json` → `cross_validated: true`} |
| cli_only_routes | {routes in CLI output but NOT in `raw_routes.json` → `source: "cli_only"`, `cross_validated: false`} |
| parse_only_routes | {routes in `raw_routes.json` but NOT in CLI output → `cli_missing: true`} |
| discrepancies | {array of all mismatches with type and detail} |

**Discrepancy types:**

| Type | Description |
|------|-------------|
| `cli_only` | Found in CLI output but not in static parse |
| `parse_only` | Found in static parse but not in CLI output |
| `method_mismatch` | Same path but different HTTP methods |
| `controller_mismatch` | Same path+method but different controller resolution |

### Procedure D: Produce Validated Route List

| Field | Fill-in Value |
|-------|--------------|
| merge_strategy | {both-source routes get highest confidence; CLI-only flagged for review; parse-only annotated} |
| cli_route_list | {`available` / `unavailable` / `not_available`} |
| cli_command | {actual command string executed, or `null`} |
| total_parsed | {count from `raw_routes.json`} |
| total_cli | {count from CLI output, or `0`} |
| matched | {count of routes confirmed by both sources} |
| cli_only | {count of CLI-only routes} |
| parse_only | {count of parse-only routes} |
| fallback | {if no CLI command available → copy `raw_routes.json` as-is with `cli_route_list: "not_available"`} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| validated_routes.json | `$WORK_DIR/原始数据/validated_routes.json` | See schema below | Cross-validated route list with confidence annotations |

### Output Schema

```json
{
  "cli_route_list": "available",
  "cli_command": "php artisan route:list --json",
  "cli_error": null,
  "total_parsed": 85,
  "total_cli": 82,
  "matched": 80,
  "cli_only": 2,
  "parse_only": 5,
  "routes": [
    {
      "id": "route_001",
      "path": "/api/users/{id}",
      "method": "GET",
      "controller": "App\Http\Controllers\UserController",
      "action": "show",
      "file": "app/Http/Controllers/UserController.php",
      "line": 45,
      "cross_validated": true,
      "middleware": ["auth:sanctum"]
    }
  ],
  "discrepancies": [
    {
      "type": "cli_only",
      "path": "/api/internal/health",
      "detail": "Found in CLI output but not in static parse"
    }
  ]
}
```

## Examples

### ✅ GOOD: Cross-Validated Route Entry
```json
{
  "cli_route_list": "available",
  "cli_command": "php artisan route:list --json",
  "cli_error": null,
  "total_parsed": 85,
  "total_cli": 82,
  "matched": 80,
  "cli_only": 2,
  "parse_only": 5,
  "routes": [
    {
      "id": "route_001",
      "path": "/api/users/{id}",
      "method": "GET",
      "controller": "App\Http\Controllers\UserController",
      "action": "show",
      "file": "app/Http/Controllers/UserController.php",
      "line": 45,
      "cross_validated": true,
      "middleware": ["auth:sanctum"]
    }
  ],
  "discrepancies": []
}
```
CLI command executed (CR-2). Route confirmed by both static parse and runtime CLI. Provenance present (CR-1). ✅

### ❌ BAD: CLI Command Available but Not Executed
```json
{
  "cli_route_list": "not_available",
  "cli_command": null,
  "routes": [
    {
      "id": "route_001",
      "path": "/api/users/{id}",
      "method": "GET",
      "controller": "App\Http\Controllers\UserController",
      "action": "show",
      "file": "app/Http/Controllers/UserController.php",
      "line": 45,
      "cross_validated": false
    }
  ],
  "discrepancies": []
}
```
Framework is Laravel which supports `php artisan route:list`, but `cli_route_list` is `not_available` — violates **CR-2**. Must attempt execution even if Docker container is down (then set `unavailable` with error). ❌

## Error Handling
| Error | Action |
|-------|--------|
| Docker container not running | Log warning, set `cli_route_list: "unavailable"`, proceed with parse-only results |
| Route command exits non-zero | Log error message, set `cli_route_list: "unavailable"`, proceed with parse-only results |
| Command output not valid JSON | Attempt text parsing; if that fails, log error and proceed with parse-only results |
| Container name unknown | Try `docker ps` to discover PHP containers; if none found, set unavailable |
| Command times out (>30s) | Terminate process, log timeout, proceed with parse-only results |
