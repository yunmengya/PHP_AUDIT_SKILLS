> **Skill ID**: S-030b | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: framework type + Docker container access + `raw_routes.json` from S-030a
> **Output**: `validated_routes.json` — cross-validated route list

# Route Command Executor

## Purpose

Execute framework-provided route listing commands (e.g., `artisan route:list`, `debug:router`) inside the Docker container to obtain the authoritative route table. Cross-validate command output against the statically parsed routes from S-030a. Annotate discrepancies. This step enforces CR-2: frameworks with route-listing commands MUST have them executed.

## Procedure

### Step 1: Identify Available Route Commands

Based on the detected framework, determine which CLI route-listing command is available:

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

If the framework has no route-listing command, skip to Step 4.

### Step 2: Execute Route Command in Docker

1. Determine the PHP container name from `environment_status.json` or by inspecting `docker-compose.yml`.
2. Execute the route command:
   ```bash
   docker exec {container} {command} {format_flag} 2>/dev/null
   ```
3. Capture output. If the command fails (non-zero exit code), log the error and annotate:
   ```json
   { "cli_route_list": "unavailable", "cli_error": "{error message}" }
   ```
4. Parse the JSON (or text) output into a normalized route list.

### Step 3: Cross-Validate Against Parsed Routes

Compare the CLI-obtained route list with `raw_routes.json` from S-030a:

1. **Match routes** by `(method, path)` tuple.
2. For each route in the CLI output:
   - If a matching route exists in `raw_routes.json` → mark as `"cross_validated": true`.
   - If NO matching route in `raw_routes.json` → add it with `"source": "cli_only"` and `"cross_validated": false`.
3. For each route in `raw_routes.json`:
   - If NO matching route in CLI output → annotate `"cli_missing": true`.
4. Log all discrepancies in a `discrepancies` array.

### Step 4: Produce Validated Route List

Merge both sources into `validated_routes.json`:
- Routes confirmed by both sources get highest confidence.
- CLI-only routes are included but flagged for manual review.
- Parse-only routes (missing from CLI) are included but annotated.
- If no CLI command was available, copy `raw_routes.json` as-is with `"cli_route_list": "not_available"`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| raw_routes.json | `$WORK_DIR/raw_routes.json` | ✅ | Parsed route entries from S-030a |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework`, `docker_container` |
| Docker container | Running container | ⚠️ Optional | CLI route command execution |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| validated_routes.json | `$WORK_DIR/validated_routes.json` | Cross-validated route list with confidence annotations |

### Output Schema

```json
{
  "cli_route_list": "available|unavailable|not_available",
  "cli_command": "php artisan route:list --json",
  "cli_error": null,
  "total_parsed": 85,
  "total_cli": 82,
  "matched": 80,
  "cli_only": 2,
  "parse_only": 5,
  "routes": [ ... ],
  "discrepancies": [
    {
      "type": "cli_only|parse_only|method_mismatch|controller_mismatch",
      "path": "/api/internal/health",
      "detail": "Found in CLI output but not in static parse"
    }
  ]
}
```

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-2 | If the framework supports a route-listing command, it MUST be executed. Skipping without attempting is a violation. |
| CR-1 | CLI-only routes still need provenance. Attempt to locate their source file via controller class resolution. |

## Error Handling

| Error | Action |
|-------|--------|
| Docker container not running | Log warning, set `cli_route_list: "unavailable"`, proceed with parse-only results |
| Route command exits non-zero | Log error message, set `cli_route_list: "unavailable"`, proceed with parse-only results |
| Command output not valid JSON | Attempt text parsing; if that fails, log error and proceed with parse-only results |
| Container name unknown | Try `docker ps` to discover PHP containers; if none found, set unavailable |
| Command times out (>30s) | Kill process, log timeout, proceed with parse-only results |
