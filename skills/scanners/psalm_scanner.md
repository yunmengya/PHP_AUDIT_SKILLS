# Psalm Taint Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-023 |
| Phase | Phase-2 |
| Responsibility | Run Psalm taint analysis inside Docker container and output structured taint paths |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `php_version` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Output MUST be wrapped in `{"tool": "psalm", "status": "...", "results": [...]}` | Missing wrapper breaks downstream aggregation |
| CR-2 | Each result MUST include `type` (taint type), `file`, and `line` | Incomplete taint entries cannot be correlated with other scanner findings |
| CR-3 | On failure, MUST include both `"status": "failed"` AND `"error"` field | Silent failures hide scanning gaps from the audit report |
| CR-4 | MUST use `--taint-analysis` flag (not regular analysis) | Regular analysis misses Source→Sink data flow tracking |

## Fill-in Procedure

### Procedure A: Install Psalm

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php composer require --dev vimeo/psalm --no-interaction 2>&1 \|\| true` |
| on_failure | Record reason, set `status` = `"failed"`, `error` = failure message |

### Procedure B: Generate Configuration

| Field | Fill-in Value |
|-------|--------------|
| config_format | XML (`psalm.xml`) |
| error_level | `4` |
| project_dirs | `app`, `routes` |
| ignore_dirs | `vendor` |
| deploy_method | Write `psalm.xml` into container at `/var/www/html/psalm.xml` |
| schema_ref | `https://getpsalm.org/schema/config vendor/vimeo/psalm/config.xsd` |

### Procedure C: Execute Scan

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php vendor/bin/psalm --taint-analysis --output-format=json 2>&1` |
| mode | Taint analysis (Source→Sink tracking) |
| output_format | Psalm native JSON |

### Procedure D: Save Output

| Field | Fill-in Value |
|-------|--------------|
| output_path | `$WORK_DIR/psalm_taint.json` |
| wrapper_format | `{"tool": "psalm", "status": "success/failed", "results": [...]}` |

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| psalm_taint.json | `$WORK_DIR/psalm_taint.json` | `{"tool": "psalm", "status": string, "results": [TaintFinding]}` | Taint analysis results with Source→Sink paths |

## Examples

### ✅ GOOD: Valid output with taint paths
```json
{
  "tool": "psalm",
  "status": "success",
  "results": [
    {
      "type": "TaintedSql",
      "file": "app/Models/User.php",
      "line": 42,
      "message": "Detected tainted SQL query"
    }
  ]
}
```
Explanation: Contains standard wrapper, taint type, file location, and descriptive message. ✅

### ❌ BAD: Missing status field on failure
```json
{
  "results": []
}
```
Missing `"tool"`, `"status"`, and `"error"` fields — violates CR-1 and CR-3. Cannot distinguish between "no findings" and "scan failed". ❌

## Error Handling

| Error | Action |
|-------|--------|
| Composer install fails | Output `{"tool": "psalm", "status": "failed", "error": "install failed", "results": []}` |
| Psalm crashes on legacy code | Output `{"tool": "psalm", "status": "failed", "error": "...", "results": []}` |
| No taint paths found | Output `{"tool": "psalm", "status": "success", "results": []}` (valid empty) |
