# CodeQL Deep Scanner (Optional)

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-024 |
| Phase | Phase-2 |
| Responsibility | Run CodeQL deep taint tracking analysis for full Source→Sink path discovery (optional — skip on install failure) |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `php_version` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Each result MUST include both `source` and `sink` with `file` + `line` | CodeQL's value is the full taint path — omitting source/sink defeats the purpose |
| CR-2 | Output MUST be wrapped in `{"tool": "codeql", "status": "...", "results": [...]}` | Downstream aggregation fails without standard wrapper |
| CR-3 | This scanner is OPTIONAL — skip entirely on install failure with `"status": "skipped"` | Do NOT block the pipeline for CodeQL installation issues |
| CR-4 | MUST include `rule` identifier (e.g., `php/sql-injection`) in each result | Without rule ID, findings cannot be classified by vulnerability type |

## Fill-in Procedure

### Procedure A: Create CodeQL Database

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php codeql database create /tmp/codeql-db --language=php` |
| language | `php` |
| db_path | `/tmp/codeql-db` inside container |
| on_failure | Set `status` = `"skipped"`, skip remaining procedures |

### Procedure B: Run Security Queries

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php codeql database analyze /tmp/codeql-db codeql/php-queries:Security --format=json --output=/tmp/codeql_results.json` |
| query_suite | `codeql/php-queries:Security` |
| key_queries | Taint tracking (full Source→Sink path), SQL injection, command injection, path injection |
| output_format | CodeQL native JSON |

### Procedure C: Save Output

| Field | Fill-in Value |
|-------|--------------|
| output_path | `$WORK_DIR/codeql.json` |
| wrapper_format | `{"tool": "codeql", "status": "success/failed/skipped", "results": [...]}` |
| note | CodeQL installation is large; this scanner is optional — skip entirely on installation failure |

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| codeql.json | `$WORK_DIR/codeql.json` | `{"tool": "codeql", "status": string, "results": [CodeQLFinding]}` | Deep taint tracking results with full Source→Sink paths |

## Examples

### ✅ GOOD: Taint path result
```json
{
  "tool": "codeql",
  "status": "success",
  "results": [
    {
      "rule": "php/sql-injection",
      "source": {"file": "routes/api.php", "line": 12},
      "sink": {"file": "app/Models/User.php", "line": 45},
      "message": "User input flows to SQL query"
    }
  ]
}
```
Explanation: Contains full Source→Sink path with rule identifier for classification. ✅

### ❌ BAD: Missing source/sink path
```json
{
  "results": [
    {
      "rule": "php/sql-injection"
    }
  ]
}
```
Missing `source`/`sink` — violates CR-1. Missing wrapper — violates CR-2. CodeQL's value is the full path; omitting it defeats the purpose. ❌

## Error Handling

| Error | Action |
|-------|--------|
| CodeQL not installed | Output `{"tool": "codeql", "status": "skipped", "error": "codeql not available", "results": []}` |
| Database creation fails | Output `{"tool": "codeql", "status": "skipped", "error": "...", "results": []}` |
| Analysis timeout | Kill process, output partial results with `"status": "partial"` |
| No findings | Output `{"tool": "codeql", "status": "success", "results": []}` |
