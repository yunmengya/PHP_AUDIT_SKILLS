# Progpilot Security Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-025 |
| Phase | Phase-2 |
| Responsibility | Run Progpilot security scan inside Docker container with custom Source/Sink definitions |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Output MUST be wrapped in `{"tool": "progpilot", "status": "...", "results": [...]}` | Raw Progpilot output breaks downstream aggregation |
| CR-2 | Each result MUST include `vuln_type`, `file`, and `line` | Incomplete entries cannot be correlated with other scanner findings |
| CR-3 | Configuration MUST be tailored to detected framework from `environment_status.json` | Generic config misses framework-specific Source/Sink patterns |

## Fill-in Procedure

### Procedure A: Install Progpilot

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php composer require --dev designsecurity/progpilot --no-interaction 2>&1 \|\| true` |
| on_failure | Set `status` = `"failed"`, record error reason in output JSON |

### Procedure B: Generate Configuration

| Field | Fill-in Value |
|-------|--------------|
| config_format | JSON (`config.json`) |
| content | Custom Source/Sink definitions tailored to detected framework |
| framework_source | Read `framework` field from `environment_status.json` |
| deploy_method | Write `config.json` into container |

### Procedure C: Execute Scan

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php php vendor/designsecurity/progpilot/progpilot.phar --configuration config.json /var/www/html 2>&1` |
| scan_target | `/var/www/html` (mapped from TARGET_PATH) |
| output_format | Progpilot native JSON |

### Procedure D: Save Output

| Field | Fill-in Value |
|-------|--------------|
| output_path | `$WORK_DIR/progpilot.json` |
| wrapper_format | `{"tool": "progpilot", "status": "success/failed", "results": [...]}` |

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| progpilot.json | `$WORK_DIR/progpilot.json` | `{"tool": "progpilot", "status": string, "results": [ProgpilotFinding]}` | Security vulnerability scan results |

## Examples

### ✅ GOOD: Valid output with vulnerability details
```json
{
  "tool": "progpilot",
  "status": "success",
  "results": [
    {
      "vuln_type": "sql_injection",
      "file": "lib/db.php",
      "line": 18,
      "source": "$_GET['id']",
      "sink": "mysql_query()"
    }
  ]
}
```
Explanation: Wrapped in standard format with vulnerability type, location, and Source/Sink context. ✅

### ❌ BAD: Raw output without wrapper
```json
[
  {"vuln_type": "sql_injection"}
]
```
Missing `tool`/`status` wrapper — violates CR-1. Missing `file`/`line` — violates CR-2. ❌

## Error Handling

| Error | Action |
|-------|--------|
| Install fails | Output `{"tool": "progpilot", "status": "failed", "error": "...", "results": []}` |
| Scan timeout | Kill process, output `{"tool": "progpilot", "status": "failed", "error": "timeout", "results": [...partial]}` |
| No vulnerabilities found | Output `{"tool": "progpilot", "status": "success", "results": []}` |
