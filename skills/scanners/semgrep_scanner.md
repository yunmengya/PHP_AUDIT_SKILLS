# Semgrep Security Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-021 |
| Phase | Phase-2 |
| Responsibility | Run Semgrep pattern-matching security rules inside Docker targeting PHP-specific vulnerability patterns |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Every result MUST include `check_id` (rule identifier) | Without `check_id`, findings cannot be traced back to the matching rule |
| CR-2 | Output MUST be wrapped in `{"tool": "semgrep", "status": "...", "results": [...]}` | Downstream aggregation fails without standard wrapper |
| CR-3 | Use built-in `p/php` ruleset as baseline; custom rules are supplementary | Missing baseline rules leads to incomplete coverage |

## Fill-in Procedure

### Procedure A: Install Semgrep

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php pip3 install semgrep 2>&1 \|\| true` |
| on_failure | Set `status` = `"skipped"`, `error` = `"pip3 unavailable"` |

### Procedure B: Execute with PHP Security Ruleset

| Field | Fill-in Value |
|-------|--------------|
| command_builtin | `docker exec php semgrep --config "p/php" --json /var/www/html 2>&1` |
| command_custom | `docker exec php semgrep --config /tmp/custom_rules.yaml --json /var/www/html 2>&1` (optional) |
| custom_rule_focus | `$_GET`/`$_POST` → dangerous functions, `==` in auth logic, `unserialize()` without `allowed_classes`, `extract()` without second param, `eval()`/`assert()` calls |
| scan_target | `/var/www/html` (mapped from TARGET_PATH) |
| output_format | Semgrep native JSON |

### Procedure C: Save Output

| Field | Fill-in Value |
|-------|--------------|
| output_path | `$WORK_DIR/semgrep.json` |
| wrapper_format | `{"tool": "semgrep", "status": "success/failed/skipped", "results": [...]}` |

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| semgrep.json | `$WORK_DIR/semgrep.json` | `{"tool": "semgrep", "status": string, "results": [SemgrepFinding]}` | Pattern-matching security scan results |

## Examples

### ✅ GOOD: Valid semgrep output
```json
{
  "tool": "semgrep",
  "status": "success",
  "results": [
    {
      "check_id": "php.lang.security.eval-use",
      "path": "lib/calc.php",
      "start": {"line": 15},
      "extra": {"message": "Detected use of eval()"}
    }
  ]
}
```
Explanation: Contains `check_id` for rule traceability, path and line for location. ✅

### ❌ BAD: Missing check_id and wrapper
```json
{
  "results": [
    {
      "path": "lib/calc.php",
      "line": 15
    }
  ]
}
```
Missing `check_id` — violates CR-1. Missing `tool`/`status` wrapper — violates CR-2. ❌

## Error Handling

| Error | Action |
|-------|--------|
| pip3 not available | Output `{"tool": "semgrep", "status": "skipped", "error": "pip3 unavailable", "results": []}` |
| Install fails | Output `{"tool": "semgrep", "status": "failed", "error": "...", "results": []}` |
| No matches found | Output `{"tool": "semgrep", "status": "success", "results": []}` |
