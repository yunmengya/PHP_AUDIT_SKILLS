# PHPStan Security Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-022 |
| Phase | Phase-2 |
| Responsibility | Run PHPStan static analysis inside Docker focusing on type-safety issues that may lead to vulnerabilities |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Output MUST be wrapped in `{"tool": "phpstan", "status": "...", "results": [...]}` | Raw PHPStan output breaks downstream aggregation |
| CR-2 | Each result MUST include `file`, `line`, `message`, and `level` | Incomplete entries cannot be correlated with other scanner findings |
| CR-3 | Analysis level MUST be set to 6+ for security-relevant type checking | Lower levels miss type confusion and unsafe cast issues |

## Fill-in Procedure

### Procedure A: Install PHPStan

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php composer require --dev phpstan/phpstan --no-interaction 2>&1 \|\| true` |
| on_failure | Set `status` = `"failed"`, record error reason in output JSON |

### Procedure B: Generate Configuration

| Field | Fill-in Value |
|-------|--------------|
| config_format | NEON (phpstan.neon) |
| analysis_level | `6` |
| paths | `app`, `src` |
| ignore_errors | `[]` |
| report_unmatched | `false` |
| deploy_command | `docker cp phpstan.neon php:/var/www/html/phpstan.neon` |

### Procedure C: Execute Analysis

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php vendor/bin/phpstan analyse --error-format=json 2>&1` |
| output_format | PHPStan native JSON |
| security_focus | Type mismatches (type confusion), undefined method calls (injection points), unsafe array access (out-of-bounds) |

### Procedure D: Save Output

| Field | Fill-in Value |
|-------|--------------|
| output_path | `$WORK_DIR/phpstan.json` |
| wrapper_format | `{"tool": "phpstan", "status": "success/failed", "results": [...]}` |

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| phpstan.json | `$WORK_DIR/phpstan.json` | `{"tool": "phpstan", "status": string, "results": [PHPStanError]}` | Type analysis results focused on security issues |

## Examples

### ✅ GOOD: Output with security focus
```json
{
  "tool": "phpstan",
  "status": "success",
  "results": [
    {
      "file": "src/Auth.php",
      "line": 22,
      "message": "Parameter #1 expects string, mixed given",
      "level": "error"
    }
  ]
}
```
Explanation: Wrapped in standard format with all required fields for downstream correlation. ✅

### ❌ BAD: Raw PHPStan output without wrapper
```json
{
  "totals": {"errors": 1},
  "files": {
    "src/Auth.php": {
      "errors": 1,
      "messages": [{"line": 22, "message": "..."}]
    }
  }
}
```
Raw PHPStan format — violates CR-1. Must wrap in `{"tool", "status", "results"}` structure. ❌

## Error Handling

| Error | Action |
|-------|--------|
| Install fails | Output `{"tool": "phpstan", "status": "failed", "error": "...", "results": []}` |
| Analysis crashes | Output `{"tool": "phpstan", "status": "failed", "error": "...", "results": []}` |
| No issues found | Output `{"tool": "phpstan", "status": "success", "results": []}` |
