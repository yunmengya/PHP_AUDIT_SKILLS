# AST Sink Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-020 |
| Phase | Phase-2 |
| Responsibility | Run sink_finder.php AST parser inside Docker to discover all dangerous Sink function calls |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `php_version` |
| tools/sink_finder.php | Project tools | ✅ | AST parser script |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Every sink entry MUST include `arg_safety` field | Without `arg_safety`, context_extractor cannot filter and prioritize traces |
| CR-2 | Output MUST be wrapped in `{"tool": "ast_sinks", "status": "...", "results": [...]}` | Downstream aggregation fails without standard wrapper |
| CR-3 | `sink_type` MUST use standard categories (RCE, SQLi, XSS, SSRF, FileOp, Deserial, etc.) | Non-standard types break vulnerability classification |

## Fill-in Procedure

### Procedure A: Install PHP Parser

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php composer require --dev nikic/php-parser --no-interaction 2>&1 \|\| true` |
| on_failure | Record error reason, set `status` = `"failed"` in output JSON |

### Procedure B: Copy Script into Container

| Field | Fill-in Value |
|-------|--------------|
| command | `docker cp tools/sink_finder.php php:/tmp/sink_finder.php` |
| source_file | `tools/sink_finder.php` from project tools directory |
| destination | `/tmp/sink_finder.php` inside `php` container |

### Procedure C: Execute Scan

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php php /tmp/sink_finder.php /var/www/html` |
| scan_target | `/var/www/html` (mapped from TARGET_PATH) |
| output_format | JSON array of sink entries |

### Procedure D: Save Output

| Field | Fill-in Value |
|-------|--------------|
| output_path | `$WORK_DIR/ast_sinks.json` |
| entry_fields | `file`, `line`, `sink_function`, `sink_type`, `arg_safety` |
| arg_safety_values | `safe` / `needs_trace` / `suspicious` |

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| ast_sinks.json | `$WORK_DIR/ast_sinks.json` | `{"tool": "ast_sinks", "status": string, "results": [SinkEntry]}` | All dangerous Sink calls with argument safety classification |

## Examples

### ✅ GOOD: Sink entry with arg_safety
```json
{
  "tool": "ast_sinks",
  "status": "success",
  "results": [
    {
      "file": "app/Http/Controllers/RunController.php",
      "line": 55,
      "sink_function": "eval",
      "sink_type": "RCE",
      "arg_safety": "needs_trace"
    }
  ]
}
```
Explanation: Contains all required fields including `arg_safety` for downstream filtering. ✅

### ❌ BAD: Missing arg_safety
```json
{
  "tool": "ast_sinks",
  "status": "success",
  "results": [
    {
      "file": "app/Http/Controllers/RunController.php",
      "line": 55,
      "sink_function": "eval"
    }
  ]
}
```
Missing `arg_safety` — violates CR-1. context_extractor cannot determine trace priority. ❌

## Error Handling

| Error | Action |
|-------|--------|
| PHP Parser install fails | Output `{"tool": "ast_sinks", "status": "failed", "error": "...", "results": []}` |
| sink_finder.php crash | Record error, output `{"tool": "ast_sinks", "status": "failed", "error": "...", "results": []}` |
| No sinks found | Output `{"tool": "ast_sinks", "status": "success", "results": []}` (valid empty — application may be genuinely safe) |
