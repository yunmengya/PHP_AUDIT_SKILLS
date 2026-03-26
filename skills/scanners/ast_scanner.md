# AST Sink Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-022 |
| Phase | Phase-2 (Static Asset Reconnaissance) |
| Responsibility | Run sink_finder.php AST parser inside Docker to discover all dangerous Sink function calls |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `php_version` |
| tools/sink_finder.php | Project tools | ✅ | AST parser script |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## Fill-in Procedure

### Procedure A: Install PHP Parser

```bash
docker exec php composer require --dev nikic/php-parser --no-interaction 2>&1 || true
```

### Procedure B: Copy Script into Container

```bash
docker cp tools/sink_finder.php php:/tmp/sink_finder.php
```

### Procedure C: Execute Scan

```bash
docker exec php php /tmp/sink_finder.php /var/www/html
```

### Procedure D: Save Output

Save output as `$WORK_DIR/ast_sinks.json`.

Each entry contains: `file`, `line`, `sink_function`, `sink_type`, `arg_safety` (safe/needs_trace/suspicious).

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| ast_sinks.json | `$WORK_DIR/ast_sinks.json` | All dangerous Sink calls with argument safety classification |

## Examples

### ✅ GOOD: Sink entry with arg_safety
```json
{"file": "app/Http/Controllers/RunController.php", "line": 55, "sink_function": "eval", "sink_type": "RCE", "arg_safety": "needs_trace"}
```

### ❌ BAD: Missing arg_safety
```json
{"file": "app/Http/Controllers/RunController.php", "line": 55, "sink_function": "eval"}
```
`arg_safety` is required for context_extractor filtering. ❌

## Error Handling

| Error Condition | Action |
|----------------|--------|
| PHP Parser install fails | Output `{"tool": "ast_sinks", "status": "failed", "error": "...", "results": []}` |
| sink_finder.php crash | Record error, output failed status |
| No sinks found | Output valid empty result (application may be genuinely safe) |
