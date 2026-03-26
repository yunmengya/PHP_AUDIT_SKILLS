# Semgrep Security Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-024 |
| Phase | Phase-2 (Static Asset Reconnaissance) |
| Responsibility | Run Semgrep pattern-matching security rules inside Docker targeting PHP-specific vulnerability patterns |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## Fill-in Procedure

### Procedure A: Install Semgrep

```bash
docker exec php pip3 install semgrep 2>&1 || true
```

### Procedure B: Execute with PHP Security Ruleset

```bash
# Built-in PHP security rules
docker exec php semgrep --config "p/php" --json /var/www/html 2>&1

# Optional: custom rules
docker exec php semgrep --config /tmp/custom_rules.yaml --json /var/www/html 2>&1
```

Custom rules focus on:
- `$_GET`/`$_POST` flowing directly into dangerous functions
- Use of `==` in authentication logic
- `unserialize()` without `allowed_classes` parameter
- `extract()` without second parameter
- `eval()`/`assert()` calls

### Procedure C: Save Output

Save output as `$WORK_DIR/semgrep.json`.

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| semgrep.json | `$WORK_DIR/semgrep.json` | Pattern-matching security scan results |

## Examples

### ✅ GOOD: Valid semgrep output
```json
{"tool": "semgrep", "status": "success", "results": [{"check_id": "php.lang.security.eval-use", "path": "lib/calc.php", "start": {"line": 15}}]}
```

### ❌ BAD: Missing check_id
```json
{"results": [{"path": "lib/calc.php", "line": 15}]}
```
Must include rule identifier for traceability. ❌

## Error Handling

| Error Condition | Action |
|----------------|--------|
| pip3 not available | Skip semgrep, output `{"tool": "semgrep", "status": "skipped", "error": "pip3 unavailable", "results": []}` |
| Install fails | Output failed status JSON |
| No matches found | Output `{"tool": "semgrep", "status": "success", "results": []}` |
