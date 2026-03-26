# PHPStan Security Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-023 |
| Phase | Phase-2 (Static Asset Reconnaissance) |
| Responsibility | Run PHPStan static analysis inside Docker focusing on type-safety issues that may lead to vulnerabilities |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## Fill-in Procedure

### Procedure A: Install PHPStan

```bash
docker exec php composer require --dev phpstan/phpstan --no-interaction 2>&1 || true
```

### Procedure B: Generate Configuration

```bash
cat > /tmp/phpstan.neon << 'NEON'
parameters:
    level: 6
    paths:
        - app
        - src
    ignoreErrors: []
    reportUnmatchedIgnoredErrors: false
NEON
docker cp /tmp/phpstan.neon php:/var/www/html/phpstan.neon
```

### Procedure C: Execute Analysis

```bash
docker exec php vendor/bin/phpstan analyse --error-format=json 2>&1
```

### Procedure D: Save Output

Save output as `$WORK_DIR/phpstan.json`.

Focus on security-relevant findings:
- Type mismatches (may lead to type confusion vulnerabilities)
- Undefined method calls (potential injection points)
- Unsafe array access (potential out-of-bounds)

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| phpstan.json | `$WORK_DIR/phpstan.json` | Type analysis results focused on security issues |

## Examples

### ✅ GOOD: Output with security focus
```json
{"tool": "phpstan", "status": "success", "results": [{"file": "src/Auth.php", "line": 22, "message": "Parameter #1 expects string, mixed given", "level": "error"}]}
```

### ❌ BAD: Raw PHPStan output without wrapper
Not valid — must include tool/status wrapper. ❌

## Error Handling

| Error Condition | Action |
|----------------|--------|
| Install fails | Output `{"tool": "phpstan", "status": "failed", "error": "...", "results": []}` |
| Analysis crashes | Record error, output failed status |
| No issues found | Output `{"tool": "phpstan", "status": "success", "results": []}` |
