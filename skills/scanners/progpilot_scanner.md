# Progpilot Security Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-021 |
| Phase | Phase-2 (Static Asset Reconnaissance) |
| Responsibility | Run Progpilot security scan inside Docker container with custom Source/Sink definitions |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## Fill-in Procedure

### Procedure A: Install Progpilot

```bash
docker exec php composer require --dev designsecurity/progpilot --no-interaction 2>&1 || true
```

### Procedure B: Generate Configuration

Generate progpilot configuration file with custom Source/Sink definitions tailored to the detected framework.

### Procedure C: Execute Scan

```bash
docker exec php php vendor/designsecurity/progpilot/progpilot.phar --configuration config.json /var/www/html 2>&1
```

### Procedure D: Save Output

Save output as `$WORK_DIR/progpilot.json`.

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| progpilot.json | `$WORK_DIR/progpilot.json` | Security vulnerability scan results |

## Examples

### ✅ GOOD: Valid output
```json
{"tool": "progpilot", "status": "success", "results": [{"vuln_type": "sql_injection", "file": "lib/db.php", "line": 18}]}
```

### ❌ BAD: Raw output without wrapper
```
[{"vuln_type": "sql_injection"}]
```
Must include tool name and status. ❌

## Error Handling

| Error Condition | Action |
|----------------|--------|
| Install fails | Output `{"tool": "progpilot", "status": "failed", "error": "...", "results": []}` |
| Scan timeout | Kill process, output partial results if available |
| No vulnerabilities found | Output `{"tool": "progpilot", "status": "success", "results": []}` |
