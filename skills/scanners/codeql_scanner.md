# CodeQL Deep Scanner (Optional)

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-026 |
| Phase | Phase-2 (Static Asset Reconnaissance) |
| Responsibility | Run CodeQL deep taint tracking analysis for full Source→Sink path discovery (optional — skip on install failure) |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `php_version` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## Fill-in Procedure

### Procedure A: Create CodeQL Database

```bash
docker exec php codeql database create /tmp/codeql-db --language=php
```

### Procedure B: Run Security Queries

```bash
docker exec php codeql database analyze /tmp/codeql-db \
  codeql/php-queries:Security --format=json --output=/tmp/codeql_results.json
```

Key queries:
- Taint tracking: Full Source → Sink path
- SQL injection: User input to SQL queries
- Command injection: User input to system commands
- Path injection: User input to file paths

### Procedure C: Save Output

Save output as `$WORK_DIR/codeql.json`.

> CodeQL installation is large; this scanner is **optional**. Skip entirely on installation failure.

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| codeql.json | `$WORK_DIR/codeql.json` | Deep taint tracking results with full paths |

## Examples

### ✅ GOOD: Taint path result
```json
{"tool": "codeql", "status": "success", "results": [{"rule": "php/sql-injection", "source": {"file": "routes/api.php", "line": 12}, "sink": {"file": "app/Models/User.php", "line": 45}}]}
```

### ❌ BAD: Missing source/sink path
```json
{"results": [{"rule": "php/sql-injection"}]}
```
CodeQL's value is the full path — omitting it defeats the purpose. ❌

## Error Handling

| Error Condition | Action |
|----------------|--------|
| CodeQL not installed | Output `{"tool": "codeql", "status": "skipped", "error": "codeql not available", "results": []}` |
| Database creation fails | Output skipped status |
| Analysis timeout | Kill process, output partial results |
| No findings | Output `{"tool": "codeql", "status": "success", "results": []}` |
