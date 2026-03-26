# Psalm Taint Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-020 |
| Phase | Phase-2 (Static Asset Reconnaissance) |
| Responsibility | Run Psalm taint analysis inside Docker container and output structured taint paths |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `php_version` |
| TARGET_PATH | Orchestrator | ✅ | Source code root |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## Fill-in Procedure

### Procedure A: Install Psalm

```bash
docker exec php composer require --dev vimeo/psalm --no-interaction 2>&1 || true
```

On failure: record reason, output failed status JSON.

### Procedure B: Generate Configuration

Generate `psalm.xml`:
```xml
<?xml version="1.0"?>
<psalm errorLevel="4" resolveFromConfigFile="true"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns="https://getpsalm.org/schema/config"
       xsi:schemaLocation="https://getpsalm.org/schema/config vendor/vimeo/psalm/config.xsd">
    <projectFiles>
        <directory name="app" />
        <directory name="routes" />
        <ignoreFiles>
            <directory name="vendor" />
        </ignoreFiles>
    </projectFiles>
</psalm>
```

Write configuration into the container.

### Procedure C: Execute Scan

```bash
docker exec php vendor/bin/psalm --taint-analysis --output-format=json 2>&1
```

### Procedure D: Save Output

Save output as `$WORK_DIR/psalm_taint.json`.

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| psalm_taint.json | `$WORK_DIR/psalm_taint.json` | Taint analysis results with Source→Sink paths |

## Examples

### ✅ GOOD: Valid output with taint paths
```json
{"tool": "psalm", "status": "success", "results": [{"type": "TaintedSql", "file": "app/Models/User.php", "line": 42}]}
```

### ❌ BAD: Missing status field on failure
```json
{"results": []}
```
Must include `"status": "failed"` and `"error"` field on failure. ❌

## Error Handling

| Error Condition | Action |
|----------------|--------|
| Composer install fails | Output `{"tool": "psalm", "status": "failed", "error": "install failed", "results": []}` |
| Psalm crashes on legacy code | Record error, output failed status JSON |
| No taint paths found | Output `{"tool": "psalm", "status": "success", "results": []}` (valid empty) |
