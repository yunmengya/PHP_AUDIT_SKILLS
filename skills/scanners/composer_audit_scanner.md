# Composer Audit Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-025 |
| Phase | Phase-2 (Static Asset Reconnaissance) |
| Responsibility | Run Composer audit to detect known CVEs in project dependencies |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `framework_version` |
| TARGET_PATH | Orchestrator | ✅ | Source code root (must contain composer.json) |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## Fill-in Procedure

### Procedure A: Execute Audit

```bash
# Composer 2.4+ built-in audit command
docker exec php composer audit --format=json 2>&1
```

### Procedure B: Save Output

Save output as `$WORK_DIR/composer_audit.json`.

Serves as supplementary data source for `dep_scanner.md`, providing official CVE matching.

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| composer_audit.json | `$WORK_DIR/composer_audit.json` | Official dependency vulnerability scan with CVE IDs |

## Examples

### ✅ GOOD: Output with CVE details
```json
{"tool": "composer_audit", "status": "success", "results": [{"package": "guzzlehttp/guzzle", "cve": "CVE-2022-31090", "severity": "high"}]}
```

### ❌ BAD: Missing CVE ID
```json
{"results": [{"package": "guzzlehttp/guzzle", "severity": "high"}]}
```
CVE ID is critical for cross-referencing with known_cves.md. ❌

## Error Handling

| Error Condition | Action |
|----------------|--------|
| Composer < 2.4 | Output `{"tool": "composer_audit", "status": "skipped", "error": "composer version < 2.4", "results": []}` |
| No composer.json | Output skipped status |
| No vulnerabilities | Output `{"tool": "composer_audit", "status": "success", "results": []}` |
