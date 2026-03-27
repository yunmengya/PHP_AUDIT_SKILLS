# Composer Audit Scanner

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-026 |
| Phase | Phase-2 |
| Responsibility | Run Composer audit to detect known CVEs in project dependencies |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| environment_status.json | Phase-1 | ✅ | `framework`, `framework_version` |
| TARGET_PATH | Orchestrator | ✅ | Source code root (must contain `composer.json`) |
| WORK_DIR | Orchestrator | ✅ | Working directory |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Each result MUST include `cve` field with CVE identifier | CVE ID is critical for cross-referencing with known_cves.md |
| CR-2 | Output MUST be wrapped in `{"tool": "composer_audit", "status": "...", "results": [...]}` | Missing wrapper breaks downstream aggregation |
| CR-3 | Requires Composer 2.4+ — MUST check version before running | Older Composer versions do not have the `audit` subcommand |
| CR-4 | Each result MUST include `package`, `cve`, and `severity` | Incomplete entries cannot be prioritized or cross-referenced |

## Fill-in Procedure

### Procedure A: Execute Audit

| Field | Fill-in Value |
|-------|--------------|
| command | `docker exec php composer audit --format=json 2>&1` |
| prerequisite | Composer 2.4+ (built-in audit command) |
| scan_target | `composer.json` / `composer.lock` in project root |
| on_version_fail | Set `status` = `"skipped"`, `error` = `"composer version < 2.4"` |

### Procedure B: Save Output

| Field | Fill-in Value |
|-------|--------------|
| output_path | `$WORK_DIR/composer_audit.json` |
| wrapper_format | `{"tool": "composer_audit", "status": "success/failed/skipped", "results": [...]}` |
| downstream_use | Supplementary data source for `dep_scanner.md`, providing official CVE matching |

## Output Contract

| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| composer_audit.json | `$WORK_DIR/composer_audit.json` | `{"tool": "composer_audit", "status": string, "results": [CVEFinding]}` | Official dependency vulnerability scan with CVE IDs |

## Examples

### ✅ GOOD: Output with CVE details
```json
{
  "tool": "composer_audit",
  "status": "success",
  "results": [
    {
      "package": "guzzlehttp/guzzle",
      "cve": "CVE-2022-31090",
      "severity": "high",
      "title": "CURLOPT_HTTPAUTH option not cleared on change of origin"
    }
  ]
}
```
Explanation: Contains CVE ID for cross-referencing, package name, severity, and description. ✅

### ❌ BAD: Missing CVE ID
```json
{
  "results": [
    {
      "package": "guzzlehttp/guzzle",
      "severity": "high"
    }
  ]
}
```
Missing `cve` field — violates CR-1. Missing wrapper — violates CR-2. Cannot cross-reference with known_cves.md. ❌

## Error Handling

| Error | Action |
|-------|--------|
| Composer < 2.4 | Output `{"tool": "composer_audit", "status": "skipped", "error": "composer version < 2.4", "results": []}` |
| No composer.json | Output `{"tool": "composer_audit", "status": "skipped", "error": "no composer.json found", "results": []}` |
| No vulnerabilities | Output `{"tool": "composer_audit", "status": "success", "results": []}` |
