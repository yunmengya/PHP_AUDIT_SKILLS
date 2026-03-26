> **Skill ID**: S-080 | **Phase**: 1 (QC) | **Gate**: GATE_1
> **Input**: Phase 1 outputs
> **Output**: quality_report_phase1.json

# Phase-1 Quality Check — Environment Setup

## Identity

Quality checker for Phase 1. Validates environment detection and Docker build outputs before GATE_1 passage. Ensures Docker containers are running, PHP version is correctly detected, framework is identified, and composer.json is properly parsed.

## Input Contract

| Source | Path | Required | Validation |
|--------|------|----------|------------|
| Environment status | `$WORK_DIR/environment_status.json` | YES | Must exist, valid JSON, pass `schemas/environment_status.schema.json` |
| Docker Compose config | `$WORK_DIR/docker-compose.yml` | YES | Must exist, YAML parseable |
| Docker directory | `$WORK_DIR/docker/` | YES | Directory exists, contains Dockerfile(s) |

## Check Procedure

### Check 1: Container Health
- [ ] All Docker services in `running` state — no `restarting` or `exited` containers
- [ ] `docker compose ps` shows all defined services healthy
- [ ] Web service responds: `http://nginx:80/` returns HTTP 200/301/302

### Check 2: PHP Version Detection
- [ ] `environment_status.json.php_version` is non-empty and matches semver format (e.g. `8.1.27`)
- [ ] Actual container PHP version (`docker exec php php -v`) matches `php_version` field
- [ ] Required PHP extensions loaded: `pdo`, `pdo_mysql`/`pdo_pgsql`, `mbstring`, `xml`, `curl`, `json`, `Xdebug`

### Check 3: Framework Identification
- [ ] `framework` field is one of: `Laravel`, `ThinkPHP`, `Yii2`, `Symfony`, `CakePHP`, `CodeIgniter`, `Native`
- [ ] `framework_version` is non-empty when framework ≠ `Native`
- [ ] Framework identification is consistent with source code markers (e.g. `artisan` for Laravel, `think` for ThinkPHP)

### Check 4: Composer Parsing
- [ ] `composer.json` exists in target project and was successfully parsed
- [ ] `db_type` is one of: `mysql`, `pgsql`, `sqlite`
- [ ] Database connection is functional — PDO connection succeeds from within container

### Check 5: Xdebug & Route Classification
- [ ] `xdebug_working` is `true` — `xdebug.mode` includes `trace`
- [ ] `routes_accessible + routes_error + routes_inaccessible > 0` — route classification completed
- [ ] SSRF target reachable: `http://ssrf-target:80/` returns 200

### Check 6: Schema Validation
- [ ] `environment_status.json` passes `schemas/environment_status.schema.json` validation
- [ ] All required fields present per schema: `mode`, `framework`, `framework_version`, `php_version`, `db_type`, `startup_rounds`, `fixes_applied`, `web_accessible`, `routes_accessible`, `routes_error`, `routes_inaccessible`, `xdebug_working`, `db_tables_total`, `db_tables_from_migration`, `db_tables_from_inference`, `disabled_features`, `encrypted_files`
- [ ] No placeholder residue: `grep '【填写】\|TODO\|TBD\|PLACEHOLDER'` returns 0 hits

## Verdict Rules

| Condition | Verdict |
|-----------|---------|
| Checks 1–4 all pass (containers, PHP, framework, composer) | PASS |
| Checks 5–6 partially fail (Xdebug or SSRF target issues) | CONDITIONAL_PASS — record degradation impact: Phase 3 may fall back to static tracing |
| Any of Checks 1–4 fail | FAIL — environment not viable for audit |

**MUST-PASS items:** Container status, PHP version, web accessible, database connection
**MAY-WARN items:** Xdebug, SSRF target, route classification completeness

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase1.json` | Detailed check results with per-item pass/fail |

**Output JSON structure:**
```json
{
  "qc_id": "qc-phase1-docker_builder-{timestamp}",
  "phase": "1",
  "target_agent": "docker_builder",
  "timestamp": "ISO-8601",
  "verdict": "pass|conditional_pass|fail",
  "checks": {
    "container_health": { "status": "pass|fail", "details": "..." },
    "php_version": { "status": "pass|fail", "expected": "...", "actual": "..." },
    "framework_id": { "status": "pass|fail", "detected": "..." },
    "composer_parsed": { "status": "pass|fail", "details": "..." },
    "xdebug_trace": { "status": "pass|fail|warn", "details": "..." },
    "schema_valid": { "status": "pass|fail", "errors": [] }
  },
  "pass_count": 0,
  "total_count": 6,
  "failed_items": [],
  "degradation_impact": ""
}
```

## Error Handling

| Error | Action |
|-------|--------|
| Missing `environment_status.json` | FAIL — cannot validate; docker_builder did not produce output |
| Malformed JSON in `environment_status.json` | FAIL — data integrity issue; re-run docker_builder |
| Docker daemon not running | FAIL — prerequisite not met; cannot verify containers |
| Schema validation errors | FAIL on required fields; WARN on optional fields |
| Xdebug not working | CONDITIONAL_PASS — Phase 3 degrades to static-only tracing |

## Redo Rules

| Attempt | Action |
|---------|--------|
| 1st failure | Return to docker_builder with specific fix requirements |
| 2nd failure | Retry with alternative remediation strategy |
| 3rd failure | Phase-1 cannot degrade — halt for user intervention |
