# Phase-1 QC — Environment Setup

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-080 |
| Category | QC |
| Responsibility | Validate environment detection and Docker build outputs before GATE_1 passage |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `environment_status.json` | docker_builder | YES | `php_version`, `framework`, `framework_version`, `db_type`, `xdebug_working`, `web_accessible`, `routes_accessible`, `routes_error`, `routes_inaccessible`, all schema-required fields |
| `docker-compose.yml` | docker_builder | YES | Service definitions, container names |
| `docker/` directory | docker_builder | YES | Dockerfile(s) presence |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Checks 1–4 (Container Health, PHP Version, Framework ID, Composer) ALL must pass | Verdict = PASS |
| CR-2 | Any of Checks 1–4 fails | Verdict = FAIL — environment not viable for audit |
| CR-3 | Checks 5–6 partially fail (Xdebug or SSRF issues) while 1–4 pass | Verdict = CONDITIONAL_PASS — record degradation impact: Phase 3 may fall back to static tracing |
| CR-4 | MUST-PASS items: container status, PHP version, web accessible, database connection | Failure of any MUST-PASS item → immediate FAIL |
| CR-5 | MAY-WARN items: Xdebug, SSRF target, route classification completeness | Failure only degrades — does not block gate |

## Fill-in Procedure

### Procedure A: Container Health
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 1.1 | All Docker services in `running` state (no `restarting` / `exited`) | all services `running` | `{fill-in: list service states}` | `{✅/❌}` |
| 1.2 | `docker compose ps` shows all defined services healthy | healthy count = total count | `{fill-in: healthy count / total count}` | `{✅/❌}` |
| 1.3 | Web service responds: `http://nginx:80/` returns HTTP 200/301/302 | HTTP 200/301/302 | `{fill-in: HTTP status code}` | `{✅/❌}` |

### Procedure B: PHP Version Detection
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 2.1 | `php_version` is non-empty and matches semver (e.g. `8.1.27`) | non-empty semver string | `{fill-in: detected version}` | `{✅/❌}` |
| 2.2 | Container PHP version (`docker exec php php -v`) matches `php_version` field | version matches `php_version` field | `{fill-in: container PHP version}` | `{✅/❌}` |
| 2.3 | Required extensions loaded: `pdo`, `pdo_mysql`/`pdo_pgsql`, `mbstring`, `xml`, `curl`, `json`, `Xdebug` | all required extensions loaded | `{fill-in: missing extensions list}` | `{✅/❌}` |

### Procedure C: Framework Identification
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 3.1 | `framework` is one of: `Laravel`, `ThinkPHP`, `Yii2`, `Symfony`, `CakePHP`, `CodeIgniter`, `Native` | one of allowed framework values | `{fill-in: detected framework}` | `{✅/❌}` |
| 3.2 | `framework_version` is non-empty when framework ≠ `Native` | non-empty version string | `{fill-in: version value}` | `{✅/❌}` |
| 3.3 | Framework consistent with source code markers (e.g. `artisan` → Laravel, `think` → ThinkPHP) | marker matches declared framework | `{fill-in: marker found}` | `{✅/❌}` |

### Procedure D: Composer Parsing
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 4.1 | `composer.json` exists and was successfully parsed | file exists and parses as valid JSON | `{fill-in: parse status}` | `{✅/❌}` |
| 4.2 | `db_type` is one of: `mysql`, `pgsql`, `sqlite` | one of `mysql`, `pgsql`, `sqlite` | `{fill-in: detected db_type}` | `{✅/❌}` |
| 4.3 | Database connection functional — PDO connection succeeds from within container | PDO connection succeeds | `{fill-in: connection result}` | `{✅/❌}` |

### Procedure E: Xdebug & Route Classification
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 5.1 | `xdebug_working` is `true` — `xdebug.mode` includes `trace` | `xdebug.mode` includes `trace` | `{fill-in: xdebug.mode value}` | `{✅/❌}` |
| 5.2 | `routes_accessible + routes_error + routes_inaccessible > 0` — route classification completed | total route count > 0 | `{fill-in: route counts}` | `{✅/❌}` |
| 5.3 | SSRF target reachable: `http://ssrf-target:80/` returns 200 | HTTP 200 | `{fill-in: HTTP status}` | `{✅/❌}` |

### Procedure F: Schema Validation
| # | Check Item | Expected | Actual | Status |
|---|-----------|----------|--------|--------|
| 6.1 | `environment_status.json` passes `schemas/environment_status.schema.json` | schema validation passes with 0 errors | `{fill-in: validation errors}` | `{✅/❌}` |
| 6.2 | All required fields present: `mode`, `framework`, `framework_version`, `php_version`, `db_type`, `startup_rounds`, `fixes_applied`, `web_accessible`, `routes_accessible`, `routes_error`, `routes_inaccessible`, `xdebug_working`, `db_tables_total`, `db_tables_from_migration`, `db_tables_from_inference`, `disabled_features`, `encrypted_files` | all 17 required fields present | `{fill-in: missing fields}` | `{✅/❌}` |
| 6.3 | No placeholder residue: `grep 'TODO\|TBD\|PLACEHOLDER'` returns 0 hits | 0 hits | `{fill-in: hit count}` | `{✅/❌}` |

### Procedure G: Verdict Determination

| Field | Fill-in Value |
|-------|--------------|
| Checks 1–4 all pass? | `{yes/no}` |
| Checks 5–6 status | `{all_pass / partial_fail / all_fail}` |
| Final verdict | `{pass / conditional_pass / fail}` |
| Degradation impact (if conditional_pass) | `{description}` |
| pass_count | `{N}` / 6 |
| failed_items | `{list}` |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| QC report | `$WORK_DIR/质量报告/quality_report_phase1.json` | `schemas/quality_report_phase1.schema.json` | Per-check pass/fail results with details |

## Examples

### ✅ GOOD: All core checks pass, Xdebug working
```json
{
  "basic_info": {
    "quality_checker": "S-080",
    "target": "Phase-1 output",
    "validated_files": ["environment_status.json", "docker-compose.yml", "docker/"]
  },
  "qc_id": "qc-phase1-docker_builder-20250101T120000",
  "phase": "1",
  "target_agent": "docker_builder",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "checks": {
    "container_health": { "status": "pass", "details": "3/3 services running and healthy" },
    "php_version": { "status": "pass", "expected": "8.1.27", "actual": "8.1.27" },
    "framework_id": { "status": "pass", "detected": "Laravel 10.x" },
    "composer_parsed": { "status": "pass", "details": "composer.json parsed, db_type=mysql, PDO connected" },
    "xdebug_trace": { "status": "pass", "details": "xdebug.mode=trace, SSRF target reachable" },
    "schema_valid": { "status": "pass", "errors": [] }
  },
  "item_results": [
    {"id": 1, "check_item": "Container Health", "expected": "all services running", "actual": "3/3 running and healthy", "status": "✅"},
    {"id": 2, "check_item": "PHP Version Detection", "expected": "non-empty semver, matches container", "actual": "8.1.27 matches", "status": "✅"},
    {"id": 3, "check_item": "Framework Identification", "expected": "valid framework with version", "actual": "Laravel 10.x detected", "status": "✅"},
    {"id": 4, "check_item": "Composer Parsing", "expected": "parsed, valid db_type, PDO connected", "actual": "composer.json parsed, db_type=mysql, PDO connected", "status": "✅"},
    {"id": 5, "check_item": "Xdebug & Route Classification", "expected": "xdebug.mode includes trace, routes > 0, SSRF reachable", "actual": "xdebug.mode=trace, 12 routes classified, SSRF 200", "status": "✅"},
    {"id": 6, "check_item": "Schema Validation", "expected": "schema passes, all fields present, 0 placeholders", "actual": "0 errors, 17/17 fields, 0 placeholder hits", "status": "✅"}
  ],
  "final_verdict": {
    "status": "PASS",
    "passed": "6/6",
    "failed_items": []
  },
  "pass_count": 6,
  "total_count": 6,
  "failed_items": [],
  "degradation_impact": ""
}
```
Explanation: All 6 checks pass — containers healthy, PHP version matches, framework detected, composer parsed, Xdebug functional, schema valid. Verdict is PASS. ✅

### ❌ BAD: PHP version mismatch causes FAIL
```json
{
  "qc_id": "qc-phase1-docker_builder-20250101T120000",
  "phase": "1",
  "target_agent": "docker_builder",
  "timestamp": "2025-01-01T12:00:00Z",
  "verdict": "pass",
  "checks": {
    "container_health": { "status": "pass", "details": "all running" },
    "php_version": { "status": "fail", "expected": "8.1.27", "actual": "7.4.33" },
    "framework_id": { "status": "pass", "detected": "Laravel" },
    "composer_parsed": { "status": "pass", "details": "ok" },
    "xdebug_trace": { "status": "pass", "details": "ok" },
    "schema_valid": { "status": "pass", "errors": [] }
  },
  "pass_count": 5,
  "total_count": 6,
  "failed_items": ["php_version"],
  "degradation_impact": ""
}
```
What's wrong: Check 2 (PHP Version) failed but verdict is still "pass". Violates CR-2 — any failure in Checks 1–4 must produce verdict = "fail". ❌

## Error Handling
| Error | Action |
|-------|--------|
| Missing `environment_status.json` | FAIL — docker_builder did not produce output |
| Malformed JSON in `environment_status.json` | FAIL — data integrity issue; re-run docker_builder |
| Docker daemon not running | FAIL — prerequisite not met; cannot verify containers |
| Schema validation errors on required fields | FAIL — re-run docker_builder |
| Schema validation errors on optional fields | WARN — annotate which fields are missing and propagate as `[OPTIONAL_MISSING: field_name]` to downstream. If `framework_version` or `db_type` optional fields are missing → upgrade to FAIL (these are critical for Phase-4 auditor behavior) |
| Xdebug not working | CONDITIONAL_PASS — Phase 3 degrades to static-only tracing |
| 1st redo attempt | Return to docker_builder with specific fix requirements |
| 2nd redo attempt | Retry with alternative remediation strategy |
| 3rd redo attempt | Phase-1 cannot degrade — halt for user intervention |
