# Docker-Builder (Environment Builder)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-011 |
| Phase | Phase-1 |
| Responsibility | Generate Docker configurations and progressively start the audit environment |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| TARGET_PATH | Orchestrator parameter | ✅ | Target source code path |
| WORK_DIR | Orchestrator parameter | ✅ | Working directory path |
| Env-Detective results | S-010 output | ✅ | framework, php_version, database, extensions, fallback_strategies, encrypted_files |
| reconstructed_schema.sql | `$WORK_DIR/reconstructed_schema.sql` (S-012 output) | ✅ | Reconstructed database schema for import |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST proceed layer-by-layer startup; next layer only after current layer passes verification | Skipping verification → cascading failures |
| CR-2 | Dockerfile runs as `USER www-data` by default; self-healing MUST use `docker exec -u root` for privilege escalation | Permission denied errors block fixes |
| CR-3 | Phase A self-healing max 5 rounds, Phase B max 3 rounds | Infinite loop → resource exhaustion |
| CR-4 | If Phase B entirely fails, MUST pause and ask user via AskUserQuestion | Unrecoverable state without human guidance |
| CR-5 | Resource tier MUST be determined before rendering templates | Over/under-provisioned containers → OOM or waste |
| CR-6 | MUST NOT modify test files under ANY circumstance | Test integrity compromise |

## Fill-in Procedure

### Procedure A: Resource Tier Decision
| Field | Fill-in Value |
|-------|--------------|
| php_file_count | {`find "$TARGET_PATH" -name "*.php" -not -path "*/vendor/*" -not -path "*/node_modules/*" | wc -l`} |
| composer_deps | {`jq '.packages | length' "$TARGET_PATH/composer.lock"` or 0 if missing} |
| tier_small | {PHP_FILES ≤ 100 AND COMPOSER_DEPS ≤ 20 → PHP_MEMORY_LIMIT=512m, DB_MEMORY_LIMIT=512m, PHP_CPU_LIMIT=1.0} |
| tier_medium | {PHP_FILES ≤ 500 OR COMPOSER_DEPS ≤ 50 → PHP_MEMORY_LIMIT=1g, DB_MEMORY_LIMIT=1g, PHP_CPU_LIMIT=2.0} |
| tier_large | {PHP_FILES > 500 OR COMPOSER_DEPS > 50 → PHP_MEMORY_LIMIT=2g, DB_MEMORY_LIMIT=2g, PHP_CPU_LIMIT=3.0} |

### Procedure B: Configuration File Generation
| Field | Fill-in Value |
|-------|--------------|
| output_dir | {`$WORK_DIR/docker/`} |
| docker_compose | {Render from `templates/docker-compose.template.yml`; replace `{{WORK_DIR}}`, `{{PROJECT_NAME}}`, `{{PHP_VERSION}}`, `{{DB_TYPE}}`, `{{DB_VERSION}}`, `{{NGINX_CONF}}`, `{{ENABLE_REDIS}}`, `{{PHP_MEMORY_LIMIT}}`, `{{PHP_CPU_LIMIT}}`, `{{DB_MEMORY_LIMIT}}`, `{{OOB_PORT}}` (default 9001)} |
| dockerfile | {Render from `templates/Dockerfile.template`; replace `{{BASE_IMAGE}}`, `{{PHP_VERSION}}`, `{{EXTENSIONS}}`, `{{EXTRA_PACKAGES}}`} |
| nginx_conf | {Select by framework: Laravel→`templates/nginx/laravel.conf`, ThinkPHP→`templates/nginx/thinkphp.conf`, Yii2→`templates/nginx/yii2.conf`, Other→`templates/nginx/generic.conf`} |
| xdebug_ini | {Copy from `templates/xdebug.ini.template`} |
| env_file | {If `.env.example` exists→copy and modify DB connection; else→generate minimal .env; apply fallback strategies; set `APP_DEBUG=true`} |

#### Image Selection Decision Table

| Priority | Condition | BASE_IMAGE |
|----------|-----------|------------|
| 1 | WordPress project | `wordpress:php{{PHP_VERSION}}-fpm` (skip composer install) |
| 2 | PHP 5.6 | `php:5.6-fpm` (Alpine does not support 5.6) |
| 3 | Requires FFI or encrypted files exist | `php:{{PHP_VERSION}}-fpm` (Alpine has difficulty compiling FFI) |
| 4 | Extension count ≥ 5 custom extensions | `php:{{PHP_VERSION}}-fpm` (Alpine low compilation success rate) |
| 5 | PHP ≥ 7.1 and few extensions | `php:{{PHP_VERSION}}-fpm-alpine` (image ~1/3 size of Debian) |
| 6 | Default | `php:{{PHP_VERSION}}-fpm` |

### Procedure C: Progressive Startup (Layer-by-Layer)
| Field | Fill-in Value |
|-------|--------------|
| layer_1_php_nginx | {`docker compose up -d php nginx` → verify: `docker compose ps` + `docker exec php php -v`} |
| layer_2_composer | {`docker exec php composer install --no-interaction --no-scripts` → verify: `docker exec php ls vendor/autoload.php`} |
| layer_3_database | {`docker compose up -d db` → wait for healthcheck (up to 2 min) → import schema: `docker exec -i db mysql -uroot -paudit_root_pass audit_db < reconstructed_schema.sql` (or Laravel: `docker exec php php artisan migrate --force`)} |
| layer_4_web | {`docker exec php curl -sS -o /dev/null -w "%{http_code}" http://nginx:80/` → expected: 200 or 302} |
| layer_5_xdebug | {`docker exec php php -m | grep -i xdebug` → trigger trace: `docker exec php curl -sS -H "Cookie: XDEBUG_TRIGGER=1" http://nginx:80/` → verify: `docker exec php ls /tmp/xdebug_traces/`} |
| layer_6_ssrf_oob | {SSRF target: `docker exec php curl -sS -o /dev/null -w "%{http_code}" http://ssrf-target:80/` → expected 200; OOB listener: `docker exec php curl -sS -o /dev/null -w "%{http_code}" http://oob-listener:9001/healthcheck` → expected 200} |

### Procedure D: Error Self-Healing Loop
| Field | Fill-in Value |
|-------|--------------|

**Phase A — Standard Self-Healing (max 5 rounds per round):**

| Error Type | Fix Strategy |
|------------|-------------|
| Class not found | `docker exec -u root php composer require <package>` |
| Table doesn't exist | Infer from Model → `ALTER TABLE` to create missing table |
| Column not found | `ALTER TABLE ADD COLUMN` |
| Permission denied | `docker exec -u root php chmod -R 777 storage bootstrap/cache` |
| SQLSTATE Connection refused | Wait for DB healthcheck → retry |
| Undefined index | Add missing config entries to `.env` |
| ext not loaded | Modify Dockerfile to add extension → `docker compose build` (rebuild auto-restores USER www-data) |
| 404 Not Found | Check nginx rewrite configuration |
| CSRF token mismatch | Disable CSRF middleware |

**Phase B — Compatibility Fix (max 3 rounds, enter ONLY after Phase A has completely failed):**

| Round | Fix Type | Description |
|-------|----------|-------------|
| B-1 | Missing helper/function | `Call to undefined function` → composer require compatibility package (e.g., `laravel/helpers`) |
| B-2 | ServiceProvider/Middleware | Comment out non-core Providers and middleware (preserve core: auth/session/route) |
| B-3 | PHP version switch | Modify Dockerfile to switch PHP version → rebuild → re-run composer install |

> Verify after each round: `curl -sS -o /dev/null -w "%{http_code}" http://nginx:80/` → 200/302 = pass.
> Phase B entirely fails → pause and use AskUserQuestion. See `shared/env_selfheal.md` for detailed strategies.

### Procedure E: Route Availability Classification
| Field | Fill-in Value |
|-------|--------------|
| route_source | {Obtain route list from route_map (if available) or framework route commands} |
| test_method | {Send basic HTTP request to each route} |
| class_A | {HTTP 200/301/302 → Accessible} |
| class_B | {HTTP 500 with response body → Partial Error} |
| class_C | {Connection failure/timeout → Completely Inaccessible} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| environment_status.json | `$WORK_DIR/environment_status.json` | `schemas/environment_status.schema.json` | Startup mode (full/partial), framework info, startup rounds+fix records, web accessibility, route classification (A/B/C), Xdebug status, DB table stats, disabled features, encrypted file list, base_image |

## Examples

### ✅ GOOD: Successful Progressive Startup
```json
{
  "startup_mode": "full",
  "framework": {"type": "Laravel", "version": "10.48.0"},
  "base_image": "php:8.1-fpm-alpine",
  "resource_tier": "medium",
  "startup_rounds": 2,
  "fix_records": [
    {"round": 1, "error": "Permission denied on storage/", "fix": "chmod -R 777 storage bootstrap/cache"}
  ],
  "web_accessible": true,
  "web_status_code": 200,
  "route_classification": {"A": 45, "B": 3, "C": 2},
  "xdebug_enabled": true,
  "db_tables": 28,
  "disabled_features": ["redis_cache→file", "smtp_mail→log"],
  "encrypted_files": []
}
```
Explanation ✅ Progressive startup completed in 2 rounds. Permission fix applied in round 1. All 6 layers verified. Routes classified. Resource tier correctly set as medium.

### ❌ BAD: Skipped Layer Verification
```json
{
  "startup_mode": "full",
  "web_accessible": true,
  "startup_rounds": 0
}
```
What's wrong ❌ startup_rounds=0 implies no verification was performed (CR-1 violated). Missing: framework, base_image, resource_tier, fix_records, route_classification, xdebug_enabled, db_tables, disabled_features. No evidence layers were checked sequentially.

## Error Handling
| Error | Action |
|-------|--------|
| Docker daemon not running | Abort with error: "Docker daemon is not running" |
| Template file not found | Abort with error specifying which template is missing |
| Port conflict (OOB_PORT in use) | Auto-select next available port (9002, 9003, ...) |
| `docker compose build` fails | Capture build log, identify failing step, apply self-healing |
| Database healthcheck timeout (>2 min) | Log timeout, attempt restart, if still fails → mark DB as unavailable |
| All self-healing rounds exhausted | Pause and invoke AskUserQuestion for user guidance |
| `reconstructed_schema.sql` not found | Skip DB import, log warning, proceed with empty database |
| Image pull failure (network issue) | Retry up to 3 times with 10s backoff; abort if still fails |
