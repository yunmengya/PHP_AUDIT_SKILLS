# Env-Detective (Environment Detective)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-010 |
| Phase | Phase-1 |
| Responsibility | Collect PHP project environment information (framework, version, config, dependencies) |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| TARGET_PATH | Orchestrator parameter | ✅ | Target source code path |
| WORK_DIR | Orchestrator parameter | ✅ | Working directory path |
| shared/known_cves.md | Shared resource (L2) | ✅ | CVE database for version security pre-assessment |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST scan all key files/dirs before framework fingerprinting | Missed assets → incorrect framework detection |
| CR-2 | PHP version MUST be determined by intersecting ALL constraints (composer.json + syntax features + framework version) | Wrong PHP version → Docker build failure |
| CR-3 | If `.env` missing but `.env.example` exists, MUST generate `.env` from `.env.example` | Missing runtime config → application crash |
| CR-4 | Encrypted/obfuscated files MUST be marked as "unanalyzable" | Analyzing encrypted code → hallucinated results |
| CR-5 | Version alerts MUST cross-reference `shared/known_cves.md` | Missing known CVEs → incomplete security assessment |
| CR-6 | Take intersection of all PHP version constraints, select lowest satisfying version | Over-specified version → compatibility issues |

## Fill-in Procedure

### Procedure A: Asset Inventory
| Field | Fill-in Value |
|-------|--------------|
| scan_root | {TARGET_PATH root directory} |
| file_checklist | {Check existence of each: `composer.json` (dependency mgmt), `composer.lock` (version locking), `.env` (runtime config), `.env.example` (config template), `config/` (framework config dir), `database/migrations/` (DB migrations), `*.sql` (SQL dumps in root or database/), `docker-compose.yml` (existing Docker config), `nginx.conf` or similar (web server config), `vendor/` (installed deps)} |
| output_per_file | {filename + status (present/missing) + impact description} |
| env_fallback | {If `.env` missing but `.env.example` exists → copy `.env.example` to `.env`} |

### Procedure B: Framework Fingerprinting
| Field | Fill-in Value |
|-------|--------------|
| composer_require | {Parse `require` field from `composer.json`} |
| framework_match | {`laravel/framework`→Laravel, `topthink/framework`→ThinkPHP, `yiisoft/yii2`→Yii2, `symfony/symfony`→Symfony, `cakephp/cakephp`→CakePHP, `codeigniter4/framework`→CodeIgniter, no framework dep→Native} |
| extended_match | {`slim/slim`→Slim, `illuminate/routing` (without laravel/framework)→Lumen} |
| cms_fingerprint | {WordPress: `wp-config.php` + `wp-includes/` + `wp-content/`; Drupal: `core/lib/Drupal.php` + `sites/default/settings.php`; Joomla: `libraries/joomla/` + `configuration.php`} |
| cms_version_parse | {WP: parse `$wp_version` from `wp-includes/version.php`; WP plugins: `wp-content/plugins/*/`; WP themes: `wp-content/themes/*/style.css`; Drupal modules: `modules/*/` + `sites/all/modules/`} |
| microservice_match | {`hyperf/hyperf`→Hyperf, `swoft/swoft`→Swoft, `api-platform/core`→API Platform, `dingo/api`→Dingo API} |
| entry_files | {Detect: `public/index.php`, `index.php`, `web/app.php`, etc.} |
| output | {framework type + version number} |

### Procedure C: PHP Version Inference
| Field | Fill-in Value |
|-------|--------------|
| constraint_1_composer | {Parse `"php"` constraint in `composer.json` (e.g., `">=7.4"`)} |
| constraint_2_syntax | {Sample first 50 .php files: `match`/`enum`/`Fiber`→8.1+, named args/union types/`?->`→8.0+, typed props/`fn()`→7.4+, none→7.2 fallback} |
| constraint_3_framework | {Laravel 10.x→8.1+, Laravel 9.x→8.0+, Laravel 8.x→7.3+, ThinkPHP 6.x→7.2+, Yii2 2.0.43+→7.4+, Symfony 6.x→8.1+, Symfony 5.x→7.2.5+, CakePHP 5.x→8.1+, CakePHP 4.x→7.4+, CodeIgniter 4.x→7.4+, WordPress 6.x→7.0+ (recommended 8.0+), Drupal 10.x→8.1+, Drupal 9.x→7.3+} |
| final_version | {Intersect all constraints → select lowest version satisfying all} |

### Procedure D: Database Type Inference
| Field | Fill-in Value |
|-------|--------------|
| priority_1 | {`'default'` value in `config/database.php`} |
| priority_2 | {`DB_CONNECTION` in `.env` or `.env.example`} |
| priority_3 | {`ext-pdo_mysql` / `ext-pdo_pgsql` in `composer.json`} |
| priority_4_dialect | {SQL dialect features: `LIMIT ?,?`→MySQL, `OFFSET...FETCH`→PostgreSQL, `AUTOINCREMENT`→SQLite} |
| cms_db | {WordPress: `DB_HOST`/`DB_NAME` in `wp-config.php`; Drupal: `$databases` in `sites/default/settings.php`} |
| nosql_check | {Search for `MongoDB\Client`, `Predis\Client`} |
| default | {MySQL 8.0 if no evidence found} |

### Procedure E: Dependency Service Identification
| Field | Fill-in Value |
|-------|--------------|
| config_scan | {`CACHE_DRIVER=redis`→Redis cache (fallback→file), `QUEUE_CONNECTION=redis`→Redis queue (fallback→sync), `MAIL_MAILER=smtp`→Mail service (fallback→log), `FILESYSTEM_DISK=s3`→S3 storage (fallback→local), OAuth/SMS calls→mark as untestable} |
| extension_scan | {Scan `ext-*` in `composer.json` + source code function calls: `gd_info()`/`imagecreate()`→ext-gd, `curl_init()`→ext-curl, `openssl_encrypt()`→ext-openssl, `mb_strlen()`→ext-mbstring, `sodium_*`→ext-sodium} |

### Procedure F: Encrypted/Obfuscated Code Detection
| Field | Fill-in Value |
|-------|--------------|
| header_signatures | {ionCube: starts with `<?php //0` + garbled content; Zend Guard: `<?php @Zend;`; SourceGuardian: `<?php $sg`} |
| obfuscation_patterns | {`eval(base64_decode(...))`, `eval(gzinflate(...))`, `eval(str_rot13(...))`} |
| handling_encrypted | {Encrypted files → mark "unanalyzable", record in encrypted_files list} |
| handling_obfuscated | {eval obfuscation → mark, attempt deobfuscation after Docker starts} |

### Procedure G: Version Security Pre-Assessment
| Field | Fill-in Value |
|-------|--------------|
| version_triple | {Extract `(framework, framework_version, php_version)` from Procedures B+C} |
| cross_reference | {Match against `shared/known_cves.md` by framework type and version range (precise to minor version)} |
| alert_entry_fields | {`component`, `detected_version`, `cve_id`, `severity`, `description`, `affected_auditors`} |
| severity_classification | {CVSS: critical (≥9.0), high (7.0-8.9), medium (4.0-6.9), low (<4.0)} |
| priority_marking | {critical/high CVE → annotate `⚠️ Version warning: known high-severity vulnerability`; map affected_auditors (e.g., ThinkPHP 5.x RCE → `["rce_auditor"]`)} |

#### Version-CVE Mapping Reference

| Component | Version Range | Typical CVE | Affected Auditor |
|-----------|---------------|-------------|------------------|
| ThinkPHP | 5.0.x - 5.0.23 | CVE-2018-20062 | rce_auditor |
| ThinkPHP | 5.1.x - 5.1.31 | CVE-2019-9082 | rce_auditor |
| Laravel | < 8.x | Mass Assignment | authz_auditor |
| WordPress | < 6.0 | Multiple Core CVEs | wordpress_auditor |
| PHP | < 5.3.4 | Null Byte LFI | lfi_auditor |
| PHP | < 8.0 | Type Juggling | authz_auditor, crypto_auditor |

> Complete mapping is defined in `shared/known_cves.md`; this table is a reference example only.

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| environment_status.json | `$WORK_DIR/environment_status.json` | `schemas/environment_status.schema.json` | Asset inventory, framework type+version, recommended PHP version, DB type+version, PHP extension list, fallback strategy table, encrypted/obfuscated file list, version_alerts array |

## Examples

### ✅ GOOD: Laravel 10 Project Detection
```json
{
  "asset_inventory": [
    {"file": "composer.json", "status": "present", "impact": "Dependency management available"},
    {"file": "composer.lock", "status": "present", "impact": "Exact version locking available"},
    {"file": ".env", "status": "missing", "impact": "Generated from .env.example"},
    {"file": ".env.example", "status": "present", "impact": "Configuration template available"},
    {"file": "vendor/", "status": "present", "impact": "Dependencies pre-installed"}
  ],
  "framework": {"type": "Laravel", "version": "10.48.0"},
  "php_version": "8.1",
  "database": {"type": "mysql", "version": "8.0"},
  "extensions": ["ext-gd", "ext-curl", "ext-mbstring", "ext-openssl"],
  "fallback_strategies": [
    {"service": "CACHE_DRIVER", "original": "redis", "fallback": "file"},
    {"service": "QUEUE_CONNECTION", "original": "redis", "fallback": "sync"}
  ],
  "encrypted_files": [],
  "version_alerts": [
    {
      "component": "Laravel",
      "detected_version": "10.48.0",
      "cve_id": "N/A",
      "severity": "info",
      "description": "No known CVEs for this version",
      "affected_auditors": []
    }
  ]
}
```
Explanation ✅ All 7 procedures executed correctly. PHP version 8.1 inferred from intersection of composer.json (`>=8.1`) + Laravel 10.x requirement (8.1+). Missing `.env` generated from `.env.example`. Redis services correctly fell back to file/sync.

### ❌ BAD: Missing Version Intersection
```json
{
  "framework": {"type": "Laravel", "version": "10.x"},
  "php_version": "7.2",
  "database": {"type": "mysql"}
}
```
What's wrong ❌ PHP 7.2 contradicts Laravel 10.x minimum (8.1+) — version intersection was not computed (CR-2 violated). Missing: asset_inventory, extensions, fallback_strategies, encrypted_files, version_alerts. Database version omitted.

## Error Handling
| Error | Action |
|-------|--------|
| `composer.json` not found | Set framework=Native, skip composer-based detection, rely on code scanning only |
| `composer.json` parse error (invalid JSON) | Log warning, fall back to code-based framework detection |
| No `.php` files found in TARGET_PATH | Abort with error: "Not a PHP project" |
| All PHP version constraints conflict | Use framework-implied minimum version, log conflict warning |
| `shared/known_cves.md` not found | Skip version_alerts, set to empty array, log warning |
| Permission denied on source files | Log inaccessible files, continue scanning accessible ones |
| Multiple frameworks detected in composer.json | Select primary framework (first match by priority), log secondary as note |
