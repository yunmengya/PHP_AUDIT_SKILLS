# CRON / Queue / Hook Entry Scanner

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030c |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Discover non-HTTP entry points: scheduled tasks (CRON), queue workers (Jobs), and deployment/git hooks |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Target source code | `$TARGET_PATH/` | ✅ | Kernel.php, Jobs/, hooks, deploy scripts |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework` |
| CI/CD config | `$TARGET_PATH/.github/`, `$TARGET_PATH/.gitlab-ci.yml` | ⚠️ Optional | Pipeline definitions |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Each entry MUST have source file path + line number | Entry deleted from output |
| CR-4 | Input sources for queue jobs MUST come from actual code analysis of `handle()` / constructor | False taint analysis downstream |

## Fill-in Procedure

### Procedure A: Scan CRON / Scheduled Task Entry Points (ENTRY_CRON:)

#### A.1 — Laravel Schedule

| Field | Fill-in Value |
|-------|--------------|
| schedule_file | {`app/Console/Kernel.php` → locate `schedule()` method} |
| task_type | {`command` / `call` / `job` / `exec`} |
| target | {command name, closure location, job class, or external script path} |
| frequency | {`daily`, `hourly`, `everyFiveMinutes`, `weekly`, `monthly`, `everyMinute`, `twiceDaily`} |
| file | {source file path} |
| line | {line number of schedule registration} |

**Laravel schedule registration patterns:**
- `$schedule->command('report:export')->daily()`
- `$schedule->call(function () { ... })->hourly()`
- `$schedule->job(new ProcessPending)->everyFiveMinutes()`
- `$schedule->exec('node /home/forge/script.js')->daily()`

#### A.2 — Symfony Scheduler

| Field | Fill-in Value |
|-------|--------------|
| scheduler_config | {parse `config/packages/scheduler.yaml`} |
| cron_attributes | {scan for `#[AsCronTask('*/5 * * * *')]` attributes on service classes} |
| tagged_services | {check `config/services.yaml` for tagged scheduler services} |

#### A.3 — Crontab / External Schedulers

| Field | Fill-in Value |
|-------|--------------|
| crontab_files | {`find $TARGET_PATH -name 'crontab*' -o -name '*.cron' -o -name 'schedule*'`} |
| cron_dirs | {check `$TARGET_PATH/cron/`, `$TARGET_PATH/scheduler/`} |
| docker_cron | {check `docker-compose.yml` for cron container definitions} |

**Synthetic ID format:** `ENTRY_CRON:{task_name}`, e.g. `ENTRY_CRON:daily_report_export`

### Procedure B: Scan Queue Worker Entry Points (ENTRY_QUEUE:)

#### B.1 — Laravel Queue Jobs

| Field | Fill-in Value |
|-------|--------------|
| job_directory | {scan `app/Jobs/*.php`} |
| handle_method | {parse `handle()` method for input sources} |
| constructor_params | {identify constructor parameters — these come from serialized job payload} |
| deserialization_risk | {flag deserialization of payloads from external sources (DB, Redis, SQS) — potential object injection} |
| serializes_models | {check for `SerializesModels` trait usage} |
| event_listeners | {check `app/Listeners/*.php` for queue payload processing} |

#### B.2 — Symfony Messenger

| Field | Fill-in Value |
|-------|--------------|
| handlers | {scan `src/MessageHandler/*.php`} |
| invoke_method | {identify `__invoke()` method and its message type parameter} |
| transport_config | {check `config/packages/messenger.yaml`} |

#### B.3 — ThinkPHP Queue

| Field | Fill-in Value |
|-------|--------------|
| job_classes | {scan for classes implementing `think\queue\Job`} |
| entry_method | {parse `fire()` or `handle()` method} |

#### B.4 — Generic Queue Patterns

| Field | Fill-in Value |
|-------|--------------|
| scan_command | {`grep -rln 'implements ShouldQueue\|extends Job\|@queue\|Queue::push' --include="*.php" $TARGET_PATH/`} |

**Synthetic ID format:** `ENTRY_QUEUE:{job_class}`, e.g. `ENTRY_QUEUE:ProcessUploadedFile`

### Procedure C: Scan Git Hook / Deployment Hook Entry Points (ENTRY_HOOK:)

#### C.1 — Git Hooks

| Field | Fill-in Value |
|-------|--------------|
| php_hooks | {`find $TARGET_PATH/.git/hooks/ $TARGET_PATH/.githooks/ -name '*.php'`} |
| shell_hooks_with_php | {`grep -l 'php ' $TARGET_PATH/.git/hooks/* $TARGET_PATH/.githooks/*`} |

#### C.2 — Deployment Scripts

| Field | Fill-in Value |
|-------|--------------|
| deploy_php | {`find $TARGET_PATH/deploy/ $TARGET_PATH/scripts/ $TARGET_PATH/bin/ -name '*.php'`} |
| deploy_tools | {check for `deployer.php`, `envoy.blade.php` (Laravel Envoy)} |

#### C.3 — CI/CD Pipeline PHP Invocations

| Field | Fill-in Value |
|-------|--------------|
| github_actions | {`.github/workflows/*.yml` — look for `php` commands in `run:` steps} |
| gitlab_ci | {`.gitlab-ci.yml` — look for `php` in `script:` blocks} |
| jenkinsfile | {`Jenkinsfile` — look for `sh 'php ...'` calls} |
| bitbucket | {`bitbucket-pipelines.yml` — look for PHP commands} |

**Synthetic ID format:** `ENTRY_HOOK:{hook_name}`, e.g. `ENTRY_HOOK:post_deploy_migrate`

### Procedure D: Assess Auth Levels

| Field | Fill-in Value |
|-------|--------------|
| default_auth | {`system` — assumes server access required} |
| web_trigger_check | {if triggered via web panel (queue dashboard, cron manager UI) → downgrade accordingly} |
| user_data_queue | {queue jobs with payloads from user-submitted data → `authenticated`} |

### Procedure E: Generate Synthetic Route Entries

For each discovered entry, fill in:

| Field | Fill-in Value |
|-------|--------------|
| id | {`route_synth_{NNN}`} |
| entry_type | {`CRON` / `QUEUE` / `HOOK`} |
| synthetic_id | {`ENTRY_CRON:{name}` / `ENTRY_QUEUE:{class}` / `ENTRY_HOOK:{hook}`} |
| file | {source file path} |
| line | {line number} |
| method | {entry method: `schedule`, `handle`, `fire`, `execute`} |
| input_sources | {array of input source objects from code analysis (CR-4)} |
| auth_level | {from Procedure D} |
| middleware | {`[]`} |
| schedule | {frequency string, only for CRON entries} |
| note | {description of entry type and lifecycle context} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| background_entries.json | `$WORK_DIR/原始数据/background_entries.json` | See schema below | Array of ENTRY_CRON, ENTRY_QUEUE, ENTRY_HOOK synthetic routes |

### Output Schema (per entry)

```json
{
  "id": "route_synth_{NNN}",
  "entry_type": "CRON",
  "synthetic_id": "ENTRY_CRON:daily_report_export",
  "file": "app/Console/Kernel.php",
  "line": 34,
  "method": "schedule",
  "input_sources": [],
  "auth_level": "system",
  "middleware": [],
  "schedule": "daily",
  "note": "Scheduled task — runs outside HTTP lifecycle"
}
```

## Examples

### ✅ GOOD: Laravel Queue Job Entry
```json
{
  "id": "route_synth_005",
  "entry_type": "QUEUE",
  "synthetic_id": "ENTRY_QUEUE:ProcessUploadedFile",
  "file": "app/Jobs/ProcessUploadedFile.php",
  "line": 18,
  "method": "handle",
  "input_sources": [
    { "source": "constructor_param", "key": "filePath" },
    { "source": "constructor_param", "key": "userId" }
  ],
  "auth_level": "system",
  "middleware": [],
  "note": "Queue job — deserialized payload from Redis; constructor params are user-controlled data"
}
```
File + line present (CR-1). Input sources extracted from actual constructor and `handle()` analysis (CR-4). Deserialization risk noted. ✅

### ❌ BAD: Missing Line Number and Empty Sources
```json
{
  "id": "route_synth_005",
  "entry_type": "QUEUE",
  "synthetic_id": "ENTRY_QUEUE:ProcessUploadedFile",
  "file": "app/Jobs/ProcessUploadedFile.php",
  "method": "handle",
  "input_sources": [],
  "auth_level": "system",
  "middleware": []
}
```
Missing `line` field — violates **CR-1**. `input_sources` is empty despite the job having constructor params that receive deserialized data — violates **CR-4** (must analyze actual code). ❌

## Error Handling
| Error | Action |
|-------|--------|
| No Kernel.php found | Skip CRON scanning for Laravel; try alternative scheduler locations |
| No Jobs directory found | Skip queue scanning, output empty queue entries |
| No hooks directory found | Skip hook scanning, output empty hook entries |
| No background entry points found in entire project | Valid result — output empty array |
| CI/CD config not found | Skip CI/CD scanning, continue with other sources |
