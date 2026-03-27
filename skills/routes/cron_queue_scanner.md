> **Skill ID**: S-030f | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: Kernel.php + Jobs directory + hooks/deploy scripts + CI config
> **Output**: `background_entries.json` — synthetic `ENTRY_CRON:` / `ENTRY_QUEUE:` / `ENTRY_HOOK:` routes

# CRON / Queue / Hook Entry Scanner

## Purpose

Discover non-HTTP, non-CLI entry points: scheduled tasks (CRON), queue workers (Jobs), and deployment/git hooks. These entry points execute outside the HTTP request lifecycle, often with elevated privileges and without middleware protection. Deserialized queue payloads are a common source of object injection vulnerabilities.

## Procedure

### Part 1: CRON / Scheduled Task Entry Points (ENTRY_CRON:)

#### 1a. Laravel Schedule

1. Parse `app/Console/Kernel.php` — locate the `schedule()` method.
2. Extract all scheduled task registrations:
   ```php
   $schedule->command('report:export')->daily();
   $schedule->call(function () { ... })->hourly();
   $schedule->job(new ProcessPending)->everyFiveMinutes();
   $schedule->exec('node /home/forge/script.js')->daily();
   ```
3. For each scheduled task, record:
   - Task type: `command` / `call` / `job` / `exec`
   - Target: command name, closure location, job class, or external script
   - Schedule frequency
   - File and line number

#### 1b. Symfony Scheduler

1. Parse `config/packages/scheduler.yaml` for scheduled task definitions.
2. Scan for `#[AsCronTask('*/5 * * * *')]` attributes on service classes.
3. Check `config/services.yaml` for tagged scheduler services.

#### 1c. Crontab / External Schedulers

1. Search for crontab-related files:
   ```bash
   find $TARGET_PATH -name 'crontab*' -o -name '*.cron' -o -name 'schedule*' 2>/dev/null
   ls $TARGET_PATH/cron/ $TARGET_PATH/scheduler/ 2>/dev/null
   ```
2. Parse crontab entries that invoke PHP scripts.
3. Check `docker-compose.yml` for cron container definitions.

#### CRON Synthetic ID Format

`ENTRY_CRON:{task_name}`, e.g., `ENTRY_CRON:daily_report_export`

---

### Part 2: Queue Worker Entry Points (ENTRY_QUEUE:)

#### 2a. Laravel Queue Jobs

1. Scan `app/Jobs/*.php` for job classes.
2. For each job class:
   - Parse the `handle()` method for input sources.
   - Identify constructor parameters (these come from the serialized job payload).
   - **Pay special attention to deserialization of job payloads from external data sources** (database, Redis, SQS) — these are potential object injection vectors.
   - Check for `SerializesModels` trait usage.
3. Check `app/Listeners/*.php` for event listeners that process queue payloads.

#### 2b. Symfony Messenger

1. Scan `src/MessageHandler/*.php` for message handler classes.
2. Identify the `__invoke()` method and its message type parameter.
3. Check `config/packages/messenger.yaml` for transport configuration.

#### 2c. ThinkPHP Queue

1. Scan for classes implementing `think\queue\Job`.
2. Parse the `fire()` or `handle()` method.

#### 2d. Generic Queue Patterns

Search for common queue consumption patterns:
```bash
grep -rln 'implements ShouldQueue\|extends Job\|@queue\|Queue::push' --include="*.php" $TARGET_PATH/
```

#### Queue Synthetic ID Format

`ENTRY_QUEUE:{job_class}`, e.g., `ENTRY_QUEUE:ProcessUploadedFile`

---

### Part 3: Git Hook / Deployment Hook Entry Points (ENTRY_HOOK:)

#### 3a. Git Hooks

1. Scan PHP scripts in hook directories:
   ```bash
   find $TARGET_PATH/.git/hooks/ $TARGET_PATH/.githooks/ -name '*.php' 2>/dev/null
   ```
2. Check for PHP invocations in shell-based hooks:
   ```bash
   grep -l 'php ' $TARGET_PATH/.git/hooks/* $TARGET_PATH/.githooks/* 2>/dev/null
   ```

#### 3b. Deployment Scripts

1. Scan deployment directories for PHP scripts:
   ```bash
   find $TARGET_PATH/deploy/ $TARGET_PATH/scripts/ $TARGET_PATH/bin/ -name '*.php' 2>/dev/null
   ```
2. Check for deployment tools: `deployer.php`, `envoy.blade.php` (Laravel Envoy).

#### 3c. CI/CD Pipeline PHP Invocations

1. Parse CI/CD configuration files for PHP script execution:
   - `.github/workflows/*.yml` — look for `php` commands in `run:` steps
   - `.gitlab-ci.yml` — look for `php` in `script:` blocks
   - `Jenkinsfile` — look for `sh 'php ...'` calls
   - `bitbucket-pipelines.yml` — look for PHP commands
2. Record the PHP scripts being invoked and their arguments.

#### Hook Synthetic ID Format

`ENTRY_HOOK:{hook_name}`, e.g., `ENTRY_HOOK:post_deploy_migrate`

---

### Part 4: Assess Auth Levels

For all discovered entries:
- Default `auth_level: "system"` (assumes server access required).
- If triggered via web panel (e.g., queue dashboard, cron manager UI), downgrade appropriately.
- Queue jobs with payloads from user-submitted data → `auth_level: "authenticated"`.

### Part 5: Generate Synthetic Route Entries

Output format for each entry:

```json
{
  "id": "route_synth_{NNN}",
  "entry_type": "CRON|QUEUE|HOOK",
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

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Target source code | `$TARGET_PATH/` | ✅ | Kernel.php, Jobs/, hooks, deploy scripts |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework` |
| CI/CD config | `$TARGET_PATH/.github/`, `$TARGET_PATH/.gitlab-ci.yml` | ⚠️ Optional | Pipeline definitions |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| background_entries.json | `$WORK_DIR/background_entries.json` | Array of ENTRY_CRON, ENTRY_QUEUE, ENTRY_HOOK synthetic routes |

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-1 | Each entry MUST have source file path + line number. |
| CR-4 | Input sources for queue jobs MUST come from actual code analysis of `handle()` / constructor. |

## Error Handling

| Error | Action |
|-------|--------|
| No Kernel.php found | Skip CRON scanning for Laravel; try alternative scheduler locations |
| No Jobs directory found | Skip queue scanning, output empty queue entries |
| No hooks directory found | Skip hook scanning, output empty hook entries |
| No background entry points found in entire project | Valid result — output empty array |
| CI/CD config not found | Skip CI/CD scanning, continue with other sources |
