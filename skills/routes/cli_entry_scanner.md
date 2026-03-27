# CLI Entry Scanner

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-030b |
| Phase | Phase-2 |
| Parent | S-030 (route_mapper) |
| Responsibility | Scan CLI command entry points and generate synthetic ENTRY_CLI routes |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Target source code | `$TARGET_PATH/` | ✅ | CLI command files |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework` (to determine scan locations) |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Each CLI entry MUST have source file path + line number | Entry deleted from output |
| CR-4 | Input sources MUST come from actual `$this->argument()` / `getopt()` code analysis, NOT guessed | Taint analysis produces false results |

## Fill-in Procedure

### Procedure A: Identify CLI Command Locations by Framework

| Field | Fill-in Value |
|-------|--------------|
| framework | {read from `environment_status.json`} |
| scan_directories | {select from table below based on framework} |

**Framework scan directory reference:**

| Framework | Scan Directory | Key Patterns |
|-----------|---------------|--------------|
| Laravel | `app/Console/Commands/*.php` | `$signature` property, `handle()` method |
| Symfony | `src/Command/*.php` | `configure()` with `addArgument()`/`addOption()`, `execute()` method |
| ThinkPHP | `app/command/*.php` | Command class definitions |
| CodeIgniter | `app/Commands/*.php` | `run()` method |
| CakePHP | `src/Command/*.php` | `execute()` method |
| Native PHP | Project root, `bin/`, `cli/`, `scripts/` | `$argv`, `$_SERVER['argv']`, `getopt()` |

### Procedure B: Parse CLI Commands per Framework

#### B.1 — Laravel Artisan Commands

For each file in `app/Console/Commands/`:

| Field | Fill-in Value |
|-------|--------------|
| command_name | {extract from `$signature` property, e.g. `'import:users {file} {--format=csv}'`} |
| description | {extract from `$description` property} |
| method | {`handle()`} |
| input_sources | {parse `handle()` method for: `$this->argument('key')` → `cli_arg`, `$this->option('key')` → `cli_opt`, `$this->ask()` → `cli_interactive`} |
| registered | {check if command listed in `app/Console/Kernel.php` → `$commands` array} |

#### B.2 — Symfony Console Commands

For each file in `src/Command/`:

| Field | Fill-in Value |
|-------|--------------|
| command_name | {extract from `configure()` → `$this->setName('app:import-users')`} |
| method | {`execute()`} |
| input_sources | {parse `execute()` for: `$input->getArgument('key')` → `cli_arg`, `$input->getOption('key')` → `cli_opt`} |

#### B.3 — Native PHP CLI Scripts

| Field | Fill-in Value |
|-------|--------------|
| scan_command | {`grep -rln '\$argv\|\$_SERVER\[.argv.\]\|getopt(' --include="*.php" $TARGET_PATH/`} |
| is_cli_script | {check for shebang `#!/usr/bin/env php` or no HTML output} |
| input_sources | {extract `getopt()` parameters and `$argv` index access patterns} |

### Procedure C: Assess Auth Level

| Field | Fill-in Value |
|-------|--------------|
| default_auth | {`system` — assumes server/shell access required} |
| downgrade_check | {if command triggerable via web interface (admin panel, web cron manager) → downgrade to `authenticated` or `authorized`} |
| web_references | {check for references to the command in web controllers or scheduled tasks} |

### Procedure D: Generate Synthetic Route Entries

For each CLI entry point, fill in:

| Field | Fill-in Value |
|-------|--------------|
| id | {`route_synth_{NNN}` — sequential synthetic ID} |
| entry_type | {`CLI`} |
| synthetic_id | {`ENTRY_CLI:{command_name}`} |
| file | {source file path of the command class} |
| line | {line number of `handle()` / `execute()` / `run()` method} |
| method | {entry method name: `handle`, `execute`, `run`} |
| input_sources | {array of `{"source": "cli_arg|cli_opt|cli_interactive", "key": "{param_name}"}`} |
| auth_level | {`system` / `authenticated` / `authorized` from Procedure C} |
| middleware | {`[]` — CLI commands have no HTTP middleware} |
| note | {`CLI command — no HTTP middleware protection; input from command-line arguments`} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| cli_entries.json | `$WORK_DIR/原始数据/cli_entries.json` | See schema below | Array of synthetic ENTRY_CLI route entries |

### Output Schema (per entry)

```json
{
  "id": "route_synth_{NNN}",
  "entry_type": "CLI",
  "synthetic_id": "ENTRY_CLI:{command_name}",
  "file": "app/Console/Commands/ImportUsers.php",
  "line": 28,
  "method": "handle",
  "input_sources": [
    { "source": "cli_arg", "key": "file" },
    { "source": "cli_opt", "key": "format" }
  ],
  "auth_level": "system",
  "middleware": [],
  "note": "CLI command — no HTTP middleware protection; input from command-line arguments"
}
```

## Examples

### ✅ GOOD: Laravel Artisan Command Entry
```json
{
  "id": "route_synth_001",
  "entry_type": "CLI",
  "synthetic_id": "ENTRY_CLI:import:users",
  "file": "app/Console/Commands/ImportUsers.php",
  "line": 28,
  "method": "handle",
  "input_sources": [
    { "source": "cli_arg", "key": "file" },
    { "source": "cli_opt", "key": "format" }
  ],
  "auth_level": "system",
  "middleware": [],
  "note": "CLI command — no HTTP middleware protection; input from command-line arguments"
}
```
File + line provenance present (CR-1). Input sources extracted from actual `$this->argument()` / `$this->option()` code (CR-4). ✅

### ❌ BAD: Guessed Input Sources
```json
{
  "id": "route_synth_001",
  "entry_type": "CLI",
  "synthetic_id": "ENTRY_CLI:import:users",
  "file": "app/Console/Commands/ImportUsers.php",
  "line": 28,
  "method": "handle",
  "input_sources": [
    { "source": "cli_arg", "key": "filename" },
    { "source": "cli_arg", "key": "output_dir" }
  ],
  "auth_level": "system",
  "middleware": [],
  "note": "CLI command"
}
```
Input sources guessed from command name rather than parsed from `handle()` body — violates **CR-4**. Actual code uses `$this->argument('file')` not `'filename'`, and `output_dir` does not exist in the source. ❌

## Error Handling
| Error | Action |
|-------|--------|
| No CLI command directory found | Output empty `cli_entries.json` with `"entries": []` |
| Command file not parseable | Log warning, skip file, continue with others |
| Kernel.php not found (Laravel) | Scan `Commands/` directory directly without registration check |
| No CLI entry points in entire project | Valid result — output empty array |
