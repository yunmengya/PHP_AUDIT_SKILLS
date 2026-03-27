> **Skill ID**: S-030e | **Phase**: 2 | **Parent**: S-030 (route_mapper)
> **Input**: CLI command directories in the target project
> **Output**: `cli_entries.json` — synthetic `ENTRY_CLI:` routes

# CLI Entry Scanner

## Purpose

Scan the target project for CLI command entry points (artisan commands, console commands, native PHP CLI scripts). CLI commands bypass HTTP middleware protections and may accept external input that triggers vulnerabilities. Each discovered CLI entry point is assigned a synthetic route ID (`ENTRY_CLI:{command_name}`) for inclusion in the unified route map.

## Procedure

### Step 1: Identify CLI Command Locations by Framework

| Framework | Scan Directory | Key Patterns |
|-----------|---------------|--------------|
| Laravel | `app/Console/Commands/*.php` | `$signature` property, `handle()` method |
| Symfony | `src/Command/*.php` | `configure()` with `addArgument()`/`addOption()`, `execute()` method |
| ThinkPHP | `app/command/*.php` | Command class definitions |
| CodeIgniter | `app/Commands/*.php` | `run()` method |
| CakePHP | `src/Command/*.php` | `execute()` method |
| Native PHP | Project root and `bin/`, `cli/`, `scripts/` | `$argv`, `$_SERVER['argv']`, `getopt()` |

### Step 2: Parse Laravel Artisan Commands

For each file in `app/Console/Commands/`:

1. Extract the `$signature` property to determine command name and parameters:
   ```php
   protected $signature = 'import:users {file} {--format=csv}';
   ```
2. Parse the `handle()` method for input sources:
   - `$this->argument('file')` → `cli_arg`
   - `$this->option('format')` → `cli_opt`
   - `$this->ask()` / `$this->anticipate()` → `cli_interactive`
3. Check `$description` property for command purpose.
4. Check if the command is registered in `app/Console/Kernel.php` → `$commands` array.

### Step 3: Parse Symfony Console Commands

For each file in `src/Command/`:

1. Extract command name from `configure()`:
   ```php
   $this->setName('app:import-users')
        ->addArgument('file', InputArgument::REQUIRED)
        ->addOption('format', null, InputOption::VALUE_OPTIONAL, '', 'csv');
   ```
2. Parse the `execute()` method for input usage:
   - `$input->getArgument('file')` → `cli_arg`
   - `$input->getOption('format')` → `cli_opt`

### Step 4: Parse Native PHP CLI Scripts

Scan for PHP files that use CLI-specific globals:

```bash
grep -rln '\$argv\|\$_SERVER\[.argv.\]\|getopt(' --include="*.php" $TARGET_PATH/
```

For each file found:
1. Determine if it is intended as a CLI script (shebang line `#!/usr/bin/env php`, or no HTML output).
2. Extract `getopt()` parameters.
3. Extract `$argv` index access patterns.

### Step 5: Assess Auth Level

- Default `auth_level: "system"` (assumes server/shell access required).
- If the command can be triggered via web interface (e.g., admin panel "run command" feature, or scheduled via web-based cron manager), downgrade to `"authenticated"` or `"authorized"`.
- Check for references to the command in web controllers or scheduled tasks.

### Step 6: Generate Synthetic Route Entries

For each CLI entry point, generate a synthetic route entry:

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

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Target source code | `$TARGET_PATH/` | ✅ | CLI command files |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | `framework` (to determine scan locations) |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| cli_entries.json | `$WORK_DIR/cli_entries.json` | Array of synthetic ENTRY_CLI: route entries |

## Validation Rules

| Rule | Description |
|------|-------------|
| CR-1 | Each CLI entry MUST have source file path + line number. |
| CR-4 | Input sources MUST come from actual `$this->argument()` / `getopt()` code analysis. |

## Error Handling

| Error | Action |
|-------|--------|
| No CLI command directory found | Output empty `cli_entries.json` with `"entries": []` |
| Command file not parseable | Log warning, skip file, continue with others |
| Kernel.php not found (Laravel) | Scan `Commands/` directory directly without registration check |
| No CLI entry points in entire project | Valid result — output empty array |
