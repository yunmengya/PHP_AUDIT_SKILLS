# Lessons Learned — Experience Repository

This file is the experience accumulation center for all audit projects. After each audit, the Report-Writer automatically extracts key lessons and writes them to this file.
Manual additions during retrospectives are also welcome. Entries are in reverse chronological order, with the latest experience at the top.

---

## Usage Guide

### File Purpose
- **Who writes**: Report-Writer Agent automatically appends after generating reports; auditors add manually
- **Who reads**: All Agents load this file before starting an audit, used to adjust strategy priorities
- **Growth model**: Append-only (never delete); each project MUST contribute at least 1-3 lessons
- **Feedback markers**: Success/failure rates are automatically tracked, marked as `[Proven Effective]` / `[Proven Ineffective]`

### How to Use This File
1. **Before audit**: Scanner / Exploiter reads this file, prioritizes payloads and bypass techniques marked `[Proven Effective]`
2. **During audit**: Record any unusual findings immediately under "Newly Discovered Patterns"
3. **After audit**: Report-Writer batch-extracts lessons from this audit and auto-categorizes them

### Entry Format Template

```markdown
### [Date] [Framework] [Vuln Type] — Brief Description
- **Project**: {project name}
- **Finding**: {one-sentence description of the finding}
- **Key Details**: {why it worked/why it failed}
- **Impact**: {suggested updates to shared files}
```

---

## Category 1: Effective Bypasses

> Bypass techniques, payload variants, and chained attacks confirmed to work in practice.

### [2026-01-15] [Laravel] [RCE] — Ignition filecontents + log poisoning chained RCE
- **Project**: example-shop-v2
- **Finding**: Laravel 8 + Ignition 2.5.1 combination allows RCE by writing phar to log via `_ignition/execute-solution`
- **Key Details**: Requires APP_DEBUG=true and Ignition < 2.5.2; payload first clears log then writes byte by byte to avoid base64 padding issues
- **Impact**: Recommend adding Ignition version detection to `framework_patterns.md` Laravel section; add log poisoning phar template to `payload_templates.md`
- **Marker**: `[Proven Effective]` — 3/3 projects succeeded

### [2026-01-10] [ThinkPHP] [SQLi] — ThinkPHP 5.x where array injection bypassing PDO prepared statements
- **Project**: cms-admin-panel
- **Finding**: `where(['id' => $_GET['id']])` when id is passed as array `id[0]=exp&id[1]=... ` can bypass parameter binding
- **Key Details**: ThinkPHP 5.0.0 ~ 5.0.23 affected; 5.1.x fixed exp but `LIKE` / `BETWEEN` variants still exist
- **Impact**: SQLi section of `payload_templates.md` needs ThinkPHP array injection specific payloads
- **Marker**: `[Proven Effective]` — 5/5 projects succeeded

### [2026-02-20] [WordPress] [Upload] — Content-Type + double extension bypass of wp_check_filetype
- **Project**: wp-blog-enterprise
- **Finding**: Uploading `shell.php.jpg` with `Content-Type: image/jpeg` is executable in Apache + mod_php environments
- **Key Details**: Depends on Apache `AddHandler` configuration; ineffective on Nginx; requires `AllowOverride` with `.htaccess`
- **Impact**: Add double extension bypass entry to `waf_bypass.md`; note environment dependency
- **Marker**: `[Proven Effective]` — conditional, Apache environments only

---

## Category 2: Failure Records

> Techniques attempted but failed; failure reasons recorded to avoid wasting rounds on repeat attempts.

### [2026-02-01] [Laravel] [SSTI] — Blade template injection attempt failed
- **Project**: api-gateway-v3
- **Finding**: Attempted to inject Blade syntax `@php system('id') @endphp` at `{!! $userInput !!}` location
- **Key Details**: Blade compilation occurs before server-side rendering; user input is inserted after compilation, so Blade directives are not parsed. Only possible when user input directly enters `eval()` or `Blade::compileString()`
- **Impact**: Add "Blade raw output ≠ SSTI" entry to `false_positive_patterns.md`
- **Marker**: `[Proven Ineffective]` — 0/4 projects succeeded, 8 rounds all failed

### [2026-02-10] [ThinkPHP] [Deserialization] — ThinkPHP 6 session deserialization requires Redis driver
- **Project**: erp-system
- **Finding**: ThinkPHP 6 session deserialization vulnerability only triggers when using file driver with controllable session filename
- **Key Details**: Target project uses Redis as session driver with `php_serialize` serialization format; cannot inject malicious objects. Spent 6 rounds trying different gadget chains, all failed
- **Impact**: ThinkPHP 6 session deserialization conditions in `framework_patterns.md` need driver prerequisite annotation
- **Marker**: `[Proven Ineffective]` — requires prerequisites: file driver + controllable session filename

### [2026-03-05] [General] [XXE] — PHP 8.0+ libxml disables external entities by default
- **Project**: data-import-service
- **Finding**: Attempted XXE payload injection on XML parsing interface, all failed
- **Key Details**: Since PHP 8.0, `libxml_disable_entity_loader()` is deprecated and `LIBXML_NOENT` is not set by default. External entities are not parsed unless code explicitly passes the `LIBXML_NOENT` flag
- **Impact**: Add PHP 8.0+ XXE condition notes to `php_specific_patterns.md`; Scanner SHOULD lower XXE priority on PHP 8.0+
- **Marker**: `[Proven Ineffective]` — largely ineffective on PHP 8.0+ environments

---

## Category 3: Newly Discovered Patterns

> New attack surfaces, undocumented behaviors, and atypical vulnerability patterns discovered during audits.

### [2026-03-01] [Laravel] [Mass Assignment] — Implicit $guarded=[] in pivot models
- **Project**: social-platform
- **Finding**: Laravel pivot models default to `$guarded = []`; even if the main model has `$fillable` set, passing extra fields via `attach()` / `sync()` can write to arbitrary columns of the pivot table
- **Key Details**: Documentation does not explicitly describe pivot model mass assignment behavior; all `belongsToMany` relationships with `withPivot()` declarations MUST be checked
- **Impact**: Add pivot model mass assignment checkpoint to `framework_patterns.md` Laravel section

### [2026-03-10] [General] [Race Condition] — TOCTOU file operations under PHP-FPM multi-process
- **Project**: file-sharing-app
- **Finding**: Race window exists between `file_exists()` check and `unlink()` deletion; concurrent requests can achieve arbitrary file retention
- **Key Details**: Only exploitable under PHP-FPM multi-worker mode; ineffective in CLI mode. Exploitation window is ~2-5ms, requires high concurrency
- **Impact**: Add TOCTOU race condition chain to `attack_chains.md`; add concurrency script template to `payload_templates.md`

---

## Automated Feedback Statistics

> Automatically maintained by Report-Writer, tracking success rates of various techniques.

| Technique | Attempts | Successes | Success Rate | Marker |
|-----------|----------|-----------|-------------|--------|
| ThinkPHP where array injection | 5 | 5 | 100% | [Proven Effective] |
| Ignition log poisoning RCE | 3 | 3 | 100% | [Proven Effective] |
| Apache double extension upload | 4 | 2 | 50% | — |
| Blade raw output SSTI | 4 | 0 | 0% | [Proven Ineffective] |
| PHP 8.0+ XXE | 3 | 0 | 0% | [Proven Ineffective] |
| TP6 session deserialization | 2 | 0 | 0% | [Proven Ineffective] |
