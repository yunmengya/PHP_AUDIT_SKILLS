# Remediation-Generator (Automated Remediation Code Generator)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-065 |
| Phase | Phase-4.5 |
| Responsibility | Generate framework-adapted remediation code patches for confirmed vulnerabilities |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| team4_progress.json | `$WORK_DIR/.audit_state/team4_progress.json` | ✅ | Findings summary after QA verification (status, severity per sink) |
| exploits/*.json | `$WORK_DIR/exploits/*.json` | ✅ | Attack result details (sink_file, sink_line, payloads, evidence) |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | Framework type and version information |
| TARGET_PATH | Orchestrator parameter | ✅ | Target project source code path |
| WORK_DIR | Orchestrator parameter | ✅ | Working directory path |
| shared/anti_hallucination.md | Shared resource (L2) | ✅ | Anti-hallucination rules |
| shared/framework_patterns.md | Shared resource (L2) | ✅ | Framework security pattern quick reference |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST only generate patches for confirmed and highly_suspected vulnerabilities | Patching unverified issues → false positives, breaking changes |
| CR-2 | Patches MUST be minimal changes; MUST NOT refactor surrounding code | Over-scoped changes → regression risks |
| CR-3 | MUST maintain the target project's code style and conventions | Style mismatch → developer rejection |
| CR-4 | MUST NOT modify test files under ANY circumstance | Test integrity compromise |
| CR-5 | Each patch MUST be independently applicable (`git apply --check` passes) | Dependent patches → partial application failures |
| CR-6 | MUST NOT introduce new dependencies unless no built-in alternative exists (document justification) | Unnecessary dependencies → supply chain risk |
| CR-7 | For complex vulns that cannot be auto-fixed, generate comment markers + manual remediation guide | Silent skip → unaddressed vulnerabilities |
| CR-8 | Config file changes ONLY when root cause is a misconfigured security setting; document original config | Unnecessary config changes → application breakage |

## Fill-in Procedure

### Procedure A: Vulnerability Classification and Prioritization
| Field | Fill-in Value |
|-------|--------------|
| source | {Read `team4_progress.json`} |
| priority_1 | {confirmed + Critical/High severity} |
| priority_2 | {confirmed + Medium severity} |
| priority_3 | {highly_suspected + Critical/High severity} |

### Procedure B: Source Code Location
| Field | Fill-in Value |
|-------|--------------|
| sink_file | {Get `sink_file` from `exploits/{sink_id}.json`} |
| sink_line | {Get `sink_line` from `exploits/{sink_id}.json`} |
| context_read | {Read code section at sink_file:sink_line ±20 lines} |
| identify_patterns | {Identify framework patterns and coding style from context} |

### Procedure C: Remediation Code Generation

Select fix strategy from the Remediation Strategy Matrix below based on vuln_type + framework:

| Field | Fill-in Value |
|-------|--------------|
| fix_strategy | {Select from Remediation Strategy Matrix by vuln_type + framework} |
| code_changes | {Generate minimal fix — modify only necessary code} |
| style_match | {Maintain original code style: indentation, naming conventions} |
| no_new_deps | {Avoid new dependencies — use built-in functions; if unavoidable, document justification} |
| fix_comment | {Add inline comment explaining the remediation rationale} |

#### Remediation Strategy Matrix

**SQL Injection:**

| Framework | Remediation Approach |
|-----------|---------------------|
| Laravel | `DB::raw()` → `DB::select()` + parameter binding; `whereRaw($input)` → `where('col', $input)` |
| ThinkPHP | `where("id=".$id)` → `where('id', $id)`; `$db->query($raw)` → `$db->query($sql, $binds)` |
| Yii2 | `createCommand($raw)` → `createCommand($sql, $params)` |
| WordPress | `$wpdb->query("...{$var}...")` → `$wpdb->prepare("...%s...", $var)` |
| Native PHP | `mysqli_query($conn, $raw)` → `mysqli_prepare()` + `bind_param()` |

**XSS:**

| Scenario | Remediation Approach |
|----------|---------------------|
| Blade `{!! !!}` | Change to `{{ }}` (automatic htmlspecialchars) |
| Native echo | `echo $var` → `echo htmlspecialchars($var, ENT_QUOTES, 'UTF-8')` |
| Twig `\|raw` | Remove the `\|raw` filter |
| JavaScript context | `echo "var x='$input'"` → `echo "var x=".json_encode($input)` |
| URL context | `href="$url"` → `href="`.htmlspecialchars($url, ENT_QUOTES).`"` + URL whitelist validation |

**RCE:**

| Sink | Remediation Approach |
|------|---------------------|
| `system()/exec()/shell_exec()` | Wrap params with `escapeshellarg()` + `escapeshellcmd()`; prefer native PHP functions |
| `eval()` | Remove entirely, replace with equivalent logic |
| `preg_replace('/e')` | Change to `preg_replace_callback()` |
| `unserialize()` | Add `['allowed_classes' => [Safe::class]]`; switch to `json_decode()` |
| `extract()` | Replace with explicit variable assignment; or add `EXTR_SKIP` flag |

**File Operations:**

| Vulnerability | Remediation Approach |
|---------------|---------------------|
| LFI `include($input)` | Whitelist validation: `in_array($input, $allowed)` |
| File upload | MIME whitelist + extension whitelist + random rename + store in web-inaccessible dir |
| Path traversal | `realpath()` + `strpos($real, $base_dir) === 0` validation |
| File write race condition | Add `LOCK_EX` flag |

**SSRF:**

| Scenario | Remediation Approach |
|----------|---------------------|
| User-controllable URL | URL whitelist + block internal IPs + block non-HTTP(S) protocols |
| DNS Rebinding | Resolve DNS first then request + IP validation |
| Redirects | `CURLOPT_FOLLOWLOCATION = false` or limit redirect count |

**XXE:**

| PHP Version | Remediation Approach |
|-------------|---------------------|
| PHP < 8.0 | `libxml_disable_entity_loader(true);` |
| All versions | `$doc->loadXML($xml, LIBXML_NONET \| LIBXML_NOENT);` (replace `LIBXML_DTDLOAD \| LIBXML_DTDATTR`) |

**Authorization Bypass:**

| Vulnerability | Remediation Approach |
|---------------|---------------------|
| Vertical privilege escalation | Add middleware permission checks; Laravel: `Gate::authorize()` / `$this->authorize()` |
| Horizontal privilege escalation/IDOR | Add `where('user_id', auth()->id())` to query conditions; use Policy |
| Mass Assignment | Define `$fillable` whitelist; remove `$guarded = []` |
| JWT none algorithm | Enforce algorithm: `JWT::decode($token, $key, ['HS256'])` |

**Configuration:**

| Issue | Remediation Approach |
|-------|---------------------|
| APP_DEBUG=true | Set `APP_DEBUG=false` in `.env` |
| Missing security headers | Add middleware: X-Frame-Options, CSP, HSTS |
| CORS wildcard | Specify explicit Origin whitelist |
| Default credentials | Force change default passwords; disable default accounts |

**Cryptography:**

| Issue | Remediation Approach |
|-------|---------------------|
| MD5/SHA1 passwords | `password_hash($pwd, PASSWORD_BCRYPT)` + `password_verify()` |
| `rand()/mt_rand()` token | `random_bytes()` or `bin2hex(random_bytes(32))` |
| ECB mode | Switch to CBC/GCM mode + random IV |
| Weak JWT secret | Generate random key ≥256 bits |

**Race Condition:**

| Issue | Remediation Approach |
|-------|---------------------|
| TOCTOU | Use `flock()` or atomic operations |
| Database race condition | `SELECT ... FOR UPDATE` or optimistic locking (version field) |
| Balance double spending | DB transaction + `WHERE balance >= amount` atomic deduction |
| Token replay | Mark as used immediately after use (atomic operation) |

### Procedure D: Patch File Generation
| Field | Fill-in Value |
|-------|--------------|
| format | {Unified diff format (`--- a/path` / `+++ b/path`)} |
| patch_file | {`$WORK_DIR/修复补丁/{sink_id}.patch`} |
| validate | {Each patch must pass `git apply --check`} |

### Procedure E: Verification Recommendations
| Field | Fill-in Value |
|-------|--------------|
| expected_behavior | {Describe expected behavior after applying patch} |
| regression_test | {Recommend regression testing approach} |
| compatibility_impact | {List potential compatibility impacts} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| {sink_id}.patch | `$WORK_DIR/修复补丁/{sink_id}.patch` | Unified diff | Git-applicable remediation patch per vulnerability |
| remediation_summary.json | `$WORK_DIR/修复补丁/remediation_summary.json` | JSON | Summary: generated_at, total_vulns, patches_generated, patches_skipped, skip_reasons, patches[] |

### remediation_summary.json Schema
```json
{
  "generated_at": "ISO-8601",
  "total_vulns": "number",
  "patches_generated": "number",
  "patches_skipped": "number",
  "skip_reasons": ["string"],
  "patches": [{
    "sink_id": "string",
    "vuln_type": "string",
    "file": "string (modified file path)",
    "patch_file": "string (patch file path)",
    "fix_strategy": "string (fix strategy description)",
    "breaking_change": "boolean",
    "verification": "string (verification recommendation)"
  }]
}
```

## Examples

### ✅ GOOD: SQL Injection Patch (Laravel)
```diff
--- a/app/Http/Controllers/UserController.php
+++ b/app/Http/Controllers/UserController.php
@@ -45,3 +45,3 @@ class UserController extends Controller
     public function search(Request $request) {
-        $users = DB::select("SELECT * FROM users WHERE name LIKE '%" . $request->input('q') . "%'");
+        $users = DB::select("SELECT * FROM users WHERE name LIKE ?", ['%' . $request->input('q') . '%']);
         return response()->json($users);
```
Explanation ✅ Minimal change — only the vulnerable line modified. Parameter binding applied. Original code style preserved. No new dependencies.

### ❌ BAD: Over-scoped Refactoring Patch
```diff
--- a/app/Http/Controllers/UserController.php
+++ b/app/Http/Controllers/UserController.php
@@ -1,50 +1,80 @@
-<?php
+<?php declare(strict_types=1);
 
-namespace App\Http\Controllers;
+namespace App\Http\Controllers;
+
+use App\Services\UserSearchService;
+use App\Repositories\UserRepository;
 
 class UserController extends Controller
 {
+    private UserRepository $repo;
+    public function __construct(UserRepository $repo) { $this->repo = $repo; }
     public function search(Request $request) {
-        $users = DB::select("SELECT * FROM users WHERE name LIKE '%" . $request->input('q') . "%'");
+        $users = $this->repo->searchByName($request->validated('q'));
```
What's wrong ❌ Introduced new dependencies (UserRepository, UserSearchService). Refactored surrounding code. Changed constructor. Modified code style (strict_types). Violated CR-2 (minimal changes) and CR-6 (no new deps).

## Error Handling
| Error | Action |
|-------|--------|
| Sink file not found at specified path | Log warning, skip this vulnerability, record in skip_reasons |
| Sink line out of range | Read entire file, search for matching code pattern nearby |
| Framework not recognized | Use Native PHP remediation approach |
| Complex vulnerability (no auto-fix possible) | Generate comment markers: `// SECURITY TODO: [sink_id] — manual fix required` + manual guide |
| Patch conflicts with existing code | Log conflict details, generate as best-effort with conflict markers |
| Multiple vulnerabilities in same file | Generate separate patches, note potential merge conflicts in summary |
