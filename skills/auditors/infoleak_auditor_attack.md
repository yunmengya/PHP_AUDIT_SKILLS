> **Skill ID**: S-050-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploit_results/{sink_id}_result.json, PoC脚本/{sink_id}_poc.py

## Attack Rounds

### R1 - Grep Scan for Hardcoded Sensitive Information

Search source code for:
- `password\s*=`, `passwd\s*=`, `DB_PASSWORD` (`*.php`)
- `api_key\s*=`, `secret_key\s*=`, `AKIA[0-9A-Z]{16}` (AWS key pattern)
- `Bearer\s`, `token\s*=\s*['"]` (`*.php`)
- `BEGIN.*PRIVATE KEY`, `BEGIN CERTIFICATE`
- Internal IP patterns: `192\.168`, `10\.`, `172\.(1[6-9]|2[0-9]|3[01])`

**Evidence:** Active, usable hardcoded keys discovered (not placeholders/test values).

### R2 - Git History Search

```bash
git log -p --all -S "password" -- "*.php" "*.env" "*.yml"
git log -p --all -S "AKIA" -- .
git log --diff-filter=D --name-only | grep -E "\.(env|pem|key|p12)"
git log --oneline --all | grep -iE "(password|secret|credential)"
git show <commit>:<filepath>  # Recover deleted files
```
**Evidence:** Keys recovered from Git history are still valid on the current system.

### R3 - API Response Field Analysis

- Call each endpoint with valid credentials and analyze all JSON fields
- Look for: `password_hash`, `secret`, `token`, `ssn`, `internal_ip`
- Compare admin vs regular user responses for extra fields
- Analyze nested sensitive fields in list/paginated endpoints

**Evidence:** API response contains fields not appropriate for the current requesting user.

### R4 - User Enumeration Testing

**Login:** Valid user + wrong password vs invalid user + wrong password — compare messages, status codes, timing.
**Registration:** Existing email vs new email — compare responses.
**Password reset:** Existing user vs non-existing user — compare responses and timing.
**API:** `GET /api/users/1` (exists) vs `GET /api/users/99999` (does not exist).

**Evidence:** Measurable response differences allow reliable account enumeration.

### R5 - Error Message Triggering

- Invalid types: send string where int expected, send array where string expected
- SQL probes: `'`, `"`, `\` to trigger SQL errors
- Path traversal: `../` to trigger path errors
- Missing required fields: trigger validation errors containing column names
- Malformed JSON/XML body, division by zero errors

**Evidence:** Errors leak internal paths, SQL queries, database structure, or framework internals.

### R6 - Data Masking Check

Analyze endpoints returning personal data:
- User profiles: phone numbers, emails, ID numbers, addresses
- Orders/transactions: bank card numbers, billing addresses
- Admin lists: bulk user data; exports: CSV/Excel containing PII
- Verify: phone number middle 4 digits masked, email partially masked, bank card showing only last 4 digits, ID number middle section masked

**Evidence:** At least one endpoint returns unmasked PII.

### R7 - Framework Debug Endpoint Scan

```
GET /_ignition/health-check        GET /_ignition/execute-solution
GET /telescope/requests             GET /horizon/api/stats
GET /_profiler                      GET /_wdt/<token>
GET /phpinfo.php  /info.php  /test.php  /debug.php  /status.php
GET /nonexistent-page (check for debug stack traces)
POST /api/endpoint with malformed body
```
**Evidence:** Debug endpoints are accessible, leaking internal state, environment variables, or configuration.

### R8 - Combination (Leaked Keys → Exploitation)

1. Hardcoded AWS keys (R1) -> enumerate S3 buckets -> download data
2. Git-recovered database password (R2) -> connect to exposed database
3. Error-leaked JWT Secret (R5) -> forge admin Token
4. API-exposed password hash (R3) -> offline cracking -> account takeover
5. Internal IPs in source code (R1) -> SSRF to internal services

**Evidence:** Leaked information is directly used for unauthorized access.

### R9 - Supply Chain Information Leakage

- **composer.lock analysis**:
  - Scan all dependency versions and match against known CVEs
  - `composer audit` output analysis
  - Outdated dependencies: locate versions of major security dependencies
- **NPM/Yarn lock files**: Frontend dependency vulnerabilities
- **Docker image information**:
  - `docker history` leaks secrets in build steps
  - Missing `.dockerignore` causes sensitive files to be included in image
- **CI/CD configuration leakage**:
  - Hardcoded tokens in `.github/workflows/*.yml`
  - Environment variables in `.gitlab-ci.yml`
  - Credentials in `Jenkinsfile`

### R10 - Timing Side Channels

- **Password comparison timing**: Time differences between `===` vs `==` vs `hash_equals()`
  - Character-by-character comparison leaks password length and prefix
  - Secure: `hash_equals()` constant-time comparison
- **Database query timing**: Response time difference between existing vs non-existing users
- **Cache hit/miss timing**: Infer whether specific data exists in cache
- **HMAC verification timing**: Timing leak in `$computed_mac == $provided_mac`
- Measurement method: Send 50+ requests per test case, take the median

### R11 - Frontend Source Code Leakage

- **Source Map exposure**:
  - `app.js.map` → full source code reconstruction
  - `*.css.map` → SCSS/LESS variables (may contain paths)
  - Search for `//# sourceMappingURL=`
- **Webpack public path leakage**:
  - `/__webpack_hmr` → development mode
  - `/webpack.config.js` → build configuration
- **Vue/React debug mode**:
  - `__VUE_DEVTOOLS_GLOBAL_HOOK__` present
  - React DevTools markers
- **Inline comment leakage**:
  - `<!-- TODO: Remember to delete test account admin/test123 -->`
  - `<!-- API endpoint: http://internal-api:8080 -->`

### R12 - DNS/Network Information Leakage

- **DNS zone transfer**: `dig axfr target.com @ns1.target.com`
- **Subdomain enumeration**: Subdomain discovery based on CSP, CORS, and Cookie domains
- **Internal service discovery**:
  - Error pages leaking internal hostnames
  - `X-Forwarded-For` response leaking proxy chain
  - `Via` header leaking middleware information
  - `Server` header leaking web server version

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| Hardcoded key | `$stripe_key = "sk_live_4eC39..."` in source code |
| Git history leak | `git show abc123:.env` shows `DB_PASSWORD=prod_secret` |
| API over-exposure | JSON contains `"password_hash": "$2y$10$..."` |
| User enumeration | Valid user: "Wrong password" vs invalid: "User not found" |
| Error disclosure | Stack trace contains `/var/www/app/Models/User.php:42` and SQL |
| Unmasked PII | `"phone": "13812345678"` not masked |
| Debug endpoint | `/telescope/requests` shows all HTTP requests and their payloads |

## Report Format

```json
{
  "vuln_type": "InfoLeak",
  "sub_type": "hardcoded_secret|git_history|api_overexposure|user_enumeration|error_disclosure|unmasked_pii|debug_endpoint",
  "round": 1,
  "location": "app/Services/PaymentService.php:23",
  "evidence": "$stripe_key = 'sk_live_4eC39...'",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Credential leakage|PII exposure|Internal architecture disclosure",
  "remediation": "Use environment variables for key storage, implement field masking, standardize error responses, restrict debug endpoints"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential information leakage vulnerabilities:
- Pattern 1: `var_dump($user)` / `print_r($config)` / `dd($request)` — Debug output left in production code
- Pattern 2: `catch(Exception $e) { echo $e->getMessage(); }` — Exception details returned directly to the client, leaking stack traces, file paths, SQL
- Pattern 3: `$apiKey = "sk-proj-xxxx..."` / `define('DB_PASS', 'hardcoded')` — Hardcoded keys/credentials in source code
- Pattern 4: `return response()->json($user)` without field filtering — API returns complete Model data (including password_hash, token, etc.)
- Pattern 5: `phpinfo()` / `server-status` / `/_profiler` — Information leakage endpoints exposed in production
- Pattern 6: `.git/` / `.env` / `composer.lock` accessible via HTTP — Version control and configuration files exposed

## Key Insight (Critical Judgment Basis)

> **Key point**: Information leakage itself usually does not directly cause harm, but it is the "intelligence gathering" phase of an attack chain — a leaked APP_KEY makes deserialization RCE feasible, leaked database credentials turn SQLi into direct access, and leaked internal paths help LFI precisely locate targets. During auditing, each information leakage finding SHOULD be cross-referenced with other vulnerability categories to assess combined impact.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other specialists
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths are found, terminate early to avoid wasting rounds on hallucinated results

## Prerequisites and Scoring (MUST be filled)

The output `exploits/{sink_id}.json` MUST include the following two objects:

### prerequisite_conditions (Prerequisites)
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the auth_level for that route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` MUST list all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

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
- All reason fields MUST be filled with specific justification; MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_LEAK_SOURCE_POINT` — Leak source location ✅ Required
- `EVID_LEAK_DATA_TYPE` — Leaked data type ✅ Required
- `EVID_LEAK_ACCESS_PATH` — Access path ✅ Required
- `EVID_LEAK_RESPONSE_CONTENT` — Response content evidence (required for confirmed findings)

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-back

After the attack cycle ends, write experience to the attack memory store (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit_result.json`).

> The `## Report Format` above is the per-round internal recording format; the final output MUST be consolidated into the exploit_result.json structure.

## Collaboration

- Pass credentials to the Privilege Escalation Auditor. Pass internal IPs/URLs to the SSRF Auditor.
- Pass API keys to the Configuration Auditor. Submit all findings to the QA Reviewer for validation.

## Real-time Sharing and Second-Order Tracking

### Shared Write
When the following information is discovered, it **MUST** be written to the shared findings store (`$WORK_DIR/audit_session.db`) (format per `shared/realtime_sharing.md`):
- Hardcoded credentials (DB passwords, API keys, JWT Secrets) → `finding_type: credential/secret_key`
- Internal IPs/URLs → `finding_type: internal_url`
- Leaked configuration values (APP_KEY, etc.) → `finding_type: config_value`

### Shared Read
Read the shared findings store before starting the attack phase to leverage credentials and endpoints discovered by other auditors.

## Constraints

- MUST NOT export real customer PII; only record field names and masking status
- MUST NOT crack password hashes from production environments; only record exposure
- Enumeration MUST be limited to a sample size sufficient to confirm the pattern through sample comparison (maximum 10 usernames)


---

## Pre-submission Self-check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized self-check items below (S1-S3); submit only after all are ✅
3. If any item is ❌ → fix and re-check; MUST NOT skip

### Specialized Self-check (Info Leak Auditor specific)
- [ ] S1: Leak type (source code/configuration/stack trace/credentials) has been classified and labeled
- [ ] S2: Production environment triggerability has been confirmed (not only in DEBUG mode)
- [ ] S3: Sensitivity level and exploitation value of leaked information has been assessed

## Shared Protocols
> 📄 `skills/shared/round_record_format.md` (S-101) — Per-round JSON format
> 📄 `skills/shared/smart_skip_protocol.md` (S-102) — Smart skip
> 📄 `skills/shared/smart_pivot_protocol.md` (S-103) — Smart pivot
> 📄 `skills/shared/prerequisite_scoring_3d.md` (S-104) — 3D scoring
> 📄 `skills/shared/attack_memory_writer.md` (S-105) — Memory write
> 📄 `skills/shared/second_order_tracking.md` (S-106) — Second-order tracking
> 📄 `skills/shared/general_self_check.md` (S-108) — G1-G8 self-check
