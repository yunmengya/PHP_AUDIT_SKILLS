## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-053-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 8-round progressive attack against cryptographic weakness sinks |

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
| CR-5 | MUST write exploit result to `$WORK_DIR/exploits/{sink_id}.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST demonstrate practical exploitation (crack hash, forge token, predict random) — theoretical weakness without PoC is `potential` not `confirmed` | FAIL — theoretical attack reported as confirmed |
| CR-PAYLOAD | MUST test payloads in priority order (1→2→3→4) within each round — MUST NOT skip Priority 1 to try creative payloads directly | FAIL — uncontrolled payload selection, wastes rounds on low-probability attacks |

## 8 Attack Rounds
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

### R1 - Password Hashing Audit

Static Analysis:
```bash
# Search for insecure password hashing
grep -rn "md5(\|sha1(\|sha256(\|hash('md5'\|hash('sha1'" \
  $TARGET_PATH/app/ $TARGET_PATH/src/ --include="*.php"

# Search for secure password hashing (confirm positive cases)
grep -rn "password_hash\|bcrypt\|argon2" \
  $TARGET_PATH/ --include="*.php"

# Search for unsalted hashing
grep -rn "md5(\$\|sha1(\$" $TARGET_PATH/ --include="*.php" | \
  grep -v "salt\|\..*\."
```

Dynamic Testing:
- Register a user, check the password field format in the database
- `$2y$10$...` → bcrypt (secure)
- `$argon2id$...` → Argon2 (secure)
- 32-character hex → MD5 (insecure)
- 40-character hex → SHA1 (insecure)
- Locate `password_hash()` cost/time_cost/memory_cost parameters

**Evidence:** Password hash stored in MD5/SHA1 format in the database.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R2 - Random Number Predictability

Static Analysis:
```bash
# Search for insecure random numbers used in security contexts
grep -rn "rand()\|mt_rand()\|uniqid()\|microtime()" \
  $TARGET_PATH/ --include="*.php" | \
  grep -i "token\|key\|secret\|password\|reset\|session\|csrf\|nonce\|otp"

# Search for fixed seeds
grep -rn "srand(\|mt_srand(" $TARGET_PATH/ --include="*.php"

# Search for secure random numbers (confirm positive cases)
grep -rn "random_bytes\|random_int\|openssl_random_pseudo_bytes" \
  $TARGET_PATH/ --include="*.php"
```

Dynamic Testing:
- Obtain multiple password reset Tokens, analyze predictability
- Obtain multiple Session IDs, analyze entropy
- If Token is based on `mt_rand()`:
  - Use the `php_mt_seed` tool to reverse-engineer the seed from output
  - Predict the next Token
- If Token is based on `uniqid()`:
  - Estimate based on server time, margin of error < 1 second

**Evidence:** Predicted Token matches the actually generated Token.


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R3 - Encryption Algorithm Audit

Static Analysis:
```bash
# Search for encryption functions
grep -rn "openssl_encrypt\|openssl_decrypt\|mcrypt_\|sodium_" \
  $TARGET_PATH/ --include="*.php"

# Search for ECB mode
grep -rn "ECB\|ecb\|OPENSSL_ZERO_PADDING" \
  $TARGET_PATH/ --include="*.php"

# Search for hardcoded keys
grep -rn "encryption_key\s*=\s*['\"]" $TARGET_PATH/ --include="*.php"
grep -rn "MCRYPT_\|OPENSSL_" $TARGET_PATH/ --include="*.php"
```

Checklist:
- ECB mode → Critical (data pattern leakage)
- CBC without HMAC → High (Padding Oracle)
- Fixed IV → High (reduced CBC first-block security)
- `mcrypt_*` → High (deprecated)
- `base64_encode`/`str_rot13` used as encryption → Critical
- DES/3DES/RC4 → High (broken/weak algorithms)

**Evidence:** ECB mode or hardcoded keys found in source code.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R4 - JWT Security Audit

Static Analysis:
```bash
# Search for JWT libraries
grep -rn "firebase/php-jwt\|lcobucci/jwt\|tymon/jwt-auth\|namshi/jose" \
  $TARGET_PATH/composer.json

# Search for JWT configuration
grep -rn "JWT_SECRET\|jwt_key\|alg.*HS256\|alg.*none" \
  $TARGET_PATH/ --include="*.php" --include="*.env*"
```

Dynamic Testing:
1. **Weak Key Brute Force**:
   ```bash
   # Using jwt_tool or hashcat
   docker exec php python3 -c "
   import jwt, itertools
   token = 'eyJ...'
   for word in open('/tmp/jwt_wordlist.txt'):
       try:
           jwt.decode(token, word.strip(), algorithms=['HS256'])
           print(f'Found: {word.strip()}')
           break
       except: pass
   "
   ```
   - Common weak keys: `secret`, `password`, `123456`, `jwt_secret`, `changeme`, APP_KEY
2. **alg:none attack**: Modify Header to `{"alg":"none"}`, remove signature
3. **RS256→HS256 confusion**: Obtain public key, sign with public key as HS256 secret
4. **Expiration analysis**: Modify `exp` to a past time, test whether server rejects it
5. **Claim tampering**: Modify `role`/`sub`/`admin` fields

**Evidence:** JWT key brute-forced, or alg:none Token accepted.


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R5 - Session / CSRF Token Security

Analysis:
1. Locate `session.sid_length` (recommended ≥ 48)
2. Locate `session.sid_bits_per_character` (recommended 6)
3. Measure Session ID entropy: collect 100 Session IDs, calculate Shannon entropy
4. Locate CSRF Token generation:
   - Uses `random_bytes()` → Secure
   - Uses `md5(time())` → Insecure
   - Uses `md5(session_id())` → Insecure (Session ID is known)

Attack:
- Collect 1000 CSRF Tokens, analyze patterns
- If time-based: generate candidate Tokens within a known time window
- If based on `mt_rand()`: use php_mt_seed to reverse-engineer

**Evidence:** Successfully predicted CSRF Token or Session ID.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R6 - Signature & Integrity Verification

Analysis:
1. Search for HMAC usage:
   ```bash
   grep -rn "hash_hmac\|hmac\|signature\|sign\|verify" \
     $TARGET_PATH/ --include="*.php"
   ```
2. Analyze comparison methods:
   - `$computed == $provided` → Timing attack (insecure)
   - `hash_equals($computed, $provided)` → Constant-time (secure)
3. Analyze signature coverage:
   - Only partial data signed → Unsigned portions can be tampered
   - Signature does not include timestamp → Replay attack

Attack:
- **Timing attack**: Guess HMAC value byte-by-byte, observe response time differences
  - 50+ requests per byte, take the median
  - Time difference > 1ms between correct byte vs wrong byte is exploitable
- **Length extension attack**: When MD5/SHA1 HMAC is incorrectly implemented: `H(key||msg||padding||ext)`
- **Signature bypass**: Modify unsigned fields

**Evidence:** Measurable timing differences in timing attack, or signature bypassed.


#### R7 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R7 - Key Management Audit

Analysis:
1. **Key Storage Location**:
   - Hardcoded in PHP source code → Critical
   - Stored in `.env` file → Medium (MUST be combined with .env exposure analysis)
   - Uses KMS/Vault → Secure
2. **Key Rotation Mechanism**:
   - No rotation policy → High
   - Manual rotation → Medium
   - Automated rotation → Secure
3. **Key Reuse**:
   - Same key used for both encryption and signing → High
   - Same key used across environments (dev/staging/prod) → High
   - `APP_KEY` used for multiple purposes (encryption+signing+Token) → Medium
4. **Key Strength**:
   - AES-128 key < 16 bytes → High
   - AES-256 key < 32 bytes → High
   - HMAC key < 32 bytes → Medium

**Evidence:** Valid keys hardcoded in source code, or keys reused across environments.


#### R8 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R8 - Combined Attack Chains

1. **Weak RNG → Token Prediction → Password Reset**: `mt_rand()` Token → Reverse-engineer seed → Predict next reset Token → Account takeover
2. **ECB Mode → Data Block Reordering**: Encrypted Cookie uses ECB → Swap ciphertext blocks → Privilege tampering
3. **JWT Weak Key → Token Forgery → Admin Access**: Brute-force JWT Secret → Forge admin Token → Full access
4. **MD5 Password → Rainbow Table → Credential Stuffing**: Leaked MD5 hash → Rainbow table recovery → Login to other platforms
5. **Timing Attack → Byte-by-byte HMAC Cracking → API Signature Forgery**: Non-constant-time comparison → Byte-by-byte leakage → Forge arbitrary request signatures

**Success Criteria:** Cryptographic weakness exploited to achieve real security impact.

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| Weak Password Hash | Database field `e10adc3949ba59abbe56e057f20f883e` (MD5 of 123456) |
| Predictable Token | Predicted value `abc123` matches the actually generated value |
| JWT Weak Key | Key is `secret`, Token forged with this key is accepted |
| ECB Detection | Identical plaintext blocks produce identical ciphertext blocks |
| Timing Difference | Correct first byte avg 5.2ms vs incorrect first byte 4.8ms |

## Report Format

```json
{
  "vuln_type": "Cryptography",
  "sub_type": "weak_hash|predictable_random|insecure_encryption|jwt_weakness|timing_attack|key_management",
  "round": 1,
  "location": "app/Models/User.php:45",
  "evidence": "Password stored as MD5: $user->password = md5($input)",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Password brute-forceable|Token predictable|Data decryptable",
  "remediation": "Use password_hash(PASSWORD_ARGON2ID), use random_bytes() for Token generation, use AES-256-GCM"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential cryptographic weaknesses:
- Pattern 1: `md5($password)` / `sha1($password)` — Insecure hash algorithms used for password storage; MUST use `password_hash()`
- Pattern 2: `openssl_encrypt($data, 'AES-128-ECB', $key)` — ECB mode without IV; identical plaintext produces identical ciphertext, causing pattern leakage
- Pattern 3: `$token = md5(time())` / `$reset = substr(md5(rand()), 0, 16)` — Predictable seed used to generate security Tokens
- Pattern 4: `if(md5($input) == md5($stored))` — Loose comparison of hash values; magic hashes starting with `0e` can bypass
- Pattern 5: `$iv = str_repeat("\0", 16)` / `$key = "hardcoded_key_123"` — Hardcoded IV or key
- Pattern 6: `hash_equals($a, $b)` not used, instead `$a === $b` — Non-constant-time comparison, timing attack risk

## Key Insight (Critical Judgment Criteria)

> **Key Point**: The core of cryptographic auditing is NOT about finding "what algorithm is used", but about finding "where the key/IV/random number comes from". Even with AES-256-GCM, if the key is hardcoded in source code, the IV is all zeros, or the Token is generated with `rand()`, the encryption is effectively useless. Priority analysis: whether password hashing uses `password_hash()`, whether Tokens use `random_bytes()`/`openssl_random_pseudo_bytes()`, whether comparisons use `hash_equals()`.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find missed filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other specialists
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. Terminate early when no new paths exist, to avoid wasting rounds producing hallucinated results

## Prerequisites & Scoring (MUST be filled)

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
- `auth_requirement` MUST match the route's auth_level in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` MUST list all non-authentication prerequisites (e.g., PHP config, Composer dependencies, environment variables)

### severity (Three-Dimensional Scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-CRYPTO-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_CRYPTO_ALGORITHM_USAGE` — Encryption algorithm usage ✅ Required
- `EVID_CRYPTO_KEY_MANAGEMENT` — Key management ✅ Required
- `EVID_CRYPTO_SECURITY_CONTEXT` — Security context ✅ Required
- `EVID_CRYPTO_EXPLOIT_PROOF` — Exploit proof (required when confirmed)

Missing required EVID → Conclusion automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-back

After the attack cycle ends, write experience to the attack memory store (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit.json`).

> The `## Report Format` above is the per-round internal recording format; the final output MUST be aggregated into the exploit.json structure.

## Collaboration

- Pass discovered weak keys to the Configuration Auditor and Authorization Auditor
- Pass predictable Tokens to the Authorization Auditor (forgery scenarios)
- Pass JWT weaknesses to the Authorization Auditor (R5 Token tampering)
- Submit all findings to the QA Inspector for evidence verification

## Real-time Sharing & Second-Order Tracking

### Shared Write
Discovered weak keys/predictable values **MUST** be written to the shared findings store (`$WORK_DIR/audit_session.db`):
- Cracked passwords/keys → `finding_type: secret_key`
- Predictable Token algorithms → `finding_type: bypass_method`

### Shared Read
Read the shared findings store before starting the attack phase to leverage leaked encryption configurations.

## Constraints

- Password hash brute-forcing is permitted SOLELY for confirming hash type (e.g., MD5 vs bcrypt). Do NOT attempt to crack or recover actual user passwords under any circumstances
- Timing attacks require a low-latency environment (Docker internal network); results MUST have statistical significance
- JWT brute-forcing uses a limited dictionary (top 10000); MUST NOT perform exhaustive search
- MUST NOT export or store any real user passwords


---

## Pre-submission Self-check (MUST be executed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute all 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialist self-check items below (S1-S3); submit only after all are ✅
3. Any item ❌ → Correct and re-run self-check; MUST NOT skip

### Specialist Self-check (Crypto Auditor Specific)
- [ ] S1: Specific usage locations of weak algorithms (MD5/SHA1/DES) have been annotated
- [ ] S2: Evidence of hardcoded or predictable keys/IVs has been presented
- [ ] S3: Secure alternatives (bcrypt/AES-256-GCM) have been recommended

## Shared Protocols
> 📄 `skills/shared/round_record_format.md` (S-101) — Per-round JSON format
> 📄 `skills/shared/smart_skip_protocol.md` (S-102) — Smart skip
> 📄 `skills/shared/smart_pivot_protocol.md` (S-103) — Smart pivot
> 📄 `skills/shared/prerequisite_scoring_3d.md` (S-104) — 3D scoring
> 📄 `skills/shared/attack_memory_writer.md` (S-105) — Memory write
> 📄 `skills/shared/second_order_tracking.md` (S-106) — Second-order tracking
> 📄 `skills/shared/general_self_check.md` (S-108) — G1-G8 self-check


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

## Examples

### ✅ GOOD Output Example

```json
{
  "sink_id": "CRYPTO-001",
  "vuln_type": "Cryptography",
  "sub_type": "weak_hash",
  "final_verdict": "confirmed",
  "rounds_executed": 2,
  "confirmed_round": 1,
  "location": "app/Models/User.php:45",
  "payload": "Registration with password 123456, database stores md5 hash",
  "evidence": "EVID_CRYPTO_ALGORITHM_USAGE: User.php:45 — $this->password = md5($input); EVID_CRYPTO_KEY_MANAGEMENT: No salt used; EVID_CRYPTO_SECURITY_CONTEXT: Password storage for user authentication; EVID_CRYPTO_EXPLOIT_PROOF: DB field value e10adc3949ba59abbe56e057f20f883e matches md5('123456')",
  "confidence": "confirmed",
  "impact": "Password brute-forceable via rainbow tables",
  "prerequisite_conditions": { "auth_requirement": "anonymous", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 3, "impact": 2, "complexity": 3, "score": 2.55, "cvss": 8.5, "level": "H" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "CRYPTO-001",
  "vuln_type": "Cryptography",
  "final_verdict": "confirmed",
  "evidence": "Uses MD5 somewhere",
  "severity": { "level": "H" }
}
// ❌ No sub_type, location, or payload
// ❌ evidence has no EVID references, no file:line, no DB proof
// ❌ "somewhere" — must specify exact code location
// ❌ severity missing scores and reasons
```
## Error Handling

| Error | Action |
|-------|--------|
| Container unreachable or crashed | Restart container, retry current round; if 2nd failure → mark `"status": "container_failed"`, skip remaining rounds |
| Target endpoint returns 500 | Reduce payload complexity, retry once; if persistent → record `"status": "target_error"`, continue next round |
| Timeout during exploitation (>AGENT_TIMEOUT_MIN) | Save partial results, set `"status": "timeout_partial"`, proceed to scoring |
| Cipher suite negotiation fails | Fallback to TLS 1.2/1.1 probes; if connection refused → record `"status": "crypto_handshake_failed"` |
| Encrypted token not decryptable for analysis | Attempt known-plaintext and padding oracle attacks; if infeasible → record `"status": "encryption_opaque"` |
| No weak cryptographic implementation detected | Record `"status": "crypto_secure"`, set `final_verdict: "not_vulnerable"` |
