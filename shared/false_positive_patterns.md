# Known False Positive Patterns

This file defines known false positive patterns for each vulnerability type. All auditors MUST cross-reference this list before making a final determination to avoid misidentifying framework built-in protections or secure designs as vulnerabilities.

---

## General False Positive Patterns

### FP-001: Global Middleware Protection Active

**Pattern**: A Sink function accepts user input, but global middleware already intercepts malicious input.
**Check**: Confirm the middleware actually covers the target route (inspect `$middleware` and `$middlewareGroups`, noting the `$except` exclusion list).
**Common Scenarios**:
- Laravel `VerifyCsrfToken` middleware — but routes excluded in `$except` remain vulnerable
- ThinkPHP input filtering `default_filter` — but the `input()` filter parameter can override it
- Symfony request validation — but `$request->query->get()` bypasses validation

### FP-002: Framework Auto-Escaping

**Pattern**: Template outputs user data, but the framework auto-escapes by default.
**Check**: Confirm the escaped syntax is used rather than raw output syntax.
**Common Scenarios**:
- Blade `{{ $var }}` auto htmlspecialchars — **Not FP**: `{!! $var !!}` does not escape
- Twig `{{ var }}` auto-escapes — **Not FP**: `{{ var|raw }}` does not escape
- Smarty `{$var}` depends on configuration — check `$smarty->escape_html`

### FP-003: Parameter Type Constraints

**Pattern**: Route parameters are injected, but the route defines type constraints.
**Check**: Confirm whether the framework route's parameter constraints take effect before reaching the Sink.
**Common Scenarios**:
- Laravel `Route::get('/user/{id}', ...)->where('id', '[0-9]+')` — non-numeric values get 404
- Symfony `@Route("/user/{id}", requirements={"id"="\d+"})` — type mismatch is rejected
- **Note**: Constraints apply only to route parameters; Query String parameters are not restricted

## SQL Injection False Positives

### FP-SQL-001: ORM Parameter Binding

**Pattern**: Code contains `DB::` or `$db->` calls, but uses parameter binding.
**FP Condition**: `DB::select('SELECT * FROM users WHERE id = ?', [$id])` — parameter binding is safe
**Not FP Condition**: `DB::select("SELECT * FROM users WHERE id = $id")` — string concatenation is unsafe

### FP-SQL-002: Laravel Eloquent Safe Methods

**Safe Methods (False Positive)**:
- `User::find($id)` — automatic parameter binding
- `User::where('id', $id)->first()` — automatic parameter binding
- `User::where('status', $request->status)->get()` — automatic parameter binding

**Unsafe Methods (Not False Positive)**:
- `User::whereRaw("name LIKE '%{$input}%'")` — raw SQL
- `DB::raw("COUNT(*) as count WHERE status = '{$status}'")` — raw expression
- `User::select(DB::raw($userInput))` — user input enters raw

### FP-SQL-003: Integer Type Casting

**Pattern**: `$id = (int) $request->input('id'); DB::select("... WHERE id = $id")`
**Analysis**: Forced type cast to integer makes SQL injection impossible. However, this only applies when used **immediately after casting**; intermediate operations introduce uncertainty.

## XSS False Positives

### FP-XSS-001: Non-HTML Content-Type

**Pattern**: Endpoint returns JSON/XML/CSV, not rendered as HTML.
**FP Condition**: `Content-Type: application/json` + `X-Content-Type-Options: nosniff`
**Not FP Condition**: Missing `nosniff` header allows browser MIME sniffing

### FP-XSS-002: HttpOnly Cookie

**Pattern**: XSS exists but Cookie has HttpOnly set.
**Analysis**: HttpOnly prevents JS from reading Cookie, but XSS can still:
- Make AJAX requests (CSRF)
- Modify page content (phishing)
- Log keyboard input
- **Conclusion**: Still a vulnerability, only impact is reduced, not a false positive

### FP-XSS-003: CSP Blocks Execution

**Pattern**: XSS Payload injected successfully but CSP blocks execution.
**Analysis**: Strict CSP (no `unsafe-inline`) can block most XSS, but:
- `<base>` tag hijacking can bypass
- CSS injection is not restricted by `script-src`
- Data exfiltration via `<img src=attacker>` is unrestricted
- **Conclusion**: Downgrade to Medium, not a complete false positive

## RCE False Positives

### FP-RCE-001: disable_functions Active

**Pattern**: `system()`, `exec()` etc. are in `disable_functions`.
**Check**: Confirm via `phpinfo()` or `ini_get('disable_functions')`.
**Note**: `disable_functions` can be bypassed by certain methods (LD_PRELOAD, FFI, PHP Bug)

### FP-RCE-002: open_basedir Restriction

**Pattern**: File operation Sink exists but `open_basedir` restricts the access scope.
**Check**: Confirm `open_basedir` is set and the target path is not within the allowed range.
**Note**: `open_basedir` has known bypass methods (chdir + ini_set, glob://)

### FP-RCE-003: eval Content From Safe Source

**Pattern**: `eval()` call exists, but input comes entirely from internal code/config files.
**FP Condition**: `eval('return ' . $config['formula'] . ';')` where `$config` is read from a protected config file
**Not FP Condition**: Config file can be modified by users (e.g., via admin panel)

## SSRF False Positives

### FP-SSRF-001: URL Allowlist Active

**Pattern**: URL is user-controllable but has allowlist validation.
**FP Condition**: Strict domain allowlist + no redirect following
**Not FP Condition**: Allowlist uses `strpos` instead of strict matching (`evil.com.trusted.com` bypass)

### FP-SSRF-002: HTTP(S) Protocol Only

**Pattern**: cURL has `CURLOPT_PROTOCOLS` set to allow only HTTP/HTTPS.
**Analysis**: Blocks `file://`, `gopher://` and other protocols, but HTTP SSRF can still reach internal networks.

## Authorization False Positives

### FP-AUTHZ-001: Intentionally Public Endpoints

**Pattern**: Unauthenticated endpoint returns data.
**FP Condition**: Endpoint is designed to be public (e.g., product listings, public user profiles)
**Check**: Whether returned fields contain sensitive information (password hashes, private emails, etc.)

### FP-AUTHZ-002: IDOR But No Sensitive Data

**Pattern**: `GET /api/posts/123` can access another user's post.
**FP Condition**: The post itself is public, `is_public=true`
**Not FP Condition**: Post contains private content or allows modification operations

## Configuration False Positives

### FP-CONFIG-001: .env.example Instead of .env

**Pattern**: `/.env` returns content.
**Check**: Whether the response is `.env.example` (containing placeholder values like `DB_PASSWORD=secret`)
**Determination**: Placeholder values (`secret`, `password`, `your-key-here`) = not a leak; specific values = leak

### FP-CONFIG-002: phpinfo Behind Protected Path

**Pattern**: phpinfo.php exists.
**FP Condition**: Under an authentication-protected admin path requiring admin privileges
**Not FP Condition**: Publicly accessible

## Cryptography False Positives

### FP-CRYPTO-001: MD5 for Non-Security Purposes

**Pattern**: Code uses `md5()`.
**FP Condition**: Used for cache keys `md5($url)`, filenames `md5($filename)`, ETag generation
**Not FP Condition**: Used for password hashing `md5($password)`, Token generation, signature verification

### FP-CRYPTO-002: rand() for Non-Security Purposes

**Pattern**: Code uses `rand()` or `mt_rand()`.
**FP Condition**: Used for pagination randomization, UI display randomization, test data generation
**Not FP Condition**: Used for Token/captcha/password reset link/Session ID generation

## Type Juggling False Positive Patterns

### FP-JUGGLE-001: `==` Used in Non-Security Contexts (String Format Checks)

**Pattern**: Code uses `==` for comparison, but the comparison purpose does not involve security decisions.
**Code Example**:
```php
// Check user input date format
if ($dateFormat == 'Y-m-d') {
    $formatter = new DateFormatter($dateFormat);
}

// Check pagination parameter
if ($request->input('sort') == 'asc') {
    $query->orderBy('created_at', 'asc');
}
```
**Why It's a False Positive**: Type juggling with `==` only constitutes a threat in security-related comparisons (e.g., password verification, Token comparison, identity checks). In the above scenarios, even if type confusion occurs, it would not lead to privilege escalation or authentication bypass.
**How to Distinguish**: Confirm whether the comparison result affects authentication/authorization logic. If it only affects display/formatting/sorting or other non-security behavior → false positive.

### FP-JUGGLE-002: `in_array` Used for Allowlist Checks (Implicit strict=true Guarantee)

**Pattern**: `in_array` checks whether user input is in an allowed list, without explicitly passing the third parameter `true`.
**Code Example**:
```php
$allowedStatuses = ['active', 'inactive', 'pending'];
if (in_array($request->input('status'), $allowedStatuses)) {
    $user->status = $request->input('status');
}

// Allowlist values are all strings and input is also a string
$allowedColumns = ['name', 'email', 'created_at'];
if (in_array($sortBy, $allowedColumns)) {
    $query->orderBy($sortBy);
}
```
**Why It's a False Positive**: When all allowlist values are of the **same string type**, and input is also a string (e.g., from `$_GET`, `$request->input()`), loose comparison `in_array` will not produce type juggling issues. String-to-string `==` comparison behaves identically to `===`.
**How to Distinguish**: Check whether the allowlist array element types are consistent. If the allowlist contains `0`, `false`, `null` or other mixed types → not a false positive, bypass risk exists.

### FP-JUGGLE-003: `==` Used for Same-Type Variable Comparison (int==int)

**Pattern**: Both sides of the comparison are the same type (e.g., int==int), type juggling does not change the comparison result.
**Code Example**:
```php
// $userId from database (int), $routeId cast via (int)
$userId = Auth::user()->id;       // int from DB
$routeId = (int) $request->route('id');  // explicitly cast to int
if ($userId == $routeId) {
    // Authorization passed
}

// Two integer constant comparison
if ($retryCount == 3) {
    throw new TooManyAttemptsException();
}
```
**Why It's a False Positive**: `==` between same-type variables is semantically identical to `===`, no type juggling risk exists. `int == int` does not produce classic bypasses like `"0e12345" == "0"`.
**How to Distinguish**: Confirm the type origin of both sides. If one side comes from user input without type casting → not a false positive. If both sides are known same-type → low risk/false positive.

---

## JWT False Positive Patterns

### FP-JWT-001: JWT Used for Non-Sensitive Scenarios

**Pattern**: JWT is used to store user preference settings and other non-security-related data, with lax signature verification.
**Code Example**:
```php
// JWT stores UI preferences (language, theme, layout)
$payload = JWT::decode($token, new Key($key, 'HS256'));
$theme = $payload->theme ?? 'default';
$locale = $payload->locale ?? 'en';

// JWT used to track anonymous user behavior (no sensitive data)
$trackingToken = JWT::encode(['session_start' => time(), 'ab_group' => 'B'], $key, 'HS256');
```
**Why It's a False Positive**: JWT signature weaknesses only constitute a security threat when the Token carries authentication/authorization information. Even if preferences are tampered with, system security is not affected.
**How to Distinguish**: Check whether the JWT payload contains `user_id`, `role`, `permissions` or other identity/permission fields. If it only contains non-sensitive configuration data → low severity, can be downgraded.

### FP-JWT-002: HS256 Weak Key But Very Short Expiration

**Pattern**: JWT uses HS256 + a weak key, but the Token expiration is set very short (e.g., a few minutes).
**Code Example**:
```php
$payload = [
    'user_id' => $user->id,
    'exp' => time() + 300,  // 5-minute expiration
    'iat' => time(),
];
$token = JWT::encode($payload, config('app.key'), 'HS256');

// Strict expiration check during verification
try {
    $decoded = JWT::decode($token, new Key(config('app.key'), 'HS256'));
} catch (ExpiredException $e) {
    return response()->json(['error' => 'Token expired'], 401);
}
```
**Why It's a False Positive (Downgrade)**: Even if an attacker can brute-force the HS256 key, the short expiration significantly narrows the attack window. Cracking time typically far exceeds the Token's validity period.
**How to Distinguish**: Check the `exp` claim time window. If > 1 hour → SHOULD NOT downgrade. If <= 5 minutes + has refresh mechanism → MAY downgrade to Low. Strong key usage is still recommended.

### FP-JWT-003: JWT Combined with Server-Side Session Verification

**Pattern**: JWT is used to carry identity information, but the server simultaneously maintains Session state for secondary verification.
**Code Example**:
```php
// After JWT decode, also compare with server-side Session
$decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
$jwtUserId = $decoded->sub;

// Server-side Session secondary verification
$sessionUserId = $_SESSION['authenticated_user_id'] ?? null;
if ($jwtUserId !== $sessionUserId) {
    http_response_code(401);
    die('Session mismatch');
}

// Also check if Token is in blacklist (revoked after logout)
if (TokenBlacklist::isRevoked($decoded->jti)) {
    http_response_code(401);
    die('Token revoked');
}
```
**Why It's a False Positive (Downgrade)**: Even if the JWT is forged or tampered with, server-side Session verification provides an additional defense layer. An attacker would need to control both the JWT and Session to bypass.
**How to Distinguish**: Confirm that server-side Session verification is **mandatory** rather than optional. If Session verification can be skipped (e.g., only active on certain routes) → not a false positive.

---

## CORS False Positive Patterns

### FP-CORS-001: `Access-Control-Allow-Origin: *` Without `Allow-Credentials`

**Pattern**: CORS configured as `*` but `Access-Control-Allow-Credentials: true` is not set.
**Code Example**:
```php
// Public API, no Cookie authentication needed
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
// Note: Access-Control-Allow-Credentials is NOT set

// Laravel CORS configuration
'allowed_origins' => ['*'],
'supports_credentials' => false,  // Key: credentials not enabled
```
**Why It's a False Positive**: When `Allow-Origin: *`, browsers **prohibit** cross-origin requests from carrying Cookies (even if the frontend sets `withCredentials: true`). Attackers cannot steal authenticated user data via CORS.
**How to Distinguish**: Check whether `Access-Control-Allow-Credentials: true` is also present. If present → **critical vulnerability** (but note browsers do not allow `*` and `Credentials: true` simultaneously; some server-side frameworks dynamically replace `*` with the request Origin). If not present → low severity.

### FP-CORS-002: CORS Configuration in Internal/Development Environment

**Pattern**: Permissive CORS configuration appears in dev/staging environment config.
**Code Example**:
```php
// config/cors.php
if (app()->environment('local', 'development', 'testing')) {
    $allowedOrigins = ['*'];  // Allow all in dev environment
} else {
    $allowedOrigins = ['https://app.example.com'];
}

// .env.development
CORS_ALLOWED_ORIGINS=*
```
**Why It's a False Positive**: Development/testing environment CORS configuration does not affect production security.
**How to Distinguish**: Confirm whether the configuration only takes effect in non-production environments. If the production `.env` or deployment config also uses `*` → not a false positive. Record the finding but **do not alert**; note it in the review.

### FP-CORS-003: CORS Restricted to Known Subdomains

**Pattern**: CORS configuration allows requests from subdomains of the same organization.
**Code Example**:
```php
$allowedOrigins = [
    'https://app.example.com',
    'https://admin.example.com',
    'https://api.example.com',
];

// Or regex matching subdomains
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (preg_match('/^https:\/\/[\w-]+\.example\.com$/', $origin)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Access-Control-Allow-Credentials: true');
}
```
**Why It's a False Positive**: Restricting to known controlled subdomains is a normal security configuration, not a CORS vulnerability.
**How to Distinguish**: Check whether the regex matching is strict. `/\.example\.com$/` can be bypassed by `evil-example.com` → **not a false positive**. Correct implementation MUST anchor `://` or use an exact list.

---

## php://filter False Positive Patterns

### FP-FILTER-001: `include` Parameter From Hardcoded Allowlist

**Pattern**: Dynamic `include` exists, but the filename comes from a fixed allowlist rather than user input.
**Code Example**:
```php
$allowedPages = [
    'home' => 'pages/home.php',
    'about' => 'pages/about.php',
    'contact' => 'pages/contact.php',
];

$page = $_GET['page'] ?? 'home';
if (isset($allowedPages[$page])) {
    include $allowedPages[$page];  // Safe: only includes files from the allowlist
} else {
    include 'pages/404.php';
}
```
**Why It's a False Positive**: User input only serves as a key to query the allowlist mapping; the actual included file path is hardcoded. Attackers cannot control the include target via `php://filter` or path traversal.
**How to Distinguish**: Confirm whether the allowlist is **truly hardcoded**. If the allowlist is dynamically loaded from a database/config file and can be modified by users → not a false positive. If allowlist values directly concatenate user input → not a false positive.

### FP-FILTER-002: `include` in `switch-case` Only Accepts Predefined Values

**Pattern**: `include` path is controlled by `switch-case`, and only predefined cases trigger include.
**Code Example**:
```php
$module = $_GET['module'] ?? 'dashboard';

switch ($module) {
    case 'dashboard':
        include 'modules/dashboard.php';
        break;
    case 'profile':
        include 'modules/profile.php';
        break;
    case 'settings':
        include 'modules/settings.php';
        break;
    default:
        include 'modules/dashboard.php';  // Safe default fallback
        break;
}
```
**Why It's a False Positive**: Each branch of the `switch-case` uses a hardcoded path; user input cannot affect the actually included file. Even if `php://filter/convert.base64-encode/resource=index` is passed, it will only hit the `default` branch.
**How to Distinguish**: Confirm there are no dynamic cases like `case $userInput:` in the `switch`, and no fall-through to dangerous branches. If `include "modules/{$module}.php"` exists in the default branch → **false positive becomes a real vulnerability**.

---

## Open Redirect False Positive Patterns

### FP-REDIR-001: Redirect Target Passes Domain Allowlist Check

**Pattern**: User-controllable redirect URL passes strict domain allowlist validation.
**Code Example**:
```php
$redirectUrl = $_GET['redirect'] ?? '/';

$allowedHosts = ['example.com', 'app.example.com', 'login.example.com'];
$parsedUrl = parse_url($redirectUrl);

if (isset($parsedUrl['host']) && !in_array($parsedUrl['host'], $allowedHosts)) {
    $redirectUrl = '/';  // Redirect to homepage if not in allowlist
}

header("Location: $redirectUrl");
exit;
```
**Why It's a False Positive**: The domain allowlist strictly restricts redirect targets; attackers cannot redirect users to malicious sites.
**How to Distinguish**:
- Check whether `parse_url` can be bypassed: `http://evil.com\@example.com`, `//evil.com` and other edge cases
- Check allowlist matching method: `strpos($url, 'example.com')` can be bypassed by `example.com.evil.com` → **not a false positive**
- Confirm whether `parse_url` results fully validate scheme + host → if only host is checked and `javascript:` scheme is ignored → **not a false positive**

### FP-REDIR-002: Redirect to Internal Paths Only (`/` Prefix, No `//`)

**Pattern**: Redirect only accepts relative paths starting with `/`, and excludes `//` protocol-relative URLs.
**Code Example**:
```php
$returnPath = $_GET['return'] ?? '/dashboard';

// Strict check: must start with single /, disallow // or /\
if (preg_match('#^/[^/\\\\]#', $returnPath) || $returnPath === '/') {
    header("Location: $returnPath");
} else {
    header("Location: /dashboard");
}
exit;

// Another safe implementation
function safeRedirect(string $path): void {
    // Only allow internal paths
    $path = '/' . ltrim($path, '/');
    if (str_starts_with($path, '//') || str_contains($path, '://')) {
        $path = '/';
    }
    header("Location: $path");
    exit;
}
```
**Why It's a False Positive**: Only allowing `/path` format relative paths means the browser will resolve them under the current domain, making it impossible to redirect to external domains. Excluding `//` prevents protocol-relative URLs (e.g., `//evil.com`).
**How to Distinguish**:
- Check whether `//` is filtered: if not → `//evil.com/path` can cause Open Redirect → **not a false positive**
- Check whether `/\` is filtered: some browsers resolve `/\evil.com` as an external domain → **not a false positive**
- Check for CRLF injection: `/path%0d%0aLocation:%20http://evil.com` → requires additional protection

---

## Usage Guide

Auditors MUST cross-check the following before marking a vulnerability as `confirmed`:

1. Review the false positive patterns for the corresponding vulnerability type in this file
2. Check whether any false positive conditions match
3. If matched:
   - Confirm the "Not FP Condition" does not hold
   - If still a false positive → downgrade or discard
   - If it's a borderline case → mark as `[Needs Verification]` with explanation
4. Note in the report which false positive patterns were excluded

## Update Rules

- Newly discovered false positive patterns SHALL be appended to this file after QA reviewer confirmation
- Each pattern MUST include: pattern name, FP condition, Not FP condition
- Framework version updates MAY invalidate certain false positive patterns; periodic review is required
