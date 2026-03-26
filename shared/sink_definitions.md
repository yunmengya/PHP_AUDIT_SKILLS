# Sink Function Definitions (Complete List)

This file defines all Sink functions to be detected, categorized by vulnerability type. Shared by all Agents.

---

## 1. RCE Sink (Remote Code/Command Execution)

### Code Execution
| Function | Risk Level | Description |
|------|----------|------|
| `eval($code)` | Critical | Directly executes PHP code |
| `assert($code)` | Critical | Can execute code strings before PHP 7 |
| `preg_replace('/e', $replacement)` | Critical | /e modifier executes replacement as code (removed in PHP 7) |
| `create_function($args, $code)` | Critical | Uses eval internally (deprecated in PHP 7.2) |

### Command Execution
| Function | Risk Level | Description |
|------|----------|------|
| `system($cmd)` | Critical | Executes command and outputs result |
| `exec($cmd)` | Critical | Executes command and returns last line |
| `passthru($cmd)` | Critical | Executes command and outputs raw data directly |
| `shell_exec($cmd)` | Critical | Equivalent to backtick \`$cmd\` |
| `popen($cmd, $mode)` | Critical | Opens process pipe |
| `proc_open($cmd, ...)` | Critical | Advanced process control |
| `pcntl_exec($path)` | Critical | Replaces current process with new program |

### Callback Execution
| Function | Risk Level | Description |
|------|----------|------|
| `call_user_func($callback, ...)` | High | Dynamically invokes function |
| `call_user_func_array($callback, $args)` | High | Dynamically invokes function (array arguments) |
| `array_map($callback, $array)` | Medium | Dangerous when callback is controllable |
| `array_filter($array, $callback)` | Medium | Dangerous when callback is controllable |
| `usort($array, $callback)` | Medium | Dangerous when callback is controllable |
| `array_walk($array, $callback)` | Medium | Dangerous when callback is controllable |

### Dynamic Invocation
| Pattern | Risk Level | Description |
|------|----------|------|
| `$func()` | High | Variable function call |
| `$$var` | High | Variable variable |
| `${$var}` | High | Variable variable (curly brace syntax) |

### Variable Overwriting
| Function | Risk Level | Description |
|------|----------|------|
| `extract($array)` | High | Imports array into current symbol table |
| `parse_str($string)` | High | Imports variables into current scope when no second argument |
| `mb_parse_str($string)` | High | Same as parse_str |

---

## 2. SQL Sink (SQL Injection)

### Native PHP
| Function | Risk Level | Description |
|------|----------|------|
| `$pdo->query($sql)` | High | Directly executes SQL |
| `$pdo->exec($sql)` | High | Executes SQL without result set |
| `$mysqli->query($sql)` | High | MySQLi query |
| `$mysqli->multi_query($sql)` | Critical | Supports stacked queries |
| `mysql_query($sql)` | High | Deprecated MySQL function |
| `pg_query($conn, $sql)` | High | PostgreSQL query |

### Laravel
| Function | Risk Level | Description |
|------|----------|------|
| `DB::raw($sql)` | High | Raw SQL expression |
| `DB::select($sql)` | High | Raw SQL query (when not parameterized) |
| `->whereRaw($sql)` | High | Raw WHERE clause |
| `->havingRaw($sql)` | High | Raw HAVING clause |
| `->orderByRaw($sql)` | High | Raw ORDER BY |
| `->selectRaw($sql)` | High | Raw SELECT columns |
| `->groupByRaw($sql)` | High | Raw GROUP BY |

### ThinkPHP
| Function | Risk Level | Description |
|------|----------|------|
| `Db::query($sql)` | High | Raw SQL query |
| `Db::execute($sql)` | High | Raw SQL execution |
| `->where(string concatenation)` | High | Non-array/closure form of where |

### Yii2
| Function | Risk Level | Description |
|------|----------|------|
| `Model::findBySql($sql)` | High | Raw SQL query |
| `createCommand()->rawSql` | High | Raw SQL command |

---

## 3. File Inclusion Sink (LFI/RFI)

| Function | Risk Level | Description |
|------|----------|------|
| `include $path` | Critical | Includes and executes file |
| `include_once $path` | Critical | Same as above, only once |
| `require $path` | Critical | Includes and executes file (fatal on failure) |
| `require_once $path` | Critical | Same as above, only once |
| `highlight_file($path)` | High | Displays file source code |
| `show_source($path)` | High | Alias for highlight_file |
| `file_get_contents($path)` | High | Reads file contents |
| `readfile($path)` | High | Outputs file contents |
| `fread($handle, $length)` | Medium | Reads an opened file |
| `file($path)` | High | Reads file into array |
| `fpassthru($handle)` | Medium | Outputs remaining file contents |

---

## 4. File Write Sink

| Function | Risk Level | Description |
|------|----------|------|
| `file_put_contents($path, $data)` | Critical | Writes to file (can write WebShell) |
| `fwrite($handle, $data)` | High | Writes to an opened file |
| `fputs($handle, $data)` | High | Alias for fwrite |
| `move_uploaded_file($tmp, $dest)` | Critical | Moves uploaded file (file upload vulnerability) |
| `copy($src, $dest)` | High | Copies file |
| `rename($old, $new)` | Medium | Renames/moves file |
| `mkdir($path)` | Low | Creates directory |
| `tempnam($dir, $prefix)` | Low | Creates temporary file |
| `ZipArchive::extractTo($dest)` | High | Extracts to specified directory (path traversal) |

---

## 5. Deserialization Sink

| Function/Pattern | Risk Level | Description |
|-----------|----------|------|
| `unserialize($data)` | Critical | Deserializes object (triggers magic methods) |
| `phar://` stream wrapper | Critical | Triggers phar metadata deserialization |
| Memcached/Redis object retrieval | High | Serialized objects stored in cache |
| `json_decode()` + magic methods | Medium | Requires specific code patterns |

### Associated Magic Methods (Gadget Entry Points)
| Method | Description |
|------|------|
| `__destruct()` | Triggered on object destruction |
| `__wakeup()` | Triggered on deserialization |
| `__toString()` | Triggered on object-to-string conversion |
| `__call()` | Triggered when calling non-existent method |
| `__get()` | Triggered when accessing non-existent property |

---

## 6. SSRF Sink (Server-Side Request Forgery)

| Function | Risk Level | Description |
|------|----------|------|
| `curl_init()` + `curl_exec()` | Critical | cURL request |
| `curl_multi_exec()` | Critical | Concurrent cURL requests |
| `file_get_contents($url)` | High | When argument is a URL |
| `fopen($url, $mode)` | High | When argument is a URL |
| `SoapClient($wsdl)` | High | SOAP request |
| `SimpleXMLElement($url)` | High | Loads remote XML |
| `get_headers($url)` | High | Retrieves HTTP headers |
| `getimagesize($url)` | Medium | Retrieves remote image info |

---

## 7. XSS/SSTI Sink (Cross-Site Scripting / Template Injection)

### XSS Output Functions
| Function/Pattern | Risk Level | Description |
|-----------|----------|------|
| `echo $var` | High | Direct output (no escaping) |
| `print $var` | High | Direct output |
| `printf($format, ...)` | Medium | Formatted output |
| `sprintf($format, ...)` | Medium | Formatted string |
| `vprintf($format, $args)` | Medium | Array-argument formatted output |

### Template Engines (Unescaped Output)
| Pattern | Framework | Risk Level | Description |
|------|------|----------|------|
| `{!! $var !!}` | Laravel Blade | High | Unescaped output |
| `{:$var}` | ThinkPHP | High | Unescaped output |
| `<?= $var ?>` | Native PHP | High | Short tag output |

### SSTI Template Injection
| Pattern | Engine | Risk Level | Description |
|------|------|----------|------|
| `{{ user_input }}` | Twig | Critical | User input enters template expression |
| `{$user_input}` | Smarty | Critical | User input as template variable |
| `{php}` | Smarty | Critical | Smarty PHP tag |
| User input enters `render()`/`compile()` | General | Critical | Controllable template string |

---

## 8. XXE Sink (XML External Entity Injection)

| Function | Risk Level | Description |
|------|----------|------|
| `simplexml_load_string($xml)` | Critical | Parses XML string |
| `simplexml_load_file($file)` | Critical | Parses XML file |
| `DOMDocument::loadXML($xml)` | Critical | DOM parses XML |
| `DOMDocument::load($file)` | Critical | DOM loads XML file |
| `XMLReader::xml($xml)` | High | XMLReader parsing |
| `XMLReader::open($file)` | High | XMLReader opens file |
| `libxml_disable_entity_loader(false)` | Critical | Explicitly enables external entity loading |

---

## 9. Mass Assignment Sink

| Pattern | Framework | Risk Level | Description |
|------|------|----------|------|
| `Model::create($request->all())` | Laravel | High | Creates model with all request parameters |
| `$model->fill($request->all())` | Laravel | High | Fills model with all request parameters |
| `$model->update($request->all())` | Laravel | High | Updates model with all request parameters |
| `$guarded = []` | Laravel | Critical | No guarded fields, all mass-assignable |
| `$fillable` includes sensitive fields | Laravel | Medium | role/is_admin/status etc. |

---

## 10. NoSQL Injection Sink

### MongoDB (PHP Driver)
| Function/Pattern | Risk Level | Description |
|-----------|----------|------|
| `$collection->find($filter)` | High | When $filter contains user input |
| `$collection->findOne($filter)` | High | Same as above |
| `$collection->aggregate($pipeline)` | High | Aggregation pipeline injectable |
| `$collection->updateOne($filter, $update)` | High | `$set` in $update is controllable |
| `$collection->deleteMany($filter)` | Critical | Controllable filter causes mass deletion |
| MongoDB `$where` operator | Critical | Executes JavaScript expressions |
| MongoDB `$regex` operator | Medium | ReDoS or information leakage |
| MongoDB `$gt/$lt/$ne/$in` operators | High | Operator injection bypasses authentication |

### Laravel MongoDB (jenssegers)
| Function/Pattern | Risk Level | Description |
|-----------|----------|------|
| `Model::whereRaw($rawQuery)` | High | Raw MongoDB query |
| `Model::where($field, $operator, $value)` | Medium | When $operator is controllable |

### Redis
| Function/Pattern | Risk Level | Description |
|-----------|----------|------|
| `$redis->eval($script)` | Critical | Executes Lua script |
| `$redis->rawCommand($cmd)` | Critical | Raw command injection |

---

## 11. GraphQL Sink

| Pattern | Risk Level | Description |
|------|----------|------|
| GraphQL query with no depth limit | High | Nested query DoS |
| Mutation without authorization | Critical | Unauthenticated write operation |
| `__schema` introspection not disabled | Medium | Schema information leakage |
| User input directly concatenated into GraphQL query | High | GraphQL injection |
| Batch query with no rate limiting | Medium | Enumeration attack |
| Subscription without authentication | High | Unauthorized WebSocket access |

---

## 12. Race Condition Sink

| Pattern | Risk Level | Description |
|------|----------|------|
| Check-then-use (TOCTOU) | High | Race between file existence check and operation |
| Balance check then deduction | Critical | Double spending / overdraft |
| Non-atomic rate limiting counter | High | Concurrent bypass of rate limiting |
| Non-atomic one-time token validation | High | Token replay |
| `file_exists()` + `include()` | High | Race condition file inclusion |
| `move_uploaded_file()` + validation + deletion | High | Race condition file upload |
| File operation missing `flock()` | Medium | Concurrent write race |

---

## 13. Cache Poisoning Sink

| Pattern | Risk Level | Description |
|------|----------|------|
| `Cache::put($key, $userInput)` | High | Controllable cache content |
| `Cache::remember($key, $ttl, $callback)` | Medium | Controllable cache key leads to poisoning |
| Improper HTTP cache headers | Medium | Incorrect `Cache-Control`/`Vary` causes cross-user caching |
| CDN/Reverse proxy cache | High | Web cache poisoning (parameters, headers) |
| Session stored in shared cache | Medium | Session confusion |
| Template cache write | High | Template cache injection for persistent XSS/RCE |

---

## 14. Cryptography Sink

| Function/Pattern | Risk Level | Description |
|-----------|----------|------|
| `md5($password)` / `sha1($password)` | High | Insecure password hashing (no salt, fast hash) |
| `rand()` / `mt_rand()` | High | Insecure random number generation (predictable) |
| `openssl_encrypt` using ECB mode | High | ECB mode leaks data patterns |
| Hardcoded IV / zero IV | High | Non-random initialization vector |
| `mcrypt_*` | High | Deprecated encryption library |
| `base64_encode` used as "encryption" | Critical | Encoding is not encryption |
| `crc32` / `adler32` used for integrity checks | Medium | Easily collided |
| `password_hash` using `PASSWORD_DEFAULT` | Low | Secure but cost parameter SHOULD be verified |
| JWT using HS256 + weak secret | High | Secret can be brute-forced |

---

## 15. WordPress-Specific Sink

| Function/Pattern | Risk Level | Description |
|-----------|----------|------|
| `$wpdb->query($sql)` | Critical | Raw SQL (not prepared) |
| `$wpdb->get_results($sql)` | High | Same as above |
| `update_option($key, $value)` | High | Overwrites arbitrary configuration |
| `update_user_meta($id, $key, $value)` | High | Modifies user metadata |
| `wp_set_auth_cookie($user_id)` | Critical | Directly sets auth cookie |
| `do_shortcode($content)` | High | Shortcode injection |
| `call_user_func` in Hooks | High | Callback control |
| `wp_remote_get($url)` | High | SSRF |
| `wp_mail` 5th parameter | High | Mail header injection |
| `sanitize_text_field` misuse | Medium | Not suitable for SQL/HTML context |
| `wp_kses_post` improper use | Medium | Allows partial HTML |
| `is_admin()` used for authorization check | Critical | Only checks if on admin page, not permission check |

---

## Supplementary Notes on Vulnerability Pattern Recognition for All Sink Categories

> The following are **Vulnerability Pattern Recognition** supplementary notes for the Sink categories listed above.
> The focus is not only on function names themselves, but on distinguishing **context patterns** and **direct calls vs. indirect calls**.

### RCE Sink Vulnerability Pattern Recognition
- **Direct Call**: `eval($_GET['code'])` — parameter directly sourced from user input with no filtering.
- **Indirect Call**: User input stored in database/cache, later read and executed by `eval()` or `create_function()` (second-order injection pattern).
- **Context Pattern**: Parameter originates from `$_GET` / `$_POST` / `$_REQUEST` and is passed directly to `system()` / `exec()` without being wrapped by `escapeshellarg()` / `escapeshellcmd()`.
- **Variable Function Pattern**: `$func = $_GET['action']; $func();` — controllable function name equals RCE.
- **Callback Abuse Pattern**: `array_map($_GET['func'], $data)` — controllable callback parameter is equivalent to code execution.

### SQL Sink Vulnerability Pattern Recognition
- **Direct Call**: `$pdo->query("SELECT * FROM users WHERE id=" . $_GET['id'])` — string concatenation in SQL.
- **Indirect Call**: ORM's `whereRaw($userInput)` vs safe `where('id', $userInput)` — the former is dangerous, the latter is parameterized.
- **Context Pattern**: Parameter originates from `$_GET` and is concatenated directly into numeric SQL fields without `intval()` / `(int)` type casting.
- **Framework Pitfall**: Laravel `DB::raw()` nested inside `->where()` is easily overlooked: `->where(DB::raw("id = $input"))`.
- **ORDER BY Injection**: `->orderByRaw($_GET['sort'])` — ORDER BY cannot use parameter binding, often missed.

### File Inclusion Sink Vulnerability Pattern Recognition
- **Direct Call**: `include $_GET['page'] . '.php'` — controllable path; even with suffix appended, can be bypassed via `%00` (PHP < 5.3.4) or long path truncation.
- **Indirect Call**: Config file `$template = $config['theme'];` then `include $template` — forms indirect inclusion when config is user-modifiable.
- **Context Pattern**: `file_get_contents($_GET['url'])` serves as both SSRF + file read Sink; note protocol wrappers such as `php://filter`.

### File Write Sink Vulnerability Pattern Recognition
- **Direct Call**: `file_put_contents($_GET['file'], $_POST['data'])` — both filename and content are controllable.
- **Indirect Call**: Uploaded filename not randomized, `move_uploaded_file($tmp, 'uploads/' . $_FILES['f']['name'])` — can write `.php` extension.
- **Context Pattern**: Extraction operation `ZipArchive::extractTo()` without validating file paths inside the archive, leading to `../` path traversal writing to arbitrary locations.

### Deserialization Sink Vulnerability Pattern Recognition
- **Direct Call**: `unserialize($_COOKIE['data'])` — deserialization source is client-controllable data.
- **Indirect Call**: `phar://` protocol trigger — `file_exists('phar://user_upload.jpg')` can trigger phar metadata deserialization.
- **Context Pattern**: Second parameter `allowed_classes` of `unserialize()` is not set or set to `true`, allowing arbitrary class instantiation.

### SSRF Sink Vulnerability Pattern Recognition
- **Direct Call**: `curl_setopt($ch, CURLOPT_URL, $_GET['url']); curl_exec($ch);` — URL is directly controllable.
- **Indirect Call**: `file_get_contents($config['webhook_url'])` — webhook URL configured in admin panel; if admin account is compromised, SSRF occurs.
- **Context Pattern**: Only checking `http://` / `https://` prefix without validating target IP (can be bypassed via DNS Rebinding). Internal addresses `127.0.0.1` / `169.254.169.254` / `10.x.x.x` SHOULD be blacklisted.

### XSS/SSTI Sink Vulnerability Pattern Recognition
- **Direct Call**: `echo $_GET['name']` — input directly output without `htmlspecialchars()` escaping.
- **Indirect Call**: Stored in database then rendered on page — `echo $article->content` — stored XSS.
- **Context Pattern**: Distinguish HTML context, JavaScript context, URL context — `htmlspecialchars()` is insufficient in JS context, MUST use `json_encode()` + `JSON_HEX_TAG`.
- **Template Engine**: Blade `{!! $var !!}` vs `{{ $var }}` — the former is unescaped, the latter auto-escapes.

### XXE Sink Vulnerability Pattern Recognition
- **Direct Call**: `simplexml_load_string($_POST['xml'])` — without calling `libxml_disable_entity_loader(true)` or setting the `LIBXML_NOENT` flag.
- **Context Pattern**: In PHP 8.0+, `libxml_disable_entity_loader()` is deprecated; MUST use the `LIBXML_NOENT` flag instead. Easily missed during legacy code migration.

### Mass Assignment Sink Vulnerability Pattern Recognition
- **Direct Call**: `User::create($request->all())` with `$fillable` including `role` / `is_admin`.
- **Indirect Call**: `$model->forceFill($request->all())` — bypasses `$fillable` protection.
- **Context Pattern**: Check for `$guarded = []` (empty array) which means all fields are mass-assignable, extremely dangerous.

---

## 16. JWT-Related Sink

> Common security pitfalls of JWT (JSON Web Token) in PHP, covering token parsing, signature verification, algorithm confusion, and more.

| Function/Pattern | Risk Level | Context Pattern Description |
|-----------|----------|----------------|
| `JWT::decode($token, $key, [])` — algorithm array is empty | Critical | In the `firebase/php-jwt` library, `JWT::decode()` third parameter does not specify allowed algorithms, allowing attackers to set `alg` to `none` in the header to bypass signature verification. **Correct approach**: specify `['HS256']` or use a `Key` object to explicitly bind the algorithm. |
| `JWT::decode($token, $key)` — no distinction between HS256 / RS256 | Critical | Algorithm Confusion attack: when the server uses an RSA public key for verification, the attacker changes `alg` to `HS256` and signs with the public key as the HMAC secret, causing verification to pass. **Context pattern**: check whether decode uses `new Key($publicKey, 'RS256')` to explicitly bind the algorithm. |
| Manually `base64_decode()` + `json_decode()` to parse JWT | High | Manually splitting JWT (`explode('.', $token)`) then `base64_decode` + `json_decode` to read payload, but **skipping signature verification**. Attackers can arbitrarily tamper with payload contents (e.g., `user_id`, `role`). |
| `openssl_verify()` return value uses `==` instead of `===` | High | `openssl_verify()` returns `1` (success), `0` (failure), `-1` (error). Using `if(openssl_verify(...) == true)`, `-1` is also treated as `true` (PHP type coercion), causing verification to pass on error. MUST use `=== 1` for strict comparison. |
| JWT `exp` / `nbf` claims not validated | Medium | After decoding JWT, `exp` (expiration) or `nbf` (not-before) are not checked, causing expired tokens to remain valid indefinitely. Some libraries require explicit `leeway` configuration. |
| JWT Secret hardcoded or weak key | High | `JWT::encode($payload, 'secret123', 'HS256')` — using short/predictable key; attackers can brute-force it. **Context pattern**: check whether key comes from `env()` or config file, and whether length is >= 256 bits. |
| `kid` Header parameter injection | Critical | If the `kid` (Key ID) field in JWT header is directly concatenated into file paths or SQL queries (e.g., `file_get_contents("/keys/" . $header->kid)`), it can lead to directory traversal or SQL injection to obtain arbitrary keys. |

---

## 17. Open Redirect Sink

> Open redirect vulnerabilities allow attackers to construct legitimate domain URLs that redirect users to malicious websites, commonly used for phishing attacks.

| Function/Pattern | Risk Level | Context Pattern Description |
|-----------|----------|----------------|
| `header("Location: " . $userInput)` | Critical | User input directly concatenated into the `Location` response header. **Context pattern**: parameter originates from `$_GET['redirect']` / `$_GET['url']` / `$_GET['next']` / `$_GET['return_to']` and similar common parameter names without allowlist validation. Attacker can set it to `https://evil.com`. |
| `header("Location: " . $url)` with prefix-only check | High | Using `strpos($url, 'https://example.com') === 0` for validation, but can be bypassed by `https://example.com.evil.com`. **Correct approach**: use `parse_url()` to extract host and strictly compare against allowlist. |
| Laravel `redirect($userInput)` / `Redirect::to($userInput)` | High | Framework `redirect()` helper accepts full URLs (including external domains). **Context pattern**: check whether the parameter passed to `redirect()` comes from user input without `url()->isValidUrl()` or domain allowlist validation. |
| ThinkPHP `$this->redirect($url)` | High | ThinkPHP controller `redirect()` method also accepts external URLs. **Context pattern**: parameter comes from `input('get.url')` or `$request->param('url')` without validation. |
| `<meta http-equiv="refresh" content="0;url=$userInput">` | High | HTML meta tag redirect with user input embedded after `url=`. Common in frontend templates like `<meta ... content="0;url=<?= $redirect ?>">`. Even if `header()` is protected, HTML-level redirects MUST also be checked. |
| JavaScript `window.location = phpVar` | Medium | PHP assigns user input to a JavaScript variable used for redirection: `<script>window.location = '<?= $url ?>';</script>`. MUST guard against both XSS and Open Redirect. |
| `wp_redirect($url)` without `$safe` parameter | High | WordPress `wp_redirect()` does not restrict target domain by default. SHOULD use `wp_safe_redirect()` instead, which only allows redirection to allowlisted domains. |

---

## 18. CORS Configuration Sink (Cross-Origin Resource Sharing Misconfiguration)

> CORS misconfiguration can lead to cross-origin data theft, especially when `Access-Control-Allow-Credentials: true` is used.

| Function/Pattern | Risk Level | Context Pattern Description |
|-----------|----------|----------------|
| `header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN'])` | Critical | The `Origin` header from the request is directly echoed as `Access-Control-Allow-Origin`, equivalent to allowing access from any domain. **Context pattern**: check whether `$_SERVER['HTTP_ORIGIN']` is directly concatenated into the response header without allowlist validation. |
| `Access-Control-Allow-Credentials: true` + dynamic Origin echo | Critical | When both `Access-Control-Allow-Credentials: true` and dynamic Origin echo are set, attackers can read authenticated user's sensitive data from malicious sites (cookies are sent). **This is the most dangerous CORS configuration combination.** |
| `Access-Control-Allow-Origin: *` + sensitive API | High | Although `*` does not allow credentials, it is still dangerous for sensitive data that doesn't require authentication (e.g., internal APIs, public user information). **Context pattern**: check whether APIs using `*` return any information that SHOULD NOT be public. |
| Origin allowlist validation using improper `strpos()` / `preg_match()` | High | `if(strpos($origin, 'example.com') !== false)` can be bypassed by `evil-example.com` or `example.com.evil.com`. **Correct approach**: exact domain match `in_array($origin, $allowedOrigins)`. |
| `Access-Control-Allow-Headers` includes `Authorization` but Origin is unrestricted | High | Allows cross-origin sending of the `Authorization` header (e.g., Bearer Token), but Origin has no allowlist, enabling any site to send requests with the token. **Context pattern**: check whether preflight response `Allow-Headers` contains sensitive headers while Origin is unrestricted. |
| Laravel `cors.php` config `'allowed_origins' => ['*']` | Medium | Laravel framework `config/cors.php` has `allowed_origins` set to wildcard. MUST be evaluated together with `supports_credentials` field: if `supports_credentials = true`, the risk is Critical. |
| Nginx/Apache layer CORS config overrides application layer | Medium | Web server level config `add_header Access-Control-Allow-Origin *` overrides PHP application layer's fine-grained CORS policy, rendering application-level allowlists ineffective. **Context pattern**: MUST audit both `.htaccess` / Nginx conf and PHP code. |

---

## 19. HTTP Method Check Missing Sink (Improper HTTP Method Restriction)

> Failure to properly restrict HTTP methods can lead to CSRF bypass, information leakage, and unintended operations.

| Pattern | Risk Level | Context Pattern Description |
|------|----------|----------------|
| Route registers only GET/POST but does not restrict TRACE/OPTIONS etc. | High | Web servers with TRACE enabled by default can lead to Cross-Site Tracing (XST) attacks, leaking `HttpOnly` cookies. **Context pattern**: check whether Apache has `TraceEnable Off` configured; Nginx does not support TRACE by default but custom config MAY enable it. |
| `Route::any($uri, $handler)` route registration | High | Laravel `Route::any()` / ThinkPHP `Route::rule($uri, $handler)` matches all HTTP methods by default. **Context pattern**: when sensitive operations (e.g., delete, change password) use `any()`, they can be triggered by GET requests (CSRF via `<img src>`), bypassing CSRF token protection (since GET typically doesn't check tokens). |
| Middleware only intercepts specific methods, missing others | High | CSRF Middleware typically excludes GET/HEAD/OPTIONS, but if routes also accept PUT/PATCH/DELETE and Middleware doesn't cover these methods, they can be bypassed. **Context pattern**: check `VerifyCsrfToken` Middleware's `$except` list and method filtering logic. |
| REST API does not restrict DELETE/PUT methods | Critical | API routes lack additional permission checks for DELETE/PUT methods. **Context pattern**: `Route::resource()` auto-registers `destroy` (DELETE) and `update` (PUT) methods; if these Controller actions lack independent permission checks (relying only on unified `auth` Middleware), regular users MAY delete/modify other users' resources. |
| `$_SERVER['REQUEST_METHOD']` check can be overridden | High | Frameworks like Laravel support `_method` parameter to override HTTP method: `<input type="hidden" name="_method" value="DELETE">`. **Context pattern**: check for method spoofing without CSRF protection in forms; attackers can use this mechanism to send DELETE/PUT requests. |
| HEAD method information leakage | Medium | HEAD requests typically return the same response headers as GET but without body. Some APIs leak sensitive information in headers (e.g., `X-Total-Count`, custom debug headers). **Context pattern**: check for cases where permission checks apply only to GET but HEAD method is not covered. |
| WebDAV methods not disabled | High | PROPFIND, MKCOL, COPY, MOVE and other WebDAV methods, if not disabled at the web server level, can lead to directory traversal and file operations. **Context pattern**: check whether Apache loads `mod_dav` or Nginx has the dav module configured. |

## 20. CRLF Injection Sink (CRLF Injection / HTTP Response Splitting)

> CRLF injection inserts `\r\n` line breaks into HTTP headers, which can lead to response splitting, XSS, cache poisoning, and Session Fixation.

| Pattern | Risk Level | Context Pattern Description |
|------|----------|----------------|
| `header("Location: " . $userInput)` | Critical | User input directly concatenated into Location header; if `\r\n`/`%0d%0a` is not filtered, arbitrary headers can be injected. PHP >=7.0 checks for multi-line headers but framework wrappers MAY bypass this. |
| `header("X-Custom: " . $value)` | High | Custom header value contains user input. Attacker injects `\r\nSet-Cookie: session=evil` to achieve Session Fixation. |
| `setcookie($name, $value)` where `$name`/`$value` comes from user input | High | `\r\n` in cookie name/value can inject additional Set-Cookie headers. PHP 7.0+ restricts `$name` but `$value` still MUST be checked. |
| `mail($to, $subject, $body, $additionalHeaders)` | Critical | When `$additionalHeaders` contains user input, CC/BCC/Content-Type and other mail headers can be injected, enabling mail hijacking or phishing. |
| `$response->header($key, $value)` framework response header setting | High | Laravel/Symfony Response objects setting headers; if `$value` does not filter line breaks, it MAY bypass PHP native `header()` checks. |
| `header("Content-Disposition: attachment; filename=\"$filename\"")` | High | Filename containing `\r\n` can inject additional headers; combined with `Content-Type` injection to achieve XSS. |

## 21. CSRF Sink (Cross-Site Request Forgery)

> CSRF exploits the browser's automatic cookie-sending behavior to trick authenticated users into performing unintended actions.

| Pattern | Risk Level | Context Pattern Description |
|------|----------|----------------|
| POST form without `csrf_token`/`_token` hidden field | Critical | State-changing form missing CSRF Token. Check whether `<form method="POST">` includes `@csrf`(Laravel)/`csrf_token()`(Symfony)/`__token__`(ThinkPHP). |
| `VerifyCsrfToken::$except` exclusion list too broad | High | Laravel CSRF middleware's `$except` array contains wildcards (e.g., `api/*`, `webhook/*`), potentially exposing sensitive operations. |
| AJAX request without `X-CSRF-TOKEN` header | High | Frontend AJAX calls to POST/PUT/DELETE endpoints without reading Token from `<meta name="csrf-token">` or cookie and attaching it to the request header. |
| `Route::any()` / `Route::match(['get','post'])` | High | State-changing operation accepts GET requests simultaneously, bypassing CSRF protection (GET typically doesn't check Token). |
| API route using session auth but no CSRF protection | Critical | `api.php` routes use the `web` middleware group (with session), but APIs typically don't check CSRF Token. |
| Lax custom CSRF implementation validation | High | Self-implemented Token validation logic has flaws: empty values pass, Token not rotated, predictable Token generation algorithm. |
| `session.cookie_samesite` not set or set to `None` | High | SameSite not configured in php.ini or `session_set_cookie_params()`; default browser behavior varies by version. |

## 22. Session/Cookie Security Sink

> Session management flaws can lead to Session Fixation, Session Hijacking, and sensitive data leakage.

| Pattern | Risk Level | Context Pattern Description |
|------|----------|----------------|
| `session_start()` then auth succeeds but `session_regenerate_id(true)` not called | Critical | Core Session Fixation flaw: attacker pre-sets Session ID; after victim logs in, the ID is not rotated, allowing the attacker to reuse it directly. |
| `session.cookie_httponly = 0` or `setcookie()` without HttpOnly | Critical | Session cookie readable by JavaScript (`document.cookie`); XSS → Session Hijacking chain is complete. |
| `session.cookie_secure = 0` on an HTTPS site | High | Session cookie transmitted in HTTP cleartext. MITM can intercept Session ID. |
| `session.use_strict_mode = 0` | High | PHP accepts client-submitted uninitialized Session IDs, a prerequisite for Session Fixation. |
| `session.use_only_cookies = 0` | High | Allows Session ID via URL parameter (`?PHPSESSID=xxx`); Referer leakage + logging risk. |
| Logout flow does not fully destroy Session | High | Only calls `session_destroy()` without clearing cookie and `$_SESSION`, or without invalidating the old ID. |
| `/tmp/sess_*` file permissions 0644 (shared hosting) | High | On shared hosting, other users can read Session files, leaking Session data. |
| `session.serialize_handler` inconsistency | Critical | Different code paths use different serialization handlers (php/php_serialize), which can lead to Session deserialization injection. |

## 23. LDAP Injection Sink

> LDAP injection inserts special characters into LDAP query filters or DNs, which can lead to authentication bypass, data leakage, and privilege escalation.

| Pattern | Risk Level | Context Pattern Description |
|------|----------|----------------|
| `ldap_search($conn, $dn, "(uid=" . $userInput . ")")` | Critical | User input directly concatenated into LDAP filter. Attacker injects `*)(uid=*))(|(uid=*` to enumerate all users. |
| `ldap_bind($conn, $userDN, $password)` where `$password` is empty string | Critical | LDAP anonymous bind or empty password bind; some LDAP servers accept empty passwords as successful authentication. |
| `ldap_search($conn, $baseDN, $filter)` where `$filter` comes from form | High | Search filter contains user input; OR/AND logical operators can be injected to alter query semantics. |
| Symfony `LdapAdapter` / `adldap2` query construction | High | Framework LDAP package query builders using string concatenation instead of parameterization are equally vulnerable to injection. |
| `ldap_add()`/`ldap_modify()` with attribute values from user input | High | Injecting additional attributes (e.g., `userPassword`) in write operations can lead to privilege escalation. |
| LDAP DN concatenation: `"cn=" . $username . ",ou=users,dc=example"` | High | DN component injection can lead to accessing resources under different OUs. Special characters `,`, `+`, `"`, `\`, `<`, `>`, `;` MUST be escaped. |

## 24. Logging Security Sink

> Logging security flaws can lead to log injection (forged entries), sensitive data leakage, log file web exposure, and log inclusion RCE.

| Pattern | Risk Level | Context Pattern Description |
|------|----------|----------------|
| `error_log($userInput)` / `Log::info($userInput)` | High | User input directly written to logs. Injecting `\n[2024-01-01] CRITICAL:` can forge log entries, interfering with security monitoring. |
| `Log::info("Login: " . $username . " password: " . $password)` | Critical | Passwords/Tokens/API Keys and other sensitive data logged in plaintext. Violates compliance requirements (PCI-DSS, GDPR). |
| Log file stored in `public/` or `storage/logs/` and web-accessible | Critical | `storage/logs/laravel.log` can be directly downloaded to leak all logs if not blocked by `.htaccess`/nginx rules. |
| `ini_set('display_errors', '1')` in production | High | Error messages (containing file paths, SQL statements, stack traces) displayed directly to users. |
| Log file include: `include($logPath)` | Critical | If attacker controls log content (injects `<?php system($cmd); ?>`) and the log file is included, RCE is achieved. |
| Missing audit of critical security events | High | Login failures, permission changes, password resets, and other security events not logged, affecting forensics and real-time alerting. |
