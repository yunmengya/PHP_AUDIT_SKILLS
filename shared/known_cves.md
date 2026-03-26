# Known CVEs — PHP Ecosystem High-Frequency CVE Quick Reference

Quickly compare target component versions during audits to determine whether known vulnerabilities exist. Organized by component, each entry includes complete exploitation prerequisites.

---

## Laravel

### CVE-2021-3129 — Ignition RCE (Log Poisoning + Phar)
- **Affected Versions**: Ignition < 2.5.2 (Laravel 6.x / 7.x / 8.x with debug mode)
- **Vulnerability Type**: RCE (Remote Code Execution)
- **Detection Method**: Access `/_ignition/execute-solution`; non-404 response indicates presence; check `facade/ignition` version in `composer.lock`
- **Prerequisites**: `APP_DEBUG=true`; Ignition component present and accessible; writable storage/logs
- **Exploit Chain**: Clear logs via `_ignition/execute-solution` → write phar payload byte by byte → trigger deserialization via `phar://`

### CVE-2018-15133 — APP_KEY Deserialization RCE
- **Affected Versions**: Laravel 5.5.x ~ 5.6.29
- **Vulnerability Type**: RCE (Deserialization)
- **Detection Method**: Send malicious cookie, observe whether 500 error stack exposes deserialization-related classes; requires known APP_KEY
- **Prerequisites**: MUST obtain `APP_KEY` (via `.env` leak, debug page, git leak, etc.)
- **Exploit Chain**: Encrypt malicious serialized object using APP_KEY → place in laravel_session cookie → server-side decryption triggers `unserialize()`

### CVE-2021-21263 — Query Binding Bypass (SQLi)
- **Affected Versions**: Laravel < 8.22.1
- **Vulnerability Type**: SQL Injection
- **Detection Method**: Check `composer.lock` version; search for code using `whereIn` / `whereNotIn` with user input
- **Prerequisites**: Application uses PostgreSQL; user input enters query binding without additional type validation
- **Exploit Chain**: Pass specially crafted array parameter → bypass PDO parameter binding → inject SQL fragment

### CVE-2024-13918 / CVE-2024-13919 — Laravel Reflected XSS
- **Affected Versions**: Laravel 11.9.0 ~ 11.35.1, 12.0.0 ~ 12.1.1
- **Vulnerability Type**: Reflected XSS
- **Detection Method**: Check `composer.lock` version; test whether route parameters are reflected in error pages
- **Prerequisites**: `APP_DEBUG=true` or custom error pages render user input
- **Exploit Chain**: Craft URL route parameter containing XSS payload → trigger 404/500 → error page outputs unescaped content

---

## ThinkPHP

### ThinkPHP 5.0 RCE — invokefunction Remote Code Execution
- **CVE**: No official number (CNVD-2018-24942)
- **Affected Versions**: ThinkPHP 5.0.0 ~ 5.0.23
- **Vulnerability Type**: RCE
- **Detection Method**: Send `?s=index/think\app/invokefunction&function=phpinfo&vars[0]=1`; phpinfo response confirms presence
- **Prerequisites**: Default routing enabled (typically on by default); no WAF interception
- **Exploit Chain**: Controller/method route parsing flaw → can invoke any method of any class → `call_user_func_array()` executes arbitrary functions

### ThinkPHP 5.1 SQLi — Builder Component SQL Injection
- **CVE**: No official number
- **Affected Versions**: ThinkPHP 5.1.0 ~ 5.1.25
- **Vulnerability Type**: SQL Injection
- **Detection Method**: Search for code using `order()` / `where()` with user input parameters; check framework version
- **Prerequisites**: User input directly enters `order()` / `where()` and other query builder methods
- **Exploit Chain**: Pass error-based injection functions like `updatexml` via `order` parameter → concatenated into SQL → database executes and leaks data via error

### ThinkPHP 6 Session Deserialization
- **CVE**: No official number
- **Affected Versions**: ThinkPHP 6.0.0 ~ 6.0.1
- **Vulnerability Type**: Deserialization RCE
- **Detection Method**: Check whether session config uses file driver; whether session ID comes from unfiltered user input
- **Prerequisites**: Session driver MUST be file (not Redis/Memcache); session file path controllable (session ID not strictly filtered)
- **Exploit Chain**: Control session ID → write session file containing malicious serialized data → arbitrary file creation + deserialization

### ThinkPHP Multi-Language RCE — lang Parameter Inclusion
- **CVE**: No official number (disclosed 2022)
- **Affected Versions**: ThinkPHP 5.x / 6.x with multi-language feature enabled
- **Vulnerability Type**: RCE (File Inclusion)
- **Detection Method**: Send `?lang=../../../../usr/local/lib/php/pearcmd`; observe response; check whether middleware loads `LoadLangPack`
- **Prerequisites**: Multi-language middleware enabled; PHP has pearcmd.php installed (typically present in default installations)
- **Exploit Chain**: `lang` parameter controls language file path → file inclusion → leverage `pearcmd.php` for file write → Webshell

---

## WordPress

### CVE-2022-21661 — WP_Query SQL Injection
- **Affected Versions**: WordPress < 5.8.3
- **Vulnerability Type**: SQL Injection
- **Detection Method**: Check WordPress version; search for code using `WP_Query` with `tax_query` parameters from user input
- **Prerequisites**: Functionality exists that allows user control of `WP_Query` parameters (e.g., custom REST endpoint, AJAX handler)
- **Exploit Chain**: Craft malicious `tax_query` parameter → `WP_Tax_Query::clean_query()` mishandles → SQL injection

### CVE-2019-8942 — WordPress Image RCE (Crop Feature)
- **Affected Versions**: WordPress < 5.0.1 / < 4.9.9
- **Vulnerability Type**: RCE (via Post Meta Overwrite + Path Traversal)
- **Detection Method**: Check WP version; requires at least Author privileges
- **Prerequisites**: Attacker has Author role or above; server uses GD/Imagick library
- **Exploit Chain**: Upload image with malicious EXIF → exploit path traversal in `wp_crop_image()` to overwrite → modify post meta to point to malicious file → include and execute

### WordPress REST API Authorization Bypass (CVE-2017-1001000)
- **Affected Versions**: WordPress 4.7.0 ~ 4.7.1
- **Vulnerability Type**: Authorization Bypass → Content Injection
- **Detection Method**: Send `POST /wp-json/wp/v2/posts/1?id=1abc`; ability to modify content confirms presence
- **Prerequisites**: REST API enabled (enabled by default in WordPress 4.7+); target has Posts
- **Exploit Chain**: Exploit type casting flaw by passing non-integer ID in URL → bypass permission check → unauthenticated modification of arbitrary posts

### CVE-2023-2745 — WordPress Directory Traversal
- **Affected Versions**: WordPress < 6.2.1
- **Vulnerability Type**: Directory Traversal → Information Disclosure
- **Detection Method**: Check WP version; try `wp-login.php?wp_lang=../../../etc/passwd%00`
- **Prerequisites**: Attacker can access `wp-login.php`
- **Exploit Chain**: `wp_lang` parameter path traversal → include arbitrary `.mo` file → information disclosure / combined with file upload for RCE

---

## Common Components

### PHPUnit RCE — eval-stdin.php Remote Code Execution
- **CVE**: CVE-2017-9841
- **Affected Versions**: PHPUnit 4.8.19 ~ 4.8.27, 5.x ~ 5.6.2
- **Vulnerability Type**: RCE
- **Detection Method**: Access `vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`; non-404 response confirms presence
- **Prerequisites**: `vendor/` directory accessible via Web (dev dependencies not removed in production or web root misconfigured)
- **Exploit Chain**: POST request sends PHP code to `eval-stdin.php` → directly `eval()` executed

### PHPMailer RCE — CVE-2016-10033 / CVE-2016-10045
- **Affected Versions**: PHPMailer < 5.2.18 (10033), < 5.2.20 (10045 patch bypass)
- **Vulnerability Type**: RCE (mail() argument injection)
- **Detection Method**: Check phpmailer version in `composer.lock`; search whether `Sender` / `setFrom()` accepts user input
- **Prerequisites**: Application uses `mail()` as transport (not SMTP); user-controllable sender/from address
- **Exploit Chain**: Inject `-X` / `-OQueueDirectory` arguments in email address → Sendmail writes file to web directory → Webshell

### Guzzle SSRF — CVE-2022-29248 / CVE-2022-31042 / CVE-2022-31043
- **Affected Versions**: Guzzle < 7.4.4 (cookie / header cross-domain leak), all versions (SSRF depends on usage)
- **Vulnerability Type**: SSRF / Credential Leakage
- **Detection Method**: Search for `GuzzleHttp\Client` usage; check whether URL comes from user input; check version
- **Prerequisites**: User-controllable request target URL or partial URL (host/path/query)
- **Exploit Chain**: Pass internal network URL → Guzzle makes server-side request → access cloud metadata / internal services → information disclosure or further attacks

### Monolog RCE — Deserialization Gadget Chain
- **CVE**: No official CVE (POP chain component)
- **Affected Versions**: Monolog 1.x ~ 3.x (as part of deserialization chain)
- **Vulnerability Type**: Deserialization → RCE (POP Gadget)
- **Detection Method**: Confirm deserialization entry point exists; monolog present in `composer.lock`
- **Prerequisites**: Application has a triggerable `unserialize()` entry point; Monolog is within autoload scope
- **Exploit Chain**: Construct `Monolog\Handler\BufferHandler` → nest `SyslogUdpHandler` → `__destruct()` triggers → file write / command execution

### Symfony Debug RCE — CVE-2021-21381
- **Affected Versions**: Symfony 3.4.x ~ 5.x (HttpKernel debug mode)
- **Vulnerability Type**: RCE (via _fragment route)
- **Detection Method**: Access `/_fragment`; 500 response instead of 404 indicates route exists; requires obtaining APP_SECRET
- **Prerequisites**: Debug mode or `_fragment` route enabled; known `APP_SECRET` (can be leaked via `/_profiler`)
- **Exploit Chain**: Sign `_fragment` URL using APP_SECRET → `HttpKernel::handleSubRequest()` → execute arbitrary controller

### Twig SSTI — Server-Side Template Injection
- **CVE**: No fixed CVE (improper code usage)
- **Affected Versions**: All Twig versions (depends on usage)
- **Vulnerability Type**: SSTI → RCE
- **Detection Method**: Input `{{7*7}}`; response of 49 confirms presence; check for `Twig\Environment::createTemplate()` usage
- **Prerequisites**: User input is passed as a template string to Twig (not as a template variable)
- **Exploit Chain**: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` → RCE

---

## PHP Runtime Security Fixes

### PHP 8.x Key Security Changes

| PHP Version | Security Fix | Impact |
|-------------|-------------|--------|
| PHP 8.0.0 | `libxml_disable_entity_loader()` deprecated, external entities disabled by default | XXE largely ineffective on PHP 8.0+ (unless `LIBXML_NOENT` explicitly enabled) |
| PHP 8.0.0 | `assert()` no longer executes string code | `assert($userInput)` no longer viable as RCE vector |
| PHP 8.1.0 | `$GLOBALS` becomes read-only copy | Variable overwrite techniques via `$GLOBALS` no longer work |
| PHP 8.1.0 | Fibers introduced | New async code MAY introduce race conditions |
| PHP 8.2.0 | Dynamic properties deprecated | Some deserialization gadget chains MAY need adjustment |
| PHP 8.3.0 | `json_validate()` added | No security impact, but can detect if application runs 8.3+ |

### PHP 7.x Legacy Security Issues

| PHP Version | CVE / Issue | Type |
|-------------|------------|------|
| PHP 7.0 ~ 7.4 | CVE-2019-11043 | Nginx + php-fpm path handling RCE |
| PHP 7.0 ~ 7.2 | `mt_rand()` seed predictable | Cryptographic security flaw |
| PHP < 7.4.21 | CVE-2021-21705 | `filter_var()` SSRF / URL validation bypass |
| PHP < 7.3.29 | CVE-2021-21702 | SOAP client null pointer DoS |

### CVE-2019-11043 — PHP-FPM + Nginx RCE
- **Affected Versions**: PHP 7.1.x ~ 7.3.x (specific versions), PHP-FPM
- **Vulnerability Type**: RCE (Buffer Underflow)
- **Detection Method**: Scan using `phuip-fpizdam` tool; check `fastcgi_split_path_info` regex in Nginx config
- **Prerequisites**: Nginx config uses specific `fastcgi_split_path_info` regex with `PATH_INFO`; PHP-FPM
- **Exploit Chain**: Send specially crafted URL containing `%0a` → `fastcgi_split_path_info` regex match anomaly → env variable underflow → overwrite PHP-FPM worker config → RCE

### CVE-2024-4577 — PHP CGI Argument Injection (Windows)
- **Affected Versions**: PHP 8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8 (Windows only)
- **Vulnerability Type**: RCE (CGI Argument Injection)
- **Detection Method**: Windows + PHP CGI mode; send `?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input`
- **Prerequisites**: Windows system; PHP running in CGI mode (not PHP-FPM/Apache mod_php)
- **Exploit Chain**: Windows Best-Fit character mapping converts `%AD` (soft hyphen) to `-` → inject PHP CLI arguments → `-d` modifies config → `auto_prepend_file=php://input` → RCE

---

## Quick Reference: Index by Vulnerability Type

| Vulnerability Type | Related CVEs |
|-------------------|-------------|
| RCE | CVE-2021-3129, CVE-2018-15133, ThinkPHP 5.0, CVE-2017-9841, CVE-2016-10033, CVE-2019-11043, CVE-2019-8942, CVE-2024-4577 |
| SQLi | CVE-2021-21263, ThinkPHP 5.1, CVE-2022-21661 |
| Deserialization | CVE-2018-15133, ThinkPHP 6 Session, Monolog chain |
| SSRF | Guzzle CVE-2022-29248 |
| SSTI | Twig (usage-dependent) |
| Auth Bypass | CVE-2017-1001000 (WordPress REST API) |
| XSS | CVE-2024-13918, CVE-2024-13919 |
| File Inclusion | ThinkPHP Multi-Language, CVE-2023-2745 |
