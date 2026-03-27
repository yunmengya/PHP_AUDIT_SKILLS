# Attack Memory Write Protocol

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-105 |
| Category | Shared Protocol |
| Responsibility | Persist attack experience (successes and failures) to memory store after attack cycle ends so future audits optimize round ordering |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Attack outcome | Auditor runtime context | ✅ | `final_verdict` (confirmed/failed/partial), rounds attempted count, round results |
| Sink metadata | `$WORK_DIR/sinks/{sink_id}.json` | ✅ | `sink_type`, `sink_function`, framework, PHP version |
| Exploit results | `$WORK_DIR/exploits/{sink_id}.json` | ✅ | Successful payload, bypass technique, strategy used, failure reasons |
| Memory write tool | `tools/audit_db.sh` | ✅ | `memory-write` subcommand — SQLite WAL mode ensures concurrent safety |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | **NEVER** write records when < 3 rounds of testing were attempted | Insufficient evidence pollutes the memory store, causing future audits to skip viable strategies or prioritize weak ones |
| CR-2 | **One record per sink_id** — do NOT write multiple records for the same sink | Duplicate records corrupt future query results and inflate strategy statistics |
| CR-3 | **MUST include `framework` and `php_version`** in every record | These are key index fields for future queries — records without them are unfindable |
| CR-4 | Failure reasons MUST be specific — describe the exact defense encountered | "Did not work" is unacceptable; vague reasons provide no value to future audits |
| CR-5 | `status` MUST be exactly one of `confirmed`, `failed`, or `partial` | Downstream consumers match on this enum to filter memory store queries |

## Fill-in Procedure

### Procedure A: Determine Write Eligibility
Check the attack outcome to decide whether to write a memory record:

| Attack Outcome | Write? | Rationale |
|---------------|--------|-----------|
| ✅ Confirmed | YES — proceed to Procedure B | Future audits prioritize proven strategies |
| ❌ Failed (≥ 3 rounds attempted) | YES — proceed to Procedure C | Future audits skip known-ineffective approaches |
| ⚠️ Partial success | YES — proceed to Procedure D | Future audits know what nearly worked and what remains |
| ❌ Failed (< 3 rounds attempted) | **NO — STOP, do not write** (CR-1) | Insufficient data would pollute the memory store |

### Procedure B: Confirmed Record
Fill in for successfully exploited sinks:

| Field | Fill-in Value |
|-------|--------------|
| action | `memory-write` |
| sink_type | {Vulnerability type — e.g., `rce`, `sqli`, `xss`, `ssrf`, `lfi`} |
| framework | {Target framework — e.g., `laravel`, `thinkphp`, `wordpress`} |
| php_version | {PHP version of target — e.g., `8.1`, `7.4`} |
| status | `confirmed` |
| successful_round | {Round number where exploitation succeeded} |
| payload_type | {Category of the successful payload — e.g., `wildcard_bypass`, `union_injection`} |
| bypass_technique | {Specific technique that bypassed defenses — describe exactly what was bypassed and how} |
| strategy | {Strategy identifier used — e.g., `wildcard_and_whitespace_bypass`} |
| sink_function | {The vulnerable function — e.g., `system()`, `mysqli_query()`} |
| notes | {Additional context — what defense was missing or misconfigured} |

### Procedure C: Failed Record (≥ 3 rounds)
Fill in for sinks where all attack rounds failed:

| Field | Fill-in Value |
|-------|--------------|
| action | `memory-write` |
| sink_type | {Vulnerability type} |
| framework | {Target framework} |
| php_version | {PHP version of target} |
| status | `failed` |
| rounds_attempted | {Total number of rounds attempted, must be ≥ 3} |
| excluded_strategies | {Array of objects, each with `strategy` name and `reason` — reason MUST describe the exact defense encountered per CR-4} |
| defense_summary | {One-line summary of the overall defense mechanism — e.g., "All query paths use PDO::prepare() with positional placeholders"} |

### Procedure D: Partial Success Record
Fill in for sinks where exploitation partially succeeded:

| Field | Fill-in Value |
|-------|--------------|
| action | `memory-write` |
| sink_type | {Vulnerability type} |
| framework | {Target framework} |
| php_version | {PHP version of target} |
| status | `partial` |
| partial_round | {Round number where partial success was achieved} |
| strategy | {Strategy identifier that partially worked} |
| partial_result | {What was achieved — describe the observable effect} |
| blocking_reason | {What prevented full exploitation — the specific defense or condition} |
| notes | {What would be needed for full exploitation — conditions or bypasses that remain} |

### Procedure E: Execute Write Command
After filling in the appropriate record from Procedures B/C/D:

```bash
bash tools/audit_db.sh memory-write '<json>'
```

SQLite WAL (Write-Ahead Logging) mode automatically ensures concurrent safety when multiple auditors write simultaneously.

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Memory record (confirmed) | `audit_session.db` via `tools/audit_db.sh memory-write` | See Confirmed schema below | Records successful payload, bypass technique, and round number for future prioritization |
| Memory record (failed) | `audit_session.db` via `tools/audit_db.sh memory-write` | See Failed schema below | Records all excluded strategies with specific failure reasons |
| Memory record (partial) | `audit_session.db` via `tools/audit_db.sh memory-write` | See Partial schema below | Records partially successful strategy, what worked, and what blocked full exploitation |

**Confirmed Record Schema:**
```json
{
  "action": "memory-write",
  "sink_type": "<string>",
  "framework": "<string>",
  "php_version": "<string>",
  "status": "confirmed",
  "successful_round": "<int>",
  "payload_type": "<string>",
  "bypass_technique": "<string>",
  "strategy": "<string>",
  "sink_function": "<string>",
  "notes": "<string>"
}
```

**Failed Record Schema (≥ 3 rounds):**
```json
{
  "action": "memory-write",
  "sink_type": "<string>",
  "framework": "<string>",
  "php_version": "<string>",
  "status": "failed",
  "rounds_attempted": "<int, ≥ 3>",
  "excluded_strategies": [
    {"strategy": "<string>", "reason": "<string>"}
  ],
  "defense_summary": "<string>"
}
```

**Partial Success Record Schema:**
```json
{
  "action": "memory-write",
  "sink_type": "<string>",
  "framework": "<string>",
  "php_version": "<string>",
  "status": "partial",
  "partial_round": "<int>",
  "strategy": "<string>",
  "partial_result": "<string>",
  "blocking_reason": "<string>",
  "notes": "<string>"
}
```

## Examples

### ✅ GOOD: Confirmed RCE with specific bypass details
```json
{
  "action": "memory-write",
  "sink_type": "rce",
  "framework": "laravel",
  "php_version": "8.1",
  "status": "confirmed",
  "successful_round": 3,
  "payload_type": "wildcard_bypass",
  "bypass_technique": "$IFS substitution bypassed space filter in preg_match('/\\s/', $input)",
  "strategy": "wildcard_and_whitespace_bypass",
  "sink_function": "system()",
  "notes": "escapeshellarg() not applied to concatenated command string — only applied to first argument"
}
```
Explanation: Status is `confirmed` (CR-5 ✅). Framework and php_version included (CR-3 ✅). bypass_technique describes the exact defense bypassed with the specific regex pattern (CR-4 ✅). Single record for this sink (CR-2 ✅). ✅

### ✅ GOOD: Failed SQLi with detailed exclusion reasons
```json
{
  "action": "memory-write",
  "sink_type": "sqli",
  "framework": "thinkphp",
  "php_version": "7.4",
  "status": "failed",
  "rounds_attempted": 5,
  "excluded_strategies": [
    {"strategy": "basic_injection", "reason": "PDO prepared statements used throughout — all queries use positional ? placeholders"},
    {"strategy": "encoding_bypass", "reason": "Input cast to (int) before query via intval() on line 42"},
    {"strategy": "comment_obfuscation", "reason": "Parameterized query — SQL structure not modifiable by user input"},
    {"strategy": "wide_byte_injection", "reason": "UTF-8 encoding enforced, no GBK — SET NAMES utf8mb4 in connection config"},
    {"strategy": "time_based_blind", "reason": "Prepared statement prevents injection entirely — no observable timing difference"}
  ],
  "defense_summary": "All query paths use PDO::prepare() with positional placeholders"
}
```
Explanation: 5 rounds attempted, exceeds minimum 3 (CR-1 ✅). Each excluded strategy has a specific reason describing the exact defense (CR-4 ✅). Framework and php_version present (CR-3 ✅). ✅

### ❌ BAD: Writing record after only 1 round
```json
{
  "action": "memory-write",
  "sink_type": "xss",
  "framework": "wordpress",
  "php_version": "8.0",
  "status": "failed",
  "rounds_attempted": 1,
  "excluded_strategies": [
    {"strategy": "reflected_xss", "reason": "did not work"}
  ],
  "defense_summary": "Some filtering exists"
}
```
What's wrong: Only 1 round attempted — this record MUST NOT be written (CR-1 ❌). The failure reason "did not work" is unacceptably vague — must describe the exact defense (CR-4 ❌). defense_summary "Some filtering exists" provides no useful information for future audits. ❌

### ❌ BAD: Missing framework and duplicate record
```json
{
  "action": "memory-write",
  "sink_type": "ssrf",
  "status": "confirmed",
  "successful_round": 2,
  "payload_type": "dns_rebinding",
  "bypass_technique": "Bypassed IP check",
  "strategy": "dns_rebinding",
  "sink_function": "file_get_contents()",
  "notes": "Works"
}
```
What's wrong: Missing `framework` and `php_version` fields — these are required index fields (CR-3 ❌). bypass_technique "Bypassed IP check" is too vague — must specify which IP check and how (CR-4 ❌). notes "Works" provides no useful context for future audits. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Attack completed with < 3 rounds attempted and failed | **Do NOT write** — silently skip memory write per CR-1; this is expected behavior, not an error |
| `tools/audit_db.sh` not found or not executable | Log error and continue — memory write is non-blocking; the audit result itself is still valid |
| `audit_session.db` is locked (concurrent write conflict) | SQLite WAL mode handles this automatically — retry is built into the tool; if persistent failure, log and skip |
| Framework or PHP version unknown | Set to `"unknown"` rather than omitting — the field must exist per CR-3, and `"unknown"` is queryable |
| Multiple records attempted for same sink_id | Write only the **final** record that reflects the complete attack outcome — discard earlier drafts per CR-2 |
| Reason field contains only generic text | Rewrite with specific defense details before writing — vague records actively harm future audits per CR-4 |
