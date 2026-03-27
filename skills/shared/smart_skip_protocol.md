# Smart Skip Protocol

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-102 |
| Category | Shared Protocol |
| Responsibility | Allow auditors to skip remaining attack rounds when continued testing is demonstrably futile |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Completed round records | Invoking auditor (S-040 ~ S-060) | ✅ | `round`, `strategy`, `result` for each completed round |
| Defense analysis | Invoking auditor | ✅ | Identified defense mechanism type and specifics |
| Smart Pivot result (S-103) | S-103 protocol output | Recommended | Whether pivot was attempted before skip |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Skip MUST NOT be used before R4 under any circumstances | Premature skip abandons viable attack paths; minimum 4 rounds required |
| CR-2 | Skip MUST NOT be used if any round resulted in `suspected` | Suspected results indicate potential vulnerability; further testing required |
| CR-3 | After skip, auditor MUST still produce final `exploits/{sink_id}.json` with all attempted rounds recorded | Missing records break audit completeness and traceability |
| CR-4 | All three activation conditions must be met simultaneously (round ≥ R4, ≥ 3 consecutive failures, clear defense identified) | Partial conditions do not justify skip |
| CR-5 | Skip justification must include all three components: attempted strategies list, analysis conclusion, bypass infeasibility reasoning | Incomplete justification invalidates the skip request |
| CR-6 | Smart Pivot (S-103) MUST be attempted before requesting skip | Skip without pivot attempt may miss alternative attack vectors |

## Fill-in Procedure

### Procedure A: Verify Activation Conditions
| Field | Fill-in Value |
|-------|--------------|
| current_round | {integer: current round number, must be ≥ 4} |
| consecutive_failures | {integer: count of consecutive failed rounds, must be ≥ 3} |
| defense_identified | {boolean: whether a clear defensive mechanism has been identified} |
| all_conditions_met | {boolean: true only if all three conditions above are satisfied} |

### Procedure B: Build Skip Request
| Field | Fill-in Value |
|-------|--------------|
| skip_requested | {boolean: true} |
| skip_after_round | {integer: the last round attempted before skip, e.g., 4, 5, 6} |
| consecutive_failures | {integer: number of consecutive failures} |
| attempted_strategies | {array: list of `{"round": N, "strategy": "name", "result": "failed"}` for every round attempted} |
| defense_mechanism | {string: specific filtering/defense mechanism identified, e.g., "Parameterized queries via PDO::prepare()", "WAF ModSecurity CRS v3.3"} |
| skip_reasoning | {string: explanation of why remaining strategies (R5-R8 or beyond) cannot bypass the identified defenses} |

### Procedure C: Produce Final Output After Skip
| Field | Fill-in Value |
|-------|--------------|
| output_file | {path: `exploits/{sink_id}.json`} |
| rounds_recorded | {array: all attempted round records in S-101 format} |
| skip_metadata | {object: the skip request from Procedure B, embedded in the output file} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Skip request record | `exploits/{sink_id}.json` → `skip_request` field | See example below | Skip justification metadata appended to the exploit file |
| Complete round records | `exploits/{sink_id}.json` → `rounds[]` array | S-101 format | All attempted rounds before skip, in standard record format |

## Examples

### ✅ GOOD: Valid skip after R4 with full justification
```json
{
  "skip_requested": true,
  "skip_after_round": 4,
  "consecutive_failures": 4,
  "attempted_strategies": [
    {"round": 1, "strategy": "basic_injection", "result": "failed"},
    {"round": 2, "strategy": "encoding_bypass", "result": "failed"},
    {"round": 3, "strategy": "comment_obfuscation", "result": "failed"},
    {"round": 4, "strategy": "advanced_bypass", "result": "failed"}
  ],
  "defense_mechanism": "Parameterized queries via PDO::prepare() — all user input is bound via placeholders, never concatenated into SQL strings",
  "skip_reasoning": "Remaining strategies (R5-R8) target WAF bypass, encoding tricks, and logic flaws. None can bypass server-side parameterized queries as the SQL structure is fixed at compile time."
}
```
Explanation ✅ Round ≥ R4, 4 consecutive failures, defense clearly identified (PDO::prepare). All three justification components present: strategies enumerated, defense mechanism specified, bypass infeasibility explained.

### ✅ GOOD: Skip at R5 after pivot attempt
```json
{
  "skip_requested": true,
  "skip_after_round": 5,
  "consecutive_failures": 3,
  "attempted_strategies": [
    {"round": 1, "strategy": "union_select", "result": "failed"},
    {"round": 2, "strategy": "blind_boolean", "result": "failed"},
    {"round": 3, "strategy": "time_based_blind", "result": "failed"},
    {"round": 4, "strategy": "stacked_queries", "result": "failed"},
    {"round": 5, "strategy": "pivot_to_error_based", "result": "failed"}
  ],
  "defense_mechanism": "Input validated by allowlist regex ^[a-zA-Z0-9_]+$ on all user-controlled parameters before SQL construction",
  "skip_reasoning": "Allowlist regex permits only alphanumeric characters and underscores. No SQL syntax characters can pass. R6-R8 strategies (second-order, out-of-band, stored procedure abuse) all require SQL metacharacters in the input."
}
```
Explanation ✅ Smart Pivot was attempted at R5 (CR-6 satisfied). All conditions met. Defense mechanism is specific and verifiable.

### ❌ BAD: Skip requested before R4
```json
{
  "skip_requested": true,
  "skip_after_round": 2,
  "consecutive_failures": 2,
  "attempted_strategies": [
    {"round": 1, "strategy": "basic_injection", "result": "failed"},
    {"round": 2, "strategy": "encoding_bypass", "result": "failed"}
  ],
  "defense_mechanism": "Input seems filtered",
  "skip_reasoning": "Tried two strategies and both failed"
}
```
What's wrong: Skip requested after only R2 — violates CR-1 (must be ≥ R4). Only 2 consecutive failures (need ≥ 3). Defense mechanism is vague ("seems filtered"). Skip reasoning lacks analysis of why remaining strategies would fail. ❌

### ❌ BAD: Skip with suspected result in history
```json
{
  "skip_requested": true,
  "skip_after_round": 5,
  "consecutive_failures": 3,
  "attempted_strategies": [
    {"round": 1, "strategy": "basic_injection", "result": "failed"},
    {"round": 2, "strategy": "encoding_bypass", "result": "suspected"},
    {"round": 3, "strategy": "comment_obfuscation", "result": "failed"},
    {"round": 4, "strategy": "advanced_bypass", "result": "failed"},
    {"round": 5, "strategy": "nested_encoding", "result": "failed"}
  ],
  "defense_mechanism": "WAF blocking common patterns",
  "skip_reasoning": "Most strategies failed, WAF is too strong"
}
```
What's wrong: Round 2 has `result: "suspected"` — violates CR-2 (skip forbidden when any round is suspected; further testing required for that vector). ❌

## Error Handling
| Error | Action |
|-------|--------|
| Skip requested before R4 | REJECT skip request; continue with next round |
| Suspected result exists in round history | REJECT skip request; investigate suspected result further before reconsidering |
| Defense mechanism not clearly identified | REJECT skip request; require specific defense identification before allowing skip |
| Missing justification component (strategies, analysis, or reasoning) | REJECT skip request; require all three components per CR-5 |
| Smart Pivot (S-103) not attempted | Issue warning; recommend attempting pivot before skip; skip may still proceed if justified |
| Final exploit file not produced after skip | HALT — violates CR-3; auditor must produce `exploits/{sink_id}.json` with all attempted rounds |
