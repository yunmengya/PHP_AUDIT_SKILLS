# Smart Pivot Protocol (Stuck Detection)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-103 |
| Category | Shared Protocol |
| Responsibility | Trigger structured pivot sequence when auditor encounters repeated attack failures to find alternative paths before giving up |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Current attack state | Auditor runtime context | ✅ | `consecutive_failures` (int), `current_round` (int) |
| Target source code | `$WORK_DIR/targets/` | ✅ | Source files related to the current sink under attack |
| Shared findings store | `$WORK_DIR/audit_session.db` | ✅ | Cross-auditor findings, bypass techniques, leaked credentials |
| Pivot strategy decision tree | `shared/pivot_strategy.md` | ✅ | Failure pattern → pivot recommendation mappings |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Smart Pivot activates ONLY when **both**: ≥ 3 consecutive rounds failed AND current round ≥ R4 | Triggering too early wastes pivot resources on normal exploration; too late wastes rounds on hallucinated results |
| CR-2 | Execute all 4 pivot steps **in order** — do NOT skip steps | Skipping Re-Reconnaissance or Cross-Intelligence may miss viable paths, leading to premature termination |
| CR-3 | Smart Pivot MUST be attempted **before** requesting Smart Skip (S-102) | If pivot finds a new path → continue (no skip); if no paths found → proceed to Smart Skip with full documentation |
| CR-4 | If Steps 1-3 yield no viable paths, set outcome to `early_termination` and proceed to Smart Skip (S-102) — do NOT continue with rounds that have no realistic chance of success | Continuing produces hallucinated "successful" attacks that waste downstream review effort |
| CR-5 | `outcome` MUST be exactly one of `pivot_to_new_strategy` or `early_termination` — no other values allowed | Downstream consumers rely on this enum to decide next action |

## Fill-in Procedure

### Procedure A: Re-Reconnaissance (Step 1)
Re-read the target source code with fresh eyes. Fill in findings:

| Field | Fill-in Value |
|-------|--------------|
| missed_filtering | {Filtering logic or validation functions not noticed during pre-attack preparation} |
| alternative_entry_points | {Alternative entry points to the same sink — different routes, different parameters} |
| conditional_branches | {Conditional branches that may bypass the identified defense under certain conditions} |
| config_dependent_behavior | {Configuration-dependent behavior — debug mode, environment variables, feature flags} |

### Procedure B: Cross-Intelligence (Step 2)
Consult `$WORK_DIR/audit_session.db` for relevant findings from other auditors:

| Field | Fill-in Value |
|-------|--------------|
| waf_bypass_techniques | {WAF bypass techniques discovered by other auditors on the same target} |
| leaked_credentials | {Leaked credentials or configuration values that may unlock new attack surfaces} |
| related_sinks | {Related sinks that share code paths with the current target} |
| auth_bypass_methods | {Authentication bypass methods that could change the attack context} |

### Procedure C: Decision Tree Matching (Step 3)
Use `shared/pivot_strategy.md` to select a new attack direction:

| Field | Fill-in Value |
|-------|--------------|
| failure_pattern | {Map current failure patterns to known pivot recommendations} |
| untried_categories | {Attack categories that remain untried} |
| selected_strategy | {Most promising next strategy based on the defense type identified} |

### Procedure D: Early Termination Decision (Step 4)
Only if Steps 1-3 yield no new viable attack paths:

| Field | Fill-in Value |
|-------|--------------|
| termination_justified | {true if no viable paths found after Steps 1-3, false otherwise} |
| justification | {Full justification for why no new paths are viable — reference specific defenses and exhausted strategies} |

### Procedure E: Assemble Pivot Record
Combine results from Steps 1-4 into the final pivot record:

| Field | Fill-in Value |
|-------|--------------|
| smart_pivot_triggered | `true` |
| trigger_round | {Current round number when pivot was activated, must be ≥ R4} |
| consecutive_failures | {Number of consecutive failed rounds, must be ≥ 3} |
| pivot_actions.re_recon_findings | {Summary from Procedure A — key new findings or "No new findings"} |
| pivot_actions.cross_intel_hits | {Array of relevant findings from Procedure B, empty array if none} |
| pivot_actions.decision_tree_match | {Pattern → Recommendation string from Procedure C, or "No matching pattern"} |
| pivot_actions.new_strategy | {Selected new strategy identifier from Procedure C, or null if terminating} |
| outcome | {`pivot_to_new_strategy` if new path found, `early_termination` if no paths found} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Pivot Record | Embedded in `exploits/{sink_id}.json` | See Pivot Record JSON below | Documents the pivot decision, actions taken, and outcome |

**Pivot Record Schema:**
```json
{
  "smart_pivot_triggered": true,
  "trigger_round": "<int, ≥ 4>",
  "consecutive_failures": "<int, ≥ 3>",
  "pivot_actions": {
    "re_recon_findings": "<string>",
    "cross_intel_hits": ["<string>"],
    "decision_tree_match": "<string>",
    "new_strategy": "<string | null>"
  },
  "outcome": "pivot_to_new_strategy | early_termination"
}
```

## Examples

### ✅ GOOD: Successful pivot via Cross-Intelligence
```json
{
  "smart_pivot_triggered": true,
  "trigger_round": 5,
  "consecutive_failures": 3,
  "pivot_actions": {
    "re_recon_findings": "Discovered alternative route /api/v2/exec that uses different filtering — no escapeshellarg() on $cmd parameter",
    "cross_intel_hits": ["WAF bypass via chunked encoding found by XSS auditor on same target"],
    "decision_tree_match": "Pattern: WAF-blocked → Recommendation: Try HTTP smuggling or chunked encoding",
    "new_strategy": "chunked_transfer_encoding_bypass"
  },
  "outcome": "pivot_to_new_strategy"
}
```
Explanation: Pivot triggered at R5 after 3 consecutive failures (CR-1 ✅). All 4 steps executed in order (CR-2 ✅). New strategy found so outcome is `pivot_to_new_strategy` (CR-5 ✅). Specific findings documented with concrete evidence. ✅

### ❌ BAD: Premature pivot and vague findings
```json
{
  "smart_pivot_triggered": true,
  "trigger_round": 2,
  "consecutive_failures": 1,
  "pivot_actions": {
    "re_recon_findings": "Nothing found",
    "cross_intel_hits": [],
    "decision_tree_match": "",
    "new_strategy": null
  },
  "outcome": "continue_trying"
}
```
What's wrong: Triggered at R2 with only 1 failure — violates activation conditions (CR-1 ❌). `re_recon_findings` is vague "Nothing found" without specifics. `outcome` is "continue_trying" which is not a valid enum value (CR-5 ❌). Should either be `pivot_to_new_strategy` or `early_termination`. ❌

### ❌ BAD: Continuing rounds after no viable paths found
```json
{
  "smart_pivot_triggered": true,
  "trigger_round": 6,
  "consecutive_failures": 4,
  "pivot_actions": {
    "re_recon_findings": "No alternative entry points found — all routes use the same sanitize() wrapper",
    "cross_intel_hits": [],
    "decision_tree_match": "No matching pattern",
    "new_strategy": null
  },
  "outcome": "pivot_to_new_strategy"
}
```
What's wrong: All steps found no viable paths (`new_strategy` is null, no cross-intel hits, no matching pattern), yet outcome is `pivot_to_new_strategy` instead of `early_termination` (CR-4 ❌). This will cause the auditor to continue with rounds that produce hallucinated results. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Activation conditions not met (< 3 failures or round < R4) | Do NOT trigger pivot — continue normal attack rounds |
| `audit_session.db` unavailable or empty | Log warning, skip Cross-Intelligence step, proceed with Steps 1, 3, 4 |
| `shared/pivot_strategy.md` not found | Log warning, skip Decision Tree Matching, rely on Re-Recon and Cross-Intelligence only |
| Pivot finds new path but strategy identifier is ambiguous | Use the most specific strategy name available; never leave `new_strategy` as a generic label |
| Smart Skip (S-102) requested before Smart Pivot attempted | Reject — Smart Pivot must be attempted first per CR-3 |
