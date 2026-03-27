# Context Compression Protocol

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-107 |
| Category | Shared Protocol |
| Responsibility | Manage token budget during multi-round attack loops by compressing completed rounds into summary tables |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Attack round details | Current auditor's context window | Yes | Round number, strategy used, payload summary, HTTP result, key findings |
| `{sink_id}_plan.json` | `$WORK_DIR/` | Yes | `compressed_rounds`, `current_round`, `remaining_budget_hint` |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Compression MUST be performed after every **3 completed attack rounds** (after R3, R6, R9, …) | Context window overflow, loss of analysis capacity for subsequent rounds |
| CR-2 | Round summary table, eliminated paths list, key findings, and full details of the most recent round MUST be retained after compression | Loss of critical intelligence needed for subsequent round strategy selection |
| CR-3 | Strategies listed in the eliminated paths list MUST NOT be retried in subsequent rounds | Wasted rounds repeating proven-ineffective strategies |
| CR-4 | Full HTTP request/response bodies, step-by-step reasoning, duplicate source code refs, and raw tool output from earlier rounds MUST be removed during compression | Token budget exhausted, insufficient space for new rounds |
| CR-5 | The `compressed_rounds` field in `{sink_id}_plan.json` MUST be updated after each compression | Plan file becomes stale, round tracking and strategy continuity breaks |

## Fill-in Procedure

### Procedure A: Build Compressed Summary Table

After every 3 completed rounds, compress the detailed records into a summary table:

| Field | Fill-in Value |
|-------|--------------|
| Range | {Round range, e.g. `R1-R3`} |
| Per-round row: Round | {Round number, e.g. `R1`} |
| Per-round row: Strategy | {Attack strategy name, e.g. `Basic command separators`} |
| Per-round row: Payload Summary | {Key payloads tried, e.g. `;id / \|id / $(id)`} |
| Per-round row: Result | {HTTP status and outcome, e.g. `❌ 403 WAF blocked`} |
| Per-round row: Key Findings | {Discoveries from this round, e.g. `ModSecurity CRS activated`} |

### Procedure B: Assemble Retained Content

After compression, the context MUST contain exactly these items:

| Retained Item | Fill-in Value |
|---------------|--------------|
| Round summary table | {Markdown table from Procedure A covering all compressed rounds} |
| Eliminated paths list | {Comma-separated strategies proven ineffective — subsequent rounds MUST NOT retry these} |
| Key findings | {WAF type, filtering rules, exploitable characteristics discovered across all rounds} |
| Full details of most recent round | {Complete HTTP request/response and analysis of the latest round — MUST remain intact} |

### Procedure C: Remove Verbose Content

During compression, remove the following from earlier rounds:

| Removed Content | Description |
|----------------|-------------|
| HTTP request/response bodies | Full bodies from rounds prior to the most recent |
| Step-by-step analysis reasoning | Detailed reasoning text from earlier rounds |
| Duplicate source code references | Already recorded in pre-attack preparation |
| Raw tool output | Retain only key result lines from tool invocations |

### Procedure D: Update Plan JSON

After each compression, update `{sink_id}_plan.json` with the new compressed rounds entry:

| Field | Fill-in Value |
|-------|--------------|
| compressed_rounds[].range | {Round range, e.g. `R1-R3`} |
| compressed_rounds[].summary | {One-line summary of what was tried, e.g. `Basic injection/encoding/wildcards all failed`} |
| compressed_rounds[].eliminated | {Array of eliminated strategy names, e.g. `["basic_separators", "url_encoding"]`} |
| compressed_rounds[].discoveries | {Array of key=value findings, e.g. `["waf_type=ModSecurity_CRS", "blind_possible=true"]`} |
| compressed_rounds[].next_hint | {Suggested strategy for next round, e.g. `Try time-based blind injection or OOB`} |
| current_round | {Next round number to execute, e.g. `4`} |
| remaining_budget_hint | {Token budget guidance, e.g. `Keep each round's analysis within 2000 tokens`} |

### Token Budget Reference

| Total Rounds | Estimated Tokens After Compression | Available Tokens Per Round |
|-------------|-----------------------------------|--------------------------|
| 8 rounds | R1-3 summary ~800 + R4-6 summary ~800 + R7-8 full ~4000 | ~2000/round |
| 11 rounds | R1-3 ~800 + R4-6 ~800 + R7-9 ~800 + R10-11 full | ~2000/round |
| 12 rounds | R1-3 ~800 + R4-6 ~800 + R7-9 ~800 + R10-12 full | ~2000/round |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Compressed summary | In-context (replaces verbose round records) | Markdown summary table + eliminated list + key findings + latest round full details | Compressed representation of completed rounds within the context window |
| Updated plan JSON | `$WORK_DIR/{sink_id}_plan.json` | JSON with `compressed_rounds` array, `current_round`, `remaining_budget_hint` | Persistent record of compression history and round tracking |

## Examples

### ✅ GOOD: Proper R1-R3 Compression

**Compressed summary (replaces ~8000 tokens of verbose content with ~800 tokens):**
```
## R1-R3 Compressed Summary

| Round | Strategy | Result | Key Findings |
|-------|----------|--------|-------------|
| R1 | Basic command separators | ❌ 403 | ModSecurity CRS v3.x |
| R2 | URL/double encoding | ❌ 403 | All encoding bypasses failed |
| R3 | $IFS/wildcards | ❌ 200 no output | Command may execute but no output |

Eliminated: basic separators, URL encoding, double encoding
Key findings: WAF=ModSecurity CRS, 200 response may indicate blind injection
Next suggestion: Try time-based blind injection (sleep 5) or OOB (DNS/HTTP callback)
```

**Updated `{sink_id}_plan.json`:**
```json
{
  "compressed_rounds": [
    {
      "range": "R1-R3",
      "summary": "Basic injection/encoding/wildcards all failed",
      "eliminated": ["basic_separators", "url_encoding", "double_encoding", "wildcards"],
      "discoveries": ["waf_type=ModSecurity_CRS", "blind_possible=true"],
      "next_hint": "Try time-based blind injection or OOB"
    }
  ],
  "current_round": 4,
  "remaining_budget_hint": "Keep each round's analysis within 2000 tokens"
}
```
Explanation ✅ Summary table captures all 3 rounds concisely. Eliminated paths are listed (CR-3 enforced). Key findings preserved (CR-2). Plan JSON updated with compression record (CR-5). Token usage reduced from ~8000 to ~800.

### ❌ BAD: Compression Retains Verbose Content and Misses Plan Update

```
## R1-R3 Summary

R1: Sent curl -X POST http://target/cmd.php -d "cmd=;id" -H "Host: target.com" -H "Cookie: sess=abc123"
HTTP/1.1 403 Forbidden
<html><body>ModSecurity Action... [full 500-line HTML body preserved]...
Analysis: The ModSecurity WAF detected the semicolon character as a command separator...
[300 words of detailed reasoning kept in full]

| Round | Strategy | Result |
|-------|----------|--------|
| R2 | URL encoding | ❌ 403 |
| R3 | Wildcards | ❌ 200 |
```
What's wrong ❌ Violates **CR-4**: Full HTTP request/response body and step-by-step reasoning from R1 are retained instead of removed. Violates **CR-2**: No eliminated paths list, no key findings section. R1 has verbose content but R2/R3 only have table rows — inconsistent. Violates **CR-5**: `{sink_id}_plan.json` was not updated with `compressed_rounds`. Missing `next_hint` to guide R4 strategy.

## Error Handling
| Error | Action |
|-------|--------|
| Compression trigger missed (e.g., R4 starts without compressing R1-R3) | Immediately perform compression before continuing; do not proceed with new rounds until done |
| `{sink_id}_plan.json` does not exist | Create the file with initial `compressed_rounds: []` and `current_round` set to the next round number |
| Token budget exceeded despite compression | Compress more aggressively: reduce summary table descriptions to keywords, shorten key findings |
| Fewer than 3 rounds completed at audit end | No compression required; retain full details of all completed rounds |
| Eliminated strategy accidentally retried | Halt the round immediately, mark it as wasted, update eliminated list, proceed to next strategy |
