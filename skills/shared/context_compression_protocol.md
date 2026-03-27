> **Skill ID**: S-107 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Context Compression Protocol

## Purpose

Manage token budget during multi-round attack loops by compressing completed rounds into summary tables, ensuring sufficient context window capacity for detailed analysis in subsequent rounds.

## Procedure

### Compression Trigger

After every **3 attack rounds** are completed (i.e., after R3, R6, R9), a context compression MUST be performed.

### Compression Format

Compress detailed records of completed rounds into a single-line summary table:

```
| Round | Strategy | Payload Summary | Result | Key Findings |
|-------|----------|----------------|--------|-------------|
| R1 | Basic injection | ;id / |id / $(id) | ❌ 403 WAF blocked | ModSecurity CRS activated |
| R2 | Encoding bypass | %3Bid / double-URL | ❌ 403 still blocked | URL encoding ineffective |
| R3 | Wildcard substitution | $IFS / {cmd,arg} | ❌ 200 no output | Possible blind injection |
```

### Retained Content (MUST keep after compression)

1. **Round summary table** — formatted as above
2. **Eliminated paths list** — strategies proven ineffective; subsequent rounds MUST NOT retry them
3. **Key findings** — WAF type, filtering rules, exploitable characteristics discovered
4. **Full details of the most recent round** — the latest round's HTTP request/response MUST remain intact for reference

### Removed Content (SHALL be removed during compression)

1. Full HTTP request/response bodies from earlier rounds
2. Step-by-step analysis reasoning from earlier rounds
3. Duplicate source code references (already recorded in pre-attack preparation)
4. Raw output from tool invocations (retain only key result lines)

### Compression Example

**Before compression** (~8000 tokens):
```
R1: Sent curl -X POST ... -d "cmd=;id" → Response 403 ... [full HTML body 500 lines] ...
Analysis: ModSecurity detected command injection pattern ... [detailed reasoning 300 words] ...
R2: Tried encoding ... [repeated analysis] ...
R3: Tried wildcards ... [detailed process] ...
```

**After compression** (~800 tokens):
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

### Plan JSON Update

After each compression, update the `compressed_rounds` field in `{sink_id}_plan.json`:

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

### Token Budget Reference

| Total Rounds | Estimated Tokens After Compression | Available Tokens Per Round |
|-------------|-----------------------------------|--------------------------|
| 8 rounds | R1-3 summary ~800 + R4-6 summary ~800 + R7-8 full ~4000 | ~2000/round |
| 11 rounds | R1-3 ~800 + R4-6 ~800 + R7-9 ~800 + R10-11 full | ~2000/round |
| 12 rounds | R1-3 ~800 + R4-6 ~800 + R7-9 ~800 + R10-12 full | ~2000/round |

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/context_compression_protocol.md`
