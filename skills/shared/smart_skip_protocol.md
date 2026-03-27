> **Skill ID**: S-102 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Smart Skip Protocol

## Purpose

Allow auditors to skip remaining attack rounds when continued testing is demonstrably futile, while preventing premature abandonment of viable attack paths.

## Procedure

### Activation Conditions

Smart Skip MAY be requested only when **all** of the following conditions are met:

1. Current round ≥ **R4** (at least 4 rounds have been attempted)
2. ≥ **3 consecutive failures** have occurred
3. A clear defensive mechanism has been identified

### Required Justification

A skip request MUST provide all three of the following:

| Requirement | Description |
|-------------|-------------|
| **Attempted strategies list** | Enumerate every strategy tried so far with round numbers |
| **Analysis conclusion** | Identify the specific filtering/defense mechanism (e.g., WAF type, parameterized queries, input validation regex) |
| **Bypass infeasibility reasoning** | Explain why the remaining strategies (R5-R8 or beyond) cannot bypass the identified defenses |

### Skip Request Format

```json
{
  "skip_requested": true,
  "skip_after_round": 4,
  "consecutive_failures": 3,
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

### Constraints

- Skip MUST NOT be used before R4 under any circumstances
- Skip MUST NOT be used if any round resulted in `suspected` — further testing is required
- After skip, the auditor MUST still produce the final `exploits/{sink_id}.json` with all attempted rounds recorded
- Smart Pivot (S-103) SHOULD be attempted before requesting skip

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/smart_skip_protocol.md`
