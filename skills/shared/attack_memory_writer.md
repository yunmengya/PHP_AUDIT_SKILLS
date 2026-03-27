> **Skill ID**: S-105 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Attack Memory Write Protocol

## Purpose

After an attack cycle ends, persist the experience (successes and failures) to the attack memory store so future audits against similar targets can optimize their round ordering.

## Procedure

### Write Conditions

| Attack Outcome | Action | Rationale |
|---------------|--------|-----------|
| ✅ **Confirmed** | Record successful payload type + bypass technique + successful round number | Future audits prioritize proven strategies |
| ❌ **Failed (≥3 rounds attempted)** | Record all excluded strategies + failure reasons | Future audits skip known-ineffective approaches |
| ⚠️ **Partial success** | Record partially successful strategies + blocking reasons | Future audits know what nearly worked and what remains |
| ❌ **Failed (<3 rounds attempted)** | **Do not record** | Insufficient data — would pollute the memory store |

### Write Command

```bash
bash tools/audit_db.sh memory-write '<json>'
```

SQLite WAL (Write-Ahead Logging) mode automatically ensures concurrent safety when multiple auditors write simultaneously.

### Confirmed Record Format

```json
{
  "action": "memory-write",
  "sink_type": "rce",
  "framework": "laravel",
  "php_version": "8.1",
  "status": "confirmed",
  "successful_round": 3,
  "payload_type": "wildcard_bypass",
  "bypass_technique": "$IFS substitution bypassed space filter",
  "strategy": "wildcard_and_whitespace_bypass",
  "sink_function": "system()",
  "notes": "escapeshellarg() not applied to concatenated command string"
}
```

### Failed Record Format (≥3 rounds)

```json
{
  "action": "memory-write",
  "sink_type": "sqli",
  "framework": "thinkphp",
  "php_version": "7.4",
  "status": "failed",
  "rounds_attempted": 5,
  "excluded_strategies": [
    {"strategy": "basic_injection", "reason": "PDO prepared statements used throughout"},
    {"strategy": "encoding_bypass", "reason": "Input cast to integer before query"},
    {"strategy": "comment_obfuscation", "reason": "Parameterized — SQL structure not modifiable"},
    {"strategy": "wide_byte_injection", "reason": "UTF-8 encoding, no GBK"},
    {"strategy": "time_based_blind", "reason": "Prepared statement prevents injection entirely"}
  ],
  "defense_summary": "All query paths use PDO::prepare() with positional placeholders"
}
```

### Partial Success Record Format

```json
{
  "action": "memory-write",
  "sink_type": "xss",
  "framework": "wordpress",
  "php_version": "8.0",
  "status": "partial",
  "partial_round": 4,
  "strategy": "dom_based_injection",
  "partial_result": "Payload reflected in page source but CSP blocks execution",
  "blocking_reason": "Content-Security-Policy: script-src 'self'",
  "notes": "If CSP can be bypassed (e.g., via JSONP endpoint), full exploitation is possible"
}
```

### Important Rules

1. **Never write records for < 3 rounds of testing** — insufficient evidence pollutes the memory store
2. **One record per sink_id** — do not write multiple records for the same sink
3. **Include framework and PHP version** — these are key index fields for future queries
4. **Be specific in reasons** — "did not work" is unacceptable; describe the exact defense encountered

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/attack_memory_writer.md`
