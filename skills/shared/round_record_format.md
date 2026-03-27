> **Skill ID**: S-101 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Per-Round Record Format

## Purpose

Define the standard JSON structure that every attack round MUST produce, ensuring consistency across all 21 auditors.

## Procedure

### Required Record Fields

Each round MUST be fully recorded using the following JSON structure:

```json
{
  "round": 1,
  "strategy": "basic_cmd_injection",
  "payload": ";echo RCE_R1 > /tmp/rce_proof_round_1",
  "injection_point": "POST body param 'name'",
  "request": "POST /api/user/update HTTP/1.1\nHost: target\nCookie: ...\n\n<body>",
  "response_status": 200,
  "response_body_snippet": "first 500 chars...",
  "evidence_check": "docker exec php cat /tmp/rce_proof_round_1",
  "evidence_result": "file not found",
  "result": "failed",
  "failure_reason": "Parameter was filtered by escapeshellarg()"
}
```

### Field Specification

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `round` | integer | Round number (1-8, or extended rounds) | ✅ |
| `strategy` | string | Short identifier for the attack strategy used | ✅ |
| `payload` | string | Exact payload sent to the target | ✅ |
| `injection_point` | string | Where the payload was injected (e.g., GET param, POST body, Cookie, Header) | ✅ |
| `request` | string | Full HTTP request in Burp-style format (Host, Cookie, headers, body) | ✅ |
| `response_status` | integer | HTTP response status code | ✅ |
| `response_body_snippet` | string | First 500 characters of response body | ✅ |
| `evidence_check` | string | Command or method used to verify exploitation success | ✅ |
| `evidence_result` | string | Output of the evidence check command | ✅ |
| `result` | string | One of: `confirmed`, `suspected`, `failed` | ✅ |
| `failure_reason` | string | Explanation of why the attack failed (empty if confirmed) | ✅ when failed |

### Result Value Semantics

| Value | Meaning |
|-------|---------|
| `confirmed` | Evidence check proves command/query execution with matching output |
| `suspected` | Anomalous behavior observed (status code, timing, error message) but no definitive evidence |
| `failed` | No evidence of exploitation; payload was blocked or had no effect |

### Format Rules

1. `request` MUST be Burp-style format with complete headers (Host, Cookie at minimum)
2. `response_body_snippet` MUST be at most 500 characters (truncate with `...` if longer)
3. `payload` MUST be the exact string sent — no pseudocode or placeholders
4. `failure_reason` MUST describe the specific defense mechanism encountered (not generic "did not work")

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/round_record_format.md`
