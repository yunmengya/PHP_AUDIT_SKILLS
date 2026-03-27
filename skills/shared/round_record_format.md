# Per-Round Record Format

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-101 |
| Category | Shared Protocol |
| Responsibility | Define the standard JSON structure every attack round must produce for consistency across all auditors |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Attack round execution result | Invoking auditor (S-040 ~ S-060) | ✅ | Round number, strategy, payload, HTTP request/response, evidence |
| Sink context | Invoking auditor | ✅ | `sink_id`, `injection_point` |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | `request` MUST be Burp-style format with complete headers (Host, Cookie at minimum) | Incomplete requests prevent reproduction and verification |
| CR-2 | `response_body_snippet` MUST be at most 500 characters (truncate with `...` if longer) | Oversized snippets bloat records and may leak sensitive data |
| CR-3 | `payload` MUST be the exact string sent — no pseudocode or placeholders | Pseudocode payloads make reproduction impossible |
| CR-4 | `failure_reason` MUST describe the specific defense mechanism encountered (not generic "did not work") | Vague reasons provide no actionable intelligence for subsequent rounds |
| CR-5 | `result` MUST be one of exactly three values: `confirmed`, `suspected`, `failed` | Invalid result values break downstream aggregation and skip logic |
| CR-6 | All required fields must be present in every round record | Missing fields break record schema validation and audit consistency |

## Fill-in Procedure

### Procedure A: Fill Round Record
| Field | Fill-in Value |
|-------|--------------|
| round | {integer: round number, 1-8 or extended rounds} |
| strategy | {string: short identifier for attack strategy, e.g., "basic_cmd_injection", "encoding_bypass"} |
| payload | {string: exact payload string sent to the target, verbatim} |
| injection_point | {string: where payload was injected — e.g., "GET param 'id'", "POST body param 'name'", "Cookie 'session'", "Header 'X-Forward'"} |
| request | {string: full HTTP request in Burp-style format including method, path, Host, Cookie, other headers, and body} |
| response_status | {integer: HTTP response status code, e.g., 200, 403, 500} |
| response_body_snippet | {string: first 500 characters of response body, truncated with "..." if longer} |
| evidence_check | {string: command or method used to verify exploitation, e.g., "docker exec php cat /tmp/rce_proof"} |
| evidence_result | {string: actual output of the evidence check command} |
| result | {string: one of "confirmed", "suspected", "failed"} |
| failure_reason | {string: specific defense mechanism description if failed; empty string if confirmed} |

### Procedure B: Determine Result Value
| Field | Fill-in Value |
|-------|--------------|
| confirmed | {use when: evidence check proves command/query execution with matching output} |
| suspected | {use when: anomalous behavior observed (status code, timing, error message) but no definitive evidence} |
| failed | {use when: no evidence of exploitation; payload was blocked or had no effect} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Round record entry | `exploits/{sink_id}.json` → `rounds[]` array | See example below | One JSON object per attack round appended to the rounds array |

## Examples

### ✅ GOOD: Failed round with specific failure reason
```json
{
  "round": 1,
  "strategy": "basic_cmd_injection",
  "payload": ";echo RCE_R1 > /tmp/rce_proof_round_1",
  "injection_point": "POST body param 'name'",
  "request": "POST /api/user/update HTTP/1.1\nHost: target.local\nCookie: PHPSESSID=abc123\nContent-Type: application/x-www-form-urlencoded\n\nname=%3Becho+RCE_R1+%3E+%2Ftmp%2Frce_proof_round_1",
  "response_status": 200,
  "response_body_snippet": "{\"status\":\"success\",\"message\":\"User updated\"}",
  "evidence_check": "docker exec php cat /tmp/rce_proof_round_1",
  "evidence_result": "cat: /tmp/rce_proof_round_1: No such file or directory",
  "result": "failed",
  "failure_reason": "Parameter was filtered by escapeshellarg() — all shell metacharacters (; > |) were escaped"
}
```
Explanation ✅ All fields present. Payload is exact string. Request is full Burp-style with Host and Cookie. Failure reason identifies specific defense (escapeshellarg). Result is valid enum value.

### ✅ GOOD: Confirmed exploitation
```json
{
  "round": 3,
  "strategy": "double_url_encoding",
  "payload": "%253Becho%2520PWNED%2520%253E%2520%252Ftmp%252Frce_proof",
  "injection_point": "GET param 'file'",
  "request": "GET /download?file=%253Becho%2520PWNED%2520%253E%2520%252Ftmp%252Frce_proof HTTP/1.1\nHost: target.local\nCookie: PHPSESSID=abc123",
  "response_status": 200,
  "response_body_snippet": "File downloaded successfully",
  "evidence_check": "docker exec php cat /tmp/rce_proof",
  "evidence_result": "PWNED",
  "result": "confirmed",
  "failure_reason": ""
}
```
Explanation ✅ Result is "confirmed" with matching evidence output. Failure reason is empty as required for confirmed results. Payload is exact encoded string.

### ❌ BAD: Pseudocode payload
```json
{
  "round": 2,
  "strategy": "encoding_bypass",
  "payload": "<inject shell command here with URL encoding>",
  "injection_point": "POST body param 'cmd'",
  "request": "POST /api/exec HTTP/1.1\nHost: target.local\n\ncmd=<payload>",
  "response_status": 200,
  "response_body_snippet": "OK",
  "evidence_check": "check if command ran",
  "evidence_result": "unknown",
  "result": "failed",
  "failure_reason": "did not work"
}
```
What's wrong: `payload` contains pseudocode instead of exact string — violates CR-3. `evidence_check` is vague description, not actual command. `failure_reason` is generic "did not work" — violates CR-4. ❌

### ❌ BAD: Missing required fields
```json
{
  "round": 1,
  "strategy": "basic_sqli",
  "payload": "' OR 1=1 --",
  "result": "failed"
}
```
What's wrong: Missing `injection_point`, `request`, `response_status`, `response_body_snippet`, `evidence_check`, `evidence_result`, and `failure_reason`. Violates CR-6 — all required fields must be present. ❌

## Error Handling
| Error | Action |
|-------|--------|
| Response body exceeds 500 characters | Truncate to 500 characters and append `...`; do not omit the field |
| Evidence check command fails to execute | Record the error message as `evidence_result`; set `result` to `failed` |
| Unable to determine injection point | HALT — injection point is required; revisit sink analysis before proceeding |
| HTTP request cannot be captured in Burp-style | Reconstruct from available data (method, URL, headers, body); note reconstruction in request |
| Round number exceeds standard range (1-8) | Allowed for extended rounds; record actual round number as integer |
| Result value unclear (between suspected and confirmed) | Default to `suspected`; only use `confirmed` when evidence definitively proves execution |
