# Vulnerability Severity Three-Dimensional Scoring Standard

> All Phase-4 Auditors MUST calculate severity scores for each finding according to this standard.
> QA reviewers use this standard to verify scoring reasonableness.

## Scoring Formula

```
Score = R × 0.40 + I × 0.35 + C × 0.25
CVSS  = (Score / 3.0) × 10.0
```

- **R** = Reachability
- **I** = Impact
- **C** = Complexity (inverted scoring: easier to exploit = higher score)

## Dimension Definitions

### R — Reachability (Weight 40%)

| Value | Condition | PHP Scenario Examples |
|:--:|------|-------------|
| 3 | No authentication, directly reachable via HTTP | Anonymously accessible API endpoints, public upload interfaces |
| 2 | Requires regular user authentication | Post-login user profile, comment interfaces |
| 1 | Requires admin privileges or intranet access | Admin panel, internal API, cron scripts |
| 0 | Code unreachable / dead code | Unregistered routes, commented-out functions, deprecated interfaces |

**Relationship with auth_matrix:**
- `auth_level = "anonymous"` → R = 3
- `auth_level = "authenticated"` → R = 2
- `auth_level = "admin"` → R = 1
- Route not present in route_map → R = 0

### I — Impact (Weight 35%)

| Value | Condition | PHP Scenario Examples |
|:--:|------|-------------|
| 3 | RCE / arbitrary file write / full data breach / system compromise | eval() injection, Webshell upload, full-table UNION injection |
| 2 | Sensitive data leak / privilege escalation / partial file read | .env leak, IDOR privilege escalation, LFI reading /etc/passwd |
| 1 | Limited information leak / non-sensitive config read | phpinfo exposure, directory listing, error stack trace |
| 0 | No actual security impact | Pure styling issues, ineffective XSS (blocked by CSP) |

### C — Complexity (Weight 25%, Inverted Scoring)

| Value | Condition | PHP Scenario Examples |
|:--:|------|-------------|
| 3 | Single request, no prerequisites | Direct `?id=1 UNION SELECT` or `?cmd=id` |
| 2 | Requires special payload or multiple steps | Requires Base64 encoding, needs CSRF Token first |
| 1 | Requires specific environment / race condition / chained exploitation | disable_functions bypass, deserialization POP chain, TOCTOU |
| 0 | Effective defenses in place, unexploitable | WAF fully blocking, parameterized queries, CSP strict-dynamic |

## Severity Level Mapping

| Level | ID Prefix | Score Range | CVSS Range | Meaning |
|:----:|:-------:|:----------:|:---------:|------|
| **C** (Critical) | C- | 2.70 — 3.00 | 9.0 — 10.0 | Can directly lead to system compromise |
| **H** (High) | H- | 2.10 — 2.69 | 7.0 — 8.9 | Can cause significant damage |
| **M** (Medium) | M- | 1.20 — 2.09 | 4.0 — 6.9 | Medium risk |
| **L** (Low) | L- | 0.10 — 1.19 | 0.1 — 3.9 | Security hardening recommendations |

**Vulnerability ID Format:** `{Level}-{Type}-{Sequence}`
- Examples: `C-RCE-001`, `H-SQLI-002`, `M-AUTH-003`, `L-CONFIG-001`

## Impact of Exploitability on Scoring

| exploitability_judgment | R Effect | C Effect |
|------------------------|--------|--------|
| directly_exploitable | Use actual value | Use actual value |
| conditionally_exploitable | Use actual value | C reduced by 1 level (more conservative) |
| not_exploitable | R = 0 | C = 0 |

**Rule:** `not_exploitable` → Score forced to 0 → maximum verdict = `potential`

## PHP Scenario Quick Reference

| Vulnerability Type | Typical R | Typical I | Typical C | Typical Score | Typical Level |
|----------|:------:|:------:|:------:|:----------:|:--------:|
| eval() + no auth | 3 | 3 | 3 | 3.00 | C |
| SQLi UNION + no auth | 3 | 3 | 3 | 3.00 | C |
| File upload Webshell + no type check | 3 | 3 | 2 | 2.75 | C |
| XXE with echo + requires login | 2 | 3 | 3 | 2.60 | H |
| SSRF intranet probe + no auth | 3 | 2 | 2 | 2.40 | H |
| IDOR unauthorized read + requires login | 2 | 2 | 3 | 2.25 | H |
| Deserialization RCE + POP chain | 2 | 3 | 1 | 2.10 | H |
| Stored XSS + requires login | 2 | 2 | 2 | 2.00 | M |
| CSRF state modification + requires phishing | 2 | 2 | 1 | 1.75 | M |
| Weak password hash (MD5) | 2 | 1 | 2 | 1.65 | M |
| Insecure Session config | 2 | 1 | 1 | 1.40 | M |
| phpinfo exposure | 3 | 1 | 3 | 2.30 | H |
| Error stack trace leak | 3 | 1 | 3 | 2.30 | H |
| .env file downloadable + no auth | 3 | 2 | 3 | 2.65 | H |
| Log poisoning + LFI chain | 2 | 3 | 1 | 2.10 | H |
| LDAP injection + requires admin | 1 | 2 | 2 | 1.60 | M |
| CRLF header injection (PHP ≥7.0) | 2 | 1 | 1 | 1.40 | M |
| Race condition (balance) | 2 | 2 | 1 | 1.75 | M |

## Auditor Output Requirements

Fill in the `severity` object in `exploits/{sink_id}.json`:

```json
{
  "severity": {
    "reachability": 3,
    "reachability_reason": "anonymous endpoint, no middleware",
    "impact": 3,
    "impact_reason": "eval() allows arbitrary code execution",
    "complexity": 2,
    "complexity_reason": "need base64 encoding to bypass WAF",
    "score": 2.75,
    "cvss": 9.2,
    "level": "C",
    "vuln_id": "C-RCE-001"
  }
}
```

**Reason fields MUST be filled in alongside numeric values.** Numbers without explanations → QA rejection.

## Relationship with evidence_score

| severity.score | Corresponding evidence_score Range | Description |
|:--------------:|:------------------------:|------|
| ≥ 2.10 | 7 — 10 | High/Critical findings; evidence_score MUST NOT be below 7 |
| 1.20 — 2.09 | 4 — 6 | Medium findings |
| 0.10 — 1.19 | 1 — 3 | Low findings |
| 0 | 0 | Unexploitable |

**Consistency rule:** If severity.score ≥ 2.70 but evidence_score < 7 → QA flags as contradiction.
