# Prerequisite Conditions and 3D Severity Scoring Model

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-104 |
| Category | Shared Protocol |
| Responsibility | Standardize prerequisite declaration and 3D severity scoring for consistent vulnerability ratings across all auditors |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Auth matrix | `$WORK_DIR/auth_matrix.json` | ✅ | `auth_level` for the route under test — prerequisite `auth_requirement` MUST match |
| Attack results | Auditor runtime context | ✅ | Exploitation outcome, bypass methods discovered, defense observations |
| Sink metadata | `$WORK_DIR/sinks/{sink_id}.json` | ✅ | `sink_type`, `sink_function`, route information for vuln_id generation |
| Evidence score | Auditor exploit output | ✅ | `evidence_score` (1-10) — must be consistent with computed severity score |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | `auth_requirement` MUST match the `auth_level` for the route in `auth_matrix.json` | Mismatched auth levels produce incorrect reachability scores and misleading severity ratings |
| CR-2 | When `exploitability_judgment = "conditionally_exploitable"` → `severity.complexity` MUST be downgraded by 1 level | Failing to downgrade inflates severity for vulnerabilities that require specific preconditions |
| CR-3 | When `exploitability_judgment = "not_exploitable"` → `final_verdict` MUST NOT exceed `potential` and `confidence` MUST NOT exceed `low` | Marking unreachable vulnerabilities as confirmed wastes remediation effort |
| CR-4 | All three reason fields (`reachability_reason`, `impact_reason`, `complexity_reason`) MUST be non-empty strings with specific justification | Empty or vague reasons make the scoring unverifiable and non-reproducible |
| CR-5 | `score` and `evidence_score` MUST be consistent: score ≥ 2.10 requires evidence_score ≥ 7; 1.20 ≤ score < 2.10 requires 4 ≤ evidence_score ≤ 6; score < 1.20 requires 1 ≤ evidence_score ≤ 3 | Inconsistent scores indicate either inflated severity or insufficient evidence |
| CR-6 | `vuln_id` MUST follow the `C-{TYPE}-NNN` format (e.g., `C-RCE-001`, `C-SQLI-003`) | Non-conforming IDs break downstream deduplication and tracking |
| CR-7 | All 10 severity fields MUST be present: reachability, reachability_reason, impact, impact_reason, complexity, complexity_reason, score, cvss, level, vuln_id | Missing fields cause schema validation failures in the report generator |

## Fill-in Procedure

### Procedure A: Prerequisite Conditions
Fill in the `prerequisite_conditions` object for the exploit output:

| Field | Fill-in Value |
|-------|--------------|
| auth_requirement | {`anonymous` \| `authenticated` \| `admin` \| `internal_network` — MUST match auth_matrix.json auth_level for this route} |
| bypass_method | {Description of how authentication can be bypassed, or `null` if no bypass exists} |
| other_preconditions | {Array of non-auth prerequisites — PHP config requirements, Composer deps, env vars, specific DB type, writable directories, network access} |
| exploitability_judgment | {`directly_exploitable` \| `conditionally_exploitable` \| `not_exploitable`} |

**Exploitability Impact on Verdict:**

| Judgment | Verdict Ceiling | Confidence Ceiling |
|----------|----------------|--------------------|
| `directly_exploitable` | `confirmed` | `high` |
| `conditionally_exploitable` | `confirmed` (with complexity downgrade per CR-2) | `high` |
| `not_exploitable` | `potential` (maximum per CR-3) | `low` (maximum) |

### Procedure B: Three-Dimensional Severity Scoring
Score each dimension 0-3 using the definitions below, then compute aggregate score:

**Dimension Definitions:**

| Dimension | Weight | 0 | 1 | 2 | 3 |
|-----------|--------|---|---|---|---|
| **Reachability** | 0.40 | Unreachable | Requires chaining multiple conditions | Requires authentication | Directly reachable (anonymous) |
| **Impact** | 0.35 | No impact | Information disclosure | Data modification / partial control | Full system compromise (RCE/full DB access) |
| **Complexity** | 0.25 | Infeasible | Requires deep expertise + specific conditions | Requires some skill / minor conditions | Trivial exploitation (copy-paste payload) |

Fill in the severity object:

| Field | Fill-in Value |
|-------|--------------|
| reachability | {0-3 per dimension definition above} |
| reachability_reason | {Format: "{CATEGORY}: {specific_detail}" — CATEGORY must be one of: `route_anonymous` / `route_auth_bypass` / `route_authenticated` / `param_injectable` / `framework_detected` / `middleware_absent` — e.g., "route_anonymous: Route /api/exec has no auth middleware"} |
| impact | {0-3 per dimension definition above} |
| impact_reason | {Format: "{CATEGORY}: {specific_detail}" — CATEGORY must be one of: `rce_confirmed` / `data_exfiltration` / `privilege_escalation` / `auth_bypass` / `resource_access` / `dos_possible` / `info_disclosure` — e.g., "rce_confirmed: system() call allows arbitrary OS command execution"} |
| complexity | {0-3 per dimension definition above; downgrade by 1 if conditionally_exploitable per CR-2} |
| complexity_reason | {Format: "{CATEGORY}: {specific_detail}" — CATEGORY must be one of: `direct_injection` / `requires_encoding` / `requires_gadget_chain` / `requires_timing` / `multi_step_required` / `no_filter` / `weak_filter` — e.g., "no_filter: Payload requires no encoding, direct injection into system()"} |

### Procedure C: Score Calculation
Compute the final score, CVSS, and level:

| Field | Fill-in Value |
|-------|--------------|
| score | {reachability × 0.40 + impact × 0.35 + complexity × 0.25} |
| cvss | {(score / 3.0) × 10.0} |
| level | {`C` if score ≥ 2.10, `H` if 1.50 ≤ score < 2.10, `M` if 1.20 ≤ score < 1.50, `L` if score < 1.20} |
| vuln_id | {`C-{TYPE}-NNN` format — e.g., `C-RCE-001`, `C-SQLI-003`} |

**Level Thresholds:**

| Level | Label | Score Range | CVSS Range |
|-------|-------|-------------|------------|
| **C** | Critical | score ≥ 2.10 | cvss ≥ 7.0 |
| **H** | High | 1.50 ≤ score < 2.10 | 5.0 ≤ cvss < 7.0 |
| **M** | Medium | 1.20 ≤ score < 1.50 | 4.0 ≤ cvss < 5.0 |
| **L** | Low | score < 1.20 | cvss < 4.0 |

### Procedure D: Consistency Validation
Verify score ↔ evidence_score consistency per CR-5:

| Score Range | Required evidence_score Range |
|-------------|------------------------------|
| score ≥ 2.10 | evidence_score ≥ 7 |
| 1.20 ≤ score < 2.10 | 4 ≤ evidence_score ≤ 6 |
| score < 1.20 | 1 ≤ evidence_score ≤ 3 |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| Prerequisite Conditions | `exploits/{sink_id}.json` → `prerequisite_conditions` | See schema below | Declares authentication and other prerequisites for exploitation |
| Severity Object | `exploits/{sink_id}.json` → `severity` | See schema below | 3D severity score with justifications, CVSS, and level |

**Prerequisite Conditions Schema:**
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "<string | null>",
  "other_preconditions": ["<string>"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```

**Severity Schema:**
```json
{
  "reachability": "<int 0-3>",
  "reachability_reason": "<string>",
  "impact": "<int 0-3>",
  "impact_reason": "<string>",
  "complexity": "<int 0-3>",
  "complexity_reason": "<string>",
  "score": "<float>",
  "cvss": "<float>",
  "level": "C|H|M|L",
  "vuln_id": "C-{TYPE}-NNN"
}
```

## Examples

### ✅ GOOD: Critical RCE with anonymous access
```json
{
  "prerequisite_conditions": {
    "auth_requirement": "anonymous",
    "bypass_method": null,
    "other_preconditions": ["PHP exec functions not in disable_functions"],
    "exploitability_judgment": "directly_exploitable"
  },
  "severity": {
    "reachability": 3,
    "reachability_reason": "Route /api/ping is publicly accessible without authentication middleware",
    "impact": 3,
    "impact_reason": "system() call allows arbitrary OS command execution — full server compromise",
    "complexity": 3,
    "complexity_reason": "No input filtering applied — direct concatenation into system() call",
    "score": 3.0,
    "cvss": 10.0,
    "level": "C",
    "vuln_id": "C-RCE-001"
  }
}
```
Explanation: auth_requirement matches auth_matrix.json (CR-1 ✅). directly_exploitable allows confirmed verdict. All reason fields are specific (CR-4 ✅). score = 3×0.40 + 3×0.35 + 3×0.25 = 3.0 → level C correct (CR-7 ✅). vuln_id follows format (CR-6 ✅). ✅

### ❌ BAD: Inconsistent scoring and missing reasons
```json
{
  "prerequisite_conditions": {
    "auth_requirement": "anonymous",
    "bypass_method": null,
    "other_preconditions": [],
    "exploitability_judgment": "conditionally_exploitable"
  },
  "severity": {
    "reachability": 3,
    "reachability_reason": "Reachable",
    "impact": 3,
    "impact_reason": "",
    "complexity": 3,
    "complexity_reason": "Easy to exploit",
    "score": 3.0,
    "cvss": 10.0,
    "level": "C",
    "vuln_id": "RCE-001"
  }
}
```
What's wrong: `exploitability_judgment` is `conditionally_exploitable` but `complexity` was not downgraded by 1 level — should be 2, not 3 (CR-2 ❌). `impact_reason` is empty string (CR-4 ❌). `reachability_reason` "Reachable" is too vague — no specific justification (CR-4 ❌). `vuln_id` is "RCE-001" instead of "C-RCE-001" format (CR-6 ❌). ❌

### ❌ BAD: Not-exploitable with confirmed verdict
```json
{
  "prerequisite_conditions": {
    "auth_requirement": "admin",
    "bypass_method": null,
    "other_preconditions": ["Requires specific PHP 5.x version with known bug"],
    "exploitability_judgment": "not_exploitable"
  },
  "severity": {
    "reachability": 1,
    "reachability_reason": "Requires admin auth and chaining two conditions",
    "impact": 2,
    "impact_reason": "Can modify database records",
    "complexity": 1,
    "complexity_reason": "Requires deep expertise and PHP 5.x specific bug",
    "score": 0.90,
    "cvss": 3.0,
    "level": "L",
    "vuln_id": "C-SQLI-005"
  }
}
```
What's wrong: `exploitability_judgment` is `not_exploitable` which means `final_verdict` MUST NOT exceed `potential` — if the auditor sets `final_verdict: "confirmed"` this violates CR-3 ❌. The score itself (0.90 → L) is mathematically correct, but the prerequisite constraints on verdict/confidence must be enforced by the auditor. ❌

## Error Handling
| Error | Action |
|-------|--------|
| `auth_matrix.json` not found or route not listed | HALT — cannot determine auth_requirement without authoritative source; report missing dependency |
| `auth_requirement` does not match `auth_matrix.json` | Correct `auth_requirement` to match auth_matrix; do NOT override the matrix value |
| score ↔ evidence_score inconsistency detected | Adjust `evidence_score` to match the valid range for the computed score, or re-evaluate dimension scores if evidence is genuinely weak |
| Any of the 10 severity fields missing | Add the missing field(s) — do NOT output partial severity objects |
| Reason field is empty or contains only generic text (e.g., "High impact") | Rewrite with specific justification referencing the actual code path, function, or defense |
| `vuln_id` does not match `C-{TYPE}-NNN` pattern | Reformat to correct pattern using the appropriate vulnerability type abbreviation |
| `conditionally_exploitable` but complexity not downgraded | Downgrade complexity by 1 level before computing final score |
