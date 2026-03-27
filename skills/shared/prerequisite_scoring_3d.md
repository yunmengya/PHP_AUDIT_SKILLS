> **Skill ID**: S-104 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Prerequisite Conditions and 3D Severity Scoring Model

## Purpose

Standardize how all auditors declare exploitation prerequisites and compute severity scores, ensuring consistent and comparable vulnerability ratings across all 21 auditor types.

## Procedure

### Part 1: Prerequisite Conditions

The output `exploits/{sink_id}.json` MUST contain a `prerequisite_conditions` object:

```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method description, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```

#### Field Rules

| Field | Description | Constraint |
|-------|-------------|------------|
| `auth_requirement` | Minimum authentication level needed to reach the sink | MUST match the `auth_level` for the route in `auth_matrix.json` |
| `bypass_method` | How authentication can be bypassed (if applicable) | Set to `null` if no bypass exists |
| `other_preconditions` | Non-authentication prerequisites | List all: PHP config, Composer deps, env vars, specific DB type, etc. |
| `exploitability_judgment` | Overall exploitability assessment | Determines ceiling for `final_verdict` |

#### Exploitability Impact on Verdict

| Judgment | Verdict Ceiling | Confidence Ceiling |
|----------|----------------|--------------------|
| `directly_exploitable` | `confirmed` | `high` |
| `conditionally_exploitable` | `confirmed` (with complexity downgrade) | `high` |
| `not_exploitable` | `potential` (maximum) | `low` (maximum) |

- When `exploitability_judgment = "conditionally_exploitable"` → `severity.complexity` MUST be downgraded by 1 level
- When `exploitability_judgment = "not_exploitable"` → `final_verdict` MUST NOT exceed `potential`

### Part 2: Three-Dimensional Severity Scoring

The output MUST contain a `severity` object with the 3D scoring model:

```json
{
  "reachability": 0-3,
  "reachability_reason": "Specific justification for score",
  "impact": 0-3,
  "impact_reason": "Specific justification for score",
  "complexity": 0-3,
  "complexity_reason": "Specific justification for score",
  "score": "R×0.40 + I×0.35 + C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-{TYPE}-NNN"
}
```

#### Dimension Definitions

| Dimension | Weight | 0 | 1 | 2 | 3 |
|-----------|--------|---|---|---|---|
| **Reachability** | 0.40 | Unreachable | Requires chaining multiple conditions | Requires authentication | Directly reachable (anonymous) |
| **Impact** | 0.35 | No impact | Information disclosure | Data modification / partial control | Full system compromise (RCE/full DB access) |
| **Complexity** | 0.25 | Infeasible | Requires deep expertise + specific conditions | Requires some skill / minor conditions | Trivial exploitation (copy-paste payload) |

#### Score Calculation

```
score = reachability × 0.40 + impact × 0.35 + complexity × 0.25
cvss  = (score / 3.0) × 10.0
```

#### Level Thresholds

| Level | Label | Score Range | CVSS Range |
|-------|-------|-------------|------------|
| **C** | Critical | score ≥ 2.10 | cvss ≥ 7.0 |
| **H** | High | 1.50 ≤ score < 2.10 | 5.0 ≤ cvss < 7.0 |
| **M** | Medium | 1.20 ≤ score < 1.50 | 4.0 ≤ cvss < 5.0 |
| **L** | Low | score < 1.20 | cvss < 4.0 |

#### Consistency Rules (score ↔ evidence_score)

| Score Range | Required evidence_score Range |
|-------------|------------------------------|
| score ≥ 2.10 | evidence_score ≥ 7 |
| 1.20 ≤ score < 2.10 | 4 ≤ evidence_score ≤ 6 |
| score < 1.20 | 1 ≤ evidence_score ≤ 3 |

#### Validation Checklist

- [ ] All three reason fields are non-empty strings with specific justification
- [ ] All 10 fields are present: R, R_reason, I, I_reason, C, C_reason, score, cvss, level, vuln_id
- [ ] score and evidence_score are consistent per the table above
- [ ] `vuln_id` follows the `C-{TYPE}-NNN` format (e.g., `C-RCE-001`, `C-SQLI-003`)

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/prerequisite_scoring_3d.md`
