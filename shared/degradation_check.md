# Upstream Degradation Check Protocol

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-109 |
| Category | Shared Protocol |
| Responsibility | Mandatory Step 0 for all agents consuming upstream phase data — verify degradation status before processing |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-DEG-1 | This check MUST be the FIRST step in Fill-in Procedure (Step 0) — before any data processing | Degraded data treated as complete → false confirmed findings |
| CR-DEG-2 | The Degradation Status Table MUST be fully filled — empty cells = QC FAIL | Agent skipped degradation awareness |
| CR-DEG-3 | When ANY upstream phase is degraded, ALL findings from that data MUST use verdict `suspected`, NOT `confirmed` | Over-confidence from incomplete data |
| CR-DEG-4 | When ANY upstream phase is degraded, evidence fields MUST include `[DEGRADED INPUT]` prefix | Downstream consumers unaware of data quality |

## Fill-in Procedure

### Step 0 — Upstream Degradation Status (MANDATORY)

Fill the following table by reading environment variables or checkpoint.json:

| Upstream Phase | Flag Variable | Value | Affected Input Files |
|---------------|---------------|-------|---------------------|
| Phase-1 (Environment) | PHASE1_DEGRADED | {read value: true / false / not_set} | {list files from Phase-1 you consume, or "N/A"} |
| Phase-2 (Reconnaissance) | PHASE2_DEGRADED | {read value: true / false / not_set} | {list files from Phase-2 you consume, or "N/A"} |
| Phase-3 (Trace & Auth) | PHASE3_DEGRADED | {read value: true / false / not_set} | {list files from Phase-3 you consume, or "N/A"} |
| Phase-4 (Exploit) | PHASE4_DEGRADED | {read value: true / false / not_set} | {list files from Phase-4 you consume, or "N/A"} |

### Degradation Impact Assessment (fill ONLY if any Value = true)

| Degraded Phase | Specific Data Gap | Impact on My Task | Mitigation Applied |
|---------------|-------------------|-------------------|-------------------|
| {phase name} | {which fields/files are missing or incomplete} | {how this affects your analysis accuracy} | {what adjustment you made — e.g., "downgraded all findings to suspected"} |

### Degradation Enforcement Rules

When degradation is detected, apply the following constraints:

| Condition | Mandatory Action |
|-----------|-----------------|
| Any upstream degraded | ALL `final_verdict` values capped at `suspected` (never `confirmed`) |
| Phase-2 degraded | Skip sinks without context_pack — do NOT guess context |
| Phase-3 degraded | ALL auth-dependent test cases skipped — mark `[AUTH UNAVAILABLE]` |
| Phase-4 degraded (for Phase-4.5/5) | Use only available exploit results — do NOT extrapolate missing auditor outputs |
| Multiple phases degraded | Add `[MULTI-DEGRADED]` tag to all output files |

## Integration Template

Each consuming agent MUST add the following to their Fill-in Procedure as **Step 0**:

```markdown
### Step 0 — Upstream Degradation Check (MANDATORY)

Per `shared/degradation_check.md`, fill the degradation status table:

| Upstream Phase | Flag Variable | Value | Affected Input Files |
|---------------|---------------|-------|---------------------|
| Phase-{N} | PHASE{N}_DEGRADED | {true/false/not_set} | {files consumed} |

IF any Value = true → apply Degradation Enforcement Rules before proceeding.
```

## Examples

### ✅ GOOD: Properly Handled Degradation

```
Step 0 — Upstream Degradation Status:
| Upstream Phase | Flag Variable | Value | Affected Input Files |
|---------------|---------------|-------|---------------------|
| Phase-1 | PHASE1_DEGRADED | false | N/A |
| Phase-2 | PHASE2_DEGRADED | true | route_map.json, priority_queue.json |
| Phase-3 | PHASE3_DEGRADED | false | N/A |

Degradation Impact Assessment:
| Degraded Phase | Specific Data Gap | Impact on My Task | Mitigation Applied |
|---------------|-------------------|-------------------|-------------------|
| Phase-2 | 3 of 12 routes missing from route_map.json | Coverage reduced to 75% | Downgraded all findings to suspected; added [DEGRADED INPUT] prefix |
```
Correctly identified degradation, quantified impact, applied mitigations ✅

### ❌ BAD: Degradation Ignored

```
Step 0 — Upstream Degradation Status:
| Upstream Phase | Flag Variable | Value | Affected Input Files |
|---------------|---------------|-------|---------------------|
| Phase-2 | PHASE2_DEGRADED | true | route_map.json |

(No Impact Assessment table filled)

Result: final_verdict = "confirmed"
```
Violates CR-DEG-2 (Impact Assessment not filled), CR-DEG-3 (verdict "confirmed" despite degraded input) ❌
