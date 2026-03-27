> **Skill ID**: S-103 | **Phase**: 4 | **Type**: Shared Protocol
> **Used by**: All 21 Phase-4 auditors (S-040 ~ S-060)

# Smart Pivot Protocol (Stuck Detection)

## Purpose

When an auditor encounters repeated failures, trigger a structured pivot sequence to find alternative attack paths before giving up. This prevents wasted rounds that produce hallucinated results.

## Procedure

### Activation Conditions

Smart Pivot is triggered when **both** conditions are met:

1. **≥ 3 consecutive rounds** have failed
2. **Current round ≥ R4**

### Pivot Sequence (4 Steps)

Execute these steps in order:

#### Step 1: Re-Reconnaissance

Re-read the target source code with fresh eyes, specifically looking for:

- Missed filtering logic or validation functions not noticed during pre-attack preparation
- Alternative entry points to the same sink (different routes, different parameters)
- Conditional branches that may bypass the identified defense under certain conditions
- Configuration-dependent behavior (debug mode, environment variables, feature flags)

#### Step 2: Cross-Intelligence

Consult the shared findings store (`$WORK_DIR/audit_session.db`) for relevant findings from other expert auditors:

- WAF bypass techniques discovered by other auditors on the same target
- Leaked credentials or configuration values that may unlock new attack surfaces
- Related sinks that share code paths with the current target
- Authentication bypass methods that could change the attack context

#### Step 3: Decision Tree Matching

Use the failure pattern matching decision tree in `shared/pivot_strategy.md` to select a new attack direction:

- Map current failure patterns to known pivot recommendations
- Identify which attack categories remain untried
- Select the most promising next strategy based on the defense type identified

#### Step 4: Early Termination Decision

If Steps 1-3 yield no new viable attack paths:

- **Terminate early** rather than continuing with rounds that have no realistic chance of success
- Record the termination decision with full justification in the exploit result
- This prevents hallucinated "successful" attacks that waste downstream review effort

### Pivot Record Format

```json
{
  "smart_pivot_triggered": true,
  "trigger_round": 4,
  "consecutive_failures": 3,
  "pivot_actions": {
    "re_recon_findings": "Discovered alternative route /api/v2/exec that uses different filtering",
    "cross_intel_hits": ["WAF bypass via chunked encoding found by XSS auditor"],
    "decision_tree_match": "Pattern: WAF-blocked → Recommendation: Try HTTP smuggling or chunked encoding",
    "new_strategy": "chunked_transfer_encoding_bypass"
  },
  "outcome": "pivot_to_new_strategy | early_termination"
}
```

### Relationship with Smart Skip (S-102)

- Smart Pivot SHOULD be attempted **before** requesting Smart Skip
- If Smart Pivot finds a new path → continue with new strategy (no skip)
- If Smart Pivot finds no new paths → proceed to Smart Skip with full documentation

## Integration

Reference this skill from auditor files:
`> 📄 Shared protocol: skills/shared/smart_pivot_protocol.md`
