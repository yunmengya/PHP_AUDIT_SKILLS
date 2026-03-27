# Crypto Auditor — Dispatcher

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-053 |
| Phase | Phase-4 |
| Type | 2-Stage Dispatcher |
| Responsibility | Dispatch to analyze (Stage-1) and attack (Stage-2) sub-skills |

## 2-Stage Execution

This auditor operates in two stages. The orchestrator controls stage transitions.

### Stage-1: Analysis (Read-Only)

**Read**: `skills/auditors/crypto_auditor_analyze.md`

- Analyze assigned routes for vulnerability patterns
- Produce attack plan: `$WORK_DIR/attack_plans/{sink_id}_plan.json`
- NO container access, NO exploitation attempts

### Stage-2: Attack (Container Access)

**Read**: `skills/auditors/crypto_auditor_attack.md`

- Execute up to 8 rounds of progressive attack testing
- Produce exploit results: `$WORK_DIR/exploits/{sink_id}.json`
- Generate PoC scripts and patches if confirmed

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST read the sub-skill file completely before responding — partial reading leads to missing attack vectors | Missed vulnerabilities |
| CR-2 | Stage-1 MUST NOT access the Docker container or send HTTP requests — analysis only | Stage violation → QC FAIL |
| CR-3 | MUST follow `shared/degradation_check.md` Step 0 before processing | Degraded data treated as complete |
| CR-4 | Output MUST pass `shared/pre_submission_checklist.md` P1-P8 before returning to orchestrator | Known-bad output wastes QC cycle |

## Shared Resources (Injected by Orchestrator)

- L1 (all agents): `shared/anti_hallucination.md`, `shared/data_contracts.md`, `shared/evidence_contract.md`
- L2 (this auditor): `shared/sink_definitions.md`, `shared/attack_memory.md`, `shared/severity_rating.md`
- L3 (attack stage): `shared/pivot_strategy.md`, `shared/auditor_self_check.md`

## References

- Auditor registry: `skills/auditors/auditor_index.md`
- Shared protocols: `skills/shared/shared_index.md`
