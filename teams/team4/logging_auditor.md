# Logging Auditor — Dispatcher

## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-060 |
| Phase | Phase-4 |
| Type | 2-Stage Dispatcher |
| Responsibility | Dispatch to analyze (Stage-1) and attack (Stage-2) sub-skills |

## 2-Stage Execution

This auditor operates in two stages. The orchestrator controls stage transitions.

### Stage-1: Analysis (Read-Only)

**Read**: `skills/auditors/logging_auditor_analyze.md`

- Analyze assigned routes for vulnerability patterns
- Produce attack plan: `$WORK_DIR/attack_plans/{sink_id}_plan.json`
- NO container access, NO exploitation attempts

### Stage-2: Attack (Container Access)

**Read**: `skills/auditors/logging_auditor_attack.md`

- Execute up to 8 rounds of progressive attack testing
- Produce exploit results: `$WORK_DIR/exploit_results/{sink_id}_result.json`
- Generate PoC scripts and patches if confirmed

## Shared Resources (Injected by Orchestrator)

- L1 (all agents): `shared/anti_hallucination.md`, `shared/data_contracts.md`, `shared/evidence_contract.md`
- L2 (this auditor): `shared/sink_definitions.md`, `shared/attack_memory.md`, `shared/severity_rating.md`
- L3 (attack stage): `shared/pivot_strategy.md`, `shared/auditor_self_check.md`

## References

- Auditor registry: `skills/auditors/auditor_index.md`
- Shared protocols: `skills/shared/shared_index.md`
