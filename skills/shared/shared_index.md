# Shared Protocol Skills — Index

> **Phase**: Cross-phase shared protocols for Phase-4 auditors
> **Directory**: `skills/shared/`

This index lists all 9 shared protocol skills that standardize auditor behavior across all Phase-4 attack agents.

| Skill ID | File | Responsibility |
|----------|------|----------------|
| S-100 | `auditor_memory_query.md` | Query attack memory store before starting attacks to optimize round ordering from historical data |
| S-101 | `round_record_format.md` | Define the standard JSON structure every attack round must produce for cross-auditor consistency |
| S-102 | `smart_skip_protocol.md` | Allow auditors to skip remaining attack rounds when continued testing is demonstrably futile |
| S-103 | `smart_pivot_protocol.md` | Trigger structured pivot sequence when auditor encounters repeated failures to find alternative paths |
| S-104 | `prerequisite_scoring_3d.md` | Standardize prerequisite declaration and 3D severity scoring for consistent vulnerability ratings |
| S-105 | `attack_memory_writer.md` | Persist attack experience (successes and failures) to memory store after attack cycle ends |
| S-106 | `second_order_tracking.md` | Enable cross-auditor intelligence sharing and track second-order vulnerability patterns |
| S-107 | `context_compression_protocol.md` | Manage token budget during multi-round attack loops by compressing completed rounds into summaries |
| S-108 | `general_self_check.md` | Define 8 universal self-check items (G1–G8) every Phase-4 auditor must execute before submission |

## Terminology Mapping

| Concept | round_record_format (S-101) | exploit result (final) | prerequisite_scoring_3d (S-105) |
|---------|---------------------------|----------------------|-------------------------------|
| Vulnerability confirmed exploitable | `result: "confirmed"` | `final_verdict: "CONFIRMED"` | `exploitability_judgment: "exploitable"` |
| Suspicious but unverified | `result: "suspected"` | `final_verdict: "SUSPECTED"` | `exploitability_judgment: "conditionally_exploitable"` |
| Defense prevents exploitation | `result: "failed"` | `final_verdict: "FAILED"` | `exploitability_judgment: "not_exploitable"` |
