# Agent Injection Layering System (Prompt Construction Specification)

> This file is extracted from SKILL.md and loaded by the main orchestrator via reference.

### Section 12: Agent Injection Layering System

To control the prompt token usage of each Agent, shared resources are divided into three tiers by injection priority:

#### Injection Tier Definitions

| Tier | Name | Strategy | Description |
|------|------|----------|-------------|
| **L1** | Required Injection (All Agents) | Full-text injection into all Agent prompts | Core rules; absence leads to hallucination or format errors |
| **L2** | Role-based Injection | Inject only to Agents requiring this resource | Domain knowledge, selectively injected by Agent responsibility |
| **L3** | On-demand Reference | Inject only file path + one-line summary; Agent reads on demand | Large reference libraries; full-text injection would exceed token budget |

#### L1 Required Injection Resources (All Agents)

- `shared/anti_hallucination.md` — Anti-hallucination rules
- `shared/data_contracts.md` — JSON Schema data contracts
- `shared/evidence_contract.md` — EVID_* evidence point dictionary (evidence citation specification for Phase-4 expert conclusion output)

> **Note**: `shared/sink_definitions.md` has been demoted from L1 to L2, injected only to Agents requiring Sink definitions (Phase-2 scanner agents/context-extractor/risk-classifier + Phase-4 experts). This saves approximately 25KB (~6000 tokens) of context space, reducing attention distraction for unrelated Agents.

#### L2 Role-based Injection Resources

| Resource File | Target Agent for Injection |
|---------------|----------------------------|
| `shared/sink_definitions.md` | Phase-2 scanner agents, context-extractor, risk-classifier + all Phase-4 experts |
| `shared/php_specific_patterns.md` | All Phase-4 experts + Phase-2 context-extractor |
| `shared/attack_chains.md` | Phase-4.5 attack-graph-builder + correlation-engine |
| `shared/known_cves.md` | Phase-2 dep-scanner + all Phase-4 experts |
| `shared/payload_templates.md` | All Phase-4 experts |
| `shared/waf_bypass.md` | All Phase-4 experts |
| `shared/context_compression.md` | All Phase-4 experts |
| `shared/pivot_strategy.md` | All Phase-4 experts |
| `shared/attack_memory.md` | All Phase-4 experts |
| `shared/attack_memory_graph.md` | All Phase-4 experts + Phase-4.5 correlation-engine + attack-graph-builder |
| `shared/framework_patterns.md` | Phase-2 context-extractor/risk-classifier + Phase-4 experts + Phase-4.5 remediation-generator |
| `shared/docker_snapshot.md` | Phase-4 experts (during Stage 2 attacks) |
| `shared/realtime_sharing.md` | Phase-4 experts |
| `shared/second_order.md` | Phase-4 experts + Phase-4.5 correlation-engine |
| `shared/false_positive_patterns.md` | Quality checker + Phase-4.5 correlation-engine |
| `shared/env_selfheal.md` | Phase-1 docker-builder |

> **Environment-conditional Injection**: When WAF is detected in `environment_status.json`, `shared/waf_bypass.md` is promoted from L2 to **L1.5** (forced full-text injection for all Phase-4 experts, not just on-demand reference).
> When the target is WordPress, the WordPress-related sections in `shared/known_cves.md` are fully injected to wordpress_auditor; other experts still reference via L3.

#### L3 On-demand Reference Resources

The following resources are **NOT fully injected**; only the path and summary are injected into the Agent prompt. Agents use the Read tool to read them when needed:

- `shared/lessons_learned.md` — Field experience library (historical audit pitfall records and solutions)
- `teams/team4/mini_researcher.md` — On-demand researcher Agent (spawned by the main orchestrator when an Auditor encounters unknown components or needs new direction after consecutive failures)

**L3 Injection Template** (format written into Agent prompt):
```
--- On-demand Reference Resources (L3) ---
The following resources are not fully injected; use the Read tool to read them when needed:

- ${SKILL_DIR}/shared/lessons_learned.md
  Summary: Historical audit field experience library, containing common pitfall scenarios, false positive/negative cases, and solutions for environment compatibility issues.
  Usage scenario: When you encounter abnormal behavior, uncertain Sink determination, or consecutive attack failures, you SHOULD consult this file for reference first.
```

#### Token Budget Rules

The L1 + L2 injected content (excluding the task instruction file itself) for each Agent MUST comply with the following line count limits:

| Agent Type | L1 + L2 Line Count Limit |
|------------|--------------------------|
| Phase-4 Expert Agent | **<= 1500 lines** |
| Phase-4.5 Agent | **<= 800 lines** |
| Phase-2 Agent | **<= 500 lines** |

**Over-budget Automatic Demotion Rules**: When constructing Agent prompts, the main orchestrator SHOULD count total L1 + L2 lines before injection:
- If exceeding the Agent type's line count limit → print warning:
  `"⚠️ Agent {name} L1+L2 injected content is {actual} lines, exceeding budget of {limit} lines. Automatically demoting the largest L2 resource to L3 (path + summary only)."`
- Demotion order: demote L2 resources to L3 one by one from largest to smallest file line count, until total lines <= limit
- Demoted resources SHALL be injected with path and summary using the L3 template format

