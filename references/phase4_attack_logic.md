# Phase 4: Deep Adversarial Audit (Attack Logic + Quality Check Orchestration)

> This file is extracted from SKILL.md and loaded by reference by the main orchestrator.

### Phase-4: Deep Adversarial Audit (Parallel Analysis + Sequential Attack)

**⚠️ This Phase is the sole source of Burp reproduction packages and physical evidence; it MUST NOT under any circumstances be skipped.**

**Container Conflict Avoidance Strategy**: Multiple specialists MUST NOT operate on the same Docker container simultaneously.
Use a **two-phase model**: first perform parallel static analysis (read files, no container interaction), then perform sequential dynamic attacks (exclusive container access).

Inject the following instructions into each specialist Agent's prompt:
```
Your work is divided into two stages:

Stage 1 (Analysis Stage): Read context_packs, traces, and source code; analyze filtering mechanisms; plan attack strategy;
  generate Payloads and injection points for each round. In this stage, MUST NOT send any HTTP requests or operate Docker containers.
  Write analysis results and attack plan to $WORK_DIR/attack_plans/{sink_id}_plan.json.

Stage 2 (Attack Stage): Read $WORK_DIR/attack_plans/{sink_id}_plan.json,
  execute attacks round by round per plan, collect evidence, snapshot and rollback.
  Write final results to $WORK_DIR/exploits/{sink_id}.json.

In both stages, write critical findings to the shared_findings table in $WORK_DIR/audit_session.db (refer to shared/realtime_sharing.md).
Before starting the attack stage, read the shared findings store to obtain other auditors' discoveries.
Record storage points and usage points to $WORK_DIR/second_order/ (refer to shared/second_order.md).

Enter Stage 2 only when you receive the "START_ATTACK" signal. Until then, only perform Stage 1.
```

> **Attack Memory**: Before a Phase-4 specialist starts the attack stage, it automatically queries `~/.php_audit/attack_memory.db` for historical records matching (sink_type + framework + PHP version range), prioritizes historically successful payloads, and skips known ineffective strategies. After completing the attack, it writes experience to the memory store. See `shared/attack_memory.md` for details.

── Step 1: Parallel Analysis (All specialists work simultaneously, no container interaction) ──

Spawn all specialist Agents simultaneously (background mode):

  For example (spawn on demand — skip if no corresponding sink exists, but framework-mandatory items MUST be started):

  Agent(name="rce_auditor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #{id} instructions (Stage 1 mode) + teams/team4/rce_auditor.md + shared/docker_snapshot.md
            + shared/payload_templates.md + shared/waf_bypass.md + shared/framework_patterns.md
            + shared resources + corresponding sink's context_packs + traces + credentials
            + tools/payload_encoder.php (provide path and usage) + tools/waf_detector.php (provide path and usage)
            + TARGET_PATH + WORK_DIR

  **Enhanced Context Injection** (applies to every specialist Agent):
  Extract enhanced fields from context_pack and inject at the end of the Agent prompt:
  ```
  --- Enhanced Context ---
  Route Priority: {context_pack.route_priority} (P0=Highest Risk, P3=Low Risk)
  Authentication Bypass Summary: auth_type={auth_bypass_summary.auth_type}, bypass_possibility={auth_bypass_summary.bypass_possibility}
    Available Bypass Methods: {auth_bypass_summary.bypass_methods}
  Filter Strength Score: {filter_strength_score}/100
    → ≤30: Weak defenses, prioritize direct injection attempts
    → 31-60: Filtering exists but may be bypassable, prioritize encoded/mutated payloads
    → 61-90: Strict filtering, prioritize logic bypass or context switching
    → ≥91: Nearly impossible to bypass, document effective defenses and attempt pivot
  Version Pre-assessment: {CVE list from version_alerts matching this Auditor; prioritize exploitation if available}
  ```

  **Strategy Selection Rules**:
  - `filter_strength_score ≤ 30` → Direct Attack mode (start with standard payloads)
  - `filter_strength_score 31-60` → Encoding Bypass mode (prioritize base64/hex/double-url encoding)
  - `filter_strength_score ≥ 61` → Logic Bypass mode (prioritize type confusion/second-order injection/context switching)
  - `auth_bypass_summary.bypass_possibility = "none"` → MUST use legitimate credentials (obtain from credentials.json)
  - `version_alert_priority = true` → Place known CVE exploitation plan first in attack plan

  Agent(name="sqli_auditor", ...) and other specialists... (all specialists use mode="bypassPermissions")
  (All Phase-4 specialist Agents MUST be injected with: shared/payload_templates.md + shared/waf_bypass.md
    + shared/framework_patterns.md + shared/php_specific_patterns.md + shared/known_cves.md
    + tools/payload_encoder.php + tools/waf_detector.php)

Wait for all analyses to complete
── Step 2: Sequential Attack (Specialists take exclusive container access one at a time) ──

Sort specialists by priority (specialists corresponding to P0 sinks first):

  Iterate over each specialist that has completed analysis:

    Agent(name="{type}-auditor-attack", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
      → prompt: "START_ATTACK signal + You have completed Stage 1 analysis, now execute Stage 2.
                Read $WORK_DIR/attack_plans/{sink_id}_plan.json and attack round by round per plan."
              + teams/team4/{type}_auditor.md + shared/docker_snapshot.md
              + shared/payload_templates.md + shared/waf_bypass.md + shared/framework_patterns.md
              + shared resources + tools/payload_encoder.php (provide path and usage) + tools/waf_detector.php (provide path and usage)
              + TARGET_PATH + WORK_DIR

    Completed → Next specialist

    **Exception Handling**: If a specialist Agent exits abnormally (crash/timeout/error):
    1. Log exception information to `$WORK_DIR/exploits/{sink_id}_error.json`:
       ```json
       {"sink_id": "...", "specialist": "...", "error": "Agent exited abnormally", "partial_results": true}
       ```
    2. Check if `$WORK_DIR/attack_plans/{sink_id}_plan.json` exists (preserve Stage 1 analysis results)
    3. Mark ⚠️ in pipeline view
    4. **Continue to next specialist** (do not interrupt overall flow)

── Step 3: Pivot When Stuck (Auto-Redirect When Stuck) ──

#### Pivot Pre-assessment (Environment Pre-filtering)

During Stage 1 analysis, each Auditor pre-assesses which Pivot paths are unavailable based on `environment_status.json`, to avoid ineffective attempts during the attack stage:

| Environment Condition | Unavailable Pivot | Reason |
|----------|-------------|------|
| `allow_url_include = Off` | php://filter chain RCE | Cannot load remote streams via include |
| `disable_functions` contains `mail` | mail() header injection pivot | mail() is disabled |
| No `unserialize()` entry point and no phar:// | Deserialization RCE pivot | No deserialization trigger point |
| Not MySQL or no wide-byte encoding | Wide-byte SQLi pivot | Wide-byte bypass only applies to MySQL with GBK/GB2312 encoding |
| PHP ≥ 8.0 | Type Juggling `0e` hash | PHP 8.0 made string/number comparisons strict |
| No LDAP extension | LDAP authentication bypass pivot | Target has no LDAP dependency |
| Framework CSRF middleware covers all routes | CSRF except-route pivot | No excluded routes to exploit |

**Pre-assessment Output**: Each Auditor adds `available_pivots` and `excluded_pivots` fields in `{sink_id}_plan.json`:
```json
{
  "available_pivots": ["second_order_sqli", "blind_sqli_oob"],
  "excluded_pivots": [
    {"pivot": "widechar_sqli", "reason": "DB encoding is utf8mb4, not wide-byte"}
  ]
}
```

When a specialist Agent continuously fails during Stage 2 attacks, the following pivot rules automatically switch audit strategy:

| Trigger Condition | Switch To | Additional Resources |
|---|---|---|
| **sqli_auditor fails 8 consecutive rounds of Payload** (no error differences, no time differences, no response differences) | Switch to **Second-Order SQLi audit**: Have context-extractor trace data usage points after retrieval from DB (store→read→concatenate SQL), reconstruct payload targeting the storage point | `shared/second_order.md` + context-extractor's data-flow output; need to trace back INSERT/UPDATE statements to corresponding SELECT consumption paths |
| **xss_ssti_auditor fully blocked by WAF/htmlspecialchars** (all XSS vectors filtered, no bypass possible) | Auto-attempt **SSTI audit**: The same injection point may be a template engine rendering entry (Twig/Blade/Smarty), probe with `{{7*7}}` / `${7*7}` | `teams/team4/xss_ssti_auditor.md` SSTI section; requires `shared/framework_patterns.md` to confirm template engine type |
| **lfi_auditor path traversal filtered** (`../` replaced, realpath restricted, open_basedir blocked) | Pivot to **php://filter chain** attack: Bypass filesystem paths using `php://filter/convert.base64-encode/resource=` or filter chain RCE | `shared/payload_templates.md` LFI filter chain templates; need to confirm `allow_url_include` status |
| **rce_auditor dangerous functions disabled by disable_functions** (system/exec/passthru/shell_exec all in disabled list) | Pivot to **Deserialization RCE**: Find `unserialize()` entry points, trigger code execution via POP chain through `__destruct`/`__wakeup` | `teams/team4/deserial_auditor.md` + `shared/payload_templates.md` deserialization section; need Composer dependency list to construct gadget chain |
| **ssrf_auditor internal addresses unreachable** (target server network-isolated, 127.0.0.1/internal ranges filtered or no callback possible) | Pivot to **DNS Rebinding**: Use controllable DNS records (TTL=0) to let target first resolve to external IP for validation, then rebind to internal address | Requires DNS rebinding service (e.g., rbndr.us or self-hosted); `shared/payload_templates.md` SSRF DNS rebinding templates |
| **crlf_auditor PHP ≥7.0 header() built-in protection cannot be bypassed** (native header() detects `\r\n` and throws Warning) | Pivot to **mail() header injection**: Target `mail()` `additional_headers` parameter (not protected by header()), or audit framework response header wrapper methods for native check bypasses | `shared/payload_templates.md` CRLF templates; check framework version's handling of header wrapping |
| **csrf_auditor Token validation strict and cannot be bypassed** (framework CSRF middleware correctly implemented, Token not reusable/predictable) | Pivot to **JSON CSRF + CORS audit**: Check if API endpoints have permissive CORS configuration (`Access-Control-Allow-Origin: *`) allowing cross-origin credentialed requests, or find routes excluded by `$except` | `teams/team4/config_auditor.md` CORS audit results; check `VerifyCsrfToken::$except` and API route middleware groups |
| **session_auditor Session management fully hardened** (strict_mode=1, regenerate_id correct, HttpOnly/Secure both set) | Pivot to **Session serialization injection**: Check `session.serialize_handler` inconsistency (php vs php_serialize) leading to deserialization injection, or missing authentication on Session storage backend (Redis/Memcached) | `teams/team4/deserial_auditor.md` deserialization knowledge; `shared/framework_patterns.md` Session driver configuration |
| **ldap_auditor LDAP filter properly escaped** (using `ldap_escape()` or parameterized queries) | Pivot to **LDAP authentication bypass**: Check `ldap_bind()` empty password/anonymous bind, DN component injection, LDAP referral following configuration | No additional resources; focus on LDAP server configuration rather than code level |
| **logging_auditor log recording is secure with no injection** (log content escaped, no sensitive data) | Pivot to **Log file inclusion chain**: Check if log file paths overlap with LFI audit inclusion paths, construct "inject PHP code into log → LFI include log file" attack chain | `teams/team4/lfi_auditor.md` LFI knowledge; need to confirm intersection of log file paths and LFI-controllable paths |

> **Smart Pivot (v2)**: The above static mapping serves as the base strategy. When 3 consecutive rounds fail and no static mapping matches, trigger the Smart Pivot subprocess (see `shared/pivot_strategy.md`): first execute Mini-Researcher to re-reconnoiter target code → consult shared_findings for cross-intelligence → select new attack direction via failure-pattern decision tree. If breakthrough remains impossible after Pivot, terminate early and provide manual review recommendations.

── Mini-Researcher Delegation Mechanism (Triggered on Demand) ──

> See `teams/team4/mini_researcher.md` for the complete researcher Agent definition.

**Design Principle**: Inspired by PentAGI's Expert Delegation pattern — when an Auditor encounters a problem beyond its knowledge scope, it SHOULD NOT blindly attempt solutions, but instead delegate to a specialized researcher Agent to gather intelligence before proceeding.

**Trigger Conditions** (any one met triggers main orchestrator to spawn Mini-Researcher):

| ID | Trigger Scenario | Judgment Criteria | Delegation Content |
|------|----------|----------|----------|
| MR-1 | Auditor encounters unknown third-party component | `dep_scanner` output contains a component not in `framework_patterns.md` | Search for known CVEs + exploitation methods for that component |
| MR-2 | version_alerts has Critical CVE but lacks exploitation details | `version_alerts[].severity = "critical"` and `known_cves.md` has no corresponding PoC | Search for specific CVE exploitation chain + prerequisites |
| MR-3 | Auditor fails 5 consecutive rounds with filter_strength_score ≥ 61 | Attack log shows 5 consecutive rounds with verdict = failed | Research known bypass techniques for the target filtering mechanism |
| MR-4 | Still failing after Pivot (secondary deadlock) | pivot_triggered = true followed by another 3 consecutive failed rounds | Comprehensive search for alternative attack surfaces in the target environment |
| MR-5 | Non-standard framework feature discovered | Auditor encounters unrecognizable security middleware/filter during analysis stage | Security implications + bypass methods for that feature |

**Delegation Flow**:

1. **Main orchestrator detects trigger conditions**: During Step 2 sequential attack loop, check the above 5 conditions after each Auditor's attack round
2. **Construct research request**:
   ```json
   {
     "research_query": "Does Laravel Sanctum 2.x token validation have a time-of-check-to-time-of-use race condition bypass",
     "context": "authz_auditor failed 5 consecutive rounds on /api/admin/* routes, all token forgery attempts correctly rejected",
     "target_component": "laravel/sanctum@2.15.1"
   }
   ```
3. **Spawn Mini-Researcher**:
   ```
   Agent(name="mini-researcher-{N}", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
     → prompt: teams/team4/mini_researcher.md
             + RESEARCH_QUERY + CONTEXT + TARGET_COMPONENT
             + WORK_DIR + SKILL_DIR
   ```
4. **Inject research results**: After the researcher outputs `$WORK_DIR/research/{research_id}.json`, the main orchestrator injects the result summary into the requesting Auditor's next attack round prompt:
   ```
   ## Researcher Intelligence (Auto-injected)
   Regarding your query: "{research_query}"
   Researcher findings: {findings summary}
   Suggested attempts: {recommendations}
   Confidence: {confidence} | Sources: {sources}
   ```
5. **Auditor continues attack**: After receiving research results, the Auditor adjusts strategy based on intelligence and continues remaining attack rounds

**Constraints**:
- Each audit triggers at most **10** research delegations (global counter `research_count`; skip if limit exceeded)
- Each research is limited to **3 minutes**; return partial results on timeout
- Mini-Researcher MUST only research, not attack (MUST NOT send HTTP requests or operate containers)
- Research results MUST include source attribution and confidence level; Auditor MUST NOT use `low` confidence intelligence as sole basis

**Pivot Execution Flow**:
1. Specialist Agent marks `pivot_triggered: true` + reason in attack log
2. Main orchestrator detects pivot marker and spawns the corresponding new specialist (or reuses the same specialist in a different mode)
3. New specialist inherits original specialist's context_packs and collected information, avoiding redundant reconnaissance
4. Pivot results are written to `$WORK_DIR/exploits/{sink_id}_pivot.json` and merged with original results

── Step 4: Quality check immediately after each Auditor completes attack ("verify each upon completion") ──

  **Quality Checker Pool Management:** Maintain a quality-checker pool with max concurrency of min(active Auditor count, 5).
  Prioritize reusing idle quality checkers; spawn new instances when insufficient. Pool quality checkers SHALL NOT be closed until Phase 4 ends.

  After each Auditor completes the attack stage:

  1. Check if there is an idle quality checker in the pool:
     - Yes → Reuse that quality checker (send new task via write_agent)
     - No and limit not reached → Spawn new quality checker
     - No and limit reached → Wait for the first quality checker to complete

  2. Assign quality check task (9 general items + specialized checks):

  Agent(name="quality-checker-N", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: teams/qc/quality_checker.md
            + references/quality_check_templates.md (Phase 4: Individual Auditor verification + corresponding Auditor specialized checks)
            + shared/output_standard.md + shared/evidence_contract.md
            + PHASE=4-auditor, TARGET_AGENT={auditor_name}, OUTPUT_FILES=exploits/{sink_id}.json
            + WORK_DIR

  **Specialized Check Assignment:** Quality checker locates the corresponding specialized table in quality_check_templates.md based on TARGET_AGENT type:
  - rce_auditor → "rce_auditor specialized" 5 items
  - sqli_auditor → "sqli_auditor specialized" 5 items
  - xss_ssti_auditor → "xss_ssti_auditor specialized" 5 items
  - ... 21 Auditor types total, each with specialized checks (5 items each)

  Quality checker MUST complete both: 9 general items table + corresponding 5 specialized items table = 14 total checks.

  3. Handle quality check results:
  - verdict=pass → Close that Auditor, mark quality checker as idle for reuse
  - verdict=fail → Send failed_items (including specialized failures) back to that Auditor for remediation:
    * 1st redo: Auditor supplements physical evidence per fix requirements
    * 2nd redo: Still failing → Downgrade that Auditor's confidence (confirmed → suspected), no further redo
  - All redo records written to SQLite: `bash tools/audit_db.sh qc-write "$WORK_DIR" '{...}'`

  **Parallel QC Example:** If sqli_auditor, rce_auditor, xss_ssti_auditor complete attacks in sequence:
  ```
  sqli_auditor completed → spawn quality-checker-1 (verify sqli general + specialized)
  rce_auditor completed  → spawn quality-checker-2 (verify rce general + specialized)
  xss_ssti_auditor completed → quality-checker-1 idle → reuse (verify xss general + specialized)
  ```

── Step 5: Phase 4 Comprehensive Verification + Cross-phase Consistency Verification ──

  After all Auditors pass individual verification, spawn one quality checker for comprehensive verification:

  Agent(name="quality-checker-final-phase4", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: teams/qc/quality_checker.md
            + references/quality_check_templates.md (Phase 4: Physical Evidence Comprehensive Verification + Cross-phase Data Consistency Verification)
            + shared/output_standard.md + shared/evidence_contract.md + shared/false_positive_patterns.md
            + PHASE=4, TARGET_AGENT=team4, OUTPUT_FILES=team4_progress.json,exploits/,priority_queue.json,auth_matrix.json,credentials.json
            + WORK_DIR

  Comprehensive quality checker performs two parts:
  (a) Physical Evidence Comprehensive Verification (8 items) — team4_progress.json + exploits/*.json completeness
  (b) Cross-phase Data Consistency Verification (18 items) — P0 coverage/auth consistency/Sink mapping/filter bypass/credential depth/EVID completeness

  verdict=fail:
  - Comprehensive verification failure → Locate specific Auditor for remediation (no new redo counter; part of Phase 4 overall flow)
  - Cross-phase consistency MUST-PASS (C1-C4, C16-C18) failure → Mandatory fix
  - Cross-phase consistency SHOULD-PASS (C5-C15) allows ≤2 WARN items → Mark as degraded and continue

Completed
Parse comprehensive quality check results, close all quality checkers in Phase 4 quality checker pool

**Phase-4 Gate Verification** (MUST execute):
```bash
test -d "$WORK_DIR/exploits" && ls "$WORK_DIR/exploits/"*.json >/dev/null 2>&1 && echo "GATE-4 PASS" || echo "GATE-4 FAIL: exploits/ 不存在或为空，report-writer 将无法生成 Burp 复现包"
```
GATE-4 PASS → Write to checkpoint.json: {"completed": ["env", "scan", "trace", "exploit"], "current": "report"}

**Generate Vulnerability Summary**: Execute immediately after GATE-4 PASS:
```bash
# Aggregate all exploit results to generate exploit_summary.json
CONFIRMED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="confirmed")] | length')
SUSPECTED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="suspected")] | length')
TOTAL=$(ls "$WORK_DIR/exploits/"*.json 2>/dev/null | wc -l)
RACE=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.race_condition_results.result=="vulnerable")] | length')
cat > "$WORK_DIR/exploit_summary.json" << EOF
{
  "total_sinks": $TOTAL,
  "vulnerabilities_confirmed": $CONFIRMED,
  "vulnerabilities_suspected": $SUSPECTED,
  "race_conditions_found": $RACE
}
EOF
```

GATE-4 FAIL → **Do NOT write to checkpoint**. Check whether Phase-4 specialist Agents were actually spawned. If not spawned, immediately return to Phase-4 Step 1 and execute.

Print pipeline view

