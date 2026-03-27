# Dynamic Task Creation (Executed After Phase 2 Completion)

Read $WORK_DIR/priority_queue.json and create Phase-4 specialist tasks by sink type.

## Sink Type → Agent Mapping Table

| sink_type | agent_name | agent_md file |
|-----------|-----------|--------------|
| eval/system/exec/extract/parse_str | rce-auditor | teams/team4/rce_auditor.md |
| query/execute/DB::raw/whereRaw | sqli-auditor | teams/team4/sqli_auditor.md |
| unserialize/phar | deserial-auditor | teams/team4/deserial_auditor.md |
| include/require | lfi-auditor | teams/team4/lfi_auditor.md |
| file_put_contents/move_uploaded_file | filewrite-auditor | teams/team4/filewrite_auditor.md |
| curl_exec/file_get_contents(url) | ssrf-auditor | teams/team4/ssrf_auditor.md |
| echo/print/template rendering | xss-auditor | teams/team4/xss_ssti_auditor.md |
| simplexml_load/DOMDocument | xxe-auditor | teams/team4/xxe_auditor.md |
| auth bypass/mass_assignment/weak comparison | authz-auditor | teams/team4/authz_auditor.md |
| Configuration issues | config-auditor | teams/team4/config_auditor.md |
| Information leakage | infoleak-auditor | teams/team4/infoleak_auditor.md |
| MongoDB/$where/Redis | nosql-auditor | teams/team4/nosql_auditor.md |
| Race condition/TOCTOU/concurrency | race-auditor | teams/team4/race_condition_auditor.md |
| md5/sha1/rand/weak cryptography | crypto-auditor | teams/team4/crypto_auditor.md |
| wp_ajax/xmlrpc/shortcode | wp-auditor | teams/team4/wordpress_auditor.md |
| Price tampering/flow bypass/business logic | bizlogic-auditor | teams/team4/business_logic_auditor.md |
| form without token/AJAX without X-CSRF/state-change GET | csrf-auditor | teams/team4/csrf_auditor.md |
| session_start/session_regenerate_id/cookie flags | session-auditor | teams/team4/session_auditor.md |
| ldap_search/ldap_bind/ldap_modify | ldap-auditor | teams/team4/ldap_auditor.md |
| header()/setcookie()/Location redirect injection | crlf-auditor | teams/team4/crlf_auditor.md |
| error_log/syslog/Log::info/sensitive data in logs | logging-auditor | teams/team4/logging_auditor.md |

## Framework-Adaptive Dispatch

Read the `framework` field from $WORK_DIR/environment_status.json:

- **WordPress** → MUST launch wp-auditor
- **Laravel** → MUST launch config-auditor + authz-auditor
- **ThinkPHP** → MUST launch rce-auditor + sqli-auditor
- **Symfony** → MUST launch config-auditor
- **All frameworks** → MUST launch infoleak-auditor + bizlogic-auditor

## Task Creation

**TEMPLATE: Task numbers 15+ are dynamic. Orchestrator MUST renumber based on actual sink count and order. Do NOT use these numbers literally.**

Create Tasks ONLY for specialists whose corresponding sink type exists (or is framework-mandatory):

```
task-15: "{type} specialist audit"  activeForm="Audit {type} vulnerabilities"  (blockedBy: [14])
task-16: ...(one per sink type)
```

Create quality checker Task:
```
task-N: "Quality checker forensic verification"  activeForm="Forensic verification"  (blockedBy: [all exploit tasks])
```

Create Phase-4.5 tasks:
```
task-M:   "Attack graph construction"       activeForm="Build attack graph"       (blockedBy: [N])
task-M+1: "Cross-auditor correlation analysis"  activeForm="Correlation analysis"  (blockedBy: [N])
task-M+2: "Remediation code generation"     activeForm="Generate fix patches"     (blockedBy: [M, M+1])
task-M+3: "PoC script generation"           activeForm="Generate PoC scripts"     (blockedBy: [M, M+1])
```

Create Phase-5 tasks:
```
task-N+1: "Environment cleanup"       activeForm="Clean up test environment"   (blockedBy: [M+2, M+3])
task-N+2: "Report writing"            activeForm="Write audit report"          (blockedBy: [M+2, M+3])
task-N+3: "SARIF export"              activeForm="Export SARIF report"         (blockedBy: [M+2, M+3])
task-N+4: "quality-checker-final"     activeForm="Verify report completeness"  (blockedBy: [N+1, N+2, N+3])
```

**Record all dynamic TASK_ID mappings for use by subsequent Phases.**
