# Phase-4 Auditor Skills — Master Index

> This index documents the 21 auditor agents and their 2-stage invocation pattern.
> Each auditor is physically split into two skill files: `_analyze.md` (Stage 1) and `_attack.md` (Stage 2).

## 2-Stage Invocation Pattern (2-File Structure)

Each auditor is split into **two independent skill files** for focused context loading:

| Stage | Suffix | Access | Duration | Description |
|-------|--------|--------|----------|-------------|
| Stage 1 | `_analyze.md` | Read-only (source + traces) | Until WAIT signal | Read trace chains, identify filters, plan attack vectors, generate `{sink_id}_plan.json` |
| Stage 2 | `_attack.md` | Container exec | 8 rounds max | Execute planned attacks via `docker exec`, collect evidence, record results |

**Transition**: Orchestrator sends `START_ATTACK` signal after ALL auditors of the same priority tier (P0/P1/P2/P3) complete Stage 1.

## Auditor Registry — All 42 Files

| Skill ID | Analyze File | Attack File | Sink Types | Priority |
|----------|-------------|-------------|-----------|----------|
| S-040 | `skills/auditors/rce_auditor_analyze.md` | `skills/auditors/rce_auditor_attack.md` | eval, system, exec, passthru, shell_exec, popen, proc_open, call_user_func, create_function | P0 |
| S-041 | `skills/auditors/sqli_auditor_analyze.md` | `skills/auditors/sqli_auditor_attack.md` | query, prepare, raw SQL, DB::statement, whereRaw | P0-P1 |
| S-042 | `skills/auditors/deserial_auditor_analyze.md` | `skills/auditors/deserial_auditor_attack.md` | unserialize, __wakeup, __destruct, json_decode+instantiate | P0 |
| S-043 | `skills/auditors/lfi_auditor_analyze.md` | `skills/auditors/lfi_auditor_attack.md` | include, require, include_once, require_once, file_get_contents | P0-P1 |
| S-044 | `skills/auditors/filewrite_auditor_analyze.md` | `skills/auditors/filewrite_auditor_attack.md` | file_put_contents, fwrite, move_uploaded_file, rename, copy | P0-P1 |
| S-045 | `skills/auditors/ssrf_auditor_analyze.md` | `skills/auditors/ssrf_auditor_attack.md` | curl_exec, file_get_contents(url), fopen(url), SoapClient | P1 |
| S-046 | `skills/auditors/xss_ssti_auditor_analyze.md` | `skills/auditors/xss_ssti_auditor_attack.md` | echo, print, Blade {!! !!}, Twig raw, Smarty, template injection | P1-P2 |
| S-047 | `skills/auditors/xxe_auditor_analyze.md` | `skills/auditors/xxe_auditor_attack.md` | simplexml_load_string, DOMDocument::loadXML, XMLReader | P1 |
| S-048 | `skills/auditors/authz_auditor_analyze.md` | `skills/auditors/authz_auditor_attack.md` | Auth::check, Gate::allows, $this->authorize, middleware bypass | P0-P1 |
| S-049 | `skills/auditors/config_auditor_analyze.md` | `skills/auditors/config_auditor_attack.md` | .env, config(), debug mode, exposed keys, default credentials | P1-P2 |
| S-050 | `skills/auditors/infoleak_auditor_analyze.md` | `skills/auditors/infoleak_auditor_attack.md` | phpinfo, var_dump, print_r, error display, debug endpoints | P2 |
| S-051 | `skills/auditors/nosql_auditor_analyze.md` | `skills/auditors/nosql_auditor_attack.md` | MongoDB::find, Redis::eval, Memcached injection | P1 |
| S-052 | `skills/auditors/race_condition_auditor_analyze.md` | `skills/auditors/race_condition_auditor_attack.md` | flock, DB transaction, file-based locks, TOCTOU | P1-P2 |
| S-053 | `skills/auditors/crypto_auditor_analyze.md` | `skills/auditors/crypto_auditor_attack.md` | md5, sha1, rand, openssl_encrypt, weak key derivation | P2 |
| S-054 | `skills/auditors/wordpress_auditor_analyze.md` | `skills/auditors/wordpress_auditor_attack.md` | wp_ajax, add_action, apply_filters, wpdb::prepare | P0-P2 |
| S-055 | `skills/auditors/business_logic_auditor_analyze.md` | `skills/auditors/business_logic_auditor_attack.md` | Price manipulation, coupon reuse, step skip, rate limit | P1-P2 |
| S-056 | `skills/auditors/crlf_auditor_analyze.md` | `skills/auditors/crlf_auditor_attack.md` | header(), setcookie(), Location redirect | P2 |
| S-057 | `skills/auditors/csrf_auditor_analyze.md` | `skills/auditors/csrf_auditor_attack.md` | form without token, AJAX without X-CSRF, state-change GET | P2 |
| S-058 | `skills/auditors/session_auditor_analyze.md` | `skills/auditors/session_auditor_attack.md` | session_start, session_regenerate_id, cookie flags | P1-P2 |
| S-059 | `skills/auditors/ldap_auditor_analyze.md` | `skills/auditors/ldap_auditor_attack.md` | ldap_search, ldap_bind, ldap_modify | P1 |
| S-060 | `skills/auditors/logging_auditor_analyze.md` | `skills/auditors/logging_auditor_attack.md` | error_log, syslog, Log::info, sensitive data in logs | P2-P3 |

## Priority-Tiered Dispatch Order

```
P0 auditors → Stage 1 (parallel) → WAIT ALL → Stage 2 (sequential, container-exclusive)
P1 auditors → Stage 1 (parallel) → WAIT ALL → Stage 2 (sequential)
P2 auditors → Stage 1 (parallel) → WAIT ALL → Stage 2 (sequential)
P3 auditors → Stage 1 (parallel) → WAIT ALL → Stage 2 (sequential)
```

## Output Per Auditor

| File | Path | Description |
|------|------|-------------|
| Attack plan | `$WORK_DIR/attack_plans/{sink_id}_plan.json` | Stage 1 output: vectors, payloads, bypass strategies |
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | Stage 2 output: final_verdict, evidence, PoC |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Standalone reproduction script |
| Patch | `$WORK_DIR/修复补丁/{sink_id}_patch.diff` | Recommended fix |

## mini_researcher (S-061)

| Skill ID | File | Role |
|----------|------|------|
| S-061 | `teams/team4/mini_researcher.md` | Triggered when an auditor's 8 rounds all fail but confidence > threshold. Spawns a focused research sub-agent with fresh context. Max 3 per audit. |
