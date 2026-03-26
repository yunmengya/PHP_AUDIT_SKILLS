# Phase-4 Auditor Skills — Master Index

> This index documents the 21 auditor agents and their 2-stage invocation pattern.

## 2-Stage Invocation Pattern

Each auditor operates in two stages within a single agent lifecycle:

| Stage | Name | Access | Duration | Description |
|-------|------|--------|----------|-------------|
| Stage 1 | **Analyze** | Read-only (source + traces) | Until WAIT signal | Read trace chains, identify filters, plan attack vectors, generate `{sink_id}_plan.json` |
| Stage 2 | **Attack** | Container exec | 8 rounds max | Execute planned attacks via `docker exec`, collect evidence, record results |

**Transition**: Orchestrator sends `START_ATTACK` signal after ALL auditors of the same priority tier (P0/P1/P2/P3) complete Stage 1.

## Auditor Registry

| Skill ID | File | Sink Types | Priority Coverage |
|----------|------|-----------|-------------------|
| S-040 | `teams/team4/rce_auditor.md` | eval, system, exec, passthru, shell_exec, popen, proc_open, call_user_func, create_function | P0 (Anonymous+High) |
| S-041 | `teams/team4/sqli_auditor.md` | query, prepare, raw SQL, DB::statement, whereRaw | P0-P1 |
| S-042 | `teams/team4/deserial_auditor.md` | unserialize, __wakeup, __destruct, json_decode+instantiate | P0 |
| S-043 | `teams/team4/lfi_auditor.md` | include, require, include_once, require_once, file_get_contents | P0-P1 |
| S-044 | `teams/team4/filewrite_auditor.md` | file_put_contents, fwrite, move_uploaded_file, rename, copy | P0-P1 |
| S-045 | `teams/team4/ssrf_auditor.md` | curl_exec, file_get_contents(url), fopen(url), SoapClient | P1 |
| S-046 | `teams/team4/xss_ssti_auditor.md` | echo, print, Blade {!! !!}, Twig raw, Smarty, template injection | P1-P2 |
| S-047 | `teams/team4/xxe_auditor.md` | simplexml_load_string, DOMDocument::loadXML, XMLReader | P1 |
| S-048 | `teams/team4/authz_auditor.md` | Auth::check, Gate::allows, $this->authorize, middleware bypass | P0-P1 |
| S-049 | `teams/team4/config_auditor.md` | .env, config(), debug mode, exposed keys, default credentials | P1-P2 |
| S-050 | `teams/team4/infoleak_auditor.md` | phpinfo, var_dump, print_r, error display, debug endpoints | P2 |
| S-051 | `teams/team4/nosql_auditor.md` | MongoDB::find, Redis::eval, Memcached injection | P1 |
| S-052 | `teams/team4/race_condition_auditor.md` | flock, DB transaction, file-based locks, TOCTOU | P1-P2 |
| S-053 | `teams/team4/crypto_auditor.md` | md5, sha1, rand, openssl_encrypt, weak key derivation | P2 |
| S-054 | `teams/team4/wordpress_auditor.md` | wp_ajax, add_action, apply_filters, wpdb::prepare | P0-P2 |
| S-055 | `teams/team4/business_logic_auditor.md` | Price manipulation, coupon reuse, step skip, rate limit | P1-P2 |
| S-056 | `teams/team4/crlf_auditor.md` | header(), setcookie(), Location redirect | P2 |
| S-057 | `teams/team4/csrf_auditor.md` | form without token, AJAX without X-CSRF, state-change GET | P2 |
| S-058 | `teams/team4/session_auditor.md` | session_start, session_regenerate_id, cookie flags | P1-P2 |
| S-059 | `teams/team4/ldap_auditor.md` | ldap_search, ldap_bind, ldap_modify | P1 |
| S-060 | `teams/team4/logging_auditor.md` | error_log, syslog, Log::info, sensitive data in logs | P2-P3 |

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
| Exploit result | `$WORK_DIR/exploit_results/{sink_id}_result.json` | Stage 2 output: final_verdict, evidence, PoC |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Standalone reproduction script |
| Patch | `$WORK_DIR/修复补丁/{sink_id}_patch.diff` | Recommended fix |

## mini_researcher (S-061)

| Skill ID | File | Role |
|----------|------|------|
| S-061 | `teams/team4/mini_researcher.md` | Triggered when an auditor's 8 rounds all fail but confidence > threshold. Spawns a focused research sub-agent with fresh context. Max 3 per audit. |
