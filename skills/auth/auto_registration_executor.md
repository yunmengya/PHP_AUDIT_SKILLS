# Auto-Registration & Login Executor

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038b |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | Automatically register a test account on the target application, log in, and extract session credentials (cookie or bearer token). Preferred (least-invasive) strategy for obtaining authenticated-level credentials. |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Route map | `$WORK_DIR/route_map.json` | ✅ | Endpoint URLs, HTTP methods, controller references |
| Controller source | `$TARGET_PATH/app/Http/Controllers/` | ✅ | Registration/login controller parameter lists |
| Docker environment | Running containers (`php`, `nginx`, `db`) | ✅ | Curl execution context |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate credentials for existing accounts — only use credentials discovered from source code analysis, `$WORK_DIR/credentials.json`, or test accounts created by this procedure | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to `$WORK_DIR/auth/` directory conforming to output contract schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST verify registration was successful by logging in with the registered credentials | FAIL — registration silently failed, no valid account created |

---

## Fill-in Procedure

### Step 1 — Locate Registration & Login Endpoints

Search `route_map.json` for endpoints matching:
- URL contains: `register`, `signup`, `login`, `auth`
- Method: `POST`

### Step 2 — Analyze Request Parameters

Read the corresponding controller source code to identify required fields. Common fields:

| Field | Example Value |
|-------|---------------|
| `name` | `audit_user` |
| `email` | `audit@test.com` |
| `password` | `AuditPass123!` |
| `password_confirmation` | `AuditPass123!` |
| `username` | `audit_user` |

### Step 3 — Execute Registration & Login

**Fill in the execution steps table — one row per HTTP request:**

| Step | URL | Method | Body | Expected Response |
|------|-----|--------|------|-------------------|
| 1. Register account | `___` (e.g. `http://nginx:80/register`) | POST | `___` (e.g. `name=audit_user&email=audit@test.com&password=AuditPass123!&password_confirmation=AuditPass123!`) | `___` (e.g. `302 redirect` or `201 JSON`) |
| 2. Login | `___` (e.g. `http://nginx:80/login`) | POST | `___` (e.g. `email=audit@test.com&password=AuditPass123!`) | `___` (e.g. `200 + Set-Cookie` or `200 + {"token":"..."}`) |
| 3. Extract credential | (from response) | — | — | `___` (e.g. `laravel_session=abc123` or `Bearer eyJ...`) |
| 4. Verify access | `___` (e.g. `http://nginx:80/api/user`) | GET | (with credential) | `___` (e.g. `200 + user data`) |

### Step 4 — Register Test Account

```bash
docker exec php curl -X POST http://nginx:80/register \
  -d "name=audit_user&email=audit@test.com&password=AuditPass123!&password_confirmation=AuditPass123!"
```

Adapt the fields and URL based on Step 2 analysis.

### Step 5 — Login to Obtain Credentials

```bash
docker exec php curl -X POST http://nginx:80/login \
  -d "email=audit@test.com&password=AuditPass123!" \
  -c /tmp/cookies.txt -v
```

### Step 6 — Extract Cookie or Token

- **Cookie-based auth**: Extract `Set-Cookie` header (e.g., `laravel_session=xxx` or `PHPSESSID=xxx`)
- **Token-based auth**: Extract token from JSON response body (e.g., `{"token": "eyJ..."}`)

### Step 7 — Save as Authenticated Credentials

Write the extracted credential into the `authenticated` section of `credentials.json`.

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Credentials file | `$WORK_DIR/credentials.json` → `authenticated` section | Method (cookie/bearer), token/cookie value, user_id, username |

Example output fragment:
```json
{
  "authenticated": {
    "method": "cookie",
    "cookie": "laravel_session=abc123xyz",
    "token": null,
    "user_id": 1,
    "username": "audit_user",
    "scopes": ["read", "write"]
  }
}
```

---

## Examples

### ✅ GOOD — Complete registration flow with all steps filled

| Step | URL | Method | Body | Expected Response |
|------|-----|--------|------|-------------------|
| 1. Register account | `http://nginx:80/register` | POST | `name=audit_user&email=audit@test.com&password=AuditPass123!&password_confirmation=AuditPass123!` | `302 → /home` |
| 2. Login | `http://nginx:80/login` | POST | `email=audit@test.com&password=AuditPass123!` | `200 + Set-Cookie: laravel_session=abc123` |
| 3. Extract credential | (from Set-Cookie header) | — | — | `laravel_session=abc123` |
| 4. Verify access | `http://nginx:80/api/user` | GET | (Cookie: laravel_session=abc123) | `200 {"id":1,"name":"audit_user"}` |

### ❌ BAD — Missing steps or unverified credentials

| Step | URL | Method | Body | Expected Response |
|------|-----|--------|------|-------------------|
| 1. Register account | `http://nginx:80/register` | POST | `email=audit@test.com&password=123` | (not checked) |

> Skipped login, extraction, and verification. Credential validity unknown.

---

## Error Handling

| Error | Action |
|-------|--------|
| No registration endpoint found | Skip; escalate to S-038c (Admin User Injector) |
| Registration returns validation error | Adjust fields based on error response; retry with corrected payload |
| Registration requires CSRF token | Fetch the registration form page first, extract `_token`, include in POST |
| Registration requires email verification | Check database for verification token; call verification URL directly |
| Login returns 401/403 | Verify account was created in DB; try alternate login endpoint |
| No cookie or token in response | Check response headers and body thoroughly; try API login endpoint if web login fails |
