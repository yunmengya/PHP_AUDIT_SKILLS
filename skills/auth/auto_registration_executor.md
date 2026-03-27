> **Skill ID**: S-038b | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: route_map.json, registration/login endpoint info
> **Output**: test account credentials (cookie / token)

# Auto-Registration & Login Executor

## Purpose

Automatically register a test account on the target application, log in, and extract session credentials (cookie or bearer token). This is the preferred (least-invasive) strategy for obtaining authenticated-level credentials.

## Procedure

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

### Step 3 — Auto-Register a Test Account

```bash
docker exec php curl -X POST http://nginx:80/register \
  -d "name=audit_user&email=audit@test.com&password=AuditPass123!&password_confirmation=AuditPass123!"
```

Adapt the fields and URL based on Step 2 analysis.

### Step 4 — Login to Obtain Credentials

```bash
docker exec php curl -X POST http://nginx:80/login \
  -d "email=audit@test.com&password=AuditPass123!" \
  -c /tmp/cookies.txt -v
```

### Step 5 — Extract Cookie or Token

- **Cookie-based auth**: Extract `Set-Cookie` header (e.g., `laravel_session=xxx` or `PHPSESSID=xxx`)
- **Token-based auth**: Extract token from JSON response body (e.g., `{"token": "eyJ..."}`)

### Step 6 — Save as Authenticated Credentials

Write the extracted credential into the `authenticated` section of `credentials.json`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Route map | `$WORK_DIR/route_map.json` | ✅ | Endpoint URLs, HTTP methods, controller references |
| Source code | `$TARGET_PATH/app/Http/Controllers/` | ✅ | Registration/login controller parameter lists |
| Docker environment | Running containers (`php`, `nginx`, `db`) | ✅ | Curl execution context |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Credentials | `$WORK_DIR/credentials.json` → `authenticated` section | Method (cookie/bearer), token/cookie value, user_id, username |

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

## Error Handling

| Error | Action |
|-------|--------|
| No registration endpoint found | Skip; escalate to S-038c (Admin User Injector) |
| Registration returns validation error | Adjust fields based on error response; retry with corrected payload |
| Registration requires CSRF token | Fetch the registration form page first, extract `_token`, include in POST |
| Registration requires email verification | Check database for verification token; call verification URL directly |
| Login returns 401/403 | Verify account was created in DB; try alternate login endpoint |
| No cookie or token in response | Check response headers and body thoroughly; try API login endpoint if web login fails |
