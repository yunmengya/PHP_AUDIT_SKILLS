# OAuth2 Token Acquisition

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038e |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | When the target application uses OAuth2 (e.g., Laravel Passport or Sanctum), obtain access tokens through supported grant types. Extract tokens with different scopes to enable scope-bypass testing in later phases. |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| OAuth config | `$TARGET_PATH/config/auth.php`, `AuthServiceProvider.php` | ✅ | Guard definitions, Passport routes |
| Database | Docker `db` → `oauth_clients`, `personal_access_tokens` | ✅ | Client ID, client secret, token hashes |
| User credentials | From S-038b or S-038c | Optional | Username, password for password grant |
| Docker env | Running containers (`php`, `nginx`, `db`) | ✅ | Curl + DB query execution |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT use hardcoded credentials — only use credentials discovered from source code analysis or `$WORK_DIR/credentials.json` | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to `$WORK_DIR/auth/` directory conforming to output contract schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST verify obtained token grants actual API access by making an authenticated request | FAIL — expired or invalid token passed to downstream agents |

---

## Fill-in Procedure

### Step 1 — Detect OAuth2 Provider

Identify which OAuth2 library is in use:
- **Laravel Passport**: `Passport::routes()` in `AuthServiceProvider`
- **Laravel Sanctum**: `sanctum` middleware, `HasApiTokens` trait
- **Custom OAuth2**: `league/oauth2-server` or custom implementation

### Step 2 — Fill in Token Acquisition Parameters

**Fill in the grant type details table — one row per grant type attempted:**

| Grant Type | Endpoint | Client ID | Client Secret | Scope |
|------------|----------|-----------|---------------|-------|
| `password` | `___` (e.g. `http://nginx:80/oauth/token`) | `___` | `___` | `___` (e.g. `*`) |
| `client_credentials` | `___` (e.g. `http://nginx:80/oauth/token`) | `___` | `___` | `___` (e.g. `*`) |
| `personal_access_token` | (direct DB insert) | — | — | `___` (e.g. `["*"]`) |

### Step 3 — Password Grant

Requires a valid user account (from S-038b or S-038c):

```bash
docker exec php curl -X POST http://nginx:80/oauth/token \
  -d "grant_type=password&client_id=1&client_secret=xxx&username=audit@test.com&password=AuditPass123!&scope=*"
```

### Step 4 — Client Credentials Grant

Retrieve client credentials from the database:

```bash
# Retrieve client_id and client_secret from the database
docker exec db mysql -e "SELECT id, secret FROM oauth_clients LIMIT 5;"

docker exec php curl -X POST http://nginx:80/oauth/token \
  -d "grant_type=client_credentials&client_id=$ID&client_secret=$SECRET&scope=*"
```

### Step 5 — Personal Access Token (Laravel Sanctum)

Directly insert a token into the database:

```bash
docker exec db mysql -e "INSERT INTO personal_access_tokens (tokenable_type, tokenable_id, name, token, abilities) VALUES ('App\\Models\\User', 1, 'audit', '$HASH', '[\"*\"]');"
```

For Sanctum, the plain-text token value must be hashed with SHA-256 before insertion. The plain-text version is used in the `Authorization: Bearer` header.

### Step 6 — Extract Tokens with Different Scopes

Request tokens with varying scope sets to test for scope bypass:

| Token Label | Scope | Purpose |
|-------------|-------|---------|
| `read_only` | `read` | Minimal permission token |
| `full_access` | `*` | Full permission token |
| `write_only` | `write` | Write-only for escalation testing |

### Step 7 — Save Tokens to Credentials

Write all tokens into the `oauth_tokens` section of `credentials.json`.

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Credentials file | `$WORK_DIR/credentials.json` → `oauth_tokens` section | Tokens keyed by scope label |

Example output fragment:
```json
{
  "oauth_tokens": {
    "read_only": "eyJhbGciOiJSUzI1NiJ9...",
    "full_access": "eyJhbGciOiJSUzI1NiJ9...",
    "write_only": "eyJhbGciOiJSUzI1NiJ9..."
  }
}
```

---

## Examples

### ✅ GOOD — Complete grant type table with all fields filled

| Grant Type | Endpoint | Client ID | Client Secret | Scope |
|------------|----------|-----------|---------------|-------|
| `password` | `http://nginx:80/oauth/token` | `2` | `abc123secret` | `*` |
| `client_credentials` | `http://nginx:80/oauth/token` | `1` | `def456secret` | `read write` |
| `personal_access_token` | (DB insert into `personal_access_tokens`) | — | — | `["*"]` |

### ❌ BAD — Missing client credentials or untested scopes

| Grant Type | Endpoint | Client ID | Client Secret | Scope |
|------------|----------|-----------|---------------|-------|
| `password` | `http://nginx:80/oauth/token` | `1` | (unknown) | `*` |

> Cannot issue token without client_secret. Must query `oauth_clients` table first. No scope variation tested.

---

## Error Handling

| Error | Action |
|-------|--------|
| No `oauth_clients` table exists | OAuth2 is not configured; skip this strategy |
| Client secret is encrypted/hashed | Check Passport version; v10+ hashes secrets — use the `plain_text_secret` if available in migration output |
| Password grant returns `invalid_client` | Ensure the client has `password_client` flag set to `1` in `oauth_clients` |
| Sanctum token insertion fails | Verify table schema; adapt column names (e.g., `abilities` vs `scopes`) |
| Token endpoint returns 404 | Check `routes/api.php` or `routes/web.php` for custom OAuth routes |
