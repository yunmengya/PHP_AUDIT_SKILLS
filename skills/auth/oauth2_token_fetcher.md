> **Skill ID**: S-038e | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: OAuth configuration, database (oauth_clients table), existing user credentials
> **Output**: OAuth2 access tokens with various scopes

# OAuth2 Token Acquisition

## Purpose

When the target application uses OAuth2 (e.g., Laravel Passport or Sanctum), obtain access tokens through supported grant types. Also extract tokens with different scopes to enable scope-bypass testing in later phases.

## Procedure

### Step 1 — Detect OAuth2 Provider

Identify which OAuth2 library is in use:
- **Laravel Passport**: `Passport::routes()` in `AuthServiceProvider`
- **Laravel Sanctum**: `sanctum` middleware, `HasApiTokens` trait
- **Custom OAuth2**: `league/oauth2-server` or custom implementation

### Step 2 — Password Grant

Requires a valid user account (from S-038b or S-038c):

```bash
docker exec php curl -X POST http://nginx:80/oauth/token \
  -d "grant_type=password&client_id=1&client_secret=xxx&username=audit@test.com&password=AuditPass123!&scope=*"
```

### Step 3 — Client Credentials Grant

Retrieve client credentials from the database:

```bash
# Retrieve client_id and client_secret from the database
docker exec db mysql -e "SELECT id, secret FROM oauth_clients LIMIT 5;"

docker exec php curl -X POST http://nginx:80/oauth/token \
  -d "grant_type=client_credentials&client_id=$ID&client_secret=$SECRET&scope=*"
```

### Step 4 — Personal Access Token (Laravel Sanctum)

Directly insert a token into the database:

```bash
docker exec db mysql -e "INSERT INTO personal_access_tokens (tokenable_type, tokenable_id, name, token, abilities) VALUES ('App\\Models\\User', 1, 'audit', '$HASH', '[\"*\"]');"
```

For Sanctum, the plain-text token value must be hashed with SHA-256 before insertion. The plain-text version is used in the `Authorization: Bearer` header.

### Step 5 — Extract Tokens with Different Scopes

Request tokens with varying scope sets to test for scope bypass:

| Token Label | Scope | Purpose |
|-------------|-------|---------|
| `read_only` | `read` | Minimal permission token |
| `full_access` | `*` | Full permission token |
| `write_only` | `write` | Write-only for escalation testing |

### Step 6 — Save Tokens to Credentials

Write all tokens into the `oauth_tokens` section of `credentials.json`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| OAuth config | `$TARGET_PATH/config/auth.php`, `$TARGET_PATH/app/Providers/AuthServiceProvider.php` | ✅ | Guard definitions, Passport routes |
| Database | Docker `db` container → `oauth_clients`, `personal_access_tokens` | ✅ | Client ID, client secret, token hashes |
| User credentials | From S-038b or S-038c | Optional | Username, password for password grant |
| Docker env | Running containers (`php`, `nginx`, `db`) | ✅ | Curl + DB query execution |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Credentials | `$WORK_DIR/credentials.json` → `oauth_tokens` section | Tokens keyed by scope label |

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

## Error Handling

| Error | Action |
|-------|--------|
| No `oauth_clients` table exists | OAuth2 is not configured; skip this strategy |
| Client secret is encrypted/hashed | Check Passport version; v10+ hashes secrets — use the `plain_text_secret` if available in migration output |
| Password grant returns `invalid_client` | Ensure the client has `password_client` flag set to `1` in `oauth_clients` |
| Sanctum token insertion fails | Verify table schema; adapt column names (e.g., `abilities` vs `scopes`) |
| Token endpoint returns 404 | Check `routes/api.php` or `routes/web.php` for custom OAuth routes |
