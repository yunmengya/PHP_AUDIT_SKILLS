# JWT / Session Signing Reverse-Engineer

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038d |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | When the target application uses JWT-based authentication, extract the signing secret from configuration files or source code and self-sign tokens at various privilege levels (user, admin, moderator, superadmin) without needing to go through the login flow. |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Environment file | `$TARGET_PATH/.env` | ✅ | `JWT_SECRET`, `APP_KEY` |
| JWT config | `$TARGET_PATH/config/jwt.php` | Optional | Algorithm, TTL, required claims |
| Source code | `$TARGET_PATH/app/` | ✅ | JWT encoding/decoding logic, payload structure |
| Docker env | Running `php` container | ✅ | Token generation execution context |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT use hardcoded credentials — only use credentials discovered from source code analysis or `$WORK_DIR/credentials.json` | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to `$WORK_DIR/auth/` directory conforming to output contract schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST execute all three JWT attack categories (none algorithm exploit, key confusion attack, weak secret brute-force) and report which succeeded — testing only one category is insufficient | FAIL — misses exploitable JWT weakness |

---

## Fill-in Procedure

### Step 1 — Search for Secret Keys

Scan multiple locations for JWT signing secrets:

| Location | Grep Pattern | Key Name |
|----------|-------------|----------|
| `.env` file | `JWT_SECRET=`, `APP_KEY=` | Primary signing key |
| Config files | `'secret'`, `'key'` in `config/jwt.php`, `config/app.php` | Framework config |
| Source code | Hard-coded strings near `JWT::encode`, `sign(` | Inline secrets |
| `composer.json` | `tymon/jwt-auth`, `firebase/php-jwt` | Library identification |

```bash
# Search .env
grep -E 'JWT_SECRET|APP_KEY|JWT_KEY' $TARGET_PATH/.env

# Search config files
grep -rn "secret\|key" $TARGET_PATH/config/jwt.php $TARGET_PATH/config/app.php --include="*.php" 2>/dev/null

# Search for hard-coded keys
grep -rn "JWT::encode\|jwt_encode\|sign(" $TARGET_PATH/app/ --include="*.php"
```

### Step 2 — Fill in JWT Configuration Parameters

**Fill in the JWT signing details table:**

| Field | Value |
|-------|-------|
| **algorithm** | `___` (e.g. `HS256`, `RS256`, `HS384`) |
| **secret_source** | `___` (e.g. `.env JWT_SECRET`, `config/jwt.php`, hard-coded) |
| **secret_value** | `___` (the actual secret key or path to private key file) |
| **header** | `___` (e.g. `{"alg":"HS256","typ":"JWT"}`) |
| **payload_claims** | `___` (e.g. `sub, role, iss, aud, exp, iat`) |
| **expiration** | `___` (e.g. `86400` seconds / `1 day`) |
| **library** | `___` (e.g. `firebase/php-jwt`, `tymon/jwt-auth`, `lcobucci/jwt`) |

### Step 3 — Identify Token Structure

Examine existing JWT usage in the codebase to determine:
- Required payload claims (`sub`, `role`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`)
- Signing algorithm (`HS256`, `RS256`, `HS384`, `HS512`, `RS384`, `RS512`, `ES256`, `none`)
- Token expiry conventions

### Step 4 — Self-Sign Tokens Inside the Container

```bash
docker exec php php -r "
  require 'vendor/autoload.php';
  use Firebase\JWT\JWT;
  \$payload = ['sub' => 1, 'role' => 'admin', 'exp' => time()+86400];
  echo JWT::encode(\$payload, env('JWT_SECRET'), 'HS256');
"
```

### Step 5 — Issue Tokens at Multiple Privilege Levels

Generate separate tokens for each target role:

| Role | Payload Overrides |
|------|-------------------|
| `user` | `'sub' => 100, 'role' => 'user'` |
| `editor` | `'sub' => 101, 'role' => 'editor'` |
| `admin` | `'sub' => 1, 'role' => 'admin'` |
| `super_admin` | `'sub' => 1, 'role' => 'super_admin'` |

Ensure `sub` values reference existing user IDs when the application validates them against the database.

### Step 6 — Save Tokens to Credentials

Write each token into the appropriate section of `credentials.json`.

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Credentials file | `$WORK_DIR/credentials.json` → `authenticated` + `admin` sections | Self-signed JWT tokens per privilege level |

Example output fragment:
```json
{
  "authenticated": {
    "method": "bearer",
    "token": "eyJhbGciOiJIUzI1NiJ9...",
    "user_id": 100,
    "username": "audit_user"
  },
  "admin": {
    "method": "bearer",
    "token": "eyJhbGciOiJIUzI1NiJ9...",
    "user_id": 1,
    "username": "audit_admin"
  }
}
```

---

## Examples

### ✅ GOOD — Complete JWT config with all fields identified

| Field | Value |
|-------|-------|
| **algorithm** | `HS256` |
| **secret_source** | `.env JWT_SECRET` |
| **secret_value** | `base64:abc123def456ghi789jkl012mno345pqr678stu901=` |
| **header** | `{"alg":"HS256","typ":"JWT"}` |
| **payload_claims** | `sub, role, iss, aud, exp, iat` |
| **expiration** | `86400` (1 day) |
| **library** | `tymon/jwt-auth` |

### ❌ BAD — Incomplete configuration

| Field | Value |
|-------|-------|
| **algorithm** | (not checked) |
| **secret_source** | `.env` |
| **secret_value** | (not extracted) |
| **header** | (default assumed) |
| **payload_claims** | `sub` only |
| **expiration** | (not set) |
| **library** | (unknown) |

> Token will be rejected: missing required claims, wrong algorithm, or incorrect secret. Always verify ALL fields before signing.

---

## Error Handling

| Error | Action |
|-------|--------|
| `JWT_SECRET` not found in `.env` | Search `config/app.php` for `APP_KEY`; check for hard-coded secrets in source |
| RS256 algorithm (asymmetric) | Look for private key file path in config; use private key for signing |
| Token rejected by application | Compare self-signed token structure with a valid token (decode existing ones); ensure all required claims are present |
| `firebase/php-jwt` not installed | Check for alternative JWT libraries (`lcobucci/jwt`, `namshi/jose`); adapt encode call accordingly |
| User ID in `sub` claim doesn't exist in DB | First insert a test user (via S-038c) then reference that user's ID |
