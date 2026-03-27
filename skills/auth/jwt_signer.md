> **Skill ID**: S-038d | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: environment files (.env), source code (JWT configuration)
> **Output**: self-signed JWT tokens at multiple privilege levels

# JWT / Session Signing Reverse-Engineer

## Purpose

When the target application uses JWT-based authentication, extract the signing secret from configuration files or source code and self-sign tokens at various privilege levels (user, admin, etc.) without needing to go through the login flow.

## Procedure

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

### Step 2 — Identify Token Structure

Examine existing JWT usage in the codebase to determine:
- Required payload claims (`sub`, `role`, `iss`, `aud`, `exp`, etc.)
- Signing algorithm (`HS256`, `RS256`, etc.)
- Token expiry conventions

### Step 3 — Self-Sign Tokens Inside the Container

```bash
docker exec php php -r "
  require 'vendor/autoload.php';
  use Firebase\JWT\JWT;
  \$payload = ['sub' => 1, 'role' => 'admin', 'exp' => time()+86400];
  echo JWT::encode(\$payload, env('JWT_SECRET'), 'HS256');
"
```

### Step 4 — Issue Tokens at Multiple Privilege Levels

Generate separate tokens for each target role:

| Role | Payload Overrides |
|------|-------------------|
| `user` | `'sub' => 100, 'role' => 'user'` |
| `editor` | `'sub' => 101, 'role' => 'editor'` |
| `admin` | `'sub' => 1, 'role' => 'admin'` |
| `super_admin` | `'sub' => 1, 'role' => 'super_admin'` |

Ensure `sub` values reference existing user IDs when the application validates them against the database.

### Step 5 — Save Tokens to Credentials

Write each token into the appropriate section of `credentials.json`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Environment file | `$TARGET_PATH/.env` | ✅ | `JWT_SECRET`, `APP_KEY` |
| JWT config | `$TARGET_PATH/config/jwt.php` | Optional | Algorithm, TTL, required claims |
| Source code | `$TARGET_PATH/app/` | ✅ | JWT encoding/decoding logic, payload structure |
| Docker env | Running `php` container | ✅ | Token generation execution context |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Credentials | `$WORK_DIR/credentials.json` → `authenticated` + `admin` sections | Self-signed JWT tokens per privilege level |

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

## Error Handling

| Error | Action |
|-------|--------|
| `JWT_SECRET` not found in `.env` | Search `config/app.php` for `APP_KEY`; check for hard-coded secrets in source |
| RS256 algorithm (asymmetric) | Look for private key file path in config; use private key for signing |
| Token rejected by application | Compare self-signed token structure with a valid token (decode existing ones); ensure all required claims are present |
| `firebase/php-jwt` not installed | Check for alternative JWT libraries (`lcobucci/jwt`, `namshi/jose`); adapt encode call accordingly |
| User ID in `sub` claim doesn't exist in DB | First insert a test user (via S-038c) then reference that user's ID |
