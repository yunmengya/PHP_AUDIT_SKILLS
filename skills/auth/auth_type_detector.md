> **Skill ID**: S-038a | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: TARGET_PATH (source code root)
> **Output**: auth_type_report (detected auth types + recommended strategies)

# Auth Type Auto-Detection

## Purpose

Automatically identify the target PHP application's authentication mechanism(s) by scanning source code for known signatures. This avoids blind credential-acquisition attempts and routes execution to the correct downstream sub-skill (S-038b–S-038g).

## Procedure

### Step 1 — Scan Source Code for Auth Signatures

Run grep-based detection against `$TARGET_PATH` using the signature table below. Record every match.

| Source Code Signature (grep pattern) | Auth Type | Recommended Strategy |
|--------------------------------------|-----------|----------------------|
| `Auth::attempt(` / `Auth::guard(` | Laravel Session Auth | S-038b (Auto-Registration) |
| `Passport::routes()` / `CreateFreshApiToken` | Laravel Passport (OAuth2) | S-038e (OAuth2 Token) |
| `JWT::decode(` / `JWTAuth::parseToken()` / `tymon/jwt-auth` | JWT Bearer Token | S-038d (JWT Signer) |
| `wp_authenticate(` / `wp_set_auth_cookie(` | WordPress Cookie Auth | S-038b + WordPress-specific flow |
| `$_SERVER['PHP_AUTH_USER']` / `$_SERVER['PHP_AUTH_PW']` | HTTP Basic Auth | Construct `Authorization: Basic base64(user:pass)` directly |
| `$_SESSION['user_id']` / `session_start()` + manual check | Native PHP Session | S-038b (Extract PHPSESSID after login) |
| `Sanctum::actingAs(` / `sanctum` middleware | Laravel Sanctum (SPA / API Token) | S-038e (Personal Access Token) |
| `hash_hmac(` + `$_SERVER['HTTP_X_SIGNATURE']` | HMAC Signature Auth | S-038f + signature construction |
| `api_key` / `apikey` / `API_KEY` in middleware or config | API Key Auth | S-038f (API Key Discoverer) |

### Step 2 — Auto-Detection Script

```bash
echo "=== Auth Type Detection ==="
# Laravel Session
grep -rl 'Auth::attempt\|Auth::guard' $TARGET_PATH/app/ --include="*.php" && echo "[DETECTED] Laravel Session Auth"
# OAuth2 / Passport
grep -rl 'Passport::routes\|passport' $TARGET_PATH/app/ $TARGET_PATH/config/ --include="*.php" && echo "[DETECTED] OAuth2 (Passport)"
# JWT
grep -rl 'JWT::decode\|JWTAuth\|tymon/jwt' $TARGET_PATH/ --include="*.php" --include="composer.json" && echo "[DETECTED] JWT Auth"
# WordPress
grep -rl 'wp_authenticate\|wp_set_auth_cookie' $TARGET_PATH/ --include="*.php" && echo "[DETECTED] WordPress Auth"
# HTTP Basic
grep -rl 'PHP_AUTH_USER\|PHP_AUTH_PW' $TARGET_PATH/ --include="*.php" && echo "[DETECTED] HTTP Basic Auth"
# Native Session
grep -rl '\$_SESSION\[.user' $TARGET_PATH/ --include="*.php" && echo "[DETECTED] Native Session Auth"
# Sanctum
grep -rl 'sanctum\|Sanctum' $TARGET_PATH/ --include="*.php" && echo "[DETECTED] Laravel Sanctum"
# HMAC Signature
grep -rl 'hash_hmac.*HTTP_X_SIG\|HTTP_X_SIGNATURE' $TARGET_PATH/ --include="*.php" && echo "[DETECTED] HMAC Signature Auth"
# API Key
grep -rl 'api_key\|apikey\|API_KEY' $TARGET_PATH/ --include="*.php" --include="*.env*" && echo "[DETECTED] API Key Auth"
```

### Step 3 — Classify & Recommend

For each detected auth type, record:
- The grep matches (file paths + line numbers)
- The corresponding recommended sub-skill
- Confidence level (high / medium / low based on match count and context)

If multiple auth types are detected, list all and mark the primary mechanism (most matches / referenced in middleware).

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Source code | `$TARGET_PATH/` | ✅ | `*.php`, `composer.json`, `.env*`, config files |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Auth type report | `$WORK_DIR/auth_type_report.json` | JSON with detected types, matched files, recommended strategies |

Example output:
```json
{
  "detected_types": [
    {
      "type": "laravel_session",
      "confidence": "high",
      "matched_files": ["app/Http/Controllers/AuthController.php"],
      "recommended_skill": "S-038b"
    }
  ],
  "primary_type": "laravel_session",
  "fallback_types": []
}
```

## Error Handling

| Error | Action |
|-------|--------|
| No auth signatures detected | Report `unknown` type; recommend trying S-038b (Auto-Registration) and S-038f (API Key) as fallbacks |
| Multiple conflicting types detected | List all types; mark the one used in route middleware as primary |
| `$TARGET_PATH` is empty or inaccessible | Fail with error; cannot proceed without source code |
