# Auth Type Auto-Detection

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038a |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | Automatically identify the target PHP application's authentication mechanism(s) by scanning source code for known signatures. Routes execution to the correct downstream sub-skill (S-038b–S-038g). |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| PHP source files | `$TARGET_PATH/**/*.php` | ✅ | Auth patterns, middleware references |
| Composer config | `$TARGET_PATH/composer.json` | ✅ | Dependency packages (JWT, OAuth2, Sanctum, Passport, tymon/jwt-auth) |
| Environment file | `$TARGET_PATH/.env*` | Optional | Key names hinting at auth type |
| Framework config | `$TARGET_PATH/config/*.php` | Optional | Guard definitions, auth driver config |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT use hardcoded credentials — only use credentials discovered from source code analysis or `$WORK_DIR/credentials.json` | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to the path specified in Output Contract conforming to its schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST check ALL authentication mechanisms (session, JWT, OAuth, API key, basic auth) — reporting only the first found creates blind spots | FAIL — partial auth detection leads to incomplete testing |

---

## Fill-in Procedure

### Step 1 — Scan Source Code for Auth Signatures

Run grep-based detection against `$TARGET_PATH` using the signature table below. Record every match.

**Fill in the detection results table — one row per pattern match found:**

| Pattern | File | Line | Match Type | Auth Type |
|---------|------|------|------------|-----------|
| `Auth::attempt(` / `Auth::guard(` | `___` | `___` | exact / regex | Laravel Session Auth → S-038b |
| `Passport::routes()` / `CreateFreshApiToken` | `___` | `___` | exact / regex | Laravel Passport (OAuth2) → S-038e |
| `JWT::decode(` / `JWTAuth::parseToken()` / `tymon/jwt-auth` | `___` | `___` | exact / regex | JWT Bearer Token → S-038d |
| `wp_authenticate(` / `wp_set_auth_cookie(` | `___` | `___` | exact / regex | WordPress Cookie Auth → S-038b |
| `$_SERVER['PHP_AUTH_USER']` / `$_SERVER['PHP_AUTH_PW']` | `___` | `___` | exact / regex | HTTP Basic Auth → direct header |
| `$_SESSION['user_id']` / `session_start()` + manual check | `___` | `___` | exact / regex | Native PHP Session → S-038b |
| `Sanctum::actingAs(` / `sanctum` middleware | `___` | `___` | exact / regex | Laravel Sanctum → S-038e |
| `hash_hmac(` + `$_SERVER['HTTP_X_SIGNATURE']` | `___` | `___` | exact / regex | HMAC Signature Auth → S-038f |
| `api_key` / `apikey` / `API_KEY` in middleware or config | `___` | `___` | exact / regex | API Key Auth → S-038f |

### Step 2 — Run Auto-Detection Script

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

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
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

---

## Examples

### ✅ GOOD — Complete detection with confidence levels

| Pattern | File | Line | Match Type | Auth Type |
|---------|------|------|------------|-----------|
| `Auth::attempt(` | `app/Http/Controllers/LoginController.php` | 42 | exact | Laravel Session Auth → S-038b |
| `Sanctum::actingAs(` | `tests/Feature/ApiTest.php` | 15 | exact | Laravel Sanctum → S-038e |
| `api_key` | `app/Http/Middleware/ApiKeyAuth.php` | 23 | regex | API Key Auth → S-038f |

> Primary type: `Laravel Session Auth` (most matches, referenced in route middleware)

### ❌ BAD — Incomplete or ambiguous detection

| Pattern | File | Line | Match Type | Auth Type |
|---------|------|------|------------|-----------|
| `Auth::attempt(` | (not recorded) | ? | ? | maybe session? |

> Missing file paths, line numbers, and confidence assessment. Cannot route to downstream skill.

---

## Error Handling

| Error | Action |
|-------|--------|
| No auth signatures detected | Report `unknown` type; recommend trying S-038b (Auto-Registration) and S-038f (API Key) as fallbacks |
| Multiple conflicting types detected | List all types; mark the one used in route middleware as primary |
| `$TARGET_PATH` is empty or inaccessible | Fail with error; cannot proceed without source code |
