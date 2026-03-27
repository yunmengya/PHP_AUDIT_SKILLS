# Direct Database Admin Insertion

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038c |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | When auto-registration (S-038b) cannot yield admin-level credentials, directly insert an admin user into the database. Bypasses application-layer restrictions to obtain the highest privilege level for security testing. |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| DB schema | `$WORK_DIR/reconstructed_schema.sql` | ✅ | `users` table columns, types, constraints |
| Database | Docker `db` container | ✅ | Direct SQL access for INSERT |
| Docker env | Running containers (`php`, `nginx`, `db`) | ✅ | Password hashing + login |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT fabricate credentials for existing accounts — only use credentials discovered from source code analysis, `$WORK_DIR/credentials.json`, or test accounts created by this procedure | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to the path specified in Output Contract conforming to its schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST verify injected admin user has actual admin privileges by testing an admin-only endpoint | FAIL — user created but without real admin access |

---

## Fill-in Procedure

### Step 1 — Analyze Users Table Structure

Read `reconstructed_schema.sql` or query the database to understand the `users` table:

```bash
docker exec db mysql -uroot -paudit_root_pass audit_db -e "DESCRIBE users;"
```

### Step 2 — Identify Privilege Fields

Look for columns that control access level:

| Candidate Column | Example Values |
|------------------|----------------|
| `role` | `admin`, `user`, `moderator` |
| `is_admin` | `1` / `0` |
| `level` | `99`, `1`, `0` |
| `type` | `admin`, `member` |
| `group_id` | FK to a groups/roles table |

### Step 3 — Fill in Admin Injection Parameters

**Fill in the admin user details table:**

| Field | Value |
|-------|-------|
| **table_name** | `___` (e.g. `users`) |
| **hash_algorithm** | `___` (e.g. `PASSWORD_BCRYPT`, `md5`, `sha256`) |
| **admin_username** | `___` (e.g. `audit_admin`) |
| **admin_email** | `___` (e.g. `admin@test.com`) |
| **admin_password** | `___` (e.g. `AuditAdmin123!`) |
| **admin_password_hash** | `___` (output of hash generation command) |
| **privilege_column** | `___` (e.g. `role`, `is_admin`, `level`) |
| **privilege_value** | `___` (e.g. `admin`, `1`, `99`) |
| **extra_required_columns** | `___` (e.g. `created_at=NOW()`, `status=1`) |

### Step 4 — Generate Password Hash

```bash
docker exec php php -r "echo password_hash('AuditAdmin123!', PASSWORD_BCRYPT);"
```

Store the output as `$HASH`.

### Step 5 — Insert Admin User

```bash
docker exec db mysql -uroot -paudit_root_pass audit_db -e \
  "INSERT INTO users (name, email, password, role) VALUES ('audit_admin', 'admin@test.com', '$HASH', 'admin');"
```

Adapt the column names and privilege value based on the filled-in table above.

### Step 6 — Login with Admin Account

Use the same login flow as S-038b but with admin credentials:

```bash
docker exec php curl -X POST http://nginx:80/login \
  -d "email=admin@test.com&password=AuditAdmin123!" \
  -c /tmp/cookies.txt -v
```

### Step 7 — Save as Admin Credentials

Write the extracted credential into the `admin` section of `credentials.json`.

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Credentials file | `$WORK_DIR/credentials.json` → `admin` section | Method (cookie/bearer), token/cookie value, user_id, username |

Example output fragment:
```json
{
  "admin": {
    "method": "cookie",
    "cookie": "laravel_session=yyy",
    "token": null,
    "user_id": 2,
    "username": "audit_admin",
    "scopes": ["*"]
  }
}
```

---

## Examples

### ✅ GOOD — Complete admin injection with all fields identified

| Field | Value |
|-------|-------|
| **table_name** | `users` |
| **hash_algorithm** | `PASSWORD_BCRYPT` |
| **admin_username** | `audit_admin` |
| **admin_email** | `admin@test.com` |
| **admin_password** | `AuditAdmin123!` |
| **admin_password_hash** | `$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi` |
| **privilege_column** | `role` |
| **privilege_value** | `admin` |
| **extra_required_columns** | `created_at=NOW(), updated_at=NOW()` |

### ❌ BAD — Missing hash algorithm or privilege column

| Field | Value |
|-------|-------|
| **table_name** | `users` |
| **hash_algorithm** | (not checked) |
| **admin_username** | `admin` |
| **admin_password_hash** | (used plaintext password instead of hash) |
| **privilege_column** | (not identified) |

> INSERT will fail: password stored in plaintext won't pass bcrypt verification. Privilege column unknown — account may be created as regular user.

---

## Error Handling

| Error | Action |
|-------|--------|
| Users table has NOT NULL columns without defaults | Query existing rows for reference values; populate all required columns |
| Unique constraint violation on email | Use a different email (e.g., `admin2@test.com`) or check if admin already exists |
| Foreign key constraint on role/group | First query the roles/groups table; use a valid FK value for admin |
| Password hash format mismatch (e.g., MD5 instead of bcrypt) | Detect hash format from existing rows; generate matching hash |
| Admin login still returns non-admin access | Check for additional permission tables (e.g., Spatie `model_has_roles`); insert role assignments there too |
