> **Skill ID**: S-038c | **Phase**: 3 | **Parent**: S-038 (auth_simulator)
> **Input**: DB schema (reconstructed_schema.sql), users table structure
> **Output**: admin-level credentials (cookie / token)

# Direct Database Admin Insertion

## Purpose

When auto-registration (S-038b) cannot yield admin-level credentials, directly insert an admin user into the database. This bypasses application-layer restrictions to obtain the highest privilege level for security testing.

## Procedure

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

### Step 3 — Generate Password Hash

```bash
docker exec php php -r "echo password_hash('AuditAdmin123!', PASSWORD_BCRYPT);"
```

Store the output as `$HASH`.

### Step 4 — Insert Admin User

```bash
docker exec db mysql -uroot -paudit_root_pass audit_db -e \
  "INSERT INTO users (name, email, password, role) VALUES ('audit_admin', 'admin@test.com', '$HASH', 'admin');"
```

Adapt the column names and privilege value based on Step 2.

### Step 5 — Login with Admin Account

Use the same login flow as S-038b but with admin credentials:

```bash
docker exec php curl -X POST http://nginx:80/login \
  -d "email=admin@test.com&password=AuditAdmin123!" \
  -c /tmp/cookies.txt -v
```

### Step 6 — Save as Admin Credentials

Write the extracted credential into the `admin` section of `credentials.json`.

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| DB schema | `$WORK_DIR/reconstructed_schema.sql` | ✅ | `users` table columns, types, constraints |
| Database | Docker `db` container | ✅ | Direct SQL access for INSERT |
| Docker env | Running containers (`php`, `nginx`, `db`) | ✅ | Password hashing + login |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| Credentials | `$WORK_DIR/credentials.json` → `admin` section | Method (cookie/bearer), token/cookie value, user_id, username |

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

## Error Handling

| Error | Action |
|-------|--------|
| Users table has NOT NULL columns without defaults | Query existing rows for reference values; populate all required columns |
| Unique constraint violation on email | Use a different email (e.g., `admin2@test.com`) or check if admin already exists |
| Foreign key constraint on role/group | First query the roles/groups table; use a valid FK value for admin |
| Password hash format mismatch (e.g., MD5 instead of bcrypt) | Detect hash format from existing rows; generate matching hash |
| Admin login still returns non-admin access | Check for additional permission tables (e.g., Spatie `model_has_roles`); insert role assignments there too |
