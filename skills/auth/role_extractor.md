# Multi-Role Credential Acquisition

## Identity

| Field | Value |
|-------|-------|
| **Skill ID** | S-038h |
| **Phase** | 3 — Authentication Simulation |
| **Parent** | S-038 (auth_simulator) |
| **Responsibility** | Extract the full list of roles defined in the application and create test accounts for each role. Enables granular privilege escalation testing — both vertical (low role → high-role endpoints) and horizontal (same-level cross-user access). |

---

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Database seeds | `$TARGET_PATH/database/seeders/`, `$TARGET_PATH/database/seeds/` | Optional | Role definitions in seed classes |
| Migrations | `$TARGET_PATH/database/migrations/` | Optional | Role enum definitions, roles table schema |
| Database | Docker `db` → `roles`, `permissions`, `model_has_roles` | ✅ | Role names, permission mappings |
| Docker env | Running containers (`php`, `db`) | ✅ | User creation + login execution |

---

## 🚨 CRITICAL Rules

| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | MUST NOT guess or fabricate passwords for pre-existing application accounts — credentials for existing accounts MUST come from source code analysis or `$WORK_DIR/credentials.json`. Test accounts created by THIS procedure may use procedure-defined passwords | FAIL — test uses fabricated credentials, results unreliable |
| CR-2 | MUST write output to `$WORK_DIR/auth/` directory conforming to output contract schema | FAIL — downstream Phase-3/4 agents cannot locate auth artifacts |
| CR-3 | MUST extract ALL defined roles with their permission mappings — incomplete role list causes missing privilege escalation tests | FAIL — partial role extraction leads to incomplete authz testing |

---

## Fill-in Procedure

### Step 1 — Extract Role Definitions

Security audits SHOULD NOT focus solely on anonymous / authenticated / admin. Many applications define more granular roles:

| Role | Typical Permissions | Audit Value |
|------|---------------------|-------------|
| `anonymous` | Unauthenticated visitor | Largest attack surface, no credentials required |
| `subscriber` / `user` | Basic authenticated user | Common starting point for horizontal privilege escalation |
| `editor` / `contributor` | Content editor | May access file upload and content injection Sinks |
| `moderator` | Content manager | May access user management and bulk operation Sinks |
| `admin` / `administrator` | Administrator | Full permission baseline |
| `super_admin` / `root` | Super administrator | System-level operations (config changes, plugin installation) |

```bash
# Laravel: Search for role definitions in Seeders
grep -rn "role\|Role::create\|'name'.*=>" $TARGET_PATH/database/seeders/ --include="*.php" | head -30
grep -rn "role\|Role::create\|'name'.*=>" $TARGET_PATH/database/seeds/ --include="*.php" | head -30

# Laravel: Search for role enums in Migrations
grep -rn "enum.*role\|->enum(\|roles.*table" $TARGET_PATH/database/migrations/ --include="*.php" | head -20

# WordPress: Roles are in wp_options, query database directly
docker exec db mysql -uroot -paudit_root_pass audit_db -e \
  "SELECT option_value FROM wp_options WHERE option_name = 'wp_user_roles';" | php -r "print_r(unserialize(file_get_contents('php://stdin')));"

# Spatie Permission package (commonly used Laravel permission package)
docker exec db mysql -uroot -paudit_root_pass audit_db -e "SELECT * FROM roles;"
docker exec db mysql -uroot -paudit_root_pass audit_db -e "SELECT * FROM permissions;"
docker exec db mysql -uroot -paudit_root_pass audit_db -e \
  "SELECT r.name as role, p.name as permission FROM role_has_permissions rp JOIN roles r ON rp.role_id=r.id JOIN permissions p ON rp.permission_id=p.id;"

# ThinkPHP / Custom: Search for role-related tables
docker exec db mysql -uroot -paudit_root_pass audit_db -e "SHOW TABLES LIKE '%role%';"
docker exec db mysql -uroot -paudit_root_pass audit_db -e "SHOW TABLES LIKE '%permission%';"
docker exec db mysql -uroot -paudit_root_pass audit_db -e "SHOW TABLES LIKE '%group%';"
```

### Step 2 — Fill in Discovered Roles Table

**Fill in the role discovery table — one row per role found:**

| Role Name | Source (seed/migration/table) | Permissions | Account Created |
|-----------|-------------------------------|-------------|-----------------|
| `___` (e.g. `subscriber`) | `___` (e.g. `roles table, id=1`) | `___` (e.g. `read`) | `___` (✅ / ❌) |
| `___` (e.g. `editor`) | `___` (e.g. `RoleSeeder.php`) | `___` (e.g. `read, write, upload`) | `___` (✅ / ❌) |
| `___` (e.g. `moderator`) | `___` (e.g. `roles table, id=3`) | `___` (e.g. `read, write, delete_others`) | `___` (✅ / ❌) |
| `___` (e.g. `admin`) | `___` (e.g. `roles table, id=4`) | `___` (e.g. `*`) | `___` (✅ / ❌) |
| `___` (e.g. `super_admin`) | `___` (e.g. `migration enum`) | `___` (e.g. `*`) | `___` (✅ / ❌) |

### Step 3 — Batch Create Multi-Role Accounts

```bash
# Generate password hash
HASH=$(docker exec php php -r "echo password_hash('AuditRole123!', PASSWORD_BCRYPT);")

# Create test accounts for each discovered role
for ROLE in subscriber editor moderator admin super_admin; do
  docker exec db mysql -uroot -paudit_root_pass audit_db -e \
    "INSERT IGNORE INTO users (name, email, password, role, created_at) \
     VALUES ('audit_${ROLE}', '${ROLE}@audit.test', '${HASH}', '${ROLE}', NOW());"
  echo "[CREATED] User audit_${ROLE} with role ${ROLE}"
done
```

### Step 4 — Spatie Permission: Assign Roles via `model_has_roles`

```bash
for ROLE in subscriber editor moderator admin super_admin; do
  ROLE_ID=$(docker exec db mysql -uroot -paudit_root_pass audit_db -sN -e \
    "SELECT id FROM roles WHERE name='${ROLE}' LIMIT 1;")
  USER_ID=$(docker exec db mysql -uroot -paudit_root_pass audit_db -sN -e \
    "SELECT id FROM users WHERE email='${ROLE}@audit.test' LIMIT 1;")
  if [ -n "$ROLE_ID" ] && [ -n "$USER_ID" ]; then
    docker exec db mysql -uroot -paudit_root_pass audit_db -e \
      "INSERT IGNORE INTO model_has_roles (role_id, model_type, model_id) \
       VALUES (${ROLE_ID}, 'App\\\\Models\\\\User', ${USER_ID});"
  fi
done
```

### Step 5 — Login Each Role Account & Collect Credentials

For each created account, log in and extract the credential (cookie or token). Use the same method determined by S-038a (auth type detection).

### Step 6 — Save Extended Credential Output

Write per-role credentials into the `roles` section of `credentials.json`.

---

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| Credentials file | `$WORK_DIR/输出结果/credentials.json` → `roles` section | Per-role tokens with permission lists |

Example output fragment:
```json
{
  "roles": {
    "subscriber": {
      "method": "bearer",
      "token": "eyJ...",
      "user_id": 10,
      "username": "audit_subscriber",
      "permissions": ["read"]
    },
    "editor": {
      "method": "bearer",
      "token": "eyJ...",
      "user_id": 11,
      "username": "audit_editor",
      "permissions": ["read", "write", "upload"]
    },
    "moderator": {
      "method": "bearer",
      "token": "eyJ...",
      "user_id": 12,
      "username": "audit_moderator",
      "permissions": ["read", "write", "delete_others"]
    },
    "admin": {
      "method": "bearer",
      "token": "eyJ...",
      "user_id": 13,
      "username": "audit_admin",
      "permissions": ["*"]
    }
  }
}
```

### Downstream Usage for Trace-Dispatcher

When dispatching tasks, Trace-Dispatcher SHOULD specify the list of roles to test for each route:
- **Admin endpoints** → Test with `editor` / `subscriber` credentials for vertical privilege escalation
- **User endpoints** → Test with other same-level user credentials for horizontal privilege escalation
- **Public endpoints** → Test with `anonymous` to confirm no authentication is required

---

## Examples

### ✅ GOOD — All roles extracted with accounts and permissions mapped

| Role Name | Source (seed/migration/table) | Permissions | Account Created |
|-----------|-------------------------------|-------------|-----------------|
| `subscriber` | `roles` table, id=1 | `read` | ✅ `subscriber@audit.test` |
| `editor` | `roles` table, id=2 | `read, write, upload` | ✅ `editor@audit.test` |
| `moderator` | `roles` table, id=3 | `read, write, delete_others` | ✅ `moderator@audit.test` |
| `admin` | `roles` table, id=4 + `RoleSeeder.php` | `*` | ✅ `admin@audit.test` |
| `super_admin` | migration enum in `2023_01_01_create_users_table.php` | `*` | ✅ `super_admin@audit.test` |

### ❌ BAD — Only admin role discovered, no account creation

| Role Name | Source (seed/migration/table) | Permissions | Account Created |
|-----------|-------------------------------|-------------|-----------------|
| `admin` | (assumed) | (unknown) | ❌ |

> Only one role found — missed granular roles. No accounts created. Vertical privilege escalation testing impossible.

---

## Error Handling

| Error | Action |
|-------|--------|
| No role definitions found in seeds/migrations | Query database directly for roles table; fall back to common role names |
| Spatie `roles` table does not exist | Check for alternative permission packages or custom role implementations |
| Role column in users table uses integer IDs | Map IDs to role names via the roles table |
| Account creation fails due to unique constraints | Use `INSERT IGNORE` or check for existing audit accounts first |
| Some roles have no corresponding permissions | Still create the account; the audit will reveal if the role is dead/unused |
