# Schema-Reconstructor (Table Schema Reconstructor)

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-012 |
| Phase | Phase-1 |
| Responsibility | Infer and reconstruct database table schemas from multiple sources |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| TARGET_PATH | Orchestrator parameter | ✅ | Target source code path |
| WORK_DIR | Orchestrator parameter | ✅ | Working directory path |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Migration files have HIGHEST priority on conflict; validation rules have LOWEST | Wrong merge priority → incorrect schema |
| CR-2 | All tables MUST auto-include `id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY` | Missing primary key → DB import failure |
| CR-3 | All tables MUST auto-include `created_at TIMESTAMP NULL, updated_at TIMESTAMP NULL` | Framework ORM errors on missing timestamps |
| CR-4 | Foreign key fields MUST auto-include INDEX | Missing indexes → slow query performance |
| CR-5 | Fields with unknown types default to `VARCHAR(255)` | Type errors during import |
| CR-6 | Output MUST use `CREATE TABLE IF NOT EXISTS` | Re-import failures on existing tables |

## Fill-in Procedure

### Procedure A: Migration File Parsing
| Field | Fill-in Value |
|-------|--------------|
| scan_path | {`$TARGET_PATH/database/migrations/*.php`} |
| create_table | {Parse `Schema::create('table_name', ...)` → generate `CREATE TABLE` SQL} |
| alter_table | {Parse `Schema::table('table_name', ...)` → generate `ALTER TABLE` SQL} |
| type_mapping | {`$table->string('name', 100)`→`VARCHAR(100)`, `$table->integer('age')`→`INT`, `$table->text('content')`→`TEXT`, `$table->boolean('active')`→`TINYINT(1)`, `$table->timestamp('created_at')`→`TIMESTAMP`, `$table->json('data')`→`JSON`, `$table->unsignedBigInteger('user_id')`→`BIGINT UNSIGNED`, `$table->id()`→`BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY`, `$table->timestamps()`→`created_at TIMESTAMP, updated_at TIMESTAMP`, `$table->softDeletes()`→`deleted_at TIMESTAMP NULL`} |

### Procedure B: Model Definition Extraction
| Field | Fill-in Value |
|-------|--------------|
| scan_target | {All class files extending Model/Eloquent} |
| table_name | {Extract `protected $table = 'xxx'`} |
| field_list | {Extract `protected $fillable = [...]`} |
| type_casts | {Extract `protected $casts = [...]` → field type mapping} |
| hidden_fields | {Extract `protected $hidden = [...]` (typically includes password)} |
| merge_rule | {Supplement fields not found in migration files (priority 2)} |

### Procedure C: Source Code SQL Statement Extraction
| Field | Fill-in Value |
|-------|--------------|
| scan_target | {All `.php` files in TARGET_PATH} |
| regex_match | {Match strings starting with `SELECT\|INSERT\|UPDATE\|DELETE\|CREATE\|ALTER`} |
| extract | {Table names + field names from matched SQL statements} |
| merge_rule | {Supplement tables and fields not discovered in Procedures A+B (priority 3)} |

### Procedure D: Validation Rule Analysis
| Field | Fill-in Value |
|-------|--------------|
| scan_patterns | {`$rules = [...]` arrays, `$request->validate([...])` calls, `rules()` methods in `FormRequest` classes} |
| type_inference | {`'email\|max:255'`→`VARCHAR(255)`, `'integer\|min:0'`→`INT UNSIGNED`, `'string\|max:1000'`→`VARCHAR(1000)` or `TEXT`, `'boolean'`→`TINYINT(1)`, `'date'`→`DATE`, `'numeric'`→`DECIMAL`} |
| merge_rule | {Infer field constraints (priority 4 — lowest)} |

### Procedure E: Relationship Analysis
| Field | Fill-in Value |
|-------|--------------|
| hasMany | {`hasMany(Comment::class)` → comments table has `{model}_id` foreign key} |
| belongsTo | {`belongsTo(User::class)` → current table has `user_id` foreign key} |
| hasOne | {`hasOne(Profile::class)` → profiles table has `{model}_id` foreign key} |
| belongsToMany | {`belongsToMany(Role::class)` → pivot table `{model}_role` with two foreign keys} |
| output | {Inferred foreign key fields + pivot table structures} |

### Procedure F: Merge and Output
| Field | Fill-in Value |
|-------|--------------|
| priority_order | {1. Migration files (highest) → 2. Model definitions → 3. SQL statements → 4. Validation rules (lowest)} |
| default_type | {Unknown type → `VARCHAR(255)`} |
| auto_id | {All tables → `id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY`} |
| auto_timestamps | {All tables → `created_at TIMESTAMP NULL, updated_at TIMESTAMP NULL`} |
| auto_index | {Foreign key fields → `INDEX`} |
| format | {`CREATE TABLE IF NOT EXISTS` with `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`} |

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| reconstructed_schema.sql | `$WORK_DIR/reconstructed_schema.sql` | Standard SQL DDL | Executable SQL file with all reconstructed CREATE TABLE statements, comments indicating sources |

## Examples

### ✅ GOOD: Complete Reconstructed Schema
```sql
-- Auto-reconstructed schema
-- Sources: migrations, models, sql_statements, validation_rules

CREATE TABLE IF NOT EXISTS `users` (
  `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `is_admin` TINYINT(1) DEFAULT 0,
  `created_at` TIMESTAMP NULL,
  `updated_at` TIMESTAMP NULL,
  INDEX `idx_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `posts` (
  `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `title` VARCHAR(255) NOT NULL,
  `content` TEXT,
  `created_at` TIMESTAMP NULL,
  `updated_at` TIMESTAMP NULL,
  `deleted_at` TIMESTAMP NULL,
  INDEX `idx_posts_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```
Explanation ✅ All merge priorities applied. Tables include auto-generated `id`, `created_at`, `updated_at`. Foreign key `user_id` has INDEX. `IF NOT EXISTS` used. Source comment header present.

### ❌ BAD: Missing Defaults and Priorities
```sql
CREATE TABLE users (
  name VARCHAR(255),
  email VARCHAR(255)
);
```
What's wrong ❌ Missing `id` primary key (CR-2 violated). Missing `created_at`/`updated_at` (CR-3 violated). No `IF NOT EXISTS` (CR-6 violated). No ENGINE/CHARSET. No source comment header.

## Error Handling
| Error | Action |
|-------|--------|
| No migration files found | Skip Procedure A, rely on Model/SQL/Validation sources |
| No Model files found | Skip Procedure B, rely on migrations/SQL/Validation sources |
| No SQL statements found in code | Skip Procedure C, rely on other sources |
| No sources found at all | Generate minimal schema with only framework-default tables (e.g., users, migrations), log warning |
| Migration file parse error (invalid PHP syntax) | Log warning for that file, continue with remaining migrations |
| Conflicting field types across sources | Use highest-priority source's type per merge rules |
| Circular foreign key relationships detected | Log warning, omit foreign key constraints (keep INDEX only) |
