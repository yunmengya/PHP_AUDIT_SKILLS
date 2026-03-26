# Unified Output Standard (Hard Constraints)

> This file defines mandatory constraints for all Agent outputs. The QA Inspector uses this as the standard during validation. Any output violating hard constraints MUST be rejected.

---

## 6 Hard Constraints

### Constraint 1: No Adding or Removing Sections
- Each Agent's output MUST strictly include all sections defined in its corresponding data_contracts.md
- MUST NOT add undefined sections
- MUST NOT remove or skip any section (if no content, mark as `N/A` or `None`, MUST NOT omit)

### Constraint 2: No Modifying Table Headers/Column Names
- JSON output field names MUST exactly match the schema definitions (case-sensitive)
- Markdown table column names MUST match the template definitions
- MUST NOT rename, merge, or split columns

### Constraint 3: All Placeholders MUST Be Replaced
- Output MUST NOT contain any remaining placeholder markers: `【填写】`, `TODO`, `TBD`, `PLACEHOLDER`, `xxx`
- The QA Inspector uses the following command to detect remnants:
  ```bash
  grep -rn '【填写】\|TODO\|TBD\|PLACEHOLDER\|xxx' "$FILE"
  ```
- Any remnant found → that validation item is immediately marked ❌

### Constraint 4: JSON MUST Pass Schema Validation
- All JSON output files MUST pass validation against their corresponding `schemas/*.schema.json`
- Validation method (executed by QA Inspector):
  ```bash
  # Using Python built-in jsonschema (if available)
  python3 -c "
  import json, jsonschema
  data = json.load(open('$FILE'))
  schema = json.load(open('schemas/$SCHEMA'))
  jsonschema.validate(data, schema)
  print('PASS')
  "
  ```
- When the jsonschema module is unavailable, at minimum verify JSON syntax is correct:
  ```bash
  python3 -m json.tool "$FILE" > /dev/null
  ```

### Constraint 5: File Naming Convention
- JSON files: lowercase + underscore, `.json` suffix
  - ✅ `route_map.json`, `auth_matrix.json`, `priority_queue.json`
  - ❌ `routeMap.json`, `Route_Map.JSON`
- Exploit files: `exploits/{sink_id}.json`, sink_id uses kebab-case
  - ✅ `exploits/sqli-user-login.json`
  - ❌ `exploits/SQLi_User_Login.json`
- PoC files: `PoC脚本/{vuln_type}_{sink_id}.py`
- Patch files: `修复补丁/{finding_id}.patch`

### Constraint 6: UTF-8 Encoding
- All text files MUST be UTF-8 encoded (no BOM)
- Detection method:
  ```bash
  file --mime-encoding "$FILE" | grep -q 'utf-8\|us-ascii'
  ```

---

## Required Output Files per Team

> **Output directory structure**: All files MUST be organized in the following directory structure. Files MUST NOT be placed directly in the WORK_DIR root.

```
$WORK_DIR/
├── 报告/
│   ├── 审计报告.md              ← Main report (full Chinese, with Burp templates + attack chains + AI verification markers)
│   └── audit_report.sarif.json  ← Machine-readable report (for CI/CD)
├── PoC脚本/
│   ├── poc_{sink_id}.py         ← Standalone PoC scripts
│   ├── requirements.txt
│   └── 一键运行.sh
├── 修复补丁/
│   └── {finding_id}.patch
├── 经验沉淀/
│   ├── 经验总结.md
│   └── 共享文件更新建议.md
├── 质量报告/
│   └── 质量报告.md
└── 原始数据/
    ├── environment_status.json
    ├── route_map.json
    ├── auth_matrix.json
    ├── ast_sinks.json
    ├── priority_queue.json
    ├── credentials.json
    ├── dep_risk.json
    ├── exploit_summary.json
    ├── attack_graph.json
    ├── correlation_report.json
    ├── attack_graph_data.json
    ├── context_packs/
    ├── traces/
    ├── exploits/
    └── .audit_state/
```

### Team-1 (Environment Setup)

| File | Schema | Required | Description |
|------|--------|:--------:|-------------|
| environment_status.json | environment_status.schema.json | ✅ | PHP version, framework, extensions, route classification |

### Team-2 (Static Reconnaissance)

| File | Schema | Required | Description |
|------|--------|:--------:|-------------|
| route_map.json | route_map.schema.json | ✅ | Route table |
| auth_matrix.json | auth_matrix.schema.json | ✅ | Authorization matrix |
| ast_sinks.json | — | ✅ | AST Sink scan results |
| priority_queue.json | priority_queue.schema.json | ✅ | Priority ranking |
| context_packs/*.json | context_pack.schema.json | ✅ | Context packs |
| dep_risk.json | dep_risk.schema.json | ⚠️ | Dependency risk assessment |

### Team-3 (Dynamic Tracing)

| File | Schema | Required | Description |
|------|--------|:--------:|-------------|
| credentials.json | credentials.schema.json | ✅ | 3-tier credentials |
| traces/*.json | trace_record.schema.json | ✅ | Call chain trace records |

### Team-4 (Exploit Verification)

| File | Schema | Required | Description |
|------|--------|:--------:|-------------|
| exploits/{sink_id}.json | — | ✅ | Individual exploit results |
| .audit_state/team4_progress.json | — | ✅ | Progress summary |

### Team-4.5 (Correlation Analysis)

| File | Schema | Required | Description |
|------|--------|:--------:|-------------|
| attack_graph.json | — | ✅ | Attack graph |
| correlation_report.json | — | ✅ | Correlation analysis report |
| 修复补丁/*.patch | — | ⚠️ | Fix patches |

### Team-5 (Report Generation)

| File | Schema | Required | Description |
|------|--------|:--------:|-------------|
| 报告/审计报告.md | — | ✅ | Full Chinese audit report |
| 报告/audit_report.sarif.json | SARIF 2.1.0 | ✅ | Machine-readable report |
| PoC脚本/poc_*.py | — | ✅ | PoC scripts (if confirmed findings exist) |
| PoC脚本/一键运行.sh | — | ✅ | Batch PoC execution |
| 质量报告/质量报告.md | — | ✅ | Final quality report |

---

## Violation Detection Methods (Executed by QA Inspector)

### Quick Full-Scan Detection Script

The QA Inspector executes the following checks sequentially during validation:

```bash
# 1. Placeholder remnant detection
echo "=== 占位符残留检测 ==="
find "$WORK_DIR" -name "*.json" -o -name "*.md" | xargs grep -ln '【填写】\|TODO\|TBD\|PLACEHOLDER' 2>/dev/null

# 2. JSON syntax detection
echo "=== JSON 语法检测 ==="
find "$WORK_DIR" -name "*.json" | while read f; do
  python3 -m json.tool "$f" > /dev/null 2>&1 || echo "FAIL: $f"
done

# 3. Encoding detection
echo "=== 编码检测 ==="
find "$WORK_DIR" -name "*.json" -o -name "*.md" | while read f; do
  enc=$(file --mime-encoding "$f" | awk -F= '{print $2}')
  case "$enc" in
    utf-8|us-ascii) ;;
    *) echo "BAD ENCODING: $f ($enc)" ;;
  esac
done

# 4. File naming detection
echo "=== 文件命名检测 ==="
find "$WORK_DIR" -name "*.json" | while read f; do
  basename "$f" | grep -qE '^[a-z][a-z0-9_-]*\.json$' || echo "BAD NAME: $f"
done

# 5. Required file existence detection
echo "=== 必需文件检测 ==="
for f in environment_status.json route_map.json auth_matrix.json ast_sinks.json \
         priority_queue.json credentials.json; do
  [ -f "$WORK_DIR/$f" ] || echo "MISSING: $f"
done
[ -f "$WORK_DIR/报告/审计报告.md" ] || echo "MISSING: 报告/审计报告.md"
[ -f "$WORK_DIR/报告/audit_report.sarif.json" ] || echo "MISSING: 报告/audit_report.sarif.json"
[ -d "$WORK_DIR/context_packs" ] || echo "MISSING: context_packs/"
[ -d "$WORK_DIR/traces" ] || echo "MISSING: traces/"
[ -d "$WORK_DIR/exploits" ] || echo "MISSING: exploits/"
```

### Single-File Schema Validation

```bash
validate_schema() {
  local file="$1" schema="$2"
  python3 -c "
import json, sys
try:
    import jsonschema
    data = json.load(open('$file'))
    schema = json.load(open('$schema'))
    jsonschema.validate(data, schema)
    print('PASS: $file')
except jsonschema.ValidationError as e:
    print(f'FAIL: $file — {e.message}')
    sys.exit(1)
except ImportError:
    data = json.load(open('$file'))
    print('PASS (syntax only): $file')
" 2>&1
}
```

---

## Markdown Report Format Constraints

### Required Sections in 审计报告.md

1. **概述** — Audit scope, objectives, methodology
2. **环境信息** — PHP version, framework, database
3. **漏洞摘要表** — Summary table of all findings (ID / Type / Severity / AI Verification / Endpoint)
4. **漏洞详情** (one subsection per vulnerability):
   - AI 验证状态 (🟢/🟡/🔴 prominent labels)
   - 攻击链 (Mermaid flowchart)
   - 数据流 (Source → Sink)
   - Burp 复现模板 (complete HTTP request, directly copyable to Burp Repeater)
   - 服务器响应 (physical evidence)
   - 修复方案 (before-fix vs after-fix code)
5. **联合攻击链** — Cross-vulnerability combined attack paths (Mermaid diagram)
6. **覆盖率统计** — Audited/Skipped/Total routes + Agent execution status table
7. **待补证风险池** — Items not fully verified

### Burp Format Hard Constraints

```http
POST /api/user/login HTTP/1.1
Host: target:80
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=xxx
Content-Length: 42

username=admin'OR+1=1--&password=anything
```

- MUST include complete request line (METHOD URI HTTP/1.1)
- MUST include Host header
- MUST include Content-Type (for POST requests)
- MUST include authentication information (Cookie/Authorization, if applicable)
- MUST include request body (for POST/PUT)
- MUST be directly copyable to Burp Repeater
