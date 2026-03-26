# 统一输出规范（硬约束）

> 本文件定义所有 Agent 输出的强制约束。质检员校验时以此为标准。任何违反硬约束的输出一律判定不通过。

---

## 6 条硬约束

### 约束 1：不增删章节
- 每个 Agent 的输出必须严格包含其对应 data_contracts.md 中定义的所有章节
- 不得新增未定义的章节
- 不得删除或跳过任何章节（无内容则标注 `无` 或 `N/A`，不得省略）

### 约束 2：不改表头/列名
- JSON 输出的字段名必须与 schema 定义完全一致（大小写敏感）
- Markdown 表格的列名必须与模板定义一致
- 不得重命名、合并或拆分列

### 约束 3：占位符必须全部替换
- 输出中不得残留任何占位符标记：`【填写】`、`TODO`、`TBD`、`PLACEHOLDER`、`xxx`
- 质检员使用以下命令检测残留：
  ```bash
  grep -rn '【填写】\|TODO\|TBD\|PLACEHOLDER\|xxx' "$FILE"
  ```
- 发现任何残留 → 该校验项立即判定 ❌

### 约束 4：JSON 必须通过 Schema 校验
- 所有 JSON 输出文件必须通过对应的 `schemas/*.schema.json` 校验
- 校验方法（质检员执行）：
  ```bash
  # 使用 Python 内置 jsonschema（如可用）
  python3 -c "
  import json, jsonschema
  data = json.load(open('$FILE'))
  schema = json.load(open('schemas/$SCHEMA'))
  jsonschema.validate(data, schema)
  print('PASS')
  "
  ```
- 无 jsonschema 模块时，至少验证 JSON 语法正确：
  ```bash
  python3 -m json.tool "$FILE" > /dev/null
  ```

### 约束 5：文件命名规范
- JSON 文件：小写 + 下划线，`.json` 后缀
  - ✅ `route_map.json`, `auth_matrix.json`, `priority_queue.json`
  - ❌ `routeMap.json`, `Route_Map.JSON`
- Exploit 文件：`exploits/{sink_id}.json`，sink_id 使用 kebab-case
  - ✅ `exploits/sqli-user-login.json`
  - ❌ `exploits/SQLi_User_Login.json`
- PoC 文件：`poc/{vuln_type}_{sink_id}.py`
- Patch 文件：`patches/{finding_id}.patch`

### 约束 6：编码 UTF-8
- 所有文本文件必须为 UTF-8 编码（无 BOM）
- 检测方法：
  ```bash
  file --mime-encoding "$FILE" | grep -q 'utf-8\|us-ascii'
  ```

---

## 各 Team 输出必需文件清单

> **输出目录结构**: 所有文件按以下目录组织，不得散放在 WORK_DIR 根目录。

```
$WORK_DIR/
├── 报告/
│   ├── 审计报告.md              ← 主报告（全中文，含 Burp 模板 + 攻击链 + AI验证标记）
│   └── audit_report.sarif.json  ← 机器可读报告（给 CI/CD 用）
├── PoC脚本/
│   ├── poc_{sink_id}.py         ← 独立 PoC 脚本
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

### Team-1（环境构建）

| 文件 | Schema | 必需 | 说明 |
|------|--------|:----:|------|
| environment_status.json | environment_status.schema.json | ✅ | PHP版本、框架、扩展、路由分类 |

### Team-2（静态侦察）

| 文件 | Schema | 必需 | 说明 |
|------|--------|:----:|------|
| route_map.json | route_map.schema.json | ✅ | 路由表 |
| auth_matrix.json | auth_matrix.schema.json | ✅ | 权限矩阵 |
| ast_sinks.json | — | ✅ | AST Sink 扫描结果 |
| priority_queue.json | priority_queue.schema.json | ✅ | 优先级排序 |
| context_packs/*.json | context_pack.schema.json | ✅ | 上下文包 |
| dep_risk.json | dep_risk.schema.json | ⚠️ | 依赖风险评估 |

### Team-3（动态追踪）

| 文件 | Schema | 必需 | 说明 |
|------|--------|:----:|------|
| credentials.json | credentials.schema.json | ✅ | 3 级凭证 |
| traces/*.json | trace_record.schema.json | ✅ | 调用链追踪记录 |

### Team-4（漏洞利用）

| 文件 | Schema | 必需 | 说明 |
|------|--------|:----:|------|
| exploits/{sink_id}.json | — | ✅ | 每个利用结果 |
| .audit_state/team4_progress.json | — | ✅ | 进度汇总 |

### Team-4.5（关联分析）

| 文件 | Schema | 必需 | 说明 |
|------|--------|:----:|------|
| attack_graph.json | — | ✅ | 攻击图 |
| correlation_report.json | — | ✅ | 关联分析报告 |
| 修复补丁/*.patch | — | ⚠️ | 修复补丁 |

### Team-5（报告生成）

| 文件 | Schema | 必需 | 说明 |
|------|--------|:----:|------|
| 报告/审计报告.md | — | ✅ | 全中文审计报告 |
| 报告/audit_report.sarif.json | SARIF 2.1.0 | ✅ | 机器可读报告 |
| PoC脚本/poc_*.py | — | ✅ | PoC 脚本（如有 confirmed） |
| PoC脚本/一键运行.sh | — | ✅ | 批量执行 PoC |
| 质量报告/质量报告.md | — | ✅ | 最终质量报告 |

---

## 违规检测方法（质检员执行）

### 快速全量检测脚本

质检员在校验时依次执行以下检测：

```bash
# 1. 占位符残留检测
echo "=== 占位符残留检测 ==="
find "$WORK_DIR" -name "*.json" -o -name "*.md" | xargs grep -ln '【填写】\|TODO\|TBD\|PLACEHOLDER' 2>/dev/null

# 2. JSON 语法检测
echo "=== JSON 语法检测 ==="
find "$WORK_DIR" -name "*.json" | while read f; do
  python3 -m json.tool "$f" > /dev/null 2>&1 || echo "FAIL: $f"
done

# 3. 编码检测
echo "=== 编码检测 ==="
find "$WORK_DIR" -name "*.json" -o -name "*.md" | while read f; do
  enc=$(file --mime-encoding "$f" | awk -F= '{print $2}')
  case "$enc" in
    utf-8|us-ascii) ;;
    *) echo "BAD ENCODING: $f ($enc)" ;;
  esac
done

# 4. 文件命名检测
echo "=== 文件命名检测 ==="
find "$WORK_DIR" -name "*.json" | while read f; do
  basename "$f" | grep -qE '^[a-z][a-z0-9_-]*\.json$' || echo "BAD NAME: $f"
done

# 5. 必需文件存在性检测
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

### 单文件 Schema 校验

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

## Markdown 报告格式约束

### 审计报告.md 必需章节

1. **概述** — 审计范围、目标、方法
2. **环境信息** — PHP 版本、框架、数据库
3. **漏洞摘要表** — 全部发现的一览表（编号 / 类型 / 等级 / AI验证 / 端点）
4. **漏洞详情**（每条漏洞一个子章节）:
   - AI 验证状态（🟢/🟡/🔴 醒目标签）
   - 攻击链（Mermaid 流程图）
   - 数据流（Source → Sink）
   - Burp 复现模板（完整 HTTP 请求，可直接复制到 Burp Repeater）
   - 服务器响应（物理证据）
   - 修复方案（修复前 vs 修复后代码）
5. **联合攻击链** — 跨漏洞组合攻击路径（Mermaid 图）
6. **覆盖率统计** — 已审计/跳过/总路由 + Agent 执行状态表
7. **待补证风险池** — 未完全验证的条目

### Burp 格式硬约束

```http
POST /api/user/login HTTP/1.1
Host: target:80
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=xxx
Content-Length: 42

username=admin'OR+1=1--&password=anything
```

- 必须包含完整请求行（METHOD URI HTTP/1.1）
- 必须包含 Host header
- 必须包含 Content-Type（如 POST）
- 必须包含认证信息（Cookie/Authorization，如适用）
- 必须包含请求体（如 POST/PUT）
- 可直接复制到 Burp Repeater 使用
