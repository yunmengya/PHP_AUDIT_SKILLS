# Phase-4 Auditor 输出模板（填充式）

> **所有 Phase-4 Auditor 必须严格按本模板生成 `exploits/{sink_id}.json`。**
> 本模板是 `schemas/exploit_result.schema.json` 的填充式版本，LLM 只需将【填写】替换为实际内容。
> 硬约束详见 `shared/output_standard.md`。

---

## ⛔ 输出铁律

1. **文件路径**: `$WORK_DIR/exploits/{sink_id}.json` — 一个 Sink 一个文件，不得合并
2. **JSON 语法**: 提交前执行 `python3 -m json.tool exploits/{sink_id}.json`，语法错误 → 不提交
3. **字段完整**: 所有 `required` 字段必须存在且非空，缺字段 → 质检不通过
4. **【填写】清零**: 提交时 `grep '【填写】' exploits/{sink_id}.json` 命中数必须为 0
5. **auth_matrix 只读**: `auth_requirement` 必须与 `auth_matrix.json` 中该路由的 `auth_level` 严格一致，禁止自行修改鉴权判定
6. **evidence_score ↔ severity 一致**: score ≥ 2.10 → evidence_score ≥ 7；1.20-2.09 → 4-6；< 1.20 → 1-3

---

## JSON 填充模板

```json
{
  "sink_id": "【填写：如 sink_042】",
  "route_url": "【填写：如 /api/user/profile】",
  "sink_function": "【填写：如 mysqli_query、include、exec】",
  "specialist": "【填写：本 Auditor 名称，如 sqli_auditor】",
  "route_type": "【填写：A=高危无鉴权 / B=有鉴权 / C=间接调用】",
  "rounds_executed": "【填写：实际执行的攻击轮次数，1-8】",
  "rounds_skipped": "【填写：跳过的轮次数，0-8】",
  "skip_reason": "【填写：跳过原因，无则 null】",

  "results": [
    {
      "round": 1,
      "strategy": "【填写：策略名称，如 经典单引号探测】",
      "payload": "【填写：实际发送的完整 payload】",
      "injection_point": "【填写：注入点，如 GET参数id / POST body username / Cookie session_id】",
      "request": "【填写：完整 HTTP 请求，Burp 风格，含 Host/Cookie/Content-Type 头】",
      "response_status": "【填写：HTTP 状态码，如 200】",
      "response_body_snippet": "【填写：响应体前 500 字符】",
      "evidence_type": "【填写：证据类型，如 error_based / time_based / blind_boolean，无则 null】",
      "evidence_detail": "【填写：证据详情，如 响应含 SQL syntax error near...，无则 null】",
      "result": "【填写：confirmed / suspected / failed】",
      "failure_reason": "【填写：失败原因，成功则 null】"
    }
  ],

  "final_verdict": "【填写：confirmed / suspected / potential / not_vulnerable】",
  "confidence": "【填写：high / medium / low】",
  "evidence_score": "【填写：1-10 整数，与 severity.score 区间对应】",

  "evidence": {
    "EVID_XXX_FIRST": "【填写：第一个证据点，如 app/Models/User.php:89 — DB::select(\"SELECT * FROM...\")】",
    "EVID_XXX_SECOND": "【填写：第二个证据点，引用 shared/evidence_contract.md 中本漏洞类型的 EVID 列表】"
  },

  "trace": {
    "source": "【填写：用户输入来源，如 $_GET['id']】",
    "sink": "【填写：危险函数，如 mysqli_query($conn, $sql)】",
    "call_chain": "【填写：完整调用链，如 Controller::show() → Model::findRaw() → DB::select()】",
    "taint_flow": "【填写：污点传播路径，如 $id(未过滤) → $sql(拼接) → mysqli_query(执行)】"
  },

  "severity": {
    "reachability": "【填写：0-3 整数】",
    "reachability_reason": "【填写：判定依据，如 该路由无鉴权中间件，任何人可访问】",
    "impact": "【填写：0-3 整数】",
    "impact_reason": "【填写：判定依据，如 可读取全部用户表数据含密码哈希】",
    "complexity": "【填写：0-3 整数】",
    "complexity_reason": "【填写：判定依据，如 单个 GET 请求即可触发，无 WAF】",
    "score": "【填写：R×0.40 + I×0.35 + C×0.25 计算结果】",
    "cvss": "【填写：(score / 3.0) × 10.0 计算结果】",
    "level": "【填写：C / H / M / L（按 score 区间映射）】",
    "vuln_id": "【填写：如 C-SQL-001，格式 {Level}-{Type}-{Sequence}】"
  },

  "prerequisite_conditions": {
    "auth_requirement": "【填写：anonymous / authenticated / admin / internal_network — 必须与 auth_matrix 一致】",
    "bypass_method": "【填写：鉴权绕过方法，如 IDOR via user_id param，无则 null】",
    "other_preconditions": ["【填写：前提条件，如 APP_DEBUG=true，无则空数组 []】"],
    "exploitability_judgment": "【填写：directly_exploitable / conditionally_exploitable / not_exploitable】"
  }
}
```

---

## 降级规则（Auditor 必须自行执行）

| 条件 | 降级动作 |
|------|----------|
| `exploitability_judgment = "not_exploitable"` | `final_verdict` 最高 `potential`，`confidence` 最高 `low` |
| `exploitability_judgment = "conditionally_exploitable"` | `severity.complexity` 降 1 级 |
| 任何 EVID 标注 `[未获取: 原因]` | `final_verdict` 从 `confirmed` 降为 `suspected` |
| `evidence_score < 7` | `final_verdict` 不得为 `confirmed` |

---

## 特殊字段说明

### race_condition_results（仅 race_condition_auditor 填写）
```json
{
  "race_condition_results": {
    "tested": true,
    "concurrent_requests": "【填写：并发请求数】",
    "result": "【填写：vulnerable / not_vulnerable】",
    "detail": "【填写：竞争结果描述】"
  }
}
```
其他 Auditor 此字段填 `null`。

### evidence 字段的 EVID 命名
- 参照 `shared/evidence_contract.md` 中对应漏洞类型的 EVID 列表
- 每个 EVID 的值 = `文件路径:行号 — 代码片段或描述`
- 如无法获取某 EVID，填 `[未获取: 具体原因]`，不得留空或省略

---

## 提交前检查命令

```bash
# 1. JSON 语法校验
python3 -m json.tool "$WORK_DIR/exploits/${SINK_ID}.json" > /dev/null 2>&1 && echo "✅ JSON valid" || echo "❌ JSON invalid"

# 2. 占位符残留检测
grep -c '【填写】' "$WORK_DIR/exploits/${SINK_ID}.json" | grep -q '^0$' && echo "✅ No placeholders" || echo "❌ Placeholders remain"

# 3. 必填字段检查
python3 -c "
import json, sys
with open(sys.argv[1]) as f: d = json.load(f)
required = ['sink_id','route_url','sink_function','specialist','route_type','rounds_executed','results','final_verdict','confidence','evidence','severity','prerequisite_conditions']
missing = [k for k in required if k not in d or d[k] is None]
print('✅ All required fields present' if not missing else f'❌ Missing: {missing}')
" "$WORK_DIR/exploits/${SINK_ID}.json"
```
