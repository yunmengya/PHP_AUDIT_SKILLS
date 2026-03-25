# Auditor 提交前自检清单（通用 8 项）

> 每个 Phase 4 Auditor 在提交 exploit JSON 前**必须**逐项自检。
> 自检不通过则修正后重新提交，不得跳过。

---

## 通用自检项（所有 Auditor 适用）

| # | 自检项 | 自检方法 | 通过标准 |
|---|--------|----------|----------|
| G1 | **文件存在且路径正确** | 执行 `ls $WORK_DIR/exploits/{sink_id}.json`，确认文件已写入 | 文件存在、大小 > 0 |
| G2 | **JSON Schema 合规** | 用 `cat exploits/{sink_id}.json \| python3 -m json.tool` 校验语法 | 无 JSON 语法错误 |
| G3 | **必填字段完整** | 逐一核对：sink_id、vuln_type、specialist、status、confidence、evidence_score、severity、prerequisite_conditions、evidence、trace | 全部存在且非空 |
| G4 | **EVID 证据链完整** | 对照 `shared/evidence_contract.md` 中本漏洞类型的 EVID 列表，逐个检查 | 每个 EVID 有实际代码片段或 `[未获取: 原因]` 标注 |
| G5 | **evidence_score 与 severity 一致** | 按 `shared/severity_rating.md` 公式：score ≥ 2.10 → evidence_score ≥ 7；1.20-2.09 → 4-6；< 1.20 → 1-3 | 数值区间匹配 |
| G6 | **HTTP 证据格式正确** | Burp 风格：包含完整 Request（含 Host/Cookie 头）和 Response（含 Status Line + Body 摘要） | 非截断、非编造、含时间戳 |
| G7 | **severity 三维评分完整** | 检查 severity 对象：R/I/C 三个值 + 三个 reason 字段 + score + cvss + level + vuln_id | 10 个字段全部填写，reason ≠ 空字符串 |
| G8 | **前置条件已声明** | 检查 prerequisite_conditions：auth_requirement + bypass_method + other_preconditions + exploitability_judgment | 4 个子项全部填写；auth_requirement 与 auth_matrix 一致 |

---

## 降级规则自检

| 条件 | 自动降级动作 | 自检方法 |
|------|-------------|----------|
| `exploitability_judgment = "not_exploitable"` | final_verdict 最高 `potential`，confidence 最高 `low` | 确认 status ≠ confirmed/suspected |
| `exploitability_judgment = "conditionally_exploitable"` | severity.complexity 降 1 级 | 确认 C 值已经降级 |
| EVID 有 `[未获取]` 标注 | status 从 `confirmed` 降为 `suspected` | 确认 status ≠ confirmed |
| evidence_score < 7 | status 不得为 `confirmed` | 确认 status ≠ confirmed |

---

## 使用方式

每个 Auditor 的 prompt 末尾引用本文件：

```
## 提交前自检（必须执行）

完成 exploit JSON 编写后，按 `shared/auditor_self_check.md` 逐项自检：

1. 执行通用 8 项（G1-G8），全部 ✅ 后继续
2. 执行下方专项自检（S1-S3），全部 ✅ 后提交
3. 任何项 ❌ → 修正后重新自检，不得跳过

### 专项自检（本 Auditor 特有）
- [ ] S1: [此处由各 Auditor 自定义]
- [ ] S2: [此处由各 Auditor 自定义]
- [ ] S3: [此处由各 Auditor 自定义]
```
