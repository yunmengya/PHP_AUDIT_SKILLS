#!/usr/bin/env bash
# ============================================================
# quality_report_gen.sh — 质量报告生成脚本
# ============================================================
# 从 SQLite 读取 QC 记录，生成 $WORK_DIR/质量报告/质量报告.md
#
# 用法: quality_report_gen.sh <WORK_DIR>
# ============================================================
set -euo pipefail

WORK_DIR="${1:?用法: quality_report_gen.sh <WORK_DIR>}"
SESSION_DB="${WORK_DIR}/audit_session.db"
OUTPUT="${WORK_DIR}/质量报告/质量报告.md"
mkdir -p "${WORK_DIR}/质量报告"

if [ ! -f "$SESSION_DB" ]; then
    echo "错误: 数据库不存在 $SESSION_DB"
    exit 1
fi

sql() {
    sqlite3 -batch "$SESSION_DB" ".timeout 5000" "$@" 2>/dev/null
}

sql_json() {
    sqlite3 -batch -json "$SESSION_DB" ".timeout 5000" "$@" 2>/dev/null
}

# ── 收集数据 ──

TOTAL_CHECKS=$(sql "SELECT COUNT(*) FROM qc_records")
PASSED=$(sql "SELECT COUNT(*) FROM qc_records WHERE verdict='pass'")
FAILED=$(sql "SELECT COUNT(*) FROM qc_records WHERE verdict='fail'")
TOTAL_REDOS=$(sql "SELECT COALESCE(SUM(redo_count),0) FROM qc_records")

# 漏洞统计（从 shared_findings）
CONFIRMED=$(sql "SELECT COUNT(*) FROM shared_findings WHERE finding_type='credential'" 2>/dev/null || echo "0")
TOTAL_FINDINGS=$(sql "SELECT COUNT(*) FROM shared_findings" 2>/dev/null || echo "0")

# exploit 统计（如果有 exploits 目录）
EXPLOIT_CONFIRMED=0
EXPLOIT_SUSPECTED=0
EXPLOIT_POTENTIAL=0
if [ -d "$WORK_DIR/exploits" ]; then
    EXPLOIT_CONFIRMED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="confirmed" or .confidence=="confirmed")] | length' 2>/dev/null || echo "0")
    EXPLOIT_SUSPECTED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="suspected" or .confidence=="highly_suspected")] | length' 2>/dev/null || echo "0")
    EXPLOIT_POTENTIAL=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="potential" or .confidence=="potential_risk")] | length' 2>/dev/null || echo "0")
fi

# ── 生成报告 ──

cat > "$OUTPUT" << HEADER
# 审计质量报告

> 由 quality_report_gen.sh 自动生成于 $(date -u +"%Y-%m-%dT%H:%M:%SZ")

## 总览

| 指标 | 值 |
|------|-----|
| 审计目标 | $(basename "$WORK_DIR") |
| 生成时间 | $(date -u +"%Y-%m-%dT%H:%M:%SZ") |
| 总校验次数 | ${TOTAL_CHECKS} |
| 通过次数 | ${PASSED} |
| 不通过次数 | ${FAILED} |
| 总重做次数 | ${TOTAL_REDOS} |
| 漏洞统计 | confirmed=${EXPLOIT_CONFIRMED} / suspected=${EXPLOIT_SUSPECTED} / potential=${EXPLOIT_POTENTIAL} |

## 各阶段校验明细

HEADER

# 按阶段输出
sql "SELECT DISTINCT phase FROM qc_records ORDER BY phase" | while IFS= read -r phase; do
    [ -z "$phase" ] && continue

    # Sanitize phase value (should be numeric, reject anything else)
    case "$phase" in
        [0-9]|[0-9][0-9]) ;;  # valid: 1-99
        *) continue ;;        # skip non-numeric values
    esac

    phase_pass=$(sql "SELECT COUNT(*) FROM qc_records WHERE phase='${phase}' AND verdict='pass'")
    phase_fail=$(sql "SELECT COUNT(*) FROM qc_records WHERE phase='${phase}' AND verdict='fail'")
    phase_total=$(sql "SELECT COUNT(*) FROM qc_records WHERE phase='${phase}'")
    phase_redos=$(sql "SELECT COALESCE(SUM(redo_count),0) FROM qc_records WHERE phase='${phase}'")
    avg_rate=$(sql "SELECT ROUND(AVG(pass_count * 100.0 / NULLIF(total_count, 0)), 1) FROM qc_records WHERE phase='${phase}'")

    # Phase name mapping
    case "$phase" in
        1)     phase_name="Phase 1 环境构建" ;;
        2)     phase_name="Phase 2 静态侦察" ;;
        3)     phase_name="Phase 3 动态追踪" ;;
        4)     phase_name="Phase 4 漏洞利用" ;;
        4-auditor) phase_name="Phase 4 Auditor 级别" ;;
        4.5)   phase_name="Phase 4.5 关联分析" ;;
        5)     phase_name="Phase 5 报告生成" ;;
        *)     phase_name="Phase $phase" ;;
    esac

    cat >> "$OUTPUT" << PHASE
### ${phase_name}

| 指标 | 值 |
|------|-----|
| 校验次数 | ${phase_total}（通过: ${phase_pass} / 不通过: ${phase_fail}）|
| 平均通过率 | ${avg_rate}% |
| 重做次数 | ${phase_redos} |

PHASE

    # 输出每条记录的详情
    echo "| Agent | 结果 | 通过项 | 不通过项 | 重做 |" >> "$OUTPUT"
    echo "|-------|------|--------|---------|------|" >> "$OUTPUT"

    sql "SELECT target_agent, verdict, pass_count, total_count, failed_items, redo_count FROM qc_records WHERE phase='$phase' ORDER BY timestamp" | while IFS='|' read -r agent verdict pc tc fi rc; do
        [ -z "$agent" ] && continue
        verdict_icon="✅"
        [ "$verdict" = "fail" ] && verdict_icon="❌"
        echo "| ${agent} | ${verdict_icon} ${verdict} | ${pc}/${tc} | ${fi} | ${rc} |" >> "$OUTPUT"
    done

    echo "" >> "$OUTPUT"
done

# ── 降级记录 ──
cat >> "$OUTPUT" << DEGRADE

## 降级记录

DEGRADE

DEGRADED=$(sql "SELECT COUNT(*) FROM qc_records WHERE verdict='fail' AND redo_count >= 2")
if [ "$DEGRADED" -gt 0 ]; then
    echo "以下 Agent 多次重做后仍未通过，已降级处理：" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    sql "SELECT phase, target_agent, redo_count, failed_items FROM qc_records WHERE verdict='fail' AND redo_count >= 2" | while IFS='|' read -r phase agent rc fi; do
        echo "- **Phase ${phase} / ${agent}**: 重做 ${rc} 次，剩余不通过项: ${fi}" >> "$OUTPUT"
    done
else
    echo "无降级记录。" >> "$OUTPUT"
fi

# ── 质量结论 ──
if [ "$FAILED" -eq 0 ]; then
    GRADE="A"
    GRADE_DESC="全部通过，无降级"
elif [ "$DEGRADED" -eq 0 ]; then
    GRADE="B"
    GRADE_DESC="全部通过（含重做），无降级"
elif [ "$DEGRADED" -lt 3 ]; then
    GRADE="C"
    GRADE_DESC="有不通过项已修正或降级处理"
else
    GRADE="D"
    GRADE_DESC="多个环节降级"
fi

cat >> "$OUTPUT" << CONCLUSION

## 质量结论

| 指标 | 值 |
|------|-----|
| 整体评级 | **${GRADE}** — ${GRADE_DESC} |
| 校验通过率 | $([ "$TOTAL_CHECKS" -gt 0 ] && echo "$((PASSED * 100 / TOTAL_CHECKS))%" || echo "N/A") |
| 总重做次数 | ${TOTAL_REDOS} |
CONCLUSION

echo "" >> "$OUTPUT"
echo "---" >> "$OUTPUT"
echo "*报告由 quality_report_gen.sh 自动生成*" >> "$OUTPUT"

echo "✅ 质量报告已生成: $OUTPUT"
