#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# PHP Audit Skills — 实时审计进度面板
# 用法: bash tools/audit_monitor.sh <WORK_DIR>
# 依赖: bash, jq (macOS/Linux 自带)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

WORK_DIR="${1:?用法: bash tools/audit_monitor.sh <WORK_DIR>}"

if [ ! -d "$WORK_DIR" ]; then
  echo "❌ 工作目录不存在: $WORK_DIR"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "❌ 需要 jq（brew install jq / apt install jq）"
  exit 1
fi

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

phase_status() {
  local label="$1" check="$2" color="$3"
  if eval "$check"; then
    echo -e "  ${color}✅ ${label}${NC}"
    return 0
  else
    echo -e "  ${GRAY}⬜ ${label}${NC}"
    return 1
  fi
}

while true; do
  clear
  echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║          🔒 PHP Security Audit — 实时进度面板           ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
  echo -e "${GRAY}  目标: ${WORK_DIR}${NC}"
  echo -e "${GRAY}  时间: $(date '+%H:%M:%S')${NC}"
  echo ""

  # ── Phase 1: 环境构建 ──
  if [ -f "$WORK_DIR/environment_status.json" ]; then
    FRAMEWORK=$(jq -r '.framework // "unknown"' "$WORK_DIR/environment_status.json" 2>/dev/null)
    FW_VER=$(jq -r '.framework_version // ""' "$WORK_DIR/environment_status.json" 2>/dev/null)
    PHP_VER=$(jq -r '.php_version // "?"' "$WORK_DIR/environment_status.json" 2>/dev/null)
    DB_TYPE=$(jq -r '.db_type // "?"' "$WORK_DIR/environment_status.json" 2>/dev/null)
    ROUNDS=$(jq -r '.startup_rounds // "?"' "$WORK_DIR/environment_status.json" 2>/dev/null)
    ROUTES_A=$(jq -r '.routes_accessible // 0' "$WORK_DIR/environment_status.json" 2>/dev/null)
    ROUTES_B=$(jq -r '.routes_error // 0' "$WORK_DIR/environment_status.json" 2>/dev/null)
    ROUTES_C=$(jq -r '.routes_inaccessible // 0' "$WORK_DIR/environment_status.json" 2>/dev/null)
    echo -e "  ${GREEN}✅ Phase 1: 环境构建完成${NC}"
    echo -e "     ${FRAMEWORK} ${FW_VER} | PHP ${PHP_VER} | ${DB_TYPE} | ${ROUNDS}轮启动"
    echo -e "     路由: ${GREEN}A:${ROUTES_A}${NC} ${YELLOW}B:${ROUTES_B}${NC} ${RED}C:${ROUTES_C}${NC}"
  else
    echo -e "  ${YELLOW}⏳ Phase 1: 环境构建中...${NC}"
  fi

  # ── Phase 2: 静态侦察 ──
  if [ -f "$WORK_DIR/priority_queue.json" ]; then
    SINK_TOTAL=$(jq '. | length' "$WORK_DIR/priority_queue.json" 2>/dev/null || echo 0)
    P0=$(jq '[.[] | select(.priority=="P0")] | length' "$WORK_DIR/priority_queue.json" 2>/dev/null || echo 0)
    P1=$(jq '[.[] | select(.priority=="P1")] | length' "$WORK_DIR/priority_queue.json" 2>/dev/null || echo 0)
    P2=$(jq '[.[] | select(.priority=="P2")] | length' "$WORK_DIR/priority_queue.json" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}✅ Phase 2: 侦察完成${NC} (${SINK_TOTAL} sinks)"
    echo -e "     优先级: ${RED}P0:${P0}${NC} ${YELLOW}P1:${P1}${NC} ${BLUE}P2:${P2}${NC}"
  elif [ -f "$WORK_DIR/route_map.json" ]; then
    ROUTE_COUNT=$(jq '.routes | length' "$WORK_DIR/route_map.json" 2>/dev/null || echo "?")
    echo -e "  ${YELLOW}⏳ Phase 2: 侦察中...${NC} (${ROUTE_COUNT} 路由已映射)"
  elif [ -f "$WORK_DIR/environment_status.json" ]; then
    echo -e "  ${YELLOW}⏳ Phase 2: 侦察中...${NC}"
  else
    echo -e "  ${GRAY}⬜ Phase 2: 等待中${NC}"
  fi

  # ── Phase 3: 鉴权+追踪 ──
  if [ -f "$WORK_DIR/credentials.json" ]; then
    ROLES=$(jq '. | keys | length' "$WORK_DIR/credentials.json" 2>/dev/null || echo "?")
    TRACE_COUNT=$(ls "$WORK_DIR/traces/"*.json 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  ${GREEN}✅ Phase 3: 鉴权+追踪完成${NC} (${ROLES}角色, ${TRACE_COUNT}条trace)"
  elif [ -f "$WORK_DIR/priority_queue.json" ]; then
    echo -e "  ${YELLOW}⏳ Phase 3: 鉴权/追踪中...${NC}"
  else
    echo -e "  ${GRAY}⬜ Phase 3: 等待中${NC}"
  fi

  # ── Phase 4: 深度攻击 ──
  PLANS=$(ls "$WORK_DIR/exploits/"*_plan.json 2>/dev/null | wc -l | tr -d ' ')
  RESULTS=$(ls "$WORK_DIR/exploits/"*.json 2>/dev/null | grep -cv '_plan' 2>/dev/null || echo 0)
  CONFIRMED=$(grep -rl '"confirmed"' "$WORK_DIR/exploits/"*.json 2>/dev/null | grep -cv '_plan' 2>/dev/null || echo 0)
  SUSPECTED=$(grep -rl '"suspected"' "$WORK_DIR/exploits/"*.json 2>/dev/null | grep -cv '_plan' 2>/dev/null || echo 0)

  if [ "$RESULTS" -gt 0 ] && [ "$PLANS" -eq "$RESULTS" ]; then
    echo -e "  ${GREEN}✅ Phase 4: 攻击完成${NC}"
    echo -e "     ${RED}确认:${CONFIRMED}${NC} ${YELLOW}疑似:${SUSPECTED}${NC} ${GRAY}总计:${RESULTS}${NC}"
  elif [ "$RESULTS" -gt 0 ] || [ "$PLANS" -gt 0 ]; then
    echo -e "  ${RED}🔴 Phase 4: 攻击进行中${NC}"
    echo -e "     分析计划: ${PLANS} | 攻击完成: ${RESULTS} | ${RED}确认:${CONFIRMED}${NC}"
  elif [ -f "$WORK_DIR/credentials.json" ]; then
    echo -e "  ${YELLOW}⏳ Phase 4: 准备启动...${NC}"
  else
    echo -e "  ${GRAY}⬜ Phase 4: 等待中${NC}"
  fi

  # ── Phase 4.5: 后渗透 ──
  if [ -f "$WORK_DIR/attack_graph.json" ] && [ -f "$WORK_DIR/correlation_report.json" ]; then
    POC_COUNT=$(ls "$WORK_DIR/poc/"*.py 2>/dev/null | wc -l | tr -d ' ')
    PATCH_COUNT=$(ls "$WORK_DIR/patches/"*.patch 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  ${GREEN}✅ Phase 4.5: 后渗透完成${NC} (${POC_COUNT} PoC, ${PATCH_COUNT} Patch)"
  elif [ -f "$WORK_DIR/attack_graph.json" ] || [ -f "$WORK_DIR/correlation_report.json" ]; then
    echo -e "  ${PURPLE}⏳ Phase 4.5: 后渗透分析中...${NC}"
  elif [ "$RESULTS" -gt 0 ]; then
    echo -e "  ${YELLOW}⏳ Phase 4.5: 等待攻击完成...${NC}"
  else
    echo -e "  ${GRAY}⬜ Phase 4.5: 等待中${NC}"
  fi

  # ── Phase 5: 报告 ──
  if [ -f "$WORK_DIR/报告/审计报告.md" ]; then
    REPORT_SIZE=$(wc -c < "$WORK_DIR/报告/审计报告.md" | tr -d ' ')
    REPORT_KB=$((REPORT_SIZE / 1024))
    SARIF_OK="❌"
    [ -f "$WORK_DIR/报告/audit_report.sarif.json" ] && SARIF_OK="✅"
    echo -e "  ${GREEN}✅ Phase 5: 报告完成${NC} (${REPORT_KB}KB) SARIF:${SARIF_OK}"
  elif [ -f "$WORK_DIR/attack_graph.json" ]; then
    echo -e "  ${CYAN}⏳ Phase 5: 报告生成中...${NC}"
  else
    echo -e "  ${GRAY}⬜ Phase 5: 等待中${NC}"
  fi

  # ── 分隔线 ──
  echo ""
  echo -e "${BOLD}──────────── 实时情报 ────────────${NC}"

  # ── 最新共享发现 ──
  if [ -f "$WORK_DIR/audit_session.db" ]; then
    FINDING_COUNT=$(sqlite3 "$WORK_DIR/audit_session.db" "SELECT COUNT(*) FROM shared_findings;" 2>/dev/null || echo 0)
    echo -e "  ${CYAN}📡 共享发现: ${FINDING_COUNT} 条${NC}"
    sqlite3 -json "$WORK_DIR/audit_session.db" "SELECT source_agent, finding_type, json_extract(data,'$.key') as data_key FROM shared_findings ORDER BY timestamp DESC LIMIT 3;" 2>/dev/null | jq -r '.[] | "\(.source_agent) [\(.finding_type)] \(.data_key // "...")"' 2>/dev/null | while IFS= read -r line; do
      echo -e "     ${GRAY}${line}${NC}"
    done
  else
    echo -e "  ${GRAY}📡 暂无共享发现${NC}"
  fi

  # ── OOB 回调日志 ──
  if [ -f "$WORK_DIR/oob/log.jsonl" ]; then
    OOB_COUNT=$(wc -l < "$WORK_DIR/oob/log.jsonl" | tr -d ' ')
    echo -e "  ${RED}🎯 OOB 回调: ${OOB_COUNT} 次${NC}"
    tail -2 "$WORK_DIR/oob/log.jsonl" 2>/dev/null | while IFS= read -r line; do
      PATH_VAL=$(echo "$line" | jq -r '.path // "?"' 2>/dev/null)
      TS=$(echo "$line" | jq -r '.timestamp // ""' 2>/dev/null | cut -d'T' -f2 | cut -d'.' -f1)
      echo -e "     ${GRAY}${TS}${NC} ${PATH_VAL}"
    done
  fi

  # ── 计时 ──
  if [ -f "$WORK_DIR/checkpoint.json" ]; then
    ENV_SEC=$(jq -r '.timing.env_seconds // 0' "$WORK_DIR/checkpoint.json" 2>/dev/null)
    SCAN_SEC=$(jq -r '.timing.scan_seconds // 0' "$WORK_DIR/checkpoint.json" 2>/dev/null)
    TRACE_SEC=$(jq -r '.timing.trace_seconds // 0' "$WORK_DIR/checkpoint.json" 2>/dev/null)
    EXPLOIT_SEC=$(jq -r '.timing.exploit_seconds // 0' "$WORK_DIR/checkpoint.json" 2>/dev/null)
    TOTAL=$((ENV_SEC + SCAN_SEC + TRACE_SEC + EXPLOIT_SEC))
    echo ""
    echo -e "  ${GRAY}⏱ 耗时: 环境${ENV_SEC}s 侦察${SCAN_SEC}s 追踪${TRACE_SEC}s 攻击${EXPLOIT_SEC}s 总计${TOTAL}s${NC}"
  fi

  echo ""
  echo -e "${GRAY}  按 Ctrl+C 退出 | 每 5 秒刷新${NC}"
  sleep 5
done
