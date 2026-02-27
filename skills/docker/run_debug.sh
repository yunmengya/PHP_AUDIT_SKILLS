#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

usage() {
  cat <<'USAGE'
Usage:
  skills/docker/run_debug.sh <project> [out] [debug options...]

AI options:
  --ai-realtime                         Enable realtime AI supplement (default)
  --disable-ai-realtime                 Disable realtime AI supplement
  --ai-model <model>                    Override model
  --ai-rounds <n>                       AI rounds (default: 2)
  --ai-candidates-per-round <n>         AI candidates per round (default: 5)
  --ai-timeout <sec>                    AI timeout in seconds (default: 30)
  --trace-verbose                       Write per-case trace JSON under debug_verify/trace_cases

Default out:
  If [out] is omitted, output path is /tmp/{project_name}/{timestamp}.
USAGE
}

abs_path() {
  local input="$1"
  if [[ "${input}" == /* ]]; then
    printf '%s\n' "${input}"
  else
    printf '%s\n' "$(pwd)/${input}"
  fi
}

default_tmp_out_dir() {
  local project_host="$1"
  local base_tmp="${SKILLS_TMP_DIR:-/tmp}"
  local project_name
  local timestamp
  local out_dir
  local suffix=0
  project_name="$(basename "${project_host%/}")"
  project_name="$(printf '%s' "${project_name}" | tr -cs 'A-Za-z0-9._-' '_')"
  timestamp="$(date +%Y%m%d_%H%M%S)"
  out_dir="${base_tmp}/${project_name}/${timestamp}"
  while [[ -e "${out_dir}" ]]; do
    suffix=$((suffix + 1))
    out_dir="${base_tmp}/${project_name}/${timestamp}_${suffix}"
  done
  mkdir -p "${out_dir}"
  printf '%s\n' "${out_dir}"
}

docker_daemon_ready() {
  docker info >/dev/null 2>&1
}

start_docker_desktop_best_effort() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    return 0
  fi
  if command -v open >/dev/null 2>&1; then
    if [[ -d "/Applications/Docker.app" ]]; then
      open -ga Docker >/dev/null 2>&1 || open -a Docker >/dev/null 2>&1 || true
    fi
  fi
}

ensure_docker_daemon() {
  if docker_daemon_ready; then
    return
  fi
  echo "[INFO] Docker daemon is not ready; trying to start Docker..." >&2
  start_docker_desktop_best_effort

  local timeout_sec="${DOCKER_START_TIMEOUT_SEC:-120}"
  local waited=0
  while (( waited < timeout_sec )); do
    if docker_daemon_ready; then
      echo "[INFO] Docker daemon is ready." >&2
      return
    fi
    sleep 2
    waited=$((waited + 2))
  done

  echo "Error: Docker daemon not ready after ${timeout_sec}s." >&2
  echo "Hint: start Docker Desktop manually, then rerun skills/docker/run_debug.sh." >&2
  exit 1
}

ensure_readable_dir() {
  local dir="$1"
  local label="$2"
  if [[ ! -e "${dir}" ]]; then
    echo "Error: ${label} does not exist: ${dir}" >&2
    exit 1
  fi
  if [[ ! -d "${dir}" ]]; then
    echo "Error: ${label} must be a directory: ${dir}" >&2
    exit 1
  fi
  if [[ ! -r "${dir}" ]]; then
    echo "Error: ${label} is not readable: ${dir}" >&2
    exit 1
  fi
}

ensure_writable_dir() {
  local dir="$1"
  mkdir -p "${dir}" || {
    echo "Error: failed to create output directory: ${dir}" >&2
    exit 1
  }
  if [[ ! -d "${dir}" ]]; then
    echo "Error: output path is not a directory: ${dir}" >&2
    exit 1
  fi
  local probe="${dir}/.write_probe_$$"
  if ! : > "${probe}" 2>/dev/null; then
    echo "Error: output directory is not writable: ${dir}" >&2
    exit 1
  fi
  rm -f "${probe}"
}

mount_cases_file() {
  local host_path="$1"
  if [[ ! -e "${host_path}" ]]; then
    echo "Error: cases file does not exist: ${host_path}" >&2
    exit 1
  fi
  if [[ ! -f "${host_path}" ]]; then
    echo "Error: cases path must be a file: ${host_path}" >&2
    exit 1
  fi
  if [[ ! -r "${host_path}" ]]; then
    echo "Error: cases file is not readable: ${host_path}" >&2
    exit 1
  fi
  printf '/work/cases/%s\n' "$(basename "${host_path}")"
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

PROJECT_INPUT="$1"
shift

OUT_INPUT=""
if [[ $# -gt 0 && "$1" != --* ]]; then
  OUT_INPUT="$1"
  shift
fi

PROJECT_HOST="$(abs_path "${PROJECT_INPUT}")"
ensure_readable_dir "${PROJECT_HOST}" "project"

if [[ -n "${OUT_INPUT}" ]]; then
  OUT_HOST="$(abs_path "${OUT_INPUT}")"
else
  OUT_HOST="$(default_tmp_out_dir "${PROJECT_HOST}")"
fi
ensure_writable_dir "${OUT_HOST}"
ensure_docker_daemon

AI_REALTIME=1
AI_MODEL=""
AI_ROUNDS=2
AI_CANDIDATES_PER_ROUND=5
AI_TIMEOUT=30

MOUNTS=(
  -v "${PROJECT_HOST}:/work/project:ro"
  -v "${OUT_HOST}:/work/out:rw"
)
RUNNER_ARGS=()

while [[ $# -gt 0 ]]; do
  token="$1"
  case "${token}" in
    --project|--out)
      echo "Error: use positional <project> [out], do not pass ${token}." >&2
      exit 1
      ;;
    --project=*|--out=*)
      echo "Error: use positional <project> [out], do not pass ${token}." >&2
      exit 1
      ;;

    --ai-realtime)
      AI_REALTIME=1
      shift
      ;;
    --disable-ai-realtime)
      AI_REALTIME=0
      shift
      ;;

    --ai-model)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-model requires a value" >&2
        exit 1
      fi
      AI_MODEL="$2"
      shift 2
      ;;
    --ai-model=*)
      AI_MODEL="${token#--ai-model=}"
      shift
      ;;

    --ai-rounds)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-rounds requires a value" >&2
        exit 1
      fi
      AI_ROUNDS="$2"
      shift 2
      ;;
    --ai-rounds=*)
      AI_ROUNDS="${token#--ai-rounds=}"
      shift
      ;;

    --ai-candidates-per-round)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-candidates-per-round requires a value" >&2
        exit 1
      fi
      AI_CANDIDATES_PER_ROUND="$2"
      shift 2
      ;;
    --ai-candidates-per-round=*)
      AI_CANDIDATES_PER_ROUND="${token#--ai-candidates-per-round=}"
      shift
      ;;

    --ai-timeout)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-timeout requires a value" >&2
        exit 1
      fi
      AI_TIMEOUT="$2"
      shift 2
      ;;
    --ai-timeout=*)
      AI_TIMEOUT="${token#--ai-timeout=}"
      shift
      ;;

    --cases)
      if [[ $# -lt 2 ]]; then
        echo "Error: --cases requires a path" >&2
        exit 1
      fi
      cases_host="$(abs_path "$2")"
      cases_container="$(mount_cases_file "${cases_host}")"
      MOUNTS+=( -v "${cases_host}:${cases_container}:ro" )
      RUNNER_ARGS+=( --cases "${cases_container}" )
      shift 2
      ;;
    --cases=*)
      cases_value="${token#--cases=}"
      cases_host="$(abs_path "${cases_value}")"
      cases_container="$(mount_cases_file "${cases_host}")"
      MOUNTS+=( -v "${cases_host}:${cases_container}:ro" )
      RUNNER_ARGS+=( "--cases=${cases_container}" )
      shift
      ;;

    *)
      RUNNER_ARGS+=( "${token}" )
      shift
      ;;
  esac
done

run_debug_runner() {
  local -a extra=("$@")
  local -a cmd=(
    docker compose -f "${COMPOSE_FILE}" run --rm
    "${MOUNTS[@]}"
    debug
    python3 /app/skills/_scripts/debug_runner.py
    --project /work/project
    --out /work/out
    "${extra[@]}"
  )
  "${cmd[@]}"
}

if [[ -z "${AI_MODEL}" ]]; then
  if [[ -n "${AI_CONFIRM_MODEL:-}" ]]; then
    AI_MODEL="${AI_CONFIRM_MODEL}"
  elif [[ -n "${AI_AUDIT_MODEL:-}" ]]; then
    AI_MODEL="${AI_AUDIT_MODEL}"
  else
    AI_MODEL="sonnet"
  fi
fi

echo "[INFO] Project: ${PROJECT_HOST}" >&2
echo "[INFO] Output: ${OUT_HOST}" >&2

if [[ "${AI_REALTIME}" -eq 1 ]]; then
  echo "[INFO] Preparing AI debug context in container..."
  if [[ ${#RUNNER_ARGS[@]} -gt 0 ]]; then
    run_debug_runner "${RUNNER_ARGS[@]}" --prepare-ai-context-only
  else
    run_debug_runner --prepare-ai-context-only
  fi

  AI_STATUS="failed"
  export AI_CONFIRM_MODEL="${AI_MODEL}"
  export AI_DEBUG_ROUNDS="${AI_ROUNDS}"
  export AI_DEBUG_CANDIDATES_PER_ROUND="${AI_CANDIDATES_PER_ROUND}"
  export AI_DEBUG_TIMEOUT="${AI_TIMEOUT}"

  MCP_CONFIG="${REPO_ROOT}/skills/_scripts/mcp_config.debug.json"
  SUGGESTIONS_HOST="${OUT_HOST}/mcp_raw/ai-confirm-mcp-debug.json"

  echo "[INFO] Running host-side realtime AI suggestions..."
  set +e
  python3 "${REPO_ROOT}/skills/_scripts/mcp_adapter.py" \
    --project "${PROJECT_HOST}" \
    --out "${OUT_HOST}" \
    --tool ai-confirm-debug-mcp \
    --config "${MCP_CONFIG}"
  MCP_RC=$?
  set -e

  if [[ ${MCP_RC} -eq 0 && -f "${SUGGESTIONS_HOST}" ]]; then
    AI_STATUS="ok"
  else
    AI_STATUS="failed"
    echo "[WARN] Realtime AI failed or missing suggestions; falling back to dictionary-only result." >&2
  fi

  FINAL_ARGS=()
  if [[ ${#RUNNER_ARGS[@]} -gt 0 ]]; then
    FINAL_ARGS+=( "${RUNNER_ARGS[@]}" )
  fi
  FINAL_ARGS+=(
    --ai-realtime
    --ai-model "${AI_MODEL}"
    --ai-rounds "${AI_ROUNDS}"
    --ai-candidates-per-round "${AI_CANDIDATES_PER_ROUND}"
    --ai-timeout "${AI_TIMEOUT}"
    --ai-runtime-status "${AI_STATUS}"
  )

  if [[ -f "${SUGGESTIONS_HOST}" ]]; then
    FINAL_ARGS+=( --ai-suggestions /work/out/mcp_raw/ai-confirm-mcp-debug.json )
  fi

  echo "[INFO] Running debug verification in container..."
  run_debug_runner "${FINAL_ARGS[@]}"
else
  echo "[INFO] Running debug verification (AI realtime disabled)..."
  if [[ ${#RUNNER_ARGS[@]} -gt 0 ]]; then
    run_debug_runner \
      "${RUNNER_ARGS[@]}" \
      --disable-ai-realtime \
      --ai-model "${AI_MODEL}" \
      --ai-rounds "${AI_ROUNDS}" \
      --ai-candidates-per-round "${AI_CANDIDATES_PER_ROUND}" \
      --ai-timeout "${AI_TIMEOUT}" \
      --ai-runtime-status "disabled"
  else
    run_debug_runner \
      --disable-ai-realtime \
      --ai-model "${AI_MODEL}" \
      --ai-rounds "${AI_ROUNDS}" \
      --ai-candidates-per-round "${AI_CANDIDATES_PER_ROUND}" \
      --ai-timeout "${AI_TIMEOUT}" \
      --ai-runtime-status "disabled"
  fi
fi
