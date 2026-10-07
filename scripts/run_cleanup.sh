#!/usr/bin/env bash
set -euo pipefail

ROOT="${HOME}/StorageCleanupAgent"
SCRIPTS="${ROOT}/scripts"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
STATE_FILE="${ROOT}/reports/live_state.json"
LOG_DIR="${ROOT}/logs"
LAUNCHER_LOG="${LOG_DIR}/launcher_${RUN_ID}.log"

mkdir -p "${LOG_DIR}" "${ROOT}/reports" "${ROOT}/quarantine" "${ROOT}/manifests"

export PYTHONUNBUFFERED=1
export STORAGE_CLEANUP_RUN_ID="${RUN_ID}"
export STORAGE_CLEANUP_STATE_FILE="${STATE_FILE}"
export STORAGE_CLEANUP_ROOT="${ROOT}"

DASHBOARD_PID=""

cleanup() {
  if [[ -n "${DASHBOARD_PID}" ]] && kill -0 "${DASHBOARD_PID}" 2>/dev/null; then
    kill "${DASHBOARD_PID}" 2>/dev/null || true
    wait "${DASHBOARD_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

python3 "${SCRIPTS}/dashboard.py" \
  --state-file "${STATE_FILE}" \
  --refresh-seconds 2 \
  --hold-seconds 30 &
DASHBOARD_PID=$!

nice -n 10 python3 "${SCRIPTS}/storage_cleanup_agent.py" \
  --root "${ROOT}" \
  --run-id "${RUN_ID}" \
  --state-file "${STATE_FILE}"
