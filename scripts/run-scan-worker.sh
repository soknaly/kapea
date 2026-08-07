#!/usr/bin/env bash
# Supervised KAPEA scan-worker launcher.
# Restarts the worker if it exits so BullMQ jobs never sit forever in QUEUED.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SCAN_WORKER_BIN:-$ROOT/rust/target/debug/scan-worker}"
RESTART_DELAY_SEC="${SCAN_WORKER_RESTART_DELAY_SEC:-2}"

if [[ ! -x "$BIN" ]]; then
  echo "[scan-worker] binary missing at $BIN — building..." >&2
  (cd "$ROOT/rust" && cargo build -p kapea-scan-worker) || exit 1
fi

echo "[scan-worker] supervised launcher pid=$$ bin=$BIN"

cleanup() {
  if [[ -n "${CHILD_PID:-}" ]] && kill -0 "$CHILD_PID" 2>/dev/null; then
    kill "$CHILD_PID" 2>/dev/null || true
    wait "$CHILD_PID" 2>/dev/null || true
  fi
  exit 0
}
trap cleanup INT TERM

while true; do
  echo "[scan-worker] starting $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "$BIN" &
  CHILD_PID=$!
  wait "$CHILD_PID"
  code=$?
  CHILD_PID=""
  echo "[scan-worker] exited code=${code} at $(date -u +%Y-%m-%dT%H:%M:%SZ); restarting in ${RESTART_DELAY_SEC}s" >&2
  sleep "$RESTART_DELAY_SEC"
done
