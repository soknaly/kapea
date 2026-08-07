#!/usr/bin/env bash
# Stop hybrid local apps and optionally tear down Compose.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/infrastructure/docker/docker-compose.yml")
STACK_DIR="$ROOT/.tmp/stack"
PID_FILE="$STACK_DIR/pids"
FULL="${FULL:-0}"

log() { printf '[stack] %s\n' "$*"; }

if [[ -f "$PID_FILE" ]]; then
  log "Stopping local stack processes..."
  while read -r pid; do
    [[ -z "$pid" ]] && continue
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done < "$PID_FILE"
  # Child processes (nest/cargo/worker) may outlive the shell wrappers
  pkill -f "nest start" 2>/dev/null || true
  pkill -f "run-scan-worker.sh" 2>/dev/null || true
  pkill -f "target/debug/scan-worker" 2>/dev/null || true
  pkill -f "target/release/scan-worker" 2>/dev/null || true
  pkill -f "kapea-scan-worker" 2>/dev/null || true
  pkill -f "cargo run -p kapea-scan-worker" 2>/dev/null || true
  rm -f "$PID_FILE"
  log "Local apps stopped"
else
  log "No local PID file — nothing to stop locally"
fi

if [[ "$FULL" == "1" ]]; then
  log "Tearing down Docker Compose..."
  "${COMPOSE[@]}" down
fi
