#!/usr/bin/env bash
# Bring up KAPEA as one system.
#
# Default: hybrid — Docker for postgres/redis/minio/clamav; Nest + Rust locally.
# Full Compose: MODE=compose pnpm stack:up
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/infrastructure/docker/docker-compose.yml")
API_URL="${API_URL:-http://localhost:3000}"
MODE="${MODE:-hybrid}"
SKIP_E2E="${SKIP_E2E:-0}"
WAIT_SECONDS="${WAIT_SECONDS:-600}"
STACK_DIR="$ROOT/.tmp/stack"
PID_FILE="$STACK_DIR/pids"

log() { printf '[stack] %s\n' "$*"; }
err() { printf '[stack] ERROR: %s\n' "$*" >&2; }

ensure_env() {
  if [[ ! -f "$ROOT/.env" ]]; then
    log "No .env found — copying .env.example"
    cp "$ROOT/.env.example" "$ROOT/.env"
  fi
  # Prefer repo .env over stale shell exports (e.g. old DATABASE_URL after renames).
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
}

wait_http() {
  local url="$1"
  local label="$2"
  local started=$SECONDS
  until curl -sf "$url" 2>/dev/null | grep -q '"status"'; do
    if (( SECONDS - started >= WAIT_SECONDS )); then
      err "$label did not become healthy ($url)"
      return 1
    fi
    sleep 3
  done
  log "$label is healthy"
}

wait_compose_healthy() {
  local service="$1"
  local started=$SECONDS
  while true; do
    local status
    status="$("${COMPOSE[@]}" ps --format json "$service" 2>/dev/null | head -1 || true)"
    if echo "$status" | grep -q '"Health":"healthy"'; then
      log "$service is healthy"
      return 0
    fi
    # Services without healthchecks
    if "${COMPOSE[@]}" ps "$service" 2>/dev/null | grep -q 'Up'; then
      if [[ "$service" == "minio-init" ]]; then
        return 0
      fi
    fi
    if (( SECONDS - started >= WAIT_SECONDS )); then
      err "$service not healthy in time"
      "${COMPOSE[@]}" ps
      "${COMPOSE[@]}" logs --tail=40 "$service" || true
      return 1
    fi
    sleep 5
  done
}

stop_local_apps() {
  if [[ -f "$PID_FILE" ]]; then
    log "Stopping local stack processes..."
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
      fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  fi
  # Child processes (nest/cargo/worker) may outlive the shell wrappers
  pkill -f "nest start" 2>/dev/null || true
  pkill -f "run-scan-worker.sh" 2>/dev/null || true
  pkill -f "target/debug/scan-worker" 2>/dev/null || true
  pkill -f "target/release/scan-worker" 2>/dev/null || true
  pkill -f "cargo run -p kapea-scan-worker" 2>/dev/null || true
}

start_local_apps() {
  mkdir -p "$STACK_DIR"
  stop_local_apps

  export DATABASE_URL="${DATABASE_URL:-postgresql://kapea:kapea@localhost:5432/kapea}"
  export REDIS_URL="${REDIS_URL:-redis://localhost:6379}"
  export S3_ENDPOINT="${S3_ENDPOINT:-http://localhost:9000}"
  export CLAMAV_HOST="${CLAMAV_HOST:-localhost}"
  export CLAMAV_PORT="${CLAMAV_PORT:-3310}"
  export YARA_RULES_PATH="${YARA_RULES_PATH:-$ROOT/infrastructure/yara/rules}"
  export WORK_DIR="${WORK_DIR:-$ROOT/.tmp/kapea-work}"
  export STORAGE_PROVIDER="${STORAGE_PROVIDER:-minio}"
  export RUN_MIGRATIONS="${RUN_MIGRATIONS:-false}"

  # If preferred port is occupied by a non-KAPEA process, move to 3010.
  # Check IPv4 and localhost (macOS often has another app on [::1]:3000 only).
  local preferred="${API_PORT:-3000}"
  if curl -sf --max-time 1 "http://127.0.0.1:${preferred}/health/live" 2>/dev/null | grep -q '"status"'; then
    : # KAPEA already running on preferred port — reuse it
  elif (echo >"/dev/tcp/127.0.0.1/${preferred}") >/dev/null 2>&1 \
    || curl -sf --max-time 1 "http://127.0.0.1:${preferred}/" >/dev/null 2>&1 \
    || curl -sf --max-time 1 "http://localhost:${preferred}/" >/dev/null 2>&1; then
    preferred=3010
    log "Port ${API_PORT:-3000} is in use by another app — binding API to :3010"
  fi
  export API_PORT="$preferred"
  export API_HOST="${API_HOST:-127.0.0.1}"
  API_URL="http://127.0.0.1:${API_PORT}"
  export API_URL
  mkdir -p "$WORK_DIR"

  if [[ -z "${UNRAR_PATH:-}" && -x "$ROOT/tools/bin/unrar" ]]; then
    export UNRAR_PATH="$ROOT/tools/bin/unrar"
  fi
  if [[ -z "${SEVEN_Z_PATH:-}" && -x "$ROOT/tools/bin/7z" ]]; then
    export SEVEN_Z_PATH="$ROOT/tools/bin/7z"
  fi

  log "Generating Prisma client + applying migrations..."
  pnpm --filter @kapea/database prisma:generate
  pnpm --filter @kapea/database prisma:deploy

  log "Starting API..."
  : >"$PID_FILE"
  nohup pnpm --filter @kapea/api start:dev \
    >"$STACK_DIR/api.log" 2>&1 &
  echo $! >>"$PID_FILE"
  disown || true

  log "Starting result-consumer..."
  nohup pnpm --filter @kapea/result-consumer start:dev \
    >"$STACK_DIR/result-consumer.log" 2>&1 &
  echo $! >>"$PID_FILE"
  disown || true

  log "Starting scan-worker in Docker (restart: unless-stopped)..."
  # Prefer containerized worker so it survives shell/agent teardown and is
  # auto-restarted by Docker. Falls back to supervised local binary if build fails.
  if "${COMPOSE[@]}" --env-file "$ROOT/.env" up -d --build scan-worker; then
    local worker_wait=$SECONDS
    until "${COMPOSE[@]}" ps scan-worker 2>/dev/null | grep -q 'Up'; do
      if (( SECONDS - worker_wait >= 180 )); then
        err "docker scan-worker did not start"
        "${COMPOSE[@]}" logs --tail=40 scan-worker || true
        return 1
      fi
      sleep 2
    done
    log "scan-worker is running in Docker"
  else
    log "Docker scan-worker failed — falling back to supervised local binary"
    local worker_env=(
      "S3_ACCESS_KEY=${S3_ACCESS_KEY:-minioadmin}"
      "S3_SECRET_KEY=${S3_SECRET_KEY:-minioadmin}"
      "S3_BUCKET=${S3_BUCKET:-quarantine}"
      "S3_REGION=${S3_REGION:-us-east-1}"
      "S3_ENDPOINT=${S3_ENDPOINT}"
      "REDIS_URL=${REDIS_URL}"
      "CLAMAV_HOST=${CLAMAV_HOST}"
      "CLAMAV_PORT=${CLAMAV_PORT}"
      "YARA_RULES_PATH=${YARA_RULES_PATH}"
      "WORK_DIR=${WORK_DIR}"
      "STORAGE_PROVIDER=${STORAGE_PROVIDER}"
      "SCAN_WORKER_CONCURRENCY=${SCAN_WORKER_CONCURRENCY:-2}"
    )
    [[ -n "${UNRAR_PATH:-}" ]] && worker_env+=("UNRAR_PATH=${UNRAR_PATH}")
    [[ -n "${SEVEN_Z_PATH:-}" ]] && worker_env+=("SEVEN_Z_PATH=${SEVEN_Z_PATH}")
    if [[ ! -x "$ROOT/rust/target/debug/scan-worker" ]]; then
      log "Building scan-worker binary..."
      (cd "$ROOT/rust" && cargo build -p kapea-scan-worker)
    fi
    nohup env "${worker_env[@]}" \
      bash "$ROOT/scripts/run-scan-worker.sh" \
      >"$STACK_DIR/scan-worker.log" 2>&1 &
    echo $! >>"$PID_FILE"
    disown || true
    local worker_wait=$SECONDS
    until pgrep -f 'target/debug/scan-worker' >/dev/null 2>&1; do
      if (( SECONDS - worker_wait >= 60 )); then
        err "scan-worker did not start"
        tail -n 40 "$STACK_DIR/scan-worker.log" || true
        return 1
      fi
      sleep 1
    done
    log "scan-worker is running (supervised local)"
  fi

  wait_http "$API_URL/health/live" "API"
  wait_http "http://127.0.0.1:${RESULT_CONSUMER_PORT:-3001}/health/live" "result-consumer"

}

bring_up_infra() {
  log "Starting infrastructure containers (postgres redis minio clamav)..."
  "${COMPOSE[@]}" up -d postgres redis minio minio-init clamav
  wait_compose_healthy postgres
  wait_compose_healthy redis
  wait_compose_healthy minio
  # minio-init is a one-shot
  local started=$SECONDS
  until "${COMPOSE[@]}" ps minio-init 2>/dev/null | grep -Eqi 'exited \(0\)|Exit 0|complete'; do
    if (( SECONDS - started >= 120 )); then
      log "minio-init wait timed out — continuing (bucket may already exist)"
      break
    fi
    sleep 2
  done
  wait_compose_healthy clamav
}

bring_up_compose() {
  log "Building and starting full Compose stack (MODE=compose)..."
  "${COMPOSE[@]}" up -d --build
  wait_http "$API_URL/health/live" "API"

  local started=$SECONDS
  until "${COMPOSE[@]}" ps scan-worker 2>/dev/null | grep -q 'Up'; do
    if (( SECONDS - started >= WAIT_SECONDS )); then
      err "scan-worker did not start"
      "${COMPOSE[@]}" ps
      "${COMPOSE[@]}" logs --tail=80 clamav scan-worker || true
      exit 1
    fi
    sleep 5
  done
  log "scan-worker is running"
}

print_urls() {
  log "Stack is up ($MODE)."
  log "  API:      $API_URL"
  log "  Swagger:  $API_URL/api/docs"
  log "  MinIO:    http://localhost:9001  (minioadmin / minioadmin)"
  if [[ "$MODE" == "compose" ]]; then
    log "  Grafana:  http://localhost:3301  (admin / admin)"
  else
    log "  Logs:     $STACK_DIR/*.log"
    log "  Stop apps: pnpm stack:down"
  fi
}

main() {
  ensure_env
  case "$MODE" in
    hybrid)
      bring_up_infra
      start_local_apps
      ;;
    compose)
      bring_up_compose
      ;;
    *)
      err "Unknown MODE=$MODE (use hybrid|compose)"
      exit 1
      ;;
  esac

  if [[ "$SKIP_E2E" != "1" ]]; then
    log "Running e2e smoke tests..."
    STRICT=1 API_URL="$API_URL" bash "$ROOT/scripts/e2e-smoke.sh"
  else
    log "Skipping e2e (SKIP_E2E=1). Run: pnpm e2e"
  fi

  print_urls
}

main "$@"
