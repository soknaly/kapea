#!/usr/bin/env bash
# End-to-end smoke test for KAPEA (requires docker compose stack).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_URL="${API_URL:-}"
CLEAN_FIXTURE="${CLEAN_FIXTURE:-$ROOT/test-fixtures/clean/hello.txt}"
EICAR_FIXTURE="${EICAR_FIXTURE:-$ROOT/test-fixtures/eicar/eicar.com.txt}"
RAR_FIXTURE="${RAR_FIXTURE:-$ROOT/test-fixtures/archives/test2.z}"
SEVENZ_FIXTURE="${SEVENZ_FIXTURE:-$ROOT/test-fixtures/archives/test1.7z}"
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-300}"
POLL_INTERVAL="${POLL_INTERVAL:-3}"
# STRICT=1 fails if API is unreachable (used by stack-up). Default soft-skip for ad-hoc runs.
STRICT="${STRICT:-0}"

log() { printf '[e2e] %s\n' "$*"; }
warn() { printf '[e2e] WARN: %s\n' "$*" >&2; }
die() { printf '[e2e] ERROR: %s\n' "$*" >&2; exit 1; }

resolve_api_url() {
  if [[ -n "$API_URL" ]]; then
    return 0
  fi
  local candidate
  for candidate in \
    "http://127.0.0.1:3000" \
    "http://127.0.0.1:3010" \
    "http://localhost:3000" \
    "http://localhost:3010"; do
    if curl -sf --max-time 1 "$candidate/health/live" 2>/dev/null | grep -q '"status"'; then
      API_URL="$candidate"
      return 0
    fi
  done
  API_URL="http://127.0.0.1:3000"
}

wait_for_api() {
  resolve_api_url
  local attempt=0
  local max_attempts=30
  while (( attempt < max_attempts )); do
    if curl -sf "$API_URL/health/live" 2>/dev/null | grep -q '"status"'; then
      log "API is up at $API_URL"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  if [[ "$STRICT" == "1" ]]; then
    die "API not reachable at $API_URL"
  fi
  warn "API not reachable at $API_URL — skipping smoke test"
  exit 0
}

upload_file() {
  local path="$1"
  local out="/tmp/kapea-upload-$$.json"
  curl -sf -X POST "$API_URL/api/v1/files/scan" \
    -F "file=@${path}" \
    | tee "$out" >/dev/null
  UPLOAD_JSON_PATH="$out"
}

poll_scan() {
  local scan_id="$1"
  local expected_verdict="${2:-}"
  local elapsed=0

  while (( elapsed < MAX_WAIT_SECONDS )); do
    local status_json
    status_json="$(curl -sf "$API_URL/api/v1/scans/$scan_id")"
    local status
    status="$(echo "$status_json" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"

    if [[ "$status" == "COMPLETED" || "$status" == "FAILED" ]]; then
      log "Scan $scan_id finished with status=$status"
      if [[ -n "$expected_verdict" ]]; then
        local result_json verdict
        result_json="$(curl -sf "$API_URL/api/v1/scans/$scan_id/result")"
        verdict="$(echo "$result_json" | sed -n 's/.*"verdict"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
        # Some responses nest automatedVerdict; prefer explicit verdict field, then automatedVerdict.
        if [[ -z "$verdict" ]]; then
          verdict="$(echo "$result_json" | sed -n 's/.*"automatedVerdict"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
        fi
        log "Verdict=$verdict (expected $expected_verdict)"
        if [[ "$verdict" != "$expected_verdict" ]]; then
          warn "Result payload: $result_json"
          die "Unexpected verdict for $scan_id: got $verdict want $expected_verdict"
        fi
      fi
      return 0
    fi

    log "Scan $scan_id status=$status ($(printf '%ss' "$elapsed"))..."
    sleep "$POLL_INTERVAL"
    elapsed=$((elapsed + POLL_INTERVAL))
  done

  die "Timed out waiting for scan $scan_id"
}

extract_scan_id() {
  sed -n 's/.*"scanId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$UPLOAD_JSON_PATH" | head -1
}

run_case() {
  local label="$1"
  local path="$2"
  local expected="$3"

  if [[ ! -f "$path" ]]; then
    warn "Skipping $label — fixture missing: $path"
    return 0
  fi

  log "Uploading $label ($path)..."
  upload_file "$path"
  local scan_id
  scan_id="$(extract_scan_id)"
  [[ -n "$scan_id" ]] || die "No scanId in upload response for $label"
  log "$label scan id=$scan_id"
  poll_scan "$scan_id" "$expected"
}

main() {
  log "Starting KAPEA e2e smoke test"
  wait_for_api

  run_case "clean" "$CLEAN_FIXTURE" "CLEAN"
  run_case "eicar" "$EICAR_FIXTURE" "MALICIOUS"
  run_case "rar-malware" "$RAR_FIXTURE" "MALICIOUS"
  run_case "7z-malware" "$SEVENZ_FIXTURE" "MALICIOUS"

  log "Smoke test passed"
}

main "$@"
