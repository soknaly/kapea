#!/usr/bin/env bash
# Local single-file scan wrapper.
# pnpm may forward a leading "--"; strip it so clap still sees real flags.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == "--" ]]; then
  shift
fi

# Prefer repo-local tools (tools/bin) when present.
if [[ -z "${UNRAR_PATH:-}" && -x "$ROOT/tools/bin/unrar" ]]; then
  export UNRAR_PATH="$ROOT/tools/bin/unrar"
fi
if [[ -z "${SEVEN_Z_PATH:-}" && -x "$ROOT/tools/bin/7z" ]]; then
  export SEVEN_Z_PATH="$ROOT/tools/bin/7z"
fi

exec cargo run --manifest-path "$ROOT/rust/Cargo.toml" -p kapea-scan-worker --quiet -- "$@"
