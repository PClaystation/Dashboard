#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERN="$ROOT_DIR/server.js"

find_pids() {
  pgrep -f "$PATTERN" || true
}

stop_backend() {
  local pids
  pids="$(find_pids)"

  if [[ -z "$pids" ]]; then
    echo "Backend is not running."
    return 0
  fi

  echo "Stopping backend: $pids"
  kill $pids
}

status_backend() {
  if pgrep -af "$PATTERN" >/dev/null; then
    pgrep -af "$PATTERN"
  else
    echo "Backend is not running."
  fi
}

start_backend() {
  cd "$ROOT_DIR"
  exec npm run dev
}

case "${1:-restart}" in
  stop)
    stop_backend
    ;;
  status)
    status_backend
    ;;
  restart)
    stop_backend
    sleep 1
    start_backend
    ;;
  *)
    echo "Usage: $0 [stop|status|restart]"
    exit 1
    ;;
esac
