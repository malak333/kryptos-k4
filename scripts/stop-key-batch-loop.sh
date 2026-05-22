#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/stop-key-batch-loop.sh [options]

Stops a background batch key-material experiment loop.

Options:
  --out-root DIR    Result root directory. Default: results/key-tests
  -h, --help        Show this help.
EOF
}

out_root="${OUT_ROOT:-results/key-tests}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-root)
      out_root="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

pid_file="$out_root/batch-loop.pid"
caffeinate_pid_file="$out_root/batch-loop.caffeinate.pid"

if [[ ! -f "$pid_file" ]]; then
  echo "No batch key-material loop PID file found at $pid_file"
  exit 0
fi

pid="$(cat "$pid_file")"
if kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  echo "Stopped batch key-material loop with PID $pid"
else
  echo "Batch key-material loop PID $pid is not running"
fi

rm -f "$pid_file"

if [[ -f "$caffeinate_pid_file" ]]; then
  caffeinate_pid="$(cat "$caffeinate_pid_file")"
  if kill -0 "$caffeinate_pid" 2>/dev/null; then
    kill "$caffeinate_pid"
    echo "Stopped keep-awake process with PID $caffeinate_pid"
  fi
  rm -f "$caffeinate_pid_file"
fi
