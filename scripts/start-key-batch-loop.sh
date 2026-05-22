#!/usr/bin/env bash
set -euo pipefail

out_root="${OUT_ROOT:-results/key-tests}"
pid_file="$out_root/batch-loop.pid"
log_file="$out_root/batch-loop.log"

mkdir -p "$out_root"

if [[ -f "$pid_file" ]]; then
  existing_pid="$(cat "$pid_file")"
  if kill -0 "$existing_pid" 2>/dev/null; then
    echo "Batch key-material loop is already running with PID $existing_pid"
    exit 0
  fi
fi

nohup scripts/run-key-batch-loop.sh >"$log_file" 2>&1 &
pid="$!"
echo "$pid" >"$pid_file"

echo "Started batch key-material loop with PID $pid"
echo "Log: $log_file"
echo "Latest summary: $out_root/latest-summary.md"
