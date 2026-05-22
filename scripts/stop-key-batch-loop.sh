#!/usr/bin/env bash
set -euo pipefail

out_root="${OUT_ROOT:-results/key-tests}"
pid_file="$out_root/batch-loop.pid"

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
