#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/start-key-batch-loop.sh [options]

Starts the batch key-material experiment loop in the background.

Options:
  --input PATH              Candidate CSV input. Default: experiments/k4-candidates.csv
  --out-root DIR            Result root directory. Default: results/key-tests
  --iterations N            Sweep baseline iterations per candidate. Default: 10000
  --seed-start N            First deterministic seed. Default: 42
  --runs N                  Number of batches to run. Use 0 for continuous. Default: 1
  --continuous              Alias for --runs 0
  --interval-seconds N      Sleep between batches. Default: 0
  --binary PATH             Release binary path. Default: ./target/release/kryptos-k4
  --keep-awake              On macOS, keep the machine awake while the loop runs.
  -h, --help                Show this help.

Environment variable fallbacks are also supported by run-key-batch-loop.sh.
EOF
}

out_root="${OUT_ROOT:-results/key-tests}"
keep_awake="0"
run_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-root)
      out_root="$2"
      run_args+=("$1" "$2")
      shift 2
      ;;
    --keep-awake)
      keep_awake="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --input|--iterations|--seed-start|--runs|--interval-seconds|--binary)
      run_args+=("$1" "$2")
      shift 2
      ;;
    --continuous)
      run_args+=("$1")
      shift
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
log_file="$out_root/batch-loop.log"

mkdir -p "$out_root"

if [[ -f "$pid_file" ]]; then
  existing_pid="$(cat "$pid_file")"
  if kill -0 "$existing_pid" 2>/dev/null; then
    echo "Batch key-material loop is already running with PID $existing_pid"
    exit 0
  fi
fi

nohup scripts/run-key-batch-loop.sh "${run_args[@]}" >"$log_file" 2>&1 &
pid="$!"
echo "$pid" >"$pid_file"

if [[ "$keep_awake" == "1" ]]; then
  if command -v caffeinate >/dev/null 2>&1; then
    caffeinate -dimsu -w "$pid" >/dev/null 2>&1 &
    echo "$!" >"$caffeinate_pid_file"
  else
    echo "Warning: --keep-awake requested, but caffeinate is not available." >&2
  fi
fi

echo "Started batch key-material loop with PID $pid"
echo "Log: $log_file"
echo "Latest summary: $out_root/latest-summary.md"
if [[ "$keep_awake" == "1" && -f "$caffeinate_pid_file" ]]; then
  echo "Keep-awake PID: $(cat "$caffeinate_pid_file")"
fi
