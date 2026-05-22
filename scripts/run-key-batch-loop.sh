#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run-key-batch-loop.sh [options]

Runs batch key-material experiments and writes timestamped result folders.

Options:
  --input PATH              Candidate CSV input. Default: experiments/k4-candidates.csv
  --out-root DIR            Result root directory. Default: results/key-tests
  --iterations N            Sweep baseline iterations per candidate. Default: 10000
  --seed-start N            First deterministic seed. Default: 42
  --runs N                  Number of batches to run. Use 0 for continuous. Default: 1
  --continuous              Alias for --runs 0
  --interval-seconds N      Sleep between batches. Default: 0
  --binary PATH             Release binary path. Default: ./target/release/kryptos-k4
  -h, --help                Show this help.

Environment variable fallbacks are also supported: INPUT, OUT_ROOT, ITERATIONS,
SEED_START, RUNS, INTERVAL_SECONDS, and BINARY.
EOF
}

require_non_negative_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer: $value" >&2
    exit 2
  fi
}

input="${INPUT:-experiments/k4-candidates.csv}"
out_root="${OUT_ROOT:-results/key-tests}"
iterations="${ITERATIONS:-10000}"
seed_start="${SEED_START:-42}"
interval_seconds="${INTERVAL_SECONDS:-0}"
runs="${RUNS:-1}"
binary="${BINARY:-./target/release/kryptos-k4}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input)
      input="$2"
      shift 2
      ;;
    --out-root)
      out_root="$2"
      shift 2
      ;;
    --iterations)
      iterations="$2"
      shift 2
      ;;
    --seed-start)
      seed_start="$2"
      shift 2
      ;;
    --runs)
      runs="$2"
      shift 2
      ;;
    --continuous)
      runs="0"
      shift
      ;;
    --interval-seconds)
      interval_seconds="$2"
      shift 2
      ;;
    --binary)
      binary="$2"
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

require_non_negative_integer "--iterations" "$iterations"
require_non_negative_integer "--seed-start" "$seed_start"
require_non_negative_integer "--runs" "$runs"
require_non_negative_integer "--interval-seconds" "$interval_seconds"

mkdir -p "$out_root"

if [[ ! -x "$binary" ]]; then
  cargo build --locked --release
fi

run_index=0
while :; do
  seed=$((seed_start + run_index))
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  output_dir="$out_root/$timestamp-seed-$seed"

  "$binary" batch-test-keys \
    --input "$input" \
    --sweep-baseline-iterations "$iterations" \
    --seed "$seed" \
    --output-dir "$output_dir"

  cp "$output_dir/summary.md" "$out_root/latest-summary.md"
  ln -sfn "$(basename "$output_dir")" "$out_root/latest"

  run_index=$((run_index + 1))
  if [[ "$runs" != "0" && "$run_index" -ge "$runs" ]]; then
    break
  fi
  sleep "$interval_seconds"
done
