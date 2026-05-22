#!/usr/bin/env bash
set -euo pipefail

input="${INPUT:-experiments/k4-candidates.csv}"
out_root="${OUT_ROOT:-results/key-tests}"
iterations="${ITERATIONS:-10000}"
seed_start="${SEED_START:-42}"
interval_seconds="${INTERVAL_SECONDS:-0}"
runs="${RUNS:-1}"
binary="${BINARY:-./target/release/kryptos-k4}"

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
