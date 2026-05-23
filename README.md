# Kryptos K4 Research CLI

`kryptos-k4` is a Rust CLI for source-grounded Kryptos K4 research. It preserves the public K4 ciphertext, known public anchors, source provenance, and repeatable constraint analyses without using leaked or archive-discovered plaintext.

This project is not a claimed K4 solution.

## Features

- Built-in K4 ciphertext and known public anchors.
- 0-based and 1-based anchor positions.
- Source-provenance records for public facts.
- Standard A-Z, Kryptos, and reversed Kryptos alphabet analysis.
- Additive, subtractive, and Beaufort-style anchor-derived fragments.
- Proposed key-material checks, explanations, and descriptive match-pattern metrics against public span-derived additive fragments.
- Gromark-style recurrence screening over known-anchor fragments.
- Seeded baseline controls, pre-registered contextual candidates, and bounded route screens.
- Findings ledger tying observations to sources, transformations, baselines, interpretation, and next tests.
- Ranked hypothesis register from the research plan.
- Markdown and JSON reports.
- CLI E2E tests and local release checks.

## Usage

```bash
cargo run -- facts
cargo run -- anchors
cargo run -- constraints
cargo run -- constraints --spans
cargo run -- key-fragments --span BERLINCLOCK --alphabet kryptos --mode additive-key
cargo run -- test-key --material BERLINWORLDCLOCK
cargo run -- test-key --material WELTZEITUHR
cargo run -- test-key --material ALEXANDERPLATZ --format json
cargo run -- test-key --material BERLINWORLDCLOCK --sweep-offsets --top 5
cargo run -- test-key --material BERLINWORLDCLOCK --sweep-offsets --sweep-baseline-iterations 1000 --seed 42
cargo run -- explain-key --material WELTZEITUHR --transform a1-z26-one-based --offset 5
cargo run -- batch-test-keys --input experiments/k4-candidates.csv --sweep-baseline-iterations 1000 --batch-baseline-iterations 1000 --seed 42 --output-dir results/key-tests/latest
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --top 20
cargo run -- baseline --target spans --iterations 1000 --seed 42
cargo run -- baseline --target spans --iterations 1000 --seed 42 --format json
cargo run -- candidate-sequences
cargo run -- candidate-sequences --format json
cargo run -- routes
cargo run -- routes --format json
cargo run -- findings
cargo run -- findings --format json
cargo run -- release-check
cargo run -- hypotheses
cargo run -- sources
cargo run -- export-data --directory data
cargo run -- report --format markdown --output notes/k4-report.md
cargo run -- report --format json
```

## Background Batch Runs

Run a long batch once without tying up the terminal:

```bash
scripts/start-key-batch-loop.sh --iterations 100000 --runs 1 --keep-awake
tail -f results/key-tests/batch-loop.log
cat results/key-tests/latest-summary.md
```

Run repeated batches until stopped:

```bash
scripts/start-key-batch-loop.sh --iterations 100000 --continuous --interval-seconds 300 --keep-awake
scripts/stop-key-batch-loop.sh
```

Use a custom candidate file or result directory when you want a separate experiment lane:

```bash
scripts/start-key-batch-loop.sh \
  --input experiments/k4-candidates.csv \
  --out-root results/key-tests/berlin-clock \
  --iterations 100000 \
  --batch-baseline-iterations 1000 \
  --continuous \
  --interval-seconds 300
scripts/stop-key-batch-loop.sh --out-root results/key-tests/berlin-clock
```

The loop writes timestamped folders under `results/key-tests/`, updates `results/key-tests/latest`, and copies the newest ranked table to `results/key-tests/latest-summary.md`. The `results/` tree is ignored by git. These background runs automate scoring and baseline checks over registered candidates; they do not claim or guarantee a K4 solution.

Summarize a completed lane:

```bash
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --top 20
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --format json
```

## Commands

| Command | Output |
| --- | --- |
| `facts` | K4 ciphertext length, ciphertext, and evidence boundary. |
| `anchors` | Public known-plaintext anchors with 0-based and 1-based positions plus source IDs. |
| `constraints` | Anchor-derived fragments for supported alphabets. |
| `constraints --spans` | Adjacent public clues merged into known-plaintext spans before screening. |
| `key-fragments` | Raw derived key-fragment rows with anchor/span/alphabet/mode filters. |
| `test-key` | Proposed key material transformed and compared against public span additive fragments at true K4 positions, with optional cyclic offset sweep and seeded sweep baseline. |
| `explain-key` | Exact matching public-span positions for one key-material lead, including one-based modulo caveats and descriptive pattern metrics when relevant. |
| `batch-test-keys` | CSV-driven key-material batch runner with ranked Markdown/JSON summaries, optional output artifacts, pattern metrics, and optional batch-level best-of-candidate-file null controls. |
| `summarize-key-runs` | Historical scanner for batch result folders, ranking individual runs and per-candidate p-value stability. |
| `baseline` | Seeded false-positive controls for the generic recurrence screen. |
| `candidate-sequences` | Pre-registered Berlin/compass/Egypt/Berlin Wall candidate material. |
| `routes` | Small named route/permutation screens with fixed baselines. |
| `findings` | Findings ledger with evidence inputs, transformations, baselines, interpretation, and next tests. |
| `release-check` | Local release preflight confirming no hosted automation, required docs, generated report presence, and plaintext-leakage sentinel absence. |
| `hypotheses` | Ranked source-grounded hypothesis register. |
| `sources` | Source provenance records. |
| `export-data` | Machine-readable JSON for ciphertext, anchors, and sources. |
| `report` | Full Markdown or JSON report. |

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

The supported Rust toolchain is pinned in `rust-toolchain.toml`; the crate declares MSRV `1.95`.

## Install / Release

```bash
cargo install --path .
kryptos-k4 --help
```

Releases are manual. Run the local verification gate, build the release binary, then create a GitHub release with the `gh` CLI. Do not use GitHub Actions for this repo.

```bash
VERSION=v0.1.0
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked --release
cargo run --locked -- release-check
target/release/kryptos-k4 --help
git tag v0.1.0
git push origin v0.1.0
gh release create "$VERSION" target/release/kryptos-k4 README.md LICENSE --title "$VERSION" --notes "Initial public Kryptos K4 research CLI release."
```

## Evidence Boundary

Allowed:

- CIA pages.
- Public Sanborn statements and reputable reporting.
- Academic cryptanalysis.
- Publicly released anchor words.

Excluded:

- Claimed full K4 plaintexts.
- Leaked or archive-discovered plaintext content.
- Paid/private archive material.
- Community claims used as proof.

See [docs/research-method.md](docs/research-method.md) and [kryptos-k4-research-plan.md](kryptos-k4-research-plan.md).
Implementation diagrams are tracked in [docs/architecture-current.md](docs/architecture-current.md) and [docs/architecture-production-goal.md](docs/architecture-production-goal.md).
