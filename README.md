# Kryptos K4 Research CLI

`kryptos-k4` is a Rust CLI for source-grounded Kryptos K4 research. It preserves the public K4 ciphertext, known public anchors, source provenance, and repeatable constraint analyses without using leaked or archive-discovered plaintext.

This project is not a claimed K4 solution.

## Features

- Built-in K4 ciphertext and known public anchors.
- 0-based and 1-based anchor positions.
- Source-provenance records for public facts.
- Standard A-Z, Kryptos, and reversed Kryptos alphabet analysis.
- Additive, subtractive, and Beaufort-style anchor-derived fragments.
- Gromark-style recurrence screening over known-anchor fragments.
- Ranked hypothesis register from the research plan.
- Markdown and JSON reports.
- CLI E2E tests and CI workflow.

## Usage

```bash
cargo run -- anchors
cargo run -- constraints
cargo run -- hypotheses
cargo run -- export-data --directory data
cargo run -- report --format markdown --output notes/k4-report.md
cargo run -- report --format json
```

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
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
