# Research Method

The project follows the source-led plan in `kryptos-k4-research-plan.md`.

## Operating Rules

1. Preserve strict source provenance for all facts.
2. Separate public facts from assumptions and hypotheses.
3. Treat the 2025 archive/plaintext discovery as historical context only.
4. Do not include claimed full plaintext content.
5. Promote a hypothesis only when it produces a falsifiable next test.

## Current Implementation Boundary

The CLI implements the first production slice:

- canonical public data;
- machine-readable exports for ciphertext, anchors, and source provenance;
- source IDs, confidence labels, and allowed-use notes for public facts;
- anchor normalization;
- alphabet-specific constraint extraction;
- adjacent-span analysis and generic mod-10 recurrence screening with random-baseline warnings;
- seeded null-distribution baselines with add-one empirical p-values and Holm adjustment;
- targeted raw key-fragment filtering by anchor/span, alphabet, and derivation mode;
- pre-registered contextual candidate sequences for H4/H5;
- bounded named route/permutation screens for H3;
- ranked hypothesis reporting;
- Markdown/JSON output.

It does not attempt unconstrained key search or claim decryption.

## E2E Coverage

The integration tests in `tests/cli_e2e.rs` execute the compiled CLI and verify:

- anchor output includes known public anchors and positions;
- constraint output includes alphabet-specific fragments and recurrence warnings;
- Markdown report generation writes a complete report;
- JSON report output is parseable and includes the expected top-level sections;
- source-provenance fields remain attached to anchor and source output.
- key-fragment filters are mutually exclusive for anchors/spans and fail clearly on empty results;
- baseline output is deterministic for a fixed seed and includes p-value fields without promoting candidates.
- candidate-sequence output includes family, source IDs, transform metadata, and no promoted candidates;
- route output uses only small named route families and emits no plaintext guesses.

## Release Gate

Production release tags require local verification first. This repo intentionally does not use GitHub Actions. Before creating a tag or GitHub Release, run:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked --release
target/release/kryptos-k4 --help
```

Then create the tag and release manually with `git` and `gh release create`.
