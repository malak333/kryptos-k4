# Research Method

The project follows the source-led plan in `kryptos-k4-research-plan.md`.

## Operating Rules

1. Preserve strict source provenance for all facts.
2. Separate public facts from assumptions and hypotheses.
3. Treat archive/plaintext discovery and community archive-research notes as
   historical context only unless a separate preregistration defines an
   independent evaluation target first.
4. Do not include claimed full plaintext content.
5. Promote a hypothesis only when it produces a falsifiable next test.

## Current Implementation Boundary

The CLI implements the first production slice:

- canonical public data;
- machine-readable exports for ciphertext, anchors, and source provenance;
- source IDs, confidence labels, and allowed-use notes for public facts;
- a source packet with exact URLs, access dates, allowed-use boundaries, and quote-free summaries;
- anchor normalization;
- alphabet-specific constraint extraction;
- adjacent-span analysis and generic mod-10 recurrence screening with random-baseline warnings;
- candidate-independent residue/spacing structure controls over fixed public-fragment positions;
- pre-registered structural model controls that evaluate fixed period models before adding new key material;
- preregistration validation for any future lane that would add candidate material, transforms, routes, or structural tests;
- seeded null-distribution baselines with add-one empirical p-values and Holm adjustment;
- targeted raw key-fragment filtering by anchor/span, alphabet, and derivation mode;
- proposed key-material checks, exact match explanations, descriptive pattern metrics, composite pattern scores, cyclic offset sweeps, seeded shuffled-value sweep baselines, CSV-driven batch runs, and batch-level best-of-candidate-file null controls against public span-derived additive fragments at actual K4 positions;
- a documented candidate-material registry that ties CSV rows to source IDs and rationale before batch testing;
- pre-registered contextual candidate sequences for H4/H5;
- bounded named route/permutation screens for H3;
- ranked hypothesis reporting;
- Markdown/JSON output.
- findings ledger entries that tie each current observation to public source inputs, transformation steps, baseline context, interpretation, and a repeatable next test.

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
- test-key output compares proposed material against public spans in Markdown/JSON, ranks cyclic phase offsets when requested, attaches seeded sweep baselines when requested, and rejects material that cannot produce numeric values;
- explain-key output prints exact matching positions for one candidate/offset, includes one-based modulo caveats, descriptive pattern metrics, and composite pattern scores when relevant, and stays non-promotional;
- batch-test-keys output ranks CSV candidate rows, can attach both per-candidate sweep baselines and candidate-file-level best-score baselines for match count and composite pattern score, includes pattern metrics for each best offset, writes optional summary/results/input/command artifacts, and keeps every row non-promotional;
- summarize-key-runs scans completed batch result folders, ranks individual rows and candidate stability, and keeps repeated low p-values scoped as follow-up leads rather than solution evidence;
- position-structure output compares observed public-fragment residue/spacing scores against seeded shuffles without using candidate key material;
- structural-models output evaluates a fixed registry of period models with seeded nulls and Holm adjustment before any candidate-word expansion;
- validate-preregistration rejects new lanes that reuse public anchor-derived fragments as discovery inputs or primary evidence;
- period-prediction-plan emits predeclared non-anchor residue-class targets from K4 positions only, without scoring public fragment values or candidate material;
- experiments/PROGRESS_LOG.md records command-backed negative controls and active gates so weak lanes are not repeatedly rerun as evidence;
- candidate-sequence output includes family, source IDs, transform metadata, and no promoted candidates;
- route output uses only small named route families and emits no plaintext guesses.
- findings output includes evidence inputs, baseline comparison, next-test fields, and non-promotion flags in Markdown and JSON.

## Release Gate

Production release tags require local verification first. This repo intentionally does not use GitHub Actions. Before creating a tag or GitHub Release, run:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked --release
cargo run --locked -- release-check
target/release/kryptos-k4 --help
```

Then create the tag and release manually with `git` and `gh release create`.

The `release-check` command verifies the no-Actions/no-Dependabot policy, required release docs, generated Markdown report presence, candidate CSV/registry alignment, source-packet/source-registry field alignment, latest source access-date metadata, and absence of explicit leaked/full-plaintext sentinel markers before release.

The source packet and `src/data.rs` source registry must stay aligned. Archive-sale reporting and community archive-research pages are historical or preregistration context only; they must not introduce archive-discovered plaintext, private auction material, or unregistered community interpretations into the data model, reports, exports, or tests.

The candidate CSV and candidate registry must also stay aligned. Candidate words
remain stopped-lane exploratory inputs unless they are represented in
`experiments/k4-candidates.md` with registered source IDs and rationale, then
survive the current batch, routed, and held-out controls.
