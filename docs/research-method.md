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
- preregistration validation for any future lane that would add candidate material, transforms, routes, structural tests, or independent prediction targets;
- committed non-anchor period and spacing prediction artifacts plus source-backed observation validation before any independent position evidence is scored;
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
- validate-prediction-artifact checks committed independent prediction artifacts against the deterministic generator;
- independent-lane-status summarizes preregistered lanes, artifact validity, readiness for source-backed observations, and the next validator or evaluator command;
- next-evidence-gate combines lane readiness, unique/duplicate prediction-target accounting, eligible scored-observation sources, current evidence-archive status, current source-review status, required observation fields, and the exact scaffold/validate/evaluate/archive command sequence before any future source-backed scoring is interpreted;
- independent-evidence-status scans archived period/spacing source-backed evaluation outputs and reports whether valid independent evidence is available;
- source-review-status scans saved pre-score source-review artifacts and reports whether any valid source-review file is available before observation scaffolding;
- non-anchor-positions prints the one-based K4 position universe allowed for future source-backed observation files, with excluded public anchor ranges;
- validate-period-observations and validate-spacing-observations reject unregistered source IDs, disallowed source-use boundaries, duplicate positions, public-anchor positions, and unchanged observation templates before scoring;
- period-prediction-plan emits predeclared non-anchor residue-class targets from K4 positions only, without scoring public fragment values or candidate material;
- spacing-prediction-plan emits predeclared non-anchor spacing residue targets from K4 positions only, without scoring public fragment values or candidate material;
- evaluate-period-prediction scores explicit non-anchor position inputs or source-backed observation files, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, and marks source-backed files distinctly in JSON/Markdown output;
- evaluate-spacing-prediction scores explicit non-anchor position inputs or source-backed observation files, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, and rejects undersized source-backed spacing observations before scoring;
- report --output writes the generated report through a temporary file before replacing the target path;
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

The `release-check` command verifies the no-Actions/no-Dependabot policy, required release docs, generated Markdown report presence, candidate CSV/registry alignment, committed preregistration validity, committed prediction-artifact validity, independent-lane readiness for source-backed observations, intentionally non-scorable observation-template status, findings source-input integrity, source-packet/source-registry field alignment, latest source access-date metadata, and absence of explicit leaked/full-plaintext sentinel markers before release.

The source packet and `src/data.rs` source registry must stay aligned.
Registered local source archive paths must exist, and `release-check` verifies
them before release. Archive-sale reporting and community archive-research pages
are historical or preregistration context only; they must not introduce
archive-discovered plaintext, private auction material, or unregistered
community interpretations into the data model, reports, exports, or tests.

The candidate CSV and candidate registry must also stay aligned. Candidate words
remain stopped-lane exploratory inputs unless they are represented in
`experiments/k4-candidates.md` with registered source IDs and rationale, then
survive the current batch, routed, and held-out controls.

Source-backed period and spacing observation files are stricter than general
source registration: `validate-period-observations` and
`validate-spacing-observations` reject public-anchor summary, public-clue
context, methodology context, and archive-context-only sources as scored
independent position evidence. Those sources can still document context or
controls, but not the held-out target being scored.
Run `observation-sources` before creating an observation file to see which
registered sources are eligible for scored independent position observations,
including their URLs, access dates, source types, local-archive status, and
use-boundary notes.
Run `next-evidence-gate` to see the current eligible source IDs, unique ready
prediction targets, and the exact command sequence required before a future
source-backed observation can be treated as evidence. The gate repeats eligible
source details so the source and archive boundary is visible at the point where
an observation file would be scaffolded.
Run `source-review-packet` when preparing a concrete observation pass. It
separates the pre-score source-review checklist from the scoring commands and
shows which eligible sources currently lack local archive URLs. Its observation
requirements include the validated source-review artifact that must cover every
cited observation source.
Run `source-review-status` to check whether a saved pre-score review artifact
already exists and validates. A missing default review directory or zero valid
reviews means the next step is still source review, not observation scoring.
One valid source-review file only clears the pre-score source-review gate; it
does not create evidence until a separate source-backed observation file is
validated, scored, archived, and revalidated.
Local source snapshots under `sources/archives/` are quote-free review records
for auditability; they are not raw page mirrors and do not define scored
positions.
Use `init-source-review` to materialize that pre-score review into JSON before
choosing observation positions; it rejects context-only sources, duplicate
source IDs, placeholders, and accidental overwrites.
Run `validate-source-review` before scaffolding observations from a saved review
file so edited or stale source-review artifacts cannot bypass current source
eligibility metadata.
Run `independent-evidence-status` to confirm whether any source-backed
observation evaluation archives already exist before interpreting a lane as
having evidence.
Run `non-anchor-positions` when preparing that observation file so the selected
positions come from the non-anchor universe and not from the public clue ranges.
Use `init-position-observations` to create the JSON file for a future
source-backed observation; it refuses placeholders, duplicate positions, public
anchor positions, out-of-range positions, disallowed source uses, and accidental
overwrites before the validator/evaluator commands can score the file. Scored
observation files must also include a `position_notes` entry for every
one-based position so a later archive reviewer can audit why each position was
included. When a saved source-review artifact exists, pass it with
`--source-review`; the scaffold and later validators re-run the source-review
gate and require it to cover every observation source ID.

Direct `evaluate-period-prediction --positions ...` and
`evaluate-spacing-prediction --positions ...` runs are diagnostic only. They can
check mechanics or reproduce examples, but evidence-bearing evaluation requires
`--positions-file` with registered source IDs, a matching `--preregistration`,
and a passing period or spacing observation validation result.

Run `independent-lane-status` before adding a source-backed observation file. It
must show a valid preregistration and prediction artifact for the target lane,
then follow the family-specific observation validator and evaluator named in the
status output.
Use the family summary in that output as the evidence count: duplicate period
preregistration rows that share one deterministic artifact are operational
readiness records, not separate cryptanalytic signals.

Public methodology-context sources can document why a search family is stopped
or why a null control is required. They still do not supply plaintext,
candidate rows, or scored observations.
