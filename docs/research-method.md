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
- committed non-anchor period, spacing, mirror, grid, Tableau/HILL, ciphertext-prior, ciphertext-hotspot, ciphertext-rarity, ciphertext-transition, ciphertext-skip-transition, ciphertext-turning-point, and ciphertext-residue-balance prediction artifacts plus source-backed observation validation before any independent position evidence is scored;
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
- validate-preregistration rejects new lanes that reuse public anchor-derived fragments as discovery inputs or primary evidence, and it requires the lane filename stem to match the preregistration `id` so copied placeholders cannot pass as real lanes;
- validate-prediction-artifact checks committed independent prediction artifacts against the deterministic generator;
- independent-lane-status summarizes preregistered lanes, artifact validity, readiness for source-backed observations, and the next validator or evaluator command;
- next-evidence-gate combines lane readiness, unique/duplicate prediction-target accounting, eligible scored-observation sources, used/unused eligible source accounting, quarantined plaintext-claim source IDs and the safe claim-verifier commands, current evidence-archive score direction, structured archive support details including null means, an all-source-backed-archives-negative flag, current source-review status, machine-readable next-action and blocking-condition fields, explicit next-check commands including the distinct-artifact `--require-unique-artifact` gate, required observation fields, a recommended next evidence step, and the exact scaffold/validate/evaluate/archive command sequence before any future source-backed scoring is interpreted;
- independent-evidence-status scans archived period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-residue-balance source-backed evaluation outputs and reports whether valid independent evidence is available, including best model, observed hits, p-value, and support status per archive;
- source-review-status scans saved pre-score source-review artifacts and reports whether any valid source-review file is available before observation scaffolding;
- source-intake-packet prints the required registry fields, source-use boundaries, quote-free local archive requirements, scoreable-evidence requirements, rejection rules, and follow-up command sequence for adding any new evidence source;
- validate-source-archive checks a quote-free local source snapshot against the registered source metadata, required archive markers, no-promotion boundary, non-scorable/scored-position consistency, and scored-position allowed-use boundary before a source archive is committed or scored;
- non-anchor-positions prints the one-based K4 position universe allowed for future source-backed observation files, with excluded public anchor ranges;
- validate-period-observations, validate-ciphertext-prior-observations, validate-ciphertext-hotspot-observations, validate-ciphertext-rarity-observations, validate-ciphertext-repeat-distance-observations, validate-ciphertext-adjacent-contrast-observations, validate-ciphertext-transition-observations, validate-ciphertext-skip-transition-observations, validate-ciphertext-turning-point-observations, validate-ciphertext-residue-balance-observations, validate-spacing-observations, validate-mirror-observations, and validate-grid-observations reject unregistered source IDs, disallowed source-use boundaries, duplicate positions, public-anchor positions, and unchanged observation templates before scoring;
- period-prediction-plan emits predeclared non-anchor residue-class targets from K4 positions only, without scoring public fragment values or candidate material; the registered period set now includes period 14 from context-only 7-by-14 layout rationale, not from scored K4 evidence;
- spacing-prediction-plan emits predeclared non-anchor spacing residue targets from K4 positions only, without scoring public fragment values or candidate material;
- mirror-prediction-plan emits a predeclared non-anchor mirror-pair target from the 97-character K4 position axis and registered physical-screen context, without scoring public fragment values or candidate material;
- grid-layout-prediction-plan emits a predeclared 7-by-14 padded grid-layout artifact from source-context layout rationale, with an explicit scored row or column edge axis, without scoring public fragment values or candidate material;
- evaluate-period-prediction scores explicit non-anchor position inputs or source-backed observation files, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, and marks source-backed files distinctly in JSON/Markdown output;
- evaluate-spacing-prediction scores explicit non-anchor position inputs or source-backed observation files, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, and rejects undersized source-backed spacing observations before scoring;
- evaluate-mirror-prediction scores explicit non-anchor position inputs or source-backed observation files against predeclared mirror pairs, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, and uses a seeded same-size non-anchor position-set null;
- evaluate-grid-prediction scores explicit non-anchor position inputs or source-backed observation files against a selected predeclared grid edge axis, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, rejects source-backed scoring when the requested `--edge-axis` does not match the preregistered `grid_edge_axis`, records the selected `--edge-axis` in archives, and uses a seeded same-size non-anchor position-set null. The committed v1 evidence axis is row; column-axis scoring is diagnostic or future-preregistered follow-up only;
- evaluate-tableau-hill-prediction scores explicit non-anchor position inputs or source-backed observation files against the committed Tableau/HILL 7-by-14 source map, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, rejects padding and public-anchor positions through the validator, and uses a seeded same-size non-anchor position-set null over best row/column concentration;
- evaluate-ciphertext-hotspot scores explicit non-anchor position inputs or source-backed observation files against the committed ciphertext-hotspot prior, marks ad hoc `--positions` input as diagnostic, requires `--preregistration` for source-backed files, and uses a seeded same-size non-anchor position-set null;
- evaluate-ciphertext-rarity, evaluate-ciphertext-transition, evaluate-ciphertext-skip-transition, evaluate-ciphertext-turning-point, and evaluate-ciphertext-residue-balance score explicit non-anchor position inputs or source-backed observation files against committed ciphertext-only artifacts, mark ad hoc `--positions` input as diagnostic, require `--preregistration` for source-backed files, and use seeded same-size non-anchor position-set null controls;
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

The `release-check` command verifies the no-Actions/no-Dependabot policy, required release docs, generated Markdown report presence, candidate CSV/registry alignment, committed preregistration validity, committed prediction-artifact validity, preregistration README inventory freshness, independent-lane readiness for source-backed observations, intentionally non-scorable observation-template status, committed source-backed observation-file validity, evidence-summary coverage with archived period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-residue-balance command references and negative result metrics, committed source-review validity, findings source-input integrity, source-packet/source-registry field alignment, latest source access-date metadata, local source-archive metadata/boundary structure including non-empty `non_scorable_reason` markers that cannot coexist with `scored_positions_one_based`, source-archive coverage for committed observation positions, stopped-lane documentation coverage, progress-log freshness against the live lane and observation inventory, and absence of explicit leaked/full-plaintext sentinel markers across release-facing files and artifacts before release.

The source packet and `src/data.rs` source registry must stay aligned.
Registered local source archive paths must exist, and `release-check` verifies
them before release. Archive-sale reporting and community archive-research pages
are historical or preregistration context only; they must not introduce
archive-discovered plaintext, private auction material, or unregistered
community interpretations into the data model, reports, exports, or tests.
External plaintext claims use a separate quarantine boundary: register them with
`allowed_use=unverified-solution-claim`, keep the local archive quote-free, and
screen local claim files with `verify-plaintext-claim` or local reconciliation
tables with `verify-claim-reconciliation`. These commands check only table
shape, normalized length, K4 ciphertext alignment, public-anchor compatibility,
optional published `Tier`/`Lane`, `R`/shift, `BaseR`, and `Gate` arithmetic,
and aggregate shift diagnostics; they do not print or store claimed plaintext
and cannot promote a candidate.

The candidate CSV and candidate registry must also stay aligned. Candidate words
remain stopped-lane exploratory inputs unless they are represented in
`experiments/k4-candidates.md` with registered source IDs and rationale, then
survive the current batch, routed, and held-out controls.

Prediction artifacts should be treated as the evidence unit, not lane count.
`validate-prediction-artifact` now warns when a lane's committed artifact
duplicates another committed artifact, because duplicate readiness lanes are
inventory only and do not add independent support. `independent-lane-status`
reports both duplicate artifact lanes and extra duplicate lanes beyond the
first artifact instance, so a large ready-lane count cannot be read as a large
independent evidence count. Use
`validate-prediction-artifact --require-unique-artifact` when the next work
requires a genuinely distinct prediction target rather than another duplicate
readiness lane.

Source-backed period, ciphertext-prior, ciphertext-hotspot, spacing, mirror, grid, and Tableau/HILL observation files are stricter than
general source registration: `validate-period-observations`,
`validate-ciphertext-prior-observations`,
`validate-ciphertext-hotspot-observations`, `validate-spacing-observations`,
`validate-mirror-observations`, `validate-grid-observations`, and
`validate-tableau-hill-observations` reject public-anchor summary,
public-clue context, methodology context, and archive-context-only sources as
scored independent position evidence. Those
sources can still document context or controls, but not the held-out target
being scored.
Run `observation-sources` before creating an observation file to see which
registered sources are eligible for scored independent position observations,
including their URLs, access dates, source types, local-archive status, and
use-boundary notes.
Run `next-evidence-gate` to see the current eligible source IDs, unique ready
prediction targets, and the exact command sequence required before a future
source-backed observation can be treated as evidence. The gate repeats eligible
source details so the source and archive boundary is visible at the point where
an observation file would be scaffolded. It also summarizes current archive
support status and currently recommends against adding duplicate period lanes or
rerunning public-anchor-derived tests while the only valid source-backed
archives remain negative/non-significant. The gate distinguishes eligible
sources already consumed by valid archives from unused eligible sources, so a
new observation pass cannot hide a recycled source behind a fresh lane id. It
also checks whether unused eligible source archives contain scored-position
markers or an explicit `non_scorable_reason`; the current unused `cia-artifact`
archive has no marker and is explicitly non-scorable until a new source-backed
rationale changes that archive boundary.
The JSON output also exposes `next_action_kind`, `blocking_conditions`, and
the duplicate prediction-artifact groups behind those conditions; in the
current state these mark duplicate period lanes as non-evidence, the valid
source-backed archives as negative/non-significant, and the unused eligible
source as explicitly non-scorable. It also exposes `next_check_commands`,
including `source-frontier`, `source-observation-status`,
`validate-source-archive`, and
`validate-prediction-artifact --require-unique-artifact`, so source readiness
and distinct-target status can be checked directly before any observation
scaffold or new preregistration is treated as evidence.
Use `source-frontier --summary` when the immediate question is simply whether
the repo has any scoreable source frontier left; it prints the same blocker and
required-evidence boundary without the full registered-source table.
The source frontier also carries prior source-backed archive counts and support
statuses for already-used sources, so a source with valid scored-position
markers is not reopened without first seeing whether its existing archived
evaluations were negative or non-significant. It now also exposes
machine-readable `frontier_blocking_conditions`, `required_next_evidence`, and
`disallowed_next_actions`, so automation and release review can distinguish a
genuinely new evidence input from a rerun of the same negative archive surface.
When every valid source-backed archive is negative/non-significant and every
unused eligible source is explicitly non-scorable, `source-frontier` makes the
same next-step boundary as `next-evidence-gate`: add a new source-backed
rationale, add a new eligible source, or add a distinct preregistered prediction
artifact before further scoring.
Distinct preregistered targets now include period, spacing, mirror, grid,
Tableau/HILL, and several ciphertext-only position priors. The committed CIA
row-boundary observation has been scored against those available evaluators,
including the ultra-high residue-balance target, and remains
negative/non-significant under the seeded controls.
Run `source-review-packet` when preparing a concrete observation pass. It
separates the pre-score source-review checklist from the scoring commands and
shows which eligible sources currently lack local archive URLs. Its observation
requirements include the validated source-review artifact that must cover every
cited observation source, and it links `source-observation-status --format json`
so reviewed-but-not-scoreable sources remain visible before scaffolding.
Run `source-review-status` to check whether a saved pre-score review artifact
already exists and validates. A missing default review directory or zero valid
reviews means the next step is still source review, not observation scoring.
One valid source-review file only clears the pre-score source-review gate; it
does not create evidence until a separate source-backed observation file is
validated, scored, archived, and revalidated.
Run `source-observation-status` when deciding whether an eligible source is
actually ready for observation scaffolding. It combines valid source-review
coverage, local archive state, scored-position marker state, and existing
source-backed archive use. For already-used sources, it also reports archived
artifact kind, best model, observed hits, null mean best hits, p-value, and
support status. In the current state, `cia-artifact` is reviewed and locally
archived but lacks scored-position markers and carries a `non_scorable_reason`
marker explaining that the archive provides context rather than one-based K4
positions, so it must not be scored until a new source-backed rationale
supplies non-anchor positions and per-position notes.
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
The current source-backed row-boundary observation is documented in
`experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`. It validates and
archives locally, but the period, spacing, mirror, grid, and Tableau/HILL controls are negative
(`p=0.7897`, `p=1.0000`, `p=0.2090`, `p=0.5600`, and `p=0.3311` respectively), so
it is evidence against continuing that row-boundary lane rather than support for
a candidate.
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
