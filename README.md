# Kryptos K4 Research CLI

`kryptos-k4` is a Rust CLI for source-grounded Kryptos K4 research. It preserves the public K4 ciphertext, known public anchors, source provenance, and repeatable constraint analyses without using leaked or archive-discovered plaintext.

This project is not a claimed K4 solution.

## Features

- Built-in K4 ciphertext and known public anchors.
- 0-based and 1-based anchor positions.
- Source-provenance records for public facts.
- Standard A-Z, Kryptos, and reversed Kryptos alphabet analysis.
- Additive, subtractive, and Beaufort-style anchor-derived fragments.
- Proposed key-material checks, explanations, routed key-material screens, held-out controls, descriptive match-pattern metrics, and composite pattern-score controls against public span-derived additive fragments.
- Gromark-style recurrence screening over known-anchor fragments.
- Seeded baseline controls, pre-registered contextual candidates, and bounded route screens.
- Findings ledger tying observations to sources, transformations, baselines, interpretation, and next tests.
- Ranked hypothesis register from the research plan.
- Markdown and JSON reports.
- CLI E2E tests and local release checks.

## Usage

```bash
cargo run -- facts --format json
cargo run -- anchors --format json
cargo run -- constraints --format json
cargo run -- constraints --spans --format json
cargo run -- key-fragments --span BERLINCLOCK --alphabet kryptos --mode additive-key --format json
cargo run -- test-key --material BERLINWORLDCLOCK
cargo run -- test-key --material WELTZEITUHR
cargo run -- test-key --material ALEXANDERPLATZ --format json
cargo run -- test-key --material BERLINWORLDCLOCK --sweep-offsets --top 5
cargo run -- test-key --material BERLINWORLDCLOCK --sweep-offsets --sweep-baseline-iterations 1000 --seed 42
cargo run -- explain-key --material WELTZEITUHR --transform a1-z26-one-based --offset 5
cargo run -- batch-test-keys --input experiments/k4-candidates.csv --sweep-baseline-iterations 1000 --batch-baseline-iterations 1000 --seed 42 --output-dir results/key-tests/latest
cargo run -- batch-test-routed-keys --input experiments/k4-candidates.csv --sweep-baseline-iterations 1000 --batch-baseline-iterations 1000 --seed 42 --output-dir results/key-tests/routed-latest
cargo run -- heldout-key-control --input experiments/k4-candidates.csv --iterations 1000 --seed 42 --output-dir results/key-tests/heldout-control
cargo run -- position-structure --target spans --alphabet all --iterations 1000 --seed 42
cargo run -- structural-models --target spans --alphabet kryptos --iterations 1000 --seed 42
cargo run -- validate-preregistration --input experiments/preregistrations/non-anchor-position-period-v1.json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-period-v1.json
cargo run -- validate-preregistration --input experiments/preregistrations/non-anchor-position-period-v2.json --format json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-period-v2.json --format json
cargo run -- validate-preregistration --input experiments/preregistrations/non-anchor-position-period-v3.json --format json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-period-v3.json --format json
cargo run -- validate-preregistration --input experiments/preregistrations/non-anchor-position-period-v4.json --format json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-period-v4.json --format json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-period-followup-v1.json --format json
cargo run -- validate-preregistration --input experiments/preregistrations/non-anchor-position-spacing-v1.json --format json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json --format json
cargo run -- validate-preregistration --input experiments/preregistrations/non-anchor-position-mirror-v1.json --format json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-mirror-v1.json --format json
cargo run -- validate-preregistration --input experiments/preregistrations/non-anchor-position-grid-layout-v1.json --format json
cargo run -- validate-prediction-artifact --preregistration experiments/preregistrations/non-anchor-position-grid-layout-v1.json --format json
cargo run -- independent-lane-status --format json
cargo run -- next-evidence-gate --format json
cargo run -- next-evidence-gate --summary --format json
cargo run -- independent-evidence-status --format json
cargo run -- source-review-status --format json
cargo run -- source-observation-status --format json
cargo run -- non-anchor-positions --format json
cargo run -- init-position-observations --id <observation-id> --source-id <eligible-source-id-with-scored-position-rationale> --source-review <source-review.json> --positions <comma-separated-non-anchor-positions> --rationale "<source-backed non-anchor observation rationale>" --position-note "<position>=<source-backed note for that position>" --output <source-backed-observations.json>
cargo run -- period-prediction-plan --period 3
cargo run -- period-prediction-plan --all
cargo run -- period-prediction-plan --all --format json
cargo run -- spacing-prediction-plan
cargo run -- spacing-prediction-plan --format json
cargo run -- mirror-prediction-plan
cargo run -- mirror-prediction-plan --format json
cargo run -- grid-layout-prediction-plan
cargo run -- grid-layout-prediction-plan --rows 14 --columns 7 --format json
cargo run -- validate-period-observations --artifact experiments/predictions/non-anchor-position-period-v1.json --preregistration experiments/preregistrations/non-anchor-position-period-v1.json --input <source-backed-observations.json> --format json
cargo run -- evaluate-period-prediction --artifact experiments/predictions/non-anchor-position-period-v1.json --preregistration experiments/preregistrations/non-anchor-position-period-v1.json --positions-file <source-backed-observations.json> --iterations 1000 --seed 67 --output-dir results/period-observations/latest --format json
cargo run -- validate-evaluation-archive --input results/period-observations/latest
cargo run -- validate-spacing-observations --artifact experiments/predictions/non-anchor-position-spacing-v1.json --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json --input <source-backed-observations.json> --format json
cargo run -- evaluate-spacing-prediction --artifact experiments/predictions/non-anchor-position-spacing-v1.json --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json --positions-file <source-backed-observations.json> --iterations 1000 --seed 67 --output-dir results/spacing-observations/latest --format json
cargo run -- validate-evaluation-archive --input results/spacing-observations/latest
cargo run -- validate-mirror-observations --artifact experiments/predictions/non-anchor-position-mirror-v1.json --preregistration experiments/preregistrations/non-anchor-position-mirror-v1.json --input <source-backed-observations.json> --format json
cargo run -- evaluate-mirror-prediction --artifact experiments/predictions/non-anchor-position-mirror-v1.json --preregistration experiments/preregistrations/non-anchor-position-mirror-v1.json --positions-file <source-backed-observations.json> --iterations 1000 --seed 67 --output-dir results/mirror-observations/latest --format json
cargo run -- validate-evaluation-archive --input results/mirror-observations/latest
cargo run -- validate-grid-observations --artifact experiments/predictions/non-anchor-position-grid-layout-v1.json --preregistration experiments/preregistrations/non-anchor-position-grid-layout-v1.json --input <source-backed-observations.json> --format json
cargo run -- evaluate-grid-prediction --artifact experiments/predictions/non-anchor-position-grid-layout-v1.json --preregistration experiments/preregistrations/non-anchor-position-grid-layout-v1.json --positions-file <source-backed-observations.json> --edge-axis row --iterations 1000 --seed 67 --output-dir results/grid-observations/latest --format json
cargo run -- validate-evaluation-archive --input results/grid-observations/latest
cargo run -- validate-tableau-hill-observations --artifact experiments/predictions/tableau-hill-v1.json --preregistration experiments/preregistrations/tableau-hill-v1.json --input <source-backed-observations.json> --format json
cargo run -- evaluate-tableau-hill-prediction --artifact experiments/predictions/tableau-hill-v1.json --preregistration experiments/preregistrations/tableau-hill-v1.json --positions-file <source-backed-observations.json> --iterations 1000 --seed 67 --output-dir results/tableau-hill-observations/latest --format json
cargo run -- validate-evaluation-archive --input results/tableau-hill-observations/latest
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --top 20
cargo run -- baseline --target spans --iterations 1000 --seed 42
cargo run -- baseline --target spans --iterations 1000 --seed 42 --format json
cargo run -- candidate-sequences
cargo run -- candidate-sequences --format json
cargo run -- routes
cargo run -- routes --format json
cargo run -- findings
cargo run -- findings --format json
cargo run -- release-check --format json
cargo run -- hypotheses --format json
cargo run -- sources
cargo run -- sources --format json
cargo run -- observation-sources
cargo run -- observation-sources --format json
cargo run -- source-review-packet
cargo run -- source-review-packet --format json
cargo run -- init-source-review --id cia-source-review-v1 --source-id cia-artifact --source-id cia-sculpture --review-note "Reviewed eligible source pages before selecting non-anchor positions." --output experiments/source-reviews/cia-source-review-v1.json
cargo run -- validate-source-review --input experiments/source-reviews/cia-source-review-v1.json --format json
cargo run -- export-data --directory data
cargo run -- report --format markdown --output notes/k4-report.md
cargo run -- report --format json
```

`independent-lane-status` includes a family summary that should be used as the
current evidence count: most period-family files share one deterministic
all-period target, while `non-anchor-position-period-v40`,
`non-anchor-position-period-v42`, and `non-anchor-position-period-v43` commit
distinct single-period period-3, period-5, and period-14 targets. Spacing,
mirror, and grid-layout remain distinct unique ready targets. The all-period
target contains eight registered periods; period 14 is a context-only 7-by-14
layout hypothesis, not a score or promoted candidate.
The current independent target inventory also includes a distinct mirror-pair
artifact, `non-anchor-position-mirror-v1`, which predeclares 35 non-anchor
mirror pairs across the 97-character K4 axis. That artifact is source-context
grounded and now has a source-backed validation/evaluation path; it is still
not evidence by itself.
It also includes `non-anchor-position-grid-layout-v1`,
`non-anchor-position-grid-column-v1`, and
`non-anchor-position-grid-width7-row-v1`, plus
`non-anchor-position-grid-4x25-row-v1`, which separately predeclare bounded
padded grid-layout edge targets from context-only Sanborn-papers and Project K4
source rationale. Each deterministic artifact carries its registered
`grid_edge_axis` and dimensions, and source-backed
`evaluate-grid-prediction --positions-file` runs must match that axis and
artifact. The archived row-boundary evidence command uses the 7-by-14 row-edge
preregistration and `--edge-axis row`; the column-edge and width-7 lanes are
distinct future targets, and the 4-by-25 lane is a separate segmented-grid row
edge target, not a
reinterpretation of that archive.
That source can justify the preregistered structure, but it cannot directly
provide scored observation positions.
`next-evidence-gate` combines the live lane inventory with source eligibility
and prints the exact scaffold, validation, evaluation, and archive-check
commands that must pass before future source-backed observations can be
interpreted. It also reports whether any valid source-backed observation
archives already exist, summarizes their score direction, exposes structured
`evidence_support_details` with archive directory/source/model/hit/null-mean/
p-value fields, reports `all_source_backed_archives_negative`, shows which
eligible sources have already been used by valid archives, checks whether unused
eligible source archives contain scored-position markers, and recommends the
next useful evidence step. It also emits
machine-readable
`next_action_kind` and
`blocking_conditions` fields plus `next_check_commands`, including
`validate-prediction-artifact --require-unique-artifact`, so automation can
distinguish a real source-backed observation step from duplicate-lane churn.
That keeps duplicate ready lanes from being confused with scored evidence or
independent target count, and currently steers away from adding more duplicate
period lanes while the committed source-backed archives remain
negative/non-significant. `ciphertext-window-balance-v1` is a distinct
ciphertext-only prediction artifact with a source-backed validator/evaluator;
the committed CIA row-boundary observation scored `0/6` window-balance hits
with empirical `p=1.0000`. The window-balance family also includes narrow,
mid, and wide preregistered ciphertext-only variants that remain unscored until
future source-backed non-anchor observations pass the same validator/evaluator
boundary. The current unused
eligible `cia-artifact` archive has
no scored-position markers and now carries an explicit `non_scorable_reason`,
so the gate reports it as non-scorable until a new source-backed rationale
changes that archive boundary. The gate
includes the eligible source URLs, access dates, local-archive status,
use-boundary notes, the explicit `non_scorable_reason` marker when present, and
the explicit `scored_positions_one_based` source-archive marker required by
`release-check` so source review requirements are visible before an observation
file is created.
It also links the focused `source-observation-status --format json` command so
unused-source readiness can be checked directly before any scaffold command.
Quarantined plaintext-claim sources are reported separately from scored
observation sources, with `verify-plaintext-claim`,
`verify-running-key-claim`, and `verify-claim-reconciliation` commands, plus
`verify-claim-bundle` for local canonical-bundle cross-checks and
`verify-claim-mechanism` for published helper-mechanism and Y-pass
gate-template cross-checks, for local structure checks that do not print,
store, or promote the claimed text or key material. When a
reconciliation table includes
published `Tier`/`Lane`, `C#`/`P#`, `R`/shift, `BaseR`, and `Gate` columns,
the reconciliation verifier also checks the 7-by-14 coordinate rule,
letter-value arithmetic, final shift arithmetic, binary gate values, and
`BaseR + Gate` agreement against the K4 ciphertext and local claim text.
`source-review-packet` prints the same eligible-source review boundary as a
standalone pre-score checklist, including missing local archives and the
required observation fields, including the validated source-review artifact and
explicit local archive position marker, that must be filled before any
evaluator command. It also links `source-observation-status --format json` so a
reviewed source is not mistaken for a scoreable observation source.
`init-source-review` writes that review boundary to a JSON artifact with the
reviewed eligible sources and a reviewer note, so source review can be audited
before any non-anchor positions are selected.
`validate-source-review` rechecks that artifact against the registered source
metadata before observation scoring, catching stale URLs, disallowed source
uses, placeholders, duplicate source IDs, and tampering.
`init-position-observations --source-review <source-review.json>` links the
saved review into the observation file and revalidates that it covers every
observation source before scoring.
`non-anchor-positions` prints the one-based K4 position universe eligible for
future source-backed observations and the public anchor ranges that must stay
excluded from scored evidence.
`independent-evidence-status` scans archived period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-residue-balance observation
evaluations and reports whether any valid source-backed evidence has actually
been scored yet, including each archive's best model, observed hits, raw p-value,
source-backed archive-surface adjusted p-value, and support status. It also
reports the source-backed correction count and whether the archive set is
negative/non-significant after correction.
`source-review-status` scans saved pre-score source-review artifacts and reports
whether any valid review file is available before source-backed observations are
scaffolded.
`source-observation-status` combines eligible-source review coverage, local
archive state, scored-position marker state, and existing source-backed archive
usage into one pre-score status table. For sources already used by evaluation
archives, it also surfaces archived artifact kind, best model, observed hits,
null mean best hits, p-value, and support status so negative/non-significant
results remain visible before any follow-up scaffold. It also reports
`all_source_backed_archives_negative`, so the current stop/replan boundary is
machine-readable from the focused source-readiness command. Its current output shows
`cia-sculpture`
as reviewed and already used by archived row-boundary evaluations, while
`cia-artifact` is reviewed and locally archived but still lacks
`scored_positions_one_based` markers. That means `cia-artifact` must not be
scored until a new source-backed rationale selects non-anchor positions with
per-position notes.
The current committed source-review artifact is
`experiments/source-reviews/cia-source-review-v1.json`; it records pre-score
review of the eligible CIA artifact and sculpture pages only, backed by
quote-free local source snapshots under `sources/archives/`. It does not select
positions, score observations, or make evidence available.
The first source-backed observation file is
`experiments/position-observations/cia-k4-row-boundaries-v1.json`, summarized in
`experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`. It scores the CIA
sculpture text-rendering row-boundary positions after public-anchor exclusion
and is negative under the committed controls: period best-of-model `p=0.7897`,
period-5 single-period target `p=1.0000`, spacing best-of-model `p=1.0000`, mirror same-size position-set `p=0.2090`,
grid-layout same-size position-set `p=0.5600`, Tableau/HILL row/column
concentration `p=0.3311`, ciphertext-prior `p=0.6845`,
ciphertext-hotspot `p=1.0000`, ciphertext-rarity `p=0.5282`,
ciphertext-period-match `p=0.9733`,
ciphertext-transition `p=1.0000`, ciphertext-skip-transition `p=1.0000`,
ciphertext-turning-point `p=0.5247`, ciphertext-window-balance `p=1.0000`,
ciphertext-residue-balance `p=0.4803`,
high-moduli ciphertext-residue-balance `p=0.6416`, very-high-moduli
ciphertext-residue-balance `p=0.3125`, and ultra-high-moduli
ciphertext-residue-balance `p=0.8289`, and super-extreme-moduli
ciphertext-residue-balance `p=0.6741`. The distinct 14-by-7 width-7
row-edge grid artifact is also negative on this same observation
(`2/6`, `p=0.5590`), and the distinct 4-by-25 segmented row-edge
artifact is negative as well (`1/6`, `p=0.3558`).
It promotes no candidate.
`release-check` requires registered local source archive paths to exist, so the
source registry cannot silently point at missing snapshots.
Use `report --output notes/k4-report.md` to regenerate the Markdown report; the
CLI writes through a temporary file and replaces the report only after the
preflight-backed render succeeds.

Observation files must cite registered sources whose `allowed_use` boundary is
compatible with scored independent position evidence. Public-anchor summary,
public-clue context, methodology context, and archive-context-only sources are
rejected for scoring. Source-backed observation files must include
`position_notes`, one note per listed position, so each scored position remains
auditable. When `source_review_file` is present, the validators re-run the
source-review gate and require it to cover every cited `source_id`. The
observation template intentionally has an empty
`positions_one_based` list and empty `position_notes` map, so copied lanes
cannot accidentally score synthetic example positions.
Pass one explicit `--position-note POS=NOTE` for every listed position; the
scaffold rejects omitted notes so each scored position has its own source-backed
audit text.

Direct `evaluate-period-prediction --positions ...` and
`evaluate-spacing-prediction --positions ...` runs are diagnostic only.
Evidence-bearing evaluations must use `--positions-file` with
`--preregistration` after the matching period or spacing observation validator
passes. Add `--output-dir` to archive the scored `artifact.json`,
`preregistration.json`, `observations.json`, optional linked
`source-review.json`, `result.json`, `summary.md`, and `command.txt` for
source-backed observation runs under the ignored `results/` tree.
`validate-evaluation-archive` revalidates the archived preregistration,
prediction artifact, source review, and source-backed observations so copied
archives cannot pass by only keeping `observations.json` and `result.json`
internally aligned.

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

Candidate rows in `experiments/k4-candidates.csv` are documented in
`experiments/k4-candidates.md`. Add new rows only with a public source ID and
rationale so batch histories remain auditable.

The first independent period prediction lane is preregistered in
`experiments/preregistrations/non-anchor-position-period-v1.json`, and its
committed evidence-free prediction artifact is
`experiments/predictions/non-anchor-position-period-v1.json`. Regenerate that
artifact only with `period-prediction-plan --all --format json`; it must remain
free of fragment values, candidate key material, and claimed plaintext.

The follow-up independent prediction lane in
`experiments/preregistrations/non-anchor-position-period-v2.json` carries the stable lane id
`non-anchor-position-period-v2` and has its own committed artifact at
`experiments/predictions/non-anchor-position-period-v2.json`. It uses the same
evidence-free position-period generator and exists to keep future non-anchor
position evidence separate from the already mined public-anchor fragments.

The earlier follow-up preregistration
`experiments/preregistrations/non-anchor-position-period-followup-v1.json` also
has a committed deterministic artifact at
`experiments/predictions/non-anchor-position-period-followup-v1.json`, so
`independent-lane-status` can report it as ready for source-backed observations
rather than awaiting artifact setup.

The newly populated independent prediction proposal at
`experiments/preregistrations/non-anchor-position-period-v3.json` has a
matching committed artifact at
`experiments/predictions/non-anchor-position-period-v3.json`. It is another
pre-scoring position-period target for future non-anchor evidence, not a
candidate-word, route, or public-anchor mining result.

The follow-up lane in
`experiments/preregistrations/non-anchor-position-period-v4.json` has a
matching committed artifact at
`experiments/predictions/non-anchor-position-period-v4.json`. It keeps the
same non-anchor, position-only prediction boundary and exists to lock the next
period target before any source-backed observation scoring.

The latest populated period lane,
`experiments/preregistrations/non-anchor-position-period-v10.json`, replaces the
temporary copied filename with stable lane id `non-anchor-position-period-v10`
and has a matching deterministic artifact at
`experiments/predictions/non-anchor-position-period-v10.json`. It remains a
pre-scoring independent prediction target; it adds no candidate material and
does not reuse public-anchor fragments as evidence.

The next populated period lane,
`experiments/preregistrations/non-anchor-position-period-v11.json`, carries the
same independent prediction boundary with a matching deterministic artifact at
`experiments/predictions/non-anchor-position-period-v11.json`. It exists to
lock a source-backed non-anchor evaluation target before any new observation
file is scored, not to add evidence from the reused public anchors.

The copied preregistration was normalized to
`experiments/preregistrations/non-anchor-position-period-v12.json` with stable
lane id `non-anchor-position-period-v12`, a concrete non-anchor rationale, and
a matching deterministic artifact at
`experiments/predictions/non-anchor-position-period-v12.json`. It remains a
period-family readiness lane sharing the same unique prediction target, not a
new independent cryptanalytic signal.

The populated period lane in
`experiments/preregistrations/non-anchor-position-period-v16.json` carries a
stable lane id, concrete non-anchor rationale, predeclared discovery and
evaluation inputs, and controls for seeded shuffles, multiple comparisons, and
best-of-period selection. It has a matching deterministic artifact at
`experiments/predictions/non-anchor-position-period-v16.json`; it remains a
pre-score prediction target, not scored evidence.

`experiments/preregistrations/non-anchor-position-period-v17.json` is another
populated period-family readiness lane created from the copied-template prompt
with a stable lane id and the same strict non-anchor boundary. Its deterministic
artifact is `experiments/predictions/non-anchor-position-period-v17.json`.
Validation reports the lane and artifact as valid, but this is still only a
pre-score prediction target; it adds no candidate key material and promotes no
candidate.

`experiments/preregistrations/non-anchor-position-period-v21.json`,
`experiments/preregistrations/non-anchor-position-period-v22.json`,
`experiments/preregistrations/non-anchor-position-period-v23.json`, and
`experiments/preregistrations/non-anchor-position-period-v24.json` replace
copied placeholder lanes with stable ids, concrete period-family rationales,
predeclared discovery/evaluation inputs, and explicit null, best-of-period,
multiple-comparison, and source-backed validation controls. Their deterministic
artifacts are under `experiments/predictions/`; all four remain period-family
readiness lanes and do not add independent scored evidence.
`experiments/preregistrations/non-anchor-position-period-v25.json` follows the
same populated-lane pattern and validates with its matching deterministic
artifact, but it also remains duplicate period-family readiness inventory
rather than independent scored evidence.
`experiments/preregistrations/non-anchor-position-period-v28.json`,
`experiments/preregistrations/non-anchor-position-period-v29.json`, and
`experiments/preregistrations/non-anchor-position-period-v30.json`, and
`experiments/preregistrations/non-anchor-position-period-v31.json` are the
latest populated follow-up lanes created from placeholder prompts. They have
stable ids, concrete non-anchor rationales, predeclared discovery/evaluation
inputs, explicit null/best-of-period/multiple-comparison/source-backed controls,
and matching deterministic artifacts under `experiments/predictions/`. They
validate, but their artifacts duplicate the existing period-family target, so
they are inventory only and not new independent evidence.
`experiments/preregistrations/non-anchor-position-period-v40.json` is a
period-family exception: it commits the deterministic period-3-only artifact at
`experiments/predictions/non-anchor-position-period-v40.json` and validates with
`validate-prediction-artifact --require-unique-artifact`. It is a distinct
pre-score target, not scored evidence or a promoted candidate.
`experiments/preregistrations/non-anchor-position-period-v43.json` is another
period-family exception: it commits the deterministic period-14-only artifact at
`experiments/predictions/non-anchor-position-period-v43.json` and validates with
`validate-prediction-artifact --require-unique-artifact`. It is tied to the
context-only 7-by-14 Sanborn-papers rationale, but the source does not provide
scored positions or candidate evidence.
`experiments/preregistrations/non-anchor-position-period-v45.json` is a
populated period-family readiness lane with concrete non-anchor rationale,
predeclared discovery/evaluation inputs, explicit controls, and a matching
deterministic artifact at
`experiments/predictions/non-anchor-position-period-v45.json`. The artifact
validates, but it duplicates the existing all-period target, so it is duplicate
inventory only and not new independent evidence.
`validate-prediction-artifact` warns when a committed artifact duplicates
another committed artifact, so duplicated readiness lanes are visible at the
artifact gate rather than mistaken for independent evidence. `independent-lane-status`
also reports duplicate artifact lane counts and extra duplicate lanes so the
working evidence surface stays tied to unique prediction artifacts rather than
raw ready-lane totals.

Summarize a completed lane:

```bash
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --top 20
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --format json
```

## Commands

| Command | Output |
| --- | --- |
| `facts` | K4 ciphertext length, ciphertext, and evidence boundary in Markdown or JSON. |
| `ciphertext-profile` | Ciphertext-only frequency, repeated n-gram spacing, index-of-coincidence, period-coincidence diagnostics, and optional seeded shuffle baselines without anchors, candidate material, claimed plaintext, or promotion. |
| `ciphertext-structure-prior` | Planning-only ciphertext-derived position prior for future source-backed observations, currently selecting the weak period-2 spacing and period-7 shifted-coincidence diagnostics without treating either as evidence. |
| `ciphertext-period-match-prior` | Planning-only shifted same-letter period-match endpoint prior for future source-backed observations, fixing top ciphertext-only period-match endpoint sets before any source-backed position scoring. |
| `validate-ciphertext-prior-observations` | Non-scoring gate for source-backed independent positions before ciphertext-prior scoring; validates the committed ciphertext-only prior artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-prior` | Scores source-backed non-anchor position observations against the planning-only ciphertext-derived prior with a seeded same-size non-anchor position-shuffle null; archives `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`, and never treats the prior itself as evidence. |
| `ciphertext-hotspot-prior` | Planning-only ciphertext hotspot prior for future source-backed observations, fixing top non-anchor positions from repeated n-gram coverage and shifted self-coincidence endpoints without treating them as evidence. |
| `validate-ciphertext-hotspot-observations` | Non-scoring gate for source-backed independent positions before ciphertext-hotspot scoring; validates the committed hotspot artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-hotspot` | Scores source-backed non-anchor position observations against the committed ciphertext-hotspot prior with a seeded same-size non-anchor position-shuffle null; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `ciphertext-rarity-prior` | Planning-only ciphertext rare-letter position prior for future source-backed observations, fixing the rarest non-anchor ciphertext-letter positions without candidate words, routes, or public-anchor-derived fragment scoring. |
| `validate-ciphertext-rarity-observations` | Non-scoring gate for source-backed independent positions before ciphertext-rarity scoring; validates the committed rarity artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-rarity` | Scores source-backed non-anchor position observations against the committed ciphertext-rarity prior with a seeded same-size non-anchor position-shuffle null; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `ciphertext-transition-prior` | Planning-only ciphertext adjacent-transition prior for future source-backed observations, fixing high transition-pressure non-anchor positions from Kryptos-alphabet ciphertext adjacency only. |
| `validate-ciphertext-transition-observations` | Non-scoring gate for source-backed independent positions before ciphertext-transition scoring; validates the committed transition artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-transition` | Scores source-backed non-anchor position observations against the committed ciphertext-transition prior with a seeded same-size non-anchor position-shuffle null; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `ciphertext-skip-transition-prior` | Planning-only ciphertext skip-transition prior for future source-backed observations, fixing high adjacent and distance-two transition-pressure non-anchor positions from Kryptos-alphabet ciphertext only. |
| `validate-ciphertext-skip-transition-observations` | Non-scoring gate for source-backed independent positions before ciphertext-skip-transition scoring; validates the committed skip-transition artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-skip-transition` | Scores source-backed non-anchor position observations against the committed ciphertext-skip-transition prior with a seeded same-size non-anchor position-shuffle null; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `ciphertext-turning-point-prior` | Planning-only ciphertext local-turning-point prior for future source-backed observations, fixing high-curvature local extrema from Kryptos-alphabet ciphertext indexes only. |
| `validate-ciphertext-turning-point-observations` | Non-scoring gate for source-backed independent positions before ciphertext-turning-point scoring; validates the committed turning-point artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-turning-point` | Scores source-backed non-anchor position observations against the committed ciphertext-turning-point prior with a seeded same-size non-anchor position-shuffle null; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `ciphertext-residue-balance-prior` | Planning-only ciphertext residue-balance prior for future source-backed observations, fixing residue classes with high distinct-letter balance before any source-backed position scoring. |
| `validate-ciphertext-residue-balance-observations` | Non-scoring gate for source-backed independent positions before ciphertext-residue-balance scoring; validates the committed residue-balance artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-residue-balance` | Scores source-backed non-anchor position observations against the committed ciphertext-residue-balance prior with a best-of-modulus seeded same-size non-anchor position-shuffle null; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `ciphertext-stehle-regularity-prior` | Emits the source-grounded Stehle local-regularity planning artifact, recording the source-reported 55 through 63 anomaly label and repo canonical 56 through 64 coordinate mapping. |
| `validate-ciphertext-stehle-regularity-observations` | Non-scoring gate for source-backed independent positions before ciphertext-Stehle-regularity scoring; validates the committed artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-stehle-regularity` | Scores source-backed non-anchor position observations against the committed Stehle window and lag-confirmed +5 subset with seeded same-size non-anchor position-shuffle nulls; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `anchors` | Public known-plaintext anchors with 0-based and 1-based positions plus source IDs in Markdown or JSON. |
| `constraints` | Anchor-derived fragments for supported alphabets in Markdown or JSON. |
| `constraints --spans` | Adjacent public clues merged into known-plaintext spans before screening in Markdown or JSON. |
| `key-fragments` | Raw derived key-fragment rows with anchor/span/alphabet/mode filters in Markdown or JSON. |
| `test-key` | Proposed key material transformed and compared against public span additive fragments at true K4 positions, with optional cyclic offset sweep and seeded sweep baseline. |
| `explain-key` | Exact matching public-span positions for one key-material lead, including one-based modulo caveats, descriptive pattern metrics, and composite pattern score when relevant. |
| `batch-test-keys` | CSV-driven key-material batch runner with ranked Markdown/JSON summaries, optional output artifacts, pattern metrics, and optional batch-level best-of-candidate-file null controls for both match count and composite pattern score. |
| `batch-test-routed-keys` | CSV-driven routed key-material batch runner that applies registered route/permutation families before candidate scoring, with match-count and composite pattern-score null controls over the routed search surface. |
| `heldout-key-control` | Leave-one-public-group-out control that selects candidate material and offset on non-overlapping training groups, then scores the withheld anchor/span group against seeded null selection runs. |
| `position-structure` | Candidate-independent residue/spacing structure control over public fragments, comparing fixed-position scores against seeded value shuffles. |
| `structural-models` | Pre-registered period-model controls that score public fragments only after the model registry is fixed, with seeded nulls and Holm adjustment. |
| `ciphertext-window-balance-prior` | Emits the ciphertext-only local-window balance prediction artifact for future independent non-anchor observations. |
| `validate-ciphertext-window-balance-observations` | Non-scoring gate for source-backed independent positions before ciphertext-window-balance scoring; validates the committed window-balance artifact, preregistration, source-review coverage, source-use boundary, per-position notes, duplicates, and non-anchor universe. |
| `evaluate-ciphertext-window-balance` | Scores source-backed non-anchor position observations against the committed ciphertext-window-balance prior with a seeded same-size non-anchor position-set null; archives the source-backed inputs and result files with `--output-dir`, and never treats the prior itself as evidence. |
| `validate-preregistration` | Gate for proposed new lanes in Markdown or JSON; rejects reuse of public anchor-derived fragments as discovery inputs or primary evidence. |
| `validate-prediction-artifact` | Gate for committed independent prediction artifacts in Markdown or JSON; checks the preregistration and deterministic generator output still match, and `--require-unique-artifact` fails duplicate prediction targets when the next lane must be distinct. |
| `independent-lane-status` | Operational summary of preregistered independent lanes, artifact validity, readiness for source-backed observations, family summaries, unique ready prediction artifacts, duplicate artifact groups, duplicate/extra duplicate artifact lane counts, and next required validator/evaluator command. |
| `next-evidence-gate` | Operational checklist combining independent-lane readiness, unique/duplicate prediction-target accounting, evaluator-pending lane inventory, eligible observation sources, used/unused eligible source accounting, unused-source scored-position marker and non-scorable status, quarantined plaintext-claim source IDs with the safe verifier commands and committed claim-verification archive inventory, current evidence-archive score direction, structured archive support details including null means, source-review status, machine-readable next-action/blocking-condition fields, explicit next-check commands including `--require-unique-artifact`, required observation fields including source-review coverage, recommended next evidence step, a concise `--summary` mode, and exact scaffold/validate/evaluate/archive commands before source-backed scoring. |
| `independent-evidence-status` | Archive status for period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-residue-balance independent observation evaluations, separating valid source-backed evidence, diagnostic archives, invalid archives, no-evidence states, per-archive raw and adjusted p-values, and correction-aware score direction. |
| `non-anchor-positions` | Non-scoring one-based position universe for future source-backed observations, with excluded public anchor ranges and source IDs. |
| `source-observation-status` | Pre-score source readiness table for eligible sources, showing valid source-review coverage, local archive state, scored-position marker state, prior source-backed archive use, archived evidence support status and null means for used sources, and the allowed next action before observation scoring. |
| `source-frontier` | Classifies every registered source as scored-observation ready, currently non-scorable, context-only, or quarantined-claim, including prior source-backed archive counts, raw and source-archive-corrected all-negative status, minimum empirical/adjusted p-values, support statuses for already-used sources, machine-readable frontier blockers, required next-evidence criteria, disallowed next actions, and a concise Markdown `--summary` mode, so future work can pick evidence sources without crossing source-use boundaries or reusing negative evidence blindly. |
| `source-intake-packet` | Checklist for adding a new evidence source without crossing source-use boundaries, including required registry fields, quote-free archive metadata, scoreable-evidence requirements, rejection rules, follow-up commands, and an archive template. |
| `validate-source-archive` | Standalone validator for quote-free local source snapshots; checks source registry metadata, required archive markers, no-promotion boundary, non-scorable/scored-position consistency, and scored-position use boundaries before a source archive is committed or scored. |
| `init-position-observations` | Guarded source-backed observation-file creator in Markdown or JSON; writes only registered-source, non-anchor K4 positions plus per-position notes, can link a validated `--source-review`, and refuses placeholders, disallowed source uses, duplicate positions, anchors, out-of-range positions, uncovered source-review files, and accidental overwrites unless `--force` is passed. |
| `validate-period-observations` | Gate for source-backed independent position observations in Markdown or JSON; can also validate the prediction artifact preregistration and any linked source-review file, and rejects unregistered or disallowed source IDs, missing position notes, duplicates, and public-anchor positions before scoring. |
| `validate-ciphertext-prior-observations` | Gate for source-backed independent position observations before ciphertext-prior scoring in Markdown or JSON; can also validate the ciphertext-prior artifact preregistration and any linked source-review file. |
| `validate-ciphertext-hotspot-observations` | Gate for source-backed independent position observations before ciphertext-hotspot scoring in Markdown or JSON; can also validate the ciphertext-hotspot artifact preregistration and any linked source-review file. |
| `validate-ciphertext-rarity-observations` | Gate for source-backed independent position observations before ciphertext-rarity scoring in Markdown or JSON; can also validate the ciphertext-rarity artifact preregistration and any linked source-review file. |
| `validate-ciphertext-repeat-distance-observations` | Gate for source-backed independent position observations before ciphertext-repeat-distance scoring in Markdown or JSON; can also validate the ciphertext-repeat-distance artifact preregistration and any linked source-review file. |
| `validate-ciphertext-period-match-observations` | Gate for source-backed independent position observations before ciphertext-period-match scoring in Markdown or JSON; can also validate the ciphertext-period-match artifact preregistration and any linked source-review file. |
| `validate-ciphertext-adjacent-contrast-observations` | Gate for source-backed independent position observations before ciphertext-adjacent-contrast scoring in Markdown or JSON; can also validate the ciphertext-adjacent-contrast artifact preregistration and any linked source-review file. |
| `validate-ciphertext-transition-observations` | Gate for source-backed independent position observations before ciphertext-transition scoring in Markdown or JSON; can also validate the ciphertext-transition artifact preregistration and any linked source-review file. |
| `validate-ciphertext-skip-transition-observations` | Gate for source-backed independent position observations before ciphertext-skip-transition scoring in Markdown or JSON; can also validate the ciphertext-skip-transition artifact preregistration and any linked source-review file. |
| `validate-ciphertext-turning-point-observations` | Gate for source-backed independent position observations before ciphertext-turning-point scoring in Markdown or JSON; can also validate the ciphertext-turning-point artifact preregistration and any linked source-review file. |
| `validate-ciphertext-residue-balance-observations` | Gate for source-backed independent position observations before ciphertext-residue-balance scoring in Markdown or JSON; can also validate the ciphertext-residue-balance artifact preregistration and any linked source-review file. |
| `validate-spacing-observations` | Gate for source-backed independent position observations with per-position notes before spacing scoring in Markdown or JSON; can also validate the spacing prediction artifact preregistration and any linked source-review file. |
| `validate-mirror-observations` | Gate for source-backed independent position observations with per-position notes before mirror-pair scoring in Markdown or JSON; can also validate the mirror prediction artifact preregistration and any linked source-review file. |
| `validate-grid-observations` | Gate for source-backed independent position observations with per-position notes before grid-layout scoring in Markdown or JSON; can also validate the grid prediction artifact preregistration and any linked source-review file. |
| `validate-tableau-hill-observations` | Non-scoring gate for source-backed Tableau/HILL source-map observations in Markdown or JSON; validates the committed source-mapping artifact and rejects padding, public-anchor, duplicate, uncovered, or source-use-incompatible positions before `evaluate-tableau-hill-prediction` can score them. |
| `period-prediction-plan` | Emits non-anchor K4 position residue classes for one or all registered periods in Markdown or JSON without scoring fragment values or candidate material. |
| `spacing-prediction-plan` | Emits non-anchor K4 spacing residue classes for registered moduli in Markdown or JSON without scoring fragment values or candidate material. |
| `mirror-prediction-plan` | Emits non-anchor mirror-pair targets across the 97-character K4 position axis in Markdown or JSON without scoring fragment values or candidate material. |
| `grid-layout-prediction-plan` | Emits a non-anchor padded grid-layout artifact in Markdown or JSON with explicit row/column dimensions and a scored row, column, or compass edge axis, without scoring fragment values or candidate material. |
| `tableau-hill-prediction-plan` | Emits a fixed HILL/tableau source-mapping artifact in Markdown or JSON for source-backed row/column concentration evaluation, without scoring fragment values, candidate material, or public-anchor-derived evidence. |
| `evaluate-period-prediction` | Scores independently supplied one-based non-anchor positions against a committed period prediction artifact with a best-of-period null control in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-spacing-prediction` | Scores independently supplied one-based non-anchor positions against a committed spacing prediction artifact with a best-of-modulus null control in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-mirror-prediction` | Scores independently supplied one-based non-anchor positions against committed mirror-pair targets with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-grid-prediction` | Scores independently supplied one-based non-anchor positions against a committed grid-layout artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, rejects source-backed scoring when `--edge-axis` does not match the preregistered `grid_edge_axis`, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-tableau-hill-prediction` | Scores independently supplied one-based non-anchor positions for best row/column concentration on the committed Tableau/HILL 7-by-14 source map with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-hotspot` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-hotspot artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-rarity` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-rarity artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-repeat-distance` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-repeat-distance artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-period-match` | Scores independently supplied one-based non-anchor positions against shifted same-letter period-match endpoint sets with a seeded same-size best-of-period position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-adjacent-contrast` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-adjacent-contrast artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-transition` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-transition artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-skip-transition` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-skip-transition artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-turning-point` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-turning-point artifact with a seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-ciphertext-residue-balance` | Scores independently supplied one-based non-anchor positions against the committed ciphertext-residue-balance artifact with a best-of-modulus seeded same-size non-anchor position-set null in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, linked `source-review.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `validate-evaluation-archive` | Gate for archived independent observation evaluations in Markdown or JSON; checks archive files, matching evaluator command name, local replay command paths, source-backed observation consistency, archived source-review/preregistration/artifact/observation validity, artifact kind, and no-promotion boundaries. |
| `summarize-key-runs` | Historical scanner for batch result folders, ranking individual runs and per-candidate p-value stability. |
| `baseline` | Seeded false-positive controls for the generic recurrence screen. |
| `candidate-sequences` | Pre-registered Berlin/compass/Egypt/Berlin Wall candidate material. |
| `routes` | Small named route/permutation screens with fixed baselines. |
| `findings` | Findings ledger with evidence inputs, transformations, baselines, interpretation, and next tests. |
| `release-check` | Local release preflight in Markdown or JSON confirming no hosted automation, required docs, generated report presence, candidate CSV/registry alignment, preregistration and prediction-artifact validity, preregistration README inventory freshness, independent-lane readiness, non-scorable observation template status, committed source-backed observation-file validity, evidence-summary coverage with archived period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-residue-balance command references and negative result metrics, committed source-review validity, source-readiness command documentation, findings source-input integrity, source-packet/source-registry field and latest-access-date alignment, local source-archive metadata/boundary structure including non-scorable/scored-position consistency, source-archive coverage for committed observation positions, stopped-lane documentation coverage, progress-log freshness, claim-verification archive quarantine boundaries, and plaintext-leakage sentinel absence across release-facing files and artifacts. |
| `hypotheses` | Ranked source-grounded hypothesis register in Markdown or JSON. |
| `sources` | Source provenance records in Markdown or JSON for source-policy audits. |
| `verify-plaintext-claim` | Local verifier for quarantined external plaintext claims; checks length, public-anchor compatibility, and aggregate shift diagnostics without printing or storing the claim text. |
| `verify-running-key-claim` | Local verifier for quarantined external plaintext plus running-key-stream claims; checks length, public-anchor compatibility, and additive ciphertext reconstruction under a selectable alphabet without printing or storing plaintext or key material. |
| `verify-claim-reconciliation` | Local verifier for quarantined external reconciliation tables; checks row count, one-based position sequence, K4 ciphertext alignment, optional published `Tier`/`Lane`, `C#`/`P#`, `R`/shift, `BaseR`, and `Gate` arithmetic, public-anchor compatibility, and aggregate shift diagnostics without printing or storing any claimed plaintext column. |
| `verify-claim-bundle` | Local verifier for quarantined external canonical bundles; cross-checks required local files, repo ciphertext, plaintext length only, reconciliation arithmetic, `R`/`r` grids, gate map, Z2 handoff, and public anchors without printing or storing claimed plaintext. |
| `verify-claim-mechanism` | Local verifier for quarantined external mechanism files; checks published `f`/helper-card relationships, control-card consistency, Z2 footer handoff, Y-pass gate-template consistency, and the Z2 helper path into the `r`/`R` grids without printing or storing claimed plaintext. |
| `claim-verification-status` | Focused quarantine inventory for registered solution-claim sources, committed non-leaking verification archives, unarchived claim sources, per-source verifier/input-plan guidance, safe local verifier commands, and a concise `--summary` mode for the remaining local-input work. |
| `claim-input-plan` | Local-only intake checklist for one quarantined claim source, mapping temporary plaintext/key/table/bundle/mechanism paths to the safe verifier commands without creating or committing claim material. |
| `observation-sources` | Focused source-use report showing which registered sources may support scored independent position observations and why other sources are context-only. |
| `source-review-packet` | Pre-score source review packet for eligible observation sources, local archive status, source URLs, use boundaries, required review steps, and the observation requirement to link the validated source-review file. |
| `source-review-status` | Pre-score source-review artifact scanner, separating valid reviews, invalid reviews, missing review roots, and no-review states. |
| `init-source-review` | Guarded pre-score source-review file creator that writes reviewed eligible sources and review notes before any observation positions are selected. |
| `validate-source-review` | Gate for pre-score source-review artifacts, checking reviewed source IDs and metadata against the registered eligible source set. |
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

See [docs/research-method.md](docs/research-method.md), [experiments/PROGRESS_LOG.md](experiments/PROGRESS_LOG.md), [experiments/STOPPED_LANES.md](experiments/STOPPED_LANES.md), and [kryptos-k4-research-plan.md](kryptos-k4-research-plan.md).
Implementation diagrams are tracked in [docs/architecture-current.md](docs/architecture-current.md) and [docs/architecture-production-goal.md](docs/architecture-production-goal.md).
