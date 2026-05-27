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
cargo run -- independent-lane-status --format json
cargo run -- next-evidence-gate --format json
cargo run -- independent-evidence-status --format json
cargo run -- non-anchor-positions --format json
cargo run -- init-position-observations --id future-observation-v1 --source-id cia-artifact --source-review experiments/source-reviews/cia-source-review-v1.json --positions 1,4,7 --rationale "Source-backed non-anchor observation rationale." --position-note "1=Source note for position 1." --position-note "4=Source note for position 4." --position-note "7=Source note for position 7." --output results/key-tests/future-observation-v1.json
cargo run -- period-prediction-plan --period 3
cargo run -- period-prediction-plan --all
cargo run -- period-prediction-plan --all --format json
cargo run -- spacing-prediction-plan
cargo run -- spacing-prediction-plan --format json
cargo run -- evaluate-period-prediction --artifact experiments/predictions/non-anchor-position-period-v1.json --positions 1,4,7 --iterations 1000 --seed 67
cargo run -- validate-period-observations --artifact experiments/predictions/non-anchor-position-period-v1.json --preregistration experiments/preregistrations/non-anchor-position-period-v1.json --input <source-backed-observations.json> --format json
cargo run -- evaluate-period-prediction --artifact experiments/predictions/non-anchor-position-period-v1.json --preregistration experiments/preregistrations/non-anchor-position-period-v1.json --positions-file <source-backed-observations.json> --iterations 1000 --seed 67 --output-dir results/period-observations/latest --format json
cargo run -- validate-evaluation-archive --input results/period-observations/latest
cargo run -- validate-spacing-observations --artifact experiments/predictions/non-anchor-position-spacing-v1.json --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json --input <source-backed-observations.json> --format json
cargo run -- evaluate-spacing-prediction --artifact experiments/predictions/non-anchor-position-spacing-v1.json --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json --positions-file <source-backed-observations.json> --iterations 1000 --seed 67 --output-dir results/spacing-observations/latest --format json
cargo run -- validate-evaluation-archive --input results/spacing-observations/latest
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
current evidence count: the period-family files share one deterministic target,
while the spacing family is the second unique ready target.
`next-evidence-gate` combines the live lane inventory with source eligibility
and prints the exact scaffold, validation, evaluation, and archive-check
commands that must pass before future source-backed observations can be
interpreted. It also reports whether any valid source-backed observation
archives already exist and whether ready lanes share duplicate prediction
artifacts, so lane inventory is not confused with scored evidence or independent
target count. The gate includes the eligible source URLs, access dates,
local-archive status, and use-boundary notes so source review requirements are
visible before an observation file is created.
`source-review-packet` prints the same eligible-source review boundary as a
standalone pre-score checklist, including missing local archives and the
required observation fields that must be filled before any evaluator command.
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
`independent-evidence-status` scans archived period/spacing observation
evaluations and reports whether any valid source-backed evidence has actually
been scored yet.
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
`preregistration.json`, `observations.json`, `result.json`, `summary.md`, and
`command.txt` for source-backed observation runs under the ignored `results/`
tree. `validate-evaluation-archive` revalidates the archived preregistration,
prediction artifact, and source-backed observations so copied archives cannot
pass by only keeping `observations.json` and `result.json` internally aligned.

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

Summarize a completed lane:

```bash
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --top 20
cargo run -- summarize-key-runs --input-dir results/key-tests/expanded-lane --format json
```

## Commands

| Command | Output |
| --- | --- |
| `facts` | K4 ciphertext length, ciphertext, and evidence boundary in Markdown or JSON. |
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
| `validate-preregistration` | Gate for proposed new lanes in Markdown or JSON; rejects reuse of public anchor-derived fragments as discovery inputs or primary evidence. |
| `validate-prediction-artifact` | Gate for committed independent prediction artifacts in Markdown or JSON; checks the preregistration and deterministic generator output still match. |
| `independent-lane-status` | Operational summary of preregistered independent lanes, artifact validity, readiness for source-backed observations, family summaries, unique ready prediction artifacts, duplicate artifact groups, and next required validator/evaluator command. |
| `next-evidence-gate` | Operational checklist combining independent-lane readiness, unique/duplicate prediction-target accounting, eligible observation sources, current evidence-archive status, required observation fields, and exact scaffold/validate/evaluate/archive commands before source-backed scoring. |
| `independent-evidence-status` | Archive status for period/spacing independent observation evaluations, separating valid source-backed evidence, diagnostic archives, invalid archives, and no-evidence states. |
| `non-anchor-positions` | Non-scoring one-based position universe for future source-backed observations, with excluded public anchor ranges and source IDs. |
| `init-position-observations` | Guarded source-backed observation-file creator in Markdown or JSON; writes only registered-source, non-anchor K4 positions plus per-position notes, can link a validated `--source-review`, and refuses placeholders, disallowed source uses, duplicate positions, anchors, out-of-range positions, uncovered source-review files, and accidental overwrites unless `--force` is passed. |
| `validate-period-observations` | Gate for source-backed independent position observations in Markdown or JSON; can also validate the prediction artifact preregistration and any linked source-review file, and rejects unregistered or disallowed source IDs, missing position notes, duplicates, and public-anchor positions before scoring. |
| `validate-spacing-observations` | Gate for source-backed independent position observations with per-position notes before spacing scoring in Markdown or JSON; can also validate the spacing prediction artifact preregistration and any linked source-review file. |
| `period-prediction-plan` | Emits non-anchor K4 position residue classes for one or all registered periods in Markdown or JSON without scoring fragment values or candidate material. |
| `spacing-prediction-plan` | Emits non-anchor K4 spacing residue classes for registered moduli in Markdown or JSON without scoring fragment values or candidate material. |
| `evaluate-period-prediction` | Scores independently supplied one-based non-anchor positions against a committed period prediction artifact with a best-of-period null control in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `evaluate-spacing-prediction` | Scores independently supplied one-based non-anchor positions against a committed spacing prediction artifact with a best-of-modulus null control in Markdown or JSON; marks quick `--positions` input as diagnostic, requires `--preregistration` for source-backed `--positions-file` JSON records, and can archive `artifact.json`, `preregistration.json`, `observations.json`, `result.json`, `summary.md`, and `command.txt` with `--output-dir`. |
| `validate-evaluation-archive` | Gate for archived independent observation evaluations in Markdown or JSON; checks archive files, matching evaluator command name, local replay command paths, source-backed observation consistency, archived preregistration/artifact/observation validity, artifact kind, and no-promotion boundaries. |
| `summarize-key-runs` | Historical scanner for batch result folders, ranking individual runs and per-candidate p-value stability. |
| `baseline` | Seeded false-positive controls for the generic recurrence screen. |
| `candidate-sequences` | Pre-registered Berlin/compass/Egypt/Berlin Wall candidate material. |
| `routes` | Small named route/permutation screens with fixed baselines. |
| `findings` | Findings ledger with evidence inputs, transformations, baselines, interpretation, and next tests. |
| `release-check` | Local release preflight in Markdown or JSON confirming no hosted automation, required docs, generated report presence, candidate CSV/registry alignment, preregistration and prediction-artifact validity, independent-lane readiness, non-scorable observation template status, findings source-input integrity, source-packet/source-registry field and latest-access-date alignment, and plaintext-leakage sentinel absence. |
| `hypotheses` | Ranked source-grounded hypothesis register in Markdown or JSON. |
| `sources` | Source provenance records in Markdown or JSON for source-policy audits. |
| `observation-sources` | Focused source-use report showing which registered sources may support scored independent position observations and why other sources are context-only. |
| `source-review-packet` | Pre-score source review packet for eligible observation sources, local archive status, source URLs, use boundaries, and required review steps. |
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
