# K4 Experiment Progress Log

This log records command-backed findings that affect what should be tried next.
It is not a claimed solution.

## 2026-05-25: Methodology Context Source

The public KryptosBot methodology page is now registered as
`kryptosbot-methodology-2026` with `allowed_use = methodology-context`.

Interpretation: this source can document why saturated single-layer,
word-list, route, or uncorrected best-of-search lanes should not be rerun as
evidence. It does not provide plaintext, candidate material, or scored
observations. Any future use still needs a preregistered target and a null or
multiple-comparison control before interpretation.

Follow-up: this boundary is now represented in the findings ledger as `F6`,
so the generated report records the methodology source as a stopped-lane
discipline finding rather than only as source metadata.

## 2026-05-25: Methodology Context Scoring Gate

The period-observation validator now rejects `methodology-context` sources as
scored independent position evidence. Methodology pages can still justify
stopped lanes, controls, or preregistration rationale, but they cannot supply
the scored non-anchor positions for `validate-period-observations` or
`evaluate-period-prediction --positions-file`.

Interpretation: source-backed future evidence must come from a source boundary
compatible with scored position observations. Methodology-only sources remain
context, not evidence.

## 2026-05-25: Observation Source-Use Gate

The period-observation path now rejects registered sources whose `allowed_use`
boundary is not compatible with scored independent position evidence.
`public-anchor-summary`, `public-clue-context`, `methodology-context`, and
`archive-context-only` sources remain valid context/control sources, but they
cannot be used as scored observation evidence for `validate-period-observations` or
`evaluate-period-prediction --positions-file`.

Interpretation: future non-anchor position evidence must be both source-backed
and source-policy compatible before it can be scored against committed period
prediction artifacts.

Template hardening follow-up: `experiments/position-observations-template.json`
now leaves `positions_one_based` empty so a copied template cannot accidentally
score synthetic example positions such as period-3-friendly non-anchor rows.

## 2026-05-25: Machine-Readable Validation Gates

The future-evidence path now has documented JSON output for the gate commands
that matter before any independent observation is interpreted:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/non-anchor-position-period-v2.json \
  --format json
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/non-anchor-position-period-v2.json \
  --format json
cargo run --locked -- release-check --format json
```

Result summary:

- preregistration validation: `valid: true`, `promoted_candidate: false`
- prediction artifact validation: `valid: true`, `expected_period_count: 7`,
  `artifact_period_count: 7`, `promoted_candidate: false`
- release-check JSON: every local preflight check reports `passed: true`
- release-check now includes `position-observation-template-guarded`, requiring
  the observation template to stay intentionally non-scorable
- release-check now includes `findings-source-inputs-valid`, requiring each
  findings ledger input to resolve to a registered source, committed file, or
  known local command reference

Interpretation: future non-anchor evidence can now be audited through
machine-readable preregistration, artifact, observation, period-evaluation, and
release gates. This improves reproducibility but still contributes no K4
plaintext or promoted candidate by itself.

Follow-up documentation update: this gate is now represented in the findings
ledger as `F7`, so the generated report records the v2 preregistration,
committed artifact, and JSON gate boundary as a reproducibility finding rather
than a cryptanalytic result.

## 2026-05-25: Period Evaluation Source-Backing Flag

`evaluate-period-prediction` now distinguishes diagnostic ad hoc `--positions`
input from source-backed `--positions-file` evidence. Source-backed
`--positions-file` evaluation requires `--preregistration`, so the committed
prediction artifact is validated before scoring. JSON and Markdown output
include `source_backed_observation`; ad hoc position lists also include a warning
that they are diagnostic only.

Interpretation: the command remains useful for quick mechanics checks, but
future evidence-bearing period evaluations should come from validated
observation files with registered source IDs and rationale.

Follow-up documentation update: this guard is now represented in the findings
ledger as `F8`, so the generated report records source-backed observation
scoring as a reproducibility boundary rather than a cryptanalytic result.

## 2026-05-25: Preregistration Gate

Command:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/non-anchor-position-period-v1.json
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/non-anchor-position-period-v2.json
```

Result:

- `valid: true`
- `promoted: false`
- warning: no source IDs are attached, acceptable only because this is an
  `independent-prediction-target`

Interpretation: the proposed `non-anchor-position-period-v1` lane is allowed as
a preregistered independent target, but it does not provide evidence by itself.
The follow-up file `non-anchor-position-period-v2.json` carries the stable lane id
`non-anchor-position-period-v2`, explicitly declares non-anchor position-period
prediction as its family, and keeps public anchor-derived fragments out of both
discovery inputs and primary evidence.

## 2026-05-25: Structural Model Rerun

Command:

```bash
cargo run --locked -- structural-models \
  --target spans \
  --alphabet kryptos \
  --iterations 100000 \
  --seed 67
```

Result summary:

- model count: 7
- fragments: 24 public span-derived additive fragments
- best raw model: `period-3-triad`
- best raw p-value: `0.1129`
- Holm-adjusted p-value: `0.7904`
- promoted: false

Interpretation: the current period-model registry does not show meaningful
candidate-independent structure on public span fragments. Do not expand a
period lane from this public-fragment result. The only defensible use of the
period registry is as a preregistered rule for an independent future target.

## 2026-05-25: Non-Anchor Period Prediction Plan

Command:

```bash
cargo run --locked -- period-prediction-plan --period 3
cargo run --locked -- period-prediction-plan --all
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/non-anchor-position-period-v1.json
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/non-anchor-position-period-v2.json
```

Result summary:

- period: `3`
- registered periods in `--all` mode: `7`
- public-anchor positions excluded: `24`
- non-anchor positions emitted as prediction targets: `73`
- fragment values scored: none
- candidate material scored: none
- promoted: false
- committed prediction artifact:
  `experiments/predictions/non-anchor-position-period-v1.json`
- prediction artifact validation: `valid: true`
- follow-up committed prediction artifact:
  `experiments/predictions/non-anchor-position-period-v2.json`

Interpretation: this makes the `non-anchor-position-period-v1` lane executable
as a predeclared target. It does not use public anchor-derived key fragments as
evidence. Future independent evidence can be compared to these residue classes
without retuning the period or residue assignment. Prefer `--all` when the
period has not been justified independently, because that preserves the full
registered-period search surface for later best-of-period controls.
The committed artifact is intentionally evidence-free: it contains K4 position
classes only, excludes public-anchor positions, and does not include fragment
values or candidate key material.
The `non-anchor-position-period-v2` follow-up artifact is generated by the same
deterministic evidence-free command so release checks can reject stale or
hand-edited lane targets.

Follow-up documentation update: this lane is now represented in the findings
ledger as `F5`, so the generated report records the artifact and validation
gate instead of only the older public-anchor-derived lanes.

Evaluator added: `evaluate-period-prediction` can now score a future
independent set of one-based non-anchor K4 positions against the committed
artifact with a seeded best-of-period null. It rejects public-anchor positions
and remains non-promotional.

Evaluator input hardened: `evaluate-period-prediction` now also accepts
`--positions-file`, a JSON observation record with registered `source_ids`,
`positions_one_based`, and rationale. This keeps future non-anchor position
evidence source-backed instead of only accepting ad hoc comma-separated inputs.
`validate-period-observations` now checks those files before scoring, rejecting
unregistered source IDs, duplicate positions, and positions outside the
committed non-anchor prediction artifact. It also rejects unchanged template
placeholder text and carries observation rationale into validation/evaluation
output. Pass `--preregistration` to validate the committed prediction artifact
and observation file in one pre-score gate; the same preregistration guard is
available on `evaluate-period-prediction` before scoring.

Concrete follow-up lane registered:
`experiments/preregistrations/non-anchor-position-period-followup-v1.json`
predeclares future independent non-anchor position observations as the
evaluation surface. It intentionally has no source IDs and validates only as a
pure independent prediction target.

Template-derived diagnostic lane populated and renamed:
`experiments/preregistrations/non-anchor-position-period-diagnostic-v1.json`
carries the stable lane id `non-anchor-position-period-diagnostic-v1` and
declares the committed target artifact
`experiments/predictions/non-anchor-position-period-diagnostic-v1.json`. Both
`validate-preregistration` and `validate-prediction-artifact` pass. This is
still only a pre-score independent target; it contributes no evidence until a
source-backed non-anchor observation file is added.

Independent spacing lane registered:
`experiments/preregistrations/non-anchor-position-spacing-v1.json` predeclares
a position-only spacing/delta residue target before any candidate-word,
route, or fragment-value scoring. The deterministic artifact
`experiments/predictions/non-anchor-position-spacing-v1.json` is emitted by
`spacing-prediction-plan --format json`; both preregistration and artifact
validation pass. This lane is a future-evidence target only, not a K4 solve or
promotion claim.

Additional independent period lane populated:
`experiments/preregistrations/non-anchor-position-period-v3.json` carries
stable lane id `non-anchor-position-period-v3` and
declares non-anchor position-period prediction as its family. Its deterministic
artifact at `experiments/predictions/non-anchor-position-period-v3.json` is
emitted by `period-prediction-plan --all --format json`. Both preregistration
and artifact validation pass. This is a pre-scoring target for future
source-backed non-anchor observations only.

Spacing evaluator added: `evaluate-spacing-prediction` scores independent
non-anchor observation positions against the committed spacing artifact with a
best-of-modulus seeded null. Direct `--positions` input is diagnostic; scored
source-backed use requires `--positions-file` plus the spacing preregistration
so the artifact is validated before evaluation.

Spacing observation validation added: `validate-spacing-observations` now checks
source-backed observation files against the committed spacing artifact before
spacing evaluation. It rejects duplicate positions, public-anchor positions, and
source IDs whose allowed-use boundary cannot support scored independent
position evidence.

Follow-up hardening: `validate-spacing-observations` now also rejects
single-position files because spacing evaluation needs at least two positions to
form one pair. This closes a pre-score validation gap where a source-backed file
could pass validation but fail at evaluation time.

2026 archive-research context registered:
`kryptosbot-sanborn-papers-2026` was added to the source registry after checking
the public KryptosBot Sanborn papers archive page. It is explicitly
`archive-context-only`: the page may inform future preregistration rationale,
but it does not add candidate rows, scored observations, plaintext, or promoted
claims.

## Existing Completed 100k Controls

### Pattern Score Candidate Batch

Source artifact: `results/key-tests/pattern-score-control/summary.md`

Key result:

- top row: `WELTZEITUHR` / `A1Z26OneBased` / offset `5`
- observed best: `5/24` matches
- per-candidate empirical p-value: `0.0338`
- batch-level best-match p-value: `0.6573`
- batch-level best-pattern-score p-value: `0.2657`
- promoted: false

Interpretation: `WELTZEITUHR` looked cleaner than short repeated material such
as `CLOCK`, but the candidate-file-level controls do not support promotion.

### Routed Batch Control

Source artifact: `results/key-tests/routed-pattern-control/summary.md`

Key result:

- result rows: 165
- observed best: `3` matches
- routed batch best-match p-value: `1.0000`
- routed batch best-pattern-score p-value: `0.9916`
- promoted: false

Interpretation: route/permutation plus key-material scoring is negative at the
batch level. Do not start another long routed run over the same candidate file.

### Source-Expanded Held-Out Control

Source artifact: `results/key-tests/source-expanded-heldout/summary.md`

Key result:

- candidates: 48
- folds: 6
- every selected training lead scored `0` held-out matches
- every held-out p-value: `1.0000`
- every held-out pattern p-value: `1.0000`
- promoted: false

Interpretation: the expanded source-adjacent candidate lane fails the strongest
current control. More candidate words from the same public-anchor-derived
evidence surface should not be added.

## Runtime Note

A fresh 100k `heldout-key-control` rerun was started for
`results/key-tests/latest-heldout-check` but exceeded the interactive iteration
window and was terminated before writing artifacts. Existing completed 100k
held-out artifacts remain the authoritative evidence for this lane.

## Next Work Gate

The next useful work must satisfy at least one of these:

- introduce genuinely new source-documented evidence with registered source IDs;
- define an independent prediction target before scoring;
- add a structural test that does not use public anchor-derived fragments as the
  discovery input or primary evidence.

Before implementation, validate a lane-specific preregistration:

```bash
cargo run --locked -- validate-preregistration --input <lane-preregistration.json>
```
