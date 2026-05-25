# K4 Experiment Progress Log

This log records command-backed findings that affect what should be tried next.
It is not a claimed solution.

## 2026-05-25: Preregistration Gate

Command:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/non-anchor-position-period-v1.json
```

Result:

- `valid: true`
- `promoted: false`
- warning: no source IDs are attached, acceptable only because this is an
  `independent-prediction-target`

Interpretation: the proposed `non-anchor-position-period-v1` lane is allowed as
a preregistered independent target, but it does not provide evidence by itself.

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

Interpretation: this makes the `non-anchor-position-period-v1` lane executable
as a predeclared target. It does not use public anchor-derived key fragments as
evidence. Future independent evidence can be compared to these residue classes
without retuning the period or residue assignment. Prefer `--all` when the
period has not been justified independently, because that preserves the full
registered-period search surface for later best-of-period controls.
The committed artifact is intentionally evidence-free: it contains K4 position
classes only, excludes public-anchor positions, and does not include fragment
values or candidate key material.

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

Template-derived diagnostic lane populated:
`experiments/preregistrations/new-lane-id.json` now carries the stable lane id
`non-anchor-position-period-diagnostic-v1` and declares the committed target
artifact `experiments/predictions/non-anchor-position-period-diagnostic-v1.json`.
Both `validate-preregistration` and `validate-prediction-artifact` pass. This is
still only a pre-score independent target; it contributes no evidence until a
source-backed non-anchor observation file is added.

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
