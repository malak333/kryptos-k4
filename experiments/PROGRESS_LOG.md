# K4 Experiment Progress Log

This log records command-backed findings that affect what should be tried next.
It is not a claimed solution.

## 2026-06-01: Extended Ciphertext Period-Match Lane Scored Negative

Added and scored `ciphertext-period-match-extended-v1`, a distinct
ciphertext-only shifted same-letter period-match endpoint target. The lane fixes
periods `1..=40` and the top `9` period-match endpoint sets before observation
scoring. It uses only raw K4 ciphertext self-coincidence structure, with public
anchors as an exclusion mask; it does not use public-anchor fragments, candidate
key material, routes, additive fragment values, or prior row-boundary scores for
discovery.

Commands:

```bash
cargo run --locked -- ciphertext-period-match-prior \
  --max-period 40 \
  --top-periods 9 \
  --format json > experiments/predictions/ciphertext-period-match-extended-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-period-match-extended-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-period-match-extended-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- evaluate-ciphertext-period-match \
  --artifact experiments/predictions/ciphertext-period-match-extended-v1.json \
  --preregistration experiments/preregistrations/ciphertext-period-match-extended-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-period-match-observations/cia-k4-row-boundaries-extended-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-period-match-observations/cia-k4-row-boundaries-extended-v1 \
  --format json
```

Result:

- preregistration valid: `true`
- prediction artifact valid: `true`
- artifact kind: `ciphertext-period-match`
- expected/artifact plan count: `9` / `9`
- expected/artifact period count: `9` / `9`
- best selected period-match set: period `2`
- observed hits: `1/6`
- matching position: `36`
- null mean best hits: `1.8447`
- empirical p-value: `0.9978`
- archive valid: `true`
- independent lanes: `85`
- ready for source-backed observations: `85`
- prediction artifacts: `85`
- unique ready prediction targets: `43`
- ciphertext-period-match-position-prior-family lanes: `4`
- ciphertext-period-match-position-prior-family unique ready targets: `4`
- valid source-backed archives: `40`
- source-backed archive correction count: `40`
- minimum source-backed adjusted p-value: `1.0`
- all source-backed archives negative after correction: `true`
- promoted: `false`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-06-01: 4-by-25 Segmented Grid Lane Preregistered

Added `non-anchor-position-grid-4x25-row-v1`, a source-context-only
4-by-25 padded grid-layout row-edge prediction target. The lane uses the
refreshed `kryptosbot-sanborn-papers-2026` archive context only as rationale
for a bounded segmented-cipher/overlay structural rule; it does not score public
anchor fragments, candidate key material, routes, additive fragment values, or
prior row-boundary evidence.

Commands:

```bash
cargo run --locked -- grid-layout-prediction-plan \
  --rows 4 \
  --columns 25 \
  --edge-axis row \
  --format json > experiments/predictions/non-anchor-position-grid-4x25-row-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/non-anchor-position-grid-4x25-row-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/non-anchor-position-grid-4x25-row-v1.json \
  --require-unique-artifact \
  --format json
```

Result:

- preregistration valid: `true`
- prediction artifact valid: `true`
- artifact kind: `grid`
- registered grid edge axis: `row`
- expected/artifact plan count: `4` / `4`
- expected/artifact period count: `4` / `4`
- warnings: none
- promoted: `false`
- independent lanes: `84`
- ready for source-backed observations: `84`
- prediction artifacts: `84`
- unique ready prediction targets: `42`
- grid-layout-family lanes: `5`
- grid-layout-family unique ready targets: `5`

This is a pre-score prediction artifact only. It does not promote a K4
solution, key, route, plaintext, or candidate.

## 2026-06-01: 4-by-25 Segmented Grid Row-Edge Lane Scored Negative

Scored the already-preregistered
`non-anchor-position-grid-4x25-row-v1` artifact against the validated CIA
row-boundary source-backed observation. This was allowed by the evidence gate
because the artifact is a distinct preregistered prediction target; it does not
reuse the row-boundary observation to construct the 4-by-25 grid rule.

Commands:

```bash
cargo run --locked -- validate-grid-observations \
  --artifact experiments/predictions/non-anchor-position-grid-4x25-row-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-4x25-row-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-grid-prediction \
  --artifact experiments/predictions/non-anchor-position-grid-4x25-row-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-4x25-row-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --edge-axis row \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/grid-observations/cia-k4-row-boundaries-4x25-row-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/grid-observations/cia-k4-row-boundaries-4x25-row-v1 \
  --format json
```

Result:

- observed row-edge hits: `1/6`
- matching position: `1`
- null mean: `0.4106`
- empirical p-value: `0.3558`
- archive valid: `true`
- valid source-backed archives: `39`
- source-backed archive correction count: `39`
- minimum source-backed adjusted p-value: `1.0`
- all source-backed archives negative after correction: `true`
- promoted: `false`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-06-01: Sanborn-Papers Archive Context Refreshed

Refreshed the quote-free local snapshot for
`kryptosbot-sanborn-papers-2026` against the current public archive page. The
refresh records newer source-context facts around overlay/null-mask language,
the code-breaker template concept, a Dan Brown-related 4-by-4 segmented-cipher
context, and a separate Sanborn artwork described as duplicating Kryptos text.

Boundary preserved:

- no public K4 plaintext, key material, route, or verified method was added
- no non-anchor K4 observation positions were selected from this context-only
  source
- any future overlay/null-mask or grille-style model must be preregistered
  before scoring and evaluated only against independently sourced non-anchor
  observations
- the source remains `archive-context-only`

This is source-governance progress only. It does not promote a K4 solution,
key, route, plaintext, or candidate.

## 2026-06-01: Post-Terminal Residue-Balance Lane Scored Negative

Scored the already-preregistered
`ciphertext-residue-balance-post-terminal-moduli-v1` artifact against the
validated CIA row-boundary source-backed observation. This closes the remaining
post-terminal residue-balance archive gap without adding new key material,
plaintext, routes, or public-anchor-derived evidence.

Commands:

```bash
cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-post-terminal-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-post-terminal-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-post-terminal-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-post-terminal-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-post-terminal-moduli-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-post-terminal-moduli-v1 \
  --format json
```

Result:

- selected modulus/residue: `55` / `0`
- observed hits: `1/6`
- matching position: `1`
- null mean: `0.5472`
- empirical p-value: `0.5141`
- promoted: `false`
- archive valid: `true`
- valid source-backed archives: `38`
- source-backed archive correction count: `38`
- minimum source-backed adjusted p-value: `1.0`
- all source-backed archives negative after correction: `true`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-06-01: Narrow Period-Match Lane Scored Negative

Added `ciphertext-period-match-narrow-v1`, a distinct ciphertext-only
shifted same-letter period-match lane that fixes the top 3 periods over the
existing period range `1..=20` before any source-backed observation scoring.
The lane uses public anchors only as an exclusion mask and does not use
known-plaintext fragments, candidate words, routes, or prior source-backed
observation hits for discovery.

Committed files:

- `experiments/preregistrations/ciphertext-period-match-narrow-v1.json`
- `experiments/predictions/ciphertext-period-match-narrow-v1.json`
- `results/ciphertext-period-match-observations/cia-k4-row-boundaries-narrow-v1/`

Commands:

```bash
cargo run --locked -- ciphertext-period-match-prior \
  --top-periods 3 \
  --format json > experiments/predictions/ciphertext-period-match-narrow-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-period-match-narrow-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-period-match-narrow-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- evaluate-ciphertext-period-match \
  --artifact experiments/predictions/ciphertext-period-match-narrow-v1.json \
  --preregistration experiments/preregistrations/ciphertext-period-match-narrow-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-period-match-observations/cia-k4-row-boundaries-narrow-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-period-match-observations/cia-k4-row-boundaries-narrow-v1 \
  --format json
```

Result:

- selected periods: `1`, `4`, `7`
- best selected period: `7`
- matching period-match positions: `1`
- observed hits: `1/6`
- null mean: `1.4145`
- empirical p-value: `0.9051`
- promoted: `false`
- archive valid: `true`
- valid source-backed archives: `37`
- source-backed archive correction count: `37`
- minimum source-backed adjusted p-value: `1.0`
- all source-backed archives negative after correction: `true`

Current inventory markers:

- independent lanes: `83`
- ready for source-backed observations: `83`
- prediction artifacts: `83`
- unique ready prediction targets: `41`
- ciphertext-period-match-position-prior-family lanes: `3`
- ciphertext-period-match-position-prior-family unique ready targets: `3`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-06-01: Mid Adjacent-Contrast Lane Scored Negative

Added `ciphertext-adjacent-contrast-mid-v1`, a distinct ciphertext-only
adjacent-contrast lane that fixes the top 16 interior non-anchor positions by
predeclared left/right neighbor contrast in Kryptos alphabet order. The lane
uses public anchors only as an exclusion mask and does not use known-plaintext
fragments, candidate words, routes, or prior source-backed observation hits for
discovery.

Committed files:

- `experiments/preregistrations/ciphertext-adjacent-contrast-mid-v1.json`
- `experiments/predictions/ciphertext-adjacent-contrast-mid-v1.json`
- `results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-mid-v1/`

Implementation note:

- `validate-evaluation-archive` now honors preregistered custom
  `ciphertext_adjacent_contrast_top` and `ciphertext_window_balance_*`
  parameters instead of comparing every archive to only the default committed
  artifact shape.

Commands:

```bash
cargo run --locked -- ciphertext-adjacent-contrast-prior \
  --top 16 \
  --format json > experiments/predictions/ciphertext-adjacent-contrast-mid-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-adjacent-contrast-mid-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-adjacent-contrast-mid-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- evaluate-ciphertext-adjacent-contrast \
  --artifact experiments/predictions/ciphertext-adjacent-contrast-mid-v1.json \
  --preregistration experiments/preregistrations/ciphertext-adjacent-contrast-mid-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-mid-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-mid-v1 \
  --format json
```

Result:

- matched adjacent-contrast positions: `5, 37`
- observed hits: `2/6`
- null mean: `1.31194`
- empirical p-value: `0.3911`
- promoted: `false`
- archive valid: `true`
- valid source-backed archives: `36`
- source-backed archive correction count: `36`
- minimum source-backed adjusted p-value: `1.0`
- all source-backed archives negative after correction: `true`

Current inventory markers:

- independent lanes: `82`
- ready for source-backed observations: `82`
- prediction artifacts: `82`
- unique ready prediction targets: `40`
- ciphertext-adjacent-contrast-position-prior-family lanes: `3`
- ciphertext-adjacent-contrast-position-prior-family unique ready targets: `3`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-06-01: Width-7 Grid Row Lane Scored Against CIA Row Boundaries

Scored the distinct `non-anchor-position-grid-width7-row-v1` 14-by-7 row-edge
artifact against the existing CIA sculpture row-boundary observation file. This
is allowed by the current frontier because the artifact is a distinct
pre-registered prediction target; it does not create a new source-backed
observation.

Commands:

```bash
cargo run --locked -- evaluate-grid-prediction \
  --artifact experiments/predictions/non-anchor-position-grid-width7-row-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-width7-row-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --edge-axis row \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/grid-observations/cia-k4-row-boundaries-width7-row-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/grid-observations/cia-k4-row-boundaries-width7-row-v1 \
  --format json
```

Result:

- observed selected-edge hits: `2/6`
- empirical p-value: `0.5590`
- archive valid: `true`
- valid source-backed archives: `34`
- source-backed archive correction count: `34`
- minimum source-backed adjusted p-value: `1.0`
- all source-backed archives negative after correction: `true`
- promoted: `false`

Interpretation: the width-7 grid row-edge hypothesis is negative/non-significant
on the existing source-backed row-boundary observation. This closes that
artifact against the current observation; future progress still requires a new
eligible source, changed source-backed observation boundary, or another
distinct preregistered prediction target.

## 2026-06-01: Width-7 Grid Prediction Lane Added

Added dimension-aware grid-layout prediction artifacts and a new
`non-anchor-position-grid-width7-row-v1` lane. The new lane fixes a 14-by-7
row-major grid with row-edge scoring before any future source-backed
observation file is selected or evaluated.

This is a distinct prediction artifact from the existing 7-by-14 grid lanes.
It is grounded only in the registered `kryptos-today-progress-2026`
methodology-context width-7 rationale, so it does not use that source as scored
evidence and does not use candidate material, route results, plaintext claims,
or public known-plaintext fragment values.

Validation commands for this lane:

```bash
cargo run --locked -- grid-layout-prediction-plan \
  --rows 14 \
  --columns 7 \
  --edge-axis row \
  --format json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/non-anchor-position-grid-width7-row-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/non-anchor-position-grid-width7-row-v1.json \
  --require-unique-artifact \
  --format json
```

Current boundary: this is a pre-score structural target only. It does not add a
source-backed observation file, promote evidence, or claim a solution.

Current inventory markers after this lane:

- independent lanes: `80`
- ready for source-backed observations: `80`
- prediction artifacts: `80`
- unique ready prediction targets: `38`
- grid-layout-family lanes: `4`
- grid-layout-family unique ready targets: `4`

## 2026-06-01: Next Evidence Gate Summary Mode Added

Added `next-evidence-gate --summary` so automation and future K4 work can read
the current source-backed evidence boundary without expanding the full gate
table or all archived evidence-support details.

The summary preserves the fields needed to avoid repeating stopped lanes:

- `next_action_kind`
- `blocking_conditions`
- source-backed archive counts and corrected p-value status
- used and unused eligible source IDs
- claim-verification archive counts
- next-check commands, including `--require-unique-artifact`
- required source-backed observation fields

Validation:

```bash
cargo run --locked -- next-evidence-gate --summary --format json
cargo test --locked --test cli_e2e next_evidence_gate
cargo run --locked -- release-check --format json
cargo test --locked
```

Current boundary: this is operational tooling only. It does not add evidence,
score a source, promote a candidate, or claim a solution.

## 2026-06-01: SSRN Full Derivation Claim Quarantined

Added `ssrn-bonifacino-full-derivation-2025`, the companion SSRN full
derivation paper for the Weltzeituhr error-key claim family, after live search
surfaced it as a separate record from the already-registered error-key,
running-key, and generative papers.

This is a metadata-only, quote-free source snapshot. It is registered as
`unverified-solution-claim` and is not eligible for scored independent
observations, candidate material, or release-facing plaintext. A direct
unauthenticated PDF fetch to `/private/tmp` returned HTTP 403, so no paper
text, plaintext, key stream, reconciliation table, or mechanism payload was
stored.

Validation:

```bash
cargo run --locked -- validate-source-archive \
  --source-id ssrn-bonifacino-full-derivation-2025 \
  --input sources/archives/ssrn-bonifacino-full-derivation-2025-2026-06-01.md \
  --format json

cargo run --locked -- claim-verification-status --format json

cargo run --locked -- release-check --format json
```

Current boundary:

- registered source type: `community-solution-claim`
- allowed use: `unverified-solution-claim`
- recommended intake: `claim-input-plan`
- promoted: `false`

## 2026-06-01: Quarantined Claim Input Plans Added

Added `claim-input-plan`, a local-only intake checklist for quarantined external
K4 claim sources. The command maps one registered `unverified-solution-claim`
source ID to temporary `/private/tmp` plaintext/key/table/bundle/mechanism
paths and prints the matching safe verifier commands without creating,
printing, storing, or committing any claim material.

This improves the next claim-screening step for the three unarchived SSRN
Bonifacino claim sources while preserving the quarantine boundary: claim inputs
stay outside the repository, and only non-leaking verifier summaries/results are
eligible for committed archives.

Validation:

```bash
cargo run --locked -- claim-input-plan \
  --source-id ssrn-bonifacino-running-key-2025 \
  --format json

cargo test --locked --test cli_e2e claim_input_plan_reports_local_only_intake_paths

cargo run --locked -- release-check --format json

cargo test --locked
```

Current boundary:

- source IDs must have `allowed_use` = `unverified-solution-claim`
- `claim-verification-status` links each claim source to its exact
  `claim-input-plan` command
- non-claim sources are rejected by `claim-input-plan`
- generated plans are quarantine checklists only, not source-backed evidence
- promoted: `false`

## 2026-06-01: Narrow Adjacent-Contrast Prediction Target Added

Added `ciphertext-adjacent-contrast-narrow-v1`, a ciphertext-only adjacent
contrast lane that fixes a distinct top-12 non-anchor target from the existing
predeclared adjacent-neighbor contrast rule.

This lane is a preregistered prediction target only. It uses K4 ciphertext and
the fixed public-anchor exclusion mask as discovery inputs; it does not score
or mine public anchor fragments as evidence.

Validation:

```bash
cargo run --locked -- ciphertext-adjacent-contrast-prior \
  --top 12 \
  --format json > experiments/predictions/ciphertext-adjacent-contrast-narrow-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-adjacent-contrast-narrow-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-adjacent-contrast-narrow-v1.json \
  --require-unique-artifact \
  --format json
```

Current committed target:

- artifact: `experiments/predictions/ciphertext-adjacent-contrast-narrow-v1.json`
- selected positions: `5, 6, 7, 37, 38, 39, 46, 53, 75, 78, 81, 87`
- independent lanes: `79`
- ready for source-backed observations: `79`
- prediction artifacts: `79`
- unique prediction artifacts: `37`
- unique ready prediction artifacts: `37`
- unique ready prediction targets: `37`
- ciphertext-adjacent-contrast-position-prior-family lanes: `2`
- ciphertext-adjacent-contrast-position-prior-family unique ready targets: `2`
- promoted: `false`

## 2026-06-01: Ultra-Wide Window-Balance Prediction Target Added

Added `ciphertext-window-balance-ultra-wide-v1`, a ciphertext-only local-window
balance lane that fixes a distinct top-12 non-anchor target using ultra-wide
window widths `[15, 17, 19]`.

This lane is a preregistered prediction target only. It uses K4 ciphertext and
the fixed public-anchor exclusion mask as discovery inputs; it does not score
or mine public anchor fragments as evidence.

Validation:

```bash
cargo run --locked -- ciphertext-window-balance-prior \
  --top 12 \
  --window-widths 15,17,19 \
  --format json > experiments/predictions/ciphertext-window-balance-ultra-wide-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-window-balance-ultra-wide-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-window-balance-ultra-wide-v1.json \
  --require-unique-artifact \
  --format json
```

Current committed target:

- artifact: `experiments/predictions/ciphertext-window-balance-ultra-wide-v1.json`
- selected positions: `58, 59, 60, 61, 62, 76, 77, 80, 81, 82, 87, 88`
- independent lanes: `78`
- ready for source-backed observations: `78`
- prediction artifacts: `78`
- unique prediction artifacts: `36`
- unique ready prediction artifacts: `36`
- unique ready prediction targets: `36`
- ciphertext-window-balance-position-prior-family lanes: `5`
- ciphertext-window-balance-position-prior-family unique ready targets: `5`
- promoted: `false`

## 2026-05-31: Claim-Verification Status Guidance Added

Extended `claim-verification-status` with per-source verification guidance for
the quarantined solution-claim lane.

Purpose:

- keep the existing quarantine inventory and non-leaking archive status
- show whether each registered claim source already has a verification archive
- list the local verifier commands appropriate to each claim family
- list required temporary local inputs without committing or printing plaintext,
  key streams, plaintext-bearing reconciliation tables, or mechanism bundles

This is still a verifier-routing aid only. It does not promote any claim and
does not convert claim material into source-backed evidence.

Validation:

```bash
cargo run --locked -- claim-verification-status --format json
cargo run --locked -- release-check --format json
cargo test --locked
```

Current result:

- quarantined claim sources: `6`
- claim verification archives: `3`
- unarchived SSRN claim sources now carry explicit local input/verifier
  guidance
- promoted: `false`

## 2026-05-31: Weltzeituhr Error-Key SSRN Metadata Corrected

Corrected the registered SSRN source metadata for
`ssrn-bonifacino-weltzeituhr-error-key-2025` after live source verification.

Current source metadata:

- canonical URL: `https://ssrn.com/abstract=5779863`
- title: `The Weltzeituhr Error Key: A Mechanically Reproducible Decryption of Kryptos K4`
- posted date: `2025-12-23`
- written date: `2025-11-18`
- allowed use: `unverified-solution-claim`
- promoted: `false`

This is provenance hygiene only. The source remains quarantined and does not
become source-backed evidence, candidate material, key-stream evidence, or a
claimed solution.

## 2026-05-31: Mid Window-Balance Prediction Target Added

Added `ciphertext-window-balance-mid-v1`, a ciphertext-only local-window
balance lane that fixes a distinct top-16 non-anchor target using window widths
`[5, 7, 9]`.

This lane is a preregistered prediction target only. It uses K4 ciphertext and
the fixed public-anchor exclusion mask as discovery inputs; it does not score
or mine public anchor fragments as evidence.

Validation:

```bash
cargo run --locked -- ciphertext-window-balance-prior \
  --top 16 \
  --window-widths 5,7,9 \
  --format json > experiments/predictions/ciphertext-window-balance-mid-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-window-balance-mid-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-window-balance-mid-v1.json \
  --require-unique-artifact \
  --format json
```

Current readiness markers:

- lane count: `77`
- independent lanes: `77`
- ready for source-backed observations: `77`
- prediction artifacts: `77`
- unique prediction artifacts: `35`
- unique ready prediction artifacts: `35`
- unique ready prediction targets: `35`
- ciphertext-window-balance-position-prior-family lanes: `4`
- ciphertext-window-balance-position-prior-family unique ready targets: `4`
- promoted: `false`

The lane remains unscored until future source-backed non-anchor observations
pass the family-specific validator and evaluator.

## 2026-05-31: Source Frontier Correction-Aware Boundary

Updated `source-frontier` so the source-use frontier reports both the raw
archive support-status boundary and the source-archive-corrected boundary.

Validation:

```bash
cargo run --locked -- source-frontier --summary --format json
```

Current correction-aware markers:

- valid source-backed archives: `33`
- raw all-negative flag: `false`
- source-backed archive correction count: `33`
- minimum empirical p-value: `< 0.05`
- minimum adjusted p-value: `1.0`
- all source-backed archives negative after correction: `true`
- frontier blocker:
  `source-backed-evidence-negative-or-non-significant-after-correction`
- promoted: `false`

This preserves the raw follow-up signal while making the corrected stop/replan
boundary explicit before any future evidence work.

## 2026-05-31: Focused Claim-Verification Status Added

Added a focused `claim-verification-status` command for the quarantined
solution-claim lane.

Purpose:

- list registered `unverified-solution-claim` source IDs
- list committed non-leaking claim-verification archives
- list quarantined claim sources still missing a local verification archive
- print the safe verifier commands without printing or storing claimed
  plaintext, key streams, or plaintext-bearing tables

This does not promote any claim and does not convert claim material into
source-backed evidence.

Validation:

```bash
cargo run --locked -- claim-verification-status --format json
```

Current result:

- quarantined claim sources: `6`
- claim verification archives: `3`
- sources still without verification archive:
  `ssrn-bonifacino-running-key-2025`,
  `ssrn-bonifacino-weltzeituhr-error-key-2025`, and
  `ssrn-bonifacino-generative-running-key-2025`
- promoted: `false`

## 2026-05-31: Stein Courtyard-Crypto Methodology Source Added

Registered a quote-free methodology-context source snapshot for David Stein's
publicly mirrored CIA article on solving the earlier Kryptos sections:

- source id: `stein-courtyard-crypto`
- archive: `sources/archives/stein-courtyard-crypto-2026-05-31.md`
- source packet: `sources/source-packet.md`
- boundary: solved-section method history only; no K4 plaintext, key material,
  route, scored non-anchor position set, or candidate promotion

Validation:

```bash
cargo run --locked -- validate-source-archive \
  --source-id stein-courtyard-crypto \
  --input sources/archives/stein-courtyard-crypto-2026-05-31.md \
  --format json

cargo run --locked -- source-frontier --summary --format json
```

Result:

- source archive valid: `true`
- source count: `29`
- scored-observation eligible sources: `2`
- context-only sources: `21`
- valid source-backed archives: `33`
- promoted: `false`

Practical consequence: Stein's solved-section methods are now documented as
methodology context for future preregistration rationale and stopped-lane
boundaries, not as independent K4 evidence. The current source-frontier action
is unchanged: future scored progress still requires a new eligible
`public-facts-only` source, a scored-position update to an eligible archive, or
a genuinely distinct prediction artifact.

## 2026-05-31: CT-Perturbation Lane Scored And Rejected

Added and scored a source-grounded CT-perturbation lane:

- preregistration: `experiments/preregistrations/ciphertext-ct-perturbation-v1.json`
- prediction artifact: `experiments/predictions/ciphertext-ct-perturbation-v1.json`
- archive:
  `results/ciphertext-ct-perturbation-observations/cia-k4-row-boundaries-v1`
- source rationale: `kryptosbot-findings-2026` methodology-context note about
  the unresolved CT-perturbation/symbol-swap anomaly
- fixed target positions: non-anchor C/T ciphertext positions `36`, `38`,
  `51`, `81`, `83`, and `95`

Validation:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-ct-perturbation-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-ct-perturbation-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- validate-ciphertext-ct-perturbation-observations \
  --artifact experiments/predictions/ciphertext-ct-perturbation-v1.json \
  --preregistration experiments/preregistrations/ciphertext-ct-perturbation-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-ciphertext-ct-perturbation \
  --artifact experiments/predictions/ciphertext-ct-perturbation-v1.json \
  --preregistration experiments/preregistrations/ciphertext-ct-perturbation-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-ct-perturbation-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-ct-perturbation-observations/cia-k4-row-boundaries-v1 \
  --format json
```

Result:

- preregistration valid: `true`
- prediction artifact valid: `true`
- observation validation valid: `true`
- evaluation archive valid: `true`
- artifact kind: `ciphertext-ct-perturbation`
- artifact plan count: `6`
- observed CT hits: `1/6`
- empirical p-value: `0.4139`
- source-backed adjusted p-value: `1.0000`
- promoted: `false`

Observed inventory after scoring:

- independent lanes: `75`
- ready for source-backed observations: `75`
- invalid lanes: `0`
- evaluator-pending lanes: `0`
- prediction artifacts: `75`
- unique ready prediction targets: `33`
- duplicate prediction artifact groups: `1`
- ciphertext-ct-perturbation-position-prior-family lanes: `1`
- ciphertext-ct-perturbation-position-prior-family unique ready targets: `1`

Practical consequence: CT-perturbation is now a committed, distinct target with
a family-specific source-backed observation validator and evaluator. The
committed CIA row-boundary observation does not support it after seeded same-size
non-anchor position null controls and source-archive correction.

## 2026-05-31: Wide Window-Balance Target Registered And Rejected

Added a distinct ciphertext-only local-window balance prediction target:

- preregistration: `experiments/preregistrations/ciphertext-window-balance-wide-v1.json`
- prediction artifact: `experiments/predictions/ciphertext-window-balance-wide-v1.json`
- rule: centered local-window balance over widths `[9, 11, 13]`, top 12
  non-anchor positions, public anchors used only as an exclusion mask
- archive:
  `results/ciphertext-window-balance-observations/cia-k4-row-boundaries-wide-v1`

Validation and scoring:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-window-balance-wide-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-window-balance-wide-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- validate-ciphertext-window-balance-observations \
  --artifact experiments/predictions/ciphertext-window-balance-wide-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-wide-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-ciphertext-window-balance \
  --artifact experiments/predictions/ciphertext-window-balance-wide-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-wide-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-window-balance-observations/cia-k4-row-boundaries-wide-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-window-balance-observations/cia-k4-row-boundaries-wide-v1 \
  --format json
```

Result:

- window-balance hits: `0/6`
- null mean hits: `0.98574`
- empirical p-value: `1.0000`
- promoted: `false`
- next-evidence-gate after this archive: `74` ready lanes, `32` unique ready
  prediction targets, `32` valid source-backed archives, source-backed adjusted
  minimum p-value `1.0000`, and action
  `new-source-backed-rationale-or-distinct-prediction-artifact`

Observed inventory after registration and archive:

- independent lanes: `74`
- ready for source-backed observations: `74`
- invalid lanes: `0`
- prediction artifacts: `74`
- unique ready prediction targets: `32`
- duplicate prediction artifact groups: `1`
- ciphertext-window-balance-position-prior-family lanes: `3`
- ciphertext-window-balance-position-prior-family unique ready targets: `3`

Practical consequence: the wide local-window balance artifact was a valid
distinct target, but the current CIA row-boundary observation rejects it. This
does not produce a key, route, plaintext, or candidate promotion.

## 2026-05-31: SolveKryptos Mechanism Failure Archived

Archived the latest plaintext-free mechanism verifier result:

- result: `results/claim-verifications/solvekryptos-mechanism-20260531-latest/result.json`
- summary: `results/claim-verifications/solvekryptos-mechanism-20260531-latest/summary.md`
- source snapshot updated: `sources/archives/solvekryptos-2026-05-27.md`

Command:

```bash
cargo run --locked -- verify-claim-mechanism \
  --directory /private/tmp/k4-latest-solvekryptos/solvekryptos-canonical-bundle \
  --source-id solvekryptos-2026-claim \
  --format json
```

Result:

- required mechanism files: `8/8`
- f-table, helper-card, Z1/Z2 delta, control-card, and Z2 helper-path checks:
  matched
- Y-template rule checks: `27/31`
- Y-template gate-map checks: `27/31`
- structural checks passed: `false`
- promoted: `false`

The non-leaking diagnostic localizes the Y-pass disagreements to Y positions
`23`, `27`, `28`, and `29`, corresponding to K4 positions `27`, `31`, `32`,
and `33`. The archive stores only structural counts and position/gate
diagnostics; it does not store claimed plaintext, key material, or
plaintext-bearing reconciliation rows.

Practical consequence: the SolveKryptos claim remains quarantined. Its
top-level bundle consistency checks are not enough to promote it because the
published helper machinery still fails the mechanism verifier.

## 2026-05-31: Terminal Residue-Balance Target Registered

Added a distinct ciphertext-only residue-balance prediction target:

- preregistration: `experiments/preregistrations/ciphertext-residue-balance-terminal-moduli-v1.json`
- prediction artifact: `experiments/predictions/ciphertext-residue-balance-terminal-moduli-v1.json`
- rule: for each modulus `48..=54`, select the non-anchor residue class with
  highest distinct ciphertext-letter rate, tie-breaking by larger position
  count and then lower residue number

Validation:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-residue-balance-terminal-moduli-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-terminal-moduli-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- independent-lane-status --format json
```

Observed inventory after registration:

- independent lanes: `72`
- ready for source-backed observations: `72`
- invalid lanes: `0`
- prediction artifacts: `72`
- unique ready prediction targets: `30`
- duplicate prediction artifact groups: `1`
- ciphertext-residue-balance-position-prior-family lanes: `8`
- ciphertext-residue-balance-position-prior-family unique ready targets: `8`

Practical consequence: this adds one more predeclared, unique future-observation
target. It is not evidence by itself, does not score public anchors, and does
not promote candidate material, key stream, route, or plaintext.

## 2026-05-31: Hyper-Extreme Residue-Balance Target Registered

Added a distinct ciphertext-only residue-balance prediction target:

- preregistration: `experiments/preregistrations/ciphertext-residue-balance-hyper-extreme-moduli-v1.json`
- prediction artifact: `experiments/predictions/ciphertext-residue-balance-hyper-extreme-moduli-v1.json`
- rule: for each modulus `41..=47`, select the non-anchor residue class with
  highest distinct ciphertext-letter rate, tie-breaking by larger position
  count and then lower residue number

Validation:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-residue-balance-hyper-extreme-moduli-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-hyper-extreme-moduli-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- independent-lane-status --format json
```

Observed inventory after registration:

- independent lanes: `71`
- ready for source-backed observations: `71`
- invalid lanes: `0`
- prediction artifacts: `71`
- unique ready prediction targets: `29`
- duplicate prediction artifact groups: `1`
- ciphertext-residue-balance-position-prior-family lanes: `7`
- ciphertext-residue-balance-position-prior-family unique ready targets: `7`

Practical consequence: this adds one more predeclared, unique future-observation
target. It is not evidence by itself, does not score public anchors, and does
not promote candidate material, key stream, route, or plaintext.

## 2026-05-31: Stephen Bishop PRLog K4 Claim Quarantined

Added a quote-free local source snapshot for a public PRLog PDF claim:

- `prlog-bishop-k4-plaintext-2020`

This is distinct from the earlier checked PRLog URL ending in `12839961`,
which resolved to unrelated charity press-release content and remains
unregistered. The newly registered `12845348` PDF is a usable public claim
artifact, but it is still registered only as `unverified-solution-claim`.

Validation:

```bash
cargo run --locked -- validate-source-archive \
  --source-id prlog-bishop-k4-plaintext-2020 \
  --input sources/archives/prlog-bishop-k4-plaintext-2020-2026-05-31.md \
  --format json

cargo run --locked -- verify-plaintext-claim \
  --input /private/tmp/prlog-bishop-12845348-claim.txt \
  --source-id prlog-bishop-k4-plaintext-2020 \
  --format json
```

Observed quarantine-check result: the temporary claim normalized to 97 letters,
matched the expected K4 length, preserved all four registered public anchors,
reported all 26 implied shift values, 71 repeated shift values, and maximum
shift bucket count 10. `promoted_candidate` remained `false`.

Practical consequence: public claim intake is broader, but the source remains
quarantined and does not change the scoring frontier. The repository stores no
claimed plaintext and no plaintext-bearing artifact.

## 2026-05-31: Narrow Window-Balance Target Registered

Added a distinct ciphertext-only local-window balance prediction target:

- preregistration: `experiments/preregistrations/ciphertext-window-balance-narrow-v1.json`
- prediction artifact: `experiments/predictions/ciphertext-window-balance-narrow-v1.json`
- rule: centered local-window balance over widths `[3, 5]`, top 12 non-anchor
  positions, public anchors used only as an exclusion mask

Validation:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-window-balance-narrow-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-window-balance-narrow-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- next-evidence-gate --format json
```

Observed inventory after registration:

- independent lanes: `70`
- ready for source-backed observations: `70`
- invalid lanes: `0`
- prediction artifacts: `70`
- unique ready prediction targets: `28`
- duplicate prediction artifact groups: `1`
- ciphertext-window-balance-position-prior-family lanes: `2`
- ciphertext-window-balance-position-prior-family unique ready targets: `2`

Practical consequence: this creates a sharper predeclared target for future
source-backed non-anchor observations, but it is still not evidence by itself.
No candidate material, key stream, route, plaintext, or promotion is claimed.

## 2026-05-31: Dear Cipher Public K4 Claim Quarantined

Added a quote-free local source snapshot for an additional public K4 solution
claim surface:

- `dearcipher-k4-claim-2026`

The source is registered as `unverified-solution-claim`. It is not eligible
for scored independent position observations and is not source-backed evidence.
The repository snapshot records only metadata, high-level claim boundaries, and
quarantine-check results; no claimed plaintext, key stream, route, table, or
plaintext-bearing artifact is stored.

Validation:

```bash
cargo run --locked -- validate-source-archive \
  --source-id dearcipher-k4-claim-2026 \
  --input sources/archives/dearcipher-k4-claim-2026-05-31.md \
  --format json

cargo run --locked -- verify-plaintext-claim \
  --input /private/tmp/dearcipher-k4-claim.txt \
  --source-id dearcipher-k4-claim-2026 \
  --format json
```

Observed quarantine-check result: the temporary claim normalized to 97 letters,
matched the expected K4 length, preserved all four registered public anchors,
reported all 26 implied shift values, 71 repeated shift values, and maximum
shift bucket count 8. `promoted_candidate` remained `false`.

A stale-looking PRLog PDF URL surfaced during the public-source scan, but a
2026-05-31 temporary download resolved to unrelated charity press-release
content rather than a usable K4 claim artifact. It was not registered as a K4
claim source.

Practical consequence: public claim intake is broader, but the evidence
frontier is unchanged for scoring. Any future use of this source must pass
temporary local verifier commands such as `verify-plaintext-claim`,
`verify-running-key-claim`, or a claim-specific mechanism verifier without
adding release-facing plaintext-bearing artifacts.

## 2026-05-31: Latest Public-Source Scan Added No Scoring Evidence

A live source scan on 2026-05-31 checked current public reporting and project
pages for new K4 evidence before adding another experiment lane. The reviewed
surfaces included:

- Popular Mechanics final-clues reporting:
  `https://www.popularmechanics.com/science/math/a69447312/kryptos-puzzle-clues/`
- RR Auction's public Kryptos archive lot page:
  `https://www.rrauction.com/jim-sanborn-kryptos-k4-solution-auction`
- Kryptos.today progress/status pages:
  `https://kryptos.today/` and `https://kryptos.today/progress`
- Search results for recent K4 solution claims and Sanborn/archive updates.

Result: no new eligible source-backed non-anchor observation positions, public
key stream, route, reusable coding rule, or verifier-compatible plaintext claim
was found. The RR Auction lot is already registered as
`rr-auction-kryptos-archive-2025` with a quote-free local snapshot and remains
`archive-context-only`; Popular Mechanics corroborates already registered
public-clue/archive context; Kryptos.today remains methodology/progress context
only. None of these sources changes the current scoring frontier.

Current command-backed frontier:

```bash
cargo run --locked -- source-frontier --summary --format markdown
cargo run --locked -- next-evidence-gate --format json
```

Observed frontier: `24` registered sources, `2` scored-observation eligible
sources, `1` committed source-backed observation file, `27` valid
source-backed evaluation archives, all source-backed archives
negative/non-significant, `20` context-only sources, `2` quarantined claims,
and `promoted=false`.

Practical consequence: do not add another public-anchor-derived key-material,
routed-key, held-out public-group, W-delimiter, ciphertext-prior, or
row-boundary scoring lane from these sources. The next scoring step still
requires a new eligible source, a changed eligible source archive with explicit
non-anchor scored-position markers, a verifier-compatible local claim artifact,
or a genuinely distinct preregistered prediction artifact before evaluation.

## 2026-05-31: SSRN Running-Key Claim Quarantined

Added `ssrn-bonifacino-running-key-2025`, a quote-free local source snapshot
for the SSRN running-key candidate paper by Ryan Bonifacino.

- source record: `ssrn-bonifacino-running-key-2025`
- local archive:
  `sources/archives/ssrn-bonifacino-running-key-2025-2026-05-31.md`
- allowed use: `unverified-solution-claim`
- boundary: no claimed plaintext, published key stream, route, or
  plaintext-bearing table is copied or promoted

Validation:

```bash
cargo run --locked -- validate-source-archive \
  --source-id ssrn-bonifacino-running-key-2025 \
  --input sources/archives/ssrn-bonifacino-running-key-2025-2026-05-31.md \
  --format json
cargo run --locked -- source-frontier --format json
```

Result: the archive validates and `source-frontier` classifies the paper as a
second quarantined claim source. The evidence frontier remains unchanged for
scoring: `23` registered sources, `2` scored-observation eligible sources, `1`
committed source-backed observation file, `27` valid source-backed evaluation
archives, all negative/non-significant, and no promoted candidate.

## 2026-05-31: Scientific American Archive-Discovery Context Registered

Added `scientific-american-2026-kryptos-cracked`, a quote-free
archive-context source for Scientific American's October 2025 Kryptos archive
discovery reporting.

- source record: `scientific-american-2026-kryptos-cracked`
- local archive:
  `sources/archives/scientific-american-2026-kryptos-cracked-2026-05-31.md`
- allowed use: `archive-context-only`
- boundary: no public plaintext, key material, route, candidate stream, or
  scoreable non-anchor K4 observation positions are copied or promoted

This expands the registered source registry from 21 to 22 sources while keeping
the evidence frontier unchanged: 27 valid source-backed archives, all
negative/non-significant, and no promoted candidate. The source is useful for
claim-boundary and archive-discovery context only.

## 2026-05-31: W-Delimiter Source-Context Diagnostic Stopped

Checked the registered KryptosBot findings page's W-delimiter context against
the existing source-backed CIA row-boundary observation before adding a larger
W-delimiter evaluator family. This was a source-context diagnostic only: the
KryptosBot page supplies rationale, not scoreable positions or a plaintext/key
claim.

Fixed diagnostic inputs:

- K4 non-anchor W positions: `21,37,49,59,75`
- Existing source-backed row-boundary observation:
  `experiments/position-observations/cia-k4-row-boundaries-v1.json`
- Observed row-boundary positions: `1,4,5,36,37,97`
- Hit count: `1/6` at position `37`
- Same-size non-anchor hypergeometric null: population `73`, W targets `5`,
  draws `6`, null mean `0.4110`, `p>=1 = 0.3570`

Practical consequence: the W-delimiter source-context diagnostic is
negative/non-significant against the only current committed source-backed
position observation. Do not spend a full implementation pass on a dedicated
W-delimiter evaluator unless a future eligible source supplies independent
non-anchor observations or a stronger pre-score structural prediction target.

## 2026-06-01: W-Delimiter Coordinate Reconciliation Recorded

Added a quote-free coordinate reconciliation for the registered
`kryptosbot-findings-2026` methodology-context source:

- reconciliation artifact:
  `experiments/coordinate-reconciliations/kryptosbot-w-delimiter-v1.md`
- source archive refreshed:
  `sources/archives/kryptosbot-findings-2026-05-31.md`
- repo canonical K4 one-based W positions: `21,37,49,59,75`
- external source-side W-delimiter labels observed during refresh:
  `20,36,48,58,74`

Practical consequence: future W-delimiter work must use repo canonical
one-based positions `21,37,49,59,75` unless an alternate coordinate convention
is explicitly preregistered and validated before scoring. This is a coordinate
guardrail only; it does not reopen the stopped W-delimiter lane, and it does not
promote plaintext, key material, route, or mechanism evidence.

## 2026-06-01: SolveKryptos Current v13 Mechanism Rechecked

Downloaded the current public SolveKryptos canonical bundle only to
`/private/tmp` after the public resources page labeled the bundle v13, then
ran the existing non-leaking quarantine verifiers.

- source: `solvekryptos-2026-claim`
- archived mechanism result:
  `results/claim-verifications/solvekryptos-current-v13-20260601/`
- `verify-claim-bundle`: passed internal bundle/reconciliation checks
- `verify-claim-mechanism`: failed
- Y-template rule checks: `27/31`
- Y-template gate-map checks: `27/31`
- failed Y positions: `23,27,28,29`
- corresponding K4 positions: `27,31,32,33`

Practical consequence: the current v13 bundle remains internally compatible at
the reconciliation/file level, but the stricter mechanism verifier still
rejects full helper-machinery consistency. No plaintext, key stream,
plaintext-bearing reconciliation table, or mechanism bundle was committed, and
the claim remains quarantined and unpromoted.

## 2026-05-31: KryptosBot Findings Source Registered

Added `kryptosbot-findings-2026` as a quote-free local source snapshot for the
public KryptosBot findings/open-questions page. This is methodology context
only: it records W-delimiter, CT-perturbation, HILL-tableau, open-question, and
negative-search boundary context, but it does not add candidate material, a key
stream, a route, plaintext, or scoreable non-anchor observations.

Source archive:

```bash
cargo run --locked -- validate-source-archive \
  --source-id kryptosbot-findings-2026 \
  --input sources/archives/kryptosbot-findings-2026-05-31.md
```

Practical consequence: this gives future work a source-grounded rationale for a
bounded W-delimiter, CT-perturbation, or Stehle-regularity preregistration, but
it does not itself change the evidence frontier. Future scored use still
requires a separate prediction artifact, source-backed observation file when
applicable, and seeded controls before interpreting any result.

## 2026-05-31: Stehle Regularity Planning Lane Registered

Added `ciphertext-stehle-regularity-v1` as a source-grounded planning lane for
the Stehle local regularity described by the registered
`kryptosbot-findings-2026` methodology-context source.

Committed files:

- `experiments/preregistrations/ciphertext-stehle-regularity-v1.json`
- `experiments/predictions/ciphertext-stehle-regularity-v1.json`

The artifact records the source-reported 55 through 63 anomaly label and the
repo canonical one-based coordinate mapping: the displayed `DIAWINFBN` sequence
is K4 positions 56 through 64 in this repository. Position 64 is a public
known-plaintext anchor position, so the committed non-anchor regularity target
contains positions 56 through 63 only.

Validation status:

- `validate-preregistration` passes.
- `validate-prediction-artifact --require-unique-artifact` passes.
- The lane is intentionally evaluator-pending. It must not be scored or
  interpreted until a family-specific observation validator, evaluator,
  same-size non-anchor position-shuffle null, and ciphertext-symbol shuffle
  control are implemented.

Current independent-lane inventory markers:

- independent lanes: `73`
- ready for source-backed observations: `72`
- invalid lanes: `0`
- prediction artifacts: `73`
- unique prediction artifacts: `31`
- unique ready prediction targets: `30`
- evaluator-pending lanes: `1`
- ciphertext-stehle-regularity-position-prior-family lanes: `1`
- ciphertext-stehle-regularity-position-prior-family unique ready targets: `0`

This is not a K4 solution, key, route, plaintext, or candidate. It only turns a
source-grounded structural anomaly into an auditable future-work artifact
without reusing the existing public-anchor-derived or CIA row-boundary evidence
as proof.

## 2026-05-31: Stehle Regularity Evaluator Added

Added the family-specific validator and evaluator for
`ciphertext-stehle-regularity-v1`.

New commands:

```sh
cargo run --locked -- validate-ciphertext-stehle-regularity-observations \
  --artifact experiments/predictions/ciphertext-stehle-regularity-v1.json \
  --preregistration experiments/preregistrations/ciphertext-stehle-regularity-v1.json \
  --input <source-backed-observations.json> \
  --format json

cargo run --locked -- evaluate-ciphertext-stehle-regularity \
  --artifact experiments/predictions/ciphertext-stehle-regularity-v1.json \
  --preregistration experiments/preregistrations/ciphertext-stehle-regularity-v1.json \
  --positions-file <source-backed-observations.json> \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-stehle-regularity-observations/<observation-id> \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-stehle-regularity-observations/<observation-id> \
  --format json
```

The evaluator scores independent non-anchor observation positions against both
the full committed Stehle window and the lag-confirmed +5 subset, with seeded
same-size non-anchor position-shuffle null controls. Archive validation now
uses the artifact's full non-anchor universe for allowed observations, so source
observations are not forced to be in the Stehle target before scoring.

Validation status:

- `cargo check --locked` passes.
- `validate-preregistration` passes for `ciphertext-stehle-regularity-v1`.
- `validate-prediction-artifact --require-unique-artifact` passes for
  `ciphertext-stehle-regularity-v1`.
- `next-evidence-gate --format json` now reports the Stehle family as ready,
  not evaluator-pending.

Current independent-lane inventory markers:

- independent lanes: `73`
- ready for source-backed observations: `73`
- invalid lanes: `0`
- prediction artifacts: `73`
- unique prediction artifacts: `31`
- unique ready prediction targets: `31`
- evaluator-pending lanes: `0`
- ciphertext-stehle-regularity-position-prior-family lanes: `1`
- ciphertext-stehle-regularity-position-prior-family unique ready targets: `1`

This still is not a K4 solution, key, route, plaintext, or candidate. The
Stehle artifact remains only a preregistered target until a genuinely
independent source-backed observation file is validated and archived.

## 2026-05-31: Project K4 Methodology Source Registered

Added `kryptos-today-project-k4-2026` as a quote-free local source snapshot
for the public Project K4 live-cryptanalysis press page. This is methodology
context only: it documents an independent live-search effort, claimed reject
telemetry, attack-queue framing, and negative-result discipline, but it does
not add candidate material, a key stream, a route, plaintext, or scoreable
non-anchor observations.

Source archive:

```bash
cargo run --locked -- validate-source-archive \
  --source-id kryptos-today-project-k4-2026 \
  --input sources/archives/kryptos-today-project-k4-2026-05-31.md
```

Practical consequence: this can inform future attack-family triage and stop
rules, but it does not change the evidence frontier. Future scored work still
requires a new eligible source with explicit non-anchor scored-position
markers, a changed source-backed archive boundary, or a genuinely distinct
validated prediction artifact.

Follow-up live-source check: the press page advertises a
`kryptos.today/press/knowledge-pack` reference link, but a 2026-05-31 `curl -L`
check returned a 404 page. No new source record, candidate material, or scored
observation is added from that unavailable endpoint.

## 2026-05-31: Project K4 Progress Source Registered

Added `kryptos-today-progress-2026` as a quote-free local source snapshot for
the public Project K4 progress page. This is methodology context only: it
records attack-family triage, the Weltzeituhr phase closeout and expansion,
period-7 attribution demotion for width-7 transposition, and the revised queue
including Weltzeituhr, Mengenlehreuhr lamp-state, Morse-panel, K3-style, and
width-7/Vigenere families. It does not add candidate material, a key stream,
a route, plaintext, or scoreable non-anchor observations.

Source archive:

```bash
cargo run --locked -- validate-source-archive \
  --source-id kryptos-today-progress-2026 \
  --input sources/archives/kryptos-today-progress-2026-05-31.md
```

Practical consequence: this informs attack-family triage and stop rules. It
does not reopen width-7 or Weltzeituhr evidence; future scoring still requires
separate preregistration, artifact, eligible observation, and seeded controls.

## 2026-05-31: SolveKryptos Canonical Bundle Quarantine Check

Downloaded the public SolveKryptos canonical bundle only into `/private/tmp`
and screened it with the local quarantined-claim verifiers. A refreshed
download later the same day changed the mechanism result: reconciliation and
bundle-level checks still passed, but the mechanism check failed at the Y-pass
template layer. No claimed plaintext or plaintext-bearing table was added to
the repository.

```bash
curl -L https://solvekryptos.com/downloads/solvekryptos-canonical-bundle.zip \
  -o /private/tmp/solvekryptos-canonical-bundle.zip
unzip -o /private/tmp/solvekryptos-canonical-bundle.zip \
  -d /private/tmp/solvekryptos-canonical-bundle
cargo run --locked -- verify-claim-reconciliation \
  --input /private/tmp/solvekryptos-canonical-bundle/solvekryptos-canonical-bundle/k4_reconciliation.csv \
  --source-id solvekryptos-2026-claim \
  --format json
cargo run --locked -- verify-claim-bundle \
  --directory /private/tmp/solvekryptos-canonical-bundle/solvekryptos-canonical-bundle \
  --source-id solvekryptos-2026-claim \
  --format json
cargo run --locked -- verify-claim-mechanism \
  --directory /private/tmp/solvekryptos-canonical-bundle/solvekryptos-canonical-bundle \
  --source-id solvekryptos-2026-claim \
  --format json
```

Observed quarantine-check result: 97 rows, 97/97 K4 ciphertext alignment,
97/97 tier values, 97/97 lane values, 97/97 checked `R` values, 97/97 binary
gate values, 97/97 checked `r + gate` values, 31/31 checked Z2 handoff values,
and 4/4 registered public anchors preserved. `promoted_candidate` remained
false.

Observed bundle-level result: 5/5 required files present, repo ciphertext
matched, plaintext length matched, reconciliation structural checks passed,
97/97 `R` grid values matched, 97/97 base-`r` grid values matched, 97/97
gate-map values matched, 31/31 Z2 handoff values matched, and 4/4 public
anchors preserved. `promoted_candidate` remained false.

Observed mechanism-file result: 8/8 required files present, 26/26 `f` table
values matched, 26/26 helper-card delta checks matched, 9/9 control-card
entries matched, Z2 effective key derivation matched, 31/31 Z2 helper-path
base-`r` grid checks matched, and 31/31 Z2 helper-path final `R` grid checks
matched, but only 27/31 Y-pass template rule checks and 27/31 Y-pass gate-map
checks matched. `structural_checks_passed` was false and
`promoted_candidate` remained false.

The non-leaking Y-pass mismatch diagnostic localizes the four disagreements to
Y positions 23, 27, 28, and 29, corresponding to K4 positions 27, 31, 32, and
33. The diagnostic reports expected and observed gate values only; it does not
print or store the claimed plaintext.

A follow-up Y-template consistency diagnostic found an internal contradiction
inside `y_master_template.txt`: the declared zero-position list is
`1,2,8,11,16,17,23,24,28,29,30`, while the positions implied by the printed
rule and `Y_ROW` are `1,2,8,11,16,17,24,27,30`. Declared-only positions are
23, 28, and 29; rule-only position is 27.

A later same-day upstream recheck downloaded the current public ZIP to
`/private/tmp/k4-latest-solvekryptos`:

```bash
curl -L https://solvekryptos.com/downloads/solvekryptos-canonical-bundle.zip \
  -o /private/tmp/k4-latest-solvekryptos/solvekryptos-canonical-bundle.zip
shasum -a 256 /private/tmp/k4-latest-solvekryptos/solvekryptos-canonical-bundle.zip
cargo run --locked -- verify-claim-bundle \
  --directory /private/tmp/k4-latest-solvekryptos/solvekryptos-canonical-bundle \
  --source-id solvekryptos-2026-claim \
  --format json
cargo run --locked -- verify-claim-mechanism \
  --directory /private/tmp/k4-latest-solvekryptos/solvekryptos-canonical-bundle \
  --source-id solvekryptos-2026-claim \
  --format json
```

The ZIP SHA-256 was
`bc9dbf5c20798f711a5f3f4b0f6fb2f14fe6f4d2faa237b161ab67419b156a7f`.
The bundle-level verifier still passed, while the mechanism verifier still
failed with the same 27/31 Y-pass template rule and gate-map matches, the same
four Y-position disagreements, and the same declared-vs-rule zero-position
disagreement. The unzip command emitted a path-separator warning and returned
non-zero, but the expected bundle directory and files were extracted and
verified by the repo commands.

Practical consequence: the published reconciliation table and top-level bundle
remain internally compatible with the repo's structural verifier, but the
refreshed published helper machinery is not fully consistent with the verifier
or with its own printed Y-template rule. The claim remains quarantined, not
promoted, and not source-backed evidence.

## 2026-05-31: Extreme-Moduli Residue-Balance Prior Registered

Added `ciphertext-residue-balance-extreme-moduli-v1`, a distinct
ciphertext-only residue-balance preregistration and committed prediction
artifact for moduli `27..=33`. This is a pre-score planning target only: it
uses public K4 ciphertext positions plus the fixed non-anchor exclusion mask,
and it does not use candidate words, key material, routes, claimed plaintext,
public-anchor additive fragments, or source-backed observation positions as
discovery evidence.

```bash
cargo run --locked -- ciphertext-residue-balance-prior \
  --min-modulus 27 \
  --max-modulus 33 \
  --format json \
  > experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json \
  --format json
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json \
  --require-unique-artifact \
  --format json
```

Validation status: preregistration valid; prediction artifact valid and unique.
The artifact fixes one selected non-anchor residue class for each modulus
`27..=33`; promotion remains `false`. This does not reopen any negative
source-backed row-boundary archive. It gives future independent source-backed
observations one additional distinct predeclared target to test.

Current independent-lane inventory after this addition:

- independent lanes: `68`
- ready for source-backed observations: `68`
- evaluator-pending lanes: `0`
- invalid lanes: `0`
- prediction artifacts: `68`
- unique prediction artifacts: `26`
- unique ready prediction targets: `26`
- duplicate artifact lanes: `43`
- extra duplicate artifact lanes: `42`
- ciphertext-residue-balance-position-prior-family lanes: `5`
- ciphertext-residue-balance-position-prior-family unique ready targets: `5`

## 2026-05-31: Extreme-Moduli Residue-Balance Row-Boundary Check

Scored the already-preregistered, unique
`ciphertext-residue-balance-extreme-moduli-v1` artifact against the committed
CIA row-boundary observation. This uses the existing ciphertext-residue-balance
evaluator over the fixed moduli `27..=33`; it does not add candidate words,
public-anchor fragments, or a new route/key-material search.

```bash
cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json
cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-extreme-moduli-v1 \
  --format json
cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-extreme-moduli-v1 \
  --format json
```

Result: best modulus `27` residue `8`, `1/6` source-backed row-boundary
positions hit the committed extreme-moduli residue-balance target, empirical
`p=0.7859`, promoted `false`. This is negative/non-significant evidence for
this preregistered target and does not reopen the row-boundary lane.

## 2026-05-31: Super-Extreme-Moduli Residue-Balance Prior Registered And Checked

Added `ciphertext-residue-balance-super-extreme-moduli-v1`, a distinct
ciphertext-only residue-balance preregistration and committed prediction
artifact for moduli `34..=40`. This is a pre-score planning target only: it
uses public K4 ciphertext positions plus the fixed non-anchor exclusion mask,
and it does not use candidate words, key material, routes, claimed plaintext,
public-anchor additive fragments, or source-backed observation positions as
discovery evidence.

```bash
cargo run --locked -- ciphertext-residue-balance-prior \
  --min-modulus 34 \
  --max-modulus 40 \
  --format json \
  > experiments/predictions/ciphertext-residue-balance-super-extreme-moduli-v1.json
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-residue-balance-super-extreme-moduli-v1.json \
  --format json
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-super-extreme-moduli-v1.json \
  --require-unique-artifact \
  --format json
```

Validation status: preregistration valid; prediction artifact valid and unique.
The artifact fixes one selected non-anchor residue class for each modulus
`34..=40`; promotion remains `false`.

The new super-extreme-moduli target was then scored against the committed CIA
row-boundary observation and archived.

```bash
cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-super-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-super-extreme-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json
cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-super-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-super-extreme-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-super-extreme-moduli-v1 \
  --format json
cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-super-extreme-moduli-v1 \
  --format json
```

Result: best modulus `35` residue `4`, `1/6` source-backed row-boundary
positions hit the committed super-extreme-moduli residue-balance target,
empirical `p=0.6741`, promoted `false`. This is negative/non-significant
evidence for this preregistered target and does not reopen the row-boundary
lane.

Current independent-lane inventory after this addition:

- independent lanes: `69`
- ready for source-backed observations: `69`
- evaluator-pending lanes: `0`
- invalid lanes: `0`
- prediction artifacts: `69`
- unique prediction artifacts: `27`
- unique ready prediction targets: `27`
- duplicate artifact lanes: `43`
- extra duplicate artifact lanes: `42`
- ciphertext-residue-balance-position-prior-family lanes: `6`
- ciphertext-residue-balance-position-prior-family unique ready targets: `6`

## 2026-05-31: Ultra-High Residue-Balance Row-Boundary Check

Scored the already-preregistered, unique
`ciphertext-residue-balance-ultra-high-moduli-v1` artifact against the
committed CIA row-boundary observation. This uses the existing
ciphertext-residue-balance evaluator over the fixed moduli `21..=26`; it does
not add candidate words, public-anchor fragments, or a new route/key-material
search.

```bash
cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json
cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-ultra-high-moduli-v1 \
  --format json
cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-ultra-high-moduli-v1 \
  --format json
```

Result: best modulus `21` residue `12`, `1/6` source-backed row-boundary
positions hit the committed ultra-high residue-balance target, empirical
`p=0.8289`, promoted `false`. This is negative/non-significant evidence for
this preregistered target and does not reopen the row-boundary lane.

## 2026-05-31: Ciphertext Window-Balance Evaluator Added

Added source-backed observation validation and evaluation support for
`ciphertext-window-balance-v1`, then scored the committed CIA row-boundary
observation against the preregistered artifact.

```bash
cargo run --locked -- validate-ciphertext-window-balance-observations \
  --artifact experiments/predictions/ciphertext-window-balance-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json
cargo run --locked -- evaluate-ciphertext-window-balance \
  --artifact experiments/predictions/ciphertext-window-balance-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-window-balance-observations/cia-k4-row-boundaries-v1 \
  --format json
cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-window-balance-observations/cia-k4-row-boundaries-v1 \
  --format json
```

Result: `0/6` source-backed row-boundary positions hit the committed
window-balance target, empirical `p=1.0000`, promoted `false`. This is
negative/non-significant evidence for this family, not a K4 solution claim.

Current independent-lane inventory after adding the evaluator:

- independent lanes: `67`
- ready for source-backed observations: `67`
- evaluator-pending lanes: `0`
- invalid lanes: `0`
- prediction artifacts: `67`
- unique prediction artifacts: `25`
- unique ready prediction targets: `25`
- duplicate artifact lanes: `43`
- extra duplicate artifact lanes: `42`
- ciphertext-window-balance-position-prior-family lanes: `1`
- ciphertext-window-balance-position-prior-family unique ready targets: `1`

## 2026-05-28: Ciphertext Window-Balance Prior Registered

Superseded by the 2026-05-31 evaluator entry above.

Added `ciphertext-window-balance-v1`, a ciphertext-only local-window balance
preregistration and committed prediction artifact. The artifact is generated by
the new deterministic command:

```bash
cargo run --locked -- ciphertext-window-balance-prior --format json \
  > experiments/predictions/ciphertext-window-balance-v1.json
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-window-balance-v1.json \
  --format json
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-window-balance-v1.json \
  --require-unique-artifact \
  --format json
```

Validation status: preregistration valid; prediction artifact valid and unique.
The artifact fixes 20 non-anchor positions selected from public K4 ciphertext
only, using centered window widths `[3, 5, 7]`, closeness to a balanced Kryptos
alphabet-index sum, distinct-letter count, repeated-letter penalty, and fixed
tie-breaks. Public known-plaintext anchors are used only as an exclusion mask,
not as discovery evidence or primary evidence.

Current independent-lane inventory after this addition:

- independent lanes: `67`
- ready for source-backed observations: `66`
- evaluator-pending lanes: `1` (`ciphertext-window-balance-v1`)
- invalid lanes: `0`
- prediction artifacts: `67`
- unique prediction artifacts: `25`
- unique ready prediction targets: `24`
- duplicate artifact lanes: `43`
- extra duplicate artifact lanes: `42`
- ciphertext-window-balance-position-prior-family lanes: `1`
- ciphertext-window-balance-position-prior-family unique ready targets: `0`

Practical consequence: this is a distinct preregistered prediction artifact, but
it is not yet scoreable evidence. The next engineering step for this family is a
family-specific source-backed observation validator/evaluator; the next evidence
step still requires future independent non-anchor observations before scoring.

## 2026-05-28: Period v45 Registered As Duplicate Readiness Inventory

Added `non-anchor-position-period-v45`, a populated independent prediction
target with a concrete non-anchor rationale, predeclared discovery and
evaluation inputs, explicit seeded null/best-of-period/multiple-comparison
controls, and committed deterministic artifact
`experiments/predictions/non-anchor-position-period-v45.json`.

Validation:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/non-anchor-position-period-v45.json
cargo run --locked -- period-prediction-plan --all --format json \
  > experiments/predictions/non-anchor-position-period-v45.json
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/non-anchor-position-period-v45.json \
  --format json
```

The preregistration and artifact validate, but the artifact duplicates the
existing all-period prediction target. This lane is therefore readiness
inventory only, not new independent evidence and not a K4 solution claim.

Current independent-lane inventory after v45:

- independent lanes: `66`
- ready for source-backed observations: `66`
- invalid lanes: `0`
- prediction artifacts: `66`
- unique ready prediction targets: `24`
- duplicate artifact lanes: `43`
- extra duplicate artifact lanes: `42`
- period-family lanes: `47`
- period-family unique ready targets: `5`

Practical consequence: do not treat v45 as a fresh signal. The useful next
evidence step still requires a genuinely distinct prediction artifact or a new
eligible source-backed non-anchor observation file.

## 2026-05-28: Source Frontier Summary Added

Added a compact `source-frontier --summary` mode for the current evidence
frontier. This does not add evidence or promote any candidate; it makes the
current stopping condition easier to inspect before anyone runs another scoring
command.

Command:

```bash
cargo run --locked -- source-frontier --summary
```

Current output confirms:

- registered sources: `17`
- scored-observation eligible sources: `2`
- sources with scored-position markers: `1`
- valid source-backed archives: `23`
- all source-backed archives negative/non-significant: `true`
- scored-observation-ready source: `cia-sculpture`
- eligible but currently non-scorable source: `cia-artifact`
- frontier blockers:
  `source-backed-evidence-negative-or-non-significant`,
  `unused-eligible-source-marked-non-scorable`, and
  `already-used-source-archives-negative`

Practical consequence: do not rerun the existing CIA row-boundary evidence as
new evidence. The next evidence-bearing move still requires a new eligible
source, a changed source-backed archive rationale with explicit non-anchor
positions, or a genuinely distinct preregistered prediction artifact before
scoring.

## 2026-05-28: NSA DOC_7 Technical Analysis Registered As Context

Added `nsa-kryptos-doc7-technical-analysis`, a quote-free local archive for
the official NSA declassified technical-analysis memo at
`sources/archives/nsa-kryptos-doc7-technical-analysis-2026-05-28.md`.

Validation:

```bash
cargo run --locked -- validate-source-archive \
  --source-id nsa-kryptos-doc7-technical-analysis \
  --input sources/archives/nsa-kryptos-doc7-technical-analysis-2026-05-28.md
```

The archive validates with `valid: true`, `allowed use: archive-context-only`,
no scored-position marker, and an explicit non-scorable reason. The reviewed
facts are useful for declassified NSA solved-section methodology and the
unresolved-section boundary, but they do not provide a confirmed K4 key, route,
plaintext, or one-based non-anchor K4 position-selection rule.

Updated source-frontier inventory:

- registered sources: `18`
- scored-observation eligible sources: `2`
- sources with scored-position markers: `1`
- context-only sources: `15`
- quarantined claims: `1`
- valid source-backed archives: `23`
- all source-backed archives negative/non-significant: `true`

Practical consequence: this closes a source-provenance gap, not an evidence
gap. The frontier remains source-limited: future scoring still needs a new
eligible scored-observation source, a changed source-backed archive rationale
with explicit non-anchor positions, or a genuinely distinct prediction artifact.

## 2026-05-28: Ultra-High-Moduli Residue-Balance Target Preregistered

Added `ciphertext-residue-balance-ultra-high-moduli-v1`, a distinct
ciphertext-only residue-balance target for moduli `21..=26`, with committed
artifact
`experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json`.
The lane is an independent prediction target only: it uses public K4 ciphertext
and the fixed non-anchor universe, and it does not use candidate words, key
material, routes, plaintext guesses, public-anchor additive fragment values, or
source-backed observation positions to construct the target.

Validation:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --require-unique-artifact
```

Both commands pass. This is a future-observation target, not source-backed
evidence and not a K4 solution.

Current inventory markers:

- independent lanes: `65`
- ready for source-backed observations: `65`
- prediction artifacts: `65`
- unique ready prediction targets: `24`
- duplicate artifact lanes: `42`
- extra duplicate artifact lanes: `41`
- source-backed observation files: `1`
- source-backed observation file:
  `experiments/position-observations/cia-k4-row-boundaries-v1.json`
- evidence summaries: `1`
- evidence summary:
  `experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`
- registered sources: `17`
- scored-observation eligible sources: `2`
- reviewed eligible sources: `2`
- used eligible sources: `1`
- unused eligible sources: `1`
- context-only sources: `14`
- quarantined claims: `1`
- valid source-backed archives: `23`
- all source-backed archives negative/non-significant: `true`
- period-family lanes: `46`
- period-family unique ready targets: `5`
- ciphertext-residue-balance-position-prior-family lanes: `4`
- ciphertext-residue-balance-position-prior-family unique ready targets: `4`

## 2026-05-28: Period-7 Unique Artifact Scored Negative

Added `non-anchor-position-period-v44`, a distinct period-7-only
preregistered target with committed artifact
`experiments/predictions/non-anchor-position-period-v44.json`. The lane is a
pure independent prediction target: it uses the registered period-7
absolute-position residue rule, excludes public-anchor positions from scoring,
and does not use candidate words, key material, routes, plaintext guesses, or
public-anchor additive fragment values for discovery.

The artifact validates with
`validate-prediction-artifact --require-unique-artifact`, and the existing CIA
row-boundary observation validates through
`results/period-observations/cia-k4-row-boundaries-period7-v44`.

Result: best model `period 7 residue 0`, `2/6` hits, null mean `2.21`, null sd
`0.56`, empirical `p=0.9476`, promoted `false`. This is
negative/non-significant source-backed evidence, not a K4 solution.

Current inventory markers:

- independent lanes: `64`
- ready for source-backed observations: `64`
- prediction artifacts: `64`
- unique ready prediction targets: `23`
- duplicate artifact lanes: `42`
- extra duplicate artifact lanes: `41`
- source-backed observation files: `1`
- source-backed observation file:
  `experiments/position-observations/cia-k4-row-boundaries-v1.json`
- evidence summaries: `1`
- evidence summary:
  `experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`
- registered sources: `17`
- scored-observation eligible sources: `2`
- reviewed eligible sources: `2`
- used eligible sources: `1`
- unused eligible sources: `1`
- context-only sources: `14`
- quarantined claims: `1`
- valid source-backed archives: `23`
- all source-backed archives negative/non-significant: `true`
- period-family lanes: `46`
- period-family unique ready targets: `5`

## 2026-05-28: Evidence Frontier Rechecked After DOC_1 Intake

Re-ran the operational evidence gates after adding the NSA DOC_1
context-only source. The current machine-readable boundary is unchanged:
existing source-backed archives are all negative/non-significant, the only
unused eligible source (`cia-artifact`) is still explicitly non-scorable from
its local archive, and duplicate period-family lanes remain inventory rather
than evidence.

Current gate markers:

- independent lanes: `63`
- ready for source-backed observations: `63`
- prediction artifacts: `63`
- unique ready prediction targets: `22`
- duplicate artifact lanes: `42`
- extra duplicate artifact lanes: `41`
- source-backed observation files: `1`
- source-backed observation file:
  `experiments/position-observations/cia-k4-row-boundaries-v1.json`
- evidence summaries: `1`
- evidence summary:
  `experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`
- registered sources: `17`
- scored-observation eligible sources: `2`
- reviewed eligible sources: `2`
- used eligible sources: `1`
- unused eligible sources: `1`
- context-only sources: `14`
- quarantined claims: `1`
- valid source-backed archives: `22`
- all source-backed archives negative/non-significant: `true`

Current next-action kind:
`new-source-backed-rationale-or-distinct-prediction-artifact`.

Current blocking conditions:

- blocking condition: `duplicate-period-lanes-not-evidence`
- blocking condition: `source-backed-evidence-negative-or-non-significant`
- blocking condition: `unused-eligible-source-marked-non-scorable`
- source-frontier blocking condition: `source-backed-evidence-negative-or-non-significant`
- source-frontier blocking condition: `unused-eligible-source-marked-non-scorable`
- source-frontier blocking condition: `already-used-source-archives-negative`

The current `next-evidence-gate --format json` output includes
`evidence_support_details` with archive directory, source/model label, hit
count, null mean best hits, empirical p-value, and support status for each
valid archive. It reports `all_source_backed_archives_negative: true`.
The current `source-observation-status --format json` output exposes
`source_observation_status_command`, and `source-frontier --format json`
exposes `frontier_blocking_conditions`, `required_next_evidence`, and
`disallowed_next_actions`.

Interpretation: do not run another score over `cia-k4-row-boundaries-v1` or
the current public-anchor/key-material family as new evidence. Productive work
now requires one of:

- a new eligible source with a quote-free local archive and explicit
  non-anchor `scored_positions_one_based` markers,
- a new source-backed rationale that changes an eligible archive boundary
  before scoring, or
- a distinct preregistered prediction artifact that passes
  `validate-prediction-artifact --require-unique-artifact`.

## 2026-05-28: NSA Summary And DOC_8 Context Registered

Added two official NSA declassification pages to close source-provenance gaps:
`nsa-kryptos-summary-revelations` for the NSA previous-work/new-revelations
summary page and `nsa-kryptos-doc8-cryptogram` for the official cryptogram-text
document page. Both have quote-free local archives under `sources/archives/`.

These sources are not scored evidence. The summary source is
`archive-context-only`, and the DOC_8 cryptogram source is public ciphertext
provenance only. Neither archive records non-anchor scored positions, key
material, routes, candidate material, or plaintext.

Updated source-frontier markers after this intake:

- registered sources: `17`
- scored-observation eligible sources: `2`
- context-only sources: `14`
- quarantined claims: `1`
- valid source-backed archives: `22`
- all source-backed archives negative/non-significant: `true`

## 2026-05-28: NSA DOC_1 Source Context Registered

Added the official NSA DOC_1 challenge/resolution memo page as
`nsa-kryptos-doc1-resolution-memo` with a quote-free local archive at
`sources/archives/nsa-kryptos-doc1-resolution-memo-2026-05-28.md`. The source
is registered as `archive-context-only`: it can support future preregistration
or methodology provenance, but it supplies no scored non-anchor K4 positions,
key material, route, or plaintext.

This does not reopen the stopped public-anchor or row-boundary lanes. It
improves the primary-source boundary for future independent structural work
while preserving the current `source-frontier` requirement: any scored evidence
still needs a public-facts source with explicit non-anchor scored-position
markers or a distinct preregistered prediction target.

Current source-frontier markers after this intake:

- registered sources: `15`
- scored-observation eligible sources: `2`
- context-only sources: `12`
- quarantined claims: `1`
- valid source-backed archives: `22`
- all source-backed archives negative/non-significant: `true`

## 2026-05-28: Period-14 Source-Context Artifact Scored Negative

Added `non-anchor-position-period-v43`, a distinct period-14-only
preregistered target tied to the context-only 7-by-14 Sanborn-papers rationale
from `kryptosbot-sanborn-papers-2026`. The source fixes only the structural
period choice; it does not provide scored positions, plaintext, key material,
or candidate evidence. The committed artifact at
`experiments/predictions/non-anchor-position-period-v43.json` contains one
deterministic period-14 plan set and passes
`validate-prediction-artifact --require-unique-artifact`.

The existing CIA row-boundary observation validates against the v43 artifact,
and the archive at
`results/period-observations/cia-k4-row-boundaries-period14-v43` passes
`validate-evaluation-archive`.

Result: best model `period 14 residue 0`, `1/6` hits, null mean `1.71`, null
sd `0.56`, empirical `p=1.0000`, promoted `false`. This is
negative/non-significant source-backed evidence, not a K4 solution. It closes
the new v43 ready-artifact gap by representing the distinct period-14 target in
the source-backed archive inventory.

Current inventory markers:

- independent lanes: `63`
- ready for source-backed observations: `63`
- prediction artifacts: `63`
- unique ready prediction targets: `22`
- period-family lanes: `45`
- period-family unique ready targets: `4`

## 2026-05-28: Period-3 Unique Artifact Scored Negative

Closed the remaining ready-artifact gap by scoring
`non-anchor-position-period-v40`, the distinct period-3-only prediction target,
against the committed CIA row-boundary observation. The artifact already passed
`validate-prediction-artifact --require-unique-artifact`; the observation
validator accepted the committed source-backed row-boundary positions, and the
archive at `results/period-observations/cia-k4-row-boundaries-period3-v40`
passes `validate-evaluation-archive`.

Result: best model `period 3 residue 0`, `4/6` hits, null mean `3.19`, null sd
`0.72`, empirical `p=0.2755`, promoted `false`. This is
negative/non-significant evidence, not a K4 solution. It is still useful because
the period-3 target is now represented in the source-backed archive inventory
instead of remaining only a ready preregistered artifact.

## 2026-05-28: Frontier and Template Gate Rechecked

Refreshed the current evidence frontier after the ciphertext period-match lane.
`source-frontier --format json` still reports `14` registered sources, `2`
scored-observation eligible sources, `20` valid source-backed archives, `0`
invalid archives, and all source-backed archives negative/non-significant.
`cia-sculpture` is already used by the scored row-boundary archive set, while
`cia-artifact` remains eligible but explicitly non-scorable from its current
local archive because it has no one-based non-anchor K4 positions or
position-selection rule. The required next evidence remains a new eligible
source, a new source-backed rationale that changes an archive boundary, or a
distinct preregistered prediction artifact validated as unique.

The original copied-template failure mode was also rechecked directly:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/independent-lane-template.json
```

The command exits non-zero and rejects the unchanged template with placeholder
errors for `id`, `title`, `hypothesis_family`, `rationale`,
`prediction_target`, `discovery_inputs`, and `evaluation_inputs`, plus the
filename/id mismatch. That confirms copied placeholder lanes no longer pass as
real preregistrations.

## 2026-05-28: Ciphertext Period-Match Lane Scored Negative

Added `ciphertext-period-match-v1`, a ciphertext-only shifted same-letter
period-match endpoint prior. The preregistration and committed artifact validate
as a distinct prediction target with artifact kind `ciphertext-period-match`.
Discovery uses ciphertext self-coincidence structure only, with public anchors
used as an exclusion mask and no candidate words, routes, key material, or
public-anchor additive fragment scoring.

The committed CIA row-boundary observation was validated and scored through
`results/ciphertext-period-match-observations/cia-k4-row-boundaries-v1`. The
archive validates and reports best model `ciphertext shifted same-letter period
2 endpoints`, `1/6` hits, null mean `1.61`, null sd `0.73`, empirical
`p=0.9733`, promoted `false`. This is negative/non-significant source-backed
evidence, not a K4 solution.

After this archive, `independent-lane-status --format json` reports `62` lanes,
`62` ready lanes, `21` unique ready prediction artifacts, and `0` invalid
lanes. `independent-evidence-status --format json` reports `20` valid
source-backed archives, `0` invalid archives, and all support statuses remain
negative/non-significant. `next-evidence-gate --format json` keeps the same
boundary: future progress needs a new source-backed rationale, a new eligible
source, or a distinct preregistered prediction artifact. No candidate is
promoted.

Current inventory markers:

- independent lanes: `62`
- ready for source-backed observations: `62`
- prediction artifacts: `62`
- unique ready prediction targets: `21`
- ciphertext-period-match-position-prior-family lanes: `1`
- ciphertext-period-match-position-prior-family unique ready targets: `1`

## 2026-05-28: Evidence Frontier Refreshed After Adjacent-Contrast Scoring

Refreshed the current source/evidence boundary after the adjacent-contrast lane
was scored. `independent-evidence-status --format json` reports `19` valid
source-backed archives, `0` invalid archives, and every archive remains
negative/non-significant. `source-observation-status --format json` reports two
eligible sources: `cia-sculpture` is already used by the row-boundary archive
set, while `cia-artifact` is reviewed and archived but explicitly
non-scorable from its current local archive because it has no one-based
non-anchor K4 positions or position-selection rule. It also now exposes
`all_source_backed_archives_negative: true`, making the current stop/replan
boundary explicit in the focused source-readiness output. A serial
`source-frontier --format json` run confirms `14` registered sources, `2`
scored-observation eligible sources, `1` source with scored-position markers,
`11` context-only sources, and `1` quarantined claim. It now also reports that
`cia-sculpture` has already been used in `19` source-backed evaluation archives,
all surfaced as archived support statuses before any follow-up can reuse that
source. `source-frontier` now also emits `frontier_blocking_conditions`,
`required_next_evidence`, and `disallowed_next_actions`, making the replan
boundary machine-readable rather than only prose. Because those source-backed
archives are all negative/non-significant and `cia-artifact` is non-scorable,
the frontier recommendation now matches `next-evidence-gate`: future progress
needs a new source-backed rationale, a new eligible source, or a distinct
preregistered prediction artifact. The
`next-evidence-gate` output now also exposes
`all_source_backed_archives_negative: true`, matching the focused
`source-observation-status` flag.

Documentation was aligned so README and `docs/research-method.md` include the
current ciphertext-repeat-distance and ciphertext-adjacent-contrast observation
validators/evaluators in the independent-evidence and release-check surfaces.

Replaced the copied placeholder lane with
`non-anchor-position-period-v39.json` and committed matching prediction
artifact `experiments/predictions/non-anchor-position-period-v39.json`. That
lane validates and is ready for source-backed observations, but
`validate-prediction-artifact` reports it duplicates the existing period-family
target, so it is inventory/workflow traceability only and not independent
evidence.

Follow-up hardening converted the next placeholder into
`non-anchor-position-period-v40.json`, a distinct period-3-only preregistered
prediction target with committed artifact
`experiments/predictions/non-anchor-position-period-v40.json`. The artifact
contains one deterministic period plan, validates with
`validate-prediction-artifact --require-unique-artifact`, and increases the
unique ready prediction target count. It is still only a pre-score prediction
artifact; no source-backed observation has supported it and no candidate is
promoted.

Follow-up placeholder cleanup converted the copied template request into
`non-anchor-position-period-v41.json` with committed artifact
`experiments/predictions/non-anchor-position-period-v41.json`. The
preregistration validates and the artifact matches the deterministic
`period-prediction-plan --all --format json` generator, but
`validate-prediction-artifact --require-unique-artifact` correctly rejects it
because it duplicates `41` existing period-family artifacts. This lane is
therefore duplicate workflow inventory only, not new independent evidence and
not a reason to rerun period-family scoring.

Follow-up distinct period-target work converted the next placeholder into
`non-anchor-position-period-v42.json`, a single-period period-5 preregistered
prediction target with committed artifact
`experiments/predictions/non-anchor-position-period-v42.json`. The artifact
contains one deterministic period-5 plan set, validates with
`validate-prediction-artifact --require-unique-artifact`, and raises the ready
lane inventory to `60` with `19` unique ready prediction artifacts. It is still
only a pre-score prediction target; no source-backed observation has supported
it and no K4 candidate is promoted.

The period-5 target was then scored against the committed CIA row-boundary
observation using
`results/period-observations/cia-k4-row-boundaries-period5-v42`. It found best
period 5 residue 0 with `2/6` hits, null mean `2.51`, null sd `0.63`,
empirical `p=1.0000`, and promoted `false`. The archive passes
`validate-evaluation-archive`. This is negative/non-significant source-backed
evidence, not a K4 solution.

Follow-up distinct-target work added
`ciphertext-residue-balance-high-moduli-v1.json` with committed artifact
`experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json`.
This is a ciphertext-only high-moduli residue-balance target over moduli
`7..=13`; it does not use public-anchor additive fragments, candidate words,
routes, key material, or already scored observation positions for discovery.
The validator now accepts deterministic residue-balance artifacts whose
selected modulus range is encoded in the artifact, so this lane passes
`validate-prediction-artifact --require-unique-artifact` with artifact kind
`ciphertext-residue-balance`, `7` committed residue sets, and no duplicate
artifact warning. It is a pre-score prediction target only, not source-backed
evidence by itself.

The high-moduli residue-balance target was then scored against the committed
CIA row-boundary observation using
`results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-high-moduli-v1`.
The archive validates and reports best model `ciphertext residue-balance
modulus 8 residue 3`, `2/6` hits, null mean `1.76`, null sd `0.67`,
empirical `p=0.6416`, promoted `false`. This is another
negative/non-significant source-backed archive, not a K4 solution or promotion.

Follow-up distinct-target work added
`ciphertext-residue-balance-very-high-moduli-v1.json` with committed artifact
`experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json`.
This is a ciphertext-only very-high-moduli residue-balance target over moduli
`14..=20`; it uses the same predeclared distinct-letter-rate rule as the lower
residue-balance lanes but over a separate modulus band and still excludes
public-anchor additive fragments, candidate words, routes, and scored
observation positions for discovery. It passes
`validate-prediction-artifact --require-unique-artifact` with artifact kind
`ciphertext-residue-balance`, `7` committed residue sets, and no duplicate
artifact warning.

The very-high-moduli residue-balance target was then scored against the
committed CIA row-boundary observation using
`results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-very-high-moduli-v1`.
The archive validates and reports best model `ciphertext residue-balance
modulus 16 residue 0`, `2/6` hits, null mean `1.28`, null sd `0.62`,
empirical `p=0.3125`, promoted `false`. This is another
negative/non-significant source-backed archive, not a K4 solution or promotion.

Current inventory after the preregistration refresh:

- independent lanes: `61`
- ready for source-backed observations: `61`
- prediction artifacts: `61`
- unique ready prediction targets: `20`
- duplicate artifact lanes: `42`
- extra duplicate artifact lanes: `41`
- period-family lanes: `44`
- period-family unique ready targets: `3`
- ciphertext-residue-balance-position-prior-family lanes: `3`
- ciphertext-residue-balance-position-prior-family unique ready targets: `3`

Follow-up hardening: `next-evidence-gate --format json` now emits
`next_check_commands`, including `source-frontier`, `source-observation-status`,
`validate-source-archive`, and
`validate-prediction-artifact --require-unique-artifact`. This makes the
required distinct-target and source-boundary checks machine-readable before
another copied period-family lane or unscored source archive can be mistaken for
new evidence.

This does not promote a K4 solution, key, route, plaintext, or candidate. The
next useful work still requires a new source-backed rationale that changes the
`cia-artifact` archive boundary, a new eligible scored-observation source, or a
distinct preregistered prediction artifact fixed before any source-backed
scoring.

## 2026-05-28: Ciphertext Adjacent-Contrast Lane Added And Scored

Added `ciphertext-adjacent-contrast-prior-v1` as a ciphertext-only independent
prediction lane. The lane fixes the 20 interior non-anchor positions with the
strongest predeclared left/right neighbor contrast in Kryptos alphabet order.
It does not use public-anchor additive fragments, candidate words, routes, key
material, or plaintext.

Committed files:

- `experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json`
- `experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json`
- `results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-v1`

Result against `cia-k4-row-boundaries-v1`:

- observed positions: `1, 4, 5, 36, 37, 97`
- matching adjacent-contrast positions: `5, 37`
- result: `2/6` adjacent-contrast hits
- null mean: `1.64`
- null sd: `1.05`
- empirical p-value: `0.5259`
- promoted: `false`

Validation status:

- `validate-preregistration` passes with the standard pure-prediction warning.
- `validate-prediction-artifact` passes with a unique adjacent-contrast artifact.
- `validate-ciphertext-adjacent-contrast-observations` accepts the CIA
  row-boundary observation.
- `validate-evaluation-archive` accepts
  `results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-v1`.

Current inventory after the archive:

- independent lanes: `55`
- ready for source-backed observations: `55`
- prediction artifacts: `55`
- unique ready prediction targets: `16`
- ciphertext-adjacent-contrast-position-prior-family lanes: `1`
- ciphertext-adjacent-contrast-position-prior-family unique ready targets: `1`
- ciphertext-hotspot-position-prior-family lanes: `1`
- ciphertext-hotspot-position-prior-family unique ready targets: `1`
- ciphertext-only-position-prior-family lanes: `1`
- ciphertext-only-position-prior-family unique ready targets: `1`
- ciphertext-rarity-position-prior-family lanes: `1`
- ciphertext-rarity-position-prior-family unique ready targets: `1`
- ciphertext-repeat-distance-position-prior-family lanes: `1`
- ciphertext-repeat-distance-position-prior-family unique ready targets: `1`
- ciphertext-residue-balance-position-prior-family lanes: `1`
- ciphertext-residue-balance-position-prior-family unique ready targets: `1`
- ciphertext-skip-transition-position-prior-family lanes: `1`
- ciphertext-skip-transition-position-prior-family unique ready targets: `1`
- ciphertext-transition-position-prior-family lanes: `1`
- ciphertext-transition-position-prior-family unique ready targets: `1`
- ciphertext-turning-point-position-prior-family lanes: `1`
- ciphertext-turning-point-position-prior-family unique ready targets: `1`
- grid-layout-family lanes: `3`
- grid-layout-family unique ready targets: `3`
- mirror-family lanes: `1`
- mirror-family unique ready targets: `1`
- period-family lanes: `40`
- period-family unique ready targets: `1`
- spacing-family lanes: `1`
- spacing-family unique ready targets: `1`
- tableau-hill-prediction-family lanes: `1`
- tableau-hill-prediction-family unique ready targets: `1`
- source-backed observation files: `1`
- evidence summaries: `1`
- valid source-backed archives: `16`
- invalid source-backed archives: `0`

Current gate state remains
`new-source-backed-rationale-or-distinct-prediction-artifact`, with blocking
condition: `duplicate-period-lanes-not-evidence`, blocking condition:
`source-backed-evidence-negative-or-non-significant`, and blocking condition:
`unused-eligible-source-marked-non-scorable`.

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-05-31 - Post-Terminal Residue-Balance Lane Added

Added `ciphertext-residue-balance-post-terminal-moduli-v1` as a distinct
ciphertext-only independent prediction lane. The lane covers moduli `55`
through `61` and fixes, for each modulus, the non-anchor residue class with the
highest distinct ciphertext-letter rate before any future source-backed
observation scoring.

Committed files:

- `experiments/preregistrations/ciphertext-residue-balance-post-terminal-moduli-v1.json`
- `experiments/predictions/ciphertext-residue-balance-post-terminal-moduli-v1.json`

Validation status:

- `validate-preregistration` passes with only the expected pure-independent
  warning about no source IDs.
- `validate-prediction-artifact --require-unique-artifact` passes with artifact
  kind `ciphertext-residue-balance`, `7` committed plan rows, and no duplicate
  artifact warning.
- `independent-lane-status --format json` reports `76` ready lanes, `34`
  unique ready prediction artifacts, and `9` unique
  `ciphertext-residue-balance-position-prior` artifacts.

Current independent-lane inventory markers:

- independent lanes: `76`
- ready for source-backed observations: `76`
- prediction artifacts: `76`
- unique ready prediction targets: `34`
- ciphertext-residue-balance-position-prior-family lanes: `9`
- ciphertext-residue-balance-position-prior-family unique ready targets: `9`

This is not scored evidence and not a K4 solution. Future use still requires a
validated independent source-backed observation file with one note per
non-anchor position before any interpretation.

## 2026-05-31 - SSRN Claim-Family Quarantine Boundary

Registered the Bonifacino SSRN Weltzeituhr running-key claim family as
quarantined `unverified-solution-claim` sources only:

- `ssrn-bonifacino-running-key-2025`
- `ssrn-bonifacino-weltzeituhr-error-key-2025`
- `ssrn-bonifacino-generative-running-key-2025`

Quote-free local source snapshots record only SSRN metadata, high-level claim
boundaries, and the no-promotion/no-plaintext storage rule. These sources are
not source-backed observation evidence, not candidate material, and not a K4
solution.

Temporary verifier status: direct non-browser PDF fetch for the running-key
paper returned an SSRN/Cloudflare challenge page rather than a PDF, and the
web-accessible SSRN page exposed only metadata and abstract text. No claimed
plaintext, key stream, route, table, or plaintext-bearing artifact was added to
the repository or release-facing files. The SSRN claim-family sources therefore
remain unscreened by `verify-plaintext-claim`, `verify-running-key-claim`,
`verify-claim-reconciliation`, `verify-claim-bundle`, or
`verify-claim-mechanism` until temporary local claim files are available
outside the repository.

Current gate meaning: `next-evidence-gate` should continue listing these SSRN
claim sources under `quarantined_claim_source_ids_without_archive`. That is a
data-availability boundary, not a negative verification result and not evidence
for promotion.

## 2026-05-31 - Remaining Unique Row-Boundary Artifacts Scored

Closed the local inventory gap between unique ready prediction artifacts and
source-backed row-boundary archives by evaluating three already-preregistered
artifacts against `cia-k4-row-boundaries-v1`:

```bash
cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-hyper-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-hyper-extreme-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-hyper-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-hyper-extreme-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-hyper-extreme-moduli-v1 \
  --format json

cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-terminal-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-terminal-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-terminal-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-terminal-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-terminal-moduli-v1 \
  --format json

cargo run --locked -- validate-ciphertext-window-balance-observations \
  --artifact experiments/predictions/ciphertext-window-balance-narrow-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-narrow-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-ciphertext-window-balance \
  --artifact experiments/predictions/ciphertext-window-balance-narrow-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-narrow-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-window-balance-observations/cia-k4-row-boundaries-narrow-v1 \
  --format json
```

Results:

- hyper-extreme residue-balance: modulus `41`, residue `0`, `1/6` hits,
  `p=0.7602`, promoted `false`.
- terminal residue-balance: modulus `48`, residue `0`, `2/6` hits,
  `p=0.0436`, promoted `false`, status `follow-up-required` in
  `next-evidence-gate`.
- narrow window-balance: `0/6` hits, `p=1.0000`, promoted `false`.

Interpretation: the terminal-moduli result is a narrow follow-up flag only. It
is not a K4 solution and does not validate a key, route, plaintext, or
candidate. Do not rescore the same row-boundary observation to tune around this
result. Any follow-up must be preregistered narrowly and evaluated only against
new independent source-backed observations.

Implementation note: `validate-evaluation-archive` was updated to accept
deterministic ciphertext-window-balance variants such as the narrow
`window_widths=[3,5]` artifact, matching the existing variant-aware behavior
for ciphertext-residue-balance artifacts.

## 2026-05-31 - Quarantined Plaintext Claim Verifier Archives

Archived non-leaking `verify-plaintext-claim` outputs for two quarantined
community plaintext claims that already existed as temporary local files. These
checks preserve only structural diagnostics and do not store claimed plaintext,
key material, routes, or plaintext-bearing tables in the repository.

Committed archives:

- `results/claim-verifications/dearcipher-plaintext-20260531/result.json`
- `results/claim-verifications/dearcipher-plaintext-20260531/summary.md`
- `results/claim-verifications/prlog-bishop-plaintext-20260531/result.json`
- `results/claim-verifications/prlog-bishop-plaintext-20260531/summary.md`

Commands run:

```bash
cargo run --locked -- verify-plaintext-claim \
  --input /private/tmp/dearcipher-k4-claim.txt \
  --source-id dearcipher-k4-claim-2026 \
  --format json

cargo run --locked -- verify-plaintext-claim \
  --input /private/tmp/prlog-bishop-12845348-claim.txt \
  --source-id prlog-bishop-k4-plaintext-2020 \
  --format json
```

Results:

- Dear Cipher: normalized length `97`, public anchors `4/4`, distinct implied
  shifts `26`, repeated shift values `71`, max shift bucket `8`, structural
  checks passed, promoted `false`.
- PRLog Bishop: normalized length `97`, public anchors `4/4`, distinct implied
  shifts `26`, repeated shift values `71`, max shift bucket `10`, structural
  checks passed, promoted `false`.

These are quarantine screen results only. They do not validate a mechanism or
promote a K4 solution.

## 2026-05-28: Grid Compass-Axis Archive Added

Added a third 7-by-14 grid-layout lane, `non-anchor-position-grid-compass-axis-v1`,
using the already fixed padded grid plus context-only NSA compass/lodestone
physical-clue notes. The lane predeclares the central row plus the two center
columns as a compass-axis target before scoring any source-backed observation.
The sources provide rationale only; they do not provide scored positions,
candidate key material, routes, or plaintext.

Committed files:

- `experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json`
- `experiments/predictions/non-anchor-position-grid-compass-axis-v1.json`
- `results/grid-observations/cia-k4-row-boundaries-compass-axis-v1`

Result against `cia-k4-row-boundaries-v1`:

- observed positions: `1, 4, 5, 36, 37, 97`
- matching compass-axis positions: `36`
- result: `1/6` compass-axis hits
- null mean: `1.97`
- null sd: `1.11`
- empirical p-value: `0.9166`
- promoted: `false`

Validation status:

- `validate-preregistration` passes without warnings.
- `validate-prediction-artifact` passes with `grid_edge_axis: compass-axis`.
- `validate-grid-observations` accepts the CIA row-boundary observation for
  this preregistered axis.
- `validate-evaluation-archive` accepts
  `results/grid-observations/cia-k4-row-boundaries-compass-axis-v1`.

Current inventory after the archive:

- independent lanes: `54`
- ready for source-backed observations: `54`
- prediction artifacts: `54`
- unique ready prediction targets: `15`
- grid-layout-family lanes: `3`
- grid-layout-family unique ready targets: `3`
- valid source-backed archives: `15`
- invalid source-backed archives: `0`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-05-28: Grid Column-Edge Archive Formalized

Formalized the previously diagnostic column-edge grid check as a separate
source-backed preregistered archive. The archive uses
`non-anchor-position-grid-column-v1`, whose preregistration fixes
`grid_edge_axis: column` before scoring the CIA row-boundary observation.

Committed files:

- `experiments/preregistrations/non-anchor-position-grid-column-v1.json`
- `experiments/predictions/non-anchor-position-grid-column-v1.json`
- `results/grid-observations/cia-k4-row-boundaries-column-v1`

Result:

- observed positions: `1, 4, 5, 36, 37, 97`
- matching column-edge positions: `1, 4, 5, 97`
- result: `4/6` column-edge hits
- null mean: `2.22`
- null sd: `1.14`
- empirical p-value: `0.1303`
- promoted: `false`

`validate-evaluation-archive` now rebuilds the deterministic grid artifact
using the archived or preregistered edge axis instead of assuming row edges for
every grid archive. `independent-evidence-status` and
`source-observation-status` both report `14` valid source-backed archives and
`0` invalid archives after this fix. The column result remains
negative/non-significant evidence.

## 2026-05-28: Ciphertext Repeat-Distance Lane Added And Scored

Added `ciphertext-repeat-distance-v1` as a new ciphertext-only independent
prediction lane. The lane fixes the 20 non-anchor positions with the strongest
same-symbol repeat-distance structure in K4 ciphertext, using only ciphertext
repetition geometry and public anchors as an exclusion mask. It does not use
public-anchor additive fragments, candidate words, routes, key material, or
the CIA row-boundary observation as discovery input.

Committed files:

- `experiments/preregistrations/ciphertext-repeat-distance-v1.json`
- `experiments/predictions/ciphertext-repeat-distance-v1.json`
- `results/ciphertext-repeat-distance-observations/cia-k4-row-boundaries-v1`

Current independent-lane inventory markers:

- independent lanes: `53`
- ready for source-backed observations: `53`
- prediction artifacts: `53`
- unique ready prediction targets: `14`
- ciphertext-repeat-distance-position-prior-family lanes: `1`
- ciphertext-repeat-distance-position-prior-family unique ready targets: `1`

Validation status:

- `validate-preregistration` passes with only the expected pure-independent
  warning about no source IDs.
- `validate-prediction-artifact` passes with artifact kind
  `ciphertext-repeat-distance`, 20 committed positions, and promoted `false`.
- `validate-ciphertext-repeat-distance-observations` accepts
  `experiments/position-observations/cia-k4-row-boundaries-v1.json`.
- `validate-evaluation-archive` accepts
  `results/ciphertext-repeat-distance-observations/cia-k4-row-boundaries-v1`.

The existing CIA row-boundary source-backed observation was scored through the
new repeat-distance evaluator:

- observed positions: `1, 4, 5, 36, 37, 97`
- matching repeat-distance positions: `5, 36`
- result: `2/6` repeat-distance hits
- null mean: `1.64`
- null sd: `1.05`
- empirical p-value: `0.5273`
- promoted: `false`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.

## 2026-05-28: Source Observation Next-Action Alignment

`source-observation-status --format json` now reports
`new-source-backed-rationale-new-source-or-distinct-prediction-artifact` when
every unused eligible source is explicitly marked non-scorable in its local
archive. This keeps the machine-readable action aligned with the human-readable
gate: future progress needs a changed source-backed archive boundary, a new
eligible source, or a distinct preregistered prediction artifact. This is a
workflow guardrail only and does not promote any K4 candidate.

## 2026-05-28: Non-Anchor Period Lane v38 Preregistration

Populated the placeholder preregistration as
`non-anchor-position-period-v38`, then renamed the file to satisfy the validator
rule that preregistration filenames match their stable lane IDs. The lane is a
period-family independent prediction target; it does not use public
known-plaintext anchors, additive fragment values, candidate key material,
routed-key results, held-out anchor controls, source-expanded candidate
screens, or prior public-fragment structure screens as discovery evidence.

Committed files:

- `experiments/preregistrations/non-anchor-position-period-v38.json`
- `experiments/predictions/non-anchor-position-period-v38.json`

Current independent-lane inventory markers:

- independent lanes: `52`
- ready for source-backed observations: `52`
- prediction artifacts: `52`
- unique ready prediction targets: `13`
- period-family lanes: `40`
- period-family unique ready targets: `1`

Validation status:

- `validate-preregistration` passes with only the expected pure-independent
  warning about no source IDs.
- The prediction artifact is generated by
  `period-prediction-plan --all --format json`; it is a readiness artifact for
  future independent source-backed observations, not evidence by itself.

## 2026-05-27: Independent Lane Inventory Guardrails

Source-backed observation scoring update:

- Current web-source triage found `solvekryptos-2026-claim`, a public
  community solution claim. It is now registered with allowed use
  `unverified-solution-claim` and a quote-free local archive snapshot. The
  repository stores no claimed full plaintext from this source and treats it
  only as input for a future independent mechanical verifier.
- `kryptosbot-sanborn-papers-2026` now has a quote-free local archive snapshot
  for context-only Sanborn papers notes. It is not eligible scored evidence, but
  it source-grounds the new `period-14-grid-padding` structural model: one
  padding position would make the 97-character K4 text compatible with a
  7-by-14 grid.
- `rumkin-k4-reference` is now registered with a quote-free local archive as
  methodology context only. It records direct-mapping uncertainty and the HILL
  tableau open question, but adds no candidate material, no scored positions,
  and no evidence. Any Hill/tableau follow-up must be separately
  preregistered before scoring.
- `smithsonian-2026-archive-discovery` is now registered with a quote-free
  local archive as institutional archive-discovery context only. It improves
  provenance around archive-discovery reporting, but it adds no release-facing
  plaintext, key material, routes, scored positions, or evidence.
- HistoCrypt's Gromark-family methodology context was rechecked with the
  bounded public-span recurrence baseline:
  `cargo run --locked -- baseline --target spans --alphabet all --iterations 100000 --seed 67`.
  The strongest raw row was `EASTNORTHEAST` under the Kryptos alphabet with
  `2/11` contiguous triples, raw `p=0.3138`, and adjusted `p=1.0000`; all
  recurrence rows remained unpromoted. Interpretation: do not expand
  Gromark-style recurrence work from public span fragments without a larger
  independently justified fragment set.
- `next-evidence-gate` omits families without a supported validator/evaluator
  instead of falling through to period-observation commands. The Tableau/HILL
  family now has its own validator/evaluator commands.
- `next-evidence-gate` also reports evaluator-pending lane IDs, families,
  artifacts, and next steps explicitly when such lanes exist, while advertising
  Tableau/HILL through its dedicated observation validator and evaluator.
- `source-frontier` now classifies every registered source before evidence work:
  `cia-sculpture` is the only source-backed observation source with current
  scored-position markers and is tied to `16` archived source-backed evaluations
  whose support statuses must be inspected before follow-up, `cia-artifact` is
  eligible but explicitly non-scorable from its current archive, eleven
  registered sources are context-only, and `solvekryptos-2026-claim` remains
  quarantined for temporary local claim verification only.
- `tableau-hill-prediction-plan` now emits a deterministic, tooling-ready
  source-mapping artifact for the Rumkin/CIA/Sanborn HILL/tableau context. It
  fixes a 7-by-14 row-major coordinate map for K4 positions 1 through 97 plus
  one padding cell, without scoring public anchor fragments, candidate
  material, plaintext, routes, or observations.
- `experiments/preregistrations/tableau-hill-v1.json` and
  `experiments/predictions/tableau-hill-v1.json` now commit that source map as
  a valid source-backed observation lane. It contributes one unique prediction
  artifact to inventory and must be scored only through the Tableau/HILL
  validator/evaluator path with padding/public-anchor rejection and seeded
  controls.
- `validate-tableau-hill-observations` now provides the non-scoring Tableau/HILL
  validator for candidate observation files. It validates the committed source
  map and source-review coverage, rejects padding, public-anchor, duplicate, and
  uncovered positions.
- `evaluate-tableau-hill-prediction` now provides the family-specific
  Tableau/HILL scorer for future source-backed observation files. It scores only
  best row/column concentration on the committed 7-by-14 source map with a
  seeded same-size non-anchor position-set null, keeps quick `--positions`
  diagnostic, and still produces no promoted candidate or plaintext.
- `period-prediction-plan --all` and the committed period prediction artifacts
  now include eight registered periods. Period 14 is a distinct preregistered
  target for future source-backed observations, not a candidate, plaintext,
  key, or score.
- `sources/archives/cia-sculpture-2026-05-27.md` now records a pre-score,
  quote-free source observation from the CIA sculpture page text-version
  rendering: after public-anchor positions are excluded, the K4 row-boundary
  positions retained for scoring are `1, 4, 5, 36, 37, 97`.
- `experiments/position-observations/cia-k4-row-boundaries-v1.json` records
  those six positions with explicit per-position notes and a linked validated
  source-review file.
- Period validation and scoring accepted the observation under
  `non-anchor-position-period-v1`; the best result was period `2`, residue `0`,
  with `4/6` hits and seeded best-of-period empirical `p=0.7897`.
- Spacing validation and scoring accepted the same observation under
  `non-anchor-position-spacing-v1`; the best result was modulus `2`, residue
  `1`, with `8/15` pair hits and seeded best-of-modulus empirical `p=1.0000`.
- `non-anchor-position-mirror-v1` adds a distinct source-grounded prediction
  artifact rather than another duplicate period lane. `mirror-prediction-plan`
  emits 35 non-anchor mirror pairs across the 97-character K4 position axis,
  centered on position 49, using only K4 length, anchor exclusion, and
  registered physical-screen/back-side chart context.
- Mirror validation and scoring accepted the same observation under
  `non-anchor-position-mirror-v1`; the result was `1/3` possible mirror-pair
  hits, matching pair `1-97`, and seeded same-size non-anchor position-set
  empirical `p=0.2090`.
- `non-anchor-position-grid-layout-v1` adds a distinct source-context
  7-by-14 padded grid-layout row-edge prediction artifact from the registered
  archive-context-only Sanborn-papers rationale. The source fixes the structure
  but remains ineligible for scored observation positions.
- The grid-layout prediction artifacts now carry the scored edge axis directly.
  The archived v1 grid evidence command explicitly uses `--edge-axis row`, and
  the row-edge preregistration declares `grid_edge_axis: row` so source-backed
  grid scoring cannot switch to column edges post hoc. The separate
  `non-anchor-position-grid-column-v1` lane now preregisters
  `grid_edge_axis: column` with its own deterministic artifact for future
  source-backed observations.
- Grid validation and scoring accepted the same observation under
  `non-anchor-position-grid-layout-v1`; the result was `1/6` row-edge hits,
  matching position `1`, and seeded same-size non-anchor position-set empirical
  `p=0.5600`.
- A non-archived diagnostic rerun of the same positions with `--edge-axis
  column` found `4/6` column-edge hits with seeded same-size null `p=0.1303`.
  Because this was not run through the new column-edge preregistration with a
  source-backed archive, it remains diagnostic only and promotes nothing.
- The local period, spacing, mirror, grid, Tableau/HILL, ciphertext-prior, and
  ciphertext residue-balance archive directories passed
  `validate-evaluation-archive`; the committed stable summary is
  `experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`.
- `release-check` now requires committed source-backed observation positions to
  be covered by local source archives that reference the observation file and
  scored positions. This keeps the quote-free source snapshot from drifting
  away from the evidence it supports.
- `source-review-packet` and `next-evidence-gate` now expose that same local
  source-archive coverage requirement before new observation files are created,
  so the operational checklist matches the release gate.
- The archive coverage check now requires an explicit
  `scored_positions_one_based: ...` marker instead of accepting incidental
  digit matches elsewhere in the archive text.
- `next-evidence-gate` now separates used eligible sources from unused eligible
  sources and checks whether unused eligible source archives contain scored
  position markers. Current state: `cia-sculpture` is already consumed by the
  negative row-boundary archives, while `cia-artifact` is unused but has no
  `scored_positions_one_based` marker in its current archive. Do not score
  `cia-artifact` without a new or updated source-backed observation rationale.
- `next-evidence-gate --format json` now exposes `next_action_kind` and
  `blocking_conditions` so follow-up automation can see that duplicate period
  lanes are not evidence, existing source-backed archives are
  negative/non-significant, and the unused eligible `cia-artifact` archive lacks
  scored-position markers.
Interpretation: this is the first source-backed independent observation scored
through the period, spacing, mirror, grid, and Tableau/HILL gates, but all
controls are negative. It is not a K4 solution, key, plaintext, or promoted
candidate. Do not keep
mining this row-boundary observation; future progress needs a different
source-backed observation or a new preregistered prediction target.

Additional preregistration cleanup:

- The copied preregistration placeholder was promoted to stable filename
  `experiments/preregistrations/non-anchor-position-period-v14.json`. It now
  declares stable lane ID `non-anchor-position-period-v14`, a position-period
  hypothesis family, independent prediction target, non-anchor
  discovery/evaluation boundaries, and explicit
  seeded/null/multiple-comparison/source-validation controls.
- `experiments/predictions/non-anchor-position-period-v14.json` was generated
  deterministically with `period-prediction-plan --all --format json`.
- `validate-preregistration` and `validate-prediction-artifact` both pass for
  the v14 lane. `independent-lane-status` now reports 17 ready lanes but still
  only 2 unique ready prediction artifacts, so this is another operational lane
  definition and not a new cryptanalytic signal.
- The follow-up placeholder requested in the interactive workflow was
  materialized as
  `experiments/preregistrations/non-anchor-position-period-v15.json`, with a
  matching deterministic artifact at
  `experiments/predictions/non-anchor-position-period-v15.json`.
- `validate-preregistration` and `validate-prediction-artifact` both pass for
  the v15 lane. `independent-lane-status` now reports 18 ready lanes but still
  only 2 unique ready prediction artifacts, so v15 is workflow traceability,
  not a new cryptanalytic signal.
- `experiments/preregistrations/non-anchor-position-period-v16.json` and
  `experiments/preregistrations/non-anchor-position-period-v17.json` now carry
  stable non-anchor period-family preregistrations with matching deterministic
  artifacts. They preserve the same pre-score, position-only prediction
  boundary and do not add new candidate material or scored evidence.
- `experiments/preregistrations/non-anchor-position-period-v20.json` replaces
  another copied placeholder with a stable lane ID, explicit non-anchor
  discovery/evaluation boundaries, and matching deterministic prediction
  artifact. It is an operational preregistration only; the duplicated artifact
  content does not add new evidence.
- `experiments/preregistrations/non-anchor-position-period-v22.json` now has concrete lane ID
  `non-anchor-position-period-v22`, explicit position-period hypothesis
  family, independent non-anchor prediction target, non-anchor
  discovery/evaluation boundaries, and seeded shuffle, best-of-period,
  multiple-comparison, and source-backed observation controls.
- `experiments/predictions/non-anchor-position-period-v22.json` was generated
  deterministically with `period-prediction-plan --all --format json`.
  `validate-preregistration`, `validate-prediction-artifact`, and
  `independent-lane-status` pass for this lane; the artifact duplicates the
  existing period target and is not new evidence.
- One source-backed observation has been committed and archived through both
  period and spacing controls. No K4 candidate, plaintext, key, or solution is
  promoted.
- Source traceability was added to the observation-source and next-evidence
  gates: eligible sources now expose URL, access date, source type,
  local-archive status, and use-boundary notes before any source-backed
  observation file is scaffolded. Current eligible CIA sources are locally
  archived, but `cia-sculpture` has already been consumed by negative
  row-boundary archives and the current `cia-artifact` archive has no scored
  position markers. Future scoring still requires an explicit source-backed
  rationale, per-position notes, and archive validation.
- `source-review-packet` now emits the eligible-source pre-score checklist as a
  standalone Markdown/JSON command. This keeps source review, missing local
  archive status, required observation fields, and no-promotion boundaries
  visible before any period or spacing evaluator can be run. Its observation
  requirements now explicitly include the linked validated source-review file.
- `init-source-review` now materializes that pre-score source review as a JSON
  artifact before any non-anchor observation positions are selected. It accepts
  only registered scored-observation-eligible source IDs, rejects duplicate or
  context-only sources, records missing local-archive status, and remains
  non-promotional.
- `validate-source-review` now rechecks saved source-review artifacts against
  the current source registry before observation scoring. It catches stale
  reviewed source metadata, duplicate source IDs, placeholders, context-only
  sources, and tampering while still making no cryptanalytic claim.
- `init-position-observations` can now link a saved `--source-review` artifact,
  and observation validators re-run that source-review gate and require coverage
  for every cited observation source ID before any period/spacing/mirror/grid,
  Tableau/HILL, or ciphertext-prior scoring.

Current independent-lane status:

```bash
cargo run --locked -- independent-lane-status --format json
cargo run --locked -- release-check --format json
```

Result summary:

- independent lanes: `47`
- ready for source-backed observations: `47`
- prediction artifacts: `47`
- unique prediction artifacts: `9`
- unique ready prediction targets: `9`
- ciphertext-hotspot-position-prior-family lanes: `1`
- ciphertext-hotspot-position-prior-family unique ready targets: `1`
- ciphertext-only-position-prior-family lanes: `1`
- ciphertext-only-position-prior-family unique ready targets: `1`
- ciphertext-residue-balance-position-prior-family lanes: `1`
- ciphertext-residue-balance-position-prior-family unique ready targets: `1`
- grid-layout-family lanes: `2`
- grid-layout-family unique ready targets: `2`
- mirror-family lanes: `1`
- mirror-family unique ready targets: `1`
- period-family lanes: `39`
- period-family unique ready targets: `1`
- spacing-family lanes: `1`
- spacing-family unique ready targets: `1`
- tableau-hill-prediction-family lanes: `1`
- tableau-hill-prediction-family unique ready targets: `1`
- evaluator-pending lanes: `0`
- source-backed observation files: `1`
- evidence summaries: `1`
- invalid lanes: `0`
- release-check failures: `0`
- promoted: false

Ciphertext-only profile update:

- `ciphertext-profile` now reports K4 ciphertext-only letter frequencies,
  repeated n-grams, repeated n-gram gap-factor support, index of coincidence,
  period coincidence diagnostics, and seeded shuffle baselines. It does not use public anchors,
  candidate key material, claimed plaintext, or decrypted output.
- Running
  `cargo run --locked -- ciphertext-profile --max-period 20 --max-ngram 4 --top 20 --iterations 100000 --seed 67`
  found overall IC `0.0361`; most frequent letters `K=8`, `S=6`, `T=6`,
  `U=6`; only repeated bigrams in the scanned repeated n-gram table; and a
  best shifted period signal at period `7` with `9/90` matches
  (`0.1000`).
- The period-7 shifted ciphertext matches are now printed directly:
  `1-8 O`, `8-15 O`, `13-20 B`, `16-23 L`, `33-40 S`, `46-53 K`,
  `66-73 P`, `77-84 D`, and `87-94 K`. They are useful for inspection only;
  they are not a route, key, plaintext, or promotion criterion.
- The repeated n-gram spacing diagnostic found best factor support at period
  `2` with `7/10` supported gaps (`0.7000`): `SO` gap 20, `FB` gap 44,
  `SS` gap 10, `EK` gap 48, `KZ` gap 32, `TJ` gap 30, and `DI` gap 28.
  The seeded ciphertext-only spacing null gave null mean best supported gaps
  `3.47`, null sd `1.75`, and empirical `p=0.0568` over 100000 shuffles.
  Interpretation: this is also weak diagnostic-only structure, not promoted
  evidence and not a K4 solution.
- The seeded ciphertext-only best-of-period null gave null mean best shifted
  rate `0.0783`, null sd `0.0133`, and empirical `p=0.0719` over 100000
  shuffles. Interpretation: period 7 is a weak ciphertext-only diagnostic lead,
  not statistically promoted evidence and not a K4 solution.
- `ciphertext-structure-prior` now emits these weak ciphertext-only diagnostics
  as a planning-only future-observation prior. The selected periods are period
  `2` from repeated-ngram gap factors and period `7` from shifted ciphertext
  coincidences; public anchor positions are excluded from the residue targets.
  This artifact is not source-backed evidence and must not be interpreted until
  a future source-reviewed non-anchor observation file is scored under same-size
  position-shuffle, best-of-selected-period, and multiple-comparison controls.
- `evaluate-ciphertext-prior` now scores source-backed non-anchor observation
  files against that planning-only prior. Running
  `cargo run --locked -- evaluate-ciphertext-prior --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json --prior-iterations 100000 --iterations 100000 --seed 67 --prior-seed 67 --output-dir results/ciphertext-prior-observations/cia-k4-row-boundaries-v1`
  retained positions `1, 4, 5, 36, 37, 97`. The best selected-period result
  was period `2` residue `0` with `4/6` hits (`0.6667`), while period `7`
  gave `2/6`. The seeded same-size non-anchor position-shuffle null gave mean
  best hits `3.91`, sd `0.77`, and empirical `p=0.6845` over 100000
  iterations. Interpretation: the ciphertext-only prior does not predict the
  source-backed CIA row-boundary observation better than null, promotes
  nothing, and remains a rejected/negative diagnostic lane.
- `validate-ciphertext-prior-observations` now provides the matching
  non-scoring family gate for ciphertext-prior observation files, so
  `next-evidence-gate` no longer routes this family through the period
  validator or a period artifact. It validates the committed ciphertext-prior
  artifact/preregistration plus source-review coverage, source-use boundaries,
  per-position notes, duplicates, and the ciphertext-prior non-anchor universe
  before `evaluate-ciphertext-prior` can be interpreted.
- The ciphertext-prior output archive is now included in
  `independent-evidence-status` and `next-evidence-gate` through
  `results/ciphertext-prior-observations/cia-k4-row-boundaries-v1`; it validates
  without preregistration/artifact files because the source-backed observation
  itself is the scored input and the prior is planning-only.

`non-anchor-position-period-v32` replaces the copied placeholder lane with a
stable id, concrete absolute-position period family, non-anchor rationale,
predeclared prediction target, independent evaluation target, and explicit
seeded null, best-of-period, multiple-comparison, and source-backed validation
controls. Its deterministic period prediction artifact validates but duplicates
the existing period-family artifacts, so it is readiness inventory only and not
independent evidence.

`non-anchor-position-period-v21` replaces the copied placeholder lane with a
stable id, concrete absolute-position period family, non-anchor rationale,
predeclared prediction target, independent evaluation target, and explicit
seeded null, best-of-period, multiple-comparison, and source-backed validation
controls. It uses the same deterministic period prediction artifact shape as
the other period-family readiness lanes; this is workflow traceability only,
not new evidence and not a promoted candidate.

Duplicate-artifact warnings were added to `validate-prediction-artifact`.
Period-family follow-up lanes now validate successfully while warning that
their committed artifact duplicates other committed artifacts; this makes the
duplicate-lane boundary visible at the artifact gate, not only in
`independent-lane-status`.

Interpretation: the independent evidence workflow is ready for additional
source-backed observation files, and the first committed row-boundary
observation has already scored negative under period, spacing, mirror,
grid-layout, Tableau/HILL, and ciphertext-prior controls. No K4 candidate,
plaintext, or solution is promoted.

`ciphertext-structure-prior-v1` is now a preregistered independent lane with
committed artifact `experiments/predictions/ciphertext-structure-prior-v1.json`.
It is distinct from the duplicate period-family artifacts: the artifact fixes
the ciphertext-only period-2 repeated-ngram gap-factor and period-7 shifted
coincidence residue targets before source-backed observation scoring. The
existing CIA row-boundary archive remains negative for this target
(`4/6`, empirical p-value `0.6845`), so this adds a clearer prediction boundary,
not positive evidence.

`ciphertext-hotspot-prior-v1` is now a preregistered independent lane with
committed artifact `experiments/predictions/ciphertext-hotspot-prior-v1.json`.
It is not another public-anchor mining pass: the artifact fixes top non-anchor
K4 positions from ciphertext-only repeated n-gram coverage and shifted
self-coincidence endpoints before source-backed scoring. A quick diagnostic
against the already-known CIA row-boundary positions produced `0/6` hotspot
hits with empirical p-value `1.0000`; because that source observation predated
the hotspot artifact, it is recorded only as a non-evidence sanity check, not
as archived support.

Duplicate-artifact accounting updated: the lane-status command now reports 44
declared prediction artifacts, 8 unique artifact contents, and 8 unique ready
prediction artifacts after adding the separate column-edge grid target,
`ciphertext-structure-prior-v1`, and `ciphertext-hotspot-prior-v1`. The 37
period-family lanes shared one deterministic position-period target at this
checkpoint; this is an operational readiness inventory, not multiple independent
cryptanalytic signals.
Future interpretation should count unique prediction targets and source-backed
observations, not just preregistration rows.

`non-anchor-position-period-v36` replaces the copied placeholder lane with a
filename/id-aligned preregistration, concrete absolute-position period family,
non-anchor rationale, predeclared prediction target, independent evaluation
target, and explicit seeded null, best-of-period, multiple-comparison, and
source-review controls. `validate-preregistration` and
`validate-prediction-artifact` both accept the lane; artifact validation warns
that it duplicates the existing period-family artifact set. The lane is
readiness inventory only and not new independent evidence.

The live inventory after v36 reports 46 independent lanes, 46 ready lanes, 46
prediction artifacts, 9 unique ready prediction artifacts, and 38 period-family
lanes sharing one unique ready period artifact.

`non-anchor-position-period-v35` replaces the copied placeholder lane with a
filename/id-aligned preregistration, concrete absolute-position period family,
non-anchor rationale, predeclared prediction target, independent evaluation
target, and explicit seeded null, best-of-period, multiple-comparison, and
source-review controls. `validate-prediction-artifact` accepts the generated
artifact, but warns that it duplicates the existing period-family artifact set;
therefore v35 is readiness inventory only and not new independent evidence.

`next-evidence-gate` now includes the duplicate prediction-artifact groups in
both Markdown and JSON output. The main operational gate now shows that the
period-family duplicate group contains 38 lanes, including
`non-anchor-position-period-v35` and `non-anchor-position-period-v36`, so the
`duplicate-period-lanes-not-evidence`
blocking condition is self-contained in the command that recommends the next
action.

`validate-prediction-artifact --require-unique-artifact` now fails duplicate
prediction targets. This keeps normal duplicate period-family readiness
inventory available when intentional, while giving future distinct-target work a
hard gate that rejects another v35-style duplicate artifact before it can be
treated as new evidence.

Family-level inventory added: `independent-lane-status` now reports a family
summary showing `position-period-prediction` has 22 lanes but 1 unique ready
artifact, while `position-spacing-prediction` has 1 lane and 1 unique ready
artifact. This keeps future work from treating duplicate period preregistration
rows as separate evidence.

Follow-up hardening:

- `non-anchor-position-period-v6`, `non-anchor-position-period-v7`,
  `non-anchor-position-period-v8`, `non-anchor-position-period-v9`, and
  `non-anchor-position-period-v10` now have
  committed preregistrations and deterministic prediction artifacts.
- `non-anchor-position-period-v11` now has a stable preregistration filename
  and matching deterministic prediction artifact; it is another readiness lane,
  not a new unique cryptanalytic signal.
- `non-anchor-position-period-v12` now replaces the copied placeholder fields in
  the template copy, uses stable filename
  `experiments/preregistrations/non-anchor-position-period-v12.json`, and has a
  matching deterministic prediction artifact. It is another period-family
  readiness lane, not a third unique prediction target or scored evidence.
- `non-anchor-position-period-v18` replaces the copied `new-lane-id` placeholder
  path with a stable filename and matching deterministic prediction artifact.
  It raises the operational period-lane inventory to 20, but does not add a new
  unique prediction target or scored evidence.
- `non-anchor-position-period-v19` replaces a copied placeholder preregistration
  with a stable filename and matching deterministic prediction artifact. It
  raises the operational period-lane inventory to 21, but does not add a new
  unique prediction target or scored evidence.
- `non-anchor-position-period-v20` replaces a copied placeholder
  preregistration with a stable filename and matching deterministic prediction
  artifact. It raises the operational period-lane inventory to 22, but still
  does not add a new unique prediction target or scored evidence.
- `non-anchor-position-period-v24.json` now replaces the copied `new-lane-id`
  placeholder path with stable lane id `non-anchor-position-period-v24`, a
  concrete non-anchor period-family rationale, predeclared
  discovery/evaluation inputs, and matching deterministic artifact
  `experiments/predictions/non-anchor-position-period-v24.json`. Both
  `validate-preregistration` and `validate-prediction-artifact` pass; the
  artifact duplicates the existing period-family prediction target, so this is
  readiness inventory only and not new scored evidence.
- `non-anchor-position-period-v25.json` now replaces the copied `new-lane-id`
  placeholder request with stable lane id `non-anchor-position-period-v25`, a
  concrete non-anchor period-family rationale, predeclared
  discovery/evaluation inputs, and matching deterministic artifact
  `experiments/predictions/non-anchor-position-period-v25.json`. Both
  `validate-preregistration` and `validate-prediction-artifact` pass, and
  `independent-lane-status --format json` is back to `invalid_lanes: 0`.
  The artifact duplicates the existing period-family prediction target, so
  this is operational readiness inventory only and not new scored evidence.
- `non-anchor-position-period-v26.json` replaces a missing copied
  `new-lane-id` placeholder path with stable lane id
  `non-anchor-position-period-v26`, a concrete non-anchor period-family
  rationale, predeclared discovery/evaluation inputs, and matching
  deterministic artifact
  `experiments/predictions/non-anchor-position-period-v26.json`. Both
  `validate-preregistration` and `validate-prediction-artifact` pass. The
  artifact duplicates the existing period-family prediction target, so this is
  operational readiness inventory only and not new scored evidence.
- `non-anchor-position-period-v27.json` replaces the copied placeholder lane
  path with stable lane id `non-anchor-position-period-v27`, concrete
  non-anchor period-family rationale, predeclared discovery/evaluation inputs,
  and matching deterministic artifact
  `experiments/predictions/non-anchor-position-period-v27.json`. Both
  `validate-preregistration` and `validate-prediction-artifact` pass, and
  `independent-lane-status --format json` reports `invalid_lanes: 0`. The
  artifact duplicates the existing period-family prediction target, so this is
  operational readiness inventory only and not new scored evidence.
- `non-anchor-position-period-v28.json` replaces the copied placeholder prompt
  with stable lane id `non-anchor-position-period-v28`, concrete non-anchor
  period-family rationale, predeclared discovery/evaluation inputs, and
  matching deterministic artifact
  `experiments/predictions/non-anchor-position-period-v28.json`. Both
  `validate-preregistration` and `validate-prediction-artifact` pass. The
  artifact validator warns that it duplicates the existing period-family target,
  so this is valid inventory only and not new independent evidence.
- `non-anchor-position-period-v29.json` replaces the copied `new-lane-id`
  placeholder path with stable lane id `non-anchor-position-period-v29`,
  concrete non-anchor period-family rationale, predeclared
  discovery/evaluation inputs, and matching deterministic artifact
  `experiments/predictions/non-anchor-position-period-v29.json`. Both
  `validate-preregistration` and `validate-prediction-artifact` pass. The
  artifact validator warns that it duplicates the existing period-family target,
  so this is valid readiness inventory only and not new independent evidence.
- `non-anchor-position-period-v30.json` replaces the latest copied
  `new-lane-id` placeholder path with stable lane id
  `non-anchor-position-period-v30`, concrete non-anchor period-family
  rationale, predeclared discovery/evaluation inputs, and matching
  deterministic artifact
  `experiments/predictions/non-anchor-position-period-v30.json`. It validates
  as pure independent prediction-target inventory, but duplicates the existing
  period-family artifact and is not new independent scored evidence.
- `non-anchor-position-period-v31.json` replaces the latest copied
  `new-lane-id` placeholder request with stable lane id
  `non-anchor-position-period-v31`, concrete non-anchor period-family
  rationale, predeclared discovery/evaluation inputs, and matching
  deterministic artifact
  `experiments/predictions/non-anchor-position-period-v31.json`. It validates
  as pure independent prediction-target inventory, but duplicates the existing
  period-family artifact and is not new independent scored evidence.
- The findings ledger now guards `F5` against missing committed period
  preregistration/artifact source inputs.
- The findings ledger now guards `F7` against missing committed independent
  lane preregistration/artifact source inputs, including the spacing lane.
- The findings ledger now guards `F10` against stale independent-lane counts by
  comparing its summary against the live preregistration directory.

Next gate: do not add more public-anchor-derived candidate material. Before any
new scoring, create or receive a source-backed non-anchor observation file,
validate it with the family-specific observation validator, evaluate it with
the matching preregistration and artifact, and archive the evaluation output.

Archive validation hardening added: `validate-evaluation-archive` now revalidates
archived source-backed evaluations against the archived preregistration,
deterministic prediction artifact, linked source-review file, and observation
file. Tampered archives that rewrite both `observations.json` and `result.json`,
drop `source-review.json`, or swap in a mismatched preregistration family fail
validation before they can be treated as reproducible evidence.

Observation-note hardening added: source-backed observation files now require a
`position_notes` entry for every scored one-based position. The scaffold command
emits those notes, accepts repeatable `--position-note POS=NOTE` entries for
position-specific source notes, period and spacing validators reject missing or
placeholder notes, and archived source-backed evaluations require
`observations.json` `position_notes` to match `result.json`
`observation_position_notes`. This keeps future non-anchor evidence auditable
before any scoring result can be interpreted.

Next-evidence-gate checklist added: `next-evidence-gate` now joins the live
independent-lane inventory with `observation-sources` and emits the exact
scaffold, validation, evaluation, and archive-validation commands required for
period and spacing prediction families. At introduction, the command reported
16 ready lanes but only 2 unique ready prediction artifacts; current runs should
be treated as live state. Only `cia-artifact` and `cia-sculpture` are eligible
scored-observation sources. This is an operational gate, not evidence or a
promoted K4 result.

Non-anchor position universe added: `non-anchor-positions` now prints the 73
one-based positions that are eligible for future source-backed observation
files and the 24 excluded public-anchor positions. This is a setup aid for the
next evidence gate, not a structural score or candidate signal.

Report-output hardening added: `report --output` now writes through a temporary
file in the destination directory before replacing the generated report path.
Use this instead of shell redirection so a failed preflight-backed render cannot
truncate `notes/k4-report.md` before the command returns an error.

Independent evidence status added: `independent-evidence-status` now scans the
period and spacing observation-evaluation archive roots and reports whether any
valid source-backed independent evidence has actually been scored. At the time
this gate was added, the repo had 0 archived source-backed independent
evaluations, so the next productive step was a source-backed non-anchor
observation file followed by the validator/evaluator/archive gate sequence.

Next-evidence-gate now includes evidence archive status directly: it reports
valid source-backed archives and `evidence_available` directly. This keeps
ready lanes from being mistaken for scored independent evidence.

Next-evidence-gate now also reports duplicate prediction-artifact groups and a
readiness note. Lane count remains an operational inventory rather than an
independent evidence count.

Observation scaffold hardening: `init-position-observations` now rejects omitted
`--position-note` values instead of deriving notes from the rationale. Future
source-backed observation files must provide one explicit `POS=NOTE` entry per
scored position before validation or evaluation.

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
- prediction artifact validation: `valid: true`, `expected_period_count: 8`,
  `artifact_period_count: 8`, `promoted_candidate: false`
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

## 2026-05-28: Structural Model Rerun

Command:

```bash
cargo run --locked -- structural-models \
  --target spans \
  --alphabet kryptos \
  --iterations 100000 \
  --seed 67
```

Result summary:

- model count: 8
- fragments: 24 public span-derived additive fragments
- best raw model: `period-3-triad`
- best raw p-value: `0.1129`
- Holm-adjusted p-value: `0.9034`
- source-context model `period-14-grid-padding`: composite `0`, empirical
  `p=1.0000`, adjusted `p=1.0000`
- promoted: false

Interpretation: the current period-model registry does not show meaningful
candidate-independent structure on public span fragments, including the
source-grounded 7-by-14 padding model. Do not expand a period lane from this
public-fragment result. The only defensible use of the period registry is as a
preregistered rule for an independent future target.

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
`positions_one_based`, per-position `position_notes`, and rationale. This keeps
future non-anchor position evidence source-backed and auditable instead of only
accepting ad hoc comma-separated inputs.
`validate-period-observations` now checks those files before scoring, rejecting
unregistered source IDs, duplicate positions, and positions outside the
committed non-anchor prediction artifact. It also rejects unchanged template
placeholder text, requires a position note for every scored position, and
carries observation rationale into validation/evaluation output. Pass
`--preregistration` to validate the committed prediction artifact and
observation file in one pre-score gate; the same preregistration guard is
available on `evaluate-period-prediction` before scoring.

Concrete follow-up lane registered:
`experiments/preregistrations/non-anchor-position-period-followup-v1.json`
predeclares future independent non-anchor position observations as the
evaluation surface. It intentionally has no source IDs and validates only as a
pure independent prediction target. Its deterministic artifact at
`experiments/predictions/non-anchor-position-period-followup-v1.json` is
emitted by `period-prediction-plan --all --format json`, closing the earlier
gap where the preregistration was valid but not ready for source-backed
observation scoring.

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

Additional independent period lane populated:
`experiments/preregistrations/non-anchor-position-period-v4.json` carries
stable lane id `non-anchor-position-period-v4` and keeps the same position-only,
non-anchor prediction boundary. Its deterministic artifact at
`experiments/predictions/non-anchor-position-period-v4.json` is emitted by
`period-prediction-plan --all --format json`. Both preregistration and artifact
validation pass. This lane adds no candidate material and contributes no scored
evidence until source-backed non-anchor observations exist.

Additional independent period lane populated:
`experiments/preregistrations/non-anchor-position-period-v5.json` carries
stable lane id `non-anchor-position-period-v5`, replacing the temporary copied
placeholder filename with a concrete lane id. Its deterministic artifact at
`experiments/predictions/non-anchor-position-period-v5.json` is emitted by
`period-prediction-plan --all --format json`. `validate-preregistration`,
`validate-prediction-artifact`, `independent-lane-status`, and `release-check`
all pass. This is still a pre-scoring, source-backed-observation target only;
it adds no plaintext, candidate material, or promoted evidence.

Source-backed observation scaffold added:
`init-position-observations` creates a source-backed non-anchor observation JSON
file without hand-editing template placeholders. It rejects placeholder fields,
unregistered or disallowed source IDs, duplicate positions, public-anchor
positions, out-of-range positions, and accidental overwrites unless `--force` is
passed. The command is a file-creation guard only; the resulting file must still
pass `validate-period-observations` or `validate-spacing-observations` with the
matching preregistration and prediction artifact before scoring.

Observation source eligibility report added:
`observation-sources` lists every registered source and marks whether its
`allowed_use` boundary can support scored independent position observations.
Current eligible sources are the primary public-facts-only CIA source records;
public-anchor summaries, public-clue context, methodology context, and archive
context remain ineligible for scoring and can only support rationale or
stopped-lane documentation.

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

Independent lane status command added:
`independent-lane-status --format json` scans the preregistration directory,
validates each preregistration and committed prediction artifact, and reports
the next validator/evaluator command for each lane. Earlier status snapshot: 18 lanes,
18 ready for source-backed observations, 0 invalid lanes, 18 prediction
artifacts, 2 unique prediction artifact contents, 2 unique ready prediction
artifact contents, 1 duplicate artifact group, period family 17 lanes/1 unique
ready artifact, spacing family 1 lane/1 unique ready artifact, promoted false.
This is an
operational gate summary only; it adds no plaintext, key material, or scored
evidence.

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

`source-intake-packet` now prints the concrete gate for the first option:
required source-registry fields, allowed-use boundaries, quote-free archive
requirements, scoreable-evidence requirements, rejection rules, follow-up
commands, and an archive template. `validate-source-archive` now provides the
matching standalone gate for a draft quote-free local source snapshot before it
is committed or scored. Current web/source reconnaissance did not identify a
new immediately scoreable source; the visible candidates are still
context/reporting, public clue summaries, methodology archives, or quarantined
claim material. New source work must therefore pass the intake packet and
source-archive validator before it can alter `source-frontier` or
`next-evidence-gate` evidence status.

Before implementation, validate a lane-specific preregistration:

```bash
cargo run --locked -- validate-preregistration --input <lane-preregistration.json>
```

## Source-Review Status Gate

`non-anchor-position-period-v17.json` has been populated from the copied-lane
prompt with a stable id, concrete non-anchor rationale, independent prediction
target, predeclared discovery/evaluation inputs, and explicit null and
multiple-comparison controls. It now points at the matching deterministic period
prediction artifact. Single-lane validation, artifact validation, and
`independent-lane-status` report the lane as valid and ready for source-backed
observations; the lane remains an independent prediction target, not scored
evidence.

`source-review-status` now scans saved pre-score source-review artifacts before
observation scaffolding. `experiments/source-reviews/cia-source-review-v1.json`
records a pre-score review of the CIA Kryptos artifact and sculpture pages for
`cia-artifact` and `cia-sculpture`; `validate-source-review --format json`
reports `valid=true`, `reviewed_source_count=2`, and
`missing_local_archive_count=0`. The reviewed source snapshots are stored in
`sources/archives/cia-artifact-2026-05-27.md` and
`sources/archives/cia-sculpture-2026-05-27.md`.

`next-evidence-gate --format json` now reports `source_review_available=true`
with one valid source-review file, `evidence_available=true`, and four valid
source-backed archives. Those archives are the CIA row-boundary period,
spacing, mirror, and grid evaluations. Interpretation: source-backed observation
scoring is now archived and auditable, but the scored controls are negative and
no candidate is promoted. The same gate now emits:

- next action kind:
  `new-source-backed-rationale-or-distinct-prediction-artifact`
- blocking condition: `duplicate-period-lanes-not-evidence`
- blocking condition: `source-backed-evidence-negative-or-non-significant`
- blocking condition: `unused-eligible-source-marked-non-scorable`

`source-observation-status --format json` now exposes the same source-readiness
boundary as a focused pre-score command. Current interpretation:
`cia-sculpture` is reviewed, has scored-position markers, and is already used
by archived source-backed evaluations; `cia-artifact` is reviewed and locally
archived but has no scored-position markers, has no source-backed archive use,
and now carries an explicit archive-level `non_scorable_reason` noting that the
reviewed facts do not provide one-based non-anchor K4 positions. Do not scaffold
or score `cia-artifact` observations until a new source-backed rationale selects
one-based non-anchor positions with per-position notes. The
`next-evidence-gate --format json` checklist now includes the focused
`source_observation_status_command` field so this readiness check is part of the
standard evidence gate output, not a separate remembered step. The
`source-review-packet --format json` output now includes the same command field,
so the pre-score review packet points directly to the readiness check before
any observation scaffold is generated. `release-check --format json` now also
includes `source-readiness-commands-documented`, which fails if the readiness
command disappears from release-facing docs or the generated report.
`release-check` also rejects source archives with an empty
`non_scorable_reason` marker or with both `non_scorable_reason` and
`scored_positions_one_based`, so context-only archive boundaries cannot be
silently mixed with scored observation markers.

`source-observation-status` now includes archived evidence summaries for each
already-used eligible source. For `cia-sculpture`, the status output carries
the archived period, spacing, mirror, grid, and Tableau/HILL support summaries,
including best model, observed hits, null mean best hits, empirical p-value,
and `negative/non-significant` support status. This keeps the current negative
evidence visible at the pre-scaffold source-readiness gate instead of requiring
a separate manual scan of result directories. `cia-artifact` still has no
archived evidence summaries because it has not supplied scored-position markers
or a source-backed observation rationale.

`next-evidence-gate --format json` now also exposes structured
`evidence_support_details` for each valid source-backed archive. These entries
include archive directory, artifact kind, observation source IDs, best model,
observed hits, null mean best hits, empirical p-value, and support status. The
Markdown gate prints the same detail table. This makes the negative
row-boundary archive evidence machine-readable at the main operational gate,
not only in
`independent-evidence-status` or `source-observation-status`.

`scientific-american-2025` now has a quote-free local archive at
`sources/archives/scientific-american-2025-final-clues-2026-05-27.md` and is
listed in `sources/source-packet.md`. The archive records public clue context
from the 2025 final-clues report, including the Berlin World Clock
clarification and K5 parallel-position context, but it remains
`public-clue-context`, not an eligible scored-observation source. It adds no
K4 plaintext, route, key material, candidate evidence, or promoted result.

The two Associated Press 2025 reporting sources and the Smithsonian 2026
archive-discovery report are now also locally archived:
`sources/archives/ap-2025-auction-2026-05-27.md` and
`sources/archives/ap-2025-archive-sale-2026-05-27.md`, and
`sources/archives/smithsonian-2026-archive-discovery-2026-05-28.md`. These
snapshots are quote-free archive-sale or archive-discovery context only. They
document the archive-discovery versus decipherment boundary, sale-history
context, and institutional provenance, but they do not provide scored non-anchor
observations, candidate material, key streams, routes, plaintext, or promoted
evidence.

Remaining registered context/reference sources are now locally archived as
quote-free snapshots as well:
`sources/archives/elonka-kryptos-2026-05-27.md`,
`sources/archives/histocrypt-2021-bean-2026-05-27.md`, and
`sources/archives/kryptosbot-methodology-2026-05-27.md`. These archives tighten
the source packet and release preflight boundaries around public anchors,
cryptodiagnosis context, and methodology/claim-taxonomy context. They do not
create new scored evidence or change the current `next-evidence-gate`
recommendation.

## 2026-05-27 - External Plaintext Claim Quarantine

The SolveKryptos external solution claim remains registered only as
`unverified-solution-claim`; the local archive is quote-free and does not copy
claimed plaintext. A new `verify-plaintext-claim` command screens a local claim
file for normalized length, public-anchor compatibility, and aggregate shift
diagnostics without printing or storing the claim text. The command rejects
source IDs that are not explicitly quarantined as `unverified-solution-claim`
and always reports `promoted: false`.

Follow-up guardrail: `verify-claim-reconciliation` now applies the same
quarantine boundary to local reconciliation tables. It checks row count,
one-based position sequence, K4 ciphertext alignment, public-anchor
compatibility, and aggregate shift diagnostics while omitting any claimed
plaintext column from Markdown and JSON output.

Follow-up hardening: `next-evidence-gate` now reports quarantined
plaintext-claim source IDs separately from eligible scored-observation sources
and prints the safe plaintext and reconciliation verifier commands. This keeps
current public solution-claim material on the claim-verification path instead
of allowing it to masquerade as source-backed evidence or candidate material.

Follow-up check: the public SolveKryptos claim text was screened through
`verify-plaintext-claim` using a temporary local file that was deleted after
the command completed. The verifier reported `length_matches=true`, 97
normalized letters, `public_anchor_match_count=4` out of 4, all 26 implied
shift values present, 71 repeated shift values, maximum shift bucket count 8,
`structural_checks_passed=true`, and `promoted_candidate=false`. This is only a
quarantine structure check: it confirms compatibility with currently registered
public anchors, but it does not independently verify the claimed mechanism or
promote any plaintext, key stream, source-derived hypothesis, or candidate.

## 2026-05-28 - Duplicate Period-Lane Consistency Check

`non-anchor-position-period-v35` now points at its own committed artifact,
`experiments/predictions/non-anchor-position-period-v35.json`, instead of the
shared v1 artifact path. Focused validation confirms the lane is internally
consistent: `validate-preregistration --format json` reports `valid: true`,
and `validate-prediction-artifact --format json` reports `valid: true` with
eight expected period plans.

The distinct-target guard also behaves as intended:
`validate-prediction-artifact --require-unique-artifact --format json` fails
for v35 because the artifact duplicates 36 other committed period artifacts.
That failure is the expected safety signal. The v35 lane remains operational
readiness inventory only, not a new K4 signal, key, plaintext, or promoted
candidate.

## 2026-05-28 - NSA Declassified Physical-Context Source Intake

`nsa-declassified-kryptos-doc3` is now registered with a quote-free local
archive at
`sources/archives/nsa-declassified-kryptos-doc3-2026-05-28.md`. The declassified
document supplies physical-context notes around the sculpture, including
compass/lodestone, Morse, dimensions, and installation-layout context.

The source is deliberately classified as `archive-context-only`, not
`public-facts-only`, because the reviewed facts do not provide one-based
non-anchor K4 positions or a source-backed K4 position-selection rule. It may
support future preregistration rationale for a physical-context model, but it
does not alter the current source-backed evidence status and promotes no
candidate, key, route, plaintext, or solution.

Follow-up hardening: the archive now carries an explicit
`non_scorable_reason` matching that boundary. This makes the source reviewable
without leaving an ambiguous warning about missing scored positions, while
preserving the rule that archive-context-only material cannot be scored as
independent K4 evidence.

The related `nsa-kryptos-foia-release-index` source is also registered with a
quote-free local archive at
`sources/archives/nsa-kryptos-foia-release-index-2026-05-28.md`. This records
the NSA declassification index as source-discovery provenance for the CIA
Kryptos Sculpture document set. The index remains `archive-context-only` with
an explicit `non_scorable_reason`: it can point future source intake toward
underlying primary documents, but it does not itself provide scored K4
positions, key material, routes, plaintext, or a promoted candidate.

## 2026-05-28 - Ciphertext Residue-Balance Prior Lane

Added `ciphertext-residue-balance-prior-v1` as a populated independent
prediction-target lane. The lane uses hypothesis family
`ciphertext-residue-balance-position-prior`, does not use public
anchor-derived fragments for discovery or primary evidence, and points to the
committed deterministic artifact
`experiments/predictions/ciphertext-residue-balance-prior-v1.json`.

The new `ciphertext-residue-balance-prior` command emits a ciphertext-only
planning artifact over the 73 non-anchor K4 positions. For each modulus 2
through 13, it predeclares the non-anchor residue class with the highest
distinct ciphertext-letter rate, with larger position count and then lower
residue number as deterministic tie-breakers. This is a prediction target for
future source-backed non-anchor observations only; it is not a key, route,
plaintext, solution claim, or promoted candidate.

Validation status: `validate-preregistration` passes for the lane, and
`validate-prediction-artifact` confirms 12 expected residue sets and 12
committed artifact residue sets. The only warning is the expected one for a
pure independent prediction target with no source IDs attached.

The committed CIA row-boundary source-backed observation now includes a
residue-balance evaluation archive under
`results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-v1`.
The best residue-balance target is modulus `2`, residue `0`, with `4/6`
observed positions and seeded best-of-modulus empirical `p=0.4803`. This is
negative/non-significant evidence and promotes no candidate.

## 2026-05-28 - Source Archive Non-Scorable Marker Sweep

All local source archives now take one of two explicit shapes: either they
carry `scored_positions_one_based` markers that back a committed observation
file, or they carry a `non_scorable_reason` explaining why the source cannot be
used as scored independent K4 evidence in its current form. This hardens the
source frontier against accidental promotion of public-anchor summaries,
methodology context, archive-sale reporting, archive-discovery context,
archive-research context, or quarantined solution claims.

This sweep does not change the evidence status. `cia-sculpture` remains the
only source with scored-position markers, its archived source-backed evaluations
remain negative/non-significant, `cia-artifact` remains explicitly
non-scorable, and no candidate, key, route, plaintext, or solution is promoted.

## 2026-05-28 - Stable Preregistration Replacement for Placeholder Lane

The copied placeholder lane path was replaced with stable preregistration
inventory under `experiments/preregistrations/non-anchor-position-period-v37.json`
and matching deterministic artifact
`experiments/predictions/non-anchor-position-period-v37.json`. The populated
fields declare the lane id, title, hypothesis family, rationale,
prediction target, discovery inputs, evaluation inputs, and controls without
using public anchor-derived additive fragments as discovery or primary
evidence.

Validation status: `validate-preregistration` passes, and
`validate-prediction-artifact` confirms the committed artifact matches the
deterministic period prediction plan. The artifact duplicates 38 other
period-family artifacts, so `validate-prediction-artifact
--require-unique-artifact` correctly fails. This lane is therefore duplicate
readiness inventory only, not a distinct prediction target, score, key,
plaintext, solution, or promoted candidate.

## 2026-05-28 - Ciphertext Rarity Prior Added

Added `ciphertext-rarity-prior-v1` as a distinct ciphertext-only independent
prediction target rather than another duplicate period lane. The new
preregistration lives at
`experiments/preregistrations/ciphertext-rarity-prior-v1.json`, with committed
artifact `experiments/predictions/ciphertext-rarity-prior-v1.json`.

The artifact fixes the 20 non-anchor positions whose ciphertext letters are
rarest in the non-anchor universe, tie-breaking by lower one-based position. It
uses public K4 ciphertext for discovery and the known clue spans only as an
exclusion mask; it does not use candidate words, routes, public-anchor additive
fragments, claimed plaintext, or anchor-derived match counts as evidence.

Validation status: `validate-prediction-artifact` passes for the new lane.
`independent-lane-status` now reports:

- independent lanes: `48`
- ready for source-backed observations: `48`
- prediction artifacts: `48`
- unique ready prediction targets: `10`
- ciphertext-rarity-position-prior-family lanes: `1`
- ciphertext-rarity-position-prior-family unique ready targets: `1`

The already committed CIA row-boundary observation was scored against this new
target and archived under
`results/ciphertext-rarity-observations/cia-k4-row-boundaries-v1`.
Result: `2/6` rare-position hits, null mean `1.64`, null sd `1.05`,
empirical `p=0.5282` over `100000` seeded shuffles, promoted `false`.
This is negative/non-significant source-backed evidence, not a K4 solution.

## 2026-05-28 - Ciphertext Transition Prior Added

Added `ciphertext-transition-prior-v1` as another distinct ciphertext-only
independent prediction target, replacing the copied-placeholder pattern with a
stable lane id, title, hypothesis family, rationale, prediction target,
discovery inputs, evaluation inputs, and controls. The new preregistration lives
at `experiments/preregistrations/ciphertext-transition-prior-v1.json`, with
committed artifact `experiments/predictions/ciphertext-transition-prior-v1.json`.

The artifact maps K4 ciphertext letters onto Kryptos alphabet order, sums
circular adjacent-letter distances for each non-anchor position, and fixes the
20 highest adjacent-transition-pressure positions before scoring any future
source-backed observation. It uses public K4 ciphertext for discovery and the
known clue spans only as an exclusion mask; it does not use candidate words,
routes, public-anchor additive fragments, claimed plaintext, or anchor-derived
match counts as evidence.

Validation status: `validate-preregistration` and `validate-prediction-artifact
--require-unique-artifact` pass for the new lane. `independent-lane-status` now
reports:

- independent lanes: `49`
- ready for source-backed observations: `49`
- prediction artifacts: `49`
- unique ready prediction targets: `11`
- ciphertext-transition-position-prior-family lanes: `1`
- ciphertext-transition-position-prior-family unique ready targets: `1`

The already committed CIA row-boundary observation was scored against this new
target and archived under
`results/ciphertext-transition-observations/cia-k4-row-boundaries-v1`.
Result: `0/6` transition-position hits, null mean `1.63`, null sd `1.05`,
empirical `p=1.0000` over `100000` seeded shuffles, promoted `false`. This is
negative/non-significant source-backed evidence, not a K4 solution.

## 2026-05-28 - Skip-Transition Draft Preregistration

`experiments/preregistrations/ciphertext-skip-transition-v1.json` replaces the
copied placeholder concept with a stable draft lane ID, plain title,
`ciphertext-skip-transition-position-prior` hypothesis family, non-anchor
ciphertext-only discovery inputs, independent future source-backed evaluation
inputs, and seeded null/multiple-comparison controls.

Validation status: `validate-preregistration` and `validate-prediction-artifact
--require-unique-artifact` pass with only the expected pure-independent-target
warning about no source IDs. The lane now has deterministic artifact, artifact
validator, evaluator, and archive validator support for source-backed
non-anchor observation files.

`independent-lane-status` now reports:

- independent lanes: `50`
- ready for source-backed observations: `50`
- prediction artifacts: `50`
- unique ready prediction targets: `12`
- ciphertext-skip-transition-position-prior-family lanes: `1`
- ciphertext-skip-transition-position-prior-family unique ready targets: `1`

The existing CIA row-boundary source-backed observation was scored through the
new skip-transition evaluator at
`results/ciphertext-skip-transition-observations/cia-k4-row-boundaries-v1`:
0/6 skip-transition hits, null mean 1.64, empirical p-value 1.0000, promoted
false. The result is negative and does not promote any K4 solution, key, route,
plaintext, or candidate.

## 2026-05-28 - Stopped-Lane Documentation Tightened

The live gates still report all committed source-backed observation evidence as
negative/non-significant and `cia-artifact` remains reviewed but explicitly
non-scorable from its current archive. No K4 solution, key, route, plaintext, or
candidate was promoted.

Documentation was tightened so the human-facing stopped-lane and command
inventory now names the full current CIA row-boundary evaluation surface:
period, spacing, mirror, grid, Tableau/HILL, ciphertext-prior,
ciphertext-hotspot, ciphertext-rarity, ciphertext-transition, and
ciphertext-residue-balance. The stopped-lane boundary now explicitly blocks
retuning ciphertext-only position heuristics against the same row-boundary
positions unless a new source-backed observation or preregistered prediction
target is fixed before scoring.

## 2026-05-28 - Ciphertext Hotspot Archive Scored

## 2026-06-01: Wide Ciphertext Period-Match Lane Scored Negative

Added `ciphertext-period-match-wide-v1`, a wider ciphertext-only shifted
same-letter period-match endpoint prior. The preregistration fixes periods
`1..=26` and the top 7 selected periods before scoring. Discovery uses only K4
ciphertext self-coincidence structure, with public anchors used only as an
exclusion mask and no candidate words, routes, key material, plaintext claims,
or public-anchor additive fragment scoring.

Committed files:

- `experiments/preregistrations/ciphertext-period-match-wide-v1.json`
- `experiments/predictions/ciphertext-period-match-wide-v1.json`
- `results/ciphertext-period-match-observations/cia-k4-row-boundaries-wide-v1/`

Validator/tooling update:

- `validate-prediction-artifact` now reads preregistered
  `ciphertext_period_match_max_period` and
  `ciphertext_period_match_top_periods` fields instead of validating only the
  default period-match artifact shape.
- `validate-evaluation-archive` applies the same preregistered period-match
  parameters to archived source-backed evaluations.

Commands run:

```bash
cargo run --locked -- ciphertext-period-match-prior \
  --max-period 26 \
  --top-periods 7 \
  --format json > experiments/predictions/ciphertext-period-match-wide-v1.json

cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/ciphertext-period-match-wide-v1.json \
  --format json

cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/ciphertext-period-match-wide-v1.json \
  --require-unique-artifact \
  --format json

cargo run --locked -- evaluate-ciphertext-period-match \
  --artifact experiments/predictions/ciphertext-period-match-wide-v1.json \
  --preregistration experiments/preregistrations/ciphertext-period-match-wide-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-period-match-observations/cia-k4-row-boundaries-wide-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-period-match-observations/cia-k4-row-boundaries-wide-v1 \
  --format json
```

Result: best selected period `2`, `1/6` hits, null mean `1.7441`, null sd
`0.6998`, empirical `p=0.9934`, promoted `false`. This is
negative/non-significant source-backed evidence, not a K4 solution.

Current inventory markers:

- independent lanes: `81`
- ready for source-backed observations: `81`
- prediction artifacts: `81`
- unique ready prediction targets: `39`
- ciphertext-period-match-position-prior-family lanes: `2`
- ciphertext-period-match-position-prior-family unique ready targets: `2`

The previously preregistered `ciphertext-hotspot-prior-v1` lane was scored
against the committed CIA row-boundary observation so the archive inventory no
longer has a ready-but-unscored ciphertext-only target.

Commands run:

```bash
cargo run --locked -- validate-ciphertext-hotspot-observations \
  --artifact experiments/predictions/ciphertext-hotspot-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-hotspot-prior-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-ciphertext-hotspot \
  --artifact experiments/predictions/ciphertext-hotspot-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-hotspot-prior-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-hotspot-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-hotspot-observations/cia-k4-row-boundaries-v1 \
  --format json
```

Result: `0/6` hotspot hits, null mean `1.64`, null sd `1.05`, empirical
`p=1.0000`, promoted `false`. This is negative/non-significant source-backed
evidence, not a K4 solution.

## 2026-05-28 - Ciphertext Turning-Point Lane Added

Added `ciphertext-turning-point-v1` as a distinct ciphertext-only independent
prediction lane. The lane uses only K4 ciphertext letters mapped into the
Kryptos alphabet and predeclares the 20 non-anchor positions with strongest
local turning-point structure: local extrema first, then higher
second-difference curvature. It does not use public known-plaintext anchors,
candidate words, key material, routes, or previously scored observation
positions for discovery.

Committed files:

- `experiments/preregistrations/ciphertext-turning-point-v1.json`
- `experiments/predictions/ciphertext-turning-point-v1.json`

Current independent-lane inventory markers:

- independent lanes: `51`
- ready for source-backed observations: `51`
- prediction artifacts: `51`
- unique ready prediction targets: `13`
- ciphertext-turning-point-position-prior-family lanes: `1`
- ciphertext-turning-point-position-prior-family unique ready targets: `1`

Validation status:

- `validate-preregistration` passes with only the expected pure-independent
  warning about no source IDs.
- `validate-prediction-artifact --require-unique-artifact` passes with artifact
  kind `ciphertext-turning-point`, 20 committed positions, and no duplicate
  artifact warning.
- `validate-ciphertext-turning-point-observations` accepts
  `experiments/position-observations/cia-k4-row-boundaries-v1.json`.
- `validate-evaluation-archive` accepts
  `results/ciphertext-turning-point-observations/cia-k4-row-boundaries-v1`.

The existing CIA row-boundary source-backed observation was scored through the
new turning-point evaluator:

- observed positions: `1, 4, 5, 36, 37, 97`
- matching turning-point positions: `5, 37`
- result: `2/6` turning-point hits
- null mean: `1.64`
- null sd: `1.05`
- empirical p-value: `0.5247`
- promoted: `false`

This is negative/non-significant source-backed evidence. It does not promote a
K4 solution, key, route, plaintext, or candidate.
