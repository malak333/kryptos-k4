# Kryptos K4 Constraint Report

This report uses public anchors only and is not a claimed solution. Production readiness here means the local, source-grounded research CLI and release package are repeatable and bounded; it does not mean Kryptos K4 is solved or that any candidate plaintext, key, route, or method is promoted.

## Research Boundary and Production Readiness

- Evidence boundary: public ciphertext, public known-plaintext anchors, source provenance, deterministic controls, and pre-registered exploratory screens only.
- Research boundary: no generated plaintext is treated as decoded K4 text; all promoted-candidate flags remain false unless independent corroboration and stronger samples justify a future change.
- Production-readiness scope: local Rust CLI, report rendering, JSON output, candidate registry alignment, source packet/source registry field and access-date alignment, release preflight, and no-GitHub-Actions policy. External publication, peer review, and cryptanalytic validation remain outside this report.

## Feature Coverage

| Feature | Included result |
| --- | --- |
| `facts` | Ciphertext length, ciphertext, and evidence boundary in Markdown or JSON. |
| `ciphertext-profile` | Ciphertext-only frequency, repeated n-gram spacing, index-of-coincidence, period-coincidence diagnostics, and optional seeded shuffle baselines without anchors, candidate material, claimed plaintext, or promotion in Markdown or JSON. |
| `ciphertext-structure-prior` | Planning-only ciphertext-derived position prior for future source-backed observations, selecting weak ciphertext-only diagnostics without treating them as evidence in Markdown or JSON. |
| `evaluate-ciphertext-prior` | Source-backed non-anchor position evaluator for the planning-only ciphertext-derived prior, with seeded same-size non-anchor position-shuffle controls and optional self-contained archives for observations, linked source review, result, summary, and replay command in Markdown or JSON. |
| `ciphertext-hotspot-prior` | Planning-only ciphertext hotspot prior for future source-backed observations, fixing top repeated-ngram and shifted-coincidence endpoint positions without treating them as evidence in Markdown or JSON. |
| `evaluate-ciphertext-hotspot` | Source-backed non-anchor position evaluator for the committed ciphertext-hotspot prior, with seeded same-size non-anchor position-shuffle controls and optional self-contained archives in Markdown or JSON. |
| `ciphertext-repeat-distance-prior` | Planning-only ciphertext repeat-distance prior for future source-backed observations, fixing same-symbol repeat-distance non-anchor positions without treating them as evidence in Markdown or JSON. |
| `ciphertext-adjacent-contrast-prior` | Planning-only ciphertext adjacent-contrast prior for future source-backed observations, fixing high left/right neighbor-contrast non-anchor positions without treating them as evidence in Markdown or JSON. |
| `ciphertext-turning-point-prior` | Planning-only ciphertext turning-point prior for future source-backed observations, fixing local extrema/high-curvature non-anchor positions from Kryptos-alphabet ciphertext only in Markdown or JSON. |
| `ciphertext-window-balance-prior` | Planning-only ciphertext local-window balance prior for future source-backed observations, fixing centered-window balance non-anchor positions from Kryptos-alphabet ciphertext only in Markdown or JSON. |
| `ciphertext-ct-perturbation-prior` | Planning-only source-grounded ciphertext C/T perturbation prior for future source-backed observations, fixing non-anchor C/T ciphertext positions in Markdown or JSON. |
| `anchors` | Public known-plaintext anchors with positions, source IDs, confidence, claim type, and notes in Markdown or JSON. |
| `constraints` | Per-anchor key fragments across supported alphabets and modes, with recurrence screens in Markdown or JSON. |
| `key-fragments` | The same fragment rows are rendered in full for anchors and adjacent spans in Markdown or JSON. |
| `test-key` | Proposed key material is transformed and compared against public span additive fragments at true K4 positions, with optional cyclic offset sweep and seeded sweep baseline in Markdown or JSON. |
| `explain-key` | Exact matching public-span positions, modulo caveats, descriptive pattern metrics, and composite pattern score in Markdown or JSON. |
| `batch-test-keys` | CSV candidate rows are ranked with the same public-fragment checks, optional output artifacts, and batch-level controls in Markdown or JSON. |
| `batch-test-routed-keys` | Registered route/permutation families are applied before candidate scoring, with routed search-surface controls in Markdown or JSON. |
| `heldout-key-control` | Leave-one-public-group-out candidate selection and withheld-group scoring with seeded null controls in Markdown or JSON. |
| `summarize-key-runs` | Historical scanner for batch result folders, ranking individual runs and per-candidate p-value stability in Markdown or JSON. |
| `position-structure` | Candidate-independent residue/spacing control over public fragment positions in Markdown or JSON. |
| `structural-models` | Pre-registered period-model controls over public fragment positions in Markdown or JSON. |
| `validate-preregistration` | Research-lane gate for future source evidence or independent prediction targets in Markdown or JSON. |
| `validate-prediction-artifact` | Gate confirming committed independent prediction artifacts still match their preregistration and deterministic generator, with optional `--require-unique-artifact` duplicate rejection for distinct-target work, in Markdown or JSON. |
| `independent-lane-status` | Operational summary of preregistered independent lanes, artifact validity, family summaries, unique ready prediction artifacts, duplicate artifact groups, duplicate/extra duplicate artifact lane counts, and the next source-backed observation gate in Markdown or JSON. |
| `next-evidence-gate` | Operational checklist joining lane readiness, unique/duplicate prediction-target accounting, evaluator-pending lane inventory, eligible observation sources, used/unused eligible source accounting, unused-source scored-position marker and non-scorable status, quarantined plaintext-claim source IDs with the safe verifier commands and committed claim-verification archive inventory, current evidence-archive score direction, source-backed archive-surface adjusted p-values, structured archive support details including null means, all-source-backed-archives-negative flags before and after correction, machine-readable next-action/blocking-condition fields, explicit next-check commands including `--require-unique-artifact`, recommended next evidence step, required observation fields, and exact scaffold/validate/evaluate/archive commands before future source-backed scoring in Markdown or JSON. |
| `independent-evidence-status` | Archive status for source-backed period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-CT-perturbation/ciphertext-Stehle-regularity/ciphertext-residue-balance observation evaluations, separating valid source-backed evidence, diagnostic archives, invalid archives, no-evidence states, and per-archive score direction in Markdown or JSON. |
| `source-review-status` | Pre-score source-review artifact scanner, separating valid reviews, invalid reviews, missing review roots, and no-review states in Markdown or JSON. |
| `source-observation-status` | Pre-score source readiness table for eligible observation sources, showing source-review coverage, local archive state, scored-position marker state, existing source-backed archive usage, archived evidence support status and null means for used sources, an all-source-backed-archives-negative flag, and the allowed next action in Markdown or JSON. |
| `source-review-packet` | Pre-score source review packet for eligible observation sources, local archive status, source URLs, use boundaries, and required review steps in Markdown or JSON. |
| `source-intake-packet` | New-source intake checklist with registry fields, allowed-use boundaries, quote-free archive requirements, scoreable-evidence requirements, rejection rules, follow-up commands, and an archive template in Markdown or JSON. |
| `validate-source-archive` | Standalone gate for quote-free local source snapshots, checking registered source metadata, required archive markers, no-promotion boundary, non-scorable/scored-position consistency, and scored-position use boundaries in Markdown or JSON. |
| `source-frontier` | Source-use frontier table for every registered source, classifying scored-observation-ready, currently non-scorable, context-only, and quarantined-claim sources, with prior source-backed archive counts, all-negative archive status, support statuses for already-used sources, machine-readable frontier blockers, required next-evidence criteria, disallowed next actions, and a concise Markdown `--summary` mode before future evidence work. |
| `init-source-review` | Guarded pre-score source-review file creator that records reviewed eligible sources, local archive status, required review steps, and review notes before any observation positions are selected. |
| `validate-source-review` | Gate for pre-score source-review artifacts, checking reviewed source IDs and metadata against the registered eligible source set in Markdown or JSON. |
| `non-anchor-positions` | Non-scoring one-based K4 position universe for future source-backed observations, including excluded public anchor ranges, in Markdown or JSON. |
| `init-position-observations` | Guarded source-backed observation-file creator that writes registered-source non-anchor positions plus required per-position notes (`--position-note POS=NOTE`) only, can link a validated source-review artifact, and performs no scoring, in Markdown or JSON. |
| `observation-sources` | Focused source-use report for scored independent position observations, separating eligible public-facts sources from context-only sources in Markdown or JSON. |
| `validate-period-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before period prediction scoring in Markdown or JSON. |
| `validate-ciphertext-prior-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-prior artifact preregistration validation before ciphertext-prior scoring in Markdown or JSON. |
| `validate-ciphertext-hotspot-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-hotspot artifact preregistration validation before ciphertext-hotspot scoring in Markdown or JSON. |
| `validate-ciphertext-rarity-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-rarity artifact preregistration validation before ciphertext-rarity scoring in Markdown or JSON. |
| `validate-ciphertext-repeat-distance-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-repeat-distance artifact preregistration validation before ciphertext-repeat-distance scoring in Markdown or JSON. |
| `validate-ciphertext-adjacent-contrast-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-adjacent-contrast artifact preregistration validation before ciphertext-adjacent-contrast scoring in Markdown or JSON. |
| `validate-ciphertext-transition-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-transition artifact preregistration validation before ciphertext-transition scoring in Markdown or JSON. |
| `validate-ciphertext-skip-transition-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-skip-transition artifact preregistration validation before ciphertext-skip-transition scoring in Markdown or JSON. |
| `validate-ciphertext-turning-point-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-turning-point artifact preregistration validation before ciphertext-turning-point scoring in Markdown or JSON. |
| `validate-ciphertext-window-balance-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-window-balance artifact preregistration validation before ciphertext-window-balance scoring in Markdown or JSON. |
| `validate-ciphertext-ct-perturbation-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-CT-perturbation artifact preregistration validation before C/T-position enrichment scoring in Markdown or JSON. |
| `validate-ciphertext-stehle-regularity-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-Stehle-regularity artifact preregistration validation before Stehle-window scoring in Markdown or JSON. |
| `validate-spacing-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before spacing prediction scoring in Markdown or JSON. |
| `validate-mirror-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before mirror prediction scoring in Markdown or JSON. |
| `validate-grid-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before grid-layout prediction scoring in Markdown or JSON. |
| `validate-tableau-hill-observations` | Non-scoring gate for source-backed Tableau/HILL source-map observations, per-position notes, source allowed-use compatibility, linked source-review coverage, committed source-map coverage, and padding/public-anchor rejection before `evaluate-tableau-hill-prediction` can score them in Markdown or JSON. |
| `period-prediction-plan` | Non-anchor residue-class target emission for a registered period, without scoring public fragment values, in Markdown or JSON. |
| `spacing-prediction-plan` | Non-anchor spacing residue-class target emission for registered moduli, without scoring fragment values or candidate words, in Markdown or JSON. |
| `mirror-prediction-plan` | Non-anchor mirror-pair target emission across the 97-character position axis, without scoring fragment values or candidate words, in Markdown or JSON. |
| `grid-layout-prediction-plan` | Non-anchor 7-by-14 padded grid-layout artifact emission with an explicit scored row, column, or compass axis, without scoring fragment values or candidate words, in Markdown or JSON. |
| `tableau-hill-prediction-plan` | Fixed HILL/tableau source-mapping artifact emission for source-backed row/column concentration evaluation, without scoring fragment values, candidate words, or public-anchor-derived evidence, in Markdown or JSON. |
| `evaluate-period-prediction` | Independent-position evaluator for committed period prediction artifacts with best-of-period null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-spacing-prediction` | Independent-position evaluator for committed spacing prediction artifacts with best-of-modulus null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-mirror-prediction` | Independent-position evaluator for committed mirror prediction artifacts with seeded same-size non-anchor position-set null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-grid-prediction` | Independent-position evaluator for committed 7-by-14 grid-layout artifacts with selected row, column, or compass-axis scoring, seeded same-size non-anchor position-set null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation and matching preregistered `grid_edge_axis`, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, selected edge axis, and scored observation input, and Markdown/JSON output. |
| `evaluate-tableau-hill-prediction` | Independent-position evaluator for committed Tableau/HILL 7-by-14 source-map artifacts with best row/column concentration scoring, seeded same-size non-anchor position-set null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-rarity` | Independent-position evaluator for committed ciphertext rare-letter position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-repeat-distance` | Independent-position evaluator for committed ciphertext same-symbol repeat-distance position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-adjacent-contrast` | Independent-position evaluator for committed ciphertext adjacent-contrast position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-transition` | Independent-position evaluator for committed ciphertext adjacent-transition position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-skip-transition` | Independent-position evaluator for committed ciphertext skip-transition position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-turning-point` | Independent-position evaluator for committed ciphertext local turning-point position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-window-balance` | Independent-position evaluator for committed ciphertext local-window balance position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-ct-perturbation` | Independent-position evaluator for committed ciphertext C/T perturbation artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-stehle-regularity` | Independent-position evaluator for the committed source-described Stehle local-regularity artifact with seeded same-size non-anchor position-set null controls over both the full window and lag-confirmed +5 subset, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives, and Markdown/JSON output. |
| `validate-evaluation-archive` | Archive gate for independent observation evaluations, checking required files, matching evaluator command name, local replay command paths, artifact kind, source-backed observation consistency, archived source-review/preregistration/artifact/observation validity, and no-promotion boundaries in Markdown or JSON. |
| `baseline` | Seeded false-positive controls for anchors and spans across all supported alphabets in Markdown or JSON. |
| `hypotheses` | Ranked source-grounded hypotheses with facts, assumptions, falsification tests, and risks in Markdown or JSON. |
| `candidate-sequences` | Pre-registered contextual sequences and score results in Markdown or JSON. |
| `routes` | Bounded named route experiments with identity, reverse, and seeded-random baselines in Markdown or JSON. |
| `findings` | Reproducible findings ledger with sources, transformations, baselines, interpretation, and next tests in Markdown or JSON. |
| `sources` | Source provenance records and allowed-use notes in Markdown or JSON. |
| `verify-plaintext-claim` | Quarantined external-claim verifier that checks local plaintext-claim files for length, public-anchor compatibility, and aggregate shift diagnostics without printing or storing claim text in Markdown or JSON. |
| `verify-running-key-claim` | Quarantined external-claim verifier that checks local plaintext plus running-key-stream files for length, public-anchor compatibility, and additive ciphertext reconstruction under a selectable alphabet without printing or storing plaintext or key material in Markdown or JSON. |
| `verify-claim-reconciliation` | Quarantined external-claim reconciliation verifier that checks local tables for row count, one-based position sequence, K4 ciphertext alignment, optional published Tier/Lane, C#/P#, R/shift, BaseR, and Gate arithmetic, public-anchor compatibility, and aggregate shift diagnostics without printing or storing claimed plaintext in Markdown or JSON. |
| `verify-claim-bundle` | Quarantined external-claim bundle verifier that checks required local files, repo ciphertext, plaintext length only, reconciliation arithmetic, R/r grids, gate map, Z2 handoff, and public anchors without printing or storing claimed plaintext in Markdown or JSON. |
| `verify-claim-mechanism` | Quarantined external-claim mechanism verifier that checks published f/helper-card relationships, control-card consistency, Z2 footer handoff, Y-pass gate-template consistency, and the Z2 helper path into the r/R grids without printing or storing claimed plaintext in Markdown or JSON. |
| `claim-verification-status` | Focused quarantine inventory for registered solution-claim sources, committed non-leaking verification archives, unarchived claim sources, and the safe local verifier commands in Markdown or JSON. |
| `release-check` | Local release preflight results, including no-GitHub-Actions, candidate CSV/registry alignment, preregistration and prediction-artifact validation, preregistration README inventory freshness, independent-lane readiness, non-scorable observation template status, committed source-backed observation-file validity, evidence-summary coverage with archived period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-CT-perturbation/ciphertext-Stehle-regularity/ciphertext-residue-balance command references and negative result metrics, committed source-review validity, source-readiness command documentation, findings source-input integrity, source-packet/source-registry field and latest-access-date alignment, local source-archive metadata/boundary gates including non-scorable/scored-position consistency, source-archive coverage for committed observation positions, stopped-lane documentation coverage, progress-log freshness, claim-verification archive quarantine boundaries, and plaintext-leakage sentinels across release-facing artifacts in Markdown or JSON. |
| `export-data` | Covered by the source data rendered here; the command writes ciphertext, anchor, and source JSON files. |

## Ciphertext

- Length: 97
- Text: `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`

## Known Anchors

| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Source IDs | Confidence | Claim Type | Note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EAST` | `FLRV` | 21-24 | 22-25 | `elonka-kryptos` | high | public-anchor | Publicly released after Sanborn correspondence, summarized by Elonka Dunin. |
| `NORTHEAST` | `QQPRNGKSS` | 25-33 | 26-34 | `elonka-kryptos` | high | public-anchor | Sanborn's 2020 public clue, summarized by major reporting and Elonka Dunin. |
| `BERLIN` | `NYPVTT` | 63-68 | 64-69 | `elonka-kryptos` | high | public-anchor | Sanborn's 2010 public clue. |
| `CLOCK` | `MZFPK` | 69-73 | 70-74 | `elonka-kryptos`, `scientific-american-2025` | high | public-anchor | Sanborn's 2014 public clue. |

## Known Plaintext Spans

| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Anchors |
| --- | --- | --- | --- | --- |
| `EASTNORTHEAST` | `FLRVQQPRNGKSS` | 21-33 | 22-34 | `EAST`, `NORTHEAST` |
| `BERLINCLOCK` | `NYPVTTMZFPK` | 63-73 | 64-74 | `BERLIN`, `CLOCK` |

## Constraint Fragments

### EAST / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `B` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 9 | `J` |
| 23 | `A` | `L` | AdditiveKey | 11 | `L` |
| 23 | `A` | `L` | SubtractiveKey | 15 | `P` |
| 23 | `A` | `L` | BeaufortKey | 11 | `L` |
| 24 | `S` | `R` | AdditiveKey | 25 | `Z` |
| 24 | `S` | `R` | SubtractiveKey | 1 | `B` |
| 24 | `S` | `R` | BeaufortKey | 9 | `J` |
| 25 | `T` | `V` | AdditiveKey | 2 | `C` |
| 25 | `T` | `V` | SubtractiveKey | 24 | `Y` |
| 25 | `T` | `V` | BeaufortKey | 14 | `O` |

Recurrence screen: 0/2 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.2. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EAST / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `R` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 23 | `W` |
| 23 | `A` | `L` | AdditiveKey | 10 | `D` |
| 23 | `A` | `L` | SubtractiveKey | 16 | `J` |
| 23 | `A` | `L` | BeaufortKey | 24 | `X` |
| 24 | `S` | `R` | AdditiveKey | 21 | `U` |
| 24 | `S` | `R` | SubtractiveKey | 5 | `O` |
| 24 | `S` | `R` | BeaufortKey | 7 | `A` |
| 25 | `T` | `V` | AdditiveKey | 18 | `M` |
| 25 | `T` | `V` | SubtractiveKey | 8 | `B` |
| 25 | `T` | `V` | BeaufortKey | 0 | `K` |

Recurrence screen: 1/2 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.2. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EAST / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 25 | `K` |
| 22 | `E` | `F` | SubtractiveKey | 1 | `X` |
| 22 | `E` | `F` | BeaufortKey | 1 | `X` |
| 23 | `A` | `L` | AdditiveKey | 16 | `C` |
| 23 | `A` | `L` | SubtractiveKey | 10 | `I` |
| 23 | `A` | `L` | BeaufortKey | 0 | `Z` |
| 24 | `S` | `R` | AdditiveKey | 5 | `Q` |
| 24 | `S` | `R` | SubtractiveKey | 21 | `T` |
| 24 | `S` | `R` | BeaufortKey | 17 | `B` |
| 25 | `T` | `V` | AdditiveKey | 8 | `L` |
| 25 | `T` | `V` | SubtractiveKey | 18 | `A` |
| 25 | `T` | `V` | BeaufortKey | 24 | `R` |

Recurrence screen: 0/2 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.2. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### NORTHEAST / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 26 | `N` | `Q` | AdditiveKey | 3 | `D` |
| 26 | `N` | `Q` | SubtractiveKey | 23 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 3 | `D` |
| 27 | `O` | `Q` | AdditiveKey | 2 | `C` |
| 27 | `O` | `Q` | SubtractiveKey | 24 | `Y` |
| 27 | `O` | `Q` | BeaufortKey | 4 | `E` |
| 28 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 28 | `R` | `P` | BeaufortKey | 6 | `G` |
| 29 | `T` | `R` | AdditiveKey | 24 | `Y` |
| 29 | `T` | `R` | SubtractiveKey | 2 | `C` |
| 29 | `T` | `R` | BeaufortKey | 10 | `K` |
| 30 | `H` | `N` | AdditiveKey | 6 | `G` |
| 30 | `H` | `N` | SubtractiveKey | 20 | `U` |
| 30 | `H` | `N` | BeaufortKey | 20 | `U` |
| 31 | `E` | `G` | AdditiveKey | 2 | `C` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `Y` |
| 31 | `E` | `G` | BeaufortKey | 10 | `K` |
| 32 | `A` | `K` | AdditiveKey | 10 | `K` |
| 32 | `A` | `K` | SubtractiveKey | 16 | `Q` |
| 32 | `A` | `K` | BeaufortKey | 10 | `K` |
| 33 | `S` | `S` | AdditiveKey | 0 | `A` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `A` |
| 33 | `S` | `S` | BeaufortKey | 10 | `K` |
| 34 | `T` | `S` | AdditiveKey | 25 | `Z` |
| 34 | `T` | `S` | SubtractiveKey | 1 | `B` |
| 34 | `T` | `S` | BeaufortKey | 11 | `L` |

Recurrence screen: 0/7 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.7. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### NORTHEAST / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 26 | `N` | `Q` | AdditiveKey | 1 | `R` |
| 26 | `N` | `Q` | SubtractiveKey | 25 | `Z` |
| 26 | `N` | `Q` | BeaufortKey | 13 | `G` |
| 27 | `O` | `Q` | AdditiveKey | 15 | `I` |
| 27 | `O` | `Q` | SubtractiveKey | 11 | `E` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `Z` |
| 28 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 28 | `R` | `P` | BeaufortKey | 4 | `T` |
| 29 | `T` | `R` | AdditiveKey | 23 | `W` |
| 29 | `T` | `R` | SubtractiveKey | 3 | `P` |
| 29 | `T` | `R` | BeaufortKey | 5 | `O` |
| 30 | `H` | `N` | AdditiveKey | 5 | `O` |
| 30 | `H` | `N` | SubtractiveKey | 21 | `U` |
| 30 | `H` | `N` | BeaufortKey | 7 | `A` |
| 31 | `E` | `G` | AdditiveKey | 2 | `Y` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `X` |
| 31 | `E` | `G` | BeaufortKey | 24 | `X` |
| 32 | `A` | `K` | AdditiveKey | 19 | `N` |
| 32 | `A` | `K` | SubtractiveKey | 7 | `A` |
| 32 | `A` | `K` | BeaufortKey | 7 | `A` |
| 33 | `S` | `S` | AdditiveKey | 0 | `K` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `K` |
| 33 | `S` | `S` | BeaufortKey | 12 | `F` |
| 34 | `T` | `S` | AdditiveKey | 2 | `Y` |
| 34 | `T` | `S` | SubtractiveKey | 24 | `X` |
| 34 | `T` | `S` | BeaufortKey | 10 | `D` |

Recurrence screen: 1/7 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.7. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### NORTHEAST / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 26 | `N` | `Q` | AdditiveKey | 25 | `K` |
| 26 | `N` | `Q` | SubtractiveKey | 1 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 11 | `H` |
| 27 | `O` | `Q` | AdditiveKey | 11 | `H` |
| 27 | `O` | `Q` | SubtractiveKey | 15 | `D` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `K` |
| 28 | `R` | `P` | AdditiveKey | 24 | `R` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 28 | `R` | `P` | BeaufortKey | 20 | `O` |
| 29 | `T` | `R` | AdditiveKey | 3 | `V` |
| 29 | `T` | `R` | SubtractiveKey | 23 | `Y` |
| 29 | `T` | `R` | BeaufortKey | 19 | `S` |
| 30 | `H` | `N` | AdditiveKey | 21 | `T` |
| 30 | `H` | `N` | SubtractiveKey | 5 | `Q` |
| 30 | `H` | `N` | BeaufortKey | 17 | `B` |
| 31 | `E` | `G` | AdditiveKey | 24 | `R` |
| 31 | `E` | `G` | SubtractiveKey | 2 | `W` |
| 31 | `E` | `G` | BeaufortKey | 0 | `Z` |
| 32 | `A` | `K` | AdditiveKey | 7 | `M` |
| 32 | `A` | `K` | SubtractiveKey | 19 | `S` |
| 32 | `A` | `K` | BeaufortKey | 17 | `B` |
| 33 | `S` | `S` | AdditiveKey | 0 | `Z` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `Z` |
| 33 | `S` | `S` | BeaufortKey | 12 | `G` |
| 34 | `T` | `S` | AdditiveKey | 24 | `R` |
| 34 | `T` | `S` | SubtractiveKey | 2 | `W` |
| 34 | `T` | `S` | BeaufortKey | 14 | `E` |

Recurrence screen: 1/7 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.7. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLIN / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 12 | `M` |
| 64 | `B` | `N` | SubtractiveKey | 14 | `O` |
| 64 | `B` | `N` | BeaufortKey | 14 | `O` |
| 65 | `E` | `Y` | AdditiveKey | 20 | `U` |
| 65 | `E` | `Y` | SubtractiveKey | 6 | `G` |
| 65 | `E` | `Y` | BeaufortKey | 2 | `C` |
| 66 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 66 | `R` | `P` | BeaufortKey | 6 | `G` |
| 67 | `L` | `V` | AdditiveKey | 10 | `K` |
| 67 | `L` | `V` | SubtractiveKey | 16 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 6 | `G` |
| 68 | `I` | `T` | AdditiveKey | 11 | `L` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `P` |
| 68 | `I` | `T` | BeaufortKey | 1 | `B` |
| 69 | `N` | `T` | AdditiveKey | 6 | `G` |
| 69 | `N` | `T` | SubtractiveKey | 20 | `U` |
| 69 | `N` | `T` | BeaufortKey | 6 | `G` |

Recurrence screen: 0/4 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.4. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLIN / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 11 | `E` |
| 64 | `B` | `N` | SubtractiveKey | 15 | `I` |
| 64 | `B` | `N` | BeaufortKey | 1 | `R` |
| 65 | `E` | `Y` | AdditiveKey | 17 | `L` |
| 65 | `E` | `Y` | SubtractiveKey | 9 | `C` |
| 65 | `E` | `Y` | BeaufortKey | 13 | `G` |
| 66 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 66 | `R` | `P` | BeaufortKey | 4 | `T` |
| 67 | `L` | `V` | AdditiveKey | 5 | `O` |
| 67 | `L` | `V` | SubtractiveKey | 21 | `U` |
| 67 | `L` | `V` | BeaufortKey | 13 | `G` |
| 68 | `I` | `T` | AdditiveKey | 15 | `I` |
| 68 | `I` | `T` | SubtractiveKey | 11 | `E` |
| 68 | `I` | `T` | BeaufortKey | 19 | `N` |
| 69 | `N` | `T` | AdditiveKey | 11 | `E` |
| 69 | `N` | `T` | SubtractiveKey | 15 | `I` |
| 69 | `N` | `T` | BeaufortKey | 23 | `W` |

Recurrence screen: 0/4 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.4. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLIN / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 15 | `D` |
| 64 | `B` | `N` | SubtractiveKey | 11 | `H` |
| 64 | `B` | `N` | BeaufortKey | 23 | `Y` |
| 65 | `E` | `Y` | AdditiveKey | 9 | `J` |
| 65 | `E` | `Y` | SubtractiveKey | 17 | `B` |
| 65 | `E` | `Y` | BeaufortKey | 11 | `H` |
| 66 | `R` | `P` | AdditiveKey | 24 | `R` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 66 | `R` | `P` | BeaufortKey | 20 | `O` |
| 67 | `L` | `V` | AdditiveKey | 21 | `T` |
| 67 | `L` | `V` | SubtractiveKey | 5 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 11 | `H` |
| 68 | `I` | `T` | AdditiveKey | 11 | `H` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `D` |
| 68 | `I` | `T` | BeaufortKey | 5 | `Q` |
| 69 | `N` | `T` | AdditiveKey | 15 | `D` |
| 69 | `N` | `T` | SubtractiveKey | 11 | `H` |
| 69 | `N` | `T` | BeaufortKey | 1 | `X` |

Recurrence screen: 1/4 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.4. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### CLOCK / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 70 | `C` | `M` | AdditiveKey | 10 | `K` |
| 70 | `C` | `M` | SubtractiveKey | 16 | `Q` |
| 70 | `C` | `M` | BeaufortKey | 14 | `O` |
| 71 | `L` | `Z` | AdditiveKey | 14 | `O` |
| 71 | `L` | `Z` | SubtractiveKey | 12 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 10 | `K` |
| 72 | `O` | `F` | AdditiveKey | 17 | `R` |
| 72 | `O` | `F` | SubtractiveKey | 9 | `J` |
| 72 | `O` | `F` | BeaufortKey | 19 | `T` |
| 73 | `C` | `P` | AdditiveKey | 13 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 13 | `N` |
| 73 | `C` | `P` | BeaufortKey | 17 | `R` |
| 74 | `K` | `K` | AdditiveKey | 0 | `A` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `A` |
| 74 | `K` | `K` | BeaufortKey | 20 | `U` |

Recurrence screen: 1/3 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.3. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### CLOCK / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 70 | `C` | `M` | AdditiveKey | 9 | `C` |
| 70 | `C` | `M` | SubtractiveKey | 17 | `L` |
| 70 | `C` | `M` | BeaufortKey | 1 | `R` |
| 71 | `L` | `Z` | AdditiveKey | 8 | `B` |
| 71 | `L` | `Z` | SubtractiveKey | 18 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 16 | `J` |
| 72 | `O` | `F` | AdditiveKey | 7 | `A` |
| 72 | `O` | `F` | SubtractiveKey | 19 | `N` |
| 72 | `O` | `F` | BeaufortKey | 17 | `L` |
| 73 | `C` | `P` | AdditiveKey | 20 | `Q` |
| 73 | `C` | `P` | SubtractiveKey | 6 | `S` |
| 73 | `C` | `P` | BeaufortKey | 12 | `F` |
| 74 | `K` | `K` | AdditiveKey | 0 | `K` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `K` |
| 74 | `K` | `K` | BeaufortKey | 0 | `K` |

Recurrence screen: 1/3 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.3. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### CLOCK / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 70 | `C` | `M` | AdditiveKey | 17 | `B` |
| 70 | `C` | `M` | SubtractiveKey | 9 | `J` |
| 70 | `C` | `M` | BeaufortKey | 23 | `Y` |
| 71 | `L` | `Z` | AdditiveKey | 18 | `A` |
| 71 | `L` | `Z` | SubtractiveKey | 8 | `L` |
| 71 | `L` | `Z` | BeaufortKey | 8 | `L` |
| 72 | `O` | `F` | AdditiveKey | 19 | `S` |
| 72 | `O` | `F` | SubtractiveKey | 7 | `M` |
| 72 | `O` | `F` | BeaufortKey | 7 | `M` |
| 73 | `C` | `P` | AdditiveKey | 6 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 20 | `O` |
| 73 | `C` | `P` | BeaufortKey | 12 | `G` |
| 74 | `K` | `K` | AdditiveKey | 0 | `Z` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `Z` |
| 74 | `K` | `K` | BeaufortKey | 24 | `R` |

Recurrence screen: 0/3 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.3. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.


## Span Constraint Fragments

### EASTNORTHEAST / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `B` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 9 | `J` |
| 23 | `A` | `L` | AdditiveKey | 11 | `L` |
| 23 | `A` | `L` | SubtractiveKey | 15 | `P` |
| 23 | `A` | `L` | BeaufortKey | 11 | `L` |
| 24 | `S` | `R` | AdditiveKey | 25 | `Z` |
| 24 | `S` | `R` | SubtractiveKey | 1 | `B` |
| 24 | `S` | `R` | BeaufortKey | 9 | `J` |
| 25 | `T` | `V` | AdditiveKey | 2 | `C` |
| 25 | `T` | `V` | SubtractiveKey | 24 | `Y` |
| 25 | `T` | `V` | BeaufortKey | 14 | `O` |
| 26 | `N` | `Q` | AdditiveKey | 3 | `D` |
| 26 | `N` | `Q` | SubtractiveKey | 23 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 3 | `D` |
| 27 | `O` | `Q` | AdditiveKey | 2 | `C` |
| 27 | `O` | `Q` | SubtractiveKey | 24 | `Y` |
| 27 | `O` | `Q` | BeaufortKey | 4 | `E` |
| 28 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 28 | `R` | `P` | BeaufortKey | 6 | `G` |
| 29 | `T` | `R` | AdditiveKey | 24 | `Y` |
| 29 | `T` | `R` | SubtractiveKey | 2 | `C` |
| 29 | `T` | `R` | BeaufortKey | 10 | `K` |
| 30 | `H` | `N` | AdditiveKey | 6 | `G` |
| 30 | `H` | `N` | SubtractiveKey | 20 | `U` |
| 30 | `H` | `N` | BeaufortKey | 20 | `U` |
| 31 | `E` | `G` | AdditiveKey | 2 | `C` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `Y` |
| 31 | `E` | `G` | BeaufortKey | 10 | `K` |
| 32 | `A` | `K` | AdditiveKey | 10 | `K` |
| 32 | `A` | `K` | SubtractiveKey | 16 | `Q` |
| 32 | `A` | `K` | BeaufortKey | 10 | `K` |
| 33 | `S` | `S` | AdditiveKey | 0 | `A` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `A` |
| 33 | `S` | `S` | BeaufortKey | 10 | `K` |
| 34 | `T` | `S` | AdditiveKey | 25 | `Z` |
| 34 | `T` | `S` | SubtractiveKey | 1 | `B` |
| 34 | `T` | `S` | BeaufortKey | 11 | `L` |

Recurrence screen: 0/11 local additive triples matched generic mod-10 recurrence. Expected random matches: 1.1. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EASTNORTHEAST / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `R` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 23 | `W` |
| 23 | `A` | `L` | AdditiveKey | 10 | `D` |
| 23 | `A` | `L` | SubtractiveKey | 16 | `J` |
| 23 | `A` | `L` | BeaufortKey | 24 | `X` |
| 24 | `S` | `R` | AdditiveKey | 21 | `U` |
| 24 | `S` | `R` | SubtractiveKey | 5 | `O` |
| 24 | `S` | `R` | BeaufortKey | 7 | `A` |
| 25 | `T` | `V` | AdditiveKey | 18 | `M` |
| 25 | `T` | `V` | SubtractiveKey | 8 | `B` |
| 25 | `T` | `V` | BeaufortKey | 0 | `K` |
| 26 | `N` | `Q` | AdditiveKey | 1 | `R` |
| 26 | `N` | `Q` | SubtractiveKey | 25 | `Z` |
| 26 | `N` | `Q` | BeaufortKey | 13 | `G` |
| 27 | `O` | `Q` | AdditiveKey | 15 | `I` |
| 27 | `O` | `Q` | SubtractiveKey | 11 | `E` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `Z` |
| 28 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 28 | `R` | `P` | BeaufortKey | 4 | `T` |
| 29 | `T` | `R` | AdditiveKey | 23 | `W` |
| 29 | `T` | `R` | SubtractiveKey | 3 | `P` |
| 29 | `T` | `R` | BeaufortKey | 5 | `O` |
| 30 | `H` | `N` | AdditiveKey | 5 | `O` |
| 30 | `H` | `N` | SubtractiveKey | 21 | `U` |
| 30 | `H` | `N` | BeaufortKey | 7 | `A` |
| 31 | `E` | `G` | AdditiveKey | 2 | `Y` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `X` |
| 31 | `E` | `G` | BeaufortKey | 24 | `X` |
| 32 | `A` | `K` | AdditiveKey | 19 | `N` |
| 32 | `A` | `K` | SubtractiveKey | 7 | `A` |
| 32 | `A` | `K` | BeaufortKey | 7 | `A` |
| 33 | `S` | `S` | AdditiveKey | 0 | `K` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `K` |
| 33 | `S` | `S` | BeaufortKey | 12 | `F` |
| 34 | `T` | `S` | AdditiveKey | 2 | `Y` |
| 34 | `T` | `S` | SubtractiveKey | 24 | `X` |
| 34 | `T` | `S` | BeaufortKey | 10 | `D` |

Recurrence screen: 2/11 local additive triples matched generic mod-10 recurrence. Expected random matches: 1.1. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EASTNORTHEAST / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 25 | `K` |
| 22 | `E` | `F` | SubtractiveKey | 1 | `X` |
| 22 | `E` | `F` | BeaufortKey | 1 | `X` |
| 23 | `A` | `L` | AdditiveKey | 16 | `C` |
| 23 | `A` | `L` | SubtractiveKey | 10 | `I` |
| 23 | `A` | `L` | BeaufortKey | 0 | `Z` |
| 24 | `S` | `R` | AdditiveKey | 5 | `Q` |
| 24 | `S` | `R` | SubtractiveKey | 21 | `T` |
| 24 | `S` | `R` | BeaufortKey | 17 | `B` |
| 25 | `T` | `V` | AdditiveKey | 8 | `L` |
| 25 | `T` | `V` | SubtractiveKey | 18 | `A` |
| 25 | `T` | `V` | BeaufortKey | 24 | `R` |
| 26 | `N` | `Q` | AdditiveKey | 25 | `K` |
| 26 | `N` | `Q` | SubtractiveKey | 1 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 11 | `H` |
| 27 | `O` | `Q` | AdditiveKey | 11 | `H` |
| 27 | `O` | `Q` | SubtractiveKey | 15 | `D` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `K` |
| 28 | `R` | `P` | AdditiveKey | 24 | `R` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 28 | `R` | `P` | BeaufortKey | 20 | `O` |
| 29 | `T` | `R` | AdditiveKey | 3 | `V` |
| 29 | `T` | `R` | SubtractiveKey | 23 | `Y` |
| 29 | `T` | `R` | BeaufortKey | 19 | `S` |
| 30 | `H` | `N` | AdditiveKey | 21 | `T` |
| 30 | `H` | `N` | SubtractiveKey | 5 | `Q` |
| 30 | `H` | `N` | BeaufortKey | 17 | `B` |
| 31 | `E` | `G` | AdditiveKey | 24 | `R` |
| 31 | `E` | `G` | SubtractiveKey | 2 | `W` |
| 31 | `E` | `G` | BeaufortKey | 0 | `Z` |
| 32 | `A` | `K` | AdditiveKey | 7 | `M` |
| 32 | `A` | `K` | SubtractiveKey | 19 | `S` |
| 32 | `A` | `K` | BeaufortKey | 17 | `B` |
| 33 | `S` | `S` | AdditiveKey | 0 | `Z` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `Z` |
| 33 | `S` | `S` | BeaufortKey | 12 | `G` |
| 34 | `T` | `S` | AdditiveKey | 24 | `R` |
| 34 | `T` | `S` | SubtractiveKey | 2 | `W` |
| 34 | `T` | `S` | BeaufortKey | 14 | `E` |

Recurrence screen: 1/11 local additive triples matched generic mod-10 recurrence. Expected random matches: 1.1. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLINCLOCK / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 12 | `M` |
| 64 | `B` | `N` | SubtractiveKey | 14 | `O` |
| 64 | `B` | `N` | BeaufortKey | 14 | `O` |
| 65 | `E` | `Y` | AdditiveKey | 20 | `U` |
| 65 | `E` | `Y` | SubtractiveKey | 6 | `G` |
| 65 | `E` | `Y` | BeaufortKey | 2 | `C` |
| 66 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 66 | `R` | `P` | BeaufortKey | 6 | `G` |
| 67 | `L` | `V` | AdditiveKey | 10 | `K` |
| 67 | `L` | `V` | SubtractiveKey | 16 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 6 | `G` |
| 68 | `I` | `T` | AdditiveKey | 11 | `L` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `P` |
| 68 | `I` | `T` | BeaufortKey | 1 | `B` |
| 69 | `N` | `T` | AdditiveKey | 6 | `G` |
| 69 | `N` | `T` | SubtractiveKey | 20 | `U` |
| 69 | `N` | `T` | BeaufortKey | 6 | `G` |
| 70 | `C` | `M` | AdditiveKey | 10 | `K` |
| 70 | `C` | `M` | SubtractiveKey | 16 | `Q` |
| 70 | `C` | `M` | BeaufortKey | 14 | `O` |
| 71 | `L` | `Z` | AdditiveKey | 14 | `O` |
| 71 | `L` | `Z` | SubtractiveKey | 12 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 10 | `K` |
| 72 | `O` | `F` | AdditiveKey | 17 | `R` |
| 72 | `O` | `F` | SubtractiveKey | 9 | `J` |
| 72 | `O` | `F` | BeaufortKey | 19 | `T` |
| 73 | `C` | `P` | AdditiveKey | 13 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 13 | `N` |
| 73 | `C` | `P` | BeaufortKey | 17 | `R` |
| 74 | `K` | `K` | AdditiveKey | 0 | `A` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `A` |
| 74 | `K` | `K` | BeaufortKey | 20 | `U` |

Recurrence screen: 1/9 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.9. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLINCLOCK / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 11 | `E` |
| 64 | `B` | `N` | SubtractiveKey | 15 | `I` |
| 64 | `B` | `N` | BeaufortKey | 1 | `R` |
| 65 | `E` | `Y` | AdditiveKey | 17 | `L` |
| 65 | `E` | `Y` | SubtractiveKey | 9 | `C` |
| 65 | `E` | `Y` | BeaufortKey | 13 | `G` |
| 66 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 66 | `R` | `P` | BeaufortKey | 4 | `T` |
| 67 | `L` | `V` | AdditiveKey | 5 | `O` |
| 67 | `L` | `V` | SubtractiveKey | 21 | `U` |
| 67 | `L` | `V` | BeaufortKey | 13 | `G` |
| 68 | `I` | `T` | AdditiveKey | 15 | `I` |
| 68 | `I` | `T` | SubtractiveKey | 11 | `E` |
| 68 | `I` | `T` | BeaufortKey | 19 | `N` |
| 69 | `N` | `T` | AdditiveKey | 11 | `E` |
| 69 | `N` | `T` | SubtractiveKey | 15 | `I` |
| 69 | `N` | `T` | BeaufortKey | 23 | `W` |
| 70 | `C` | `M` | AdditiveKey | 9 | `C` |
| 70 | `C` | `M` | SubtractiveKey | 17 | `L` |
| 70 | `C` | `M` | BeaufortKey | 1 | `R` |
| 71 | `L` | `Z` | AdditiveKey | 8 | `B` |
| 71 | `L` | `Z` | SubtractiveKey | 18 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 16 | `J` |
| 72 | `O` | `F` | AdditiveKey | 7 | `A` |
| 72 | `O` | `F` | SubtractiveKey | 19 | `N` |
| 72 | `O` | `F` | BeaufortKey | 17 | `L` |
| 73 | `C` | `P` | AdditiveKey | 20 | `Q` |
| 73 | `C` | `P` | SubtractiveKey | 6 | `S` |
| 73 | `C` | `P` | BeaufortKey | 12 | `F` |
| 74 | `K` | `K` | AdditiveKey | 0 | `K` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `K` |
| 74 | `K` | `K` | BeaufortKey | 0 | `K` |

Recurrence screen: 1/9 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.9. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLINCLOCK / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 15 | `D` |
| 64 | `B` | `N` | SubtractiveKey | 11 | `H` |
| 64 | `B` | `N` | BeaufortKey | 23 | `Y` |
| 65 | `E` | `Y` | AdditiveKey | 9 | `J` |
| 65 | `E` | `Y` | SubtractiveKey | 17 | `B` |
| 65 | `E` | `Y` | BeaufortKey | 11 | `H` |
| 66 | `R` | `P` | AdditiveKey | 24 | `R` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 66 | `R` | `P` | BeaufortKey | 20 | `O` |
| 67 | `L` | `V` | AdditiveKey | 21 | `T` |
| 67 | `L` | `V` | SubtractiveKey | 5 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 11 | `H` |
| 68 | `I` | `T` | AdditiveKey | 11 | `H` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `D` |
| 68 | `I` | `T` | BeaufortKey | 5 | `Q` |
| 69 | `N` | `T` | AdditiveKey | 15 | `D` |
| 69 | `N` | `T` | SubtractiveKey | 11 | `H` |
| 69 | `N` | `T` | BeaufortKey | 1 | `X` |
| 70 | `C` | `M` | AdditiveKey | 17 | `B` |
| 70 | `C` | `M` | SubtractiveKey | 9 | `J` |
| 70 | `C` | `M` | BeaufortKey | 23 | `Y` |
| 71 | `L` | `Z` | AdditiveKey | 18 | `A` |
| 71 | `L` | `Z` | SubtractiveKey | 8 | `L` |
| 71 | `L` | `Z` | BeaufortKey | 8 | `L` |
| 72 | `O` | `F` | AdditiveKey | 19 | `S` |
| 72 | `O` | `F` | SubtractiveKey | 7 | `M` |
| 72 | `O` | `F` | BeaufortKey | 7 | `M` |
| 73 | `C` | `P` | AdditiveKey | 6 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 20 | `O` |
| 73 | `C` | `P` | BeaufortKey | 12 | `G` |
| 74 | `K` | `K` | AdditiveKey | 0 | `Z` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `Z` |
| 74 | `K` | `K` | BeaufortKey | 24 | `R` |

Recurrence screen: 1/9 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.9. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

## Ranked Hypotheses

1. **Gromark-like or running-key additive system (H1)**
   - Supporting facts: Bean's HistoCrypt abstract reports one-to-one evidence and identifies Gromark as a possible method family.
   - Required assumptions: K4 uses a keyed alphabet and running numeric key stream or adjacent additive construction.
   - Test: Derive public-anchor key fragments and check whether they can coexist under Gromark-style recurrence rules.
   - Risk: Flexible additive models can be overfit to known anchors.
2. **Kryptos-alphabet Vigenere descendant with added transformation (H2)**
   - Supporting facts: K1 and K2 use Vigenere-like mechanics with the Kryptos alphabet.
   - Required assumptions: K4 preserves family resemblance while adding a new key schedule, route, or preprocessing layer.
   - Test: Compute anchor-implied key letters for supported alphabets and reject structureless fragments.
   - Risk: Prior-method bias may obscure a deliberate departure from K1/K2.
3. **Hybrid substitution plus route or matrix transposition (H3)**
   - Supporting facts: CIA says earlier sections combine chart and matrix systems; K3 uses transposition-like behavior.
   - Required assumptions: K4 combines a one-to-one layer with a stable route or matrix permutation.
   - Test: Pre-register route families and test whether one permutation improves fragment coherence.
   - Risk: Route spaces are large and can create false positives.
4. **Berlin World Clock, compass, or directional mechanism (H4)**
   - Supporting facts: Sanborn clarified BERLINCLOCK points to Berlin's World Clock; known anchors include EAST and NORTHEAST.
   - Required assumptions: Clock or compass data contributes to key generation, ordering, or validation.
   - Test: Define source-derived numeric sequences before checking them against anchor fragments.
   - Risk: The clock clue is highly ambiguous without a pre-registered mapping.
5. **Egypt 1986 or Berlin Wall 1989 event-timeline key material (H5)**
   - Supporting facts: 2025 reporting says both events figure in the solution.
   - Required assumptions: The events provide constrained key words, dates, places, routes, or ordering rules.
   - Test: Pre-register a small event-key list from strict sources and test without ad hoc expansion.
   - Risk: Underspecified source material invites unconstrained key hunting.

## Baseline Controls

Baseline output is a false-positive control, not a claimed solution. Target: all; alphabet: all; iterations: 10000; seed: 42.

| Target | Kind | Alphabet | Observed | Triples | Null Mean | Null SD | Empirical P | Adjusted P | Promoted | Warning |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EAST | anchor | Standard | 0 | 2 | 0.17 | 0.37 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EAST | anchor | Kryptos | 1 | 2 | 0.33 | 0.47 | 0.3331 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EAST | anchor | KryptosReversed | 0 | 2 | 0.00 | 0.00 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| NORTHEAST | anchor | Standard | 0 | 7 | 0.56 | 0.72 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| NORTHEAST | anchor | Kryptos | 1 | 7 | 0.69 | 0.78 | 0.5124 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| NORTHEAST | anchor | KryptosReversed | 1 | 7 | 0.82 | 0.84 | 0.5857 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLIN | anchor | Standard | 0 | 4 | 0.20 | 0.44 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLIN | anchor | Kryptos | 0 | 4 | 0.33 | 0.49 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLIN | anchor | KryptosReversed | 1 | 4 | 0.53 | 0.60 | 0.4776 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| CLOCK | anchor | Standard | 1 | 3 | 0.30 | 0.52 | 0.2664 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| CLOCK | anchor | Kryptos | 1 | 3 | 0.10 | 0.30 | 0.1019 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| CLOCK | anchor | KryptosReversed | 0 | 3 | 0.19 | 0.43 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EASTNORTHEAST | span | Standard | 0 | 11 | 1.00 | 0.94 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EASTNORTHEAST | span | Kryptos | 2 | 11 | 1.14 | 1.00 | 0.3150 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EASTNORTHEAST | span | KryptosReversed | 1 | 11 | 1.12 | 0.99 | 0.6964 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLINCLOCK | span | Standard | 1 | 9 | 0.79 | 0.83 | 0.5702 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLINCLOCK | span | Kryptos | 1 | 9 | 0.82 | 0.87 | 0.5729 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLINCLOCK | span | KryptosReversed | 1 | 9 | 0.97 | 0.92 | 0.6498 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |

## Sources

- `cia-artifact` [CIA Kryptos artifact page](https://www.cia.gov/legacy/museum/artifact/kryptos/) - Installation context and unresolved fourth-section status.; type: primary; accessed 2026-05-20; use: public-facts-only
- `cia-sculpture` [CIA Kryptos sculpture page](https://www.cia.gov/legacy/headquarters/kryptos-sculpture/) - Sculpture components, Vigenere chart context, and 97-character K4 statement.; type: primary; accessed 2026-05-20; use: public-facts-only
- `elonka-kryptos` [Elonka Dunin Kryptos page](https://www.elonka.com/kryptos/) - Public ciphertext transcription and public clue summary.; type: reference; accessed 2026-05-27; use: public-anchor-summary
- `histocrypt-2021-bean` [HistoCrypt 2021 Richard Bean abstract](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153) - Academic cryptodiagnosis and Gromark-family hypothesis.; type: academic; accessed 2026-05-27; use: methodology-context
- `stein-courtyard-crypto` [David Stein courtyard-crypto article mirror](https://www.elonka.com/kryptos/mirrors/daw/steinarticle.html) - Public mirror of David Stein's CIA solved-section methodology article; useful for historical method boundaries, not scored K4 observations.; type: reference; accessed 2026-05-31; use: methodology-context
- `scientific-american-2025` [Scientific American 2025 final clues report](https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/) - 2025 public clue context, Berlin World Clock clarification, and K5 parallel-position context.; type: major-reporting; accessed 2026-05-27; use: public-clue-context
- `scientific-american-2026-kryptos-cracked` [Scientific American 2026 Kryptos archive-discovery report](https://www.scientificamerican.com/article/how-the-cias-kryptos-sculpture-gave-up-its-final-secret/) - Archive-discovery and claim-boundary reporting; no public plaintext, key material, route, or scored K4 observations.; type: major-reporting; accessed 2026-05-31; use: archive-context-only
- `ap-2025-auction` [Associated Press 2025 auction report](https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/) - Archive-discovery context and Sanborn decipherment distinction.; type: major-reporting; accessed 2026-05-27; use: archive-context-only
- `ap-2025-archive-sale` [Associated Press 2025 archive sale follow-up](https://apnews.com/article/kryptos-jim-sanborn-auction-cia-secret-code-cb8ee8554ca473910cbd0592f8bdb350) - Archive sale outcome and context only; no archive-discovered plaintext content.; type: major-reporting; accessed 2026-05-27; use: archive-context-only
- `rr-auction-kryptos-archive-2025` [RR Auction 2025 Kryptos archive lot](https://www.rrauction.com/auctions/lot-detail/350761607302001-the-complete-secrets-of-kryptos-jim-sanborns-private-archive/?cat=0) - Primary auction-lot provenance for the private K4/K5 archive and explicit no-independent-examination boundary; no public plaintext, key material, routes, or scored K4 observations.; type: auction-primary; accessed 2026-05-31; use: archive-context-only
- `smithsonian-2026-archive-discovery` [Smithsonian 2026 archive-discovery report](https://www.smithsonianmag.com/blogs/office-of-the-secretary-of-the-smithsonian/2026/02/17/smithsonian-archives-help-unlock-mysteries-connect-americans-history/) - Smithsonian archive-discovery context; no archive-discovered plaintext, key material, routes, or scoreable observations.; type: institutional-reporting; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-doc1-resolution-memo` [NSA Kryptos challenge and resolution memo](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760459/) - Declassified NSA challenge/resolution memo context for solved sections and methodology boundaries; no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-declassified-kryptos-doc3` [NSA declassified Kryptos sculpture notes](https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cia-kryptos-sculpture/doc_3.pdf) - Declassified physical-clue context including compass, lodestone, Morse, and sculpture-layout notes; no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-doc7-technical-analysis` [NSA Kryptos technical analysis memo](https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cia-kryptos-sculpture/doc_7.pdf) - Declassified NSA solved-section methodology and unresolved-section boundary context; no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-foia-release-index` [NSA CIA Kryptos Sculpture FOIA release index](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760460/) - NSA declassification index for CIA Kryptos Sculpture document releases; source-discovery context only, no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-summary-revelations` [NSA Kryptos previous work and revelations summary](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760463/) - NSA declassified summary context for prior work and later revelations; no scored K4 positions, plaintext, key material, or route evidence.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-doc8-cryptogram` [NSA Kryptos cryptogram text document](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760461/) - NSA declassified cryptogram-text context; public ciphertext provenance only, not independent scored observation evidence.; type: primary; accessed 2026-05-28; use: public-anchor-summary
- `kryptosbot-sanborn-papers-2026` [KryptosBot 2026 Sanborn papers research archive](https://kryptosbot.com/archive/) - Curated public notes from Smithsonian Sanborn papers research; context for future preregistration only, including a 7-by-14-compatible K4 layout rationale, not scored plaintext or candidate evidence.; type: community-research-archive; accessed 2026-05-27; use: archive-context-only
- `kryptosbot-methodology-2026` [KryptosBot 2026 methodology and eliminations](https://kryptosbot.com/methodology/) - Public reproducibility and elimination-scope context; not plaintext, not candidate evidence, and not scored observations.; type: community-research-methodology; accessed 2026-05-27; use: methodology-context
- `kryptosbot-findings-2026` [KryptosBot 2026 findings and open questions](https://kryptosbot.com/findings/) - Public findings and open-question context around W-delimiter, CT-perturbation, Stehle local regularity, HILL-tableau, and negative-search boundaries; not plaintext, candidate evidence, or scored observations.; type: community-research-findings; accessed 2026-05-31; use: methodology-context
- `kryptos-today-project-k4-2026` [Project K4 2026 live cryptanalysis press page](https://kryptos.today/press/2026-05-01-launch) - Independent live-search and negative-result context; not plaintext, not candidate evidence, and not scored observations.; type: independent-cryptanalysis-project; accessed 2026-05-31; use: methodology-context
- `kryptos-today-progress-2026` [Project K4 2026 progress log](https://kryptos.today/progress) - Independent progress-log context for attack-family triage, including Weltzeituhr, width-7 transposition, and Morse/Mengenlehreuhr queue updates; not plaintext, candidate evidence, or scored observations.; type: independent-cryptanalysis-progress; accessed 2026-05-31; use: methodology-context
- `rumkin-k4-reference` [Rumkin K4 reference notes](https://rumkin.com/reference/kryptos/k4/) - K4 reference and open-question context around direct mapping, installation threads, and the HILL tableau question; not plaintext, not candidate evidence, and not scored observations.; type: community-reference; accessed 2026-05-27; use: methodology-context
- `solvekryptos-2026-claim` [SolveKryptos 2026 K4 solution claim](https://solvekryptos.com/) - Public claimed K4 plaintext and mechanism; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-27; use: unverified-solution-claim
- `dearcipher-k4-claim-2026` [Dear Cipher Kryptos K4 claim](https://www.dearcipher.space/kryptos) - Public claimed K4 plaintext and explanation; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `prlog-bishop-k4-plaintext-2020` [Stephen Bishop PRLog K4 plaintext claim](https://www.prlog.org/12845348-stephen-bishop-discovers-us-central-intelligence-agency-sculpture-kryptos-k4-plaintext.pdf) - Public claimed K4 plaintext via CIA New Headquarters Building visual construction; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `ssrn-bonifacino-running-key-2025` [SSRN Bonifacino 2025 running-key K4 paper](https://ssrn.com/abstract=5876405) - Public running-key candidate paper; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `ssrn-bonifacino-weltzeituhr-error-key-2025` [SSRN Bonifacino 2025 Weltzeituhr error-key derivation paper](https://ssrn.com/abstract=5779902) - Public claimed derivation for a Weltzeituhr running-key K4 method; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `ssrn-bonifacino-generative-running-key-2025` [SSRN Bonifacino 2025 generative running-key paper](https://ssrn.com/abstract=5876462) - Public claimed generative ruleset for a Weltzeituhr running-key K4 method; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim

## Candidate Sequences

Pre-registered contextual candidates only; no candidate is a claimed solution.

- `h4-berlin-world-clock-english` BerlinWorldClock A1Z26ZeroBased: `BERLINWORLDCLOCK` values=[1, 4, 17, 11, 8, 13, 22, 14, 17, 11, 3, 2, 11, 14, 2, 10] sources=`scientific-american-2025`
- `h4-berlin-world-clock-german` BerlinWorldClock A1Z26ZeroBased: `WELTZEITUHR` values=[22, 4, 11, 19, 25, 4, 8, 19, 20, 7, 17] sources=`scientific-american-2025`
- `h4-berlin-world-clock-place` BerlinWorldClock A1Z26ZeroBased: `ALEXANDERPLATZ` values=[0, 11, 4, 23, 0, 13, 3, 4, 17, 15, 11, 0, 19, 25] sources=`scientific-american-2025`
- `h4-compass-8point-east-northeast` CompassDirections Compass8Point: `EASTNORTHEAST` values=[2, 1] sources=`elonka-kryptos`
- `h4-compass-16point-east-northeast` CompassDirections Compass16Point: `EASTNORTHEAST` values=[4, 2] sources=`elonka-kryptos`
- `h5-egypt-1986-literal` Egypt1986 A1Z26ZeroBased: `EGYPT` values=[4, 6, 24, 15, 19] sources=`scientific-american-2025`
- `h5-egypt-1986-year` Egypt1986 DecimalDigits: `1986` values=[1, 9, 8, 6] sources=`scientific-american-2025`
- `h5-berlin-wall-1989-literal` BerlinWall1989 A1Z26ZeroBased: `BERLINWALL` values=[1, 4, 17, 11, 8, 13, 22, 0, 11, 11] sources=`scientific-american-2025`
- `h5-berlin-wall-1989-date` BerlinWall1989 DecimalDigits: `19891109` values=[1, 9, 8, 9, 1, 1, 0, 9] sources=`scientific-american-2025`

## Candidate Sequence Scores

| Candidate | Family | Compared Fragments | Exact Mod-26 Matches | Match Rate | Promoted | Note |
| --- | --- | --- | --- | --- | --- | --- |
| `h4-berlin-world-clock-english` | BerlinWorldClock | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-berlin-world-clock-german` | BerlinWorldClock | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-berlin-world-clock-place` | BerlinWorldClock | 24 | 2 | 0.083 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-compass-8point-east-northeast` | CompassDirections | 24 | 0 | 0.000 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-compass-16point-east-northeast` | CompassDirections | 24 | 3 | 0.125 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-egypt-1986-literal` | Egypt1986 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-egypt-1986-year` | Egypt1986 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-berlin-wall-1989-literal` | BerlinWall1989 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-berlin-wall-1989-date` | BerlinWall1989 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |

## Route Experiments

Exploratory named route screens only; no decryption text is emitted.

- Identity / EASTNORTHEAST: score=0 identity=0 reverse=1 seeded_random=1 promoted=false
- Reverse / EASTNORTHEAST: score=1 identity=0 reverse=1 seeded_random=1 promoted=false
- RowToColumnWidth13 / EASTNORTHEAST: score=0 identity=0 reverse=1 seeded_random=1 promoted=false
- Identity / BERLINCLOCK: score=1 identity=1 reverse=0 seeded_random=1 promoted=false
- Reverse / BERLINCLOCK: score=0 identity=1 reverse=0 seeded_random=1 promoted=false

## Findings Ledger

Findings are reproducible research observations, not promoted solution claims.

- **F1 Public anchors normalize into two adjacent known-plaintext spans (H1/H2)**
  - Sources: `elonka-kryptos`, `scientific-american-2025`
  - Steps: store public anchors with zero-based and one-based positions; join anchors only when public positions are directly adjacent; derive alphabet-specific additive, subtractive, and Beaufort fragments
  - Output: EAST joins NORTHEAST as EASTNORTHEAST, and BERLIN joins CLOCK as BERLINCLOCK.
  - Baseline: Span-level recurrence results are compared against seeded shuffled controls in the baseline command.
  - Interpretation: The spans are useful constraints, not solution text beyond the public anchors.
  - Next test: Use the span fragments as fixed validation points for any future key-schedule or alphabet hypothesis.
  - Promoted: false
- **F2 Generic Gromark-style recurrence screens are underpowered (H1)**
  - Sources: `histocrypt-2021-bean`, `elonka-kryptos`
  - Steps: derive additive key fragments from public known-plaintext spans; screen contiguous triples for a mod-10 sum recurrence; run deterministic shuffled null controls with Holm adjustment
  - Output: The 100000-iteration span/all-alphabet baseline found no adjusted recurrence signal: the strongest raw row was EASTNORTHEAST/Kryptos with 2/11 triples, raw p=0.3138, adjusted p=1.0000.
  - Baseline: Seeded shuffled controls over public-anchor span fragments leave every adjusted p-value at 1.0000, so the Gromark-style screen remains negative and underpowered.
  - Interpretation: The result is a falsifiable diagnostic lane, not evidence for a Gromark solution.
  - Next test: Require a larger independently justified fragment set before considering any recurrence signal meaningful.
  - Promoted: false
- **F3 Contextual candidate sequences are registered before scoring (H4/H5)**
  - Sources: `scientific-american-2025`, `elonka-kryptos`
  - Steps: define Berlin World Clock, compass, Egypt 1986, and Berlin Wall 1989 material before scoring; convert each candidate with a declared transform; compare only against public-anchor-derived additive fragments
  - Output: Candidate scores are reproducible and marked exploratory with no promoted candidate.
  - Baseline: The candidate-sequences command reports match rates but does not treat them as independent proof.
  - Interpretation: The feature constrains future contextual testing without expanding into ad hoc key hunting.
  - Next test: Add new contextual material only when it has a source ID, declared transform, and pre-registration rationale.
  - Promoted: false
- **F4 Route experiments stay bounded to named permutation families (H3)**
  - Sources: `cia-sculpture`, `elonka-kryptos`
  - Steps: derive public span additive fragments under the standard alphabet; apply identity, reverse, and compatible row-to-column route families; score routed fragments against the same local recurrence diagnostic
  - Output: Route screens report scores and baselines without emitting guessed plaintext.
  - Baseline: Each route result is shown beside identity, reverse, and seeded-random baselines.
  - Interpretation: The route lane is an exploratory guardrail against unconstrained permutation search.
  - Next test: Only add route families that are named, deterministic, and justified before seeing their score.
  - Promoted: false
- **F5 Independent non-anchor period targets are materialized before scoring (H3)**
  - Sources: `experiments/preregistrations/non-anchor-position-period-v1.json`, `experiments/predictions/non-anchor-position-period-v1.json`, `experiments/preregistrations/non-anchor-position-period-diagnostic-v1.json`, `experiments/predictions/non-anchor-position-period-diagnostic-v1.json`, `experiments/preregistrations/non-anchor-position-period-followup-v1.json`, `experiments/predictions/non-anchor-position-period-followup-v1.json`, `experiments/preregistrations/non-anchor-position-period-v2.json`, `experiments/predictions/non-anchor-position-period-v2.json`, `experiments/preregistrations/non-anchor-position-period-v3.json`, `experiments/predictions/non-anchor-position-period-v3.json`, `experiments/preregistrations/non-anchor-position-period-v4.json`, `experiments/predictions/non-anchor-position-period-v4.json`, `experiments/preregistrations/non-anchor-position-period-v5.json`, `experiments/predictions/non-anchor-position-period-v5.json`, `experiments/preregistrations/non-anchor-position-period-v6.json`, `experiments/predictions/non-anchor-position-period-v6.json`, `experiments/preregistrations/non-anchor-position-period-v7.json`, `experiments/predictions/non-anchor-position-period-v7.json`, `experiments/preregistrations/non-anchor-position-period-v8.json`, `experiments/predictions/non-anchor-position-period-v8.json`, `experiments/preregistrations/non-anchor-position-period-v9.json`, `experiments/predictions/non-anchor-position-period-v9.json`, `experiments/preregistrations/non-anchor-position-period-v10.json`, `experiments/predictions/non-anchor-position-period-v10.json`, `experiments/preregistrations/non-anchor-position-period-v11.json`, `experiments/predictions/non-anchor-position-period-v11.json`, `experiments/preregistrations/non-anchor-position-period-v12.json`, `experiments/predictions/non-anchor-position-period-v12.json`, `experiments/preregistrations/non-anchor-position-period-v13.json`, `experiments/predictions/non-anchor-position-period-v13.json`, `experiments/preregistrations/non-anchor-position-period-v14.json`, `experiments/predictions/non-anchor-position-period-v14.json`, `experiments/preregistrations/non-anchor-position-period-v15.json`, `experiments/predictions/non-anchor-position-period-v15.json`, `experiments/preregistrations/non-anchor-position-period-v16.json`, `experiments/predictions/non-anchor-position-period-v16.json`, `experiments/preregistrations/non-anchor-position-period-v17.json`, `experiments/predictions/non-anchor-position-period-v17.json`, `experiments/preregistrations/non-anchor-position-period-v18.json`, `experiments/predictions/non-anchor-position-period-v18.json`, `experiments/preregistrations/non-anchor-position-period-v19.json`, `experiments/predictions/non-anchor-position-period-v19.json`, `experiments/preregistrations/non-anchor-position-period-v20.json`, `experiments/predictions/non-anchor-position-period-v20.json`, `experiments/preregistrations/non-anchor-position-period-v21.json`, `experiments/predictions/non-anchor-position-period-v21.json`, `experiments/preregistrations/non-anchor-position-period-v22.json`, `experiments/predictions/non-anchor-position-period-v22.json`, `experiments/preregistrations/non-anchor-position-period-v23.json`, `experiments/predictions/non-anchor-position-period-v23.json`, `experiments/preregistrations/non-anchor-position-period-v24.json`, `experiments/predictions/non-anchor-position-period-v24.json`, `experiments/preregistrations/non-anchor-position-period-v25.json`, `experiments/predictions/non-anchor-position-period-v25.json`, `experiments/preregistrations/non-anchor-position-period-v26.json`, `experiments/predictions/non-anchor-position-period-v26.json`, `experiments/preregistrations/non-anchor-position-period-v27.json`, `experiments/predictions/non-anchor-position-period-v27.json`, `experiments/preregistrations/non-anchor-position-period-v28.json`, `experiments/predictions/non-anchor-position-period-v28.json`, `experiments/preregistrations/non-anchor-position-period-v29.json`, `experiments/predictions/non-anchor-position-period-v29.json`, `experiments/preregistrations/non-anchor-position-period-v30.json`, `experiments/predictions/non-anchor-position-period-v30.json`, `experiments/preregistrations/non-anchor-position-period-v31.json`, `experiments/predictions/non-anchor-position-period-v31.json`, `experiments/preregistrations/non-anchor-position-period-v32.json`, `experiments/predictions/non-anchor-position-period-v32.json`, `experiments/preregistrations/non-anchor-position-period-v33.json`, `experiments/predictions/non-anchor-position-period-v33.json`, `experiments/preregistrations/non-anchor-position-period-v34.json`, `experiments/predictions/non-anchor-position-period-v34.json`, `experiments/preregistrations/non-anchor-position-period-v35.json`, `experiments/predictions/non-anchor-position-period-v35.json`, `experiments/preregistrations/non-anchor-position-period-v36.json`, `experiments/predictions/non-anchor-position-period-v36.json`, `experiments/preregistrations/non-anchor-position-period-v37.json`, `experiments/predictions/non-anchor-position-period-v37.json`, `experiments/preregistrations/non-anchor-position-period-v38.json`, `experiments/predictions/non-anchor-position-period-v38.json`, `experiments/preregistrations/non-anchor-position-period-v39.json`, `experiments/predictions/non-anchor-position-period-v39.json`, `experiments/preregistrations/non-anchor-position-period-v40.json`, `experiments/predictions/non-anchor-position-period-v40.json`, `experiments/preregistrations/non-anchor-position-period-v41.json`, `experiments/predictions/non-anchor-position-period-v41.json`, `experiments/preregistrations/non-anchor-position-period-v42.json`, `experiments/predictions/non-anchor-position-period-v42.json`, `experiments/preregistrations/non-anchor-position-period-v43.json`, `experiments/predictions/non-anchor-position-period-v43.json`, `experiments/preregistrations/non-anchor-position-period-v44.json`, `experiments/predictions/non-anchor-position-period-v44.json`, `experiments/preregistrations/non-anchor-position-period-v45.json`, `experiments/predictions/non-anchor-position-period-v45.json`, `kryptosbot-sanborn-papers-2026`
  - Steps: validate each non-anchor position-period preregistration; emit all registered period residue classes before observing independent evidence; compare each committed prediction artifact against deterministic generator output
  - Output: The committed artifacts lock eight registered periods, including source-context period 14, exclude 24 public-anchor positions, and emit 73 non-anchor K4 positions per period.
  - Baseline: The artifacts have no score yet; future evidence must use held-out or best-of-period controls before interpretation.
  - Interpretation: These are evidence-free prediction targets, not positive signals or K4 solution claims.
  - Next test: Use validate-prediction-artifact before evaluating any future independent evidence against the committed residue classes, and keep source-backed observation files separate from public-anchor-derived fragments.
  - Promoted: false
- **F6 Methodology context stops repeated single-layer search mining (H1/H2/H3/H4/H5)**
  - Sources: `kryptosbot-methodology-2026`, `experiments/STOPPED_LANES.md`, `experiments/PROGRESS_LOG.md`
  - Steps: register methodology context with a non-scored allowed-use boundary; compare it against completed batch, routed, held-out, and structural controls; record saturated search families as stopped unless a preregistration narrows the target before scoring
  - Output: Simple single-layer, word-list, route, and uncorrected best-of-search lanes are documented as stopped for current evidence.
  - Baseline: The stopped-lane decision is backed by existing negative batch-level, routed, held-out, and structural controls rather than a new positive score.
  - Interpretation: Methodology context improves research discipline, but it is not plaintext, candidate evidence, or an independent scored observation.
  - Next test: Only reopen a stopped search family with a lane-specific preregistration that fixes the cipher family, transform set, target, and multiple-comparison control before scoring.
  - Promoted: false
- **F7 Machine-readable gates protect future independent evidence (H3)**
  - Sources: `experiments/preregistrations/non-anchor-position-period-v1.json`, `experiments/predictions/non-anchor-position-period-v1.json`, `experiments/preregistrations/non-anchor-position-period-diagnostic-v1.json`, `experiments/predictions/non-anchor-position-period-diagnostic-v1.json`, `experiments/preregistrations/non-anchor-position-period-followup-v1.json`, `experiments/predictions/non-anchor-position-period-followup-v1.json`, `experiments/preregistrations/non-anchor-position-period-v2.json`, `experiments/predictions/non-anchor-position-period-v2.json`, `experiments/preregistrations/non-anchor-position-period-v3.json`, `experiments/predictions/non-anchor-position-period-v3.json`, `experiments/preregistrations/non-anchor-position-period-v4.json`, `experiments/predictions/non-anchor-position-period-v4.json`, `experiments/preregistrations/non-anchor-position-period-v5.json`, `experiments/predictions/non-anchor-position-period-v5.json`, `experiments/preregistrations/non-anchor-position-period-v6.json`, `experiments/predictions/non-anchor-position-period-v6.json`, `experiments/preregistrations/non-anchor-position-period-v7.json`, `experiments/predictions/non-anchor-position-period-v7.json`, `experiments/preregistrations/non-anchor-position-period-v8.json`, `experiments/predictions/non-anchor-position-period-v8.json`, `experiments/preregistrations/non-anchor-position-period-v9.json`, `experiments/predictions/non-anchor-position-period-v9.json`, `experiments/preregistrations/non-anchor-position-period-v10.json`, `experiments/predictions/non-anchor-position-period-v10.json`, `experiments/preregistrations/non-anchor-position-period-v11.json`, `experiments/predictions/non-anchor-position-period-v11.json`, `experiments/preregistrations/non-anchor-position-period-v12.json`, `experiments/predictions/non-anchor-position-period-v12.json`, `experiments/preregistrations/non-anchor-position-period-v13.json`, `experiments/predictions/non-anchor-position-period-v13.json`, `experiments/preregistrations/non-anchor-position-period-v14.json`, `experiments/predictions/non-anchor-position-period-v14.json`, `experiments/preregistrations/non-anchor-position-period-v15.json`, `experiments/predictions/non-anchor-position-period-v15.json`, `experiments/preregistrations/non-anchor-position-period-v16.json`, `experiments/predictions/non-anchor-position-period-v16.json`, `experiments/preregistrations/non-anchor-position-period-v17.json`, `experiments/predictions/non-anchor-position-period-v17.json`, `experiments/preregistrations/non-anchor-position-period-v18.json`, `experiments/predictions/non-anchor-position-period-v18.json`, `experiments/preregistrations/non-anchor-position-period-v19.json`, `experiments/predictions/non-anchor-position-period-v19.json`, `experiments/preregistrations/non-anchor-position-period-v20.json`, `experiments/predictions/non-anchor-position-period-v20.json`, `experiments/preregistrations/non-anchor-position-period-v21.json`, `experiments/predictions/non-anchor-position-period-v21.json`, `experiments/preregistrations/non-anchor-position-period-v22.json`, `experiments/predictions/non-anchor-position-period-v22.json`, `experiments/preregistrations/non-anchor-position-period-v23.json`, `experiments/predictions/non-anchor-position-period-v23.json`, `experiments/preregistrations/non-anchor-position-period-v24.json`, `experiments/predictions/non-anchor-position-period-v24.json`, `experiments/preregistrations/non-anchor-position-period-v25.json`, `experiments/predictions/non-anchor-position-period-v25.json`, `experiments/preregistrations/non-anchor-position-period-v26.json`, `experiments/predictions/non-anchor-position-period-v26.json`, `experiments/preregistrations/non-anchor-position-period-v27.json`, `experiments/predictions/non-anchor-position-period-v27.json`, `experiments/preregistrations/non-anchor-position-period-v28.json`, `experiments/predictions/non-anchor-position-period-v28.json`, `experiments/preregistrations/non-anchor-position-period-v29.json`, `experiments/predictions/non-anchor-position-period-v29.json`, `experiments/preregistrations/non-anchor-position-period-v30.json`, `experiments/predictions/non-anchor-position-period-v30.json`, `experiments/preregistrations/non-anchor-position-period-v31.json`, `experiments/predictions/non-anchor-position-period-v31.json`, `experiments/preregistrations/non-anchor-position-period-v32.json`, `experiments/predictions/non-anchor-position-period-v32.json`, `experiments/preregistrations/non-anchor-position-period-v33.json`, `experiments/predictions/non-anchor-position-period-v33.json`, `experiments/preregistrations/non-anchor-position-period-v34.json`, `experiments/predictions/non-anchor-position-period-v34.json`, `experiments/preregistrations/non-anchor-position-period-v35.json`, `experiments/predictions/non-anchor-position-period-v35.json`, `experiments/preregistrations/non-anchor-position-period-v36.json`, `experiments/predictions/non-anchor-position-period-v36.json`, `experiments/preregistrations/non-anchor-position-period-v37.json`, `experiments/predictions/non-anchor-position-period-v37.json`, `experiments/preregistrations/non-anchor-position-period-v38.json`, `experiments/predictions/non-anchor-position-period-v38.json`, `experiments/preregistrations/non-anchor-position-period-v39.json`, `experiments/predictions/non-anchor-position-period-v39.json`, `experiments/preregistrations/non-anchor-position-period-v40.json`, `experiments/predictions/non-anchor-position-period-v40.json`, `experiments/preregistrations/non-anchor-position-period-v41.json`, `experiments/predictions/non-anchor-position-period-v41.json`, `experiments/preregistrations/non-anchor-position-period-v42.json`, `experiments/predictions/non-anchor-position-period-v42.json`, `experiments/preregistrations/non-anchor-position-period-v43.json`, `experiments/predictions/non-anchor-position-period-v43.json`, `experiments/preregistrations/non-anchor-position-period-v44.json`, `experiments/predictions/non-anchor-position-period-v44.json`, `experiments/preregistrations/non-anchor-position-period-v45.json`, `experiments/predictions/non-anchor-position-period-v45.json`, `experiments/preregistrations/ciphertext-structure-prior-v1.json`, `experiments/predictions/ciphertext-structure-prior-v1.json`, `experiments/preregistrations/ciphertext-hotspot-prior-v1.json`, `experiments/predictions/ciphertext-hotspot-prior-v1.json`, `experiments/preregistrations/ciphertext-rarity-prior-v1.json`, `experiments/predictions/ciphertext-rarity-prior-v1.json`, `experiments/preregistrations/ciphertext-repeat-distance-v1.json`, `experiments/predictions/ciphertext-repeat-distance-v1.json`, `experiments/preregistrations/ciphertext-period-match-v1.json`, `experiments/predictions/ciphertext-period-match-v1.json`, `experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json`, `experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json`, `experiments/preregistrations/ciphertext-transition-prior-v1.json`, `experiments/predictions/ciphertext-transition-prior-v1.json`, `experiments/preregistrations/ciphertext-turning-point-v1.json`, `experiments/predictions/ciphertext-turning-point-v1.json`, `experiments/preregistrations/ciphertext-window-balance-v1.json`, `experiments/predictions/ciphertext-window-balance-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-high-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-very-high-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-super-extreme-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-super-extreme-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-hyper-extreme-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-hyper-extreme-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-terminal-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-terminal-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-post-terminal-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-post-terminal-moduli-v1.json`, `experiments/preregistrations/non-anchor-position-spacing-v1.json`, `experiments/predictions/non-anchor-position-spacing-v1.json`, `experiments/preregistrations/non-anchor-position-mirror-v1.json`, `experiments/predictions/non-anchor-position-mirror-v1.json`, `experiments/preregistrations/non-anchor-position-grid-layout-v1.json`, `experiments/predictions/non-anchor-position-grid-layout-v1.json`, `experiments/preregistrations/non-anchor-position-grid-column-v1.json`, `experiments/predictions/non-anchor-position-grid-column-v1.json`, `experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json`, `experiments/predictions/non-anchor-position-grid-compass-axis-v1.json`, `experiments/preregistrations/tableau-hill-v1.json`, `experiments/predictions/tableau-hill-v1.json`, `experiments/PROGRESS_LOG.md`, `release-check`
  - Steps: validate every committed independent-lane preregistration with JSON output; validate every committed independent-lane prediction artifact with JSON output; run release-check in JSON mode and require every local preflight gate to pass
  - Output: All committed independent-lane preregistrations and artifacts validate as non-promotional, and release-check JSON reports every local gate as passed.
  - Baseline: This is a reproducibility gate, not a scored cryptanalytic baseline; it prevents stale or unregistered evidence from being interpreted as a signal.
  - Interpretation: Future evidence can be audited by tools before scoring, but the gate result itself provides no plaintext and promotes no candidate.
  - Next test: Before any new non-anchor observation is scored, run the JSON preregistration, prediction-artifact, observation, evaluation, and release gates and archive the exact outputs.
  - Promoted: false
- **F8 Source-backed observation scoring requires preregistration (H3)**
  - Sources: `src/main.rs`, `src/position_structure.rs`, `tests/cli_e2e.rs`, `experiments/PROGRESS_LOG.md`
  - Steps: mark direct evaluate-period-prediction --positions input as diagnostic; require --preregistration when evaluate-period-prediction scores a --positions-file; require per-position notes before any source-backed observation file can validate; validate the committed prediction artifact before source-backed observations are scored; revalidate archived preregistration, artifact, and observation files before accepting archived source-backed evaluations
  - Output: Ad hoc position lists now emit a diagnostic warning, source-backed observation files require preregistration-backed artifact validation and one note per scored position before scoring, and archived evaluations re-run archive-local preregistration/artifact/observation checks.
  - Baseline: This is an evidence-boundary guard rather than a positive statistical signal; it prevents stale artifacts, ad hoc position lists, thin observation files, or internally tampered archives from being interpreted as independent support.
  - Interpretation: The period-prediction workflow is stricter, but no new K4 plaintext, key material, or promoted candidate is produced.
  - Next test: When a real non-anchor observation file exists, validate its preregistration and artifact, run validate-period-observations, then evaluate-period-prediction with --positions-file and archive the JSON outputs.
  - Promoted: false
- **F9 Spacing prediction scoring has a source-backed validation gate (H3)**
  - Sources: `src/main.rs`, `src/position_structure.rs`, `tests/cli_e2e.rs`, `experiments/PROGRESS_LOG.md`
  - Steps: emit a committed non-anchor spacing prediction artifact; require per-position notes in source-backed observation files; validate source-backed observation files against the spacing artifact before scoring; evaluate spacing observations with a best-of-modulus seeded null only after artifact validation
  - Output: Spacing observations now have a pre-score validation command and evaluator, both keeping ad hoc inputs diagnostic and source-backed files preregistration-gated with per-position notes.
  - Baseline: This is a guardrail for future independent evidence; the diagnostic toy spacing check was non-promotional and did not produce a meaningful p-value.
  - Interpretation: The spacing lane is now executable for future independent observations, but it does not add K4 plaintext, key material, or a promoted candidate.
  - Next test: When a real non-anchor observation file exists, run validate-spacing-observations with the spacing preregistration, then evaluate-spacing-prediction with --positions-file and archive the JSON outputs.
  - Promoted: false
- **F10 Independent lane status exposes the next evidence gate (H3)**
  - Sources: `src/preregistration.rs`, `src/main.rs`, `tests/cli_e2e.rs`, `experiments/preregistrations/ciphertext-window-balance-narrow-v1.json`, `experiments/predictions/ciphertext-window-balance-narrow-v1.json`, `experiments/preregistrations/ciphertext-window-balance-wide-v1.json`, `experiments/predictions/ciphertext-window-balance-wide-v1.json`, `experiments/preregistrations/ciphertext-ct-perturbation-v1.json`, `experiments/predictions/ciphertext-ct-perturbation-v1.json`, `experiments/preregistrations/ciphertext-stehle-regularity-v1.json`, `experiments/predictions/ciphertext-stehle-regularity-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-post-terminal-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-post-terminal-moduli-v1.json`, `experiments/PROGRESS_LOG.md`
  - Steps: scan committed preregistration files except the template; validate each preregistration and declared prediction artifact; require grid-layout preregistrations to declare the source-backed edge axis before scoring; warn when a committed prediction artifact duplicates another committed artifact; report lane readiness and the next observation validator or evaluator command
  - Output: The lane-status command reports 76 lanes, 76 ready for source-backed observations, 0 invalid lanes, 0 evaluator-pending lanes, 76 prediction artifacts, 34 unique prediction artifact contents, 34 unique ready prediction artifact contents, 1 duplicate artifact group, 43 duplicate artifact lanes, and 42 extra duplicate artifact lanes beyond the first artifact instance; ciphertext-adjacent-contrast-position-prior family 1 lane/1 unique ready artifact, ciphertext-ct-perturbation-position-prior family 1 lane/1 unique ready artifact, ciphertext-hotspot-position-prior family 1 lane/1 unique ready artifact, ciphertext-only-position-prior family 1 lane/1 unique ready artifact, ciphertext-period-match-position-prior family 1 lane/1 unique ready artifact, ciphertext-rarity-position-prior family 1 lane/1 unique ready artifact, ciphertext-repeat-distance-position-prior family 1 lane/1 unique ready artifact, ciphertext-residue-balance-position-prior family 9 lanes/9 unique ready artifacts, ciphertext-skip-transition-position-prior family 1 lane/1 unique ready artifact, ciphertext-stehle-regularity-position-prior family 1 lane/1 unique ready artifact, ciphertext-transition-position-prior family 1 lane/1 unique ready artifact, ciphertext-turning-point-position-prior family 1 lane/1 unique ready artifact, ciphertext-window-balance-position-prior family 3 lanes/3 unique ready artifacts, grid-layout family 3 lanes/3 unique ready artifacts, mirror family 1 lane/1 unique ready artifact, period family 47 lanes/5 unique ready artifacts, spacing family 1 lane/1 unique ready artifact, tableau-hill-prediction family 1 lane/1 unique ready artifact, and promoted false. Prediction-artifact validation warns that duplicate period artifacts are inventory only, not independent evidence; the period-v40 artifact is a distinct period-3-only target with source-backed negative/non-significant support, the period-v42 artifact is a distinct period-5-only target with source-backed negative/non-significant support, the period-v43 artifact is a distinct period-14-only source-context target with source-backed negative/non-significant support, the period-v44 artifact is a distinct period-7-only target with source-backed negative/non-significant support, and the period-v45 artifact is a duplicate all-period readiness target only. The ciphertext-only prior fixes weak period-2 and period-7 ciphertext-derived residue targets before source-backed observation scoring. The ciphertext-hotspot prior fixes top ciphertext-only hotspots from repeated n-gram coverage and shifted self-coincidence endpoints before any source-backed scoring. The ciphertext-rarity prior fixes the 20 non-anchor positions whose ciphertext letters are rarest in the non-anchor universe before source-backed observation scoring. The ciphertext repeat-distance prior fixes the 20 non-anchor positions with strongest same-symbol repeat-distance structure before source-backed observation scoring. The ciphertext period-match prior fixes shifted same-letter period-match endpoint sets before source-backed observation scoring. The ciphertext adjacent-contrast prior fixes the 20 interior non-anchor positions with strongest left/right neighbor contrast in Kryptos alphabet order before source-backed observation scoring. The ciphertext CT-perturbation prior fixes six non-anchor C/T ciphertext positions from the source-documented unresolved symbol-swap context and now has a family-specific validator/evaluator for source-backed observation files. The ciphertext transition prior fixes the 20 non-anchor positions with highest adjacent ciphertext-transition pressure before source-backed observation scoring. The ciphertext skip-transition prior fixes the 20 non-anchor positions with highest adjacent and distance-two ciphertext skip-transition pressure before source-backed observation scoring. The ciphertext turning-point prior fixes the 20 non-anchor positions with strongest local turning-point/high-curvature structure before source-backed observation scoring. The ciphertext window-balance family now has three unique source-backed-observation targets: the broader 20-position `[3, 5, 7]` local-window balance artifact, the narrower top-12 `[3, 5]` artifact, and the wide top-12 `[9, 11, 13]` artifact. The ciphertext Stehle-regularity prior fixes the source-described local regularity window and lag-confirmed +5 subset before source-backed observation scoring. The ciphertext residue-balance prior fixes ciphertext-only residue classes per modulus before source-backed observation scoring, including distinct high-moduli 7..=13, very-high-moduli 14..=20, ultra-high-moduli 21..=26, extreme-moduli 27..=33, super-extreme-moduli 34..=40, hyper-extreme-moduli 41..=47, terminal-moduli 48..=54, and post-terminal-moduli 55..=61 targets. Grid-layout preregistrations now declare `grid_edge_axis: row`, `grid_edge_axis: column`, or `grid_edge_axis: compass-axis`, so source-backed grid scoring must use a matching preregistered artifact rather than switching axes post hoc. The tableau-hill lane has a committed source-mapping artifact that fixes 7-by-14 row-major coordinates and the single padding cell, plus a validator/evaluator that scores only row/column concentration on source-backed non-anchor observations with seeded null controls.
  - Baseline: This is an operational gate summary rather than a statistical cryptanalytic baseline.
  - Interpretation: All current supported independent prediction lanes are ready for source-backed observation files; scored observation evidence is tracked separately from lane inventory, and no candidate is promoted.
  - Next test: Use independent-lane-status and next-evidence-gate before adding any observation file, then run the family-specific validator, evaluator, and archive validator named by the gate output.
  - Promoted: false
- **F11 CIA row-boundary observation is source-backed but negative (H3)**
  - Sources: `sources/archives/cia-sculpture-2026-05-27.md`, `experiments/source-reviews/cia-source-review-v1.json`, `experiments/position-observations/cia-k4-row-boundaries-v1.json`, `experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`, `experiments/preregistrations/non-anchor-position-mirror-v1.json`, `experiments/predictions/non-anchor-position-mirror-v1.json`, `experiments/preregistrations/non-anchor-position-grid-layout-v1.json`, `experiments/predictions/non-anchor-position-grid-layout-v1.json`, `experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json`, `experiments/predictions/non-anchor-position-grid-compass-axis-v1.json`, `experiments/preregistrations/tableau-hill-v1.json`, `experiments/predictions/tableau-hill-v1.json`, `experiments/preregistrations/ciphertext-hotspot-prior-v1.json`, `experiments/predictions/ciphertext-hotspot-prior-v1.json`, `experiments/preregistrations/ciphertext-rarity-prior-v1.json`, `experiments/predictions/ciphertext-rarity-prior-v1.json`, `experiments/preregistrations/ciphertext-repeat-distance-v1.json`, `experiments/predictions/ciphertext-repeat-distance-v1.json`, `experiments/preregistrations/ciphertext-period-match-v1.json`, `experiments/predictions/ciphertext-period-match-v1.json`, `experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json`, `experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json`, `experiments/preregistrations/ciphertext-transition-prior-v1.json`, `experiments/predictions/ciphertext-transition-prior-v1.json`, `experiments/preregistrations/ciphertext-skip-transition-v1.json`, `experiments/predictions/ciphertext-skip-transition-v1.json`, `experiments/preregistrations/ciphertext-turning-point-v1.json`, `experiments/predictions/ciphertext-turning-point-v1.json`, `experiments/preregistrations/ciphertext-window-balance-v1.json`, `experiments/predictions/ciphertext-window-balance-v1.json`, `experiments/preregistrations/ciphertext-ct-perturbation-v1.json`, `experiments/predictions/ciphertext-ct-perturbation-v1.json`, `results/ciphertext-ct-perturbation-observations/cia-k4-row-boundaries-v1`, `experiments/preregistrations/ciphertext-stehle-regularity-v1.json`, `experiments/predictions/ciphertext-stehle-regularity-v1.json`, `results/ciphertext-stehle-regularity-observations/cia-k4-row-boundaries-v1`, `experiments/preregistrations/ciphertext-residue-balance-high-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-very-high-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json`, `experiments/preregistrations/ciphertext-residue-balance-super-extreme-moduli-v1.json`, `experiments/predictions/ciphertext-residue-balance-super-extreme-moduli-v1.json`, `results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-super-extreme-moduli-v1`
  - Steps: record CIA sculpture text-version row-boundary positions before scoring; exclude public-anchor positions from the row-boundary set; validate the retained positions against period, spacing, mirror, grid row, grid column, grid compass-axis, Tableau/HILL, and ciphertext-only preregistrations including window-balance, CT-perturbation, Stehle-regularity, period-match, high-moduli, very-high-moduli, ultra-high-moduli, extreme-moduli, and super-extreme-moduli residue balance; score the retained positions with seeded best-of-model null controls; validate the local period, spacing, mirror, grid-row, grid-column, grid-compass-axis, Tableau/HILL, ciphertext-hotspot, ciphertext-rarity, ciphertext-repeat-distance, ciphertext-period-match, ciphertext-adjacent-contrast, ciphertext-transition, ciphertext-skip-transition, ciphertext-turning-point, ciphertext-window-balance, ciphertext-CT-perturbation, ciphertext-Stehle-regularity, ciphertext-residue-balance, and other ciphertext-only evaluation archives
  - Output: The source-backed observation retains non-anchor positions 1, 4, 5, 36, 37, and 97. Period scoring found best period 2 residue 0 with 4/6 hits and empirical p=0.7897. Period-5 scoring found best residue 0 with 2/6 hits and empirical p=1.0000. Period-7 scoring found best residue 0 with 2/6 hits and empirical p=0.9476. Spacing scoring found best modulus 2 residue 1 with 8/15 pair hits and empirical p=1.0000. Mirror scoring found 1/3 possible mirror-pair hits and empirical p=0.2090. Grid-row scoring found 1/6 row-edge hits and empirical p=0.5600 under the archived `--edge-axis row` target, matching preregistered `grid_edge_axis: row`. Grid-column scoring found 4/6 column-edge hits at positions 1, 4, 5, and 97 with empirical p=0.1303 under the archived `--edge-axis column` target, matching preregistered `grid_edge_axis: column`. Grid-compass-axis scoring found 1/6 compass-axis hits at position 36 with empirical p=0.9166 under the archived `--edge-axis compass-axis` target, matching preregistered `grid_edge_axis: compass-axis`. Tableau/HILL scoring found best row 1 concentration with 3/6 hits and empirical p=0.3311. Ciphertext-hotspot scoring found 0/6 hotspot hits and empirical p=1.0000. Ciphertext-rarity scoring found 2/6 rare-position hits and empirical p=0.5282. Ciphertext-repeat-distance scoring found 2/6 repeat-distance hits and empirical p=0.5273. Ciphertext-period-match scoring found best shifted same-letter period 2 endpoints with 1/6 hits and empirical p=0.9733. Ciphertext-adjacent-contrast scoring found 2/6 adjacent-contrast hits at positions 5 and 37 with empirical p=0.5259. Ciphertext-transition scoring found 0/6 adjacent-transition-position hits and empirical p=1.0000. Ciphertext-skip-transition scoring found 0/6 skip-transition-position hits and empirical p=1.0000. Ciphertext-turning-point scoring found 2/6 turning-point hits and empirical p=0.5247. Ciphertext-window-balance scoring found 0/6 window-balance hits and empirical p=1.0000. Ciphertext-CT-perturbation scoring found 1/6 C/T-position hits at position 36 with empirical p=0.4139. Ciphertext-Stehle-regularity scoring found 0/6 Stehle-window hits with empirical p=1.0000 and 0/6 lag-confirmed +5 hits with empirical p=1.0000. Ciphertext-residue-balance scoring found best modulus 2 residue 0 with 4/6 hits and empirical p=0.4803. High-moduli ciphertext-residue-balance scoring found best modulus 8 residue 3 with 2/6 hits and empirical p=0.6416. Very-high-moduli ciphertext-residue-balance scoring found best modulus 16 residue 0 with 2/6 hits and empirical p=0.3125. Ultra-high-moduli ciphertext-residue-balance scoring found best modulus 21 residue 12 with 1/6 hits and empirical p=0.8289. Extreme-moduli ciphertext-residue-balance scoring found best modulus 27 residue 8 with 1/6 hits and empirical p=0.7859. Super-extreme-moduli ciphertext-residue-balance scoring found best modulus 35 residue 4 with 1/6 hits and empirical p=0.6741.
  - Baseline: The period and spacing evaluations use seeded best-of-model null controls, and the mirror, grid-row, grid-column, grid-compass-axis, Tableau/HILL, ciphertext-hotspot, ciphertext-rarity, ciphertext-repeat-distance, ciphertext-period-match, ciphertext-adjacent-contrast, ciphertext-transition, ciphertext-skip-transition, ciphertext-turning-point, ciphertext-window-balance, ciphertext-CT-perturbation, ciphertext-Stehle-regularity, and ciphertext-residue-balance evaluations use seeded same-size non-anchor position-set nulls; none of the results is unusual under the configured controls.
  - Interpretation: The row-boundary observation is auditable independent evidence, but it is negative for the committed period, spacing, mirror, grid-row, grid-column, grid-compass-axis, Tableau/HILL, and ciphertext-only targets and promotes no K4 candidate.
  - Next test: Stop mining this row-boundary observation. Future progress needs a new source-backed observation or a pre-registered prediction target that is not derived from these same row-boundary positions.
  - Promoted: false
- **F12 Unused CIA artifact source is eligible context but not currently scoreable (H3)**
  - Sources: `sources/archives/cia-artifact-2026-05-27.md`, `src/main.rs`, `tests/cli_e2e.rs`, `experiments/PROGRESS_LOG.md`
  - Steps: compare eligible observation sources against valid source-backed evidence archives; identify eligible sources already consumed by scored archives; inspect unused eligible source archives for explicit scored-position markers or non-scorable reasons; report unused eligible source status in next-evidence-gate before recommending any new score; summarize reviewed/used/scored-marker/non-scorable state with source-observation-status
  - Output: The live gate and focused source-observation-status command report `cia-sculpture` as reviewed, scored-marker backed, and used by archived source-backed evaluations. They report `cia-artifact` as reviewed and locally archived but unused, with no `scored_positions_one_based` marker and an explicit `non_scorable_reason`, so it must not be scored unless new source-backed rationale changes that archive boundary.
  - Baseline: This is a source-use and evidence-readiness guard, not a statistical baseline; it prevents treating an eligible contextual source as scored evidence without a new observation rationale.
  - Interpretation: No new K4 plaintext, key material, candidate, or solution is produced. The next scoreable step would require a new source-backed rationale that changes the archive boundary, a new eligible source, or a distinct preregistered prediction artifact.
  - Next test: Do not score `cia-artifact` from the current archive alone. First add a source-backed non-anchor observation with explicit per-position notes and archive markers, or keep it non-scorable and use a new eligible source.
  - Promoted: false
- **F13 External plaintext claims are quarantined before verification (H3)**
  - Sources: `sources/archives/solvekryptos-2026-05-27.md`, `sources/archives/ssrn-bonifacino-running-key-2025-2026-05-31.md`, `sources/archives/smithsonian-2026-archive-discovery-2026-05-28.md`, `sources/source-packet.md`, `src/claim.rs`, `src/data.rs`, `src/main.rs`, `tests/cli_e2e.rs`
  - Steps: register external solution claims with allowed_use unverified-solution-claim; archive claim metadata and boundary language without copying claimed plaintext; register institutional archive-discovery reporting as context-only provenance rather than scoreable evidence; verify local claim files with length, public-anchor, and aggregate shift diagnostics only; verify local plaintext plus running-key-stream files with length, public-anchor, and additive ciphertext reconstruction checks only; verify local claim reconciliation tables with row, ciphertext, optional coordinate, numeric-letter, and shift/gate arithmetic, public-anchor, and aggregate shift diagnostics only; screen the public SolveKryptos claim through a temporary local file that is deleted after verification; register the SSRN running-key claim as an unverified solution-claim source and require local plaintext/key-stream files for any reconstruction check; screen the public SolveKryptos canonical bundle reconciliation table from /private/tmp without committing plaintext-bearing files; screen the public SolveKryptos canonical bundle files from /private/tmp with repo ciphertext, plaintext length-only, reconciliation, R/r grid, gate-map, Z2 handoff, and public-anchor cross-checks; screen the public SolveKryptos canonical mechanism files from /private/tmp with f/helper-card, control-card, Z2 handoff, Y-pass gate-template, and Z2 helper-path grid checks; compare the Y-template declared zero-position list against the zero positions implied by its printed rule and Y row; reject non-quarantined source IDs for plaintext-claim verification; surface quarantined claim sources and the safe verifier commands in next-evidence-gate
  - Output: The SolveKryptos and SSRN running-key claims are registered as quarantined external claims, and the Smithsonian 2026 archive-discovery article is registered as context-only provenance. The public SolveKryptos claim text passes the narrow local structure check: 97 normalized letters, 4/4 public anchors preserved, all 26 implied shift values present, 71 repeated shift values, and maximum shift bucket count 8. The SSRN running-key source has a dedicated local verifier for plaintext plus key-stream files that checks normalized length, public anchors, and additive ciphertext reconstruction under a declared alphabet without printing or storing either input. The public canonical bundle reconciliation table also passes the local quarantine check from a temporary `/private/tmp` download: 97 rows, 97/97 K4 ciphertext alignment, 97/97 tier values, 97/97 lane values, 97/97 checked `R` values, 97/97 binary gate values, 97/97 checked `r + gate` values, 31/31 checked Z2 handoff values, and 4/4 registered public anchors preserved. The bundle-level check also cross-checks the required local files, repo ciphertext, plaintext length only, reconciliation table, 97/97 `R` grid values, 97/97 `r` grid values, and 97/97 gate-map values. A refreshed mechanism-file check cross-checks 8/8 required mechanism files, 26/26 `f` table values, 26/26 helper-card delta relationships, 9/9 control-card entries, Z2 effective-key derivation, 31/31 Z2 helper-path base-`r` grid checks, and 31/31 Z2 helper-path final `R` grid checks, but fails the Y-pass layer with only 27/31 Y-pass template rule checks and 27/31 Y-pass gate-map checks matched. The non-leaking mismatch diagnostic localizes those disagreements to Y positions 23, 27, 28, and 29, corresponding to K4 positions 27, 31, 32, and 33. A follow-up Y-template diagnostic also finds that the template's declared zero-position list differs from the zero positions implied by its printed rule and Y row: declared-only positions are 23, 28, and 29; rule-only position is 27. The checks use temporary local files only, do not print or store the claimed plaintext, key stream, or plaintext-bearing table, and next-evidence-gate reports claim sources separately from scoreable observation sources.
  - Baseline: This is an intake and leakage-control gate, not evidence for a solution; public-anchor compatibility remains a minimum structural check and cannot promote a candidate.
  - Interpretation: The external claim is compatible with the currently registered public anchors, and its published reconciliation table and top-level bundle files remain internally compatible with the repo's quarantine verifiers. The refreshed published helper machinery is not fully compatible with the mechanism verifier because the Y-pass template layer fails and the Y-template's declared zero-position list disagrees with its printed rule. None of these checks validates an on-site physical helper-stream reading or verifies the claimed mechanism as independent evidence.
  - Next test: Do not promote any claim from length/anchor, running-key reconstruction, table-shape compatibility, archive-discovery reporting, canonical-bundle reconciliation, bundle-file cross-checks, or mechanism-file consistency checks. Any follow-up must independently validate the claimed physical helper stream or obtain independent non-anchor evidence before adding source-derived hypothesis or candidate material.
  - Promoted: false
- **F14 Ciphertext-only period profile is weak after shuffled controls (H3)**
  - Sources: `src/ciphertext_profile.rs`, `src/main.rs`, `tests/cli_e2e.rs`, `experiments/PROGRESS_LOG.md`
  - Steps: profile public K4 ciphertext letters without anchors or candidate material; compute letter frequencies, repeated n-grams, repeated n-gram gap-factor support, overall index of coincidence, and shifted period coincidence rates; shuffle ciphertext letters with a deterministic seed and record the best repeated n-gram gap-factor support and best shifted period-match rate across the scanned period range; emit a planning-only ciphertext-structure prior for future source-backed non-anchor observations; score the CIA row-boundary source-backed non-anchor observation file against the planning-only prior with same-size non-anchor position-shuffle controls
  - Output: The ciphertext-only profile over periods 1 through 20 reports overall IC 0.0361, a best repeated n-gram spacing factor at period 2 with 7/10 supported gaps, and a best shifted period signal at period 7 with 9/90 matches. The 100000-iteration seeded null gives spacing p=0.0568 and shifted-period p=0.0719; ciphertext-structure-prior records periods 2 and 7 as future-observation priors only. The source-backed CIA row-boundary observation scores best at period 2 residue 0 with 4/6 hits, but the same-size non-anchor position-shuffle null gives empirical p=0.6845 over 100000 iterations.
  - Baseline: The repeated n-gram spacing and shifted-period signals are each compared against seeded ciphertext-only shuffles that preserve the K4 letter multiset and scan the same period range. The row-boundary prior evaluation is compared against seeded same-size shuffles over the non-anchor position universe.
  - Interpretation: The period-2 spacing factor and period-7 shifted coincidence are weak diagnostic leads only, and the first source-backed prior evaluation is negative. They are not independently significant, not plaintext, not a key, and not promoted candidates.
  - Next test: Stop mining this ciphertext-prior lane unless a genuinely independent source-backed observation or mechanically independent model predicts the same structure before scoring.
  - Promoted: false

## Release Check

Local preflight only. This repo does not use GitHub Actions.

- github-actions-disabled: true (GitHub Actions workflow directory must not exist. path=/Users/michaelnobile/Antigravity/Ciphers/.github/workflows)
- dependabot-disabled: true (Dependabot config must not exist because releases are locally gated. path=/Users/michaelnobile/Antigravity/Ciphers/.github/dependabot.yml)
- readme-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/README.md)
- research-method-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/docs/research-method.md)
- current-architecture-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/docs/architecture-current.md)
- production-goal-architecture-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/docs/architecture-production-goal.md)
- source-packet-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/sources/source-packet.md)
- candidate-csv-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.csv)
- candidate-registry-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.md)
- research-plan-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/kryptos-k4-research-plan.md)
- license-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/LICENSE)
- lockfile-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/Cargo.lock)
- markdown-report-present: true (Generated release report must be present. path=/Users/michaelnobile/Antigravity/Ciphers/notes/k4-report.md)
- candidate-registry-aligned: true (Candidate CSV rows are represented in the candidate registry with source IDs and rationale. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.csv; registry_path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.md)
- preregistrations-valid: true (Committed non-template preregistrations validate. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/preregistrations; checked=76)
- preregistration-readme-current: true (Preregistration README names every committed lane and declared prediction artifact. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/preregistrations/README.md; checked=76)
- prediction-artifacts-valid: true (Committed prediction artifacts match their preregistrations and deterministic generators. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/predictions; checked=76)
- independent-lanes-ready: true (Supported independent preregistered lanes are ready for source-backed observation files; evaluator-pending lanes are inventoried separately. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/preregistrations; ready=76; checked=76; prediction_artifacts=76; unique_prediction_artifacts=34; unique_ready_prediction_artifacts=34; duplicate_artifact_groups=1; duplicate_artifact_lanes=43; extra_duplicate_artifact_lanes=42; family_summary=ciphertext-adjacent-contrast-position-prior:1_lanes/1_unique_ready,ciphertext-ct-perturbation-position-prior:1_lanes/1_unique_ready,ciphertext-hotspot-position-prior:1_lanes/1_unique_ready,ciphertext-only-position-prior:1_lanes/1_unique_ready,ciphertext-period-match-position-prior:1_lanes/1_unique_ready,ciphertext-rarity-position-prior:1_lanes/1_unique_ready,ciphertext-repeat-distance-position-prior:1_lanes/1_unique_ready,ciphertext-residue-balance-position-prior:9_lanes/9_unique_ready,ciphertext-skip-transition-position-prior:1_lanes/1_unique_ready,ciphertext-stehle-regularity-position-prior:1_lanes/1_unique_ready,ciphertext-transition-position-prior:1_lanes/1_unique_ready,ciphertext-turning-point-position-prior:1_lanes/1_unique_ready,ciphertext-window-balance-position-prior:3_lanes/3_unique_ready,position-grid-layout-prediction:3_lanes/3_unique_ready,position-mirror-prediction:1_lanes/1_unique_ready,position-period-prediction:47_lanes/5_unique_ready,position-spacing-prediction:1_lanes/1_unique_ready,tableau-hill-prediction:1_lanes/1_unique_ready)
- position-observation-template-guarded: true (Position observation template remains intentionally non-scorable. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/position-observations-template.json)
- position-observations-valid: true (Committed source-backed observation files validate. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/position-observations; checked=1)
- evidence-summaries-present: true (Committed source-backed observations have evidence summaries with archive command references and negative period/spacing/mirror/grid-row/grid-column/grid-compass-axis/tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-ct-perturbation/ciphertext-stehle-regularity/ciphertext-residue-balance result metrics. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/evidence-summaries; checked=1)
- findings-source-inputs-valid: true (Findings source inputs resolve to registered sources, committed files, or known local command references. path=/Users/michaelnobile/Antigravity/Ciphers/src/findings.rs; checked=14)
- source-packet-latest-access-date: true (Source packet includes latest registered source access date. path=/Users/michaelnobile/Antigravity/Ciphers/sources/source-packet.md; latest_access_date=2026-05-31)
- source-packet-registry-aligned: true (Source packet matches every registered source ID, URL, type, and allowed-use boundary. path=/Users/michaelnobile/Antigravity/Ciphers/sources/source-packet.md)
- source-archives-complete: true (Every registered source has a local quote-free archive path. path=/Users/michaelnobile/Antigravity/Ciphers/sources/archives; checked=29)
- source-archives-present: true (Registered local source archive paths exist. path=/Users/michaelnobile/Antigravity/Ciphers; checked=29)
- source-archives-structured: true (Registered local source archives preserve required metadata, no-promotion boundaries, and explicit non-scorable/scored-position consistency. path=/Users/michaelnobile/Antigravity/Ciphers/sources/archives; checked=29)
- observation-source-archives-cover-positions: true (Committed source-backed observations are covered by local source archives with explicit scored-position markers. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/position-observations; checked=1)
- source-reviews-valid: true (Committed source-review files validate against current source metadata. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/source-reviews; checked=1)
- source-readiness-commands-documented: true (Source readiness command is documented in release-facing files. path=/Users/michaelnobile/Antigravity/Ciphers)
- next-evidence-structured-support-documented: true (Next-evidence structured archive support details are documented in release-facing files. path=/Users/michaelnobile/Antigravity/Ciphers)
- stopped-lanes-documented: true (Stopped-lane ledger documents negative lanes, duplicate-period inventory, row-boundary evidence, preregistration gate, and no-solution boundary. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/STOPPED_LANES.md)
- progress-log-current: true (Progress log reflects current lane inventory and committed source-backed observation evidence. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/PROGRESS_LOG.md)
- claim-verification-archives-structured: true (Committed claim-verification archives are tied to quarantined claim sources and preserve non-promotion/no-plaintext boundaries. path=/Users/michaelnobile/Antigravity/Ciphers/results/claim-verifications; checked=3)
- no-plaintext-leakage-markers: true (No leaked/full-plaintext sentinel markers found in release-facing files or artifacts.)
