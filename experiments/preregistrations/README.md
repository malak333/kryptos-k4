# Preregistrations

Use this directory for proposed K4 research lanes before adding candidate rows,
transforms, routes, or structural tests.

Start by copying the template to a lane-specific file and replacing every
placeholder. The filename stem must match the JSON `id`; copied placeholder
names such as `new-lane-id.json` are rejected by `validate-preregistration`.

```bash
cp experiments/preregistrations/independent-lane-template.json \
  experiments/preregistrations/<lane-id>.json
```

Validate the lane-specific proposal with:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/<lane-id>.json
```

If the preregistration declares `prediction_artifact`, also validate the
committed prediction target:

```bash
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/<lane-id>.json
```

The validator rejects lanes that reuse public anchor-derived fragments as
discovery inputs or primary evidence. Those fragments can still be listed as
controls after an independent target is defined. The validator also rejects
unchanged template placeholder text.

Before adding another lane, run `independent-lane-status` and check the family
summary. A new preregistration that points to the same deterministic artifact as
an existing family adds workflow traceability, not independent evidence. Treat
the command's unique ready artifact count as the evidence inventory and the
duplicate/extra duplicate artifact lane counts as a warning against treating
copied period lanes as fresh support.
When a lane is intended to add a new prediction target, validate with
`--require-unique-artifact` so duplicate period-style artifacts fail fast:

```bash
cargo run --locked -- validate-prediction-artifact \
  --preregistration experiments/preregistrations/<lane-id>.json \
  --require-unique-artifact
```

For future period-prediction evidence, first check which registered sources can
support scored observations, then use the guarded scaffold command to create a
lane-specific observation file:

```bash
cargo run --locked -- observation-sources
cargo run --locked -- init-source-review \
  --id <source-review-id> \
  --source-id <registered-public-facts-source-id> \
  --review-note "<what source pages were reviewed before choosing positions>" \
  --output <source-review.json>
cargo run --locked -- validate-source-review \
  --input <source-review.json>
cargo run --locked -- init-position-observations \
  --id <observation-id> \
  --source-id <registered-public-facts-source-id> \
  --source-review <source-review.json> \
  --positions <comma-separated-non-anchor-positions> \
  --rationale "<why these positions are independent observations>" \
  --position-note "<position>=<source-backed note for that position>" \
  --output <source-backed-observations.json>
```

Repeat `--source-id` for every reviewed eligible source and repeat
`--position-note` for every listed position. The source-review scaffold records
pre-score review only, and the source-review validator rechecks the reviewed
source metadata before any observation positions are scored. Passing
`--source-review` links that validated review into the observation file and
requires it to cover every cited source ID. The observation scaffold rejects
omitted notes instead of deriving them from the rationale, so every scored
position has its own source-backed audit text. Committed source-backed
observations must also be covered by local source archives that reference the
observation file or ID and include an explicit
`scored_positions_one_based: ...` marker for the scored positions;
`release-check` enforces that archive-coverage boundary.

The committed pre-score review artifact
`experiments/source-reviews/cia-source-review-v1.json` covers the eligible
`cia-artifact` and `cia-sculpture` source IDs and links quote-free local
snapshots under `sources/archives/`. It makes the source-review gate available
for a future observation file, but it is not itself an observation file and
contains no selected positions.

Validate the observation file first:

```bash
cargo run --locked -- validate-period-observations \
  --artifact experiments/predictions/non-anchor-position-period-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v1.json \
  --input <source-backed-observations.json>
```

Then score it:

```bash
cargo run --locked -- evaluate-period-prediction \
  --artifact experiments/predictions/non-anchor-position-period-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v1.json \
  --positions-file <source-backed-observations.json> \
  --output-dir results/period-observations/latest
cargo run --locked -- validate-evaluation-archive \
  --input results/period-observations/latest
```

For spacing lanes, use the same source-backed observation-file format, but score
against the committed spacing artifact. The `--output-dir` archive contains the
scored `artifact.json`, `preregistration.json`, `observations.json`,
linked `source-review.json` when present, `result.json`, `summary.md`, and
`command.txt`.

```bash
cargo run --locked -- validate-spacing-observations \
  --artifact experiments/predictions/non-anchor-position-spacing-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json \
  --input <source-backed-observations.json>
cargo run --locked -- evaluate-spacing-prediction \
  --artifact experiments/predictions/non-anchor-position-spacing-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json \
  --positions-file <source-backed-observations.json> \
  --output-dir results/spacing-observations/latest
cargo run --locked -- validate-evaluation-archive \
  --input results/spacing-observations/latest
```

Observation source IDs must be registered and must have an `allowed_use`
boundary compatible with scored independent position evidence. Sources marked
`public-anchor-summary`, `public-clue-context`, `methodology-context`, or
`archive-context-only` can be used for context or controls, but not as scored
observation evidence.

The template intentionally fails validation until every `replace-with...` field,
the explanatory rationale, the empty `positions_one_based` list, and the empty
`position_notes` map are replaced with a source-backed non-anchor target. Every
scored position must carry its own note.

Current independent lanes:

- `ciphertext-adjacent-contrast-prior-v1.json`, a populated ciphertext-only
  adjacent-contrast lane with committed artifact
  `experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json`. The
  artifact fixes the 20 interior non-anchor positions with strongest
  predeclared left/right neighbor contrast in Kryptos alphabet order; score it
  only through future source-backed non-anchor observations and
  `validate-ciphertext-adjacent-contrast-observations` then
  `evaluate-ciphertext-adjacent-contrast` with seeded controls.
- `ciphertext-structure-prior-v1.json`, a populated ciphertext-only position
  prior lane with committed artifact
  `experiments/predictions/ciphertext-structure-prior-v1.json`. The artifact
  fixes the weak period-2 repeated-ngram gap-factor and period-7 shifted
  ciphertext-coincidence residue targets from ciphertext-only diagnostics; score
  it only through source-backed non-anchor observations and
  `validate-ciphertext-prior-observations` then `evaluate-ciphertext-prior`
  with seeded controls.
- `ciphertext-hotspot-prior-v1.json`, a populated ciphertext-only hotspot lane
  with committed artifact
  `experiments/predictions/ciphertext-hotspot-prior-v1.json`. The artifact
  fixes top non-anchor positions from repeated n-gram coverage and shifted
  self-coincidence endpoints; score it only through future source-backed
  non-anchor observations and `validate-ciphertext-hotspot-observations` then
  `evaluate-ciphertext-hotspot` with seeded controls.
- `ciphertext-rarity-prior-v1.json`, a populated ciphertext-only rare-letter
  lane with committed artifact
  `experiments/predictions/ciphertext-rarity-prior-v1.json`. The artifact
  fixes the 20 non-anchor positions whose ciphertext letters are rarest in the
  non-anchor universe, with lower one-based positions as the tie-break; score it
  only through future source-backed non-anchor observations and
  `validate-ciphertext-rarity-observations` then `evaluate-ciphertext-rarity`
  with seeded controls.
- `ciphertext-repeat-distance-v1.json`, a populated ciphertext-only
  repeat-distance lane with committed artifact
  `experiments/predictions/ciphertext-repeat-distance-v1.json`. The artifact
  fixes the 20 non-anchor positions with strongest same-symbol repeat-distance
  structure in K4 ciphertext, using only ciphertext repetitions and public
  anchors as an exclusion mask; score it only through future source-backed
  non-anchor observations and `validate-ciphertext-repeat-distance-observations`
  then `evaluate-ciphertext-repeat-distance` with seeded controls.
- `ciphertext-period-match-v1.json`, a populated ciphertext-only shifted
  same-letter period-match lane with committed artifact
  `experiments/predictions/ciphertext-period-match-v1.json`. The artifact fixes
  endpoint sets from the top shifted same-letter period matches in K4
  ciphertext, using public anchors only as an exclusion mask; score it only
  through future source-backed non-anchor observations and
  `validate-ciphertext-period-match-observations` then
  `evaluate-ciphertext-period-match` with seeded controls.
- `ciphertext-transition-prior-v1.json`, a populated ciphertext-only
  adjacent-transition lane with committed artifact
  `experiments/predictions/ciphertext-transition-prior-v1.json`. The artifact
  fixes the 20 non-anchor positions with highest circular adjacent-letter
  transition pressure in Kryptos alphabet order; score it only through future
  source-backed non-anchor observations and
  `validate-ciphertext-transition-observations` then
  `evaluate-ciphertext-transition` with seeded controls.
- `ciphertext-skip-transition-v1.json`, a populated ciphertext-only
  skip-transition lane with committed artifact
  `experiments/predictions/ciphertext-skip-transition-v1.json`. The artifact
  fixes the 20 non-anchor positions with highest predeclared adjacent and
  distance-two ciphertext skip-transition pressure in Kryptos alphabet order;
  score it only through future source-backed non-anchor observations and
  `validate-ciphertext-skip-transition-observations` then
  `evaluate-ciphertext-skip-transition` with seeded controls.
- `ciphertext-turning-point-v1.json`, a populated ciphertext-only local
  turning-point lane with committed artifact
  `experiments/predictions/ciphertext-turning-point-v1.json`. The artifact
  fixes the 20 non-anchor positions with strongest predeclared local-extremum
  and high-curvature structure in Kryptos alphabet order; score it only through
  future source-backed non-anchor observations and
  `validate-ciphertext-turning-point-observations` then
  `evaluate-ciphertext-turning-point` with seeded controls.
- `ciphertext-window-balance-v1.json`, a populated ciphertext-only local-window
  balance lane with committed artifact
  `experiments/predictions/ciphertext-window-balance-v1.json`. The artifact
  fixes the 20 non-anchor positions with strongest predeclared centered-window
  balance across window widths `[3, 5, 7]`, using only K4 ciphertext and public
  anchors as an exclusion mask. Score it only through future source-backed
  non-anchor observations and `validate-ciphertext-window-balance-observations`
  then `evaluate-ciphertext-window-balance` with seeded controls.
- `ciphertext-window-balance-narrow-v1.json`, a populated ciphertext-only
  narrow local-window balance lane with committed artifact
  `experiments/predictions/ciphertext-window-balance-narrow-v1.json`. The
  artifact fixes the top 12 non-anchor positions with strongest predeclared
  centered-window balance across only window widths `[3, 5]`, using only K4
  ciphertext and public anchors as an exclusion mask. Score it only through
  future source-backed non-anchor observations and
  `validate-ciphertext-window-balance-observations` then
  `evaluate-ciphertext-window-balance` with seeded controls.
- `ciphertext-window-balance-mid-v1.json`, a populated ciphertext-only
  mid-window balance lane with committed artifact
  `experiments/predictions/ciphertext-window-balance-mid-v1.json`. The
  artifact fixes the top 16 non-anchor positions with strongest predeclared
  centered-window balance across only window widths `[5, 7, 9]`, using only K4
  ciphertext and public anchors as an exclusion mask. Score it only through
  future source-backed non-anchor observations and
  `validate-ciphertext-window-balance-observations` then
  `evaluate-ciphertext-window-balance` with seeded controls.
- `ciphertext-window-balance-wide-v1.json`, a populated ciphertext-only wide
  local-window balance lane with committed artifact
  `experiments/predictions/ciphertext-window-balance-wide-v1.json`. The
  artifact fixes the top 12 non-anchor positions with strongest predeclared
  centered-window balance across only window widths `[9, 11, 13]`, using only
  K4 ciphertext and public anchors as an exclusion mask. Its committed
  CIA row-boundary archive is negative/non-significant (`0/6`, empirical
  `p=1.0000`, promoted `false`).
- `non-anchor-position-period-v1.json` with committed artifact
  `experiments/predictions/non-anchor-position-period-v1.json`
- `non-anchor-position-period-followup-v1.json` for future source-backed
  non-anchor observations, with committed artifact
  `experiments/predictions/non-anchor-position-period-followup-v1.json`
- `non-anchor-position-period-diagnostic-v1.json`, a populated diagnostic lane
  derived from the template,
  with committed artifact
  `experiments/predictions/non-anchor-position-period-diagnostic-v1.json`
- `non-anchor-position-period-v2.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v2.json`
- `non-anchor-position-period-v3.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v3.json`
- `non-anchor-position-period-v4.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v4.json`
- `non-anchor-position-period-v5.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v5.json`
- `non-anchor-position-period-v6.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v6.json`
- `non-anchor-position-period-v7.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v7.json`
- `non-anchor-position-period-v8.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v8.json`
- `non-anchor-position-period-v9.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v9.json`
- `non-anchor-position-period-v10.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v10.json`
- `non-anchor-position-period-v11.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v11.json`
- `non-anchor-position-period-v12.json`, a copied template now populated as a
  stable period lane with committed artifact
  `experiments/predictions/non-anchor-position-period-v12.json`
- `non-anchor-position-period-v13.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v13.json`
- `non-anchor-position-period-v14.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v14.json`
- `non-anchor-position-period-v15.json`, a populated follow-up lane
  with committed artifact
  `experiments/predictions/non-anchor-position-period-v15.json`
- `non-anchor-position-period-v16.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v16.json`
- `non-anchor-position-period-v17.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v17.json`
- `non-anchor-position-period-v18.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v18.json`
- `non-anchor-position-period-v19.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v19.json`
- `non-anchor-position-period-v20.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v20.json`
- `non-anchor-position-period-v21.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v21.json`
- `non-anchor-position-period-v22.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v22.json`
- `non-anchor-position-period-v23.json`, a populated follow-up lane with
  committed artifact
  `experiments/predictions/non-anchor-position-period-v23.json`
- `non-anchor-position-period-v24.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v24` and committed artifact
  `experiments/predictions/non-anchor-position-period-v24.json`
- `non-anchor-position-period-v25.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v25` and committed artifact
  `experiments/predictions/non-anchor-position-period-v25.json`
- `non-anchor-position-period-v26.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v26` and committed artifact
  `experiments/predictions/non-anchor-position-period-v26.json`
- `non-anchor-position-period-v27.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v27` and committed artifact
  `experiments/predictions/non-anchor-position-period-v27.json`
- `non-anchor-position-period-v28.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v28` and committed artifact
  `experiments/predictions/non-anchor-position-period-v28.json`
- `non-anchor-position-period-v29.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v29` and committed artifact
  `experiments/predictions/non-anchor-position-period-v29.json`
- `non-anchor-position-period-v30.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v30` and committed artifact
  `experiments/predictions/non-anchor-position-period-v30.json`
- `non-anchor-position-period-v31.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v31` and committed artifact
  `experiments/predictions/non-anchor-position-period-v31.json`
- `non-anchor-position-period-v32.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v32` and committed artifact
  `experiments/predictions/non-anchor-position-period-v32.json`
- `non-anchor-position-period-v33.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v33` and committed artifact
  `experiments/predictions/non-anchor-position-period-v33.json`
- `non-anchor-position-period-v34.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v34` and committed artifact
  `experiments/predictions/non-anchor-position-period-v34.json`
- `non-anchor-position-period-v35.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v35` and committed artifact
  `experiments/predictions/non-anchor-position-period-v35.json`
- `non-anchor-position-period-v36.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v36` and committed artifact
  `experiments/predictions/non-anchor-position-period-v36.json`
- `non-anchor-position-period-v37.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v37` and committed artifact
  `experiments/predictions/non-anchor-position-period-v37.json`
- `non-anchor-position-period-v38.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v38` and committed artifact
  `experiments/predictions/non-anchor-position-period-v38.json`
- `non-anchor-position-period-v39.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v39` and committed artifact
  `experiments/predictions/non-anchor-position-period-v39.json`
- `non-anchor-position-period-v40.json`, a populated period-3-only follow-up
  lane with stable id `non-anchor-position-period-v40` and committed artifact
  `experiments/predictions/non-anchor-position-period-v40.json`. Unlike the
  duplicated all-period readiness lanes, this artifact commits a single
  deterministic period-3 plan and validates with
  `validate-prediction-artifact --require-unique-artifact`; it is still only a
  pre-score prediction target until future source-backed non-anchor observations
  are evaluated.
- `non-anchor-position-period-v41.json`, a populated follow-up lane with
  stable id `non-anchor-position-period-v41` and committed artifact
  `experiments/predictions/non-anchor-position-period-v41.json`. It validates
  without `--require-unique-artifact`, but the unique-artifact gate rejects it
  because it duplicates existing all-period period-family artifacts; treat it
  as workflow inventory only, not a fresh prediction target.
- `non-anchor-position-period-v42.json`, a populated period-5-only follow-up
  lane with stable id `non-anchor-position-period-v42` and committed artifact
  `experiments/predictions/non-anchor-position-period-v42.json`. This artifact
  commits a single deterministic period-5 plan and validates with
  `validate-prediction-artifact --require-unique-artifact`; it is still only a
  pre-score prediction target until future source-backed non-anchor
  observations are evaluated.
- `non-anchor-position-period-v43.json`, a populated period-14-only follow-up
  lane with stable id `non-anchor-position-period-v43`, source id
  `kryptosbot-sanborn-papers-2026`, and committed artifact
  `experiments/predictions/non-anchor-position-period-v43.json`. This artifact
  commits a single deterministic period-14 plan and validates with
  `validate-prediction-artifact --require-unique-artifact`; the source is
  context-only and fixes the 7-by-14-compatible period choice rather than
  supplying scored positions or candidate evidence.
- `non-anchor-position-period-v44.json`, a populated period-7-only follow-up
  lane with stable id `non-anchor-position-period-v44` and committed artifact
  `experiments/predictions/non-anchor-position-period-v44.json`. This artifact
  commits a single deterministic period-7 plan, validates with
  `validate-prediction-artifact --require-unique-artifact`, and is a pure
  independent prediction target with no attached source IDs.
- `non-anchor-position-period-v45.json`, a populated all-period follow-up lane
  with stable id `non-anchor-position-period-v45`, concrete non-anchor
  rationale, predeclared discovery/evaluation inputs, explicit controls, and
  committed artifact
  `experiments/predictions/non-anchor-position-period-v45.json`. It validates,
  but duplicates existing all-period artifacts, so treat it as readiness
  inventory only rather than new independent evidence.
- `non-anchor-position-spacing-v1.json`, a populated position-only spacing lane
  with committed artifact
  `experiments/predictions/non-anchor-position-spacing-v1.json`
- `non-anchor-position-mirror-v1.json`, a populated position-only mirror lane
  with committed artifact
  `experiments/predictions/non-anchor-position-mirror-v1.json`
- `non-anchor-position-grid-layout-v1.json`, a populated 7-by-14 row-edge
  layout lane with `grid_edge_axis: row` in the committed artifact
  `experiments/predictions/non-anchor-position-grid-layout-v1.json`
- `non-anchor-position-grid-column-v1.json`, a populated 7-by-14 column-edge
  layout lane with `grid_edge_axis: column` in the committed artifact
  `experiments/predictions/non-anchor-position-grid-column-v1.json`
- `non-anchor-position-grid-compass-axis-v1.json`, a populated 7-by-14
  compass-axis layout lane with `grid_edge_axis: compass-axis` in the committed
  artifact
  `experiments/predictions/non-anchor-position-grid-compass-axis-v1.json`
- `tableau-hill-v1.json`, a tooling-ready Tableau/HILL source-mapping
  lane grounded in `rumkin-k4-reference`, `cia-sculpture`, and
  `kryptosbot-sanborn-papers-2026`, with committed artifact
  `experiments/predictions/tableau-hill-v1.json`. The artifact fixes a
  7-by-14 row-major coordinate map and one padding cell; score it only through
  `validate-tableau-hill-observations` and `evaluate-tableau-hill-prediction`
  with source-backed non-anchor observations and seeded controls.
- `ciphertext-residue-balance-prior-v1.json`, a ciphertext-only residue
  balance prior with committed artifact
  `experiments/predictions/ciphertext-residue-balance-prior-v1.json`. The
  artifact predeclares one selected non-anchor residue set for each modulus
  2 through 13, using only ciphertext positions and known anchor positions as
  an exclusion mask. It is readiness inventory for future source-backed
  observations, not evidence by itself.
- `ciphertext-residue-balance-high-moduli-v1.json`, a distinct ciphertext-only
  high-moduli residue balance prior with committed artifact
  `experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  7 through 13. The artifact passes `--require-unique-artifact`; it is a
  pre-score prediction target for future source-backed observations, not
  evidence by itself.
- `ciphertext-residue-balance-very-high-moduli-v1.json`, a distinct
  ciphertext-only very-high-moduli residue balance prior with committed
  artifact
  `experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  14 through 20. The artifact passes `--require-unique-artifact`; its committed
  CIA row-boundary archive is negative/non-significant (`2/6`, empirical
  `p=0.3125`, promoted `false`).
- `ciphertext-residue-balance-ultra-high-moduli-v1.json`, a distinct
  ciphertext-only ultra-high-moduli residue balance prior with committed
  artifact
  `experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  21 through 26. The artifact passes `--require-unique-artifact`; it is a
  pre-score prediction target for future source-backed observations, not
  evidence by itself.
- `ciphertext-residue-balance-extreme-moduli-v1.json`, a distinct
  ciphertext-only extreme-moduli residue balance prior with committed artifact
  `experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  27 through 33. The artifact passes `--require-unique-artifact`; it is a
  pre-score prediction target for future source-backed observations, not
  evidence by itself.
- `ciphertext-residue-balance-super-extreme-moduli-v1.json`, a distinct
  ciphertext-only super-extreme-moduli residue balance prior with committed
  artifact
  `experiments/predictions/ciphertext-residue-balance-super-extreme-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  34 through 40. The artifact passes `--require-unique-artifact`; its committed
  CIA row-boundary archive is negative/non-significant (`1/6`, empirical
  `p=0.6741`, promoted `false`).
- `ciphertext-residue-balance-hyper-extreme-moduli-v1.json`, a distinct
  ciphertext-only hyper-extreme-moduli residue balance prior with committed
  artifact
  `experiments/predictions/ciphertext-residue-balance-hyper-extreme-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  41 through 47. The artifact passes `--require-unique-artifact`; it is a
  pre-score prediction target for future source-backed observations, not
  evidence by itself.
- `ciphertext-residue-balance-terminal-moduli-v1.json`, a distinct
  ciphertext-only terminal-moduli residue balance prior with committed artifact
  `experiments/predictions/ciphertext-residue-balance-terminal-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  48 through 54. The artifact passes `--require-unique-artifact`; it is a
  pre-score prediction target for future source-backed observations, not
  evidence by itself.
- `ciphertext-residue-balance-post-terminal-moduli-v1.json`, a distinct
  ciphertext-only post-terminal-moduli residue balance prior with committed
  artifact
  `experiments/predictions/ciphertext-residue-balance-post-terminal-moduli-v1.json`.
  The artifact predeclares one selected non-anchor residue set for each modulus
  55 through 61. The artifact passes `--require-unique-artifact`; it is a
  pre-score prediction target for future source-backed observations, not
  evidence by itself.
- `ciphertext-stehle-regularity-v1.json`, a source-grounded Stehle
  local-regularity planning lane with committed artifact
  `experiments/predictions/ciphertext-stehle-regularity-v1.json`. The artifact
  records the source-reported 55 through 63 anomaly window and the repo
  canonical 56 through 64 coordinate mapping for the displayed `DIAWINFBN`
  sequence. It is ready for future source-backed non-anchor observations through
  `validate-ciphertext-stehle-regularity-observations` and
  `evaluate-ciphertext-stehle-regularity`, which score the full Stehle window
  and lag-confirmed +5 subset with seeded same-size non-anchor position nulls.
- `ciphertext-ct-perturbation-v1.json`, a source-grounded CT-perturbation
  planning lane with committed artifact
  `experiments/predictions/ciphertext-ct-perturbation-v1.json`. The artifact
  fixes six non-anchor C/T ciphertext positions from the registered
  KryptosBot findings context. It is ready for future source-backed non-anchor
  observations through
  `validate-ciphertext-ct-perturbation-observations` and
  `evaluate-ciphertext-ct-perturbation`, which score C/T-position enrichment
  with seeded same-size non-anchor position nulls.

The mirror and grid-layout lanes are now source-observation ready: validate
their artifacts with `validate-prediction-artifact`, then use the matching
`validate-*-observations`, `evaluate-*-prediction`, and
`validate-evaluation-archive` commands for any source-backed observation file.

Required JSON fields:

- `id`
- `title`
- `hypothesis_family`
- `evidence_kind`: `source-documented-evidence` or
  `independent-prediction-target`
- `source_ids`
- `rationale`
- `prediction_target`
- `prediction_artifact` optional path to a committed prediction target artifact
- `grid_edge_axis` required for `position-grid-layout-prediction` lanes and
  limited to the axis that source-backed grid scoring may use: `row`,
  `column`, or `compass-axis`
- `discovery_inputs`
- `evaluation_inputs`
- `controls`
- `uses_public_anchor_fragments_for_discovery`
- `uses_public_anchor_fragments_as_primary_evidence`
