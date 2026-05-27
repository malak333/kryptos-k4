# Preregistrations

Use this directory for proposed K4 research lanes before adding candidate rows,
transforms, routes, or structural tests.

Start by copying the template to a lane-specific file and replacing every
placeholder:

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
an existing family adds workflow traceability, not independent evidence.

For future period-prediction evidence, first check which registered sources can
support scored observations, then use the guarded scaffold command to create a
lane-specific observation file:

```bash
cargo run --locked -- observation-sources
cargo run --locked -- init-position-observations \
  --id <observation-id> \
  --source-id <registered-public-facts-source-id> \
  --positions <comma-separated-non-anchor-positions> \
  --rationale "<why these positions are independent observations>" \
  --position-note "<position>=<source-backed note for that position>" \
  --output <source-backed-observations.json>
```

Repeat `--position-note` for every listed position. The scaffold rejects omitted
notes instead of deriving them from the rationale, so every scored position has
its own source-backed audit text.

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
`result.json`, `summary.md`, and `command.txt`.

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

Current independent period lanes:

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
- `non-anchor-position-spacing-v1.json`, a populated position-only spacing lane
  with committed artifact
  `experiments/predictions/non-anchor-position-spacing-v1.json`

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
- `discovery_inputs`
- `evaluation_inputs`
- `controls`
- `uses_public_anchor_fragments_for_discovery`
- `uses_public_anchor_fragments_as_primary_evidence`
