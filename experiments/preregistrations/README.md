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
