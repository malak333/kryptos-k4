# Preregistrations

Use this directory for proposed K4 research lanes before adding candidate rows,
transforms, routes, or structural tests.

Validate a proposal with:

```bash
cargo run --locked -- validate-preregistration \
  --input experiments/preregistrations/independent-lane-template.json
```

The validator rejects lanes that reuse public anchor-derived fragments as
discovery inputs or primary evidence. Those fragments can still be listed as
controls after an independent target is defined.

Required JSON fields:

- `id`
- `title`
- `hypothesis_family`
- `evidence_kind`: `source-documented-evidence` or
  `independent-prediction-target`
- `source_ids`
- `rationale`
- `prediction_target`
- `discovery_inputs`
- `evaluation_inputs`
- `controls`
- `uses_public_anchor_fragments_for_discovery`
- `uses_public_anchor_fragments_as_primary_evidence`
