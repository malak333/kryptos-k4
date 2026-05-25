# Stopped K4 Experiment Lanes

This file records research lanes that should not be expanded without genuinely
new source-grounded evidence or an independent pre-registered prediction target.
It is not a solution claim.

## Public Anchor-Derived Key-Material Lanes

Status: stopped.

Reason: repeated `batch-test-keys`, `batch-test-routed-keys`, and
`heldout-key-control` runs over the public known-plaintext fragments did not
produce a promoted candidate. The held-out controls selected apparent training
leads but scored zero held-out matches across the public groups.

Latest evidence is summarized in `experiments/PROGRESS_LOG.md`.

Do not restart this lane by adding more candidate words unless a preregistration
passes `validate-preregistration`.

## Source-Expanded Sculpture/Chart/Matrix Lane

Status: stopped.

Reason: source-documented additions such as `KRYPTOS`, `VIGENERE`,
`VIGENERETABLE`, `MATRIX`, `MATRIXCODING`, `NINETYSEVEN`, and `97` did not
survive batch-level or held-out controls.

Latest evidence is summarized in `experiments/PROGRESS_LOG.md`.

Do not expand this lane by adding more source-adjacent strings unless the new
rows are tied to a different evidence target, not only the same public
anchor-derived fragment scores.

## Candidate-Independent Position Structure Lanes

Status: stopped for current registered models.

Reason: `position-structure` and `structural-models` did not show meaningful
candidate-independent structure on public spans after seeded null controls and
multiple-comparison correction.

Latest evidence is summarized in `experiments/PROGRESS_LOG.md`.

Future structural work must define the model before looking at the public
fragment-derived scores and must pass preregistration.

## Simple Single-Layer And Uncorrected Search Lanes

Status: stopped unless a preregistration narrows the search before scoring.

Reason: the public methodology context now registered as
`kryptosbot-methodology-2026` reinforces the existing local result: repeated
single-layer, word-list, route, or uncorrected best-of-search runs are more
likely to mine the search surface than produce independent evidence.

Future work in this area must specify the cipher family, transform set,
candidate source, scoring target, and multiple-comparison control before any
new score is interpreted.

## Required Gate For New Lanes

Before adding new candidates, transforms, routes, or structural tests, create a
JSON preregistration and run:

```bash
cargo run --locked -- validate-preregistration --input <path>
```

A valid preregistration must use either genuinely new source-documented evidence
or an independent prediction target. Public anchor-derived fragments may be used
as controls, but not as discovery inputs or primary evidence.
