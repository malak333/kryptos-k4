# SolveKryptos Mechanism Quarantine Check

This is not a claimed solution.

source: `solvekryptos-2026-claim`
command:

```bash
cargo run --locked -- verify-claim-mechanism \
  --directory /private/tmp/k4-latest-solvekryptos/solvekryptos-canonical-bundle \
  --source-id solvekryptos-2026-claim \
  --format json
```

result file: `results/claim-verifications/solvekryptos-mechanism-20260531-latest/result.json`

## Result

- required mechanism files: `8/8`
- f-table checks: `26/26`
- helper-card checks: `26/26`
- Z1/Z2 delta checks: `26/26`
- control-card checks: `9/9`
- Z2 effective key: matched
- Z2 helper-path base-r grid checks: `31/31`
- Z2 helper-path final-R grid checks: `31/31`
- Y-template rule checks: `27/31`
- Y-template gate-map checks: `27/31`
- structural checks passed: `false`
- promoted: `false`

## Mismatch Boundary

The non-leaking mismatch diagnostic localizes four Y-pass gate disagreements:

| Y Position | K4 Position | Expected Gate | Observed Gate |
| --- | --- | --- | --- |
| 23 | 27 | 1 | 0 |
| 27 | 31 | 0 | 1 |
| 28 | 32 | 1 | 0 |
| 29 | 33 | 1 | 0 |

The template's declared zero-position list also disagrees with the zero
positions implied by its printed rule and Y row:

- declared-only zero positions: `23,28,29`
- rule-only zero positions: `27`

## Boundary

- No claimed plaintext, key stream, or plaintext-bearing reconciliation table is
  stored in this archive.
- This is a quarantine verifier result only; it does not validate an on-site
  physical helper stream, promote the claim, or provide independent K4 evidence.
