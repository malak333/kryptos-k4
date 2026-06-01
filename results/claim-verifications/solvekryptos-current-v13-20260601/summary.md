# SolveKryptos Current v13 Mechanism Quarantine Check

This is not a claimed solution.

source: `solvekryptos-2026-claim`
downloaded_at: 2026-06-01
public resource page: https://solvekryptos.com/resources.html
bundle URL: https://solvekryptos.com/downloads/solvekryptos-canonical-bundle.zip
result file: `results/claim-verifications/solvekryptos-current-v13-20260601/result.json`

The current public resources page labels the downloadable canonical bundle as
v13. The ZIP was downloaded only to `/private/tmp` and checked with the local
quarantine verifier:

```bash
cargo run --locked -- verify-claim-mechanism \
  --directory /private/tmp/solvekryptos-current-bundle/solvekryptos-canonical-bundle \
  --source-id solvekryptos-2026-claim \
  --format json
```

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

The template's declared zero-position list still disagrees with the zero
positions implied by its printed rule and Y row:

- declared-only zero positions: `23,28,29`
- rule-only zero positions: `27`

## Boundary

- No claimed plaintext, key stream, or plaintext-bearing reconciliation table is
  stored in this archive.
- The bundle-level reconciliation/file check passed during the same temporary
  review, but this archive records the stricter mechanism check because it
  still fails.
- This is a quarantine verifier result only; it does not validate an on-site
  physical helper stream, promote the claim, or provide independent K4 evidence.
