# KryptosBot W-Delimiter Coordinate Reconciliation

This is not a claimed solution.

source_id: `kryptosbot-findings-2026`
source_archive: `sources/archives/kryptosbot-findings-2026-05-31.md`
reviewed_at: 2026-06-01
promoted_candidate: false

## Purpose

The registered KryptosBot findings source is methodology context only, but its
W-delimiter discussion is a tempting future lane. Before any future W-delimiter
work is scored, the source-side coordinate labels must be reconciled with the
repo's canonical one-based K4 ciphertext indexing.

## Reconciliation

Repo canonical K4 ciphertext begins:

```text
OBKRUOXOGHULBSOLIFBBW...
```

Under repo one-based indexing, the carved `W` positions in K4 are:

```text
21,37,49,59,75
```

The external source-side W-delimiter labels observed in the 2026-06-01 review
use a one-position lower convention for the same structural surface:

```text
20,36,48,58,74
```

Therefore, future repo-local W-delimiter artifacts must use
`21,37,49,59,75` unless they explicitly define and validate an alternate
coordinate convention before scoring.

## Boundary

- This file is a coordinate reconciliation, not a scoring artifact.
- It does not promote W-delimiter, a plaintext, a route, a key, or a mechanism.
- The current W-delimiter source-context diagnostic remains stopped because the
  only committed source-backed position observation gives `1/6` hits against
  these positions with non-significant same-size non-anchor controls.
- Any future W-delimiter scoring still requires a distinct preregistration,
  a validated prediction artifact, and independent source-backed observations.
