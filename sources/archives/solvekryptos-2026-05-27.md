# SolveKryptos 2026 Claim Source Snapshot

source_id: `solvekryptos-2026-claim`
source_url: https://solvekryptos.com/
reviewed_at: 2026-05-27
archive_kind: quote-free local review snapshot
non_scorable_reason: Quarantined solution claims are not source-backed observation evidence and must only be screened by temporary local verifiers.
promoted_candidate: false

This local snapshot records metadata and high-level claim boundaries only. It is
not a mirror of the site, not an endorsement, and not a plaintext-bearing
artifact.

## Reviewed Facts

- The site publicly claims a complete 97-position K4 plaintext and a closed
  mechanism that preserves the four artist-confirmed anchors.
- The site publishes verification-oriented pages, downloadable support
  material, and a per-position reconciliation table for public review.
- The source is a community solution claim, not a primary source confirmation
  from Jim Sanborn, the CIA, or another authoritative validating body.
- The claim should be treated as an input to a future independent verifier, not
  as source-backed observation evidence or candidate material.

## Local Quarantine Check

- On 2026-05-27, the public claim text was copied only into a temporary
  `/private/tmp` file and screened with `verify-plaintext-claim`.
- The temporary claim normalized to 97 letters, matched the expected K4 length,
  and preserved all four registered public anchors at their documented
  positions.
- Aggregate shift diagnostics reported all 26 implied shift values, 71 repeated
  shift values, and a maximum shift bucket count of 8.
- The temporary claim file was deleted after verification. The repository still
  does not store the claimed plaintext.
- Follow-up tooling now includes `verify-claim-reconciliation` for local
  reconciliation tables. It checks row count, one-based position sequence, K4
  ciphertext alignment, optional published `Tier`/`Lane`, `C#`/`P#`,
  `R`/shift, `BaseR`, and `Gate` arithmetic, public-anchor compatibility, and
  aggregate shift diagnostics without printing or storing any claimed plaintext
  column.
- On 2026-05-31, the public canonical bundle was downloaded only into
  `/private/tmp` and screened with `verify-claim-reconciliation` against
  `k4_reconciliation.csv`.
- The temporary reconciliation table had 97 rows, matched all 97 K4 ciphertext
  positions, matched all checked tier/lane values, matched all checked `R`
  values, had binary gate values at all rows, matched all checked `r + gate`
  values, matched all checked Z2 handoff values, and preserved all four
  registered public anchors.
- Follow-up tooling now includes `verify-claim-bundle` for local canonical
  bundle directories. It checks the required local files, repo ciphertext,
  plaintext length only, reconciliation arithmetic, published `R`/`r` grids,
  gate map, Z2 handoff values, and public anchors without printing or storing
  claimed plaintext.
- On 2026-05-31, the same temporary canonical bundle passed
  `verify-claim-bundle`: 5/5 required files present, repo ciphertext matched,
  plaintext length matched, reconciliation structural checks passed, 97/97
  `R` grid values matched, 97/97 base-`r` grid values matched, 97/97 gate-map
  values matched, 31/31 Z2 handoff values matched, and 4/4 public anchors
  matched.
- Follow-up tooling now includes `verify-claim-mechanism` for local canonical
  mechanism files. It checks published `f`/helper-card relationships,
  control-card consistency, Z2 footer handoff, Y-pass gate-template
  consistency, and the Z2 helper path into the `r`/`R` grids without printing
  or storing claimed plaintext.
- On 2026-05-31, the same temporary canonical bundle passed
  `verify-claim-mechanism`: 8/8 required files present, 26/26 `f` table
  values matched, 26/26 helper-card delta checks matched, 9/9 control-card
  entries matched, Z2 effective key derivation matched, 31/31 Z2 helper-path
  base-`r` grid checks matched, and 31/31 Z2 helper-path final `R` grid
  checks matched, plus 31/31 Y-pass template rule checks and 31/31 Y-pass
  gate-map checks matched.
- The temporary bundle remains outside the repository. The repository still
  does not store the claimed plaintext or any plaintext-bearing reconciliation
  table.

## Boundary

- This source is registered as `unverified-solution-claim`; it is not eligible
  for scored independent position observations.
- No claimed full plaintext is stored in this repository snapshot.
- No candidate material, key stream, route, or plaintext is promoted.
- The structural quarantine check is not independent confirmation; it only
  confirms length and public-anchor compatibility for a public claim.
- A reconciliation-table compatibility check, including published coordinate,
  numeric-letter, shift, and gate arithmetic, is still a quarantine check, not
  independent confirmation of the claimed physical mechanism.
- The 2026-05-31 canonical-bundle reconciliation check confirms internal table
  compatibility only; it does not independently derive the table, validate
  source provenance for the physical helper stream, or promote the claim.
- The 2026-05-31 canonical-bundle file cross-check confirms local file
  consistency only; it still does not independently derive the table, validate
  source provenance for the physical helper stream, or promote the claim.
- The 2026-05-31 mechanism-file cross-check confirms consistency of published
  helper machinery only; it still does not verify an on-site physical reading
  of the helper stream, validate source provenance for that stream, or promote
  the claim.
- Any future use must implement an independent mechanical verifier that checks
  the claimed mechanism without adding release-facing full plaintext or
  accepting the claim as evidence by assertion.
