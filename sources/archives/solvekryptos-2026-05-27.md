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
  ciphertext alignment, optional published `R`/shift, `BaseR`, and `Gate`
  arithmetic, public-anchor compatibility, and aggregate shift diagnostics
  without printing or storing any claimed plaintext column.

## Boundary

- This source is registered as `unverified-solution-claim`; it is not eligible
  for scored independent position observations.
- No claimed full plaintext is stored in this repository snapshot.
- No candidate material, key stream, route, or plaintext is promoted.
- The structural quarantine check is not independent confirmation; it only
  confirms length and public-anchor compatibility for a public claim.
- A reconciliation-table compatibility check, including published shift and gate
  arithmetic, is still a quarantine check, not independent confirmation of the
  claimed physical mechanism.
- Any future use must implement an independent mechanical verifier that checks
  the claimed mechanism without adding release-facing full plaintext or
  accepting the claim as evidence by assertion.
