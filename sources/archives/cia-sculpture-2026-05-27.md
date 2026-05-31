# CIA Kryptos Sculpture Source Snapshot

source_id: `cia-sculpture`
source_url: https://www.cia.gov/legacy/headquarters/kryptos-sculpture/
reviewed_at: 2026-05-27
archive_kind: quote-free local review snapshot
promoted_candidate: false

This local snapshot records what was reviewed before selecting any scored
non-anchor positions. It intentionally stores source metadata and paraphrased
facts only; it is not a raw page mirror, a plaintext claim, or a scored
observation file.

## Reviewed Facts

- The CIA sculpture page locates Kryptos at the New Headquarters Building and
  adjacent courtyard and gives its dedication date as 1990-11-03.
- The page describes Kryptos as an intelligence-gathering themed sculpture with
  encoded messages written in different codes.
- The page describes the courtyard copper screen and a companion alphabet chart
  related to Vigenere's table, with the chart readable from the back side.
- The page says the first three encoded texts used the chart system in
  combination with matrix coding systems.
- The page states that K4, the fourth section, was designed to be difficult and
  remains unbroken.
- The page frames the remaining message as 97 characters.
- In the page's encoded-text rendering, the K4 ciphertext appears as a short
  suffix on one encoded-text line followed by three subsequent rendered lines;
  this gives pre-score row-boundary positions 1, 4, 5, 36, 37, 68, 69, and 97.
  Public-anchor positions are excluded before scoring, leaving positions 1, 4,
  5, 36, 37, and 97 for source-backed observation tests.

## Boundary

- Source-backed non-anchor row-boundary positions selected from this snapshot
  are recorded only in
  `experiments/position-observations/cia-k4-row-boundaries-v1.json` and
  summarized in
  `experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`.
- scored_observation: `experiments/position-observations/cia-k4-row-boundaries-v1.json`
- scored_positions_one_based: 1,4,5,36,37,97
- No candidate material, key stream, route, or plaintext is promoted.
- Any future observation file must cite this source ID, include one note per
  scored position, pass the family validator, and archive the evaluation output.
