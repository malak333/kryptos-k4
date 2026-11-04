# Negative Results

This page records what the independent-lane phase (2026-05-21 through
2026-06-01) tested and found. It is not a solution claim. Full history,
including every pruned lane, its evaluation archive, and the long-form
`PROGRESS_LOG.md`, is preserved at git tag `pre-slimdown`.

## Summary

Every source-backed evaluation in this phase scored the same single
observation file, `experiments/position-observations/cia-k4-row-boundaries-v1.json`:
six non-anchor positions (`1, 4, 5, 36, 37, 97`, one-based) taken from where
the CIA sculpture web page's text rendering wraps K4 onto new lines.

All results were negative or non-significant. No model, lane, or archive
promoted a candidate.

Interpretation: the row-boundary observation is a web-page layout artifact,
not a physical or cryptographic property of K4, and six positions give almost
no statistical power. These nulls say little about K4 itself. They mainly
show that this observation should not be scored again.

## Surviving evaluation archives

Archives live under `results/<family>/cia-k4-row-boundaries-*/` (each has
`summary.md`, `result.json`, and the exact command). Empirical p-values come
from seeded non-anchor position-shuffle nulls (seed 67, 100,000 iterations
unless the archive says otherwise).

| Lane family | Archive | Best observed | p |
| --- | --- | --- | --- |
| Period (all periods) | `period-observations/…-v1` | period 2, 4/6 | 0.7897 |
| Period 3 | `period-observations/…-period3-v40` | 4/6 | 0.2755 |
| Period 5 | `period-observations/…-period5-v42` | 2/6 | 1.0000 |
| Period 7 | `period-observations/…-period7-v44` | 2/6 | 0.9476 |
| Period 14 | `period-observations/…-period14-v43` | 1/6 | 1.0000 |
| Spacing | `spacing-observations/…-v1` | mod 2, 8/15 pairs | 1.0000 |
| Mirror | `mirror-observations/…-v1` | — | 0.2090 |
| Grid 7×14 row edge | `grid-observations/…-v1` | — | 0.5600 |
| Grid column edge | `grid-observations/…-column-v1` | — | 0.1303 |
| Grid compass axis | `grid-observations/…-compass-axis-v1` | — | 0.9166 |
| Grid width-7 row | `grid-observations/…-width7-row-v1` | — | 0.5590 |
| Grid 4×25 row | `grid-observations/…-4x25-row-v1` | — | 0.3558 |
| Tableau/HILL | `tableau-hill-observations/…-v1` | row 1, 3/6 | 0.3311 |
| Ciphertext structure prior | `ciphertext-prior-observations/…-v1` | period 2, 4/6 | 0.6845 |
| Ciphertext hotspot | `ciphertext-hotspot-observations/…-v1` | 0/6 | 1.0000 |
| Ciphertext rarity | `ciphertext-rarity-observations/…-v1` | — | 0.5282 |
| Ciphertext transition | `ciphertext-transition-observations/…-v1` | — | 1.0000 |
| Ciphertext skip-transition | `ciphertext-skip-transition-observations/…-v1` | — | 1.0000 |
| Ciphertext turning point | `ciphertext-turning-point-observations/…-v1` | 2/6 | 0.5247 |
| Ciphertext residue balance | `ciphertext-residue-balance-observations/…-v1` | — | 0.4803 |
| Ciphertext window balance | `ciphertext-window-balance-observations/…-v1` | — | 1.0000 |
| Ciphertext period match | `ciphertext-period-match-observations/…-v1` | — | 0.9733 |
| Ciphertext adjacent contrast | `ciphertext-adjacent-contrast-observations/…-v1` | — | 0.5259 |
| Ciphertext repeat distance | `ciphertext-repeat-distance-observations/…-v1` | — | 0.5273 |
| Ciphertext CT perturbation | `ciphertext-ct-perturbation-observations/…-v1` | — | 0.4139 |
| Ciphertext Stehle regularity | `ciphertext-stehle-regularity-observations/…-v1` | — | 1.0000 |

Related pre-implementation diagnostic (not archived): W-delimiter positions
`21,37,49,59,75` gave 1/6 row-boundary hits, hypergeometric `p=0.3570`.

## Pruned lanes

Removed in the slim-down (recoverable from `pre-slimdown`):

- **42 duplicate period lanes**: `non-anchor-position-period-v2` through
  `v39`, `v41`, `v45`, `-diagnostic-v1`, and `-followup-v1`. Their prediction
  content was identical to `-v1`; only prose differed. They added no
  independent evidence.
- **18 escalating parameter variants** of lanes kept above: residue balance
  (high, very-high, ultra-high, extreme, super-extreme, hyper-extreme,
  terminal, post-terminal moduli), window balance (narrow, mid, wide,
  ultra-wide, mega-wide), period match (narrow, wide, extended), and adjacent
  contrast (narrow, mid).

The lowest raw p-value anywhere in the phase came from one of these
variants (terminal residue balance, `p=0.0436`). After correcting for the
number of archives searched it was `p=1.0000`. That is the expected result of
sweeping parameters over one small observation.

## Lessons

1. One six-position observation cannot support dozens of models. Adding
   lanes against it is multiple comparisons, not new evidence.
2. Periodic additive keys are already ruled out by the public anchors:
   Vigenère, Beaufort, and variant Beaufort, in both the standard and the
   Kryptos alphabet, are inconsistent at every period from 1 to 26. Keyword
   candidates scored by cyclic offset can never succeed.
3. The public anchors (24 known plaintext letters) are a far stronger test
   than any position-shuffle null. A correct method reproduces all 24 letters,
   which happens by chance with probability about 26^-24. Future work should
   score methods by anchor reproduction and treat misses as eliminations.
