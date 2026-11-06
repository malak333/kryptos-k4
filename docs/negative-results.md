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
`summary.md`, `result.json`, and the exact command). The scoring commands in
`command.txt` were removed from the CLI in the slim-down; to re-run one, check
out git tag `pre-slimdown` first. Empirical p-values come
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

## Other stopped lanes

These lanes ran before or alongside the row-boundary work. Each is stopped:
rerunning it on the same inputs is not new evidence.

- **Public anchor-derived key material.** `batch-test-keys`,
  `batch-test-routed-keys`, and the former held-out control found no candidate.
  Held-out controls picked apparent training leads that scored zero matches on
  the withheld anchor groups. Source-adjacent words (`KRYPTOS`, `VIGENERE`,
  `MATRIX`, `NINETYSEVEN`, `97`, and similar) did not survive batch-level
  controls either. Lesson 2 below explains why cyclic short-word keys cannot
  work.
- **Gromark-style recurrence screen.** `baseline --target spans --alphabet all
  --iterations 100000 --seed 67`: strongest row `EASTNORTHEAST`, Kryptos
  alphabet, 2/11 contiguous triples, raw `p=0.3138`, adjusted `p=1.0000`. A
  proper Gromark test needs the anchor-reproduction approach, not this screen.
- **Candidate-independent position structure.** The former
  `position-structure` and `structural-models` commands found nothing after
  correction; the `period-14-grid-padding` model scored 0 with `p=1.0000`.
- **W-delimiter positions.** Non-anchor `W` positions `21,37,49,59,75`
  (one-based, repo convention) gave 1/6 row-boundary hits, hypergeometric
  `p=0.3570`. External sources may label the same letters `20,36,48,58,74`;
  convert coordinates explicitly before comparing.
- **Stehle regularity, HILL tableau, CT perturbation.** Each was fixed as a
  prediction artifact from community methodology context and scored only
  against the row-boundary observation (table above). None is plaintext, key,
  or route evidence.
- **CIA artifact page.** Reviewed and archived, but it has no per-position
  rationale, so it is not scoreable.

## External claim screening

Claims of a full K4 solution are registered as quarantined
`unverified-solution-claim` sources. They are checked only with
`verify-claim` against temporary local files, and no claimed plaintext or key
stream is committed. Non-leaking results live under
`results/claim-verifications/`.

- **SolveKryptos (2026).** The claim text keeps 97 letters and all four public
  anchors. Before the slim-down, dedicated verifiers (at tag `pre-slimdown`)
  checked its published bundle: the reconciliation table and grids were
  internally consistent, but the Y-pass template matched only 27/31 rule
  checks, failing at K4 positions 27, 31, 32, and 33. The template's declared
  zero positions also disagree with its printed rule.
- **DearCipher (2026) and PRLog/Bishop (2020).** Each claim text keeps 97
  letters and all four public anchors. Neither publishes a mechanism that can
  be checked, so this says only that the authors kept the public anchors.
- **SSRN Bonifacino claims (four papers).** Not screened. The public records
  expose only abstracts, not the plaintext and key stream a check needs.

Anchor compatibility is a minimum check. It cannot promote a claim.

## Anchor elimination

`kryptos-k4 eliminate` tests concrete cipher families by whether they
reproduce all 24 anchor letters. Each configuration has a list of checks; one
failure eliminates it. The run is archived in
`results/eliminations/anchor-elimination-v1/`.

Facts from the anchors alone:

- **No pure transposition.** The anchors need three `E`; K4 has two.
- **No Porta, and no cipher that never maps a letter to itself.** Anchor
  letters encrypt to themselves at one-based positions 33 (`S`) and 74 (`K`).
- **Bean's equality.** Positions 28 and 66 both encrypt `R` to `P`, so any
  position-keyed tableau cipher has equal keys there.
- **No periodic substitution, with any alphabets, fits at periods** 1–7, 9,
  10, 14, 15, 17, 21, 25, 34, 42, 43, or 45.
- **No Quagmire I with any plaintext alphabet fits at periods** 1–12, 14, 15,
  17, 18, 20–22, or 25, and **no Quagmire II with any ciphertext alphabet** at
  1–15, 17, 18, 21, 22, or 25. This is exact: each anchor is a difference
  constraint between an unknown alphabet position and an unknown key column.
  Passing that test is necessary only, but the exact search below confirms
  every passing period is solvable. Both pass at period 19, which 1.5–2.1% of ciphertext shuffles also do. A
  post-hoc combined test gives p = 0.049, which is not evidence.
- **Quagmire I–IV with arbitrary alphabets (exact search, F21–F22).** Every
  cell up to period 26 is decided, for both sign conventions:

  | Kind | Impossible | Solvable |
  | --- | --- | --- |
  | Quagmire I (mixed plaintext alphabet) | 1–12, 14, 15, 17, 18, 20–22, 25 | 13, 16, 19, 23, 24, 26 |
  | Quagmire II (mixed ciphertext alphabet) | 1–15, 17, 18, 21, 22, 25 | 16, 19, 20, 23, 24, 26 |
  | Quagmire III, Vigenère or variant Beaufort | 1–26 | none |
  | Quagmire III, Beaufort | 1–22, 24, 25 | 23, 26 |
  | Quagmire IV (two free alphabets) | 1–7, 9–12, 14, 15, 17, 18, 21, 22, 25 | 8, 13, 16, 19, 20, 23, 24, 26 |

  Quagmire III Vigenère period 24 had stayed undecided after 20 billion
  search nodes, but it has a one-line proof. Position 74 (`K`→`K`) and
  position 26 (`N`→`Q`) share a column. With one alphabet on both sides,
  `K`→`K` forces that column's key to 0, and key 0 cannot turn `N` into `Q`.
  The search now applies this rule during propagation. "Solvable" means the
  anchors can be fitted; it is not evidence for the method.
- **No dictionary keyword alphabet fits Quagmire I, II, or III at periods
  1–25.** Every word in Webster's Second and the system proper-names list
  (about 208,000 distinct alphabets, 48.8 million configurations) was tested.
  The only survivors are at period 26, where the anchors are almost
  untested, at the chance rate. Preregistration:
  `experiments/eliminations/dictionary-keywords-preregistration.md`.

Families, using 37 keyed alphabets fixed before scoring (standard plus 36
Kryptos, clue, and theme keywords) in every plaintext/ciphertext pairing:

| Family | Configurations | Survivors | Expected by chance | Most checks survived |
| --- | ---: | ---: | ---: | ---: |
| Periodic tableau and Quagmire I–IV, period 1–26 | 106,782 | 188 | 158.2 | 1 |
| Gronsfeld, period 1–26 | 2,886 | 0 | 0.0 | — |
| Ciphertext autokey, lag 1–52 | 421,356 | 0 | 0.0 | — |
| Plaintext autokey, lag 1–52 | 421,356 | 1,261 | 960.4 | 3 |
| Gromark, lag 2–12, mod 10 or 26 | 90,354 | 0 | 0.0 | — |
| Keyed columnar (width 2–8, every order) with periodic tableau (period 1–13), both orders | 14,424,384 | 0 | 0.0 | — |

Survivors pass at most three checks, at the rate chance predicts. Each checker
keeps a planted true key in its unit tests, so zero survivors is a real
elimination, not a bug.

Limits: the 37 registered alphabets plus the dictionary alphabets above (Quagmire IV is tested only with registered pairs), the stated
periods, lags, and widths, and standard/Kryptos tableaux for the columnar
search. Running keys are covered below.

## Route transpositions

Run: `results/eliminations/anchor-elimination-v6/`. Plaintext is written row by
row into a grid of width 2–48 (97 is prime, so the last row is partial) and
read by ten routes: columns (down, up, right to left), column and row
serpentines, spirals both ways, and diagonals. K3-style double rotations
(rotate, rewrite at a second width, rotate again) are added for every width
pair. With each route also inverted and reversed, there are 18,849 distinct
permutations, each tested before and after the key.

- **With a periodic tableau key** (standard and Kryptos alphabets, period
  1–26): 11.8 million configurations, 9,232 survivors against 9,169 expected
  by chance, none passing more than three checks.
- **With any alphabet per key column** (general periodic substitution): no
  route fits at period 1 or 2. At periods 3–8, the counts that fit match a null
  that keeps each route and shuffles the ciphertext letters (smallest p =
  0.065, at period 3, before correcting for eight periods).

Limits: these route families only; keyed transpositions longer than width 8
and non-periodic keys after a route are not covered.

## Running keys

Preregistration: `experiments/running-key/preregistration.md`. Results:
`results/running-key/`.

**Fixed corpus (`running-key`).** Eight texts were fixed before scoring: the
K1–K3 plaintext, the K1–K3 ciphertext, the tableau rows, and Carter and Mace's
*Tomb of Tut.ankh.Amen* Vol. I (1923), each forward and reversed. Every offset
was tested on Vigenère, Beaufort, and variant Beaufort with standard and
Kryptos alphabets: 10.2 million configurations. None reproduces all 24 anchor
letters. The best is 9/24 (reversed Carter, 0.72 expected by chance); every
corpus's best is at chance level.

**Any English text (`key-language`).** A running key from English puts English
letters at the anchors. For each of the 8,103 registered tableau
configurations, the implied key at the two anchor runs (13 and 11 letters) was
scored with a trigram model trained on half of Carter's text and compared with
held-out English windows. One configuration reaches the 0.1% English quantile,
against 1.13 expected from random keys, and its implied key
(`CDHIRMEFADCNE FYEDNICKTHE`) is not English. A running key from any English
text is eliminated for the 37 registered alphabets.

Limits: registered alphabets only; a key that is itself enciphered, non-English,
or transposed is not covered.

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
