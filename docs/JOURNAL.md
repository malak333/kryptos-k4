# Journal

Short dated entries, newest first. One entry per meaningful change in
direction or result. Record what was tried, the outcome, and what it rules out.
Routine runs that repeat an earlier result do not get an entry.

The earlier long-form log (96 entries, 2026-05-20 through 2026-06-01) is
`experiments/PROGRESS_LOG.md` at git tag `pre-slimdown`.

## 2026-11-04: Route transpositions (phase 6)

- Added the route family to `eliminate`: 18,849 route permutations (ten grid
  routes at widths 2–48, K3-style double rotations, inverses, reversals).
  With a periodic tableau key: chance-level survivors only. With any alphabet
  per key column: no excess over a ciphertext-shuffle null (F18).
- Exact any-alphabet test for Quagmire I and II (weighted union-find): ruled
  out at every period to 12 and most to 26; period 19 is the weakest gap,
  p = 0.049 post hoc (F19).
- Added `eliminate --wordlist`: every Webster's Second and proper-name keyword
  alphabet as Quagmire I–III. No survivor at periods 1–25 (F20).

## 2026-11-04: Running keys (phase 5)

- Preregistered a running-key corpus before scoring: K1–K3 plaintext and
  ciphertext, tableau rows, and Carter Vol. I, forward and reversed. 10.2
  million configurations, no full match, best 9/24 at chance level (F16).
- Added `key-language`: no registered tableau implies an English-looking key
  at the anchors (1 compatible of 8,103; 1.13 expected by chance). A running
  key from any English text is eliminated for the registered alphabets (F17).

## 2026-11-04: Anchor elimination (phase 4)

- Added `eliminate`: each configuration gets the anchor checks a correct
  configuration must pass, with a chance probability per check. 15.5 million
  configurations. Zero survivors for Gronsfeld, ciphertext autokey, Gromark
  (lag 2–12), and keyed columnar width 2–8 plus periodic tableau. Periodic
  Quagmire I–IV and plaintext autokey leave only chance-level survivors (at
  most 1 and 3 checks).
- From the anchors alone: no pure transposition (needs three `E`, K4 has
  two), no Porta (two self-encryptions), no periodic substitution with any
  alphabet at periods 1–7, 9, 10, 14, 15, 17, 21, 25.
- Added `running-key --corpus FILE`. Not yet run on a real corpus.

## 2026-11-04: Slim-down phases 2 and 3

- Cut the CLI from about 100 commands to 19 and the source from about 45k lines
  to 7k. Removed every lane, observation, source-review, and evidence-gate
  command, plus the held-out key control and key-run summarizer. Five claim
  verifiers became one `verify-claim`. Release check now covers only no CI,
  claim-archive boundaries, and no leaked-plaintext markers.
- Replaced the progress log, stopped-lanes file, evidence summary, and three
  architecture/method docs with `README.md`, `docs/negative-results.md`, this
  journal, and `docs/research-plan.md`. Removed the per-lane preregistration
  and prediction files; the results archives hold the copies that were scored.
  Removed the continuous batch-loop scripts.

## 2026-11-03: Slim-down phase 1

- Pruned 60 duplicate or escalating-variant lanes (86 down to 26) and their 14
  archives. The surviving 26 archives are now tracked in git.
- Selection caveat: the lowest raw p of the phase (`p=0.0436`, terminal
  residue balance; corrected `p=1.0000`) was a pruned variant.
- Checked periodic Vigenère, Beaufort, and variant Beaufort in the standard and
  Kryptos alphabets against the anchors: inconsistent at every period 1 to 26.

## 2026-05-20 to 2026-06-01: Source-grounded tooling and independent lanes

- Built the source registry, anchor constraints, key-material tests, route
  screens, and Gromark-style recurrence baseline. All negative.
- Scored one source-backed observation (CIA web-page row boundaries, six
  positions) against 86 lanes. All negative; see `docs/negative-results.md`.
- Screened the SolveKryptos claim: anchor-compatible, but its published
  mechanism is not self-consistent.
