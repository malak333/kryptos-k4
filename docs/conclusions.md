# Conclusions

Written: 2026-11-04, after phases 4–6; updated 2026-11-05 for the exact Quagmire search (F21, F22). This is not a claimed solution.

K4 has 97 letters, and 24 of them are known: `EASTNORTHEAST` at one-based
22–34 and `BERLINCLOCK` at 64–74. This project asked one question of every
method it could state precisely: does it reproduce all 24 known letters at
their positions? A wrong method passes by chance with probability about
26^-c, where c is the number of independent checks the anchors give it. One
miss eliminates a configuration. When a family has many configurations, its
survivors are compared with the number expected by chance.

## What the anchors rule out

Each line is exact or measured against a stated null. The full record is
`docs/negative-results.md`. Findings are listed by `kryptos-k4 findings`.

| Method class | Result | Finding |
| --- | --- | --- |
| Pure transposition | Impossible: the anchors need three `E`, K4 has two | F15 |
| Porta, or any cipher with no self-encryption | Impossible: anchor letters encrypt to themselves at 33 and 74 | F15 |
| Periodic substitution, any alphabet per column | Impossible at periods 1–7, 9, 10, 14, 15, 17, 21, 25 | F15 |
| Quagmire I / II, any mixed alphabet (exact search) | Impossible at every period 1–12, and at 14, 15, 17, 18, 21, 22, 25 (I also 20, II also 13); solvable at the rest up to 26 | F19, F22 |
| Vigenère, Beaufort, variant Beaufort; standard or Kryptos alphabet | Eliminated at periods 1–26 | F15 |
| Quagmire I–IV, 37 registered keyword alphabets in every pairing | Chance-level survivors only (at most 1 check) | F15 |
| Quagmire I–III, keyword from any dictionary word (about 208,000 alphabets) | No survivor at periods 1–25 | F20 |
| Quagmire III, any alphabet (exact search) | Vigenère: impossible at every period 1–26. Beaufort: solvable only at 23 and 26 | F21, F22 |
| Quagmire IV, any two alphabets (exact search) | Impossible at 1–7, 9–12, 14, 15, 17, 18, 21, 22, 25; solvable at 8, 13, 16, 19, 20, 23, 24, 26 | F21 |
| Gronsfeld, ciphertext autokey, Gromark (lag 2–12) | Zero survivors | F15 |
| Plaintext autokey, lag 1–52 | Chance-level survivors only (at most 3 checks) | F15 |
| Keyed columnar, width 2–8, every order, plus periodic tableau | Zero survivors over 14.4 million configurations | F15 |
| Route transpositions (10 routes, width 2–48, K3-style double rotations) plus periodic tableau | Chance-level survivors only | F18 |
| Same routes plus any per-column alphabet | No excess over a ciphertext-shuffle null | F18 |
| Running key from K1–K3 plaintext, K1–K3 ciphertext, the tableau, or Carter's 1923 account | No full match; best at chance level | F16 |
| Running key from any English text, on any registered tableau | 1 compatible configuration of 8,103, against 1.13 expected by chance | F17 |
| Ciphertext-only statistics and the six-position web-page prior | No lane survived | F5, F14 |
| Published solution claims | Quarantined; the one checkable mechanism is internally inconsistent | F13 |

Taken together: **K4 is not any classical single-layer periodic or autokey
cipher, nor a bounded transposition combined with one, nor a running key
from English text, using any alphabet the sculpture, its clues, or a
dictionary suggests.** That fits the CIA's description of K4 as a more
difficult code than K1–K3, and Sanborn's remark that the solution is not
necessarily mathematical. This project reached it using only the public
anchors.

## What remains open, and why the anchors cannot close it

The anchors give 24 checks. A method family can be eliminated only if its
configurations leave fewer than about 24 free key values at the anchor
positions. Every class below is open for that reason, not for lack of trying:

1. **Non-periodic keys with free values at the anchors.** These include a
   running key from non-English or already-enciphered text, a key stream from
   numbers (the World Clock, dates, coordinates) beyond the preregistered
   sequences in F3, and one-time-pad-like material. Any such key can fit 24
   letters by construction. The anchors can only test a *specific* proposed
   key source.
2. **Quagmire with arbitrary alphabets at the remaining periods.** An exact
   search (F21) shows that Quagmire IV fits the anchors at periods 8, 13, 16,
   19, 20, 23, 24, and 26, so the anchors alone cannot rule it out there.
   Quagmire I is solvable at 13, 16, 19, 23, 24, and 26, and Quagmire II at
   16, 19, 20, 23, 24, and 26 (exact, F22). Quagmire III is solvable only with
   Beaufort at 23 and 26. Every cell up to period 26 is now decided. Period 19 for Quagmire
   I/II is not evidence (post-hoc p = 0.049; F19).
3. **Arbitrary transpositions combined with substitution.** A free
   permutation of 97 letters plus a free substitution can fit any 24
   letters. Only named, low-parameter routes can be tested (F18).
4. **Multi-layer or irregular methods:** nulls, deliberate misspellings like
   those in K1–K3, homophones, a changed alphabet partway through, or a
   procedure tied to the physical sculpture. These are not well-defined
   enough to test until someone states them precisely.

## What would move K4 forward

- **More plaintext.** Each additional known letter adds a check to every test
  above. Sanborn has released anchors in 2010, 2014, and 2020. A further
  release would make the tools here immediately more powerful:
  `kryptos-k4 eliminate` and `key-language` read the anchors from
  `src/data.rs`.
- **A specific key-source hypothesis, stated before it is scored.** The
  machinery is in place: `running-key --corpus`, `eliminate --wordlist`,
  `test-key`, and `candidate-sequences`. A proposal that names its material
  and procedure can be checked in seconds, and a miss is decisive.
- **An exact check for a full candidate now exists.** After Sanborn's
  November 2025 archive auction, Paradigm had him enter the plaintext on a
  fresh machine and kept only a commitment (a SHA-256 digest turned into an
  HMAC tag with a Google Cloud KMS key). It checks submissions
  at paradigm.xyz/kryptos/k4 for $1 each. Their form takes exactly 97 letters
  A–Z with the anchors fixed. Its hint shows only the same two anchors, so it
  adds no known letters (checked 2026-11-05). A candidate from a stated
  method should pass every anchor test here before anyone pays to submit it.
- **Not more statistics on the ciphertext alone.** Every ciphertext-only lane
  here was negative after controls (F5, F14). The 97 letters are too few to
  carry a hidden structure past a fair null.

## Reproducing

```bash
cargo build --release
target/release/kryptos-k4 eliminate --wordlist /usr/share/dict/web2 --wordlist /usr/share/dict/propernames --quagmire-search-budget 2000000000
target/release/kryptos-k4 running-key --corpus <file>      # corpus files: experiments/running-key/preregistration.md
target/release/kryptos-k4 key-language --corpus <carter-v1.txt>
target/release/kryptos-k4 findings
```

Archived runs: `results/eliminations/anchor-elimination-v6/` and
`results/running-key/`.
