# Running-Key Corpus Preregistration (v1)

Registered: 2026-11-04, before any corpus below was scored.

This is not a claimed solution. Corpus texts are not committed; each file is
identified by its public source and SHA-256 so the run can be repeated.

## Method

`kryptos-k4 running-key --corpus FILE`: the key at K4 position i is corpus
letter `offset + i` (letters A–Z only, case folded). Every offset is tested on
Vigenère, Beaufort, and variant Beaufort over the standard and Kryptos
alphabets, with the key letter read in each tableau's key alphabets.

## Decision rule

- A configuration that reproduces all 24 anchor letters would be a candidate
  for review, not a solution.
- Otherwise the corpus is eliminated as a direct running key under these
  tableaux. The best match count is reported against the count expected by
  chance (binomial, p = 1/26 per anchor letter).
- No corpus, offset rule, or tableau is added after seeing results. Any later
  corpus gets a new preregistration version.

## Corpus

| File | Source | Letters | SHA-256 |
| --- | --- | ---: | --- |
| `k1k3-plain.txt` | K1, K2, K3 plaintext blocks as published on English Wikipedia, "Kryptos" (`action=raw`, fetched 2026-11-04), concatenated in that order | 769 | `84d4ad42279e8899e5bebefd4adbd98608a2345c9a0ab0b5d148680849676813` |
| `k1k3-cipher.txt` | Sculpture cipher side, K1–K3 ciphertext (all letters before K4's `OBKR`, `?` removed), same page | 768 | `23e71c225898eb2776995eebd5a190221cd4c38b7f8a5c5db743845ada9bcf85` |
| `tableau.txt` | Sculpture tableau side rows, same page, read row by row | 871 | `14fc954ea275107889ea1b188149bc5c3b8dda2ecbee40dd22dcff7ca3ab39cc` |
| `carter-v1.txt` | Carter and Mace, *The Tomb of Tut.ankh.Amen*, Vol. I (1923), Internet Archive item `in.ernet.dli.2015.77344`, `_djvu.txt` OCR | 282392 | `355086705f8d02be7f49efcb41f4652deaab74a3b438d8e3bf20e2fb6e0a6e9b` |
| `*-reversed.txt` | Each of the four above, letters only, reversed | same | k1k3-plain `72726c9d…`, k1k3-cipher `fc30f98c…`, tableau `bcb700ab…`, carter-v1 `d022910a…` |

Why these: K3's plaintext paraphrases Carter's account of opening the tomb in
November 1922, and Sanborn's 2025 clues name his 1986 Egypt trip; K1–K3 and
the tableau are the sculpture's own text. Carter's Vol. I is public domain in
the United States. Its OCR has errors, so a true key from it could fall a few
letters short of 24; any result well above chance gets a manual check against
a page scan.

## Addendum: any-English running key (registered before scoring)

`kryptos-k4 key-language --corpus carter-v1.txt` (defaults: quantile 0.001,
200,000 uniform samples, seed 1). It tests whether a running key from *any*
English text, not only the files above, fits the registered tableaux.

- The trigram model is trained on the first half of `carter-v1.txt`. Held-out
  English windows come from the second half, read at the 24 anchor positions
  of a 74-letter window.
- For each of the 37 × 37 × 3 registered tableaux and each key alphabet, the
  key letters implied at the two anchor runs (13 and 11 letters) are scored.
- A configuration whose score falls below the 0.1% quantile of held-out
  English windows is eliminated as an English running key. A true English key
  would be wrongly eliminated with probability about 0.001.
- The count of compatible configurations is compared with the count expected
  from uniform random keys. Compatible configurations are leads, not results.
