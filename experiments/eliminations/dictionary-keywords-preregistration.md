# Dictionary Keyword Alphabets: Preregistration (v1)

Registered: 2026-11-04, before scoring.

This is not a claimed solution. It extends F15 (37 registered keyword
alphabets) and follows up F19 (Quagmire I/II with any alphabet pass at
period 19).

## Method

`kryptos-k4 eliminate --wordlist /usr/share/dict/web2 --wordlist /usr/share/dict/propernames`
adds the `dictionary-quagmire` family: every word becomes a keyword alphabet
(keyword letters without repeats, then the rest in order). Duplicate
alphabets and the standard alphabet are skipped. Each alphabet is tested as
Quagmire I (mixed plaintext alphabet), II (mixed ciphertext alphabet), and
III (the same mixed alphabet on both sides), with Vigenère, Beaufort, and
variant Beaufort, at periods 1–26. Anchor checks and chance probabilities are
the same as the `periodic-tableau` family.

## Word lists

| File | Lines | SHA-256 |
| --- | ---: | --- |
| `/usr/share/dict/web2` (Webster's Second International, 1934, as shipped with macOS) | 235,976 | `be41ad97963bf8dabedd5871d5d691596175269d540956b0f9965a885c2bbab9` |
| `/usr/share/dict/propernames` | 1,308 | `626d634b40b1ad9257d0e4f16e155ea87d258dd458e9ccf94fb84bb1b63e585a` |

## Decision rule

A configuration that passes every anchor check with chance probability below
1e-9 would be a candidate for review. Otherwise the family is eliminated if
its survivor count matches the chance expectation. No word list, period
range, or tableau kind is added after seeing results.
