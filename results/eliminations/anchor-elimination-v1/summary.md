# Anchor Elimination

This is not a claimed solution.

A correct method must reproduce all 24 public anchor letters. One failed check eliminates a configuration.

## Structural facts

- Self-encrypting anchor positions (one-based): [33, 74]. Porta and any cipher that never maps a letter to itself are impossible.
- Identical plaintext/ciphertext pairs (one-based): [(28, 66)]. Position-keyed tableau ciphers must use equal keys there.
- Pure transposition is impossible: E needs 3, K4 has 2.
- No periodic substitution (any alphabet per column) fits at periods: [1, 2, 3, 4, 5, 6, 7, 9, 10, 14, 15, 17, 21, 25, 34, 42, 43, 45] (checked 1..=48).

## Families

| Family | Configurations | Eliminated | Untestable | Surviving | Expected by chance | Most checks survived |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `periodic-tableau` | 106782 | 106594 | 0 | 188 | 158.2 | 1 |
| `gronsfeld` | 2886 | 2886 | 0 | 0 | 0.0 | 0 |
| `ciphertext-autokey` | 421356 | 421356 | 0 | 0 | 0.0 | 0 |
| `plaintext-autokey` | 421356 | 395786 | 24309 | 1261 | 960.4 | 3 |
| `gromark` | 90354 | 90354 | 0 | 0 | 0.0 | 0 |
| `columnar-plus-tableau` | 14424384 | 14424384 | 0 | 0 | 0.0 | 0 |

### `periodic-tableau`

Vigenère, Beaufort, and variant Beaufort over every pair of registered alphabets (standard tableau and Quagmire I–IV) with a repeating key of period 1..=max

Least likely survivors (chance = probability a random configuration passes the same checks):

- quagmire-i variant-beaufort pt=abscissa ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i variant-beaufort pt=cairo ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i variant-beaufort pt=iqlusion ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i variant-beaufort pt=lucid ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i variant-beaufort pt=pyramid ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i variant-beaufort pt=shadow ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i variant-beaufort pt=urania ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i vigenere pt=abscissa ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i vigenere pt=cairo ct=standard period=26 — 1 checks, chance 3.85e-2
- quagmire-i vigenere pt=iqlusion ct=standard period=26 — 1 checks, chance 3.85e-2

### `gronsfeld`

Periodic digit key (0..=9) on same-alphabet tableaux for every registered alphabet, three sign conventions, period 1..=max

No survivors.

### `ciphertext-autokey`

Key at position i is the ciphertext letter at i-L, after an unknown L-letter primer; every registered tableau, L in 1..=max

No survivors.

### `plaintext-autokey`

Key at position i is the plaintext letter at i-L, after an unknown L-letter primer; every registered tableau, L in 1..=max

Least likely survivors (chance = probability a random configuration passes the same checks):

- quagmire-ii vigenere pt=standard ct=tutankhamun key=ct lag=32 — 3 checks, chance 5.69e-5
- quagmire-iv beaufort pt=enigma ct=kryptos key=ct lag=25 — 3 checks, chance 5.69e-5
- quagmire-iv variant-beaufort pt=enigma ct=alexanderplatz key=ct lag=50 — 3 checks, chance 5.69e-5
- quagmire-i variant-beaufort pt=layertwo ct=standard key=pt lag=31 — 2 checks, chance 1.48e-3
- quagmire-iv beaufort pt=carter ct=giza key=pt lag=31 — 2 checks, chance 1.48e-3
- quagmire-iv beaufort pt=digetal ct=eastnortheast key=ct lag=51 — 2 checks, chance 1.48e-3
- quagmire-iv beaufort pt=eastnortheast ct=carter key=pt lag=51 — 2 checks, chance 1.48e-3
- quagmire-iv beaufort pt=eastnortheast ct=pyramid key=ct lag=51 — 2 checks, chance 1.48e-3
- quagmire-iv beaufort pt=eastnortheast ct=scheidt key=pt lag=51 — 2 checks, chance 1.48e-3
- quagmire-iv beaufort pt=lodestone ct=pyramid key=ct lag=51 — 2 checks, chance 1.48e-3

### `gromark`

Lagged-Fibonacci key k[i] = k[i-L] + k[i-L+1] mod m (m=10 classic Gromark, m=26 letter variant), L in 2..=12, every registered tableau

No survivors.

### `columnar-plus-tableau`

Keyed columnar transposition (every column order, width 2..=max) before or after a periodic Vigenère/Beaufort/variant key on standard and Kryptos tableaux, period 1..=max

No survivors.

A configuration survives only if it passes every anchor check it has. Survivors with few checks are expected by chance (compare expected_chance_survivors); none is a decryption or a promoted candidate.

promoted: false
