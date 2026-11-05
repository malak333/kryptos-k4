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
| `route-plus-tableau` | 11761776 | 11749256 | 3288 | 9232 | 9168.7 | 3 |

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

### `route-plus-tableau`

Route transposition (columns, serpentines, spirals, diagonals, K3-style double rotations; each also inverted and reversed; grid width 2..=max) before or after a periodic Vigenère/Beaufort/variant key on standard and Kryptos tableaux, period 1..=max

Least likely survivors (chance = probability a random configuration passes the same checks):

- substitute-then-transpose double-rotate-ccw widths=26,7 inverse standard beaufort pt=standard ct=standard period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=38,12 inverse reversed quagmire-i variant-beaufort pt=kryptos ct=standard period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=38,12 inverse reversed quagmire-i vigenere pt=kryptos ct=standard period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=43,34 reversed quagmire-iii variant-beaufort pt=kryptos ct=kryptos period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=43,34 reversed quagmire-iii vigenere pt=kryptos ct=kryptos period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=44,8 quagmire-ii beaufort pt=standard ct=kryptos period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=47,39 inverse reversed quagmire-i variant-beaufort pt=kryptos ct=standard period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=47,39 inverse reversed quagmire-i vigenere pt=kryptos ct=standard period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-ccw widths=6,46 inverse quagmire-iii beaufort pt=kryptos ct=kryptos period=25 — 3 checks, chance 5.69e-5
- substitute-then-transpose double-rotate-cw widths=10,34 inverse reversed quagmire-i beaufort pt=kryptos ct=standard period=25 — 3 checks, chance 5.69e-5

### `route-plus-any-substitution`

Same routes and orders as route-plus-tableau, but any alphabet per key column (general periodic substitution); consistent means each key column maps plaintext to ciphertext one-to-one

18849 routes; random-permutation null from 200000 permutations; ciphertext-shuffle null from 200 shuffles for periods 1..=8 (seed 1).

| Period | Configurations | Consistent | Random rate | Expected by random permutation | Expected by ciphertext shuffle | Shuffle p | Examples |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 37698 | 0 | 0.00e0 | 0.0 | 0.0 | 1.000 |  |
| 2 | 37698 | 0 | 0.00e0 | 0.0 | 0.0 | 1.000 |  |
| 3 | 37698 | 14 | 1.22e-4 | 4.6 | 7.1 | 0.065 | transpose-then-substitute diagonals-snake width=40 reversed; transpose-then-substitute columns-up width=47 inverse reversed; transpose-then-substitute double-rotate-cw widths=4,48 reversed |
| 4 | 37698 | 70 | 1.47e-3 | 55.5 | 59.1 | 0.275 | transpose-then-substitute columns-down width=3; transpose-then-substitute rows-snake width=5; transpose-then-substitute rows-snake width=5 reversed |
| 5 | 37698 | 182 | 3.72e-3 | 140.2 | 223.3 | 0.775 | transpose-then-substitute columns-down width=3 inverse; transpose-then-substitute rows-snake width=19; transpose-then-substitute columns-up width=22 inverse reversed |
| 6 | 37698 | 5280 | 1.36e-1 | 5122.5 | 5165.9 | 0.315 | transpose-then-substitute columns-down width=2; transpose-then-substitute columns-down width=2 reversed; transpose-then-substitute columns-up width=2 |
| 7 | 37698 | 6728 | 1.72e-1 | 6473.7 | 6997.4 | 0.815 | transpose-then-substitute columns-down width=2; transpose-then-substitute columns-down width=2 reversed; substitute-then-transpose columns-down width=2 inverse reversed |
| 8 | 37698 | 8976 | 2.26e-1 | 8527.1 | 8321.8 | 0.090 | transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse; transpose-then-substitute columns-down width=2 reversed |
| 9 | 37698 | 2419 | 5.95e-2 | 2242.3 | — | — | transpose-then-substitute columns-down width=3; transpose-then-substitute columns-down width=3 reversed; transpose-then-substitute columns-up width=4 |
| 10 | 37698 | 11483 | 2.93e-1 | 11056.2 | — | — | substitute-then-transpose columns-down width=2 inverse; substitute-then-transpose columns-down-rtl width=2 inverse reversed; substitute-then-transpose rows-snake width=2 |
| 11 | 37698 | 13863 | 3.53e-1 | 13315.0 | — | — | substitute-then-transpose columns-down width=2 inverse reversed; substitute-then-transpose columns-down-rtl width=2 inverse; transpose-then-substitute columns-down-rtl width=2 inverse |
| 12 | 37698 | 16531 | 4.24e-1 | 15975.7 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse |
| 13 | 37698 | 18591 | 4.67e-1 | 17590.3 | — | — | transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse; transpose-then-substitute columns-down width=2 reversed |
| 14 | 37698 | 17971 | 4.57e-1 | 17213.7 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 reversed |
| 15 | 37698 | 5983 | 1.45e-1 | 5466.6 | — | — | substitute-then-transpose columns-down width=2 inverse; transpose-then-substitute columns-down width=2 inverse reversed; transpose-then-substitute columns-down-rtl width=2 inverse |
| 16 | 37698 | 20492 | 5.21e-1 | 19625.8 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse |
| 17 | 37698 | 7265 | 1.76e-1 | 6621.5 | — | — | transpose-then-substitute columns-down width=2 inverse; transpose-then-substitute columns-down-rtl width=2 inverse reversed; transpose-then-substitute columns-snake width=2 inverse reversed |
| 18 | 37698 | 22995 | 6.01e-1 | 22653.5 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse |
| 19 | 37698 | 8877 | 2.13e-1 | 8017.3 | — | — | transpose-then-substitute columns-down width=2 inverse; transpose-then-substitute columns-down width=2 inverse reversed; substitute-then-transpose columns-up width=2 reversed |
| 20 | 37698 | 20861 | 5.41e-1 | 20392.1 | — | — | substitute-then-transpose columns-down width=2 inverse; transpose-then-substitute columns-down width=2 inverse; transpose-then-substitute columns-down width=2 inverse reversed |
| 21 | 37698 | 20632 | 5.38e-1 | 20292.8 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 reversed |
| 22 | 37698 | 23223 | 5.92e-1 | 22323.8 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2 inverse; substitute-then-transpose columns-down width=2 reversed |
| 23 | 37698 | 25437 | 6.55e-1 | 24684.4 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse |
| 24 | 37698 | 26392 | 6.92e-1 | 26096.1 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse |
| 25 | 37698 | 25749 | 6.63e-1 | 24994.4 | — | — | substitute-then-transpose columns-down width=2 inverse; transpose-then-substitute columns-down width=2 inverse; substitute-then-transpose columns-down width=2 reversed |
| 26 | 37698 | 30474 | 7.86e-1 | 29621.1 | — | — | substitute-then-transpose columns-down width=2; transpose-then-substitute columns-down width=2; substitute-then-transpose columns-down width=2 inverse |

A configuration survives only if it passes every anchor check it has. Survivors with few checks are expected by chance (compare expected_chance_survivors); none is a decryption or a promoted candidate.

promoted: false
