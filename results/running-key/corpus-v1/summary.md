# Running-Key Corpus Scan (v1)

This is not a claimed solution. Preregistration: `experiments/running-key/preregistration.md`.

Command per corpus file: `cargo run --locked --release -- running-key --corpus <file> --format json`. Corpus texts are not committed; see the preregistration for sources and SHA-256.

| Corpus | Letters | Configurations | Best | Expected at best by chance | Full matches | Best configuration |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `k1k3-plain` | 769 | 12,528 | 6/24 | 3.00 | 0 | quagmire-i vigenere pt=kryptos ct=standard key=ct @ 480 |
| `k1k3-cipher` | 768 | 12,510 | 6/24 | 2.99 | 0 | quagmire-i beaufort pt=kryptos ct=standard key=ct @ 154 |
| `tableau` | 871 | 14,364 | 6/24 | 3.44 | 0 | quagmire-i variant-beaufort pt=kryptos ct=standard key=pt @ 16 |
| `carter-v1` | 282,392 | 5,081,742 | 8/24 | 10.28 | 0 | quagmire-i vigenere pt=kryptos ct=standard key=ct @ 5971 |
| `k1k3-plain-reversed` | 769 | 12,528 | 6/24 | 3.00 | 0 | quagmire-iii vigenere pt=kryptos ct=kryptos key=pt @ 91 |
| `k1k3-cipher-reversed` | 768 | 12,510 | 6/24 | 2.99 | 0 | quagmire-i variant-beaufort pt=kryptos ct=standard key=pt @ 503 |
| `tableau-reversed` | 871 | 14,364 | 7/24 | 0.35 | 0 | quagmire-i vigenere pt=kryptos ct=standard key=pt @ 768 |
| `carter-v1-reversed` | 282,392 | 5,081,742 | 9/24 | 0.72 | 0 | quagmire-i vigenere pt=kryptos ct=standard key=ct @ 235156 |

Total: 10,242,288 configurations. No configuration reproduces all 24 anchor letters. The best score in every corpus is within chance (largest: 9/24 in reversed Carter, 0.72 expected; summed over the eight corpora about 1.5 configurations are expected at 9 or more).

Interpretation: none of these texts is a direct running key for K4 under Vigenère, Beaufort, or variant Beaufort with standard or Kryptos alphabets. OCR errors in the Carter text could cost a true key a few letters, but no offset comes near 24.

promoted: false
