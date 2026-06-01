# Ciphertext Period-Match Evaluation

This is not a claimed solution.

observation id: `cia-k4-row-boundaries-v1`
observation sources: cia-sculpture
observation rationale: Pre-score source-backed observation from the CIA sculpture page text-version rendering: K4 appears as a short suffix followed by three rendered lines, so only non-anchor row-boundary positions are retained for evaluation.
source-backed observation: true
observed positions: 1, 4, 5, 36, 37, 97
best period-match set: period 7; hits 1/6 (0.1667)

| Period | Hits | Hit Rate | Matching Positions |
| --- | --- | --- | --- |
| 1 | 0 | 0.0000 |  |
| 4 | 0 | 0.0000 |  |
| 7 | 1 | 0.1667 | 1 |

null: mean 1.41; sd 0.80; empirical p-value 0.9051; iterations 100000; seed 67
promoted: false
note: Ciphertext period-match evaluation scores source-backed non-anchor positions against endpoints of ciphertext-only shifted same-letter period matches with a seeded same-size position-set null; it is not a claimed solution.
