# Ciphertext Prior Evaluation

This is not a claimed solution.

observation id: `cia-k4-row-boundaries-v1`
observation sources: cia-sculpture
observation rationale: Pre-score source-backed observation from the CIA sculpture page text-version rendering: K4 appears as a short suffix followed by three rendered lines, so only non-anchor row-boundary positions are retained for evaluation.
source-backed observation: true
observed positions: 1, 4, 5, 36, 37, 97
best: period 2 residue 0 with 4/6 hits (0.6667)
selected-period null: mean 3.91; sd 0.77; empirical p-value 0.6845; iterations 100000; seed 67
promoted: false
note: Ciphertext-prior evaluation scores source-backed non-anchor positions against a planning-only ciphertext-derived prior; it is not a claimed solution.

| Period | Support Kind | Best Residue | Hits | Hit Rate |
| --- | --- | --- | --- | --- |
| 2 | repeated-ngram-gap-factor | 0 | 4/6 | 0.6667 |
| 7 | shifted-ciphertext-coincidence | 0 | 2/6 | 0.3333 |
