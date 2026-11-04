# Spacing Prediction Evaluation

This is not a claimed solution.

artifact: `experiments/predictions/non-anchor-position-spacing-v1.json`
observation id: `cia-k4-row-boundaries-v1`
observation sources: cia-sculpture
observation rationale: Pre-score source-backed observation from the CIA sculpture page text-version rendering: K4 appears as a short suffix followed by three rendered lines, so only non-anchor row-boundary positions are retained for evaluation.
position notes: 6
source-backed observation: true
observed positions: 1, 4, 5, 36, 37, 97
observed position count: 6; observed pair count: 15
best: modulus 2 residue 1 with 8/15 pair hits (0.5333)
best-of-modulus null: mean 8.94; sd 1.29; empirical p-value 1.0000; iterations 100000; seed 67
promoted: false
note: Spacing prediction evaluation scores independent non-anchor positions against a committed spacing artifact with a best-of-modulus null; it is not a claimed solution.

| Modulus | Best Residue | Pair Hits | Hit Rate |
| --- | --- | --- | --- |
| 2 | 1 | 8/15 | 0.5333 |
| 4 | 0 | 7/15 | 0.4667 |
| 3 | 0 | 6/15 | 0.4000 |
| 5 | 1 | 6/15 | 0.4000 |
| 7 | 1 | 4/15 | 0.2667 |
| 8 | 4 | 4/15 | 0.2667 |
| 14 | 4 | 4/15 | 0.2667 |
| 13 | 1 | 3/15 | 0.2000 |
