# Mirror Prediction Evaluation

This is not a claimed solution.

artifact: `experiments/predictions/non-anchor-position-mirror-v1.json`
observation id: `cia-k4-row-boundaries-v1`
observation sources: cia-sculpture
observation rationale: Pre-score source-backed observation from the CIA sculpture page text-version rendering: K4 appears as a short suffix followed by three rendered lines, so only non-anchor row-boundary positions are retained for evaluation.
position notes: 6
source-backed observation: true
observed positions: 1, 4, 5, 36, 37, 97
observed position count: 6; possible observed mirror pairs: 3
mirror pair hits: 1/3 (0.3333)
same-size null: mean 0.22; sd 0.44; empirical p-value 0.2090; iterations 100000; seed 67
promoted: false
note: Mirror prediction evaluation scores independent non-anchor positions against committed mirror pairs with a seeded same-size position-set null; it is not a claimed solution.

## Matching Mirror Pairs

- 1-97

## Singleton Mirror Positions

4, 5, 36, 37
