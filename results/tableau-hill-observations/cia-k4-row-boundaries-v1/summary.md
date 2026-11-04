# Tableau/HILL Prediction Evaluation

This is not a claimed solution.

artifact: `experiments/predictions/tableau-hill-v1.json`
observation id: `cia-k4-row-boundaries-v1`
observation sources: cia-sculpture
observation rationale: Pre-score source-backed observation from the CIA sculpture page text-version rendering: K4 appears as a short suffix followed by three rendered lines, so only non-anchor row-boundary positions are retained for evaluation.
position notes: 6
source-backed observation: true
observed positions: 1, 4, 5, 36, 37, 97
observed position count: 6
best: row 1 with 3/6 hits (0.5000)
same-size null: mean 2.36; sd 0.58; empirical p-value 0.3311; iterations 100000; seed 67
promoted: false
note: Tableau/HILL prediction evaluation scores independent non-anchor positions for row/column concentration on the committed 7-by-14 source map with a seeded same-size position-set null; it is not a claimed solution.

## Matching Best-Axis Positions

1, 4, 5

## Row Results

| Row | Hits | Hit Rate | Matching Positions |
| --- | --- | --- | --- |
| 1 | 3 | 0.5000 | 1, 4, 5 |
| 3 | 2 | 0.3333 | 36, 37 |
| 7 | 1 | 0.1667 | 97 |

## Column Results

| Column | Hits | Hit Rate | Matching Positions |
| --- | --- | --- | --- |
| 1 | 1 | 0.1667 | 1 |
| 4 | 1 | 0.1667 | 4 |
| 5 | 1 | 0.1667 | 5 |
| 8 | 1 | 0.1667 | 36 |
| 9 | 1 | 0.1667 | 37 |
| 13 | 1 | 0.1667 | 97 |
