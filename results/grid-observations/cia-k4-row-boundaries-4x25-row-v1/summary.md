# Grid Layout Prediction Evaluation

This is not a claimed solution.

artifact: `experiments/predictions/non-anchor-position-grid-4x25-row-v1.json`
observation id: `cia-k4-row-boundaries-v1`
observation sources: cia-sculpture
observation rationale: Pre-score source-backed observation from the CIA sculpture page text-version rendering: K4 appears as a short suffix followed by three rendered lines, so only non-anchor row-boundary positions are retained for evaluation.
position notes: 6
source-backed observation: true
observed positions: 1, 4, 5, 36, 37, 97
observed position count: 6
edge axis: row
selected-edge hits: 1/6 (0.1667)
same-size null: mean 0.41; sd 0.60; empirical p-value 0.3558; iterations 100000; seed 67
row-edge hits: 1/6 (0.1667)
column-edge hits: 4/6 (0.6667)
promoted: false
note: Grid-layout prediction evaluation scores independent non-anchor positions against a committed grid edge-axis artifact with a seeded same-size position-set null; it is not a claimed solution.

## Matching Selected-Edge Positions

1

## Non-Selected-Edge Positions

4, 5, 36, 37, 97

## Matching Row-Edge Positions

1

## Matching Column-Edge Positions

1, 4, 5, 97
