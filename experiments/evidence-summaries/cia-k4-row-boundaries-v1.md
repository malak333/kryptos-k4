# CIA K4 Row-Boundary Observation Summary

This is not a claimed solution.

## Inputs

- Observation file:
  `experiments/position-observations/cia-k4-row-boundaries-v1.json`
- Source snapshot:
  `sources/archives/cia-sculpture-2026-05-27.md`
- Source review:
  `experiments/source-reviews/cia-source-review-v1.json`
- Period preregistration:
  `experiments/preregistrations/non-anchor-position-period-v1.json`
- Period artifact:
  `experiments/predictions/non-anchor-position-period-v1.json`
- Period-3 preregistration:
  `experiments/preregistrations/non-anchor-position-period-v40.json`
- Period-3 artifact:
  `experiments/predictions/non-anchor-position-period-v40.json`
- Period-5 preregistration:
  `experiments/preregistrations/non-anchor-position-period-v42.json`
- Period-5 artifact:
  `experiments/predictions/non-anchor-position-period-v42.json`
- Period-14 preregistration:
  `experiments/preregistrations/non-anchor-position-period-v43.json`
- Period-14 artifact:
  `experiments/predictions/non-anchor-position-period-v43.json`
- Spacing preregistration:
  `experiments/preregistrations/non-anchor-position-spacing-v1.json`
- Spacing artifact:
  `experiments/predictions/non-anchor-position-spacing-v1.json`
- Mirror preregistration:
  `experiments/preregistrations/non-anchor-position-mirror-v1.json`
- Mirror artifact:
  `experiments/predictions/non-anchor-position-mirror-v1.json`
- Grid row preregistration:
  `experiments/preregistrations/non-anchor-position-grid-layout-v1.json`
- Grid row artifact:
  `experiments/predictions/non-anchor-position-grid-layout-v1.json`
- Grid column preregistration:
  `experiments/preregistrations/non-anchor-position-grid-column-v1.json`
- Grid column artifact:
  `experiments/predictions/non-anchor-position-grid-column-v1.json`
- Grid compass-axis preregistration:
  `experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json`
- Grid compass-axis artifact:
  `experiments/predictions/non-anchor-position-grid-compass-axis-v1.json`
- Tableau/HILL preregistration:
  `experiments/preregistrations/tableau-hill-v1.json`
- Tableau/HILL artifact:
  `experiments/predictions/tableau-hill-v1.json`
- Ciphertext prior preregistration:
  `experiments/preregistrations/ciphertext-structure-prior-v1.json`
- Ciphertext prior artifact:
  `experiments/predictions/ciphertext-structure-prior-v1.json`
- Ciphertext hotspot preregistration:
  `experiments/preregistrations/ciphertext-hotspot-prior-v1.json`
- Ciphertext hotspot artifact:
  `experiments/predictions/ciphertext-hotspot-prior-v1.json`
- Ciphertext rarity preregistration:
  `experiments/preregistrations/ciphertext-rarity-prior-v1.json`
- Ciphertext rarity artifact:
  `experiments/predictions/ciphertext-rarity-prior-v1.json`
- Ciphertext repeat-distance preregistration:
  `experiments/preregistrations/ciphertext-repeat-distance-v1.json`
- Ciphertext repeat-distance artifact:
  `experiments/predictions/ciphertext-repeat-distance-v1.json`
- Ciphertext period-match preregistration:
  `experiments/preregistrations/ciphertext-period-match-v1.json`
- Ciphertext period-match artifact:
  `experiments/predictions/ciphertext-period-match-v1.json`
- Ciphertext adjacent-contrast preregistration:
  `experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json`
- Ciphertext adjacent-contrast artifact:
  `experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json`
- Ciphertext transition preregistration:
  `experiments/preregistrations/ciphertext-transition-prior-v1.json`
- Ciphertext transition artifact:
  `experiments/predictions/ciphertext-transition-prior-v1.json`
- Ciphertext skip-transition preregistration:
  `experiments/preregistrations/ciphertext-skip-transition-v1.json`
- Ciphertext skip-transition artifact:
  `experiments/predictions/ciphertext-skip-transition-v1.json`
- Ciphertext turning-point preregistration:
  `experiments/preregistrations/ciphertext-turning-point-v1.json`
- Ciphertext turning-point artifact:
  `experiments/predictions/ciphertext-turning-point-v1.json`
- Ciphertext window-balance preregistration:
  `experiments/preregistrations/ciphertext-window-balance-v1.json`
- Ciphertext window-balance artifact:
  `experiments/predictions/ciphertext-window-balance-v1.json`
- Ciphertext residue-balance preregistration:
  `experiments/preregistrations/ciphertext-residue-balance-prior-v1.json`
- Ciphertext residue-balance artifact:
  `experiments/predictions/ciphertext-residue-balance-prior-v1.json`
- Ciphertext high-moduli residue-balance preregistration:
  `experiments/preregistrations/ciphertext-residue-balance-high-moduli-v1.json`
- Ciphertext high-moduli residue-balance artifact:
  `experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json`
- Ciphertext very-high-moduli residue-balance preregistration:
  `experiments/preregistrations/ciphertext-residue-balance-very-high-moduli-v1.json`
- Ciphertext very-high-moduli residue-balance artifact:
  `experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json`
- Ciphertext ultra-high-moduli residue-balance preregistration:
  `experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json`
- Ciphertext ultra-high-moduli residue-balance artifact:
  `experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json`
- Ciphertext extreme-moduli residue-balance preregistration:
  `experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json`
- Ciphertext extreme-moduli residue-balance artifact:
  `experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json`

## Observation

The CIA sculpture page text-version rendering records K4 as a short suffix on
one encoded-text line followed by three rendered lines. Before scoring, public
anchor positions are excluded, leaving the source-backed non-anchor positions:

`1, 4, 5, 36, 37, 97`

Each retained position has an explicit per-position source note in the
observation file. The observation is source-backed but does not contain
plaintext, key material, or a promoted candidate.

## Commands

```bash
cargo run --locked -- validate-period-observations \
  --artifact experiments/predictions/non-anchor-position-period-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-period-observations \
  --artifact experiments/predictions/non-anchor-position-period-v42.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v42.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-period-observations \
  --artifact experiments/predictions/non-anchor-position-period-v40.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v40.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-period-observations \
  --artifact experiments/predictions/non-anchor-position-period-v43.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v43.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-spacing-observations \
  --artifact experiments/predictions/non-anchor-position-spacing-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-mirror-observations \
  --artifact experiments/predictions/non-anchor-position-mirror-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-mirror-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-grid-observations \
  --artifact experiments/predictions/non-anchor-position-grid-layout-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-layout-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-grid-observations \
  --artifact experiments/predictions/non-anchor-position-grid-column-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-column-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-grid-observations \
  --artifact experiments/predictions/non-anchor-position-grid-compass-axis-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-tableau-hill-observations \
  --artifact experiments/predictions/tableau-hill-v1.json \
  --preregistration experiments/preregistrations/tableau-hill-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-prior-observations \
  --artifact experiments/predictions/ciphertext-structure-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-structure-prior-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-hotspot-observations \
  --artifact experiments/predictions/ciphertext-hotspot-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-hotspot-prior-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-rarity-observations \
  --artifact experiments/predictions/ciphertext-rarity-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-rarity-prior-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-repeat-distance-observations \
  --artifact experiments/predictions/ciphertext-repeat-distance-v1.json \
  --preregistration experiments/preregistrations/ciphertext-repeat-distance-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-period-match-observations \
  --artifact experiments/predictions/ciphertext-period-match-v1.json \
  --preregistration experiments/preregistrations/ciphertext-period-match-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-adjacent-contrast-observations \
  --artifact experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-transition-observations \
  --artifact experiments/predictions/ciphertext-transition-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-transition-prior-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-skip-transition-observations \
  --artifact experiments/predictions/ciphertext-skip-transition-v1.json \
  --preregistration experiments/preregistrations/ciphertext-skip-transition-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-turning-point-observations \
  --artifact experiments/predictions/ciphertext-turning-point-v1.json \
  --preregistration experiments/preregistrations/ciphertext-turning-point-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-window-balance-observations \
  --artifact experiments/predictions/ciphertext-window-balance-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-prior-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-high-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-very-high-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- validate-ciphertext-residue-balance-observations \
  --artifact experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json \
  --input experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --format json

cargo run --locked -- evaluate-period-prediction \
  --artifact experiments/predictions/non-anchor-position-period-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/period-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-period-prediction \
  --artifact experiments/predictions/non-anchor-position-period-v42.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v42.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/period-observations/cia-k4-row-boundaries-period5-v42 \
  --format json

cargo run --locked -- evaluate-period-prediction \
  --artifact experiments/predictions/non-anchor-position-period-v40.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v40.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/period-observations/cia-k4-row-boundaries-period3-v40 \
  --format json

cargo run --locked -- evaluate-period-prediction \
  --artifact experiments/predictions/non-anchor-position-period-v43.json \
  --preregistration experiments/preregistrations/non-anchor-position-period-v43.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/period-observations/cia-k4-row-boundaries-period14-v43 \
  --format json

cargo run --locked -- evaluate-spacing-prediction \
  --artifact experiments/predictions/non-anchor-position-spacing-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-spacing-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/spacing-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-mirror-prediction \
  --artifact experiments/predictions/non-anchor-position-mirror-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-mirror-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/mirror-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-grid-prediction \
  --artifact experiments/predictions/non-anchor-position-grid-layout-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-layout-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --edge-axis row \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/grid-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-grid-prediction \
  --artifact experiments/predictions/non-anchor-position-grid-column-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-column-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --edge-axis column \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/grid-observations/cia-k4-row-boundaries-column-v1 \
  --format json

cargo run --locked -- evaluate-grid-prediction \
  --artifact experiments/predictions/non-anchor-position-grid-compass-axis-v1.json \
  --preregistration experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --edge-axis compass-axis \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/grid-observations/cia-k4-row-boundaries-compass-axis-v1 \
  --format json

cargo run --locked -- evaluate-tableau-hill-prediction \
  --artifact experiments/predictions/tableau-hill-v1.json \
  --preregistration experiments/preregistrations/tableau-hill-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/tableau-hill-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-prior \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --prior-iterations 100000 \
  --iterations 100000 \
  --seed 67 \
  --prior-seed 67 \
  --output-dir results/ciphertext-prior-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-hotspot \
  --artifact experiments/predictions/ciphertext-hotspot-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-hotspot-prior-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-hotspot-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-rarity \
  --artifact experiments/predictions/ciphertext-rarity-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-rarity-prior-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-rarity-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-repeat-distance \
  --artifact experiments/predictions/ciphertext-repeat-distance-v1.json \
  --preregistration experiments/preregistrations/ciphertext-repeat-distance-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-repeat-distance-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-period-match \
  --artifact experiments/predictions/ciphertext-period-match-v1.json \
  --preregistration experiments/preregistrations/ciphertext-period-match-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-period-match-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-adjacent-contrast \
  --artifact experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-transition \
  --artifact experiments/predictions/ciphertext-transition-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-transition-prior-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-transition-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-skip-transition \
  --artifact experiments/predictions/ciphertext-skip-transition-v1.json \
  --preregistration experiments/preregistrations/ciphertext-skip-transition-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-skip-transition-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-turning-point \
  --artifact experiments/predictions/ciphertext-turning-point-v1.json \
  --preregistration experiments/preregistrations/ciphertext-turning-point-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-turning-point-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-window-balance \
  --artifact experiments/predictions/ciphertext-window-balance-v1.json \
  --preregistration experiments/preregistrations/ciphertext-window-balance-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-window-balance-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-prior-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-prior-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-high-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-high-moduli-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-very-high-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-very-high-moduli-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-ultra-high-moduli-v1 \
  --format json

cargo run --locked -- evaluate-ciphertext-residue-balance \
  --artifact experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json \
  --preregistration experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json \
  --positions-file experiments/position-observations/cia-k4-row-boundaries-v1.json \
  --iterations 100000 \
  --seed 67 \
  --output-dir results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-extreme-moduli-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/period-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/period-observations/cia-k4-row-boundaries-period5-v42 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/period-observations/cia-k4-row-boundaries-period3-v40 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/period-observations/cia-k4-row-boundaries-period14-v43 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/spacing-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/mirror-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/grid-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/grid-observations/cia-k4-row-boundaries-column-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/grid-observations/cia-k4-row-boundaries-compass-axis-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/tableau-hill-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-prior-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-hotspot-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-rarity-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-repeat-distance-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-period-match-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-transition-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-skip-transition-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-turning-point-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-window-balance-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-high-moduli-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-very-high-moduli-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-ultra-high-moduli-v1 \
  --format json

cargo run --locked -- validate-evaluation-archive \
  --input results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-extreme-moduli-v1 \
  --format json
```

All twenty-four observation validators accepted the observation file, and all twenty-four
archived evaluation directories passed `validate-evaluation-archive` locally.

## Results

| Family | Best Model | Observed Hits | Null Mean | Null SD | Empirical P | Promoted |
| --- | --- | --- | --- | --- | --- | --- |
| Period | period 2 residue 0 | 4/6 | 4.06 | 0.73 | 0.7897 | false |
| Period-3 | period 3 residue 0 | 4/6 | 3.19 | 0.72 | 0.2755 | false |
| Period-5 | period 5 residue 0 | 2/6 | 2.51 | 0.63 | 1.0000 | false |
| Period-14 | period 14 residue 0 | 1/6 | 1.71 | 0.56 | 1.0000 | false |
| Spacing | modulus 2 residue 1 | 8/15 pairs | 8.94 | 1.29 | 1.0000 | false |
| Mirror | mirror pairs | 1/3 pairs | 0.22 | 0.44 | 0.2090 | false |
| Grid row | 7x14 row edges | 1/6 | 0.74 | 0.78 | 0.5600 | false |
| Grid column | 7x14 column edges | 4/6 | 2.22 | 1.14 | 0.1303 | false |
| Grid compass-axis | 7x14 compass-axis positions | 1/6 | 1.97 | 1.11 | 0.9166 | false |
| Tableau/HILL | 7x14 row 1 concentration | 3/6 | 2.36 | 0.58 | 0.3311 | false |
| Ciphertext prior | ciphertext prior period 2 residue 0 | 4/6 | 3.91 | 0.77 | 0.6845 | false |
| Ciphertext hotspot | ciphertext hotspot positions | 0/6 | 1.64 | 1.05 | 1.0000 | false |
| Ciphertext rarity | rare ciphertext-letter positions | 2/6 | 1.64 | 1.05 | 0.5282 | false |
| Ciphertext repeat-distance | ciphertext repeat-distance positions | 2/6 | 1.64 | 1.05 | 0.5273 | false |
| Ciphertext period-match | ciphertext shifted same-letter period 2 endpoints | 1/6 | 1.61 | 0.73 | 0.9733 | false |
| Ciphertext adjacent-contrast | ciphertext adjacent-contrast positions | 2/6 | 1.64 | 1.05 | 0.5259 | false |
| Ciphertext transition | adjacent transition-pressure positions | 0/6 | 1.63 | 1.05 | 1.0000 | false |
| Ciphertext skip-transition | skip-transition positions | 0/6 | 1.64 | 1.05 | 1.0000 | false |
| Ciphertext turning-point | turning-point positions | 2/6 | 1.64 | 1.05 | 0.5247 | false |
| Ciphertext window-balance | ciphertext window-balance positions | 0/6 | 1.65 | 1.06 | 1.0000 | false |
| Ciphertext residue-balance | ciphertext residue-balance modulus 2 residue 0 | 4/6 | 3.55 | 0.86 | 0.4803 | false |
| Ciphertext high-moduli residue-balance | ciphertext residue-balance modulus 8 residue 3 | 2/6 | 1.76 | 0.67 | 0.6416 | false |
| Ciphertext very-high-moduli residue-balance | ciphertext residue-balance modulus 16 residue 0 | 2/6 | 1.28 | 0.62 | 0.3125 | false |
| Ciphertext ultra-high-moduli residue-balance | ciphertext residue-balance modulus 21 residue 12 | 1/6 | 1.01 | 0.60 | 0.8289 | false |
| Ciphertext extreme-moduli residue-balance | ciphertext residue-balance modulus 27 residue 8 | 1/6 | 0.92 | 0.59 | 0.7859 | false |

The grid row, grid column, and grid compass-axis artifacts are separately preregistered with
matching `grid_edge_axis` values, so each archive interprets only its fixed
axis. The column-edge archive found `4/6` hits at positions `1, 4, 5, 97`, but
the seeded same-size null still gives `p=0.1303`; this is source-backed
negative/non-significant evidence, not a promotion criterion. The compass-axis
archive found `1/6` hits at position `36`, with seeded same-size null
`p=0.9166`; this is also negative/non-significant evidence.

Interpretation: the source-backed row-boundary observation does not support the
committed period, period-3, period-5, period-14, spacing, mirror, grid-row, grid-column, grid-compass-axis, Tableau/HILL, ciphertext-prior,
ciphertext-hotspot, ciphertext-rarity, ciphertext-repeat-distance,
ciphertext-adjacent-contrast,
ciphertext-transition,
ciphertext-skip-transition, ciphertext-turning-point, ciphertext-window-balance, or
ciphertext-residue-balance targets, including the high-moduli,
very-high-moduli, ultra-high-moduli, and extreme-moduli residue-balance targets, beyond the
seeded null controls. This is negative evidence for this observation lane, not
a K4 solution.
