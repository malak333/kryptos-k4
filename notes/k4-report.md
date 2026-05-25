# Kryptos K4 Constraint Report

This report uses public anchors only and is not a claimed solution. Production readiness here means the local, source-grounded research CLI and release package are repeatable and bounded; it does not mean Kryptos K4 is solved or that any candidate plaintext, key, route, or method is promoted.

## Research Boundary and Production Readiness

- Evidence boundary: public ciphertext, public known-plaintext anchors, source provenance, deterministic controls, and pre-registered exploratory screens only.
- Research boundary: no generated plaintext is treated as decoded K4 text; all promoted-candidate flags remain false unless independent corroboration and stronger samples justify a future change.
- Production-readiness scope: local Rust CLI, report rendering, JSON output, candidate registry alignment, source packet/source registry field and access-date alignment, release preflight, and no-GitHub-Actions policy. External publication, peer review, and cryptanalytic validation remain outside this report.

## Feature Coverage

| Feature | Included result |
| --- | --- |
| `facts` | Ciphertext length, ciphertext, and evidence boundary. |
| `anchors` | Public known-plaintext anchors with positions, source IDs, confidence, claim type, and notes. |
| `constraints` | Per-anchor key fragments across supported alphabets and modes, with recurrence screens. |
| `key-fragments` | The same fragment rows are rendered in full for anchors and adjacent spans. |
| `test-key` | Proposed key material is transformed and compared against public span additive fragments at true K4 positions, with optional cyclic offset sweep and seeded sweep baseline. |
| `batch-test-keys` | CSV candidate rows are ranked with the same public-fragment checks and optional output artifacts. |
| `position-structure` | Candidate-independent residue/spacing control over public fragment positions. |
| `structural-models` | Pre-registered period-model controls over public fragment positions. |
| `validate-preregistration` | Research-lane gate for future source evidence or independent prediction targets. |
| `validate-prediction-artifact` | Gate confirming committed independent prediction artifacts still match their preregistration and deterministic generator. |
| `validate-period-observations` | Gate for source-backed independent position observations and optional prediction-artifact preregistration validation before period prediction scoring. |
| `period-prediction-plan` | Non-anchor residue-class target emission for a registered period, without scoring public fragment values. |
| `evaluate-period-prediction` | Independent-position evaluator for committed period prediction artifacts with best-of-period null controls, source-backed observation-file input, and optional artifact preregistration validation. |
| `baseline` | Seeded false-positive controls for anchors and spans across all supported alphabets. |
| `hypotheses` | Ranked source-grounded hypotheses with facts, assumptions, falsification tests, and risks. |
| `candidate-sequences` | Pre-registered contextual sequences and score results. |
| `routes` | Bounded named route experiments with identity, reverse, and seeded-random baselines. |
| `findings` | Reproducible findings ledger with sources, transformations, baselines, interpretation, and next tests. |
| `sources` | Source provenance records and allowed-use notes in Markdown or JSON. |
| `release-check` | Local release preflight results, including no-GitHub-Actions, candidate CSV/registry alignment, and source-packet/source-registry field and latest-access-date alignment gates. |
| `export-data` | Covered by the source data rendered here; the command writes ciphertext, anchor, and source JSON files. |

## Ciphertext

- Length: 97
- Text: `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`

## Known Anchors

| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Source IDs | Confidence | Claim Type | Note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EAST` | `FLRV` | 21-24 | 22-25 | `elonka-kryptos` | high | public-anchor | Publicly released after Sanborn correspondence, summarized by Elonka Dunin. |
| `NORTHEAST` | `QQPRNGKSS` | 25-33 | 26-34 | `elonka-kryptos` | high | public-anchor | Sanborn's 2020 public clue, summarized by major reporting and Elonka Dunin. |
| `BERLIN` | `NYPVTT` | 63-68 | 64-69 | `elonka-kryptos` | high | public-anchor | Sanborn's 2010 public clue. |
| `CLOCK` | `MZFPK` | 69-73 | 70-74 | `elonka-kryptos`, `scientific-american-2025` | high | public-anchor | Sanborn's 2014 public clue. |

## Known Plaintext Spans

| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Anchors |
| --- | --- | --- | --- | --- |
| `EASTNORTHEAST` | `FLRVQQPRNGKSS` | 21-33 | 22-34 | `EAST`, `NORTHEAST` |
| `BERLINCLOCK` | `NYPVTTMZFPK` | 63-73 | 64-74 | `BERLIN`, `CLOCK` |

## Constraint Fragments

### EAST / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `B` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 9 | `J` |
| 23 | `A` | `L` | AdditiveKey | 11 | `L` |
| 23 | `A` | `L` | SubtractiveKey | 15 | `P` |
| 23 | `A` | `L` | BeaufortKey | 11 | `L` |
| 24 | `S` | `R` | AdditiveKey | 25 | `Z` |
| 24 | `S` | `R` | SubtractiveKey | 1 | `B` |
| 24 | `S` | `R` | BeaufortKey | 9 | `J` |
| 25 | `T` | `V` | AdditiveKey | 2 | `C` |
| 25 | `T` | `V` | SubtractiveKey | 24 | `Y` |
| 25 | `T` | `V` | BeaufortKey | 14 | `O` |

Recurrence screen: 0/2 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.2. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EAST / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `R` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 23 | `W` |
| 23 | `A` | `L` | AdditiveKey | 10 | `D` |
| 23 | `A` | `L` | SubtractiveKey | 16 | `J` |
| 23 | `A` | `L` | BeaufortKey | 24 | `X` |
| 24 | `S` | `R` | AdditiveKey | 21 | `U` |
| 24 | `S` | `R` | SubtractiveKey | 5 | `O` |
| 24 | `S` | `R` | BeaufortKey | 7 | `A` |
| 25 | `T` | `V` | AdditiveKey | 18 | `M` |
| 25 | `T` | `V` | SubtractiveKey | 8 | `B` |
| 25 | `T` | `V` | BeaufortKey | 0 | `K` |

Recurrence screen: 1/2 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.2. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EAST / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 25 | `K` |
| 22 | `E` | `F` | SubtractiveKey | 1 | `X` |
| 22 | `E` | `F` | BeaufortKey | 1 | `X` |
| 23 | `A` | `L` | AdditiveKey | 16 | `C` |
| 23 | `A` | `L` | SubtractiveKey | 10 | `I` |
| 23 | `A` | `L` | BeaufortKey | 0 | `Z` |
| 24 | `S` | `R` | AdditiveKey | 5 | `Q` |
| 24 | `S` | `R` | SubtractiveKey | 21 | `T` |
| 24 | `S` | `R` | BeaufortKey | 17 | `B` |
| 25 | `T` | `V` | AdditiveKey | 8 | `L` |
| 25 | `T` | `V` | SubtractiveKey | 18 | `A` |
| 25 | `T` | `V` | BeaufortKey | 24 | `R` |

Recurrence screen: 0/2 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.2. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### NORTHEAST / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 26 | `N` | `Q` | AdditiveKey | 3 | `D` |
| 26 | `N` | `Q` | SubtractiveKey | 23 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 3 | `D` |
| 27 | `O` | `Q` | AdditiveKey | 2 | `C` |
| 27 | `O` | `Q` | SubtractiveKey | 24 | `Y` |
| 27 | `O` | `Q` | BeaufortKey | 4 | `E` |
| 28 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 28 | `R` | `P` | BeaufortKey | 6 | `G` |
| 29 | `T` | `R` | AdditiveKey | 24 | `Y` |
| 29 | `T` | `R` | SubtractiveKey | 2 | `C` |
| 29 | `T` | `R` | BeaufortKey | 10 | `K` |
| 30 | `H` | `N` | AdditiveKey | 6 | `G` |
| 30 | `H` | `N` | SubtractiveKey | 20 | `U` |
| 30 | `H` | `N` | BeaufortKey | 20 | `U` |
| 31 | `E` | `G` | AdditiveKey | 2 | `C` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `Y` |
| 31 | `E` | `G` | BeaufortKey | 10 | `K` |
| 32 | `A` | `K` | AdditiveKey | 10 | `K` |
| 32 | `A` | `K` | SubtractiveKey | 16 | `Q` |
| 32 | `A` | `K` | BeaufortKey | 10 | `K` |
| 33 | `S` | `S` | AdditiveKey | 0 | `A` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `A` |
| 33 | `S` | `S` | BeaufortKey | 10 | `K` |
| 34 | `T` | `S` | AdditiveKey | 25 | `Z` |
| 34 | `T` | `S` | SubtractiveKey | 1 | `B` |
| 34 | `T` | `S` | BeaufortKey | 11 | `L` |

Recurrence screen: 0/7 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.7. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### NORTHEAST / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 26 | `N` | `Q` | AdditiveKey | 1 | `R` |
| 26 | `N` | `Q` | SubtractiveKey | 25 | `Z` |
| 26 | `N` | `Q` | BeaufortKey | 13 | `G` |
| 27 | `O` | `Q` | AdditiveKey | 15 | `I` |
| 27 | `O` | `Q` | SubtractiveKey | 11 | `E` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `Z` |
| 28 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 28 | `R` | `P` | BeaufortKey | 4 | `T` |
| 29 | `T` | `R` | AdditiveKey | 23 | `W` |
| 29 | `T` | `R` | SubtractiveKey | 3 | `P` |
| 29 | `T` | `R` | BeaufortKey | 5 | `O` |
| 30 | `H` | `N` | AdditiveKey | 5 | `O` |
| 30 | `H` | `N` | SubtractiveKey | 21 | `U` |
| 30 | `H` | `N` | BeaufortKey | 7 | `A` |
| 31 | `E` | `G` | AdditiveKey | 2 | `Y` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `X` |
| 31 | `E` | `G` | BeaufortKey | 24 | `X` |
| 32 | `A` | `K` | AdditiveKey | 19 | `N` |
| 32 | `A` | `K` | SubtractiveKey | 7 | `A` |
| 32 | `A` | `K` | BeaufortKey | 7 | `A` |
| 33 | `S` | `S` | AdditiveKey | 0 | `K` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `K` |
| 33 | `S` | `S` | BeaufortKey | 12 | `F` |
| 34 | `T` | `S` | AdditiveKey | 2 | `Y` |
| 34 | `T` | `S` | SubtractiveKey | 24 | `X` |
| 34 | `T` | `S` | BeaufortKey | 10 | `D` |

Recurrence screen: 1/7 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.7. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### NORTHEAST / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 26 | `N` | `Q` | AdditiveKey | 25 | `K` |
| 26 | `N` | `Q` | SubtractiveKey | 1 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 11 | `H` |
| 27 | `O` | `Q` | AdditiveKey | 11 | `H` |
| 27 | `O` | `Q` | SubtractiveKey | 15 | `D` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `K` |
| 28 | `R` | `P` | AdditiveKey | 24 | `R` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 28 | `R` | `P` | BeaufortKey | 20 | `O` |
| 29 | `T` | `R` | AdditiveKey | 3 | `V` |
| 29 | `T` | `R` | SubtractiveKey | 23 | `Y` |
| 29 | `T` | `R` | BeaufortKey | 19 | `S` |
| 30 | `H` | `N` | AdditiveKey | 21 | `T` |
| 30 | `H` | `N` | SubtractiveKey | 5 | `Q` |
| 30 | `H` | `N` | BeaufortKey | 17 | `B` |
| 31 | `E` | `G` | AdditiveKey | 24 | `R` |
| 31 | `E` | `G` | SubtractiveKey | 2 | `W` |
| 31 | `E` | `G` | BeaufortKey | 0 | `Z` |
| 32 | `A` | `K` | AdditiveKey | 7 | `M` |
| 32 | `A` | `K` | SubtractiveKey | 19 | `S` |
| 32 | `A` | `K` | BeaufortKey | 17 | `B` |
| 33 | `S` | `S` | AdditiveKey | 0 | `Z` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `Z` |
| 33 | `S` | `S` | BeaufortKey | 12 | `G` |
| 34 | `T` | `S` | AdditiveKey | 24 | `R` |
| 34 | `T` | `S` | SubtractiveKey | 2 | `W` |
| 34 | `T` | `S` | BeaufortKey | 14 | `E` |

Recurrence screen: 1/7 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.7. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLIN / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 12 | `M` |
| 64 | `B` | `N` | SubtractiveKey | 14 | `O` |
| 64 | `B` | `N` | BeaufortKey | 14 | `O` |
| 65 | `E` | `Y` | AdditiveKey | 20 | `U` |
| 65 | `E` | `Y` | SubtractiveKey | 6 | `G` |
| 65 | `E` | `Y` | BeaufortKey | 2 | `C` |
| 66 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 66 | `R` | `P` | BeaufortKey | 6 | `G` |
| 67 | `L` | `V` | AdditiveKey | 10 | `K` |
| 67 | `L` | `V` | SubtractiveKey | 16 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 6 | `G` |
| 68 | `I` | `T` | AdditiveKey | 11 | `L` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `P` |
| 68 | `I` | `T` | BeaufortKey | 1 | `B` |
| 69 | `N` | `T` | AdditiveKey | 6 | `G` |
| 69 | `N` | `T` | SubtractiveKey | 20 | `U` |
| 69 | `N` | `T` | BeaufortKey | 6 | `G` |

Recurrence screen: 0/4 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.4. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLIN / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 11 | `E` |
| 64 | `B` | `N` | SubtractiveKey | 15 | `I` |
| 64 | `B` | `N` | BeaufortKey | 1 | `R` |
| 65 | `E` | `Y` | AdditiveKey | 17 | `L` |
| 65 | `E` | `Y` | SubtractiveKey | 9 | `C` |
| 65 | `E` | `Y` | BeaufortKey | 13 | `G` |
| 66 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 66 | `R` | `P` | BeaufortKey | 4 | `T` |
| 67 | `L` | `V` | AdditiveKey | 5 | `O` |
| 67 | `L` | `V` | SubtractiveKey | 21 | `U` |
| 67 | `L` | `V` | BeaufortKey | 13 | `G` |
| 68 | `I` | `T` | AdditiveKey | 15 | `I` |
| 68 | `I` | `T` | SubtractiveKey | 11 | `E` |
| 68 | `I` | `T` | BeaufortKey | 19 | `N` |
| 69 | `N` | `T` | AdditiveKey | 11 | `E` |
| 69 | `N` | `T` | SubtractiveKey | 15 | `I` |
| 69 | `N` | `T` | BeaufortKey | 23 | `W` |

Recurrence screen: 0/4 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.4. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLIN / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 15 | `D` |
| 64 | `B` | `N` | SubtractiveKey | 11 | `H` |
| 64 | `B` | `N` | BeaufortKey | 23 | `Y` |
| 65 | `E` | `Y` | AdditiveKey | 9 | `J` |
| 65 | `E` | `Y` | SubtractiveKey | 17 | `B` |
| 65 | `E` | `Y` | BeaufortKey | 11 | `H` |
| 66 | `R` | `P` | AdditiveKey | 24 | `R` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 66 | `R` | `P` | BeaufortKey | 20 | `O` |
| 67 | `L` | `V` | AdditiveKey | 21 | `T` |
| 67 | `L` | `V` | SubtractiveKey | 5 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 11 | `H` |
| 68 | `I` | `T` | AdditiveKey | 11 | `H` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `D` |
| 68 | `I` | `T` | BeaufortKey | 5 | `Q` |
| 69 | `N` | `T` | AdditiveKey | 15 | `D` |
| 69 | `N` | `T` | SubtractiveKey | 11 | `H` |
| 69 | `N` | `T` | BeaufortKey | 1 | `X` |

Recurrence screen: 1/4 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.4. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### CLOCK / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 70 | `C` | `M` | AdditiveKey | 10 | `K` |
| 70 | `C` | `M` | SubtractiveKey | 16 | `Q` |
| 70 | `C` | `M` | BeaufortKey | 14 | `O` |
| 71 | `L` | `Z` | AdditiveKey | 14 | `O` |
| 71 | `L` | `Z` | SubtractiveKey | 12 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 10 | `K` |
| 72 | `O` | `F` | AdditiveKey | 17 | `R` |
| 72 | `O` | `F` | SubtractiveKey | 9 | `J` |
| 72 | `O` | `F` | BeaufortKey | 19 | `T` |
| 73 | `C` | `P` | AdditiveKey | 13 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 13 | `N` |
| 73 | `C` | `P` | BeaufortKey | 17 | `R` |
| 74 | `K` | `K` | AdditiveKey | 0 | `A` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `A` |
| 74 | `K` | `K` | BeaufortKey | 20 | `U` |

Recurrence screen: 1/3 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.3. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### CLOCK / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 70 | `C` | `M` | AdditiveKey | 9 | `C` |
| 70 | `C` | `M` | SubtractiveKey | 17 | `L` |
| 70 | `C` | `M` | BeaufortKey | 1 | `R` |
| 71 | `L` | `Z` | AdditiveKey | 8 | `B` |
| 71 | `L` | `Z` | SubtractiveKey | 18 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 16 | `J` |
| 72 | `O` | `F` | AdditiveKey | 7 | `A` |
| 72 | `O` | `F` | SubtractiveKey | 19 | `N` |
| 72 | `O` | `F` | BeaufortKey | 17 | `L` |
| 73 | `C` | `P` | AdditiveKey | 20 | `Q` |
| 73 | `C` | `P` | SubtractiveKey | 6 | `S` |
| 73 | `C` | `P` | BeaufortKey | 12 | `F` |
| 74 | `K` | `K` | AdditiveKey | 0 | `K` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `K` |
| 74 | `K` | `K` | BeaufortKey | 0 | `K` |

Recurrence screen: 1/3 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.3. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### CLOCK / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 70 | `C` | `M` | AdditiveKey | 17 | `B` |
| 70 | `C` | `M` | SubtractiveKey | 9 | `J` |
| 70 | `C` | `M` | BeaufortKey | 23 | `Y` |
| 71 | `L` | `Z` | AdditiveKey | 18 | `A` |
| 71 | `L` | `Z` | SubtractiveKey | 8 | `L` |
| 71 | `L` | `Z` | BeaufortKey | 8 | `L` |
| 72 | `O` | `F` | AdditiveKey | 19 | `S` |
| 72 | `O` | `F` | SubtractiveKey | 7 | `M` |
| 72 | `O` | `F` | BeaufortKey | 7 | `M` |
| 73 | `C` | `P` | AdditiveKey | 6 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 20 | `O` |
| 73 | `C` | `P` | BeaufortKey | 12 | `G` |
| 74 | `K` | `K` | AdditiveKey | 0 | `Z` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `Z` |
| 74 | `K` | `K` | BeaufortKey | 24 | `R` |

Recurrence screen: 0/3 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.3. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.


## Span Constraint Fragments

### EASTNORTHEAST / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `B` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 9 | `J` |
| 23 | `A` | `L` | AdditiveKey | 11 | `L` |
| 23 | `A` | `L` | SubtractiveKey | 15 | `P` |
| 23 | `A` | `L` | BeaufortKey | 11 | `L` |
| 24 | `S` | `R` | AdditiveKey | 25 | `Z` |
| 24 | `S` | `R` | SubtractiveKey | 1 | `B` |
| 24 | `S` | `R` | BeaufortKey | 9 | `J` |
| 25 | `T` | `V` | AdditiveKey | 2 | `C` |
| 25 | `T` | `V` | SubtractiveKey | 24 | `Y` |
| 25 | `T` | `V` | BeaufortKey | 14 | `O` |
| 26 | `N` | `Q` | AdditiveKey | 3 | `D` |
| 26 | `N` | `Q` | SubtractiveKey | 23 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 3 | `D` |
| 27 | `O` | `Q` | AdditiveKey | 2 | `C` |
| 27 | `O` | `Q` | SubtractiveKey | 24 | `Y` |
| 27 | `O` | `Q` | BeaufortKey | 4 | `E` |
| 28 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 28 | `R` | `P` | BeaufortKey | 6 | `G` |
| 29 | `T` | `R` | AdditiveKey | 24 | `Y` |
| 29 | `T` | `R` | SubtractiveKey | 2 | `C` |
| 29 | `T` | `R` | BeaufortKey | 10 | `K` |
| 30 | `H` | `N` | AdditiveKey | 6 | `G` |
| 30 | `H` | `N` | SubtractiveKey | 20 | `U` |
| 30 | `H` | `N` | BeaufortKey | 20 | `U` |
| 31 | `E` | `G` | AdditiveKey | 2 | `C` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `Y` |
| 31 | `E` | `G` | BeaufortKey | 10 | `K` |
| 32 | `A` | `K` | AdditiveKey | 10 | `K` |
| 32 | `A` | `K` | SubtractiveKey | 16 | `Q` |
| 32 | `A` | `K` | BeaufortKey | 10 | `K` |
| 33 | `S` | `S` | AdditiveKey | 0 | `A` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `A` |
| 33 | `S` | `S` | BeaufortKey | 10 | `K` |
| 34 | `T` | `S` | AdditiveKey | 25 | `Z` |
| 34 | `T` | `S` | SubtractiveKey | 1 | `B` |
| 34 | `T` | `S` | BeaufortKey | 11 | `L` |

Recurrence screen: 0/11 local additive triples matched generic mod-10 recurrence. Expected random matches: 1.1. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EASTNORTHEAST / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 1 | `R` |
| 22 | `E` | `F` | SubtractiveKey | 25 | `Z` |
| 22 | `E` | `F` | BeaufortKey | 23 | `W` |
| 23 | `A` | `L` | AdditiveKey | 10 | `D` |
| 23 | `A` | `L` | SubtractiveKey | 16 | `J` |
| 23 | `A` | `L` | BeaufortKey | 24 | `X` |
| 24 | `S` | `R` | AdditiveKey | 21 | `U` |
| 24 | `S` | `R` | SubtractiveKey | 5 | `O` |
| 24 | `S` | `R` | BeaufortKey | 7 | `A` |
| 25 | `T` | `V` | AdditiveKey | 18 | `M` |
| 25 | `T` | `V` | SubtractiveKey | 8 | `B` |
| 25 | `T` | `V` | BeaufortKey | 0 | `K` |
| 26 | `N` | `Q` | AdditiveKey | 1 | `R` |
| 26 | `N` | `Q` | SubtractiveKey | 25 | `Z` |
| 26 | `N` | `Q` | BeaufortKey | 13 | `G` |
| 27 | `O` | `Q` | AdditiveKey | 15 | `I` |
| 27 | `O` | `Q` | SubtractiveKey | 11 | `E` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `Z` |
| 28 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 28 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 28 | `R` | `P` | BeaufortKey | 4 | `T` |
| 29 | `T` | `R` | AdditiveKey | 23 | `W` |
| 29 | `T` | `R` | SubtractiveKey | 3 | `P` |
| 29 | `T` | `R` | BeaufortKey | 5 | `O` |
| 30 | `H` | `N` | AdditiveKey | 5 | `O` |
| 30 | `H` | `N` | SubtractiveKey | 21 | `U` |
| 30 | `H` | `N` | BeaufortKey | 7 | `A` |
| 31 | `E` | `G` | AdditiveKey | 2 | `Y` |
| 31 | `E` | `G` | SubtractiveKey | 24 | `X` |
| 31 | `E` | `G` | BeaufortKey | 24 | `X` |
| 32 | `A` | `K` | AdditiveKey | 19 | `N` |
| 32 | `A` | `K` | SubtractiveKey | 7 | `A` |
| 32 | `A` | `K` | BeaufortKey | 7 | `A` |
| 33 | `S` | `S` | AdditiveKey | 0 | `K` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `K` |
| 33 | `S` | `S` | BeaufortKey | 12 | `F` |
| 34 | `T` | `S` | AdditiveKey | 2 | `Y` |
| 34 | `T` | `S` | SubtractiveKey | 24 | `X` |
| 34 | `T` | `S` | BeaufortKey | 10 | `D` |

Recurrence screen: 2/11 local additive triples matched generic mod-10 recurrence. Expected random matches: 1.1. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### EASTNORTHEAST / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 22 | `E` | `F` | AdditiveKey | 25 | `K` |
| 22 | `E` | `F` | SubtractiveKey | 1 | `X` |
| 22 | `E` | `F` | BeaufortKey | 1 | `X` |
| 23 | `A` | `L` | AdditiveKey | 16 | `C` |
| 23 | `A` | `L` | SubtractiveKey | 10 | `I` |
| 23 | `A` | `L` | BeaufortKey | 0 | `Z` |
| 24 | `S` | `R` | AdditiveKey | 5 | `Q` |
| 24 | `S` | `R` | SubtractiveKey | 21 | `T` |
| 24 | `S` | `R` | BeaufortKey | 17 | `B` |
| 25 | `T` | `V` | AdditiveKey | 8 | `L` |
| 25 | `T` | `V` | SubtractiveKey | 18 | `A` |
| 25 | `T` | `V` | BeaufortKey | 24 | `R` |
| 26 | `N` | `Q` | AdditiveKey | 25 | `K` |
| 26 | `N` | `Q` | SubtractiveKey | 1 | `X` |
| 26 | `N` | `Q` | BeaufortKey | 11 | `H` |
| 27 | `O` | `Q` | AdditiveKey | 11 | `H` |
| 27 | `O` | `Q` | SubtractiveKey | 15 | `D` |
| 27 | `O` | `Q` | BeaufortKey | 25 | `K` |
| 28 | `R` | `P` | AdditiveKey | 24 | `R` |
| 28 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 28 | `R` | `P` | BeaufortKey | 20 | `O` |
| 29 | `T` | `R` | AdditiveKey | 3 | `V` |
| 29 | `T` | `R` | SubtractiveKey | 23 | `Y` |
| 29 | `T` | `R` | BeaufortKey | 19 | `S` |
| 30 | `H` | `N` | AdditiveKey | 21 | `T` |
| 30 | `H` | `N` | SubtractiveKey | 5 | `Q` |
| 30 | `H` | `N` | BeaufortKey | 17 | `B` |
| 31 | `E` | `G` | AdditiveKey | 24 | `R` |
| 31 | `E` | `G` | SubtractiveKey | 2 | `W` |
| 31 | `E` | `G` | BeaufortKey | 0 | `Z` |
| 32 | `A` | `K` | AdditiveKey | 7 | `M` |
| 32 | `A` | `K` | SubtractiveKey | 19 | `S` |
| 32 | `A` | `K` | BeaufortKey | 17 | `B` |
| 33 | `S` | `S` | AdditiveKey | 0 | `Z` |
| 33 | `S` | `S` | SubtractiveKey | 0 | `Z` |
| 33 | `S` | `S` | BeaufortKey | 12 | `G` |
| 34 | `T` | `S` | AdditiveKey | 24 | `R` |
| 34 | `T` | `S` | SubtractiveKey | 2 | `W` |
| 34 | `T` | `S` | BeaufortKey | 14 | `E` |

Recurrence screen: 1/11 local additive triples matched generic mod-10 recurrence. Expected random matches: 1.1. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLINCLOCK / Standard

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 12 | `M` |
| 64 | `B` | `N` | SubtractiveKey | 14 | `O` |
| 64 | `B` | `N` | BeaufortKey | 14 | `O` |
| 65 | `E` | `Y` | AdditiveKey | 20 | `U` |
| 65 | `E` | `Y` | SubtractiveKey | 6 | `G` |
| 65 | `E` | `Y` | BeaufortKey | 2 | `C` |
| 66 | `R` | `P` | AdditiveKey | 24 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `C` |
| 66 | `R` | `P` | BeaufortKey | 6 | `G` |
| 67 | `L` | `V` | AdditiveKey | 10 | `K` |
| 67 | `L` | `V` | SubtractiveKey | 16 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 6 | `G` |
| 68 | `I` | `T` | AdditiveKey | 11 | `L` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `P` |
| 68 | `I` | `T` | BeaufortKey | 1 | `B` |
| 69 | `N` | `T` | AdditiveKey | 6 | `G` |
| 69 | `N` | `T` | SubtractiveKey | 20 | `U` |
| 69 | `N` | `T` | BeaufortKey | 6 | `G` |
| 70 | `C` | `M` | AdditiveKey | 10 | `K` |
| 70 | `C` | `M` | SubtractiveKey | 16 | `Q` |
| 70 | `C` | `M` | BeaufortKey | 14 | `O` |
| 71 | `L` | `Z` | AdditiveKey | 14 | `O` |
| 71 | `L` | `Z` | SubtractiveKey | 12 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 10 | `K` |
| 72 | `O` | `F` | AdditiveKey | 17 | `R` |
| 72 | `O` | `F` | SubtractiveKey | 9 | `J` |
| 72 | `O` | `F` | BeaufortKey | 19 | `T` |
| 73 | `C` | `P` | AdditiveKey | 13 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 13 | `N` |
| 73 | `C` | `P` | BeaufortKey | 17 | `R` |
| 74 | `K` | `K` | AdditiveKey | 0 | `A` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `A` |
| 74 | `K` | `K` | BeaufortKey | 20 | `U` |

Recurrence screen: 1/9 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.9. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLINCLOCK / Kryptos

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 11 | `E` |
| 64 | `B` | `N` | SubtractiveKey | 15 | `I` |
| 64 | `B` | `N` | BeaufortKey | 1 | `R` |
| 65 | `E` | `Y` | AdditiveKey | 17 | `L` |
| 65 | `E` | `Y` | SubtractiveKey | 9 | `C` |
| 65 | `E` | `Y` | BeaufortKey | 13 | `G` |
| 66 | `R` | `P` | AdditiveKey | 2 | `Y` |
| 66 | `R` | `P` | SubtractiveKey | 24 | `X` |
| 66 | `R` | `P` | BeaufortKey | 4 | `T` |
| 67 | `L` | `V` | AdditiveKey | 5 | `O` |
| 67 | `L` | `V` | SubtractiveKey | 21 | `U` |
| 67 | `L` | `V` | BeaufortKey | 13 | `G` |
| 68 | `I` | `T` | AdditiveKey | 15 | `I` |
| 68 | `I` | `T` | SubtractiveKey | 11 | `E` |
| 68 | `I` | `T` | BeaufortKey | 19 | `N` |
| 69 | `N` | `T` | AdditiveKey | 11 | `E` |
| 69 | `N` | `T` | SubtractiveKey | 15 | `I` |
| 69 | `N` | `T` | BeaufortKey | 23 | `W` |
| 70 | `C` | `M` | AdditiveKey | 9 | `C` |
| 70 | `C` | `M` | SubtractiveKey | 17 | `L` |
| 70 | `C` | `M` | BeaufortKey | 1 | `R` |
| 71 | `L` | `Z` | AdditiveKey | 8 | `B` |
| 71 | `L` | `Z` | SubtractiveKey | 18 | `M` |
| 71 | `L` | `Z` | BeaufortKey | 16 | `J` |
| 72 | `O` | `F` | AdditiveKey | 7 | `A` |
| 72 | `O` | `F` | SubtractiveKey | 19 | `N` |
| 72 | `O` | `F` | BeaufortKey | 17 | `L` |
| 73 | `C` | `P` | AdditiveKey | 20 | `Q` |
| 73 | `C` | `P` | SubtractiveKey | 6 | `S` |
| 73 | `C` | `P` | BeaufortKey | 12 | `F` |
| 74 | `K` | `K` | AdditiveKey | 0 | `K` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `K` |
| 74 | `K` | `K` | BeaufortKey | 0 | `K` |

Recurrence screen: 1/9 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.9. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

### BERLINCLOCK / KryptosReversed

| Pos | P | C | Mode | Value | Symbol |
| --- | --- | --- | --- | --- | --- |
| 64 | `B` | `N` | AdditiveKey | 15 | `D` |
| 64 | `B` | `N` | SubtractiveKey | 11 | `H` |
| 64 | `B` | `N` | BeaufortKey | 23 | `Y` |
| 65 | `E` | `Y` | AdditiveKey | 9 | `J` |
| 65 | `E` | `Y` | SubtractiveKey | 17 | `B` |
| 65 | `E` | `Y` | BeaufortKey | 11 | `H` |
| 66 | `R` | `P` | AdditiveKey | 24 | `R` |
| 66 | `R` | `P` | SubtractiveKey | 2 | `W` |
| 66 | `R` | `P` | BeaufortKey | 20 | `O` |
| 67 | `L` | `V` | AdditiveKey | 21 | `T` |
| 67 | `L` | `V` | SubtractiveKey | 5 | `Q` |
| 67 | `L` | `V` | BeaufortKey | 11 | `H` |
| 68 | `I` | `T` | AdditiveKey | 11 | `H` |
| 68 | `I` | `T` | SubtractiveKey | 15 | `D` |
| 68 | `I` | `T` | BeaufortKey | 5 | `Q` |
| 69 | `N` | `T` | AdditiveKey | 15 | `D` |
| 69 | `N` | `T` | SubtractiveKey | 11 | `H` |
| 69 | `N` | `T` | BeaufortKey | 1 | `X` |
| 70 | `C` | `M` | AdditiveKey | 17 | `B` |
| 70 | `C` | `M` | SubtractiveKey | 9 | `J` |
| 70 | `C` | `M` | BeaufortKey | 23 | `Y` |
| 71 | `L` | `Z` | AdditiveKey | 18 | `A` |
| 71 | `L` | `Z` | SubtractiveKey | 8 | `L` |
| 71 | `L` | `Z` | BeaufortKey | 8 | `L` |
| 72 | `O` | `F` | AdditiveKey | 19 | `S` |
| 72 | `O` | `F` | SubtractiveKey | 7 | `M` |
| 72 | `O` | `F` | BeaufortKey | 7 | `M` |
| 73 | `C` | `P` | AdditiveKey | 6 | `N` |
| 73 | `C` | `P` | SubtractiveKey | 20 | `O` |
| 73 | `C` | `P` | BeaufortKey | 12 | `G` |
| 74 | `K` | `K` | AdditiveKey | 0 | `Z` |
| 74 | `K` | `K` | SubtractiveKey | 0 | `Z` |
| 74 | `K` | `K` | BeaufortKey | 24 | `R` |

Recurrence screen: 1/9 local additive triples matched generic mod-10 recurrence. Expected random matches: 0.9. Promoted: false. Warning: Exploratory only; do not promote without larger samples and baselines.

## Ranked Hypotheses

1. **Gromark-like or running-key additive system (H1)**
   - Supporting facts: Bean's HistoCrypt abstract reports one-to-one evidence and identifies Gromark as a possible method family.
   - Required assumptions: K4 uses a keyed alphabet and running numeric key stream or adjacent additive construction.
   - Test: Derive public-anchor key fragments and check whether they can coexist under Gromark-style recurrence rules.
   - Risk: Flexible additive models can be overfit to known anchors.
2. **Kryptos-alphabet Vigenere descendant with added transformation (H2)**
   - Supporting facts: K1 and K2 use Vigenere-like mechanics with the Kryptos alphabet.
   - Required assumptions: K4 preserves family resemblance while adding a new key schedule, route, or preprocessing layer.
   - Test: Compute anchor-implied key letters for supported alphabets and reject structureless fragments.
   - Risk: Prior-method bias may obscure a deliberate departure from K1/K2.
3. **Hybrid substitution plus route or matrix transposition (H3)**
   - Supporting facts: CIA says earlier sections combine chart and matrix systems; K3 uses transposition-like behavior.
   - Required assumptions: K4 combines a one-to-one layer with a stable route or matrix permutation.
   - Test: Pre-register route families and test whether one permutation improves fragment coherence.
   - Risk: Route spaces are large and can create false positives.
4. **Berlin World Clock, compass, or directional mechanism (H4)**
   - Supporting facts: Sanborn clarified BERLINCLOCK points to Berlin's World Clock; known anchors include EAST and NORTHEAST.
   - Required assumptions: Clock or compass data contributes to key generation, ordering, or validation.
   - Test: Define source-derived numeric sequences before checking them against anchor fragments.
   - Risk: The clock clue is highly ambiguous without a pre-registered mapping.
5. **Egypt 1986 or Berlin Wall 1989 event-timeline key material (H5)**
   - Supporting facts: 2025 reporting says both events figure in the solution.
   - Required assumptions: The events provide constrained key words, dates, places, routes, or ordering rules.
   - Test: Pre-register a small event-key list from strict sources and test without ad hoc expansion.
   - Risk: Underspecified source material invites unconstrained key hunting.

## Baseline Controls

Baseline output is a false-positive control, not a claimed solution. Target: all; alphabet: all; iterations: 10000; seed: 42.

| Target | Kind | Alphabet | Observed | Triples | Null Mean | Null SD | Empirical P | Adjusted P | Promoted | Warning |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EAST | anchor | Standard | 0 | 2 | 0.17 | 0.37 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EAST | anchor | Kryptos | 1 | 2 | 0.33 | 0.47 | 0.3331 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EAST | anchor | KryptosReversed | 0 | 2 | 0.00 | 0.00 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| NORTHEAST | anchor | Standard | 0 | 7 | 0.56 | 0.72 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| NORTHEAST | anchor | Kryptos | 1 | 7 | 0.69 | 0.78 | 0.5124 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| NORTHEAST | anchor | KryptosReversed | 1 | 7 | 0.82 | 0.84 | 0.5857 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLIN | anchor | Standard | 0 | 4 | 0.20 | 0.44 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLIN | anchor | Kryptos | 0 | 4 | 0.33 | 0.49 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLIN | anchor | KryptosReversed | 1 | 4 | 0.53 | 0.60 | 0.4776 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| CLOCK | anchor | Standard | 1 | 3 | 0.30 | 0.52 | 0.2664 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| CLOCK | anchor | Kryptos | 1 | 3 | 0.10 | 0.30 | 0.1019 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| CLOCK | anchor | KryptosReversed | 0 | 3 | 0.19 | 0.43 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EASTNORTHEAST | span | Standard | 0 | 11 | 1.00 | 0.94 | 1.0000 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EASTNORTHEAST | span | Kryptos | 2 | 11 | 1.14 | 1.00 | 0.3150 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| EASTNORTHEAST | span | KryptosReversed | 1 | 11 | 1.12 | 0.99 | 0.6964 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLINCLOCK | span | Standard | 1 | 9 | 0.79 | 0.83 | 0.5702 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLINCLOCK | span | Kryptos | 1 | 9 | 0.82 | 0.87 | 0.5729 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |
| BERLINCLOCK | span | KryptosReversed | 1 | 9 | 0.97 | 0.92 | 0.6498 | 1.0000 | false | Underpowered public-anchor sample; never promote from this result. |

## Sources

- `cia-artifact` [CIA Kryptos artifact page](https://www.cia.gov/legacy/museum/artifact/kryptos/) - Installation context and unresolved fourth-section status.; type: primary; accessed 2026-05-20; use: public-facts-only
- `cia-sculpture` [CIA Kryptos sculpture page](https://www.cia.gov/legacy/headquarters/kryptos-sculpture/) - Sculpture components, Vigenere chart context, and 97-character K4 statement.; type: primary; accessed 2026-05-20; use: public-facts-only
- `elonka-kryptos` [Elonka Dunin Kryptos page](https://www.elonka.com/kryptos/) - Public ciphertext transcription and public clue summary.; type: reference; accessed 2026-05-20; use: public-anchor-summary
- `histocrypt-2021-bean` [HistoCrypt 2021 Richard Bean abstract](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153) - Academic cryptodiagnosis and Gromark-family hypothesis.; type: academic; accessed 2026-05-20; use: methodology-context
- `scientific-american-2025` [Scientific American 2025 final clues report](https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/) - 2025 public clue context and Berlin World Clock clarification.; type: major-reporting; accessed 2026-05-20; use: public-clue-context
- `ap-2025-auction` [Associated Press 2025 auction report](https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/) - Archive-discovery context and Sanborn decipherment distinction.; type: major-reporting; accessed 2026-05-20; use: archive-context-only
- `ap-2025-archive-sale` [Associated Press 2025 archive sale follow-up](https://apnews.com/article/kryptos-jim-sanborn-auction-cia-secret-code-cb8ee8554ca473910cbd0592f8bdb350) - Archive sale outcome and context only; no archive-discovered plaintext content.; type: major-reporting; accessed 2026-05-20; use: archive-context-only
- `kryptosbot-sanborn-papers-2026` [KryptosBot 2026 Sanborn papers research archive](https://kryptosbot.com/archive/) - Curated public notes from Smithsonian Sanborn papers research; context for future preregistration only, not scored plaintext or candidate evidence.; type: community-research-archive; accessed 2026-05-25; use: archive-context-only

## Candidate Sequences

Pre-registered contextual candidates only; no candidate is a claimed solution.

- `h4-berlin-world-clock-english` BerlinWorldClock A1Z26ZeroBased: `BERLINWORLDCLOCK` values=[1, 4, 17, 11, 8, 13, 22, 14, 17, 11, 3, 2, 11, 14, 2, 10] sources=`scientific-american-2025`
- `h4-berlin-world-clock-german` BerlinWorldClock A1Z26ZeroBased: `WELTZEITUHR` values=[22, 4, 11, 19, 25, 4, 8, 19, 20, 7, 17] sources=`scientific-american-2025`
- `h4-berlin-world-clock-place` BerlinWorldClock A1Z26ZeroBased: `ALEXANDERPLATZ` values=[0, 11, 4, 23, 0, 13, 3, 4, 17, 15, 11, 0, 19, 25] sources=`scientific-american-2025`
- `h4-compass-8point-east-northeast` CompassDirections Compass8Point: `EASTNORTHEAST` values=[2, 1] sources=`elonka-kryptos`
- `h4-compass-16point-east-northeast` CompassDirections Compass16Point: `EASTNORTHEAST` values=[4, 2] sources=`elonka-kryptos`
- `h5-egypt-1986-literal` Egypt1986 A1Z26ZeroBased: `EGYPT` values=[4, 6, 24, 15, 19] sources=`scientific-american-2025`
- `h5-egypt-1986-year` Egypt1986 DecimalDigits: `1986` values=[1, 9, 8, 6] sources=`scientific-american-2025`
- `h5-berlin-wall-1989-literal` BerlinWall1989 A1Z26ZeroBased: `BERLINWALL` values=[1, 4, 17, 11, 8, 13, 22, 0, 11, 11] sources=`scientific-american-2025`
- `h5-berlin-wall-1989-date` BerlinWall1989 DecimalDigits: `19891109` values=[1, 9, 8, 9, 1, 1, 0, 9] sources=`scientific-american-2025`

## Candidate Sequence Scores

| Candidate | Family | Compared Fragments | Exact Mod-26 Matches | Match Rate | Promoted | Note |
| --- | --- | --- | --- | --- | --- | --- |
| `h4-berlin-world-clock-english` | BerlinWorldClock | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-berlin-world-clock-german` | BerlinWorldClock | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-berlin-world-clock-place` | BerlinWorldClock | 24 | 2 | 0.083 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-compass-8point-east-northeast` | CompassDirections | 24 | 0 | 0.000 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h4-compass-16point-east-northeast` | CompassDirections | 24 | 3 | 0.125 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-egypt-1986-literal` | Egypt1986 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-egypt-1986-year` | Egypt1986 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-berlin-wall-1989-literal` | BerlinWall1989 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |
| `h5-berlin-wall-1989-date` | BerlinWall1989 | 24 | 1 | 0.042 | false | Exploratory candidate screen only; no candidate is promoted without independent baselines. |

## Route Experiments

Exploratory named route screens only; no decryption text is emitted.

- Identity / EASTNORTHEAST: score=0 identity=0 reverse=1 seeded_random=1 promoted=false
- Reverse / EASTNORTHEAST: score=1 identity=0 reverse=1 seeded_random=1 promoted=false
- RowToColumnWidth13 / EASTNORTHEAST: score=0 identity=0 reverse=1 seeded_random=1 promoted=false
- Identity / BERLINCLOCK: score=1 identity=1 reverse=0 seeded_random=1 promoted=false
- Reverse / BERLINCLOCK: score=0 identity=1 reverse=0 seeded_random=1 promoted=false

## Findings Ledger

Findings are reproducible research observations, not promoted solution claims.

- **F1 Public anchors normalize into two adjacent known-plaintext spans (H1/H2)**
  - Sources: `elonka-kryptos`, `scientific-american-2025`
  - Steps: store public anchors with zero-based and one-based positions; join anchors only when public positions are directly adjacent; derive alphabet-specific additive, subtractive, and Beaufort fragments
  - Output: EAST joins NORTHEAST as EASTNORTHEAST, and BERLIN joins CLOCK as BERLINCLOCK.
  - Baseline: Span-level recurrence results are compared against seeded shuffled controls in the baseline command.
  - Interpretation: The spans are useful constraints, not solution text beyond the public anchors.
  - Next test: Use the span fragments as fixed validation points for any future key-schedule or alphabet hypothesis.
  - Promoted: false
- **F2 Generic Gromark-style recurrence screens are underpowered (H1)**
  - Sources: `histocrypt-2021-bean`, `elonka-kryptos`
  - Steps: derive additive key fragments from public known-plaintext spans; screen contiguous triples for a mod-10 sum recurrence; run deterministic shuffled null controls with Holm adjustment
  - Output: The CLI can reproduce recurrence counts and adjusted p-values, but never promotes them.
  - Baseline: Public-anchor samples contain too few triples for promotion under the configured release boundary.
  - Interpretation: The result is a falsifiable diagnostic lane, not evidence for a Gromark solution.
  - Next test: Require a larger independently justified fragment set before considering any recurrence signal meaningful.
  - Promoted: false
- **F3 Contextual candidate sequences are registered before scoring (H4/H5)**
  - Sources: `scientific-american-2025`, `elonka-kryptos`
  - Steps: define Berlin World Clock, compass, Egypt 1986, and Berlin Wall 1989 material before scoring; convert each candidate with a declared transform; compare only against public-anchor-derived additive fragments
  - Output: Candidate scores are reproducible and marked exploratory with no promoted candidate.
  - Baseline: The candidate-sequences command reports match rates but does not treat them as independent proof.
  - Interpretation: The feature constrains future contextual testing without expanding into ad hoc key hunting.
  - Next test: Add new contextual material only when it has a source ID, declared transform, and pre-registration rationale.
  - Promoted: false
- **F4 Route experiments stay bounded to named permutation families (H3)**
  - Sources: `cia-sculpture`, `elonka-kryptos`
  - Steps: derive public span additive fragments under the standard alphabet; apply identity, reverse, and compatible row-to-column route families; score routed fragments against the same local recurrence diagnostic
  - Output: Route screens report scores and baselines without emitting guessed plaintext.
  - Baseline: Each route result is shown beside identity, reverse, and seeded-random baselines.
  - Interpretation: The route lane is an exploratory guardrail against unconstrained permutation search.
  - Next test: Only add route families that are named, deterministic, and justified before seeing their score.
  - Promoted: false
- **F5 Independent non-anchor period targets are materialized before scoring (H3)**
  - Sources: `experiments/preregistrations/non-anchor-position-period-v1.json`, `experiments/predictions/non-anchor-position-period-v1.json`, `experiments/preregistrations/new-lane-id.json`, `experiments/predictions/non-anchor-position-period-diagnostic-v1.json`
  - Steps: validate each non-anchor position-period preregistration; emit all registered period residue classes before observing independent evidence; compare each committed prediction artifact against deterministic generator output
  - Output: The committed artifacts lock seven registered periods, exclude 24 public-anchor positions, and emit 73 non-anchor K4 positions per period.
  - Baseline: The artifacts have no score yet; future evidence must use held-out or best-of-period controls before interpretation.
  - Interpretation: These are evidence-free prediction targets, not positive signals or K4 solution claims.
  - Next test: Use validate-prediction-artifact before evaluating any future independent evidence against the committed residue classes, and keep source-backed observation files separate from public-anchor-derived fragments.
  - Promoted: false

## Release Check

Local preflight only. This repo does not use GitHub Actions.

- github-actions-disabled: true (GitHub Actions workflow directory must not exist. path=/Users/michaelnobile/Antigravity/Ciphers/.github/workflows)
- dependabot-disabled: true (Dependabot config must not exist because releases are locally gated. path=/Users/michaelnobile/Antigravity/Ciphers/.github/dependabot.yml)
- readme-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/README.md)
- research-method-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/docs/research-method.md)
- current-architecture-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/docs/architecture-current.md)
- production-goal-architecture-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/docs/architecture-production-goal.md)
- source-packet-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/sources/source-packet.md)
- candidate-csv-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.csv)
- candidate-registry-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.md)
- research-plan-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/kryptos-k4-research-plan.md)
- license-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/LICENSE)
- lockfile-present: true (Required release file must be present. path=/Users/michaelnobile/Antigravity/Ciphers/Cargo.lock)
- markdown-report-present: true (Generated release report must be present. path=/Users/michaelnobile/Antigravity/Ciphers/notes/k4-report.md)
- candidate-registry-aligned: true (Candidate CSV rows are represented in the candidate registry with source IDs and rationale. path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.csv; registry_path=/Users/michaelnobile/Antigravity/Ciphers/experiments/k4-candidates.md)
- source-packet-latest-access-date: true (Source packet includes latest registered source access date. path=/Users/michaelnobile/Antigravity/Ciphers/sources/source-packet.md; latest_access_date=2026-05-25)
- source-packet-registry-aligned: true (Source packet matches every registered source ID, URL, type, and allowed-use boundary. path=/Users/michaelnobile/Antigravity/Ciphers/sources/source-packet.md)
- no-plaintext-leakage-markers: true (No leaked/full-plaintext sentinel markers found in release-facing files.)
