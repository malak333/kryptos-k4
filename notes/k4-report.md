# Kryptos K4 Constraint Report

This report uses public anchors only and is not a claimed solution. Production readiness here means the local, source-grounded research CLI and release package are repeatable and bounded; it does not mean Kryptos K4 is solved or that any candidate plaintext, key, route, or method is promoted.

## Research Boundary and Production Readiness

- Evidence boundary: public ciphertext, public known-plaintext anchors, source provenance, deterministic controls, and pre-registered exploratory screens only.
- Research boundary: no generated plaintext is treated as decoded K4 text; all promoted-candidate flags remain false unless independent corroboration and stronger samples justify a future change.
- Production-readiness scope: local Rust CLI, report rendering, JSON output, release preflight, and no-GitHub-Actions policy. External publication, peer review, and cryptanalytic validation remain outside this report.

## Feature Coverage

| Feature | Included result |
| --- | --- |
| `facts` | Ciphertext length, ciphertext, and evidence boundary in Markdown or JSON. |
| `ciphertext-profile` | Ciphertext-only frequency, repeated n-gram spacing, index-of-coincidence, period-coincidence diagnostics, and optional seeded shuffle baselines without anchors, candidate material, claimed plaintext, or promotion in Markdown or JSON. |
| `anchors` | Public known-plaintext anchors with positions, source IDs, confidence, claim type, and notes in Markdown or JSON. |
| `constraints` | Per-anchor key fragments across supported alphabets and modes, with recurrence screens in Markdown or JSON. |
| `key-fragments` | The same fragment rows are rendered in full for anchors and adjacent spans in Markdown or JSON. |
| `test-key` | Proposed key material is transformed and compared against public span additive fragments at true K4 positions, with optional cyclic offset sweep and seeded sweep baseline in Markdown or JSON. |
| `explain-key` | Exact matching public-span positions, modulo caveats, descriptive pattern metrics, and composite pattern score in Markdown or JSON. |
| `batch-test-keys` | CSV candidate rows are ranked with the same public-fragment checks, optional output artifacts, and batch-level controls in Markdown or JSON. |
| `batch-test-routed-keys` | Registered route/permutation families are applied before candidate scoring, with routed search-surface controls in Markdown or JSON. |
| `baseline` | Seeded false-positive controls for anchors and spans across all supported alphabets in Markdown or JSON. |
| `hypotheses` | Ranked source-grounded hypotheses with facts, assumptions, falsification tests, and risks in Markdown or JSON. |
| `candidate-sequences` | Pre-registered contextual sequences and score results in Markdown or JSON. |
| `routes` | Bounded named route experiments with identity, reverse, and seeded-random baselines in Markdown or JSON. |
| `findings` | Reproducible findings ledger with sources, transformations, baselines, interpretation, and next tests in Markdown or JSON. |
| `sources` | Source provenance records and allowed-use notes in Markdown or JSON. |
| `eliminate` | Anchor-reproduction elimination: structural facts (self-encryptions, identical pairs, transposition and periodic-substitution impossibility) and per-family counts of eliminated, untestable, and surviving configurations with the survivors expected by chance, for periodic tableaux and Quagmire I–IV, Gronsfeld, ciphertext and plaintext autokey, Gromark, keyed columnar plus tableau, and route transpositions (columns, serpentines, spirals, diagonals, K3-style double rotations) plus tableau, with a general periodic-substitution route check against random-permutation and ciphertext-shuffle nulls, exact any-alphabet tests for Quagmire I-IV, and an optional dictionary keyword family, in Markdown or JSON. |
| `running-key` | Every offset of a local corpus file as a running key on standard and Kryptos tableaux, with a match histogram and the count expected by chance at the best score, in Markdown or JSON. |
| `key-language` | Trigram English score of the key each registered tableau implies at the anchors, against held-out English windows and uniform random keys, with the compatible count expected by chance, in Markdown or JSON. |
| `verify-claim` | Local quarantine check for an external plaintext claim (and optional running-key stream): normalized length, public-anchor preservation, aggregate shift diagnostics, and additive ciphertext reconstruction, without printing or storing the claim, in Markdown or JSON. |
| `release-check` | Local release gate: no GitHub Actions or Dependabot config, committed claim-verification archives stay non-promoting and non-leaking, and no leaked-plaintext sentinel markers appear in release-facing files, in Markdown or JSON. |
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
- `elonka-kryptos` [Elonka Dunin Kryptos page](https://www.elonka.com/kryptos/) - Public ciphertext transcription and public clue summary.; type: reference; accessed 2026-05-27; use: public-anchor-summary
- `histocrypt-2021-bean` [HistoCrypt 2021 Richard Bean abstract](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153) - Academic cryptodiagnosis and Gromark-family hypothesis.; type: academic; accessed 2026-05-27; use: methodology-context
- `stein-courtyard-crypto` [David Stein courtyard-crypto article mirror](https://www.elonka.com/kryptos/mirrors/daw/steinarticle.html) - Public mirror of David Stein's CIA solved-section methodology article; useful for historical method boundaries, not scored K4 observations.; type: reference; accessed 2026-05-31; use: methodology-context
- `scientific-american-2025` [Scientific American 2025 final clues report](https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/) - 2025 public clue context, Berlin World Clock clarification, and K5 parallel-position context.; type: major-reporting; accessed 2026-05-27; use: public-clue-context
- `scientific-american-2026-kryptos-cracked` [Scientific American 2026 Kryptos archive-discovery report](https://www.scientificamerican.com/article/how-the-cias-kryptos-sculpture-gave-up-its-final-secret/) - Archive-discovery and claim-boundary reporting; no public plaintext, key material, route, or scored K4 observations.; type: major-reporting; accessed 2026-05-31; use: archive-context-only
- `ap-2025-auction` [Associated Press 2025 auction report](https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/) - Archive-discovery context and Sanborn decipherment distinction.; type: major-reporting; accessed 2026-05-27; use: archive-context-only
- `ap-2025-archive-sale` [Associated Press 2025 archive sale follow-up](https://apnews.com/article/kryptos-jim-sanborn-auction-cia-secret-code-cb8ee8554ca473910cbd0592f8bdb350) - Archive sale outcome and context only; no archive-discovered plaintext content.; type: major-reporting; accessed 2026-05-27; use: archive-context-only
- `rr-auction-kryptos-archive-2025` [RR Auction 2025 Kryptos archive lot](https://www.rrauction.com/auctions/lot-detail/350761607302001-the-complete-secrets-of-kryptos-jim-sanborns-private-archive/?cat=0) - Primary auction-lot provenance for the private K4/K5 archive and explicit no-independent-examination boundary; no public plaintext, key material, routes, or scored K4 observations.; type: auction-primary; accessed 2026-05-31; use: archive-context-only
- `smithsonian-2026-archive-discovery` [Smithsonian 2026 archive-discovery report](https://www.smithsonianmag.com/blogs/office-of-the-secretary-of-the-smithsonian/2026/02/17/smithsonian-archives-help-unlock-mysteries-connect-americans-history/) - Smithsonian archive-discovery context; no archive-discovered plaintext, key material, routes, or scoreable observations.; type: institutional-reporting; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-doc1-resolution-memo` [NSA Kryptos challenge and resolution memo](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760459/) - Declassified NSA challenge/resolution memo context for solved sections and methodology boundaries; no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-declassified-kryptos-doc3` [NSA declassified Kryptos sculpture notes](https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cia-kryptos-sculpture/doc_3.pdf) - Declassified physical-clue context including compass, lodestone, Morse, and sculpture-layout notes; no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-doc7-technical-analysis` [NSA Kryptos technical analysis memo](https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cia-kryptos-sculpture/doc_7.pdf) - Declassified NSA solved-section methodology and unresolved-section boundary context; no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-foia-release-index` [NSA CIA Kryptos Sculpture FOIA release index](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760460/) - NSA declassification index for CIA Kryptos Sculpture document releases; source-discovery context only, no scored K4 positions.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-summary-revelations` [NSA Kryptos previous work and revelations summary](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760463/) - NSA declassified summary context for prior work and later revelations; no scored K4 positions, plaintext, key material, or route evidence.; type: primary; accessed 2026-05-28; use: archive-context-only
- `nsa-kryptos-doc8-cryptogram` [NSA Kryptos cryptogram text document](https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760461/) - NSA declassified cryptogram-text context; public ciphertext provenance only, not independent scored observation evidence.; type: primary; accessed 2026-05-28; use: public-anchor-summary
- `kryptosbot-sanborn-papers-2026` [KryptosBot 2026 Sanborn papers research archive](https://kryptosbot.com/archive/) - Curated public notes from Smithsonian Sanborn papers research; context for future preregistration only, including a 7-by-14-compatible K4 layout rationale, not scored plaintext or candidate evidence.; type: community-research-archive; accessed 2026-05-27; use: archive-context-only
- `kryptosbot-methodology-2026` [KryptosBot 2026 methodology and eliminations](https://kryptosbot.com/methodology/) - Public reproducibility and elimination-scope context; not plaintext, not candidate evidence, and not scored observations.; type: community-research-methodology; accessed 2026-05-27; use: methodology-context
- `kryptosbot-findings-2026` [KryptosBot 2026 findings and open questions](https://kryptosbot.com/findings/) - Public findings and open-question context around W-delimiter, CT-perturbation, Stehle local regularity, HILL-tableau, and negative-search boundaries; not plaintext, candidate evidence, or scored observations.; type: community-research-findings; accessed 2026-05-31; use: methodology-context
- `kryptos-today-project-k4-2026` [Project K4 2026 live cryptanalysis press page](https://kryptos.today/press/2026-05-01-launch) - Independent live-search and negative-result context; not plaintext, not candidate evidence, and not scored observations.; type: independent-cryptanalysis-project; accessed 2026-05-31; use: methodology-context
- `kryptos-today-progress-2026` [Project K4 2026 progress log](https://kryptos.today/progress) - Independent progress-log context for attack-family triage, including Weltzeituhr, width-7 transposition, and Morse/Mengenlehreuhr queue updates; not plaintext, candidate evidence, or scored observations.; type: independent-cryptanalysis-progress; accessed 2026-05-31; use: methodology-context
- `rumkin-k4-reference` [Rumkin K4 reference notes](https://rumkin.com/reference/kryptos/k4/) - K4 reference and open-question context around direct mapping, installation threads, and the HILL tableau question; not plaintext, not candidate evidence, and not scored observations.; type: community-reference; accessed 2026-05-27; use: methodology-context
- `solvekryptos-2026-claim` [SolveKryptos 2026 K4 solution claim](https://solvekryptos.com/) - Public claimed K4 plaintext and mechanism; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-27; use: unverified-solution-claim
- `dearcipher-k4-claim-2026` [Dear Cipher Kryptos K4 claim](https://www.dearcipher.space/kryptos) - Public claimed K4 plaintext and explanation; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `prlog-bishop-k4-plaintext-2020` [Stephen Bishop PRLog K4 plaintext claim](https://www.prlog.org/12845348-stephen-bishop-discovers-us-central-intelligence-agency-sculpture-kryptos-k4-plaintext.pdf) - Public claimed K4 plaintext via CIA New Headquarters Building visual construction; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `ssrn-bonifacino-running-key-2025` [SSRN Bonifacino 2025 running-key K4 paper](https://ssrn.com/abstract=5876405) - Public running-key candidate paper; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `ssrn-bonifacino-weltzeituhr-error-key-2025` [SSRN Bonifacino 2025 Weltzeituhr error-key paper](https://ssrn.com/abstract=5779863) - Public claimed derivation for a Weltzeituhr running-key K4 method; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim
- `ssrn-bonifacino-full-derivation-2025` [SSRN Bonifacino 2025 full Weltzeituhr derivation paper](https://ssrn.com/abstract=5779902) - Public claimed full derivation for the Weltzeituhr error-key K4 method; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-06-01; use: unverified-solution-claim
- `ssrn-bonifacino-generative-running-key-2025` [SSRN Bonifacino 2025 generative running-key paper](https://ssrn.com/abstract=5876462) - Public claimed generative ruleset for a Weltzeituhr running-key K4 method; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.; type: community-solution-claim; accessed 2026-05-31; use: unverified-solution-claim

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
  - Output: The 100000-iteration span/all-alphabet baseline found no adjusted recurrence signal: the strongest raw row was EASTNORTHEAST/Kryptos with 2/11 triples, raw p=0.3138, adjusted p=1.0000.
  - Baseline: Seeded shuffled controls over public-anchor span fragments leave every adjusted p-value at 1.0000, so the Gromark-style screen remains negative and underpowered.
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
- **F5 Independent-lane phase is closed and negative (H3)**
  - Sources: `docs/negative-results.md`, `experiments/position-observations/cia-k4-row-boundaries-v1.json`, `sources/archives/cia-sculpture-2026-05-27.md`
  - Steps: record CIA sculpture web-page row-boundary positions 1, 4, 5, 36, 37, and 97 as the only source-backed non-anchor observation; score that observation against 26 distinct preregistered position models (period, spacing, mirror, grid, Tableau/HILL, and ciphertext-only priors) with seeded same-size position-shuffle nulls; prune 60 duplicate or escalating-variant lanes and their archives in the slim-down; history is preserved at git tag pre-slimdown
  - Output: None of the 26 surviving archives is significant: the lowest raw empirical p is 0.1303 (grid column edge, 4/6 hits). The lowest raw p anywhere in the phase, p=0.0436 (terminal residue balance), came from a pruned parameter variant and was p=1.0000 after correcting for the archives searched.
  - Baseline: Every archive used seeded same-size non-anchor position-shuffle or best-of-model nulls (seed 67, 100000 iterations unless the archive says otherwise).
  - Interpretation: The row-boundary observation is a web-page layout artifact with six positions, so it has almost no power. These nulls say little about K4 itself and mainly show this observation should not be scored again.
  - Next test: Do not add models against this observation. Score future methods by reproducing all 24 public anchor letters, which happens by chance with probability about 26^-24.
  - Promoted: false
- **F6 Methodology context stops repeated single-layer search mining (H1/H2/H3/H4/H5)**
  - Sources: `kryptosbot-methodology-2026`, `docs/negative-results.md`, `docs/research-plan.md`
  - Steps: register methodology context with a non-scored allowed-use boundary; compare it against completed batch, routed, and structural controls; record saturated search families as stopped unless a preregistration narrows the target before scoring
  - Output: Simple single-layer, word-list, route, and uncorrected best-of-search lanes are documented as stopped for current evidence.
  - Baseline: The stopped-lane decision is backed by existing negative batch-level, routed, and structural controls rather than a new positive score.
  - Interpretation: Methodology context improves research discipline, but it is not plaintext, candidate evidence, or an independent scored observation.
  - Next test: Do not reopen a stopped search family on the same inputs. Test a concrete cipher method by whether it reproduces all 24 public anchor letters; a miss eliminates it.
  - Promoted: false
- **F13 External plaintext claims are quarantined before verification (H3)**
  - Sources: `sources/archives/solvekryptos-2026-05-27.md`, `sources/archives/ssrn-bonifacino-running-key-2025-2026-05-31.md`, `sources/archives/smithsonian-2026-archive-discovery-2026-05-28.md`, `sources/source-packet.md`, `results/claim-verifications`, `src/claim.rs`
  - Steps: register external solution claims with allowed_use unverified-solution-claim; archive claim metadata and boundary language without copying claimed plaintext; register institutional archive-discovery reporting as context-only provenance rather than scoreable evidence; verify local claim files with length, public-anchor, aggregate shift, and optional running-key reconstruction checks only, from temporary files outside the repo
  - Output: The SolveKryptos and SSRN running-key claims are registered as quarantined external claims, and the Smithsonian 2026 archive-discovery article is context-only provenance. The public SolveKryptos claim text passes the narrow local structure check: 97 normalized letters and 4/4 public anchors preserved. Before the slim-down, dedicated verifiers (preserved at git tag pre-slimdown) also checked the SolveKryptos canonical bundle and mechanism files: the reconciliation table and bundle grids were internally consistent, but the Y-pass template layer matched only 27/31 rule checks, with disagreements at K4 positions 27, 31, 32, and 33, and the template's declared zero positions disagree with its printed rule. No claimed plaintext or key stream is printed or stored.
  - Baseline: This is an intake and leakage-control gate, not evidence for a solution; public-anchor compatibility is a minimum structural check and cannot promote a candidate.
  - Interpretation: The external claim is compatible with the public anchors, but its published helper machinery is not fully self-consistent. None of these checks validates a physical helper-stream reading or the claimed mechanism as independent evidence.
  - Next test: Do not promote any claim from anchor compatibility or file-consistency checks. A follow-up must independently validate the claimed mechanism or obtain independent non-anchor evidence.
  - Promoted: false
- **F14 Ciphertext-only period profile is weak after shuffled controls (H3)**
  - Sources: `src/ciphertext_profile.rs`, `results/ciphertext-prior-observations/cia-k4-row-boundaries-v1`
  - Steps: profile public K4 ciphertext letters without anchors or candidate material; compute letter frequencies, repeated n-grams, repeated n-gram gap-factor support, overall index of coincidence, and shifted period coincidence rates; shuffle ciphertext letters with a deterministic seed and record the best repeated n-gram gap-factor support and best shifted period-match rate across the scanned period range; score the CIA row-boundary observation against the period-2/period-7 prior with same-size non-anchor position-shuffle controls (archived; scorer preserved at git tag pre-slimdown)
  - Output: The ciphertext-only profile over periods 1 through 20 reports overall IC 0.0361, a best repeated n-gram spacing factor at period 2 with 7/10 supported gaps, and a best shifted period signal at period 7 with 9/90 matches. The 100000-iteration seeded null gives spacing p=0.0568 and shifted-period p=0.0719; periods 2 and 7 were recorded as priors only. The source-backed CIA row-boundary observation scores best at period 2 residue 0 with 4/6 hits, but the same-size non-anchor position-shuffle null gives empirical p=0.6845 over 100000 iterations.
  - Baseline: The repeated n-gram spacing and shifted-period signals are each compared against seeded ciphertext-only shuffles that preserve the K4 letter multiset and scan the same period range. The row-boundary prior evaluation is compared against seeded same-size shuffles over the non-anchor position universe.
  - Interpretation: The period-2 spacing factor and period-7 shifted coincidence are weak diagnostic leads only, and the first source-backed prior evaluation is negative. They are not independently significant, not plaintext, not a key, and not promoted candidates.
  - Next test: Stop mining ciphertext-only priors; test concrete cipher methods against the public anchors instead.
  - Promoted: false
- **F15 Anchor reproduction eliminates the classical periodic, autokey, Gromark, and bounded columnar families (H1/H2/H3)**
  - Sources: `elonka-kryptos`, `histocrypt-2021-bean`, `src/eliminate.rs`, `results/eliminations/anchor-elimination-v1`
  - Steps: derive structural facts from the 24 public anchor letters alone; for each configuration (family, alphabets, sign, period or lag, transposition), list the anchor checks a correct configuration must pass and eliminate it on any failure; use 37 keyed alphabets fixed before scoring (standard plus 36 Kryptos, clue, and theme keywords) in every plaintext/ciphertext pairing; record the probability that a random configuration passes the same checks, and sum it into the survivors expected by chance; confirm with planted synthetic encryptions that each checker keeps a true key
  - Output: No pure transposition fits (the anchors need three E but K4 has two). Porta and any cipher without self-encryption are impossible (anchor letters encrypt to themselves at one-based 33 and 74). No periodic substitution with any alphabets fits at periods 1-7, 9, 10, 14, 15, 17, 21, 25, 34, 42, 43, or 45. Over 15.5 million configurations, Gronsfeld (2886), ciphertext autokey (421356), Gromark with lag 2-12 mod 10 or 26 (90354), and keyed columnar width 2-8 before or after a periodic tableau of period 1-13 (14424384) have zero survivors. Periodic tableaux and Quagmire I-IV with period 1-26 leave 188 survivors against 158.2 expected by chance, none passing more than one check; plaintext autokey with lag 1-52 leaves 1261 against 960.4 expected, none passing more than three.
  - Baseline: Each check carries its chance pass probability (1/26 for a letter equality, 10/26 for a digit-range check, 1/10 for a mod-10 recurrence). Survivor counts match the chance expectation, and the best survivor of any family has chance probability above 5e-5 among hundreds of thousands of configurations.
  - Interpretation: Within the registered alphabets and bounds, these families cannot produce K4. The result is limited to the 37 alphabets and the stated periods, lags, and widths; arbitrary unkeyed alphabets, longer transposition keys, and other families remain open.
  - Next test: Run running-key offsets over a fixed public corpus with running-key, and extend elimination to route transpositions and non-keyword alphabets.
  - Promoted: false
- **F16 No preregistered sculpture or Carter text is a direct running key (H1/H5)**
  - Sources: `experiments/running-key/preregistration.md`, `src/eliminate.rs`, `results/running-key/corpus-v1`
  - Steps: fix the corpus before scoring: K1-K3 plaintext, K1-K3 ciphertext, the tableau rows, and Carter and Mace's Tomb of Tut.ankh.Amen Vol. I (1923 OCR), each forward and reversed, identified by SHA-256; read the key at K4 position i as corpus letter offset + i, for every offset; count anchor letters reproduced on Vigenere, Beaufort, and variant Beaufort with standard and Kryptos alphabets, reading the key in each key alphabet; compare the best count with the binomial chance expectation at p = 1/26
  - Output: 10,242,288 configurations over eight corpora. No configuration reproduces all 24 anchor letters. The best scores are 6/24 for each sculpture text, 8/24 for Carter forward (10.3 configurations expected at that level by chance), and 9/24 for Carter reversed (0.72 expected).
  - Baseline: Binomial tail at p = 1/26 per anchor letter times the configuration count. Every corpus's best is at or near its chance expectation; summed over the eight corpora about 1.5 configurations are expected at 9 or more.
  - Interpretation: None of these texts is a direct running key for K4 under the standard or Kryptos tableaux. OCR errors could cost a true Carter key a few letters, but no offset comes near 24.
  - Next test: Test whether a running key from any English text fits any registered tableau (F17).
  - Promoted: false
- **F17 A running key from any English text fits none of the registered tableaux (H1/H2)**
  - Sources: `experiments/running-key/preregistration.md`, `src/key_language.rs`, `results/running-key/key-language-v1`
  - Steps: train a smoothed trigram model on the first half of the Carter Vol. I letters; score held-out English windows from the second half at the 24 anchor positions of a 74-letter window, and set the threshold at their 0.1% quantile; for each of the 37 x 37 x 3 registered tableaux and each key alphabet, score the key letters implied at the two anchor runs (13 and 11 letters); score 200,000 uniform random keys (seed 1) to estimate how many configurations pass by chance
  - Output: 8,103 configurations. One passes the threshold (Quagmire IV Vigenere, pt=enigma ct=carter, implied key CDHIRMEFADCNE FYEDNICKTHE, English quantile 1.25e-3) against 1.13 expected from random keys. Held-out English windows have median score -7.61; the best anchor-implied key scores -9.41.
  - Baseline: Uniform random keys pass the threshold at rate 1.40e-4, so 1.13 of 8,103 configurations are expected to pass by chance; 1 passed.
  - Interpretation: No registered tableau implies an English-looking key at the anchors, so a running key taken from any English text is eliminated for the registered alphabets. A true English key would be wrongly rejected about 0.1% of the time. Arbitrary unkeyed alphabets and non-English or enciphered key texts remain open.
  - Next test: Extend anchor elimination to route transpositions combined with periodic tableaux.
  - Promoted: false
- **F18 Route transpositions with a periodic key, on any alphabets, show nothing beyond chance (H3)**
  - Sources: `src/route_elimination.rs`, `results/eliminations/anchor-elimination-v6`
  - Steps: write the 97 letters row by row into grids of width 2-48 (last row partial) and read them by ten routes: columns down, up, and right-to-left, column and row serpentines, clockwise and counterclockwise spirals, diagonals, and diagonal serpentines; add K3-style double rotations (rotate a width-w1 grid, rewrite at width w2, rotate again, both directions, w1 and w2 in 2-48), then each route inverted and reversed, deduplicated: 18,849 permutations; apply each before or after a periodic Vigenere, Beaufort, or variant Beaufort key on standard and Kryptos tableaux, period 1-26, with a chance probability per anchor check; separately, check each route and order for a general periodic substitution (any alphabet per key column, period 1-26); compare general-substitution counts with 200,000 random permutations and with 200 shuffles of the K4 ciphertext letters under the same routes (seed 1)
  - Output: Route plus tableau: 11,761,776 configurations, 9,232 survivors against 9,168.7 expected by chance, none passing more than three checks. General periodic substitution: no route fits at period 1 or 2; at periods 3-8 the consistent counts (14, 70, 182, 5280, 6728, 8976) match the ciphertext-shuffle expectation (7.1, 59.1, 223.3, 5165.9, 6997.4, 8321.8), smallest empirical p = 0.065 at period 3 before correcting for eight periods.
  - Baseline: Tableau checks carry 1/26 per letter equality. The general-substitution null keeps each route's structure and shuffles ciphertext letters, so correlated route variants are accounted for.
  - Interpretation: No registered route, with or without double rotation, combined with a periodic key on standard or Kryptos tableaux, produces K4. With arbitrary per-column alphabets, no route fits better than shuffled ciphertext. Longer keyed transpositions and non-periodic keys after a route remain open.
  - Next test: Test Quagmire I/II with any alphabet exactly (F19).
  - Promoted: false
- **F19 Quagmire I and II fail at most periods even with an arbitrary mixed alphabet (H2)**
  - Sources: `src/eliminate.rs`, `results/eliminations/anchor-elimination-v6`
  - Steps: write each anchor as a difference constraint mod 26 between the unknown alphabet position of a letter and an unknown key column (Quagmire I: plaintext alphabet mixed, ciphertext standard; Quagmire II: the reverse; the sign convention is absorbed by reflecting the alphabet); solve with a weighted union-find; a contradiction, or two letters forced to one alphabet position, eliminates the period for every possible alphabet and key; confirm with planted encryptions under a scrambled alphabet that a true key always passes; compare the periods K4 passes with 2,000 shuffles of the K4 ciphertext letters, and score the pattern by summed surprisal against an independent 2,000 shuffles (seed 1)
  - Output: With any alphabet, Quagmire I is impossible at periods 1-12, 14, 15, 17, 18, 20-22, and 25; Quagmire II at 1-15, 17, 18, 21, 22, and 25. Both pass at period 19, where 1.5% and 2.1% of shuffles pass; the other passes (13, 16, 20, 23, 24, 26) are common under shuffling. Combined surprisal: K4 13.48 against a null mean of 6.37, p = 0.049.
  - Baseline: Impossibility is exact and needs no null. The surprisal p-value is post hoc (the statistic was chosen after period 19 was seen) and is not significant after that choice.
  - Interpretation: Quagmire I and II, with any alphabet at all, are ruled out at every period up to 12 and at most periods up to 26. The registered keyword alphabets were already eliminated at period 19 (F15). Period 19 is the weakest remaining gap, not evidence for it. Passing this test is necessary, not sufficient; F22 confirms by exact search that every passing period is genuinely solvable. Quagmire III and IV with arbitrary alphabets are not covered by this test.
  - Next test: Check whether any dictionary keyword alphabet, not only the registered ones, fits Quagmire I-III (F20).
  - Promoted: false
- **F20 No dictionary keyword alphabet fits Quagmire I, II, or III at any period up to 25 (H2)**
  - Sources: `experiments/eliminations/dictionary-keywords-preregistration.md`, `src/eliminate.rs`, `results/eliminations/anchor-elimination-v6`
  - Steps: make a keyword alphabet from every word in /usr/share/dict/web2 (Webster's Second, 235,976 words) and /usr/share/dict/propernames (1,308 names), skipping duplicates and the standard alphabet; test each as Quagmire I, II, and III with Vigenere, Beaufort, and variant Beaufort at periods 1-26, with the periodic-tableau anchor checks; confirm with a planted keyword encryption that the checker keeps a true key
  - Output: 48,829,248 configurations. 65,571 survive against 72,339.6 expected by chance, and none passes more than one check: every survivor is at a period (26) that leaves the anchors almost untested. No configuration survives at any period from 1 to 25, including period 19.
  - Baseline: Each check carries chance 1/26; survivor counts match the chance expectation.
  - Interpretation: Quagmire I-III with a keyword alphabet from any English dictionary word cannot produce K4 at periods 1-25. Together with F19, the period-19 gap for Quagmire I/II needs a non-dictionary mixed alphabet.
  - Next test: Search Quagmire III and IV with arbitrary alphabets exactly (F21).
  - Promoted: false
- **F21 Exact search: Quagmire III fits almost no period with any alphabet; Quagmire IV stays solvable at eight (H2)**
  - Sources: `src/quagmire_search.rs`, `results/eliminations/anchor-elimination-v6`
  - Steps: write each anchor as posB(c) - posA(p) = k[col] (Vigenere; variant Beaufort is the same with k negated) or posB(c) + posA(p) = k[col] (Beaufort), with posA = posB for Quagmire III; mark periods impossible where no per-column substitution fits at all; otherwise drop columns holding a single anchor, whose key is free, and fix one letter per alphabet at 0 to remove translation symmetry; depth-first search over alphabet positions with key derivation and forced partner letters, re-verifying every solution found, with a budget of 2 billion nodes per period; confirm with planted encryptions under scrambled alphabets that true keys are found for both kinds and signs
  - Output: Quagmire III, Vigenere or variant Beaufort: impossible with any alphabet at every period 1-26 except 24, which was undecided here and is impossible by F22; no solution found at any period. Quagmire III, Beaufort: impossible at 1-22, 24, 25; solvable at 23 and 26. Quagmire IV, either sign, fully decided: impossible at 1-7, 9-12, 14, 15, 17, 18, 21, 22, 25; solvable at 8, 13, 16, 19, 20, 23, 24, 26.
  - Baseline: Impossibility is exact. Solvable periods are found within 30 search nodes; the hardest decided period needed 1.23 billion nodes. Quagmire III Vigenere period 24 exhausts the 2-billion-node budget, and also a 20-billion-node run (eliminate --max-lag 1 --max-columnar-width 0 --max-route-width 0 --route-random-permutations 0 --route-ciphertext-shuffles 0 --quagmire-search-budget 20000000000), which suggests but does not prove impossibility. F22 decides it: the cell is impossible by a one-line argument the search had not encoded.
  - Interpretation: Even with alphabets chosen freely, a single-alphabet Quagmire III is nearly ruled out at periods up to 26. Quagmire IV has enough freedom to fit the anchors at eight periods, so the anchors cannot eliminate it there; a specific alphabet pair or key would be needed.
  - Next test: Decide the last Quagmire III cell and Quagmire I/II exactly (F22).
  - Promoted: false
- **F22 Every Quagmire I-IV cell up to period 26 is decided; Quagmire III with the Vigenere sign is impossible at all of them (H2)**
  - Sources: `src/quagmire_search.rs`, `results/eliminations/anchor-elimination-v6`
  - Steps: add to the F21 propagation: under one shared alphabet with the Vigenere sign, a letter that encrypts to itself forces its column key to 0, and key 0 cannot pair two different letters; extend the exact search to Quagmire I (ciphertext alphabet fixed to the standard order) and Quagmire II (plaintext alphabet fixed), both sign conventions, periods 1-26, budget 2 billion nodes per period; cross-check on the K4 anchors: every period the F19 union-find test rejects must be impossible here, the two signs must agree for Quagmire I and II (reflecting the mixed alphabet turns Beaufort into Vigenere), and Quagmire IV must be solvable wherever I or II is; confirm with planted encryptions under scrambled alphabets, including columns with key 0, that true keys are found for all four kinds and both signs
  - Output: No cell is undecided. Quagmire III, Vigenere or variant Beaufort: impossible at every period 1-26. At period 24, position 74 (K to K) and position 26 (N to Q) share a column, so the column key is 0 and N cannot become Q. Quagmire I, either sign: impossible at 1-12, 14, 15, 17, 18, 20-22, 25; solvable at 13, 16, 19, 23, 24, 26. Quagmire II, either sign: impossible at 1-15, 17, 18, 21, 22, 25; solvable at 16, 19, 20, 23, 24, 26. Quagmire III Beaufort and Quagmire IV are unchanged from F21.
  - Baseline: Impossibility and solvability are both exact; every solution found is re-verified against all anchor equations. Every Quagmire I/II cell is decided within 5 search nodes and Quagmire III Vigenere period 24 at the root; the hardest cell overall is still Quagmire III Beaufort period 16 at 1.23 billion nodes, so the 2-billion-node budget is not binding. The F19 union-find passes are exactly the solvable Quagmire I/II periods, so that necessary test lost nothing at K4. Solvable is not evidence: shuffled ciphertexts pass the F19 necessary test at these periods at the rates given there.
  - Interpretation: The anchors decide every Quagmire configuration with arbitrary alphabets at periods up to 26. What survives (Quagmire I at 6 periods, II at 6, III Beaufort at 2, IV at 8) survives because those periods leave too few anchor pairs per column to test, not because anything fits well. A specific alphabet or key source is needed to go further.
  - Next test: See docs/conclusions.md: test only specific, preregistered key sources, or rerun when more plaintext is released.
  - Promoted: false

## Release Check

Local preflight only. This repo does not use GitHub Actions.

- github-actions-disabled: true (GitHub Actions workflow directory must not exist. path=/Users/michaelnobile/Antigravity/Ciphers/.github/workflows)
- dependabot-disabled: true (Dependabot config must not exist because releases are locally gated. path=/Users/michaelnobile/Antigravity/Ciphers/.github/dependabot.yml)
- claim-verification-archives-structured: true (Committed claim-verification archives are tied to quarantined claim sources and preserve non-promotion/no-plaintext boundaries. path=/Users/michaelnobile/Antigravity/Ciphers/results/claim-verifications; checked=8)
- no-plaintext-leakage-markers: true (No leaked/full-plaintext sentinel markers found in release-facing files or artifacts.)
