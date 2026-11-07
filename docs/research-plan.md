# Kryptos K4 Research Plan

Created: 2026-05-20

## Scope and Rules

This document defines a source-grounded research plan for investigating Kryptos K4. It is not a claimed solution and does not use any non-public, leaked, paid, or archive-discovered plaintext content.

Success for this phase means:

- Build a curated dossier of verified public facts, clues, constraints, and source links.
- Rank plausible K4 cracking hypotheses by source fit and testability.
- Define repeatable next tests for future manual or computational work.
- Keep research claims, assumptions, and speculative hypotheses visibly separate.

Allowed evidence:

- CIA descriptions of Kryptos.
- Public statements or reported statements from Jim Sanborn.
- Major reporting from reputable outlets.
- Academic cryptanalysis.
- Established Kryptos reference material used only when the underlying fact is public and traceable.

Excluded evidence:

- Claimed full K4 plaintexts.
- Leaked or archive-discovered plaintext content.
- Paid/private archive material.
- Community claims used as proof.
- Numerology, visual coincidence, or acrostic-like findings unless they generate falsifiable tests.

## Verified Public Facts

| Fact | Status | Source |
| --- | --- | --- |
| Kryptos is installed at CIA headquarters and includes multiple coded messages. | Verified | CIA artifact page; CIA headquarters page |
| CIA states the first three sections have been cracked and the fourth remains elusive. | Verified | CIA artifact page |
| CIA describes K4 as a remaining 97-character message using a more difficult cryptographic code. | Verified | CIA headquarters page |
| The sculpture includes a Vigenere table-like alphabet chart, intentionally flipped so it is read from the back. | Verified | CIA headquarters page |
| CIA says Sanborn used the chart system with matrix coding systems for the first three encoded texts. | Verified | CIA headquarters page |
| K4 ciphertext is publicly transcribed as `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`. | High confidence | Elonka Dunin reference page |
| Sanborn publicly disclosed K4 anchors `BERLIN`, `CLOCK`, `NORTHEAST`, and later `EAST`. | High confidence | Elonka Dunin reference page; major reporting |
| The known anchors imply `EASTNORTHEAST` appears together in the first half and `BERLINCLOCK` appears later. | High confidence | Elonka Dunin reference page |
| Sanborn said in 2025 that K4 had not been fully deciphered, despite archive-discovered text reports. | Verified reporting | Scientific American |
| Sanborn clarified in 2025 reporting that `BERLINCLOCK` refers to the Berlin World Clock. | Verified reporting | Scientific American |
| AP reported Sanborn distinguished discovering archived text from deciphering the method/key. | Verified reporting | AP |
| Richard Bean's HistoCrypt abstract reports statistical evidence for a one-to-one plaintext/ciphertext relationship and suggests Gromark as a possible method family. | Verified academic abstract | HistoCrypt 2021 |
| Public KryptosBot methodology notes emphasize reproducibility, broad elimination of simple single-layer systems, and correction for repeated search surfaces. | Community methodology context | KryptosBot methodology |

## Source Timeline

| Date | Event | Research Use |
| --- | --- | --- |
| 1990 | Kryptos installed at CIA headquarters. | Establishes artwork context and intended cryptographic sculpture frame. |
| 1998-1999 | Publicly reported solving of K1-K3 by CIA employee and outside computer scientist. | Confirms K4 is the remaining section and that earlier sections use varied methods. |
| 2010 | Sanborn clue: K4 ciphertext `NYPVTT` decrypts to `BERLIN`. | Fixed known-plaintext anchor. |
| 2014 | Sanborn clue: the word after `BERLIN` is `CLOCK`. | Extends fixed anchor to `BERLINCLOCK`. |
| 2020 | Sanborn clue: `NORTHEAST`; later public release of `EAST`. | Adds direction anchor and supports `EASTNORTHEAST` sequence. |
| 2021 | Richard Bean publishes HistoCrypt cryptodiagnosis abstract. | Prioritizes one-to-one and Gromark-like hypotheses for test design. |
| 2025 | Scientific American reports Sanborn's final public clues before archive sale. | Adds Berlin World Clock clarification and event/theme clues. |
| 2025 | AP reports archive-discovered text and sale of Sanborn archive. | Context only; do not use discovered plaintext content. |
| 2026 | KryptosBot publishes public methodology and elimination notes. | Methodology context only; use to avoid rerunning saturated single-layer or uncorrected-search lanes, not as plaintext or candidate evidence. |

## Constraint Ledger

| Constraint | Why It Matters | Confidence |
| --- | --- | --- |
| K4 has 97 ciphertext characters. | Rules out simple grid sizes unless padding/nulls or irregular routing are explained. | High |
| Known anchors must land at their public positions. | Any candidate mechanism must reproduce anchors without post hoc adjustment. | High |
| `BERLINCLOCK` is a phrase clue, but its role may be plaintext, key material, or thematic confirmation. | Avoid assuming clue role beyond what sources confirm. | High |
| `BERLINCLOCK` refers to Berlin's World Clock per 2025 reporting. | Key-source and theme searches should prioritize the World Clock over generic Berlin clocks. | Medium-high |
| K1 and K2 use Vigenere-like mechanics with the Kryptos alphabet. | K4 may inherit alphabet or table conventions, but this is not guaranteed. | Medium |
| K3 uses transposition/matrix behavior. | Hybrid substitution/transposition remains plausible, but must preserve known anchors. | Medium |
| Bean's analysis suggests a one-to-one plaintext/ciphertext relationship. | Prioritize substitution/additive stream-like systems before pure transposition. | Medium-high |
| Sanborn emphasizes creativity and has said K4 is not necessarily a math solution. | Mechanism may involve art/context/key generation rather than pure cipher taxonomy. | Medium |
| 2025 archive discovery is not a cryptographic decipherment. | It should inform history, not provide solution material. | High |
| Public methodology notes report broad negative coverage for simple single-layer cipher families and warn against uncorrected search-space mining. | Future work should prioritize preregistered independent targets or richer structural models instead of repeated word/route mining over public anchors. | Medium |

## Hypothesis Register

### H1: Gromark-like or Running-Key Additive System

- Priority: 1
- Supporting facts: Bean's HistoCrypt abstract reports evidence for one-to-one plaintext/ciphertext correspondence and identifies Gromark as a possible method family.
- Required assumptions: K4 uses a keyed alphabet and running numerical key stream or related additive construction.
- Predicted artifacts: Known plaintext anchors should imply consistent key-stream fragments under one or more plausible alphabets.
- Falsification test: Derive key-stream fragments from each public anchor under standard and Kryptos alphabets; reject variants whose fragments cannot plausibly coexist under Gromark-like recurrence rules.
- Risk: Overfitting anchor fragments to a flexible additive model.

### H2: Kryptos-Alphabet Vigenere Descendant with Added Transformation

- Priority: 2
- Supporting facts: K1 and K2 use Vigenere-like mechanics with the Kryptos alphabet; the sculpture includes the alphabet chart.
- Required assumptions: K4 preserves a family resemblance to earlier sections but adds a new key schedule, route, or preprocessing layer.
- Predicted artifacts: Known anchors should imply repeated or structured key fragments under the Kryptos alphabet.
- Falsification test: Compute anchor-implied key letters for standard, Kryptos, and reversed Kryptos alphabets; reject if fragments are structureless across all public anchors.
- Risk: Prior-method bias. K4 may intentionally depart from K1/K2.

### H3: Hybrid Substitution Plus Route/Matrix Transposition

- Priority: 3
- Supporting facts: CIA says Sanborn used chart and matrix coding systems for earlier sections; K3 uses transposition-like behavior.
- Required assumptions: K4 may combine a one-to-one substitution/additive layer with a route or matrix layer.
- Predicted artifacts: Known anchors should align after a stable permutation, not arbitrary manual rearrangement.
- Falsification test: Enumerate simple route/permutation families compatible with length 97 and test whether anchor positions become more coherent under a single rule.
- Risk: Route spaces are large and can generate false positives.

### H4: Berlin World Clock / Compass / Directional Mechanism

- Priority: 4
- Supporting facts: Sanborn clarified `BERLINCLOCK` refers to the Berlin World Clock; CIA describes a navigational compass rose component; known anchors include `EAST` and `NORTHEAST`.
- Required assumptions: Clock or compass data contributes to key generation, ordering, or validation, not only plaintext content.
- Predicted artifacts: Berlin World Clock structure, time display, location, or compass-rose geometry should map to a repeatable numeric/key sequence.
- Falsification test: Define candidate sequences before testing them against ciphertext; reject if sequence definitions are adjusted after seeing results.
- Risk: High ambiguity in choosing which clock feature matters.

### H5: Egypt 1986 / Berlin Wall 1989 Event-Timeline Key Material

- Priority: 5
- Supporting facts: 2025 reporting says two events figure in the solution: Sanborn's 1986 Egypt trip and the 1989 fall of the Berlin Wall.
- Required assumptions: The events provide key words, dates, places, routes, or ordering rules.
- Predicted artifacts: Event-derived material should improve anchor consistency under H1-H3 mechanisms.
- Falsification test: Pre-register a limited event-key list from strict sources, then test it without expanding ad hoc.
- Risk: Underspecified and prone to unconstrained key hunting.

## Next-Test Plan

The original eight-step plan (source packet, normalized data, anchor
constraints, then H1 through H5 screens, then a findings ledger) is complete;
see `docs/negative-results.md` for what it found. The full original text is
preserved at git tag `pre-slimdown`.

Current direction: score each concrete cipher method by whether it reproduces
all 24 public anchor letters at their positions. Chance agreement is about
26^-24, so a miss eliminates the method and no null model is needed.

1. Done (`eliminate`): Quagmire I–IV, plaintext and ciphertext autokey,
   Porta, Gronsfeld, and Gromark, with Bean's equality as a unit test. See
   `docs/negative-results.md`.
2. Tool ready (`running-key`), not yet run: running keys from a fixed public
   corpus (K1–K3 plaintexts, Carter's account, Berlin World Clock material,
   Egypt 1986 and Berlin Wall 1989 texts) at every offset. Corpus texts are
   not committed; record each file's source and checksum with its result.
3. Done for keyed columnar width 2–8 (`eliminate`). Still open: route
   transpositions, longer keys, and non-keyword alphabets.

## Decision Log

| Decision | Alternatives Considered | Reason |
| --- | --- | --- |
| Use a research-design phase before implementation. | Immediate computational testing; manual puzzle solving. | K4 has many false-positive traps; source discipline comes first. |
| Optimize for historical/source grounding. | Cryptanalytic rigor first; fast exploration first; balanced workflow. | Sanborn's public clues and contextual statements are central constraints. |
| Success means dossier, ranked hypotheses, and repeatable next-test plan. | Dossier only; hypothesis list only; test plan only. | Each artifact supports the others; none is sufficient alone. |
| Use strict sources. | Include community work cautiously; broad intake. | Community claims are useful for awareness but weak as evidence. |
| Treat 2025 archive/plaintext discovery as context only. | Avoid it entirely; use discovered plaintext content. | It affects puzzle history but should not become solving material. |
| Save the validated design as Markdown in this workspace. | Written strategy only; prepare but do not write files. | The plan should become durable project material. |
| Recommended design is source-led dossier plus hypothesis register plus test plan. | Cryptanalytic-first review; chronological clue reconstruction. | Best balance of rigor, source control, and future testability. |
| 2026-11: stop scoring position models against the single row-boundary observation; slim the repo and score methods by anchor reproduction. | Keep adding preregistered lanes; abandon the project. | Six positions cannot support many models, and the 24 anchor letters are a far stronger test. |

## Source List

- CIA, "Kryptos" artifact page: https://www.cia.gov/legacy/museum/artifact/kryptos/
- CIA, "Kryptos" Sculpture page: https://www.cia.gov/legacy/headquarters/kryptos-sculpture/
- Elonka Dunin, Kryptos reference page: https://www.elonka.com/kryptos/
- Richard Bean, "Cryptodiagnosis of Kryptos K4," HistoCrypt 2021 abstract: https://ecp.ep.liu.se/index.php/histocrypt/article/view/153
- Scientific American, "Final Clues to Mystery of CIA Kryptos Puzzle Released," 2025-11-12: https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/
- Associated Press, "Kryptos' final code remains unsolved. The CIA sculpture's creator is auctioning the solution," 2025-11-12: https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/
- Associated Press, "Archive about encoded artwork at CIA headquarters sells for nearly $1M," 2025-11-21: https://apnews.com/article/kryptos-jim-sanborn-auction-cia-secret-code-cb8ee8554ca473910cbd0592f8bdb350

## Open Risks

- The public clues may describe plaintext content, key material, mechanism, or thematic validation; source evidence does not always distinguish those roles.
- Reported clue positions sometimes appear in 0-based and 1-based forms across secondary references. The next phase must normalize positions explicitly.
- Gromark-like tests can be overfit unless compared against random or permuted baselines.
- Context clues such as Berlin World Clock and Egypt/Berlin Wall events are meaningful but underspecified; they should not be allowed to expand into unlimited key searches.
