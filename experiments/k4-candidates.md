# K4 Candidate Key-Material Registry

This registry documents the source and rationale for rows in
`k4-candidates.csv`. Candidate rows are pre-registered exploratory
key-material inputs only. They are not solution claims, plaintext claims, or
promotion criteria.

## Rules

- Use only public facts already represented in `sources/source-packet.md`,
  `src/data.rs`, or `kryptos-k4-research-plan.md`.
- Add new rows only with a source ID and a short rationale.
- Evaluate candidate rows through batch, routed, and held-out controls before
  treating any result as a follow-up lead.
- Keep archive-sale reporting as historical context only; do not use
  archive-discovered plaintext or private auction material.

## Berlin World Clock Clue Family

Source IDs: `scientific-american-2025`, `elonka-kryptos`

Rationale: the public K4 clues include `BERLIN` and `CLOCK`, and 2025 public
reporting clarified the intended Berlin World Clock context. `ALEXANDERPLATZ`
is included as a source-grounded place association for the Berlin World Clock.

Rows:

- `BERLINWORLDCLOCK`, A1/Z26 zero-based and one-based
- `BERLINCLOCK`, A1/Z26 zero-based and one-based
- `WORLDCLOCK`, A1/Z26 zero-based and one-based
- `WELTZEITUHR`, A1/Z26 zero-based and one-based
- `ALEXANDERPLATZ`, A1/Z26 zero-based and one-based

## Public Anchor And Compass Direction Family

Source IDs: `elonka-kryptos`, `cia-sculpture`

Rationale: public anchors include `EAST` and `NORTHEAST`, while CIA public
sculpture context describes a compass/navigational component. These rows test
whether public direction words or bounded compass encodings align with public
additive fragments.

Rows:

- `EASTNORTHEAST`, A1/Z26 zero-based, A1/Z26 one-based, 8-point compass, and
  16-point compass
- `EAST`, A1/Z26 zero-based, A1/Z26 one-based, 8-point compass, and 16-point
  compass
- `NORTHEAST`, A1/Z26 zero-based, A1/Z26 one-based, 8-point compass, and
  16-point compass
- `BERLIN`, A1/Z26 zero-based and one-based
- `CLOCK`, A1/Z26 zero-based and one-based

## 2025 Reporting Event Clue Family

Source IDs: `scientific-american-2025`

Rationale: 2025 public reporting discussed Sanborn's final clue context around
Egypt, 1986, the Berlin Wall, and November 9, 1989. The date rows are decimal
digit candidates only.

Rows:

- `EGYPT`, A1/Z26 zero-based and one-based
- `1986`, decimal digits
- `BERLINWALL`, A1/Z26 zero-based and one-based
- `19891109`, decimal digits
- `11091989`, decimal digits

## CIA Sculpture/Chart/Matrix Family

Source IDs: `cia-artifact`, `cia-sculpture`

Rationale: CIA public pages identify Kryptos as a CIA sculpture/artifact,
describe the chart/table context, and frame K4 as a 97-character unsolved
section. The research plan also pre-registers Vigenere-like and matrix/route
families because CIA public context connects the sculpture's chart system and
matrix coding systems to the solved sections. This lane is intentionally
separate from the Berlin World Clock clue family.

Rows:

- `KRYPTOS`, A1/Z26 zero-based and one-based
- `KRYPTOSSCULPTURE`, A1/Z26 zero-based and one-based
- `VIGENERE`, A1/Z26 zero-based and one-based
- `VIGENERETABLE`, A1/Z26 zero-based and one-based
- `MATRIX`, A1/Z26 zero-based and one-based
- `MATRIXCODING`, A1/Z26 zero-based and one-based
- `NINETYSEVEN`, A1/Z26 zero-based and one-based
- `97`, decimal digits
