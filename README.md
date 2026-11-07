# Kryptos K4 Research CLI

`kryptos-k4` is a Rust CLI for source-grounded work on Kryptos K4, the
unsolved fourth section of Jim Sanborn's sculpture at CIA headquarters. It
holds the public ciphertext, the public plaintext anchors, and a registry of
public sources. It derives what the anchors imply about a key, and tests
proposed keys and claims against them.

This project is not a claimed K4 solution. It never uses leaked,
archive-discovered, or private plaintext.

## Where things stand

- **K4 is 97 letters with 24 known plaintext letters:** `EASTNORTHEAST` at
  one-based positions 22–34 and `BERLINCLOCK` at 64–74.
- **Periodic additive keys are ruled out.** Vigenère, Beaufort, and variant
  Beaufort with either the standard or the Kryptos alphabet contradict the
  anchors at every period from 1 to 26. Cyclic short-word keys cannot work.
- **Anchor reproduction eliminates whole cipher families.** Pure
  transposition and Porta are impossible outright. Gronsfeld, ciphertext
  autokey, Gromark, and keyed columnar plus periodic tableau leave zero
  survivors over 15 million configurations. Periodic Quagmire I–IV and
  plaintext autokey leave only chance-level survivors. Limits apply; see
  [docs/negative-results.md](docs/negative-results.md).
- **Every statistical lane so far is negative.** One source-backed observation
  (six web-page row-boundary positions) was scored against 86 lanes, and none
  survived. See [docs/negative-results.md](docs/negative-results.md).
- **External solution claims are quarantined.** Three published claims keep
  the public anchors. The only one with a checkable mechanism (SolveKryptos)
  is not internally consistent.

Next step: run running keys from a fixed public corpus, and extend the
elimination to route transpositions and non-keyword alphabets. A method that
reproduces all 24 anchor letters by chance has probability about 26^-24, so a
miss is an elimination. See [docs/research-plan.md](docs/research-plan.md).

## Quick start

```bash
cargo build --release
target/release/kryptos-k4 facts
target/release/kryptos-k4 anchors
target/release/kryptos-k4 key-fragments --span BERLINCLOCK --alphabet kryptos
```

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.95). Every command
accepts `--format json`.

## Commands

| Command | What it does |
| --- | --- |
| `facts` | Ciphertext, length, and evidence boundary. |
| `anchors` | Public anchors with 0- and 1-based positions and source IDs. |
| `sources` | Source registry with allowed-use boundaries. |
| `constraints` | Key fragments implied by each anchor or merged span, per alphabet and mode. |
| `key-fragments` | One row per derived key value, filterable by anchor, span, alphabet, mode. |
| `ciphertext-profile` | Ciphertext-only frequencies, repeats, IC, and period coincidence, with optional shuffle nulls. |
| `test-key` | Score key material against the anchor-derived fragments; `--sweep-offsets` tries every phase. |
| `explain-key` | Show exactly which anchor positions a key matches at one offset. |
| `batch-test-keys` | `test-key` for every row of a CSV, with batch-level nulls. |
| `batch-test-routed-keys` | Same, after each registered route/permutation family. |
| `baseline` | Seeded null controls for the Gromark-style recurrence screen. |
| `candidate-sequences` | Preregistered contextual key material (World Clock, compass, 1986, 1989). |
| `routes` | Bounded named route experiments over the anchor fragments. |
| `hypotheses` | The ranked hypothesis register (H1–H5). |
| `findings` | Findings ledger: inputs, steps, baseline, interpretation, next test. |
| `eliminate` | Eliminate cipher families by anchor reproduction; reports survivors against chance. |
| `running-key` | Test every offset of a local text file as a running key. |
| `verify-claim` | Check a local claim file without printing it (see below). |
| `report` | Full Markdown or JSON report; `notes/k4-report.md` is the committed copy. |
| `export-data` | Write ciphertext, anchors, and sources as JSON. |
| `release-check` | Local release gate. |

Examples:

```bash
kryptos-k4 test-key --material BERLINWORLDCLOCK --sweep-offsets
kryptos-k4 explain-key --material BERLINWORLDCLOCK --offset 0
kryptos-k4 batch-test-keys --input experiments/k4-candidates.csv --batch-baseline-iterations 1000
kryptos-k4 eliminate
kryptos-k4 running-key --corpus /path/to/text.txt
kryptos-k4 report --format markdown --output notes/k4-report.md
```

## Checking an external claim

Claims are registered in `src/data.rs` as `unverified-solution-claim`
sources. Put the claim in a temporary file outside the repo, then run:

```bash
kryptos-k4 verify-claim --plaintext /tmp/claim.txt --source-id solvekryptos-2026-claim
kryptos-k4 verify-claim --plaintext /tmp/claim.txt --key /tmp/key.txt --alphabet standard \
  --source-id ssrn-bonifacino-running-key-2025
```

It reports normalized length, anchor preservation, shift statistics, and (with
`--key`) whether plaintext plus key reproduces the ciphertext. It never prints
or stores the claim. Commit only the aggregate result, under
`results/claim-verifications/<source-id>-<date>/`, and delete the temporary
files.

## Evidence rules

Allowed: CIA pages, public Sanborn statements, reputable reporting, academic
cryptanalysis, and the publicly released anchor words. Community research is
methodology context, not evidence.

Excluded: claimed full plaintexts used as evidence, leaked or
archive-discovered plaintext, paid or private archive material, and
coincidence-hunting that does not lead to a falsifiable test.

Every source has an ID, URL, access date, and allowed-use label in
`src/data.rs` and [sources/source-packet.md](sources/source-packet.md), with a
quote-free snapshot in `sources/archives/`.

## Layout

| Path | Contents |
| --- | --- |
| `src/data.rs`, `src/alphabet.rs` | Ciphertext, anchors, sources, alphabets. |
| `src/analysis.rs`, `src/baseline.rs` | Anchor-derived fragments and seeded null controls. |
| `src/eliminate.rs` | Anchor-reproduction elimination and running-key scan. |
| `src/key_test.rs`, `src/candidates.rs`, `src/routes.rs` | Key-material, candidate, and route tests. |
| `src/ciphertext_profile.rs` | Ciphertext-only diagnostics. |
| `src/claim.rs` | Quarantined claim verification. |
| `src/findings.rs`, `src/hypotheses.rs`, `src/report.rs` | Ledger, hypotheses, report rendering. |
| `src/release_check.rs` | Release gate. |
| `src/main.rs`, `src/cli/` | Command-line parsing and output. |
| `experiments/` | Candidate CSV and registry, the row-boundary observation, its source review, and the W-delimiter coordinate note. |
| `results/` | Scored evaluation archives and claim-verification archives. |
| `docs/` | Negative results, research plan, journal. |

The lane, preregistration, and evidence-gate tooling from May–June 2026 was
removed in November 2026. It is preserved at git tag `pre-slimdown`; check out
that tag to re-run an archived evaluation from its `command.txt`.

## Development and release

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- release-check
```

`release-check` fails if GitHub Actions or Dependabot config exists, if a
claim-verification archive could promote a claim or lacks its no-plaintext
statement, or if a leaked-plaintext sentinel marker appears in docs,
experiments, notes, sources, or claim archives. Releases are manual: run the
checks, build with `cargo build --locked --release`, tag, and publish with
`gh release create`. This repo does not use GitHub Actions.

Record changes in direction or result in [docs/JOURNAL.md](docs/JOURNAL.md).

## License

MIT. See [LICENSE](LICENSE).
