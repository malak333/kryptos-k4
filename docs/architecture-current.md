# Current Implementation Architecture

Last updated: 2026-05-22

This diagram reflects the current implementation phase for the Rust `kryptos-k4` research CLI. It describes source-grounded research tooling only; it does not claim a Kryptos K4 solution.

```mermaid
flowchart TD
    User["CLI user / researcher"] --> Cli["kryptos-k4 CLI"]
    User --> BackgroundScripts["background batch scripts"]

    Cli --> Facts["facts / anchors / sources"]
    Cli --> Constraints["constraints / key-fragments"]
    Cli --> KeyTest["test-key / explain-key / batch-test-keys / summarize-key-runs"]
    Cli --> Baseline["baseline controls"]
    Cli --> Candidates["candidate-sequences"]
    Cli --> Routes["routes"]
    Cli --> Findings["findings"]
    Cli --> Report["report"]
    Cli --> Export["export-data"]
    Cli --> Release["release-check"]
    BackgroundScripts --> BatchLoop["run-key-batch-loop.sh timestamped batch loop"]
    BackgroundScripts --> StartStop["start / stop wrappers with flags"]
    BatchLoop --> KeyTest

    Facts --> Data["src/data.rs public ciphertext, anchors, sources"]
    Constraints --> Data
    Constraints --> Alphabets["src/alphabet.rs standard, Kryptos, reversed Kryptos"]
    KeyTest --> KeyTestModel["src/key_test.rs proposed material checks"]
    KeyTest --> CandidateModel["src/candidates.rs transforms"]
    KeyTest --> Analysis["src/analysis.rs anchor/span fragments"]
    Baseline --> Analysis["src/analysis.rs anchor/span fragments"]
    Candidates --> CandidateModel["src/candidates.rs pre-registered contextual material"]
    Routes --> RouteModel["src/routes.rs bounded named route families"]
    Findings --> FindingsModel["src/findings.rs findings ledger"]
    Report --> ReportModel["src/report.rs Markdown / JSON report model"]
    Export --> Data
    Release --> ReleaseModel["src/release_check.rs local release gates"]

    Data --> SourcePacket["sources/source-packet.md quote-free source summaries"]
    Data --> ResearchPlan["kryptos-k4-research-plan.md scope, hypotheses, next tests"]
    ReportModel --> GeneratedReport["notes/k4-report.md generated release report"]
    BatchLoop --> BatchArtifacts["results/key-tests ignored local artifacts"]
    KeyTest --> BatchArtifacts
    FindingsModel --> ReportModel
    ReleaseModel --> GeneratedReport
    ReleaseModel --> SourcePacket
    ReleaseModel --> ResearchPlan

    Tests["tests/cli_e2e.rs + unit tests"] --> Cli
    Tests --> ReleaseModel
```

## Current Guarantees

- Public K4 ciphertext, public anchors, and source provenance are modeled in Rust.
- Constraint, key-material test/explanation, baseline, candidate, route, findings, report, export, and release-check commands are implemented.
- Candidate, route, and baseline outputs carry non-promotion boundaries and next-test metadata.
- `test-key`, `explain-key`, and `batch-test-keys` compare proposed material against public span-derived additive fragments at actual K4 positions, can sweep cyclic phase offsets, can print exact matching rows, can report descriptive pattern metrics, can run seeded shuffled-value and candidate-file-level baselines, and never promote candidates.
- `summarize-key-runs` scans historical batch result folders and ranks both individual run rows and per-candidate p-value stability.
- Background wrapper scripts can run repeated `batch-test-keys` experiments with explicit flags, timestamped local artifacts, latest-result pointers, and optional macOS keep-awake support.
- Local release verification is implemented without GitHub Actions.
- E2E tests execute the compiled CLI and validate command outputs.

## Keep Updated

Update this file when a new command, report section, source model, release gate, or E2E path is added or removed.
