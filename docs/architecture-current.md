# Current Implementation Architecture

Last updated: 2026-05-21

This diagram reflects the current implementation phase for the Rust `kryptos-k4` research CLI. It describes source-grounded research tooling only; it does not claim a Kryptos K4 solution.

```mermaid
flowchart TD
    User["CLI user / researcher"] --> Cli["kryptos-k4 CLI"]

    Cli --> Facts["facts / anchors / sources"]
    Cli --> Constraints["constraints / key-fragments"]
    Cli --> KeyTest["test-key"]
    Cli --> Baseline["baseline controls"]
    Cli --> Candidates["candidate-sequences"]
    Cli --> Routes["routes"]
    Cli --> Findings["findings"]
    Cli --> Report["report"]
    Cli --> Export["export-data"]
    Cli --> Release["release-check"]

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
    FindingsModel --> ReportModel
    ReleaseModel --> GeneratedReport
    ReleaseModel --> SourcePacket
    ReleaseModel --> ResearchPlan

    Tests["tests/cli_e2e.rs + unit tests"] --> Cli
    Tests --> ReleaseModel
```

## Current Guarantees

- Public K4 ciphertext, public anchors, and source provenance are modeled in Rust.
- Constraint, key-material test, baseline, candidate, route, findings, report, export, and release-check commands are implemented.
- Candidate, route, and baseline outputs carry non-promotion boundaries and next-test metadata.
- `test-key` compares proposed material against public span-derived additive fragments at actual K4 positions and never promotes candidates.
- Local release verification is implemented without GitHub Actions.
- E2E tests execute the compiled CLI and validate command outputs.

## Keep Updated

Update this file when a new command, report section, source model, release gate, or E2E path is added or removed.
