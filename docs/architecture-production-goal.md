# Production Goal Architecture

Last updated: 2026-05-25

The production goal is a public, source-grounded Rust research CLI and release package with reproducible local verification. Production readiness does not mean Kryptos K4 is solved, and it does not mean speculative plaintext, keys, routes, or methods are promoted.

```mermaid
flowchart TD
    Researcher["Researcher"] --> CLI["Rust CLI: kryptos-k4"]
    Researcher --> BackgroundRunner["Background experiment runner"]

    subgraph Evidence["Evidence Boundary"]
        PublicSources["Public sources only"]
        SourceRegistry["Rust source registry"]
        SourcePacket["Quote-free source packet"]
        Forbidden["Excluded: leaked, private, paid, archive plaintext"]
    end

    subgraph Core["Research Core"]
        DataModel["Ciphertext / anchors / spans"]
        ConstraintEngine["Alphabet and key-fragment analysis"]
        KeyMaterialChecks["Proposed key-material checks against public spans"]
        BaselineEngine["Seeded false-positive controls"]
        CandidateRegistry["Pre-registered contextual candidates"]
        RouteRegistry["Bounded deterministic route families"]
        FindingsLedger["Findings ledger with source, transform, baseline, interpretation, next test"]
        IndependentTargets["Preregistered non-anchor period, spacing, mirror, grid, and Tableau/HILL targets"]
    end

    subgraph Outputs["User Outputs"]
        MarkdownReport["Markdown report"]
        JsonReport["JSON report"]
        BatchArtifacts["Batch experiment artifacts"]
        LatestSummary["Latest ranked summary pointer"]
        HistorySummary["Historical result summary"]
        DataExports["Machine-readable exports"]
        HumanCli["Human-readable CLI output"]
    end

    subgraph Verification["Local Release Verification"]
        UnitTests["Unit tests"]
        E2ETests["CLI E2E tests"]
        FmtClippy["fmt + clippy -D warnings"]
        ReleaseBuild["locked release build"]
        ReleaseCheck["release-check local preflight"]
    end

    subgraph Release["Public Release"]
        GitHubPublic["Public GitHub repo"]
        PullRequests["Reviewable PR slices"]
        Tag["Version tag"]
        GitHubRelease["Manual GitHub release artifacts"]
    end

    CLI --> DataModel
    PublicSources --> SourceRegistry
    SourceRegistry --> DataModel
    SourcePacket --> SourceRegistry
    Forbidden -. "blocked by policy" .-> SourceRegistry

    DataModel --> ConstraintEngine
    ConstraintEngine --> KeyMaterialChecks
    ConstraintEngine --> BaselineEngine
    ConstraintEngine --> CandidateRegistry
    ConstraintEngine --> RouteRegistry
    KeyMaterialChecks --> FindingsLedger
    BaselineEngine --> FindingsLedger
    CandidateRegistry --> FindingsLedger
    RouteRegistry --> FindingsLedger
    DataModel --> IndependentTargets
    IndependentTargets --> FindingsLedger

    FindingsLedger --> MarkdownReport
    FindingsLedger --> JsonReport
    KeyMaterialChecks --> BatchArtifacts
    BackgroundRunner --> KeyMaterialChecks
    BackgroundRunner --> BatchArtifacts
    BackgroundRunner --> LatestSummary
    BatchArtifacts --> HistorySummary
    DataModel --> DataExports
    CLI --> HumanCli

    UnitTests --> ReleaseCheck
    E2ETests --> ReleaseCheck
    FmtClippy --> ReleaseCheck
    ReleaseBuild --> ReleaseCheck
    ReleaseCheck --> PullRequests
    PullRequests --> GitHubPublic
    GitHubPublic --> Tag
    Tag --> GitHubRelease
```

## Production Goal Gates

- Every factual source in the plan is registered in Rust and documented in the source packet.
- Every finding includes source inputs, transformation steps, baseline comparison, interpretation, and next test.
- Every command has E2E coverage for success paths and important guardrails.
- Proposed key material and cyclic phase offsets are evaluated only against public known-plaintext spans, explained with exact matching positions, descriptive pattern metrics, and composite pattern scores when requested, compared to seeded shuffled-value and best-of-candidate-file controls when requested, and remain non-promotional unless future independently justified evidence changes the release boundary.
- Background experiment loops are local, stoppable, and artifact-producing; they automate repeatable scoring but do not autonomously claim or promote a K4 solution.
- Historical result summaries compare completed batch runs and candidate stability before any candidate family is expanded.
- Independent prediction lanes require preregistration, committed prediction-artifact validation, source-backed observation validation, and period or spacing evaluation controls before any result is interpreted.
- Observation templates remain non-scorable, and source `allowed_use` boundaries prevent context-only sources from becoming scored evidence.
- `cargo fmt --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo test --locked --all-targets --all-features`, `cargo build --locked --release`, and `cargo run --locked -- release-check` pass locally.
- Releases remain manual and local-gated; no GitHub Actions or Dependabot policy drift.

## Keep Updated

Update this file when the release target changes, when a new production gate is added, or when the evidence boundary changes.
