use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use kryptos_k4::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, BatchKeyMaterialCandidate,
    BatchKeyMaterialRun, BatchKeyRunHistory, CandidateTransform, FragmentMode,
    HeldoutKeyControlRun, IndependentLaneStatus, IndependentLaneStatusReport, K4_CIPHERTEXT,
    KeyMaterialExplanation, KeyMaterialOffsetSweep, KeyMaterialTest, LanePreregistration,
    PeriodPredictionEvaluation, PeriodPredictionPlan, PeriodPredictionPlanSet,
    PositionStructureRun, PredictionArtifactValidation, PreregistrationValidation, ReportFormat,
    RoutedBatchKeyMaterialRun, SpacingPredictionEvaluation, SpacingPredictionPlanSet,
    StructuralModelRun, analyze_constraints, analyze_known_plaintext_spans,
    batch_test_key_material_with_batch_baseline, batch_test_routed_key_material,
    build_all_period_prediction_plans, build_all_spacing_prediction_plans,
    build_period_prediction_plan, build_report, candidate_sequences,
    evaluate_period_prediction_positions, evaluate_spacing_prediction_positions,
    explain_key_material, findings, heldout_key_control, hypotheses, known_anchors,
    load_and_validate_preregistration, render_report, run_baseline, run_position_structure_control,
    run_release_checks, run_route_experiments, run_structural_model_control,
    score_candidate_sequences, sources, summarize_batch_key_material_runs,
    summarize_independent_lanes, sweep_key_material_offsets_with_baseline, test_key_material,
    validate_prediction_artifact, validate_preregistration, validation_exit_result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print core public K4 facts and evidence boundary.
    Facts {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print public known-plaintext anchors with positions and source IDs.
    Anchors {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print derived constraint fragments for anchors or adjacent spans.
    Constraints {
        /// Analyze merged adjacent known-plaintext spans instead of individual anchors.
        #[arg(long)]
        spans: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print one row per derived key fragment, with optional filters.
    KeyFragments {
        /// Filter by individual anchor label, for example BERLIN.
        #[arg(long, conflicts_with = "span")]
        anchor: Option<String>,
        /// Filter by adjacent known-plaintext span label, for example BERLINCLOCK.
        #[arg(long, conflicts_with = "anchor")]
        span: Option<String>,
        /// Filter by alphabet.
        #[arg(long, value_enum)]
        alphabet: Option<CliAlphabet>,
        /// Filter by derivation mode.
        #[arg(long, value_enum)]
        mode: Option<CliFragmentMode>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Test proposed key material against public span-derived additive fragments.
    TestKey {
        /// Proposed key material to transform and cycle across K4 positions.
        #[arg(long)]
        material: String,
        /// Transform used to convert material into numeric values.
        #[arg(long, value_enum, default_value_t = CliCandidateTransform::A1Z26ZeroBased)]
        transform: CliCandidateTransform,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Try every cyclic phase offset and rank the resulting matches.
        #[arg(long)]
        sweep_offsets: bool,
        /// Maximum ranked offsets to print when sweeping. JSON output always includes all offsets.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Seeded shuffled-value null iterations for the best offset score. Requires --sweep-offsets.
        #[arg(long, default_value_t = 0)]
        sweep_baseline_iterations: usize,
        /// Seed for deterministic offset-sweep baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Explain one key-material lead by printing exact matching public-span positions.
    ExplainKey {
        /// Proposed key material to transform and cycle across K4 positions.
        #[arg(long)]
        material: String,
        /// Transform used to convert material into numeric values.
        #[arg(long, value_enum, default_value_t = CliCandidateTransform::A1Z26ZeroBased)]
        transform: CliCandidateTransform,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Cyclic phase offset to explain. If omitted, the best-scoring offset is used.
        #[arg(long)]
        offset: Option<usize>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Run key-material checks for every candidate row in a CSV file.
    BatchTestKeys {
        /// CSV file with rows: material,transform. Header row is optional.
        #[arg(long)]
        input: PathBuf,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Seeded shuffled-value null iterations for each candidate's best offset.
        #[arg(long, default_value_t = 1_000)]
        sweep_baseline_iterations: usize,
        /// Seeded null iterations for the best score across all candidate rows and transforms.
        #[arg(long, default_value_t = 0)]
        batch_baseline_iterations: usize,
        /// Seed for deterministic offset-sweep baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for input.csv, results.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format for stdout.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Apply registered route/permutation families before scoring every candidate row in a CSV file.
    BatchTestRoutedKeys {
        /// CSV file with rows: material,transform. Header row is optional.
        #[arg(long)]
        input: PathBuf,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Seeded shuffled-value null iterations for each routed candidate's best offset.
        #[arg(long, default_value_t = 1_000)]
        sweep_baseline_iterations: usize,
        /// Seeded null iterations for the best score across all candidate rows, transforms, spans, and routes.
        #[arg(long, default_value_t = 0)]
        batch_baseline_iterations: usize,
        /// Seed for deterministic routed offset-sweep baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for input.csv, results.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format for stdout.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Select on non-overlapping public fragment groups, then score each held-out group.
    HeldoutKeyControl {
        /// CSV file with rows: material,transform. Header row is optional.
        #[arg(long)]
        input: PathBuf,
        /// Alphabet used for public fragment groups.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Seeded null iterations that re-run training selection before scoring each held-out group.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic held-out null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for input.csv, results.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format for stdout.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Summarize historical batch-test result folders.
    SummarizeKeyRuns {
        /// Directory to scan recursively for results.json files.
        #[arg(long)]
        input_dir: PathBuf,
        /// Maximum individual result rows to print.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format for stdout.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Run deterministic false-positive controls for the generic recurrence screen.
    Baseline {
        /// Target family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineTarget::Spans)]
        target: CliBaselineTarget,
        /// Alphabet family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineAlphabet::All)]
        alphabet: CliBaselineAlphabet,
        /// Number of seeded null iterations.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Test candidate-independent residue and spacing structure over public fragments.
    PositionStructure {
        /// Target family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineTarget::Spans)]
        target: CliBaselineTarget,
        /// Alphabet family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineAlphabet::All)]
        alphabet: CliBaselineAlphabet,
        /// Public fragment mode to evaluate.
        #[arg(long, value_enum, default_value_t = CliFragmentMode::Additive)]
        mode: CliFragmentMode,
        /// Number of seeded null iterations.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Evaluate pre-registered position models before considering new key material.
    StructuralModels {
        /// Target family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineTarget::Spans)]
        target: CliBaselineTarget,
        /// Alphabet family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineAlphabet::All)]
        alphabet: CliBaselineAlphabet,
        /// Public fragment mode to evaluate.
        #[arg(long, value_enum, default_value_t = CliFragmentMode::Additive)]
        mode: CliFragmentMode,
        /// Number of seeded null iterations.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate a preregistered lane before adding new candidates or structural tests.
    ValidatePreregistration {
        /// JSON preregistration file to validate.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate a committed independent prediction artifact against its preregistration.
    ValidatePredictionArtifact {
        /// JSON preregistration file that points to the prediction artifact.
        #[arg(long)]
        preregistration: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Summarize preregistered independent lanes and their next required gate.
    IndependentLaneStatus {
        /// Directory containing lane preregistration JSON files.
        #[arg(long, default_value = "experiments/preregistrations")]
        directory: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print the next source-backed evidence gate and exact command sequence.
    NextEvidenceGate {
        /// Directory containing lane preregistration JSON files.
        #[arg(long, default_value = "experiments/preregistrations")]
        directory: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Create a guarded source-backed non-anchor position observation JSON file.
    InitPositionObservations {
        /// Stable observation file ID.
        #[arg(long)]
        id: String,
        /// Registered source ID. Repeat for multiple sources.
        #[arg(long = "source-id", required = true)]
        source_ids: Vec<String>,
        /// Comma-separated one-based K4 positions to write.
        #[arg(long)]
        positions: String,
        /// Rationale for why these positions are independent non-anchor observations.
        #[arg(long)]
        rationale: String,
        /// Per-position note as POS=NOTE. Repeat for each position when source evidence differs.
        #[arg(long = "position-note")]
        position_notes: Vec<String>,
        /// Output JSON path.
        #[arg(long)]
        output: PathBuf,
        /// Overwrite an existing output file.
        #[arg(long)]
        force: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed non-anchor position observations before scoring them.
    ValidatePeriodObservations {
        /// JSON artifact emitted by period-prediction-plan --all --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the prediction artifact at the same time.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed non-anchor position observations before spacing scoring.
    ValidateSpacingObservations {
        /// JSON artifact emitted by spacing-prediction-plan --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the spacing prediction artifact at the same time.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a predeclared non-anchor residue-class target for future independent evidence.
    PeriodPredictionPlan {
        /// Registered period to use for the residue-class prediction.
        #[arg(long, conflicts_with = "all")]
        period: Option<usize>,
        /// Emit plans for every registered period and require future best-of-period controls.
        #[arg(long)]
        all: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit predeclared non-anchor spacing residue targets for future independent evidence.
    SpacingPredictionPlan {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Evaluate independent non-anchor positions against a committed period prediction artifact.
    EvaluatePeriodPrediction {
        /// JSON artifact emitted by period-prediction-plan --all --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the prediction artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// Comma-separated one-based K4 positions to evaluate. Positions must be non-anchor positions.
        #[arg(
            long,
            conflicts_with = "positions_file",
            required_unless_present = "positions_file"
        )]
        positions: Option<String>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(
            long,
            conflicts_with = "positions",
            required_unless_present = "positions"
        )]
        positions_file: Option<PathBuf>,
        /// Seeded null iterations for best-of-period position concentration.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for artifact.json, preregistration.json, input, result.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Evaluate independent non-anchor positions against a committed spacing prediction artifact.
    EvaluateSpacingPrediction {
        /// JSON artifact emitted by spacing-prediction-plan --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the prediction artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// Comma-separated one-based K4 positions to evaluate. Positions must be non-anchor positions.
        #[arg(
            long,
            conflicts_with = "positions_file",
            required_unless_present = "positions_file"
        )]
        positions: Option<String>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(
            long,
            conflicts_with = "positions",
            required_unless_present = "positions"
        )]
        positions_file: Option<PathBuf>,
        /// Seeded null iterations for best-of-modulus spacing concentration.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for artifact.json, preregistration.json, input, result.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate a self-contained independent observation evaluation archive.
    ValidateEvaluationArchive {
        /// Directory produced by evaluate-period-prediction or evaluate-spacing-prediction --output-dir.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print ranked source-grounded hypotheses.
    Hypotheses {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print pre-registered contextual candidate sequences.
    CandidateSequences {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print bounded named route experiments over public fragments.
    Routes {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print the current findings ledger with evidence, baselines, and next tests.
    Findings {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print source provenance records.
    Sources {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print sources eligible for scored independent position observations.
    ObservationSources {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Run local release preflight checks. Does not use GitHub Actions.
    ReleaseCheck {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Render the full research report.
    Report {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
        /// Optional output path. Prints to stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Write machine-readable ciphertext, anchor, and source JSON files.
    ExportData {
        /// Directory where JSON data files should be written.
        #[arg(long, default_value = "data")]
        directory: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Markdown,
    Json,
}

#[derive(Debug, Serialize)]
struct KeyFragmentRow {
    target_kind: &'static str,
    target_label: String,
    alphabet: AlphabetKind,
    position_zero_based: usize,
    position_one_based: usize,
    plaintext: char,
    ciphertext: char,
    mode: FragmentMode,
    value: u8,
    symbol: char,
    promoted_candidate: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PeriodPredictionObservationFile {
    id: String,
    source_ids: Vec<String>,
    positions_one_based: Vec<usize>,
    #[serde(default)]
    position_notes: BTreeMap<String, String>,
    rationale: String,
}

#[derive(Debug)]
struct PeriodPredictionObservationInput {
    id: Option<String>,
    source_ids: Vec<String>,
    rationale: Option<String>,
    positions_one_based: Vec<usize>,
    position_notes: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct PeriodPredictionObservationValidation {
    artifact_path: String,
    preregistration_id: Option<String>,
    artifact_valid: Option<bool>,
    observation_id: String,
    observation_source_ids: Vec<String>,
    observation_rationale: String,
    observed_position_count: usize,
    observed_positions_one_based: Vec<usize>,
    observation_position_notes: BTreeMap<String, String>,
    valid: bool,
    errors: Vec<String>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct PositionObservationScaffoldReport {
    output_path: String,
    observation: PeriodPredictionObservationFile,
    valid: bool,
    errors: Vec<String>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct ObservationSourceEligibilityReport {
    eligible_count: usize,
    ineligible_count: usize,
    sources: Vec<ObservationSourceEligibility>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct ObservationSourceEligibility {
    id: &'static str,
    label: &'static str,
    allowed_use: &'static str,
    eligible_for_scored_observations: bool,
    reason: String,
}

#[derive(Debug, Serialize)]
struct NextEvidenceGateReport {
    lane_directory: String,
    ready_lanes: usize,
    invalid_lanes: usize,
    unique_ready_prediction_artifacts: usize,
    eligible_source_ids: Vec<String>,
    ineligible_source_count: usize,
    required_observation_fields: Vec<&'static str>,
    gates: Vec<NextEvidenceGate>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct NextEvidenceGate {
    hypothesis_family: String,
    ready_lanes: usize,
    unique_ready_prediction_artifacts: usize,
    representative_preregistration: String,
    representative_artifact: String,
    observation_scaffold_command: String,
    validation_command: String,
    evaluation_command: String,
    archive_validation_command: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliAlphabet {
    Standard,
    Kryptos,
    KryptosReversed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliFragmentMode {
    #[value(name = "additive-key")]
    Additive,
    #[value(name = "subtractive-key")]
    Subtractive,
    #[value(name = "beaufort-key")]
    Beaufort,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliBaselineTarget {
    Anchors,
    Spans,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliBaselineAlphabet {
    Standard,
    Kryptos,
    KryptosReversed,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliCandidateTransform {
    #[value(name = "a1-z26-zero-based")]
    A1Z26ZeroBased,
    #[value(name = "a1-z26-one-based")]
    A1Z26OneBased,
    #[value(name = "decimal-digits")]
    DecimalDigits,
    #[value(name = "compass8-point")]
    Compass8Point,
    #[value(name = "compass16-point")]
    Compass16Point,
}

struct TestKeyOptions {
    material: String,
    transform: CliCandidateTransform,
    alphabet: CliAlphabet,
    sweep_offsets: bool,
    top: usize,
    sweep_baseline_iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct ExplainKeyOptions {
    material: String,
    transform: CliCandidateTransform,
    alphabet: CliAlphabet,
    offset: Option<usize>,
    format: OutputFormat,
}

struct InitPositionObservationOptions {
    id: String,
    source_ids: Vec<String>,
    positions: String,
    rationale: String,
    position_notes: Vec<String>,
    output: PathBuf,
    force: bool,
    format: OutputFormat,
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Markdown => ReportFormat::Markdown,
            OutputFormat::Json => ReportFormat::Json,
        }
    }
}

impl From<CliAlphabet> for AlphabetKind {
    fn from(value: CliAlphabet) -> Self {
        match value {
            CliAlphabet::Standard => AlphabetKind::Standard,
            CliAlphabet::Kryptos => AlphabetKind::Kryptos,
            CliAlphabet::KryptosReversed => AlphabetKind::KryptosReversed,
        }
    }
}

impl From<CliFragmentMode> for FragmentMode {
    fn from(value: CliFragmentMode) -> Self {
        match value {
            CliFragmentMode::Additive => FragmentMode::AdditiveKey,
            CliFragmentMode::Subtractive => FragmentMode::SubtractiveKey,
            CliFragmentMode::Beaufort => FragmentMode::BeaufortKey,
        }
    }
}

impl From<CliBaselineTarget> for BaselineTargetScope {
    fn from(value: CliBaselineTarget) -> Self {
        match value {
            CliBaselineTarget::Anchors => BaselineTargetScope::Anchors,
            CliBaselineTarget::Spans => BaselineTargetScope::Spans,
            CliBaselineTarget::All => BaselineTargetScope::All,
        }
    }
}

impl From<CliBaselineAlphabet> for BaselineAlphabetScope {
    fn from(value: CliBaselineAlphabet) -> Self {
        match value {
            CliBaselineAlphabet::Standard => BaselineAlphabetScope::Standard,
            CliBaselineAlphabet::Kryptos => BaselineAlphabetScope::Kryptos,
            CliBaselineAlphabet::KryptosReversed => BaselineAlphabetScope::KryptosReversed,
            CliBaselineAlphabet::All => BaselineAlphabetScope::All,
        }
    }
}

impl From<CliCandidateTransform> for CandidateTransform {
    fn from(value: CliCandidateTransform) -> Self {
        match value {
            CliCandidateTransform::A1Z26ZeroBased => CandidateTransform::A1Z26ZeroBased,
            CliCandidateTransform::A1Z26OneBased => CandidateTransform::A1Z26OneBased,
            CliCandidateTransform::DecimalDigits => CandidateTransform::DecimalDigits,
            CliCandidateTransform::Compass8Point => CandidateTransform::Compass8Point,
            CliCandidateTransform::Compass16Point => CandidateTransform::Compass16Point,
        }
    }
}

fn parse_position_list(input: &str) -> std::result::Result<Vec<usize>, String> {
    let positions: Result<Vec<_>, _> = input
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<usize>()
                .map_err(|_| format!("invalid one-based position `{part}`"))
        })
        .collect();
    let positions = positions?;
    if positions.is_empty() {
        Err("positions must include at least one one-based K4 position".to_string())
    } else {
        Ok(positions)
    }
}

fn contains_template_placeholder(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("replace-with")
        || normalized.contains("replace with")
        || normalized.contains("explain why")
        || normalized.contains("describe the")
        || normalized.contains("define the")
}

fn read_period_prediction_observation_file(path: &Path) -> Result<PeriodPredictionObservationFile> {
    let input = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&input)?)
}

fn validate_period_prediction_observation_fields(
    observations: &PeriodPredictionObservationFile,
) -> Vec<String> {
    let mut errors = Vec::new();
    if observations.id.trim().is_empty() {
        errors.push("positions_file id must not be empty".to_string());
    }
    if contains_template_placeholder(&observations.id) {
        errors.push("positions_file id still contains template placeholder text".to_string());
    }
    if observations.source_ids.is_empty()
        || observations
            .source_ids
            .iter()
            .any(|source_id| source_id.trim().is_empty())
    {
        errors.push("positions_file must include at least one registered source_id".to_string());
    }
    for source_id in &observations.source_ids {
        if contains_template_placeholder(source_id) {
            errors.push(
                "positions_file source_ids still contain template placeholder text".to_string(),
            );
        }
    }
    if observations.rationale.trim().is_empty() {
        errors.push("positions_file rationale must not be empty".to_string());
    }
    if contains_template_placeholder(&observations.rationale) {
        errors
            .push("positions_file rationale still contains template placeholder text".to_string());
    }
    if observations.positions_one_based.is_empty() {
        errors.push("positions_file must include at least one one-based K4 position".to_string());
    }
    if observations.position_notes.is_empty() {
        errors.push(
            "positions_file position_notes must include one note for each one-based K4 position"
                .to_string(),
        );
    }

    let registered_sources: std::collections::BTreeMap<_, _> = sources()
        .into_iter()
        .map(|source| (source.id, source))
        .collect();
    for source_id in &observations.source_ids {
        if !source_id.trim().is_empty() && !contains_template_placeholder(source_id) {
            let Some(source) = registered_sources.get(source_id.as_str()) else {
                errors.push(format!(
                    "positions_file source_id `{source_id}` is not registered"
                ));
                continue;
            };

            if !period_observation_source_use_is_allowed(source.allowed_use) {
                errors.push(format!(
                    "positions_file source_id `{source_id}` has allowed_use `{}` and cannot be scored as independent position evidence",
                    source.allowed_use
                ));
            }
        }
    }

    let observed_positions: HashSet<_> = observations.positions_one_based.iter().copied().collect();
    for position in &observations.positions_one_based {
        let key = position.to_string();
        match observations.position_notes.get(&key) {
            Some(note) if note.trim().is_empty() => {
                errors.push(format!(
                    "position_notes entry for position `{position}` is empty"
                ));
            }
            Some(note) if contains_template_placeholder(note) => {
                errors.push(format!(
                    "position_notes entry for position `{position}` still contains template placeholder text"
                ));
            }
            Some(_) => {}
            None => errors.push(format!(
                "position_notes is missing an entry for position `{position}`"
            )),
        }
    }
    for position_key in observations.position_notes.keys() {
        match position_key.parse::<usize>() {
            Ok(position) if observed_positions.contains(&position) => {}
            Ok(position) => errors.push(format!(
                "position_notes includes position `{position}` that is not listed in positions_one_based"
            )),
            Err(_) => errors.push(format!(
                "position_notes key `{position_key}` is not a one-based K4 position"
            )),
        }
    }

    errors
}

fn period_observation_source_use_is_allowed(allowed_use: &str) -> bool {
    matches!(allowed_use, "public-facts-only")
}

fn load_period_prediction_observations(path: &Path) -> Result<PeriodPredictionObservationInput> {
    let observations = read_period_prediction_observation_file(path)?;
    let errors = validate_period_prediction_observation_fields(&observations);
    if !errors.is_empty() {
        anyhow::bail!(errors.join("; "));
    }

    Ok(PeriodPredictionObservationInput {
        id: Some(observations.id),
        source_ids: observations.source_ids,
        rationale: Some(observations.rationale),
        positions_one_based: observations.positions_one_based,
        position_notes: observations.position_notes,
    })
}

fn validate_position_observation_scaffold(
    observations: &PeriodPredictionObservationFile,
) -> Vec<String> {
    let mut errors = validate_period_prediction_observation_fields(observations);
    let anchor_positions: HashSet<_> = known_anchors()
        .into_iter()
        .flat_map(|anchor| anchor.start_one_based()..=anchor.end_one_based_inclusive())
        .collect();
    let mut seen = HashSet::new();

    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if *position == 0 || *position > K4_CIPHERTEXT.len() {
            errors.push(format!(
                "position `{position}` is outside the one-based K4 range 1..={}",
                K4_CIPHERTEXT.len()
            ));
        }
        if anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is a public-anchor position and cannot be used as independent observation evidence"
            ));
        }
    }

    errors
}

fn create_position_observation_file(
    id: String,
    source_ids: Vec<String>,
    positions: String,
    rationale: String,
    position_note_inputs: Vec<String>,
    output: PathBuf,
    force: bool,
) -> Result<PositionObservationScaffoldReport> {
    if output.exists() && !force {
        anyhow::bail!(
            "output file already exists: {}; pass --force to overwrite",
            output.display()
        );
    }

    let positions_one_based = parse_position_list(&positions).map_err(anyhow::Error::msg)?;
    let position_notes =
        build_position_notes(&positions_one_based, &rationale, &position_note_inputs)?;
    let observation = PeriodPredictionObservationFile {
        id,
        source_ids,
        positions_one_based,
        position_notes,
        rationale,
    };
    let errors = validate_position_observation_scaffold(&observation);
    if !errors.is_empty() {
        anyhow::bail!(errors.join("; "));
    }

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &output,
        format!("{}\n", serde_json::to_string_pretty(&observation)?),
    )?;

    Ok(PositionObservationScaffoldReport {
        output_path: output.display().to_string(),
        observation,
        valid: true,
        errors,
        promoted_candidate: false,
        note: "Position observation scaffolding writes source-backed non-anchor positions only; it is not a claimed solution.",
    })
}

fn build_position_notes(
    positions_one_based: &[usize],
    rationale: &str,
    position_note_inputs: &[String],
) -> Result<BTreeMap<String, String>> {
    if position_note_inputs.is_empty() {
        return Ok(positions_one_based
            .iter()
            .map(|position| {
                (
                    position.to_string(),
                    format!("Source-backed note for one-based K4 position {position}: {rationale}"),
                )
            })
            .collect());
    }

    let allowed_positions: HashSet<_> = positions_one_based.iter().copied().collect();
    let mut notes = BTreeMap::new();
    for input in position_note_inputs {
        let Some((position_text, note)) = input.split_once('=') else {
            anyhow::bail!("position-note `{input}` must use POS=NOTE");
        };
        let position = position_text
            .trim()
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("position-note `{input}` has invalid position"))?;
        if !allowed_positions.contains(&position) {
            anyhow::bail!(
                "position-note `{input}` references position `{position}` not listed in --positions"
            );
        }
        let note = note.trim();
        if note.is_empty() {
            anyhow::bail!("position-note for position `{position}` must not be empty");
        }
        if notes
            .insert(position.to_string(), note.to_string())
            .is_some()
        {
            anyhow::bail!("position-note for position `{position}` was provided more than once");
        }
    }

    for position in positions_one_based {
        if !notes.contains_key(&position.to_string()) {
            anyhow::bail!(
                "position-note is missing for position `{position}`; provide one POS=NOTE entry for every --positions value"
            );
        }
    }

    Ok(notes)
}

fn load_period_prediction_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let plans: PeriodPredictionPlanSet = serde_json::from_str(&input)?;
    let positions = plans
        .plans
        .into_iter()
        .flat_map(|plan| plan.residues)
        .flat_map(|residue| residue.positions_one_based)
        .collect();
    Ok(positions)
}

fn load_spacing_prediction_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let plans: SpacingPredictionPlanSet = serde_json::from_str(&input)?;
    let positions = plans
        .plans
        .into_iter()
        .flat_map(|plan| plan.positions_one_based)
        .collect();
    Ok(positions)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Facts { format } => print_facts(format)?,
        Command::Anchors { format } => print_anchors(format)?,
        Command::Constraints { spans, format } => print_constraints(spans, format)?,
        Command::KeyFragments {
            anchor,
            span,
            alphabet,
            mode,
            format,
        } => print_key_fragments(anchor, span, alphabet, mode, format)?,
        Command::TestKey {
            material,
            transform,
            alphabet,
            sweep_offsets,
            top,
            sweep_baseline_iterations,
            seed,
            format,
        } => print_test_key(TestKeyOptions {
            material,
            transform,
            alphabet,
            sweep_offsets,
            top,
            sweep_baseline_iterations,
            seed,
            format,
        })?,
        Command::ExplainKey {
            material,
            transform,
            alphabet,
            offset,
            format,
        } => print_explain_key(ExplainKeyOptions {
            material,
            transform,
            alphabet,
            offset,
            format,
        })?,
        Command::BatchTestKeys {
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        } => print_batch_test_keys(
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        )?,
        Command::BatchTestRoutedKeys {
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        } => print_batch_test_routed_keys(
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        )?,
        Command::HeldoutKeyControl {
            input,
            alphabet,
            iterations,
            seed,
            output_dir,
            format,
        } => print_heldout_key_control(input, alphabet, iterations, seed, output_dir, format)?,
        Command::SummarizeKeyRuns {
            input_dir,
            top,
            format,
        } => print_summarize_key_runs(input_dir, top, format)?,
        Command::Baseline {
            target,
            alphabet,
            iterations,
            seed,
            format,
        } => print_baseline(target, alphabet, iterations, seed, format)?,
        Command::PositionStructure {
            target,
            alphabet,
            mode,
            iterations,
            seed,
            format,
        } => print_position_structure(target, alphabet, mode, iterations, seed, format)?,
        Command::StructuralModels {
            target,
            alphabet,
            mode,
            iterations,
            seed,
            format,
        } => print_structural_models(target, alphabet, mode, iterations, seed, format)?,
        Command::ValidatePreregistration { input, format } => {
            print_validate_preregistration(input, format)?
        }
        Command::ValidatePredictionArtifact {
            preregistration,
            format,
        } => print_validate_prediction_artifact(preregistration, format)?,
        Command::IndependentLaneStatus { directory, format } => {
            print_independent_lane_status(directory, format)?
        }
        Command::NextEvidenceGate { directory, format } => {
            print_next_evidence_gate(directory, format)?
        }
        Command::InitPositionObservations {
            id,
            source_ids,
            positions,
            rationale,
            position_notes,
            output,
            force,
            format,
        } => print_init_position_observations(InitPositionObservationOptions {
            id,
            source_ids,
            positions,
            rationale,
            position_notes,
            output,
            force,
            format,
        })?,
        Command::ValidatePeriodObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_period_observations(artifact, preregistration, input, format)?,
        Command::ValidateSpacingObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_spacing_observations(artifact, preregistration, input, format)?,
        Command::PeriodPredictionPlan {
            period,
            all,
            format,
        } => print_period_prediction_plan(period, all, format)?,
        Command::SpacingPredictionPlan { format } => print_spacing_prediction_plan(format)?,
        Command::EvaluatePeriodPrediction {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_period_prediction(PeriodPredictionEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateSpacingPrediction {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_spacing_prediction(SpacingPredictionEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::ValidateEvaluationArchive { input, format } => {
            print_validate_evaluation_archive(input, format)?
        }
        Command::Hypotheses { format } => print_hypotheses(format)?,
        Command::CandidateSequences { format } => print_candidate_sequences(format)?,
        Command::Routes { format } => print_routes(format)?,
        Command::Findings { format } => print_findings(format)?,
        Command::Sources { format } => print_sources(format)?,
        Command::ObservationSources { format } => print_observation_sources(format)?,
        Command::ReleaseCheck { format } => print_release_check(format)?,
        Command::ExportData { directory } => export_data(directory)?,
        Command::Report { format, output } => {
            let report = build_report()?;
            let rendered = render_report(&report, format.into())?;
            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, rendered)?;
            } else {
                print!("{rendered}");
            }
        }
    }

    Ok(())
}

fn print_summarize_key_runs(input_dir: PathBuf, top: usize, format: OutputFormat) -> Result<()> {
    let history = summarize_batch_key_material_runs(&input_dir, top)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&history)?),
        OutputFormat::Markdown => print_batch_key_run_history(&history),
    }
    Ok(())
}

fn print_batch_key_run_history(history: &BatchKeyRunHistory) {
    println!("# Batch Key Run History\n");
    println!("This is not a claimed solution.\n");
    println!("input dir: `{}`", history.input_dir);
    println!("result files: {}", history.scanned_result_files);
    println!("candidate result rows: {}", history.candidate_result_count);
    println!("promoted: {}", history.promoted_candidate);
    println!("note: {}\n", history.note);

    println!("## Best Individual Results\n");
    println!(
        "| Rank | Material | Transform | Seed | Offset | Matches | Match Rate | Empirical P | Results | Promoted |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for (index, result) in history.top_results.iter().enumerate() {
        println!(
            "| {} | `{}` | {:?} | {} | {} | {}/{} | {:.4} | {} | `{}` | {} |",
            index + 1,
            result.material,
            result.transform,
            result.seed,
            result.best_offset,
            result.best_matches,
            result.compared_fragment_count,
            result.best_match_rate,
            format_optional_p(result.empirical_p_value),
            result.run_dir,
            result.promoted_candidate
        );
    }

    println!("\n## Candidate Stability\n");
    println!(
        "| Rank | Material | Transform | Runs | Best P | Mean P | Worst P | Best Matches | Best Seed | Best Offset | Promoted |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for (index, summary) in history.candidate_summaries.iter().enumerate() {
        println!(
            "| {} | `{}` | {:?} | {} | {} | {} | {} | {} | {} | {} | {} |",
            index + 1,
            summary.material,
            summary.transform,
            summary.run_count,
            format_optional_p(summary.best_empirical_p_value),
            format_optional_p(summary.mean_empirical_p_value),
            format_optional_p(summary.worst_empirical_p_value),
            summary.best_matches,
            summary.best_seed,
            summary.best_offset,
            summary.promoted_candidate
        );
    }
}

fn format_optional_p(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.4}"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn print_batch_test_keys(
    input: PathBuf,
    alphabet: CliAlphabet,
    baseline_iterations: usize,
    batch_baseline_iterations: usize,
    seed: u64,
    output_dir: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let input_text = fs::read_to_string(&input)?;
    let candidates = parse_batch_candidates(&input_text)?;
    let run = batch_test_key_material_with_batch_baseline(
        &candidates,
        alphabet.into(),
        baseline_iterations,
        seed,
        batch_baseline_iterations,
    )?;

    if let Some(output_dir) = output_dir {
        write_batch_outputs(&output_dir, &input_text, &run)?;
        println!(
            "Wrote batch key-material results to {}",
            output_dir.display()
        );
    } else {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
            OutputFormat::Markdown => print_batch_key_material_summary(&run),
        }
    }

    Ok(())
}

fn print_batch_test_routed_keys(
    input: PathBuf,
    alphabet: CliAlphabet,
    baseline_iterations: usize,
    batch_baseline_iterations: usize,
    seed: u64,
    output_dir: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let input_text = fs::read_to_string(&input)?;
    let candidates = parse_batch_candidates(&input_text)?;
    let run = batch_test_routed_key_material(
        &candidates,
        alphabet.into(),
        baseline_iterations,
        seed,
        batch_baseline_iterations,
    )?;

    if let Some(output_dir) = output_dir {
        write_routed_batch_outputs(&output_dir, &input_text, &run)?;
        println!(
            "Wrote routed batch key-material results to {}",
            output_dir.display()
        );
    } else {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
            OutputFormat::Markdown => print_routed_batch_key_material_summary(&run),
        }
    }

    Ok(())
}

fn print_heldout_key_control(
    input: PathBuf,
    alphabet: CliAlphabet,
    iterations: usize,
    seed: u64,
    output_dir: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let input_text = fs::read_to_string(&input)?;
    let candidates = parse_batch_candidates(&input_text)?;
    let run = heldout_key_control(&candidates, alphabet.into(), iterations, seed)?;

    if let Some(output_dir) = output_dir {
        write_heldout_key_control_outputs(&output_dir, &input_text, &run)?;
        println!(
            "Wrote held-out key-control results to {}",
            output_dir.display()
        );
    } else {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
            OutputFormat::Markdown => print_heldout_key_control_summary(&run),
        }
    }

    Ok(())
}

fn parse_batch_candidates(input: &str) -> Result<Vec<BatchKeyMaterialCandidate>> {
    let mut candidates = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let columns: Vec<_> = trimmed.split(',').map(str::trim).collect();
        if columns.len() != 2 {
            anyhow::bail!(
                "invalid candidate row {}: expected material,transform",
                index + 1
            );
        }
        if columns[0].eq_ignore_ascii_case("material")
            && columns[1].eq_ignore_ascii_case("transform")
        {
            continue;
        }

        let transform = CliCandidateTransform::from_str(columns[1], true).map_err(|message| {
            anyhow::anyhow!("invalid transform on row {}: {}", index + 1, message)
        })?;
        candidates.push(BatchKeyMaterialCandidate {
            material: columns[0].to_string(),
            transform: transform.into(),
        });
    }

    if candidates.is_empty() {
        anyhow::bail!("batch key-material input did not contain any candidates");
    }
    Ok(candidates)
}

fn write_batch_outputs(
    output_dir: &Path,
    input_text: &str,
    run: &BatchKeyMaterialRun,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join("input.csv"), input_text)?;
    fs::write(
        output_dir.join("results.json"),
        serde_json::to_string_pretty(run)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_batch_key_material_summary(run),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        format!(
            "batch-test-keys --input <input> --sweep-baseline-iterations {} --batch-baseline-iterations {} --seed {}\n",
            run.baseline_iterations,
            run.batch_baseline
                .as_ref()
                .map(|baseline| baseline.iterations)
                .unwrap_or(0),
            run.seed
        ),
    )?;
    Ok(())
}

fn write_routed_batch_outputs(
    output_dir: &Path,
    input_text: &str,
    run: &RoutedBatchKeyMaterialRun,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join("input.csv"), input_text)?;
    fs::write(
        output_dir.join("results.json"),
        serde_json::to_string_pretty(run)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_routed_batch_key_material_summary(run),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        format!(
            "batch-test-routed-keys --input <input> --sweep-baseline-iterations {} --batch-baseline-iterations {} --seed {}\n",
            run.baseline_iterations,
            run.batch_baseline
                .as_ref()
                .map(|baseline| baseline.iterations)
                .unwrap_or(0),
            run.seed
        ),
    )?;
    Ok(())
}

fn write_heldout_key_control_outputs(
    output_dir: &Path,
    input_text: &str,
    run: &HeldoutKeyControlRun,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join("input.csv"), input_text)?;
    fs::write(
        output_dir.join("results.json"),
        serde_json::to_string_pretty(run)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_heldout_key_control_summary(run),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        format!(
            "heldout-key-control --input <input> --iterations {} --seed {}\n",
            run.iterations, run.seed
        ),
    )?;
    Ok(())
}

fn write_period_prediction_evaluation_outputs(
    output_dir: &Path,
    evaluation: &PeriodPredictionEvaluation,
    archive: &EvaluationArchiveContext,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    write_evaluation_archive_context(output_dir, archive)?;
    fs::write(
        output_dir.join("result.json"),
        serde_json::to_string_pretty(evaluation)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_period_prediction_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-period-prediction",
            archive,
            evaluation.iterations,
            evaluation.seed,
        ),
    )?;
    Ok(())
}

fn write_spacing_prediction_evaluation_outputs(
    output_dir: &Path,
    evaluation: &SpacingPredictionEvaluation,
    archive: &EvaluationArchiveContext,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    write_evaluation_archive_context(output_dir, archive)?;
    fs::write(
        output_dir.join("result.json"),
        serde_json::to_string_pretty(evaluation)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_spacing_prediction_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-spacing-prediction",
            archive,
            evaluation.iterations,
            evaluation.seed,
        ),
    )?;
    Ok(())
}

struct EvaluationArchiveContext {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: EvaluationArchiveInput,
}

enum EvaluationArchiveInput {
    Positions(String),
    PositionsFile(PathBuf),
}

fn evaluation_archive_context(
    artifact: &Path,
    preregistration: &Option<PathBuf>,
    positions: &Option<String>,
    positions_file: &Option<PathBuf>,
) -> EvaluationArchiveContext {
    let input = if let Some(positions) = positions {
        EvaluationArchiveInput::Positions(positions.clone())
    } else if let Some(path) = positions_file {
        EvaluationArchiveInput::PositionsFile(path.clone())
    } else {
        EvaluationArchiveInput::Positions(String::new())
    };

    EvaluationArchiveContext {
        artifact: artifact.to_path_buf(),
        preregistration: preregistration.clone(),
        input,
    }
}

fn write_evaluation_archive_context(
    output_dir: &Path,
    archive: &EvaluationArchiveContext,
) -> Result<()> {
    fs::copy(&archive.artifact, output_dir.join("artifact.json"))?;
    if let Some(preregistration) = &archive.preregistration {
        fs::copy(preregistration, output_dir.join("preregistration.json"))?;
    }

    match &archive.input {
        EvaluationArchiveInput::Positions(positions) => {
            fs::write(output_dir.join("input-positions.txt"), positions)?;
        }
        EvaluationArchiveInput::PositionsFile(path) => {
            fs::copy(path, output_dir.join("observations.json"))?;
        }
    }
    Ok(())
}

fn render_archived_evaluation_command(
    command_name: &str,
    archive: &EvaluationArchiveContext,
    iterations: usize,
    seed: u64,
) -> String {
    let mut command = format!("{command_name} --artifact artifact.json");
    if archive.preregistration.is_some() {
        command.push_str(" --preregistration preregistration.json");
    }
    match &archive.input {
        EvaluationArchiveInput::Positions(positions) => {
            command.push_str(&format!(" --positions {positions}"));
        }
        EvaluationArchiveInput::PositionsFile(_) => {
            command.push_str(" --positions-file observations.json");
        }
    }
    command.push_str(&format!(" --iterations {iterations} --seed {seed}\n"));
    command
}

#[derive(Debug, Clone, Serialize)]
struct EvaluationArchiveValidation {
    directory: String,
    artifact_kind: String,
    source_backed_observation: bool,
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    files_checked: Vec<String>,
    promoted_candidate: bool,
    note: &'static str,
}

fn validate_evaluation_archive(directory: &Path) -> Result<EvaluationArchiveValidation> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut files_checked = Vec::new();

    let artifact = read_archive_json(directory, "artifact.json", &mut errors, &mut files_checked);
    let result = read_archive_json(directory, "result.json", &mut errors, &mut files_checked);
    check_archive_text_file(directory, "summary.md", &mut errors, &mut files_checked);
    let command = read_archive_text_file(directory, "command.txt", &mut errors, &mut files_checked);

    let artifact_kind = artifact
        .as_ref()
        .and_then(infer_prediction_artifact_kind)
        .unwrap_or("unknown")
        .to_string();
    if artifact_kind == "unknown" && artifact.is_some() {
        errors.push(
            "artifact.json is not a recognized period or spacing prediction artifact".to_string(),
        );
    }

    let source_backed_observation = result
        .as_ref()
        .and_then(|value| value.get("source_backed_observation"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if let Some(command) = &command {
        match artifact_kind.as_str() {
            "period" => require_command_name(command, "evaluate-period-prediction", &mut errors),
            "spacing" => require_command_name(command, "evaluate-spacing-prediction", &mut errors),
            _ => {}
        }
    }

    if let Some(result) = &result {
        if result
            .get("promoted_candidate")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        {
            errors.push("result.json must keep promoted_candidate false".to_string());
        }
        if artifact_kind == "period" && result.get("best_period").is_none() {
            errors.push("period archive result.json is missing best_period".to_string());
        }
        if artifact_kind == "spacing" && result.get("best_modulus").is_none() {
            errors.push("spacing archive result.json is missing best_modulus".to_string());
        }
    }
    if let Some(artifact) = &artifact
        && artifact
            .get("promoted_candidate")
            .and_then(serde_json::Value::as_bool)
            .is_some_and(|promoted| promoted)
    {
        errors.push("artifact.json must not promote a candidate".to_string());
    }

    if source_backed_observation {
        let observations = read_archive_json(
            directory,
            "observations.json",
            &mut errors,
            &mut files_checked,
        );
        let preregistration = read_archive_json(
            directory,
            "preregistration.json",
            &mut errors,
            &mut files_checked,
        );
        if let (Some(observations), Some(result)) = (&observations, &result) {
            validate_observations_match_result(observations, result, &mut errors);
        }
        if let (Some(artifact), Some(preregistration)) = (&artifact, &preregistration) {
            validate_archived_prediction_context(
                &artifact_kind,
                preregistration,
                artifact,
                &mut errors,
            );
        }
        if let (Some(artifact), Some(observations)) = (&artifact, &observations) {
            validate_archived_observations_against_artifact(
                &artifact_kind,
                observations,
                artifact,
                &mut errors,
            );
        }
        if let Some(command) = &command {
            require_command_token(command, "--artifact artifact.json", &mut errors);
            require_command_token(
                command,
                "--preregistration preregistration.json",
                &mut errors,
            );
            require_command_token(command, "--positions-file observations.json", &mut errors);
        }
    } else {
        let positions_path = directory.join("input-positions.txt");
        if positions_path.exists() {
            files_checked.push("input-positions.txt".to_string());
            if let (Ok(positions_text), Some(result)) =
                (fs::read_to_string(&positions_path), &result)
            {
                match parse_position_list(positions_text.trim()) {
                    Ok(positions) => {
                        if json_usize_array(result, "observed_positions_one_based")
                            != Some(positions)
                        {
                            errors.push(
                                "input-positions.txt does not match result observed positions"
                                    .to_string(),
                            );
                        }
                    }
                    Err(error) => errors.push(format!("input-positions.txt is invalid: {error}")),
                }
            }
        } else {
            warnings.push("diagnostic archive has no input-positions.txt".to_string());
        }
        if let Some(command) = &command {
            require_command_token(command, "--artifact artifact.json", &mut errors);
            require_command_token(command, "--positions", &mut errors);
        }
    }

    files_checked.sort();
    files_checked.dedup();

    Ok(EvaluationArchiveValidation {
        directory: directory.display().to_string(),
        artifact_kind,
        source_backed_observation,
        valid: errors.is_empty(),
        errors,
        warnings,
        files_checked,
        promoted_candidate: false,
        note: "Evaluation archive validation checks reproducibility artifacts only; it is not a claimed solution.",
    })
}

fn validate_archived_prediction_context(
    artifact_kind: &str,
    preregistration: &serde_json::Value,
    artifact: &serde_json::Value,
    errors: &mut Vec<String>,
) {
    match serde_json::to_string(preregistration)
        .map_err(anyhow::Error::from)
        .and_then(|input| validate_preregistration(&input))
    {
        Ok(validation) => {
            errors.extend(
                validation
                    .errors
                    .into_iter()
                    .map(|error| format!("preregistration.json: {error}")),
            );
        }
        Err(error) => errors.push(format!("preregistration.json is invalid: {error}")),
    }

    let registration = match serde_json::from_value::<LanePreregistration>(preregistration.clone())
    {
        Ok(registration) => registration,
        Err(error) => {
            errors.push(format!("preregistration.json is invalid: {error}"));
            return;
        }
    };

    let expected_kind = match registration.hypothesis_family.as_str() {
        "position-period-prediction" => Some("period"),
        "position-spacing-prediction" => Some("spacing"),
        _ => None,
    };
    if expected_kind != Some(artifact_kind) {
        errors.push(format!(
            "preregistration.json hypothesis family `{}` does not match archived {artifact_kind} artifact",
            registration.hypothesis_family
        ));
    }

    let expected_artifact = match artifact_kind {
        "period" => build_all_period_prediction_plans()
            .and_then(|plans| serde_json::to_value(plans).map_err(Into::into)),
        "spacing" => build_all_spacing_prediction_plans()
            .and_then(|plans| serde_json::to_value(plans).map_err(Into::into)),
        _ => return,
    };
    match expected_artifact {
        Ok(expected_artifact) => {
            if artifact != &expected_artifact {
                errors.push(format!(
                    "artifact.json does not match deterministic {artifact_kind} prediction plan output"
                ));
            }
        }
        Err(error) => errors.push(format!(
            "could not build deterministic {artifact_kind} prediction artifact: {error}"
        )),
    }
}

fn validate_archived_observations_against_artifact(
    artifact_kind: &str,
    observations: &serde_json::Value,
    artifact: &serde_json::Value,
    errors: &mut Vec<String>,
) {
    let observations =
        match serde_json::from_value::<PeriodPredictionObservationFile>(observations.clone()) {
            Ok(observations) => observations,
            Err(error) => {
                errors.push(format!("observations.json is invalid: {error}"));
                return;
            }
        };

    errors.extend(
        validate_period_prediction_observation_fields(&observations)
            .into_iter()
            .map(|error| format!("observations.json: {error}")),
    );

    if artifact_kind == "spacing" && observations.positions_one_based.len() < 2 {
        errors.push(
            "observations.json: spacing observation files must include at least two one-based K4 positions"
                .to_string(),
        );
    }

    let non_anchor_positions = match archived_artifact_positions(artifact_kind, artifact) {
        Ok(positions) => positions,
        Err(error) => {
            errors.push(format!("artifact.json could not be validated: {error}"));
            return;
        }
    };

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "observations.json: positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            let context = if artifact_kind == "spacing" {
                "spacing prediction artifact"
            } else {
                "prediction artifact"
            };
            errors.push(format!(
                "observations.json: position `{position}` is not in the {context} non-anchor universe"
            ));
        }
    }
}

fn archived_artifact_positions(
    artifact_kind: &str,
    artifact: &serde_json::Value,
) -> Result<HashSet<usize>> {
    match artifact_kind {
        "period" => {
            let plans: PeriodPredictionPlanSet = serde_json::from_value(artifact.clone())?;
            Ok(plans
                .plans
                .into_iter()
                .flat_map(|plan| plan.residues)
                .flat_map(|residue| residue.positions_one_based)
                .collect())
        }
        "spacing" => {
            let plans: SpacingPredictionPlanSet = serde_json::from_value(artifact.clone())?;
            Ok(plans
                .plans
                .into_iter()
                .flat_map(|plan| plan.positions_one_based)
                .collect())
        }
        _ => Ok(HashSet::new()),
    }
}

fn read_archive_json(
    directory: &Path,
    file_name: &str,
    errors: &mut Vec<String>,
    files_checked: &mut Vec<String>,
) -> Option<serde_json::Value> {
    let path = directory.join(file_name);
    if !path.exists() {
        errors.push(format!("{file_name} is missing"));
        return None;
    }
    files_checked.push(file_name.to_string());
    match fs::read_to_string(&path) {
        Ok(input) => match serde_json::from_str(&input) {
            Ok(value) => Some(value),
            Err(error) => {
                errors.push(format!("{file_name} is not valid JSON: {error}"));
                None
            }
        },
        Err(error) => {
            errors.push(format!("{file_name} could not be read: {error}"));
            None
        }
    }
}

fn read_archive_text_file(
    directory: &Path,
    file_name: &str,
    errors: &mut Vec<String>,
    files_checked: &mut Vec<String>,
) -> Option<String> {
    let path = directory.join(file_name);
    if !path.exists() {
        errors.push(format!("{file_name} is missing"));
        return None;
    }
    files_checked.push(file_name.to_string());
    match fs::read_to_string(&path) {
        Ok(input) => Some(input),
        Err(error) => {
            errors.push(format!("{file_name} could not be read: {error}"));
            None
        }
    }
}

fn check_archive_text_file(
    directory: &Path,
    file_name: &str,
    errors: &mut Vec<String>,
    files_checked: &mut Vec<String>,
) {
    let _ = read_archive_text_file(directory, file_name, errors, files_checked);
}

fn infer_prediction_artifact_kind(value: &serde_json::Value) -> Option<&'static str> {
    if value.get("period_count").is_some() && value.get("plans").is_some() {
        return Some("period");
    }
    if value.get("modulus_count").is_some() && value.get("plans").is_some() {
        return Some("spacing");
    }
    None
}

fn validate_observations_match_result(
    observations: &serde_json::Value,
    result: &serde_json::Value,
    errors: &mut Vec<String>,
) {
    if observations.get("id") != result.get("observation_id") {
        errors.push("observations.json id does not match result observation_id".to_string());
    }
    if json_string_array(observations, "source_ids")
        != json_string_array(result, "observation_source_ids")
    {
        errors.push(
            "observations.json source_ids do not match result observation_source_ids".to_string(),
        );
    }
    if json_usize_array(observations, "positions_one_based")
        != json_usize_array(result, "observed_positions_one_based")
    {
        errors
            .push("observations.json positions do not match result observed positions".to_string());
    }
    if observations.get("position_notes") != result.get("observation_position_notes") {
        errors.push(
            "observations.json position_notes do not match result observation_position_notes"
                .to_string(),
        );
    }
}

fn json_usize_array(value: &serde_json::Value, key: &str) -> Option<Vec<usize>> {
    value
        .get(key)?
        .as_array()?
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .and_then(|number| usize::try_from(number).ok())
        })
        .collect()
}

fn json_string_array(value: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    value
        .get(key)?
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_string))
        .collect()
}

fn require_command_token(command: &str, token: &str, errors: &mut Vec<String>) {
    if !command.contains(token) {
        errors.push(format!("command.txt must contain `{token}`"));
    }
}

fn require_command_name(command: &str, expected_command: &str, errors: &mut Vec<String>) {
    let command_name = command.split_whitespace().next();
    if command_name != Some(expected_command) {
        errors.push(format!("command.txt must start with `{expected_command}`"));
    }
}

fn print_batch_key_material_summary(run: &BatchKeyMaterialRun) {
    print!("{}", render_batch_key_material_summary(run));
}

fn render_batch_key_material_summary(run: &BatchKeyMaterialRun) -> String {
    let mut output = String::new();
    output.push_str("# Batch Key Material Results\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!(
        "alphabet: {:?}; candidates: {}; baseline iterations: {}; seed: {}; promoted: {}\n\n",
        run.alphabet,
        run.candidate_count,
        run.baseline_iterations,
        run.seed,
        run.promoted_candidate
    ));
    output.push_str("| Rank | Material | Transform | Best Offset | Matches | Match Rate | Pattern Score | Distinct Values | Span Coverage | Longest Run | Repeated Values | Empirical P | Promoted |\n");
    output.push_str(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for (index, result) in run.results.iter().enumerate() {
        let empirical_p = result
            .empirical_p_value
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "n/a".to_string());
        output.push_str(&format!(
            "| {} | `{}` | {:?} | {} | {}/{} | {:.4} | {} | {} | {} | {} | {} ({:.2}) | {} | {} |\n",
            index + 1,
            result.material,
            result.transform,
            result.best_offset,
            result.best_matches,
            result.compared_fragment_count,
            result.best_match_rate,
            result.best_pattern_metrics.pattern_score,
            result.best_pattern_metrics.distinct_matched_values,
            result.best_pattern_metrics.span_coverage,
            result.best_pattern_metrics.longest_contiguous_match_run,
            result.best_pattern_metrics.repeated_value_count,
            result.best_pattern_metrics.repeated_value_rate,
            empirical_p,
            result.promoted_candidate
        ));
    }
    if let Some(baseline) = &run.batch_baseline {
        output.push_str("\n## Batch Baseline\n\n");
        output.push_str(&format!(
            "observed best: {} matches; null mean best: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; candidates: {}; promoted: {}\n\n",
            baseline.observed_best_matches,
            baseline.null_mean_best_matches,
            baseline.null_std_dev_best_matches,
            baseline.empirical_p_value,
            baseline.iterations,
            baseline.seed,
            baseline.candidate_count,
            baseline.promoted_candidate
        ));
        output.push_str(&format!(
            "observed best pattern score: {}; null mean best pattern score: {:.2}; null sd: {:.2}; empirical p-value: {:.4}\n\n",
            baseline.observed_best_pattern_score,
            baseline.null_mean_best_pattern_score,
            baseline.null_std_dev_best_pattern_score,
            baseline.pattern_score_empirical_p_value
        ));
        output.push_str(&format!("note: {}\n", baseline.note));
    }
    output.push_str(&format!("\n{}\n", run.note));
    output
}

fn print_routed_batch_key_material_summary(run: &RoutedBatchKeyMaterialRun) {
    print!("{}", render_routed_batch_key_material_summary(run));
}

fn render_routed_batch_key_material_summary(run: &RoutedBatchKeyMaterialRun) -> String {
    let mut output = String::new();
    output.push_str("# Routed Batch Key Material Results\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!(
        "alphabet: {:?}; candidates: {}; result rows: {}; baseline iterations: {}; seed: {}; promoted: {}\n\n",
        run.alphabet,
        run.candidate_count,
        run.result_count,
        run.baseline_iterations,
        run.seed,
        run.promoted_candidate
    ));
    output.push_str("| Rank | Target | Route | Material | Transform | Best Offset | Matches | Match Rate | Pattern Score | Distinct Values | Span Coverage | Longest Run | Repeated Values | Empirical P | Promoted |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for (index, result) in run.results.iter().enumerate() {
        let empirical_p = result
            .empirical_p_value
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "n/a".to_string());
        output.push_str(&format!(
            "| {} | {} | {:?} | `{}` | {:?} | {} | {}/{} | {:.4} | {} | {} | {} | {} | {} ({:.2}) | {} | {} |\n",
            index + 1,
            result.target_label,
            result.route,
            result.material,
            result.transform,
            result.best_offset,
            result.best_matches,
            result.compared_fragment_count,
            result.best_match_rate,
            result.best_pattern_metrics.pattern_score,
            result.best_pattern_metrics.distinct_matched_values,
            result.best_pattern_metrics.span_coverage,
            result.best_pattern_metrics.longest_contiguous_match_run,
            result.best_pattern_metrics.repeated_value_count,
            result.best_pattern_metrics.repeated_value_rate,
            empirical_p,
            result.promoted_candidate
        ));
    }
    if let Some(baseline) = &run.batch_baseline {
        output.push_str("\n## Routed Batch Baseline\n\n");
        output.push_str(&format!(
            "observed best: {} matches; null mean best: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; candidates: {}; promoted: {}\n\n",
            baseline.observed_best_matches,
            baseline.null_mean_best_matches,
            baseline.null_std_dev_best_matches,
            baseline.empirical_p_value,
            baseline.iterations,
            baseline.seed,
            baseline.candidate_count,
            baseline.promoted_candidate
        ));
        output.push_str(&format!(
            "observed best pattern score: {}; null mean best pattern score: {:.2}; null sd: {:.2}; empirical p-value: {:.4}\n\n",
            baseline.observed_best_pattern_score,
            baseline.null_mean_best_pattern_score,
            baseline.null_std_dev_best_pattern_score,
            baseline.pattern_score_empirical_p_value
        ));
        output.push_str(&format!("note: {}\n", baseline.note));
    }
    output.push_str(&format!("\n{}\n", run.note));
    output
}

fn print_heldout_key_control_summary(run: &HeldoutKeyControlRun) {
    print!("{}", render_heldout_key_control_summary(run));
}

fn render_heldout_key_control_summary(run: &HeldoutKeyControlRun) -> String {
    let mut output = String::new();
    output.push_str("# Held-Out Key Control\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!(
        "alphabet: {:?}; candidates: {}; folds: {}; iterations: {}; seed: {}; promoted: {}\n\n",
        run.alphabet,
        run.candidate_count,
        run.fold_count,
        run.iterations,
        run.seed,
        run.promoted_candidate
    ));
    output.push_str("| Rank | Held-Out | Kind | Train Groups | Selected Material | Transform | Offset | Train Matches | Held-Out Matches | Held-Out Pattern Score | Held-Out P | Pattern P | Promoted |\n");
    output.push_str(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for (index, fold) in run.folds.iter().enumerate() {
        output.push_str(&format!(
            "| {} | {} | {:?} | {} | `{}` | {:?} | {} | {}/{} | {}/{} | {} | {:.4} | {:.4} | {} |\n",
            index + 1,
            fold.heldout_label,
            fold.heldout_kind,
            fold.train_group_count,
            fold.selected_material,
            fold.selected_transform,
            fold.selected_offset,
            fold.train_matches,
            fold.train_fragment_count,
            fold.heldout_matches,
            fold.heldout_fragment_count,
            fold.heldout_pattern_metrics.pattern_score,
            fold.baseline.empirical_p_value,
            fold.baseline.pattern_score_empirical_p_value,
            fold.promoted_candidate
        ));
    }

    output.push_str("\n## Fold Baselines\n\n");
    for fold in &run.folds {
        output.push_str(&format!(
            "- {} / {:?}: observed held-out {} matches; null mean {:.2}; null sd {:.2}; p={:.4}; observed pattern {}; null pattern mean {:.2}; pattern p={:.4}; selected `{}` {:?} offset {}; promoted: {}\n",
            fold.heldout_label,
            fold.heldout_kind,
            fold.baseline.observed_heldout_matches,
            fold.baseline.null_mean_heldout_matches,
            fold.baseline.null_std_dev_heldout_matches,
            fold.baseline.empirical_p_value,
            fold.baseline.observed_heldout_pattern_score,
            fold.baseline.null_mean_heldout_pattern_score,
            fold.baseline.pattern_score_empirical_p_value,
            fold.selected_material,
            fold.selected_transform,
            fold.selected_offset,
            fold.baseline.promoted_candidate
        ));
    }
    output.push('\n');
    if let Some(first) = run.folds.first() {
        output.push_str(&format!("note: {}\n\n", first.baseline.note));
    }
    output.push_str(&format!("{}\n", run.note));
    output
}

fn print_explain_key(options: ExplainKeyOptions) -> Result<()> {
    let explanation = explain_key_material(
        &options.material,
        options.transform.into(),
        options.alphabet.into(),
        options.offset,
    )?;
    match options.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&explanation)?),
        OutputFormat::Markdown => print_key_material_explanation(&explanation),
    }
    Ok(())
}

fn print_test_key(options: TestKeyOptions) -> Result<()> {
    if !options.sweep_offsets && options.sweep_baseline_iterations > 0 {
        anyhow::bail!("--sweep-baseline-iterations requires --sweep-offsets");
    }

    if options.sweep_offsets {
        let sweep = sweep_key_material_offsets_with_baseline(
            &options.material,
            options.transform.into(),
            options.alphabet.into(),
            options.sweep_baseline_iterations,
            options.seed,
        )?;
        match options.format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&sweep)?),
            OutputFormat::Markdown => print_key_material_offset_sweep(&sweep, options.top),
        }
        return Ok(());
    }

    let test = test_key_material(
        &options.material,
        options.transform.into(),
        options.alphabet.into(),
    )?;
    match options.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&test)?),
        OutputFormat::Markdown => print_key_material_test(&test),
    }

    Ok(())
}

fn print_key_material_offset_sweep(sweep: &KeyMaterialOffsetSweep, top: usize) {
    println!("# Key Material Offset Sweep\n");
    println!("This is not a claimed solution.\n");
    println!("material: `{}`", sweep.material);
    println!("transform: {:?}", sweep.transform);
    println!("alphabet: {:?}", sweep.alphabet);
    println!("fragment mode: {:?}", sweep.fragment_mode);
    println!("offsets tested: {}", sweep.offsets_tested);
    println!("promoted: {}", sweep.promoted_candidate);
    println!("note: {}\n", sweep.note);
    println!("| Rank | Offset | Matches | Match Rate |");
    println!("| --- | --- | --- | --- |");
    for (index, result) in sweep.results.iter().take(top).enumerate() {
        println!(
            "| {} | {} | {}/{} | {:.4} |",
            index + 1,
            result.offset,
            result.exact_mod26_matches,
            result.compared_fragment_count,
            result.match_rate
        );
    }
    if let Some(baseline) = &sweep.baseline {
        println!("\n## Sweep Baseline\n");
        println!(
            "observed best: {} matches; null mean best: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; promoted: {}",
            baseline.observed_best_matches,
            baseline.null_mean_best_matches,
            baseline.null_std_dev_best_matches,
            baseline.empirical_p_value,
            baseline.iterations,
            baseline.seed,
            baseline.promoted_candidate
        );
        println!("note: {}", baseline.note);
    }
}

fn print_key_material_test(test: &KeyMaterialTest) {
    println!("# Key Material Test\n");
    println!("This is not a claimed solution.\n");
    println!("material: `{}`", test.material);
    println!("transform: {:?}", test.transform);
    println!("alphabet: {:?}", test.alphabet);
    println!("fragment mode: {:?}", test.fragment_mode);
    println!(
        "matches: {}/{} ({:.4})",
        test.exact_mod26_matches, test.compared_fragment_count, test.match_rate
    );
    println!("promoted: {}", test.promoted_candidate);
    println!("note: {}\n", test.note);

    for span in &test.span_results {
        println!(
            "## {}: {}/{} exact mod-26 matches",
            span.target_label, span.exact_mod26_matches, span.compared_fragment_count
        );
        if span.mismatches.is_empty() {
            println!("all compared public fragments matched");
        } else {
            for mismatch in &span.mismatches {
                println!(
                    "- pos {} | {}->{} | observed {} ({}) | material {}",
                    mismatch.position_one_based,
                    mismatch.plaintext,
                    mismatch.ciphertext,
                    mismatch.observed_key_value,
                    mismatch.observed_key_symbol,
                    mismatch.material_value
                );
            }
        }
        println!();
    }
}

fn print_key_material_explanation(explanation: &KeyMaterialExplanation) {
    println!("# Key Material Explanation\n");
    println!("This is not a claimed solution.\n");
    println!("material: `{}`", explanation.material);
    println!("transform: {:?}", explanation.transform);
    println!("alphabet: {:?}", explanation.alphabet);
    println!("fragment mode: {:?}", explanation.fragment_mode);
    println!("offset: {}", explanation.offset);
    println!(
        "matches: {}/{} ({:.4})",
        explanation.exact_mod26_matches,
        explanation.compared_fragment_count,
        explanation.match_rate
    );
    println!(
        "pattern: score={} distinct_values={} span_coverage={} longest_run={} repeated_values={} ({:.2})",
        explanation.pattern_metrics.pattern_score,
        explanation.pattern_metrics.distinct_matched_values,
        explanation.pattern_metrics.span_coverage,
        explanation.pattern_metrics.longest_contiguous_match_run,
        explanation.pattern_metrics.repeated_value_count,
        explanation.pattern_metrics.repeated_value_rate
    );
    if let Some(caveat) = explanation.transform_caveat {
        println!("modulo caveat: {caveat}");
    }
    println!("promoted: {}", explanation.promoted_candidate);
    println!("note: {}\n", explanation.note);

    for span in &explanation.span_results {
        println!(
            "## {}: {}/{} exact mod-26 matches",
            span.target_label, span.exact_mod26_matches, span.compared_fragment_count
        );
        if span.matches.is_empty() {
            println!("matching positions: none");
        } else {
            println!("matching positions:");
            for key_match in &span.matches {
                println!(
                    "- pos {} | {}->{} | observed {} ({}) | material {}",
                    key_match.position_one_based,
                    key_match.plaintext,
                    key_match.ciphertext,
                    key_match.observed_key_value,
                    key_match.observed_key_symbol,
                    key_match.material_value
                );
            }
        }
        println!("mismatches: {}", span.mismatches.len());
        println!();
    }
}

fn print_facts(format: OutputFormat) -> Result<()> {
    let facts = serde_json::json!({
        "ciphertext_length": K4_CIPHERTEXT.len(),
        "ciphertext": K4_CIPHERTEXT,
        "evidence_boundary": "public anchors only; no claimed full plaintext",
        "promoted_candidate": false,
    });
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&facts)?),
        OutputFormat::Markdown => {
            println!("K4 ciphertext length: {}", K4_CIPHERTEXT.len());
            println!("K4 ciphertext: {K4_CIPHERTEXT}");
            println!("Evidence boundary: public anchors only; no claimed full plaintext.");
        }
    }

    Ok(())
}

fn print_anchors(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&known_anchors())?),
        OutputFormat::Markdown => {
            for anchor in known_anchors() {
                println!(
                    "{} => {} | 0-based {}-{} | 1-based {}-{} | sources: {} | confidence: {}",
                    anchor.ciphertext,
                    anchor.plaintext,
                    anchor.start_zero_based,
                    anchor.end_zero_based_inclusive,
                    anchor.start_one_based(),
                    anchor.end_one_based_inclusive(),
                    anchor.source_ids.join(","),
                    anchor.confidence
                );
            }
        }
    }

    Ok(())
}

fn print_constraints(spans: bool, format: OutputFormat) -> Result<()> {
    let analyses = if spans {
        analyze_known_plaintext_spans()?
    } else {
        analyze_constraints()?
    };

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&analyses)?),
        OutputFormat::Markdown => {
            for analysis in analyses {
                println!("{} / {:?}", analysis.target.label, analysis.alphabet.kind);
                for fragment in analysis.fragments {
                    println!(
                        "  pos {:>2}: {}->{} {:?} value {:>2} symbol {}",
                        fragment.position_one_based,
                        fragment.plaintext,
                        fragment.ciphertext,
                        fragment.mode,
                        fragment.value,
                        fragment.symbol
                    );
                }
                println!(
                    "  recurrence: {}/{} generic mod-10 triples matched; expected random {:.1}; promoted: {}; warning: {}",
                    analysis.recurrence.gromark_sum_matches,
                    analysis.recurrence.contiguous_pairs_checked,
                    analysis.recurrence.expected_random_matches,
                    analysis.recurrence.promoted_candidate,
                    analysis.recurrence.sample_warning
                );
            }
        }
    }
    Ok(())
}

fn print_key_fragments(
    anchor: Option<String>,
    span: Option<String>,
    alphabet: Option<CliAlphabet>,
    mode: Option<CliFragmentMode>,
    format: OutputFormat,
) -> Result<()> {
    let alphabet_filter = alphabet.map(AlphabetKind::from);
    let mode_filter = mode.map(FragmentMode::from);
    let (analyses, filter_kind, target_filter) = if let Some(anchor) = anchor {
        (
            analyze_constraints()?,
            "anchor",
            Some(anchor.to_ascii_uppercase()),
        )
    } else if let Some(span) = span {
        (
            analyze_known_plaintext_spans()?,
            "span",
            Some(span.to_ascii_uppercase()),
        )
    } else {
        let mut all = analyze_constraints()?;
        all.extend(analyze_known_plaintext_spans()?);
        (all, "target", None)
    };

    let mut rows = Vec::new();
    for analysis in analyses {
        if target_filter
            .as_ref()
            .is_some_and(|filter| analysis.target.label != *filter)
        {
            continue;
        }
        if alphabet_filter.is_some_and(|filter| analysis.alphabet.kind != filter) {
            continue;
        }

        let target_kind = match analysis.target.kind {
            kryptos_k4::AnalysisTargetKind::Anchor => "anchor",
            kryptos_k4::AnalysisTargetKind::Span => "span",
        };

        for fragment in analysis.fragments {
            if mode_filter.is_some_and(|filter| fragment.mode != filter) {
                continue;
            }

            let row = KeyFragmentRow {
                target_kind,
                target_label: analysis.target.label.clone(),
                alphabet: analysis.alphabet.kind,
                position_zero_based: fragment.position_zero_based,
                position_one_based: fragment.position_one_based,
                plaintext: fragment.plaintext,
                ciphertext: fragment.ciphertext,
                mode: fragment.mode,
                value: fragment.value,
                symbol: fragment.symbol,
                promoted_candidate: false,
            };
            rows.push(row);
        }
    }

    if rows.is_empty() {
        anyhow::bail!("no key-fragment rows matched the requested {filter_kind} filters");
    }

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
        OutputFormat::Markdown => {
            for row in rows {
                println!(
                    "{} {} / {:?} | pos {} | {}->{} | {:?} | value {} | symbol {}",
                    row.target_kind,
                    row.target_label,
                    row.alphabet,
                    row.position_one_based,
                    row.plaintext,
                    row.ciphertext,
                    row.mode,
                    row.value,
                    row.symbol
                );
            }
        }
    }

    Ok(())
}

fn print_baseline(
    target: CliBaselineTarget,
    alphabet: CliBaselineAlphabet,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let run = run_baseline(target.into(), alphabet.into(), iterations, seed)?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
        OutputFormat::Markdown => {
            println!("# Kryptos K4 Baseline Report\n");
            println!("This is not a claimed solution.\n");
            println!(
                "Target: {}; alphabet: {}; iterations: {}; seed: {}\n",
                run.target_scope, run.alphabet_scope, run.iterations, run.seed
            );
            println!(
                "| Target | Kind | Alphabet | Observed | Triples | Null mean | Null sd | Empirical p-value | Adjusted p-value | Promoted | Warning |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for result in run.results {
                println!(
                    "| {} | {} | {:?} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} | {} |",
                    result.target_label,
                    result.target_kind,
                    result.alphabet,
                    result.observed_matches,
                    result.triples_checked,
                    result.null_mean,
                    result.null_std_dev,
                    result.empirical_p_value,
                    result.adjusted_p_value,
                    result.promoted_candidate,
                    result.warning
                );
            }
        }
    }

    Ok(())
}

fn print_position_structure(
    target: CliBaselineTarget,
    alphabet: CliBaselineAlphabet,
    mode: CliFragmentMode,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let run = run_position_structure_control(
        target.into(),
        alphabet.into(),
        mode.into(),
        iterations,
        seed,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
        OutputFormat::Markdown => print_position_structure_summary(&run),
    }
    Ok(())
}

fn print_position_structure_summary(run: &PositionStructureRun) {
    println!("# Position Structure Control\n");
    println!("This is not a claimed solution.\n");
    println!(
        "target: {}; alphabet: {}; fragment mode: {:?}; moduli: {}..={}; iterations: {}; seed: {}",
        run.target_scope,
        run.alphabet_scope,
        run.fragment_mode,
        run.min_modulus,
        run.max_modulus,
        run.iterations,
        run.seed
    );
    println!("promoted: {}", run.promoted_candidate);
    println!("note: {}\n", run.note);
    println!(
        "| Target | Kind | Alphabet | Fragments | Best Modulus | Residue Score | Spacing Hits | Composite | Null Mean | Null SD | P | Adjusted P | Promoted | Warning |"
    );
    println!(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    );
    for result in &run.results {
        println!(
            "| {} | {} | {:?} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} | {} |",
            result.target_label,
            result.target_kind,
            result.alphabet,
            result.fragment_count,
            result.best_modulus,
            result.observed_residue_score,
            result.observed_spacing_hits,
            result.observed_composite_score,
            result.null_mean_composite_score,
            result.null_std_dev_composite_score,
            result.empirical_p_value,
            result.adjusted_p_value,
            result.promoted_candidate,
            result.warning
        );
    }
}

fn print_structural_models(
    target: CliBaselineTarget,
    alphabet: CliBaselineAlphabet,
    mode: CliFragmentMode,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let run = run_structural_model_control(
        target.into(),
        alphabet.into(),
        mode.into(),
        iterations,
        seed,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
        OutputFormat::Markdown => print_structural_model_summary(&run),
    }
    Ok(())
}

fn print_structural_model_summary(run: &StructuralModelRun) {
    println!("# Structural Model Control\n");
    println!("This is not a claimed solution.\n");
    println!(
        "target: {}; alphabet: {}; fragment mode: {:?}; models: {}; iterations: {}; seed: {}",
        run.target_scope,
        run.alphabet_scope,
        run.fragment_mode,
        run.model_count,
        run.iterations,
        run.seed
    );
    println!("promoted: {}", run.promoted_candidate);
    println!("note: {}\n", run.note);
    println!(
        "| Model | Kind | Period | Targets | Fragments | Residue Score | Spacing Hits | Composite | Null Mean | Null SD | P | Adjusted P | Promoted |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for result in &run.results {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} |",
            result.model_id,
            result.model_kind,
            result.period,
            result.target_count,
            result.fragment_count,
            result.observed_residue_score,
            result.observed_spacing_hits,
            result.observed_composite_score,
            result.null_mean_composite_score,
            result.null_std_dev_composite_score,
            result.empirical_p_value,
            result.adjusted_p_value,
            result.promoted_candidate
        );
    }
}

fn print_validate_preregistration(input: PathBuf, format: OutputFormat) -> Result<()> {
    let validation = load_and_validate_preregistration(&input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_preregistration_validation(&validation),
    }
    validation_exit_result(&validation)
}

fn print_preregistration_validation(validation: &PreregistrationValidation) {
    println!("# Preregistration Validation\n");
    println!("This is not a claimed solution.\n");
    println!("id: `{}`", validation.id);
    println!("title: {}", validation.title);
    println!("valid: {}", validation.valid);
    println!("promoted: {}", validation.promoted_candidate);
    println!("note: {}\n", validation.note);

    if validation.errors.is_empty() {
        println!("## Errors\n\nnone\n");
    } else {
        println!("## Errors\n");
        for error in &validation.errors {
            println!("- {error}");
        }
        println!();
    }

    if validation.warnings.is_empty() {
        println!("## Warnings\n\nnone\n");
    } else {
        println!("## Warnings\n");
        for warning in &validation.warnings {
            println!("- {warning}");
        }
        println!();
    }
}

fn print_validate_prediction_artifact(
    preregistration: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_prediction_artifact(&preregistration)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_prediction_artifact_validation(&validation),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("prediction artifact failed validation")
    }
}

fn print_prediction_artifact_validation(validation: &PredictionArtifactValidation) {
    println!("# Prediction Artifact Validation\n");
    println!("This is not a claimed solution.\n");
    println!("id: `{}`", validation.preregistration_id);
    println!("artifact kind: {}", validation.artifact_kind);
    println!("artifact: `{}`", validation.artifact_path);
    println!("valid: {}", validation.valid);
    println!("expected plans: {}", validation.expected_plan_count);
    match validation.artifact_plan_count {
        Some(plan_count) => println!("artifact plans: {plan_count}"),
        None => println!("artifact plans: unavailable"),
    }
    let unit_label = match validation.artifact_kind.as_str() {
        "spacing" => "moduli",
        "period" => "periods",
        _ => "units",
    };
    println!(
        "expected {unit_label}: {}",
        validation.expected_period_count
    );
    match validation.artifact_period_count {
        Some(period_count) => println!("artifact {unit_label}: {period_count}"),
        None => println!("artifact {unit_label}: unavailable"),
    }
    println!("promoted: {}", validation.promoted_candidate);
    println!("note: {}\n", validation.note);

    if validation.errors.is_empty() {
        println!("## Errors\n\nnone\n");
    } else {
        println!("## Errors\n");
        for error in &validation.errors {
            println!("- {error}");
        }
        println!();
    }

    if validation.warnings.is_empty() {
        println!("## Warnings\n\nnone\n");
    } else {
        println!("## Warnings\n");
        for warning in &validation.warnings {
            println!("- {warning}");
        }
        println!();
    }
}

fn print_independent_lane_status(directory: PathBuf, format: OutputFormat) -> Result<()> {
    let report = summarize_independent_lanes(&directory)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => print_independent_lane_status_report(&report),
    }
    Ok(())
}

fn build_next_evidence_gate_report(directory: &Path) -> Result<NextEvidenceGateReport> {
    let lane_report = summarize_independent_lanes(directory)?;
    let source_report = observation_source_eligibility_report();
    let eligible_source_ids = source_report
        .sources
        .iter()
        .filter(|source| source.eligible_for_scored_observations)
        .map(|source| source.id.to_string())
        .collect::<Vec<_>>();

    let mut gates = Vec::new();
    for family in &lane_report.family_summaries {
        if family.unique_ready_prediction_artifacts == 0 {
            continue;
        }
        let Some(lane) = representative_ready_lane(&lane_report, &family.hypothesis_family) else {
            continue;
        };
        let Some(preregistration) = lane.id.as_ref().map(|_| lane.path.clone()) else {
            continue;
        };
        let Some(artifact) = lane.prediction_artifact.clone() else {
            continue;
        };

        let (validation_command, evaluation_command, archive_validation_command) =
            evidence_gate_commands(&family.hypothesis_family, &artifact, &preregistration);
        gates.push(NextEvidenceGate {
            hypothesis_family: family.hypothesis_family.clone(),
            ready_lanes: family.ready_for_source_backed_observations,
            unique_ready_prediction_artifacts: family.unique_ready_prediction_artifacts,
            representative_preregistration: preregistration,
            representative_artifact: artifact,
            observation_scaffold_command:
                "cargo run --locked -- init-position-observations --id <observation-id> --source-id <eligible-source-id> --positions <comma-separated-non-anchor-positions> --rationale \"<source-backed rationale>\" --position-note \"<position>=<source-backed note>\" --output <source-backed-observations.json>"
                    .to_string(),
            validation_command,
            evaluation_command,
            archive_validation_command,
        });
    }

    Ok(NextEvidenceGateReport {
        lane_directory: lane_report.directory,
        ready_lanes: lane_report.ready_for_source_backed_observations,
        invalid_lanes: lane_report.invalid_lanes,
        unique_ready_prediction_artifacts: lane_report.unique_ready_prediction_artifacts,
        eligible_source_ids,
        ineligible_source_count: source_report.ineligible_count,
        required_observation_fields: vec![
            "registered eligible source ID",
            "one-based non-anchor K4 positions",
            "source-backed rationale",
            "one non-empty position_notes entry per scored position",
        ],
        gates,
        promoted_candidate: false,
        note: "Next-evidence-gate output is an operational checklist for future source-backed observations; it is not a claimed solution.",
    })
}

fn representative_ready_lane<'a>(
    report: &'a IndependentLaneStatusReport,
    hypothesis_family: &str,
) -> Option<&'a IndependentLaneStatus> {
    let lanes = report
        .lanes
        .iter()
        .filter(|lane| {
            lane.hypothesis_family.as_deref() == Some(hypothesis_family)
                && lane.ready_for_source_backed_observations
                && lane.prediction_artifact.is_some()
        })
        .collect::<Vec<_>>();
    lanes
        .iter()
        .find(|lane| {
            matches!(
                lane.id.as_deref(),
                Some("non-anchor-position-period-v1") | Some("non-anchor-position-spacing-v1")
            )
        })
        .copied()
        .or_else(|| lanes.first().copied())
}

fn evidence_gate_commands(
    hypothesis_family: &str,
    artifact: &str,
    preregistration: &str,
) -> (String, String, String) {
    match hypothesis_family {
        "position-spacing-prediction" => (
            format!(
                "cargo run --locked -- validate-spacing-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-spacing-prediction --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/spacing-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/spacing-observations/<observation-id> --format json".to_string(),
        ),
        _ => (
            format!(
                "cargo run --locked -- validate-period-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-period-prediction --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/period-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/period-observations/<observation-id> --format json".to_string(),
        ),
    }
}

fn print_next_evidence_gate(directory: PathBuf, format: OutputFormat) -> Result<()> {
    let report = build_next_evidence_gate_report(&directory)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Next Evidence Gate\n");
            println!("This is not a claimed solution.\n");
            println!("lane directory: `{}`", report.lane_directory);
            println!("ready lanes: {}", report.ready_lanes);
            println!(
                "unique ready prediction artifacts: {}",
                report.unique_ready_prediction_artifacts
            );
            println!(
                "eligible scored-observation sources: {}",
                report.eligible_source_ids.join(", ")
            );
            println!("ineligible sources: {}", report.ineligible_source_count);
            println!("promoted: {}", report.promoted_candidate);
            println!("note: {}\n", report.note);
            println!("required observation fields:");
            for field in &report.required_observation_fields {
                println!("- {field}");
            }
            println!("\n## Gates\n");
            for gate in &report.gates {
                println!("### {}", gate.hypothesis_family);
                println!("ready lanes: {}", gate.ready_lanes);
                println!(
                    "unique ready artifacts: {}",
                    gate.unique_ready_prediction_artifacts
                );
                println!(
                    "representative preregistration: `{}`",
                    gate.representative_preregistration
                );
                println!(
                    "representative artifact: `{}`",
                    gate.representative_artifact
                );
                println!(
                    "scaffold:\n```bash\n{}\n```",
                    gate.observation_scaffold_command
                );
                println!("validate:\n```bash\n{}\n```", gate.validation_command);
                println!("evaluate:\n```bash\n{}\n```", gate.evaluation_command);
                println!(
                    "archive check:\n```bash\n{}\n```\n",
                    gate.archive_validation_command
                );
            }
        }
    }
    Ok(())
}

fn print_independent_lane_status_report(report: &IndependentLaneStatusReport) {
    println!("# Independent Lane Status\n");
    println!("This is not a claimed solution.\n");
    println!("directory: `{}`", report.directory);
    println!("lanes: {}", report.lane_count);
    println!(
        "ready for source-backed observations: {}",
        report.ready_for_source_backed_observations
    );
    println!("invalid lanes: {}", report.invalid_lanes);
    println!("prediction artifacts: {}", report.prediction_artifacts);
    println!(
        "unique prediction artifacts: {}",
        report.unique_prediction_artifacts
    );
    println!(
        "unique ready prediction artifacts: {}",
        report.unique_ready_prediction_artifacts
    );
    println!(
        "duplicate artifact groups: {}",
        report.duplicate_prediction_artifact_groups.len()
    );
    println!("promoted: {}", report.promoted_candidate);
    println!("note: {}\n", report.note);

    if !report.family_summaries.is_empty() {
        println!("## Family Summary\n");
        println!(
            "| Family | Lanes | Ready | Artifacts | Unique Artifacts | Unique Ready Artifacts | Duplicate Groups |"
        );
        println!("| --- | --- | --- | --- | --- | --- | --- |");
        for family in &report.family_summaries {
            println!(
                "| {} | {} | {} | {} | {} | {} | {} |",
                family.hypothesis_family,
                family.lanes,
                family.ready_for_source_backed_observations,
                family.prediction_artifacts,
                family.unique_prediction_artifacts,
                family.unique_ready_prediction_artifacts,
                family.duplicate_artifact_groups
            );
        }
        println!();
    }

    if !report.duplicate_prediction_artifact_groups.is_empty() {
        println!("## Duplicate Prediction Artifacts\n");
        println!("| Lanes | Artifacts |");
        println!("| --- | --- |");
        for group in &report.duplicate_prediction_artifact_groups {
            let lanes = group
                .lane_ids
                .iter()
                .map(|lane| format!("`{lane}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let artifacts = group
                .artifact_paths
                .iter()
                .map(|artifact| format!("`{artifact}`"))
                .collect::<Vec<_>>()
                .join(", ");
            println!("| {} | {} |", lanes, artifacts);
        }
        println!();
    }

    println!("| Lane | Family | Artifact | Status | Next Step |");
    println!("| --- | --- | --- | --- | --- |");
    for lane in &report.lanes {
        let id = lane.id.as_deref().unwrap_or("unavailable");
        let family = lane.hypothesis_family.as_deref().unwrap_or("unavailable");
        let artifact = lane.prediction_artifact.as_deref().unwrap_or("none");
        println!(
            "| `{}` | {} | `{}` | {} | {} |",
            id, family, artifact, lane.status, lane.next_step
        );
    }
}

fn print_init_position_observations(options: InitPositionObservationOptions) -> Result<()> {
    let InitPositionObservationOptions {
        id,
        source_ids,
        positions,
        rationale,
        position_notes,
        output,
        force,
        format,
    } = options;
    let report = create_position_observation_file(
        id,
        source_ids,
        positions,
        rationale,
        position_notes,
        output,
        force,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => print_position_observation_scaffold_report(&report),
    }
    Ok(())
}

fn print_position_observation_scaffold_report(report: &PositionObservationScaffoldReport) {
    println!("# Position Observation File\n");
    println!("This is not a claimed solution.\n");
    println!("output: `{}`", report.output_path);
    println!("observation id: `{}`", report.observation.id);
    println!("source ids: {}", report.observation.source_ids.join(", "));
    println!(
        "positions: {}",
        report
            .observation
            .positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "position notes: {}",
        report.observation.position_notes.len()
    );
    println!("valid: {}", report.valid);
    println!("promoted: {}", report.promoted_candidate);
    println!("note: {}\n", report.note);
    println!("## Errors\n");
    if report.errors.is_empty() {
        println!("none\n");
    } else {
        for error in &report.errors {
            println!("- {error}");
        }
        println!();
    }
    println!("## Next Gates\n");
    println!(
        "- Run `validate-period-observations` or `validate-spacing-observations` with the matching committed artifact and preregistration before scoring."
    );
    println!(
        "- Then run the matching `evaluate-*-prediction --positions-file` command and archive the JSON output."
    );
}

fn print_validate_period_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_period_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_period_observation_validation(&validation),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("period observations failed validation")
    }
}

fn print_validate_spacing_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_spacing_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => {
            print_position_observation_validation("Spacing Observation Validation", &validation)
        }
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("spacing observations failed validation")
    }
}

fn validate_period_observations(
    artifact_path: &Path,
    preregistration_path: Option<&Path>,
    input_path: &Path,
) -> Result<PeriodPredictionObservationValidation> {
    let observations = read_period_prediction_observation_file(input_path)?;
    let observation_id = observations.id.clone();
    let mut errors = validate_period_prediction_observation_fields(&observations);
    let mut preregistration_id = None;
    let mut artifact_valid = None;

    if let Some(preregistration_path) = preregistration_path {
        let artifact_validation = validate_prediction_artifact(preregistration_path)?;
        preregistration_id = Some(artifact_validation.preregistration_id.clone());
        artifact_valid = Some(artifact_validation.valid);
        if artifact_validation.artifact_kind != "period" {
            errors.push(format!(
                "preregistration `{}` does not declare a period prediction artifact",
                artifact_validation.preregistration_id
            ));
        }
        if artifact_validation.artifact_path != artifact_path.display().to_string() {
            errors.push(format!(
                "artifact `{}` does not match preregistration artifact `{}`",
                artifact_path.display(),
                artifact_validation.artifact_path
            ));
        }
        errors.extend(
            artifact_validation
                .errors
                .into_iter()
                .map(|error| format!("prediction artifact: {error}")),
        );
    }

    let non_anchor_positions = load_period_prediction_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the prediction artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Period observation validation checks source-backed non-anchor positions before scoring; it is not a claimed solution.",
    })
}

fn validate_spacing_observations(
    artifact_path: &Path,
    preregistration_path: Option<&Path>,
    input_path: &Path,
) -> Result<PeriodPredictionObservationValidation> {
    let observations = read_period_prediction_observation_file(input_path)?;
    let observation_id = observations.id.clone();
    let mut errors = validate_period_prediction_observation_fields(&observations);
    let mut preregistration_id = None;
    let mut artifact_valid = None;

    if observations.positions_one_based.len() < 2 {
        errors.push(
            "spacing observation files must include at least two one-based K4 positions"
                .to_string(),
        );
    }

    if let Some(preregistration_path) = preregistration_path {
        let artifact_validation = validate_prediction_artifact(preregistration_path)?;
        preregistration_id = Some(artifact_validation.preregistration_id.clone());
        artifact_valid = Some(artifact_validation.valid);
        if artifact_validation.artifact_kind != "spacing" {
            errors.push(format!(
                "preregistration `{}` does not declare a spacing prediction artifact",
                artifact_validation.preregistration_id
            ));
        }
        if artifact_validation.artifact_path != artifact_path.display().to_string() {
            errors.push(format!(
                "artifact `{}` does not match preregistration artifact `{}`",
                artifact_path.display(),
                artifact_validation.artifact_path
            ));
        }
        errors.extend(
            artifact_validation
                .errors
                .into_iter()
                .map(|error| format!("prediction artifact: {error}")),
        );
    }

    let non_anchor_positions = load_spacing_prediction_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the spacing prediction artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Spacing observation validation checks source-backed non-anchor positions before spacing scoring; it is not a claimed solution.",
    })
}

fn print_period_observation_validation(validation: &PeriodPredictionObservationValidation) {
    print_position_observation_validation("Period Observation Validation", validation);
}

fn print_position_observation_validation(
    title: &str,
    validation: &PeriodPredictionObservationValidation,
) {
    println!("# {title}\n");
    println!("This is not a claimed solution.\n");
    println!("artifact: `{}`", validation.artifact_path);
    if let Some(preregistration_id) = &validation.preregistration_id {
        println!("preregistration id: `{preregistration_id}`");
    }
    if let Some(artifact_valid) = validation.artifact_valid {
        println!("artifact valid: {artifact_valid}");
    }
    println!("observation id: `{}`", validation.observation_id);
    println!(
        "observation sources: {}",
        validation.observation_source_ids.join(", ")
    );
    println!(
        "observation rationale: {}",
        validation.observation_rationale
    );
    println!(
        "observed positions: {}",
        validation
            .observed_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "observed position count: {}",
        validation.observed_position_count
    );
    println!(
        "position notes: {}",
        validation.observation_position_notes.len()
    );
    println!("valid: {}", validation.valid);
    println!("promoted: {}", validation.promoted_candidate);
    println!("note: {}\n", validation.note);
    println!("## Errors\n");
    if validation.errors.is_empty() {
        println!("none");
    } else {
        for error in &validation.errors {
            println!("- {error}");
        }
    }
}

fn print_period_prediction_plan(
    period: Option<usize>,
    all: bool,
    format: OutputFormat,
) -> Result<()> {
    if all {
        let plans = build_all_period_prediction_plans()?;
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plans)?),
            OutputFormat::Markdown => print_period_prediction_plan_set_markdown(&plans),
        }
    } else {
        let period = period.ok_or_else(|| {
            anyhow::anyhow!("period-prediction-plan requires --period <N> or --all")
        })?;
        let plan = build_period_prediction_plan(period)?;
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plan)?),
            OutputFormat::Markdown => print_period_prediction_plan_markdown(&plan),
        }
    }
    Ok(())
}

fn print_period_prediction_plan_set_markdown(plans: &PeriodPredictionPlanSet) {
    println!("# Period Prediction Plan Set\n");
    println!("This is not a claimed solution.\n");
    println!("periods: {}", plans.period_count);
    println!("promoted: {}", plans.promoted_candidate);
    println!("note: {}\n", plans.note);
    for plan in &plans.plans {
        print_period_prediction_plan_markdown(plan);
        println!();
    }
}

fn print_period_prediction_plan_markdown(plan: &PeriodPredictionPlan) {
    println!("# Period Prediction Plan\n");
    println!("This is not a claimed solution.\n");
    println!("period: {}", plan.period);
    println!("non-anchor positions: {}", plan.non_anchor_position_count);
    println!(
        "public-anchor positions excluded: {}",
        plan.anchor_position_count
    );
    println!("promoted: {}", plan.promoted_candidate);
    println!("source inputs: {}", plan.source_inputs);
    println!("prediction rule: {}", plan.prediction_rule);
    println!("note: {}\n", plan.note);

    println!("| Residue | Non-Anchor Position Count | Positions One-Based |");
    println!("| --- | --- | --- |");
    for residue in &plan.residues {
        let positions = residue
            .positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "| {} | {} | {} |",
            residue.residue, residue.position_count, positions
        );
    }
}

fn print_spacing_prediction_plan(format: OutputFormat) -> Result<()> {
    let plans = build_all_spacing_prediction_plans()?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plans)?),
        OutputFormat::Markdown => {
            println!("# Spacing Prediction Plan Set\n");
            println!("This is not a claimed solution.\n");
            println!("moduli: {}", plans.modulus_count);
            println!("promoted: {}", plans.promoted_candidate);
            println!("note: {}\n", plans.note);
            for plan in &plans.plans {
                println!("## Modulus {}\n", plan.modulus);
                println!("non-anchor positions: {}", plan.non_anchor_position_count);
                println!(
                    "public-anchor positions excluded: {}",
                    plan.anchor_position_count
                );
                println!("promoted: {}", plan.promoted_candidate);
                println!("source inputs: {}", plan.source_inputs);
                println!("prediction rule: {}", plan.prediction_rule);
                println!("note: {}\n", plan.note);
                println!("| Residue | Pair Count | Sample Pairs One-Based |");
                println!("| --- | --- | --- |");
                for residue in &plan.residues {
                    let sample_pairs = residue
                        .sample_pairs_one_based
                        .iter()
                        .map(|pair| format!("{}-{}", pair[0], pair[1]))
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "| {} | {} | {} |",
                        residue.residue, residue.pair_count, sample_pairs
                    );
                }
                println!();
            }
        }
    }
    Ok(())
}

struct PeriodPredictionEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct SpacingPredictionEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

fn print_evaluate_period_prediction(options: PeriodPredictionEvaluationOptions) -> Result<()> {
    let PeriodPredictionEvaluationOptions {
        artifact,
        preregistration,
        positions,
        positions_file,
        output_dir,
        iterations,
        seed,
        format,
    } = options;
    let has_preregistration = preregistration.is_some();
    if let Some(preregistration) = &preregistration {
        let artifact_validation = validate_prediction_artifact(preregistration)?;
        if artifact_validation.artifact_kind != "period" {
            anyhow::bail!(
                "preregistration `{}` does not declare a period prediction artifact",
                artifact_validation.preregistration_id
            );
        }
        if artifact_validation.artifact_path != artifact.display().to_string() {
            anyhow::bail!(
                "artifact `{}` does not match preregistration artifact `{}`",
                artifact.display(),
                artifact_validation.artifact_path
            );
        }
        if !artifact_validation.valid {
            anyhow::bail!("prediction artifact failed validation");
        }
    }
    if positions_file.is_some() && !has_preregistration {
        anyhow::bail!(
            "--positions-file requires --preregistration so the committed prediction artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_period_prediction_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_period_prediction_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_period_prediction_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_spacing_prediction(options: SpacingPredictionEvaluationOptions) -> Result<()> {
    let SpacingPredictionEvaluationOptions {
        artifact,
        preregistration,
        positions,
        positions_file,
        output_dir,
        iterations,
        seed,
        format,
    } = options;
    let has_preregistration = preregistration.is_some();
    if let Some(preregistration) = &preregistration {
        let artifact_validation = validate_prediction_artifact(preregistration)?;
        if artifact_validation.artifact_kind != "spacing" {
            anyhow::bail!(
                "preregistration `{}` does not declare a spacing prediction artifact",
                artifact_validation.preregistration_id
            );
        }
        if artifact_validation.artifact_path != artifact.display().to_string() {
            anyhow::bail!(
                "artifact `{}` does not match preregistration artifact `{}`",
                artifact.display(),
                artifact_validation.artifact_path
            );
        }
        if !artifact_validation.valid {
            anyhow::bail!("prediction artifact failed validation");
        }
    }
    if positions_file.is_some() && !has_preregistration {
        anyhow::bail!(
            "--positions-file requires --preregistration so the committed spacing prediction artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_spacing_prediction_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_spacing_prediction_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_spacing_prediction_evaluation(&evaluation),
    }
    Ok(())
}

fn print_period_prediction_evaluation(evaluation: &PeriodPredictionEvaluation) {
    print!("{}", render_period_prediction_evaluation(evaluation));
}

fn render_period_prediction_evaluation(evaluation: &PeriodPredictionEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Period Prediction Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!("artifact: `{}`\n", evaluation.artifact_path));
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}",
            evaluation.observation_source_ids.join(", ")
        ));
        output.push('\n');
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    if !evaluation.observation_position_notes.is_empty() {
        output.push_str(&format!(
            "position notes: {}\n",
            evaluation.observation_position_notes.len()
        ));
    }
    output.push_str(&format!(
        "source-backed observation: {}",
        evaluation.source_backed_observation
    ));
    output.push('\n');
    if let Some(observation_warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {observation_warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push('\n');
    output.push_str(&format!(
        "observed position count: {}",
        evaluation.observed_position_count
    ));
    output.push('\n');
    output.push_str(&format!(
        "best: period {} residue {} with {}/{} hits ({:.4})",
        evaluation.best_period,
        evaluation.best_residue,
        evaluation.best_hits,
        evaluation.observed_position_count,
        evaluation.best_hit_rate
    ));
    output.push('\n');
    output.push_str(&format!(
        "best-of-period null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}",
        evaluation.null_mean_best_hits,
        evaluation.null_std_dev_best_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push('\n');
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n\n", evaluation.note));

    output.push_str("| Period | Best Residue | Hits | Hit Rate |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for result in &evaluation.period_results {
        output.push_str(&format!(
            "| {} | {} | {}/{} | {:.4} |",
            result.period,
            result.best_residue,
            result.best_hits,
            evaluation.observed_position_count,
            result.best_hit_rate
        ));
        output.push('\n');
    }
    output
}

fn print_spacing_prediction_evaluation(evaluation: &SpacingPredictionEvaluation) {
    print!("{}", render_spacing_prediction_evaluation(evaluation));
}

fn print_validate_evaluation_archive(input: PathBuf, format: OutputFormat) -> Result<()> {
    let validation = validate_evaluation_archive(&input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => {
            println!("# Evaluation Archive Validation\n");
            println!("This is not a claimed solution.\n");
            println!("directory: `{}`", validation.directory);
            println!("artifact kind: {}", validation.artifact_kind);
            println!(
                "source-backed observation: {}",
                validation.source_backed_observation
            );
            println!("valid: {}", validation.valid);
            println!("promoted: {}", validation.promoted_candidate);
            println!("note: {}\n", validation.note);
            println!("## Files Checked\n");
            for file_name in &validation.files_checked {
                println!("- `{file_name}`");
            }
            println!("\n## Errors\n");
            if validation.errors.is_empty() {
                println!("none");
            } else {
                for error in &validation.errors {
                    println!("- {error}");
                }
            }
            println!("\n## Warnings\n");
            if validation.warnings.is_empty() {
                println!("none");
            } else {
                for warning in &validation.warnings {
                    println!("- {warning}");
                }
            }
        }
    }
    if !validation.valid {
        anyhow::bail!("evaluation archive failed validation");
    }
    Ok(())
}

fn render_spacing_prediction_evaluation(evaluation: &SpacingPredictionEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Spacing Prediction Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!("artifact: `{}`\n", evaluation.artifact_path));
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}",
            evaluation.observation_source_ids.join(", ")
        ));
        output.push('\n');
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    if !evaluation.observation_position_notes.is_empty() {
        output.push_str(&format!(
            "position notes: {}\n",
            evaluation.observation_position_notes.len()
        ));
    }
    output.push_str(&format!(
        "source-backed observation: {}",
        evaluation.source_backed_observation
    ));
    output.push('\n');
    if let Some(observation_warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {observation_warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push('\n');
    output.push_str(&format!(
        "observed position count: {}; observed pair count: {}",
        evaluation.observed_position_count, evaluation.observed_pair_count
    ));
    output.push('\n');
    output.push_str(&format!(
        "best: modulus {} residue {} with {}/{} pair hits ({:.4})",
        evaluation.best_modulus,
        evaluation.best_residue,
        evaluation.best_hits,
        evaluation.observed_pair_count,
        evaluation.best_hit_rate
    ));
    output.push('\n');
    output.push_str(&format!(
        "best-of-modulus null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}",
        evaluation.null_mean_best_hits,
        evaluation.null_std_dev_best_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push('\n');
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n\n", evaluation.note));

    output.push_str("| Modulus | Best Residue | Pair Hits | Hit Rate |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for result in &evaluation.modulus_results {
        output.push_str(&format!(
            "| {} | {} | {}/{} | {:.4} |",
            result.modulus,
            result.best_residue,
            result.best_hits,
            evaluation.observed_pair_count,
            result.best_hit_rate
        ));
        output.push('\n');
    }
    output
}

fn print_hypotheses(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&hypotheses())?),
        OutputFormat::Markdown => {
            for hypothesis in hypotheses() {
                println!(
                    "{}. {} ({})\n   test: {}\n   risk: {}",
                    hypothesis.priority,
                    hypothesis.name,
                    hypothesis.id,
                    hypothesis.falsification_test,
                    hypothesis.risk
                );
            }
        }
    }

    Ok(())
}

fn print_candidate_sequences(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "candidate_sequences": candidate_sequences(),
                "scores": score_candidate_sequences()?,
                "note": "Pre-registered contextual candidates only; not a claimed solution."
            }))?
        ),
        OutputFormat::Markdown => {
            println!("# Candidate Sequences\n");
            println!("Pre-registered contextual candidates only; not a claimed solution.\n");
            for candidate in candidate_sequences() {
                println!(
                    "- `{}` {:?} {:?}: `{}` values={:?} promoted=false",
                    candidate.id,
                    candidate.family,
                    candidate.transform,
                    candidate.raw_material,
                    candidate.values
                );
            }
        }
    }

    Ok(())
}

fn print_routes(format: OutputFormat) -> Result<()> {
    let experiments = run_route_experiments()?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&experiments)?),
        OutputFormat::Markdown => {
            println!("# Route Experiments\n");
            println!(
                "Exploratory route screen only; not a claimed solution and no decryption text is emitted.\n"
            );
            for experiment in experiments {
                println!(
                    "- {:?} / {}: score={} identity_baseline={} reverse_baseline={} seeded_random_baseline={} promoted={}",
                    experiment.route,
                    experiment.target_label,
                    experiment.score,
                    experiment.identity_baseline,
                    experiment.reverse_baseline,
                    experiment.seeded_random_baseline,
                    experiment.promoted_candidate
                );
            }
        }
    }

    Ok(())
}

fn print_findings(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&findings())?),
        OutputFormat::Markdown => {
            println!("# Findings Ledger\n");
            println!(
                "Every finding is tied to public source inputs, transformation steps, baseline context, and a next test. This is not a claimed solution.\n"
            );
            for finding in findings() {
                println!(
                    "- {} {} ({})\n  sources: {}\n  output: {}\n  baseline: {}\n  interpretation: {}\n  next test: {}\n  promoted: {}",
                    finding.id,
                    finding.title,
                    finding.related_hypothesis,
                    finding.source_inputs.join(","),
                    finding.output_summary,
                    finding.baseline_comparison,
                    finding.interpretation,
                    finding.next_test,
                    finding.promoted_candidate
                );
            }
        }
    }

    Ok(())
}

fn print_sources(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&sources())?),
        OutputFormat::Markdown => {
            for source in sources() {
                println!(
                    "{} ({}): {}\n  accessed {} | use: {}\n  {}",
                    source.label,
                    source.id,
                    source.url,
                    source.accessed_at,
                    source.allowed_use,
                    source.use_note
                );
            }
        }
    }
    Ok(())
}

fn observation_source_eligibility_report() -> ObservationSourceEligibilityReport {
    let sources: Vec<_> = sources()
        .into_iter()
        .map(|source| {
            let eligible = period_observation_source_use_is_allowed(source.allowed_use);
            let reason = if eligible {
                "allowed_use supports scored independent position observations".to_string()
            } else {
                format!(
                    "allowed_use `{}` is context-only for observation scoring",
                    source.allowed_use
                )
            };
            ObservationSourceEligibility {
                id: source.id,
                label: source.label,
                allowed_use: source.allowed_use,
                eligible_for_scored_observations: eligible,
                reason,
            }
        })
        .collect();
    let eligible_count = sources
        .iter()
        .filter(|source| source.eligible_for_scored_observations)
        .count();
    ObservationSourceEligibilityReport {
        eligible_count,
        ineligible_count: sources.len() - eligible_count,
        sources,
        promoted_candidate: false,
        note: "Observation-source eligibility is a source-use boundary for future evidence; it is not a claimed solution.",
    }
}

fn print_observation_sources(format: OutputFormat) -> Result<()> {
    let report = observation_source_eligibility_report();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Observation Sources\n");
            println!("This is not a claimed solution.\n");
            println!("eligible sources: {}", report.eligible_count);
            println!("ineligible sources: {}", report.ineligible_count);
            println!("promoted: {}", report.promoted_candidate);
            println!("note: {}\n", report.note);
            println!("| Source ID | Allowed Use | Eligible | Reason |");
            println!("| --- | --- | --- | --- |");
            for source in &report.sources {
                println!(
                    "| `{}` | {} | {} | {} |",
                    source.id,
                    source.allowed_use,
                    source.eligible_for_scored_observations,
                    source.reason
                );
            }
        }
    }
    Ok(())
}

fn print_release_check(format: OutputFormat) -> Result<()> {
    let checks = run_release_checks(std::env::current_dir()?)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&checks)?),
        OutputFormat::Markdown => {
            println!("# Release Check\n");
            println!("Local preflight only. This repo does not use GitHub Actions.\n");
            for check in checks {
                println!("- {}: {} ({})", check.name, check.passed, check.detail);
            }
        }
    }
    Ok(())
}

fn export_data(directory: PathBuf) -> Result<()> {
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join("k4-ciphertext.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "ciphertext": K4_CIPHERTEXT,
            "length": K4_CIPHERTEXT.len(),
            "evidence_boundary": "public ciphertext only; no claimed full plaintext"
        }))?,
    )?;
    fs::write(
        directory.join("k4-known-anchors.json"),
        serde_json::to_string_pretty(&known_anchors())?,
    )?;
    fs::write(
        directory.join("k4-sources.json"),
        serde_json::to_string_pretty(&sources())?,
    )?;

    println!("Exported K4 data files to {}", directory.display());
    Ok(())
}
