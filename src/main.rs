use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use kryptos_k4::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, BatchKeyMaterialCandidate,
    BatchKeyMaterialRun, BatchKeyRunHistory, CandidateTransform,
    CiphertextAdjacentContrastEvaluation, CiphertextAdjacentContrastPrior,
    CiphertextHotspotEvaluation, CiphertextHotspotPrior, CiphertextPeriodMatchEvaluation,
    CiphertextPeriodMatchPrior, CiphertextPriorEvaluation, CiphertextRarityEvaluation,
    CiphertextRarityPrior, CiphertextRepeatDistanceEvaluation, CiphertextRepeatDistancePrior,
    CiphertextResidueBalanceEvaluation, CiphertextResidueBalancePrior,
    CiphertextSkipTransitionEvaluation, CiphertextSkipTransitionPrior,
    CiphertextStehleRegularityEvaluation, CiphertextStehleRegularityPrior,
    CiphertextStructurePrior, CiphertextTransitionEvaluation, CiphertextTransitionPrior,
    CiphertextTurningPointEvaluation, CiphertextTurningPointPrior,
    CiphertextWindowBalanceEvaluation, CiphertextWindowBalancePrior, ClaimBundleVerification,
    ClaimMechanismVerification, ClaimReconciliationVerification, DuplicatePredictionArtifactGroup,
    FragmentMode, GridLayoutEdgeAxis, GridLayoutPredictionEvaluation, GridLayoutPredictionPlan,
    HeldoutKeyControlRun, IndependentLaneStatus, IndependentLaneStatusReport, K4_CIPHERTEXT,
    KeyMaterialExplanation, KeyMaterialOffsetSweep, KeyMaterialTest, LanePreregistration,
    MirrorPredictionEvaluation, MirrorPredictionPlanSet, PeriodPredictionEvaluation,
    PeriodPredictionPlan, PeriodPredictionPlanSet, PlaintextClaimVerification,
    PositionStructureRun, PredictionArtifactValidation, PreregistrationValidation, ReportFormat,
    RoutedBatchKeyMaterialRun, RunningKeyClaimVerification, SpacingPredictionEvaluation,
    SpacingPredictionPlanSet, StructuralModelRun, TableauHillPredictionEvaluation,
    TableauHillPredictionPlan, analyze_constraints, analyze_known_plaintext_spans,
    batch_test_key_material_with_batch_baseline, batch_test_routed_key_material,
    build_all_period_prediction_plans, build_all_spacing_prediction_plans,
    build_ciphertext_adjacent_contrast_prior, build_ciphertext_ct_perturbation_prior,
    build_ciphertext_hotspot_prior, build_ciphertext_period_match_prior,
    build_ciphertext_rarity_prior, build_ciphertext_repeat_distance_prior,
    build_ciphertext_residue_balance_prior, build_ciphertext_skip_transition_prior,
    build_ciphertext_stehle_regularity_prior, build_ciphertext_structure_prior,
    build_ciphertext_transition_prior, build_ciphertext_turning_point_prior,
    build_ciphertext_window_balance_prior, build_grid_layout_prediction_plan_for_axis,
    build_mirror_prediction_plan, build_period_prediction_plan, build_report,
    build_tableau_hill_prediction_plan, candidate_sequences,
    evaluate_ciphertext_adjacent_contrast_positions, evaluate_ciphertext_hotspot_positions,
    evaluate_ciphertext_period_match_positions, evaluate_ciphertext_rarity_positions,
    evaluate_ciphertext_repeat_distance_positions, evaluate_ciphertext_residue_balance_positions,
    evaluate_ciphertext_skip_transition_positions, evaluate_ciphertext_stehle_regularity_positions,
    evaluate_ciphertext_structure_prior_positions, evaluate_ciphertext_transition_positions,
    evaluate_ciphertext_turning_point_positions, evaluate_ciphertext_window_balance_positions,
    evaluate_grid_layout_prediction_positions_with_axis, evaluate_mirror_prediction_positions,
    evaluate_period_prediction_positions, evaluate_spacing_prediction_positions,
    evaluate_tableau_hill_prediction_positions, explain_key_material, findings,
    heldout_key_control, hypotheses, known_anchors, load_and_validate_preregistration,
    profile_k4_ciphertext, render_report, run_baseline, run_position_structure_control,
    run_release_checks, run_route_experiments, run_structural_model_control,
    score_candidate_sequences, sources, summarize_batch_key_material_runs,
    summarize_independent_lanes, sweep_key_material_offsets_with_baseline, test_key_material,
    validate_prediction_artifact, validate_preregistration, validation_exit_result,
    verify_claim_bundle, verify_claim_mechanism, verify_claim_reconciliation_table,
    verify_plaintext_claim, verify_running_key_claim,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
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
    /// Profile K4 ciphertext-only structure without anchors or candidate material.
    CiphertextProfile {
        /// Maximum period to include in shifted coincidence and coset IC diagnostics.
        #[arg(long, default_value_t = 20)]
        max_period: usize,
        /// Maximum repeated n-gram length to scan.
        #[arg(long, default_value_t = 4)]
        max_ngram: usize,
        /// Maximum repeated n-grams to print.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Seeded ciphertext-shuffle null iterations for the best shifted period-match rate.
        #[arg(long, default_value_t = 0)]
        iterations: usize,
        /// Seed for deterministic ciphertext-profile baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only position prior for future independent observations.
    CiphertextStructurePrior {
        /// Maximum period to include in ciphertext-only diagnostics.
        #[arg(long, default_value_t = 20)]
        max_period: usize,
        /// Maximum repeated n-gram length to scan.
        #[arg(long, default_value_t = 4)]
        max_ngram: usize,
        /// Seeded ciphertext-shuffle null iterations for diagnostic p-values.
        #[arg(long, default_value_t = 100_000)]
        iterations: usize,
        /// Seed for deterministic ciphertext-only controls.
        #[arg(long, default_value_t = 67)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only hotspot target for future independent observations.
    CiphertextHotspotPrior {
        /// Maximum period to include in shifted self-coincidence endpoint scoring.
        #[arg(long, default_value_t = 20)]
        max_period: usize,
        /// Maximum repeated n-gram length to scan.
        #[arg(long, default_value_t = 4)]
        max_ngram: usize,
        /// Number of non-anchor hotspot positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only rarity target for future independent observations.
    CiphertextRarityPrior {
        /// Number of non-anchor rare ciphertext-letter positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only adjacent-contrast target for future independent observations.
    CiphertextAdjacentContrastPrior {
        /// Number of non-anchor high adjacent-contrast positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only adjacent-transition target for future independent observations.
    CiphertextTransitionPrior {
        /// Number of non-anchor high-transition positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only skip-transition target for future independent observations.
    CiphertextSkipTransitionPrior {
        /// Number of non-anchor high skip-transition positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Comma-separated skip distances to include in the score.
        #[arg(long, default_value = "1,2")]
        skip_distances: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only local turning-point target for future independent observations.
    CiphertextTurningPointPrior {
        /// Number of non-anchor local turning-point positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only repeat-distance target for future independent observations.
    CiphertextRepeatDistancePrior {
        /// Number of non-anchor repeat-distance positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only shifted period-match target for future independent observations.
    CiphertextPeriodMatchPrior {
        /// Maximum period to include in shifted same-letter match scoring.
        #[arg(long, default_value_t = 20)]
        max_period: usize,
        /// Number of shifted-match periods to predeclare.
        #[arg(long, default_value_t = 5)]
        top_periods: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only local-window balance target for future independent observations.
    CiphertextWindowBalancePrior {
        /// Number of non-anchor local-window balance positions to predeclare.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Comma-separated odd centered window widths to score.
        #[arg(long, default_value = "3,5,7")]
        window_widths: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit the source-grounded Stehle local-regularity target for future independent observations.
    CiphertextStehleRegularityPrior {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit the source-grounded CT-perturbation target for future independent observations.
    CiphertextCtPerturbationPrior {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a ciphertext-only residue-balance target for future independent observations.
    CiphertextResidueBalancePrior {
        /// Minimum modulus to include in the residue-balance registry.
        #[arg(long, default_value_t = 2)]
        min_modulus: usize,
        /// Maximum modulus to include in the residue-balance registry.
        #[arg(long, default_value_t = 13)]
        max_modulus: usize,
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
        /// Fail validation when the artifact duplicates another committed prediction target.
        #[arg(long)]
        require_unique_artifact: bool,
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
    /// Report whether source-backed independent observation archives exist.
    IndependentEvidenceStatus {
        /// Evaluation archive root to scan. Repeat to override the default period, spacing, mirror, grid, and Tableau/HILL roots.
        #[arg(long = "root")]
        roots: Vec<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Report whether pre-score source-review artifacts exist and validate.
    SourceReviewStatus {
        /// Source-review root or JSON file to scan. Repeat to override the default source-review root.
        #[arg(long = "root")]
        roots: Vec<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Report eligible source readiness before creating source-backed observations.
    SourceObservationStatus {
        /// Directory containing lane preregistration JSON files.
        #[arg(long, default_value = "experiments/preregistrations")]
        directory: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print a pre-score review packet for eligible observation sources.
    SourceReviewPacket {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print the intake checklist for adding a new source-backed evidence source.
    SourceIntakePacket {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Create a pre-score source-review JSON file for eligible observation sources.
    InitSourceReview {
        /// Stable source-review file ID.
        #[arg(long)]
        id: String,
        /// Registered eligible source ID. Repeat for multiple sources.
        #[arg(long = "source-id", required = true)]
        source_ids: Vec<String>,
        /// Reviewer note explaining what was checked before observation scoring.
        #[arg(long = "review-note")]
        review_note: String,
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
    /// Validate a pre-score source-review JSON file before observation scoring.
    ValidateSourceReview {
        /// Source-review JSON file to validate.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate a quote-free local source archive against registered source metadata.
    ValidateSourceArchive {
        /// Registered source ID the archive is supposed to represent.
        #[arg(long = "source-id")]
        source_id: String,
        /// Quote-free local source archive file to validate.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print the one-based K4 positions eligible for future non-anchor observations.
    NonAnchorPositions {
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
        /// Optional validated source-review JSON file that covers the listed source IDs.
        #[arg(long = "source-review")]
        source_review: Option<PathBuf>,
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
    /// Validate source-backed independent observations before mirror prediction scoring.
    ValidateMirrorObservations {
        /// JSON artifact emitted by mirror-prediction-plan --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the prediction artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before grid-layout prediction scoring.
    ValidateGridObservations {
        /// JSON artifact emitted by grid-layout-prediction-plan --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the prediction artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations against a Tableau/HILL source map.
    ValidateTableauHillObservations {
        /// JSON artifact emitted by tableau-hill-prediction-plan --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the prediction artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-prior scoring.
    ValidateCiphertextPriorObservations {
        /// JSON artifact emitted by ciphertext-structure-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-prior artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-hotspot scoring.
    ValidateCiphertextHotspotObservations {
        /// JSON artifact emitted by ciphertext-hotspot-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-hotspot artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-rarity scoring.
    ValidateCiphertextRarityObservations {
        /// JSON artifact emitted by ciphertext-rarity-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-rarity artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-adjacent-contrast scoring.
    ValidateCiphertextAdjacentContrastObservations {
        /// JSON artifact emitted by ciphertext-adjacent-contrast-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-adjacent-contrast artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-transition scoring.
    ValidateCiphertextTransitionObservations {
        /// JSON artifact emitted by ciphertext-transition-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-transition artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-skip-transition scoring.
    ValidateCiphertextSkipTransitionObservations {
        /// JSON artifact emitted by ciphertext-skip-transition-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-skip-transition artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-turning-point scoring.
    ValidateCiphertextTurningPointObservations {
        /// JSON artifact emitted by ciphertext-turning-point-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-turning-point artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-window-balance scoring.
    ValidateCiphertextWindowBalanceObservations {
        /// JSON artifact emitted by ciphertext-window-balance-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-window-balance artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-repeat-distance scoring.
    ValidateCiphertextRepeatDistanceObservations {
        /// JSON artifact emitted by ciphertext-repeat-distance-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-repeat-distance artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-period-match scoring.
    ValidateCiphertextPeriodMatchObservations {
        /// JSON artifact emitted by ciphertext-period-match-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-period-match artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-Stehle-regularity scoring.
    ValidateCiphertextStehleRegularityObservations {
        /// JSON artifact emitted by ciphertext-stehle-regularity-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-Stehle-regularity artifact before scoring.
        #[arg(long)]
        preregistration: Option<PathBuf>,
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        input: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Validate source-backed independent observations before ciphertext-residue-balance scoring.
    ValidateCiphertextResidueBalanceObservations {
        /// JSON artifact emitted by ciphertext-residue-balance-prior --format json.
        #[arg(long)]
        artifact: PathBuf,
        /// Optional preregistration file used to validate the ciphertext-residue-balance artifact before scoring.
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
    /// Emit predeclared non-anchor mirror-pair targets for future independent evidence.
    MirrorPredictionPlan {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit a predeclared 7-by-14 padded grid-layout target for future independent evidence.
    GridLayoutPredictionPlan {
        /// Scored edge axis to commit in the emitted artifact.
        #[arg(long = "edge-axis", value_enum, default_value_t = CliGridEdgeAxis::Row)]
        edge_axis: CliGridEdgeAxis,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Emit fixed HILL/tableau boundaries for a source-backed independent lane.
    TableauHillPredictionPlan {
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
    /// Evaluate independent non-anchor positions against a committed mirror prediction artifact.
    EvaluateMirrorPrediction {
        /// JSON artifact emitted by mirror-prediction-plan --format json.
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
        /// Seeded null iterations for same-size mirror-pair closure.
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
    /// Evaluate independent non-anchor positions against a committed grid-layout prediction artifact.
    EvaluateGridPrediction {
        /// JSON artifact emitted by grid-layout-prediction-plan --format json.
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
        /// Grid axis to score. Source-backed scoring must match the preregistered axis.
        #[arg(long, value_enum, default_value_t = CliGridEdgeAxis::Row)]
        edge_axis: CliGridEdgeAxis,
        /// Seeded null iterations for selected edge-axis enrichment.
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
    /// Evaluate independent non-anchor positions against a committed Tableau/HILL source map.
    EvaluateTableauHillPrediction {
        /// JSON artifact emitted by tableau-hill-prediction-plan --format json.
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
        /// Seeded null iterations for best row/column concentration on the fixed source map.
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
    /// Evaluate source-backed non-anchor positions against the ciphertext-only structure prior.
    EvaluateCiphertextPrior {
        /// JSON file with source IDs and one-based non-anchor K4 positions.
        #[arg(long)]
        positions_file: PathBuf,
        /// Maximum period to include when rebuilding the ciphertext-only prior.
        #[arg(long, default_value_t = 20)]
        max_period: usize,
        /// Maximum repeated n-gram length to scan when rebuilding the ciphertext-only prior.
        #[arg(long, default_value_t = 4)]
        max_ngram: usize,
        /// Seeded ciphertext-shuffle null iterations used to annotate the prior diagnostics.
        #[arg(long, default_value_t = 100_000)]
        prior_iterations: usize,
        /// Seed for deterministic ciphertext-prior diagnostic controls.
        #[arg(long, default_value_t = 67)]
        prior_seed: u64,
        /// Seeded same-size position-shuffle null iterations for best selected-period enrichment.
        #[arg(long, default_value_t = 100_000)]
        iterations: usize,
        /// Seed for deterministic position-shuffle null controls.
        #[arg(long, default_value_t = 67)]
        seed: u64,
        /// Optional directory for observations.json, result.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Evaluate independent non-anchor positions against a committed ciphertext-hotspot artifact.
    EvaluateCiphertextHotspot {
        /// JSON artifact emitted by ciphertext-hotspot-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for hotspot enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-rarity artifact.
    EvaluateCiphertextRarity {
        /// JSON artifact emitted by ciphertext-rarity-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for rare-position enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-adjacent-contrast artifact.
    EvaluateCiphertextAdjacentContrast {
        /// JSON artifact emitted by ciphertext-adjacent-contrast-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for adjacent-contrast enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-transition artifact.
    EvaluateCiphertextTransition {
        /// JSON artifact emitted by ciphertext-transition-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for transition-position enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-skip-transition artifact.
    EvaluateCiphertextSkipTransition {
        /// JSON artifact emitted by ciphertext-skip-transition-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for skip-transition-position enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-turning-point artifact.
    EvaluateCiphertextTurningPoint {
        /// JSON artifact emitted by ciphertext-turning-point-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for turning-point-position enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-window-balance artifact.
    EvaluateCiphertextWindowBalance {
        /// JSON artifact emitted by ciphertext-window-balance-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for window-balance-position enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-repeat-distance artifact.
    EvaluateCiphertextRepeatDistance {
        /// JSON artifact emitted by ciphertext-repeat-distance-prior --format json.
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
        /// Seeded same-size position-shuffle null iterations for repeat-distance-position enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-period-match artifact.
    EvaluateCiphertextPeriodMatch {
        /// JSON artifact emitted by ciphertext-period-match-prior --format json.
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
        /// Seeded null iterations for same-size best-of-period endpoint enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-Stehle-regularity artifact.
    EvaluateCiphertextStehleRegularity {
        /// JSON artifact emitted by ciphertext-stehle-regularity-prior --format json.
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
        /// Seeded null iterations for same-size Stehle-window and expected-delta enrichment.
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
    /// Evaluate independent non-anchor positions against a committed ciphertext-residue-balance artifact.
    EvaluateCiphertextResidueBalance {
        /// JSON artifact emitted by ciphertext-residue-balance-prior --format json.
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
        /// Seeded null iterations for same-size best-of-modulus residue-balance enrichment.
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
    /// Verify a local plaintext claim without printing or storing the claim text.
    VerifyPlaintextClaim {
        /// Local text file containing the claim to verify.
        #[arg(long)]
        input: PathBuf,
        /// Optional registered source ID. Must have allowed_use unverified-solution-claim.
        #[arg(long = "source-id")]
        source_id: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Verify local plaintext and running-key claim files without printing or storing either.
    VerifyRunningKeyClaim {
        /// Local text file containing the claimed plaintext.
        #[arg(long)]
        plaintext: PathBuf,
        /// Local text file containing the claimed running-key stream.
        #[arg(long)]
        key: PathBuf,
        /// Alphabet used for additive running-key reconstruction.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Standard)]
        alphabet: CliAlphabet,
        /// Optional registered source ID. Must have allowed_use unverified-solution-claim.
        #[arg(long = "source-id")]
        source_id: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Verify a local claim reconciliation table without printing or storing claimed plaintext.
    VerifyClaimReconciliation {
        /// Local CSV/TSV/whitespace table with at least i/position and C/ciphertext columns.
        #[arg(long)]
        input: PathBuf,
        /// Optional registered source ID. Must have allowed_use unverified-solution-claim.
        #[arg(long = "source-id")]
        source_id: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Verify a local plaintext-claim bundle without printing or storing claimed plaintext.
    VerifyClaimBundle {
        /// Local directory containing the claim bundle files.
        #[arg(long)]
        directory: PathBuf,
        /// Optional registered source ID. Must have allowed_use unverified-solution-claim.
        #[arg(long = "source-id")]
        source_id: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Verify local claim helper-mechanism files without printing or storing claimed plaintext.
    VerifyClaimMechanism {
        /// Local directory containing the claim bundle files.
        #[arg(long)]
        directory: PathBuf,
        /// Optional registered source ID. Must have allowed_use unverified-solution-claim.
        #[arg(long = "source-id")]
        source_id: Option<String>,
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
    /// Classify every registered source by its current evidence-use frontier.
    SourceFrontier {
        /// Print a concise operational summary instead of the full source table.
        #[arg(long)]
        summary: bool,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliGridEdgeAxis {
    Row,
    Column,
    CompassAxis,
}

impl From<CliGridEdgeAxis> for GridLayoutEdgeAxis {
    fn from(value: CliGridEdgeAxis) -> Self {
        match value {
            CliGridEdgeAxis::Row => GridLayoutEdgeAxis::Row,
            CliGridEdgeAxis::Column => GridLayoutEdgeAxis::Column,
            CliGridEdgeAxis::CompassAxis => GridLayoutEdgeAxis::CompassAxis,
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_review_file: Option<String>,
    positions_one_based: Vec<usize>,
    #[serde(default)]
    position_notes: BTreeMap<String, String>,
    rationale: String,
}

#[derive(Debug)]
struct PeriodPredictionObservationInput {
    id: Option<String>,
    source_ids: Vec<String>,
    source_review_file: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    observation_source_review_file: Option<String>,
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

#[derive(Debug, Clone, Serialize)]
struct ObservationSourceEligibility {
    id: &'static str,
    label: &'static str,
    url: &'static str,
    archive_url: Option<&'static str>,
    locally_archived: bool,
    accessed_at: &'static str,
    publication_date: Option<&'static str>,
    source_type: &'static str,
    allowed_use: &'static str,
    use_note: &'static str,
    eligible_for_scored_observations: bool,
    reason: String,
}

#[derive(Debug, Serialize)]
struct SourceFrontierReport {
    source_count: usize,
    scored_observation_eligible_count: usize,
    scored_position_marker_count: usize,
    valid_source_backed_archive_count: usize,
    all_source_backed_archives_negative: bool,
    context_only_count: usize,
    quarantined_claim_count: usize,
    frontier_blocking_conditions: Vec<String>,
    required_next_evidence: Vec<String>,
    disallowed_next_actions: Vec<String>,
    frontier_sources: Vec<SourceFrontierEntry>,
    recommended_next_step: String,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceFrontierEntry {
    id: &'static str,
    label: &'static str,
    source_type: &'static str,
    allowed_use: &'static str,
    frontier_class: String,
    archive_url: Option<&'static str>,
    locally_archived: bool,
    current_archive_has_scored_positions: bool,
    source_backed_archive_count: usize,
    archived_support_statuses: Vec<String>,
    non_scorable_reason: Option<String>,
    allowed_next_action: String,
    use_note: &'static str,
    url: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceFrontierSummary {
    summary: bool,
    source_count: usize,
    scored_observation_eligible_count: usize,
    scored_position_marker_count: usize,
    valid_source_backed_archive_count: usize,
    all_source_backed_archives_negative: bool,
    context_only_count: usize,
    quarantined_claim_count: usize,
    frontier_blocking_conditions: Vec<String>,
    required_next_evidence: Vec<String>,
    disallowed_next_actions: Vec<String>,
    scored_observation_ready_source_ids: Vec<&'static str>,
    eligible_but_currently_non_scorable_source_ids: Vec<&'static str>,
    already_scored_source_backed_archives: Vec<String>,
    recommended_next_step: String,
    action: &'static str,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct NextEvidenceGateReport {
    lane_directory: String,
    ready_lanes: usize,
    invalid_lanes: usize,
    unique_ready_prediction_artifacts: usize,
    duplicate_prediction_artifact_group_count: usize,
    duplicate_prediction_artifact_groups: Vec<DuplicatePredictionArtifactGroup>,
    evaluator_pending_lane_count: usize,
    evaluator_pending_lanes: Vec<NextEvidencePendingLane>,
    eligible_source_ids: Vec<String>,
    eligible_sources: Vec<ObservationSourceEligibility>,
    ineligible_source_count: usize,
    quarantined_claim_source_ids: Vec<String>,
    claim_verification_archive_count: usize,
    claim_verification_archives: Vec<ClaimVerificationArchiveStatus>,
    quarantined_claim_source_ids_without_archive: Vec<String>,
    claim_verification_command: &'static str,
    valid_source_backed_archive_count: usize,
    invalid_archive_count: usize,
    all_source_backed_archives_negative: bool,
    source_backed_archive_correction_count: usize,
    min_source_backed_empirical_p_value: Option<f64>,
    min_source_backed_adjusted_p_value: Option<f64>,
    all_source_backed_archives_negative_after_correction: bool,
    used_eligible_source_ids: Vec<String>,
    unused_eligible_source_ids: Vec<String>,
    unused_eligible_source_status: Vec<EligibleSourceUseStatus>,
    source_review_roots: Vec<String>,
    scanned_source_review_count: usize,
    valid_source_review_count: usize,
    invalid_source_review_count: usize,
    source_review_available: bool,
    evidence_available: bool,
    evidence_support_summary: Vec<String>,
    evidence_support_details: Vec<NextEvidenceSupportDetail>,
    next_action_kind: String,
    blocking_conditions: Vec<String>,
    readiness_note: &'static str,
    recommended_next_step: String,
    next_check_commands: Vec<&'static str>,
    required_observation_fields: Vec<&'static str>,
    source_review_status_command: &'static str,
    source_observation_status_command: &'static str,
    source_review_scaffold_command: &'static str,
    source_review_validation_command: &'static str,
    gates: Vec<NextEvidenceGate>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct NextEvidencePendingLane {
    id: String,
    hypothesis_family: String,
    preregistration: String,
    prediction_artifact: Option<String>,
    next_step: String,
}

#[derive(Debug, Serialize)]
struct ClaimVerificationArchiveStatus {
    directory: String,
    source_id: String,
    structural_checks_passed: Option<bool>,
    promoted_candidate: bool,
    status: String,
}

#[derive(Debug, Serialize)]
struct NextEvidenceSupportDetail {
    directory: String,
    artifact_kind: String,
    observation_source_ids: Vec<String>,
    best_model: Option<String>,
    observed_hits: Option<String>,
    null_mean_best_hits: Option<f64>,
    empirical_p_value: Option<f64>,
    source_backed_adjusted_p_value: Option<f64>,
    support_status: String,
}

#[derive(Debug, Serialize)]
struct EligibleSourceUseStatus {
    source_id: String,
    archive_url: Option<String>,
    locally_archived: bool,
    current_archive_has_scored_positions: bool,
    non_scorable_reason: Option<String>,
    status: String,
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

#[derive(Debug, Serialize)]
struct SourceReviewPacketReport {
    eligible_source_count: usize,
    eligible_sources: Vec<ObservationSourceEligibility>,
    required_review_steps: Vec<&'static str>,
    observation_requirements: Vec<&'static str>,
    source_observation_status_command: &'static str,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceIntakePacketReport {
    registry_fields: Vec<&'static str>,
    allowed_use_boundaries: Vec<&'static str>,
    local_archive_requirements: Vec<&'static str>,
    scoreable_evidence_requirements: Vec<&'static str>,
    rejection_rules: Vec<&'static str>,
    followup_commands: Vec<&'static str>,
    archive_template: &'static str,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceReviewFile {
    id: String,
    source_ids: Vec<String>,
    sources: Vec<ObservationSourceEligibility>,
    review_note: String,
    required_review_steps: Vec<&'static str>,
    observation_requirements: Vec<&'static str>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceReviewScaffoldReport {
    output_path: String,
    review: SourceReviewFile,
    valid: bool,
    errors: Vec<String>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct SourceReviewValidation {
    input_path: String,
    review_id: Option<String>,
    source_ids: Vec<String>,
    reviewed_source_count: usize,
    missing_local_archive_count: usize,
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceArchiveValidation {
    input_path: String,
    source_id: String,
    source_url: Option<String>,
    allowed_use: Option<String>,
    archive_has_scored_positions: bool,
    non_scorable_reason: Option<String>,
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceReviewStatusReport {
    roots: Vec<String>,
    scanned_review_count: usize,
    valid_review_count: usize,
    invalid_review_count: usize,
    missing_root_count: usize,
    source_review_available: bool,
    reviews: Vec<SourceReviewStatusEntry>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceReviewStatusEntry {
    path: String,
    review_id: Option<String>,
    source_ids: Vec<String>,
    reviewed_source_count: usize,
    missing_local_archive_count: usize,
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SourceObservationStatusReport {
    lane_directory: String,
    eligible_source_count: usize,
    reviewed_eligible_source_count: usize,
    used_eligible_source_count: usize,
    unused_eligible_source_count: usize,
    sources_with_scored_position_markers: usize,
    valid_source_review_count: usize,
    valid_source_backed_archive_count: usize,
    all_source_backed_archives_negative: bool,
    statuses: Vec<SourceObservationStatusEntry>,
    next_action_kind: String,
    recommended_next_step: String,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceObservationStatusEntry {
    source_id: String,
    label: String,
    archive_url: Option<String>,
    locally_archived: bool,
    reviewed_by_valid_source_review: bool,
    review_ids: Vec<String>,
    used_in_source_backed_archive: bool,
    source_backed_archive_directories: Vec<String>,
    archived_evidence_summaries: Vec<SourceObservationArchivedEvidence>,
    current_archive_has_scored_positions: bool,
    non_scorable_reason: Option<String>,
    action_status: String,
}

#[derive(Clone, Debug, Serialize)]
struct SourceObservationArchivedEvidence {
    directory: String,
    artifact_kind: String,
    best_model: Option<String>,
    observed_hits: Option<String>,
    null_mean_best_hits: Option<f64>,
    empirical_p_value: Option<f64>,
    support_status: String,
}

#[derive(Debug, Serialize)]
struct NonAnchorPositionReport {
    ciphertext_length: usize,
    non_anchor_position_count: usize,
    anchor_position_count: usize,
    non_anchor_positions_one_based: Vec<usize>,
    excluded_anchor_ranges: Vec<ExcludedAnchorRange>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct IndependentEvidenceStatusReport {
    roots: Vec<String>,
    scanned_archive_count: usize,
    valid_source_backed_archive_count: usize,
    valid_diagnostic_archive_count: usize,
    invalid_archive_count: usize,
    evidence_available: bool,
    archives: Vec<IndependentEvidenceArchiveSummary>,
    promoted_candidate: bool,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct IndependentEvidenceArchiveSummary {
    directory: String,
    artifact_kind: String,
    source_backed_observation: bool,
    observation_source_ids: Vec<String>,
    valid: bool,
    best_model: Option<String>,
    observed_hits: Option<String>,
    null_mean_best_hits: Option<f64>,
    empirical_p_value: Option<f64>,
    support_status: String,
    errors: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ExcludedAnchorRange {
    label: &'static str,
    start_one_based: usize,
    end_one_based_inclusive: usize,
    positions_one_based: Vec<usize>,
    source_ids: Vec<&'static str>,
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
    source_review: Option<PathBuf>,
    output: PathBuf,
    force: bool,
    format: OutputFormat,
}

struct InitSourceReviewOptions {
    id: String,
    source_ids: Vec<String>,
    review_note: String,
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

fn parse_positive_usize_list(input: &str) -> std::result::Result<Vec<usize>, String> {
    let values: Result<Vec<_>, _> = input
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<usize>()
                .map_err(|_| format!("invalid positive integer `{part}`"))
        })
        .collect();
    let values = values?;
    if values.is_empty() {
        Err("list must include at least one positive integer".to_string())
    } else if values.iter().any(|value| *value == 0) {
        Err("values must be greater than zero".to_string())
    } else {
        Ok(values)
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
    if let Some(source_review_file) = &observations.source_review_file {
        if source_review_file.trim().is_empty() {
            errors.push("positions_file source_review_file must not be empty".to_string());
        } else if contains_template_placeholder(source_review_file) {
            errors.push(
                "positions_file source_review_file still contains template placeholder text"
                    .to_string(),
            );
        } else {
            match validate_source_review_file(Path::new(source_review_file)) {
                Ok(validation) => {
                    if !validation.valid {
                        errors.extend(
                            validation
                                .errors
                                .into_iter()
                                .map(|error| format!("source_review_file: {error}")),
                        );
                    }
                    let reviewed_source_ids =
                        validation.source_ids.into_iter().collect::<BTreeSet<_>>();
                    for source_id in &observations.source_ids {
                        if !reviewed_source_ids.contains(source_id) {
                            errors.push(format!(
                                "positions_file source_review_file `{source_review_file}` does not cover observation source_id `{source_id}`"
                            ));
                        }
                    }
                }
                Err(error) => errors.push(format!(
                    "positions_file source_review_file `{source_review_file}` failed validation: {error}"
                )),
            }
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
        source_review_file: observations.source_review_file,
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
    options: InitPositionObservationOptions,
) -> Result<PositionObservationScaffoldReport> {
    let InitPositionObservationOptions {
        id,
        source_ids,
        positions,
        rationale,
        position_notes: position_note_inputs,
        source_review,
        output,
        force,
        format: _,
    } = options;
    if output.exists() && !force {
        anyhow::bail!(
            "output file already exists: {}; pass --force to overwrite",
            output.display()
        );
    }

    let positions_one_based = parse_position_list(&positions).map_err(anyhow::Error::msg)?;
    let position_notes = build_position_notes(&positions_one_based, &position_note_inputs)?;
    let source_review_file = source_review
        .as_ref()
        .map(|path| path.display().to_string());
    let observation = PeriodPredictionObservationFile {
        id,
        source_ids,
        source_review_file,
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

fn create_source_review_file(
    id: String,
    source_ids: Vec<String>,
    review_note: String,
    output: PathBuf,
    force: bool,
) -> Result<SourceReviewScaffoldReport> {
    if output.exists() && !force {
        anyhow::bail!(
            "output file already exists: {}; pass --force to overwrite",
            output.display()
        );
    }

    if id.trim().is_empty() {
        anyhow::bail!("source-review id must not be empty");
    }
    if contains_template_placeholder(&id) {
        anyhow::bail!("source-review id still contains template placeholder text");
    }
    if review_note.trim().is_empty() {
        anyhow::bail!("review-note must not be empty");
    }
    if contains_template_placeholder(&review_note) {
        anyhow::bail!("review-note still contains template placeholder text");
    }

    let packet = source_review_packet_report();
    let eligible_by_id: BTreeMap<_, _> = packet
        .eligible_sources
        .iter()
        .cloned()
        .map(|source| (source.id, source))
        .collect();
    let all_sources: BTreeMap<_, _> = observation_source_eligibility_report()
        .sources
        .into_iter()
        .map(|source| (source.id, source))
        .collect();

    let mut selected_sources = Vec::new();
    let mut normalized_source_ids = Vec::new();
    let mut seen_source_ids = HashSet::new();
    for source_id in source_ids {
        let source_id = source_id.trim().to_string();
        if source_id.is_empty() {
            anyhow::bail!("source-id must not be empty");
        }
        if contains_template_placeholder(&source_id) {
            anyhow::bail!("source-id `{source_id}` still contains template placeholder text");
        }
        if !seen_source_ids.insert(source_id.clone()) {
            anyhow::bail!("source-id `{source_id}` was provided more than once");
        }
        if let Some(source) = eligible_by_id.get(source_id.as_str()) {
            normalized_source_ids.push(source_id);
            selected_sources.push(source.clone());
        } else if let Some(source) = all_sources.get(source_id.as_str()) {
            anyhow::bail!(
                "source-id `{source_id}` has allowed_use `{}` and cannot be used for scored source-review evidence",
                source.allowed_use
            );
        } else {
            anyhow::bail!("source-id `{source_id}` is not registered");
        }
    }

    let review = SourceReviewFile {
        id,
        source_ids: normalized_source_ids,
        sources: selected_sources,
        review_note: review_note.trim().to_string(),
        required_review_steps: packet.required_review_steps,
        observation_requirements: packet.observation_requirements,
        promoted_candidate: false,
        note: "Source-review file records pre-score source review only; it is not a claimed solution.",
    };

    write_output_file_atomically(
        &output,
        &format!("{}\n", serde_json::to_string_pretty(&review)?),
    )?;

    Ok(SourceReviewScaffoldReport {
        output_path: output.display().to_string(),
        review,
        valid: true,
        errors: Vec::new(),
        promoted_candidate: false,
        note: "Source-review scaffolding writes source eligibility and review notes only; it is not a claimed solution.",
    })
}

fn validate_source_review_file(input: &Path) -> Result<SourceReviewValidation> {
    let contents = fs::read_to_string(input)
        .with_context(|| format!("failed to read source-review file `{}`", input.display()))?;
    let value: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("source-review file `{}` is not valid JSON", input.display()))?;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let review_id = json_string_field(&value, "id", &mut errors);
    if let Some(id) = &review_id
        && contains_template_placeholder(id)
    {
        errors.push("id still contains template placeholder text".to_string());
    }

    match json_string_field(&value, "review_note", &mut errors) {
        Some(note) if contains_template_placeholder(&note) => {
            errors.push("review_note still contains template placeholder text".to_string());
        }
        Some(_) => {}
        None => {}
    }

    if value
        .get("promoted_candidate")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        errors.push("promoted_candidate must be false".to_string());
    }

    let source_ids = json_string_array_field(&value, "source_ids", &mut errors);
    let sources = value
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            errors.push("sources must be a non-empty array".to_string());
            Vec::new()
        });
    if sources.is_empty() {
        errors.push("sources must include at least one reviewed source".to_string());
    }
    if !sources.is_empty() && sources.len() != source_ids.len() {
        errors.push(format!(
            "sources length {} does not match source_ids length {}",
            sources.len(),
            source_ids.len()
        ));
    }

    let eligible_by_id: BTreeMap<_, _> = observation_source_eligibility_report()
        .sources
        .into_iter()
        .filter(|source| source.eligible_for_scored_observations)
        .map(|source| (source.id, source))
        .collect();
    let mut seen_source_ids = HashSet::new();
    let mut missing_local_archive_count = 0;
    for source_id in &source_ids {
        if !seen_source_ids.insert(source_id.clone()) {
            errors.push(format!("source_id `{source_id}` appears more than once"));
        }
        match eligible_by_id.get(source_id.as_str()) {
            Some(source) if !source.locally_archived => missing_local_archive_count += 1,
            Some(_) => {}
            None => errors.push(format!(
                "source_id `{source_id}` is not registered as eligible scored-observation evidence"
            )),
        }
    }

    for source_value in &sources {
        let Some(source_id) = json_string_field(source_value, "id", &mut errors) else {
            continue;
        };
        let Some(expected) = eligible_by_id.get(source_id.as_str()) else {
            errors.push(format!(
                "sources entry `{source_id}` is not registered as eligible scored-observation evidence"
            ));
            continue;
        };
        if !source_ids.contains(&source_id) {
            errors.push(format!(
                "sources entry `{source_id}` is not listed in source_ids"
            ));
        }
        validate_source_review_field(source_value, &source_id, "url", expected.url, &mut errors);
        validate_source_review_field(
            source_value,
            &source_id,
            "accessed_at",
            expected.accessed_at,
            &mut errors,
        );
        validate_source_review_field(
            source_value,
            &source_id,
            "allowed_use",
            expected.allowed_use,
            &mut errors,
        );
        if source_value
            .get("locally_archived")
            .and_then(serde_json::Value::as_bool)
            != Some(expected.locally_archived)
        {
            errors.push(format!(
                "sources entry `{source_id}` has stale locally_archived value"
            ));
        }
    }

    if json_array_len(&value, "required_review_steps", &mut errors) == 0 {
        errors.push("required_review_steps must not be empty".to_string());
    }
    if json_array_len(&value, "observation_requirements", &mut errors) == 0 {
        errors.push("observation_requirements must not be empty".to_string());
    }
    if missing_local_archive_count > 0 {
        warnings.push(format!(
            "{missing_local_archive_count} reviewed source(s) lack local archive URLs"
        ));
    }

    let valid = errors.is_empty();
    Ok(SourceReviewValidation {
        input_path: input.display().to_string(),
        review_id,
        source_ids,
        reviewed_source_count: sources.len(),
        missing_local_archive_count,
        valid,
        errors,
        warnings,
        promoted_candidate: false,
        note: "Source-review validation checks pre-score source eligibility and metadata; it is not a claimed solution.",
    })
}

fn json_string_field(
    value: &serde_json::Value,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    match value.get(field).and_then(serde_json::Value::as_str) {
        Some(text) if !text.trim().is_empty() => Some(text.trim().to_string()),
        Some(_) => {
            errors.push(format!("{field} must not be empty"));
            None
        }
        None => {
            errors.push(format!("{field} must be a string"));
            None
        }
    }
}

fn json_string_array_field(
    value: &serde_json::Value,
    field: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let Some(array) = value.get(field).and_then(serde_json::Value::as_array) else {
        errors.push(format!("{field} must be a non-empty array"));
        return Vec::new();
    };
    if array.is_empty() {
        errors.push(format!("{field} must be a non-empty array"));
    }
    array
        .iter()
        .filter_map(|entry| match entry.as_str() {
            Some(text) if !text.trim().is_empty() => Some(text.trim().to_string()),
            _ => {
                errors.push(format!("{field} entries must be non-empty strings"));
                None
            }
        })
        .collect()
}

fn json_array_len(value: &serde_json::Value, field: &str, errors: &mut Vec<String>) -> usize {
    match value.get(field).and_then(serde_json::Value::as_array) {
        Some(array) => array.len(),
        None => {
            errors.push(format!("{field} must be an array"));
            0
        }
    }
}

fn validate_source_review_field(
    source_value: &serde_json::Value,
    source_id: &str,
    field: &str,
    expected: &str,
    errors: &mut Vec<String>,
) {
    match source_value.get(field).and_then(serde_json::Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(_) => errors.push(format!(
            "sources entry `{source_id}` has stale {field} value"
        )),
        None => errors.push(format!(
            "sources entry `{source_id}` is missing string field `{field}`"
        )),
    }
}

fn build_position_notes(
    positions_one_based: &[usize],
    position_note_inputs: &[String],
) -> Result<BTreeMap<String, String>> {
    if position_note_inputs.is_empty() {
        anyhow::bail!("provide one --position-note POS=NOTE entry for every --positions value");
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

fn load_mirror_prediction_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let plan: MirrorPredictionPlanSet = serde_json::from_str(&input)?;
    let positions = plan
        .plans
        .into_iter()
        .flat_map(|pair| [pair.left_position_one_based, pair.right_position_one_based])
        .collect();
    Ok(positions)
}

fn load_grid_prediction_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let plan: GridLayoutPredictionPlan = serde_json::from_str(&input)?;
    let positions = plan
        .rows
        .into_iter()
        .flat_map(|row| row.non_anchor_positions_one_based)
        .collect();
    Ok(positions)
}

fn load_ciphertext_prior_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextStructurePrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-structure-prior" {
        bail!(
            "ciphertext-prior artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    let positions = artifact
        .selected_periods
        .into_iter()
        .flat_map(|period| period.non_anchor_residues)
        .flat_map(|residue| residue.positions_one_based)
        .collect();
    Ok(positions)
}

fn load_ciphertext_hotspot_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextHotspotPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-hotspot-prior" {
        bail!(
            "ciphertext-hotspot artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_rarity_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextRarityPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-rarity-prior" {
        bail!(
            "ciphertext-rarity artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_transition_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextTransitionPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-transition-prior" {
        bail!(
            "ciphertext-transition artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_adjacent_contrast_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextAdjacentContrastPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-adjacent-contrast-prior" {
        bail!(
            "ciphertext-adjacent-contrast artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_skip_transition_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextSkipTransitionPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-skip-transition-prior" {
        bail!(
            "ciphertext-skip-transition artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_turning_point_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextTurningPointPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-turning-point-prior" {
        bail!(
            "ciphertext-turning-point artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_window_balance_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextWindowBalancePrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-window-balance-prior" {
        bail!(
            "ciphertext-window-balance artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_repeat_distance_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextRepeatDistancePrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-repeat-distance-prior" {
        bail!(
            "ciphertext-repeat-distance artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_residue_balance_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextResidueBalancePrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-residue-balance-prior" {
        bail!(
            "ciphertext-residue-balance artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_period_match_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextPeriodMatchPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-period-match-prior" {
        bail!(
            "ciphertext-period-match artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_ciphertext_stehle_regularity_artifact_positions(path: &Path) -> Result<HashSet<usize>> {
    let input = fs::read_to_string(path)?;
    let artifact: CiphertextStehleRegularityPrior = serde_json::from_str(&input)?;
    if artifact.artifact_kind != "ciphertext-stehle-regularity-prior" {
        bail!(
            "ciphertext-stehle-regularity artifact `{}` has artifact_kind `{}`",
            path.display(),
            artifact.artifact_kind
        );
    }
    Ok(artifact
        .non_anchor_positions_one_based
        .into_iter()
        .collect())
}

fn load_tableau_hill_prediction_artifact_positions(
    path: &Path,
) -> Result<(HashSet<usize>, HashSet<usize>, usize)> {
    let input = fs::read_to_string(path)?;
    let plan: TableauHillPredictionPlan = serde_json::from_str(&input)?;
    let mut mapped_positions = HashSet::new();
    let mut public_anchor_positions = HashSet::new();
    let mut padding_cell_count = 0;

    for cell in plan.coordinate_mapping {
        if cell.is_padding {
            padding_cell_count += 1;
        }
        if let Some(position) = cell.k4_position_one_based {
            mapped_positions.insert(position);
            if cell.is_public_anchor_position {
                public_anchor_positions.insert(position);
            }
        }
    }

    Ok((
        mapped_positions,
        public_anchor_positions,
        padding_cell_count,
    ))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Facts { format } => print_facts(format)?,
        Command::CiphertextProfile {
            max_period,
            max_ngram,
            top,
            iterations,
            seed,
            format,
        } => print_ciphertext_profile(max_period, max_ngram, top, iterations, seed, format)?,
        Command::CiphertextStructurePrior {
            max_period,
            max_ngram,
            iterations,
            seed,
            format,
        } => print_ciphertext_structure_prior(max_period, max_ngram, iterations, seed, format)?,
        Command::CiphertextHotspotPrior {
            max_period,
            max_ngram,
            top,
            format,
        } => print_ciphertext_hotspot_prior(max_period, max_ngram, top, format)?,
        Command::CiphertextRarityPrior { top, format } => {
            print_ciphertext_rarity_prior(top, format)?
        }
        Command::CiphertextAdjacentContrastPrior { top, format } => {
            print_ciphertext_adjacent_contrast_prior(top, format)?
        }
        Command::CiphertextTransitionPrior { top, format } => {
            print_ciphertext_transition_prior(top, format)?
        }
        Command::CiphertextSkipTransitionPrior {
            top,
            skip_distances,
            format,
        } => print_ciphertext_skip_transition_prior(top, skip_distances, format)?,
        Command::CiphertextTurningPointPrior { top, format } => {
            print_ciphertext_turning_point_prior(top, format)?
        }
        Command::CiphertextRepeatDistancePrior { top, format } => {
            print_ciphertext_repeat_distance_prior(top, format)?
        }
        Command::CiphertextPeriodMatchPrior {
            max_period,
            top_periods,
            format,
        } => print_ciphertext_period_match_prior(max_period, top_periods, format)?,
        Command::CiphertextWindowBalancePrior {
            top,
            window_widths,
            format,
        } => print_ciphertext_window_balance_prior(top, window_widths, format)?,
        Command::CiphertextStehleRegularityPrior { format } => {
            print_ciphertext_stehle_regularity_prior(format)?
        }
        Command::CiphertextCtPerturbationPrior { format } => {
            print_ciphertext_ct_perturbation_prior(format)?
        }
        Command::CiphertextResidueBalancePrior {
            min_modulus,
            max_modulus,
            format,
        } => print_ciphertext_residue_balance_prior(min_modulus, max_modulus, format)?,
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
            require_unique_artifact,
            format,
        } => print_validate_prediction_artifact(preregistration, require_unique_artifact, format)?,
        Command::IndependentLaneStatus { directory, format } => {
            print_independent_lane_status(directory, format)?
        }
        Command::NextEvidenceGate { directory, format } => {
            print_next_evidence_gate(directory, format)?
        }
        Command::IndependentEvidenceStatus { roots, format } => {
            print_independent_evidence_status(roots, format)?
        }
        Command::SourceReviewStatus { roots, format } => print_source_review_status(roots, format)?,
        Command::SourceObservationStatus { directory, format } => {
            print_source_observation_status(directory, format)?
        }
        Command::SourceReviewPacket { format } => print_source_review_packet(format)?,
        Command::SourceIntakePacket { format } => print_source_intake_packet(format)?,
        Command::InitSourceReview {
            id,
            source_ids,
            review_note,
            output,
            force,
            format,
        } => print_init_source_review(InitSourceReviewOptions {
            id,
            source_ids,
            review_note,
            output,
            force,
            format,
        })?,
        Command::ValidateSourceReview { input, format } => {
            print_validate_source_review(input, format)?
        }
        Command::ValidateSourceArchive {
            source_id,
            input,
            format,
        } => print_validate_source_archive(source_id, input, format)?,
        Command::NonAnchorPositions { format } => print_non_anchor_positions(format)?,
        Command::InitPositionObservations {
            id,
            source_ids,
            positions,
            rationale,
            position_notes,
            source_review,
            output,
            force,
            format,
        } => print_init_position_observations(InitPositionObservationOptions {
            id,
            source_ids,
            positions,
            rationale,
            position_notes,
            source_review,
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
        Command::ValidateMirrorObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_mirror_observations(artifact, preregistration, input, format)?,
        Command::ValidateGridObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_grid_observations(artifact, preregistration, input, format)?,
        Command::ValidateTableauHillObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_tableau_hill_observations(artifact, preregistration, input, format)?,
        Command::ValidateCiphertextPriorObservations {
            artifact,
            preregistration,
            input,
            format,
        } => {
            print_validate_ciphertext_prior_observations(artifact, preregistration, input, format)?
        }
        Command::ValidateCiphertextHotspotObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_hotspot_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextRarityObservations {
            artifact,
            preregistration,
            input,
            format,
        } => {
            print_validate_ciphertext_rarity_observations(artifact, preregistration, input, format)?
        }
        Command::ValidateCiphertextAdjacentContrastObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_adjacent_contrast_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextTransitionObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_transition_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextSkipTransitionObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_skip_transition_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextTurningPointObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_turning_point_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextWindowBalanceObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_window_balance_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextRepeatDistanceObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_repeat_distance_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextPeriodMatchObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_period_match_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextStehleRegularityObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_stehle_regularity_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::ValidateCiphertextResidueBalanceObservations {
            artifact,
            preregistration,
            input,
            format,
        } => print_validate_ciphertext_residue_balance_observations(
            artifact,
            preregistration,
            input,
            format,
        )?,
        Command::PeriodPredictionPlan {
            period,
            all,
            format,
        } => print_period_prediction_plan(period, all, format)?,
        Command::SpacingPredictionPlan { format } => print_spacing_prediction_plan(format)?,
        Command::MirrorPredictionPlan { format } => print_mirror_prediction_plan(format)?,
        Command::GridLayoutPredictionPlan { edge_axis, format } => {
            print_grid_layout_prediction_plan(edge_axis.into(), format)?
        }
        Command::TableauHillPredictionPlan { format } => {
            print_tableau_hill_prediction_plan(format)?
        }
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
        Command::EvaluateMirrorPrediction {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_mirror_prediction(MirrorPredictionEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateGridPrediction {
            artifact,
            preregistration,
            positions,
            positions_file,
            edge_axis,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_grid_prediction(GridPredictionEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            edge_axis,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateTableauHillPrediction {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_tableau_hill_prediction(TableauHillPredictionEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateCiphertextPrior {
            positions_file,
            max_period,
            max_ngram,
            prior_iterations,
            prior_seed,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_prior(
            positions_file,
            max_period,
            max_ngram,
            prior_iterations,
            prior_seed,
            iterations,
            seed,
            output_dir,
            format,
        )?,
        Command::EvaluateCiphertextHotspot {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_hotspot(CiphertextHotspotEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateCiphertextRarity {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_rarity(CiphertextRarityEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateCiphertextAdjacentContrast {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_adjacent_contrast(
            CiphertextAdjacentContrastEvaluationOptions {
                artifact,
                preregistration,
                positions,
                positions_file,
                iterations,
                seed,
                output_dir,
                format,
            },
        )?,
        Command::EvaluateCiphertextTransition {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_transition(CiphertextTransitionEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateCiphertextSkipTransition {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => {
            print_evaluate_ciphertext_skip_transition(CiphertextSkipTransitionEvaluationOptions {
                artifact,
                preregistration,
                positions,
                positions_file,
                iterations,
                seed,
                output_dir,
                format,
            })?
        }
        Command::EvaluateCiphertextTurningPoint {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_turning_point(CiphertextTurningPointEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateCiphertextWindowBalance {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_window_balance(CiphertextWindowBalanceEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateCiphertextRepeatDistance {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => {
            print_evaluate_ciphertext_repeat_distance(CiphertextRepeatDistanceEvaluationOptions {
                artifact,
                preregistration,
                positions,
                positions_file,
                iterations,
                seed,
                output_dir,
                format,
            })?
        }
        Command::EvaluateCiphertextPeriodMatch {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_period_match(CiphertextPeriodMatchEvaluationOptions {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        })?,
        Command::EvaluateCiphertextStehleRegularity {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => print_evaluate_ciphertext_stehle_regularity(
            CiphertextStehleRegularityEvaluationOptions {
                artifact,
                preregistration,
                positions,
                positions_file,
                iterations,
                seed,
                output_dir,
                format,
            },
        )?,
        Command::EvaluateCiphertextResidueBalance {
            artifact,
            preregistration,
            positions,
            positions_file,
            iterations,
            seed,
            output_dir,
            format,
        } => {
            print_evaluate_ciphertext_residue_balance(CiphertextResidueBalanceEvaluationOptions {
                artifact,
                preregistration,
                positions,
                positions_file,
                iterations,
                seed,
                output_dir,
                format,
            })?
        }
        Command::ValidateEvaluationArchive { input, format } => {
            print_validate_evaluation_archive(input, format)?
        }
        Command::Hypotheses { format } => print_hypotheses(format)?,
        Command::CandidateSequences { format } => print_candidate_sequences(format)?,
        Command::Routes { format } => print_routes(format)?,
        Command::Findings { format } => print_findings(format)?,
        Command::Sources { format } => print_sources(format)?,
        Command::VerifyPlaintextClaim {
            input,
            source_id,
            format,
        } => print_verify_plaintext_claim(input, source_id, format)?,
        Command::VerifyRunningKeyClaim {
            plaintext,
            key,
            alphabet,
            source_id,
            format,
        } => print_verify_running_key_claim(plaintext, key, alphabet, source_id, format)?,
        Command::VerifyClaimReconciliation {
            input,
            source_id,
            format,
        } => print_verify_claim_reconciliation(input, source_id, format)?,
        Command::VerifyClaimBundle {
            directory,
            source_id,
            format,
        } => print_verify_claim_bundle(directory, source_id, format)?,
        Command::VerifyClaimMechanism {
            directory,
            source_id,
            format,
        } => print_verify_claim_mechanism(directory, source_id, format)?,
        Command::ObservationSources { format } => print_observation_sources(format)?,
        Command::SourceFrontier { summary, format } => print_source_frontier(summary, format)?,
        Command::ReleaseCheck { format } => print_release_check(format)?,
        Command::ExportData { directory } => export_data(directory)?,
        Command::Report { format, output } => {
            let report = build_report()?;
            let rendered = render_report(&report, format.into())?;
            if let Some(path) = output {
                write_output_file_atomically(&path, &rendered)?;
            } else {
                print!("{rendered}");
            }
        }
    }

    Ok(())
}

fn write_output_file_atomically(path: &Path, contents: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory `{}`", parent.display()))?;
    let file_name = path
        .file_name()
        .with_context(|| format!("output path `{}` has no file name", path.display()))?;
    let temp_path = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    fs::write(&temp_path, contents)
        .with_context(|| format!("failed to write temporary output `{}`", temp_path.display()))?;
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error)
            .with_context(|| format!("failed to replace output `{}`", path.display()));
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
            &[],
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
            &[],
        ),
    )?;
    Ok(())
}

fn write_mirror_prediction_evaluation_outputs(
    output_dir: &Path,
    evaluation: &MirrorPredictionEvaluation,
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
        render_mirror_prediction_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-mirror-prediction",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_grid_prediction_evaluation_outputs(
    output_dir: &Path,
    evaluation: &GridLayoutPredictionEvaluation,
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
        render_grid_prediction_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-grid-prediction",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[format!("--edge-axis {}", evaluation.edge_axis)],
        ),
    )?;
    Ok(())
}

fn write_tableau_hill_prediction_evaluation_outputs(
    output_dir: &Path,
    evaluation: &TableauHillPredictionEvaluation,
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
        render_tableau_hill_prediction_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-tableau-hill-prediction",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_hotspot_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextHotspotEvaluation,
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
        render_ciphertext_hotspot_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-hotspot",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_residue_balance_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextResidueBalanceEvaluation,
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
        render_ciphertext_residue_balance_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-residue-balance",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_rarity_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextRarityEvaluation,
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
        render_ciphertext_rarity_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-rarity",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_transition_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextTransitionEvaluation,
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
        render_ciphertext_transition_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-transition",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_adjacent_contrast_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextAdjacentContrastEvaluation,
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
        render_ciphertext_adjacent_contrast_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-adjacent-contrast",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_skip_transition_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextSkipTransitionEvaluation,
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
        render_ciphertext_skip_transition_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-skip-transition",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_turning_point_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextTurningPointEvaluation,
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
        render_ciphertext_turning_point_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-turning-point",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_window_balance_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextWindowBalanceEvaluation,
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
        render_ciphertext_window_balance_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-window-balance",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_repeat_distance_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextRepeatDistanceEvaluation,
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
        render_ciphertext_repeat_distance_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-repeat-distance",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_period_match_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextPeriodMatchEvaluation,
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
        render_ciphertext_period_match_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-period-match",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
        ),
    )?;
    Ok(())
}

fn write_ciphertext_stehle_regularity_evaluation_outputs(
    output_dir: &Path,
    evaluation: &CiphertextStehleRegularityEvaluation,
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
        render_ciphertext_stehle_regularity_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        render_archived_evaluation_command(
            "evaluate-ciphertext-stehle-regularity",
            archive,
            evaluation.iterations,
            evaluation.seed,
            &[],
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
            copy_observation_source_review_to_archive(path, output_dir)?;
        }
    }
    Ok(())
}

fn copy_observation_source_review_to_archive(
    observations_path: &Path,
    output_dir: &Path,
) -> Result<()> {
    let observations = read_period_prediction_observation_file(observations_path)?;
    if let Some(source_review_file) = observations.source_review_file {
        fs::copy(source_review_file, output_dir.join("source-review.json"))?;
    }
    Ok(())
}

fn render_archived_evaluation_command(
    command_name: &str,
    archive: &EvaluationArchiveContext,
    iterations: usize,
    seed: u64,
    extra_args: &[String],
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
    for arg in extra_args {
        command.push(' ');
        command.push_str(arg);
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

    let result = read_archive_json(directory, "result.json", &mut errors, &mut files_checked);
    check_archive_text_file(directory, "summary.md", &mut errors, &mut files_checked);
    let command = read_archive_text_file(directory, "command.txt", &mut errors, &mut files_checked);
    let artifact =
        read_archive_json_if_exists(directory, "artifact.json", &mut errors, &mut files_checked);

    let artifact_kind = infer_evaluation_archive_kind(artifact.as_ref(), result.as_ref(), &command)
        .unwrap_or("unknown")
        .to_string();
    if artifact_kind == "unknown" && artifact.is_some() {
        errors.push(
            "artifact.json is not a recognized period, spacing, mirror, grid, Tableau/HILL, ciphertext-prior, ciphertext-hotspot, ciphertext-rarity, ciphertext-repeat-distance, ciphertext-period-match, ciphertext-stehle-regularity, ciphertext-adjacent-contrast, ciphertext-transition, ciphertext-skip-transition, ciphertext-turning-point, ciphertext-window-balance, or ciphertext-residue-balance prediction artifact"
                .to_string(),
        );
    }
    if artifact_kind != "ciphertext-prior" && artifact.is_none() {
        errors.push("artifact.json is missing".to_string());
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
            "mirror" => require_command_name(command, "evaluate-mirror-prediction", &mut errors),
            "grid" => require_command_name(command, "evaluate-grid-prediction", &mut errors),
            "tableau-hill" => {
                require_command_name(command, "evaluate-tableau-hill-prediction", &mut errors)
            }
            "ciphertext-prior" => {
                require_command_name(command, "evaluate-ciphertext-prior", &mut errors)
            }
            "ciphertext-hotspot" => {
                require_command_name(command, "evaluate-ciphertext-hotspot", &mut errors)
            }
            "ciphertext-rarity" => {
                require_command_name(command, "evaluate-ciphertext-rarity", &mut errors)
            }
            "ciphertext-repeat-distance" => {
                require_command_name(command, "evaluate-ciphertext-repeat-distance", &mut errors)
            }
            "ciphertext-period-match" => {
                require_command_name(command, "evaluate-ciphertext-period-match", &mut errors)
            }
            "ciphertext-stehle-regularity" => require_command_name(
                command,
                "evaluate-ciphertext-stehle-regularity",
                &mut errors,
            ),
            "ciphertext-adjacent-contrast" => require_command_name(
                command,
                "evaluate-ciphertext-adjacent-contrast",
                &mut errors,
            ),
            "ciphertext-transition" => {
                require_command_name(command, "evaluate-ciphertext-transition", &mut errors)
            }
            "ciphertext-skip-transition" => {
                require_command_name(command, "evaluate-ciphertext-skip-transition", &mut errors)
            }
            "ciphertext-turning-point" => {
                require_command_name(command, "evaluate-ciphertext-turning-point", &mut errors)
            }
            "ciphertext-window-balance" => {
                require_command_name(command, "evaluate-ciphertext-window-balance", &mut errors)
            }
            "ciphertext-residue-balance" => {
                require_command_name(command, "evaluate-ciphertext-residue-balance", &mut errors)
            }
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
        if artifact_kind == "mirror" && result.get("mirror_pair_hits").is_none() {
            errors.push("mirror archive result.json is missing mirror_pair_hits".to_string());
        }
        if artifact_kind == "grid" {
            if result.get("edge_axis").is_none() {
                errors.push("grid archive result.json is missing edge_axis".to_string());
            }
            if result.get("edge_hits").is_none() {
                errors.push("grid archive result.json is missing edge_hits".to_string());
            }
            if result.get("row_edge_hits").is_none() {
                errors.push("grid archive result.json is missing row_edge_hits".to_string());
            }
        }
        if artifact_kind == "tableau-hill" {
            if result.get("best_axis").is_none() {
                errors.push("Tableau/HILL archive result.json is missing best_axis".to_string());
            }
            if result.get("best_hits").is_none() {
                errors.push("Tableau/HILL archive result.json is missing best_hits".to_string());
            }
        }
        if artifact_kind == "ciphertext-prior" {
            if result.get("best_period").is_none() {
                errors.push(
                    "ciphertext-prior archive result.json is missing best_period".to_string(),
                );
            }
            if result.get("best_residue").is_none() {
                errors.push(
                    "ciphertext-prior archive result.json is missing best_residue".to_string(),
                );
            }
            if result.get("best_hits").is_none() {
                errors
                    .push("ciphertext-prior archive result.json is missing best_hits".to_string());
            }
        }
        if artifact_kind == "ciphertext-hotspot" {
            if result.get("hotspot_hits").is_none() {
                errors.push(
                    "ciphertext-hotspot archive result.json is missing hotspot_hits".to_string(),
                );
            }
            if result.get("matching_hotspot_positions_one_based").is_none() {
                errors.push(
                    "ciphertext-hotspot archive result.json is missing matching_hotspot_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-rarity" {
            if result.get("rare_hits").is_none() {
                errors
                    .push("ciphertext-rarity archive result.json is missing rare_hits".to_string());
            }
            if result.get("matching_rare_positions_one_based").is_none() {
                errors.push(
                    "ciphertext-rarity archive result.json is missing matching_rare_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-repeat-distance" {
            if result.get("repeat_distance_hits").is_none() {
                errors.push(
                    "ciphertext-repeat-distance archive result.json is missing repeat_distance_hits"
                        .to_string(),
                );
            }
            if result
                .get("matching_repeat_distance_positions_one_based")
                .is_none()
            {
                errors.push(
                    "ciphertext-repeat-distance archive result.json is missing matching_repeat_distance_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-period-match" {
            if result.get("best_period").is_none() {
                errors.push(
                    "ciphertext-period-match archive result.json is missing best_period"
                        .to_string(),
                );
            }
            if result.get("best_hits").is_none() {
                errors.push(
                    "ciphertext-period-match archive result.json is missing best_hits".to_string(),
                );
            }
            if result.get("period_match_results").is_none() {
                errors.push(
                    "ciphertext-period-match archive result.json is missing period_match_results"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-transition" {
            if result.get("transition_hits").is_none() {
                errors.push(
                    "ciphertext-transition archive result.json is missing transition_hits"
                        .to_string(),
                );
            }
            if result
                .get("matching_transition_positions_one_based")
                .is_none()
            {
                errors.push(
                    "ciphertext-transition archive result.json is missing matching_transition_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-adjacent-contrast" {
            if result.get("contrast_hits").is_none() {
                errors.push(
                    "ciphertext-adjacent-contrast archive result.json is missing contrast_hits"
                        .to_string(),
                );
            }
            if result
                .get("matching_contrast_positions_one_based")
                .is_none()
            {
                errors.push(
                    "ciphertext-adjacent-contrast archive result.json is missing matching_contrast_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-skip-transition" {
            if result.get("skip_transition_hits").is_none() {
                errors.push(
                    "ciphertext-skip-transition archive result.json is missing skip_transition_hits"
                        .to_string(),
                );
            }
            if result
                .get("matching_skip_transition_positions_one_based")
                .is_none()
            {
                errors.push(
                    "ciphertext-skip-transition archive result.json is missing matching_skip_transition_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-turning-point" {
            if result.get("turning_point_hits").is_none() {
                errors.push(
                    "ciphertext-turning-point archive result.json is missing turning_point_hits"
                        .to_string(),
                );
            }
            if result
                .get("matching_turning_point_positions_one_based")
                .is_none()
            {
                errors.push(
                    "ciphertext-turning-point archive result.json is missing matching_turning_point_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-window-balance" {
            if result.get("window_balance_hits").is_none() {
                errors.push(
                    "ciphertext-window-balance archive result.json is missing window_balance_hits"
                        .to_string(),
                );
            }
            if result
                .get("matching_window_balance_positions_one_based")
                .is_none()
            {
                errors.push(
                    "ciphertext-window-balance archive result.json is missing matching_window_balance_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-stehle-regularity" {
            if result.get("regularity_hits").is_none() {
                errors.push(
                    "ciphertext-stehle-regularity archive result.json is missing regularity_hits"
                        .to_string(),
                );
            }
            if result.get("expected_delta_hits").is_none() {
                errors.push(
                    "ciphertext-stehle-regularity archive result.json is missing expected_delta_hits"
                        .to_string(),
                );
            }
            if result
                .get("matching_regularity_positions_one_based")
                .is_none()
            {
                errors.push(
                    "ciphertext-stehle-regularity archive result.json is missing matching_regularity_positions_one_based"
                        .to_string(),
                );
            }
        }
        if artifact_kind == "ciphertext-residue-balance" {
            if result.get("best_modulus").is_none() {
                errors.push(
                    "ciphertext-residue-balance archive result.json is missing best_modulus"
                        .to_string(),
                );
            }
            if result.get("best_residue").is_none() {
                errors.push(
                    "ciphertext-residue-balance archive result.json is missing best_residue"
                        .to_string(),
                );
            }
            if result.get("best_hits").is_none() {
                errors.push(
                    "ciphertext-residue-balance archive result.json is missing best_hits"
                        .to_string(),
                );
            }
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
        let preregistration = if artifact_kind == "ciphertext-prior" {
            None
        } else {
            read_archive_json(
                directory,
                "preregistration.json",
                &mut errors,
                &mut files_checked,
            )
        };
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
                directory,
                &mut files_checked,
                &mut errors,
            );
        }
        if artifact_kind == "ciphertext-prior"
            && let Some(observations) = &observations
        {
            validate_ciphertext_prior_archive_observations(
                observations,
                directory,
                &mut files_checked,
                &mut errors,
            );
        }
        if let Some(command) = &command {
            if artifact_kind != "ciphertext-prior" {
                require_command_token(command, "--artifact artifact.json", &mut errors);
                require_command_token(
                    command,
                    "--preregistration preregistration.json",
                    &mut errors,
                );
            }
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
        "position-mirror-prediction" => Some("mirror"),
        "position-grid-layout-prediction" => Some("grid"),
        "tableau-hill-prediction" => Some("tableau-hill"),
        "ciphertext-only-position-prior" => Some("ciphertext-prior"),
        "ciphertext-residue-balance-position-prior" => Some("ciphertext-residue-balance"),
        "ciphertext-hotspot-position-prior" => Some("ciphertext-hotspot"),
        "ciphertext-rarity-position-prior" => Some("ciphertext-rarity"),
        "ciphertext-repeat-distance-position-prior" => Some("ciphertext-repeat-distance"),
        "ciphertext-period-match-position-prior" => Some("ciphertext-period-match"),
        "ciphertext-adjacent-contrast-position-prior" => Some("ciphertext-adjacent-contrast"),
        "ciphertext-transition-position-prior" => Some("ciphertext-transition"),
        "ciphertext-skip-transition-position-prior" => Some("ciphertext-skip-transition"),
        "ciphertext-turning-point-position-prior" => Some("ciphertext-turning-point"),
        "ciphertext-window-balance-position-prior" => Some("ciphertext-window-balance"),
        "ciphertext-stehle-regularity-position-prior" => Some("ciphertext-stehle-regularity"),
        "ciphertext-ct-perturbation-position-prior" => Some("ciphertext-ct-perturbation"),
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
        "mirror" => build_mirror_prediction_plan()
            .and_then(|plan| serde_json::to_value(plan).map_err(Into::into)),
        "grid" => {
            let edge_axis = registration
                .grid_edge_axis
                .or_else(|| {
                    serde_json::from_value::<GridLayoutPredictionPlan>(artifact.clone())
                        .ok()
                        .map(|plan| plan.scored_edge_axis)
                })
                .unwrap_or(GridLayoutEdgeAxis::Row);
            build_grid_layout_prediction_plan_for_axis(edge_axis)
                .and_then(|plan| serde_json::to_value(plan).map_err(Into::into))
        }
        "tableau-hill" => {
            serde_json::to_value(build_tableau_hill_prediction_plan()).map_err(Into::into)
        }
        "ciphertext-hotspot" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_hotspot_prior())
                .map_err(Into::into)
        }
        "ciphertext-rarity" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_rarity_prior())
                .map_err(Into::into)
        }
        "ciphertext-repeat-distance" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_repeat_distance_prior())
                .map_err(Into::into)
        }
        "ciphertext-period-match" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_period_match_prior())
                .map_err(Into::into)
        }
        "ciphertext-adjacent-contrast" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_adjacent_contrast_prior())
                .map_err(Into::into)
        }
        "ciphertext-transition" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_transition_prior())
                .map_err(Into::into)
        }
        "ciphertext-skip-transition" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_skip_transition_prior())
                .map_err(Into::into)
        }
        "ciphertext-turning-point" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_turning_point_prior())
                .map_err(Into::into)
        }
        "ciphertext-residue-balance" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_residue_balance_prior())
                .map_err(Into::into)
        }
        "ciphertext-window-balance" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_window_balance_prior())
                .map_err(Into::into)
        }
        "ciphertext-stehle-regularity" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_stehle_regularity_prior())
                .map_err(Into::into)
        }
        "ciphertext-ct-perturbation" => {
            serde_json::to_value(kryptos_k4::build_committed_ciphertext_ct_perturbation_prior())
                .map_err(Into::into)
        }
        _ => return,
    };
    match expected_artifact {
        Ok(expected_artifact) => {
            if !archived_prediction_artifacts_match(artifact_kind, artifact, &expected_artifact) {
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

fn archived_prediction_artifacts_match(
    artifact_kind: &str,
    artifact_value: &serde_json::Value,
    expected_value: &serde_json::Value,
) -> bool {
    if artifact_kind == "period" {
        return archived_period_prediction_artifacts_match(artifact_value, expected_value);
    }
    if artifact_kind == "ciphertext-residue-balance" {
        return ciphertext_residue_balance_artifact_matches_deterministic(artifact_value);
    }
    if artifact_kind == "ciphertext-window-balance" {
        return ciphertext_window_balance_artifact_matches_deterministic(artifact_value);
    }
    json_values_match(artifact_value, expected_value)
}

fn archived_period_prediction_artifacts_match(
    artifact_value: &serde_json::Value,
    expected_value: &serde_json::Value,
) -> bool {
    if json_values_match(artifact_value, expected_value) {
        return true;
    }

    let Ok(artifact) = serde_json::from_value::<PeriodPredictionPlanSet>(artifact_value.clone())
    else {
        return false;
    };
    if artifact.period_count != artifact.plans.len() {
        return false;
    }

    artifact.plans.iter().all(|plan| {
        build_period_prediction_plan(plan.period)
            .map(|expected_plan| &expected_plan == plan)
            .unwrap_or(false)
    })
}

fn ciphertext_residue_balance_artifacts_match(
    left: &CiphertextResidueBalancePrior,
    right: &CiphertextResidueBalancePrior,
) -> bool {
    left.artifact_kind == right.artifact_kind
        && left.hypothesis_family == right.hypothesis_family
        && left.source_inputs == right.source_inputs
        && left.discovery_inputs == right.discovery_inputs
        && left.prediction_target == right.prediction_target
        && left.non_anchor_position_count == right.non_anchor_position_count
        && left.non_anchor_positions_one_based == right.non_anchor_positions_one_based
        && left.selected_moduli_count == right.selected_moduli_count
        && left.controls == right.controls
        && left.public_anchor_fragments_used_for_discovery
            == right.public_anchor_fragments_used_for_discovery
        && left.public_anchor_fragments_used_as_primary_evidence
            == right.public_anchor_fragments_used_as_primary_evidence
        && left.promoted_candidate == right.promoted_candidate
        && left.note == right.note
        && left.selected_residue_sets.len() == right.selected_residue_sets.len()
        && left
            .selected_residue_sets
            .iter()
            .zip(&right.selected_residue_sets)
            .all(|(left, right)| {
                left.modulus == right.modulus
                    && left.residue == right.residue
                    && left.position_count == right.position_count
                    && left.distinct_ciphertext_letters == right.distinct_ciphertext_letters
                    && (left.distinct_letter_rate - right.distinct_letter_rate).abs() < f64::EPSILON
                    && left.positions_one_based == right.positions_one_based
            })
}

fn ciphertext_residue_balance_artifact_matches_deterministic(
    artifact_value: &serde_json::Value,
) -> bool {
    let Ok(artifact) =
        serde_json::from_value::<CiphertextResidueBalancePrior>(artifact_value.clone())
    else {
        return false;
    };
    let Some(first) = artifact.selected_residue_sets.first() else {
        return false;
    };
    let Some(last) = artifact.selected_residue_sets.last() else {
        return false;
    };
    let min_modulus = first.modulus;
    let max_modulus = last.modulus;
    if min_modulus > max_modulus
        || artifact.selected_moduli_count != artifact.selected_residue_sets.len()
        || artifact.selected_residue_sets.len() != max_modulus - min_modulus + 1
        || artifact
            .selected_residue_sets
            .iter()
            .enumerate()
            .any(|(index, residue_set)| residue_set.modulus != min_modulus + index)
    {
        return false;
    }
    let expected = kryptos_k4::build_ciphertext_residue_balance_prior(min_modulus, max_modulus);
    ciphertext_residue_balance_artifacts_match(&artifact, &expected)
}

fn ciphertext_window_balance_artifacts_match(
    left: &CiphertextWindowBalancePrior,
    right: &CiphertextWindowBalancePrior,
) -> bool {
    left.artifact_kind == right.artifact_kind
        && left.hypothesis_family == right.hypothesis_family
        && left.source_inputs == right.source_inputs
        && left.discovery_inputs == right.discovery_inputs
        && left.prediction_target == right.prediction_target
        && left.alphabet == right.alphabet
        && left.window_widths == right.window_widths
        && left.non_anchor_position_count == right.non_anchor_position_count
        && left.non_anchor_positions_one_based == right.non_anchor_positions_one_based
        && left.window_balance_position_count == right.window_balance_position_count
        && left.window_balance_positions == right.window_balance_positions
        && left.controls == right.controls
        && left.public_anchor_fragments_used_for_discovery
            == right.public_anchor_fragments_used_for_discovery
        && left.public_anchor_fragments_used_as_primary_evidence
            == right.public_anchor_fragments_used_as_primary_evidence
        && left.promoted_candidate == right.promoted_candidate
        && left.note == right.note
}

fn ciphertext_window_balance_artifact_matches_deterministic(
    artifact_value: &serde_json::Value,
) -> bool {
    let Ok(artifact) =
        serde_json::from_value::<CiphertextWindowBalancePrior>(artifact_value.clone())
    else {
        return false;
    };
    if artifact.window_widths.is_empty()
        || artifact.window_balance_position_count != artifact.window_balance_positions.len()
        || artifact
            .window_widths
            .iter()
            .any(|width| *width < 3 || width % 2 == 0)
    {
        return false;
    }
    let expected = kryptos_k4::build_ciphertext_window_balance_prior(
        artifact.window_balance_position_count,
        artifact.window_widths.clone(),
    );
    ciphertext_window_balance_artifacts_match(&artifact, &expected)
}

fn json_values_match(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    left == right
        || serde_json::to_string(left).ok().as_deref()
            == serde_json::to_string(right).ok().as_deref()
}

fn validate_archived_observations_against_artifact(
    artifact_kind: &str,
    observations: &serde_json::Value,
    artifact: &serde_json::Value,
    directory: &Path,
    files_checked: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    let mut observations =
        match serde_json::from_value::<PeriodPredictionObservationFile>(observations.clone()) {
            Ok(observations) => observations,
            Err(error) => {
                errors.push(format!("observations.json is invalid: {error}"));
                return;
            }
        };

    let archived_source_review_path = directory.join("source-review.json");
    if observations.source_review_file.is_some() {
        if archived_source_review_path.exists() {
            files_checked.push("source-review.json".to_string());
            observations.source_review_file =
                Some(archived_source_review_path.display().to_string());
        } else {
            errors.push(
                "source-backed archive with source_review_file must include source-review.json"
                    .to_string(),
            );
        }
    }

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
    if artifact_kind == "mirror" && observations.positions_one_based.len() < 2 {
        errors.push(
            "observations.json: mirror observation files must include at least two one-based K4 positions"
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
            } else if artifact_kind == "mirror" {
                "mirror prediction artifact"
            } else if artifact_kind == "grid" {
                "grid-layout prediction artifact"
            } else if artifact_kind == "tableau-hill" {
                "Tableau/HILL source-mapping artifact"
            } else {
                "prediction artifact"
            };
            errors.push(format!(
                "observations.json: position `{position}` is not in the {context} non-anchor universe"
            ));
        }
    }
}

fn validate_ciphertext_prior_archive_observations(
    observations: &serde_json::Value,
    directory: &Path,
    files_checked: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    let mut observations =
        match serde_json::from_value::<PeriodPredictionObservationFile>(observations.clone()) {
            Ok(observations) => observations,
            Err(error) => {
                errors.push(format!("observations.json is invalid: {error}"));
                return;
            }
        };

    let archived_source_review_path = directory.join("source-review.json");
    if observations.source_review_file.is_some() {
        if archived_source_review_path.exists() {
            files_checked.push("source-review.json".to_string());
            observations.source_review_file =
                Some(archived_source_review_path.display().to_string());
        } else {
            errors.push(
                "source-backed ciphertext-prior archive with source_review_file must include source-review.json"
                    .to_string(),
            );
        }
    }

    errors.extend(
        validate_position_observation_scaffold(&observations)
            .into_iter()
            .map(|error| format!("observations.json: {error}")),
    );
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
        "mirror" => {
            let plan: MirrorPredictionPlanSet = serde_json::from_value(artifact.clone())?;
            Ok(plan
                .plans
                .into_iter()
                .flat_map(|pair| [pair.left_position_one_based, pair.right_position_one_based])
                .collect())
        }
        "grid" => {
            let plan: GridLayoutPredictionPlan = serde_json::from_value(artifact.clone())?;
            Ok(plan
                .rows
                .into_iter()
                .flat_map(|row| row.non_anchor_positions_one_based)
                .collect())
        }
        "tableau-hill" => {
            let plan: TableauHillPredictionPlan = serde_json::from_value(artifact.clone())?;
            Ok(plan
                .coordinate_mapping
                .into_iter()
                .filter(|cell| !cell.is_padding && !cell.is_public_anchor_position)
                .filter_map(|cell| cell.k4_position_one_based)
                .collect())
        }
        "ciphertext-hotspot" => {
            let plan: CiphertextHotspotPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-rarity" => {
            let plan: CiphertextRarityPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-repeat-distance" => {
            let plan: CiphertextRepeatDistancePrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-period-match" => {
            let plan: CiphertextPeriodMatchPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-adjacent-contrast" => {
            let plan: CiphertextAdjacentContrastPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-transition" => {
            let plan: CiphertextTransitionPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-skip-transition" => {
            let plan: CiphertextSkipTransitionPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-turning-point" => {
            let plan: CiphertextTurningPointPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-residue-balance" => {
            let plan: CiphertextResidueBalancePrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-window-balance" => {
            let plan: CiphertextWindowBalancePrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
        }
        "ciphertext-stehle-regularity" => {
            let plan: CiphertextStehleRegularityPrior = serde_json::from_value(artifact.clone())?;
            Ok(plan.non_anchor_positions_one_based.into_iter().collect())
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

fn read_archive_json_if_exists(
    directory: &Path,
    file_name: &str,
    errors: &mut Vec<String>,
    files_checked: &mut Vec<String>,
) -> Option<serde_json::Value> {
    let path = directory.join(file_name);
    if !path.exists() {
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
    if value.get("pair_count").is_some() && value.get("plans").is_some() {
        return Some("mirror");
    }
    if value.get("row_count").is_some()
        && value.get("column_count").is_some()
        && value.get("row_edge_positions_one_based").is_some()
    {
        return Some("grid");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("tableau-hill-source-mapping-plan")
    {
        return Some("tableau-hill");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-hotspot-prior")
    {
        return Some("ciphertext-hotspot");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-residue-balance-prior")
    {
        return Some("ciphertext-residue-balance");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-rarity-prior")
    {
        return Some("ciphertext-rarity");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-repeat-distance-prior")
    {
        return Some("ciphertext-repeat-distance");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-period-match-prior")
    {
        return Some("ciphertext-period-match");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-adjacent-contrast-prior")
    {
        return Some("ciphertext-adjacent-contrast");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-transition-prior")
    {
        return Some("ciphertext-transition");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-skip-transition-prior")
    {
        return Some("ciphertext-skip-transition");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-turning-point-prior")
    {
        return Some("ciphertext-turning-point");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-window-balance-prior")
    {
        return Some("ciphertext-window-balance");
    }
    if value
        .get("artifact_kind")
        .and_then(serde_json::Value::as_str)
        == Some("ciphertext-stehle-regularity-prior")
    {
        return Some("ciphertext-stehle-regularity");
    }
    None
}

fn infer_evaluation_archive_kind(
    artifact: Option<&serde_json::Value>,
    result: Option<&serde_json::Value>,
    command: &Option<String>,
) -> Option<&'static str> {
    if let Some(kind) = artifact.and_then(infer_prediction_artifact_kind) {
        return Some(kind);
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-prior")
    }) {
        return Some("ciphertext-prior");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-hotspot")
    }) {
        return Some("ciphertext-hotspot");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-rarity")
    }) {
        return Some("ciphertext-rarity");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-repeat-distance")
    }) {
        return Some("ciphertext-repeat-distance");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-period-match")
    }) {
        return Some("ciphertext-period-match");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-stehle-regularity")
    }) {
        return Some("ciphertext-stehle-regularity");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-adjacent-contrast")
    }) {
        return Some("ciphertext-adjacent-contrast");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-transition")
    }) {
        return Some("ciphertext-transition");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-skip-transition")
    }) {
        return Some("ciphertext-skip-transition");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-turning-point")
    }) {
        return Some("ciphertext-turning-point");
    }
    if command.as_ref().is_some_and(|command| {
        command.split_whitespace().next() == Some("evaluate-ciphertext-window-balance")
    }) {
        return Some("ciphertext-window-balance");
    }
    if result.is_some_and(|result| {
        result.get("selected_period_count").is_some()
            && result.get("period_results").is_some()
            && result.get("prior_summary").is_some()
    }) {
        return Some("ciphertext-prior");
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
    if observations.get("source_review_file").is_some()
        && observations.get("source_review_file") != result.get("observation_source_review_file")
    {
        errors.push(
            "observations.json source_review_file does not match result observation_source_review_file"
                .to_string(),
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

fn print_ciphertext_profile(
    max_period: usize,
    max_ngram: usize,
    top: usize,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let profile = profile_k4_ciphertext(max_period, max_ngram, top, iterations, seed);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&profile)?),
        OutputFormat::Markdown => {
            println!("# K4 Ciphertext Profile\n");
            println!("This is not a claimed solution.\n");
            println!("ciphertext length: {}", profile.ciphertext_length);
            println!("index of coincidence: {:.4}", profile.index_of_coincidence);
            println!("promoted: {}", profile.promoted_candidate);
            println!("note: {}\n", profile.note);

            println!("## Letter Frequencies\n");
            println!("| Rank | Letter | Count | Rate |");
            println!("| --- | --- | --- | --- |");
            for (index, frequency) in profile.letter_frequencies.iter().enumerate() {
                println!(
                    "| {} | {} | {} | {:.4} |",
                    index + 1,
                    frequency.letter,
                    frequency.count,
                    frequency.rate
                );
            }
            println!();

            println!("## Repeated N-grams\n");
            if profile.repeated_ngrams.is_empty() {
                println!("none\n");
            } else {
                println!("| Rank | N-gram | Length | Count | Positions |");
                println!("| --- | --- | --- | --- | --- |");
                for (index, ngram) in profile.repeated_ngrams.iter().enumerate() {
                    let positions = ngram
                        .positions_one_based
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "| {} | `{}` | {} | {} | {} |",
                        index + 1,
                        ngram.ngram,
                        ngram.length,
                        ngram.count,
                        positions
                    );
                }
                println!();
            }

            println!("## Repeated N-gram Spacing Diagnostics\n");
            if profile.kasiski_factor_profiles.is_empty() {
                println!("none\n");
            } else {
                println!("| Period | Supported Gaps | Support Rate | Example Gaps |");
                println!("| --- | --- | --- | --- |");
                for factor_profile in &profile.kasiski_factor_profiles {
                    let example_gaps = if factor_profile.supporting_gaps.is_empty() {
                        "none".to_string()
                    } else {
                        factor_profile
                            .supporting_gaps
                            .iter()
                            .take(8)
                            .map(|support| {
                                format!(
                                    "`{}` {}-{} gap {}",
                                    support.ngram,
                                    support.left_position_one_based,
                                    support.right_position_one_based,
                                    support.gap
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    println!(
                        "| {} | {}/{} | {:.4} | {} |",
                        factor_profile.period,
                        factor_profile.supported_gap_count,
                        factor_profile.total_gap_count,
                        factor_profile.support_rate,
                        example_gaps
                    );
                }
                println!();
            }
            if let Some(kasiski_baseline) = &profile.kasiski_baseline {
                println!("## Repeated N-gram Spacing Baseline\n");
                println!(
                    "observed best period: {}; observed supported gaps: {}; null mean best supported gaps: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; promoted: {}",
                    kasiski_baseline.observed_best_period,
                    kasiski_baseline.observed_best_supported_gap_count,
                    kasiski_baseline.null_mean_best_supported_gap_count,
                    kasiski_baseline.null_std_dev_best_supported_gap_count,
                    kasiski_baseline.empirical_p_value,
                    kasiski_baseline.iterations,
                    kasiski_baseline.seed,
                    kasiski_baseline.promoted_candidate
                );
                println!("note: {}\n", kasiski_baseline.note);
            }

            println!("## Period Coincidence Diagnostics\n");
            println!("| Period | Shift Matches | Shift Rate | Mean Coset IC | Matched Pairs |");
            println!("| --- | --- | --- | --- | --- |");
            for period in &profile.period_profiles {
                let matched_pairs = if period.shifted_matches.is_empty() {
                    "none".to_string()
                } else {
                    period
                        .shifted_matches
                        .iter()
                        .map(|shifted_match| {
                            format!(
                                "{}-{} {}",
                                shifted_match.left_position_one_based,
                                shifted_match.right_position_one_based,
                                shifted_match.letter
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                println!(
                    "| {} | {}/{} | {:.4} | {:.4} | {} |",
                    period.period,
                    period.shifted_match_count,
                    period.shifted_comparison_count,
                    period.shifted_match_rate,
                    period.mean_coset_ic,
                    matched_pairs
                );
            }
            if let Some(baseline) = &profile.baseline {
                println!();
                println!("## Ciphertext-Only Baseline\n");
                println!(
                    "observed best period: {}; observed best shifted rate: {:.4}; null mean best shifted rate: {:.4}; null sd: {:.4}; empirical p-value: {:.4}; iterations: {}; seed: {}; promoted: {}",
                    baseline.observed_best_period,
                    baseline.observed_best_shifted_match_rate,
                    baseline.null_mean_best_shifted_match_rate,
                    baseline.null_std_dev_best_shifted_match_rate,
                    baseline.empirical_p_value,
                    baseline.iterations,
                    baseline.seed,
                    baseline.promoted_candidate
                );
                println!("note: {}", baseline.note);
            }
        }
    }

    Ok(())
}

fn print_ciphertext_structure_prior(
    max_period: usize,
    max_ngram: usize,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let prior = build_ciphertext_structure_prior(max_period, max_ngram, iterations, seed);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Structure Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Selected Periods\n");
            println!("| Period | Support Kind | Observed Score | Empirical P | Residues |");
            println!("| --- | --- | --- | --- | --- |");
            for period in &prior.selected_periods {
                let residues = period
                    .non_anchor_residues
                    .iter()
                    .map(|residue| format!("{}:{}", residue.residue, residue.position_count))
                    .collect::<Vec<_>>()
                    .join(", ");
                let p_value = period
                    .empirical_p_value
                    .map(|value| format!("{value:.4}"))
                    .unwrap_or_else(|| "not run".to_string());
                println!(
                    "| {} | {} | {} | {} | {} |",
                    period.period, period.support_kind, period.observed_score, p_value, residues
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_hotspot_prior(
    max_period: usize,
    max_ngram: usize,
    top: usize,
    format: OutputFormat,
) -> Result<()> {
    let prior = build_ciphertext_hotspot_prior(max_period, max_ngram, top);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Hotspot Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!("hotspots: {}", prior.hotspot_count);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Hotspots\n");
            println!(
                "| Position | Ciphertext | Score | Repeated N-Gram Hits | Shifted Match Hits |"
            );
            println!("| --- | --- | --- | --- | --- |");
            for hotspot in &prior.hotspots {
                println!(
                    "| {} | {} | {} | {} | {} |",
                    hotspot.position_one_based,
                    hotspot.ciphertext,
                    hotspot.score,
                    hotspot.repeated_ngram_hits,
                    hotspot.shifted_match_hits
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_residue_balance_prior(
    min_modulus: usize,
    max_modulus: usize,
    format: OutputFormat,
) -> Result<()> {
    let prior = build_ciphertext_residue_balance_prior(min_modulus, max_modulus);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Residue-Balance Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!("selected moduli: {}", prior.selected_moduli_count);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Selected Residue Sets\n");
            println!("| Modulus | Residue | Positions | Distinct Letters | Distinct Rate |");
            println!("| --- | --- | --- | --- | --- |");
            for set in &prior.selected_residue_sets {
                println!(
                    "| {} | {} | {} | {} | {:.4} |",
                    set.modulus,
                    set.residue,
                    set.position_count,
                    set.distinct_ciphertext_letters,
                    set.distinct_letter_rate
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_rarity_prior(top: usize, format: OutputFormat) -> Result<()> {
    let prior = build_ciphertext_rarity_prior(top);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Rarity Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!("rare positions: {}", prior.rare_position_count);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Rare Positions\n");
            println!("| Position | Ciphertext | Non-Anchor Letter Count | Rarity Rank |");
            println!("| --- | --- | --- | --- |");
            for position in &prior.rare_positions {
                println!(
                    "| {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.non_anchor_letter_count,
                    position.rarity_rank
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_transition_prior(top: usize, format: OutputFormat) -> Result<()> {
    let prior = build_ciphertext_transition_prior(top);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Transition Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("alphabet: {}", prior.alphabet);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!("transition positions: {}", prior.transition_position_count);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Transition Positions\n");
            println!(
                "| Position | Ciphertext | Left Distance | Right Distance | Score | Max Adjacent | Rank |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- |");
            for position in &prior.transition_positions {
                println!(
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.left_transition_distance,
                    position.right_transition_distance,
                    position.transition_score,
                    position.max_adjacent_transition_distance,
                    position.transition_rank
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_adjacent_contrast_prior(top: usize, format: OutputFormat) -> Result<()> {
    let prior = build_ciphertext_adjacent_contrast_prior(top);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Adjacent-Contrast Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("alphabet: {}", prior.alphabet);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!(
                "adjacent-contrast positions: {}",
                prior.contrast_position_count
            );
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Adjacent-Contrast Positions\n");
            println!(
                "| Position | Ciphertext | Left Delta | Right Delta | Neighbor Gap | Center Deviation | Score | Rank |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- |");
            for position in &prior.contrast_positions {
                println!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.left_linear_delta,
                    position.right_linear_delta,
                    position.neighbor_gap,
                    position.center_neighbor_deviation,
                    position.contrast_score,
                    position.contrast_rank
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_skip_transition_prior(
    top: usize,
    skip_distances: String,
    format: OutputFormat,
) -> Result<()> {
    let skip_distances = parse_positive_usize_list(&skip_distances)
        .map_err(|error| anyhow::anyhow!("invalid --skip-distances: {error}"))?;
    let prior = build_ciphertext_skip_transition_prior(top, skip_distances);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Skip-Transition Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("alphabet: {}", prior.alphabet);
            println!(
                "skip distances: {}",
                prior
                    .skip_distances
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!(
                "skip-transition positions: {}",
                prior.skip_transition_position_count
            );
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Skip-Transition Positions\n");
            println!("| Position | Ciphertext | Score | Max Skip | Distances Used | Rank |");
            println!("| --- | --- | --- | --- | --- | --- |");
            for position in &prior.skip_transition_positions {
                println!(
                    "| {} | {} | {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.skip_transition_score,
                    position.max_skip_transition_distance,
                    position
                        .skip_distances_used
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    position.skip_transition_rank
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_turning_point_prior(top: usize, format: OutputFormat) -> Result<()> {
    let prior = build_ciphertext_turning_point_prior(top);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Turning-Point Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("alphabet: {}", prior.alphabet);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!(
                "turning-point positions: {}",
                prior.turning_point_position_count
            );
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Turning-Point Positions\n");
            println!(
                "| Position | Ciphertext | Left Delta | Right Delta | Curvature | Local Extremum | Rank |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- |");
            for position in &prior.turning_point_positions {
                println!(
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.left_delta,
                    position.right_delta,
                    position.curvature_score,
                    position.is_local_extremum,
                    position.turning_point_rank
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_repeat_distance_prior(top: usize, format: OutputFormat) -> Result<()> {
    let prior = build_ciphertext_repeat_distance_prior(top);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Repeat-Distance Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!(
                "repeat-distance positions: {}",
                prior.repeat_distance_position_count
            );
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Repeat-Distance Positions\n");
            println!(
                "| Position | Ciphertext | Same-Symbol Partners | Distinct Distances | Nearest Distance | Score | Rank |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- |");
            for position in &prior.repeat_distance_positions {
                println!(
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.same_symbol_position_count,
                    position.distinct_repeat_distances,
                    position.nearest_repeat_distance,
                    position.repeat_distance_score,
                    position.repeat_distance_rank
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_stehle_regularity_prior(format: OutputFormat) -> Result<()> {
    let prior = build_ciphertext_stehle_regularity_prior();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Stehle-Regularity Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("alphabet: {}", prior.alphabet);
            println!("source-reported window: {}", prior.source_reported_window);
            println!(
                "window: positions {}..={} lag {} delta +{} mod 26",
                prior.start_position_one_based,
                prior.start_position_one_based + prior.window_length - 1,
                prior.lag,
                prior.expected_delta_mod26
            );
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!("regularity positions: {}", prior.regularity_position_count);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Regularity Positions\n");
            println!("| Position | Ciphertext | A=0 Index | Lag Source | Lag Delta | Matches +5 |");
            println!("| --- | --- | --- | --- | --- | --- |");
            for position in &prior.regularity_positions {
                let lag_source = position
                    .lag_source_position_one_based
                    .map(|source| {
                        format!(
                            "{} ({})",
                            source,
                            position.lag_source_ciphertext.unwrap_or('?')
                        )
                    })
                    .unwrap_or_else(|| "n/a".to_string());
                let lag_delta = position
                    .lag_delta_mod26
                    .map(|delta| delta.to_string())
                    .unwrap_or_else(|| "n/a".to_string());
                println!(
                    "| {} | {} | {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.alphabet_index,
                    lag_source,
                    lag_delta,
                    position.matches_expected_delta
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_ct_perturbation_prior(format: OutputFormat) -> Result<()> {
    let prior = build_ciphertext_ct_perturbation_prior();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext CT-Perturbation Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("target symbols: {:?}", prior.target_symbols);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!("C/T positions: {}", prior.ct_position_count);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## C/T Positions\n");
            println!("| Position | Ciphertext | Target Symbol Rank | Same Target-Symbol Count |");
            println!("| --- | --- | --- | --- |");
            for position in &prior.ct_positions {
                println!(
                    "| {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.target_symbol_rank,
                    position.same_target_symbol_count
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_period_match_prior(
    max_period: usize,
    top_periods: usize,
    format: OutputFormat,
) -> Result<()> {
    let prior = build_ciphertext_period_match_prior(max_period, top_periods);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Period-Match Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("max period: {}", prior.max_period);
            println!("selected periods: {}", prior.period_match_set_count);
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Period Match Sets\n");
            println!("| Period | Shift Matches | Comparisons | Endpoint Positions |");
            println!("| --- | --- | --- | --- |");
            for set in &prior.period_match_sets {
                println!(
                    "| {} | {} | {} | {} |",
                    set.period,
                    set.shifted_match_count,
                    set.shifted_comparison_count,
                    set.endpoint_position_count
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
        }
    }

    Ok(())
}

fn print_ciphertext_window_balance_prior(
    top: usize,
    window_widths: String,
    format: OutputFormat,
) -> Result<()> {
    let window_widths =
        parse_positive_usize_list(&window_widths).map_err(|error| anyhow::anyhow!(error))?;
    let prior = build_ciphertext_window_balance_prior(top, window_widths);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&prior)?),
        OutputFormat::Markdown => {
            println!("# Ciphertext Window-Balance Prior\n");
            println!("This is not a claimed solution.\n");
            println!("artifact kind: {}", prior.artifact_kind);
            println!("hypothesis family: {}", prior.hypothesis_family);
            println!("window widths: {:?}", prior.window_widths);
            println!("non-anchor positions: {}", prior.non_anchor_position_count);
            println!(
                "window-balance positions: {}",
                prior.window_balance_position_count
            );
            println!("promoted: {}", prior.promoted_candidate);
            println!("note: {}\n", prior.note);

            println!("## Prediction Target\n");
            println!("{}\n", prior.prediction_target);

            println!("## Window-Balance Positions\n");
            println!(
                "| Position | Ciphertext | Width | Window | Sum | Ideal | Deviation | Distinct | Repeated | Score | Rank |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for position in &prior.window_balance_positions {
                println!(
                    "| {} | {} | {} | {}-{} | {} | {} | {} | {} | {} | {} | {} |",
                    position.position_one_based,
                    position.ciphertext,
                    position.best_window_width,
                    position.best_window_start_one_based,
                    position.best_window_end_one_based,
                    position.window_index_sum,
                    position.ideal_balanced_sum,
                    position.balance_deviation,
                    position.distinct_ciphertext_letters,
                    position.repeated_ciphertext_letters,
                    position.balance_score,
                    position.balance_rank
                );
            }
            println!();

            println!("## Controls\n");
            for control in &prior.controls {
                println!("- {control}");
            }
            println!();

            println!("## Discovery Inputs\n");
            for input in &prior.discovery_inputs {
                println!("- {input}");
            }
            println!();
            println!(
                "public anchor fragments used for discovery: {}",
                prior.public_anchor_fragments_used_for_discovery
            );
            println!(
                "public anchor fragments used as primary evidence: {}",
                prior.public_anchor_fragments_used_as_primary_evidence
            );
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
    require_unique_artifact: bool,
    format: OutputFormat,
) -> Result<()> {
    let mut validation = validate_prediction_artifact(&preregistration)?;
    if require_unique_artifact && !validation.duplicate_artifact_paths.is_empty() {
        validation.valid = false;
        validation.errors.push(format!(
            "prediction artifact duplicates {} other committed artifact(s); rerun without --require-unique-artifact only when duplicate readiness inventory is intentional",
            validation.duplicate_artifact_paths.len()
        ));
    }
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
    println!(
        "duplicate artifacts: {}",
        validation.duplicate_artifact_paths.len()
    );
    println!("expected plans: {}", validation.expected_plan_count);
    match validation.artifact_plan_count {
        Some(plan_count) => println!("artifact plans: {plan_count}"),
        None => println!("artifact plans: unavailable"),
    }
    let unit_label = match validation.artifact_kind.as_str() {
        "spacing" => "moduli",
        "period" => "periods",
        "mirror" => "pairs",
        "grid" => "rows",
        "ciphertext-prior" => "selected periods",
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
    if let Some(edge_axis) = &validation.registered_grid_edge_axis {
        println!("registered grid edge axis: {edge_axis}");
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
    let evidence_report = independent_evidence_status_report(Vec::new())?;
    let source_review_report = source_review_status_report(Vec::new())?;
    let eligible_source_ids = source_report
        .sources
        .iter()
        .filter(|source| source.eligible_for_scored_observations)
        .map(|source| source.id.to_string())
        .collect::<Vec<_>>();
    let eligible_sources = source_report
        .sources
        .iter()
        .filter(|source| source.eligible_for_scored_observations)
        .cloned()
        .collect::<Vec<_>>();
    let quarantined_claim_source_ids = source_report
        .sources
        .iter()
        .filter(|source| source.allowed_use == "unverified-solution-claim")
        .map(|source| source.id.to_string())
        .collect::<Vec<_>>();
    let claim_verification_archives = claim_verification_archive_statuses(Path::new("."))?;
    let archived_claim_source_ids = claim_verification_archives
        .iter()
        .map(|archive| archive.source_id.clone())
        .collect::<BTreeSet<_>>();
    let quarantined_claim_source_ids_without_archive = quarantined_claim_source_ids
        .iter()
        .filter(|source_id| !archived_claim_source_ids.contains(*source_id))
        .cloned()
        .collect::<Vec<_>>();
    let used_eligible_source_ids = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .flat_map(|archive| archive.observation_source_ids.iter())
        .filter(|source_id| eligible_source_ids.contains(source_id))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let unused_eligible_source_ids = eligible_source_ids
        .iter()
        .filter(|source_id| !used_eligible_source_ids.contains(source_id))
        .cloned()
        .collect::<Vec<_>>();
    let unused_eligible_source_status = eligible_sources
        .iter()
        .filter(|source| unused_eligible_source_ids.iter().any(|id| id == source.id))
        .map(eligible_source_use_status)
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

        let grid_edge_axis = if family.hypothesis_family == "position-grid-layout-prediction" {
            preregistered_grid_edge_axis_label(Path::new(&preregistration))
        } else {
            None
        };
        let Some((validation_command, evaluation_command, archive_validation_command)) =
            evidence_gate_commands(
                &family.hypothesis_family,
                &artifact,
                &preregistration,
                grid_edge_axis.as_deref(),
            )
        else {
            continue;
        };
        gates.push(NextEvidenceGate {
            hypothesis_family: family.hypothesis_family.clone(),
            ready_lanes: family.ready_for_source_backed_observations,
            unique_ready_prediction_artifacts: family.unique_ready_prediction_artifacts,
            representative_preregistration: preregistration,
            representative_artifact: artifact,
            observation_scaffold_command:
                "cargo run --locked -- init-position-observations --id <observation-id> --source-id <eligible-source-id> --source-review <source-review.json> --positions <comma-separated-non-anchor-positions> --rationale \"<source-backed rationale>\" --position-note \"<position>=<source-backed note>\" --output <source-backed-observations.json>"
                    .to_string(),
            validation_command,
            evaluation_command,
            archive_validation_command,
        });
    }
    let evaluator_pending_lanes = lane_report
        .lanes
        .iter()
        .filter(|lane| lane.status == "evaluator-pending")
        .map(|lane| NextEvidencePendingLane {
            id: lane.id.clone().unwrap_or_else(|| "unavailable".to_string()),
            hypothesis_family: lane
                .hypothesis_family
                .clone()
                .unwrap_or_else(|| "unavailable".to_string()),
            preregistration: lane.path.clone(),
            prediction_artifact: lane.prediction_artifact.clone(),
            next_step: lane.next_step.clone(),
        })
        .collect::<Vec<_>>();

    let source_backed_archive_correction_count = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .filter(|archive| archive.empirical_p_value.is_some())
        .count();
    let adjusted_source_backed_p_value = |p: Option<f64>| -> Option<f64> {
        p.map(|value| (value * source_backed_archive_correction_count as f64).min(1.0))
    };
    let min_source_backed_empirical_p_value = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .filter_map(|archive| archive.empirical_p_value)
        .min_by(|a, b| a.total_cmp(b));
    let min_source_backed_adjusted_p_value =
        adjusted_source_backed_p_value(min_source_backed_empirical_p_value);
    let all_source_backed_archives_negative_after_correction =
        source_backed_archive_correction_count > 0
            && evidence_report
                .archives
                .iter()
                .filter(|archive| archive.valid && archive.source_backed_observation)
                .all(|archive| {
                    adjusted_source_backed_p_value(archive.empirical_p_value)
                        .map(|p| p > 0.05)
                        .unwrap_or(false)
                });
    let evidence_support_summary = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .map(|archive| {
            format!(
                "{}: {} {}; p={}; adjusted p={}; status={}",
                archive.artifact_kind,
                archive.best_model.as_deref().unwrap_or("unknown model"),
                archive.observed_hits.as_deref().unwrap_or("unknown hits"),
                archive
                    .empirical_p_value
                    .map(|p| format!("{p:.4}"))
                    .unwrap_or_else(|| "n/a".to_string()),
                adjusted_source_backed_p_value(archive.empirical_p_value)
                    .map(|p| format!("{p:.4}"))
                    .unwrap_or_else(|| "n/a".to_string()),
                archive.support_status
            )
        })
        .collect::<Vec<_>>();
    let evidence_support_details = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .map(|archive| NextEvidenceSupportDetail {
            directory: archive.directory.clone(),
            artifact_kind: archive.artifact_kind.clone(),
            observation_source_ids: archive.observation_source_ids.clone(),
            best_model: archive.best_model.clone(),
            observed_hits: archive.observed_hits.clone(),
            null_mean_best_hits: archive.null_mean_best_hits,
            empirical_p_value: archive.empirical_p_value,
            source_backed_adjusted_p_value: adjusted_source_backed_p_value(
                archive.empirical_p_value,
            ),
            support_status: archive.support_status.clone(),
        })
        .collect::<Vec<_>>();
    let all_source_backed_archives_negative = evidence_report.valid_source_backed_archive_count > 0
        && evidence_report
            .archives
            .iter()
            .filter(|archive| archive.valid && archive.source_backed_observation)
            .all(|archive| archive.support_status == "negative/non-significant");
    let effective_all_source_backed_archives_negative =
        all_source_backed_archives_negative || all_source_backed_archives_negative_after_correction;
    let unused_sources_with_scored_positions = unused_eligible_source_status
        .iter()
        .filter(|source| source.current_archive_has_scored_positions)
        .map(|source| source.source_id.clone())
        .collect::<Vec<_>>();
    let duplicate_period_lanes_not_evidence = lane_report
        .duplicate_prediction_artifact_groups
        .iter()
        .any(|group| {
            group
                .lane_ids
                .iter()
                .any(|lane_id| lane_id.contains("non-anchor-position-period"))
        });
    let mut blocking_conditions = Vec::new();
    if duplicate_period_lanes_not_evidence {
        blocking_conditions.push("duplicate-period-lanes-not-evidence".to_string());
    }
    if effective_all_source_backed_archives_negative {
        blocking_conditions.push(
            "source-backed-evidence-negative-or-non-significant-after-correction".to_string(),
        );
    }
    let unused_sources_without_scored_positions = unused_eligible_source_status
        .iter()
        .filter(|source| !source.current_archive_has_scored_positions)
        .collect::<Vec<_>>();
    let all_unused_without_scored_positions_are_non_scorable =
        !unused_sources_without_scored_positions.is_empty()
            && unused_sources_without_scored_positions
                .iter()
                .all(|source| source.non_scorable_reason.is_some());
    if all_unused_without_scored_positions_are_non_scorable {
        blocking_conditions.push("unused-eligible-source-marked-non-scorable".to_string());
    } else if !unused_sources_without_scored_positions.is_empty() {
        blocking_conditions
            .push("unused-eligible-source-lacks-scored-position-markers".to_string());
    }

    let (next_action_kind, recommended_next_step) = if evidence_report
        .valid_source_backed_archive_count
        == 0
    {
        (
                "first-source-backed-observation".to_string(),
                "Create and validate the first source-backed non-anchor observation file before scoring any prediction artifact.".to_string(),
            )
    } else if effective_all_source_backed_archives_negative
        && !unused_sources_with_scored_positions.is_empty()
    {
        (
            "score-archived-unused-source-observation-or-distinct-prediction-artifact".to_string(),
            format!(
                "Current source-backed evidence is negative/non-significant after source-archive correction; do not add duplicate period lanes or rerun public-anchor-derived tests. Next useful work requires a new source-backed non-anchor observation from an unused eligible source with archived scored-position markers such as {} or a distinct preregistered prediction artifact.",
                unused_sources_with_scored_positions.join(", ")
            ),
        )
    } else if effective_all_source_backed_archives_negative
        && all_unused_without_scored_positions_are_non_scorable
    {
        (
            "new-source-backed-rationale-or-distinct-prediction-artifact".to_string(),
            "Current source-backed evidence is negative/non-significant after source-archive correction; every unused eligible source without scored-position markers is explicitly marked non-scorable. Next useful work requires a new source-backed rationale that changes that archive boundary, a new source-backed observation source, or a distinct preregistered prediction artifact.".to_string(),
        )
    } else if effective_all_source_backed_archives_negative
        && !unused_eligible_source_status.is_empty()
    {
        (
            "new-source-backed-observation-rationale-or-distinct-prediction-artifact".to_string(),
            "Current source-backed evidence is negative/non-significant after source-archive correction; unused eligible sources have no current archived scored-position markers. Next useful work requires a new or updated source-backed observation rationale before scoring, or a distinct preregistered prediction artifact.".to_string(),
        )
    } else if effective_all_source_backed_archives_negative {
        (
            "new-source-backed-observation-or-distinct-prediction-artifact".to_string(),
            "Current source-backed evidence is negative/non-significant after source-archive correction; do not add duplicate period lanes or rerun public-anchor-derived tests. Next useful work requires a new source-backed non-anchor observation or a distinct preregistered prediction artifact.".to_string(),
        )
    } else {
        (
            "inspect-non-negative-source-backed-archive".to_string(),
            "Inspect any non-negative source-backed archive manually, then preregister the narrowest follow-up before running more scoring.".to_string(),
        )
    };

    Ok(NextEvidenceGateReport {
        lane_directory: lane_report.directory,
        ready_lanes: lane_report.ready_for_source_backed_observations,
        invalid_lanes: lane_report.invalid_lanes,
        unique_ready_prediction_artifacts: lane_report.unique_ready_prediction_artifacts,
        duplicate_prediction_artifact_group_count: lane_report
            .duplicate_prediction_artifact_groups
            .len(),
        duplicate_prediction_artifact_groups: lane_report.duplicate_prediction_artifact_groups,
        evaluator_pending_lane_count: evaluator_pending_lanes.len(),
        evaluator_pending_lanes,
        eligible_source_ids,
        eligible_sources,
        ineligible_source_count: source_report.ineligible_count,
        quarantined_claim_source_ids,
        claim_verification_archive_count: claim_verification_archives.len(),
        claim_verification_archives,
        quarantined_claim_source_ids_without_archive,
        claim_verification_command: "cargo run --locked -- verify-plaintext-claim --input <local-claim.txt> --source-id <unverified-solution-claim-source-id> --format json\ncargo run --locked -- verify-running-key-claim --plaintext <local-claim.txt> --key <local-key-stream.txt> --source-id <unverified-solution-claim-source-id> --format json\ncargo run --locked -- verify-claim-reconciliation --input <local-claim-table.csv> --source-id <unverified-solution-claim-source-id> --format json\ncargo run --locked -- verify-claim-bundle --directory <local-claim-bundle-dir> --source-id <unverified-solution-claim-source-id> --format json\ncargo run --locked -- verify-claim-mechanism --directory <local-claim-bundle-dir> --source-id <unverified-solution-claim-source-id> --format json",
        valid_source_backed_archive_count: evidence_report.valid_source_backed_archive_count,
        invalid_archive_count: evidence_report.invalid_archive_count,
        all_source_backed_archives_negative,
        source_backed_archive_correction_count,
        min_source_backed_empirical_p_value,
        min_source_backed_adjusted_p_value,
        all_source_backed_archives_negative_after_correction,
        used_eligible_source_ids,
        unused_eligible_source_ids,
        unused_eligible_source_status,
        source_review_roots: source_review_report.roots,
        scanned_source_review_count: source_review_report.scanned_review_count,
        valid_source_review_count: source_review_report.valid_review_count,
        invalid_source_review_count: source_review_report.invalid_review_count,
        source_review_available: source_review_report.source_review_available,
        evidence_available: evidence_report.evidence_available,
        evidence_support_summary,
        evidence_support_details,
        next_action_kind,
        blocking_conditions,
        readiness_note: "Ready lane count is an operational inventory; use unique ready prediction artifacts and validated source-backed archives as the evidence counts.",
        recommended_next_step,
        next_check_commands: vec![
            "cargo run --locked -- source-frontier --format json",
            "cargo run --locked -- source-observation-status --format json",
            "cargo run --locked -- validate-source-archive --source-id <source-id> --input sources/archives/<source-id>-YYYY-MM-DD.md --format json",
            "cargo run --locked -- validate-prediction-artifact --preregistration <new-preregistration.json> --require-unique-artifact --format json",
            "cargo run --locked -- next-evidence-gate --format json",
        ],
        required_observation_fields: vec![
            "registered eligible source ID",
            "validated source-review file covering cited source IDs",
            "local source archive reference covering the observation file and scored positions",
            "one-based non-anchor K4 positions",
            "source-backed rationale",
            "one non-empty position_notes entry per scored position",
        ],
        source_review_status_command: "cargo run --locked -- source-review-status --format json",
        source_observation_status_command: "cargo run --locked -- source-observation-status --format json",
        source_review_scaffold_command: "cargo run --locked -- init-source-review --id <source-review-id> --source-id <eligible-source-id> --review-note \"<what source pages were reviewed before choosing positions>\" --output <source-review.json>",
        source_review_validation_command: "cargo run --locked -- validate-source-review --input <source-review.json> --format json",
        gates,
        promoted_candidate: false,
        note: "Next-evidence-gate output is an operational checklist for future source-backed observations; it is not a claimed solution.",
    })
}

fn claim_verification_archive_statuses(
    repo_root: &Path,
) -> Result<Vec<ClaimVerificationArchiveStatus>> {
    let dir = repo_root.join("results/claim-verifications");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut archives = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let result_path = path.join("result.json");
        if !result_path.exists() {
            continue;
        }
        let result_contents = fs::read_to_string(&result_path)
            .with_context(|| format!("failed to read `{}`", result_path.display()))?;
        let result_json: serde_json::Value = serde_json::from_str(&result_contents)
            .with_context(|| format!("failed to parse `{}`", result_path.display()))?;
        let directory = path
            .strip_prefix(repo_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let source_id = result_json
            .get("source_id")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
            .to_string();
        let structural_checks_passed = result_json
            .get("structural_checks_passed")
            .and_then(|value| value.as_bool());
        let promoted_candidate = result_json
            .get("promoted_candidate")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let status = match (promoted_candidate, structural_checks_passed) {
            (true, _) => "invalid-promoted-claim-archive",
            (false, Some(true)) => "quarantine-structural-check-passed",
            (false, Some(false)) => "quarantine-structural-check-failed",
            (false, None) => "quarantine-structural-check-not-reported",
        }
        .to_string();
        archives.push(ClaimVerificationArchiveStatus {
            directory,
            source_id,
            structural_checks_passed,
            promoted_candidate,
            status,
        });
    }
    archives.sort_by(|left, right| {
        left.source_id
            .cmp(&right.source_id)
            .then_with(|| left.directory.cmp(&right.directory))
    });
    Ok(archives)
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

fn eligible_source_use_status(source: &ObservationSourceEligibility) -> EligibleSourceUseStatus {
    let current_archive_has_scored_positions = source
        .archive_url
        .map(|archive_url| source_archive_has_scored_positions(Path::new(archive_url)))
        .unwrap_or(false);
    let non_scorable_reason = source
        .archive_url
        .and_then(|archive_url| source_archive_non_scorable_reason(Path::new(archive_url)));
    let status = if !source.locally_archived {
        "no local archive available; review/archive source before scoring".to_string()
    } else if current_archive_has_scored_positions {
        "local archive contains scored-position markers; source can support a concrete observation file".to_string()
    } else if let Some(reason) = &non_scorable_reason {
        format!(
            "local archive explicitly marks this source as non-scorable until new rationale is added: {reason}"
        )
    } else {
        "local archive is eligible context but has no current scored-position markers; do not score without a new observation rationale".to_string()
    };
    EligibleSourceUseStatus {
        source_id: source.id.to_string(),
        archive_url: source.archive_url.map(str::to_string),
        locally_archived: source.locally_archived,
        current_archive_has_scored_positions,
        non_scorable_reason,
        status,
    }
}

fn build_source_observation_status_report(
    directory: &Path,
) -> Result<SourceObservationStatusReport> {
    let gate_report = build_next_evidence_gate_report(directory)?;
    let reviewed_by_source_id = gate_report
        .source_review_roots
        .iter()
        .flat_map(|root| source_review_entries_in_root(Path::new(root)))
        .filter_map(|entry| validate_source_review_file(&entry).ok())
        .filter(|validation| validation.valid)
        .flat_map(|validation| {
            let review_id = validation
                .review_id
                .unwrap_or_else(|| "unavailable".to_string());
            validation
                .source_ids
                .into_iter()
                .map(move |source_id| (source_id, review_id.clone()))
        })
        .fold(
            BTreeMap::<String, BTreeSet<String>>::new(),
            |mut reviews, (source_id, review_id)| {
                reviews.entry(source_id).or_default().insert(review_id);
                reviews
            },
        );
    let evidence_report = independent_evidence_status_report(Vec::new())?;
    let all_source_backed_archives_negative = !evidence_report.archives.is_empty()
        && evidence_report
            .archives
            .iter()
            .filter(|archive| archive.valid && archive.source_backed_observation)
            .all(|archive| archive.support_status == "negative/non-significant");
    let archive_dirs_by_source_id = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .flat_map(|archive| {
            archive
                .observation_source_ids
                .iter()
                .cloned()
                .map(move |source_id| (source_id, archive.directory.clone()))
        })
        .fold(
            BTreeMap::<String, BTreeSet<String>>::new(),
            |mut archives, (source_id, directory)| {
                archives.entry(source_id).or_default().insert(directory);
                archives
            },
        );
    let archived_evidence_by_source_id = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .flat_map(|archive| {
            archive
                .observation_source_ids
                .iter()
                .cloned()
                .map(move |source_id| {
                    (
                        source_id,
                        SourceObservationArchivedEvidence {
                            directory: archive.directory.clone(),
                            artifact_kind: archive.artifact_kind.clone(),
                            best_model: archive.best_model.clone(),
                            observed_hits: archive.observed_hits.clone(),
                            null_mean_best_hits: archive.null_mean_best_hits,
                            empirical_p_value: archive.empirical_p_value,
                            support_status: archive.support_status.clone(),
                        },
                    )
                })
        })
        .fold(
            BTreeMap::<String, Vec<SourceObservationArchivedEvidence>>::new(),
            |mut summaries, (source_id, summary)| {
                summaries.entry(source_id).or_default().push(summary);
                summaries
            },
        );

    let statuses = gate_report
        .eligible_sources
        .iter()
        .map(|source| {
            let review_ids = reviewed_by_source_id
                .get(source.id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            let archive_dirs = archive_dirs_by_source_id
                .get(source.id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            let archived_evidence_summaries = archived_evidence_by_source_id
                .get(source.id)
                .cloned()
                .unwrap_or_default();
            let current_archive_has_scored_positions = source
                .archive_url
                .map(|archive_url| source_archive_has_scored_positions(Path::new(archive_url)))
                .unwrap_or(false);
            let non_scorable_reason = source
                .archive_url
                .and_then(|archive_url| source_archive_non_scorable_reason(Path::new(archive_url)));
            let action_status = if review_ids.is_empty() {
                "eligible but not covered by a valid source-review artifact; create and validate source review before observations".to_string()
            } else if archive_dirs.is_empty()
                && source.locally_archived
                && !current_archive_has_scored_positions
                && non_scorable_reason.is_some()
            {
                format!(
                    "eligible and reviewed, but local archive marks it non-scorable for now: {}",
                    non_scorable_reason.as_deref().unwrap_or("reason unavailable")
                )
            } else if archive_dirs.is_empty()
                && source.locally_archived
                && !current_archive_has_scored_positions
            {
                "eligible and reviewed, but current local archive has no scored-position markers; do not scaffold observations without a new source-backed rationale".to_string()
            } else if archive_dirs.is_empty() && current_archive_has_scored_positions {
                "eligible and has scored-position markers; create and validate a source-backed observation file before evaluation".to_string()
            } else if !archive_dirs.is_empty() {
                "already has source-backed evaluation archive; inspect archived support before follow-up".to_string()
            } else if !source.locally_archived {
                "eligible but not locally archived; archive and review before selecting positions".to_string()
            } else {
                "eligible source requires a validated source review and source-backed position rationale before scoring".to_string()
            };
            SourceObservationStatusEntry {
                source_id: source.id.to_string(),
                label: source.label.to_string(),
                archive_url: source.archive_url.map(str::to_string),
                locally_archived: source.locally_archived,
                reviewed_by_valid_source_review: !review_ids.is_empty(),
                review_ids,
                used_in_source_backed_archive: !archive_dirs.is_empty(),
                source_backed_archive_directories: archive_dirs,
                archived_evidence_summaries,
                current_archive_has_scored_positions,
                non_scorable_reason,
                action_status,
            }
        })
        .collect::<Vec<_>>();

    let reviewed_eligible_source_count = statuses
        .iter()
        .filter(|status| status.reviewed_by_valid_source_review)
        .count();
    let used_eligible_source_count = statuses
        .iter()
        .filter(|status| status.used_in_source_backed_archive)
        .count();
    let sources_with_scored_position_markers = statuses
        .iter()
        .filter(|status| status.current_archive_has_scored_positions)
        .count();
    let unused_eligible_source_count = statuses.len().saturating_sub(used_eligible_source_count);
    let unused_statuses = statuses
        .iter()
        .filter(|status| !status.used_in_source_backed_archive)
        .collect::<Vec<_>>();
    let all_unused_sources_are_non_scorable = !unused_statuses.is_empty()
        && unused_statuses.iter().all(|status| {
            !status.current_archive_has_scored_positions && status.non_scorable_reason.is_some()
        });
    let (next_action_kind, recommended_next_step) = if statuses.iter().any(|status| {
        !status.used_in_source_backed_archive && status.current_archive_has_scored_positions
    }) {
        (
            "score-unused-source-with-markers".to_string(),
            "At least one unused eligible source has archived scored-position markers; scaffold, validate, evaluate, and archive that observation before interpreting any signal.".to_string(),
        )
    } else if all_unused_sources_are_non_scorable {
        (
            "new-source-backed-rationale-new-source-or-distinct-prediction-artifact".to_string(),
            "Every unused eligible source is explicitly marked non-scorable in its local archive. Do not score these sources unless a new source-backed rationale changes the archive boundary; otherwise add a new eligible source or distinct preregistered prediction artifact.".to_string(),
        )
    } else if unused_eligible_source_count > 0 {
        (
            "new-source-backed-observation-rationale-required".to_string(),
            "Unused eligible sources lack scored-position markers. Do not score them until a new source-backed rationale selects one-based non-anchor positions with per-position notes.".to_string(),
        )
    } else {
        (
            "inspect-existing-source-backed-archives".to_string(),
            "All eligible sources already have source-backed archive coverage; inspect current archive support and preregister a distinct follow-up before more scoring.".to_string(),
        )
    };

    Ok(SourceObservationStatusReport {
        lane_directory: gate_report.lane_directory,
        eligible_source_count: statuses.len(),
        reviewed_eligible_source_count,
        used_eligible_source_count,
        unused_eligible_source_count,
        sources_with_scored_position_markers,
        valid_source_review_count: gate_report.valid_source_review_count,
        valid_source_backed_archive_count: gate_report.valid_source_backed_archive_count,
        all_source_backed_archives_negative,
        statuses,
        next_action_kind,
        recommended_next_step,
        promoted_candidate: false,
        note: "Source-observation status is a pre-score operational control; it is not a claimed solution.",
    })
}

fn source_archive_has_scored_positions(path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    contents.contains("scored_positions_one_based:")
}

fn source_archive_non_scorable_reason(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix("non_scorable_reason:")
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
            .map(str::to_string)
    })
}

fn evidence_gate_commands(
    hypothesis_family: &str,
    artifact: &str,
    preregistration: &str,
    grid_edge_axis: Option<&str>,
) -> Option<(String, String, String)> {
    match hypothesis_family {
        "position-spacing-prediction" => Some((
            format!(
                "cargo run --locked -- validate-spacing-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-spacing-prediction --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/spacing-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/spacing-observations/<observation-id> --format json".to_string(),
        )),
        "position-mirror-prediction" => Some((
            format!(
                "cargo run --locked -- validate-mirror-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-mirror-prediction --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/mirror-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/mirror-observations/<observation-id> --format json".to_string(),
        )),
        "position-grid-layout-prediction" => Some((
            format!(
                "cargo run --locked -- validate-grid-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-grid-prediction --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --edge-axis {} --iterations 100000 --seed 67 --output-dir results/grid-observations/<observation-id> --format json",
                grid_edge_axis.unwrap_or("row")
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/grid-observations/<observation-id> --format json".to_string(),
        )),
        "tableau-hill-prediction" => Some((
            format!(
                "cargo run --locked -- validate-tableau-hill-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-tableau-hill-prediction --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/tableau-hill-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/tableau-hill-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-only-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-prior-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            "cargo run --locked -- evaluate-ciphertext-prior --positions-file <source-backed-observations.json> --prior-iterations 100000 --prior-seed 67 --iterations 100000 --seed 67 --output-dir results/ciphertext-prior-observations/<observation-id> --format json".to_string(),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-prior-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-residue-balance-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-residue-balance-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-residue-balance --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-residue-balance-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-residue-balance-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-hotspot-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-hotspot-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-hotspot --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-hotspot-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-hotspot-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-rarity-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-rarity-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-rarity --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-rarity-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-rarity-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-repeat-distance-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-repeat-distance-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-repeat-distance --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-repeat-distance-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-repeat-distance-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-period-match-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-period-match-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-period-match --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-period-match-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-period-match-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-stehle-regularity-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-stehle-regularity-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-stehle-regularity --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-stehle-regularity-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-stehle-regularity-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-adjacent-contrast-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-adjacent-contrast-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-adjacent-contrast --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-adjacent-contrast-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-adjacent-contrast-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-transition-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-transition-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-transition --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-transition-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-transition-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-skip-transition-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-skip-transition-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-skip-transition --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-skip-transition-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-skip-transition-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-turning-point-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-turning-point-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-turning-point --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-turning-point-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-turning-point-observations/<observation-id> --format json".to_string(),
        )),
        "ciphertext-window-balance-position-prior" => Some((
            format!(
                "cargo run --locked -- validate-ciphertext-window-balance-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-ciphertext-window-balance --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/ciphertext-window-balance-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/ciphertext-window-balance-observations/<observation-id> --format json".to_string(),
        )),
        "position-period-prediction" => Some((
            format!(
                "cargo run --locked -- validate-period-observations --artifact {artifact} --preregistration {preregistration} --input <source-backed-observations.json> --format json"
            ),
            format!(
                "cargo run --locked -- evaluate-period-prediction --artifact {artifact} --preregistration {preregistration} --positions-file <source-backed-observations.json> --iterations 100000 --seed 67 --output-dir results/period-observations/<observation-id> --format json"
            ),
            "cargo run --locked -- validate-evaluation-archive --input results/period-observations/<observation-id> --format json".to_string(),
        )),
        _ => None,
    }
}

fn preregistered_grid_edge_axis_label(preregistration: &Path) -> Option<String> {
    let input = fs::read_to_string(preregistration).ok()?;
    let registration: LanePreregistration = serde_json::from_str(&input).ok()?;
    registration
        .grid_edge_axis
        .map(|axis| axis.label().to_string())
}

fn print_next_evidence_gate(directory: PathBuf, format: OutputFormat) -> Result<()> {
    let report = build_next_evidence_gate_report(&directory)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Next Evidence Gate\n");
            println!("This is not a claimed solution.\n");
            println!("lane directory: `{}`", report.lane_directory);
            println!("total ready lanes: {}", report.ready_lanes);
            println!(
                "unique ready prediction artifacts: {}",
                report.unique_ready_prediction_artifacts
            );
            println!(
                "duplicate prediction artifact groups: {}",
                report.duplicate_prediction_artifact_group_count
            );
            if !report.duplicate_prediction_artifact_groups.is_empty() {
                println!("duplicate prediction artifact details:");
                for group in &report.duplicate_prediction_artifact_groups {
                    println!(
                        "- lanes={} | artifacts={}",
                        group.lane_ids.join(", "),
                        group.artifact_paths.join(", ")
                    );
                }
            }
            println!(
                "evaluator-pending lanes: {}",
                report.evaluator_pending_lane_count
            );
            if !report.evaluator_pending_lanes.is_empty() {
                println!("evaluator-pending lane details:");
                for lane in &report.evaluator_pending_lanes {
                    println!(
                        "- {} | family={} | preregistration=`{}` | artifact=`{}` | next={}",
                        lane.id,
                        lane.hypothesis_family,
                        lane.preregistration,
                        lane.prediction_artifact.as_deref().unwrap_or("none"),
                        lane.next_step
                    );
                }
            }
            println!(
                "eligible scored-observation sources: {}",
                report.eligible_source_ids.join(", ")
            );
            println!("ineligible sources: {}", report.ineligible_source_count);
            println!(
                "quarantined plaintext-claim sources: {}",
                if report.quarantined_claim_source_ids.is_empty() {
                    "none".to_string()
                } else {
                    report.quarantined_claim_source_ids.join(", ")
                }
            );
            println!(
                "valid source-backed archives: {}",
                report.valid_source_backed_archive_count
            );
            println!("invalid archives: {}", report.invalid_archive_count);
            println!(
                "all source-backed archives negative: {}",
                report.all_source_backed_archives_negative
            );
            println!(
                "source-backed archive correction count: {}",
                report.source_backed_archive_correction_count
            );
            println!(
                "minimum source-backed p-value: {}",
                report
                    .min_source_backed_empirical_p_value
                    .map(|p| format!("{p:.4}"))
                    .unwrap_or_else(|| "n/a".to_string())
            );
            println!(
                "minimum source-backed adjusted p-value: {}",
                report
                    .min_source_backed_adjusted_p_value
                    .map(|p| format!("{p:.4}"))
                    .unwrap_or_else(|| "n/a".to_string())
            );
            println!(
                "all source-backed archives negative after correction: {}",
                report.all_source_backed_archives_negative_after_correction
            );
            println!(
                "used eligible sources: {}",
                if report.used_eligible_source_ids.is_empty() {
                    "none".to_string()
                } else {
                    report.used_eligible_source_ids.join(", ")
                }
            );
            println!(
                "unused eligible sources: {}",
                if report.unused_eligible_source_ids.is_empty() {
                    "none".to_string()
                } else {
                    report.unused_eligible_source_ids.join(", ")
                }
            );
            if !report.unused_eligible_source_status.is_empty() {
                println!("unused eligible source status:");
                for source in &report.unused_eligible_source_status {
                    let non_scorable_reason =
                        source.non_scorable_reason.as_deref().unwrap_or("none");
                    println!(
                        "- {} | archive={} | scored-position markers={} | non-scorable reason={} | {}",
                        source.source_id,
                        source.archive_url.as_deref().unwrap_or("none"),
                        source.current_archive_has_scored_positions,
                        non_scorable_reason,
                        source.status
                    );
                }
            }
            println!(
                "source-review roots: {}",
                report.source_review_roots.join(", ")
            );
            println!(
                "source reviews scanned: {}",
                report.scanned_source_review_count
            );
            println!("valid source reviews: {}", report.valid_source_review_count);
            println!(
                "invalid source reviews: {}",
                report.invalid_source_review_count
            );
            println!(
                "source review available: {}",
                report.source_review_available
            );
            println!("evidence available: {}", report.evidence_available);
            println!("promoted: {}", report.promoted_candidate);
            println!("next action kind: {}", report.next_action_kind);
            if !report.blocking_conditions.is_empty() {
                println!("blocking conditions:");
                for condition in &report.blocking_conditions {
                    println!("- {condition}");
                }
            }
            println!("readiness note: {}", report.readiness_note);
            println!("recommended next step: {}", report.recommended_next_step);
            println!("note: {}\n", report.note);
            println!("next check commands:");
            for command in &report.next_check_commands {
                println!("- `{command}`");
            }
            println!();
            if !report.evidence_support_summary.is_empty() {
                println!("evidence support summary:");
                for summary in &report.evidence_support_summary {
                    println!("- {summary}");
                }
                println!();
            }
            if !report.evidence_support_details.is_empty() {
                println!("evidence support details:");
                println!(
                    "| Directory | Source IDs | Kind | Best Model | Observed Hits | Null Mean | P | Adjusted P | Support |"
                );
                println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
                for detail in &report.evidence_support_details {
                    println!(
                        "| `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} |",
                        detail.directory,
                        detail.observation_source_ids.join("`, `"),
                        detail.artifact_kind,
                        detail.best_model.as_deref().unwrap_or("unknown model"),
                        detail.observed_hits.as_deref().unwrap_or("unknown hits"),
                        detail
                            .null_mean_best_hits
                            .map(|mean| format!("{mean:.2}"))
                            .unwrap_or_else(|| "n/a".to_string()),
                        detail
                            .empirical_p_value
                            .map(|p| format!("{p:.4}"))
                            .unwrap_or_else(|| "n/a".to_string()),
                        detail
                            .source_backed_adjusted_p_value
                            .map(|p| format!("{p:.4}"))
                            .unwrap_or_else(|| "n/a".to_string()),
                        detail.support_status
                    );
                }
                println!();
            }
            println!("required observation fields:");
            for field in &report.required_observation_fields {
                println!("- {field}");
            }
            println!(
                "\nsource review status:\n```bash\n{}\n```",
                report.source_review_status_command
            );
            println!(
                "source observation status:\n```bash\n{}\n```",
                report.source_observation_status_command
            );
            println!(
                "source review scaffold:\n```bash\n{}\n```",
                report.source_review_scaffold_command
            );
            println!(
                "source review validate:\n```bash\n{}\n```",
                report.source_review_validation_command
            );
            println!(
                "claim quarantine verifier:\n```bash\n{}\n```",
                report.claim_verification_command
            );
            println!(
                "claim verification archives: {}",
                report.claim_verification_archive_count
            );
            if !report
                .quarantined_claim_source_ids_without_archive
                .is_empty()
            {
                println!(
                    "quarantined claim sources without archive: {}",
                    report
                        .quarantined_claim_source_ids_without_archive
                        .join(", ")
                );
            }
            if !report.claim_verification_archives.is_empty() {
                println!("\n## Claim Verification Archives\n");
                println!("| Directory | Source ID | Structural Checks | Promoted | Status |");
                println!("| --- | --- | --- | --- | --- |");
                for archive in &report.claim_verification_archives {
                    println!(
                        "| `{}` | `{}` | {} | {} | {} |",
                        archive.directory,
                        archive.source_id,
                        archive
                            .structural_checks_passed
                            .map(|passed| passed.to_string())
                            .unwrap_or_else(|| "n/a".to_string()),
                        archive.promoted_candidate,
                        archive.status
                    );
                }
            }
            println!("\n## Eligible Source Details\n");
            println!("| Source ID | Local Archive | Accessed | Source Type | Use Boundary | URL |");
            println!("| --- | --- | --- | --- | --- | --- |");
            for source in &report.eligible_sources {
                let archive_status = if source.locally_archived { "yes" } else { "no" };
                println!(
                    "| `{}` | {} | {} | {} | {} | {} |",
                    source.id,
                    archive_status,
                    source.accessed_at,
                    source.source_type,
                    source.use_note,
                    source.url
                );
            }
            println!("\n## Gates\n");
            for gate in &report.gates {
                println!("### {}", gate.hypothesis_family);
                println!("family ready lanes: {}", gate.ready_lanes);
                println!(
                    "family unique ready artifacts: {}",
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

fn print_source_observation_status(directory: PathBuf, format: OutputFormat) -> Result<()> {
    let report = build_source_observation_status_report(&directory)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Source Observation Status\n");
            println!("This is not a claimed solution.\n");
            println!("lane directory: `{}`", report.lane_directory);
            println!("eligible sources: {}", report.eligible_source_count);
            println!(
                "reviewed eligible sources: {}",
                report.reviewed_eligible_source_count
            );
            println!(
                "used eligible sources: {}",
                report.used_eligible_source_count
            );
            println!(
                "unused eligible sources: {}",
                report.unused_eligible_source_count
            );
            println!(
                "sources with scored-position markers: {}",
                report.sources_with_scored_position_markers
            );
            println!("valid source reviews: {}", report.valid_source_review_count);
            println!(
                "valid source-backed archives: {}",
                report.valid_source_backed_archive_count
            );
            println!(
                "all source-backed archives negative: {}",
                report.all_source_backed_archives_negative
            );
            println!("promoted: {}", report.promoted_candidate);
            println!("next action kind: {}", report.next_action_kind);
            println!("recommended next step: {}", report.recommended_next_step);
            println!("note: {}\n", report.note);

            println!(
                "| Source ID | Reviewed | Used | Scored Markers | Non-Scorable Reason | Archive | Reviews | Evaluation Archives | Archived Evidence | Action |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for status in &report.statuses {
                let archive = status.archive_url.as_deref().unwrap_or("none");
                let reviews = if status.review_ids.is_empty() {
                    "none".to_string()
                } else {
                    status.review_ids.join("`, `")
                };
                let archives = if status.source_backed_archive_directories.is_empty() {
                    "none".to_string()
                } else {
                    status.source_backed_archive_directories.join("`, `")
                };
                let archived_evidence = if status.archived_evidence_summaries.is_empty() {
                    "none".to_string()
                } else {
                    status
                        .archived_evidence_summaries
                        .iter()
                        .map(|summary| {
                            format!(
                                "{} {} {} null_mean={} p={} {}",
                                summary.artifact_kind,
                                summary.best_model.as_deref().unwrap_or("model-unavailable"),
                                summary
                                    .observed_hits
                                    .as_deref()
                                    .unwrap_or("hits-unavailable"),
                                summary
                                    .null_mean_best_hits
                                    .map(|mean| format!("{mean:.2}"))
                                    .unwrap_or_else(|| "n/a".to_string()),
                                summary
                                    .empirical_p_value
                                    .map(|p| format!("{p:.4}"))
                                    .unwrap_or_else(|| "n/a".to_string()),
                                summary.support_status
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                };
                let non_scorable_reason = status.non_scorable_reason.as_deref().unwrap_or("none");
                println!(
                    "| `{}` | {} | {} | {} | {} | `{}` | `{}` | `{}` | {} | {} |",
                    status.source_id,
                    status.reviewed_by_valid_source_review,
                    status.used_in_source_backed_archive,
                    status.current_archive_has_scored_positions,
                    non_scorable_reason,
                    archive,
                    reviews,
                    archives,
                    archived_evidence,
                    status.action_status
                );
            }
        }
    }
    Ok(())
}

fn source_review_packet_report() -> SourceReviewPacketReport {
    let source_report = observation_source_eligibility_report();
    let eligible_sources = source_report
        .sources
        .into_iter()
        .filter(|source| source.eligible_for_scored_observations)
        .collect::<Vec<_>>();
    SourceReviewPacketReport {
        eligible_source_count: eligible_sources.len(),
        eligible_sources,
        required_review_steps: vec![
            "Review each eligible source URL before drafting observation positions.",
            "Confirm the local source archive can cover the future observation file and scored positions.",
            "Record source-backed rationale and one position note per scored one-based K4 position.",
            "Link the validated source-review artifact from the observation file.",
            "Do not use public-anchor summary, public-clue context, methodology context, or archive-context-only sources as scored evidence.",
            "Treat sources without local archives as review-required until an observation archive preserves the exact scored input.",
            "Run the family-specific observation validator before any evaluator command.",
        ],
        observation_requirements: vec![
            "registered eligible source ID",
            "validated source-review file covering cited source IDs",
            "local source archive reference covering the observation file and scored positions",
            "one-based non-anchor K4 positions",
            "source-backed rationale",
            "one non-empty position_notes entry per scored position",
            "archived evaluation output that validates with validate-evaluation-archive",
        ],
        source_observation_status_command: "cargo run --locked -- source-observation-status --format json",
        promoted_candidate: false,
        note: "Source-review packet is a pre-score audit aid for future source-backed observations; it is not a claimed solution.",
    }
}

fn print_source_review_packet(format: OutputFormat) -> Result<()> {
    let report = source_review_packet_report();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Source Review Packet\n");
            println!("This is not a claimed solution.\n");
            println!("eligible sources: {}", report.eligible_source_count);
            println!("promoted: {}", report.promoted_candidate);
            println!("note: {}\n", report.note);

            println!("## Eligible Sources\n");
            println!(
                "| Source ID | Label | Local Archive | Accessed | Allowed Use | Use Boundary | URL |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- |");
            for source in &report.eligible_sources {
                let archive_status = if source.locally_archived {
                    source.archive_url.unwrap_or("yes")
                } else {
                    "missing"
                };
                println!(
                    "| `{}` | {} | {} | {} | {} | {} | {} |",
                    source.id,
                    source.label,
                    archive_status,
                    source.accessed_at,
                    source.allowed_use,
                    source.use_note,
                    source.url
                );
            }

            println!("\n## Required Review Steps\n");
            for step in &report.required_review_steps {
                println!("- {step}");
            }

            println!("\n## Observation Requirements\n");
            for requirement in &report.observation_requirements {
                println!("- {requirement}");
            }

            println!(
                "\nsource observation status:\n```bash\n{}\n```",
                report.source_observation_status_command
            );
        }
    }
    Ok(())
}

fn source_intake_packet_report() -> SourceIntakePacketReport {
    SourceIntakePacketReport {
        registry_fields: vec![
            "id: stable lowercase source ID",
            "label: human-readable source label",
            "url: primary URL reviewed",
            "archive_url: quote-free local archive path under sources/archives",
            "accessed_at: ISO date the source was reviewed",
            "publication_date: source publication date when known",
            "source_type: primary, institutional-reporting, academic, major-reporting, community-reference, or claim class",
            "allowed_use: public-facts-only, public-anchor-summary, public-clue-context, methodology-context, archive-context-only, or unverified-solution-claim",
            "use_note: one-sentence boundary for what this source may support",
        ],
        allowed_use_boundaries: vec![
            "public-facts-only may become scored observation evidence only if the local archive records explicit non-anchor K4 positions or a position-selection rule",
            "public-anchor-summary and public-clue-context may document known clues but must not be used as independent scored evidence",
            "methodology-context and archive-context-only may justify preregistration rationale but must not supply scored observation positions",
            "unverified-solution-claim must stay quarantined and may only be used through local claim-verifier commands that do not print or store claimed plaintext",
        ],
        local_archive_requirements: vec![
            "source_id and source_url matching the registry entry",
            "reviewed_at date and archive_kind: quote-free local review snapshot",
            "promoted_candidate: false",
            "reviewed facts summarized without long quoted source text",
            "boundary section preserving no plaintext, key material, route, or candidate promotion",
            "either scored_positions_one_based for explicit non-anchor positions or non_scorable_reason for a reviewed but currently non-scoreable source",
            "never both scored_positions_one_based and non_scorable_reason in the same archive",
        ],
        scoreable_evidence_requirements: vec![
            "registered source with allowed_use public-facts-only",
            "local archive present and aligned with source registry metadata",
            "explicit scored_positions_one_based marker covering every future observation position",
            "validated source-review artifact before selecting observation positions",
            "source-backed rationale independent of public anchor-derived fragments",
            "one non-empty position note per one-based non-anchor K4 position",
            "family-specific observation validator, evaluator, and validate-evaluation-archive all pass",
        ],
        rejection_rules: vec![
            "do not score source pages that only restate public plaintext clues or anchors",
            "do not score methodology pages, context-only archive reports, or candidate search summaries as evidence",
            "do not score unverified solution claims or release-facing claimed plaintext",
            "do not add duplicate period lanes or rerun public-anchor-derived key material when the gate is asking for new evidence",
            "do not treat a source-review file as evidence; only validated observation archives can become evidence",
        ],
        followup_commands: vec![
            "cargo run --locked -- validate-source-archive --source-id <source-id> --input sources/archives/<source-id>-YYYY-MM-DD.md --format json",
            "cargo run --locked -- source-frontier --format json",
            "cargo run --locked -- source-observation-status --format json",
            "cargo run --locked -- init-source-review --id <source-review-id> --source-id <eligible-source-id> --review-note \"<what source pages were reviewed before choosing positions>\" --output <source-review.json>",
            "cargo run --locked -- validate-source-review --input <source-review.json> --format json",
            "cargo run --locked -- init-position-observations --id <observation-id> --source-id <eligible-source-id> --source-review <source-review.json> --positions <comma-separated-non-anchor-positions> --rationale \"<source-backed rationale>\" --position-note \"<position>=<source-backed note>\" --output <source-backed-observations.json>",
            "cargo run --locked -- next-evidence-gate --format json",
        ],
        archive_template: "# Source Snapshot\n\nsource_id: `<source-id>`\nsource_url: <source-url>\nreviewed_at: YYYY-MM-DD\narchive_kind: quote-free local review snapshot\npromoted_candidate: false\n\n## Reviewed Facts\n\n- Summarize only the fact needed for source-use classification.\n- Use `scored_positions_one_based: 1,2,3` only when explicit non-anchor positions or a source-backed selection rule exists.\n\n## Boundary\n\n- No candidate material, key stream, route, claimed plaintext, or solution is promoted.\n- If no scored positions are available, record `non_scorable_reason: <reason>` near the metadata instead of scoring this source.",
        promoted_candidate: false,
        note: "Source-intake packet defines the gate for adding new evidence sources; it is not a claimed solution.",
    }
}

fn print_source_intake_packet(format: OutputFormat) -> Result<()> {
    let report = source_intake_packet_report();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Source Intake Packet\n");
            println!("This is not a claimed solution.\n");
            println!("promoted: {}", report.promoted_candidate);
            println!("note: {}\n", report.note);

            println!("## Registry Fields\n");
            for field in &report.registry_fields {
                println!("- {field}");
            }

            println!("\n## Allowed-Use Boundaries\n");
            for boundary in &report.allowed_use_boundaries {
                println!("- {boundary}");
            }

            println!("\n## Local Archive Requirements\n");
            for requirement in &report.local_archive_requirements {
                println!("- {requirement}");
            }

            println!("\n## Scoreable Evidence Requirements\n");
            for requirement in &report.scoreable_evidence_requirements {
                println!("- {requirement}");
            }

            println!("\n## Rejection Rules\n");
            for rule in &report.rejection_rules {
                println!("- {rule}");
            }

            println!("\n## Follow-Up Commands\n");
            println!("```bash");
            for command in &report.followup_commands {
                println!("{command}");
            }
            println!("```");

            println!("\n## Archive Template\n");
            println!("```markdown\n{}\n```", report.archive_template);
        }
    }
    Ok(())
}

fn print_init_source_review(options: InitSourceReviewOptions) -> Result<()> {
    let InitSourceReviewOptions {
        id,
        source_ids,
        review_note,
        output,
        force,
        format,
    } = options;
    let report = create_source_review_file(id, source_ids, review_note, output, force)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => print_source_review_scaffold_report(&report),
    }
    Ok(())
}

fn print_validate_source_review(input: PathBuf, format: OutputFormat) -> Result<()> {
    let validation = validate_source_review_file(&input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_source_review_validation(&validation),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("source-review file failed validation")
    }
}

fn print_source_review_validation(validation: &SourceReviewValidation) {
    println!("# Source Review Validation\n");
    println!("This is not a claimed solution.\n");
    println!("input: `{}`", validation.input_path);
    match &validation.review_id {
        Some(id) => println!("review id: `{id}`"),
        None => println!("review id: unavailable"),
    }
    println!("source ids: {}", validation.source_ids.join(", "));
    println!("reviewed sources: {}", validation.reviewed_source_count);
    println!(
        "local archives missing: {}",
        validation.missing_local_archive_count
    );
    println!("valid: {}", validation.valid);
    println!("promoted: {}", validation.promoted_candidate);
    println!("note: {}\n", validation.note);

    println!("## Errors\n");
    if validation.errors.is_empty() {
        println!("none\n");
    } else {
        for error in &validation.errors {
            println!("- {error}");
        }
        println!();
    }

    println!("## Warnings\n");
    if validation.warnings.is_empty() {
        println!("none");
    } else {
        for warning in &validation.warnings {
            println!("- {warning}");
        }
    }
}

fn source_review_status_report(mut roots: Vec<PathBuf>) -> Result<SourceReviewStatusReport> {
    if roots.is_empty() {
        roots = vec![PathBuf::from("experiments/source-reviews")];
    }

    let mut reviews = Vec::new();
    let mut missing_root_count = 0;
    for root in &roots {
        if root.is_file() {
            reviews.push(summarize_source_review(root));
            continue;
        }
        let Ok(entries) = fs::read_dir(root) else {
            missing_root_count += 1;
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json")
            {
                reviews.push(summarize_source_review(&path));
            }
        }
    }
    reviews.sort_by(|left, right| left.path.cmp(&right.path));

    let valid_review_count = reviews.iter().filter(|review| review.valid).count();
    let invalid_review_count = reviews.iter().filter(|review| !review.valid).count();

    Ok(SourceReviewStatusReport {
        roots: roots
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        scanned_review_count: reviews.len(),
        valid_review_count,
        invalid_review_count,
        missing_root_count,
        source_review_available: valid_review_count > 0,
        reviews,
        promoted_candidate: false,
        note: "Source-review status scans pre-score source-review artifacts; it is not a claimed solution.",
    })
}

fn source_review_entries_in_root(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json")
        })
        .collect()
}

fn summarize_source_review(path: &Path) -> SourceReviewStatusEntry {
    match validate_source_review_file(path) {
        Ok(validation) => SourceReviewStatusEntry {
            path: validation.input_path,
            review_id: validation.review_id,
            source_ids: validation.source_ids,
            reviewed_source_count: validation.reviewed_source_count,
            missing_local_archive_count: validation.missing_local_archive_count,
            valid: validation.valid,
            errors: validation.errors,
            warnings: validation.warnings,
        },
        Err(error) => SourceReviewStatusEntry {
            path: path.display().to_string(),
            review_id: None,
            source_ids: Vec::new(),
            reviewed_source_count: 0,
            missing_local_archive_count: 0,
            valid: false,
            errors: vec![error.to_string()],
            warnings: Vec::new(),
        },
    }
}

fn print_validate_source_archive(
    source_id: String,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_source_archive_file(&source_id, &input);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_source_archive_validation(&validation),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("source archive failed validation")
    }
}

fn validate_source_archive_file(source_id: &str, input: &Path) -> SourceArchiveValidation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let source = sources().into_iter().find(|source| source.id == source_id);
    let source_url = source.as_ref().map(|source| source.url.to_string());
    let allowed_use = source.as_ref().map(|source| source.allowed_use.to_string());
    let contents = match fs::read_to_string(input) {
        Ok(contents) => contents,
        Err(error) => {
            return SourceArchiveValidation {
                input_path: input.display().to_string(),
                source_id: source_id.to_string(),
                source_url,
                allowed_use,
                archive_has_scored_positions: false,
                non_scorable_reason: None,
                valid: false,
                errors: vec![format!("failed to read archive: {error}")],
                warnings,
                promoted_candidate: false,
                note: "Source-archive validation checks quote-free local source snapshots before registry or evidence use; it is not a claimed solution.",
            };
        }
    };

    if let Some(source) = &source {
        validate_source_archive_contents(source, input, &contents, &mut errors);
    } else {
        errors.push(format!("source ID `{source_id}` is not registered"));
    }

    let archive_has_scored_positions = contents.contains("scored_positions_one_based:");
    let non_scorable_reason = contents
        .lines()
        .find_map(|line| line.strip_prefix("non_scorable_reason:"))
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(str::to_string);

    if !archive_has_scored_positions && non_scorable_reason.is_none() {
        warnings.push(
            "archive has neither scored_positions_one_based nor a non_scorable_reason; it cannot support scored observations yet"
                .to_string(),
        );
    }

    SourceArchiveValidation {
        input_path: input.display().to_string(),
        source_id: source_id.to_string(),
        source_url,
        allowed_use,
        archive_has_scored_positions,
        non_scorable_reason,
        valid: errors.is_empty(),
        errors,
        warnings,
        promoted_candidate: false,
        note: "Source-archive validation checks quote-free local source snapshots before registry or evidence use; it is not a claimed solution.",
    }
}

fn validate_source_archive_contents(
    source: &kryptos_k4::Source,
    path: &Path,
    contents: &str,
    errors: &mut Vec<String>,
) {
    let required_markers = [
        format!("source_id: `{}`", source.id),
        format!("source_url: {}", source.url),
        "reviewed_at:".to_string(),
        "archive_kind: quote-free local review snapshot".to_string(),
        "promoted_candidate: false".to_string(),
        "## Reviewed Facts".to_string(),
        "## Boundary".to_string(),
        "No candidate material, key stream, route, or plaintext is promoted.".to_string(),
    ];
    for marker in required_markers {
        if !contents.contains(&marker) {
            errors.push(format!("{}:missing `{marker}`", path.display()));
        }
    }
    if contents.contains("K4_FULL_PLAINTEXT")
        || contents.contains("K4_LEAKED_PLAINTEXT")
        || contents.contains("claimed solution")
    {
        errors.push(format!(
            "{}:contains forbidden solution/plaintext marker",
            path.display()
        ));
    }
    if source.allowed_use != "public-facts-only" && contents.contains("scored_positions_one_based:")
    {
        errors.push(format!(
            "{}:scored_positions_one_based is only allowed for public-facts-only sources; `{}` is `{}`",
            path.display(),
            source.id,
            source.allowed_use
        ));
    }
    let non_scorable_reason = contents
        .lines()
        .find_map(|line| line.strip_prefix("non_scorable_reason:"))
        .map(str::trim);
    if let Some(reason) = non_scorable_reason {
        if reason.is_empty() {
            errors.push(format!(
                "{}:non_scorable_reason marker must include a reason",
                path.display()
            ));
        }
        if contents.contains("scored_positions_one_based:") {
            errors.push(format!(
                "{}:non_scorable_reason cannot coexist with scored_positions_one_based",
                path.display()
            ));
        }
    }
}

fn print_source_archive_validation(validation: &SourceArchiveValidation) {
    println!("# Source Archive Validation\n");
    println!("This is not a claimed solution.\n");
    println!("input: `{}`", validation.input_path);
    println!("source id: `{}`", validation.source_id);
    if let Some(source_url) = &validation.source_url {
        println!("source url: {source_url}");
    }
    if let Some(allowed_use) = &validation.allowed_use {
        println!("allowed use: {allowed_use}");
    }
    println!(
        "scored positions marker: {}",
        validation.archive_has_scored_positions
    );
    println!(
        "non-scorable reason: {}",
        validation.non_scorable_reason.as_deref().unwrap_or("none")
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
    println!("\n## Warnings\n");
    if validation.warnings.is_empty() {
        println!("none");
    } else {
        for warning in &validation.warnings {
            println!("- {warning}");
        }
    }
}

fn print_source_review_status(roots: Vec<PathBuf>, format: OutputFormat) -> Result<()> {
    let report = source_review_status_report(roots)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Source Review Status\n");
            println!("This is not a claimed solution.\n");
            println!("roots: {}", report.roots.join(", "));
            println!("reviews scanned: {}", report.scanned_review_count);
            println!("valid reviews: {}", report.valid_review_count);
            println!("invalid reviews: {}", report.invalid_review_count);
            println!("missing roots: {}", report.missing_root_count);
            println!(
                "source review available: {}",
                report.source_review_available
            );
            println!("promoted: {}", report.promoted_candidate);
            println!("note: {}\n", report.note);

            if report.reviews.is_empty() {
                println!("No pre-score source-review artifacts were found.");
            } else {
                println!(
                    "| Path | Review ID | Source IDs | Reviewed Sources | Missing Local Archives | Valid | Errors | Warnings |"
                );
                println!("| --- | --- | --- | --- | --- | --- | --- | --- |");
                for review in &report.reviews {
                    let review_id = review.review_id.as_deref().unwrap_or("unavailable");
                    println!(
                        "| `{}` | `{}` | `{}` | {} | {} | {} | {} | {} |",
                        review.path,
                        review_id,
                        review.source_ids.join("`, `"),
                        review.reviewed_source_count,
                        review.missing_local_archive_count,
                        review.valid,
                        review.errors.join("; "),
                        review.warnings.join("; ")
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_source_review_scaffold_report(report: &SourceReviewScaffoldReport) {
    println!("# Source Review File\n");
    println!("This is not a claimed solution.\n");
    println!("output: `{}`", report.output_path);
    println!("review id: `{}`", report.review.id);
    println!("source ids: {}", report.review.source_ids.join(", "));
    let missing_archives = report
        .review
        .sources
        .iter()
        .filter(|source| !source.locally_archived)
        .count();
    println!("local archives missing: {missing_archives}");
    println!("valid: {}", report.valid);
    println!("promoted: {}", report.promoted_candidate);
    println!("note: {}\n", report.note);

    println!("## Reviewed Sources\n");
    println!("| Source ID | Local Archive | Accessed | Allowed Use | URL |");
    println!("| --- | --- | --- | --- | --- |");
    for source in &report.review.sources {
        let archive_status = if source.locally_archived {
            source.archive_url.unwrap_or("yes")
        } else {
            "missing"
        };
        println!(
            "| `{}` | {} | {} | {} | {} |",
            source.id, archive_status, source.accessed_at, source.allowed_use, source.url
        );
    }

    println!("\n## Review Note\n");
    println!("{}\n", report.review.review_note);

    println!("## Next Gates\n");
    println!(
        "- Use `init-position-observations` only after selecting source-backed non-anchor positions from reviewed sources."
    );
    println!(
        "- Run the family-specific observation validator and `validate-evaluation-archive` before interpreting any score."
    );
}

fn independent_evidence_status_report(
    mut roots: Vec<PathBuf>,
) -> Result<IndependentEvidenceStatusReport> {
    if roots.is_empty() {
        roots = vec![
            PathBuf::from("results/period-observations"),
            PathBuf::from("results/spacing-observations"),
            PathBuf::from("results/mirror-observations"),
            PathBuf::from("results/grid-observations"),
            PathBuf::from("results/tableau-hill-observations"),
            PathBuf::from("results/ciphertext-prior-observations"),
            PathBuf::from("results/ciphertext-hotspot-observations"),
            PathBuf::from("results/ciphertext-rarity-observations"),
            PathBuf::from("results/ciphertext-repeat-distance-observations"),
            PathBuf::from("results/ciphertext-period-match-observations"),
            PathBuf::from("results/ciphertext-adjacent-contrast-observations"),
            PathBuf::from("results/ciphertext-transition-observations"),
            PathBuf::from("results/ciphertext-skip-transition-observations"),
            PathBuf::from("results/ciphertext-turning-point-observations"),
            PathBuf::from("results/ciphertext-window-balance-observations"),
            PathBuf::from("results/ciphertext-stehle-regularity-observations"),
            PathBuf::from("results/ciphertext-residue-balance-observations"),
        ];
    }

    let mut archives = Vec::new();
    for root in &roots {
        if is_evaluation_archive_directory(root) {
            archives.push(summarize_evaluation_archive(root));
            continue;
        }
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && is_evaluation_archive_directory(&path) {
                archives.push(summarize_evaluation_archive(&path));
            }
        }
    }
    archives.sort_by(|left, right| left.directory.cmp(&right.directory));

    let valid_source_backed_archive_count = archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .count();
    let valid_diagnostic_archive_count = archives
        .iter()
        .filter(|archive| archive.valid && !archive.source_backed_observation)
        .count();
    let invalid_archive_count = archives.iter().filter(|archive| !archive.valid).count();

    Ok(IndependentEvidenceStatusReport {
        roots: roots
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        scanned_archive_count: archives.len(),
        valid_source_backed_archive_count,
        valid_diagnostic_archive_count,
        invalid_archive_count,
        evidence_available: valid_source_backed_archive_count > 0,
        archives,
        promoted_candidate: false,
        note: "Independent evidence status scans archived source-backed observation evaluations; it is not a claimed solution.",
    })
}

fn is_evaluation_archive_directory(path: &Path) -> bool {
    path.join("artifact.json").is_file()
        || path.join("result.json").is_file()
        || path.join("command.txt").is_file()
}

fn summarize_evaluation_archive(path: &Path) -> IndependentEvidenceArchiveSummary {
    match validate_evaluation_archive(path) {
        Ok(validation) => {
            let score_summary = read_evaluation_archive_score_summary(
                path,
                &validation.artifact_kind,
                validation.valid,
            );
            IndependentEvidenceArchiveSummary {
                directory: validation.directory,
                artifact_kind: validation.artifact_kind,
                source_backed_observation: validation.source_backed_observation,
                observation_source_ids: read_archive_observation_source_ids(path),
                valid: validation.valid,
                best_model: score_summary.best_model,
                observed_hits: score_summary.observed_hits,
                null_mean_best_hits: score_summary.null_mean_best_hits,
                empirical_p_value: score_summary.empirical_p_value,
                support_status: score_summary.support_status,
                errors: validation.errors,
                warnings: validation.warnings,
            }
        }
        Err(error) => IndependentEvidenceArchiveSummary {
            directory: path.display().to_string(),
            artifact_kind: "unknown".to_string(),
            source_backed_observation: false,
            observation_source_ids: Vec::new(),
            valid: false,
            best_model: None,
            observed_hits: None,
            null_mean_best_hits: None,
            empirical_p_value: None,
            support_status: "invalid".to_string(),
            errors: vec![error.to_string()],
            warnings: Vec::new(),
        },
    }
}

fn read_archive_observation_source_ids(path: &Path) -> Vec<String> {
    let Ok(contents) = fs::read_to_string(path.join("observations.json")) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return Vec::new();
    };
    value
        .get("source_ids")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter(|source_id| !source_id.trim().is_empty())
        .map(|source_id| source_id.trim().to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

struct EvidenceArchiveScoreSummary {
    best_model: Option<String>,
    observed_hits: Option<String>,
    null_mean_best_hits: Option<f64>,
    empirical_p_value: Option<f64>,
    support_status: String,
}

fn read_evaluation_archive_score_summary(
    path: &Path,
    artifact_kind: &str,
    valid: bool,
) -> EvidenceArchiveScoreSummary {
    if !valid {
        return EvidenceArchiveScoreSummary {
            best_model: None,
            observed_hits: None,
            null_mean_best_hits: None,
            empirical_p_value: None,
            support_status: "invalid".to_string(),
        };
    }

    let Ok(contents) = fs::read_to_string(path.join("result.json")) else {
        return EvidenceArchiveScoreSummary {
            best_model: None,
            observed_hits: None,
            null_mean_best_hits: None,
            empirical_p_value: None,
            support_status: "score-unavailable".to_string(),
        };
    };
    let Ok(result) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return EvidenceArchiveScoreSummary {
            best_model: None,
            observed_hits: None,
            null_mean_best_hits: None,
            empirical_p_value: None,
            support_status: "score-unavailable".to_string(),
        };
    };

    let best_hits = result
        .get("best_hits")
        .or_else(|| result.get("hotspot_hits"))
        .or_else(|| result.get("rare_hits"))
        .or_else(|| result.get("repeat_distance_hits"))
        .or_else(|| result.get("contrast_hits"))
        .or_else(|| result.get("transition_hits"))
        .or_else(|| result.get("skip_transition_hits"))
        .or_else(|| result.get("turning_point_hits"))
        .or_else(|| result.get("window_balance_hits"))
        .or_else(|| result.get("regularity_hits"))
        .or_else(|| result.get("mirror_pair_hits"))
        .or_else(|| result.get("edge_hits"))
        .or_else(|| result.get("row_edge_hits"))
        .and_then(serde_json::Value::as_u64);
    let null_mean_best_hits = result
        .get("null_mean_best_hits")
        .or_else(|| result.get("null_mean_hotspot_hits"))
        .or_else(|| result.get("null_mean_rare_hits"))
        .or_else(|| result.get("null_mean_repeat_distance_hits"))
        .or_else(|| result.get("null_mean_contrast_hits"))
        .or_else(|| result.get("null_mean_transition_hits"))
        .or_else(|| result.get("null_mean_skip_transition_hits"))
        .or_else(|| result.get("null_mean_turning_point_hits"))
        .or_else(|| result.get("null_mean_window_balance_hits"))
        .or_else(|| result.get("null_mean_regularity_hits"))
        .or_else(|| result.get("null_mean_mirror_pair_hits"))
        .or_else(|| result.get("null_mean_edge_hits"))
        .or_else(|| result.get("null_mean_row_edge_hits"))
        .and_then(serde_json::Value::as_f64);
    let empirical_p_value = result
        .get("empirical_p_value")
        .or_else(|| result.get("regularity_empirical_p_value"))
        .and_then(serde_json::Value::as_f64);
    let support_status = empirical_p_value
        .map(|p| {
            if p <= 0.05 {
                "follow-up-required"
            } else {
                "negative/non-significant"
            }
        })
        .unwrap_or("score-unavailable")
        .to_string();

    let (best_model, observed_hits) = match artifact_kind {
        "period" => {
            let best_period = result
                .get("best_period")
                .and_then(serde_json::Value::as_u64);
            let best_residue = result
                .get("best_residue")
                .and_then(serde_json::Value::as_u64);
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                best_period
                    .zip(best_residue)
                    .map(|(period, residue)| format!("period {period} residue {residue}")),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "spacing" => {
            let best_modulus = result
                .get("best_modulus")
                .and_then(serde_json::Value::as_u64);
            let best_residue = result
                .get("best_residue")
                .and_then(serde_json::Value::as_u64);
            let observed_pair_count = result
                .get("observed_pair_count")
                .and_then(serde_json::Value::as_u64);
            (
                best_modulus
                    .zip(best_residue)
                    .map(|(modulus, residue)| format!("modulus {modulus} residue {residue}")),
                best_hits
                    .zip(observed_pair_count)
                    .map(|(hits, total)| format!("{hits}/{total} pairs")),
            )
        }
        "mirror" => {
            let possible_observed_mirror_pairs = result
                .get("possible_observed_mirror_pairs")
                .and_then(serde_json::Value::as_u64);
            (
                Some("mirror pairs".to_string()),
                best_hits
                    .zip(possible_observed_mirror_pairs)
                    .map(|(hits, total)| format!("{hits}/{total} pairs")),
            )
        }
        "grid" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            let edge_axis = result
                .get("edge_axis")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("row");
            (
                Some(if edge_axis == "compass-axis" {
                    "7x14 compass-axis positions".to_string()
                } else {
                    format!("7x14 {edge_axis} edges")
                }),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "tableau-hill" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            let best_axis = result
                .get("best_axis")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("axis");
            let best_index = result
                .get("best_index_one_based")
                .and_then(serde_json::Value::as_u64);
            (
                best_index.map(|index| format!("7x14 {best_axis} {index} concentration")),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-prior" => {
            let best_period = result
                .get("best_period")
                .and_then(serde_json::Value::as_u64);
            let best_residue = result
                .get("best_residue")
                .and_then(serde_json::Value::as_u64);
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                best_period.zip(best_residue).map(|(period, residue)| {
                    format!("ciphertext prior period {period} residue {residue}")
                }),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-residue-balance" => {
            let best_modulus = result
                .get("best_modulus")
                .and_then(serde_json::Value::as_u64);
            let best_residue = result
                .get("best_residue")
                .and_then(serde_json::Value::as_u64);
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                best_modulus.zip(best_residue).map(|(modulus, residue)| {
                    format!("ciphertext residue-balance modulus {modulus} residue {residue}")
                }),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-hotspot" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext hotspot positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-rarity" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext rare-letter positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-repeat-distance" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext repeat-distance positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-period-match" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            let best_period = result
                .get("best_period")
                .and_then(serde_json::Value::as_u64);
            (
                best_period.map(|period| {
                    format!("ciphertext shifted same-letter period {period} endpoints")
                }),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-adjacent-contrast" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext adjacent-contrast positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-transition" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext transition-pressure positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-skip-transition" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext skip-transition positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-turning-point" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext turning-point positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-window-balance" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext window-balance positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        "ciphertext-stehle-regularity" => {
            let observed_position_count = result
                .get("observed_position_count")
                .and_then(serde_json::Value::as_u64);
            (
                Some("ciphertext Stehle-window positions".to_string()),
                best_hits
                    .zip(observed_position_count)
                    .map(|(hits, total)| format!("{hits}/{total} positions")),
            )
        }
        _ => (None, None),
    };

    EvidenceArchiveScoreSummary {
        best_model,
        observed_hits,
        null_mean_best_hits,
        empirical_p_value,
        support_status,
    }
}

fn print_independent_evidence_status(roots: Vec<PathBuf>, format: OutputFormat) -> Result<()> {
    let report = independent_evidence_status_report(roots)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Independent Evidence Status\n");
            println!("This is not a claimed solution.\n");
            println!("roots: {}", report.roots.join(", "));
            println!("archives scanned: {}", report.scanned_archive_count);
            println!(
                "valid source-backed archives: {}",
                report.valid_source_backed_archive_count
            );
            println!(
                "valid diagnostic archives: {}",
                report.valid_diagnostic_archive_count
            );
            println!("invalid archives: {}", report.invalid_archive_count);
            println!("evidence available: {}", report.evidence_available);
            println!("promoted: {}", report.promoted_candidate);
            println!("note: {}\n", report.note);
            if report.archives.is_empty() {
                println!(
                    "No archived source-backed independent observation evaluations were found."
                );
            } else {
                println!(
                    "| Directory | Kind | Sources | Source-Backed | Valid | Best Model | Hits | P | Status | Errors | Warnings |"
                );
                println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
                for archive in &report.archives {
                    println!(
                        "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                        archive.directory,
                        archive.artifact_kind,
                        archive.observation_source_ids.join(", "),
                        archive.source_backed_observation,
                        archive.valid,
                        archive.best_model.as_deref().unwrap_or(""),
                        archive.observed_hits.as_deref().unwrap_or(""),
                        archive
                            .empirical_p_value
                            .map(|p| format!("{p:.4}"))
                            .unwrap_or_default(),
                        archive.support_status,
                        archive.errors.join("; "),
                        archive.warnings.join("; ")
                    );
                }
            }
        }
    }
    Ok(())
}

fn non_anchor_position_report() -> NonAnchorPositionReport {
    let anchors = known_anchors();
    let mut anchor_positions = BTreeSet::new();
    let excluded_anchor_ranges = anchors
        .iter()
        .map(|anchor| {
            let positions_one_based =
                (anchor.start_one_based()..=anchor.end_one_based_inclusive()).collect::<Vec<_>>();
            for position in &positions_one_based {
                anchor_positions.insert(*position);
            }
            ExcludedAnchorRange {
                label: anchor.plaintext,
                start_one_based: anchor.start_one_based(),
                end_one_based_inclusive: anchor.end_one_based_inclusive(),
                positions_one_based,
                source_ids: anchor.source_ids.to_vec(),
            }
        })
        .collect::<Vec<_>>();
    let non_anchor_positions_one_based = (1..=K4_CIPHERTEXT.len())
        .filter(|position| !anchor_positions.contains(position))
        .collect::<Vec<_>>();

    NonAnchorPositionReport {
        ciphertext_length: K4_CIPHERTEXT.len(),
        non_anchor_position_count: non_anchor_positions_one_based.len(),
        anchor_position_count: anchor_positions.len(),
        non_anchor_positions_one_based,
        excluded_anchor_ranges,
        promoted_candidate: false,
        note: "Non-anchor-position output is a setup aid for future source-backed observations; it is not a claimed solution.",
    }
}

fn print_non_anchor_positions(format: OutputFormat) -> Result<()> {
    let report = non_anchor_position_report();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            println!("# Non-Anchor K4 Positions\n");
            println!("This is not a claimed solution.\n");
            println!("ciphertext length: {}", report.ciphertext_length);
            println!("non-anchor positions: {}", report.non_anchor_position_count);
            println!(
                "excluded anchor positions: {}",
                report.anchor_position_count
            );
            println!("promoted: {}", report.promoted_candidate);
            println!("note: {}\n", report.note);
            println!(
                "positions: {}\n",
                report
                    .non_anchor_positions_one_based
                    .iter()
                    .map(|position| position.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!("## Excluded Public Anchors\n");
            println!("| Label | Range | Positions | Sources |");
            println!("| --- | --- | --- | --- |");
            for anchor in &report.excluded_anchor_ranges {
                println!(
                    "| {} | {}-{} | {} | {} |",
                    anchor.label,
                    anchor.start_one_based,
                    anchor.end_one_based_inclusive,
                    anchor
                        .positions_one_based
                        .iter()
                        .map(|position| position.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    anchor.source_ids.join(",")
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
    println!(
        "duplicate artifact lanes: {}",
        report.duplicate_prediction_artifact_lane_count
    );
    println!(
        "extra duplicate artifact lanes: {}",
        report.duplicate_prediction_artifact_extra_lane_count
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
    let format = options.format;
    let report = create_position_observation_file(options)?;
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

fn print_validate_mirror_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_mirror_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => {
            print_position_observation_validation("Mirror Observation Validation", &validation)
        }
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("mirror observations failed validation")
    }
}

fn print_validate_grid_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_grid_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => {
            print_position_observation_validation("Grid Observation Validation", &validation)
        }
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("grid observations failed validation")
    }
}

fn print_validate_tableau_hill_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation =
        validate_tableau_hill_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Tableau/HILL Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("tableau/HILL observations failed validation")
    }
}

fn print_validate_ciphertext_prior_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation =
        validate_ciphertext_prior_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Prior Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-prior observations failed validation")
    }
}

fn print_validate_ciphertext_hotspot_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation =
        validate_ciphertext_hotspot_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Hotspot Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-hotspot observations failed validation")
    }
}

fn print_validate_ciphertext_residue_balance_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_residue_balance_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Residue-Balance Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-residue-balance observations failed validation")
    }
}

fn print_validate_ciphertext_rarity_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation =
        validate_ciphertext_rarity_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Rarity Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-rarity observations failed validation")
    }
}

fn print_validate_ciphertext_adjacent_contrast_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_adjacent_contrast_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Adjacent-Contrast Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-adjacent-contrast observations failed validation")
    }
}

fn print_validate_ciphertext_transition_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation =
        validate_ciphertext_transition_observations(&artifact, preregistration.as_deref(), &input)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Transition Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-transition observations failed validation")
    }
}

fn print_validate_ciphertext_skip_transition_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_skip_transition_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Skip-Transition Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-skip-transition observations failed validation")
    }
}

fn print_validate_ciphertext_turning_point_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_turning_point_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Turning-Point Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-turning-point observations failed validation")
    }
}

fn print_validate_ciphertext_window_balance_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_window_balance_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Window-Balance Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-window-balance observations failed validation")
    }
}

fn print_validate_ciphertext_repeat_distance_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_repeat_distance_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Repeat-Distance Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-repeat-distance observations failed validation")
    }
}

fn print_validate_ciphertext_period_match_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_period_match_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Period-Match Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-period-match observations failed validation")
    }
}

fn print_validate_ciphertext_stehle_regularity_observations(
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    input: PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let validation = validate_ciphertext_stehle_regularity_observations(
        &artifact,
        preregistration.as_deref(),
        &input,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&validation)?),
        OutputFormat::Markdown => print_position_observation_validation(
            "Ciphertext Stehle-Regularity Observation Validation",
            &validation,
        ),
    }
    if validation.valid {
        Ok(())
    } else {
        anyhow::bail!("ciphertext-stehle-regularity observations failed validation")
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
        observation_source_review_file: observations.source_review_file,
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

fn validate_ciphertext_prior_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-prior" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-prior artifact",
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

    let non_anchor_positions = load_ciphertext_prior_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-prior artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-prior observation validation checks source-backed non-anchor positions against the ciphertext-only committed prior before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_hotspot_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-hotspot" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-hotspot artifact",
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

    let non_anchor_positions = load_ciphertext_hotspot_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-hotspot artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-hotspot observation validation checks source-backed non-anchor positions against the ciphertext-only hotspot artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_residue_balance_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-residue-balance" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-residue-balance artifact",
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

    let non_anchor_positions = load_ciphertext_residue_balance_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-residue-balance artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-residue-balance observation validation checks source-backed non-anchor positions against the ciphertext-only residue-balance artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_rarity_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-rarity" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-rarity artifact",
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

    let non_anchor_positions = load_ciphertext_rarity_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-rarity artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-rarity observation validation checks source-backed non-anchor positions against the ciphertext-only rarity artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_adjacent_contrast_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-adjacent-contrast" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-adjacent-contrast artifact",
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

    let non_anchor_positions = load_ciphertext_adjacent_contrast_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-adjacent-contrast artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-adjacent-contrast observation validation checks source-backed non-anchor positions against the ciphertext-only adjacent-contrast artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_transition_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-transition" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-transition artifact",
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

    let non_anchor_positions = load_ciphertext_transition_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-transition artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-transition observation validation checks source-backed non-anchor positions against the ciphertext-only transition artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_skip_transition_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-skip-transition" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-skip-transition artifact",
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

    let non_anchor_positions = load_ciphertext_skip_transition_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-skip-transition artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-skip-transition observation validation checks source-backed non-anchor positions against the ciphertext-only skip-transition artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_turning_point_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-turning-point" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-turning-point artifact",
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

    let non_anchor_positions = load_ciphertext_turning_point_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-turning-point artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-turning-point observation validation checks source-backed non-anchor positions against the ciphertext-only turning-point artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_window_balance_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-window-balance" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-window-balance artifact",
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

    let non_anchor_positions = load_ciphertext_window_balance_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-window-balance artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-window-balance observation validation checks source-backed non-anchor positions against the ciphertext-only window-balance artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_repeat_distance_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-repeat-distance" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-repeat-distance artifact",
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

    let non_anchor_positions = load_ciphertext_repeat_distance_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-repeat-distance artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-repeat-distance observation validation checks source-backed non-anchor positions against the ciphertext-only repeat-distance artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_period_match_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-period-match" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-period-match artifact",
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

    let non_anchor_positions = load_ciphertext_period_match_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-period-match artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-period-match observation validation checks source-backed non-anchor positions against the ciphertext-only shifted same-letter period-match artifact before scoring; it is not a claimed solution.",
    })
}

fn validate_ciphertext_stehle_regularity_observations(
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
        if artifact_validation.artifact_kind != "ciphertext-stehle-regularity" {
            errors.push(format!(
                "preregistration `{}` does not declare a ciphertext-stehle-regularity artifact",
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

    let non_anchor_positions = load_ciphertext_stehle_regularity_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the ciphertext-stehle-regularity artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Ciphertext-Stehle-regularity observation validation checks source-backed non-anchor positions against the committed source-described local-regularity artifact before scoring; it is not a claimed solution.",
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
        observation_source_review_file: observations.source_review_file,
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

fn validate_mirror_observations(
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
            "mirror observation files must include at least two one-based K4 positions".to_string(),
        );
    }

    if let Some(preregistration_path) = preregistration_path {
        let artifact_validation = validate_prediction_artifact(preregistration_path)?;
        preregistration_id = Some(artifact_validation.preregistration_id.clone());
        artifact_valid = Some(artifact_validation.valid);
        if artifact_validation.artifact_kind != "mirror" {
            errors.push(format!(
                "preregistration `{}` does not declare a mirror prediction artifact",
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

    let non_anchor_positions = load_mirror_prediction_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the mirror prediction artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Mirror observation validation checks source-backed non-anchor positions before mirror-pair scoring; it is not a claimed solution.",
    })
}

fn validate_grid_observations(
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
        if artifact_validation.artifact_kind != "grid" {
            errors.push(format!(
                "preregistration `{}` does not declare a grid-layout prediction artifact",
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

    let non_anchor_positions = load_grid_prediction_artifact_positions(artifact_path)?;

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !non_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not in the grid-layout prediction artifact non-anchor universe"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Grid observation validation checks source-backed non-anchor positions before 7-by-14 edge-axis scoring; it is not a claimed solution.",
    })
}

fn validate_tableau_hill_observations(
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
        if artifact_validation.artifact_kind != "tableau-hill" {
            errors.push(format!(
                "preregistration `{}` does not declare a Tableau/HILL source-mapping artifact",
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

    let (mapped_positions, public_anchor_positions, padding_cell_count) =
        load_tableau_hill_prediction_artifact_positions(artifact_path)?;
    if padding_cell_count == 0 {
        errors.push(
            "tableau/HILL artifact has no explicit padding cell; source-map boundary is incomplete"
                .to_string(),
        );
    }

    let mut seen = HashSet::new();
    for position in &observations.positions_one_based {
        if !seen.insert(*position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if !mapped_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is not covered by the Tableau/HILL source-mapping artifact"
            ));
        }
        if public_anchor_positions.contains(position) {
            errors.push(format!(
                "position `{position}` is a public-anchor position and cannot be used as Tableau/HILL independent observation evidence"
            ));
        }
    }

    Ok(PeriodPredictionObservationValidation {
        artifact_path: artifact_path.display().to_string(),
        preregistration_id,
        artifact_valid,
        observation_id,
        observation_source_ids: observations.source_ids,
        observation_source_review_file: observations.source_review_file,
        observation_rationale: observations.rationale,
        observed_position_count: observations.positions_one_based.len(),
        observed_positions_one_based: observations.positions_one_based,
        observation_position_notes: observations.position_notes,
        valid: errors.is_empty(),
        errors,
        promoted_candidate: false,
        note: "Tableau/HILL observation validation checks source-backed positions against the fixed source map and rejects padding/public-anchor observations; it is not a score or claimed solution.",
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
    if let Some(source_review_file) = &validation.observation_source_review_file {
        println!("source review file: `{source_review_file}`");
    }
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

fn print_mirror_prediction_plan(format: OutputFormat) -> Result<()> {
    let plan = build_mirror_prediction_plan()?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plan)?),
        OutputFormat::Markdown => print_mirror_prediction_plan_markdown(&plan),
    }
    Ok(())
}

fn print_mirror_prediction_plan_markdown(plan: &MirrorPredictionPlanSet) {
    println!("# Mirror Prediction Plan\n");
    println!("This is not a claimed solution.\n");
    println!("mirror pairs: {}", plan.pair_count);
    println!("center position: {}", plan.center_position_one_based);
    println!("non-anchor positions: {}", plan.non_anchor_position_count);
    println!(
        "public-anchor positions excluded: {}",
        plan.anchor_position_count
    );
    println!("promoted: {}", plan.promoted_candidate);
    println!("source inputs: {}", plan.source_inputs);
    println!("prediction rule: {}", plan.prediction_rule);
    println!("note: {}\n", plan.note);
    println!("| Left | Right | Distance From Center |");
    println!("| --- | --- | --- |");
    for pair in &plan.plans {
        println!(
            "| {} | {} | {} |",
            pair.left_position_one_based, pair.right_position_one_based, pair.distance_from_center
        );
    }
}

fn print_grid_layout_prediction_plan(
    edge_axis: GridLayoutEdgeAxis,
    format: OutputFormat,
) -> Result<()> {
    let plan = build_grid_layout_prediction_plan_for_axis(edge_axis)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plan)?),
        OutputFormat::Markdown => print_grid_layout_prediction_plan_markdown(&plan),
    }
    Ok(())
}

fn print_grid_layout_prediction_plan_markdown(plan: &GridLayoutPredictionPlan) {
    println!("# Grid Layout Prediction Plan\n");
    println!("This is not a claimed solution.\n");
    println!(
        "grid: {} rows x {} columns",
        plan.row_count, plan.column_count
    );
    println!("padded positions: {}", plan.padded_position_count);
    println!(
        "pad positions: {}",
        plan.pad_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("non-anchor positions: {}", plan.non_anchor_position_count);
    println!(
        "public-anchor positions excluded: {}",
        plan.anchor_position_count
    );
    println!("scored edge axis: {}", plan.scored_edge_axis.label());
    println!(
        "row-edge positions: {}",
        plan.row_edge_positions_one_based.len()
    );
    println!(
        "column-edge positions: {}",
        plan.column_edge_positions_one_based.len()
    );
    println!("promoted: {}", plan.promoted_candidate);
    println!("source inputs: {}", plan.source_inputs);
    println!("prediction rule: {}", plan.prediction_rule);
    println!("note: {}\n", plan.note);
    println!("| Row | Start | End | Row-Edge Positions | Non-Anchor Positions |");
    println!("| --- | --- | --- | --- | --- |");
    for row in &plan.rows {
        let edges = row
            .row_edge_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let positions = row
            .non_anchor_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "| {} | {} | {} | {} | {} |",
            row.row_one_based,
            row.start_position_one_based,
            row.end_position_one_based,
            edges,
            positions
        );
    }
    println!("\n| Column | Top | Bottom | Column-Edge Positions | Non-Anchor Positions |");
    println!("| --- | --- | --- | --- | --- |");
    for column in &plan.columns {
        let edges = column
            .column_edge_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let positions = column
            .non_anchor_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "| {} | {} | {} | {} | {} |",
            column.column_one_based,
            column.top_position_one_based,
            column.bottom_position_one_based,
            edges,
            positions
        );
    }
}

fn print_tableau_hill_prediction_plan(format: OutputFormat) -> Result<()> {
    let plan = build_tableau_hill_prediction_plan();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plan)?),
        OutputFormat::Markdown => print_tableau_hill_prediction_plan_markdown(&plan),
    }
    Ok(())
}

fn print_tableau_hill_prediction_plan_markdown(plan: &TableauHillPredictionPlan) {
    println!("# Tableau/HILL Prediction Plan\n");
    println!("This is not a claimed solution.\n");
    println!("hypothesis family: {}", plan.hypothesis_family);
    println!("artifact kind: {}", plan.artifact_kind);
    println!("evaluator status: {}", plan.evaluator_status);
    println!("source ids: {}", plan.source_ids.join(", "));
    println!("mapping status: {}", plan.mapping_status);
    println!(
        "tableau dimensions: {} rows x {} columns ({} cells)",
        plan.row_count, plan.column_count, plan.cell_count
    );
    println!("K4 positions mapped: {}", plan.k4_position_count);
    println!(
        "padding cells: {}; padding cell index: {}",
        plan.padding_cell_count, plan.padding_cell_index_one_based
    );
    println!(
        "public-anchor fragments used for discovery: {}",
        plan.public_anchor_fragments_used_for_discovery
    );
    println!(
        "public-anchor fragments used as primary evidence: {}",
        plan.public_anchor_fragments_used_as_primary_evidence
    );
    println!(
        "candidate material allowed: {}",
        plan.candidate_material_allowed
    );
    println!(
        "requires preregistration before scoring: {}",
        plan.required_preregistration_before_scoring
    );
    println!("promoted: {}", plan.promoted_candidate);
    println!("source inputs: {}", plan.source_inputs);
    println!("note: {}\n", plan.note);

    println!("## Fixed Source-Backed Rules\n");
    for rule in &plan.source_backed_fixed_rules {
        println!("- {rule}");
    }
    println!();

    println!("## Fixed Questions\n");
    println!("| ID | Question | Fixed Before Scoring |");
    println!("| --- | --- | --- |");
    for question in &plan.fixed_questions {
        println!(
            "| {} | {} | {} |",
            question.id, question.question, question.fixed_before_scoring
        );
    }

    println!("\n## Required Next Steps\n");
    for step in &plan.required_next_steps {
        println!("- {step}");
    }
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

struct MirrorPredictionEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct GridPredictionEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    edge_axis: CliGridEdgeAxis,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct TableauHillPredictionEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextHotspotEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextRarityEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextAdjacentContrastEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextTransitionEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextSkipTransitionEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextTurningPointEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextWindowBalanceEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextRepeatDistanceEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextPeriodMatchEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextStehleRegularityEvaluationOptions {
    artifact: PathBuf,
    preregistration: Option<PathBuf>,
    positions: Option<String>,
    positions_file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct CiphertextResidueBalanceEvaluationOptions {
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
            source_review_file: None,
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
    evaluation.observation_source_review_file = observation_input.source_review_file;
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
            source_review_file: None,
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
    evaluation.observation_source_review_file = observation_input.source_review_file;
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

fn print_evaluate_mirror_prediction(options: MirrorPredictionEvaluationOptions) -> Result<()> {
    let MirrorPredictionEvaluationOptions {
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
        if artifact_validation.artifact_kind != "mirror" {
            anyhow::bail!(
                "preregistration `{}` does not declare a mirror prediction artifact",
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
            "--positions-file requires --preregistration so the committed mirror prediction artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_mirror_prediction_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_mirror_prediction_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_mirror_prediction_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_grid_prediction(options: GridPredictionEvaluationOptions) -> Result<()> {
    let GridPredictionEvaluationOptions {
        artifact,
        preregistration,
        positions,
        positions_file,
        edge_axis,
        output_dir,
        iterations,
        seed,
        format,
    } = options;
    let has_preregistration = preregistration.is_some();
    let selected_edge_axis: GridLayoutEdgeAxis = edge_axis.into();
    if let Some(preregistration) = &preregistration {
        let artifact_validation = validate_prediction_artifact(preregistration)?;
        if artifact_validation.artifact_kind != "grid" {
            anyhow::bail!(
                "preregistration `{}` does not declare a grid-layout prediction artifact",
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
        let preregistration_input = fs::read_to_string(preregistration)?;
        let registration: LanePreregistration = serde_json::from_str(&preregistration_input)?;
        if let Some(registered_edge_axis) = registration.grid_edge_axis
            && registered_edge_axis != selected_edge_axis
        {
            anyhow::bail!(
                "edge-axis `{}` does not match preregistered grid_edge_axis `{}`; use a matching preregistration or keep this as diagnostic --positions output",
                selected_edge_axis.label(),
                registered_edge_axis.label()
            );
        }
    }
    if positions_file.is_some() && !has_preregistration {
        anyhow::bail!(
            "--positions-file requires --preregistration so the committed grid-layout prediction artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_grid_layout_prediction_positions_with_axis(
        artifact.clone(),
        observation_input.positions_one_based,
        selected_edge_axis,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_grid_prediction_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_grid_prediction_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_tableau_hill_prediction(
    options: TableauHillPredictionEvaluationOptions,
) -> Result<()> {
    let TableauHillPredictionEvaluationOptions {
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
        if artifact_validation.artifact_kind != "tableau-hill" {
            anyhow::bail!(
                "preregistration `{}` does not declare a Tableau/HILL source-mapping artifact",
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
            "--positions-file requires --preregistration so the committed Tableau/HILL source-mapping artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => {
            let validation =
                validate_tableau_hill_observations(&artifact, preregistration.as_deref(), &path)?;
            if !validation.valid {
                anyhow::bail!("tableau/HILL observations failed validation");
            }
            load_period_prediction_observations(&path)?
        }
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_tableau_hill_prediction_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_tableau_hill_prediction_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_tableau_hill_prediction_evaluation(&evaluation),
    }
    Ok(())
}

fn print_period_prediction_evaluation(evaluation: &PeriodPredictionEvaluation) {
    print!("{}", render_period_prediction_evaluation(evaluation));
}

#[allow(clippy::too_many_arguments)]
fn print_evaluate_ciphertext_prior(
    positions_file: PathBuf,
    max_period: usize,
    max_ngram: usize,
    prior_iterations: usize,
    prior_seed: u64,
    iterations: usize,
    seed: u64,
    output_dir: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let observation_input = load_period_prediction_observations(&positions_file)?;
    let mut evaluation = evaluate_ciphertext_structure_prior_positions(
        max_period,
        max_ngram,
        prior_iterations,
        prior_seed,
        observation_input.positions_one_based,
        iterations,
        seed,
    );
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    evaluation.source_backed_observation = !evaluation.observation_source_ids.is_empty();

    if let Some(output_dir) = output_dir {
        write_ciphertext_prior_evaluation_outputs(
            &output_dir,
            &positions_file,
            &evaluation,
            max_period,
            max_ngram,
            prior_iterations,
            prior_seed,
        )?;
    }

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_prior_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_hotspot(options: CiphertextHotspotEvaluationOptions) -> Result<()> {
    let CiphertextHotspotEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-hotspot" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-hotspot artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-hotspot artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_hotspot_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_hotspot_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_hotspot_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_residue_balance(
    options: CiphertextResidueBalanceEvaluationOptions,
) -> Result<()> {
    let CiphertextResidueBalanceEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-residue-balance" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-residue-balance artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-residue-balance artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_residue_balance_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_residue_balance_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_residue_balance_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_rarity(options: CiphertextRarityEvaluationOptions) -> Result<()> {
    let CiphertextRarityEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-rarity" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-rarity artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-rarity artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_rarity_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_rarity_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_rarity_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_adjacent_contrast(
    options: CiphertextAdjacentContrastEvaluationOptions,
) -> Result<()> {
    let CiphertextAdjacentContrastEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-adjacent-contrast" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-adjacent-contrast artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-adjacent-contrast artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_adjacent_contrast_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_adjacent_contrast_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_adjacent_contrast_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_transition(
    options: CiphertextTransitionEvaluationOptions,
) -> Result<()> {
    let CiphertextTransitionEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-transition" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-transition artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-transition artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_transition_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_transition_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_transition_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_skip_transition(
    options: CiphertextSkipTransitionEvaluationOptions,
) -> Result<()> {
    let CiphertextSkipTransitionEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-skip-transition" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-skip-transition artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-skip-transition artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_skip_transition_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_skip_transition_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_skip_transition_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_turning_point(
    options: CiphertextTurningPointEvaluationOptions,
) -> Result<()> {
    let CiphertextTurningPointEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-turning-point" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-turning-point artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-turning-point artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_turning_point_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_turning_point_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_turning_point_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_window_balance(
    options: CiphertextWindowBalanceEvaluationOptions,
) -> Result<()> {
    let CiphertextWindowBalanceEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-window-balance" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-window-balance artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-window-balance artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_window_balance_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_window_balance_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_window_balance_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_repeat_distance(
    options: CiphertextRepeatDistanceEvaluationOptions,
) -> Result<()> {
    let CiphertextRepeatDistanceEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-repeat-distance" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-repeat-distance artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-repeat-distance artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_repeat_distance_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_repeat_distance_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_repeat_distance_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_period_match(
    options: CiphertextPeriodMatchEvaluationOptions,
) -> Result<()> {
    let CiphertextPeriodMatchEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-period-match" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-period-match artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-period-match artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_period_match_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_period_match_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_period_match_evaluation(&evaluation),
    }
    Ok(())
}

fn print_evaluate_ciphertext_stehle_regularity(
    options: CiphertextStehleRegularityEvaluationOptions,
) -> Result<()> {
    let CiphertextStehleRegularityEvaluationOptions {
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
        if artifact_validation.artifact_kind != "ciphertext-stehle-regularity" {
            anyhow::bail!(
                "preregistration `{}` does not declare a ciphertext-stehle-regularity artifact",
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
            "--positions-file requires --preregistration so the committed ciphertext-stehle-regularity artifact is validated before scoring source-backed observations"
        );
    }

    let archive =
        evaluation_archive_context(&artifact, &preregistration, &positions, &positions_file);
    let observation_input = match (positions, positions_file) {
        (Some(positions), None) => PeriodPredictionObservationInput {
            id: None,
            source_ids: Vec::new(),
            source_review_file: None,
            rationale: None,
            positions_one_based: parse_position_list(&positions).map_err(anyhow::Error::msg)?,
            position_notes: BTreeMap::new(),
        },
        (None, Some(path)) => load_period_prediction_observations(&path)?,
        _ => anyhow::bail!("provide exactly one of --positions or --positions-file"),
    };
    let mut evaluation = evaluate_ciphertext_stehle_regularity_positions(
        artifact.clone(),
        observation_input.positions_one_based,
        iterations,
        seed,
    )?;
    evaluation.observation_id = observation_input.id;
    evaluation.observation_source_ids = observation_input.source_ids;
    evaluation.observation_source_review_file = observation_input.source_review_file;
    evaluation.observation_rationale = observation_input.rationale;
    evaluation.observation_position_notes = observation_input.position_notes;
    if !evaluation.observation_source_ids.is_empty() {
        evaluation.source_backed_observation = true;
        evaluation.observation_warning = None;
    }
    if let Some(output_dir) = output_dir {
        write_ciphertext_stehle_regularity_evaluation_outputs(&output_dir, &evaluation, &archive)?;
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&evaluation)?),
        OutputFormat::Markdown => print_ciphertext_stehle_regularity_evaluation(&evaluation),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_ciphertext_prior_evaluation_outputs(
    output_dir: &Path,
    positions_file: &Path,
    evaluation: &CiphertextPriorEvaluation,
    max_period: usize,
    max_ngram: usize,
    prior_iterations: usize,
    prior_seed: u64,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    fs::copy(positions_file, output_dir.join("observations.json"))?;
    copy_observation_source_review_to_archive(positions_file, output_dir)?;
    fs::write(
        output_dir.join("result.json"),
        serde_json::to_string_pretty(evaluation)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_ciphertext_prior_evaluation(evaluation),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        format!(
            "evaluate-ciphertext-prior --positions-file observations.json --max-period {max_period} --max-ngram {max_ngram} --prior-iterations {prior_iterations} --prior-seed {prior_seed} --iterations {} --seed {}\n",
            evaluation.iterations, evaluation.seed
        ),
    )?;
    Ok(())
}

fn print_ciphertext_prior_evaluation(evaluation: &CiphertextPriorEvaluation) {
    print!("{}", render_ciphertext_prior_evaluation(evaluation));
}

fn print_ciphertext_hotspot_evaluation(evaluation: &CiphertextHotspotEvaluation) {
    print!("{}", render_ciphertext_hotspot_evaluation(evaluation));
}

fn print_ciphertext_rarity_evaluation(evaluation: &CiphertextRarityEvaluation) {
    print!("{}", render_ciphertext_rarity_evaluation(evaluation));
}

fn print_ciphertext_adjacent_contrast_evaluation(
    evaluation: &CiphertextAdjacentContrastEvaluation,
) {
    print!(
        "{}",
        render_ciphertext_adjacent_contrast_evaluation(evaluation)
    );
}

fn print_ciphertext_transition_evaluation(evaluation: &CiphertextTransitionEvaluation) {
    print!("{}", render_ciphertext_transition_evaluation(evaluation));
}

fn print_ciphertext_skip_transition_evaluation(evaluation: &CiphertextSkipTransitionEvaluation) {
    print!(
        "{}",
        render_ciphertext_skip_transition_evaluation(evaluation)
    );
}

fn print_ciphertext_turning_point_evaluation(evaluation: &CiphertextTurningPointEvaluation) {
    print!("{}", render_ciphertext_turning_point_evaluation(evaluation));
}

fn print_ciphertext_window_balance_evaluation(evaluation: &CiphertextWindowBalanceEvaluation) {
    print!(
        "{}",
        render_ciphertext_window_balance_evaluation(evaluation)
    );
}

fn print_ciphertext_repeat_distance_evaluation(evaluation: &CiphertextRepeatDistanceEvaluation) {
    print!(
        "{}",
        render_ciphertext_repeat_distance_evaluation(evaluation)
    );
}

fn print_ciphertext_residue_balance_evaluation(evaluation: &CiphertextResidueBalanceEvaluation) {
    print!(
        "{}",
        render_ciphertext_residue_balance_evaluation(evaluation)
    );
}

fn render_ciphertext_residue_balance_evaluation(
    evaluation: &CiphertextResidueBalanceEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Residue-Balance Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "best residue-balance set: modulus {} residue {}; hits {}/{} ({:.4})\n",
        evaluation.best_modulus,
        evaluation.best_residue,
        evaluation.best_hits,
        evaluation.observed_position_count,
        evaluation.best_hit_rate
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_best_hits,
        evaluation.null_std_dev_best_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_hotspot_evaluation(evaluation: &CiphertextHotspotEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Hotspot Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "hotspot hits: {}/{} ({:.4})\n",
        evaluation.hotspot_hits, evaluation.observed_position_count, evaluation.hotspot_hit_rate
    ));
    output.push_str(&format!(
        "matching hotspot positions: {}\n",
        evaluation
            .matching_hotspot_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-hotspot positions: {}\n",
        evaluation
            .non_hotspot_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_hotspot_hits,
        evaluation.null_std_dev_hotspot_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_rarity_evaluation(evaluation: &CiphertextRarityEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Rarity Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "rare-position hits: {}/{} ({:.4})\n",
        evaluation.rare_hits, evaluation.observed_position_count, evaluation.rare_hit_rate
    ));
    output.push_str(&format!(
        "matching rare positions: {}\n",
        evaluation
            .matching_rare_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-rare positions: {}\n",
        evaluation
            .non_rare_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_rare_hits,
        evaluation.null_std_dev_rare_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_transition_evaluation(evaluation: &CiphertextTransitionEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Transition Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "transition-position hits: {}/{} ({:.4})\n",
        evaluation.transition_hits,
        evaluation.observed_position_count,
        evaluation.transition_hit_rate
    ));
    output.push_str(&format!(
        "matching transition positions: {}\n",
        evaluation
            .matching_transition_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-transition positions: {}\n",
        evaluation
            .non_transition_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_transition_hits,
        evaluation.null_std_dev_transition_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_adjacent_contrast_evaluation(
    evaluation: &CiphertextAdjacentContrastEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Adjacent-Contrast Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "adjacent-contrast-position hits: {}/{} ({:.4})\n",
        evaluation.contrast_hits, evaluation.observed_position_count, evaluation.contrast_hit_rate
    ));
    output.push_str(&format!(
        "matching adjacent-contrast positions: {}\n",
        evaluation
            .matching_contrast_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-adjacent-contrast positions: {}\n",
        evaluation
            .non_contrast_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_contrast_hits,
        evaluation.null_std_dev_contrast_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_skip_transition_evaluation(
    evaluation: &CiphertextSkipTransitionEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Skip-Transition Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "skip-transition-position hits: {}/{} ({:.4})\n",
        evaluation.skip_transition_hits,
        evaluation.observed_position_count,
        evaluation.skip_transition_hit_rate
    ));
    output.push_str(&format!(
        "matching skip-transition positions: {}\n",
        evaluation
            .matching_skip_transition_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-skip-transition positions: {}\n",
        evaluation
            .non_skip_transition_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_skip_transition_hits,
        evaluation.null_std_dev_skip_transition_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_turning_point_evaluation(
    evaluation: &CiphertextTurningPointEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Turning-Point Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "turning-point-position hits: {}/{} ({:.4})\n",
        evaluation.turning_point_hits,
        evaluation.observed_position_count,
        evaluation.turning_point_hit_rate
    ));
    output.push_str(&format!(
        "matching turning-point positions: {}\n",
        evaluation
            .matching_turning_point_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-turning-point positions: {}\n",
        evaluation
            .non_turning_point_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_turning_point_hits,
        evaluation.null_std_dev_turning_point_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_window_balance_evaluation(
    evaluation: &CiphertextWindowBalanceEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Window-Balance Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "window-balance-position hits: {}/{} ({:.4})\n",
        evaluation.window_balance_hits,
        evaluation.observed_position_count,
        evaluation.window_balance_hit_rate
    ));
    output.push_str(&format!(
        "matching window-balance positions: {}\n",
        evaluation
            .matching_window_balance_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-window-balance positions: {}\n",
        evaluation
            .non_window_balance_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_window_balance_hits,
        evaluation.null_std_dev_window_balance_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_repeat_distance_evaluation(
    evaluation: &CiphertextRepeatDistanceEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Repeat-Distance Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "repeat-distance-position hits: {}/{} ({:.4})\n",
        evaluation.repeat_distance_hits,
        evaluation.observed_position_count,
        evaluation.repeat_distance_hit_rate
    ));
    output.push_str(&format!(
        "matching repeat-distance positions: {}\n",
        evaluation
            .matching_repeat_distance_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-repeat-distance positions: {}\n",
        evaluation
            .non_repeat_distance_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_repeat_distance_hits,
        evaluation.null_std_dev_repeat_distance_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn print_ciphertext_period_match_evaluation(evaluation: &CiphertextPeriodMatchEvaluation) {
    print!("{}", render_ciphertext_period_match_evaluation(evaluation));
}

fn render_ciphertext_period_match_evaluation(
    evaluation: &CiphertextPeriodMatchEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Period-Match Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "best period-match set: period {}; hits {}/{} ({:.4})\n",
        evaluation.best_period,
        evaluation.best_hits,
        evaluation.observed_position_count,
        evaluation.best_hit_rate
    ));
    output.push_str("\n| Period | Hits | Hit Rate | Matching Positions |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for result in &evaluation.period_match_results {
        output.push_str(&format!(
            "| {} | {} | {:.4} | {} |\n",
            result.period,
            result.hits,
            result.hit_rate,
            result
                .matching_positions_one_based
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    output.push_str(&format!(
        "\nnull: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_best_hits,
        evaluation.null_std_dev_best_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn print_ciphertext_stehle_regularity_evaluation(
    evaluation: &CiphertextStehleRegularityEvaluation,
) {
    print!(
        "{}",
        render_ciphertext_stehle_regularity_evaluation(evaluation)
    );
}

fn render_ciphertext_stehle_regularity_evaluation(
    evaluation: &CiphertextStehleRegularityEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Stehle-Regularity Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    if let Some(warning) = evaluation.observation_warning {
        output.push_str(&format!("warning: {warning}\n"));
    }
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "Stehle-window hits: {}/{} ({:.4})\n",
        evaluation.regularity_hits,
        evaluation.observed_position_count,
        evaluation.regularity_hit_rate
    ));
    output.push_str(&format!(
        "matching Stehle-window positions: {}\n",
        evaluation
            .matching_regularity_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "non-Stehle-window positions: {}\n",
        evaluation
            .non_regularity_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "lag-confirmed +5 hits: {}/{} ({:.4}); matching positions: {}\n",
        evaluation.expected_delta_hits,
        evaluation.observed_position_count,
        evaluation.expected_delta_hit_rate,
        evaluation
            .matching_expected_delta_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "window null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_regularity_hits,
        evaluation.null_std_dev_regularity_hits,
        evaluation.regularity_empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!(
        "lag-confirmed null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_expected_delta_hits,
        evaluation.null_std_dev_expected_delta_hits,
        evaluation.expected_delta_empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n", evaluation.note));
    output
}

fn render_ciphertext_prior_evaluation(evaluation: &CiphertextPriorEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Ciphertext Prior Evaluation\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    if let Some(observation_id) = &evaluation.observation_id {
        output.push_str(&format!("observation id: `{observation_id}`\n"));
    }
    if !evaluation.observation_source_ids.is_empty() {
        output.push_str(&format!(
            "observation sources: {}\n",
            evaluation.observation_source_ids.join(", ")
        ));
    }
    if let Some(observation_rationale) = &evaluation.observation_rationale {
        output.push_str(&format!("observation rationale: {observation_rationale}\n"));
    }
    output.push_str(&format!(
        "source-backed observation: {}\n",
        evaluation.source_backed_observation
    ));
    output.push_str(&format!(
        "observed positions: {}\n",
        evaluation
            .observed_positions_one_based
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "best: period {} residue {} with {}/{} hits ({:.4})\n",
        evaluation.best_period,
        evaluation.best_residue,
        evaluation.best_hits,
        evaluation.observed_position_count,
        evaluation.best_hit_rate
    ));
    output.push_str(&format!(
        "selected-period null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}\n",
        evaluation.null_mean_best_hits,
        evaluation.null_std_dev_best_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n\n", evaluation.note));
    output.push_str("| Period | Support Kind | Best Residue | Hits | Hit Rate |\n");
    output.push_str("| --- | --- | --- | --- | --- |\n");
    for result in &evaluation.period_results {
        output.push_str(&format!(
            "| {} | {} | {} | {}/{} | {:.4} |\n",
            result.period,
            result.support_kind,
            result.best_residue,
            result.best_hits,
            evaluation.observed_position_count,
            result.best_hit_rate
        ));
    }
    output
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

fn print_mirror_prediction_evaluation(evaluation: &MirrorPredictionEvaluation) {
    print!("{}", render_mirror_prediction_evaluation(evaluation));
}

fn print_grid_prediction_evaluation(evaluation: &GridLayoutPredictionEvaluation) {
    print!("{}", render_grid_prediction_evaluation(evaluation));
}

fn print_tableau_hill_prediction_evaluation(evaluation: &TableauHillPredictionEvaluation) {
    print!("{}", render_tableau_hill_prediction_evaluation(evaluation));
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

fn render_mirror_prediction_evaluation(evaluation: &MirrorPredictionEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Mirror Prediction Evaluation\n\n");
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
        "observed position count: {}; possible observed mirror pairs: {}",
        evaluation.observed_position_count, evaluation.possible_observed_mirror_pairs
    ));
    output.push('\n');
    output.push_str(&format!(
        "mirror pair hits: {}/{} ({:.4})",
        evaluation.mirror_pair_hits,
        evaluation.possible_observed_mirror_pairs,
        evaluation.mirror_pair_hit_rate
    ));
    output.push('\n');
    output.push_str(&format!(
        "same-size null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}",
        evaluation.null_mean_mirror_pair_hits,
        evaluation.null_std_dev_mirror_pair_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push('\n');
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n\n", evaluation.note));

    output.push_str("## Matching Mirror Pairs\n\n");
    if evaluation.matching_pairs_one_based.is_empty() {
        output.push_str("none\n\n");
    } else {
        for pair in &evaluation.matching_pairs_one_based {
            output.push_str(&format!("- {}-{}\n", pair[0], pair[1]));
        }
        output.push('\n');
    }
    output.push_str("## Singleton Mirror Positions\n\n");
    if evaluation.singleton_positions_one_based.is_empty() {
        output.push_str("none\n");
    } else {
        output.push_str(
            &evaluation
                .singleton_positions_one_based
                .iter()
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push('\n');
    }
    output
}

fn render_grid_prediction_evaluation(evaluation: &GridLayoutPredictionEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Grid Layout Prediction Evaluation\n\n");
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
    output.push_str(&format!("edge axis: {}", evaluation.edge_axis));
    output.push('\n');
    output.push_str(&format!(
        "selected-edge hits: {}/{} ({:.4})",
        evaluation.edge_hits, evaluation.observed_position_count, evaluation.edge_hit_rate
    ));
    output.push('\n');
    output.push_str(&format!(
        "same-size null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}",
        evaluation.null_mean_edge_hits,
        evaluation.null_std_dev_edge_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push('\n');
    output.push_str(&format!(
        "row-edge hits: {}/{} ({:.4})",
        evaluation.row_edge_hits, evaluation.observed_position_count, evaluation.row_edge_hit_rate
    ));
    output.push('\n');
    output.push_str(&format!(
        "column-edge hits: {}/{} ({:.4})",
        evaluation.column_edge_hits,
        evaluation.observed_position_count,
        evaluation.column_edge_hit_rate
    ));
    output.push('\n');
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n\n", evaluation.note));

    output.push_str("## Matching Selected-Edge Positions\n\n");
    if evaluation.matching_edge_positions_one_based.is_empty() {
        output.push_str("none\n\n");
    } else {
        output.push_str(
            &evaluation
                .matching_edge_positions_one_based
                .iter()
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str("\n\n");
    }
    output.push_str("## Non-Selected-Edge Positions\n\n");
    if evaluation.non_edge_positions_one_based.is_empty() {
        output.push_str("none\n\n");
    } else {
        output.push_str(
            &evaluation
                .non_edge_positions_one_based
                .iter()
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str("\n\n");
    }
    output.push_str("## Matching Row-Edge Positions\n\n");
    if evaluation.matching_row_edge_positions_one_based.is_empty() {
        output.push_str("none\n\n");
    } else {
        output.push_str(
            &evaluation
                .matching_row_edge_positions_one_based
                .iter()
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str("\n\n");
    }
    output.push_str("## Matching Column-Edge Positions\n\n");
    if evaluation
        .matching_column_edge_positions_one_based
        .is_empty()
    {
        output.push_str("none\n");
    } else {
        output.push_str(
            &evaluation
                .matching_column_edge_positions_one_based
                .iter()
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push('\n');
    }
    output
}

fn render_tableau_hill_prediction_evaluation(
    evaluation: &TableauHillPredictionEvaluation,
) -> String {
    let mut output = String::new();
    output.push_str("# Tableau/HILL Prediction Evaluation\n\n");
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
        "best: {} {} with {}/{} hits ({:.4})",
        evaluation.best_axis,
        evaluation.best_index_one_based,
        evaluation.best_hits,
        evaluation.observed_position_count,
        evaluation.best_hit_rate
    ));
    output.push('\n');
    output.push_str(&format!(
        "same-size null: mean {:.2}; sd {:.2}; empirical p-value {:.4}; iterations {}; seed {}",
        evaluation.null_mean_best_hits,
        evaluation.null_std_dev_best_hits,
        evaluation.empirical_p_value,
        evaluation.iterations,
        evaluation.seed
    ));
    output.push('\n');
    output.push_str(&format!("promoted: {}\n", evaluation.promoted_candidate));
    output.push_str(&format!("note: {}\n\n", evaluation.note));

    output.push_str("## Matching Best-Axis Positions\n\n");
    if evaluation.matching_positions_one_based.is_empty() {
        output.push_str("none\n\n");
    } else {
        output.push_str(
            &evaluation
                .matching_positions_one_based
                .iter()
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str("\n\n");
    }

    output.push_str("## Row Results\n\n");
    output.push_str("| Row | Hits | Hit Rate | Matching Positions |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for result in &evaluation.row_results {
        output.push_str(&format!(
            "| {} | {} | {:.4} | {} |",
            result.index_one_based,
            result.hits,
            result.hit_rate,
            format_position_list_or_none(&result.matching_positions_one_based)
        ));
        output.push('\n');
    }
    output.push_str("\n## Column Results\n\n");
    output.push_str("| Column | Hits | Hit Rate | Matching Positions |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for result in &evaluation.column_results {
        output.push_str(&format!(
            "| {} | {} | {:.4} | {} |",
            result.index_one_based,
            result.hits,
            result.hit_rate,
            format_position_list_or_none(&result.matching_positions_one_based)
        ));
        output.push('\n');
    }
    output
}

fn format_position_list_or_none(positions: &[usize]) -> String {
    if positions.is_empty() {
        "none".to_string()
    } else {
        positions
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
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

fn print_verify_plaintext_claim(
    input: PathBuf,
    source_id: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    ensure_quarantined_claim_source(source_id.as_deref(), "verify-plaintext-claim")?;

    let claim = fs::read_to_string(&input)
        .with_context(|| format!("failed to read plaintext claim `{}`", input.display()))?;
    let verification = verify_plaintext_claim(&claim, source_id)?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
        OutputFormat::Markdown => print_plaintext_claim_verification(&input, &verification),
    }
    Ok(())
}

fn print_verify_running_key_claim(
    plaintext: PathBuf,
    key: PathBuf,
    alphabet: CliAlphabet,
    source_id: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    ensure_quarantined_claim_source(source_id.as_deref(), "verify-running-key-claim")?;

    let plaintext_claim = fs::read_to_string(&plaintext).with_context(|| {
        format!(
            "failed to read running-key plaintext claim `{}`",
            plaintext.display()
        )
    })?;
    let key_stream = fs::read_to_string(&key)
        .with_context(|| format!("failed to read running-key stream `{}`", key.display()))?;
    let verification =
        verify_running_key_claim(&plaintext_claim, &key_stream, alphabet.into(), source_id)?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
        OutputFormat::Markdown => {
            print_running_key_claim_verification(&plaintext, &key, &verification)
        }
    }
    Ok(())
}

fn print_verify_claim_reconciliation(
    input: PathBuf,
    source_id: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    ensure_quarantined_claim_source(source_id.as_deref(), "verify-claim-reconciliation")?;

    let table = fs::read_to_string(&input).with_context(|| {
        format!(
            "failed to read claim reconciliation table `{}`",
            input.display()
        )
    })?;
    let verification = verify_claim_reconciliation_table(&table, source_id)?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
        OutputFormat::Markdown => print_claim_reconciliation_verification(&input, &verification),
    }
    Ok(())
}

fn print_verify_claim_bundle(
    directory: PathBuf,
    source_id: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    ensure_quarantined_claim_source(source_id.as_deref(), "verify-claim-bundle")?;

    let verification = verify_claim_bundle(&directory, source_id)?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
        OutputFormat::Markdown => print_claim_bundle_verification(&verification),
    }
    Ok(())
}

fn print_verify_claim_mechanism(
    directory: PathBuf,
    source_id: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    ensure_quarantined_claim_source(source_id.as_deref(), "verify-claim-mechanism")?;

    let verification = verify_claim_mechanism(&directory, source_id)?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
        OutputFormat::Markdown => print_claim_mechanism_verification(&verification),
    }
    Ok(())
}

fn ensure_quarantined_claim_source(source_id: Option<&str>, command_name: &str) -> Result<()> {
    if let Some(source_id) = source_id {
        let source = sources()
            .into_iter()
            .find(|source| source.id == source_id)
            .with_context(|| format!("unknown source id `{source_id}`"))?;
        if source.allowed_use != "unverified-solution-claim" {
            bail!(
                "source-id `{}` has allowed_use `{}`; {command_name} requires allowed_use `unverified-solution-claim`",
                source.id,
                source.allowed_use
            );
        }
    }
    Ok(())
}

fn print_plaintext_claim_verification(input: &Path, verification: &PlaintextClaimVerification) {
    println!("# Plaintext Claim Verification\n");
    println!("This is not a claimed solution.\n");
    println!("input: `{}`", input.display());
    println!(
        "source id: `{}`",
        verification.source_id.as_deref().unwrap_or("none")
    );
    println!("raw characters: {}", verification.raw_character_count);
    println!(
        "normalized letters: {}/{}",
        verification.normalized_letter_count, verification.expected_length
    );
    println!(
        "ignored non-letters: {}",
        verification.ignored_non_letter_count
    );
    println!("length matches: {}", verification.length_matches);
    println!(
        "public anchors: {}/{}",
        verification.public_anchor_match_count, verification.public_anchor_count
    );
    println!(
        "all public anchors match: {}",
        verification.all_public_anchors_match
    );
    println!(
        "implied shift diagnostics: distinct_values={} repeated_values={} max_bucket={}",
        verification.implied_shift_distinct_values,
        verification.implied_shift_repeated_value_count,
        verification.implied_shift_max_bucket_count
    );
    println!(
        "structural checks passed: {}",
        verification.structural_checks_passed
    );
    println!("promoted: {}", verification.promoted_candidate);
    println!("note: {}\n", verification.note);

    println!("| Anchor | Positions | Matches |");
    println!("| --- | --- | --- |");
    for check in &verification.anchor_checks {
        println!(
            "| {} | {}-{} | {} |",
            check.plaintext, check.start_one_based, check.end_one_based_inclusive, check.matches
        );
    }
}

fn print_running_key_claim_verification(
    plaintext: &Path,
    key: &Path,
    verification: &RunningKeyClaimVerification,
) {
    println!("# Running-Key Claim Verification\n");
    println!("This is not a claimed solution.\n");
    println!("plaintext input: `{}`", plaintext.display());
    println!("key input: `{}`", key.display());
    println!(
        "source id: `{}`",
        verification.source_id.as_deref().unwrap_or("none")
    );
    println!("alphabet: {:?}", verification.alphabet);
    println!(
        "plaintext normalized letters: {}/{}",
        verification.plaintext_normalized_letter_count, verification.expected_length
    );
    println!(
        "plaintext ignored non-letters: {}",
        verification.plaintext_ignored_non_letter_count
    );
    println!(
        "key normalized letters: {}/{}",
        verification.key_normalized_letter_count, verification.expected_length
    );
    println!(
        "key ignored non-letters: {}",
        verification.key_ignored_non_letter_count
    );
    println!(
        "public anchors: {}/{}",
        verification.public_anchor_match_count, verification.public_anchor_count
    );
    println!(
        "all public anchors match: {}",
        verification.all_public_anchors_match
    );
    println!(
        "ciphertext reconstruction: {}/{}",
        verification.ciphertext_match_count, verification.ciphertext_checked_count
    );
    println!(
        "all ciphertext matches: {}",
        verification.all_ciphertext_matches
    );
    if verification.mismatch_positions_one_based.is_empty() {
        println!("mismatch positions: none");
    } else {
        let positions = verification
            .mismatch_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("mismatch positions: {positions}");
    }
    println!(
        "key diagnostics: distinct_values={} repeated_values={} max_bucket={}",
        verification.key_distinct_values,
        verification.key_repeated_value_count,
        verification.key_max_bucket_count
    );
    println!(
        "structural checks passed: {}",
        verification.structural_checks_passed
    );
    println!("promoted: {}", verification.promoted_candidate);
    println!("note: {}\n", verification.note);

    println!("| Anchor | Positions | Matches |");
    println!("| --- | --- | --- |");
    for check in &verification.anchor_checks {
        println!(
            "| {} | {}-{} | {} |",
            check.plaintext, check.start_one_based, check.end_one_based_inclusive, check.matches
        );
    }
}

fn print_claim_reconciliation_verification(
    input: &Path,
    verification: &ClaimReconciliationVerification,
) {
    println!("# Claim Reconciliation Verification\n");
    println!("This is not a claimed solution.\n");
    println!("input: `{}`", input.display());
    println!(
        "source id: `{}`",
        verification.source_id.as_deref().unwrap_or("none")
    );
    println!(
        "rows: {}/{}",
        verification.row_count, verification.expected_row_count
    );
    println!("row count matches: {}", verification.row_count_matches);
    println!("unique positions: {}", verification.unique_positions);
    println!(
        "sequential positions: {}",
        verification.sequential_positions
    );
    println!(
        "ciphertext matches: {}/{}",
        verification.ciphertext_match_count, verification.ciphertext_checked_count
    );
    println!(
        "all ciphertext matches: {}",
        verification.all_ciphertext_matches
    );
    println!(
        "ciphertext numeric values: {}/{}",
        verification.ciphertext_value_match_count, verification.ciphertext_value_checked_count
    );
    println!(
        "all ciphertext numeric values match: {}",
        verification.all_ciphertext_values_match
    );
    println!("plaintext rows present: {}", verification.plaintext_rows);
    println!(
        "plaintext numeric values: {}/{}",
        verification.plaintext_value_match_count, verification.plaintext_value_checked_count
    );
    println!(
        "all plaintext numeric values match: {}",
        verification.all_plaintext_values_match
    );
    println!(
        "tier values: {}/{}",
        verification.tier_match_count, verification.tier_checked_count
    );
    println!(
        "all tier values match: {}",
        verification.all_tier_values_match
    );
    println!(
        "lane values: {}/{}",
        verification.lane_match_count, verification.lane_checked_count
    );
    println!(
        "all lane values match: {}",
        verification.all_lane_values_match
    );
    println!(
        "published R/shift values: {}/{}",
        verification.r_value_match_count, verification.r_value_checked_count
    );
    println!(
        "all published R/shift values match: {}",
        verification.all_r_values_match
    );
    println!(
        "gate values binary: {}/{}",
        verification.gate_binary_count, verification.gate_checked_count
    );
    println!(
        "all gate values binary: {}",
        verification.all_gate_values_binary
    );
    println!(
        "base-r plus gate checks: {}/{}",
        verification.r_plus_gate_match_count, verification.r_plus_gate_checked_count
    );
    println!(
        "all base-r plus gate checks match: {}",
        verification.all_r_plus_gate_matches
    );
    println!(
        "Z2 handoff checks: {}/{}",
        verification.z2_handoff_match_count, verification.z2_handoff_checked_count
    );
    println!(
        "all Z2 handoff checks match: {}",
        verification.all_z2_handoff_matches
    );
    println!(
        "public anchors: {}/{}",
        verification.public_anchor_match_count, verification.public_anchor_count
    );
    println!(
        "all public anchors match: {}",
        verification.all_public_anchors_match
    );
    if let (Some(distinct), Some(repeated), Some(max_bucket)) = (
        verification.implied_shift_distinct_values,
        verification.implied_shift_repeated_value_count,
        verification.implied_shift_max_bucket_count,
    ) {
        println!(
            "implied shift diagnostics: distinct_values={distinct} repeated_values={repeated} max_bucket={max_bucket}"
        );
    } else {
        println!("implied shift diagnostics: unavailable");
    }
    println!(
        "structural checks passed: {}",
        verification.structural_checks_passed
    );
    println!("promoted: {}", verification.promoted_candidate);
    println!("note: {}\n", verification.note);

    println!("| Anchor | Positions | Matches |");
    println!("| --- | --- | --- |");
    for check in &verification.anchor_checks {
        println!(
            "| {} | {}-{} | {} |",
            check.plaintext, check.start_one_based, check.end_one_based_inclusive, check.matches
        );
    }
}

fn print_claim_bundle_verification(verification: &ClaimBundleVerification) {
    println!("# Claim Bundle Verification\n");
    println!("This is not a claimed solution.\n");
    println!("directory: `{}`", verification.bundle_directory);
    println!(
        "source id: `{}`",
        verification.source_id.as_deref().unwrap_or("none")
    );
    println!(
        "required files: {}/{}",
        verification.required_files_checked, verification.expected_required_files
    );
    println!(
        "ciphertext file matches repo: {}",
        verification.ciphertext_file_matches_repo
    );
    println!(
        "plaintext file length matches: {}",
        verification.plaintext_file_length_matches
    );
    println!(
        "reconciliation structural checks passed: {}",
        verification.reconciliation.structural_checks_passed
    );
    println!(
        "R-grid values: {}/{}",
        verification.r_grid_match_count, verification.r_grid_checked_count
    );
    println!(
        "all R-grid values match: {}",
        verification.all_r_grid_values_match
    );
    println!(
        "base-r grid values: {}/{}",
        verification.base_r_grid_match_count, verification.base_r_grid_checked_count
    );
    println!(
        "all base-r grid values match: {}",
        verification.all_base_r_grid_values_match
    );
    println!(
        "gate-map values: {}/{}",
        verification.gate_map_match_count, verification.gate_map_checked_count
    );
    println!(
        "all gate-map values match: {}",
        verification.all_gate_map_values_match
    );
    println!(
        "Z2 handoff checks: {}/{}",
        verification.reconciliation.z2_handoff_match_count,
        verification.reconciliation.z2_handoff_checked_count
    );
    println!(
        "public anchors: {}/{}",
        verification.reconciliation.public_anchor_match_count,
        verification.reconciliation.public_anchor_count
    );
    println!(
        "structural checks passed: {}",
        verification.structural_checks_passed
    );
    println!("promoted: {}", verification.promoted_candidate);
    println!("note: {}", verification.note);
}

fn print_claim_mechanism_verification(verification: &ClaimMechanismVerification) {
    println!("# Claim Mechanism Verification\n");
    println!("This is not a claimed solution.\n");
    println!("directory: `{}`", verification.bundle_directory);
    println!(
        "source id: `{}`",
        verification.source_id.as_deref().unwrap_or("none")
    );
    println!(
        "required files: {}/{}",
        verification.required_files_checked, verification.expected_required_files
    );
    println!(
        "f-table values: {}/{}",
        verification.f_table_match_count, verification.f_table_checked_count
    );
    println!(
        "helper-card delta checks: {}/{}",
        verification.z1_z2_delta_match_count, verification.z1_z2_delta_checked_count
    );
    println!(
        "control-card values: {}/{}",
        verification.control_card_match_count, verification.control_card_checked_count
    );
    println!(
        "Z2 effective key matches: {}",
        verification.z2_effective_key_matches
    );
    println!(
        "Z2 base-r grid path: {}/{}",
        verification.z2_r_grid_match_count, verification.z2_r_grid_checked_count
    );
    println!(
        "Z2 final R-grid path: {}/{}",
        verification.z2_final_grid_match_count, verification.z2_final_grid_checked_count
    );
    println!(
        "Y template rule checks: {}/{}",
        verification.y_template_rule_match_count, verification.y_template_rule_checked_count
    );
    println!(
        "Y template gate-map checks: {}/{}",
        verification.y_template_gate_match_count, verification.y_template_gate_checked_count
    );
    if !verification.y_template_mismatches.is_empty() {
        println!("\n## Y Template Mismatches\n");
        println!("| Y Position | K4 Position | Expected Gate | Observed Gate |");
        println!("| --- | --- | --- | --- |");
        for mismatch in &verification.y_template_mismatches {
            println!(
                "| {} | {} | {} | {} |",
                mismatch.y_position_one_based,
                mismatch.k4_position_one_based,
                mismatch.expected_gate_value,
                mismatch.observed_gate_value
            );
        }
        println!();
    }
    if !verification
        .y_template_declared_not_in_rule_zero_positions_one_based
        .is_empty()
        || !verification
            .y_template_rule_not_in_declared_zero_positions_one_based
            .is_empty()
    {
        println!("\n## Y Template Zero-Position Disagreement\n");
        println!(
            "declared zero positions: {}",
            format_usize_list(&verification.y_template_declared_zero_positions_one_based)
        );
        println!(
            "rule-derived zero positions: {}",
            format_usize_list(&verification.y_template_rule_zero_positions_one_based)
        );
        println!(
            "declared only: {}",
            format_usize_list(
                &verification.y_template_declared_not_in_rule_zero_positions_one_based
            )
        );
        println!(
            "rule only: {}",
            format_usize_list(
                &verification.y_template_rule_not_in_declared_zero_positions_one_based
            )
        );
        println!();
    }
    println!(
        "structural checks passed: {}",
        verification.structural_checks_passed
    );
    println!("promoted: {}", verification.promoted_candidate);
    println!("note: {}", verification.note);
}

fn format_usize_list(values: &[usize]) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
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
                url: source.url,
                archive_url: source.archive_url,
                locally_archived: source.archive_url.is_some(),
                accessed_at: source.accessed_at,
                publication_date: source.publication_date,
                source_type: source.source_type,
                allowed_use: source.allowed_use,
                use_note: source.use_note,
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
            println!(
                "| Source ID | Allowed Use | Eligible | Local Archive | Accessed | Source Type | Reason | URL |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- |");
            for source in &report.sources {
                let archive_status = if source.locally_archived { "yes" } else { "no" };
                println!(
                    "| `{}` | {} | {} | {} | {} | {} | {} | {} |",
                    source.id,
                    source.allowed_use,
                    source.eligible_for_scored_observations,
                    archive_status,
                    source.accessed_at,
                    source.source_type,
                    source.reason,
                    source.url
                );
            }
        }
    }
    Ok(())
}

fn source_frontier_report() -> Result<SourceFrontierReport> {
    let evidence_report = independent_evidence_status_report(Vec::new())?;
    let valid_source_backed_archives = evidence_report
        .archives
        .iter()
        .filter(|archive| archive.valid && archive.source_backed_observation)
        .collect::<Vec<_>>();
    let valid_source_backed_archive_count = valid_source_backed_archives.len();
    let all_source_backed_archives_negative = valid_source_backed_archive_count > 0
        && valid_source_backed_archives
            .iter()
            .all(|archive| archive.support_status == "negative/non-significant");
    let frontier_sources = sources()
        .into_iter()
        .map(|source| {
            let archive_path = source.archive_url.map(Path::new);
            let current_archive_has_scored_positions = archive_path
                .is_some_and(source_archive_has_scored_positions);
            let non_scorable_reason = archive_path.and_then(source_archive_non_scorable_reason);
            let source_backed_archives = evidence_report
                .archives
                .iter()
                .filter(|archive| {
                    archive.valid
                        && archive.source_backed_observation
                        && archive
                            .observation_source_ids
                            .iter()
                            .any(|source_id| source_id == source.id)
                })
                .collect::<Vec<_>>();
            let source_backed_archive_count = source_backed_archives.len();
            let mut archived_support_statuses = source_backed_archives
                .iter()
                .map(|archive| format!("{}:{}", archive.artifact_kind, archive.support_status))
                .collect::<Vec<_>>();
            archived_support_statuses.sort();
            archived_support_statuses.dedup();
            let (frontier_class, allowed_next_action) = match source.allowed_use {
                "public-facts-only" if source_backed_archive_count > 0 => (
                    "scored-observation-ready".to_string(),
                    format!(
                        "Already used in {source_backed_archive_count} source-backed evaluation archives; inspect archived support statuses before any follow-up."
                    ),
                ),
                "public-facts-only" if current_archive_has_scored_positions => (
                    "scored-observation-ready".to_string(),
                    "Use only through a validated source-review, source-backed observation file, family evaluator, and archive validator.".to_string(),
                ),
                "public-facts-only" if non_scorable_reason.is_some() => (
                    "eligible-but-currently-non-scorable".to_string(),
                    "Do not score until a new source-backed rationale updates the local archive with explicit non-anchor scored-position markers.".to_string(),
                ),
                "public-facts-only" => (
                    "eligible-review-required".to_string(),
                    "Review and locally archive scored-position markers before creating an observation file.".to_string(),
                ),
                "unverified-solution-claim" => (
                    "quarantined-claim".to_string(),
                    "Keep out of release-facing artifacts; use only temporary local claim verifiers that do not print or store claimed plaintext.".to_string(),
                ),
                allowed_use if allowed_use.contains("context")
                    || allowed_use.contains("summary")
                    || allowed_use.contains("clue") =>
                {
                    (
                        "context-only".to_string(),
                        "May justify preregistration rationale or stopped-lane documentation, but must not be scored as independent observation evidence.".to_string(),
                    )
                }
                _ => (
                    "non-scoring".to_string(),
                    "Use only within the allowed-use boundary recorded in the source registry.".to_string(),
                ),
            };
            SourceFrontierEntry {
                id: source.id,
                label: source.label,
                source_type: source.source_type,
                allowed_use: source.allowed_use,
                frontier_class,
                archive_url: source.archive_url,
                locally_archived: source.archive_url.is_some(),
                current_archive_has_scored_positions,
                source_backed_archive_count,
                archived_support_statuses,
                non_scorable_reason,
                allowed_next_action,
                use_note: source.use_note,
                url: source.url,
            }
        })
        .collect::<Vec<_>>();
    let scored_observation_eligible_count = frontier_sources
        .iter()
        .filter(|source| source.allowed_use == "public-facts-only")
        .count();
    let scored_position_marker_count = frontier_sources
        .iter()
        .filter(|source| source.current_archive_has_scored_positions)
        .count();
    let context_only_count = frontier_sources
        .iter()
        .filter(|source| source.frontier_class == "context-only")
        .count();
    let quarantined_claim_count = frontier_sources
        .iter()
        .filter(|source| source.frontier_class == "quarantined-claim")
        .count();
    let unused_eligible_sources_are_non_scorable = frontier_sources
        .iter()
        .filter(|source| source.allowed_use == "public-facts-only")
        .filter(|source| source.source_backed_archive_count == 0)
        .all(|source| {
            !source.current_archive_has_scored_positions && source.non_scorable_reason.is_some()
        });
    let mut frontier_blocking_conditions = Vec::new();
    if all_source_backed_archives_negative {
        frontier_blocking_conditions
            .push("source-backed-evidence-negative-or-non-significant".to_string());
    }
    if unused_eligible_sources_are_non_scorable {
        frontier_blocking_conditions.push("unused-eligible-source-marked-non-scorable".to_string());
    }
    if frontier_sources.iter().any(|source| {
        source.source_backed_archive_count > 0
            && source
                .archived_support_statuses
                .iter()
                .all(|status| status.ends_with(":negative/non-significant"))
    }) {
        frontier_blocking_conditions.push("already-used-source-archives-negative".to_string());
    }
    let required_next_evidence = vec![
        "new eligible source with allowed_use public-facts-only and a local quote-free archive"
            .to_string(),
        "or new source-backed rationale that updates an eligible local archive with explicit non-anchor scored_positions_one_based markers"
            .to_string(),
        "or distinct preregistered prediction artifact validated with validate-prediction-artifact --require-unique-artifact"
            .to_string(),
        "validated source-review and source-backed observation file before any scoring command is interpreted"
            .to_string(),
    ];
    let disallowed_next_actions = vec![
        "do not rerun current cia-sculpture row-boundary observations as new evidence without a distinct prediction artifact or new source-backed rationale"
            .to_string(),
        "do not score cia-artifact until its local archive boundary changes from non-scorable to explicit scored-position markers"
            .to_string(),
        "do not use context-only, archive-context-only, public-anchor-summary, public-clue-context, methodology-context, or quarantined-claim sources as scored independent observation evidence"
            .to_string(),
    ];
    let recommended_next_step = if all_source_backed_archives_negative
        && unused_eligible_sources_are_non_scorable
    {
        "Current source-backed archives are all negative/non-significant, and unused eligible sources are explicitly non-scorable; next useful work requires a new source-backed rationale, a new eligible source, or a distinct preregistered prediction artifact."
                .to_string()
    } else {
        "Use scored-observation-ready sources only through source-review and observation validators; use context-only sources only for preregistration rationale; keep quarantined claims out of release-facing evidence."
                .to_string()
    };
    Ok(SourceFrontierReport {
        source_count: frontier_sources.len(),
        scored_observation_eligible_count,
        scored_position_marker_count,
        valid_source_backed_archive_count,
        all_source_backed_archives_negative,
        context_only_count,
        quarantined_claim_count,
        frontier_blocking_conditions,
        required_next_evidence,
        disallowed_next_actions,
        frontier_sources,
        recommended_next_step,
        promoted_candidate: false,
        note: "Source-frontier output classifies evidence-use boundaries only; it is not a claimed solution.",
    })
}

fn print_source_frontier(summary: bool, format: OutputFormat) -> Result<()> {
    let report = source_frontier_report()?;
    match format {
        OutputFormat::Json => {
            if summary {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&source_frontier_summary(&report))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Source Frontier\n");
            println!("This is not a claimed solution.\n");
            println!("sources: {}", report.source_count);
            println!(
                "scored-observation eligible sources: {}",
                report.scored_observation_eligible_count
            );
            println!(
                "sources with scored-position markers: {}",
                report.scored_position_marker_count
            );
            println!(
                "valid source-backed archives: {}",
                report.valid_source_backed_archive_count
            );
            println!(
                "all source-backed archives negative: {}",
                report.all_source_backed_archives_negative
            );
            println!("context-only sources: {}", report.context_only_count);
            println!("quarantined claims: {}", report.quarantined_claim_count);
            println!("promoted: {}", report.promoted_candidate);
            println!("recommended next step: {}", report.recommended_next_step);
            println!("note: {}\n", report.note);

            println!("## Frontier Blocking Conditions\n");
            for condition in &report.frontier_blocking_conditions {
                println!("- `{condition}`");
            }

            println!("\n## Required Next Evidence\n");
            for requirement in &report.required_next_evidence {
                println!("- {requirement}");
            }

            println!("\n## Disallowed Next Actions\n");
            for action in &report.disallowed_next_actions {
                println!("- {action}");
            }

            if summary {
                let scored_ready = report
                    .frontier_sources
                    .iter()
                    .filter(|source| source.frontier_class == "scored-observation-ready")
                    .map(|source| source.id)
                    .collect::<Vec<_>>();
                let non_scorable = report
                    .frontier_sources
                    .iter()
                    .filter(|source| source.frontier_class == "eligible-but-currently-non-scorable")
                    .map(|source| source.id)
                    .collect::<Vec<_>>();
                let used_negative = report
                    .frontier_sources
                    .iter()
                    .filter(|source| source.source_backed_archive_count > 0)
                    .map(|source| {
                        format!(
                            "{} ({} archived evaluations)",
                            source.id, source.source_backed_archive_count
                        )
                    })
                    .collect::<Vec<_>>();
                println!("\n## Operational Summary\n");
                println!(
                    "- scored-observation-ready sources: {}",
                    if scored_ready.is_empty() {
                        "none".to_string()
                    } else {
                        scored_ready.join(", ")
                    }
                );
                println!(
                    "- eligible but currently non-scorable sources: {}",
                    if non_scorable.is_empty() {
                        "none".to_string()
                    } else {
                        non_scorable.join(", ")
                    }
                );
                println!(
                    "- already-scored source-backed archives: {}",
                    if used_negative.is_empty() {
                        "none".to_string()
                    } else {
                        used_negative.join(", ")
                    }
                );
                println!(
                    "- action: do not rerun negative row-boundary evidence as new evidence; add a new eligible source, update a source archive with explicit non-anchor scored positions, or validate a genuinely distinct prediction artifact before scoring."
                );
                return Ok(());
            }

            println!("\n## Sources\n");
            println!(
                "| Source ID | Frontier | Allowed Use | Scored Markers | Archived Evaluations | Archived Support | Non-Scorable Reason | Next Action | Archive | URL |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for source in &report.frontier_sources {
                let archive = source.archive_url.unwrap_or("none");
                let archived_support = if source.archived_support_statuses.is_empty() {
                    "none".to_string()
                } else {
                    source.archived_support_statuses.join("; ")
                };
                let non_scorable_reason = source.non_scorable_reason.as_deref().unwrap_or("none");
                println!(
                    "| `{}` | {} | {} | {} | {} | {} | {} | {} | `{}` | {} |",
                    source.id,
                    source.frontier_class,
                    source.allowed_use,
                    source.current_archive_has_scored_positions,
                    source.source_backed_archive_count,
                    archived_support,
                    non_scorable_reason,
                    source.allowed_next_action,
                    archive,
                    source.url
                );
            }
        }
    }
    Ok(())
}

fn source_frontier_summary(report: &SourceFrontierReport) -> SourceFrontierSummary {
    let scored_observation_ready_source_ids = report
        .frontier_sources
        .iter()
        .filter(|source| source.frontier_class == "scored-observation-ready")
        .map(|source| source.id)
        .collect::<Vec<_>>();
    let eligible_but_currently_non_scorable_source_ids = report
        .frontier_sources
        .iter()
        .filter(|source| source.frontier_class == "eligible-but-currently-non-scorable")
        .map(|source| source.id)
        .collect::<Vec<_>>();
    let already_scored_source_backed_archives = report
        .frontier_sources
        .iter()
        .filter(|source| source.source_backed_archive_count > 0)
        .map(|source| {
            format!(
                "{} ({} archived evaluations)",
                source.id, source.source_backed_archive_count
            )
        })
        .collect::<Vec<_>>();

    SourceFrontierSummary {
        summary: true,
        source_count: report.source_count,
        scored_observation_eligible_count: report.scored_observation_eligible_count,
        scored_position_marker_count: report.scored_position_marker_count,
        valid_source_backed_archive_count: report.valid_source_backed_archive_count,
        all_source_backed_archives_negative: report.all_source_backed_archives_negative,
        context_only_count: report.context_only_count,
        quarantined_claim_count: report.quarantined_claim_count,
        frontier_blocking_conditions: report.frontier_blocking_conditions.clone(),
        required_next_evidence: report.required_next_evidence.clone(),
        disallowed_next_actions: report.disallowed_next_actions.clone(),
        scored_observation_ready_source_ids,
        eligible_but_currently_non_scorable_source_ids,
        already_scored_source_backed_archives,
        recommended_next_step: report.recommended_next_step.clone(),
        action: "do not rerun negative row-boundary evidence as new evidence; add a new eligible source, update a source archive with explicit non-anchor scored positions, or validate a genuinely distinct prediction artifact before scoring.",
        promoted_candidate: report.promoted_candidate,
        note: report.note,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_gate_commands_use_family_specific_commands() {
        let tableau_commands = evidence_gate_commands(
            "tableau-hill-prediction",
            "experiments/predictions/tableau-hill-v1.json",
            "experiments/preregistrations/tableau-hill-v1.json",
            None,
        )
        .expect("tableau/HILL family should have gate commands");

        assert!(
            tableau_commands
                .0
                .contains("validate-tableau-hill-observations")
        );
        assert!(
            tableau_commands
                .1
                .contains("evaluate-tableau-hill-prediction")
        );
        assert!(
            tableau_commands
                .2
                .contains("results/tableau-hill-observations/<observation-id>")
        );

        let period_commands = evidence_gate_commands(
            "position-period-prediction",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            None,
        )
        .expect("period family should have gate commands");

        assert!(period_commands.0.contains("validate-period-observations"));
        assert!(period_commands.1.contains("evaluate-period-prediction"));
        assert!(
            period_commands
                .2
                .contains("results/period-observations/<observation-id>")
        );

        let grid_commands = evidence_gate_commands(
            "position-grid-layout-prediction",
            "experiments/predictions/non-anchor-position-grid-column-v1.json",
            "experiments/preregistrations/non-anchor-position-grid-column-v1.json",
            Some("column"),
        )
        .expect("grid family should have gate commands");
        assert!(grid_commands.1.contains("--edge-axis column"));
    }
}
