pub mod baseline;

pub mod alphabet;
pub mod analysis;
pub mod candidates;
pub mod ciphertext_profile;
pub mod claim;
pub mod data;
pub mod findings;
pub mod hypotheses;
pub mod key_test;
pub mod position_structure;
pub mod preregistration;
pub mod release_check;
pub mod report;
pub mod routes;

pub use alphabet::{Alphabet, AlphabetKind};
pub use analysis::{
    AnalysisTarget, AnalysisTargetKind, BaselineSummary, ConstraintAnalysis, FragmentMode,
    analyze_constraints, analyze_known_plaintext_spans, baseline_known_plaintext_spans,
};
pub use baseline::{
    BaselineAlphabetScope, BaselineResult, BaselineRun, BaselineTargetScope, run_baseline,
};
pub use candidates::{
    CandidateSequence, CandidateSequenceFamily, CandidateSequenceScore, CandidateTransform,
    candidate_sequences, score_candidate_sequences,
};
pub use ciphertext_profile::{
    CiphertextAdjacentContrastEvaluation, CiphertextAdjacentContrastPosition,
    CiphertextAdjacentContrastPrior, CiphertextCtPerturbationEvaluation,
    CiphertextCtPerturbationPosition, CiphertextCtPerturbationPrior, CiphertextHotspot,
    CiphertextHotspotEvaluation, CiphertextHotspotPrior, CiphertextPeriodMatchEvaluation,
    CiphertextPeriodMatchEvaluationSet, CiphertextPeriodMatchPrior, CiphertextPeriodMatchSet,
    CiphertextPriorEvaluation, CiphertextPriorEvaluationPeriod, CiphertextPriorPeriod,
    CiphertextPriorResidue, CiphertextPriorResidueHit, CiphertextProfile,
    CiphertextProfileBaseline, CiphertextRarityEvaluation, CiphertextRarityPosition,
    CiphertextRarityPrior, CiphertextRepeatDistanceEvaluation, CiphertextRepeatDistancePosition,
    CiphertextRepeatDistancePrior, CiphertextResidueBalanceEvaluation,
    CiphertextResidueBalanceEvaluationSet, CiphertextResidueBalancePrior,
    CiphertextResidueBalanceSet, CiphertextSkipTransitionEvaluation,
    CiphertextSkipTransitionPosition, CiphertextSkipTransitionPrior,
    CiphertextStehleRegularityEvaluation, CiphertextStehleRegularityPosition,
    CiphertextStehleRegularityPrior, CiphertextStructurePrior, CiphertextTransitionEvaluation,
    CiphertextTransitionPosition, CiphertextTransitionPrior, CiphertextTurningPointEvaluation,
    CiphertextTurningPointPosition, CiphertextTurningPointPrior, CiphertextWindowBalanceEvaluation,
    CiphertextWindowBalancePosition, CiphertextWindowBalancePrior, KasiskiFactorBaseline,
    KasiskiFactorProfile, KasiskiGapSupport, LetterFrequency, PeriodProfile, RepeatedNgram,
    ShiftedMatch, build_ciphertext_adjacent_contrast_prior, build_ciphertext_ct_perturbation_prior,
    build_ciphertext_hotspot_prior, build_ciphertext_period_match_prior,
    build_ciphertext_rarity_prior, build_ciphertext_repeat_distance_prior,
    build_ciphertext_residue_balance_prior, build_ciphertext_skip_transition_prior,
    build_ciphertext_stehle_regularity_prior, build_ciphertext_structure_prior,
    build_ciphertext_transition_prior, build_ciphertext_turning_point_prior,
    build_ciphertext_window_balance_prior, build_committed_ciphertext_adjacent_contrast_prior,
    build_committed_ciphertext_ct_perturbation_prior, build_committed_ciphertext_hotspot_prior,
    build_committed_ciphertext_period_match_prior, build_committed_ciphertext_rarity_prior,
    build_committed_ciphertext_repeat_distance_prior,
    build_committed_ciphertext_residue_balance_prior,
    build_committed_ciphertext_skip_transition_prior,
    build_committed_ciphertext_stehle_regularity_prior, build_committed_ciphertext_structure_prior,
    build_committed_ciphertext_transition_prior, build_committed_ciphertext_turning_point_prior,
    build_committed_ciphertext_window_balance_prior,
    evaluate_ciphertext_adjacent_contrast_positions, evaluate_ciphertext_ct_perturbation_positions,
    evaluate_ciphertext_hotspot_positions, evaluate_ciphertext_period_match_positions,
    evaluate_ciphertext_rarity_positions, evaluate_ciphertext_repeat_distance_positions,
    evaluate_ciphertext_residue_balance_positions, evaluate_ciphertext_skip_transition_positions,
    evaluate_ciphertext_stehle_regularity_positions, evaluate_ciphertext_structure_prior_positions,
    evaluate_ciphertext_transition_positions, evaluate_ciphertext_turning_point_positions,
    evaluate_ciphertext_window_balance_positions, profile_k4_ciphertext,
};
pub use claim::{
    ClaimBundleVerification, ClaimMechanismVerification, ClaimReconciliationRowCheck,
    ClaimReconciliationVerification, PlaintextClaimAnchorCheck, PlaintextClaimVerification,
    RunningKeyClaimVerification, verify_claim_bundle, verify_claim_mechanism,
    verify_claim_reconciliation_table, verify_plaintext_claim, verify_running_key_claim,
};
pub use data::{
    Anchor, K4_CIPHERTEXT, KnownPlaintextSpan, Source, known_anchors, known_plaintext_spans,
    sources,
};
pub use findings::{Finding, findings};
pub use hypotheses::{Hypothesis, hypotheses};
pub use key_test::{
    BatchKeyMaterialBaseline, BatchKeyMaterialCandidate, BatchKeyMaterialResult,
    BatchKeyMaterialRun, BatchKeyRunCandidateSummary, BatchKeyRunHistory, BatchKeyRunHistoryEntry,
    HeldoutKeyControlBaseline, HeldoutKeyControlFold, HeldoutKeyControlRun, KeyMaterialExplanation,
    KeyMaterialMatch, KeyMaterialMismatch, KeyMaterialOffsetResult, KeyMaterialOffsetSweep,
    KeyMaterialPatternMetrics, KeyMaterialSpanResult, KeyMaterialSweepBaseline, KeyMaterialTest,
    RoutedBatchKeyMaterialResult, RoutedBatchKeyMaterialRun, RoutedKeyMaterialOffsetSweep,
    batch_test_key_material, batch_test_key_material_with_batch_baseline,
    batch_test_routed_key_material, explain_key_material, heldout_key_control,
    summarize_batch_key_material_runs, sweep_key_material_offsets,
    sweep_key_material_offsets_with_baseline, test_key_material,
};
pub use position_structure::{
    GridLayoutColumnPrediction, GridLayoutEdgeAxis, GridLayoutPredictionEvaluation,
    GridLayoutPredictionPlan, GridLayoutRowPrediction, MirrorPairPrediction,
    MirrorPredictionEvaluation, MirrorPredictionPlanSet, PeriodPredictionEvaluation,
    PeriodPredictionEvaluationResult, PeriodPredictionPlan, PeriodPredictionPlanSet,
    PeriodResidueHit, PeriodResiduePrediction, PositionModulusScore, PositionStructureResult,
    PositionStructureRun, SpacingPredictionEvaluation, SpacingPredictionEvaluationResult,
    SpacingPredictionPlan, SpacingPredictionPlanSet, SpacingResidueHit, SpacingResiduePrediction,
    StructuralModel, StructuralModelResult, StructuralModelRun, TableauHillAxisResult,
    TableauHillPredictionEvaluation, TableauHillPredictionPlan, TableauHillQuestion,
    build_all_period_prediction_plans, build_all_spacing_prediction_plans,
    build_grid_layout_prediction_plan, build_grid_layout_prediction_plan_for_axis,
    build_grid_layout_prediction_plan_with_dimensions, build_mirror_prediction_plan,
    build_period_prediction_plan, build_spacing_prediction_plan,
    build_tableau_hill_prediction_plan, evaluate_grid_layout_prediction_positions,
    evaluate_grid_layout_prediction_positions_with_axis, evaluate_mirror_prediction_positions,
    evaluate_period_prediction_positions, evaluate_spacing_prediction_positions,
    evaluate_tableau_hill_prediction_positions, registered_structural_models,
    run_position_structure_control, run_structural_model_control,
};
pub use preregistration::{
    DuplicatePredictionArtifactGroup, EvidenceKind, IndependentLaneStatus,
    IndependentLaneStatusReport, LanePreregistration, PredictionArtifactValidation,
    PreregistrationValidation, load_and_validate_preregistration, summarize_independent_lanes,
    summarize_independent_lanes_with_repo_root, validate_prediction_artifact,
    validate_prediction_artifact_with_repo_root, validate_preregistration, validation_exit_result,
};
pub use release_check::{ReleaseCheck, run_release_checks, run_release_checks_for_report};
pub use report::{Report, ReportFormat, build_report, render_report};
pub use routes::{RouteExperiment, RouteFamily, registered_route_families, run_route_experiments};
