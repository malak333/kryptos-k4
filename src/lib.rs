//! Kryptos K4 research library: public facts, anchor-derived constraints, and method tests.

pub mod alphabet;
pub mod analysis;
pub mod baseline;
pub mod candidates;
pub mod ciphertext_profile;
pub mod claim;
pub mod data;
pub mod eliminate;
pub mod findings;
pub mod hypotheses;
pub mod key_language;
pub mod key_test;
pub mod release_check;
pub mod report;
pub mod route_elimination;
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
    CiphertextProfile, CiphertextProfileBaseline, KasiskiFactorBaseline, KasiskiFactorProfile,
    KasiskiGapSupport, LetterFrequency, PeriodProfile, RepeatedNgram, ShiftedMatch,
    profile_k4_ciphertext,
};
pub use claim::{
    PlaintextClaimAnchorCheck, PlaintextClaimVerification, RunningKeyClaimVerification,
    verify_plaintext_claim, verify_running_key_claim,
};
pub use data::{
    Anchor, K4_CIPHERTEXT, KnownPlaintextSpan, Source, known_anchors, known_plaintext_spans,
    sources,
};
pub use eliminate::{
    EliminationOptions, EliminationReport, FamilyElimination, RunningKeyReport, StructuralFacts,
    normalize_letters, run_elimination, scan_running_key, structural_facts,
};
pub use findings::{Finding, findings};
pub use hypotheses::{Hypothesis, hypotheses};
pub use key_language::{KeyLanguageHit, KeyLanguageOptions, KeyLanguageReport, key_language};
pub use key_test::{
    BatchKeyMaterialBaseline, BatchKeyMaterialCandidate, BatchKeyMaterialResult,
    BatchKeyMaterialRun, KeyMaterialExplanation, KeyMaterialMatch, KeyMaterialMismatch,
    KeyMaterialOffsetResult, KeyMaterialOffsetSweep, KeyMaterialPatternMetrics,
    KeyMaterialSpanResult, KeyMaterialSweepBaseline, KeyMaterialTest, RoutedBatchKeyMaterialResult,
    RoutedBatchKeyMaterialRun, RoutedKeyMaterialOffsetSweep, batch_test_key_material,
    batch_test_key_material_with_batch_baseline, batch_test_routed_key_material,
    explain_key_material, sweep_key_material_offsets, sweep_key_material_offsets_with_baseline,
    test_key_material,
};
pub use release_check::{ReleaseCheck, run_release_checks};
pub use report::{Report, ReportFormat, build_report, render_report};
pub use route_elimination::{AnySubstitutionRow, AnySubstitutionSummary, Route, registered_routes};
pub use routes::{RouteExperiment, RouteFamily, registered_route_families, run_route_experiments};
