pub mod baseline;

pub mod alphabet;
pub mod analysis;
pub mod candidates;
pub mod data;
pub mod findings;
pub mod hypotheses;
pub mod key_test;
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
pub use data::{
    Anchor, K4_CIPHERTEXT, KnownPlaintextSpan, Source, known_anchors, known_plaintext_spans,
    sources,
};
pub use findings::{Finding, findings};
pub use hypotheses::{Hypothesis, hypotheses};
pub use key_test::{
    BatchKeyMaterialBaseline, BatchKeyMaterialCandidate, BatchKeyMaterialResult,
    BatchKeyMaterialRun, BatchKeyRunCandidateSummary, BatchKeyRunHistory, BatchKeyRunHistoryEntry,
    KeyMaterialExplanation, KeyMaterialMatch, KeyMaterialMismatch, KeyMaterialOffsetResult,
    KeyMaterialOffsetSweep, KeyMaterialSpanResult, KeyMaterialSweepBaseline, KeyMaterialTest,
    batch_test_key_material, batch_test_key_material_with_batch_baseline, explain_key_material,
    summarize_batch_key_material_runs, sweep_key_material_offsets,
    sweep_key_material_offsets_with_baseline, test_key_material,
};
pub use release_check::{ReleaseCheck, run_release_checks};
pub use report::{Report, ReportFormat, build_report, render_report};
pub use routes::{RouteExperiment, RouteFamily, registered_route_families, run_route_experiments};
