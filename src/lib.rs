pub mod baseline;

pub mod alphabet;
pub mod analysis;
pub mod data;
pub mod hypotheses;
pub mod report;

pub use alphabet::{Alphabet, AlphabetKind};
pub use analysis::{
    AnalysisTarget, AnalysisTargetKind, BaselineSummary, ConstraintAnalysis, FragmentMode,
    analyze_constraints, analyze_known_plaintext_spans, baseline_known_plaintext_spans,
};
pub use baseline::{
    BaselineAlphabetScope, BaselineResult, BaselineRun, BaselineTargetScope, run_baseline,
};
pub use data::{
    Anchor, K4_CIPHERTEXT, KnownPlaintextSpan, Source, known_anchors, known_plaintext_spans,
    sources,
};
pub use hypotheses::{Hypothesis, hypotheses};
pub use report::{Report, ReportFormat, build_report, render_report};
