use crate::{
    BaselineAlphabetScope, BaselineRun, BaselineTargetScope, ConstraintAnalysis, K4_CIPHERTEXT,
    ReleaseCheck, analyze_constraints, analyze_known_plaintext_spans, candidate_sequences,
    hypotheses, known_anchors, known_plaintext_spans, run_baseline, run_release_checks_for_report,
    run_route_experiments, score_candidate_sequences, sources,
};
use anyhow::Result;
use serde::Serialize;

const REPORT_BASELINE_ITERATIONS: usize = 10_000;
const REPORT_BASELINE_SEED: u64 = 42;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Markdown,
    Json,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub ciphertext: &'static str,
    pub ciphertext_length: usize,
    pub anchors: Vec<crate::Anchor>,
    pub known_plaintext_spans: Vec<crate::KnownPlaintextSpan>,
    pub sources: Vec<crate::Source>,
    pub constraints: Vec<ConstraintAnalysis>,
    pub span_constraints: Vec<ConstraintAnalysis>,
    pub hypotheses: Vec<crate::Hypothesis>,
    pub candidate_sequences: Vec<crate::CandidateSequence>,
    pub candidate_sequence_scores: Vec<crate::CandidateSequenceScore>,
    pub route_experiments: Vec<crate::RouteExperiment>,
    pub baseline: BaselineRun,
    pub release_checks: Vec<ReleaseCheck>,
    pub findings: Vec<crate::Finding>,
}

pub fn build_report() -> Result<Report> {
    Ok(Report {
        ciphertext: K4_CIPHERTEXT,
        ciphertext_length: K4_CIPHERTEXT.len(),
        anchors: known_anchors(),
        known_plaintext_spans: known_plaintext_spans(),
        sources: sources(),
        constraints: analyze_constraints()?,
        span_constraints: analyze_known_plaintext_spans()?,
        hypotheses: hypotheses(),
        candidate_sequences: candidate_sequences(),
        candidate_sequence_scores: score_candidate_sequences()?,
        route_experiments: run_route_experiments()?,
        baseline: run_baseline(
            BaselineTargetScope::All,
            BaselineAlphabetScope::All,
            REPORT_BASELINE_ITERATIONS,
            REPORT_BASELINE_SEED,
        )?,
        release_checks: run_release_checks_for_report(env!("CARGO_MANIFEST_DIR"))?,
        findings: crate::findings(),
    })
}

pub fn render_report(report: &Report, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Markdown => Ok(render_markdown(report)),
        ReportFormat::Json => Ok(serde_json::to_string_pretty(report)?),
    }
}

fn render_markdown(report: &Report) -> String {
    let mut output = String::new();

    output.push_str("# Kryptos K4 Constraint Report\n\n");
    output.push_str(
        "This report uses public anchors only and is not a claimed solution. Production readiness here means the local, source-grounded research CLI and release package are repeatable and bounded; it does not mean Kryptos K4 is solved or that any candidate plaintext, key, route, or method is promoted.\n\n",
    );
    output.push_str("## Research Boundary and Production Readiness\n\n");
    output.push_str(
        "- Evidence boundary: public ciphertext, public known-plaintext anchors, source provenance, deterministic controls, and pre-registered exploratory screens only.\n",
    );
    output.push_str(
        "- Research boundary: no generated plaintext is treated as decoded K4 text; all promoted-candidate flags remain false unless independent corroboration and stronger samples justify a future change.\n",
    );
    output.push_str(
        "- Production-readiness scope: local Rust CLI, report rendering, JSON output, candidate registry alignment, source packet/source registry field and access-date alignment, release preflight, and no-GitHub-Actions policy. External publication, peer review, and cryptanalytic validation remain outside this report.\n\n",
    );

    output.push_str("## Feature Coverage\n\n");
    output.push_str(
        "| Feature | Included result |\n| --- | --- |\n| `facts` | Ciphertext length, ciphertext, and evidence boundary. |\n| `anchors` | Public known-plaintext anchors with positions, source IDs, confidence, claim type, and notes. |\n| `constraints` | Per-anchor key fragments across supported alphabets and modes, with recurrence screens. |\n| `key-fragments` | The same fragment rows are rendered in full for anchors and adjacent spans. |\n| `test-key` | Proposed key material is transformed and compared against public span additive fragments at true K4 positions, with optional cyclic offset sweep and seeded sweep baseline. |\n| `batch-test-keys` | CSV candidate rows are ranked with the same public-fragment checks and optional output artifacts. |\n| `position-structure` | Candidate-independent residue/spacing control over public fragment positions. |\n| `structural-models` | Pre-registered period-model controls over public fragment positions. |\n| `validate-preregistration` | Research-lane gate for future source evidence or independent prediction targets. |\n| `validate-prediction-artifact` | Gate confirming committed independent prediction artifacts still match their preregistration and deterministic generator. |\n| `validate-period-observations` | Gate for source-backed independent position observations, source allowed-use compatibility, and optional prediction-artifact preregistration validation before period prediction scoring. |\n| `period-prediction-plan` | Non-anchor residue-class target emission for a registered period, without scoring public fragment values. |\n| `evaluate-period-prediction` | Independent-position evaluator for committed period prediction artifacts with best-of-period null controls, source-backed observation-file input, and optional artifact preregistration validation. |\n| `baseline` | Seeded false-positive controls for anchors and spans across all supported alphabets. |\n| `hypotheses` | Ranked source-grounded hypotheses with facts, assumptions, falsification tests, and risks. |\n| `candidate-sequences` | Pre-registered contextual sequences and score results. |\n| `routes` | Bounded named route experiments with identity, reverse, and seeded-random baselines. |\n| `findings` | Reproducible findings ledger with sources, transformations, baselines, interpretation, and next tests. |\n| `sources` | Source provenance records and allowed-use notes in Markdown or JSON. |\n| `release-check` | Local release preflight results, including no-GitHub-Actions, candidate CSV/registry alignment, and source-packet/source-registry field and latest-access-date alignment gates. |\n| `export-data` | Covered by the source data rendered here; the command writes ciphertext, anchor, and source JSON files. |\n\n",
    );

    output.push_str("## Ciphertext\n\n");
    output.push_str(&format!(
        "- Length: {}\n- Text: `{}`\n\n",
        report.ciphertext_length, report.ciphertext
    ));

    output.push_str("## Known Anchors\n\n");
    output.push_str(
        "| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Source IDs | Confidence | Claim Type | Note |\n",
    );
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for anchor in &report.anchors {
        output.push_str(&format!(
            "| `{}` | `{}` | {}-{} | {}-{} | `{}` | {} | {} | {} |\n",
            anchor.plaintext,
            anchor.ciphertext,
            anchor.start_zero_based,
            anchor.end_zero_based_inclusive,
            anchor.start_one_based(),
            anchor.end_one_based_inclusive(),
            anchor.source_ids.join("`, `"),
            anchor.confidence,
            anchor.claim_type,
            anchor.source_note
        ));
    }

    output.push_str("\n## Known Plaintext Spans\n\n");
    output.push_str("| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Anchors |\n");
    output.push_str("| --- | --- | --- | --- | --- |\n");
    for span in &report.known_plaintext_spans {
        output.push_str(&format!(
            "| `{}` | `{}` | {}-{} | {}-{} | `{}` |\n",
            span.plaintext,
            span.ciphertext,
            span.start_zero_based,
            span.end_zero_based_inclusive,
            span.start_one_based(),
            span.end_one_based_inclusive(),
            span.anchor_plaintexts.join("`, `")
        ));
    }

    output.push_str("\n## Constraint Fragments\n\n");
    render_constraint_group(&mut output, &report.constraints);

    output.push_str("\n## Span Constraint Fragments\n\n");
    render_constraint_group(&mut output, &report.span_constraints);

    output.push_str("## Ranked Hypotheses\n\n");
    for hypothesis in &report.hypotheses {
        output.push_str(&format!(
            "{}. **{} ({})**\n   - Supporting facts: {}\n   - Required assumptions: {}\n   - Test: {}\n   - Risk: {}\n",
            hypothesis.priority,
            hypothesis.name,
            hypothesis.id,
            hypothesis.supporting_facts,
            hypothesis.required_assumptions,
            hypothesis.falsification_test,
            hypothesis.risk
        ));
    }

    output.push_str("\n## Baseline Controls\n\n");
    output.push_str(&format!(
        "{} Target: {}; alphabet: {}; iterations: {}; seed: {}.\n\n",
        report.baseline.note,
        report.baseline.target_scope,
        report.baseline.alphabet_scope,
        report.baseline.iterations,
        report.baseline.seed
    ));
    output.push_str(
        "| Target | Kind | Alphabet | Observed | Triples | Null Mean | Null SD | Empirical P | Adjusted P | Promoted | Warning |\n",
    );
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for result in &report.baseline.results {
        output.push_str(&format!(
            "| {} | {} | {:?} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} | {} |\n",
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
        ));
    }

    output.push_str("\n## Sources\n\n");
    for source in &report.sources {
        output.push_str(&format!(
            "- `{}` [{}]({}) - {}; type: {}; accessed {}; use: {}\n",
            source.id,
            source.label,
            source.url,
            source.use_note,
            source.source_type,
            source.accessed_at,
            source.allowed_use
        ));
    }

    output.push_str("\n## Candidate Sequences\n\n");
    output.push_str(
        "Pre-registered contextual candidates only; no candidate is a claimed solution.\n\n",
    );
    for candidate in &report.candidate_sequences {
        output.push_str(&format!(
            "- `{}` {:?} {:?}: `{}` values={:?} sources=`{}`\n",
            candidate.id,
            candidate.family,
            candidate.transform,
            candidate.raw_material,
            candidate.values,
            candidate.source_ids.join("`, `")
        ));
    }

    output.push_str("\n## Candidate Sequence Scores\n\n");
    output.push_str("| Candidate | Family | Compared Fragments | Exact Mod-26 Matches | Match Rate | Promoted | Note |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for score in &report.candidate_sequence_scores {
        output.push_str(&format!(
            "| `{}` | {:?} | {} | {} | {:.3} | {} | {} |\n",
            score.candidate_id,
            score.family,
            score.compared_fragment_count,
            score.exact_mod26_matches,
            score.match_rate,
            score.promoted_candidate,
            score.note
        ));
    }

    output.push_str("\n## Route Experiments\n\n");
    output.push_str("Exploratory named route screens only; no decryption text is emitted.\n\n");
    for experiment in &report.route_experiments {
        output.push_str(&format!(
            "- {:?} / {}: score={} identity={} reverse={} seeded_random={} promoted={}\n",
            experiment.route,
            experiment.target_label,
            experiment.score,
            experiment.identity_baseline,
            experiment.reverse_baseline,
            experiment.seeded_random_baseline,
            experiment.promoted_candidate
        ));
    }

    output.push_str("\n## Findings Ledger\n\n");
    output.push_str(
        "Findings are reproducible research observations, not promoted solution claims.\n\n",
    );
    for finding in &report.findings {
        output.push_str(&format!(
            "- **{} {} ({})**\n  - Sources: `{}`\n  - Steps: {}\n  - Output: {}\n  - Baseline: {}\n  - Interpretation: {}\n  - Next test: {}\n  - Promoted: {}\n",
            finding.id,
            finding.title,
            finding.related_hypothesis,
            finding.source_inputs.join("`, `"),
            finding.transformation_steps.join("; "),
            finding.output_summary,
            finding.baseline_comparison,
            finding.interpretation,
            finding.next_test,
            finding.promoted_candidate
        ));
    }

    output.push_str("\n## Release Check\n\n");
    output.push_str("Local preflight only. This repo does not use GitHub Actions.\n\n");
    for check in &report.release_checks {
        output.push_str(&format!(
            "- {}: {} ({})\n",
            check.name, check.passed, check.detail
        ));
    }

    output
}

fn render_constraint_group(output: &mut String, constraints: &[ConstraintAnalysis]) {
    for analysis in constraints {
        output.push_str(&format!(
            "### {} / {:?}\n\n",
            analysis.target.label, analysis.alphabet.kind
        ));
        output.push_str("| Pos | P | C | Mode | Value | Symbol |\n");
        output.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for fragment in &analysis.fragments {
            output.push_str(&format!(
                "| {} | `{}` | `{}` | {:?} | {} | `{}` |\n",
                fragment.position_one_based,
                fragment.plaintext,
                fragment.ciphertext,
                fragment.mode,
                fragment.value,
                fragment.symbol
            ));
        }
        output.push_str(&format!(
            "\nRecurrence screen: {}/{} local additive triples matched generic mod-10 recurrence. Expected random matches: {:.1}. Promoted: {}. Warning: {}\n\n",
            analysis.recurrence.gromark_sum_matches, analysis.recurrence.contiguous_pairs_checked
            , analysis.recurrence.expected_random_matches, analysis.recurrence.promoted_candidate, analysis.recurrence.sample_warning
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_report_contains_core_sections() {
        let report = build_report().unwrap();
        let rendered = render_report(&report, ReportFormat::Markdown).unwrap();

        assert!(rendered.contains("## Known Anchors"));
        assert!(rendered.contains("## Known Plaintext Spans"));
        assert!(rendered.contains("## Ranked Hypotheses"));
        assert!(rendered.contains("## Candidate Sequences"));
        assert!(rendered.contains("## Candidate Sequence Scores"));
        assert!(rendered.contains("## Route Experiments"));
        assert!(rendered.contains("## Findings Ledger"));
        assert!(rendered.contains("## Baseline Controls"));
        assert!(rendered.contains("## Release Check"));
        assert!(rendered.contains("Production-readiness scope"));
        assert!(rendered.contains("Source IDs"));
        assert!(rendered.contains("BERLIN"));
    }
}
