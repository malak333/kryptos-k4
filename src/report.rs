use crate::{
    ConstraintAnalysis, K4_CIPHERTEXT, analyze_constraints, hypotheses, known_anchors, sources,
};
use anyhow::Result;
use serde::Serialize;

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
    pub sources: Vec<crate::Source>,
    pub constraints: Vec<ConstraintAnalysis>,
    pub hypotheses: Vec<crate::Hypothesis>,
}

pub fn build_report() -> Result<Report> {
    Ok(Report {
        ciphertext: K4_CIPHERTEXT,
        ciphertext_length: K4_CIPHERTEXT.len(),
        anchors: known_anchors(),
        sources: sources(),
        constraints: analyze_constraints()?,
        hypotheses: hypotheses(),
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
    output.push_str("This report uses public anchors only and is not a claimed solution.\n\n");
    output.push_str("## Ciphertext\n\n");
    output.push_str(&format!(
        "- Length: {}\n- Text: `{}`\n\n",
        report.ciphertext_length, report.ciphertext
    ));

    output.push_str("## Known Anchors\n\n");
    output.push_str("| Plaintext | Ciphertext | 0-Based Range | 1-Based Range |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for anchor in &report.anchors {
        output.push_str(&format!(
            "| `{}` | `{}` | {}-{} | {}-{} |\n",
            anchor.plaintext,
            anchor.ciphertext,
            anchor.start_zero_based,
            anchor.end_zero_based_inclusive,
            anchor.start_one_based(),
            anchor.end_one_based_inclusive()
        ));
    }

    output.push_str("\n## Constraint Fragments\n\n");
    for analysis in &report.constraints {
        output.push_str(&format!(
            "### {} / {:?}\n\n",
            analysis.anchor.plaintext, analysis.alphabet.kind
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
            "\nRecurrence screen: {}/{} local additive triples matched mod-10 recurrence.\n\n",
            analysis.recurrence.gromark_sum_matches, analysis.recurrence.contiguous_pairs_checked
        ));
    }

    output.push_str("## Ranked Hypotheses\n\n");
    for hypothesis in &report.hypotheses {
        output.push_str(&format!(
            "{}. **{} ({})**\n   - Test: {}\n   - Risk: {}\n",
            hypothesis.priority,
            hypothesis.name,
            hypothesis.id,
            hypothesis.falsification_test,
            hypothesis.risk
        ));
    }

    output.push_str("\n## Sources\n\n");
    for source in &report.sources {
        output.push_str(&format!(
            "- [{}]({}) - {}\n",
            source.label, source.url, source.use_note
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_report_contains_core_sections() {
        let report = build_report().unwrap();
        let rendered = render_report(&report, ReportFormat::Markdown).unwrap();

        assert!(rendered.contains("## Known Anchors"));
        assert!(rendered.contains("## Ranked Hypotheses"));
        assert!(rendered.contains("BERLIN"));
    }
}
