use crate::{Alphabet, Anchor, KnownPlaintextSpan, known_anchors, known_plaintext_spans};
use anyhow::{Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentMode {
    AdditiveKey,
    SubtractiveKey,
    BeaufortKey,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConstraintAnalysis {
    pub target: AnalysisTarget,
    pub alphabet: Alphabet,
    pub fragments: Vec<KeyFragment>,
    pub recurrence: RecurrenceScreen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisTarget {
    pub label: String,
    pub plaintext: String,
    pub ciphertext: String,
    pub start_zero_based: usize,
    pub end_zero_based_inclusive: usize,
    pub kind: AnalysisTargetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisTargetKind {
    Anchor,
    Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyFragment {
    pub position_zero_based: usize,
    pub position_one_based: usize,
    pub plaintext: char,
    pub ciphertext: char,
    pub plaintext_index: u8,
    pub ciphertext_index: u8,
    pub mode: FragmentMode,
    pub value: u8,
    pub symbol: char,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RecurrenceScreen {
    pub checked_mode: FragmentMode,
    pub contiguous_pairs_checked: usize,
    pub gromark_sum_matches: usize,
    pub expected_random_matches: f64,
    pub sample_warning: &'static str,
    pub promoted_candidate: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BaselineSummary {
    pub target_label: String,
    pub alphabet_kind: crate::AlphabetKind,
    pub mode: FragmentMode,
    pub observed_matches: usize,
    pub triples_checked: usize,
    pub expected_random_matches: f64,
    pub control_runs: usize,
    pub control_mean_matches: f64,
    pub control_max_matches: usize,
    pub empirical_p_at_least_observed: f64,
    pub promoted_candidate: bool,
    pub interpretation: &'static str,
}

pub fn analyze_constraints() -> Result<Vec<ConstraintAnalysis>> {
    let mut analyses = Vec::new();

    for anchor in known_anchors() {
        for alphabet in Alphabet::all_supported() {
            let target = AnalysisTarget::from_anchor(&anchor);
            let fragments = derive_fragments(&target, &alphabet)?;
            let recurrence = screen_gromark_recurrence(&fragments);
            analyses.push(ConstraintAnalysis {
                target,
                alphabet,
                fragments,
                recurrence,
            });
        }
    }

    Ok(analyses)
}

pub fn analyze_known_plaintext_spans() -> Result<Vec<ConstraintAnalysis>> {
    let mut analyses = Vec::new();

    for span in known_plaintext_spans() {
        for alphabet in Alphabet::all_supported() {
            let target = AnalysisTarget::from_span(&span);
            let fragments = derive_fragments(&target, &alphabet)?;
            let recurrence = screen_gromark_recurrence(&fragments);
            analyses.push(ConstraintAnalysis {
                target,
                alphabet,
                fragments,
                recurrence,
            });
        }
    }

    Ok(analyses)
}

pub fn derive_fragments(target: &AnalysisTarget, alphabet: &Alphabet) -> Result<Vec<KeyFragment>> {
    if target.plaintext.len() != target.ciphertext.len() {
        bail!(
            "plaintext/ciphertext length mismatch for {}: {} vs {}",
            target.label,
            target.plaintext.len(),
            target.ciphertext.len()
        );
    }

    let mut fragments = Vec::new();

    for (offset, (plain, cipher)) in target
        .plaintext
        .chars()
        .zip(target.ciphertext.chars())
        .enumerate()
    {
        let plaintext_index = alphabet.index_of(plain)?;
        let ciphertext_index = alphabet.index_of(cipher)?;
        let position_zero_based = target.start_zero_based + offset;

        for mode in [
            FragmentMode::AdditiveKey,
            FragmentMode::SubtractiveKey,
            FragmentMode::BeaufortKey,
        ] {
            let value = match mode {
                FragmentMode::AdditiveKey => (26 + ciphertext_index - plaintext_index) % 26,
                FragmentMode::SubtractiveKey => (26 + plaintext_index - ciphertext_index) % 26,
                FragmentMode::BeaufortKey => (26 + plaintext_index + ciphertext_index) % 26,
            };

            fragments.push(KeyFragment {
                position_zero_based,
                position_one_based: position_zero_based + 1,
                plaintext: plain,
                ciphertext: cipher,
                plaintext_index,
                ciphertext_index,
                mode,
                value,
                symbol: alphabet.char_at(value)?,
            });
        }
    }

    Ok(fragments)
}

fn screen_gromark_recurrence(fragments: &[KeyFragment]) -> RecurrenceScreen {
    let additive: Vec<&KeyFragment> = fragments
        .iter()
        .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
        .collect();

    let mut contiguous_pairs_checked = 0;
    let mut gromark_sum_matches = 0;

    for window in additive.windows(3) {
        let first = window[0];
        let second = window[1];
        let third = window[2];

        if first.position_zero_based + 1 != second.position_zero_based
            || second.position_zero_based + 1 != third.position_zero_based
        {
            continue;
        }

        contiguous_pairs_checked += 1;
        if (first.value + second.value) % 10 == third.value % 10 {
            gromark_sum_matches += 1;
        }
    }

    let mut notes = vec![format!(
        "Generic adjacent mod-10 recurrence screen over public additive fragments; it is not a Gromark proof or a solve."
    )];
    if contiguous_pairs_checked == 0 {
        notes.push("No contiguous triples available for recurrence screening.".to_string());
    } else {
        notes.push(format!(
            "{gromark_sum_matches} of {contiguous_pairs_checked} contiguous triples match a mod-10 sum recurrence."
        ));
    }

    RecurrenceScreen {
        checked_mode: FragmentMode::AdditiveKey,
        contiguous_pairs_checked,
        gromark_sum_matches,
        expected_random_matches: contiguous_pairs_checked as f64 * 0.1,
        sample_warning: "Exploratory only; do not promote without larger samples and baselines.",
        promoted_candidate: false,
        notes,
    }
}

pub fn baseline_known_plaintext_spans(control_runs: usize) -> Result<Vec<BaselineSummary>> {
    let mut summaries = Vec::new();

    for analysis in analyze_known_plaintext_spans()? {
        let additive_values: Vec<u8> = analysis
            .fragments
            .iter()
            .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
            .map(|fragment| fragment.value)
            .collect();
        let observed_matches = count_mod10_recurrence_matches(&additive_values);
        let triples_checked = additive_values.len().saturating_sub(2);
        let control_counts = deterministic_control_counts(&additive_values, control_runs);
        let control_sum: usize = control_counts.iter().sum();
        let control_mean_matches = if control_counts.is_empty() {
            0.0
        } else {
            control_sum as f64 / control_counts.len() as f64
        };
        let control_max_matches = control_counts.iter().copied().max().unwrap_or(0);
        let at_least_observed = control_counts
            .iter()
            .filter(|count| **count >= observed_matches)
            .count();
        let empirical_p_at_least_observed = if control_counts.is_empty() {
            1.0
        } else {
            at_least_observed as f64 / control_counts.len() as f64
        };

        summaries.push(BaselineSummary {
            target_label: analysis.target.label,
            alphabet_kind: analysis.alphabet.kind,
            mode: FragmentMode::AdditiveKey,
            observed_matches,
            triples_checked,
            expected_random_matches: triples_checked as f64 * 0.1,
            control_runs,
            control_mean_matches,
            control_max_matches,
            empirical_p_at_least_observed,
            promoted_candidate: false,
            interpretation: "Exploratory control only; public-anchor samples are too small to promote a candidate.",
        });
    }

    Ok(summaries)
}

fn deterministic_control_counts(values: &[u8], control_runs: usize) -> Vec<usize> {
    (0..control_runs)
        .map(|run| {
            let mut shuffled = values.to_vec();
            deterministic_shuffle(&mut shuffled, run as u64 + 0xA5A5_5A5A);
            count_mod10_recurrence_matches(&shuffled)
        })
        .collect()
}

fn deterministic_shuffle(values: &mut [u8], mut state: u64) {
    if values.len() < 2 {
        return;
    }

    for index in (1..values.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let swap_with = (state as usize) % (index + 1);
        values.swap(index, swap_with);
    }
}

fn count_mod10_recurrence_matches(values: &[u8]) -> usize {
    values
        .windows(3)
        .filter(|window| (window[0] + window[1]) % 10 == window[2] % 10)
        .count()
}

impl AnalysisTarget {
    pub fn from_anchor(anchor: &Anchor) -> Self {
        Self {
            label: anchor.plaintext.to_string(),
            plaintext: anchor.plaintext.to_string(),
            ciphertext: anchor.ciphertext.to_string(),
            start_zero_based: anchor.start_zero_based,
            end_zero_based_inclusive: anchor.end_zero_based_inclusive,
            kind: AnalysisTargetKind::Anchor,
        }
    }

    pub fn from_span(span: &KnownPlaintextSpan) -> Self {
        Self {
            label: span.plaintext.clone(),
            plaintext: span.plaintext.clone(),
            ciphertext: span.ciphertext.clone(),
            start_zero_based: span.start_zero_based,
            end_zero_based_inclusive: span.end_zero_based_inclusive,
            kind: AnalysisTargetKind::Span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlphabetKind, known_anchors};

    #[test]
    fn derives_three_modes_per_anchor_character() {
        let anchor = known_anchors()
            .into_iter()
            .find(|anchor| anchor.plaintext == "BERLIN")
            .unwrap();
        let target = AnalysisTarget::from_anchor(&anchor);

        let fragments = derive_fragments(&target, &Alphabet::standard()).unwrap();

        assert_eq!(fragments.len(), anchor.len() * 3);
        assert_eq!(fragments[0].position_one_based, 64);
        assert_eq!(fragments[0].mode, FragmentMode::AdditiveKey);
    }

    #[test]
    fn analyzes_every_anchor_against_supported_alphabets() {
        let analyses = analyze_constraints().unwrap();

        assert_eq!(analyses.len(), known_anchors().len() * 3);
        assert!(
            analyses
                .iter()
                .any(|analysis| analysis.alphabet.kind == AlphabetKind::Kryptos)
        );
    }

    #[test]
    fn rejects_mismatched_plaintext_and_ciphertext_lengths() {
        let target = AnalysisTarget {
            label: "bad".to_string(),
            plaintext: "ABC".to_string(),
            ciphertext: "AB".to_string(),
            start_zero_based: 0,
            end_zero_based_inclusive: 2,
            kind: AnalysisTargetKind::Anchor,
        };

        assert!(derive_fragments(&target, &Alphabet::standard()).is_err());
    }

    #[test]
    fn analyzes_adjacent_known_plaintext_spans() {
        let analyses = analyze_known_plaintext_spans().unwrap();

        assert!(analyses.iter().any(|analysis| {
            analysis.target.kind == AnalysisTargetKind::Span
                && analysis.target.label == "EASTNORTHEAST"
        }));
        assert!(analyses.iter().all(|analysis| {
            !analysis.recurrence.promoted_candidate
                && analysis.recurrence.sample_warning.contains("Exploratory")
        }));
    }

    #[test]
    fn baseline_never_promotes_tiny_public_span_samples() {
        let summaries = baseline_known_plaintext_spans(16).unwrap();

        assert_eq!(
            summaries.len(),
            analyze_known_plaintext_spans().unwrap().len()
        );
        assert!(summaries.iter().all(|summary| !summary.promoted_candidate));
        assert!(
            summaries
                .iter()
                .all(|summary| summary.interpretation.contains("too small"))
        );
    }
}
