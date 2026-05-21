use crate::{AlphabetKind, FragmentMode, analyze_constraints, analyze_known_plaintext_spans};
use anyhow::{Result, bail};
use rand::seq::SliceRandom;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::Serialize;

const MIN_TRIPLES_FOR_PROMOTION: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineTargetScope {
    Anchors,
    Spans,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineAlphabetScope {
    Standard,
    Kryptos,
    KryptosReversed,
    All,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BaselineRun {
    pub target_scope: &'static str,
    pub alphabet_scope: &'static str,
    pub iterations: usize,
    pub seed: u64,
    pub results: Vec<BaselineResult>,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BaselineResult {
    pub target_label: String,
    pub target_kind: &'static str,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub observed_matches: usize,
    pub triples_checked: usize,
    pub null_mean: f64,
    pub null_std_dev: f64,
    pub empirical_p_value: f64,
    pub adjusted_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub source_inputs: String,
    pub transformation_steps: &'static str,
    pub output_summary: String,
    pub baseline_comparison: String,
    pub meaningfulness: &'static str,
    pub next_test: &'static str,
    pub warning: &'static str,
}

pub fn run_baseline(
    target_scope: BaselineTargetScope,
    alphabet_scope: BaselineAlphabetScope,
    iterations: usize,
    seed: u64,
) -> Result<BaselineRun> {
    if iterations == 0 {
        bail!("baseline iterations must be greater than zero");
    }

    let mut results = Vec::new();
    if matches!(
        target_scope,
        BaselineTargetScope::Anchors | BaselineTargetScope::All
    ) {
        push_results(
            &mut results,
            analyze_constraints()?,
            "anchor",
            alphabet_scope,
            iterations,
            seed,
        );
    }
    if matches!(
        target_scope,
        BaselineTargetScope::Spans | BaselineTargetScope::All
    ) {
        push_results(
            &mut results,
            analyze_known_plaintext_spans()?,
            "span",
            alphabet_scope,
            iterations,
            seed,
        );
    }

    apply_holm_adjustment(&mut results);
    for result in &mut results {
        result.promoted_candidate = false;
    }

    Ok(BaselineRun {
        target_scope: target_scope.label(),
        alphabet_scope: alphabet_scope.label(),
        iterations,
        seed,
        results,
        note: "Baseline output is a false-positive control, not a claimed solution.",
    })
}

fn push_results(
    results: &mut Vec<BaselineResult>,
    analyses: Vec<crate::ConstraintAnalysis>,
    target_kind: &'static str,
    alphabet_scope: BaselineAlphabetScope,
    iterations: usize,
    seed: u64,
) {
    for analysis in analyses {
        if !alphabet_scope.allows(analysis.alphabet.kind) {
            continue;
        }

        let values: Vec<u8> = analysis
            .fragments
            .iter()
            .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
            .map(|fragment| fragment.value % 10)
            .collect();
        let observed_matches = count_mod10_matches(&values);
        let triples_checked = values.len().saturating_sub(2);
        let null_counts = null_distribution(&values, iterations, seed);
        let null_mean = mean(&null_counts);
        let null_std_dev = std_dev(&null_counts, null_mean);
        let at_least_observed = null_counts
            .iter()
            .filter(|count| **count >= observed_matches)
            .count();
        let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);
        let target_label = analysis.target.label;

        results.push(BaselineResult {
            target_label: target_label.clone(),
            target_kind,
            alphabet: analysis.alphabet.kind,
            fragment_mode: FragmentMode::AdditiveKey,
            observed_matches,
            triples_checked,
            null_mean,
            null_std_dev,
            empirical_p_value,
            adjusted_p_value: 1.0,
            iterations,
            seed,
            promoted_candidate: false,
            source_inputs: format!(
                "target={} target_kind={} alphabet={:?} fragment_mode={:?}",
                target_label,
                target_kind,
                analysis.alphabet.kind,
                FragmentMode::AdditiveKey
            ),
            transformation_steps: "Take public additive-key fragments modulo 10, count local a+b=c mod-10 triples, and compare against seeded shuffles of the same values.",
            output_summary: format!(
                "observed_matches={} triples_checked={} empirical_p_value={:.4} adjusted_p_value_pending",
                observed_matches, triples_checked, empirical_p_value
            ),
            baseline_comparison: format!(
                "null_mean={:.4} null_std_dev={:.4} iterations={} seed={}",
                null_mean, null_std_dev, iterations, seed
            ),
            meaningfulness: "False-positive control only; low p-values on public-anchor samples are insufficient to promote a candidate without independent prediction.",
            next_test: next_test_for_sample(triples_checked),
            warning: warning_for_sample(triples_checked),
        });
    }
}

fn null_distribution(values: &[u8], iterations: usize, seed: u64) -> Vec<usize> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    (0..iterations)
        .map(|_| {
            let mut shuffled = values.to_vec();
            shuffled.shuffle(&mut rng);
            count_mod10_matches(&shuffled)
        })
        .collect()
}

fn count_mod10_matches(values: &[u8]) -> usize {
    values
        .windows(3)
        .filter(|window| (window[0] + window[1]) % 10 == window[2] % 10)
        .count()
}

fn mean(values: &[usize]) -> f64 {
    values.iter().sum::<usize>() as f64 / values.len() as f64
}

fn std_dev(values: &[usize], mean: f64) -> f64 {
    let variance = values
        .iter()
        .map(|value| {
            let delta = *value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

fn apply_holm_adjustment(results: &mut [BaselineResult]) {
    let mut indexed: Vec<(usize, f64)> = results
        .iter()
        .enumerate()
        .map(|(index, result)| (index, result.empirical_p_value))
        .collect();
    indexed.sort_by(|left, right| left.1.total_cmp(&right.1));

    let family_size = indexed.len();
    let mut running_max: f64 = 0.0;
    for (rank, (index, p_value)) in indexed.into_iter().enumerate() {
        let adjusted = (p_value * (family_size - rank) as f64).min(1.0);
        running_max = running_max.max(adjusted);
        results[index].adjusted_p_value = running_max;
        results[index].output_summary = format!(
            "observed_matches={} triples_checked={} empirical_p_value={:.4} adjusted_p_value={:.4}",
            results[index].observed_matches,
            results[index].triples_checked,
            results[index].empirical_p_value,
            results[index].adjusted_p_value
        );
    }
}

fn warning_for_sample(triples_checked: usize) -> &'static str {
    if triples_checked < MIN_TRIPLES_FOR_PROMOTION {
        "Underpowered public-anchor sample; never promote from this result."
    } else {
        "Exploratory only; promotion requires independent corroboration."
    }
}

fn next_test_for_sample(triples_checked: usize) -> &'static str {
    if triples_checked < MIN_TRIPLES_FOR_PROMOTION {
        "Do not expand from this sample; gather a larger pre-registered public fragment set or use this only as a caveated control."
    } else {
        "Pre-register an independent prediction target, then rerun seeded controls before evaluating any candidate mechanism."
    }
}

impl BaselineTargetScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Anchors => "anchors",
            Self::Spans => "spans",
            Self::All => "all",
        }
    }
}

impl BaselineAlphabetScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Kryptos => "kryptos",
            Self::KryptosReversed => "kryptos-reversed",
            Self::All => "all",
        }
    }

    fn allows(self, alphabet: AlphabetKind) -> bool {
        match self {
            Self::Standard => alphabet == AlphabetKind::Standard,
            Self::Kryptos => alphabet == AlphabetKind::Kryptos,
            Self::KryptosReversed => alphabet == AlphabetKind::KryptosReversed,
            Self::All => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_baseline_is_deterministic() {
        let first = run_baseline(
            BaselineTargetScope::Spans,
            BaselineAlphabetScope::All,
            100,
            42,
        )
        .unwrap();
        let second = run_baseline(
            BaselineTargetScope::Spans,
            BaselineAlphabetScope::All,
            100,
            42,
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn empirical_p_value_uses_add_one_smoothing() {
        let run = run_baseline(
            BaselineTargetScope::Spans,
            BaselineAlphabetScope::Standard,
            10,
            42,
        )
        .unwrap();

        assert!(
            run.results
                .iter()
                .all(|result| result.empirical_p_value > 0.0)
        );
    }

    #[test]
    fn holm_adjustment_preserves_original_order() {
        let run =
            run_baseline(BaselineTargetScope::All, BaselineAlphabetScope::All, 20, 7).unwrap();

        assert_eq!(run.results[0].target_label, "EAST");
        assert!(
            run.results
                .iter()
                .all(|result| result.adjusted_p_value >= result.empirical_p_value)
        );
    }

    #[test]
    fn baseline_results_include_findings_ledger_and_next_test_boundaries() {
        let run = run_baseline(
            BaselineTargetScope::Spans,
            BaselineAlphabetScope::Standard,
            20,
            42,
        )
        .unwrap();

        for result in run.results {
            assert!(result.source_inputs.contains(&result.target_label));
            assert!(result.transformation_steps.contains("seeded shuffles"));
            assert!(result.output_summary.contains("adjusted_p_value="));
            assert!(result.baseline_comparison.contains("null_mean="));
            assert!(result.meaningfulness.contains("False-positive control"));
            assert!(
                result.next_test.contains("pre-registered") || result.next_test.contains("larger")
            );
        }
    }
}
