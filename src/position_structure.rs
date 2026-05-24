use crate::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, FragmentMode, analyze_constraints,
    analyze_known_plaintext_spans,
};
use anyhow::{Result, bail};
use rand::seq::SliceRandom;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::Serialize;
use std::collections::HashMap;

const MIN_FRAGMENTS_FOR_PROMOTION: usize = 20;
const DEFAULT_MIN_MODULUS: usize = 2;
const DEFAULT_MAX_MODULUS: usize = 13;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PositionStructureRun {
    pub target_scope: &'static str,
    pub alphabet_scope: &'static str,
    pub fragment_mode: FragmentMode,
    pub min_modulus: usize,
    pub max_modulus: usize,
    pub iterations: usize,
    pub seed: u64,
    pub results: Vec<PositionStructureResult>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PositionStructureResult {
    pub target_label: String,
    pub target_kind: &'static str,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub fragment_count: usize,
    pub repeated_value_pairs: usize,
    pub best_modulus: usize,
    pub observed_residue_score: usize,
    pub observed_spacing_hits: usize,
    pub observed_composite_score: i64,
    pub null_mean_composite_score: f64,
    pub null_std_dev_composite_score: f64,
    pub empirical_p_value: f64,
    pub adjusted_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub modulus_results: Vec<PositionModulusScore>,
    pub source_inputs: String,
    pub transformation_steps: &'static str,
    pub output_summary: String,
    pub baseline_comparison: String,
    pub meaningfulness: &'static str,
    pub next_test: &'static str,
    pub warning: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PositionModulusScore {
    pub modulus: usize,
    pub residue_score: usize,
    pub spacing_hits: usize,
    pub composite_score: i64,
}

pub fn run_position_structure_control(
    target_scope: BaselineTargetScope,
    alphabet_scope: BaselineAlphabetScope,
    fragment_mode: FragmentMode,
    iterations: usize,
    seed: u64,
) -> Result<PositionStructureRun> {
    if iterations == 0 {
        bail!("position-structure iterations must be greater than zero");
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
            fragment_mode,
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
            fragment_mode,
            iterations,
            seed,
        );
    }

    apply_holm_adjustment(&mut results);
    for result in &mut results {
        result.promoted_candidate = false;
    }

    Ok(PositionStructureRun {
        target_scope: target_scope.label(),
        alphabet_scope: alphabet_scope.label(),
        fragment_mode,
        min_modulus: DEFAULT_MIN_MODULUS,
        max_modulus: DEFAULT_MAX_MODULUS,
        iterations,
        seed,
        results,
        promoted_candidate: false,
        note: "Position-structure output is a candidate-independent control over public fragments; it is not a claimed solution.",
    })
}

fn push_results(
    results: &mut Vec<PositionStructureResult>,
    analyses: Vec<crate::ConstraintAnalysis>,
    target_kind: &'static str,
    alphabet_scope: BaselineAlphabetScope,
    fragment_mode: FragmentMode,
    iterations: usize,
    seed: u64,
) {
    for analysis in analyses {
        if !alphabet_scope.allows(analysis.alphabet.kind) {
            continue;
        }

        let fragments: Vec<_> = analysis
            .fragments
            .iter()
            .filter(|fragment| fragment.mode == fragment_mode)
            .collect();
        let positions: Vec<usize> = fragments
            .iter()
            .map(|fragment| fragment.position_zero_based)
            .collect();
        let values: Vec<u8> = fragments.iter().map(|fragment| fragment.value).collect();
        let modulus_results = score_all_moduli(&positions, &values);
        let best = best_modulus_score(&modulus_results);
        let null_scores = null_distribution(&positions, &values, iterations, seed);
        let null_mean = mean_i64(&null_scores);
        let null_std_dev = std_dev_i64(&null_scores, null_mean);
        let at_least_observed = null_scores
            .iter()
            .filter(|score| **score >= best.composite_score)
            .count();
        let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);
        let repeated_value_pairs = count_repeated_value_pairs(&values);
        let target_label = analysis.target.label;

        results.push(PositionStructureResult {
            target_label: target_label.clone(),
            target_kind,
            alphabet: analysis.alphabet.kind,
            fragment_mode,
            fragment_count: values.len(),
            repeated_value_pairs,
            best_modulus: best.modulus,
            observed_residue_score: best.residue_score,
            observed_spacing_hits: best.spacing_hits,
            observed_composite_score: best.composite_score,
            null_mean_composite_score: null_mean,
            null_std_dev_composite_score: null_std_dev,
            empirical_p_value,
            adjusted_p_value: 1.0,
            iterations,
            seed,
            promoted_candidate: false,
            modulus_results,
            source_inputs: format!(
                "target={} target_kind={} alphabet={:?} fragment_mode={:?}",
                target_label, target_kind, analysis.alphabet.kind, fragment_mode
            ),
            transformation_steps: "Keep public fragment positions fixed, derive candidate-independent residue/spacing scores by modulus, then compare the best observed modulus against seeded shuffles of the same values.",
            output_summary: format!(
                "best_modulus={} observed_composite_score={} empirical_p_value={:.4} adjusted_p_value_pending",
                best.modulus, best.composite_score, empirical_p_value
            ),
            baseline_comparison: format!(
                "null_mean_composite_score={:.4} null_std_dev={:.4} iterations={} seed={}",
                null_mean, null_std_dev, iterations, seed
            ),
            meaningfulness: "Candidate-independent structure control only; a low p-value would motivate a separate pre-registered structural model, not promote plaintext.",
            next_test: next_test_for_sample(values.len()),
            warning: warning_for_sample(values.len()),
        });
    }
}

fn score_all_moduli(positions: &[usize], values: &[u8]) -> Vec<PositionModulusScore> {
    (DEFAULT_MIN_MODULUS..=DEFAULT_MAX_MODULUS)
        .map(|modulus| score_modulus(positions, values, modulus))
        .collect()
}

fn score_modulus(positions: &[usize], values: &[u8], modulus: usize) -> PositionModulusScore {
    let residue_score = residue_concentration_score(positions, values, modulus);
    let spacing_hits = repeated_value_spacing_hits(positions, values, modulus);
    PositionModulusScore {
        modulus,
        residue_score,
        spacing_hits,
        composite_score: residue_score as i64 * 10 + spacing_hits as i64 * 3,
    }
}

fn residue_concentration_score(positions: &[usize], values: &[u8], modulus: usize) -> usize {
    let mut residue_counts: Vec<HashMap<u8, usize>> =
        (0..modulus).map(|_| HashMap::new()).collect();
    for (position, value) in positions.iter().zip(values) {
        *residue_counts[*position % modulus]
            .entry(*value)
            .or_insert(0) += 1;
    }

    residue_counts
        .iter()
        .map(|counts| counts.values().copied().max().unwrap_or(1) - 1)
        .sum()
}

fn repeated_value_spacing_hits(positions: &[usize], values: &[u8], modulus: usize) -> usize {
    let mut hits = 0;
    for left in 0..values.len() {
        for right in (left + 1)..values.len() {
            if values[left] == values[right]
                && (positions[right] - positions[left]).is_multiple_of(modulus)
            {
                hits += 1;
            }
        }
    }
    hits
}

fn count_repeated_value_pairs(values: &[u8]) -> usize {
    let mut pairs = 0;
    for left in 0..values.len() {
        for right in (left + 1)..values.len() {
            if values[left] == values[right] {
                pairs += 1;
            }
        }
    }
    pairs
}

fn best_modulus_score(scores: &[PositionModulusScore]) -> PositionModulusScore {
    scores
        .iter()
        .max_by(|left, right| {
            left.composite_score
                .cmp(&right.composite_score)
                .then_with(|| right.modulus.cmp(&left.modulus))
        })
        .expect("modulus range is non-empty")
        .clone()
}

fn null_distribution(positions: &[usize], values: &[u8], iterations: usize, seed: u64) -> Vec<i64> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    (0..iterations)
        .map(|_| {
            let mut shuffled = values.to_vec();
            shuffled.shuffle(&mut rng);
            best_modulus_score(&score_all_moduli(positions, &shuffled)).composite_score
        })
        .collect()
}

fn mean_i64(values: &[i64]) -> f64 {
    values.iter().sum::<i64>() as f64 / values.len() as f64
}

fn std_dev_i64(values: &[i64], mean: f64) -> f64 {
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

fn apply_holm_adjustment(results: &mut [PositionStructureResult]) {
    let mut indexed: Vec<(usize, f64)> = results
        .iter()
        .enumerate()
        .map(|(index, result)| (index, result.empirical_p_value))
        .collect();
    indexed.sort_by(|left, right| left.1.total_cmp(&right.1));

    let total = indexed.len();
    let mut previous = 0.0_f64;
    for (rank, (index, p_value)) in indexed.into_iter().enumerate() {
        let adjusted = (p_value * (total - rank) as f64).clamp(previous, 1.0);
        results[index].adjusted_p_value = adjusted;
        previous = adjusted;
    }
}

fn warning_for_sample(fragment_count: usize) -> &'static str {
    if fragment_count < MIN_FRAGMENTS_FOR_PROMOTION {
        "Underpowered public-fragment sample; never promote from this result."
    } else {
        "Exploratory public-fragment structure screen; requires independent prediction."
    }
}

fn next_test_for_sample(fragment_count: usize) -> &'static str {
    if fragment_count < MIN_FRAGMENTS_FOR_PROMOTION {
        "Treat as a diagnostic only; define a separate structural model and held-out prediction before follow-up."
    } else {
        "Pre-register the strongest residue/spacing model and test it on independent public structure without retuning."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residue_score_rewards_same_value_same_residue() {
        let positions = [0, 2, 4, 1, 3];
        let values = [7, 7, 7, 1, 2];
        let score = score_modulus(&positions, &values, 2);

        assert_eq!(score.residue_score, 2);
        assert_eq!(score.spacing_hits, 3);
        assert_eq!(score.composite_score, 29);
    }

    #[test]
    fn position_structure_control_is_seeded_and_non_promotional() {
        let run = run_position_structure_control(
            BaselineTargetScope::Spans,
            BaselineAlphabetScope::Kryptos,
            FragmentMode::AdditiveKey,
            20,
            67,
        )
        .unwrap();

        assert_eq!(run.target_scope, "spans");
        assert_eq!(run.alphabet_scope, "kryptos");
        assert!(!run.promoted_candidate);
        assert!(run.results.iter().all(|result| !result.promoted_candidate));
        assert!(run.results.iter().all(|result| result.iterations == 20));
        assert!(
            run.results
                .iter()
                .all(|result| result.best_modulus >= 2 && result.best_modulus <= 13)
        );
    }
}
