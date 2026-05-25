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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StructuralModelRun {
    pub target_scope: &'static str,
    pub alphabet_scope: &'static str,
    pub fragment_mode: FragmentMode,
    pub iterations: usize,
    pub seed: u64,
    pub model_count: usize,
    pub results: Vec<StructuralModelResult>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StructuralModelResult {
    pub model_id: &'static str,
    pub model_label: &'static str,
    pub model_kind: &'static str,
    pub period: usize,
    pub rationale: &'static str,
    pub target_count: usize,
    pub fragment_count: usize,
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
    pub source_inputs: String,
    pub transformation_steps: &'static str,
    pub output_summary: String,
    pub baseline_comparison: String,
    pub meaningfulness: &'static str,
    pub next_test: &'static str,
    pub warning: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StructuralModel {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: &'static str,
    pub period: usize,
    pub rationale: &'static str,
}

#[derive(Debug, Clone)]
struct ScoringTarget {
    label: String,
    kind: &'static str,
    alphabet: AlphabetKind,
    positions: Vec<usize>,
    values: Vec<u8>,
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

pub fn run_structural_model_control(
    target_scope: BaselineTargetScope,
    alphabet_scope: BaselineAlphabetScope,
    fragment_mode: FragmentMode,
    iterations: usize,
    seed: u64,
) -> Result<StructuralModelRun> {
    if iterations == 0 {
        bail!("structural-models iterations must be greater than zero");
    }

    let targets = scoring_targets(target_scope, alphabet_scope, fragment_mode)?;
    let models = registered_structural_models();
    let mut results: Vec<_> = models
        .iter()
        .map(|model| score_structural_model(model, &targets, fragment_mode, iterations, seed))
        .collect();
    apply_model_holm_adjustment(&mut results);
    for result in &mut results {
        result.promoted_candidate = false;
    }

    Ok(StructuralModelRun {
        target_scope: target_scope.label(),
        alphabet_scope: alphabet_scope.label(),
        fragment_mode,
        iterations,
        seed,
        model_count: models.len(),
        results,
        promoted_candidate: false,
        note: "Structural-model output evaluates pre-registered position models against public fragments; it is not a claimed solution.",
    })
}

pub fn registered_structural_models() -> Vec<StructuralModel> {
    vec![
        StructuralModel {
            id: "period-2-parity",
            label: "Period 2 parity residues",
            kind: "periodic-residue",
            period: 2,
            rationale: "Smallest nontrivial alternating-position structure; independent of candidate key words.",
        },
        StructuralModel {
            id: "period-3-triad",
            label: "Period 3 triad residues",
            kind: "periodic-residue",
            period: 3,
            rationale: "Small periodic stream structure compatible with matrix or recurrence-style hypotheses.",
        },
        StructuralModel {
            id: "period-4-tetrad",
            label: "Period 4 tetrad residues",
            kind: "periodic-residue",
            period: 4,
            rationale: "Bounded four-lane position model often used as a compact transposition/control baseline.",
        },
        StructuralModel {
            id: "period-5-pentad",
            label: "Period 5 pentad residues",
            kind: "periodic-residue",
            period: 5,
            rationale: "Five-lane periodic model included as a small matrix-width control before seeing fragment values.",
        },
        StructuralModel {
            id: "period-7-heptad",
            label: "Period 7 heptad residues",
            kind: "periodic-residue",
            period: 7,
            rationale: "Seven-lane periodic model included as a medium-width matrix/control hypothesis.",
        },
        StructuralModel {
            id: "period-8-octad",
            label: "Period 8 octad residues",
            kind: "periodic-residue",
            period: 8,
            rationale: "Eight-lane periodic model included as a byte/octant-style structural control.",
        },
        StructuralModel {
            id: "period-13-span-width",
            label: "Period 13 span-width residues",
            kind: "periodic-residue",
            period: 13,
            rationale: "Thirteen-lane model pre-registered as a bounded span/grid-width check, not inferred from key material.",
        },
    ]
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

fn scoring_targets(
    target_scope: BaselineTargetScope,
    alphabet_scope: BaselineAlphabetScope,
    fragment_mode: FragmentMode,
) -> Result<Vec<ScoringTarget>> {
    let mut targets = Vec::new();
    if matches!(
        target_scope,
        BaselineTargetScope::Anchors | BaselineTargetScope::All
    ) {
        push_scoring_targets(
            &mut targets,
            analyze_constraints()?,
            "anchor",
            alphabet_scope,
            fragment_mode,
        );
    }
    if matches!(
        target_scope,
        BaselineTargetScope::Spans | BaselineTargetScope::All
    ) {
        push_scoring_targets(
            &mut targets,
            analyze_known_plaintext_spans()?,
            "span",
            alphabet_scope,
            fragment_mode,
        );
    }
    Ok(targets)
}

fn push_scoring_targets(
    targets: &mut Vec<ScoringTarget>,
    analyses: Vec<crate::ConstraintAnalysis>,
    target_kind: &'static str,
    alphabet_scope: BaselineAlphabetScope,
    fragment_mode: FragmentMode,
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
        targets.push(ScoringTarget {
            label: analysis.target.label,
            kind: target_kind,
            alphabet: analysis.alphabet.kind,
            positions: fragments
                .iter()
                .map(|fragment| fragment.position_zero_based)
                .collect(),
            values: fragments.iter().map(|fragment| fragment.value).collect(),
        });
    }
}

fn score_structural_model(
    model: &StructuralModel,
    targets: &[ScoringTarget],
    fragment_mode: FragmentMode,
    iterations: usize,
    seed: u64,
) -> StructuralModelResult {
    let observed = score_model_targets(model, targets);
    let null_scores = model_null_distribution(model, targets, iterations, seed);
    let null_mean = mean_i64(&null_scores);
    let null_std_dev = std_dev_i64(&null_scores, null_mean);
    let at_least_observed = null_scores
        .iter()
        .filter(|score| **score >= observed.composite_score)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);
    let fragment_count = targets.iter().map(|target| target.values.len()).sum();
    let target_summary = summarize_targets(targets);

    StructuralModelResult {
        model_id: model.id,
        model_label: model.label,
        model_kind: model.kind,
        period: model.period,
        rationale: model.rationale,
        target_count: targets.len(),
        fragment_count,
        observed_residue_score: observed.residue_score,
        observed_spacing_hits: observed.spacing_hits,
        observed_composite_score: observed.composite_score,
        null_mean_composite_score: null_mean,
        null_std_dev_composite_score: null_std_dev,
        empirical_p_value,
        adjusted_p_value: 1.0,
        iterations,
        seed,
        promoted_candidate: false,
        source_inputs: format!(
            "model={} period={} fragment_mode={:?} targets={}",
            model.id, model.period, fragment_mode, target_summary
        ),
        transformation_steps: "Apply a pre-registered period model to fixed public fragment positions, score value concentration and same-value spacing inside predicted residue classes, then compare against seeded value shuffles.",
        output_summary: format!(
            "period={} observed_composite_score={} empirical_p_value={:.4} adjusted_p_value_pending",
            model.period, observed.composite_score, empirical_p_value
        ),
        baseline_comparison: format!(
            "null_mean_composite_score={:.4} null_std_dev={:.4} iterations={} seed={}",
            null_mean, null_std_dev, iterations, seed
        ),
        meaningfulness: "Pre-registered structural-model control only; a low p-value would justify a separate held-out structural prediction, not a plaintext or key claim.",
        next_test: next_test_for_sample(fragment_count),
        warning: warning_for_sample(fragment_count),
    }
}

fn summarize_targets(targets: &[ScoringTarget]) -> String {
    targets
        .iter()
        .map(|target| format!("{}:{:?}:{}", target.label, target.alphabet, target.kind))
        .collect::<Vec<_>>()
        .join("|")
}

fn score_model_targets(model: &StructuralModel, targets: &[ScoringTarget]) -> PositionModulusScore {
    let mut aggregate = PositionModulusScore {
        modulus: model.period,
        residue_score: 0,
        spacing_hits: 0,
        composite_score: 0,
    };
    for target in targets {
        let score = score_modulus(&target.positions, &target.values, model.period);
        aggregate.residue_score += score.residue_score;
        aggregate.spacing_hits += score.spacing_hits;
        aggregate.composite_score += score.composite_score;
    }
    aggregate
}

fn model_null_distribution(
    model: &StructuralModel,
    targets: &[ScoringTarget],
    iterations: usize,
    seed: u64,
) -> Vec<i64> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    (0..iterations)
        .map(|_| {
            targets
                .iter()
                .map(|target| {
                    let mut shuffled = target.values.clone();
                    shuffled.shuffle(&mut rng);
                    score_modulus(&target.positions, &shuffled, model.period).composite_score
                })
                .sum()
        })
        .collect()
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

fn apply_model_holm_adjustment(results: &mut [StructuralModelResult]) {
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

    #[test]
    fn structural_model_control_scores_registered_models_without_promotion() {
        let run = run_structural_model_control(
            BaselineTargetScope::Spans,
            BaselineAlphabetScope::Kryptos,
            FragmentMode::AdditiveKey,
            20,
            67,
        )
        .unwrap();

        assert_eq!(run.model_count, registered_structural_models().len());
        assert!(!run.promoted_candidate);
        assert!(run.results.iter().all(|result| !result.promoted_candidate));
        assert!(
            run.results
                .iter()
                .any(|result| result.model_id == "period-3-triad")
        );
        assert!(
            run.results
                .iter()
                .all(|result| result.source_inputs.contains("targets="))
        );
    }
}
