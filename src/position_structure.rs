use crate::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, FragmentMode, K4_CIPHERTEXT,
    analyze_constraints, analyze_known_plaintext_spans, known_anchors,
};
use anyhow::{Result, bail};
use rand::seq::SliceRandom;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeriodPredictionPlan {
    pub period: usize,
    pub non_anchor_position_count: usize,
    pub anchor_position_count: usize,
    pub residues: Vec<PeriodResiduePrediction>,
    pub promoted_candidate: bool,
    pub source_inputs: String,
    pub prediction_rule: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeriodPredictionPlanSet {
    pub period_count: usize,
    pub plans: Vec<PeriodPredictionPlan>,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeriodResiduePrediction {
    pub residue: usize,
    pub position_count: usize,
    pub positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpacingPredictionPlanSet {
    pub modulus_count: usize,
    pub plans: Vec<SpacingPredictionPlan>,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpacingPredictionPlan {
    pub modulus: usize,
    pub non_anchor_position_count: usize,
    pub anchor_position_count: usize,
    pub positions_one_based: Vec<usize>,
    pub residues: Vec<SpacingResiduePrediction>,
    pub promoted_candidate: bool,
    pub source_inputs: String,
    pub prediction_rule: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpacingResiduePrediction {
    pub residue: usize,
    pub pair_count: usize,
    pub sample_pairs_one_based: Vec<[usize; 2]>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeriodPredictionEvaluation {
    pub artifact_path: String,
    pub observation_id: Option<String>,
    pub observation_source_ids: Vec<String>,
    pub observation_rationale: Option<String>,
    pub observation_position_notes: BTreeMap<String, String>,
    pub source_backed_observation: bool,
    pub observation_warning: Option<&'static str>,
    pub observed_position_count: usize,
    pub observed_positions_one_based: Vec<usize>,
    pub best_period: usize,
    pub best_residue: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub null_mean_best_hits: f64,
    pub null_std_dev_best_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub period_results: Vec<PeriodPredictionEvaluationResult>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeriodPredictionEvaluationResult {
    pub period: usize,
    pub best_residue: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub residue_hits: Vec<PeriodResidueHit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeriodResidueHit {
    pub residue: usize,
    pub hits: usize,
    pub matching_positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpacingPredictionEvaluation {
    pub artifact_path: String,
    pub observation_id: Option<String>,
    pub observation_source_ids: Vec<String>,
    pub observation_rationale: Option<String>,
    pub observation_position_notes: BTreeMap<String, String>,
    pub source_backed_observation: bool,
    pub observation_warning: Option<&'static str>,
    pub observed_position_count: usize,
    pub observed_pair_count: usize,
    pub observed_positions_one_based: Vec<usize>,
    pub best_modulus: usize,
    pub best_residue: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub null_mean_best_hits: f64,
    pub null_std_dev_best_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub modulus_results: Vec<SpacingPredictionEvaluationResult>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpacingPredictionEvaluationResult {
    pub modulus: usize,
    pub best_residue: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub residue_hits: Vec<SpacingResidueHit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpacingResidueHit {
    pub residue: usize,
    pub hits: usize,
    pub matching_pairs_one_based: Vec<[usize; 2]>,
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

fn anchor_position_set() -> HashSet<usize> {
    known_anchors()
        .iter()
        .flat_map(|anchor| anchor.start_zero_based..=anchor.end_zero_based_inclusive)
        .collect()
}

fn non_anchor_positions_one_based(anchor_positions: &HashSet<usize>) -> Vec<usize> {
    (0..K4_CIPHERTEXT.len())
        .filter(|position| !anchor_positions.contains(position))
        .map(|position| position + 1)
        .collect()
}

pub fn build_period_prediction_plan(period: usize) -> Result<PeriodPredictionPlan> {
    if !registered_structural_models()
        .iter()
        .any(|model| model.period == period)
    {
        bail!("period must be one of the registered structural model periods");
    }

    let anchor_positions = anchor_position_set();
    let non_anchor_positions: Vec<usize> = (0..K4_CIPHERTEXT.len())
        .filter(|position| !anchor_positions.contains(position))
        .collect();
    let mut residues: Vec<PeriodResiduePrediction> = (0..period)
        .map(|residue| {
            let positions_one_based: Vec<usize> = non_anchor_positions
                .iter()
                .copied()
                .filter(|position| position % period == residue)
                .map(|position| position + 1)
                .collect();
            PeriodResiduePrediction {
                residue,
                position_count: positions_one_based.len(),
                positions_one_based,
            }
        })
        .collect();
    residues.sort_by_key(|prediction| prediction.residue);

    Ok(PeriodPredictionPlan {
        period,
        non_anchor_position_count: non_anchor_positions.len(),
        anchor_position_count: anchor_positions.len(),
        residues,
        promoted_candidate: false,
        source_inputs: "K4 ciphertext length and public anchor positions only; no fragment values, candidate words, or public anchor-derived key fragments are scored.".to_string(),
        prediction_rule: "Group every non-anchor K4 position by zero-based position modulo the registered period; future independent evidence must be evaluated against these residue classes without retuning.".to_string(),
        note: "Period prediction plan only; this emits a predeclared target for future independent evidence and is not a decryption claim.".to_string(),
    })
}

pub fn build_all_period_prediction_plans() -> Result<PeriodPredictionPlanSet> {
    let plans: Vec<PeriodPredictionPlan> = registered_structural_models()
        .iter()
        .map(|model| build_period_prediction_plan(model.period))
        .collect::<Result<Vec<_>>>()?;

    Ok(PeriodPredictionPlanSet {
        period_count: plans.len(),
        plans,
        promoted_candidate: false,
        note: "All-period prediction plan set only; future independent evidence must control the best-of-period search surface before any interpretation.".to_string(),
    })
}

pub fn build_spacing_prediction_plan(modulus: usize) -> Result<SpacingPredictionPlan> {
    if !registered_structural_models()
        .iter()
        .any(|model| model.period == modulus)
    {
        bail!("modulus must be one of the registered structural model periods");
    }

    let anchor_positions = anchor_position_set();
    let non_anchor_positions = non_anchor_positions_one_based(&anchor_positions);
    let mut residues: Vec<SpacingResiduePrediction> = (0..modulus)
        .map(|residue| {
            let mut pairs = Vec::new();
            let mut sample_pairs_one_based = Vec::new();
            for (left_index, left) in non_anchor_positions.iter().enumerate() {
                for right in non_anchor_positions.iter().skip(left_index + 1) {
                    if (right - left) % modulus == residue {
                        pairs.push([*left, *right]);
                        if sample_pairs_one_based.len() < 16 {
                            sample_pairs_one_based.push([*left, *right]);
                        }
                    }
                }
            }
            SpacingResiduePrediction {
                residue,
                pair_count: pairs.len(),
                sample_pairs_one_based,
            }
        })
        .collect();
    residues.sort_by_key(|prediction| prediction.residue);

    Ok(SpacingPredictionPlan {
        modulus,
        non_anchor_position_count: non_anchor_positions.len(),
        anchor_position_count: anchor_positions.len(),
        positions_one_based: non_anchor_positions,
        residues,
        promoted_candidate: false,
        source_inputs: "K4 ciphertext length and public anchor positions only; no fragment values, candidate words, routes, or public anchor-derived key fragments are scored.".to_string(),
        prediction_rule: "Group every unordered pair of non-anchor K4 positions by one-based spacing modulo the registered modulus; future independent evidence must be evaluated against these spacing residue classes without retuning.".to_string(),
        note: "Spacing prediction plan only; this emits a predeclared target for future independent evidence and is not a decryption claim.".to_string(),
    })
}

pub fn build_all_spacing_prediction_plans() -> Result<SpacingPredictionPlanSet> {
    let plans: Vec<SpacingPredictionPlan> = registered_structural_models()
        .iter()
        .map(|model| build_spacing_prediction_plan(model.period))
        .collect::<Result<Vec<_>>>()?;

    Ok(SpacingPredictionPlanSet {
        modulus_count: plans.len(),
        plans,
        promoted_candidate: false,
        note: "All-modulus spacing prediction plan set only; future independent evidence must control the best-of-modulus search surface before any interpretation.".to_string(),
    })
}

pub fn evaluate_period_prediction_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<PeriodPredictionEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("period prediction evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("period prediction evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let plans: PeriodPredictionPlanSet = serde_json::from_str(&artifact)?;
    let non_anchor_universe = non_anchor_position_universe(&plans)?;
    let universe: HashSet<_> = non_anchor_universe.iter().copied().collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !universe.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the prediction artifact"
            );
        }
    }

    let mut period_results =
        score_period_prediction_positions(&plans, &observed_positions_one_based);
    period_results.sort_by(|left, right| {
        right
            .best_hits
            .cmp(&left.best_hits)
            .then_with(|| left.period.cmp(&right.period))
    });
    let best = period_results
        .first()
        .ok_or_else(|| anyhow::anyhow!("prediction artifact does not contain any plans"))?;

    let null_best_hits = period_prediction_null_distribution(
        &plans,
        &non_anchor_universe,
        observed_positions_one_based.len(),
        iterations,
        seed,
    )?;
    let null_mean_best_hits = mean_usize(&null_best_hits);
    let null_std_dev_best_hits = std_dev_usize(&null_best_hits, null_mean_best_hits);
    let at_least_observed = null_best_hits
        .iter()
        .filter(|score| **score >= best.best_hits)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(PeriodPredictionEvaluation {
        artifact_path: artifact_path.display().to_string(),
        observation_id: None,
        observation_source_ids: Vec::new(),
        observation_rationale: None,
        observation_position_notes: BTreeMap::new(),
        source_backed_observation: false,
        observation_warning: Some(
            "Ad hoc --positions input is diagnostic only; use --positions-file with validated source IDs before treating observations as evidence.",
        ),
        observed_position_count: observed_positions_one_based.len(),
        observed_positions_one_based,
        best_period: best.period,
        best_residue: best.best_residue,
        best_hits: best.best_hits,
        best_hit_rate: best.best_hit_rate,
        null_mean_best_hits,
        null_std_dev_best_hits,
        empirical_p_value,
        iterations,
        seed,
        period_results,
        promoted_candidate: false,
        note: "Period prediction evaluation scores independent non-anchor positions against a committed artifact with a best-of-period null; it is not a claimed solution.",
    })
}

pub fn evaluate_spacing_prediction_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<SpacingPredictionEvaluation> {
    if observed_positions_one_based.len() < 2 {
        bail!("spacing prediction evaluation requires at least two observed positions");
    }
    if iterations == 0 {
        bail!("spacing prediction evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let plans: SpacingPredictionPlanSet = serde_json::from_str(&artifact)?;
    let non_anchor_universe = spacing_position_universe(&plans)?;
    let universe: HashSet<_> = non_anchor_universe.iter().copied().collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !universe.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the spacing prediction artifact"
            );
        }
    }

    let observed_pair_count = pair_count(observed_positions_one_based.len());
    let mut modulus_results =
        score_spacing_prediction_positions(&plans, &observed_positions_one_based);
    modulus_results.sort_by(|left, right| {
        right
            .best_hits
            .cmp(&left.best_hits)
            .then_with(|| left.modulus.cmp(&right.modulus))
    });
    let best = modulus_results
        .first()
        .ok_or_else(|| anyhow::anyhow!("spacing prediction artifact does not contain any plans"))?;

    let null_best_hits = spacing_prediction_null_distribution(
        &plans,
        &non_anchor_universe,
        observed_positions_one_based.len(),
        iterations,
        seed,
    )?;
    let null_mean_best_hits = mean_usize(&null_best_hits);
    let null_std_dev_best_hits = std_dev_usize(&null_best_hits, null_mean_best_hits);
    let at_least_observed = null_best_hits
        .iter()
        .filter(|score| **score >= best.best_hits)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(SpacingPredictionEvaluation {
        artifact_path: artifact_path.display().to_string(),
        observation_id: None,
        observation_source_ids: Vec::new(),
        observation_rationale: None,
        observation_position_notes: BTreeMap::new(),
        source_backed_observation: false,
        observation_warning: Some(
            "Ad hoc --positions input is diagnostic only; use --positions-file with validated source IDs before treating observations as evidence.",
        ),
        observed_position_count: observed_positions_one_based.len(),
        observed_pair_count,
        observed_positions_one_based,
        best_modulus: best.modulus,
        best_residue: best.best_residue,
        best_hits: best.best_hits,
        best_hit_rate: best.best_hit_rate,
        null_mean_best_hits,
        null_std_dev_best_hits,
        empirical_p_value,
        iterations,
        seed,
        modulus_results,
        promoted_candidate: false,
        note: "Spacing prediction evaluation scores independent non-anchor positions against a committed spacing artifact with a best-of-modulus null; it is not a claimed solution.",
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

fn non_anchor_position_universe(plans: &PeriodPredictionPlanSet) -> Result<Vec<usize>> {
    let first = plans
        .plans
        .first()
        .ok_or_else(|| anyhow::anyhow!("prediction artifact does not contain any plans"))?;
    let mut positions: Vec<_> = first
        .residues
        .iter()
        .flat_map(|residue| residue.positions_one_based.iter().copied())
        .collect();
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}

fn spacing_position_universe(plans: &SpacingPredictionPlanSet) -> Result<Vec<usize>> {
    let first = plans
        .plans
        .first()
        .ok_or_else(|| anyhow::anyhow!("spacing prediction artifact does not contain any plans"))?;
    let mut positions = first.positions_one_based.clone();
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}

fn score_period_prediction_positions(
    plans: &PeriodPredictionPlanSet,
    observed_positions_one_based: &[usize],
) -> Vec<PeriodPredictionEvaluationResult> {
    let observed: HashSet<_> = observed_positions_one_based.iter().copied().collect();
    plans
        .plans
        .iter()
        .map(|plan| {
            let mut residue_hits: Vec<_> = plan
                .residues
                .iter()
                .map(|residue| {
                    let matching_positions_one_based: Vec<_> = residue
                        .positions_one_based
                        .iter()
                        .copied()
                        .filter(|position| observed.contains(position))
                        .collect();
                    PeriodResidueHit {
                        residue: residue.residue,
                        hits: matching_positions_one_based.len(),
                        matching_positions_one_based,
                    }
                })
                .collect();
            residue_hits.sort_by_key(|hit| hit.residue);
            let best = residue_hits
                .iter()
                .max_by(|left, right| {
                    left.hits
                        .cmp(&right.hits)
                        .then_with(|| right.residue.cmp(&left.residue))
                })
                .expect("plans contain at least one residue");
            PeriodPredictionEvaluationResult {
                period: plan.period,
                best_residue: best.residue,
                best_hits: best.hits,
                best_hit_rate: best.hits as f64 / observed_positions_one_based.len() as f64,
                residue_hits,
            }
        })
        .collect()
}

fn period_prediction_null_distribution(
    plans: &PeriodPredictionPlanSet,
    non_anchor_universe: &[usize],
    observed_position_count: usize,
    iterations: usize,
    seed: u64,
) -> Result<Vec<usize>> {
    if observed_position_count > non_anchor_universe.len() {
        bail!("observed position count exceeds non-anchor prediction universe");
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut distribution = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut sampled = non_anchor_universe.to_vec();
        sampled.shuffle(&mut rng);
        sampled.truncate(observed_position_count);
        let best_hits = score_period_prediction_positions(plans, &sampled)
            .iter()
            .map(|result| result.best_hits)
            .max()
            .ok_or_else(|| anyhow::anyhow!("prediction artifact does not contain any plans"))?;
        distribution.push(best_hits);
    }
    Ok(distribution)
}

fn score_spacing_prediction_positions(
    plans: &SpacingPredictionPlanSet,
    observed_positions_one_based: &[usize],
) -> Vec<SpacingPredictionEvaluationResult> {
    let mut observed_positions = observed_positions_one_based.to_vec();
    observed_positions.sort_unstable();
    let observed_pairs = unordered_pairs(&observed_positions);
    let observed_pair_count = observed_pairs.len();

    plans
        .plans
        .iter()
        .map(|plan| {
            let mut residue_hits: Vec<_> = plan
                .residues
                .iter()
                .map(|residue| {
                    let matching_pairs_one_based: Vec<_> = observed_pairs
                        .iter()
                        .copied()
                        .filter(|pair| (pair[1] - pair[0]) % plan.modulus == residue.residue)
                        .collect();
                    SpacingResidueHit {
                        residue: residue.residue,
                        hits: matching_pairs_one_based.len(),
                        matching_pairs_one_based,
                    }
                })
                .collect();
            residue_hits.sort_by_key(|hit| hit.residue);
            let best = residue_hits
                .iter()
                .max_by(|left, right| {
                    left.hits
                        .cmp(&right.hits)
                        .then_with(|| right.residue.cmp(&left.residue))
                })
                .expect("plans contain at least one residue");
            SpacingPredictionEvaluationResult {
                modulus: plan.modulus,
                best_residue: best.residue,
                best_hits: best.hits,
                best_hit_rate: best.hits as f64 / observed_pair_count as f64,
                residue_hits,
            }
        })
        .collect()
}

fn spacing_prediction_null_distribution(
    plans: &SpacingPredictionPlanSet,
    non_anchor_universe: &[usize],
    observed_position_count: usize,
    iterations: usize,
    seed: u64,
) -> Result<Vec<usize>> {
    if observed_position_count > non_anchor_universe.len() {
        bail!("observed position count exceeds non-anchor spacing prediction universe");
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut distribution = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut sampled = non_anchor_universe.to_vec();
        sampled.shuffle(&mut rng);
        sampled.truncate(observed_position_count);
        let best_hits = score_spacing_prediction_positions(plans, &sampled)
            .iter()
            .map(|result| result.best_hits)
            .max()
            .ok_or_else(|| {
                anyhow::anyhow!("spacing prediction artifact does not contain any plans")
            })?;
        distribution.push(best_hits);
    }
    Ok(distribution)
}

fn pair_count(position_count: usize) -> usize {
    position_count.saturating_sub(1) * position_count / 2
}

fn unordered_pairs(positions: &[usize]) -> Vec<[usize; 2]> {
    let mut pairs = Vec::with_capacity(pair_count(positions.len()));
    for (left_index, left) in positions.iter().enumerate() {
        for right in positions.iter().skip(left_index + 1) {
            pairs.push([*left, *right]);
        }
    }
    pairs
}

fn mean_usize(values: &[usize]) -> f64 {
    values.iter().sum::<usize>() as f64 / values.len() as f64
}

fn std_dev_usize(values: &[usize], mean: f64) -> f64 {
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

    #[test]
    fn period_prediction_plan_excludes_public_anchor_positions() {
        let plan = build_period_prediction_plan(3).unwrap();

        assert_eq!(plan.period, 3);
        assert_eq!(plan.anchor_position_count, 24);
        assert_eq!(plan.non_anchor_position_count, K4_CIPHERTEXT.len() - 24);
        assert!(!plan.promoted_candidate);
        assert_eq!(plan.residues.len(), 3);
        assert_eq!(
            plan.residues
                .iter()
                .map(|residue| residue.position_count)
                .sum::<usize>(),
            plan.non_anchor_position_count
        );
        assert!(
            plan.residues
                .iter()
                .flat_map(|residue| residue.positions_one_based.iter())
                .all(|position| !known_anchors().iter().any(|anchor| {
                    *position >= anchor.start_one_based()
                        && *position <= anchor.end_one_based_inclusive()
                }))
        );
    }

    #[test]
    fn all_period_prediction_plans_cover_registered_periods() {
        let run = build_all_period_prediction_plans().unwrap();

        assert_eq!(run.period_count, registered_structural_models().len());
        assert!(!run.promoted_candidate);
        assert_eq!(run.plans.len(), run.period_count);
        assert!(
            run.plans
                .iter()
                .all(|plan| plan.non_anchor_position_count == K4_CIPHERTEXT.len() - 24)
        );
    }

    #[test]
    fn period_prediction_evaluation_scores_non_anchor_positions_without_promotion() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            temp.path(),
            serde_json::to_string(&build_all_period_prediction_plans().unwrap()).unwrap(),
        )
        .unwrap();

        let evaluation =
            evaluate_period_prediction_positions(temp.path(), vec![1, 4, 7], 100, 67).unwrap();

        assert_eq!(evaluation.observed_position_count, 3);
        assert_eq!(evaluation.best_period, 3);
        assert_eq!(evaluation.best_hits, 3);
        assert!(evaluation.empirical_p_value > 0.0);
        assert!(!evaluation.promoted_candidate);
    }

    #[test]
    fn period_prediction_evaluation_rejects_anchor_positions() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            temp.path(),
            serde_json::to_string(&build_all_period_prediction_plans().unwrap()).unwrap(),
        )
        .unwrap();

        let error = evaluate_period_prediction_positions(temp.path(), vec![22], 100, 67)
            .unwrap_err()
            .to_string();

        assert!(error.contains("non-anchor K4 positions"));
    }
}
