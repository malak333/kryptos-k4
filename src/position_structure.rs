use crate::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, FragmentMode, K4_CIPHERTEXT,
    analyze_constraints, analyze_known_plaintext_spans, known_anchors,
};
use anyhow::{Result, bail};
use rand::seq::SliceRandom;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorPredictionPlanSet {
    pub pair_count: usize,
    pub center_position_one_based: usize,
    pub non_anchor_position_count: usize,
    pub anchor_position_count: usize,
    pub plans: Vec<MirrorPairPrediction>,
    pub promoted_candidate: bool,
    pub source_inputs: String,
    pub prediction_rule: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorPairPrediction {
    pub left_position_one_based: usize,
    pub right_position_one_based: usize,
    pub distance_from_center: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridLayoutPredictionPlan {
    pub row_count: usize,
    pub column_count: usize,
    pub padded_position_count: usize,
    pub pad_positions_one_based: Vec<usize>,
    pub non_anchor_position_count: usize,
    pub anchor_position_count: usize,
    pub scored_edge_axis: GridLayoutEdgeAxis,
    pub row_edge_positions_one_based: Vec<usize>,
    pub column_edge_positions_one_based: Vec<usize>,
    pub rows: Vec<GridLayoutRowPrediction>,
    pub columns: Vec<GridLayoutColumnPrediction>,
    pub promoted_candidate: bool,
    pub source_inputs: String,
    pub prediction_rule: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridLayoutRowPrediction {
    pub row_one_based: usize,
    pub start_position_one_based: usize,
    pub end_position_one_based: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub row_edge_positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridLayoutColumnPrediction {
    pub column_one_based: usize,
    pub top_position_one_based: usize,
    pub bottom_position_one_based: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub column_edge_positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableauHillPredictionPlan {
    pub hypothesis_family: String,
    pub artifact_kind: String,
    pub evaluator_status: String,
    pub source_ids: Vec<String>,
    pub source_inputs: String,
    pub mapping_status: String,
    pub row_count: usize,
    pub column_count: usize,
    pub cell_count: usize,
    pub k4_position_count: usize,
    pub padding_cell_count: usize,
    pub padding_cell_index_one_based: usize,
    pub coordinate_mapping: Vec<TableauHillCoordinate>,
    pub source_backed_fixed_rules: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub candidate_material_allowed: bool,
    pub required_preregistration_before_scoring: bool,
    pub fixed_questions: Vec<TableauHillQuestion>,
    pub required_next_steps: Vec<String>,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableauHillQuestion {
    pub id: String,
    pub question: String,
    pub fixed_before_scoring: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableauHillCoordinate {
    pub cell_index_one_based: usize,
    pub row_one_based: usize,
    pub column_one_based: usize,
    pub k4_position_one_based: Option<usize>,
    pub is_padding: bool,
    pub is_public_anchor_position: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GridLayoutEdgeAxis {
    Row,
    Column,
    CompassAxis,
}

impl GridLayoutEdgeAxis {
    pub fn label(self) -> &'static str {
        match self {
            GridLayoutEdgeAxis::Row => "row",
            GridLayoutEdgeAxis::Column => "column",
            GridLayoutEdgeAxis::CompassAxis => "compass-axis",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeriodPredictionEvaluation {
    pub artifact_path: String,
    pub observation_id: Option<String>,
    pub observation_source_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_source_review_file: Option<String>,
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
pub struct GridLayoutPredictionEvaluation {
    pub artifact_path: String,
    pub observation_id: Option<String>,
    pub observation_source_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_source_review_file: Option<String>,
    pub observation_rationale: Option<String>,
    pub observation_position_notes: BTreeMap<String, String>,
    pub source_backed_observation: bool,
    pub observation_warning: Option<&'static str>,
    pub observed_position_count: usize,
    pub observed_positions_one_based: Vec<usize>,
    pub edge_axis: String,
    pub edge_hits: usize,
    pub edge_hit_rate: f64,
    pub matching_edge_positions_one_based: Vec<usize>,
    pub non_edge_positions_one_based: Vec<usize>,
    pub row_edge_hits: usize,
    pub row_edge_hit_rate: f64,
    pub matching_row_edge_positions_one_based: Vec<usize>,
    pub non_row_edge_positions_one_based: Vec<usize>,
    pub column_edge_hits: usize,
    pub column_edge_hit_rate: f64,
    pub matching_column_edge_positions_one_based: Vec<usize>,
    pub non_column_edge_positions_one_based: Vec<usize>,
    pub null_mean_edge_hits: f64,
    pub null_std_dev_edge_hits: f64,
    pub null_mean_row_edge_hits: f64,
    pub null_std_dev_row_edge_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TableauHillPredictionEvaluation {
    pub artifact_path: String,
    pub observation_id: Option<String>,
    pub observation_source_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_source_review_file: Option<String>,
    pub observation_rationale: Option<String>,
    pub observation_position_notes: BTreeMap<String, String>,
    pub source_backed_observation: bool,
    pub observation_warning: Option<&'static str>,
    pub observed_position_count: usize,
    pub observed_positions_one_based: Vec<usize>,
    pub best_axis: String,
    pub best_index_one_based: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub matching_positions_one_based: Vec<usize>,
    pub row_results: Vec<TableauHillAxisResult>,
    pub column_results: Vec<TableauHillAxisResult>,
    pub null_mean_best_hits: f64,
    pub null_std_dev_best_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TableauHillAxisResult {
    pub axis: String,
    pub index_one_based: usize,
    pub hits: usize,
    pub hit_rate: f64,
    pub matching_positions_one_based: Vec<usize>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_source_review_file: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MirrorPredictionEvaluation {
    pub artifact_path: String,
    pub observation_id: Option<String>,
    pub observation_source_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_source_review_file: Option<String>,
    pub observation_rationale: Option<String>,
    pub observation_position_notes: BTreeMap<String, String>,
    pub source_backed_observation: bool,
    pub observation_warning: Option<&'static str>,
    pub observed_position_count: usize,
    pub observed_positions_one_based: Vec<usize>,
    pub possible_observed_mirror_pairs: usize,
    pub mirror_pair_hits: usize,
    pub mirror_pair_hit_rate: f64,
    pub matching_pairs_one_based: Vec<[usize; 2]>,
    pub singleton_positions_one_based: Vec<usize>,
    pub null_mean_mirror_pair_hits: f64,
    pub null_std_dev_mirror_pair_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
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
        StructuralModel {
            id: "period-14-grid-padding",
            label: "Period 14 padded grid residues",
            kind: "periodic-residue",
            period: 14,
            rationale: "Fourteen-lane model pre-registered from source-context layout rationale: K4 has 97 characters, and one padding position would yield a 7-by-14-compatible grid. This is context for future non-anchor observations, not scored evidence.",
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
        source_inputs: if period == 14 {
            "K4 ciphertext length, public anchor positions, and context-only 7-by-14 layout rationale from `kryptosbot-sanborn-papers-2026`; no fragment values, candidate words, or public anchor-derived key fragments are scored.".to_string()
        } else {
            "K4 ciphertext length and public anchor positions only; no fragment values, candidate words, or public anchor-derived key fragments are scored.".to_string()
        },
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

pub fn build_mirror_prediction_plan() -> Result<MirrorPredictionPlanSet> {
    let anchor_positions = anchor_position_set();
    let non_anchor_positions = non_anchor_positions_one_based(&anchor_positions);
    let non_anchor_set: HashSet<_> = non_anchor_positions.iter().copied().collect();
    let k4_len = K4_CIPHERTEXT.len();
    let center_position_one_based = k4_len.div_ceil(2);
    let plans = (1..=k4_len / 2)
        .filter_map(|left| {
            let right = k4_len + 1 - left;
            if non_anchor_set.contains(&left) && non_anchor_set.contains(&right) {
                Some(MirrorPairPrediction {
                    left_position_one_based: left,
                    right_position_one_based: right,
                    distance_from_center: center_position_one_based - left,
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    Ok(MirrorPredictionPlanSet {
        pair_count: plans.len(),
        center_position_one_based,
        non_anchor_position_count: non_anchor_positions.len(),
        anchor_position_count: anchor_positions.len(),
        plans,
        promoted_candidate: false,
        source_inputs: "K4 ciphertext length, public anchor positions for exclusion only, and source context that the Vigenere chart is physically flipped/read from the back side of the sculpture; no fragment values, candidate words, routes, or public anchor-derived key fragments are scored.".to_string(),
        prediction_rule: "Pair every non-anchor K4 position with its mirror position across the 97-character one-based axis: i pairs with 98-i. Future independent evidence must test these mirror-pair targets without retuning.".to_string(),
        note: "Mirror prediction plan only; this emits a predeclared physical-symmetry target for future independent evidence and is not a decryption claim.".to_string(),
    })
}

pub fn build_grid_layout_prediction_plan() -> Result<GridLayoutPredictionPlan> {
    build_grid_layout_prediction_plan_for_axis(GridLayoutEdgeAxis::Row)
}

pub fn build_grid_layout_prediction_plan_for_axis(
    scored_edge_axis: GridLayoutEdgeAxis,
) -> Result<GridLayoutPredictionPlan> {
    let row_count = 7;
    let column_count = 14;
    let padded_position_count = row_count * column_count;
    let k4_len = K4_CIPHERTEXT.len();
    let pad_positions_one_based = ((k4_len + 1)..=padded_position_count).collect::<Vec<_>>();
    let anchor_positions = anchor_position_set();
    let non_anchor_positions = non_anchor_positions_one_based(&anchor_positions);
    let non_anchor_set: HashSet<_> = non_anchor_positions.iter().copied().collect();
    let mut row_edge_positions_one_based = Vec::new();
    let mut column_edge_positions_one_based = Vec::new();
    let mut rows = Vec::new();
    let mut columns = Vec::new();

    for row_index in 0..row_count {
        let start_position_one_based = row_index * column_count + 1;
        let end_position_one_based = start_position_one_based + column_count - 1;
        let row_non_anchor_positions = (start_position_one_based..=end_position_one_based)
            .filter(|position| *position <= k4_len && non_anchor_set.contains(position))
            .collect::<Vec<_>>();
        let row_edges = [start_position_one_based, end_position_one_based]
            .into_iter()
            .filter(|position| *position <= k4_len && non_anchor_set.contains(position))
            .collect::<Vec<_>>();
        row_edge_positions_one_based.extend(row_edges.iter().copied());
        rows.push(GridLayoutRowPrediction {
            row_one_based: row_index + 1,
            start_position_one_based,
            end_position_one_based,
            non_anchor_positions_one_based: row_non_anchor_positions,
            row_edge_positions_one_based: row_edges,
        });
    }
    row_edge_positions_one_based.sort_unstable();
    row_edge_positions_one_based.dedup();

    for column_index in 0..column_count {
        let top_position_one_based = column_index + 1;
        let bottom_position_one_based = (row_count - 1) * column_count + column_index + 1;
        let column_non_anchor_positions = (0..row_count)
            .map(|row_index| row_index * column_count + column_index + 1)
            .filter(|position| *position <= k4_len && non_anchor_set.contains(position))
            .collect::<Vec<_>>();
        let column_edges = [top_position_one_based, bottom_position_one_based]
            .into_iter()
            .filter(|position| *position <= k4_len && non_anchor_set.contains(position))
            .collect::<Vec<_>>();
        column_edge_positions_one_based.extend(column_edges.iter().copied());
        columns.push(GridLayoutColumnPrediction {
            column_one_based: column_index + 1,
            top_position_one_based,
            bottom_position_one_based,
            non_anchor_positions_one_based: column_non_anchor_positions,
            column_edge_positions_one_based: column_edges,
        });
    }
    column_edge_positions_one_based.sort_unstable();
    column_edge_positions_one_based.dedup();

    Ok(GridLayoutPredictionPlan {
        row_count,
        column_count,
        padded_position_count,
        pad_positions_one_based,
        non_anchor_position_count: non_anchor_positions.len(),
        anchor_position_count: anchor_positions.len(),
        scored_edge_axis,
        row_edge_positions_one_based,
        column_edge_positions_one_based,
        rows,
        columns,
        promoted_candidate: false,
        source_inputs: "K4 ciphertext length, public anchor positions for exclusion only, and context-only 7-by-14 padding rationale from `kryptosbot-sanborn-papers-2026`; no fragment values, candidate words, routes, or public anchor-derived key fragments are scored.".to_string(),
        prediction_rule: format!(
            "Place K4 positions into a predeclared 7-by-14 padded grid with position 98 as padding. The scored target is enrichment at non-anchor {}-edge positions; the orthogonal edge axis remains pre-score metadata only, without retuning the layout after observations are seen.",
            scored_edge_axis.label()
        ),
        note: "Grid-layout prediction plan only; this emits predeclared source-context structural targets for future independent evidence and is not a decryption claim.".to_string(),
    })
}

pub fn build_tableau_hill_prediction_plan() -> TableauHillPredictionPlan {
    let row_count = 7;
    let column_count = 14;
    let cell_count = row_count * column_count;
    let k4_position_count = K4_CIPHERTEXT.len();
    let anchor_positions = anchor_position_set();
    let coordinate_mapping = (1..=cell_count)
        .map(|cell_index_one_based| {
            let k4_position_one_based =
                (cell_index_one_based <= k4_position_count).then_some(cell_index_one_based);
            TableauHillCoordinate {
                cell_index_one_based,
                row_one_based: ((cell_index_one_based - 1) / column_count) + 1,
                column_one_based: ((cell_index_one_based - 1) % column_count) + 1,
                k4_position_one_based,
                is_padding: k4_position_one_based.is_none(),
                is_public_anchor_position: k4_position_one_based
                    .map(|position| anchor_positions.contains(&(position - 1)))
                    .unwrap_or(false),
            }
        })
        .collect();

    TableauHillPredictionPlan {
        hypothesis_family: "tableau-hill-prediction".to_string(),
        artifact_kind: "tableau-hill-source-mapping-plan".to_string(),
        evaluator_status: "tooling-ready".to_string(),
        source_ids: vec![
            "rumkin-k4-reference".to_string(),
            "cia-sculpture".to_string(),
            "kryptosbot-sanborn-papers-2026".to_string(),
        ],
        source_inputs: "Context-only Rumkin K4 reference noting the open HILL/tableau question, CIA sculpture context that K4 is 97 characters, and archived Sanborn-papers context for one-padding 7-by-14 compatibility; no plaintext, candidate key material, public-anchor additive fragments, or scored observations are used.".to_string(),
        mapping_status: "fixed-before-scoring".to_string(),
        row_count,
        column_count,
        cell_count,
        k4_position_count,
        padding_cell_count: cell_count - k4_position_count,
        padding_cell_index_one_based: cell_count,
        coordinate_mapping,
        source_backed_fixed_rules: vec![
            "Map K4 positions 1 through 97 into a row-major 7-by-14 tableau before scoring any observations.".to_string(),
            "Reserve cell 98 as a single padding cell; it is not a K4 ciphertext position and cannot be scored.".to_string(),
            "Carry public-anchor positions only as exclusion metadata for future validators; public-anchor fragment values are not discovery inputs or primary evidence.".to_string(),
            "Treat the Rumkin HILL/tableau note as source context for the family boundary, not as candidate material, plaintext, or a scored observation.".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        candidate_material_allowed: false,
        required_preregistration_before_scoring: true,
        fixed_questions: vec![
            TableauHillQuestion {
                id: "direct-mapping-boundary".to_string(),
                question: "A future HILL/tableau evaluator must use the committed row-major 7-by-14 coordinate mapping unless a new preregistration replaces it before scoring.".to_string(),
                fixed_before_scoring: true,
            },
            TableauHillQuestion {
                id: "tableau-dimension-boundary".to_string(),
                question: "The committed tableau dimensions are seven rows by fourteen columns with one padding cell, fixed from source context before observation scoring.".to_string(),
                fixed_before_scoring: true,
            },
            TableauHillQuestion {
                id: "observation-target-boundary".to_string(),
                question: "Can future source-backed observations be selected independently of EAST, NORTHEAST, BERLIN, CLOCK, key-material candidates, and public-fragment score output?".to_string(),
                fixed_before_scoring: true,
            },
        ],
        required_next_steps: vec![
            "Validate source-backed observation files with validate-tableau-hill-observations before scoring.".to_string(),
            "Evaluate only source-backed non-anchor observations with evaluate-tableau-hill-prediction and archived seeded null controls.".to_string(),
            "Require multiple-comparison context across source-backed lanes before interpreting any tableau/HILL score.".to_string(),
            "Keep public anchor fragments and candidate words out of discovery inputs and primary evidence.".to_string(),
        ],
        promoted_candidate: false,
        note: "Tableau/HILL source-mapping plan only; this fixes pre-score mapping and dimension boundaries for source-backed observation evaluation and is not a decryption claim.".to_string(),
    }
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
        observation_source_review_file: None,
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

pub fn evaluate_grid_layout_prediction_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<GridLayoutPredictionEvaluation> {
    evaluate_grid_layout_prediction_positions_with_axis(
        artifact_path,
        observed_positions_one_based,
        GridLayoutEdgeAxis::Row,
        iterations,
        seed,
    )
}

pub fn evaluate_grid_layout_prediction_positions_with_axis(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    edge_axis: GridLayoutEdgeAxis,
    iterations: usize,
    seed: u64,
) -> Result<GridLayoutPredictionEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("grid-layout prediction evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("grid-layout prediction evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let plan: GridLayoutPredictionPlan = serde_json::from_str(&artifact)?;
    let non_anchor_universe = grid_layout_position_universe(&plan)?;
    let universe: HashSet<_> = non_anchor_universe.iter().copied().collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !universe.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the grid-layout prediction artifact"
            );
        }
    }

    let selected_score = score_grid_layout_edge_prediction_positions(
        &plan,
        edge_axis,
        &observed_positions_one_based,
    );
    let row_score = score_grid_layout_edge_prediction_positions(
        &plan,
        GridLayoutEdgeAxis::Row,
        &observed_positions_one_based,
    );
    let column_score = score_grid_layout_edge_prediction_positions(
        &plan,
        GridLayoutEdgeAxis::Column,
        &observed_positions_one_based,
    );
    let null_hits = grid_layout_prediction_null_distribution(
        &plan,
        &non_anchor_universe,
        observed_positions_one_based.len(),
        edge_axis,
        iterations,
        seed,
    )?;
    let null_mean_edge_hits = mean_usize(&null_hits);
    let null_std_dev_edge_hits = std_dev_usize(&null_hits, null_mean_edge_hits);
    let at_least_observed = null_hits
        .iter()
        .filter(|hits| **hits >= selected_score.edge_hits)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(GridLayoutPredictionEvaluation {
        artifact_path: artifact_path.display().to_string(),
        observation_id: None,
        observation_source_ids: Vec::new(),
        observation_source_review_file: None,
        observation_rationale: None,
        observation_position_notes: BTreeMap::new(),
        source_backed_observation: false,
        observation_warning: Some(
            "Ad hoc --positions input is diagnostic only; use --positions-file with validated source IDs before treating observations as evidence.",
        ),
        observed_position_count: observed_positions_one_based.len(),
        observed_positions_one_based,
        edge_axis: edge_axis.label().to_string(),
        edge_hits: selected_score.edge_hits,
        edge_hit_rate: selected_score.edge_hit_rate,
        matching_edge_positions_one_based: selected_score.matching_edge_positions_one_based,
        non_edge_positions_one_based: selected_score.non_edge_positions_one_based,
        row_edge_hits: row_score.edge_hits,
        row_edge_hit_rate: row_score.edge_hit_rate,
        matching_row_edge_positions_one_based: row_score.matching_edge_positions_one_based,
        non_row_edge_positions_one_based: row_score.non_edge_positions_one_based,
        column_edge_hits: column_score.edge_hits,
        column_edge_hit_rate: column_score.edge_hit_rate,
        matching_column_edge_positions_one_based: column_score.matching_edge_positions_one_based,
        non_column_edge_positions_one_based: column_score.non_edge_positions_one_based,
        null_mean_edge_hits,
        null_std_dev_edge_hits,
        null_mean_row_edge_hits: if edge_axis == GridLayoutEdgeAxis::Row {
            null_mean_edge_hits
        } else {
            0.0
        },
        null_std_dev_row_edge_hits: if edge_axis == GridLayoutEdgeAxis::Row {
            null_std_dev_edge_hits
        } else {
            0.0
        },
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Grid-layout prediction evaluation scores independent non-anchor positions against a committed 7-by-14 edge-axis artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_tableau_hill_prediction_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<TableauHillPredictionEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("Tableau/HILL prediction evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("Tableau/HILL prediction evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let plan: TableauHillPredictionPlan = serde_json::from_str(&artifact)?;
    let non_anchor_universe = tableau_hill_position_universe(&plan)?;
    let universe: HashSet<_> = non_anchor_universe.iter().copied().collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !universe.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the Tableau/HILL source-mapping artifact"
            );
        }
    }

    let score = score_tableau_hill_prediction_positions(&plan, &observed_positions_one_based)?;
    let null_best_hits = tableau_hill_prediction_null_distribution(
        &plan,
        &non_anchor_universe,
        observed_positions_one_based.len(),
        iterations,
        seed,
    )?;
    let null_mean_best_hits = mean_usize(&null_best_hits);
    let null_std_dev_best_hits = std_dev_usize(&null_best_hits, null_mean_best_hits);
    let at_least_observed = null_best_hits
        .iter()
        .filter(|hits| **hits >= score.best_hits)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(TableauHillPredictionEvaluation {
        artifact_path: artifact_path.display().to_string(),
        observation_id: None,
        observation_source_ids: Vec::new(),
        observation_source_review_file: None,
        observation_rationale: None,
        observation_position_notes: BTreeMap::new(),
        source_backed_observation: false,
        observation_warning: Some(
            "Ad hoc --positions input is diagnostic only; use --positions-file with validated source IDs before treating observations as evidence.",
        ),
        observed_position_count: observed_positions_one_based.len(),
        observed_positions_one_based,
        best_axis: score.best_axis,
        best_index_one_based: score.best_index_one_based,
        best_hits: score.best_hits,
        best_hit_rate: score.best_hit_rate,
        matching_positions_one_based: score.matching_positions_one_based,
        row_results: score.row_results,
        column_results: score.column_results,
        null_mean_best_hits,
        null_std_dev_best_hits,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Tableau/HILL prediction evaluation scores independent non-anchor positions for row/column concentration on the committed 7-by-14 source map with a seeded same-size position-set null; it is not a claimed solution.",
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
        observation_source_review_file: None,
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

pub fn evaluate_mirror_prediction_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<MirrorPredictionEvaluation> {
    if observed_positions_one_based.len() < 2 {
        bail!("mirror prediction evaluation requires at least two observed positions");
    }
    if iterations == 0 {
        bail!("mirror prediction evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let plan: MirrorPredictionPlanSet = serde_json::from_str(&artifact)?;
    let non_anchor_universe = mirror_position_universe(&plan)?;
    let universe: HashSet<_> = non_anchor_universe.iter().copied().collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !universe.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the mirror prediction artifact"
            );
        }
    }

    let score = score_mirror_prediction_positions(&plan, &observed_positions_one_based);
    let null_hits = mirror_prediction_null_distribution(
        &plan,
        &non_anchor_universe,
        observed_positions_one_based.len(),
        iterations,
        seed,
    )?;
    let null_mean_mirror_pair_hits = mean_usize(&null_hits);
    let null_std_dev_mirror_pair_hits = std_dev_usize(&null_hits, null_mean_mirror_pair_hits);
    let at_least_observed = null_hits
        .iter()
        .filter(|hits| **hits >= score.mirror_pair_hits)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(MirrorPredictionEvaluation {
        artifact_path: artifact_path.display().to_string(),
        observation_id: None,
        observation_source_ids: Vec::new(),
        observation_source_review_file: None,
        observation_rationale: None,
        observation_position_notes: BTreeMap::new(),
        source_backed_observation: false,
        observation_warning: Some(
            "Ad hoc --positions input is diagnostic only; use --positions-file with validated source IDs before treating observations as evidence.",
        ),
        observed_position_count: observed_positions_one_based.len(),
        observed_positions_one_based,
        possible_observed_mirror_pairs: score.possible_observed_mirror_pairs,
        mirror_pair_hits: score.mirror_pair_hits,
        mirror_pair_hit_rate: score.mirror_pair_hit_rate,
        matching_pairs_one_based: score.matching_pairs_one_based,
        singleton_positions_one_based: score.singleton_positions_one_based,
        null_mean_mirror_pair_hits,
        null_std_dev_mirror_pair_hits,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Mirror prediction evaluation scores independent non-anchor positions against committed mirror pairs with a seeded same-size position-set null; it is not a claimed solution.",
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

fn mirror_position_universe(plan: &MirrorPredictionPlanSet) -> Result<Vec<usize>> {
    if plan.plans.is_empty() {
        bail!("mirror prediction artifact does not contain any pairs");
    }
    let mut positions: Vec<_> = plan
        .plans
        .iter()
        .flat_map(|pair| [pair.left_position_one_based, pair.right_position_one_based])
        .collect();
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}

fn grid_layout_position_universe(plan: &GridLayoutPredictionPlan) -> Result<Vec<usize>> {
    if plan.rows.is_empty() {
        bail!("grid-layout prediction artifact does not contain any rows");
    }
    let mut positions: Vec<_> = plan
        .rows
        .iter()
        .flat_map(|row| row.non_anchor_positions_one_based.iter().copied())
        .collect();
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}

fn tableau_hill_position_universe(plan: &TableauHillPredictionPlan) -> Result<Vec<usize>> {
    if plan.coordinate_mapping.is_empty() {
        bail!("Tableau/HILL prediction artifact does not contain any coordinate mappings");
    }
    let mut positions: Vec<_> = plan
        .coordinate_mapping
        .iter()
        .filter(|cell| !cell.is_padding && !cell.is_public_anchor_position)
        .filter_map(|cell| cell.k4_position_one_based)
        .collect();
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

#[derive(Debug, Clone)]
struct MirrorPredictionScore {
    possible_observed_mirror_pairs: usize,
    mirror_pair_hits: usize,
    mirror_pair_hit_rate: f64,
    matching_pairs_one_based: Vec<[usize; 2]>,
    singleton_positions_one_based: Vec<usize>,
}

fn score_mirror_prediction_positions(
    plan: &MirrorPredictionPlanSet,
    observed_positions_one_based: &[usize],
) -> MirrorPredictionScore {
    let observed: HashSet<_> = observed_positions_one_based.iter().copied().collect();
    let mut matching_pairs_one_based = Vec::new();
    let mut singleton_positions_one_based = Vec::new();

    for pair in &plan.plans {
        let left_observed = observed.contains(&pair.left_position_one_based);
        let right_observed = observed.contains(&pair.right_position_one_based);
        match (left_observed, right_observed) {
            (true, true) => matching_pairs_one_based
                .push([pair.left_position_one_based, pair.right_position_one_based]),
            (true, false) => singleton_positions_one_based.push(pair.left_position_one_based),
            (false, true) => singleton_positions_one_based.push(pair.right_position_one_based),
            (false, false) => {}
        }
    }
    singleton_positions_one_based.sort_unstable();
    let possible_observed_mirror_pairs = observed_positions_one_based.len() / 2;
    let mirror_pair_hits = matching_pairs_one_based.len();
    let mirror_pair_hit_rate = if possible_observed_mirror_pairs == 0 {
        0.0
    } else {
        mirror_pair_hits as f64 / possible_observed_mirror_pairs as f64
    };

    MirrorPredictionScore {
        possible_observed_mirror_pairs,
        mirror_pair_hits,
        mirror_pair_hit_rate,
        matching_pairs_one_based,
        singleton_positions_one_based,
    }
}

fn mirror_prediction_null_distribution(
    plan: &MirrorPredictionPlanSet,
    non_anchor_universe: &[usize],
    observed_position_count: usize,
    iterations: usize,
    seed: u64,
) -> Result<Vec<usize>> {
    if observed_position_count > non_anchor_universe.len() {
        bail!("observed position count exceeds non-anchor mirror prediction universe");
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut distribution = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut sampled = non_anchor_universe.to_vec();
        sampled.shuffle(&mut rng);
        sampled.truncate(observed_position_count);
        distribution.push(score_mirror_prediction_positions(plan, &sampled).mirror_pair_hits);
    }
    Ok(distribution)
}

#[derive(Debug, Clone)]
struct GridLayoutPredictionScore {
    edge_hits: usize,
    edge_hit_rate: f64,
    matching_edge_positions_one_based: Vec<usize>,
    non_edge_positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone)]
struct TableauHillPredictionScore {
    best_axis: String,
    best_index_one_based: usize,
    best_hits: usize,
    best_hit_rate: f64,
    matching_positions_one_based: Vec<usize>,
    row_results: Vec<TableauHillAxisResult>,
    column_results: Vec<TableauHillAxisResult>,
}

fn score_grid_layout_edge_prediction_positions(
    plan: &GridLayoutPredictionPlan,
    edge_axis: GridLayoutEdgeAxis,
    observed_positions_one_based: &[usize],
) -> GridLayoutPredictionScore {
    let edge_positions = grid_layout_axis_positions(plan, edge_axis);
    let edges: HashSet<_> = edge_positions.iter().copied().collect();
    let mut matching_edge_positions_one_based = Vec::new();
    let mut non_edge_positions_one_based = Vec::new();
    for position in observed_positions_one_based {
        if edges.contains(position) {
            matching_edge_positions_one_based.push(*position);
        } else {
            non_edge_positions_one_based.push(*position);
        }
    }
    matching_edge_positions_one_based.sort_unstable();
    non_edge_positions_one_based.sort_unstable();
    let edge_hits = matching_edge_positions_one_based.len();
    let edge_hit_rate = edge_hits as f64 / observed_positions_one_based.len() as f64;
    GridLayoutPredictionScore {
        edge_hits,
        edge_hit_rate,
        matching_edge_positions_one_based,
        non_edge_positions_one_based,
    }
}

fn grid_layout_axis_positions(
    plan: &GridLayoutPredictionPlan,
    edge_axis: GridLayoutEdgeAxis,
) -> Vec<usize> {
    match edge_axis {
        GridLayoutEdgeAxis::Row => plan.row_edge_positions_one_based.clone(),
        GridLayoutEdgeAxis::Column => plan.column_edge_positions_one_based.clone(),
        GridLayoutEdgeAxis::CompassAxis => {
            let center_row = (plan.row_count + 1) / 2;
            let left_center_column = plan.column_count / 2;
            let right_center_column = left_center_column + 1;
            let mut positions = BTreeSet::new();
            for row in &plan.rows {
                if row.row_one_based == center_row {
                    positions.extend(row.non_anchor_positions_one_based.iter().copied());
                }
            }
            for column in &plan.columns {
                if column.column_one_based == left_center_column
                    || column.column_one_based == right_center_column
                {
                    positions.extend(column.non_anchor_positions_one_based.iter().copied());
                }
            }
            positions.into_iter().collect()
        }
    }
}

fn score_tableau_hill_prediction_positions(
    plan: &TableauHillPredictionPlan,
    observed_positions_one_based: &[usize],
) -> Result<TableauHillPredictionScore> {
    let observed: HashSet<_> = observed_positions_one_based.iter().copied().collect();
    let mut row_buckets: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut column_buckets: BTreeMap<usize, Vec<usize>> = BTreeMap::new();

    for cell in &plan.coordinate_mapping {
        let Some(position) = cell.k4_position_one_based else {
            continue;
        };
        if !observed.contains(&position) {
            continue;
        }
        row_buckets
            .entry(cell.row_one_based)
            .or_default()
            .push(position);
        column_buckets
            .entry(cell.column_one_based)
            .or_default()
            .push(position);
    }

    let mut row_results = axis_results("row", row_buckets, observed_positions_one_based.len());
    let mut column_results =
        axis_results("column", column_buckets, observed_positions_one_based.len());
    row_results.sort_by(|left, right| {
        right
            .hits
            .cmp(&left.hits)
            .then_with(|| left.index_one_based.cmp(&right.index_one_based))
    });
    column_results.sort_by(|left, right| {
        right
            .hits
            .cmp(&left.hits)
            .then_with(|| left.index_one_based.cmp(&right.index_one_based))
    });

    let best_row = row_results.first();
    let best_column = column_results.first();
    let best = match (best_row, best_column) {
        (Some(row), Some(column)) => {
            if row.hits >= column.hits {
                row
            } else {
                column
            }
        }
        (Some(row), None) => row,
        (None, Some(column)) => column,
        (None, None) => bail!("Tableau/HILL score requires at least one mapped observation"),
    };

    Ok(TableauHillPredictionScore {
        best_axis: best.axis.clone(),
        best_index_one_based: best.index_one_based,
        best_hits: best.hits,
        best_hit_rate: best.hit_rate,
        matching_positions_one_based: best.matching_positions_one_based.clone(),
        row_results,
        column_results,
    })
}

fn axis_results(
    axis: &str,
    buckets: BTreeMap<usize, Vec<usize>>,
    observed_position_count: usize,
) -> Vec<TableauHillAxisResult> {
    buckets
        .into_iter()
        .map(|(index_one_based, mut matching_positions_one_based)| {
            matching_positions_one_based.sort_unstable();
            let hits = matching_positions_one_based.len();
            TableauHillAxisResult {
                axis: axis.to_string(),
                index_one_based,
                hits,
                hit_rate: hits as f64 / observed_position_count as f64,
                matching_positions_one_based,
            }
        })
        .collect()
}

fn grid_layout_prediction_null_distribution(
    plan: &GridLayoutPredictionPlan,
    non_anchor_universe: &[usize],
    observed_position_count: usize,
    edge_axis: GridLayoutEdgeAxis,
    iterations: usize,
    seed: u64,
) -> Result<Vec<usize>> {
    if observed_position_count > non_anchor_universe.len() {
        bail!("observed position count exceeds non-anchor grid-layout prediction universe");
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut distribution = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut sampled = non_anchor_universe.to_vec();
        sampled.shuffle(&mut rng);
        sampled.truncate(observed_position_count);
        distribution
            .push(score_grid_layout_edge_prediction_positions(plan, edge_axis, &sampled).edge_hits);
    }
    Ok(distribution)
}

fn tableau_hill_prediction_null_distribution(
    plan: &TableauHillPredictionPlan,
    non_anchor_universe: &[usize],
    observed_position_count: usize,
    iterations: usize,
    seed: u64,
) -> Result<Vec<usize>> {
    if observed_position_count > non_anchor_universe.len() {
        bail!("observed position count exceeds non-anchor Tableau/HILL prediction universe");
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut distribution = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut sampled = non_anchor_universe.to_vec();
        sampled.shuffle(&mut rng);
        sampled.truncate(observed_position_count);
        distribution.push(score_tableau_hill_prediction_positions(plan, &sampled)?.best_hits);
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
    fn tableau_hill_plan_fixes_source_backed_mapping_without_promotion() {
        let plan = build_tableau_hill_prediction_plan();

        assert_eq!(plan.artifact_kind, "tableau-hill-source-mapping-plan");
        assert_eq!(plan.mapping_status, "fixed-before-scoring");
        assert_eq!(plan.row_count, 7);
        assert_eq!(plan.column_count, 14);
        assert_eq!(plan.cell_count, 98);
        assert_eq!(plan.k4_position_count, K4_CIPHERTEXT.len());
        assert_eq!(plan.padding_cell_count, 1);
        assert_eq!(plan.padding_cell_index_one_based, 98);
        assert_eq!(plan.coordinate_mapping.len(), 98);
        assert_eq!(plan.coordinate_mapping[0].k4_position_one_based, Some(1));
        assert_eq!(plan.coordinate_mapping[0].row_one_based, 1);
        assert_eq!(plan.coordinate_mapping[0].column_one_based, 1);
        assert_eq!(plan.coordinate_mapping[97].k4_position_one_based, None);
        assert!(plan.coordinate_mapping[97].is_padding);
        assert!(
            plan.coordinate_mapping.iter().any(
                |cell| cell.k4_position_one_based == Some(22) && cell.is_public_anchor_position
            )
        );
        assert!(!plan.promoted_candidate);
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
