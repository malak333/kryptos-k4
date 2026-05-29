use crate::known_anchors;
use crate::{Alphabet, K4_CIPHERTEXT};
use anyhow::{Result, bail};
use rand::seq::SliceRandom;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextProfile {
    pub ciphertext_length: usize,
    pub letter_frequencies: Vec<LetterFrequency>,
    pub index_of_coincidence: f64,
    pub repeated_ngrams: Vec<RepeatedNgram>,
    pub kasiski_factor_profiles: Vec<KasiskiFactorProfile>,
    pub kasiski_baseline: Option<KasiskiFactorBaseline>,
    pub period_profiles: Vec<PeriodProfile>,
    pub baseline: Option<CiphertextProfileBaseline>,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LetterFrequency {
    pub letter: char,
    pub count: usize,
    pub rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepeatedNgram {
    pub ngram: String,
    pub length: usize,
    pub count: usize,
    pub positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KasiskiFactorProfile {
    pub period: usize,
    pub supported_gap_count: usize,
    pub total_gap_count: usize,
    pub support_rate: f64,
    pub supporting_gaps: Vec<KasiskiGapSupport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KasiskiGapSupport {
    pub ngram: String,
    pub length: usize,
    pub left_position_one_based: usize,
    pub right_position_one_based: usize,
    pub gap: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeriodProfile {
    pub period: usize,
    pub shifted_match_count: usize,
    pub shifted_comparison_count: usize,
    pub shifted_match_rate: f64,
    pub shifted_matches: Vec<ShiftedMatch>,
    pub mean_coset_ic: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShiftedMatch {
    pub left_position_one_based: usize,
    pub right_position_one_based: usize,
    pub letter: char,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextProfileBaseline {
    pub observed_best_period: usize,
    pub observed_best_shifted_match_rate: f64,
    pub null_mean_best_shifted_match_rate: f64,
    pub null_std_dev_best_shifted_match_rate: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KasiskiFactorBaseline {
    pub observed_best_period: usize,
    pub observed_best_supported_gap_count: usize,
    pub null_mean_best_supported_gap_count: f64,
    pub null_std_dev_best_supported_gap_count: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextStructurePrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub selected_periods: Vec<CiphertextPriorPeriod>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextHotspotPrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub hotspot_count: usize,
    pub hotspots: Vec<CiphertextHotspot>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextResidueBalancePrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub selected_moduli_count: usize,
    pub selected_residue_sets: Vec<CiphertextResidueBalanceSet>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextRarityPrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub rare_position_count: usize,
    pub rare_positions: Vec<CiphertextRarityPosition>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextTransitionPrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub alphabet: String,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub transition_position_count: usize,
    pub transition_positions: Vec<CiphertextTransitionPosition>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextAdjacentContrastPrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub alphabet: String,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub contrast_position_count: usize,
    pub contrast_positions: Vec<CiphertextAdjacentContrastPosition>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextSkipTransitionPrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub alphabet: String,
    pub skip_distances: Vec<usize>,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub skip_transition_position_count: usize,
    pub skip_transition_positions: Vec<CiphertextSkipTransitionPosition>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextTurningPointPrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub alphabet: String,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub turning_point_position_count: usize,
    pub turning_point_positions: Vec<CiphertextTurningPointPosition>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextRepeatDistancePrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub repeat_distance_position_count: usize,
    pub repeat_distance_positions: Vec<CiphertextRepeatDistancePosition>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextPeriodMatchPrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub max_period: usize,
    pub top_periods: usize,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub period_match_set_count: usize,
    pub period_match_sets: Vec<CiphertextPeriodMatchSet>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextWindowBalancePrior {
    pub artifact_kind: String,
    pub hypothesis_family: String,
    pub source_inputs: Vec<String>,
    pub discovery_inputs: Vec<String>,
    pub prediction_target: String,
    pub alphabet: String,
    pub window_widths: Vec<usize>,
    pub non_anchor_position_count: usize,
    pub non_anchor_positions_one_based: Vec<usize>,
    pub window_balance_position_count: usize,
    pub window_balance_positions: Vec<CiphertextWindowBalancePosition>,
    pub controls: Vec<String>,
    pub public_anchor_fragments_used_for_discovery: bool,
    pub public_anchor_fragments_used_as_primary_evidence: bool,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextTransitionPosition {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub left_transition_distance: usize,
    pub right_transition_distance: usize,
    pub transition_score: usize,
    pub max_adjacent_transition_distance: usize,
    pub transition_rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextAdjacentContrastPosition {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub left_index: usize,
    pub center_index: usize,
    pub right_index: usize,
    pub left_linear_delta: i32,
    pub right_linear_delta: i32,
    pub neighbor_gap: usize,
    pub center_neighbor_deviation: usize,
    pub contrast_score: usize,
    pub contrast_rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextSkipTransitionPosition {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub skip_transition_score: usize,
    pub max_skip_transition_distance: usize,
    pub skip_distances_used: Vec<usize>,
    pub skip_transition_rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextTurningPointPosition {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub left_index: usize,
    pub center_index: usize,
    pub right_index: usize,
    pub left_delta: i32,
    pub right_delta: i32,
    pub curvature_score: usize,
    pub is_local_extremum: bool,
    pub turning_point_rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextRepeatDistancePosition {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub same_symbol_position_count: usize,
    pub distinct_repeat_distances: usize,
    pub nearest_repeat_distance: usize,
    pub repeat_distance_score: usize,
    pub repeat_distance_rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextPeriodMatchSet {
    pub period: usize,
    pub shifted_match_count: usize,
    pub shifted_comparison_count: usize,
    pub endpoint_position_count: usize,
    pub positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextWindowBalancePosition {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub best_window_width: usize,
    pub best_window_start_one_based: usize,
    pub best_window_end_one_based: usize,
    pub window_index_sum: usize,
    pub ideal_balanced_sum: usize,
    pub balance_deviation: usize,
    pub distinct_ciphertext_letters: usize,
    pub repeated_ciphertext_letters: usize,
    pub balance_score: usize,
    pub balance_rank: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextTransitionEvaluation {
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
    pub transition_position_count: usize,
    pub transition_hits: usize,
    pub transition_hit_rate: f64,
    pub matching_transition_positions_one_based: Vec<usize>,
    pub non_transition_positions_one_based: Vec<usize>,
    pub null_mean_transition_hits: f64,
    pub null_std_dev_transition_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextAdjacentContrastEvaluation {
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
    pub contrast_position_count: usize,
    pub contrast_hits: usize,
    pub contrast_hit_rate: f64,
    pub matching_contrast_positions_one_based: Vec<usize>,
    pub non_contrast_positions_one_based: Vec<usize>,
    pub null_mean_contrast_hits: f64,
    pub null_std_dev_contrast_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextSkipTransitionEvaluation {
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
    pub skip_transition_position_count: usize,
    pub skip_transition_hits: usize,
    pub skip_transition_hit_rate: f64,
    pub matching_skip_transition_positions_one_based: Vec<usize>,
    pub non_skip_transition_positions_one_based: Vec<usize>,
    pub null_mean_skip_transition_hits: f64,
    pub null_std_dev_skip_transition_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextTurningPointEvaluation {
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
    pub turning_point_position_count: usize,
    pub turning_point_hits: usize,
    pub turning_point_hit_rate: f64,
    pub matching_turning_point_positions_one_based: Vec<usize>,
    pub non_turning_point_positions_one_based: Vec<usize>,
    pub null_mean_turning_point_hits: f64,
    pub null_std_dev_turning_point_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextRepeatDistanceEvaluation {
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
    pub repeat_distance_position_count: usize,
    pub repeat_distance_hits: usize,
    pub repeat_distance_hit_rate: f64,
    pub matching_repeat_distance_positions_one_based: Vec<usize>,
    pub non_repeat_distance_positions_one_based: Vec<usize>,
    pub null_mean_repeat_distance_hits: f64,
    pub null_std_dev_repeat_distance_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextPeriodMatchEvaluation {
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
    pub period_match_set_count: usize,
    pub best_period: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub period_match_results: Vec<CiphertextPeriodMatchEvaluationSet>,
    pub null_mean_best_hits: f64,
    pub null_std_dev_best_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextPeriodMatchEvaluationSet {
    pub period: usize,
    pub hits: usize,
    pub hit_rate: f64,
    pub matching_positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextRarityPosition {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub non_anchor_letter_count: usize,
    pub rarity_rank: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextRarityEvaluation {
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
    pub rare_position_count: usize,
    pub rare_hits: usize,
    pub rare_hit_rate: f64,
    pub matching_rare_positions_one_based: Vec<usize>,
    pub non_rare_positions_one_based: Vec<usize>,
    pub null_mean_rare_hits: f64,
    pub null_std_dev_rare_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextResidueBalanceSet {
    pub modulus: usize,
    pub residue: usize,
    pub position_count: usize,
    pub distinct_ciphertext_letters: usize,
    pub distinct_letter_rate: f64,
    pub positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextResidueBalanceEvaluation {
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
    pub selected_residue_set_count: usize,
    pub best_modulus: usize,
    pub best_residue: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub residue_set_results: Vec<CiphertextResidueBalanceEvaluationSet>,
    pub null_mean_best_hits: f64,
    pub null_std_dev_best_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextResidueBalanceEvaluationSet {
    pub modulus: usize,
    pub residue: usize,
    pub hits: usize,
    pub hit_rate: f64,
    pub matching_positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextHotspot {
    pub position_one_based: usize,
    pub ciphertext: char,
    pub repeated_ngram_hits: usize,
    pub shifted_match_hits: usize,
    pub score: usize,
    pub support_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CiphertextHotspotEvaluation {
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
    pub hotspot_count: usize,
    pub hotspot_hits: usize,
    pub hotspot_hit_rate: f64,
    pub matching_hotspot_positions_one_based: Vec<usize>,
    pub non_hotspot_positions_one_based: Vec<usize>,
    pub null_mean_hotspot_hits: f64,
    pub null_std_dev_hotspot_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextPriorEvaluation {
    pub observation_id: Option<String>,
    pub observation_source_ids: Vec<String>,
    pub observation_source_review_file: Option<String>,
    pub observation_rationale: Option<String>,
    pub observation_position_notes: BTreeMap<String, String>,
    pub source_backed_observation: bool,
    pub observed_position_count: usize,
    pub observed_positions_one_based: Vec<usize>,
    pub selected_period_count: usize,
    pub best_period: usize,
    pub best_residue: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub period_results: Vec<CiphertextPriorEvaluationPeriod>,
    pub null_mean_best_hits: f64,
    pub null_std_dev_best_hits: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextPriorEvaluationPeriod {
    pub period: usize,
    pub support_kind: String,
    pub best_residue: usize,
    pub best_hits: usize,
    pub best_hit_rate: f64,
    pub residue_hits: Vec<CiphertextPriorResidueHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextPriorResidueHit {
    pub residue: usize,
    pub hits: usize,
    pub matching_positions_one_based: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiphertextPriorPeriod {
    pub period: usize,
    pub support_kind: String,
    pub observed_score: String,
    pub empirical_p_value: Option<f64>,
    pub non_anchor_residues: Vec<CiphertextPriorResidue>,
    pub interpretation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextPriorResidue {
    pub residue: usize,
    pub position_count: usize,
    pub positions_one_based: Vec<usize>,
}

pub fn profile_k4_ciphertext(
    max_period: usize,
    max_ngram: usize,
    top_repeated_ngrams: usize,
    baseline_iterations: usize,
    seed: u64,
) -> CiphertextProfile {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let ciphertext_length = letters.len();
    let letter_frequencies = letter_frequencies(&letters);
    let index_of_coincidence = index_of_coincidence(&letters);
    let repeated_ngrams = repeated_ngrams(&letters, max_ngram, top_repeated_ngrams);
    let all_repeated_ngrams = repeated_ngrams_all(&letters, max_ngram);
    let kasiski_factor_profiles = kasiski_factor_profiles(&all_repeated_ngrams, max_period);
    let period_profiles = period_profiles(&letters, max_period);
    let baseline = (baseline_iterations > 0).then(|| {
        ciphertext_profile_baseline(
            &letters,
            max_period,
            &period_profiles,
            baseline_iterations,
            seed,
        )
    });
    let kasiski_baseline = (baseline_iterations > 0).then(|| {
        kasiski_factor_baseline(
            &letters,
            max_period,
            max_ngram,
            &kasiski_factor_profiles,
            baseline_iterations,
            seed,
        )
    });

    CiphertextProfile {
        ciphertext_length,
        letter_frequencies,
        index_of_coincidence,
        repeated_ngrams,
        kasiski_factor_profiles,
        kasiski_baseline,
        period_profiles,
        baseline,
        promoted_candidate: false,
        note: "Ciphertext profile is a ciphertext-only diagnostic over public K4 text; it does not use public anchors, candidate words, claimed plaintext, or decrypted output."
            .to_string(),
    }
}

pub fn build_ciphertext_structure_prior(
    max_period: usize,
    max_ngram: usize,
    baseline_iterations: usize,
    seed: u64,
) -> CiphertextStructurePrior {
    let profile = profile_k4_ciphertext(max_period, max_ngram, 20, baseline_iterations, seed);
    let mut selected_periods = Vec::new();

    let best_spacing_period = best_kasiski_factor_profile(&profile.kasiski_factor_profiles).period;
    if let Some(best_spacing) = profile
        .kasiski_factor_profiles
        .iter()
        .find(|profile| profile.period == best_spacing_period)
    {
        let p_value = profile
            .kasiski_baseline
            .as_ref()
            .map(|baseline| baseline.empirical_p_value);
        selected_periods.push(CiphertextPriorPeriod {
            period: best_spacing.period,
            support_kind: "repeated-ngram-gap-factor".to_string(),
            observed_score: format!(
                "{}/{} supported repeated n-gram gaps",
                best_spacing.supported_gap_count, best_spacing.total_gap_count
            ),
            empirical_p_value: p_value,
            non_anchor_residues: non_anchor_residues(best_spacing.period),
            interpretation: "Weak ciphertext-only spacing prior; future observations must beat independent controls before interpretation."
                .to_string(),
        });
    }

    if let Some(best_shifted) = profile.period_profiles.iter().max_by(|left, right| {
        left.shifted_match_rate
            .total_cmp(&right.shifted_match_rate)
            .then_with(|| right.period.cmp(&left.period))
    }) {
        let p_value = profile
            .baseline
            .as_ref()
            .map(|baseline| baseline.empirical_p_value);
        if !selected_periods
            .iter()
            .any(|period| period.period == best_shifted.period)
        {
            selected_periods.push(CiphertextPriorPeriod {
                period: best_shifted.period,
                support_kind: "shifted-ciphertext-coincidence".to_string(),
                observed_score: format!(
                    "{}/{} shifted matches",
                    best_shifted.shifted_match_count, best_shifted.shifted_comparison_count
                ),
                empirical_p_value: p_value,
                non_anchor_residues: non_anchor_residues(best_shifted.period),
                interpretation: "Weak ciphertext-only coincidence prior; future observations must beat independent controls before interpretation."
                    .to_string(),
            });
        }
    }

    selected_periods.sort_by_key(|period| period.period);

    CiphertextStructurePrior {
        artifact_kind: "ciphertext-structure-prior".to_string(),
        hypothesis_family: "ciphertext-only-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only to exclude anchor ranges from future residue targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Repeated n-gram gap-factor profile over ciphertext letters".to_string(),
            "Shifted ciphertext coincidence profile over ciphertext letters".to_string(),
            "Seeded letter-shuffle baselines preserving the K4 letter multiset".to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations can be checked against these predeclared residue classes only after independent source review; this artifact is not evidence by itself."
            .to_string(),
        selected_periods,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from residue targets".to_string(),
            "seeded same-size position shuffle baseline required".to_string(),
            "best-of-selected-period control required".to_string(),
            "multiple-comparison correction required before interpretation".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext-structure prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_structure_prior() -> CiphertextStructurePrior {
    CiphertextStructurePrior {
        artifact_kind: "ciphertext-structure-prior".to_string(),
        hypothesis_family: "ciphertext-only-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only to exclude anchor ranges from future residue targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Repeated n-gram gap-factor profile over ciphertext letters".to_string(),
            "Shifted ciphertext coincidence profile over ciphertext letters".to_string(),
            "Seeded letter-shuffle baselines preserving the K4 letter multiset".to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations can be checked against these predeclared residue classes only after independent source review; this artifact is not evidence by itself."
            .to_string(),
        selected_periods: vec![
            CiphertextPriorPeriod {
                period: 2,
                support_kind: "repeated-ngram-gap-factor".to_string(),
                observed_score: "7/10 supported repeated n-gram gaps".to_string(),
                empirical_p_value: Some(0.056849431505684944),
                non_anchor_residues: non_anchor_residues(2),
                interpretation: "Weak ciphertext-only spacing prior; future observations must beat independent controls before interpretation."
                    .to_string(),
            },
            CiphertextPriorPeriod {
                period: 7,
                support_kind: "shifted-ciphertext-coincidence".to_string(),
                observed_score: "9/90 shifted matches".to_string(),
                empirical_p_value: Some(0.07186928130718692),
                non_anchor_residues: non_anchor_residues(7),
                interpretation: "Weak ciphertext-only coincidence prior; future observations must beat independent controls before interpretation."
                    .to_string(),
            },
        ],
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from residue targets".to_string(),
            "seeded same-size position shuffle baseline required".to_string(),
            "best-of-selected-period control required".to_string(),
            "multiple-comparison correction required before interpretation".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext-structure prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_ciphertext_hotspot_prior(
    max_period: usize,
    max_ngram: usize,
    top_hotspots: usize,
) -> CiphertextHotspotPrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let non_anchor_positions = non_anchor_positions_one_based();
    let mut hotspots = ciphertext_hotspot_scores(&letters, max_period, max_ngram);
    let non_anchor_set: HashSet<_> = non_anchor_positions.iter().copied().collect();
    hotspots.retain(|hotspot| {
        non_anchor_set.contains(&hotspot.position_one_based) && hotspot.score > 0
    });
    hotspots.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.repeated_ngram_hits.cmp(&left.repeated_ngram_hits))
            .then_with(|| right.shifted_match_hits.cmp(&left.shifted_match_hits))
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    hotspots.truncate(top_hotspots);
    hotspots.sort_by_key(|hotspot| hotspot.position_one_based);

    CiphertextHotspotPrior {
        artifact_kind: "ciphertext-hotspot-prior".to_string(),
        hypothesis_family: "ciphertext-hotspot-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            format!("Repeated n-gram coverage over ciphertext letters for lengths 2..={max_ngram}"),
            format!("Shifted ciphertext self-coincidence endpoints for periods 1..={max_period}"),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared ciphertext-only hotspot positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        hotspot_count: hotspots.len(),
        hotspots,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from hotspot target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext-hotspot prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_hotspot_prior() -> CiphertextHotspotPrior {
    build_ciphertext_hotspot_prior(20, 4, 20)
}

pub fn build_ciphertext_residue_balance_prior(
    min_modulus: usize,
    max_modulus: usize,
) -> CiphertextResidueBalancePrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let non_anchor_positions = non_anchor_positions_one_based();
    let selected_residue_sets = (min_modulus..=max_modulus)
        .filter_map(|modulus| best_balanced_residue_set(modulus, &letters, &non_anchor_positions))
        .collect::<Vec<_>>();

    CiphertextResidueBalancePrior {
        artifact_kind: "ciphertext-residue-balance-prior".to_string(),
        hypothesis_family: "ciphertext-residue-balance-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            format!(
                "For each modulus {min_modulus}..={max_modulus}, select the non-anchor residue class with the highest distinct ciphertext-letter rate"
            ),
            "Tie-break by larger position count, then lower residue number".to_string(),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in these predeclared ciphertext-only residue-balance sets before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        selected_moduli_count: selected_residue_sets.len(),
        selected_residue_sets,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from residue-balance target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "best-of-modulus null control required".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext residue-balance prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_residue_balance_prior() -> CiphertextResidueBalancePrior {
    build_ciphertext_residue_balance_prior(2, 13)
}

pub fn build_ciphertext_rarity_prior(top_rare_positions: usize) -> CiphertextRarityPrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let non_anchor_positions = non_anchor_positions_one_based();
    let mut non_anchor_letter_counts = BTreeMap::<char, usize>::new();
    for position in &non_anchor_positions {
        if let Some(letter) = letters.get(position - 1) {
            *non_anchor_letter_counts.entry(*letter).or_default() += 1;
        }
    }

    let mut rare_positions: Vec<_> = non_anchor_positions
        .iter()
        .filter_map(|position| {
            let ciphertext = *letters.get(position - 1)?;
            let non_anchor_letter_count = *non_anchor_letter_counts.get(&ciphertext)?;
            Some(CiphertextRarityPosition {
                position_one_based: *position,
                ciphertext,
                non_anchor_letter_count,
                rarity_rank: 0,
            })
        })
        .collect();
    rare_positions.sort_by(|left, right| {
        left.non_anchor_letter_count
            .cmp(&right.non_anchor_letter_count)
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    rare_positions.truncate(top_rare_positions);
    for (index, position) in rare_positions.iter_mut().enumerate() {
        position.rarity_rank = index + 1;
    }
    rare_positions.sort_by_key(|position| position.position_one_based);

    CiphertextRarityPrior {
        artifact_kind: "ciphertext-rarity-prior".to_string(),
        hypothesis_family: "ciphertext-rarity-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Count ciphertext letters across the non-anchor K4 position universe".to_string(),
            format!(
                "Predeclare the {top_rare_positions} non-anchor positions whose ciphertext letters are rarest; tie-break by lower one-based position"
            ),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared rare-ciphertext-letter positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        rare_position_count: rare_positions.len(),
        rare_positions,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from rare-position target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext-rarity prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_rarity_prior() -> CiphertextRarityPrior {
    build_ciphertext_rarity_prior(20)
}

pub fn build_ciphertext_adjacent_contrast_prior(
    top_contrast_positions: usize,
) -> CiphertextAdjacentContrastPrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let alphabet = Alphabet::kryptos();
    let non_anchor_positions = non_anchor_positions_one_based();
    let mut contrast_positions: Vec<_> = non_anchor_positions
        .iter()
        .filter_map(|position| {
            let index = position - 1;
            if index == 0 || index + 1 >= letters.len() {
                return None;
            }
            let ciphertext = *letters.get(index)?;
            let left_index = alphabet.index_of(letters[index - 1]).ok()? as usize;
            let center_index = alphabet.index_of(ciphertext).ok()? as usize;
            let right_index = alphabet.index_of(letters[index + 1]).ok()? as usize;
            let left_linear_delta = center_index as i32 - left_index as i32;
            let right_linear_delta = right_index as i32 - center_index as i32;
            let neighbor_gap = left_index.abs_diff(right_index);
            let center_neighbor_deviation = (2 * center_index).abs_diff(left_index + right_index);
            let contrast_score = center_neighbor_deviation * 10 + neighbor_gap;
            Some(CiphertextAdjacentContrastPosition {
                position_one_based: *position,
                ciphertext,
                left_index,
                center_index,
                right_index,
                left_linear_delta,
                right_linear_delta,
                neighbor_gap,
                center_neighbor_deviation,
                contrast_score,
                contrast_rank: 0,
            })
        })
        .collect();

    contrast_positions.sort_by(|left, right| {
        right
            .contrast_score
            .cmp(&left.contrast_score)
            .then_with(|| {
                right
                    .center_neighbor_deviation
                    .cmp(&left.center_neighbor_deviation)
            })
            .then_with(|| right.neighbor_gap.cmp(&left.neighbor_gap))
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    contrast_positions.truncate(top_contrast_positions);
    for (index, position) in contrast_positions.iter_mut().enumerate() {
        position.contrast_rank = index + 1;
    }
    contrast_positions.sort_by_key(|position| position.position_one_based);

    CiphertextAdjacentContrastPrior {
        artifact_kind: "ciphertext-adjacent-contrast-prior".to_string(),
        hypothesis_family: "ciphertext-adjacent-contrast-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Map ciphertext letters onto linear Kryptos alphabet indexes".to_string(),
            "For each interior non-anchor position, score how far the center index deviates from the midpoint of its immediate neighbors".to_string(),
            format!(
                "Predeclare the {top_contrast_positions} non-anchor positions with highest adjacent-contrast pressure; tie-break by center-neighbor deviation, neighbor gap, then lower one-based position"
            ),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared high adjacent-contrast positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        alphabet: "Kryptos".to_string(),
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        contrast_position_count: contrast_positions.len(),
        contrast_positions,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from adjacent-contrast target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "ciphertext-symbol shuffle baseline preserving K4 length and alphabet membership required before interpreting any positive result".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext adjacent-contrast prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_adjacent_contrast_prior() -> CiphertextAdjacentContrastPrior {
    build_ciphertext_adjacent_contrast_prior(20)
}

pub fn build_ciphertext_transition_prior(
    top_transition_positions: usize,
) -> CiphertextTransitionPrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let alphabet = Alphabet::kryptos();
    let non_anchor_positions = non_anchor_positions_one_based();
    let mut transition_positions: Vec<_> = non_anchor_positions
        .iter()
        .filter_map(|position| {
            let index = position - 1;
            let ciphertext = *letters.get(index)?;
            let left_transition_distance = if index > 0 {
                kryptos_circular_distance(&alphabet, ciphertext, letters[index - 1]).ok()?
            } else {
                0
            };
            let right_transition_distance = if index + 1 < letters.len() {
                kryptos_circular_distance(&alphabet, ciphertext, letters[index + 1]).ok()?
            } else {
                0
            };
            let transition_score = left_transition_distance + right_transition_distance;
            let max_adjacent_transition_distance =
                left_transition_distance.max(right_transition_distance);
            Some(CiphertextTransitionPosition {
                position_one_based: *position,
                ciphertext,
                left_transition_distance,
                right_transition_distance,
                transition_score,
                max_adjacent_transition_distance,
                transition_rank: 0,
            })
        })
        .collect();

    transition_positions.sort_by(|left, right| {
        right
            .transition_score
            .cmp(&left.transition_score)
            .then_with(|| {
                right
                    .max_adjacent_transition_distance
                    .cmp(&left.max_adjacent_transition_distance)
            })
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    transition_positions.truncate(top_transition_positions);
    for (index, position) in transition_positions.iter_mut().enumerate() {
        position.transition_rank = index + 1;
    }
    transition_positions.sort_by_key(|position| position.position_one_based);

    CiphertextTransitionPrior {
        artifact_kind: "ciphertext-transition-prior".to_string(),
        hypothesis_family: "ciphertext-transition-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Map ciphertext letters onto the Kryptos alphabet order".to_string(),
            "For each non-anchor position, sum circular alphabet distances to its adjacent ciphertext letters"
                .to_string(),
            format!(
                "Predeclare the {top_transition_positions} non-anchor positions with highest adjacent-transition pressure; tie-break by max adjacent distance, then lower one-based position"
            ),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared high-transition-pressure positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        alphabet: "Kryptos".to_string(),
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        transition_position_count: transition_positions.len(),
        transition_positions,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from transition target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext-transition prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_transition_prior() -> CiphertextTransitionPrior {
    build_ciphertext_transition_prior(20)
}

pub fn build_ciphertext_skip_transition_prior(
    top_skip_transition_positions: usize,
    skip_distances: Vec<usize>,
) -> CiphertextSkipTransitionPrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let alphabet = Alphabet::kryptos();
    let non_anchor_positions = non_anchor_positions_one_based();
    let skip_distances = skip_distances
        .into_iter()
        .filter(|distance| *distance > 0)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut skip_transition_positions: Vec<_> = non_anchor_positions
        .iter()
        .filter_map(|position| {
            let index = position - 1;
            let ciphertext = *letters.get(index)?;
            let mut skip_transition_score = 0usize;
            let mut max_skip_transition_distance = 0usize;
            let mut skip_distances_used = Vec::new();
            for distance in &skip_distances {
                let mut used = false;
                if index >= *distance {
                    let distance_score =
                        kryptos_circular_distance(&alphabet, ciphertext, letters[index - distance])
                            .ok()?;
                    skip_transition_score += distance_score;
                    max_skip_transition_distance = max_skip_transition_distance.max(distance_score);
                    used = true;
                }
                if index + distance < letters.len() {
                    let distance_score =
                        kryptos_circular_distance(&alphabet, ciphertext, letters[index + distance])
                            .ok()?;
                    skip_transition_score += distance_score;
                    max_skip_transition_distance = max_skip_transition_distance.max(distance_score);
                    used = true;
                }
                if used {
                    skip_distances_used.push(*distance);
                }
            }
            Some(CiphertextSkipTransitionPosition {
                position_one_based: *position,
                ciphertext,
                skip_transition_score,
                max_skip_transition_distance,
                skip_distances_used,
                skip_transition_rank: 0,
            })
        })
        .collect();

    skip_transition_positions.sort_by(|left, right| {
        right
            .skip_transition_score
            .cmp(&left.skip_transition_score)
            .then_with(|| {
                right
                    .max_skip_transition_distance
                    .cmp(&left.max_skip_transition_distance)
            })
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    skip_transition_positions.truncate(top_skip_transition_positions);
    for (index, position) in skip_transition_positions.iter_mut().enumerate() {
        position.skip_transition_rank = index + 1;
    }
    skip_transition_positions.sort_by_key(|position| position.position_one_based);

    CiphertextSkipTransitionPrior {
        artifact_kind: "ciphertext-skip-transition-prior".to_string(),
        hypothesis_family: "ciphertext-skip-transition-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Map ciphertext letters onto the Kryptos alphabet order".to_string(),
            format!(
                "For each non-anchor position, sum circular alphabet distances to ciphertext letters at skip distances {}",
                skip_distances
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            format!(
                "Predeclare the {top_skip_transition_positions} non-anchor positions with highest skip-transition pressure; tie-break by max skip distance score, then lower one-based position"
            ),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared high skip-transition-pressure positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        alphabet: "Kryptos".to_string(),
        skip_distances,
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        skip_transition_position_count: skip_transition_positions.len(),
        skip_transition_positions,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from skip-transition target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext skip-transition prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_skip_transition_prior() -> CiphertextSkipTransitionPrior {
    build_ciphertext_skip_transition_prior(20, vec![1, 2])
}

pub fn build_ciphertext_turning_point_prior(
    top_turning_point_positions: usize,
) -> CiphertextTurningPointPrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let alphabet = Alphabet::kryptos();
    let non_anchor_positions = non_anchor_positions_one_based();
    let mut turning_point_positions: Vec<_> = non_anchor_positions
        .iter()
        .filter_map(|position| {
            let index = position - 1;
            if index == 0 || index + 1 >= letters.len() {
                return None;
            }
            let ciphertext = *letters.get(index)?;
            let left_index = alphabet.index_of(letters[index - 1]).ok()? as usize;
            let center_index = alphabet.index_of(ciphertext).ok()? as usize;
            let right_index = alphabet.index_of(letters[index + 1]).ok()? as usize;
            let left_delta = center_index as i32 - left_index as i32;
            let right_delta = right_index as i32 - center_index as i32;
            let is_local_extremum =
                (left_delta > 0 && right_delta < 0) || (left_delta < 0 && right_delta > 0);
            let curvature_score = (right_delta - left_delta).unsigned_abs() as usize;
            Some(CiphertextTurningPointPosition {
                position_one_based: *position,
                ciphertext,
                left_index,
                center_index,
                right_index,
                left_delta,
                right_delta,
                curvature_score,
                is_local_extremum,
                turning_point_rank: 0,
            })
        })
        .collect();

    turning_point_positions.sort_by(|left, right| {
        right
            .is_local_extremum
            .cmp(&left.is_local_extremum)
            .then_with(|| right.curvature_score.cmp(&left.curvature_score))
            .then_with(|| {
                right
                    .left_delta
                    .unsigned_abs()
                    .cmp(&left.left_delta.unsigned_abs())
            })
            .then_with(|| {
                right
                    .right_delta
                    .unsigned_abs()
                    .cmp(&left.right_delta.unsigned_abs())
            })
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    turning_point_positions.truncate(top_turning_point_positions);
    for (index, position) in turning_point_positions.iter_mut().enumerate() {
        position.turning_point_rank = index + 1;
    }
    turning_point_positions.sort_by_key(|position| position.position_one_based);

    CiphertextTurningPointPrior {
        artifact_kind: "ciphertext-turning-point-prior".to_string(),
        hypothesis_family: "ciphertext-turning-point-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Map ciphertext letters onto the Kryptos alphabet order".to_string(),
            "For each interior non-anchor position, compute signed index deltas to the previous and next ciphertext letters"
                .to_string(),
            format!(
                "Predeclare the {top_turning_point_positions} non-anchor positions with strongest local turning-point structure; prefer local extrema, then higher second-difference curvature, then lower one-based position"
            ),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared ciphertext local turning-point positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        alphabet: "Kryptos".to_string(),
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        turning_point_position_count: turning_point_positions.len(),
        turning_point_positions,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from turning-point target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext turning-point prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_turning_point_prior() -> CiphertextTurningPointPrior {
    build_ciphertext_turning_point_prior(20)
}

pub fn build_ciphertext_repeat_distance_prior(
    top_repeat_distance_positions: usize,
) -> CiphertextRepeatDistancePrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let non_anchor_positions = non_anchor_positions_one_based();
    let non_anchor_set: HashSet<_> = non_anchor_positions.iter().copied().collect();
    let mut positions_by_symbol = BTreeMap::<char, Vec<usize>>::new();
    for (index, letter) in letters.iter().enumerate() {
        positions_by_symbol
            .entry(*letter)
            .or_default()
            .push(index + 1);
    }

    let mut repeat_distance_positions: Vec<_> = letters
        .iter()
        .enumerate()
        .filter_map(|(index, ciphertext)| {
            let position_one_based = index + 1;
            if !non_anchor_set.contains(&position_one_based) {
                return None;
            }
            let same_symbol_positions = positions_by_symbol.get(ciphertext)?;
            let distances = same_symbol_positions
                .iter()
                .filter(|position| **position != position_one_based)
                .map(|position| position.abs_diff(position_one_based))
                .collect::<BTreeSet<_>>();
            if distances.is_empty() {
                return None;
            }
            let same_symbol_position_count = same_symbol_positions.len() - 1;
            let distinct_repeat_distances = distances.len();
            let nearest_repeat_distance = distances.iter().next().copied().unwrap_or(0);
            let repeat_distance_score = same_symbol_position_count * 10 + distinct_repeat_distances;
            Some(CiphertextRepeatDistancePosition {
                position_one_based,
                ciphertext: *ciphertext,
                same_symbol_position_count,
                distinct_repeat_distances,
                nearest_repeat_distance,
                repeat_distance_score,
                repeat_distance_rank: 0,
            })
        })
        .collect();

    repeat_distance_positions.sort_by(|left, right| {
        right
            .repeat_distance_score
            .cmp(&left.repeat_distance_score)
            .then_with(|| {
                right
                    .same_symbol_position_count
                    .cmp(&left.same_symbol_position_count)
            })
            .then_with(|| {
                right
                    .distinct_repeat_distances
                    .cmp(&left.distinct_repeat_distances)
            })
            .then_with(|| {
                left.nearest_repeat_distance
                    .cmp(&right.nearest_repeat_distance)
            })
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    repeat_distance_positions.truncate(top_repeat_distance_positions);
    for (index, position) in repeat_distance_positions.iter_mut().enumerate() {
        position.repeat_distance_rank = index + 1;
    }
    repeat_distance_positions.sort_by_key(|position| position.position_one_based);

    CiphertextRepeatDistancePrior {
        artifact_kind: "ciphertext-repeat-distance-prior".to_string(),
        hypothesis_family: "ciphertext-repeat-distance-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Group raw K4 ciphertext positions by repeated ciphertext symbol".to_string(),
            "For each non-anchor position, count same-symbol partners and distinct pairwise repeat distances across the full ciphertext".to_string(),
            format!(
                "Predeclare the {top_repeat_distance_positions} non-anchor positions with highest repeat-distance support; tie-break by same-symbol partner count, distinct distances, nearest repeat distance, then lower one-based position"
            ),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared ciphertext repeat-distance positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        repeat_distance_position_count: repeat_distance_positions.len(),
        repeat_distance_positions,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from repeat-distance target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "symbol-label shuffle baseline preserving ciphertext position count and alphabet membership required before interpreting any positive result".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext repeat-distance prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_repeat_distance_prior() -> CiphertextRepeatDistancePrior {
    build_ciphertext_repeat_distance_prior(20)
}

pub fn build_ciphertext_period_match_prior(
    max_period: usize,
    top_periods: usize,
) -> CiphertextPeriodMatchPrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let non_anchor_positions = non_anchor_positions_one_based();
    let non_anchor_set: HashSet<_> = non_anchor_positions.iter().copied().collect();
    let mut period_match_sets = period_profiles(&letters, max_period)
        .into_iter()
        .filter(|profile| profile.shifted_match_count > 0)
        .map(|profile| {
            let mut positions_one_based = profile
                .shifted_matches
                .iter()
                .flat_map(|shifted_match| {
                    [
                        shifted_match.left_position_one_based,
                        shifted_match.right_position_one_based,
                    ]
                })
                .filter(|position| non_anchor_set.contains(position))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            positions_one_based.sort_unstable();
            CiphertextPeriodMatchSet {
                period: profile.period,
                shifted_match_count: profile.shifted_match_count,
                shifted_comparison_count: profile.shifted_comparison_count,
                endpoint_position_count: positions_one_based.len(),
                positions_one_based,
            }
        })
        .filter(|set| !set.positions_one_based.is_empty())
        .collect::<Vec<_>>();
    period_match_sets.sort_by(|left, right| {
        right
            .shifted_match_count
            .cmp(&left.shifted_match_count)
            .then_with(|| {
                right
                    .endpoint_position_count
                    .cmp(&left.endpoint_position_count)
            })
            .then_with(|| left.period.cmp(&right.period))
    });
    period_match_sets.truncate(top_periods);
    period_match_sets.sort_by_key(|set| set.period);

    CiphertextPeriodMatchPrior {
        artifact_kind: "ciphertext-period-match-prior".to_string(),
        hypothesis_family: "ciphertext-period-match-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            format!("Compute same-letter shifted ciphertext matches for periods 1..={max_period}"),
            format!(
                "Predeclare the {top_periods} periods with the most shifted matches; tie-break by non-anchor endpoint coverage, then lower period"
            ),
            "Score only non-anchor endpoints of those shifted same-letter pairs".to_string(),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in endpoints of predeclared ciphertext-only same-letter period matches before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        max_period,
        top_periods,
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        period_match_set_count: period_match_sets.len(),
        period_match_sets,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from period-match endpoint target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "best-of-selected-period null control required".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext period-match prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_period_match_prior() -> CiphertextPeriodMatchPrior {
    build_ciphertext_period_match_prior(20, 5)
}

pub fn build_ciphertext_window_balance_prior(
    top_window_balance_positions: usize,
    window_widths: Vec<usize>,
) -> CiphertextWindowBalancePrior {
    let letters: Vec<char> = K4_CIPHERTEXT.chars().collect();
    let alphabet = Alphabet::kryptos();
    let non_anchor_positions = non_anchor_positions_one_based();
    let non_anchor_set: HashSet<_> = non_anchor_positions.iter().copied().collect();
    let mut normalized_window_widths: Vec<_> = window_widths
        .into_iter()
        .filter(|width| *width >= 3 && *width % 2 == 1)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if normalized_window_widths.is_empty() {
        normalized_window_widths = vec![3, 5, 7];
    }

    let mut window_balance_positions: Vec<_> = letters
        .iter()
        .enumerate()
        .filter_map(|(index, ciphertext)| {
            let position_one_based = index + 1;
            if !non_anchor_set.contains(&position_one_based) {
                return None;
            }
            normalized_window_widths
                .iter()
                .filter_map(|width| {
                    let radius = width / 2;
                    if index < radius || index + radius >= letters.len() {
                        return None;
                    }
                    let start = index - radius;
                    let end = index + radius;
                    let mut window_index_sum = 0;
                    let mut distinct_letters = BTreeSet::new();
                    for letter in &letters[start..=end] {
                        window_index_sum += alphabet.index_of(*letter).ok()? as usize;
                        distinct_letters.insert(*letter);
                    }
                    let ideal_balanced_sum = 12 * width;
                    let balance_deviation = window_index_sum.abs_diff(ideal_balanced_sum);
                    let distinct_ciphertext_letters = distinct_letters.len();
                    let repeated_ciphertext_letters = width - distinct_ciphertext_letters;
                    let balance_score = (26 * width).saturating_sub(balance_deviation)
                        + distinct_ciphertext_letters * 5
                        - repeated_ciphertext_letters * 3;
                    Some(CiphertextWindowBalancePosition {
                        position_one_based,
                        ciphertext: *ciphertext,
                        best_window_width: *width,
                        best_window_start_one_based: start + 1,
                        best_window_end_one_based: end + 1,
                        window_index_sum,
                        ideal_balanced_sum,
                        balance_deviation,
                        distinct_ciphertext_letters,
                        repeated_ciphertext_letters,
                        balance_score,
                        balance_rank: 0,
                    })
                })
                .max_by(|left, right| {
                    left.balance_score
                        .cmp(&right.balance_score)
                        .then_with(|| right.balance_deviation.cmp(&left.balance_deviation))
                        .then_with(|| {
                            left.distinct_ciphertext_letters
                                .cmp(&right.distinct_ciphertext_letters)
                        })
                        .then_with(|| right.best_window_width.cmp(&left.best_window_width))
                })
        })
        .collect();

    window_balance_positions.sort_by(|left, right| {
        right
            .balance_score
            .cmp(&left.balance_score)
            .then_with(|| left.balance_deviation.cmp(&right.balance_deviation))
            .then_with(|| {
                right
                    .distinct_ciphertext_letters
                    .cmp(&left.distinct_ciphertext_letters)
            })
            .then_with(|| {
                left.repeated_ciphertext_letters
                    .cmp(&right.repeated_ciphertext_letters)
            })
            .then_with(|| left.position_one_based.cmp(&right.position_one_based))
    });
    window_balance_positions.truncate(top_window_balance_positions);
    for (index, position) in window_balance_positions.iter_mut().enumerate() {
        position.balance_rank = index + 1;
    }
    window_balance_positions.sort_by_key(|position| position.position_one_based);

    CiphertextWindowBalancePrior {
        artifact_kind: "ciphertext-window-balance-prior".to_string(),
        hypothesis_family: "ciphertext-window-balance-position-prior".to_string(),
        source_inputs: vec![
            "Public K4 ciphertext only".to_string(),
            "Public anchor positions used only as an exclusion mask for future non-anchor targets"
                .to_string(),
        ],
        discovery_inputs: vec![
            "Map ciphertext letters onto linear Kryptos alphabet indexes".to_string(),
            format!(
                "For each non-anchor position, score centered local windows with odd widths {:?} by closeness to the alphabet midpoint and low repeated-letter count",
                normalized_window_widths
            ),
            format!(
                "Predeclare the {top_window_balance_positions} non-anchor positions with highest local-window balance score; tie-break by lower deviation, more distinct letters, fewer repeated letters, then lower one-based position"
            ),
            "No candidate words, routes, plaintext claims, or public-anchor additive fragments"
                .to_string(),
        ],
        prediction_target: "Future source-backed non-anchor K4 position observations should be enriched in the predeclared ciphertext local-window balance positions before any candidate-word or public-anchor-derived tuning is performed."
            .to_string(),
        alphabet: "Kryptos".to_string(),
        window_widths: normalized_window_widths,
        non_anchor_position_count: non_anchor_positions.len(),
        non_anchor_positions_one_based: non_anchor_positions,
        window_balance_position_count: window_balance_positions.len(),
        window_balance_positions,
        controls: vec![
            "source-backed observation file required before scoring".to_string(),
            "public anchor positions excluded from local-window balance target positions".to_string(),
            "seeded same-size non-anchor position-shuffle baseline required".to_string(),
            "ciphertext-symbol shuffle baseline preserving K4 length and alphabet membership required before interpreting any positive result".to_string(),
            "multiple-comparison context across all preregistered independent lanes required before interpretation".to_string(),
            "promotion blocked unless future independent observations beat controls without post-hoc retuning".to_string(),
        ],
        public_anchor_fragments_used_for_discovery: false,
        public_anchor_fragments_used_as_primary_evidence: false,
        promoted_candidate: false,
        note: "Ciphertext local-window balance prior is a planning artifact for future independent observations; it is not a claimed solution, key, route, plaintext, or promotion criterion."
            .to_string(),
    }
}

pub fn build_committed_ciphertext_window_balance_prior() -> CiphertextWindowBalancePrior {
    build_ciphertext_window_balance_prior(20, vec![3, 5, 7])
}

pub fn evaluate_ciphertext_transition_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextTransitionEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-transition evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-transition evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextTransitionPrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-transition-prior" {
        bail!(
            "ciphertext-transition artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-transition artifact"
            );
        }
    }

    let transition_set: HashSet<_> = prior
        .transition_positions
        .iter()
        .map(|position| position.position_one_based)
        .collect();
    let matching_transition_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| transition_set.contains(position))
        .collect();
    let non_transition_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| !transition_set.contains(position))
        .collect();
    let transition_hits = matching_transition_positions_one_based.len();
    let transition_hit_rate = transition_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let hits = shuffled
            .iter()
            .filter(|position| transition_set.contains(position))
            .count();
        null_values.push(hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= transition_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextTransitionEvaluation {
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
        transition_position_count: prior.transition_position_count,
        transition_hits,
        transition_hit_rate,
        matching_transition_positions_one_based,
        non_transition_positions_one_based,
        null_mean_transition_hits: null_mean,
        null_std_dev_transition_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext-transition evaluation scores source-backed non-anchor positions against a ciphertext-only adjacent-transition artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_period_match_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextPeriodMatchEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-period-match evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-period-match evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextPeriodMatchPrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-period-match-prior" {
        bail!(
            "ciphertext-period-match artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-period-match artifact"
            );
        }
    }

    let period_match_results = evaluate_period_match_sets(&prior, &observed_positions_one_based);
    let (best_period, best_hits) = period_match_results
        .iter()
        .max_by(|left, right| {
            left.hits
                .cmp(&right.hits)
                .then_with(|| right.period.cmp(&left.period))
        })
        .map(|result| (result.period, result.hits))
        .unwrap_or((0, 0));
    let best_hit_rate = best_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let null_results = evaluate_period_match_sets(&prior, &shuffled);
        let null_best_hits = null_results
            .iter()
            .map(|result| result.hits)
            .max()
            .unwrap_or(0);
        null_values.push(null_best_hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= best_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextPeriodMatchEvaluation {
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
        period_match_set_count: prior.period_match_set_count,
        best_period,
        best_hits,
        best_hit_rate,
        period_match_results,
        null_mean_best_hits: null_mean,
        null_std_dev_best_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext period-match evaluation scores source-backed non-anchor positions against endpoints of ciphertext-only shifted same-letter period matches with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

fn evaluate_period_match_sets(
    prior: &CiphertextPeriodMatchPrior,
    observed_positions_one_based: &[usize],
) -> Vec<CiphertextPeriodMatchEvaluationSet> {
    prior
        .period_match_sets
        .iter()
        .map(|set| {
            let target_positions = set
                .positions_one_based
                .iter()
                .copied()
                .collect::<HashSet<_>>();
            let matching_positions_one_based = observed_positions_one_based
                .iter()
                .copied()
                .filter(|position| target_positions.contains(position))
                .collect::<Vec<_>>();
            let hits = matching_positions_one_based.len();
            let hit_rate = if observed_positions_one_based.is_empty() {
                0.0
            } else {
                hits as f64 / observed_positions_one_based.len() as f64
            };
            CiphertextPeriodMatchEvaluationSet {
                period: set.period,
                hits,
                hit_rate,
                matching_positions_one_based,
            }
        })
        .collect()
}

pub fn evaluate_ciphertext_adjacent_contrast_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextAdjacentContrastEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-adjacent-contrast evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-adjacent-contrast evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextAdjacentContrastPrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-adjacent-contrast-prior" {
        bail!(
            "ciphertext-adjacent-contrast artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-adjacent-contrast artifact"
            );
        }
    }

    let contrast_set: HashSet<_> = prior
        .contrast_positions
        .iter()
        .map(|position| position.position_one_based)
        .collect();
    let matching_contrast_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| contrast_set.contains(position))
        .collect();
    let non_contrast_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| !contrast_set.contains(position))
        .collect();
    let contrast_hits = matching_contrast_positions_one_based.len();
    let contrast_hit_rate = contrast_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let hits = shuffled
            .iter()
            .filter(|position| contrast_set.contains(position))
            .count();
        null_values.push(hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= contrast_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextAdjacentContrastEvaluation {
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
        contrast_position_count: prior.contrast_position_count,
        contrast_hits,
        contrast_hit_rate,
        matching_contrast_positions_one_based,
        non_contrast_positions_one_based,
        null_mean_contrast_hits: null_mean,
        null_std_dev_contrast_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext adjacent-contrast evaluation scores source-backed non-anchor positions against a ciphertext-only adjacent-contrast artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_skip_transition_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextSkipTransitionEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-skip-transition evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-skip-transition evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextSkipTransitionPrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-skip-transition-prior" {
        bail!(
            "ciphertext-skip-transition artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-skip-transition artifact"
            );
        }
    }

    let skip_transition_set: HashSet<_> = prior
        .skip_transition_positions
        .iter()
        .map(|position| position.position_one_based)
        .collect();
    let matching_skip_transition_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| skip_transition_set.contains(position))
        .collect();
    let non_skip_transition_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| !skip_transition_set.contains(position))
        .collect();
    let skip_transition_hits = matching_skip_transition_positions_one_based.len();
    let skip_transition_hit_rate =
        skip_transition_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let hits = shuffled
            .iter()
            .filter(|position| skip_transition_set.contains(position))
            .count();
        null_values.push(hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= skip_transition_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextSkipTransitionEvaluation {
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
        skip_transition_position_count: prior.skip_transition_position_count,
        skip_transition_hits,
        skip_transition_hit_rate,
        matching_skip_transition_positions_one_based,
        non_skip_transition_positions_one_based,
        null_mean_skip_transition_hits: null_mean,
        null_std_dev_skip_transition_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext skip-transition evaluation scores source-backed non-anchor positions against a ciphertext-only skip-transition artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_turning_point_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextTurningPointEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-turning-point evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-turning-point evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextTurningPointPrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-turning-point-prior" {
        bail!(
            "ciphertext-turning-point artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-turning-point artifact"
            );
        }
    }

    let turning_point_set: HashSet<_> = prior
        .turning_point_positions
        .iter()
        .map(|position| position.position_one_based)
        .collect();
    let matching_turning_point_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| turning_point_set.contains(position))
        .collect();
    let non_turning_point_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| !turning_point_set.contains(position))
        .collect();
    let turning_point_hits = matching_turning_point_positions_one_based.len();
    let turning_point_hit_rate =
        turning_point_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let hits = shuffled
            .iter()
            .filter(|position| turning_point_set.contains(position))
            .count();
        null_values.push(hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= turning_point_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextTurningPointEvaluation {
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
        turning_point_position_count: prior.turning_point_position_count,
        turning_point_hits,
        turning_point_hit_rate,
        matching_turning_point_positions_one_based,
        non_turning_point_positions_one_based,
        null_mean_turning_point_hits: null_mean,
        null_std_dev_turning_point_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext turning-point evaluation scores source-backed non-anchor positions against a ciphertext-only local-turning-point artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_repeat_distance_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextRepeatDistanceEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-repeat-distance evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-repeat-distance evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextRepeatDistancePrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-repeat-distance-prior" {
        bail!(
            "ciphertext-repeat-distance artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-repeat-distance artifact"
            );
        }
    }

    let repeat_distance_set: HashSet<_> = prior
        .repeat_distance_positions
        .iter()
        .map(|position| position.position_one_based)
        .collect();
    let matching_repeat_distance_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| repeat_distance_set.contains(position))
        .collect();
    let non_repeat_distance_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| !repeat_distance_set.contains(position))
        .collect();
    let repeat_distance_hits = matching_repeat_distance_positions_one_based.len();
    let repeat_distance_hit_rate =
        repeat_distance_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let hits = shuffled
            .iter()
            .filter(|position| repeat_distance_set.contains(position))
            .count();
        null_values.push(hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= repeat_distance_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextRepeatDistanceEvaluation {
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
        repeat_distance_position_count: prior.repeat_distance_position_count,
        repeat_distance_hits,
        repeat_distance_hit_rate,
        matching_repeat_distance_positions_one_based,
        non_repeat_distance_positions_one_based,
        null_mean_repeat_distance_hits: null_mean,
        null_std_dev_repeat_distance_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext repeat-distance evaluation scores source-backed non-anchor positions against a ciphertext-only repeat-distance artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_rarity_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextRarityEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-rarity evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-rarity evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextRarityPrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-rarity-prior" {
        bail!(
            "ciphertext-rarity artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-rarity artifact"
            );
        }
    }

    let rare_set: HashSet<_> = prior
        .rare_positions
        .iter()
        .map(|position| position.position_one_based)
        .collect();
    let matching_rare_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| rare_set.contains(position))
        .collect();
    let non_rare_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| !rare_set.contains(position))
        .collect();
    let rare_hits = matching_rare_positions_one_based.len();
    let rare_hit_rate = rare_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let hits = shuffled
            .iter()
            .filter(|position| rare_set.contains(position))
            .count();
        null_values.push(hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= rare_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextRarityEvaluation {
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
        rare_position_count: prior.rare_position_count,
        rare_hits,
        rare_hit_rate,
        matching_rare_positions_one_based,
        non_rare_positions_one_based,
        null_mean_rare_hits: null_mean,
        null_std_dev_rare_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext-rarity evaluation scores source-backed non-anchor positions against a ciphertext-only rarity artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_residue_balance_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextResidueBalanceEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-residue-balance evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-residue-balance evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextResidueBalancePrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-residue-balance-prior" {
        bail!(
            "ciphertext-residue-balance artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-residue-balance artifact"
            );
        }
    }

    let residue_set_results = evaluate_residue_balance_sets(&prior, &observed_positions_one_based);
    let (best_modulus, best_residue, best_hits) =
        best_residue_balance_result(&residue_set_results).unwrap_or((0, 0, 0));
    let best_hit_rate = best_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let null_results = evaluate_residue_balance_sets(&prior, &shuffled);
        let (_, _, null_best_hits) =
            best_residue_balance_result(&null_results).unwrap_or((0, 0, 0));
        null_values.push(null_best_hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= best_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextResidueBalanceEvaluation {
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
        selected_residue_set_count: prior.selected_residue_sets.len(),
        best_modulus,
        best_residue,
        best_hits,
        best_hit_rate,
        residue_set_results,
        null_mean_best_hits: null_mean,
        null_std_dev_best_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext-residue-balance evaluation scores source-backed non-anchor positions against a ciphertext-only residue-balance artifact with a seeded same-size best-of-modulus null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_hotspot_positions(
    artifact_path: impl AsRef<std::path::Path>,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> Result<CiphertextHotspotEvaluation> {
    if observed_positions_one_based.is_empty() {
        bail!("ciphertext-hotspot evaluation requires at least one observed position");
    }
    if iterations == 0 {
        bail!("ciphertext-hotspot evaluation iterations must be greater than zero");
    }

    let artifact_path = artifact_path.as_ref();
    let artifact = std::fs::read_to_string(artifact_path)?;
    let prior: CiphertextHotspotPrior = serde_json::from_str(&artifact)?;
    if prior.artifact_kind != "ciphertext-hotspot-prior" {
        bail!(
            "ciphertext-hotspot artifact `{}` has artifact_kind `{}`",
            artifact_path.display(),
            prior.artifact_kind
        );
    }

    let non_anchor_set: HashSet<_> = prior
        .non_anchor_positions_one_based
        .iter()
        .copied()
        .collect();
    let mut seen = HashSet::new();
    for position in &observed_positions_one_based {
        if !seen.insert(*position) {
            bail!("observed positions must be unique");
        }
        if !non_anchor_set.contains(position) {
            bail!(
                "observed positions must be one-based non-anchor K4 positions from the ciphertext-hotspot artifact"
            );
        }
    }

    let hotspot_set: HashSet<_> = prior
        .hotspots
        .iter()
        .map(|hotspot| hotspot.position_one_based)
        .collect();
    let matching_hotspot_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| hotspot_set.contains(position))
        .collect();
    let non_hotspot_positions_one_based: Vec<_> = observed_positions_one_based
        .iter()
        .copied()
        .filter(|position| !hotspot_set.contains(position))
        .collect();
    let hotspot_hits = matching_hotspot_positions_one_based.len();
    let hotspot_hit_rate = hotspot_hits as f64 / observed_positions_one_based.len() as f64;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = prior.non_anchor_positions_one_based.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let hits = shuffled
            .iter()
            .filter(|position| hotspot_set.contains(position))
            .count();
        null_values.push(hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= hotspot_hits as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(CiphertextHotspotEvaluation {
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
        hotspot_count: prior.hotspot_count,
        hotspot_hits,
        hotspot_hit_rate,
        matching_hotspot_positions_one_based,
        non_hotspot_positions_one_based,
        null_mean_hotspot_hits: null_mean,
        null_std_dev_hotspot_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext-hotspot evaluation scores source-backed non-anchor positions against a ciphertext-only hotspot artifact with a seeded same-size position-set null; it is not a claimed solution.",
    })
}

pub fn evaluate_ciphertext_structure_prior_positions(
    max_period: usize,
    max_ngram: usize,
    prior_iterations: usize,
    prior_seed: u64,
    observed_positions_one_based: Vec<usize>,
    iterations: usize,
    seed: u64,
) -> CiphertextPriorEvaluation {
    let prior =
        build_ciphertext_structure_prior(max_period, max_ngram, prior_iterations, prior_seed);
    let period_results = evaluate_prior_periods(&prior, &observed_positions_one_based);
    let (best_period, best_residue, best_hits) =
        best_prior_period_result(&period_results).unwrap_or((0, 0, 0));
    let best_hit_rate = if observed_positions_one_based.is_empty() {
        0.0
    } else {
        best_hits as f64 / observed_positions_one_based.len() as f64
    };

    let non_anchor_positions = non_anchor_positions_one_based();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = non_anchor_positions.clone();
        shuffled.shuffle(&mut rng);
        shuffled.truncate(observed_positions_one_based.len());
        let null_period_results = evaluate_prior_periods(&prior, &shuffled);
        let (_, _, null_best_hits) =
            best_prior_period_result(&null_period_results).unwrap_or((0, 0, 0));
        null_values.push(null_best_hits as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= best_hits as f64)
        .count();
    let empirical_p_value = if iterations == 0 {
        1.0
    } else {
        (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0)
    };

    CiphertextPriorEvaluation {
        observation_id: None,
        observation_source_ids: Vec::new(),
        observation_source_review_file: None,
        observation_rationale: None,
        observation_position_notes: BTreeMap::new(),
        source_backed_observation: false,
        observed_position_count: observed_positions_one_based.len(),
        observed_positions_one_based,
        selected_period_count: prior.selected_periods.len(),
        best_period,
        best_residue,
        best_hits,
        best_hit_rate,
        period_results,
        null_mean_best_hits: null_mean,
        null_std_dev_best_hits: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Ciphertext-prior evaluation scores source-backed non-anchor positions against a planning-only ciphertext-derived prior; it is not a claimed solution."
            .to_string(),
    }
}

fn ciphertext_hotspot_scores(
    letters: &[char],
    max_period: usize,
    max_ngram: usize,
) -> Vec<CiphertextHotspot> {
    let mut repeated_ngram_hits = vec![0usize; letters.len()];
    let mut shifted_match_hits = vec![0usize; letters.len()];
    let mut support_notes = vec![Vec::<String>::new(); letters.len()];

    for repeated in repeated_ngrams_all(letters, max_ngram) {
        for start in repeated.positions_one_based {
            for offset in 0..repeated.length {
                let index = start - 1 + offset;
                repeated_ngram_hits[index] += 1;
                if support_notes[index].len() < 8 {
                    support_notes[index].push(format!(
                        "{} repeat length {} at start {}",
                        repeated.ngram, repeated.length, start
                    ));
                }
            }
        }
    }

    for profile in period_profiles(letters, max_period) {
        for shifted_match in profile.shifted_matches {
            for position in [
                shifted_match.left_position_one_based,
                shifted_match.right_position_one_based,
            ] {
                let index = position - 1;
                shifted_match_hits[index] += 1;
                if support_notes[index].len() < 8 {
                    support_notes[index].push(format!(
                        "period {} shifted match on {}",
                        profile.period, shifted_match.letter
                    ));
                }
            }
        }
    }

    letters
        .iter()
        .enumerate()
        .map(|(index, ciphertext)| CiphertextHotspot {
            position_one_based: index + 1,
            ciphertext: *ciphertext,
            repeated_ngram_hits: repeated_ngram_hits[index],
            shifted_match_hits: shifted_match_hits[index],
            score: repeated_ngram_hits[index] * 3 + shifted_match_hits[index],
            support_notes: support_notes[index].clone(),
        })
        .collect()
}

fn kryptos_circular_distance(alphabet: &Alphabet, left: char, right: char) -> Result<usize> {
    let left = alphabet.index_of(left)? as i32;
    let right = alphabet.index_of(right)? as i32;
    let absolute = (left - right).abs() as usize;
    Ok(absolute.min(26 - absolute))
}

fn evaluate_prior_periods(
    prior: &CiphertextStructurePrior,
    observed_positions_one_based: &[usize],
) -> Vec<CiphertextPriorEvaluationPeriod> {
    prior
        .selected_periods
        .iter()
        .map(|period| {
            let mut residue_hits: Vec<CiphertextPriorResidueHit> = period
                .non_anchor_residues
                .iter()
                .map(|residue| {
                    let residue_position_set: HashSet<_> =
                        residue.positions_one_based.iter().copied().collect();
                    let matching_positions_one_based: Vec<_> = observed_positions_one_based
                        .iter()
                        .copied()
                        .filter(|position| residue_position_set.contains(position))
                        .collect();
                    CiphertextPriorResidueHit {
                        residue: residue.residue,
                        hits: matching_positions_one_based.len(),
                        matching_positions_one_based,
                    }
                })
                .collect();
            residue_hits.sort_by_key(|residue| residue.residue);
            let best = residue_hits
                .iter()
                .max_by(|left, right| {
                    left.hits
                        .cmp(&right.hits)
                        .then_with(|| right.residue.cmp(&left.residue))
                })
                .cloned()
                .unwrap_or(CiphertextPriorResidueHit {
                    residue: 0,
                    hits: 0,
                    matching_positions_one_based: Vec::new(),
                });
            let best_hit_rate = if observed_positions_one_based.is_empty() {
                0.0
            } else {
                best.hits as f64 / observed_positions_one_based.len() as f64
            };
            CiphertextPriorEvaluationPeriod {
                period: period.period,
                support_kind: period.support_kind.clone(),
                best_residue: best.residue,
                best_hits: best.hits,
                best_hit_rate,
                residue_hits,
            }
        })
        .collect()
}

fn best_prior_period_result(
    period_results: &[CiphertextPriorEvaluationPeriod],
) -> Option<(usize, usize, usize)> {
    period_results
        .iter()
        .max_by(|left, right| {
            left.best_hits
                .cmp(&right.best_hits)
                .then_with(|| right.period.cmp(&left.period))
                .then_with(|| right.best_residue.cmp(&left.best_residue))
        })
        .map(|period| (period.period, period.best_residue, period.best_hits))
}

fn best_balanced_residue_set(
    modulus: usize,
    letters: &[char],
    non_anchor_positions: &[usize],
) -> Option<CiphertextResidueBalanceSet> {
    (0..modulus)
        .filter_map(|residue| {
            let positions_one_based: Vec<_> = non_anchor_positions
                .iter()
                .copied()
                .filter(|position| (position - 1) % modulus == residue)
                .collect();
            if positions_one_based.is_empty() {
                return None;
            }
            let distinct_ciphertext_letters = positions_one_based
                .iter()
                .filter_map(|position| letters.get(position - 1))
                .copied()
                .collect::<BTreeSet<_>>()
                .len();
            let distinct_letter_rate =
                distinct_ciphertext_letters as f64 / positions_one_based.len() as f64;
            Some(CiphertextResidueBalanceSet {
                modulus,
                residue,
                position_count: positions_one_based.len(),
                distinct_ciphertext_letters,
                distinct_letter_rate,
                positions_one_based,
            })
        })
        .max_by(|left, right| {
            left.distinct_letter_rate
                .total_cmp(&right.distinct_letter_rate)
                .then_with(|| left.position_count.cmp(&right.position_count))
                .then_with(|| right.residue.cmp(&left.residue))
        })
}

fn evaluate_residue_balance_sets(
    prior: &CiphertextResidueBalancePrior,
    observed_positions_one_based: &[usize],
) -> Vec<CiphertextResidueBalanceEvaluationSet> {
    prior
        .selected_residue_sets
        .iter()
        .map(|set| {
            let position_set: HashSet<_> = set.positions_one_based.iter().copied().collect();
            let matching_positions_one_based: Vec<_> = observed_positions_one_based
                .iter()
                .copied()
                .filter(|position| position_set.contains(position))
                .collect();
            let hits = matching_positions_one_based.len();
            let hit_rate = if observed_positions_one_based.is_empty() {
                0.0
            } else {
                hits as f64 / observed_positions_one_based.len() as f64
            };
            CiphertextResidueBalanceEvaluationSet {
                modulus: set.modulus,
                residue: set.residue,
                hits,
                hit_rate,
                matching_positions_one_based,
            }
        })
        .collect()
}

fn best_residue_balance_result(
    results: &[CiphertextResidueBalanceEvaluationSet],
) -> Option<(usize, usize, usize)> {
    results
        .iter()
        .max_by(|left, right| {
            left.hits
                .cmp(&right.hits)
                .then_with(|| right.modulus.cmp(&left.modulus))
                .then_with(|| right.residue.cmp(&left.residue))
        })
        .map(|result| (result.modulus, result.residue, result.hits))
}

fn non_anchor_residues(period: usize) -> Vec<CiphertextPriorResidue> {
    let non_anchor_positions = non_anchor_positions_one_based();
    let mut residues: Vec<_> = (0..period)
        .map(|residue| {
            let positions_one_based: Vec<_> = non_anchor_positions
                .iter()
                .copied()
                .filter(|position| (position - 1) % period == residue)
                .collect();
            CiphertextPriorResidue {
                residue,
                position_count: positions_one_based.len(),
                positions_one_based,
            }
        })
        .collect();
    residues.sort_by_key(|residue| residue.residue);
    residues
}

fn non_anchor_positions_one_based() -> Vec<usize> {
    let anchor_positions: HashSet<usize> = known_anchors()
        .iter()
        .flat_map(|anchor| anchor.start_zero_based..=anchor.end_zero_based_inclusive)
        .collect();
    (0..K4_CIPHERTEXT.len())
        .filter(|position| !anchor_positions.contains(position))
        .map(|position| position + 1)
        .collect()
}

fn letter_frequencies(letters: &[char]) -> Vec<LetterFrequency> {
    let mut counts = BTreeMap::<char, usize>::new();
    for letter in letters {
        *counts.entry(*letter).or_default() += 1;
    }
    let total = letters.len() as f64;
    let mut frequencies: Vec<LetterFrequency> = counts
        .into_iter()
        .map(|(letter, count)| LetterFrequency {
            letter,
            count,
            rate: count as f64 / total,
        })
        .collect();
    frequencies.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.letter.cmp(&right.letter))
    });
    frequencies
}

fn repeated_ngrams(
    letters: &[char],
    max_ngram: usize,
    top_repeated_ngrams: usize,
) -> Vec<RepeatedNgram> {
    let mut repeated = repeated_ngrams_all(letters, max_ngram);
    repeated.truncate(top_repeated_ngrams);
    repeated
}

fn repeated_ngrams_all(letters: &[char], max_ngram: usize) -> Vec<RepeatedNgram> {
    let max_ngram = max_ngram.max(2).min(letters.len());
    let mut repeated = Vec::new();
    for length in 2..=max_ngram {
        let mut positions_by_ngram = BTreeMap::<String, Vec<usize>>::new();
        for start in 0..=letters.len().saturating_sub(length) {
            let ngram: String = letters[start..start + length].iter().collect();
            positions_by_ngram.entry(ngram).or_default().push(start + 1);
        }
        repeated.extend(
            positions_by_ngram
                .into_iter()
                .filter(|(_, positions)| positions.len() > 1)
                .map(|(ngram, positions)| RepeatedNgram {
                    ngram,
                    length,
                    count: positions.len(),
                    positions_one_based: positions,
                }),
        );
    }
    repeated.sort_by(|left, right| {
        right
            .length
            .cmp(&left.length)
            .then_with(|| right.count.cmp(&left.count))
            .then_with(|| left.positions_one_based[0].cmp(&right.positions_one_based[0]))
            .then_with(|| left.ngram.cmp(&right.ngram))
    });
    repeated
}

fn kasiski_factor_profiles(
    repeated_ngrams: &[RepeatedNgram],
    max_period: usize,
) -> Vec<KasiskiFactorProfile> {
    let gap_supports = kasiski_gap_supports(repeated_ngrams);
    let total_gap_count = gap_supports.len();
    if max_period < 2 {
        return Vec::new();
    }

    (2..=max_period)
        .map(|period| {
            let supporting_gaps: Vec<KasiskiGapSupport> = gap_supports
                .iter()
                .filter(|support| support.gap % period == 0)
                .cloned()
                .collect();
            let supported_gap_count = supporting_gaps.len();
            let support_rate = if total_gap_count == 0 {
                0.0
            } else {
                supported_gap_count as f64 / total_gap_count as f64
            };
            KasiskiFactorProfile {
                period,
                supported_gap_count,
                total_gap_count,
                support_rate,
                supporting_gaps,
            }
        })
        .collect()
}

fn kasiski_gap_supports(repeated_ngrams: &[RepeatedNgram]) -> Vec<KasiskiGapSupport> {
    let mut supports = Vec::new();
    for repeated_ngram in repeated_ngrams {
        for left_index in 0..repeated_ngram.positions_one_based.len() {
            for right_index in left_index + 1..repeated_ngram.positions_one_based.len() {
                let left_position = repeated_ngram.positions_one_based[left_index];
                let right_position = repeated_ngram.positions_one_based[right_index];
                supports.push(KasiskiGapSupport {
                    ngram: repeated_ngram.ngram.clone(),
                    length: repeated_ngram.length,
                    left_position_one_based: left_position,
                    right_position_one_based: right_position,
                    gap: right_position - left_position,
                });
            }
        }
    }
    supports
}

fn period_profiles(letters: &[char], max_period: usize) -> Vec<PeriodProfile> {
    let max_period = max_period.max(1).min(letters.len().saturating_sub(1));
    (1..=max_period)
        .map(|period| {
            let shifted_comparison_count = letters.len().saturating_sub(period);
            let shifted_matches = shifted_matches(letters, period);
            let shifted_match_count = shifted_matches.len();
            let shifted_match_rate = if shifted_comparison_count == 0 {
                0.0
            } else {
                shifted_match_count as f64 / shifted_comparison_count as f64
            };
            let mean_coset_ic = mean_coset_ic(letters, period);
            PeriodProfile {
                period,
                shifted_match_count,
                shifted_comparison_count,
                shifted_match_rate,
                shifted_matches,
                mean_coset_ic,
            }
        })
        .collect()
}

fn shifted_matches(letters: &[char], period: usize) -> Vec<ShiftedMatch> {
    let shifted_comparison_count = letters.len().saturating_sub(period);
    (0..shifted_comparison_count)
        .filter(|index| letters[*index] == letters[*index + period])
        .map(|index| ShiftedMatch {
            left_position_one_based: index + 1,
            right_position_one_based: index + period + 1,
            letter: letters[index],
        })
        .collect()
}

fn ciphertext_profile_baseline(
    letters: &[char],
    max_period: usize,
    observed_profiles: &[PeriodProfile],
    iterations: usize,
    seed: u64,
) -> CiphertextProfileBaseline {
    let observed_best = best_shifted_match_rate(observed_profiles);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = letters.to_vec();
        shuffled.shuffle(&mut rng);
        let profiles = period_profiles(&shuffled, max_period);
        null_values.push(best_shifted_match_rate(&profiles).shifted_match_rate);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= observed_best.shifted_match_rate)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    CiphertextProfileBaseline {
        observed_best_period: observed_best.period,
        observed_best_shifted_match_rate: observed_best.shifted_match_rate,
        null_mean_best_shifted_match_rate: null_mean,
        null_std_dev_best_shifted_match_rate: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Seeded ciphertext-only null shuffles K4 letters and records the best shifted period-match rate across the scanned period range; it is not a decryption claim."
            .to_string(),
    }
}

fn kasiski_factor_baseline(
    letters: &[char],
    max_period: usize,
    max_ngram: usize,
    observed_profiles: &[KasiskiFactorProfile],
    iterations: usize,
    seed: u64,
) -> KasiskiFactorBaseline {
    let observed_best = best_kasiski_factor_profile(observed_profiles);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut shuffled = letters.to_vec();
        shuffled.shuffle(&mut rng);
        let repeated = repeated_ngrams_all(&shuffled, max_ngram);
        let profiles = kasiski_factor_profiles(&repeated, max_period);
        null_values.push(best_kasiski_factor_profile(&profiles).supported_gap_count as f64);
    }
    let null_mean = mean(&null_values);
    let null_std_dev = std_dev(&null_values, null_mean);
    let greater_or_equal = null_values
        .iter()
        .filter(|value| **value >= observed_best.supported_gap_count as f64)
        .count();
    let empirical_p_value = (greater_or_equal as f64 + 1.0) / (iterations as f64 + 1.0);

    KasiskiFactorBaseline {
        observed_best_period: observed_best.period,
        observed_best_supported_gap_count: observed_best.supported_gap_count,
        null_mean_best_supported_gap_count: null_mean,
        null_std_dev_best_supported_gap_count: null_std_dev,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Seeded ciphertext-only null shuffles K4 letters and records the best repeated n-gram gap-factor support across the scanned period range; it is not a decryption claim."
            .to_string(),
    }
}

fn best_shifted_match_rate(profiles: &[PeriodProfile]) -> &PeriodProfile {
    profiles
        .iter()
        .max_by(|left, right| {
            left.shifted_match_rate
                .total_cmp(&right.shifted_match_rate)
                .then_with(|| right.period.cmp(&left.period))
        })
        .expect("at least one period profile")
}

fn best_kasiski_factor_profile(profiles: &[KasiskiFactorProfile]) -> KasiskiFactorProfile {
    profiles
        .iter()
        .max_by(|left, right| {
            left.supported_gap_count
                .cmp(&right.supported_gap_count)
                .then_with(|| right.period.cmp(&left.period))
        })
        .cloned()
        .unwrap_or(KasiskiFactorProfile {
            period: 0,
            supported_gap_count: 0,
            total_gap_count: 0,
            support_rate: 0.0,
            supporting_gaps: Vec::new(),
        })
}

fn index_of_coincidence(letters: &[char]) -> f64 {
    if letters.len() < 2 {
        return 0.0;
    }
    let mut counts = BTreeMap::<char, usize>::new();
    for letter in letters {
        *counts.entry(*letter).or_default() += 1;
    }
    let numerator: usize = counts.values().map(|count| count * (count - 1)).sum();
    let denominator = letters.len() * (letters.len() - 1);
    numerator as f64 / denominator as f64
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn std_dev(values: &[f64], mean: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

fn mean_coset_ic(letters: &[char], period: usize) -> f64 {
    if period == 0 {
        return 0.0;
    }
    let mut total = 0.0;
    let mut cosets = 0usize;
    for offset in 0..period {
        let coset: Vec<char> = letters
            .iter()
            .skip(offset)
            .step_by(period)
            .copied()
            .collect();
        if coset.len() >= 2 {
            total += index_of_coincidence(&coset);
            cosets += 1;
        }
    }
    if cosets == 0 {
        0.0
    } else {
        total / cosets as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_ciphertext_only_and_bounded() {
        let profile = profile_k4_ciphertext(13, 4, 8, 100, 67);
        assert_eq!(profile.ciphertext_length, 97);
        assert_eq!(
            profile
                .letter_frequencies
                .iter()
                .map(|f| f.count)
                .sum::<usize>(),
            97
        );
        assert_eq!(profile.period_profiles.len(), 13);
        assert!(profile.index_of_coincidence > 0.0);
        assert!(profile.repeated_ngrams.iter().all(|ngram| ngram.count > 1));
        assert_eq!(profile.kasiski_factor_profiles.len(), 12);
        let kasiski_2 = profile
            .kasiski_factor_profiles
            .iter()
            .find(|profile| profile.period == 2)
            .unwrap();
        assert_eq!(
            kasiski_2.supported_gap_count,
            kasiski_2.supporting_gaps.len()
        );
        assert!(
            kasiski_2
                .supporting_gaps
                .iter()
                .all(|support| support.gap % 2 == 0)
        );
        let period_7 = profile
            .period_profiles
            .iter()
            .find(|period| period.period == 7)
            .unwrap();
        assert_eq!(period_7.shifted_match_count, period_7.shifted_matches.len());
        assert!(period_7.shifted_matches.iter().all(|shifted_match| {
            shifted_match.right_position_one_based - shifted_match.left_position_one_based == 7
        }));
        assert_eq!(profile.baseline.as_ref().unwrap().iterations, 100);
        assert_eq!(profile.kasiski_baseline.as_ref().unwrap().iterations, 100);
        assert!(!profile.promoted_candidate);
    }

    #[test]
    fn committed_ciphertext_structure_prior_matches_default_generator() {
        assert_eq!(
            build_committed_ciphertext_structure_prior(),
            build_ciphertext_structure_prior(20, 4, 100_000, 67)
        );
    }

    #[test]
    fn committed_ciphertext_hotspot_prior_is_bounded_and_non_anchor() {
        let prior = build_committed_ciphertext_hotspot_prior();
        assert_eq!(prior, build_ciphertext_hotspot_prior(20, 4, 20));
        assert_eq!(prior.hotspots.len(), 20);
        assert!(prior.hotspots.iter().all(|hotspot| {
            prior
                .non_anchor_positions_one_based
                .contains(&hotspot.position_one_based)
        }));
        assert!(!prior.promoted_candidate);
    }
}
