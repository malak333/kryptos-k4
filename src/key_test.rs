use crate::{
    AlphabetKind, CandidateTransform, FragmentMode, analyze_known_plaintext_spans,
    candidates::{expand_to_k4, transform_values},
    routes::{RouteFamily, permutation, registered_route_families},
};
use anyhow::{Result, bail};
use rand::seq::SliceRandom;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialTest {
    pub material: String,
    pub transform: CandidateTransform,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub values: Vec<u8>,
    pub expanded_to_k4: Vec<u8>,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub match_rate: f64,
    pub span_results: Vec<KeyMaterialSpanResult>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialExplanation {
    pub material: String,
    pub transform: CandidateTransform,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub offset: usize,
    pub values: Vec<u8>,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub match_rate: f64,
    pub pattern_metrics: KeyMaterialPatternMetrics,
    pub span_results: Vec<KeyMaterialSpanResult>,
    pub transform_caveat: Option<&'static str>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BatchKeyRunHistory {
    pub input_dir: String,
    pub scanned_result_files: usize,
    pub run_count: usize,
    pub candidate_result_count: usize,
    pub top_results: Vec<BatchKeyRunHistoryEntry>,
    pub candidate_summaries: Vec<BatchKeyRunCandidateSummary>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BatchKeyRunHistoryEntry {
    pub results_path: String,
    pub run_dir: String,
    pub seed: u64,
    pub baseline_iterations: usize,
    pub candidate_count: usize,
    pub material: String,
    pub transform: CandidateTransform,
    pub best_offset: usize,
    pub best_matches: usize,
    pub compared_fragment_count: usize,
    pub best_match_rate: f64,
    pub empirical_p_value: Option<f64>,
    pub promoted_candidate: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BatchKeyRunCandidateSummary {
    pub material: String,
    pub transform: CandidateTransform,
    pub run_count: usize,
    pub best_empirical_p_value: Option<f64>,
    pub worst_empirical_p_value: Option<f64>,
    pub mean_empirical_p_value: Option<f64>,
    pub best_matches: usize,
    pub best_offset: usize,
    pub best_seed: u64,
    pub best_results_path: String,
    pub promoted_candidate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchKeyMaterialCandidate {
    pub material: String,
    pub transform: CandidateTransform,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BatchKeyMaterialRun {
    pub alphabet: AlphabetKind,
    pub baseline_iterations: usize,
    pub seed: u64,
    pub candidate_count: usize,
    pub results: Vec<BatchKeyMaterialResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_baseline: Option<BatchKeyMaterialBaseline>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoutedBatchKeyMaterialRun {
    pub alphabet: AlphabetKind,
    pub baseline_iterations: usize,
    pub seed: u64,
    pub candidate_count: usize,
    pub result_count: usize,
    pub results: Vec<RoutedBatchKeyMaterialResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_baseline: Option<BatchKeyMaterialBaseline>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BatchKeyMaterialBaseline {
    pub observed_best_matches: usize,
    pub null_mean_best_matches: f64,
    pub null_std_dev_best_matches: f64,
    pub empirical_p_value: f64,
    pub observed_best_pattern_score: i64,
    pub null_mean_best_pattern_score: f64,
    pub null_std_dev_best_pattern_score: f64,
    pub pattern_score_empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub candidate_count: usize,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BatchKeyMaterialResult {
    pub material: String,
    pub transform: CandidateTransform,
    pub best_offset: usize,
    pub best_matches: usize,
    pub compared_fragment_count: usize,
    pub best_match_rate: f64,
    pub best_pattern_metrics: KeyMaterialPatternMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empirical_p_value: Option<f64>,
    pub promoted_candidate: bool,
    pub sweep: KeyMaterialOffsetSweep,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoutedBatchKeyMaterialResult {
    pub target_label: String,
    pub route: RouteFamily,
    pub permutation: Vec<usize>,
    pub material: String,
    pub transform: CandidateTransform,
    pub best_offset: usize,
    pub best_matches: usize,
    pub compared_fragment_count: usize,
    pub best_match_rate: f64,
    pub best_pattern_metrics: KeyMaterialPatternMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empirical_p_value: Option<f64>,
    pub promoted_candidate: bool,
    pub sweep: RoutedKeyMaterialOffsetSweep,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialOffsetSweep {
    pub material: String,
    pub transform: CandidateTransform,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub values: Vec<u8>,
    pub offsets_tested: usize,
    pub results: Vec<KeyMaterialOffsetResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<KeyMaterialSweepBaseline>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoutedKeyMaterialOffsetSweep {
    pub target_label: String,
    pub route: RouteFamily,
    pub permutation: Vec<usize>,
    pub material: String,
    pub transform: CandidateTransform,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub values: Vec<u8>,
    pub offsets_tested: usize,
    pub results: Vec<KeyMaterialOffsetResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<KeyMaterialSweepBaseline>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialSweepBaseline {
    pub observed_best_matches: usize,
    pub null_mean_best_matches: f64,
    pub null_std_dev_best_matches: f64,
    pub empirical_p_value: f64,
    pub iterations: usize,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialOffsetResult {
    pub offset: usize,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub match_rate: f64,
    pub pattern_metrics: KeyMaterialPatternMetrics,
    pub span_results: Vec<KeyMaterialSpanResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyMaterialPatternMetrics {
    pub pattern_score: i64,
    pub distinct_matched_values: usize,
    pub span_coverage: usize,
    pub longest_contiguous_match_run: usize,
    pub repeated_value_count: usize,
    pub repeated_value_rate: f64,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyMaterialSpanResult {
    pub target_label: String,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub matches: Vec<KeyMaterialMatch>,
    pub mismatches: Vec<KeyMaterialMismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyMaterialMatch {
    pub position_one_based: usize,
    pub plaintext: char,
    pub ciphertext: char,
    pub observed_key_value: u8,
    pub observed_key_symbol: char,
    pub material_value: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyMaterialMismatch {
    pub position_one_based: usize,
    pub plaintext: char,
    pub ciphertext: char,
    pub observed_key_value: u8,
    pub observed_key_symbol: char,
    pub material_value: u8,
}

pub fn test_key_material(
    material: &str,
    transform: CandidateTransform,
    alphabet: AlphabetKind,
) -> Result<KeyMaterialTest> {
    let values = transform_values(material, transform);
    if values.is_empty() {
        bail!("key material did not produce any numeric values");
    }
    let expanded_to_k4 = expand_to_k4(&values);
    let result = score_key_material_with_offset(&expanded_to_k4, alphabet, 0)?;

    Ok(KeyMaterialTest {
        material: material.to_string(),
        transform,
        alphabet,
        fragment_mode: FragmentMode::AdditiveKey,
        values,
        expanded_to_k4,
        compared_fragment_count: result.compared_fragment_count,
        exact_mod26_matches: result.exact_mod26_matches,
        match_rate: result.match_rate,
        span_results: result.span_results,
        promoted_candidate: false,
        note: "Exploratory key-material check over public known-plaintext spans only; not evidence of plaintext or decryption.",
    })
}

pub fn explain_key_material(
    material: &str,
    transform: CandidateTransform,
    alphabet: AlphabetKind,
    offset: Option<usize>,
) -> Result<KeyMaterialExplanation> {
    let values = transform_values(material, transform);
    if values.is_empty() {
        bail!("key material did not produce any numeric values");
    }
    let selected_offset = if let Some(offset) = offset {
        offset
    } else {
        score_all_offsets(&values, alphabet)?
            .first()
            .map(|result| result.offset)
            .expect("sweep results are non-empty for non-empty material")
    };
    let expanded_to_k4 = expand_to_k4(&values);
    let result = score_key_material_with_offset(&expanded_to_k4, alphabet, selected_offset)?;

    Ok(KeyMaterialExplanation {
        material: material.to_string(),
        transform,
        alphabet,
        fragment_mode: FragmentMode::AdditiveKey,
        offset: selected_offset,
        values,
        compared_fragment_count: result.compared_fragment_count,
        exact_mod26_matches: result.exact_mod26_matches,
        match_rate: result.match_rate,
        pattern_metrics: result.pattern_metrics,
        span_results: result.span_results,
        transform_caveat: transform.modulo_caveat(),
        promoted_candidate: false,
        note: "Explanation of public-span key-material matches only; matched rows are follow-up leads, not decrypted plaintext.",
    })
}

pub fn sweep_key_material_offsets(
    material: &str,
    transform: CandidateTransform,
    alphabet: AlphabetKind,
) -> Result<KeyMaterialOffsetSweep> {
    sweep_key_material_offsets_with_baseline(material, transform, alphabet, 0, 42)
}

pub fn sweep_key_material_offsets_with_baseline(
    material: &str,
    transform: CandidateTransform,
    alphabet: AlphabetKind,
    baseline_iterations: usize,
    seed: u64,
) -> Result<KeyMaterialOffsetSweep> {
    let values = transform_values(material, transform);
    if values.is_empty() {
        bail!("key material did not produce any numeric values");
    }
    let results = score_all_offsets(&values, alphabet)?;
    let baseline = if baseline_iterations == 0 {
        None
    } else {
        Some(run_sweep_baseline(
            &values,
            alphabet,
            results[0].exact_mod26_matches,
            baseline_iterations,
            seed,
        )?)
    };

    Ok(KeyMaterialOffsetSweep {
        material: material.to_string(),
        transform,
        alphabet,
        fragment_mode: FragmentMode::AdditiveKey,
        values,
        offsets_tested: results.len(),
        results,
        baseline,
        promoted_candidate: false,
        note: "Exploratory offset sweep over public known-plaintext spans only; best offsets are not evidence of plaintext or decryption.",
    })
}

pub fn batch_test_key_material(
    candidates: &[BatchKeyMaterialCandidate],
    alphabet: AlphabetKind,
    baseline_iterations: usize,
    seed: u64,
) -> Result<BatchKeyMaterialRun> {
    batch_test_key_material_with_batch_baseline(candidates, alphabet, baseline_iterations, seed, 0)
}

pub fn batch_test_key_material_with_batch_baseline(
    candidates: &[BatchKeyMaterialCandidate],
    alphabet: AlphabetKind,
    baseline_iterations: usize,
    seed: u64,
    batch_baseline_iterations: usize,
) -> Result<BatchKeyMaterialRun> {
    if candidates.is_empty() {
        bail!("batch key-material input did not contain any candidates");
    }

    let mut results = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let sweep = sweep_key_material_offsets_with_baseline(
            &candidate.material,
            candidate.transform,
            alphabet,
            baseline_iterations,
            seed,
        )?;
        let best = sweep
            .results
            .first()
            .expect("sweep results are non-empty for non-empty material");

        results.push(BatchKeyMaterialResult {
            material: candidate.material.clone(),
            transform: candidate.transform,
            best_offset: best.offset,
            best_matches: best.exact_mod26_matches,
            compared_fragment_count: best.compared_fragment_count,
            best_match_rate: best.match_rate,
            best_pattern_metrics: best.pattern_metrics.clone(),
            empirical_p_value: sweep
                .baseline
                .as_ref()
                .map(|baseline| baseline.empirical_p_value),
            promoted_candidate: false,
            sweep,
        });
    }

    results.sort_by(|left, right| {
        right
            .best_matches
            .cmp(&left.best_matches)
            .then_with(|| {
                let left_p = left.empirical_p_value.unwrap_or(f64::INFINITY);
                let right_p = right.empirical_p_value.unwrap_or(f64::INFINITY);
                left_p.total_cmp(&right_p)
            })
            .then_with(|| left.material.cmp(&right.material))
    });
    let observed_best_matches = results
        .iter()
        .map(|result| result.best_matches)
        .max()
        .unwrap_or(0);
    let observed_best_pattern_score = results
        .iter()
        .map(|result| result.best_pattern_metrics.pattern_score)
        .max()
        .unwrap_or(0);
    let batch_baseline = if batch_baseline_iterations == 0 {
        None
    } else {
        Some(run_batch_baseline(
            candidates,
            alphabet,
            observed_best_matches,
            observed_best_pattern_score,
            batch_baseline_iterations,
            seed,
        )?)
    };

    Ok(BatchKeyMaterialRun {
        alphabet,
        baseline_iterations,
        seed,
        candidate_count: results.len(),
        results,
        batch_baseline,
        promoted_candidate: false,
        note: "Batch key-material run over public known-plaintext spans only; ranked results are exploratory and not decryption claims.",
    })
}

pub fn batch_test_routed_key_material(
    candidates: &[BatchKeyMaterialCandidate],
    alphabet: AlphabetKind,
    baseline_iterations: usize,
    seed: u64,
    batch_baseline_iterations: usize,
) -> Result<RoutedBatchKeyMaterialRun> {
    if candidates.is_empty() {
        bail!("batch routed key-material input did not contain any candidates");
    }

    let mut results = Vec::new();
    for target in routed_targets(alphabet)? {
        for candidate in candidates {
            let values = transform_values(&candidate.material, candidate.transform);
            if values.is_empty() {
                bail!("key material did not produce any numeric values");
            }
            for route in registered_route_families() {
                let Ok(route_permutation) = permutation(route, target.fragments.len()) else {
                    continue;
                };
                let sweep = sweep_routed_key_material_offsets(RoutedSweepSpec {
                    material: &candidate.material,
                    transform: candidate.transform,
                    alphabet,
                    values: &values,
                    target: &target,
                    route,
                    route_permutation,
                    baseline_iterations,
                    seed,
                })?;
                let best = sweep
                    .results
                    .first()
                    .expect("routed sweep results are non-empty for non-empty material");
                results.push(RoutedBatchKeyMaterialResult {
                    target_label: target.label.clone(),
                    route,
                    permutation: sweep.permutation.clone(),
                    material: candidate.material.clone(),
                    transform: candidate.transform,
                    best_offset: best.offset,
                    best_matches: best.exact_mod26_matches,
                    compared_fragment_count: best.compared_fragment_count,
                    best_match_rate: best.match_rate,
                    best_pattern_metrics: best.pattern_metrics.clone(),
                    empirical_p_value: sweep
                        .baseline
                        .as_ref()
                        .map(|baseline| baseline.empirical_p_value),
                    promoted_candidate: false,
                    sweep,
                });
            }
        }
    }

    results.sort_by(compare_routed_batch_results);
    let observed_best_matches = results
        .iter()
        .map(|result| result.best_matches)
        .max()
        .unwrap_or(0);
    let observed_best_pattern_score = results
        .iter()
        .map(|result| result.best_pattern_metrics.pattern_score)
        .max()
        .unwrap_or(0);
    let batch_baseline = if batch_baseline_iterations == 0 {
        None
    } else {
        Some(run_routed_batch_baseline(
            candidates,
            alphabet,
            observed_best_matches,
            observed_best_pattern_score,
            batch_baseline_iterations,
            seed,
        )?)
    };

    Ok(RoutedBatchKeyMaterialRun {
        alphabet,
        baseline_iterations,
        seed,
        candidate_count: candidates.len(),
        result_count: results.len(),
        results,
        batch_baseline,
        promoted_candidate: false,
        note: "Routed batch key-material run over public known-plaintext span fragments only; ranked results are exploratory and not decryption claims.",
    })
}

fn run_batch_baseline(
    candidates: &[BatchKeyMaterialCandidate],
    alphabet: AlphabetKind,
    observed_best_matches: usize,
    observed_best_pattern_score: i64,
    iterations: usize,
    seed: u64,
) -> Result<BatchKeyMaterialBaseline> {
    let candidate_values: Vec<Vec<u8>> = candidates
        .iter()
        .map(|candidate| transform_values(&candidate.material, candidate.transform))
        .collect();
    if candidate_values.iter().any(Vec::is_empty) {
        bail!("batch key-material input contained a candidate without numeric values");
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_best_matches = Vec::with_capacity(iterations);
    let mut null_best_pattern_scores = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut iteration_best_matches = 0usize;
        let mut iteration_best_pattern_score = i64::MIN;
        for values in &candidate_values {
            let mut shuffled = values.clone();
            shuffled.shuffle(&mut rng);
            for result in score_all_offsets(&shuffled, alphabet)? {
                iteration_best_matches = iteration_best_matches.max(result.exact_mod26_matches);
                iteration_best_pattern_score =
                    iteration_best_pattern_score.max(result.pattern_metrics.pattern_score);
            }
        }
        null_best_matches.push(iteration_best_matches);
        null_best_pattern_scores.push(iteration_best_pattern_score);
    }

    let null_mean_best_matches = mean(&null_best_matches);
    let null_std_dev_best_matches = std_dev(&null_best_matches, null_mean_best_matches);
    let null_mean_best_pattern_score = mean_i64(&null_best_pattern_scores);
    let null_std_dev_best_pattern_score =
        std_dev_i64(&null_best_pattern_scores, null_mean_best_pattern_score);
    let at_least_observed = null_best_matches
        .iter()
        .filter(|count| **count >= observed_best_matches)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);
    let pattern_at_least_observed = null_best_pattern_scores
        .iter()
        .filter(|score| **score >= observed_best_pattern_score)
        .count();
    let pattern_score_empirical_p_value =
        (pattern_at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(BatchKeyMaterialBaseline {
        observed_best_matches,
        null_mean_best_matches,
        null_std_dev_best_matches,
        empirical_p_value,
        observed_best_pattern_score,
        null_mean_best_pattern_score,
        null_std_dev_best_pattern_score,
        pattern_score_empirical_p_value,
        iterations,
        seed,
        candidate_count: candidates.len(),
        promoted_candidate: false,
        note: "Seeded batch-level null over the best shuffled match count and composite pattern score across all candidate rows; this controls the candidate-file search surface, not the full hypothesis space.",
    })
}

fn run_routed_batch_baseline(
    candidates: &[BatchKeyMaterialCandidate],
    alphabet: AlphabetKind,
    observed_best_matches: usize,
    observed_best_pattern_score: i64,
    iterations: usize,
    seed: u64,
) -> Result<BatchKeyMaterialBaseline> {
    let candidate_values: Vec<Vec<u8>> = candidates
        .iter()
        .map(|candidate| transform_values(&candidate.material, candidate.transform))
        .collect();
    if candidate_values.iter().any(Vec::is_empty) {
        bail!("batch routed key-material input contained a candidate without numeric values");
    }
    let targets = routed_targets(alphabet)?;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_best_matches = Vec::with_capacity(iterations);
    let mut null_best_pattern_scores = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut iteration_best_matches = 0usize;
        let mut iteration_best_pattern_score = i64::MIN;
        for values in &candidate_values {
            let mut shuffled = values.clone();
            shuffled.shuffle(&mut rng);
            for target in &targets {
                for route in registered_route_families() {
                    let Ok(route_permutation) = permutation(route, target.fragments.len()) else {
                        continue;
                    };
                    for result in score_all_routed_offsets(&shuffled, target, &route_permutation)? {
                        iteration_best_matches =
                            iteration_best_matches.max(result.exact_mod26_matches);
                        iteration_best_pattern_score =
                            iteration_best_pattern_score.max(result.pattern_metrics.pattern_score);
                    }
                }
            }
        }
        null_best_matches.push(iteration_best_matches);
        null_best_pattern_scores.push(iteration_best_pattern_score);
    }

    let null_mean_best_matches = mean(&null_best_matches);
    let null_std_dev_best_matches = std_dev(&null_best_matches, null_mean_best_matches);
    let null_mean_best_pattern_score = mean_i64(&null_best_pattern_scores);
    let null_std_dev_best_pattern_score =
        std_dev_i64(&null_best_pattern_scores, null_mean_best_pattern_score);
    let at_least_observed = null_best_matches
        .iter()
        .filter(|count| **count >= observed_best_matches)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);
    let pattern_at_least_observed = null_best_pattern_scores
        .iter()
        .filter(|score| **score >= observed_best_pattern_score)
        .count();
    let pattern_score_empirical_p_value =
        (pattern_at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(BatchKeyMaterialBaseline {
        observed_best_matches,
        null_mean_best_matches,
        null_std_dev_best_matches,
        empirical_p_value,
        observed_best_pattern_score,
        null_mean_best_pattern_score,
        null_std_dev_best_pattern_score,
        pattern_score_empirical_p_value,
        iterations,
        seed,
        candidate_count: candidates.len(),
        promoted_candidate: false,
        note: "Seeded routed batch-level null over the best shuffled match count and composite pattern score across all candidate rows, compatible route families, and public spans; this controls the routed candidate-file search surface, not the full hypothesis space.",
    })
}

pub fn summarize_batch_key_material_runs(
    input_dir: &Path,
    top: usize,
) -> Result<BatchKeyRunHistory> {
    let mut result_paths = Vec::new();
    collect_results_json_paths(input_dir, &mut result_paths)?;
    result_paths.sort();

    if result_paths.is_empty() {
        bail!("no results.json files found under {}", input_dir.display());
    }

    let mut all_entries = Vec::new();
    for path in &result_paths {
        let text = fs::read_to_string(path)?;
        let run: BatchKeyMaterialRunForHistory = serde_json::from_str(&text)?;
        let run_dir = path
            .parent()
            .map(|parent| parent.display().to_string())
            .unwrap_or_else(|| ".".to_string());
        for result in run.results {
            all_entries.push(BatchKeyRunHistoryEntry {
                results_path: path.display().to_string(),
                run_dir: run_dir.clone(),
                seed: run.seed,
                baseline_iterations: run.baseline_iterations,
                candidate_count: run.candidate_count,
                material: result.material,
                transform: result.transform,
                best_offset: result.best_offset,
                best_matches: result.best_matches,
                compared_fragment_count: result.compared_fragment_count,
                best_match_rate: result.best_match_rate,
                empirical_p_value: result.empirical_p_value,
                promoted_candidate: result.promoted_candidate,
            });
        }
    }

    all_entries.sort_by(compare_history_entries);
    let candidate_summaries = summarize_history_candidates(&all_entries);
    let top_results = all_entries.into_iter().take(top).collect();

    Ok(BatchKeyRunHistory {
        input_dir: input_dir.display().to_string(),
        scanned_result_files: result_paths.len(),
        run_count: result_paths.len(),
        candidate_result_count: candidate_summaries
            .iter()
            .map(|summary| summary.run_count)
            .sum(),
        top_results,
        candidate_summaries,
        promoted_candidate: false,
        note: "Historical batch key-material summary only; repeated low p-values are leads for follow-up, not decryption claims.",
    })
}

#[derive(Debug, Deserialize)]
struct BatchKeyMaterialRunForHistory {
    baseline_iterations: usize,
    seed: u64,
    candidate_count: usize,
    results: Vec<BatchKeyMaterialResultForHistory>,
}

#[derive(Debug, Deserialize)]
struct BatchKeyMaterialResultForHistory {
    material: String,
    transform: CandidateTransform,
    best_offset: usize,
    best_matches: usize,
    compared_fragment_count: usize,
    best_match_rate: f64,
    empirical_p_value: Option<f64>,
    promoted_candidate: bool,
}

#[derive(Debug, Clone)]
struct RoutedTarget {
    label: String,
    fragments: Vec<crate::analysis::KeyFragment>,
}

struct RoutedSweepSpec<'a> {
    material: &'a str,
    transform: CandidateTransform,
    alphabet: AlphabetKind,
    values: &'a [u8],
    target: &'a RoutedTarget,
    route: RouteFamily,
    route_permutation: Vec<usize>,
    baseline_iterations: usize,
    seed: u64,
}

fn collect_results_json_paths(input_dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if !input_dir.exists() {
        bail!("input directory does not exist: {}", input_dir.display());
    }

    for entry in fs::read_dir(input_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_results_json_paths(&path, paths)?;
        } else if file_type.is_file()
            && path.file_name().and_then(|name| name.to_str()) == Some("results.json")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn compare_history_entries(
    left: &BatchKeyRunHistoryEntry,
    right: &BatchKeyRunHistoryEntry,
) -> std::cmp::Ordering {
    let left_p = left.empirical_p_value.unwrap_or(f64::INFINITY);
    let right_p = right.empirical_p_value.unwrap_or(f64::INFINITY);
    left_p
        .total_cmp(&right_p)
        .then_with(|| right.best_matches.cmp(&left.best_matches))
        .then_with(|| left.material.cmp(&right.material))
        .then_with(|| left.transform_label().cmp(right.transform_label()))
        .then_with(|| left.seed.cmp(&right.seed))
}

fn compare_routed_batch_results(
    left: &RoutedBatchKeyMaterialResult,
    right: &RoutedBatchKeyMaterialResult,
) -> std::cmp::Ordering {
    right
        .best_matches
        .cmp(&left.best_matches)
        .then_with(|| {
            right
                .best_pattern_metrics
                .pattern_score
                .cmp(&left.best_pattern_metrics.pattern_score)
        })
        .then_with(|| {
            let left_p = left.empirical_p_value.unwrap_or(f64::INFINITY);
            let right_p = right.empirical_p_value.unwrap_or(f64::INFINITY);
            left_p.total_cmp(&right_p)
        })
        .then_with(|| left.target_label.cmp(&right.target_label))
        .then_with(|| route_label(left.route).cmp(route_label(right.route)))
        .then_with(|| left.material.cmp(&right.material))
        .then_with(|| left.transform_label().cmp(right.transform_label()))
}

fn summarize_history_candidates(
    entries: &[BatchKeyRunHistoryEntry],
) -> Vec<BatchKeyRunCandidateSummary> {
    let mut grouped: BTreeMap<(String, CandidateTransform), Vec<&BatchKeyRunHistoryEntry>> =
        BTreeMap::new();
    for entry in entries {
        grouped
            .entry((entry.material.clone(), entry.transform))
            .or_default()
            .push(entry);
    }

    let mut summaries = Vec::new();
    for ((material, transform), entries) in grouped {
        let best = entries
            .iter()
            .copied()
            .min_by(|left, right| compare_history_entries(left, right))
            .expect("group contains at least one entry");
        let p_values: Vec<f64> = entries
            .iter()
            .filter_map(|entry| entry.empirical_p_value)
            .collect();
        let best_empirical_p_value = p_values.iter().copied().min_by(f64::total_cmp);
        let worst_empirical_p_value = p_values.iter().copied().max_by(f64::total_cmp);
        let mean_empirical_p_value = if p_values.is_empty() {
            None
        } else {
            Some(p_values.iter().sum::<f64>() / p_values.len() as f64)
        };

        summaries.push(BatchKeyRunCandidateSummary {
            material,
            transform,
            run_count: entries.len(),
            best_empirical_p_value,
            worst_empirical_p_value,
            mean_empirical_p_value,
            best_matches: best.best_matches,
            best_offset: best.best_offset,
            best_seed: best.seed,
            best_results_path: best.results_path.clone(),
            promoted_candidate: false,
        });
    }

    summaries.sort_by(|left, right| {
        let left_p = left.best_empirical_p_value.unwrap_or(f64::INFINITY);
        let right_p = right.best_empirical_p_value.unwrap_or(f64::INFINITY);
        left_p
            .total_cmp(&right_p)
            .then_with(|| right.best_matches.cmp(&left.best_matches))
            .then_with(|| left.material.cmp(&right.material))
            .then_with(|| left.transform_label().cmp(right.transform_label()))
    });
    summaries
}

impl BatchKeyRunHistoryEntry {
    fn transform_label(&self) -> &'static str {
        self.transform.label()
    }
}

impl BatchKeyRunCandidateSummary {
    fn transform_label(&self) -> &'static str {
        self.transform.label()
    }
}

impl RoutedBatchKeyMaterialResult {
    fn transform_label(&self) -> &'static str {
        self.transform.label()
    }
}

fn route_label(route: RouteFamily) -> &'static str {
    match route {
        RouteFamily::Identity => "identity",
        RouteFamily::Reverse => "reverse",
        RouteFamily::RowToColumnWidth7 => "row-to-column-width7",
        RouteFamily::RowToColumnWidth13 => "row-to-column-width13",
    }
}

impl CandidateTransform {
    fn label(self) -> &'static str {
        match self {
            CandidateTransform::A1Z26ZeroBased => "a1-z26-zero-based",
            CandidateTransform::A1Z26OneBased => "a1-z26-one-based",
            CandidateTransform::DecimalDigits => "decimal-digits",
            CandidateTransform::Compass8Point => "compass8-point",
            CandidateTransform::Compass16Point => "compass16-point",
        }
    }
}

fn score_all_offsets(
    values: &[u8],
    alphabet: AlphabetKind,
) -> Result<Vec<KeyMaterialOffsetResult>> {
    let expanded_to_k4 = expand_to_k4(values);
    let mut results = Vec::with_capacity(values.len());

    for offset in 0..values.len() {
        results.push(score_key_material_with_offset(
            &expanded_to_k4,
            alphabet,
            offset,
        )?);
    }
    results.sort_by(|left, right| {
        right
            .exact_mod26_matches
            .cmp(&left.exact_mod26_matches)
            .then_with(|| left.offset.cmp(&right.offset))
    });

    Ok(results)
}

fn routed_targets(alphabet: AlphabetKind) -> Result<Vec<RoutedTarget>> {
    let targets = analyze_known_plaintext_spans()?
        .into_iter()
        .filter(|analysis| analysis.alphabet.kind == alphabet)
        .map(|analysis| RoutedTarget {
            label: analysis.target.label,
            fragments: analysis
                .fragments
                .into_iter()
                .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
                .collect(),
        })
        .collect();
    Ok(targets)
}

fn sweep_routed_key_material_offsets(
    spec: RoutedSweepSpec<'_>,
) -> Result<RoutedKeyMaterialOffsetSweep> {
    let results = score_all_routed_offsets(spec.values, spec.target, &spec.route_permutation)?;
    let baseline = if spec.baseline_iterations == 0 {
        None
    } else {
        Some(run_routed_sweep_baseline(
            spec.values,
            spec.target,
            &spec.route_permutation,
            results[0].exact_mod26_matches,
            spec.baseline_iterations,
            spec.seed,
        )?)
    };

    Ok(RoutedKeyMaterialOffsetSweep {
        target_label: spec.target.label.clone(),
        route: spec.route,
        permutation: spec.route_permutation,
        material: spec.material.to_string(),
        transform: spec.transform,
        alphabet: spec.alphabet,
        fragment_mode: FragmentMode::AdditiveKey,
        values: spec.values.to_vec(),
        offsets_tested: results.len(),
        results,
        baseline,
        promoted_candidate: false,
        note: "Exploratory routed offset sweep over one public known-plaintext span only; best offsets are not evidence of plaintext or decryption.",
    })
}

fn score_all_routed_offsets(
    values: &[u8],
    target: &RoutedTarget,
    route_permutation: &[usize],
) -> Result<Vec<KeyMaterialOffsetResult>> {
    let mut results = Vec::with_capacity(values.len());
    for offset in 0..values.len() {
        results.push(score_routed_key_material_with_offset(
            values,
            target,
            route_permutation,
            offset,
        )?);
    }
    results.sort_by(|left, right| {
        right
            .exact_mod26_matches
            .cmp(&left.exact_mod26_matches)
            .then_with(|| {
                right
                    .pattern_metrics
                    .pattern_score
                    .cmp(&left.pattern_metrics.pattern_score)
            })
            .then_with(|| left.offset.cmp(&right.offset))
    });
    Ok(results)
}

fn run_routed_sweep_baseline(
    values: &[u8],
    target: &RoutedTarget,
    route_permutation: &[usize],
    observed_best_matches: usize,
    iterations: usize,
    seed: u64,
) -> Result<KeyMaterialSweepBaseline> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_best_matches = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let mut shuffled = values.to_vec();
        shuffled.shuffle(&mut rng);
        let best = score_all_routed_offsets(&shuffled, target, route_permutation)?
            .first()
            .map(|result| result.exact_mod26_matches)
            .unwrap_or(0);
        null_best_matches.push(best);
    }

    let null_mean_best_matches = mean(&null_best_matches);
    let null_std_dev_best_matches = std_dev(&null_best_matches, null_mean_best_matches);
    let at_least_observed = null_best_matches
        .iter()
        .filter(|count| **count >= observed_best_matches)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(KeyMaterialSweepBaseline {
        observed_best_matches,
        null_mean_best_matches,
        null_std_dev_best_matches,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Seeded null baseline over shuffled routed key-material values; still not a decryption claim.",
    })
}

fn run_sweep_baseline(
    values: &[u8],
    alphabet: AlphabetKind,
    observed_best_matches: usize,
    iterations: usize,
    seed: u64,
) -> Result<KeyMaterialSweepBaseline> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut null_best_matches = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let mut shuffled = values.to_vec();
        shuffled.shuffle(&mut rng);
        let best = score_all_offsets(&shuffled, alphabet)?
            .first()
            .map(|result| result.exact_mod26_matches)
            .unwrap_or(0);
        null_best_matches.push(best);
    }

    let null_mean_best_matches = mean(&null_best_matches);
    let null_std_dev_best_matches = std_dev(&null_best_matches, null_mean_best_matches);
    let at_least_observed = null_best_matches
        .iter()
        .filter(|count| **count >= observed_best_matches)
        .count();
    let empirical_p_value = (at_least_observed as f64 + 1.0) / (iterations as f64 + 1.0);

    Ok(KeyMaterialSweepBaseline {
        observed_best_matches,
        null_mean_best_matches,
        null_std_dev_best_matches,
        empirical_p_value,
        iterations,
        seed,
        promoted_candidate: false,
        note: "Seeded null baseline over shuffled key-material values; still not a decryption claim.",
    })
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

fn score_key_material_with_offset(
    expanded_to_k4: &[u8],
    alphabet: AlphabetKind,
    offset: usize,
) -> Result<KeyMaterialOffsetResult> {
    let mut span_results = Vec::new();

    for analysis in analyze_known_plaintext_spans()? {
        if analysis.alphabet.kind != alphabet {
            continue;
        }

        let mut exact_mod26_matches = 0usize;
        let mut compared_fragment_count = 0usize;
        let mut matches = Vec::new();
        let mut mismatches = Vec::new();
        for fragment in analysis
            .fragments
            .iter()
            .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
        {
            compared_fragment_count += 1;
            let material_index = (fragment.position_zero_based + offset) % expanded_to_k4.len();
            let material_value = expanded_to_k4[material_index] % 26;
            if fragment.value == material_value {
                exact_mod26_matches += 1;
                matches.push(KeyMaterialMatch {
                    position_one_based: fragment.position_one_based,
                    plaintext: fragment.plaintext,
                    ciphertext: fragment.ciphertext,
                    observed_key_value: fragment.value,
                    observed_key_symbol: fragment.symbol,
                    material_value,
                });
            } else {
                mismatches.push(KeyMaterialMismatch {
                    position_one_based: fragment.position_one_based,
                    plaintext: fragment.plaintext,
                    ciphertext: fragment.ciphertext,
                    observed_key_value: fragment.value,
                    observed_key_symbol: fragment.symbol,
                    material_value,
                });
            }
        }

        span_results.push(KeyMaterialSpanResult {
            target_label: analysis.target.label,
            compared_fragment_count,
            exact_mod26_matches,
            matches,
            mismatches,
        });
    }

    let compared_fragment_count = span_results
        .iter()
        .map(|result| result.compared_fragment_count)
        .sum();
    let exact_mod26_matches = span_results
        .iter()
        .map(|result| result.exact_mod26_matches)
        .sum();
    let match_rate = if compared_fragment_count == 0 {
        0.0
    } else {
        exact_mod26_matches as f64 / compared_fragment_count as f64
    };
    let pattern_metrics = calculate_pattern_metrics(&span_results);

    Ok(KeyMaterialOffsetResult {
        offset,
        compared_fragment_count,
        exact_mod26_matches,
        match_rate,
        pattern_metrics,
        span_results,
    })
}

fn score_routed_key_material_with_offset(
    values: &[u8],
    target: &RoutedTarget,
    route_permutation: &[usize],
    offset: usize,
) -> Result<KeyMaterialOffsetResult> {
    let mut exact_mod26_matches = 0usize;
    let mut matches = Vec::new();
    let mut mismatches = Vec::new();

    for (routed_index, fragment_index) in route_permutation.iter().copied().enumerate() {
        let fragment = &target.fragments[fragment_index];
        let material_index = (routed_index + offset) % values.len();
        let material_value = values[material_index] % 26;
        if fragment.value == material_value {
            exact_mod26_matches += 1;
            matches.push(KeyMaterialMatch {
                position_one_based: fragment.position_one_based,
                plaintext: fragment.plaintext,
                ciphertext: fragment.ciphertext,
                observed_key_value: fragment.value,
                observed_key_symbol: fragment.symbol,
                material_value,
            });
        } else {
            mismatches.push(KeyMaterialMismatch {
                position_one_based: fragment.position_one_based,
                plaintext: fragment.plaintext,
                ciphertext: fragment.ciphertext,
                observed_key_value: fragment.value,
                observed_key_symbol: fragment.symbol,
                material_value,
            });
        }
    }

    let compared_fragment_count = route_permutation.len();
    let match_rate = if compared_fragment_count == 0 {
        0.0
    } else {
        exact_mod26_matches as f64 / compared_fragment_count as f64
    };
    let span_results = vec![KeyMaterialSpanResult {
        target_label: target.label.clone(),
        compared_fragment_count,
        exact_mod26_matches,
        matches,
        mismatches,
    }];
    let pattern_metrics = calculate_pattern_metrics(&span_results);

    Ok(KeyMaterialOffsetResult {
        offset,
        compared_fragment_count,
        exact_mod26_matches,
        match_rate,
        pattern_metrics,
        span_results,
    })
}

fn calculate_pattern_metrics(span_results: &[KeyMaterialSpanResult]) -> KeyMaterialPatternMetrics {
    let mut matched_values = BTreeSet::new();
    let mut positions = Vec::new();
    let mut match_count = 0usize;
    let mut span_coverage = 0usize;

    for span in span_results {
        if !span.matches.is_empty() {
            span_coverage += 1;
        }
        for key_match in &span.matches {
            matched_values.insert(key_match.observed_key_value);
            positions.push(key_match.position_one_based);
            match_count += 1;
        }
    }

    positions.sort_unstable();
    let mut longest_contiguous_match_run = 0usize;
    let mut current_run = 0usize;
    let mut previous_position = None;
    for position in positions {
        current_run = if previous_position == Some(position.saturating_sub(1)) {
            current_run + 1
        } else {
            1
        };
        longest_contiguous_match_run = longest_contiguous_match_run.max(current_run);
        previous_position = Some(position);
    }

    let distinct_matched_values = matched_values.len();
    let repeated_value_count = match_count.saturating_sub(distinct_matched_values);
    let repeated_value_rate = if match_count == 0 {
        0.0
    } else {
        repeated_value_count as f64 / match_count as f64
    };
    let pattern_score = (match_count as i64 * 100)
        + (distinct_matched_values as i64 * 10)
        + (span_coverage as i64 * 5)
        + (longest_contiguous_match_run as i64 * 2)
        - (repeated_value_count as i64 * 8);

    KeyMaterialPatternMetrics {
        pattern_score,
        distinct_matched_values,
        span_coverage,
        longest_contiguous_match_run,
        repeated_value_count,
        repeated_value_rate,
        note: "Pattern metrics are descriptive controls for repeated values and clustering; they are not promotion criteria.".to_string(),
    }
}

impl CandidateTransform {
    pub fn modulo_caveat(self) -> Option<&'static str> {
        match self {
            CandidateTransform::A1Z26OneBased => Some(
                "A1Z26OneBased emits A=1 through Z=26; comparisons reduce material values modulo 26, so Z=26 is compared as 0.",
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_material_scores_known_material_without_promotion() {
        let test = test_key_material(
            "BERLINWORLDCLOCK",
            CandidateTransform::A1Z26ZeroBased,
            AlphabetKind::Kryptos,
        )
        .unwrap();

        assert_eq!(test.expanded_to_k4.len(), crate::K4_CIPHERTEXT.len());
        assert_eq!(test.compared_fragment_count, 24);
        assert!(!test.promoted_candidate);
        assert!(
            test.span_results
                .iter()
                .any(|span| span.target_label == "BERLINCLOCK")
        );
    }

    #[test]
    fn empty_material_is_rejected() {
        assert!(
            test_key_material(
                "!!!",
                CandidateTransform::A1Z26ZeroBased,
                AlphabetKind::Kryptos
            )
            .is_err()
        );
    }

    #[test]
    fn sweep_scores_all_material_offsets_without_promotion() {
        let sweep = sweep_key_material_offsets(
            "BERLINWORLDCLOCK",
            CandidateTransform::A1Z26ZeroBased,
            AlphabetKind::Kryptos,
        )
        .unwrap();

        assert_eq!(sweep.offsets_tested, "BERLINWORLDCLOCK".len());
        assert_eq!(sweep.results.len(), sweep.offsets_tested);
        assert!(!sweep.promoted_candidate);
        assert!(
            sweep
                .results
                .windows(2)
                .all(|pair| pair[0].exact_mod26_matches >= pair[1].exact_mod26_matches)
        );
    }

    #[test]
    fn sweep_baseline_is_seeded_and_non_promotional() {
        let first = sweep_key_material_offsets_with_baseline(
            "BERLINWORLDCLOCK",
            CandidateTransform::A1Z26ZeroBased,
            AlphabetKind::Kryptos,
            25,
            42,
        )
        .unwrap();
        let second = sweep_key_material_offsets_with_baseline(
            "BERLINWORLDCLOCK",
            CandidateTransform::A1Z26ZeroBased,
            AlphabetKind::Kryptos,
            25,
            42,
        )
        .unwrap();

        assert_eq!(first.baseline, second.baseline);
        let baseline = first.baseline.unwrap();
        assert_eq!(
            baseline.observed_best_matches,
            first.results[0].exact_mod26_matches
        );
        assert_eq!(baseline.iterations, 25);
        assert_eq!(baseline.seed, 42);
        assert!(!baseline.promoted_candidate);
    }

    #[test]
    fn batch_run_ranks_candidates_without_promotion() {
        let run = batch_test_key_material(
            &[
                BatchKeyMaterialCandidate {
                    material: "WELTZEITUHR".to_string(),
                    transform: CandidateTransform::A1Z26ZeroBased,
                },
                BatchKeyMaterialCandidate {
                    material: "BERLINWORLDCLOCK".to_string(),
                    transform: CandidateTransform::A1Z26ZeroBased,
                },
            ],
            AlphabetKind::Kryptos,
            10,
            42,
        )
        .unwrap();

        assert_eq!(run.candidate_count, 2);
        assert!(!run.promoted_candidate);
        assert!(run.results.iter().all(|result| !result.promoted_candidate));
        assert!(run.results[0].best_matches >= run.results[1].best_matches);
        assert!(
            run.results
                .iter()
                .all(|result| result.empirical_p_value.is_some())
        );
    }

    #[test]
    fn routed_batch_run_scores_compatible_routes_without_promotion() {
        let run = batch_test_routed_key_material(
            &[
                BatchKeyMaterialCandidate {
                    material: "WELTZEITUHR".to_string(),
                    transform: CandidateTransform::A1Z26OneBased,
                },
                BatchKeyMaterialCandidate {
                    material: "CLOCK".to_string(),
                    transform: CandidateTransform::A1Z26ZeroBased,
                },
            ],
            AlphabetKind::Kryptos,
            5,
            42,
            5,
        )
        .unwrap();

        assert_eq!(run.candidate_count, 2);
        assert!(run.result_count >= 8);
        assert!(!run.promoted_candidate);
        assert!(run.results.iter().all(|result| !result.promoted_candidate));
        assert!(
            run.results
                .iter()
                .any(|result| result.route == RouteFamily::Identity)
        );
        assert!(
            run.results
                .iter()
                .any(|result| result.route == RouteFamily::Reverse)
        );
        assert!(run.batch_baseline.is_some());
        assert!(run.results.windows(2).all(|pair| {
            pair[0].best_matches > pair[1].best_matches
                || (pair[0].best_matches == pair[1].best_matches
                    && pair[0].best_pattern_metrics.pattern_score
                        >= pair[1].best_pattern_metrics.pattern_score)
        }));
    }
}
