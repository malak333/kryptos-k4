use crate::K4_CIPHERTEXT;

use rand::seq::SliceRandom;

use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

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
}
