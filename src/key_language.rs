//! Does any registered tableau imply an English-looking key at the anchors?
//!
//! A running key taken from English text (any text, not a fixed corpus) puts
//! English letters at the anchor positions. For each tableau, this module
//! reads the key letters the 24 anchor letters imply, scores them with a
//! trigram model trained on half of an English corpus, and compares the score
//! with real English windows from the held-out half and with random letters.

use crate::eliminate::{
    AnchorLetter, KeyedAlphabet, Tableau, all_tableaux, anchor_letters, key_alphabets,
    registered_alphabets,
};
use rand::Rng;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::Serialize;

const TRIGRAMS: usize = 26 * 26 * 26;

/// Trigram log-probabilities with add-half smoothing.
pub struct TrigramModel {
    log_prob: Vec<f64>,
}

impl TrigramModel {
    pub fn train(letters: &[u8]) -> Self {
        let mut counts = vec![0u64; TRIGRAMS];
        for window in letters.windows(3) {
            counts[trigram(window[0], window[1], window[2])] += 1;
        }
        let total: u64 = counts.iter().sum();
        let denominator = total as f64 + 0.5 * TRIGRAMS as f64;
        let log_prob = counts
            .iter()
            .map(|&c| ((c as f64 + 0.5) / denominator).ln())
            .collect();
        Self { log_prob }
    }

    /// Mean trigram log-probability over every trigram inside each run.
    pub fn score(&self, runs: &[Vec<u8>]) -> f64 {
        let mut sum = 0.0;
        let mut count = 0usize;
        for run in runs {
            for window in run.windows(3) {
                sum += self.log_prob[trigram(window[0], window[1], window[2])];
                count += 1;
            }
        }
        if count == 0 { 0.0 } else { sum / count as f64 }
    }
}

fn trigram(a: u8, b: u8, c: u8) -> usize {
    (a as usize * 26 + b as usize) * 26 + c as usize
}

/// Anchor letters grouped into runs of consecutive positions.
fn anchor_runs(anchors: &[AnchorLetter]) -> Vec<Vec<AnchorLetter>> {
    let mut runs: Vec<Vec<AnchorLetter>> = Vec::new();
    for anchor in anchors {
        match runs.last_mut() {
            Some(run)
                if run
                    .last()
                    .is_some_and(|a| a.position + 1 == anchor.position) =>
            {
                run.push(*anchor)
            }
            _ => runs.push(vec![*anchor]),
        }
    }
    runs
}

/// Key letters (standard 0..26 indices) a tableau implies at each anchor run.
fn implied_key_runs(
    runs: &[Vec<AnchorLetter>],
    tableau: &Tableau,
    key_alphabet: &KeyedAlphabet,
) -> Vec<Vec<u8>> {
    runs.iter()
        .map(|run| {
            run.iter()
                .map(|a| key_alphabet.letter(tableau.offset(a.plain, a.cipher)))
                .collect()
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct KeyLanguageHit {
    pub tableau: String,
    pub key_fragments: Vec<String>,
    pub score: f64,
    /// Fraction of held-out English windows scoring at or below this one.
    pub english_quantile: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct KeyLanguageReport {
    pub training_letters: usize,
    pub heldout_windows: usize,
    pub anchor_runs: Vec<usize>,
    pub configurations: usize,
    pub quantile: f64,
    /// Score below which `quantile` of held-out English windows fall.
    pub threshold: f64,
    pub english_median: f64,
    pub uniform_samples: usize,
    pub uniform_median: f64,
    /// Fraction of uniform random keys scoring at or above the threshold.
    pub uniform_pass_rate: f64,
    /// Configurations expected to pass by chance if no key were English.
    pub expected_compatible_by_chance: f64,
    pub compatible: usize,
    pub top: Vec<KeyLanguageHit>,
    pub seed: u64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

pub struct KeyLanguageOptions {
    pub quantile: f64,
    pub uniform_samples: usize,
    pub seed: u64,
    pub top: usize,
}

/// Score the anchor-implied keys of every registered tableau for English.
/// `corpus` is normalized letters; the first half trains the model, the
/// second half supplies the English null windows.
pub fn key_language(corpus: &[u8], options: &KeyLanguageOptions) -> KeyLanguageReport {
    let anchors = anchor_letters();
    let runs = anchor_runs(&anchors);
    let span = anchors.last().expect("anchors").position + 1;
    let half = corpus.len() / 2;
    let (train, heldout) = corpus.split_at(half);
    let model = TrigramModel::train(train);

    let window_runs = |text: &[u8], start: usize| -> Vec<Vec<u8>> {
        runs.iter()
            .map(|run| run.iter().map(|a| text[start + a.position]).collect())
            .collect()
    };
    let windows = (heldout.len() + 1).saturating_sub(span);
    let mut english: Vec<f64> = (0..windows)
        .map(|start| model.score(&window_runs(heldout, start)))
        .collect();
    english.sort_by(f64::total_cmp);
    let threshold = quantile_value(&english, options.quantile);

    let mut rng = ChaCha8Rng::seed_from_u64(options.seed);
    let mut uniform: Vec<f64> = (0..options.uniform_samples)
        .map(|_| {
            let random: Vec<Vec<u8>> = runs
                .iter()
                .map(|run| run.iter().map(|_| rng.random_range(0..26u8)).collect())
                .collect();
            model.score(&random)
        })
        .collect();
    uniform.sort_by(f64::total_cmp);
    let uniform_pass_rate = if uniform.is_empty() {
        0.0
    } else {
        uniform.iter().filter(|&&s| s >= threshold).count() as f64 / uniform.len() as f64
    };

    let alphabets = registered_alphabets();
    let tableaux = all_tableaux(&alphabets);
    let mut hits = Vec::new();
    for tableau in &tableaux {
        for (key_label, key_alphabet) in key_alphabets(tableau) {
            let key = implied_key_runs(&runs, tableau, key_alphabet);
            let score = model.score(&key);
            hits.push(KeyLanguageHit {
                tableau: format!("{} {key_label}", tableau.label()),
                key_fragments: key
                    .iter()
                    .map(|run| run.iter().map(|&l| (b'A' + l) as char).collect())
                    .collect(),
                score,
                english_quantile: fraction_at_or_below(&english, score),
            });
        }
    }
    let configurations = hits.len();
    let compatible = hits.iter().filter(|h| h.score >= threshold).count();
    hits.sort_by(|a, b| b.score.total_cmp(&a.score));
    hits.truncate(options.top);

    KeyLanguageReport {
        training_letters: train.len(),
        heldout_windows: english.len(),
        anchor_runs: runs.iter().map(Vec::len).collect(),
        configurations,
        quantile: options.quantile,
        threshold,
        english_median: quantile_value(&english, 0.5),
        uniform_samples: uniform.len(),
        uniform_median: quantile_value(&uniform, 0.5),
        uniform_pass_rate,
        expected_compatible_by_chance: configurations as f64 * uniform_pass_rate,
        compatible,
        top: hits,
        seed: options.seed,
        promoted_candidate: false,
        note: "A configuration is compatible if its anchor-implied key scores at least as English-like as the given quantile of held-out English windows. Compare compatible with expected_compatible_by_chance; a compatible configuration is a lead to test, not a decryption.",
    }
}

fn quantile_value(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let index = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn fraction_at_or_below(sorted: &[f64], value: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted.partition_point(|&s| s <= value) as f64 / sorted.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eliminate::{Sign, normalize_letters};

    fn english_text() -> Vec<u8> {
        let base = "it was a bright cold day in april and the clocks were striking thirteen \
            the hallway smelt of boiled cabbage and old rag mats at one end of it a coloured \
            poster too large for indoor display had been tacked to the wall it depicted simply \
            an enormous face more than a metre wide the face of a man of about forty five with \
            a heavy black moustache and ruggedly handsome features winston made for the stairs ";
        normalize_letters(&base.repeat(40))
    }

    #[test]
    fn english_windows_outscore_random_letters() {
        let corpus = english_text();
        let report = key_language(
            &corpus,
            &KeyLanguageOptions {
                quantile: 0.01,
                uniform_samples: 2000,
                seed: 7,
                top: 3,
            },
        );
        assert_eq!(report.anchor_runs, vec![13, 11]);
        assert!(report.english_median > report.uniform_median);
        assert!(report.uniform_pass_rate < 0.05);
    }

    #[test]
    fn planted_english_key_is_compatible() {
        // Plant: anchor-implied key letters under the standard Vigenère
        // tableau equal held-out English, so the planted key must score
        // like English.
        let corpus = english_text();
        let model = TrigramModel::train(&corpus[..corpus.len() / 2]);
        let anchors = anchor_letters();
        let runs = anchor_runs(&anchors);
        let heldout = &corpus[corpus.len() / 2..];
        let key: Vec<Vec<u8>> = runs
            .iter()
            .map(|run| run.iter().map(|a| heldout[100 + a.position]).collect())
            .collect();
        let standard = KeyedAlphabet::standard();
        let tableau = Tableau {
            plain: &standard,
            cipher: &standard,
            sign: Sign::Vigenere,
        };
        // Re-derive the key from ciphertext letters encrypted with it.
        let planted: Vec<Vec<AnchorLetter>> = runs
            .iter()
            .zip(&key)
            .map(|(run, k)| {
                run.iter()
                    .zip(k)
                    .map(|(a, &kl)| AnchorLetter {
                        position: a.position,
                        plain: a.plain,
                        cipher: (a.plain + kl) % 26,
                    })
                    .collect()
            })
            .collect();
        let derived = implied_key_runs(&planted, &tableau, &standard);
        assert_eq!(derived, key);
        let random: Vec<Vec<u8>> = vec![
            normalize_letters("QZXJVKQWZXJQV"),
            normalize_letters("XQZJKVWQZXJ"),
        ];
        assert!(model.score(&derived) > model.score(&random));
    }
}
