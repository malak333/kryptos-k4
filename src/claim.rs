use crate::{Alphabet, AlphabetKind, K4_CIPHERTEXT, known_anchors};

use anyhow::{Result, bail};

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlaintextClaimVerification {
    pub source_id: Option<String>,
    pub raw_character_count: usize,
    pub normalized_letter_count: usize,
    pub ignored_non_letter_count: usize,
    pub expected_length: usize,
    pub length_matches: bool,
    pub public_anchor_match_count: usize,
    pub public_anchor_count: usize,
    pub all_public_anchors_match: bool,
    pub anchor_checks: Vec<PlaintextClaimAnchorCheck>,
    pub implied_shift_distinct_values: usize,
    pub implied_shift_repeated_value_count: usize,
    pub implied_shift_max_bucket_count: usize,
    pub structural_checks_passed: bool,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlaintextClaimAnchorCheck {
    pub plaintext: &'static str,
    pub start_one_based: usize,
    pub end_one_based_inclusive: usize,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunningKeyClaimVerification {
    pub source_id: Option<String>,
    pub alphabet: AlphabetKind,
    pub plaintext_raw_character_count: usize,
    pub plaintext_normalized_letter_count: usize,
    pub plaintext_ignored_non_letter_count: usize,
    pub key_raw_character_count: usize,
    pub key_normalized_letter_count: usize,
    pub key_ignored_non_letter_count: usize,
    pub expected_length: usize,
    pub plaintext_length_matches: bool,
    pub key_length_matches: bool,
    pub public_anchor_match_count: usize,
    pub public_anchor_count: usize,
    pub all_public_anchors_match: bool,
    pub anchor_checks: Vec<PlaintextClaimAnchorCheck>,
    pub ciphertext_checked_count: usize,
    pub ciphertext_match_count: usize,
    pub all_ciphertext_matches: bool,
    pub mismatch_positions_one_based: Vec<usize>,
    pub key_distinct_values: usize,
    pub key_repeated_value_count: usize,
    pub key_max_bucket_count: usize,
    pub structural_checks_passed: bool,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

pub fn verify_plaintext_claim(
    input: &str,
    source_id: Option<String>,
) -> Result<PlaintextClaimVerification> {
    let raw_character_count = input.chars().count();
    let normalized = input
        .chars()
        .filter(|value| value.is_ascii_alphabetic())
        .map(|value| value.to_ascii_uppercase())
        .collect::<String>();
    let normalized_letter_count = normalized.len();
    let ignored_non_letter_count = raw_character_count.saturating_sub(normalized_letter_count);
    let expected_length = K4_CIPHERTEXT.len();
    let length_matches = normalized_letter_count == expected_length;

    if normalized_letter_count > expected_length {
        bail!(
            "plaintext claim normalizes to {} letters; expected {expected_length}",
            normalized_letter_count
        );
    }

    let anchor_checks = known_anchors()
        .into_iter()
        .map(|anchor| {
            let actual = normalized
                .get(anchor.start_zero_based..=anchor.end_zero_based_inclusive)
                .unwrap_or("");
            PlaintextClaimAnchorCheck {
                plaintext: anchor.plaintext,
                start_one_based: anchor.start_one_based(),
                end_one_based_inclusive: anchor.end_one_based_inclusive(),
                matches: actual == anchor.plaintext,
            }
        })
        .collect::<Vec<_>>();
    let public_anchor_count = anchor_checks.len();
    let public_anchor_match_count = anchor_checks.iter().filter(|check| check.matches).count();
    let all_public_anchors_match = public_anchor_match_count == public_anchor_count;

    let mut shift_counts = [0usize; 26];
    if length_matches {
        for (ciphertext, plaintext) in K4_CIPHERTEXT.bytes().zip(normalized.bytes()) {
            let ciphertext_value = ciphertext - b'A';
            let plaintext_value = plaintext - b'A';
            let shift = (26 + ciphertext_value as i16 - plaintext_value as i16) % 26;
            shift_counts[shift as usize] += 1;
        }
    }
    let implied_shift_distinct_values = shift_counts.iter().filter(|count| **count > 0).count();
    let implied_shift_max_bucket_count = shift_counts.iter().copied().max().unwrap_or(0);
    let implied_shift_repeated_value_count = normalized_letter_count
        .saturating_sub(implied_shift_distinct_values.min(normalized_letter_count));
    let structural_checks_passed = length_matches && all_public_anchors_match;

    Ok(PlaintextClaimVerification {
        source_id,
        raw_character_count,
        normalized_letter_count,
        ignored_non_letter_count,
        expected_length,
        length_matches,
        public_anchor_match_count,
        public_anchor_count,
        all_public_anchors_match,
        anchor_checks,
        implied_shift_distinct_values,
        implied_shift_repeated_value_count,
        implied_shift_max_bucket_count,
        structural_checks_passed,
        promoted_candidate: false,
        note: "Plaintext-claim verification checks length, public anchors, and aggregate shift diagnostics only; it does not print, store, or promote claimed plaintext.",
    })
}

pub fn verify_running_key_claim(
    plaintext_input: &str,
    key_input: &str,
    alphabet_kind: AlphabetKind,
    source_id: Option<String>,
) -> Result<RunningKeyClaimVerification> {
    let (plaintext, plaintext_raw_character_count, plaintext_ignored_non_letter_count) =
        normalize_ascii_letters_with_counts(plaintext_input);
    let (key, key_raw_character_count, key_ignored_non_letter_count) =
        normalize_ascii_letters_with_counts(key_input);
    let plaintext_normalized_letter_count = plaintext.len();
    let key_normalized_letter_count = key.len();
    let expected_length = K4_CIPHERTEXT.len();
    let plaintext_length_matches = plaintext_normalized_letter_count == expected_length;
    let key_length_matches = key_normalized_letter_count == expected_length;

    if plaintext_normalized_letter_count > expected_length {
        bail!(
            "plaintext claim normalizes to {} letters; expected {expected_length}",
            plaintext_normalized_letter_count
        );
    }
    if key_normalized_letter_count > expected_length {
        bail!(
            "running-key claim normalizes to {} key letters; expected {expected_length}",
            key_normalized_letter_count
        );
    }

    let anchor_checks = known_anchors()
        .into_iter()
        .map(|anchor| {
            let actual = plaintext
                .get(anchor.start_zero_based..=anchor.end_zero_based_inclusive)
                .unwrap_or("");
            PlaintextClaimAnchorCheck {
                plaintext: anchor.plaintext,
                start_one_based: anchor.start_one_based(),
                end_one_based_inclusive: anchor.end_one_based_inclusive(),
                matches: actual == anchor.plaintext,
            }
        })
        .collect::<Vec<_>>();
    let public_anchor_count = anchor_checks.len();
    let public_anchor_match_count = anchor_checks.iter().filter(|check| check.matches).count();
    let all_public_anchors_match = public_anchor_match_count == public_anchor_count;

    let alphabet = alphabet_for_kind(alphabet_kind);
    let mut ciphertext_checked_count = 0usize;
    let mut ciphertext_match_count = 0usize;
    let mut mismatch_positions_one_based = Vec::new();
    let mut key_counts = [0usize; 26];

    if plaintext_length_matches && key_length_matches {
        for (index, ((plaintext_char, key_char), ciphertext_char)) in plaintext
            .chars()
            .zip(key.chars())
            .zip(K4_CIPHERTEXT.chars())
            .enumerate()
        {
            let plaintext_value = alphabet.index_of(plaintext_char)?;
            let key_value = alphabet.index_of(key_char)?;
            key_counts[key_value as usize] += 1;
            let expected_ciphertext = alphabet.char_at((plaintext_value + key_value) % 26)?;
            ciphertext_checked_count += 1;
            if expected_ciphertext == ciphertext_char {
                ciphertext_match_count += 1;
            } else {
                mismatch_positions_one_based.push(index + 1);
            }
        }
    }

    let key_distinct_values = key_counts.iter().filter(|count| **count > 0).count();
    let key_max_bucket_count = key_counts.iter().copied().max().unwrap_or(0);
    let key_repeated_value_count = key_normalized_letter_count
        .saturating_sub(key_distinct_values.min(key_normalized_letter_count));
    let all_ciphertext_matches =
        ciphertext_checked_count == expected_length && ciphertext_match_count == expected_length;
    let structural_checks_passed = plaintext_length_matches
        && key_length_matches
        && all_public_anchors_match
        && all_ciphertext_matches;

    Ok(RunningKeyClaimVerification {
        source_id,
        alphabet: alphabet_kind,
        plaintext_raw_character_count,
        plaintext_normalized_letter_count,
        plaintext_ignored_non_letter_count,
        key_raw_character_count,
        key_normalized_letter_count,
        key_ignored_non_letter_count,
        expected_length,
        plaintext_length_matches,
        key_length_matches,
        public_anchor_match_count,
        public_anchor_count,
        all_public_anchors_match,
        anchor_checks,
        ciphertext_checked_count,
        ciphertext_match_count,
        all_ciphertext_matches,
        mismatch_positions_one_based,
        key_distinct_values,
        key_repeated_value_count,
        key_max_bucket_count,
        structural_checks_passed,
        promoted_candidate: false,
        note: "Running-key claim verification checks local plaintext and key-stream files against the repo ciphertext without printing, storing, or promoting claimed plaintext or key material.",
    })
}

fn normalize_ascii_letters_with_counts(input: &str) -> (String, usize, usize) {
    let raw_character_count = input.chars().count();
    let normalized = input
        .chars()
        .filter(|value| value.is_ascii_alphabetic())
        .map(|value| value.to_ascii_uppercase())
        .collect::<String>();
    let ignored_non_letter_count = raw_character_count.saturating_sub(normalized.len());
    (normalized, raw_character_count, ignored_non_letter_count)
}

fn alphabet_for_kind(kind: AlphabetKind) -> Alphabet {
    match kind {
        AlphabetKind::Standard => Alphabet::standard(),
        AlphabetKind::Kryptos => Alphabet::kryptos(),
        AlphabetKind::KryptosReversed => Alphabet::kryptos_reversed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_anchor_compatible_fixture() -> String {
        let mut letters = vec![b'A'; K4_CIPHERTEXT.len()];
        for anchor in known_anchors() {
            for (index, value) in anchor.plaintext.bytes().enumerate() {
                letters[anchor.start_zero_based + index] = value;
            }
        }
        String::from_utf8(letters).unwrap()
    }

    fn standard_running_key_for_plaintext(plaintext: &str) -> String {
        K4_CIPHERTEXT
            .bytes()
            .zip(plaintext.bytes())
            .map(|(ciphertext, plaintext)| {
                let key = (26 + (ciphertext - b'A') as i16 - (plaintext - b'A') as i16) % 26;
                (b'A' + key as u8) as char
            })
            .collect()
    }

    #[test]
    fn verifies_length_and_public_anchor_compatibility_without_promotion() {
        let verification = verify_plaintext_claim(
            &public_anchor_compatible_fixture(),
            Some("synthetic-claim".to_string()),
        )
        .unwrap();

        assert!(verification.length_matches);
        assert!(verification.all_public_anchors_match);
        assert!(verification.structural_checks_passed, "{verification:#?}");
        assert_eq!(verification.public_anchor_match_count, 4);
        assert!(!verification.promoted_candidate);
    }

    #[test]
    fn verifies_running_key_claim_against_ciphertext_without_promotion() {
        let plaintext = public_anchor_compatible_fixture();
        let key = standard_running_key_for_plaintext(&plaintext);

        let verification = verify_running_key_claim(
            &plaintext,
            &key,
            AlphabetKind::Standard,
            Some("synthetic-claim".to_string()),
        )
        .unwrap();

        assert!(verification.plaintext_length_matches);
        assert!(verification.key_length_matches);
        assert!(verification.all_public_anchors_match);
        assert!(verification.all_ciphertext_matches);
        assert!(verification.structural_checks_passed, "{verification:#?}");
        assert_eq!(verification.ciphertext_match_count, K4_CIPHERTEXT.len());
        assert!(verification.mismatch_positions_one_based.is_empty());
        assert!(!verification.promoted_candidate);

        let mut corrupted_key = key.into_bytes();
        corrupted_key[0] = if corrupted_key[0] == b'A' { b'B' } else { b'A' };
        let corrupted_key = String::from_utf8(corrupted_key).unwrap();
        let corrupted = verify_running_key_claim(
            &plaintext,
            &corrupted_key,
            AlphabetKind::Standard,
            Some("synthetic-claim".to_string()),
        )
        .unwrap();

        assert!(!corrupted.all_ciphertext_matches);
        assert!(!corrupted.structural_checks_passed);
        assert_eq!(corrupted.mismatch_positions_one_based, vec![1]);
        assert!(!corrupted.promoted_candidate);
    }

    #[test]
    fn rejects_overlong_normalized_claims() {
        let error = verify_plaintext_claim(&"A".repeat(K4_CIPHERTEXT.len() + 1), None)
            .expect_err("overlong claims should fail");

        assert!(error.to_string().contains("normalizes to 98 letters"));
    }
}
