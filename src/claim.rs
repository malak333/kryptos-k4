use crate::{K4_CIPHERTEXT, known_anchors};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

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
pub struct ClaimReconciliationVerification {
    pub source_id: Option<String>,
    pub row_count: usize,
    pub expected_row_count: usize,
    pub row_count_matches: bool,
    pub unique_positions: bool,
    pub sequential_positions: bool,
    pub ciphertext_checked_count: usize,
    pub ciphertext_match_count: usize,
    pub all_ciphertext_matches: bool,
    pub plaintext_rows: usize,
    pub public_anchor_match_count: usize,
    pub public_anchor_count: usize,
    pub all_public_anchors_match: bool,
    pub anchor_checks: Vec<PlaintextClaimAnchorCheck>,
    pub row_checks: Vec<ClaimReconciliationRowCheck>,
    pub implied_shift_distinct_values: Option<usize>,
    pub implied_shift_repeated_value_count: Option<usize>,
    pub implied_shift_max_bucket_count: Option<usize>,
    pub structural_checks_passed: bool,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimReconciliationRowCheck {
    pub position_one_based: usize,
    pub ciphertext_matches: bool,
    pub plaintext_present: bool,
    pub public_anchor_position: bool,
    pub public_anchor_plaintext_matches: Option<bool>,
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

pub fn verify_claim_reconciliation_table(
    input: &str,
    source_id: Option<String>,
) -> Result<ClaimReconciliationVerification> {
    let rows = parse_reconciliation_rows(input)?;
    let row_count = rows.len();
    let expected_row_count = K4_CIPHERTEXT.len();
    let row_count_matches = row_count == expected_row_count;

    let mut seen_positions = BTreeSet::new();
    let mut unique_positions = true;
    let mut sequential_positions = row_count_matches;
    let mut ciphertext_checked_count = 0usize;
    let mut ciphertext_match_count = 0usize;
    let mut plaintext_rows = 0usize;
    let mut plaintext_by_position = vec![None; expected_row_count + 1];
    let anchors = known_anchors();
    let mut row_checks = Vec::new();

    for (index, row) in rows.iter().enumerate() {
        if !seen_positions.insert(row.position_one_based) {
            unique_positions = false;
        }
        if row.position_one_based != index + 1 {
            sequential_positions = false;
        }

        let expected_ciphertext = K4_CIPHERTEXT
            .as_bytes()
            .get(row.position_one_based.saturating_sub(1))
            .copied()
            .map(char::from);
        let ciphertext_matches = expected_ciphertext
            .zip(row.ciphertext)
            .map(|(expected, actual)| expected == actual)
            .unwrap_or(false);
        if row.ciphertext.is_some() {
            ciphertext_checked_count += 1;
            if ciphertext_matches {
                ciphertext_match_count += 1;
            }
        }

        let public_anchor_position = anchors.iter().any(|anchor| {
            (anchor.start_one_based()..=anchor.end_one_based_inclusive())
                .contains(&row.position_one_based)
        });
        let public_anchor_plaintext_matches = row.plaintext.and_then(|plaintext| {
            anchors
                .iter()
                .find(|anchor| {
                    (anchor.start_one_based()..=anchor.end_one_based_inclusive())
                        .contains(&row.position_one_based)
                })
                .map(|anchor| {
                    let offset = row.position_one_based - anchor.start_one_based();
                    anchor.plaintext.as_bytes()[offset] as char == plaintext
                })
        });

        if let Some(plaintext) = row.plaintext {
            plaintext_rows += 1;
            if row.position_one_based <= expected_row_count {
                plaintext_by_position[row.position_one_based] = Some(plaintext);
            }
        }

        row_checks.push(ClaimReconciliationRowCheck {
            position_one_based: row.position_one_based,
            ciphertext_matches,
            plaintext_present: row.plaintext.is_some(),
            public_anchor_position,
            public_anchor_plaintext_matches,
        });
    }

    let all_ciphertext_matches = ciphertext_checked_count == expected_row_count
        && ciphertext_match_count == expected_row_count;

    let anchor_checks = anchors
        .into_iter()
        .map(|anchor| {
            let matches = (anchor.start_one_based()..=anchor.end_one_based_inclusive())
                .enumerate()
                .all(|(offset, position)| {
                    plaintext_by_position
                        .get(position)
                        .and_then(|value| *value)
                        .map(|actual| actual == anchor.plaintext.as_bytes()[offset] as char)
                        .unwrap_or(false)
                });
            PlaintextClaimAnchorCheck {
                plaintext: anchor.plaintext,
                start_one_based: anchor.start_one_based(),
                end_one_based_inclusive: anchor.end_one_based_inclusive(),
                matches,
            }
        })
        .collect::<Vec<_>>();
    let public_anchor_count = anchor_checks.len();
    let public_anchor_match_count = anchor_checks.iter().filter(|check| check.matches).count();
    let all_public_anchors_match = public_anchor_match_count == public_anchor_count;

    let (
        implied_shift_distinct_values,
        implied_shift_repeated_value_count,
        implied_shift_max_bucket_count,
    ) = if plaintext_rows == expected_row_count && row_count_matches {
        let mut shift_counts = [0usize; 26];
        for position in 1..=expected_row_count {
            if let Some(plaintext) = plaintext_by_position[position] {
                let ciphertext = K4_CIPHERTEXT.as_bytes()[position - 1];
                let ciphertext_value = ciphertext - b'A';
                let plaintext_value = plaintext as u8 - b'A';
                let shift = (26 + ciphertext_value as i16 - plaintext_value as i16) % 26;
                shift_counts[shift as usize] += 1;
            }
        }
        let distinct = shift_counts.iter().filter(|count| **count > 0).count();
        (
            Some(distinct),
            Some(expected_row_count.saturating_sub(distinct)),
            Some(shift_counts.iter().copied().max().unwrap_or(0)),
        )
    } else {
        (None, None, None)
    };

    let structural_checks_passed = row_count_matches
        && unique_positions
        && sequential_positions
        && all_ciphertext_matches
        && all_public_anchors_match;

    Ok(ClaimReconciliationVerification {
        source_id,
        row_count,
        expected_row_count,
        row_count_matches,
        unique_positions,
        sequential_positions,
        ciphertext_checked_count,
        ciphertext_match_count,
        all_ciphertext_matches,
        plaintext_rows,
        public_anchor_match_count,
        public_anchor_count,
        all_public_anchors_match,
        anchor_checks,
        row_checks,
        implied_shift_distinct_values,
        implied_shift_repeated_value_count,
        implied_shift_max_bucket_count,
        structural_checks_passed,
        promoted_candidate: false,
        note: "Claim-reconciliation verification checks local table shape, K4 ciphertext alignment, public anchors, and aggregate shift diagnostics only; it does not print, store, or promote claimed plaintext.",
    })
}

#[derive(Debug)]
struct ReconciliationRow {
    position_one_based: usize,
    ciphertext: Option<char>,
    plaintext: Option<char>,
}

fn parse_reconciliation_rows(input: &str) -> Result<Vec<ReconciliationRow>> {
    let mut non_empty_lines = input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let Some(header_line) = non_empty_lines.next() else {
        bail!("claim reconciliation table is empty");
    };
    let delimiter = detect_delimiter(header_line);
    let headers = split_reconciliation_line(header_line, delimiter);
    let header_lookup = headers
        .iter()
        .enumerate()
        .map(|(index, header)| (normalize_header(header), index))
        .collect::<HashMap<_, _>>();
    let position_index = find_header(
        &header_lookup,
        &["i", "pos", "position", "position_one_based"],
    )
    .ok_or_else(|| anyhow::anyhow!("claim reconciliation table needs an i/position column"))?;
    let ciphertext_index = find_header(&header_lookup, &["c", "ciphertext"]);
    let plaintext_index = find_header(&header_lookup, &["p", "plaintext"]);

    let mut rows = Vec::new();
    for (line_number, line) in non_empty_lines.enumerate() {
        let cells = split_reconciliation_line(line, delimiter);
        let position_text = cells
            .get(position_index)
            .ok_or_else(|| anyhow::anyhow!("missing position at data line {}", line_number + 2))?;
        let position_one_based = clean_cell(position_text)
            .parse::<usize>()
            .with_context(|| {
                format!(
                    "invalid position `{position_text}` at data line {}",
                    line_number + 2
                )
            })?;
        let ciphertext = ciphertext_index
            .and_then(|index| cells.get(index))
            .and_then(|cell| single_ascii_uppercase_letter(cell));
        let plaintext = plaintext_index
            .and_then(|index| cells.get(index))
            .and_then(|cell| single_ascii_uppercase_letter(cell));
        rows.push(ReconciliationRow {
            position_one_based,
            ciphertext,
            plaintext,
        });
    }

    Ok(rows)
}

#[derive(Debug, Clone, Copy)]
enum ReconciliationDelimiter {
    Comma,
    Tab,
    Whitespace,
}

fn detect_delimiter(line: &str) -> ReconciliationDelimiter {
    if line.contains(',') {
        ReconciliationDelimiter::Comma
    } else if line.contains('\t') {
        ReconciliationDelimiter::Tab
    } else {
        ReconciliationDelimiter::Whitespace
    }
}

fn split_reconciliation_line(line: &str, delimiter: ReconciliationDelimiter) -> Vec<String> {
    match delimiter {
        ReconciliationDelimiter::Comma => line.split(',').map(clean_cell).collect(),
        ReconciliationDelimiter::Tab => line.split('\t').map(clean_cell).collect(),
        ReconciliationDelimiter::Whitespace => line.split_whitespace().map(clean_cell).collect(),
    }
}

fn clean_cell(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('`').to_string()
}

fn normalize_header(value: &str) -> String {
    clean_cell(value)
        .chars()
        .filter(|value| value.is_ascii_alphanumeric() || *value == '_')
        .collect::<String>()
        .to_ascii_lowercase()
}

fn find_header(headers: &HashMap<String, usize>, aliases: &[&str]) -> Option<usize> {
    aliases
        .iter()
        .find_map(|alias| headers.get(*alias).copied())
}

fn single_ascii_uppercase_letter(value: &str) -> Option<char> {
    let cleaned = clean_cell(value).to_ascii_uppercase();
    let mut letters = cleaned.chars().filter(|value| value.is_ascii_alphabetic());
    let first = letters.next()?;
    if letters.next().is_some() {
        return None;
    }
    Some(first)
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

    #[test]
    fn verifies_length_and_public_anchor_compatibility_without_promotion() {
        let verification = verify_plaintext_claim(
            &public_anchor_compatible_fixture(),
            Some("synthetic-claim".to_string()),
        )
        .unwrap();

        assert!(verification.length_matches);
        assert!(verification.all_public_anchors_match);
        assert!(verification.structural_checks_passed);
        assert_eq!(verification.public_anchor_match_count, 4);
        assert!(!verification.promoted_candidate);
    }

    #[test]
    fn rejects_overlong_normalized_claims() {
        let error = verify_plaintext_claim(&"A".repeat(K4_CIPHERTEXT.len() + 1), None)
            .expect_err("overlong claims should fail");

        assert!(error.to_string().contains("normalizes to 98 letters"));
    }

    #[test]
    fn verifies_reconciliation_tables_without_plaintext_output_fields() {
        let fixture = public_anchor_compatible_fixture();
        let mut table = String::from("i,C,P\n");
        for (index, (ciphertext, plaintext)) in
            K4_CIPHERTEXT.chars().zip(fixture.chars()).enumerate()
        {
            table.push_str(&format!("{},{},{}\n", index + 1, ciphertext, plaintext));
        }

        let verification =
            verify_claim_reconciliation_table(&table, Some("synthetic-claim".to_string())).unwrap();

        assert!(verification.row_count_matches);
        assert!(verification.unique_positions);
        assert!(verification.sequential_positions);
        assert!(verification.all_ciphertext_matches);
        assert!(verification.all_public_anchors_match);
        assert!(verification.structural_checks_passed);
        assert_eq!(verification.public_anchor_match_count, 4);
        assert!(!verification.promoted_candidate);
    }
}
