use crate::{K4_CIPHERTEXT, known_anchors};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

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
    pub ciphertext_value_checked_count: usize,
    pub ciphertext_value_match_count: usize,
    pub all_ciphertext_values_match: bool,
    pub plaintext_rows: usize,
    pub plaintext_value_checked_count: usize,
    pub plaintext_value_match_count: usize,
    pub all_plaintext_values_match: bool,
    pub tier_checked_count: usize,
    pub tier_match_count: usize,
    pub all_tier_values_match: bool,
    pub lane_checked_count: usize,
    pub lane_match_count: usize,
    pub all_lane_values_match: bool,
    pub r_value_checked_count: usize,
    pub r_value_match_count: usize,
    pub all_r_values_match: bool,
    pub gate_checked_count: usize,
    pub gate_binary_count: usize,
    pub all_gate_values_binary: bool,
    pub r_plus_gate_checked_count: usize,
    pub r_plus_gate_match_count: usize,
    pub all_r_plus_gate_matches: bool,
    pub z2_handoff_checked_count: usize,
    pub z2_handoff_match_count: usize,
    pub all_z2_handoff_matches: bool,
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
    pub ciphertext_value_matches: Option<bool>,
    pub plaintext_present: bool,
    pub plaintext_value_matches: Option<bool>,
    pub tier_value_matches: Option<bool>,
    pub lane_value_matches: Option<bool>,
    pub implied_shift_value: Option<u8>,
    pub r_value_matches: Option<bool>,
    pub gate_value_binary: Option<bool>,
    pub r_plus_gate_matches: Option<bool>,
    pub public_anchor_position: bool,
    pub public_anchor_plaintext_matches: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClaimBundleVerification {
    pub source_id: Option<String>,
    pub bundle_directory: String,
    pub required_files_checked: usize,
    pub expected_required_files: usize,
    pub ciphertext_file_matches_repo: bool,
    pub plaintext_file_length_matches: bool,
    pub reconciliation: ClaimReconciliationVerification,
    pub r_grid_checked_count: usize,
    pub r_grid_match_count: usize,
    pub all_r_grid_values_match: bool,
    pub base_r_grid_checked_count: usize,
    pub base_r_grid_match_count: usize,
    pub all_base_r_grid_values_match: bool,
    pub gate_map_checked_count: usize,
    pub gate_map_match_count: usize,
    pub all_gate_map_values_match: bool,
    pub structural_checks_passed: bool,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClaimMechanismVerification {
    pub source_id: Option<String>,
    pub bundle_directory: String,
    pub required_files_checked: usize,
    pub expected_required_files: usize,
    pub f_table_checked_count: usize,
    pub f_table_match_count: usize,
    pub helper_card_checked_count: usize,
    pub helper_card_match_count: usize,
    pub z1_z2_delta_checked_count: usize,
    pub z1_z2_delta_match_count: usize,
    pub control_card_checked_count: usize,
    pub control_card_match_count: usize,
    pub z2_effective_key_matches: bool,
    pub z2_r_grid_checked_count: usize,
    pub z2_r_grid_match_count: usize,
    pub z2_final_grid_checked_count: usize,
    pub z2_final_grid_match_count: usize,
    pub y_template_rule_checked_count: usize,
    pub y_template_rule_match_count: usize,
    pub y_template_gate_checked_count: usize,
    pub y_template_gate_match_count: usize,
    pub y_template_mismatches: Vec<ClaimMechanismYTemplateMismatch>,
    pub structural_checks_passed: bool,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimMechanismYTemplateMismatch {
    pub y_position_one_based: usize,
    pub k4_position_one_based: usize,
    pub expected_gate_value: usize,
    pub observed_gate_value: usize,
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
    let mut ciphertext_value_checked_count = 0usize;
    let mut ciphertext_value_match_count = 0usize;
    let mut plaintext_rows = 0usize;
    let mut plaintext_value_checked_count = 0usize;
    let mut plaintext_value_match_count = 0usize;
    let mut tier_checked_count = 0usize;
    let mut tier_match_count = 0usize;
    let mut lane_checked_count = 0usize;
    let mut lane_match_count = 0usize;
    let mut r_value_checked_count = 0usize;
    let mut r_value_match_count = 0usize;
    let mut gate_checked_count = 0usize;
    let mut gate_binary_count = 0usize;
    let mut r_plus_gate_checked_count = 0usize;
    let mut r_plus_gate_match_count = 0usize;
    let mut z2_handoff_checked_count = 0usize;
    let mut z2_handoff_match_count = 0usize;
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
        let ciphertext_value_matches = row.ciphertext_value.and_then(|ciphertext_value| {
            expected_ciphertext.map(|ciphertext| {
                ciphertext_value_checked_count += 1;
                let expected = (ciphertext as u8 - b'A') as usize;
                let matches = ciphertext_value == expected;
                if matches {
                    ciphertext_value_match_count += 1;
                }
                matches
            })
        });

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
        let plaintext_value_matches = row.plaintext_value.and_then(|plaintext_value| {
            row.plaintext.map(|plaintext| {
                plaintext_value_checked_count += 1;
                let expected = (plaintext as u8 - b'A') as usize;
                let matches = plaintext_value == expected;
                if matches {
                    plaintext_value_match_count += 1;
                }
                matches
            })
        });

        let expected_tier = expected_tier(row.position_one_based);
        let expected_lane = expected_lane(row.position_one_based);
        let tier_value_matches = row.tier_value.map(|tier_value| {
            tier_checked_count += 1;
            let matches = tier_value == expected_tier;
            if matches {
                tier_match_count += 1;
            }
            matches
        });
        let lane_value_matches = row.lane_value.map(|lane_value| {
            lane_checked_count += 1;
            let matches = lane_value == expected_lane;
            if matches {
                lane_match_count += 1;
            }
            matches
        });

        let implied_shift_value =
            expected_ciphertext
                .zip(row.plaintext)
                .map(|(ciphertext, plaintext)| {
                    let ciphertext_value = ciphertext as u8 - b'A';
                    let plaintext_value = plaintext as u8 - b'A';
                    ((26 + ciphertext_value as i16 - plaintext_value as i16) % 26) as u8
                });
        let r_value_matches = row.r_value.and_then(|r_value| {
            implied_shift_value.map(|shift| {
                r_value_checked_count += 1;
                let matches = (r_value % 26) as u8 == shift;
                if matches {
                    r_value_match_count += 1;
                }
                matches
            })
        });
        let gate_value_binary = row.gate_value.map(|gate_value| {
            gate_checked_count += 1;
            let binary = gate_value <= 1;
            if binary {
                gate_binary_count += 1;
            }
            binary
        });
        let r_plus_gate_matches =
            row.base_r_value
                .zip(row.gate_value)
                .and_then(|(base_r_value, gate_value)| {
                    implied_shift_value.map(|shift| {
                        r_plus_gate_checked_count += 1;
                        let matches = ((base_r_value + gate_value) % 26) as u8 == shift;
                        if matches {
                            r_plus_gate_match_count += 1;
                        }
                        matches
                    })
                });

        if (67..=97).contains(&row.position_one_based) {
            if let (Some(ciphertext), Some(plaintext), Some(gate_value)) =
                (expected_ciphertext, row.plaintext, row.gate_value)
            {
                if let Some(actual_g) = z2_g_value_for_position(row.position_one_based) {
                    z2_handoff_checked_count += 1;
                    let ciphertext_value = ciphertext as u8 - b'A';
                    let plaintext_value = plaintext as u8 - b'A';
                    let shift = (26 + ciphertext_value as i16 - plaintext_value as i16) % 26;
                    let raw_r = (26 + shift - (gate_value % 26) as i16) % 26;
                    let expected_g = (26 + raw_r - f_table_value(ciphertext) as i16) % 26;
                    if expected_g as usize == actual_g {
                        z2_handoff_match_count += 1;
                    }
                }
            }
        }

        row_checks.push(ClaimReconciliationRowCheck {
            position_one_based: row.position_one_based,
            ciphertext_matches,
            ciphertext_value_matches,
            plaintext_present: row.plaintext.is_some(),
            plaintext_value_matches,
            tier_value_matches,
            lane_value_matches,
            implied_shift_value,
            r_value_matches,
            gate_value_binary,
            r_plus_gate_matches,
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
        && ciphertext_value_match_count == ciphertext_value_checked_count
        && plaintext_value_match_count == plaintext_value_checked_count
        && all_public_anchors_match
        && tier_match_count == tier_checked_count
        && lane_match_count == lane_checked_count
        && r_value_match_count == r_value_checked_count
        && gate_binary_count == gate_checked_count
        && r_plus_gate_match_count == r_plus_gate_checked_count
        && z2_handoff_match_count == z2_handoff_checked_count;

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
        ciphertext_value_checked_count,
        ciphertext_value_match_count,
        all_ciphertext_values_match: ciphertext_value_match_count == ciphertext_value_checked_count,
        plaintext_rows,
        plaintext_value_checked_count,
        plaintext_value_match_count,
        all_plaintext_values_match: plaintext_value_match_count == plaintext_value_checked_count,
        tier_checked_count,
        tier_match_count,
        all_tier_values_match: tier_match_count == tier_checked_count,
        lane_checked_count,
        lane_match_count,
        all_lane_values_match: lane_match_count == lane_checked_count,
        r_value_checked_count,
        r_value_match_count,
        all_r_values_match: r_value_match_count == r_value_checked_count,
        gate_checked_count,
        gate_binary_count,
        all_gate_values_binary: gate_binary_count == gate_checked_count,
        r_plus_gate_checked_count,
        r_plus_gate_match_count,
        all_r_plus_gate_matches: r_plus_gate_match_count == r_plus_gate_checked_count,
        z2_handoff_checked_count,
        z2_handoff_match_count,
        all_z2_handoff_matches: z2_handoff_match_count == z2_handoff_checked_count,
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
        note: "Claim-reconciliation verification checks local table shape, K4 ciphertext alignment, optional coordinate, numeric-letter, and shift/gate arithmetic, public anchors, and aggregate shift diagnostics only; it does not print, store, or promote claimed plaintext.",
    })
}

pub fn verify_claim_bundle(
    bundle_directory: &Path,
    source_id: Option<String>,
) -> Result<ClaimBundleVerification> {
    let required_files = [
        "k4_ciphertext.txt",
        "k4_proposed_plaintext.txt",
        "k4_reconciliation.csv",
        "r_grid_7x14.txt",
        "gate_map.txt",
    ];
    let required_files_checked = required_files
        .iter()
        .filter(|file| bundle_directory.join(file).is_file())
        .count();
    let expected_required_files = required_files.len();

    let ciphertext_file = read_bundle_file(bundle_directory, "k4_ciphertext.txt")?;
    let normalized_ciphertext = normalize_ascii_letters(&ciphertext_file);
    let ciphertext_file_matches_repo = normalized_ciphertext == K4_CIPHERTEXT;

    let plaintext_file = read_bundle_file(bundle_directory, "k4_proposed_plaintext.txt")?;
    let normalized_plaintext = normalize_ascii_letters(&plaintext_file);
    let plaintext_file_length_matches = normalized_plaintext.len() == K4_CIPHERTEXT.len();

    let reconciliation_input = read_bundle_file(bundle_directory, "k4_reconciliation.csv")?;
    let reconciliation =
        verify_claim_reconciliation_table(&reconciliation_input, source_id.clone())?;
    let rows = parse_reconciliation_rows(&reconciliation_input)?;

    let r_grid_input = read_bundle_file(bundle_directory, "r_grid_7x14.txt")?;
    let r_grid = parse_r_grid_section(&r_grid_input, "R-grid")?;
    let base_r_grid = parse_r_grid_section(&r_grid_input, "r-grid")?;
    let gate_map_input = read_bundle_file(bundle_directory, "gate_map.txt")?;
    let gate_map = parse_gate_map(&gate_map_input)?;

    let mut r_grid_checked_count = 0usize;
    let mut r_grid_match_count = 0usize;
    let mut base_r_grid_checked_count = 0usize;
    let mut base_r_grid_match_count = 0usize;
    let mut gate_map_checked_count = 0usize;
    let mut gate_map_match_count = 0usize;

    for row in &rows {
        let position = row.position_one_based;
        if let Some(expected_r) = r_grid.get(position).and_then(|value| *value) {
            if let Some(actual_r) = row.r_value {
                r_grid_checked_count += 1;
                if actual_r % 26 == expected_r {
                    r_grid_match_count += 1;
                }
            }
        }
        if let Some(expected_base_r) = base_r_grid.get(position).and_then(|value| *value) {
            if let Some(actual_base_r) = row.base_r_value {
                base_r_grid_checked_count += 1;
                if actual_base_r % 26 == expected_base_r {
                    base_r_grid_match_count += 1;
                }
            }
        }
        if let Some(expected_gate) = gate_map.get(position).and_then(|value| *value) {
            if let Some(actual_gate) = row.gate_value {
                gate_map_checked_count += 1;
                if actual_gate == expected_gate {
                    gate_map_match_count += 1;
                }
            }
        }
    }

    let all_r_grid_values_match =
        r_grid_checked_count == K4_CIPHERTEXT.len() && r_grid_match_count == r_grid_checked_count;
    let all_base_r_grid_values_match = base_r_grid_checked_count == K4_CIPHERTEXT.len()
        && base_r_grid_match_count == base_r_grid_checked_count;
    let all_gate_map_values_match = gate_map_checked_count == K4_CIPHERTEXT.len()
        && gate_map_match_count == gate_map_checked_count;
    let structural_checks_passed = required_files_checked == expected_required_files
        && ciphertext_file_matches_repo
        && plaintext_file_length_matches
        && reconciliation.structural_checks_passed
        && all_r_grid_values_match
        && all_base_r_grid_values_match
        && all_gate_map_values_match;

    Ok(ClaimBundleVerification {
        source_id,
        bundle_directory: bundle_directory.display().to_string(),
        required_files_checked,
        expected_required_files,
        ciphertext_file_matches_repo,
        plaintext_file_length_matches,
        reconciliation,
        r_grid_checked_count,
        r_grid_match_count,
        all_r_grid_values_match,
        base_r_grid_checked_count,
        base_r_grid_match_count,
        all_base_r_grid_values_match,
        gate_map_checked_count,
        gate_map_match_count,
        all_gate_map_values_match,
        structural_checks_passed,
        promoted_candidate: false,
        note: "Claim-bundle verification cross-checks local bundle files against the repo ciphertext, reconciliation arithmetic, R/r grids, gate map, Z2 handoff, and public anchors without printing, storing, or promoting claimed plaintext.",
    })
}

pub fn verify_claim_mechanism(
    bundle_directory: &Path,
    source_id: Option<String>,
) -> Result<ClaimMechanismVerification> {
    let required_files = [
        "f_table.txt",
        "helper_cards.txt",
        "control_card.txt",
        "z2_footer_basis_handoff.txt",
        "r_grid_7x14.txt",
        "gate_map.txt",
        "k4_ciphertext.txt",
        "y_master_template.txt",
    ];
    let required_files_checked = required_files
        .iter()
        .filter(|file| bundle_directory.join(file).is_file())
        .count();
    let expected_required_files = required_files.len();

    let ciphertext_file = read_bundle_file(bundle_directory, "k4_ciphertext.txt")?;
    let normalized_ciphertext = normalize_ascii_letters(&ciphertext_file);
    let ciphertext_file_matches_repo = normalized_ciphertext == K4_CIPHERTEXT;

    let f_table_input = read_bundle_file(bundle_directory, "f_table.txt")?;
    let f_table = parse_f_table_values(&f_table_input)?;
    let helper_cards_input = read_bundle_file(bundle_directory, "helper_cards.txt")?;
    let helper_cards = parse_helper_cards(&helper_cards_input)?;
    let control_card_input = read_bundle_file(bundle_directory, "control_card.txt")?;
    let control_card = parse_control_card(&control_card_input)?;
    let z2_handoff_input = read_bundle_file(bundle_directory, "z2_footer_basis_handoff.txt")?;
    let r_grid_input = read_bundle_file(bundle_directory, "r_grid_7x14.txt")?;
    let r_grid = parse_r_grid_section(&r_grid_input, "R-grid")?;
    let base_r_grid = parse_r_grid_section(&r_grid_input, "r-grid")?;
    let gate_map_input = read_bundle_file(bundle_directory, "gate_map.txt")?;
    let gate_map = parse_gate_map(&gate_map_input)?;
    let y_template_input = read_bundle_file(bundle_directory, "y_master_template.txt")?;
    let y_row = parse_y_master_row(&y_template_input)?;

    let expected_f_table = expected_f_table_values();
    let mut f_table_checked_count = 0usize;
    let mut f_table_match_count = 0usize;
    for letter in KALPHA.chars() {
        f_table_checked_count += 1;
        if f_table.get(&letter) == expected_f_table.get(&letter) {
            f_table_match_count += 1;
        }
    }

    let mut helper_card_checked_count = 0usize;
    let mut helper_card_match_count = 0usize;
    for letter in KALPHA.chars() {
        if let Some((z1, delta, z2)) = helper_cards
            .g_z1
            .get(&letter)
            .zip(helper_cards.delta.get(&letter))
            .zip(helper_cards.g_z2.get(&letter))
            .map(|((z1, delta), z2)| (*z1, *delta, *z2))
        {
            helper_card_checked_count += 1;
            if (z1 + delta) % 26 == z2 {
                helper_card_match_count += 1;
            }
        }
    }

    let mut control_card_checked_count = 0usize;
    let mut control_card_match_count = 0usize;
    for row in &control_card {
        if let Some((z1, delta, z2)) = helper_cards
            .g_z1
            .get(&row.letter)
            .zip(helper_cards.delta.get(&row.letter))
            .zip(helper_cards.g_z2.get(&row.letter))
            .map(|((z1, delta), z2)| (*z1, *delta, *z2))
        {
            control_card_checked_count += 1;
            if row.z1 == z1 && row.delta == delta && row.z2 == z2 {
                control_card_match_count += 1;
            }
        }
    }

    let visible_z2_footer =
        parse_labeled_value(&z2_handoff_input, "Visible footer").unwrap_or_default();
    let effective_z2_key =
        parse_labeled_value(&z2_handoff_input, "Effective Z2 key").unwrap_or_default();
    let derived_effective_z2_key = derive_z2_effective_key(&visible_z2_footer)?;
    let z2_effective_key_matches = effective_z2_key == derived_effective_z2_key;

    let mut z2_r_grid_checked_count = 0usize;
    let mut z2_r_grid_match_count = 0usize;
    let mut z2_final_grid_checked_count = 0usize;
    let mut z2_final_grid_match_count = 0usize;
    for (offset, helper_letter) in derived_effective_z2_key.chars().enumerate() {
        let position = 67 + offset;
        let Some(ciphertext) = K4_CIPHERTEXT.chars().nth(position - 1) else {
            continue;
        };
        let Some(f_value) = f_table.get(&ciphertext).copied() else {
            continue;
        };
        let Some(g_value) = helper_cards.g_z2.get(&helper_letter).copied() else {
            continue;
        };
        let base_r = (f_value + g_value) % 26;
        if let Some(expected_base_r) = base_r_grid.get(position).and_then(|value| *value) {
            z2_r_grid_checked_count += 1;
            if base_r == expected_base_r {
                z2_r_grid_match_count += 1;
            }
        }
        if let Some(gate) = gate_map.get(position).and_then(|value| *value) {
            if let Some(expected_r) = r_grid.get(position).and_then(|value| *value) {
                z2_final_grid_checked_count += 1;
                if (base_r + gate) % 26 == expected_r {
                    z2_final_grid_match_count += 1;
                }
            }
        }
    }

    let mut y_template_rule_checked_count = 0usize;
    let mut y_template_rule_match_count = 0usize;
    let mut y_template_gate_checked_count = 0usize;
    let mut y_template_gate_match_count = 0usize;
    let mut y_template_mismatches = Vec::new();
    for (index, letter) in y_row.chars().take(31).enumerate() {
        let y_position = index + 1;
        let k4_position = y_position + 4;
        let rule_zero = y_template_rule_zero(y_position, letter);
        y_template_rule_checked_count += 1;
        let expected_gate = usize::from(!rule_zero);
        if let Some(gate) = gate_map.get(k4_position).and_then(|value| *value) {
            y_template_gate_checked_count += 1;
            if gate == expected_gate {
                y_template_rule_match_count += 1;
                y_template_gate_match_count += 1;
            } else {
                y_template_mismatches.push(ClaimMechanismYTemplateMismatch {
                    y_position_one_based: y_position,
                    k4_position_one_based: k4_position,
                    expected_gate_value: expected_gate,
                    observed_gate_value: gate,
                });
            }
        }
    }

    let z1_z2_delta_checked_count = helper_card_checked_count;
    let z1_z2_delta_match_count = helper_card_match_count;
    let structural_checks_passed = required_files_checked == expected_required_files
        && ciphertext_file_matches_repo
        && f_table_checked_count == KALPHA.len()
        && f_table_match_count == f_table_checked_count
        && helper_card_checked_count == KALPHA.len()
        && helper_card_match_count == helper_card_checked_count
        && control_card_checked_count == 9
        && control_card_match_count == control_card_checked_count
        && z2_effective_key_matches
        && z2_r_grid_checked_count == 31
        && z2_r_grid_match_count == z2_r_grid_checked_count
        && z2_final_grid_checked_count == 31
        && z2_final_grid_match_count == z2_final_grid_checked_count
        && y_template_rule_checked_count == 31
        && y_template_rule_match_count == y_template_rule_checked_count
        && y_template_gate_checked_count == 31
        && y_template_gate_match_count == y_template_gate_checked_count;

    Ok(ClaimMechanismVerification {
        source_id,
        bundle_directory: bundle_directory.display().to_string(),
        required_files_checked,
        expected_required_files,
        f_table_checked_count,
        f_table_match_count,
        helper_card_checked_count,
        helper_card_match_count,
        z1_z2_delta_checked_count,
        z1_z2_delta_match_count,
        control_card_checked_count,
        control_card_match_count,
        z2_effective_key_matches,
        z2_r_grid_checked_count,
        z2_r_grid_match_count,
        z2_final_grid_checked_count,
        z2_final_grid_match_count,
        y_template_rule_checked_count,
        y_template_rule_match_count,
        y_template_gate_checked_count,
        y_template_gate_match_count,
        y_template_mismatches,
        structural_checks_passed,
        promoted_candidate: false,
        note: "Claim-mechanism verification checks published f/helper-card relationships, control-card consistency, Z2 footer handoff, Y-pass gate-template consistency, and the Z2 helper path into the r/R grids without printing, storing, or promoting claimed plaintext.",
    })
}

#[derive(Debug)]
struct ReconciliationRow {
    position_one_based: usize,
    tier_value: Option<usize>,
    lane_value: Option<usize>,
    ciphertext: Option<char>,
    ciphertext_value: Option<usize>,
    plaintext: Option<char>,
    plaintext_value: Option<usize>,
    r_value: Option<usize>,
    base_r_value: Option<usize>,
    gate_value: Option<usize>,
}

#[derive(Debug)]
struct HelperCards {
    g_z1: HashMap<char, usize>,
    delta: HashMap<char, usize>,
    g_z2: HashMap<char, usize>,
}

#[derive(Debug)]
struct ControlCardRow {
    letter: char,
    z1: usize,
    delta: usize,
    z2: usize,
}

const KALPHA: &str = "KRYPTOSABCDEFGHIJLMNQUVWXZ";

fn read_bundle_file(bundle_directory: &Path, file_name: &str) -> Result<String> {
    let path = bundle_directory.join(file_name);
    fs::read_to_string(&path)
        .with_context(|| format!("failed to read bundle file `{}`", path.display()))
}

fn normalize_ascii_letters(input: &str) -> String {
    input
        .chars()
        .filter(|value| value.is_ascii_alphabetic())
        .map(|value| value.to_ascii_uppercase())
        .collect()
}

fn parse_r_grid_section(input: &str, section_marker: &str) -> Result<Vec<Option<usize>>> {
    let mut values = vec![None; K4_CIPHERTEXT.len() + 1];
    let mut in_section = false;
    let mut parsed_tiers = 0usize;
    for line in input.lines() {
        if line.contains(section_marker) {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("===") && parsed_tiers > 0 {
            break;
        }
        if !in_section || !line.trim_start().starts_with("Tier ") {
            continue;
        }
        let Some((tier_label, value_text)) = line.split_once(':') else {
            continue;
        };
        let tier = tier_label
            .trim_start_matches("Tier")
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid tier label `{tier_label}` in {section_marker}"))?;
        let cells = value_text.split_whitespace().collect::<Vec<_>>();
        for (index, cell) in cells.iter().enumerate() {
            let position = (tier - 1) * 14 + index + 1;
            if position > K4_CIPHERTEXT.len() {
                continue;
            }
            values[position] = Some(parse_grid_cell(cell, section_marker)?);
        }
        parsed_tiers += 1;
    }
    if parsed_tiers != 7 {
        bail!("expected 7 tiers in {section_marker}, found {parsed_tiers}");
    }
    Ok(values)
}

fn parse_gate_map(input: &str) -> Result<Vec<Option<usize>>> {
    let mut values = vec![None; K4_CIPHERTEXT.len() + 1];
    let mut parsed_tiers = 0usize;
    for line in input.lines() {
        if !line.trim_start().starts_with("Tier ") {
            continue;
        }
        let Some((tier_label, value_text)) = line.split_once(':') else {
            continue;
        };
        let tier = tier_label
            .trim_start_matches("Tier")
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid gate-map tier label `{tier_label}`"))?;
        let cells = value_text.split_whitespace().collect::<Vec<_>>();
        for (index, cell) in cells.iter().enumerate() {
            let lane = index + 1;
            let position = (tier - 1) * 14 + if lane == 14 { 1 } else { lane + 1 };
            if position > K4_CIPHERTEXT.len() {
                continue;
            }
            values[position] = Some(parse_grid_cell(cell, "gate-map")?);
        }
        parsed_tiers += 1;
    }
    if parsed_tiers != 7 {
        bail!("expected 7 tiers in gate-map, found {parsed_tiers}");
    }
    Ok(values)
}

fn parse_y_master_row(input: &str) -> Result<String> {
    let lines = input.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        if !line.trim().eq_ignore_ascii_case("Y_ROW:") {
            continue;
        }
        let row = lines[index + 1..]
            .iter()
            .map(|line| normalize_ascii_letters(line))
            .find(|line| !line.is_empty())
            .context("missing Y_ROW value after Y_ROW label")?;
        if row.len() < 31 {
            bail!("Y_ROW has {} letters; expected at least 31", row.len());
        }
        return Ok(row);
    }
    bail!("missing Y_ROW label in y_master_template.txt")
}

fn y_template_rule_zero(position: usize, letter: char) -> bool {
    matches!(letter, 'A' | 'F' | 'G' | 'N' | 'Q' | 'T' | 'X')
        || matches!(position, 1 | 2 | 28 | 29 | 30) && matches!(letter, 'Y' | 'X' | 'Z' | 'K')
}

fn parse_grid_cell(cell: &str, section_marker: &str) -> Result<usize> {
    if cell == "." {
        bail!("unexpected blank grid cell in active {section_marker} position");
    }
    Ok(cell.parse::<usize>()?)
}

fn parse_f_table_values(input: &str) -> Result<HashMap<char, usize>> {
    let mut values = HashMap::new();
    for line in input.lines() {
        let cells = line.split_whitespace().collect::<Vec<_>>();
        if cells.len() < 3 {
            continue;
        }
        let mut letter_chars = cells[0].chars();
        let Some(letter) = letter_chars.next() else {
            continue;
        };
        if letter_chars.next().is_some() || !KALPHA.contains(letter) {
            continue;
        }
        let Ok(_kpos) = cells[1].parse::<usize>() else {
            continue;
        };
        let value = cells[2]
            .parse::<usize>()
            .with_context(|| format!("invalid f-table value in line `{line}`"))?;
        values.insert(letter, value);
    }
    if values.len() != KALPHA.len() {
        bail!(
            "expected {} f-table rows, found {}",
            KALPHA.len(),
            values.len()
        );
    }
    Ok(values)
}

fn parse_helper_cards(input: &str) -> Result<HelperCards> {
    Ok(HelperCards {
        g_z1: parse_helper_card_line(input, "g_Z1:")?,
        delta: parse_helper_card_line(input, "delta:")?,
        g_z2: parse_helper_card_line(input, "g_Z2:")?,
    })
}

fn parse_helper_card_line(input: &str, prefix: &str) -> Result<HashMap<char, usize>> {
    let line = input
        .lines()
        .find(|line| line.trim_start().starts_with(prefix))
        .with_context(|| format!("missing helper-card line `{prefix}`"))?;
    let (_, value_text) = line
        .split_once(':')
        .with_context(|| format!("invalid helper-card line `{line}`"))?;
    let values = value_text
        .split_whitespace()
        .map(|value| value.parse::<usize>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("invalid numeric value in helper-card line `{line}`"))?;
    if values.len() != KALPHA.len() {
        bail!(
            "expected {} values in helper-card line `{prefix}`, found {}",
            KALPHA.len(),
            values.len()
        );
    }
    Ok(KALPHA.chars().zip(values).collect())
}

fn parse_control_card(input: &str) -> Result<Vec<ControlCardRow>> {
    let mut rows = Vec::new();
    for line in input.lines() {
        let cells = line.split_whitespace().collect::<Vec<_>>();
        if cells.len() < 6 || !matches!(cells[0], "LOOK" | "PLACE" | "SEND") {
            continue;
        }
        let Some(letter) = cells[1].chars().next() else {
            continue;
        };
        if !KALPHA.contains(letter) {
            continue;
        }
        let z1 = cells[3]
            .parse::<usize>()
            .with_context(|| format!("invalid control-card Z1 value in line `{line}`"))?;
        let delta = parse_signed_mod26(cells[4])
            .with_context(|| format!("invalid control-card delta in line `{line}`"))?;
        let z2 = cells[5]
            .parse::<usize>()
            .with_context(|| format!("invalid control-card Z2 value in line `{line}`"))?;
        rows.push(ControlCardRow {
            letter,
            z1,
            delta,
            z2,
        });
    }
    if rows.len() != 9 {
        bail!("expected 9 control-card rows, found {}", rows.len());
    }
    Ok(rows)
}

fn parse_signed_mod26(value: &str) -> Result<usize> {
    let parsed = value.parse::<i16>()?;
    Ok(parsed.rem_euclid(26) as usize)
}

fn parse_labeled_value(input: &str, label: &str) -> Option<String> {
    let lines = input.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        let Some((line_label, value)) = line.split_once(':') else {
            continue;
        };
        if !line_label.trim().eq_ignore_ascii_case(label) {
            continue;
        }
        let inline_value = value
            .chars()
            .filter(|ch| ch.is_ascii_alphabetic() || *ch == '_')
            .collect::<String>();
        if !inline_value.is_empty() {
            return Some(inline_value);
        }
        return lines[index + 1..].iter().find_map(|next_line| {
            let value = next_line
                .chars()
                .filter(|ch| ch.is_ascii_alphabetic() || *ch == '_')
                .collect::<String>();
            (!value.is_empty()).then_some(value)
        });
    }
    None
}

fn derive_z2_effective_key(visible_footer: &str) -> Result<String> {
    visible_footer
        .chars()
        .map(|letter| {
            if letter == '_' {
                Ok('Z')
            } else if letter.is_ascii_uppercase() {
                let standard = letter as u8 - b'A';
                let index = (standard + 25) % 26;
                KALPHA
                    .chars()
                    .nth(index as usize)
                    .with_context(|| format!("missing KALPHA index {index}"))
            } else {
                bail!("invalid Z2 footer letter `{letter}`")
            }
        })
        .collect()
}

fn expected_f_table_values() -> HashMap<char, usize> {
    [
        ('K', 8),
        ('R', 3),
        ('Y', 16),
        ('P', 11),
        ('T', 13),
        ('O', 0),
        ('S', 12),
        ('A', 4),
        ('B', 15),
        ('C', 17),
        ('D', 3),
        ('E', 23),
        ('F', 3),
        ('G', 19),
        ('H', 15),
        ('I', 16),
        ('J', 23),
        ('L', 22),
        ('M', 19),
        ('N', 25),
        ('Q', 3),
        ('U', 7),
        ('V', 11),
        ('W', 15),
        ('X', 19),
        ('Z', 23),
    ]
    .into_iter()
    .collect()
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
    let mut header_lookup = HashMap::new();
    for (index, header) in headers.iter().enumerate() {
        header_lookup
            .entry(normalize_header(header))
            .or_insert(index);
    }
    let position_index = find_header(
        &header_lookup,
        &["i", "pos", "position", "position_one_based"],
    )
    .ok_or_else(|| anyhow::anyhow!("claim reconciliation table needs an i/position column"))?;
    let tier_value_index = find_header(&header_lookup, &["tier", "t", "row"]);
    let lane_value_index = find_header(&header_lookup, &["lane", "l", "lane_phys", "lanephys"]);
    let ciphertext_index = find_header(&header_lookup, &["c", "ciphertext"]);
    let ciphertext_value_index = find_header(
        &header_lookup,
        &[
            "cnum",
            "c_value",
            "cvalue",
            "c_number",
            "cnumber",
            "ciphertext_value",
            "ciphertextvalue",
        ],
    );
    let plaintext_index = find_header(&header_lookup, &["p", "plaintext"]);
    let plaintext_value_index = find_header(
        &header_lookup,
        &[
            "pnum",
            "p_value",
            "pvalue",
            "p_number",
            "pnumber",
            "plaintext_value",
            "plaintextvalue",
        ],
    );
    let r_value_index = find_reconciliation_r_value_header(&headers, &header_lookup);
    let base_r_value_index = find_reconciliation_base_r_value_header(&headers, &header_lookup);
    let gate_value_index = find_header(&header_lookup, &["gate", "g"]);

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
        let ciphertext_value =
            parse_optional_numeric_cell(&cells, ciphertext_value_index, "C#", line_number + 2)?;
        let plaintext = plaintext_index
            .and_then(|index| cells.get(index))
            .and_then(|cell| single_ascii_uppercase_letter(cell));
        let plaintext_value =
            parse_optional_numeric_cell(&cells, plaintext_value_index, "P#", line_number + 2)?;
        let tier_value =
            parse_optional_numeric_cell(&cells, tier_value_index, "tier", line_number + 2)?;
        let lane_value =
            parse_optional_numeric_cell(&cells, lane_value_index, "lane", line_number + 2)?;
        let r_value = parse_optional_numeric_cell(&cells, r_value_index, "R", line_number + 2)?;
        let base_r_value =
            parse_optional_numeric_cell(&cells, base_r_value_index, "BaseR", line_number + 2)?;
        let gate_value =
            parse_optional_numeric_cell(&cells, gate_value_index, "Gate", line_number + 2)?;
        rows.push(ReconciliationRow {
            position_one_based,
            tier_value,
            lane_value,
            ciphertext,
            ciphertext_value,
            plaintext,
            plaintext_value,
            r_value,
            base_r_value,
            gate_value,
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
    let mut normalized = String::new();
    for value in clean_cell(value).chars() {
        if value.is_ascii_alphanumeric() || value == '_' {
            normalized.push(value.to_ascii_lowercase());
        } else if value == '#' {
            normalized.push_str("num");
        }
    }
    normalized
}

fn f_table_value(ciphertext: char) -> usize {
    match ciphertext {
        'A' => 4,
        'B' => 15,
        'C' => 17,
        'D' => 3,
        'E' => 23,
        'F' => 3,
        'G' => 19,
        'H' => 15,
        'I' => 16,
        'J' => 23,
        'K' => 8,
        'L' => 22,
        'M' => 19,
        'N' => 25,
        'O' => 0,
        'P' => 11,
        'Q' => 3,
        'R' => 3,
        'S' => 12,
        'T' => 13,
        'U' => 7,
        'V' => 11,
        'W' => 15,
        'X' => 19,
        'Y' => 16,
        'Z' => 23,
        _ => 0,
    }
}

fn z2_g_value_for_position(position_one_based: usize) -> Option<usize> {
    const Z2_EFFECTIVE_KEY: &str = "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY";
    const G_Z2_BY_KALPHA: [usize; 26] = [
        19, 17, 16, 13, 1, 18, 10, 6, 18, 25, 20, 21, 13, 24, 23, 8, 24, 6, 24, 12, 25, 19, 7, 7,
        25, 24,
    ];
    let offset = position_one_based.checked_sub(67)?;
    let key_letter = Z2_EFFECTIVE_KEY.as_bytes().get(offset).copied()? as char;
    let key_index = KALPHA.chars().position(|value| value == key_letter)?;
    G_Z2_BY_KALPHA.get(key_index).copied()
}

fn find_header(headers: &HashMap<String, usize>, aliases: &[&str]) -> Option<usize> {
    aliases
        .iter()
        .find_map(|alias| headers.get(*alias).copied())
}

fn find_exact_header(headers: &[String], exact: &str) -> Option<usize> {
    headers
        .iter()
        .position(|header| clean_cell(header) == exact)
}

fn find_reconciliation_r_value_header(
    headers: &[String],
    header_lookup: &HashMap<String, usize>,
) -> Option<usize> {
    match (
        find_exact_header(headers, "R"),
        find_exact_header(headers, "r"),
    ) {
        (Some(final_r_index), Some(_base_r_index)) => Some(final_r_index),
        _ => find_header(header_lookup, &["r", "shift", "r_value", "rvalue"]),
    }
}

fn find_reconciliation_base_r_value_header(
    headers: &[String],
    header_lookup: &HashMap<String, usize>,
) -> Option<usize> {
    if let (Some(base_r_index), Some(_final_r_index)) = (
        find_exact_header(headers, "r"),
        find_exact_header(headers, "R"),
    ) {
        return Some(base_r_index);
    }
    find_header(
        header_lookup,
        &["baser", "base_r", "base_shift", "baseshift", "rbase"],
    )
}

fn expected_tier(position_one_based: usize) -> usize {
    position_one_based.saturating_sub(1) / 14 + 1
}

fn expected_lane(position_one_based: usize) -> usize {
    (position_one_based + 12) % 14 + 1
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

fn parse_optional_numeric_cell(
    cells: &[String],
    index: Option<usize>,
    field_name: &str,
    line_number: usize,
) -> Result<Option<usize>> {
    let Some(index) = index else {
        return Ok(None);
    };
    let Some(cell) = cells.get(index) else {
        return Ok(None);
    };
    parse_optional_usize(cell).with_context(|| {
        format!(
            "invalid numeric {field_name} value `{}` at data line {line_number}",
            clean_cell(cell)
        )
    })
}

fn parse_optional_usize(value: &str) -> Result<Option<usize>> {
    let cleaned = clean_cell(value);
    if cleaned.is_empty() {
        return Ok(None);
    }
    Ok(Some(cleaned.parse::<usize>()?))
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
        assert!(verification.structural_checks_passed, "{verification:#?}");
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
        assert!(verification.structural_checks_passed, "{verification:#?}");
        assert_eq!(verification.public_anchor_match_count, 4);
        assert!(!verification.promoted_candidate);
    }

    #[test]
    fn verifies_optional_r_and_gate_columns_without_promotion() {
        let fixture = public_anchor_compatible_fixture();
        let mut table = String::from("i,T,L,C,C#,P,P#,R,BaseR,Gate\n");
        for (index, (ciphertext, plaintext)) in
            K4_CIPHERTEXT.chars().zip(fixture.chars()).enumerate()
        {
            let position = index + 1;
            let r_value = ((26 + ciphertext as i16 - plaintext as i16) % 26) as usize;
            let gate = synthetic_z2_compatible_gate(position, ciphertext, r_value);
            let base_r_value = (26 + r_value as i16 - gate as i16) as usize % 26;
            table.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                position,
                expected_tier(position),
                expected_lane(position),
                ciphertext,
                ciphertext as u8 - b'A',
                plaintext,
                plaintext as u8 - b'A',
                r_value,
                base_r_value,
                gate
            ));
        }

        let verification =
            verify_claim_reconciliation_table(&table, Some("synthetic-claim".to_string())).unwrap();

        assert_eq!(verification.tier_checked_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.tier_match_count, K4_CIPHERTEXT.len());
        assert!(verification.all_tier_values_match);
        assert_eq!(verification.lane_checked_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.lane_match_count, K4_CIPHERTEXT.len());
        assert!(verification.all_lane_values_match);
        assert_eq!(
            verification.ciphertext_value_checked_count,
            K4_CIPHERTEXT.len()
        );
        assert_eq!(
            verification.ciphertext_value_match_count,
            K4_CIPHERTEXT.len()
        );
        assert!(verification.all_ciphertext_values_match);
        assert_eq!(
            verification.plaintext_value_checked_count,
            K4_CIPHERTEXT.len()
        );
        assert_eq!(
            verification.plaintext_value_match_count,
            K4_CIPHERTEXT.len()
        );
        assert!(verification.all_plaintext_values_match);
        assert_eq!(verification.r_value_checked_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.r_value_match_count, K4_CIPHERTEXT.len());
        assert!(verification.all_r_values_match);
        assert_eq!(verification.gate_checked_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.gate_binary_count, K4_CIPHERTEXT.len());
        assert!(verification.all_gate_values_binary);
        assert_eq!(verification.r_plus_gate_checked_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.r_plus_gate_match_count, K4_CIPHERTEXT.len());
        assert!(verification.all_r_plus_gate_matches);
        assert!(!verification.promoted_candidate);
    }

    #[test]
    fn distinguishes_raw_lowercase_r_from_final_uppercase_r() {
        let fixture = public_anchor_compatible_fixture();
        let mut table = String::from("i,tier,lane,C,P,gate,r,R\n");
        for (index, (ciphertext, plaintext)) in
            K4_CIPHERTEXT.chars().zip(fixture.chars()).enumerate()
        {
            let position = index + 1;
            let r_value = ((26 + ciphertext as i16 - plaintext as i16) % 26) as usize;
            let gate = synthetic_z2_compatible_gate(position, ciphertext, r_value);
            let base_r_value = (26 + r_value as i16 - gate as i16) as usize % 26;
            table.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                position,
                expected_tier(position),
                expected_lane(position),
                ciphertext,
                plaintext,
                gate,
                base_r_value,
                r_value
            ));
        }

        let verification =
            verify_claim_reconciliation_table(&table, Some("synthetic-claim".to_string())).unwrap();

        assert_eq!(verification.r_value_checked_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.r_value_match_count, K4_CIPHERTEXT.len());
        assert!(verification.all_r_values_match);
        assert_eq!(verification.r_plus_gate_checked_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.r_plus_gate_match_count, K4_CIPHERTEXT.len());
        assert!(verification.all_r_plus_gate_matches);
        assert!(!verification.promoted_candidate);
    }

    #[test]
    fn rejects_malformed_optional_numeric_reconciliation_fields() {
        let ciphertext = K4_CIPHERTEXT.chars().next().unwrap();
        let table = format!("i,C,C#,P\n1,{ciphertext},not-a-number,A\n");

        let error = verify_claim_reconciliation_table(&table, Some("synthetic-claim".to_string()))
            .expect_err("malformed optional numeric fields should fail loudly");

        assert!(error.to_string().contains("invalid numeric C# value"));
    }

    #[test]
    fn verifies_bundle_grids_without_promoting_claim() {
        let temp = tempfile::tempdir().unwrap();
        let claim = public_anchor_compatible_fixture();
        let mut table = String::from("i,tier,lane,C,P,gate,r,R\n");
        let mut final_shifts = Vec::new();
        let mut base_shifts = Vec::new();
        let mut gates = Vec::new();
        let anchor_positions = known_anchors()
            .into_iter()
            .flat_map(|anchor| anchor.start_one_based()..=anchor.end_one_based_inclusive())
            .collect::<BTreeSet<_>>();
        for (index, (ciphertext, plaintext)) in K4_CIPHERTEXT.chars().zip(claim.chars()).enumerate()
        {
            let position = index + 1;
            let plaintext_cell = if anchor_positions.contains(&position) {
                plaintext.to_string()
            } else {
                String::new()
            };
            let shift = if anchor_positions.contains(&position) {
                ((26 + ciphertext as i16 - plaintext as i16) % 26) as usize
            } else {
                0
            };
            let gate = if anchor_positions.contains(&position) {
                synthetic_z2_compatible_gate(position, ciphertext, shift)
            } else {
                0
            };
            let base_shift = (26 + shift as i16 - gate as i16) as usize % 26;
            final_shifts.push(shift);
            base_shifts.push(base_shift);
            gates.push(gate);
            table.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                position,
                expected_tier(position),
                expected_lane(position),
                ciphertext,
                plaintext_cell,
                gate,
                base_shift,
                shift
            ));
        }

        fs::write(temp.path().join("k4_ciphertext.txt"), K4_CIPHERTEXT).unwrap();
        fs::write(temp.path().join("k4_proposed_plaintext.txt"), &claim).unwrap();
        fs::write(temp.path().join("k4_reconciliation.csv"), table).unwrap();
        fs::write(
            temp.path().join("r_grid_7x14.txt"),
            format_test_r_grid_file(&final_shifts, &base_shifts),
        )
        .unwrap();
        fs::write(
            temp.path().join("gate_map.txt"),
            format_test_gate_map(&gates),
        )
        .unwrap();

        let verification =
            verify_claim_bundle(temp.path(), Some("synthetic-claim".to_string())).unwrap();

        assert_eq!(verification.required_files_checked, 5);
        assert!(verification.ciphertext_file_matches_repo);
        assert!(verification.plaintext_file_length_matches);
        assert_eq!(verification.r_grid_match_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.base_r_grid_match_count, K4_CIPHERTEXT.len());
        assert_eq!(verification.gate_map_match_count, K4_CIPHERTEXT.len());
        assert!(verification.structural_checks_passed, "{verification:#?}");
        assert!(!verification.promoted_candidate);
    }

    #[test]
    fn verifies_mechanism_files_without_promoting_claim() {
        let temp = tempfile::tempdir().unwrap();
        let mut base_shifts = vec![0usize; K4_CIPHERTEXT.len()];
        let mut final_shifts = vec![0usize; K4_CIPHERTEXT.len()];
        let mut gates = vec![0usize; K4_CIPHERTEXT.len()];
        let y_row = "YXZKRYPTOSABCDEFGHIJKLMNOPQRSTUVWXYZKR";
        for (index, letter) in y_row.chars().take(31).enumerate() {
            let y_position = index + 1;
            let k4_index = y_position + 3;
            gates[k4_index] = usize::from(!y_template_rule_zero(y_position, letter));
        }
        let f_values = expected_f_table_values();
        let g_z2 = test_g_z2_values();
        let effective_key = derive_z2_effective_key("_ABCDEFGHIJKLMNOPQRSTUVWXYZABCD").unwrap();
        for (offset, helper_letter) in effective_key.chars().enumerate() {
            let position = 67 + offset;
            let ciphertext = K4_CIPHERTEXT.chars().nth(position - 1).unwrap();
            let base_r = (f_values[&ciphertext] + g_z2[&helper_letter]) % 26;
            base_shifts[position - 1] = base_r;
            final_shifts[position - 1] = base_r;
        }

        fs::write(temp.path().join("k4_ciphertext.txt"), K4_CIPHERTEXT).unwrap();
        fs::write(temp.path().join("f_table.txt"), format_test_f_table()).unwrap();
        fs::write(
            temp.path().join("helper_cards.txt"),
            format_test_helper_cards(),
        )
        .unwrap();
        fs::write(
            temp.path().join("control_card.txt"),
            format_test_control_card(),
        )
        .unwrap();
        fs::write(
            temp.path().join("z2_footer_basis_handoff.txt"),
            "Visible footer:\n  _ABCDEFGHIJKLMNOPQRSTUVWXYZABCD\nEffective Z2 key:\n  ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("r_grid_7x14.txt"),
            format_test_r_grid_file(&final_shifts, &base_shifts),
        )
        .unwrap();
        fs::write(
            temp.path().join("gate_map.txt"),
            format_test_gate_map(&gates),
        )
        .unwrap();
        fs::write(
            temp.path().join("y_master_template.txt"),
            format_test_y_master_template(),
        )
        .unwrap();

        let verification =
            verify_claim_mechanism(temp.path(), Some("synthetic-claim".to_string())).unwrap();

        assert_eq!(verification.required_files_checked, 8);
        assert_eq!(verification.f_table_match_count, 26);
        assert_eq!(verification.z1_z2_delta_match_count, 26);
        assert_eq!(verification.control_card_match_count, 9);
        assert!(verification.z2_effective_key_matches);
        assert_eq!(verification.z2_r_grid_match_count, 31);
        assert_eq!(verification.z2_final_grid_match_count, 31);
        assert_eq!(verification.y_template_rule_match_count, 31);
        assert_eq!(verification.y_template_gate_match_count, 31);
        assert!(verification.structural_checks_passed);
        assert!(!verification.promoted_candidate);
    }

    #[test]
    fn mechanism_verification_reports_y_template_mismatches_without_plaintext() {
        let temp = tempfile::tempdir().unwrap();
        let mut base_shifts = vec![0usize; K4_CIPHERTEXT.len()];
        let mut final_shifts = vec![0usize; K4_CIPHERTEXT.len()];
        let mut gates = vec![0usize; K4_CIPHERTEXT.len()];
        let y_row = "YXZKRYPTOSABCDEFGHIJKLMNOPQRSTUVWXYZKR";
        for (index, letter) in y_row.chars().take(31).enumerate() {
            let y_position = index + 1;
            let k4_index = y_position + 3;
            gates[k4_index] = usize::from(!y_template_rule_zero(y_position, letter));
        }
        gates[4] = 1 - gates[4];
        gates[9] = 1 - gates[9];

        let f_values = expected_f_table_values();
        let g_z2 = test_g_z2_values();
        let effective_key = derive_z2_effective_key("_ABCDEFGHIJKLMNOPQRSTUVWXYZABCD").unwrap();
        for (offset, helper_letter) in effective_key.chars().enumerate() {
            let position = 67 + offset;
            let ciphertext = K4_CIPHERTEXT.chars().nth(position - 1).unwrap();
            let base_r = (f_values[&ciphertext] + g_z2[&helper_letter]) % 26;
            base_shifts[position - 1] = base_r;
            final_shifts[position - 1] = base_r;
        }

        fs::write(temp.path().join("k4_ciphertext.txt"), K4_CIPHERTEXT).unwrap();
        fs::write(temp.path().join("f_table.txt"), format_test_f_table()).unwrap();
        fs::write(
            temp.path().join("helper_cards.txt"),
            format_test_helper_cards(),
        )
        .unwrap();
        fs::write(
            temp.path().join("control_card.txt"),
            format_test_control_card(),
        )
        .unwrap();
        fs::write(
            temp.path().join("z2_footer_basis_handoff.txt"),
            "Visible footer:\n  _ABCDEFGHIJKLMNOPQRSTUVWXYZABCD\nEffective Z2 key:\n  ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("r_grid_7x14.txt"),
            format_test_r_grid_file(&final_shifts, &base_shifts),
        )
        .unwrap();
        fs::write(
            temp.path().join("gate_map.txt"),
            format_test_gate_map(&gates),
        )
        .unwrap();
        fs::write(
            temp.path().join("y_master_template.txt"),
            format_test_y_master_template(),
        )
        .unwrap();

        let verification =
            verify_claim_mechanism(temp.path(), Some("synthetic-claim".to_string())).unwrap();

        assert_eq!(verification.y_template_rule_match_count, 29);
        assert_eq!(verification.y_template_gate_match_count, 29);
        assert_eq!(
            verification.y_template_mismatches,
            vec![
                ClaimMechanismYTemplateMismatch {
                    y_position_one_based: 1,
                    k4_position_one_based: 5,
                    expected_gate_value: 0,
                    observed_gate_value: 1,
                },
                ClaimMechanismYTemplateMismatch {
                    y_position_one_based: 6,
                    k4_position_one_based: 10,
                    expected_gate_value: 1,
                    observed_gate_value: 0,
                },
            ]
        );
        assert!(!verification.structural_checks_passed);
        assert!(!verification.promoted_candidate);
    }

    fn format_test_f_table() -> String {
        let values = expected_f_table_values();
        let mut output = String::from("Letter kpos f\n");
        for (kpos, letter) in KALPHA.chars().enumerate() {
            output.push_str(&format!("{letter} {kpos} {}\n", values[&letter]));
        }
        output
    }

    fn format_test_helper_cards() -> String {
        let z1 = [
            13, 4, 13, 13, 24, 11, 14, 17, 13, 9, 19, 13, 13, 17, 24, 4, 13, 24, 13, 5, 13, 14, 25,
            6, 13, 24,
        ];
        let delta = [
            6, 13, 3, 0, 3, 7, 22, 15, 5, 16, 1, 8, 0, 7, 25, 4, 11, 8, 11, 7, 12, 5, 8, 1, 12, 0,
        ];
        let z2 = [
            19, 17, 16, 13, 1, 18, 10, 6, 18, 25, 20, 21, 13, 24, 23, 8, 24, 6, 24, 12, 25, 19, 7,
            7, 25, 24,
        ];
        format!(
            "KALPHA: {}\ng_Z1: {}\ndelta: {}\ng_Z2: {}\n",
            KALPHA
                .chars()
                .map(|ch| ch.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            z1.iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            delta
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            z2.iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    fn format_test_control_card() -> String {
        [
            "LOOK Z EDGE 24 0 24",
            "LOOK D MIDDLE 19 +1 20",
            "LOOK H OUT 24 -1 23",
            "PLACE T EDGE 24 +3 1",
            "PLACE O MIDDLE 11 +7 18",
            "PLACE N OUT 5 +7 12",
            "SEND J EDGE 13 +11 24",
            "SEND M MIDDLE 13 +11 24",
            "SEND Q OUT 13 +12 25",
        ]
        .join("\n")
    }

    fn format_test_y_master_template() -> String {
        [
            "Kryptos K4 rev16 Y master template",
            "",
            "Rule:",
            "Let L = Y_ROW[p-1] for p in {1..31}",
            "",
            "gate(p) = 0 iff",
            "  L in {A, F, G, N, Q, T, X}",
            "  OR",
            "  (p in {1, 2, 28, 29, 30} AND L in {Y, X, Z, K})",
            "",
            "Y_ROW:",
            "YXZKRYPTOSABCDEFGHIJKLMNOPQRSTUVWXYZKR",
            "",
            "Zero positions (Y pass):",
            "1,2 | 8 | 11 | 16,17 | 23,24 | 28,29,30",
        ]
        .join("\n")
    }

    fn test_g_z2_values() -> HashMap<char, usize> {
        parse_helper_card_line(&format_test_helper_cards(), "g_Z2:").unwrap()
    }

    fn format_test_r_grid_file(final_values: &[usize], base_values: &[usize]) -> String {
        let mut output = String::from("R-grid\n");
        for tier in 1..=7 {
            output.push_str(&format!("Tier {tier}:"));
            for offset in 0..14 {
                let position = (tier - 1) * 14 + offset + 1;
                if position > K4_CIPHERTEXT.len() {
                    output.push_str(" .");
                } else {
                    output.push_str(&format!(" {}", final_values[position - 1]));
                }
            }
            output.push('\n');
        }
        output.push_str("===\nr-grid\n");
        for tier in 1..=7 {
            output.push_str(&format!("Tier {tier}:"));
            for offset in 0..14 {
                let position = (tier - 1) * 14 + offset + 1;
                if position > K4_CIPHERTEXT.len() {
                    output.push_str(" .");
                } else {
                    output.push_str(&format!(" {}", base_values[position - 1]));
                }
            }
            output.push('\n');
        }
        output
    }

    fn synthetic_z2_compatible_gate(
        position_one_based: usize,
        ciphertext: char,
        shift: usize,
    ) -> usize {
        let gate = z2_g_value_for_position(position_one_based)
            .map(|z2_g| {
                let raw_r = (z2_g + f_table_value(ciphertext)) % 26;
                (26 + shift as i16 - raw_r as i16) as usize % 26
            })
            .unwrap_or(0);
        if gate <= 1 { gate } else { 0 }
    }

    fn format_test_gate_map(gates: &[usize]) -> String {
        let mut output = String::new();
        for tier in 1..=7 {
            output.push_str(&format!("Tier {tier}:"));
            for lane in 1..=14 {
                let position = (tier - 1) * 14 + if lane == 14 { 1 } else { lane + 1 };
                if position > K4_CIPHERTEXT.len() {
                    output.push_str(" .");
                } else {
                    output.push_str(&format!(" {}", gates[position - 1]));
                }
            }
            output.push('\n');
        }
        output
    }
}
