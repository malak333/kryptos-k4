use crate::{AlphabetKind, FragmentMode, analyze_known_plaintext_spans};
use anyhow::{Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteFamily {
    Identity,
    Reverse,
    RowToColumnWidth7,
    RowToColumnWidth13,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouteExperiment {
    pub route: RouteFamily,
    pub permutation: Vec<usize>,
    pub target_label: String,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub score: usize,
    pub identity_baseline: usize,
    pub reverse_baseline: usize,
    pub seeded_random_baseline: usize,
    pub promoted_candidate: bool,
    pub notes: &'static str,
}

pub fn registered_route_families() -> Vec<RouteFamily> {
    vec![
        RouteFamily::Identity,
        RouteFamily::Reverse,
        RouteFamily::RowToColumnWidth7,
        RouteFamily::RowToColumnWidth13,
    ]
}

pub fn run_route_experiments() -> Result<Vec<RouteExperiment>> {
    let mut experiments = Vec::new();

    for analysis in analyze_known_plaintext_spans()? {
        if analysis.alphabet.kind != AlphabetKind::Standard {
            continue;
        }
        let values: Vec<u8> = analysis
            .fragments
            .iter()
            .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
            .map(|fragment| fragment.value)
            .collect();
        let identity = permutation(RouteFamily::Identity, values.len())?;
        let reverse = permutation(RouteFamily::Reverse, values.len())?;
        let random = seeded_random_permutation(values.len(), 0xC1A0_2026);
        let identity_baseline = score_permutation(&values, &identity);
        let reverse_baseline = score_permutation(&values, &reverse);
        let seeded_random_baseline = score_permutation(&values, &random);

        for route in registered_route_families() {
            let permutation = match permutation(route, values.len()) {
                Ok(permutation) => permutation,
                Err(_) => continue,
            };
            let score = score_permutation(&values, &permutation);
            experiments.push(RouteExperiment {
                route,
                permutation,
                target_label: analysis.target.label.clone(),
                alphabet: analysis.alphabet.kind,
                fragment_mode: FragmentMode::AdditiveKey,
                score,
                identity_baseline,
                reverse_baseline,
                seeded_random_baseline,
                promoted_candidate: false,
                notes: "Exploratory route screen over public known-plaintext fragments only; no decryption text is emitted.",
            });
        }
    }

    Ok(experiments)
}

pub fn permutation(route: RouteFamily, len: usize) -> Result<Vec<usize>> {
    match route {
        RouteFamily::Identity => Ok((0..len).collect()),
        RouteFamily::Reverse => Ok((0..len).rev().collect()),
        RouteFamily::RowToColumnWidth7 => row_to_column(len, 7),
        RouteFamily::RowToColumnWidth13 => row_to_column(len, 13),
    }
}

fn row_to_column(len: usize, width: usize) -> Result<Vec<usize>> {
    if !len.is_multiple_of(width) {
        bail!("route width {width} does not divide length {len} without padding");
    }

    let height = len / width;
    let mut indices = Vec::with_capacity(len);
    for column in 0..width {
        for row in 0..height {
            indices.push(row * width + column);
        }
    }
    Ok(indices)
}

fn seeded_random_permutation(len: usize, mut state: u64) -> Vec<usize> {
    let mut values: Vec<usize> = (0..len).collect();
    for index in (1..values.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let swap_with = (state as usize) % (index + 1);
        values.swap(index, swap_with);
    }
    values
}

fn score_permutation(values: &[u8], permutation: &[usize]) -> usize {
    let routed: Vec<u8> = permutation.iter().map(|index| values[*index]).collect();
    routed
        .windows(3)
        .filter(|window| (window[0] + window[1]) % 10 == window[2] % 10)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn identity_permutation_preserves_positions() {
        assert_eq!(
            permutation(RouteFamily::Identity, 5).unwrap(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn reverse_permutation_is_bijection() {
        let permutation = permutation(RouteFamily::Reverse, 5).unwrap();
        let unique: HashSet<_> = permutation.iter().copied().collect();

        assert_eq!(permutation, vec![4, 3, 2, 1, 0]);
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn grid_route_rejects_incompatible_width_without_padding() {
        assert!(permutation(RouteFamily::RowToColumnWidth7, 97).is_err());
    }

    #[test]
    fn all_registered_routes_are_bijections_when_compatible() {
        for route in registered_route_families() {
            let Ok(permutation) = permutation(route, 14) else {
                continue;
            };
            let unique: HashSet<_> = permutation.iter().copied().collect();
            assert_eq!(unique.len(), permutation.len());
        }
    }

    #[test]
    fn route_experiments_keep_promoted_candidate_false() {
        let experiments = run_route_experiments().unwrap();

        assert!(
            experiments
                .iter()
                .all(|experiment| !experiment.promoted_candidate)
        );
    }

    #[test]
    fn seeded_random_baseline_is_deterministic() {
        assert_eq!(
            seeded_random_permutation(10, 42),
            seeded_random_permutation(10, 42)
        );
    }
}
