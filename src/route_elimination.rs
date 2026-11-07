//! Route transpositions combined with a periodic substitution.
//!
//! Plaintext is written row by row into a grid of a given width (97 is prime,
//! so the last row is partial) and read off by a classical route: columns,
//! serpentines, spirals, diagonals, and K3-style double rotations. Each route
//! is also taken inverted and reversed. Every resulting permutation is tested
//! before and after a periodic key, two ways:
//!
//! - `route-plus-tableau`: Vigenère, Beaufort, and variant Beaufort on standard
//!   and Kryptos tableaux, with a chance probability per check.
//! - `route-plus-any-substitution`: any alphabet per key column (a general
//!   periodic substitution), compared with the rate for random permutations.

use crate::eliminate::{
    FamilyElimination, KeyedAlphabet, N, Problem, Tally, all_tableaux, periodic_outcome,
    tableau_offsets,
};
use rand::seq::SliceRandom;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use serde::Serialize;
use std::collections::HashSet;

/// A transposition: output position j takes input position `order[j]`.
#[derive(Debug, Clone)]
pub struct Route {
    pub label: String,
    pub order: Vec<usize>,
}

fn cell(row: usize, col: usize, width: usize) -> Option<usize> {
    let index = row * width + col;
    (index < N).then_some(index)
}

/// Read a row-filled grid of `width` by a named route.
pub fn grid_route(name: &str, width: usize) -> Vec<usize> {
    let rows = N.div_ceil(width);
    let mut order = Vec::with_capacity(N);
    let mut push = |row: usize, col: usize| {
        if let Some(index) = cell(row, col, width) {
            order.push(index);
        }
    };
    match name {
        "columns-down" => (0..width).for_each(|c| (0..rows).for_each(|r| push(r, c))),
        "columns-up" => (0..width).for_each(|c| (0..rows).rev().for_each(|r| push(r, c))),
        "columns-down-rtl" => (0..width)
            .rev()
            .for_each(|c| (0..rows).for_each(|r| push(r, c))),
        "columns-up-rtl" => (0..width)
            .rev()
            .for_each(|c| (0..rows).rev().for_each(|r| push(r, c))),
        "columns-snake" => {
            for c in 0..width {
                if c % 2 == 0 {
                    (0..rows).for_each(|r| push(r, c));
                } else {
                    (0..rows).rev().for_each(|r| push(r, c));
                }
            }
        }
        "rows-snake" => {
            for r in 0..rows {
                if r % 2 == 0 {
                    (0..width).for_each(|c| push(r, c));
                } else {
                    (0..width).rev().for_each(|c| push(r, c));
                }
            }
        }
        "spiral-cw" | "spiral-ccw" => {
            let (mut top, mut bottom, mut left, mut right) =
                (0isize, rows as isize - 1, 0isize, width as isize - 1);
            let clockwise = name == "spiral-cw";
            while top <= bottom && left <= right {
                if clockwise {
                    (left..=right).for_each(|c| push(top as usize, c as usize));
                    (top + 1..=bottom).for_each(|r| push(r as usize, right as usize));
                    if top < bottom {
                        (left..right)
                            .rev()
                            .for_each(|c| push(bottom as usize, c as usize));
                    }
                    if left < right {
                        (top + 1..bottom)
                            .rev()
                            .for_each(|r| push(r as usize, left as usize));
                    }
                } else {
                    (top..=bottom).for_each(|r| push(r as usize, left as usize));
                    (left + 1..=right).for_each(|c| push(bottom as usize, c as usize));
                    if left < right {
                        (top..bottom)
                            .rev()
                            .for_each(|r| push(r as usize, right as usize));
                    }
                    if top < bottom {
                        (left + 1..right)
                            .rev()
                            .for_each(|c| push(top as usize, c as usize));
                    }
                }
                top += 1;
                bottom -= 1;
                left += 1;
                right -= 1;
            }
        }
        "diagonals" | "diagonals-snake" => {
            for d in 0..rows + width - 1 {
                let cells: Vec<(usize, usize)> = (0..rows)
                    .filter(|&r| d >= r && d - r < width)
                    .map(|r| (r, d - r))
                    .collect();
                if name == "diagonals-snake" && d % 2 == 1 {
                    cells.iter().rev().for_each(|&(r, c)| push(r, c));
                } else {
                    cells.iter().for_each(|&(r, c)| push(r, c));
                }
            }
        }
        _ => panic!("unknown route {name}"),
    }
    debug_assert_eq!(order.len(), N);
    order
}

pub const GRID_ROUTES: &[&str] = &[
    "columns-down",
    "columns-up",
    "columns-down-rtl",
    "columns-up-rtl",
    "columns-snake",
    "rows-snake",
    "spiral-cw",
    "spiral-ccw",
    "diagonals",
    "diagonals-snake",
];

fn inverse(order: &[usize]) -> Vec<usize> {
    let mut inv = vec![0usize; order.len()];
    for (output, &input) in order.iter().enumerate() {
        inv[input] = output;
    }
    inv
}

/// Apply `first`, then `second`: output k takes input `first[second[k]]`.
fn compose(first: &[usize], second: &[usize]) -> Vec<usize> {
    second.iter().map(|&k| first[k]).collect()
}

/// Every registered route permutation up to `max_width`, deduplicated, with
/// the identity removed (no transposition is covered by `periodic-tableau`).
pub fn registered_routes(max_width: usize) -> Vec<Route> {
    let mut seen: HashSet<Vec<usize>> = HashSet::new();
    seen.insert((0..N).collect());
    let mut routes = Vec::new();
    let mut add = |label: String, order: Vec<usize>| {
        let variants = [
            (String::new(), order.clone()),
            (" inverse".to_string(), inverse(&order)),
            (
                " reversed".to_string(),
                order.iter().rev().copied().collect(),
            ),
            (
                " inverse reversed".to_string(),
                inverse(&order).into_iter().rev().collect(),
            ),
        ];
        for (suffix, variant) in variants {
            if seen.insert(variant.clone()) {
                routes.push(Route {
                    label: format!("{label}{suffix}"),
                    order: variant,
                });
            }
        }
    };
    for width in 2..=max_width {
        for name in GRID_ROUTES {
            add(format!("{name} width={width}"), grid_route(name, width));
        }
    }
    // K3-style double rotation: rotate a width-w1 grid, rewrite at width w2, rotate again.
    for (rotation, name) in [
        ("rotate-cw", "columns-up"),
        ("rotate-ccw", "columns-down-rtl"),
    ] {
        for w1 in 2..=max_width {
            for w2 in 2..=max_width {
                let order = compose(&grid_route(name, w1), &grid_route(name, w2));
                add(format!("double-{rotation} widths={w1},{w2}"), order);
            }
        }
    }
    routes
}

/// Anchor pairs (key position, plaintext, ciphertext) under a route, for
/// substitution before or after the transposition.
fn routed_pairs(
    problem: &Problem,
    order: &[usize],
    period_on_output: bool,
) -> Vec<(usize, u8, u8)> {
    let inv = inverse(order);
    problem
        .anchors
        .iter()
        .map(|a| {
            let output = inv[a.position];
            let key_position = if period_on_output { output } else { a.position };
            (key_position, a.plain, problem.ciphertext[output])
        })
        .collect()
}

/// Array version of `periodic_substitution_consistent` for the hot loops.
fn consistent(pairs: &[(usize, u8, u8)], period: usize) -> bool {
    const EMPTY: u8 = u8::MAX;
    let mut forward = [EMPTY; 26 * 48];
    let mut backward = [EMPTY; 26 * 48];
    debug_assert!(period <= 48);
    pairs.iter().all(|&(position, plain, cipher)| {
        let column = (position % period) * 26;
        let f = &mut forward[column + plain as usize];
        if *f == EMPTY {
            *f = cipher;
        }
        let b = &mut backward[column + cipher as usize];
        if *b == EMPTY {
            *b = plain;
        }
        *f == cipher && *b == plain
    })
}

const ORDERS: [(&str, bool); 2] = [
    ("substitute-then-transpose", false),
    ("transpose-then-substitute", true),
];

pub fn eliminate_routes_tableau(
    problem: &Problem,
    routes: &[Route],
    max_period: usize,
    top: usize,
) -> FamilyElimination {
    let mut tally = Tally::new(
        "route-plus-tableau",
        "Route transposition (columns, serpentines, spirals, diagonals, K3-style double rotations; each also inverted and reversed; grid width 2..=max) before or after a periodic Vigenère/Beaufort/variant key on standard and Kryptos tableaux, period 1..=max",
        top,
    );
    let alphabets = [
        KeyedAlphabet::standard(),
        KeyedAlphabet::from_keyword("kryptos", "KRYPTOS"),
    ];
    let tableaux = all_tableaux(&alphabets);
    for route in routes {
        for (label, period_on_output) in ORDERS {
            let pairs = routed_pairs(problem, &route.order, period_on_output);
            for tableau in &tableaux {
                let offsets = tableau_offsets(tableau, &pairs);
                for period in 1..=max_period {
                    tally.record(periodic_outcome(&offsets, period, false), || {
                        format!(
                            "{label} {} {} period={period}",
                            route.label,
                            tableau.label()
                        )
                    });
                }
            }
        }
    }
    tally.finish()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AnySubstitutionRow {
    pub period: usize,
    pub configurations: usize,
    pub consistent: usize,
    /// Fraction of random permutations (both orders) that are consistent.
    pub random_rate: f64,
    pub expected_by_random_permutation: f64,
    /// Mean consistent count when the same routes see shuffled K4 ciphertext
    /// letters (matched to each route's structure); None above the shuffle period cap.
    pub expected_by_ciphertext_shuffle: Option<f64>,
    /// Fraction of ciphertext shuffles whose consistent count is at least
    /// the observed count (an empirical p-value that keeps route correlations).
    pub shuffle_p_value: Option<f64>,
    /// Lowest-period consistent configurations, for review.
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AnySubstitutionSummary {
    pub family: &'static str,
    pub description: &'static str,
    pub routes: usize,
    pub random_permutations: usize,
    pub ciphertext_shuffles: usize,
    pub shuffle_max_period: usize,
    pub seed: u64,
    pub rows: Vec<AnySubstitutionRow>,
}

/// Null-model sizes and output limits for the general-substitution check.
#[derive(Debug, Clone, Copy)]
pub struct AnySubstitutionOptions {
    pub max_period: usize,
    pub random_permutations: usize,
    pub ciphertext_shuffles: usize,
    pub shuffle_max_period: usize,
    pub seed: u64,
    pub examples: usize,
}

pub fn eliminate_routes_any_substitution(
    problem: &Problem,
    routes: &[Route],
    options: AnySubstitutionOptions,
) -> AnySubstitutionSummary {
    let AnySubstitutionOptions {
        max_period,
        random_permutations,
        ciphertext_shuffles,
        shuffle_max_period,
        seed,
        examples,
    } = options;
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut random_consistent = vec![0usize; max_period + 1];
    for _ in 0..random_permutations {
        let mut order: Vec<usize> = (0..N).collect();
        order.shuffle(&mut rng);
        for (_, period_on_output) in ORDERS {
            let pairs = routed_pairs(problem, &order, period_on_output);
            for (period, count) in random_consistent.iter_mut().enumerate().skip(1) {
                if consistent(&pairs, period) {
                    *count += 1;
                }
            }
        }
    }
    let mut rows: Vec<AnySubstitutionRow> = (1..=max_period)
        .map(|period| {
            let random_rate = if random_permutations == 0 {
                0.0
            } else {
                random_consistent[period] as f64 / (2 * random_permutations) as f64
            };
            AnySubstitutionRow {
                period,
                configurations: 0,
                consistent: 0,
                random_rate,
                expected_by_random_permutation: 0.0,
                expected_by_ciphertext_shuffle: None,
                shuffle_p_value: None,
                examples: Vec::new(),
            }
        })
        .collect();
    for route in routes {
        for (label, period_on_output) in ORDERS {
            let pairs = routed_pairs(problem, &route.order, period_on_output);
            for row in rows.iter_mut() {
                row.configurations += 1;
                if consistent(&pairs, row.period) {
                    row.consistent += 1;
                    if row.examples.len() < examples {
                        row.examples.push(format!("{label} {}", route.label));
                    }
                }
            }
        }
    }
    for row in rows.iter_mut() {
        row.expected_by_random_permutation = row.configurations as f64 * row.random_rate;
    }
    // Structure-matched null: keep every route, shuffle the ciphertext letters.
    let shuffle_max_period = shuffle_max_period.min(max_period);
    if ciphertext_shuffles > 0 && shuffle_max_period > 0 {
        let skeletons: Vec<Vec<(usize, u8, usize)>> = routes
            .iter()
            .flat_map(|route| {
                let inv = inverse(&route.order);
                ORDERS
                    .iter()
                    .map(move |&(_, period_on_output)| {
                        problem
                            .anchors
                            .iter()
                            .map(|a| {
                                let output = inv[a.position];
                                let key_position =
                                    if period_on_output { output } else { a.position };
                                (key_position, a.plain, output)
                            })
                            .collect()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut counts = vec![0usize; shuffle_max_period + 1];
        let mut at_or_above = vec![0usize; shuffle_max_period + 1];
        let mut shuffled = problem.ciphertext.clone();
        let mut pairs = Vec::with_capacity(problem.anchors.len());
        for _ in 0..ciphertext_shuffles {
            shuffled.shuffle(&mut rng);
            let mut this = vec![0usize; shuffle_max_period + 1];
            for skeleton in &skeletons {
                pairs.clear();
                pairs.extend(skeleton.iter().map(|&(k, p, o)| (k, p, shuffled[o])));
                for (period, count) in this.iter_mut().enumerate().skip(1) {
                    if consistent(&pairs, period) {
                        *count += 1;
                    }
                }
            }
            for period in 1..=shuffle_max_period {
                counts[period] += this[period];
                if this[period] >= rows[period - 1].consistent {
                    at_or_above[period] += 1;
                }
            }
        }
        for row in rows.iter_mut().filter(|r| r.period <= shuffle_max_period) {
            row.expected_by_ciphertext_shuffle =
                Some(counts[row.period] as f64 / ciphertext_shuffles as f64);
            row.shuffle_p_value = Some(at_or_above[row.period] as f64 / ciphertext_shuffles as f64);
        }
    }
    AnySubstitutionSummary {
        family: "route-plus-any-substitution",
        description: "Same routes and orders as route-plus-tableau, but any alphabet per key column (general periodic substitution); consistent means each key column maps plaintext to ciphertext one-to-one",
        routes: routes.len(),
        random_permutations,
        ciphertext_shuffles,
        shuffle_max_period,
        seed,
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eliminate::{AnchorLetter, anchor_letters, periodic_substitution_consistent};

    #[test]
    fn fast_consistency_matches_reference() {
        let problem = Problem::k4();
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        for _ in 0..200 {
            let mut order: Vec<usize> = (0..N).collect();
            order.shuffle(&mut rng);
            for (_, on_output) in ORDERS {
                let pairs = routed_pairs(&problem, &order, on_output);
                for period in 1..=26 {
                    assert_eq!(
                        consistent(&pairs, period),
                        periodic_substitution_consistent(&pairs, period)
                    );
                }
            }
        }
    }

    #[test]
    fn every_route_is_a_permutation() {
        for width in 2..=48 {
            for name in GRID_ROUTES {
                let mut order = grid_route(name, width);
                order.sort_unstable();
                assert_eq!(order, (0..N).collect::<Vec<_>>(), "{name} width={width}");
            }
        }
    }

    #[test]
    fn spiral_on_a_full_grid_matches_hand_order() {
        // Width 97 is a single row: every route that reads rows left to right
        // is the identity.
        assert_eq!(grid_route("spiral-cw", 97), (0..N).collect::<Vec<_>>());
        // Width 50: two rows, second row partial (47 letters). Clockwise spiral
        // reads row 0 left to right, then row 1 right to left.
        let order = grid_route("spiral-cw", 50);
        assert_eq!(&order[..50], &(0..50).collect::<Vec<_>>()[..]);
        assert_eq!(order[50], 96);
        assert_eq!(order[96], 50);
    }

    /// Encrypt synthetic plaintext with a route and a periodic Vigenère key
    /// on the standard tableau, then confirm the checker keeps that route.
    #[test]
    fn planted_route_and_key_survive() {
        let plain: Vec<u8> = (0..N).map(|i| ((i * 11 + 5) % 26) as u8).collect();
        let key = [3u8, 14, 7, 21, 9];
        let routes = registered_routes(12);
        let target = routes
            .iter()
            .find(|r| r.label == "spiral-ccw width=9")
            .expect("route")
            .clone();
        // transpose-then-substitute: X[j] = P[order[j]], C[j] = X[j] + key[j % 5].
        let cipher: Vec<u8> = (0..N)
            .map(|j| (plain[target.order[j]] + key[j % key.len()]) % 26)
            .collect();
        let anchors: Vec<AnchorLetter> = anchor_letters()
            .iter()
            .map(|a| AnchorLetter {
                position: a.position,
                plain: plain[a.position],
                cipher: cipher[a.position],
            })
            .collect();
        let problem = Problem {
            ciphertext: cipher,
            anchors,
        };
        let result = eliminate_routes_tableau(&problem, std::slice::from_ref(&target), 5, 50);
        assert!(result.top_survivors.iter().any(|s| s.parameters
            == "transpose-then-substitute spiral-ccw width=9 standard vigenere pt=standard ct=standard period=5"));
        let any = eliminate_routes_any_substitution(
            &problem,
            &[target],
            AnySubstitutionOptions {
                max_period: 5,
                random_permutations: 0,
                ciphertext_shuffles: 0,
                shuffle_max_period: 0,
                seed: 1,
                examples: 5,
            },
        );
        assert!(
            any.rows[4]
                .examples
                .iter()
                .any(|e| e == "transpose-then-substitute spiral-ccw width=9")
        );
    }
}
