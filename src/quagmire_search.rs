//! Exact search: can Quagmire III or IV, with arbitrary mixed alphabets,
//! reproduce the anchors at a given period?
//!
//! Each anchor gives one equation in the unknown alphabet positions and the
//! key of its column: posB(c) - posA(p) = k[col] for Vigenère (variant
//! Beaufort is the same with k negated), posB(c) + posA(p) = k[col] for
//! Beaufort. Quagmire III shares one alphabet (posA = posB). A column with a
//! single anchor constrains nothing (its key is free), so only columns with
//! two or more anchors are kept. Periods where no per-column substitution fits
//! at all are impossible outright. Otherwise a depth-first search assigns alphabet
//! positions, deriving column keys and forcing partner letters as soon as an
//! equation has two known terms. Every solution found is re-verified.

use crate::eliminate::{AnchorLetter, anchor_letters, periodic_substitution_consistent};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuagmireKind {
    /// One mixed alphabet on both sides.
    #[serde(rename = "quagmire-iii")]
    III,
    /// Independent mixed plaintext and ciphertext alphabets.
    #[serde(rename = "quagmire-iv")]
    IV,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearchSign {
    /// Vigenère; variant Beaufort is equivalent with the key negated.
    VigenereOrVariant,
    Beaufort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearchResult {
    Possible,
    Impossible,
    /// The node budget ran out before the search finished.
    Undecided,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct QuagmireSearchRow {
    pub kind: QuagmireKind,
    pub sign: SearchSign,
    pub period: usize,
    pub result: SearchResult,
    pub nodes: u64,
}

const UNSET: u8 = u8::MAX;

struct Search {
    /// (ciphertext-side variable, plaintext-side variable, column).
    equations: Vec<(usize, usize, usize)>,
    /// +1 for Vigenère (b - a = k), -1 for Beaufort (b + a = k), stored as the
    /// multiplier on the plaintext-side term: k = b + sa * a.
    sa: i32,
    value: Vec<u8>,
    key: Vec<u8>,
    /// used[side][position]: side 0 = plaintext alphabet, 1 = ciphertext.
    used: [[bool; 26]; 2],
    side: Vec<usize>,
    variables: Vec<usize>,
    nodes: u64,
    budget: u64,
}

enum Trail {
    Value(usize),
    Key(usize),
}

impl Search {
    fn assign(&mut self, var: usize, x: u8, trail: &mut Vec<Trail>) -> bool {
        if self.value[var] != UNSET {
            return self.value[var] == x;
        }
        let side = self.side[var];
        if self.used[side][x as usize] {
            return false;
        }
        self.value[var] = x;
        self.used[side][x as usize] = true;
        trail.push(Trail::Value(var));
        true
    }

    fn propagate(&mut self, trail: &mut Vec<Trail>) -> bool {
        loop {
            let mut changed = false;
            for i in 0..self.equations.len() {
                let (b, a, col) = self.equations[i];
                let (vb, va, vk) = (self.value[b], self.value[a], self.key[col]);
                if vb != UNSET && va != UNSET {
                    let k = (vb as i32 + self.sa * va as i32).rem_euclid(26) as u8;
                    if vk == UNSET {
                        self.key[col] = k;
                        trail.push(Trail::Key(col));
                        changed = true;
                    } else if vk != k {
                        return false;
                    }
                } else if vk != UNSET && vb != UNSET {
                    // a = sa * (k - b), since sa = ±1 is its own inverse.
                    let x = (self.sa * (vk as i32 - vb as i32)).rem_euclid(26) as u8;
                    if !self.assign(a, x, trail) {
                        return false;
                    }
                    changed = true;
                } else if vk != UNSET && va != UNSET {
                    let x = (vk as i32 - self.sa * va as i32).rem_euclid(26) as u8;
                    if !self.assign(b, x, trail) {
                        return false;
                    }
                    changed = true;
                }
            }
            if !changed {
                return true;
            }
        }
    }

    fn undo(&mut self, trail: Vec<Trail>) {
        for entry in trail.into_iter().rev() {
            match entry {
                Trail::Value(var) => {
                    let x = self.value[var];
                    self.used[self.side[var]][x as usize] = false;
                    self.value[var] = UNSET;
                }
                Trail::Key(col) => self.key[col] = UNSET,
            }
        }
    }

    /// Unassigned variable with the most equations whose other terms are known.
    fn pick(&self) -> Option<usize> {
        let mut best: Option<(u32, usize)> = None;
        for &var in &self.variables {
            if self.value[var] != UNSET {
                continue;
            }
            let mut score = 0u32;
            for &(b, a, col) in &self.equations {
                let other_known = if var == b {
                    Some(self.value[a] != UNSET || self.key[col] != UNSET)
                } else if var == a {
                    Some(self.value[b] != UNSET || self.key[col] != UNSET)
                } else {
                    None
                };
                match other_known {
                    Some(true) => score += 20,
                    Some(false) => score += 1,
                    None => {}
                }
            }
            if best.is_none_or(|(s, _)| score > s) {
                best = Some((score, var));
            }
        }
        best.map(|(_, var)| var)
    }

    fn dfs(&mut self) -> Option<bool> {
        self.nodes += 1;
        if self.nodes > self.budget {
            return None;
        }
        let Some(var) = self.pick() else {
            return Some(true);
        };
        for x in 0..26u8 {
            if self.used[self.side[var]][x as usize] {
                continue;
            }
            let mut trail = Vec::new();
            if self.assign(var, x, &mut trail) && self.propagate(&mut trail) {
                match self.dfs() {
                    Some(true) => return Some(true),
                    None => return None,
                    Some(false) => {}
                }
            }
            self.undo(trail);
        }
        Some(false)
    }

    fn verify(&self) -> bool {
        self.equations.iter().all(|&(b, a, col)| {
            let (vb, va, vk) = (self.value[b], self.value[a], self.key[col]);
            vb != UNSET
                && va != UNSET
                && vk != UNSET
                && (vb as i32 + self.sa * va as i32).rem_euclid(26) as u8 == vk
        })
    }
}

/// Decide one (kind, sign, period) for the given anchor letters.
pub fn search_quagmire(
    anchors: &[AnchorLetter],
    kind: QuagmireKind,
    sign: SearchSign,
    period: usize,
    budget: u64,
) -> (SearchResult, u64) {
    // Variables: 0..26 plaintext-alphabet letters, 26..52 ciphertext-alphabet
    // letters (Quagmire III maps both sides to 0..26).
    let cipher_var = |letter: u8| match kind {
        QuagmireKind::III => letter as usize,
        QuagmireKind::IV => 26 + letter as usize,
    };
    // Quagmire III and IV are periodic substitutions, so a period where no
    // per-column substitution fits is impossible without searching.
    let pairs: Vec<(usize, u8, u8)> = anchors
        .iter()
        .map(|a| (a.position, a.plain, a.cipher))
        .collect();
    if !periodic_substitution_consistent(&pairs, period) {
        return (SearchResult::Impossible, 0);
    }
    let mut counts = vec![0usize; period];
    for a in anchors {
        counts[a.position % period] += 1;
    }
    let equations: Vec<(usize, usize, usize)> = anchors
        .iter()
        .filter(|a| counts[a.position % period] > 1)
        .map(|a| (cipher_var(a.cipher), a.plain as usize, a.position % period))
        .collect();
    if equations.is_empty() {
        return (SearchResult::Possible, 0);
    }
    let mut variables: Vec<usize> = equations.iter().flat_map(|&(b, a, _)| [b, a]).collect();
    variables.sort_unstable();
    variables.dedup();
    let side: Vec<usize> = (0..52)
        .map(|v| usize::from(kind == QuagmireKind::IV && v >= 26))
        .collect();
    let mut search = Search {
        sa: match sign {
            SearchSign::VigenereOrVariant => -1,
            SearchSign::Beaufort => 1,
        },
        equations,
        value: vec![UNSET; 52],
        key: vec![UNSET; period],
        used: [[false; 26]; 2],
        side,
        variables,
        nodes: 0,
        budget,
    };
    // Symmetry: translating an alphabet is absorbed by the keys, so fix one
    // plaintext-side letter (and, for IV, one ciphertext-side letter) at 0.
    let mut trail = Vec::new();
    let first_plain = search.equations[0].1;
    let mut ok = search.assign(first_plain, 0, &mut trail);
    if kind == QuagmireKind::IV {
        let first_cipher = search.equations[0].0;
        ok = ok && search.assign(first_cipher, 0, &mut trail);
    }
    ok = ok && search.propagate(&mut trail);
    if !ok {
        return (SearchResult::Impossible, search.nodes);
    }
    let result = match search.dfs() {
        Some(true) => {
            assert!(search.verify(), "search returned an unverified solution");
            SearchResult::Possible
        }
        Some(false) => SearchResult::Impossible,
        None => SearchResult::Undecided,
    };
    (result, search.nodes)
}

/// Every kind, sign, and period 1..=max_period for the K4 anchors.
pub fn quagmire_iii_iv_search(max_period: usize, budget: u64) -> Vec<QuagmireSearchRow> {
    let anchors = anchor_letters();
    let mut rows = Vec::new();
    for kind in [QuagmireKind::III, QuagmireKind::IV] {
        for sign in [SearchSign::VigenereOrVariant, SearchSign::Beaufort] {
            for period in 1..=max_period {
                let (result, nodes) = search_quagmire(&anchors, kind, sign, period, budget);
                rows.push(QuagmireSearchRow {
                    kind,
                    sign,
                    period,
                    result,
                    nodes,
                });
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eliminate::KeyedAlphabet;

    fn scrambled(keyword: &str) -> Vec<u8> {
        let alphabet = KeyedAlphabet::from_keyword("t", keyword);
        alphabet.symbols().bytes().map(|b| b - b'A').collect()
    }

    /// Encrypt synthetic plaintext with a Quagmire III/IV tableau and confirm
    /// the search finds a solution at the true period.
    fn planted(kind: QuagmireKind, sign: SearchSign, period: usize) -> Vec<AnchorLetter> {
        let order_a = scrambled("QWERTYUIOPLKJHGFDSAZXCVBNM");
        let order_b = match kind {
            QuagmireKind::III => order_a.clone(),
            QuagmireKind::IV => scrambled("MNBVCXZLKJHGFDSAPOIUYTREWQ"),
        };
        let mut pos_a = [0u8; 26];
        for (i, &l) in order_a.iter().enumerate() {
            pos_a[l as usize] = i as u8;
        }
        let key: Vec<u8> = (0..period).map(|i| ((i * 7 + 3) % 26) as u8).collect();
        anchor_letters()
            .iter()
            .map(|a| {
                let plain = ((a.position * 11 + 5) % 26) as u8;
                let k = key[a.position % period] as i32;
                let pa = pos_a[plain as usize] as i32;
                let pb = match sign {
                    SearchSign::VigenereOrVariant => (pa + k).rem_euclid(26),
                    SearchSign::Beaufort => (k - pa).rem_euclid(26),
                };
                AnchorLetter {
                    position: a.position,
                    plain,
                    cipher: order_b[pb as usize],
                }
            })
            .collect()
    }

    #[test]
    fn planted_quagmire_iii_and_iv_are_found() {
        for kind in [QuagmireKind::III, QuagmireKind::IV] {
            for sign in [SearchSign::VigenereOrVariant, SearchSign::Beaufort] {
                for period in [3, 5, 8, 11, 19] {
                    let anchors = planted(kind, sign, period);
                    let (result, _) = search_quagmire(&anchors, kind, sign, period, 50_000_000);
                    assert_eq!(result, SearchResult::Possible, "{kind:?} {sign:?} {period}");
                }
            }
        }
    }

    #[test]
    fn k4_small_periods_are_impossible() {
        let anchors = anchor_letters();
        for kind in [QuagmireKind::III, QuagmireKind::IV] {
            for sign in [SearchSign::VigenereOrVariant, SearchSign::Beaufort] {
                for period in 1..=7 {
                    let (result, _) = search_quagmire(&anchors, kind, sign, period, 50_000_000);
                    assert_eq!(
                        result,
                        SearchResult::Impossible,
                        "{kind:?} {sign:?} {period}"
                    );
                }
            }
        }
    }
}
