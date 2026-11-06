//! Exact search: can Quagmire I, II, III, or IV, with arbitrary mixed
//! alphabets, reproduce the anchors at a given period?
//!
//! Each anchor gives one equation in the unknown alphabet positions and the
//! key of its column: posB(c) - posA(p) = k[col] for Vigenère (variant
//! Beaufort is the same with k negated), posB(c) + posA(p) = k[col] for
//! Beaufort. Quagmire I fixes posB to the standard alphabet, Quagmire II fixes
//! posA, and Quagmire III shares one alphabet (posA = posB). A column with a
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
    /// Mixed plaintext alphabet, standard ciphertext alphabet.
    #[serde(rename = "quagmire-i")]
    I,
    /// Standard plaintext alphabet, mixed ciphertext alphabet.
    #[serde(rename = "quagmire-ii")]
    II,
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

impl QuagmireKind {
    pub const ALL: [QuagmireKind; 4] = [
        QuagmireKind::I,
        QuagmireKind::II,
        QuagmireKind::III,
        QuagmireKind::IV,
    ];
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
                if b == a && self.sa == -1 {
                    // A letter that encrypts to itself under one shared
                    // alphabet with the Vigenère sign forces k = b - b = 0,
                    // whatever its position.
                    if vk == UNSET {
                        self.key[col] = 0;
                        trail.push(Trail::Key(col));
                        changed = true;
                    } else if vk != 0 {
                        return false;
                    }
                } else if vk == 0 && self.sa == -1 && self.side[b] == self.side[a] {
                    // Key 0 on one shared alphabet maps every letter to
                    // itself, so two different letters cannot pair up.
                    return false;
                } else if vb != UNSET && va != UNSET {
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
        QuagmireKind::I | QuagmireKind::II | QuagmireKind::IV => 26 + letter as usize,
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
        .map(|v| usize::from(kind != QuagmireKind::III && v >= 26))
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
    // Quagmire I and II: the standard side is known, letter i at position i.
    let fixed_side = match kind {
        QuagmireKind::I => Some(1),
        QuagmireKind::II => Some(0),
        QuagmireKind::III | QuagmireKind::IV => None,
    };
    if let Some(fixed) = fixed_side {
        for letter in 0..26 {
            search.value[26 * fixed + letter] = letter as u8;
            search.used[fixed][letter] = true;
        }
    }
    // Symmetry: translating a mixed alphabet is absorbed by the keys, so fix
    // one letter of each mixed alphabet at 0.
    let mut trail = Vec::new();
    let mut ok = true;
    if fixed_side != Some(0) {
        let first_plain = search.equations[0].1;
        ok = search.assign(first_plain, 0, &mut trail);
    }
    if kind == QuagmireKind::II || kind == QuagmireKind::IV {
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
pub fn quagmire_exact_search(max_period: usize, budget: u64) -> Vec<QuagmireSearchRow> {
    let anchors = anchor_letters();
    let mut rows = Vec::new();
    for kind in QuagmireKind::ALL {
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
        let standard: Vec<u8> = (0..26).collect();
        let order_a = match kind {
            QuagmireKind::II => standard.clone(),
            _ => scrambled("QWERTYUIOPLKJHGFDSAZXCVBNM"),
        };
        let order_b = match kind {
            QuagmireKind::I => standard,
            QuagmireKind::III => order_a.clone(),
            QuagmireKind::II | QuagmireKind::IV => scrambled("MNBVCXZLKJHGFDSAPOIUYTREWQ"),
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
    fn planted_quagmires_are_found() {
        for kind in QuagmireKind::ALL {
            for sign in [SearchSign::VigenereOrVariant, SearchSign::Beaufort] {
                for period in [3, 5, 8, 11, 19] {
                    let anchors = planted(kind, sign, period);
                    let (result, _) = search_quagmire(&anchors, kind, sign, period, 50_000_000);
                    assert_eq!(result, SearchResult::Possible, "{kind:?} {sign:?} {period}");
                }
            }
        }
    }

    /// Position 74 (K -> K) shares column 1 with position 26 (N -> Q) at
    /// period 24. Under one alphabet with the Vigenère sign the self-encryption
    /// forces that column's key to 0, so N cannot become Q.
    #[test]
    fn k4_quagmire_iii_vigenere_period_24_is_impossible() {
        let anchors = anchor_letters();
        let (result, nodes) = search_quagmire(
            &anchors,
            QuagmireKind::III,
            SearchSign::VigenereOrVariant,
            24,
            1_000,
        );
        assert_eq!(result, SearchResult::Impossible);
        assert!(nodes <= 1, "decided by propagation, took {nodes} nodes");
    }

    #[test]
    fn k4_small_periods_are_impossible() {
        let anchors = anchor_letters();
        for kind in QuagmireKind::ALL {
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

    /// Cross-checks on the K4 anchors for Quagmire I and II. The union-find
    /// test in `eliminate` is necessary, so whatever it rejects must be
    /// impossible here. Reflecting the mixed alphabet turns Beaufort into
    /// Vigenère, so both signs must agree. Quagmire IV generalizes I and II,
    /// so it must be solvable wherever they are.
    #[test]
    fn k4_quagmire_i_ii_agree_with_necessary_check_and_iv() {
        use crate::eliminate::{QuagmireSide, quagmire_any_alphabet_consistent};
        let anchors = anchor_letters();
        let pairs: Vec<(usize, u8, u8)> = anchors
            .iter()
            .map(|a| (a.position, a.plain, a.cipher))
            .collect();
        for (kind, side) in [
            (QuagmireKind::I, QuagmireSide::Plain),
            (QuagmireKind::II, QuagmireSide::Cipher),
        ] {
            for period in 1..=26 {
                let budget = 50_000_000;
                let (vig, _) = search_quagmire(
                    &anchors,
                    kind,
                    SearchSign::VigenereOrVariant,
                    period,
                    budget,
                );
                let (beau, _) =
                    search_quagmire(&anchors, kind, SearchSign::Beaufort, period, budget);
                assert_eq!(vig, beau, "{kind:?} period {period}: signs disagree");
                if !quagmire_any_alphabet_consistent(&pairs, period, side) {
                    assert_eq!(vig, SearchResult::Impossible, "{kind:?} period {period}");
                }
                if vig == SearchResult::Possible {
                    let (iv, _) = search_quagmire(
                        &anchors,
                        QuagmireKind::IV,
                        SearchSign::VigenereOrVariant,
                        period,
                        budget,
                    );
                    assert_eq!(iv, SearchResult::Possible, "IV at period {period}");
                }
            }
        }
    }
}
