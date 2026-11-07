//! Anchor-reproduction elimination for concrete cipher families.
//!
//! A correct K4 method must reproduce all 24 public anchor letters at their
//! positions. Each configuration below (family plus parameters) yields a list of
//! checks that a correct configuration must pass; one failed check eliminates
//! it. Each check also carries the probability that a random configuration
//! passes it, so the report can say how many survivors chance alone would
//! produce. Surviving a handful of checks is expected by chance and is not
//! evidence for a method.

use crate::data::{K4_CIPHERTEXT, known_plaintext_spans};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

/// Keywords for keyed alphabets, fixed before scoring. They are words tied to
/// Kryptos, its solved sections, Sanborn's public clues, or the registered
/// contextual themes (Berlin World Clock, compass, Egypt 1986, Berlin Wall 1989).
pub const KEYWORDS: &[&str] = &[
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "IQLUSION",
    "UNDERGRUUND",
    "DIGETAL",
    "SHADOW",
    "LUCID",
    "MEMORY",
    "INVISIBLE",
    "LAYERTWO",
    "SANBORN",
    "SCHEIDT",
    "LANGLEY",
    "BERLIN",
    "CLOCK",
    "BERLINCLOCK",
    "WORLDCLOCK",
    "WELTZEITUHR",
    "URANIA",
    "ALEXANDERPLATZ",
    "MENGENLEHREUHR",
    "NORTHEAST",
    "EASTNORTHEAST",
    "COMPASS",
    "LODESTONE",
    "MAGNETIC",
    "EGYPT",
    "CAIRO",
    "GIZA",
    "PYRAMID",
    "TUTANKHAMUN",
    "CARTER",
    "HOWARDCARTER",
    "BERLINWALL",
    "ENIGMA",
];

/// Ciphertext length.
const N: usize = 97;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sign {
    /// c = p + k
    Vigenere,
    /// c = k - p
    Beaufort,
    /// c = p - k
    VariantBeaufort,
}

impl Sign {
    pub const ALL: [Sign; 3] = [Sign::Vigenere, Sign::Beaufort, Sign::VariantBeaufort];

    /// Key index implied by plaintext index `p` and ciphertext index `c`.
    pub fn key(self, p: u8, c: u8) -> u8 {
        match self {
            Sign::Vigenere => (c + 26 - p) % 26,
            Sign::Beaufort => (c + p) % 26,
            Sign::VariantBeaufort => (p + 26 - c) % 26,
        }
    }

    /// Plaintext index recovered from key index `k` and ciphertext index `c`.
    pub fn plain(self, k: u8, c: u8) -> u8 {
        match self {
            Sign::Vigenere => (c + 26 - k) % 26,
            Sign::Beaufort => (k + 26 - c) % 26,
            Sign::VariantBeaufort => (c + k) % 26,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Sign::Vigenere => "vigenere",
            Sign::Beaufort => "beaufort",
            Sign::VariantBeaufort => "variant-beaufort",
        }
    }
}

/// A 26-letter alphabet order. Letters are stored as 0..26 standard indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyedAlphabet {
    pub label: String,
    order: [u8; 26],
    position: [u8; 26],
}

impl KeyedAlphabet {
    pub fn standard() -> Self {
        Self::from_keyword("standard", "")
    }

    /// Keyword alphabet: keyword letters without repeats, then the rest in order.
    pub fn from_keyword(label: &str, keyword: &str) -> Self {
        let mut order = Vec::with_capacity(26);
        for letter in keyword
            .bytes()
            .filter(u8::is_ascii_alphabetic)
            .map(|b| b.to_ascii_uppercase() - b'A')
            .chain(0..26)
        {
            if !order.contains(&letter) {
                order.push(letter);
            }
        }
        let order: [u8; 26] = order.try_into().expect("26 distinct letters");
        let mut position = [0u8; 26];
        for (index, letter) in order.iter().enumerate() {
            position[*letter as usize] = index as u8;
        }
        Self {
            label: label.to_string(),
            order,
            position,
        }
    }

    pub fn symbols(&self) -> String {
        self.order.iter().map(|l| (b'A' + l) as char).collect()
    }

    fn index(&self, letter: u8) -> u8 {
        self.position[letter as usize]
    }

    fn letter(&self, index: u8) -> u8 {
        self.order[index as usize]
    }

    fn is_standard(&self) -> bool {
        self.order.iter().enumerate().all(|(i, l)| i as u8 == *l)
    }
}

/// The standard alphabet followed by one keyed alphabet per distinct keyword.
pub fn registered_alphabets() -> Vec<KeyedAlphabet> {
    let mut alphabets = vec![KeyedAlphabet::standard()];
    for keyword in KEYWORDS {
        let alphabet = KeyedAlphabet::from_keyword(&keyword.to_ascii_lowercase(), keyword);
        if !alphabets.iter().any(|a| a.order == alphabet.order) {
            alphabets.push(alphabet);
        }
    }
    alphabets
}

/// A tableau: plaintext alphabet, ciphertext alphabet, and sign convention.
#[derive(Debug, Clone, Copy)]
pub struct Tableau<'a> {
    pub plain: &'a KeyedAlphabet,
    pub cipher: &'a KeyedAlphabet,
    pub sign: Sign,
}

impl Tableau<'_> {
    fn offset(&self, p: u8, c: u8) -> u8 {
        self.sign.key(self.plain.index(p), self.cipher.index(c))
    }

    fn decrypt(&self, key: u8, c: u8) -> u8 {
        self.plain
            .letter(self.sign.plain(key, self.cipher.index(c)))
    }

    /// Classical name for the alphabet arrangement.
    pub fn kind(&self) -> &'static str {
        match (self.plain.is_standard(), self.cipher.is_standard()) {
            (true, true) => "standard",
            (false, true) => "quagmire-i",
            (true, false) => "quagmire-ii",
            (false, false) if self.plain == self.cipher => "quagmire-iii",
            (false, false) => "quagmire-iv",
        }
    }

    fn label(&self) -> String {
        format!(
            "{} {} pt={} ct={}",
            self.kind(),
            self.sign.label(),
            self.plain.label,
            self.cipher.label
        )
    }
}

/// One public anchor letter: zero-based position, plaintext and ciphertext
/// letters as 0..26 standard indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorLetter {
    pub position: usize,
    pub plain: u8,
    pub cipher: u8,
}

pub fn anchor_letters() -> Vec<AnchorLetter> {
    let ciphertext = K4_CIPHERTEXT.as_bytes();
    let mut letters = Vec::new();
    for span in known_plaintext_spans() {
        for (offset, letter) in span.plaintext.bytes().enumerate() {
            let position = span.start_zero_based + offset;
            letters.push(AnchorLetter {
                position,
                plain: letter - b'A',
                cipher: ciphertext[position] - b'A',
            });
        }
    }
    letters.sort_by_key(|letter| letter.position);
    letters
}

fn ciphertext_indices() -> Vec<u8> {
    K4_CIPHERTEXT.bytes().map(|b| b - b'A').collect()
}

/// Ciphertext plus known anchor letters. `k4()` is the real problem; tests
/// plant synthetic encryptions to confirm each checker keeps a true key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub ciphertext: Vec<u8>,
    pub anchors: Vec<AnchorLetter>,
}

impl Problem {
    pub fn k4() -> Self {
        Self {
            ciphertext: ciphertext_indices(),
            anchors: anchor_letters(),
        }
    }

    fn pairs(&self) -> Vec<(usize, u8, u8)> {
        self.anchors
            .iter()
            .map(|a| (a.position, a.plain, a.cipher))
            .collect()
    }
}

/// Outcome of checking one configuration. All checks are evaluated, so the
/// chance probability is comparable across eliminated and surviving configs.
#[derive(Debug, Clone, Copy, Default)]
struct Outcome {
    checks: usize,
    failures: usize,
    chance_probability: f64,
}

impl Outcome {
    fn new() -> Self {
        Self {
            chance_probability: 1.0,
            ..Self::default()
        }
    }

    fn check(&mut self, passed: bool, chance: f64) {
        self.checks += 1;
        self.chance_probability *= chance;
        if !passed {
            self.failures += 1;
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Survivor {
    pub parameters: String,
    pub checks: usize,
    /// Probability that a random configuration passes the same checks.
    pub chance_probability: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FamilyElimination {
    pub family: &'static str,
    pub description: &'static str,
    pub configurations: usize,
    pub eliminated: usize,
    /// Configurations the anchors cannot test (zero checks).
    pub unconstrained: usize,
    /// Configurations that passed every one of at least one check.
    pub surviving: usize,
    /// Survivors expected if every configuration were random.
    pub expected_chance_survivors: f64,
    pub max_survivor_checks: usize,
    pub top_survivors: Vec<Survivor>,
}

struct Tally {
    family: &'static str,
    description: &'static str,
    top: usize,
    configurations: usize,
    eliminated: usize,
    unconstrained: usize,
    surviving: usize,
    expected: f64,
    survivors: Vec<Survivor>,
}

impl Tally {
    fn new(family: &'static str, description: &'static str, top: usize) -> Self {
        Self {
            family,
            description,
            top,
            configurations: 0,
            eliminated: 0,
            unconstrained: 0,
            surviving: 0,
            expected: 0.0,
            survivors: Vec::new(),
        }
    }

    fn record(&mut self, outcome: Outcome, parameters: impl FnOnce() -> String) {
        self.configurations += 1;
        if outcome.checks == 0 {
            self.unconstrained += 1;
            return;
        }
        self.expected += outcome.chance_probability;
        if outcome.failures > 0 {
            self.eliminated += 1;
            return;
        }
        self.surviving += 1;
        let survivor = Survivor {
            parameters: parameters(),
            checks: outcome.checks,
            chance_probability: outcome.chance_probability,
        };
        self.survivors.push(survivor);
        if self.survivors.len() > self.top * 4 {
            self.trim();
        }
    }

    fn trim(&mut self) {
        self.survivors.sort_by(|a, b| {
            a.chance_probability
                .total_cmp(&b.chance_probability)
                .then_with(|| a.parameters.cmp(&b.parameters))
        });
        self.survivors.truncate(self.top);
    }

    fn finish(mut self) -> FamilyElimination {
        self.trim();
        FamilyElimination {
            family: self.family,
            description: self.description,
            configurations: self.configurations,
            eliminated: self.eliminated,
            unconstrained: self.unconstrained,
            surviving: self.surviving,
            expected_chance_survivors: self.expected,
            max_survivor_checks: self.survivors.iter().map(|s| s.checks).max().unwrap_or(0),
            top_survivors: self.survivors,
        }
    }
}

/// Facts that follow from the anchors alone, independent of any key.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StructuralFacts {
    pub anchor_letters: usize,
    /// One-based positions where an anchor letter encrypts to itself.
    pub self_encrypting_positions_one_based: Vec<usize>,
    /// Pairs of one-based positions with identical plaintext and ciphertext
    /// letters; any position-keyed tableau cipher has equal keys there.
    pub identical_pair_positions_one_based: Vec<(usize, usize)>,
    /// Plaintext letters needed more often than K4 contains them, as
    /// (letter, needed, available). Non-empty means no pure transposition fits.
    pub transposition_shortfall: Vec<(char, usize, usize)>,
    /// Periods (1..=max) at which no periodic substitution, with any alphabet
    /// per column, can map the anchors consistently.
    pub periodic_substitution_impossible_periods: Vec<usize>,
    pub max_period_checked: usize,
}

pub fn structural_facts(max_period: usize) -> StructuralFacts {
    let anchors = anchor_letters();
    let ciphertext = ciphertext_indices();

    let self_encrypting = anchors
        .iter()
        .filter(|a| a.plain == a.cipher)
        .map(|a| a.position + 1)
        .collect();

    let mut by_pair: BTreeMap<(u8, u8), Vec<usize>> = BTreeMap::new();
    for anchor in &anchors {
        by_pair
            .entry((anchor.plain, anchor.cipher))
            .or_default()
            .push(anchor.position + 1);
    }
    let mut identical_pairs = Vec::new();
    for positions in by_pair.values() {
        for (i, first) in positions.iter().enumerate() {
            for second in &positions[i + 1..] {
                identical_pairs.push((*first, *second));
            }
        }
    }
    identical_pairs.sort_unstable();

    let mut needed = [0usize; 26];
    let mut available = [0usize; 26];
    for anchor in &anchors {
        needed[anchor.plain as usize] += 1;
    }
    for letter in &ciphertext {
        available[*letter as usize] += 1;
    }
    let shortfall = (0..26)
        .filter(|&l| needed[l] > available[l])
        .map(|l| ((b'A' + l as u8) as char, needed[l], available[l]))
        .collect();

    let positions: Vec<(usize, u8, u8)> = anchors
        .iter()
        .map(|a| (a.position, a.plain, a.cipher))
        .collect();
    let impossible = (1..=max_period)
        .filter(|&period| !periodic_substitution_consistent(&positions, period))
        .collect();

    StructuralFacts {
        anchor_letters: anchors.len(),
        self_encrypting_positions_one_based: self_encrypting,
        identical_pair_positions_one_based: identical_pairs,
        transposition_shortfall: shortfall,
        periodic_substitution_impossible_periods: impossible,
        max_period_checked: max_period,
    }
}

/// True when each residue class mod `period` maps plaintext to ciphertext
/// letters one-to-one, i.e. some per-column substitution could fit.
fn periodic_substitution_consistent(pairs: &[(usize, u8, u8)], period: usize) -> bool {
    let mut forward: HashMap<(usize, u8), u8> = HashMap::new();
    let mut backward: HashMap<(usize, u8), u8> = HashMap::new();
    pairs.iter().all(|&(position, plain, cipher)| {
        let column = position % period;
        *forward.entry((column, plain)).or_insert(cipher) == cipher
            && *backward.entry((column, cipher)).or_insert(plain) == plain
    })
}

/// Periodic-key checks: within each residue class the implied key must be
/// constant. `digits` adds a key-range check (Gronsfeld keys are 0..=9).
fn periodic_outcome(offsets: &[(usize, u8)], period: usize, digits: bool) -> Outcome {
    let mut outcome = Outcome::new();
    let mut first: HashMap<usize, u8> = HashMap::new();
    for &(position, key) in offsets {
        match first.get(&(position % period)) {
            Some(&expected) => outcome.check(key == expected, 1.0 / 26.0),
            None => {
                first.insert(position % period, key);
                if digits {
                    outcome.check(key <= 9, 10.0 / 26.0);
                }
            }
        }
    }
    outcome
}

fn tableau_offsets(tableau: &Tableau, pairs: &[(usize, u8, u8)]) -> Vec<(usize, u8)> {
    pairs
        .iter()
        .map(|&(position, plain, cipher)| (position, tableau.offset(plain, cipher)))
        .collect()
}

fn all_tableaux(alphabets: &[KeyedAlphabet]) -> Vec<Tableau<'_>> {
    let mut tableaux = Vec::new();
    for plain in alphabets {
        for cipher in alphabets {
            for sign in Sign::ALL {
                tableaux.push(Tableau {
                    plain,
                    cipher,
                    sign,
                });
            }
        }
    }
    tableaux
}

/// Periodic polyalphabetic ciphers: standard tableaux and Quagmire I–IV.
pub fn eliminate_periodic(
    problem: &Problem,
    alphabets: &[KeyedAlphabet],
    max_period: usize,
    top: usize,
) -> FamilyElimination {
    let mut tally = Tally::new(
        "periodic-tableau",
        "Vigenère, Beaufort, and variant Beaufort over every pair of registered alphabets (standard tableau and Quagmire I–IV) with a repeating key of period 1..=max",
        top,
    );
    let pairs = problem.pairs();
    for tableau in all_tableaux(alphabets) {
        let offsets = tableau_offsets(&tableau, &pairs);
        for period in 1..=max_period {
            tally.record(periodic_outcome(&offsets, period, false), || {
                format!("{} period={period}", tableau.label())
            });
        }
    }
    tally.finish()
}

/// Gronsfeld: a periodic numeric key 0..=9 on standard or Kryptos tableaux.
pub fn eliminate_gronsfeld(
    problem: &Problem,
    alphabets: &[KeyedAlphabet],
    max_period: usize,
    top: usize,
) -> FamilyElimination {
    let mut tally = Tally::new(
        "gronsfeld",
        "Periodic digit key (0..=9) on same-alphabet tableaux for every registered alphabet, three sign conventions, period 1..=max",
        top,
    );
    let pairs = problem.pairs();
    for alphabet in alphabets {
        for sign in Sign::ALL {
            let tableau = Tableau {
                plain: alphabet,
                cipher: alphabet,
                sign,
            };
            let offsets = tableau_offsets(&tableau, &pairs);
            for period in 1..=max_period {
                tally.record(periodic_outcome(&offsets, period, true), || {
                    format!("{} period={period}", tableau.label())
                });
            }
        }
    }
    tally.finish()
}

/// Key letters are read in this alphabet: the plaintext or the ciphertext one.
fn key_alphabets<'a>(tableau: &Tableau<'a>) -> Vec<(&'static str, &'a KeyedAlphabet)> {
    if tableau.plain == tableau.cipher {
        vec![("key=pt", tableau.plain)]
    } else {
        vec![("key=pt", tableau.plain), ("key=ct", tableau.cipher)]
    }
}

/// Ciphertext autokey: key at i is ciphertext letter i-L (after an L-letter primer).
pub fn eliminate_ciphertext_autokey(
    problem: &Problem,
    alphabets: &[KeyedAlphabet],
    max_lag: usize,
    top: usize,
) -> FamilyElimination {
    let mut tally = Tally::new(
        "ciphertext-autokey",
        "Key at position i is the ciphertext letter at i-L, after an unknown L-letter primer; every registered tableau, L in 1..=max",
        top,
    );
    let anchors = &problem.anchors;
    let ciphertext = &problem.ciphertext;
    for tableau in all_tableaux(alphabets) {
        for (key_label, key_alphabet) in key_alphabets(&tableau) {
            for lag in 1..=max_lag {
                let mut outcome = Outcome::new();
                for anchor in anchors.iter().filter(|a| a.position >= lag) {
                    let expected = key_alphabet.index(ciphertext[anchor.position - lag]);
                    outcome.check(
                        tableau.offset(anchor.plain, anchor.cipher) == expected,
                        1.0 / 26.0,
                    );
                }
                tally.record(outcome, || {
                    format!("{} {key_label} lag={lag}", tableau.label())
                });
            }
        }
    }
    tally.finish()
}

/// Plaintext autokey: key at i is plaintext letter i-L. Each anchor fixes its
/// whole residue chain mod L in both directions, so a second anchor on the same
/// chain is a check.
pub fn eliminate_plaintext_autokey(
    problem: &Problem,
    alphabets: &[KeyedAlphabet],
    max_lag: usize,
    top: usize,
) -> FamilyElimination {
    let mut tally = Tally::new(
        "plaintext-autokey",
        "Key at position i is the plaintext letter at i-L, after an unknown L-letter primer; every registered tableau, L in 1..=max",
        top,
    );
    let anchors = &problem.anchors;
    let known: HashMap<usize, u8> = anchors.iter().map(|a| (a.position, a.plain)).collect();
    let ciphertext = &problem.ciphertext;
    for tableau in all_tableaux(alphabets) {
        for (key_label, key_alphabet) in key_alphabets(&tableau) {
            for lag in 1..=max_lag {
                let mut outcome = Outcome::new();
                for residue in 0..lag {
                    let chain: Vec<usize> = (residue..N).step_by(lag).collect();
                    let Some(start) = chain.iter().position(|p| known.contains_key(p)) else {
                        continue;
                    };
                    let mut plain = vec![0u8; chain.len()];
                    plain[start] = known[&chain[start]];
                    for t in start + 1..chain.len() {
                        let key = key_alphabet.index(plain[t - 1]);
                        plain[t] = tableau.decrypt(key, ciphertext[chain[t]]);
                    }
                    for t in (0..start).rev() {
                        let key = tableau.offset(plain[t + 1], ciphertext[chain[t + 1]]);
                        plain[t] = key_alphabet.letter(key);
                    }
                    for (t, position) in chain.iter().enumerate().skip(start + 1) {
                        if let Some(&expected) = known.get(position) {
                            outcome.check(plain[t] == expected, 1.0 / 26.0);
                        }
                    }
                }
                tally.record(outcome, || {
                    format!("{} {key_label} lag={lag}", tableau.label())
                });
            }
        }
    }
    tally.finish()
}

/// Gromark-style lagged-Fibonacci keys: k[i] = k[i-L] + k[i-L+1] (mod m).
/// Classic Gromark is L=5, m=10. The 13 consecutive EASTNORTHEAST keys fix the
/// whole stream for L <= 12, which then must reproduce BERLINCLOCK.
pub fn eliminate_gromark(
    problem: &Problem,
    alphabets: &[KeyedAlphabet],
    top: usize,
) -> FamilyElimination {
    let mut tally = Tally::new(
        "gromark",
        "Lagged-Fibonacci key k[i] = k[i-L] + k[i-L+1] mod m (m=10 classic Gromark, m=26 letter variant), L in 2..=12, every registered tableau",
        top,
    );
    let anchors = &problem.anchors;
    let first_span: Vec<&AnchorLetter> = anchors.iter().filter(|a| a.position < 40).collect();
    let second_span: Vec<&AnchorLetter> = anchors.iter().filter(|a| a.position >= 40).collect();
    let first_start = first_span[0].position;
    let last = second_span.last().expect("second span").position;
    for tableau in all_tableaux(alphabets) {
        let first_keys: Vec<u8> = first_span
            .iter()
            .map(|a| tableau.offset(a.plain, a.cipher))
            .collect();
        for modulus in [10u8, 26] {
            for lag in 2..=12usize {
                let mut outcome = Outcome::new();
                if modulus == 10 {
                    for key in &first_keys {
                        outcome.check(*key <= 9, 10.0 / 26.0);
                    }
                }
                let mut keys: Vec<u8> = first_keys.iter().map(|k| k % modulus).collect();
                for t in lag..keys.len() {
                    let expected = (keys[t - lag] + keys[t - lag + 1]) % modulus;
                    outcome.check(keys[t] == expected, 1.0 / f64::from(modulus));
                }
                while first_start + keys.len() <= last {
                    let t = keys.len();
                    keys.push((keys[t - lag] + keys[t - lag + 1]) % modulus);
                }
                for anchor in &second_span {
                    let derived = keys[anchor.position - first_start];
                    outcome.check(
                        tableau.offset(anchor.plain, anchor.cipher) == derived,
                        1.0 / 26.0,
                    );
                }
                tally.record(outcome, || {
                    format!("{} lag={lag} mod={modulus}", tableau.label())
                });
            }
        }
    }
    tally.finish()
}

/// Output position j of a keyed columnar transposition takes input position
/// `order[j]`: write rows of `columns.len()` letters, read columns in `columns` order.
fn columnar_order(columns: &[usize]) -> Vec<usize> {
    let width = columns.len();
    let mut order = Vec::with_capacity(N);
    for &column in columns {
        order.extend((column..N).step_by(width));
    }
    order
}

fn next_permutation(values: &mut [usize]) -> bool {
    let Some(i) = (1..values.len()).rev().find(|&i| values[i - 1] < values[i]) else {
        return false;
    };
    let j = (i..values.len())
        .rev()
        .find(|&j| values[j] > values[i - 1])
        .expect("pivot");
    values.swap(i - 1, j);
    values[i..].reverse();
    true
}

/// Keyed columnar transposition combined with a periodic tableau, in both orders.
pub fn eliminate_columnar(
    problem: &Problem,
    max_width: usize,
    max_period: usize,
    top: usize,
) -> FamilyElimination {
    let mut tally = Tally::new(
        "columnar-plus-tableau",
        "Keyed columnar transposition (every column order, width 2..=max) before or after a periodic Vigenère/Beaufort/variant key on standard and Kryptos tableaux, period 1..=max",
        top,
    );
    let alphabets = [
        KeyedAlphabet::standard(),
        KeyedAlphabet::from_keyword("kryptos", "KRYPTOS"),
    ];
    let tableaux = all_tableaux(&alphabets);
    let anchors = &problem.anchors;
    let ciphertext = &problem.ciphertext;
    for width in 2..=max_width {
        let mut columns: Vec<usize> = (0..width).collect();
        loop {
            let order = columnar_order(&columns);
            let mut inverse = vec![0usize; N];
            for (output, &input) in order.iter().enumerate() {
                inverse[input] = output;
            }
            for (label, period_on_output) in [
                ("substitute-then-transpose", false),
                ("transpose-then-substitute", true),
            ] {
                let pairs: Vec<(usize, u8, u8)> = anchors
                    .iter()
                    .map(|a| {
                        let output = inverse[a.position];
                        let key_position = if period_on_output { output } else { a.position };
                        (key_position, a.plain, ciphertext[output])
                    })
                    .collect();
                for tableau in &tableaux {
                    let offsets = tableau_offsets(tableau, &pairs);
                    for period in 1..=max_period {
                        tally.record(periodic_outcome(&offsets, period, false), || {
                            format!(
                                "{label} width={width} columns={columns:?} {} period={period}",
                                tableau.label()
                            )
                        });
                    }
                }
            }
            if !next_permutation(&mut columns) {
                break;
            }
        }
    }
    tally.finish()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EliminationReport {
    pub structural: StructuralFacts,
    pub alphabets: Vec<String>,
    pub families: Vec<FamilyElimination>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct EliminationOptions {
    pub max_period: usize,
    pub max_lag: usize,
    pub max_columnar_width: usize,
    pub max_columnar_period: usize,
    pub top: usize,
}

impl Default for EliminationOptions {
    fn default() -> Self {
        Self {
            max_period: 26,
            max_lag: 52,
            max_columnar_width: 8,
            max_columnar_period: 13,
            top: 10,
        }
    }
}

pub fn run_elimination(options: EliminationOptions) -> EliminationReport {
    let problem = Problem::k4();
    let alphabets = registered_alphabets();
    let mut families = vec![
        eliminate_periodic(&problem, &alphabets, options.max_period, options.top),
        eliminate_gronsfeld(&problem, &alphabets, options.max_period, options.top),
        eliminate_ciphertext_autokey(&problem, &alphabets, options.max_lag, options.top),
        eliminate_plaintext_autokey(&problem, &alphabets, options.max_lag, options.top),
        eliminate_gromark(&problem, &alphabets, options.top),
    ];
    if options.max_columnar_width >= 2 {
        families.push(eliminate_columnar(
            &problem,
            options.max_columnar_width,
            options.max_columnar_period,
            options.top,
        ));
    }
    EliminationReport {
        structural: structural_facts(48),
        alphabets: alphabets
            .iter()
            .map(|a| format!("{}={}", a.label, a.symbols()))
            .collect(),
        families,
        promoted_candidate: false,
        note: "A configuration survives only if it passes every anchor check it has. Survivors with few checks are expected by chance (compare expected_chance_survivors); none is a decryption or a promoted candidate.",
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RunningKeyHit {
    pub offset: usize,
    pub tableau: String,
    pub matches: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RunningKeyReport {
    pub corpus_letters: usize,
    pub offsets: usize,
    pub configurations: usize,
    pub anchor_letters: usize,
    /// Count of configurations by number of anchor letters reproduced.
    pub match_histogram: Vec<usize>,
    /// Expected count of configurations with at least `best_matches` matches
    /// if keys were random letters.
    pub expected_at_best: f64,
    pub best_matches: usize,
    pub full_matches: usize,
    pub top_hits: Vec<RunningKeyHit>,
    pub promoted_candidate: bool,
}

/// Normalize text to uppercase A–Z letters, as 0..26 indices.
pub fn normalize_letters(text: &str) -> Vec<u8> {
    text.bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|b| b.to_ascii_uppercase() - b'A')
        .collect()
}

/// Running key: the key at K4 position i is corpus letter `offset + i`.
/// Tests every offset on standard and Kryptos tableaux.
pub fn scan_running_key(corpus: &[u8], top: usize) -> RunningKeyReport {
    let alphabets = [
        KeyedAlphabet::standard(),
        KeyedAlphabet::from_keyword("kryptos", "KRYPTOS"),
    ];
    let tableaux = all_tableaux(&alphabets);
    let anchors = anchor_letters();
    let last = anchors.last().expect("anchors").position;
    let offsets = (corpus.len() + 1).saturating_sub(last + 1);
    let mut histogram = vec![0usize; anchors.len() + 1];
    let mut hits = Vec::new();
    let mut configurations = 0;
    for tableau in &tableaux {
        let implied: Vec<u8> = anchors
            .iter()
            .map(|a| tableau.offset(a.plain, a.cipher))
            .collect();
        for (key_label, key_alphabet) in key_alphabets(tableau) {
            for offset in 0..offsets {
                configurations += 1;
                let matches = anchors
                    .iter()
                    .zip(&implied)
                    .filter(|(a, k)| key_alphabet.index(corpus[offset + a.position]) == **k)
                    .count();
                histogram[matches] += 1;
                let floor = if hits.len() >= top {
                    hits.last().map_or(0, |h: &RunningKeyHit| h.matches)
                } else {
                    0
                };
                if hits.len() < top || matches > floor {
                    hits.push(RunningKeyHit {
                        offset,
                        tableau: format!("{} {key_label}", tableau.label()),
                        matches,
                    });
                    hits.sort_by(|a, b| b.matches.cmp(&a.matches).then(a.offset.cmp(&b.offset)));
                    hits.truncate(top);
                }
            }
        }
    }
    let best_matches = hits.first().map(|h| h.matches).unwrap_or(0);
    RunningKeyReport {
        corpus_letters: corpus.len(),
        offsets,
        configurations,
        anchor_letters: anchors.len(),
        expected_at_best: configurations as f64
            * binomial_tail(anchors.len(), best_matches, 1.0 / 26.0),
        best_matches,
        full_matches: histogram[anchors.len()],
        match_histogram: histogram,
        top_hits: hits,
        promoted_candidate: false,
    }
}

/// P(X >= k) for X ~ Binomial(n, p).
fn binomial_tail(n: usize, k: usize, p: f64) -> f64 {
    let mut total = 0.0;
    let mut coefficient = 1.0;
    for i in 0..=n {
        if i > 0 {
            coefficient *= (n - i + 1) as f64 / i as f64;
        }
        if i >= k {
            total += coefficient * p.powi(i as i32) * (1.0 - p).powi((n - i) as i32);
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_periodic(plain: &[u8], key: &[u8], tableau: &Tableau) -> Vec<u8> {
        plain
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let k = key[i % key.len()];
                let pi = tableau.plain.index(p);
                let ci = match tableau.sign {
                    Sign::Vigenere => (pi + k) % 26,
                    Sign::Beaufort => (k + 26 - pi) % 26,
                    Sign::VariantBeaufort => (pi + 26 - k) % 26,
                };
                tableau.cipher.letter(ci)
            })
            .collect()
    }

    fn enc(tableau: &Tableau, key: u8, plain: u8) -> u8 {
        let pi = tableau.plain.index(plain);
        let ci = match tableau.sign {
            Sign::Vigenere => (pi + key) % 26,
            Sign::Beaufort => (key + 26 - pi) % 26,
            Sign::VariantBeaufort => (pi + 26 - key) % 26,
        };
        tableau.cipher.letter(ci)
    }

    fn synthetic_plaintext() -> Vec<u8> {
        let mut state: u32 = 12345;
        (0..N)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                ((state >> 16) % 26) as u8
            })
            .collect()
    }

    /// A problem with anchors at the K4 anchor positions of a synthetic text.
    fn planted(plain: &[u8], cipher: &[u8]) -> Problem {
        let anchors = anchor_letters()
            .iter()
            .map(|a| AnchorLetter {
                position: a.position,
                plain: plain[a.position],
                cipher: cipher[a.position],
            })
            .collect();
        Problem {
            ciphertext: cipher.to_vec(),
            anchors,
        }
    }

    fn top_survivor(result: &FamilyElimination) -> &Survivor {
        result
            .top_survivors
            .first()
            .expect("planted key should survive")
    }

    #[test]
    fn planted_quagmire_iv_key_survives_periodic_check() {
        let alphabets = vec![
            KeyedAlphabet::standard(),
            KeyedAlphabet::from_keyword("palimpsest", "PALIMPSEST"),
            KeyedAlphabet::from_keyword("kryptos", "KRYPTOS"),
        ];
        let tableau = Tableau {
            plain: &alphabets[1],
            cipher: &alphabets[2],
            sign: Sign::Beaufort,
        };
        let plain = synthetic_plaintext();
        let key = [3, 14, 7, 21, 0];
        let cipher: Vec<u8> = (0..N)
            .map(|i| enc(&tableau, key[i % 5], plain[i]))
            .collect();
        let result = eliminate_periodic(&planted(&plain, &cipher), &alphabets, 26, 3);
        let best = top_survivor(&result);
        assert_eq!(
            best.parameters,
            "quagmire-iv beaufort pt=palimpsest ct=kryptos period=5"
        );
        assert!(best.checks >= 15);
    }

    #[test]
    fn planted_autokeys_survive() {
        let alphabets = vec![
            KeyedAlphabet::standard(),
            KeyedAlphabet::from_keyword("kryptos", "KRYPTOS"),
        ];
        let tableau = Tableau {
            plain: &alphabets[0],
            cipher: &alphabets[1],
            sign: Sign::Vigenere,
        };
        let plain = synthetic_plaintext();
        let primer = [4u8, 19, 2, 11, 8, 23, 15];
        let lag = primer.len();

        let mut cipher = vec![0u8; N];
        for i in 0..N {
            let key = if i < lag {
                primer[i]
            } else {
                tableau.cipher.index(cipher[i - lag])
            };
            cipher[i] = enc(&tableau, key, plain[i]);
        }
        let result = eliminate_ciphertext_autokey(&planted(&plain, &cipher), &alphabets, 20, 3);
        let best = top_survivor(&result);
        assert_eq!(
            best.parameters,
            "quagmire-ii vigenere pt=standard ct=kryptos key=ct lag=7"
        );
        assert_eq!(best.checks, 24);

        let cipher: Vec<u8> = (0..N)
            .map(|i| {
                let key = if i < lag {
                    primer[i]
                } else {
                    tableau.plain.index(plain[i - lag])
                };
                enc(&tableau, key, plain[i])
            })
            .collect();
        let result = eliminate_plaintext_autokey(&planted(&plain, &cipher), &alphabets, 20, 3);
        let best = top_survivor(&result);
        assert_eq!(
            best.parameters,
            "quagmire-ii vigenere pt=standard ct=kryptos key=pt lag=7"
        );
        assert!(best.checks >= 10);
    }

    #[test]
    fn planted_gromark_survives() {
        let alphabets = vec![
            KeyedAlphabet::standard(),
            KeyedAlphabet::from_keyword("kryptos", "KRYPTOS"),
        ];
        let tableau = Tableau {
            plain: &alphabets[0],
            cipher: &alphabets[1],
            sign: Sign::Vigenere,
        };
        let plain = synthetic_plaintext();
        let mut keys = vec![2u8, 7, 1, 8, 2];
        while keys.len() < N {
            let t = keys.len();
            keys.push((keys[t - 5] + keys[t - 4]) % 10);
        }
        let cipher: Vec<u8> = (0..N).map(|i| enc(&tableau, keys[i], plain[i])).collect();
        let result = eliminate_gromark(&planted(&plain, &cipher), &alphabets, 3);
        let best = top_survivor(&result);
        assert_eq!(
            best.parameters,
            "quagmire-ii vigenere pt=standard ct=kryptos lag=5 mod=10"
        );
        assert_eq!(result.surviving, 1);
    }

    #[test]
    fn planted_columnar_keys_survive_in_both_orders() {
        let alphabet = KeyedAlphabet::from_keyword("kryptos", "KRYPTOS");
        let tableau = Tableau {
            plain: &alphabet,
            cipher: &alphabet,
            sign: Sign::Vigenere,
        };
        let plain = synthetic_plaintext();
        let key = [5u8, 9, 2];
        let order = columnar_order(&[2, 0, 3, 1]);

        let substituted: Vec<u8> = (0..N)
            .map(|i| enc(&tableau, key[i % 3], plain[i]))
            .collect();
        let cipher: Vec<u8> = order.iter().map(|&i| substituted[i]).collect();
        let result = eliminate_columnar(&planted(&plain, &cipher), 4, 6, 3);
        assert_planted_survivor(
            &result,
            "substitute-then-transpose width=4 columns=[2, 0, 3, 1] quagmire-iii vigenere pt=kryptos ct=kryptos period=3",
        );

        let cipher: Vec<u8> = order
            .iter()
            .enumerate()
            .map(|(j, &i)| enc(&tableau, key[j % 3], plain[i]))
            .collect();
        let result = eliminate_columnar(&planted(&plain, &cipher), 4, 6, 3);
        assert_planted_survivor(
            &result,
            "transpose-then-substitute width=4 columns=[2, 0, 3, 1] quagmire-iii vigenere pt=kryptos ct=kryptos period=3",
        );
    }

    /// The planted key ties with mathematically equivalent configurations
    /// (variant Beaufort with key -k equals Vigenère with key k on one alphabet),
    /// so accept it anywhere among the equally unlikely top survivors.
    fn assert_planted_survivor(result: &FamilyElimination, expected: &str) {
        let best = top_survivor(result).chance_probability;
        assert!(
            result
                .top_survivors
                .iter()
                .any(|s| s.parameters == expected && s.chance_probability == best),
            "{expected} not among top survivors {:?}",
            result.top_survivors
        );
    }

    #[test]
    fn sign_conventions_round_trip() {
        for sign in Sign::ALL {
            for p in 0..26 {
                for k in 0..26 {
                    let c = (0..26).find(|&c| sign.key(p, c) == k).unwrap();
                    assert_eq!(sign.plain(k, c), p, "{sign:?}");
                }
            }
        }
    }

    #[test]
    fn kryptos_keyword_alphabet_matches_sculpture() {
        assert_eq!(
            KeyedAlphabet::from_keyword("kryptos", "KRYPTOS").symbols(),
            "KRYPTOSABCDEFGHIJLMNQUVWXZ"
        );
        assert!(KeyedAlphabet::standard().is_standard());
    }

    #[test]
    fn anchors_are_the_24_public_letters() {
        let anchors = anchor_letters();
        assert_eq!(anchors.len(), 24);
        assert_eq!(anchors[0].position, 21);
        assert_eq!(anchors[23].position, 73);
    }

    /// Bean (2021): positions 28 and 66 (one-based) both carry plaintext R and
    /// ciphertext P, so any position-keyed tableau cipher has equal keys there.
    #[test]
    fn bean_equality_holds_in_the_data() {
        let facts = structural_facts(48);
        assert_eq!(facts.identical_pair_positions_one_based, vec![(28, 66)]);
    }

    #[test]
    fn self_encryptions_rule_out_porta() {
        let facts = structural_facts(48);
        assert_eq!(facts.self_encrypting_positions_one_based, vec![33, 74]);
    }

    #[test]
    fn pure_transposition_is_impossible() {
        let facts = structural_facts(48);
        assert_eq!(facts.transposition_shortfall, vec![('E', 3, 2)]);
    }

    #[test]
    fn periodic_substitution_fails_at_small_periods() {
        let facts = structural_facts(48);
        for period in 1..=7 {
            assert!(
                facts
                    .periodic_substitution_impossible_periods
                    .contains(&period)
            );
        }
        assert!(!facts.periodic_substitution_impossible_periods.contains(&8));
    }

    #[test]
    fn periodic_check_accepts_a_true_key_and_rejects_a_wrong_one() {
        let alphabet = KeyedAlphabet::from_keyword("kryptos", "KRYPTOS");
        let tableau = Tableau {
            plain: &alphabet,
            cipher: &alphabet,
            sign: Sign::Vigenere,
        };
        let plain: Vec<u8> = (0..N as u8).map(|i| (i * 7 + 3) % 26).collect();
        let cipher = encrypt_periodic(&plain, &[10, 4, 17], &tableau);
        let pairs: Vec<(usize, u8, u8)> = (0..N).map(|i| (i, plain[i], cipher[i])).collect();
        let offsets = tableau_offsets(&tableau, &pairs);
        let good = periodic_outcome(&offsets, 3, false);
        assert_eq!(good.failures, 0);
        assert!(good.checks > 90);
        assert!(periodic_outcome(&offsets, 4, false).failures > 0);
    }

    #[test]
    fn known_periodic_tableaux_are_eliminated_on_k4() {
        let alphabets = vec![
            KeyedAlphabet::standard(),
            KeyedAlphabet::from_keyword("kryptos", "KRYPTOS"),
        ];
        let result = eliminate_periodic(&Problem::k4(), &alphabets, 26, 5);
        assert_eq!(result.configurations, 4 * 3 * 26);
        assert!(result.max_survivor_checks <= 1);
    }

    #[test]
    fn gromark_classic_is_eliminated() {
        let result = eliminate_gromark(&Problem::k4(), &registered_alphabets(), 5);
        assert_eq!(result.surviving, 0);
        assert!(result.eliminated > 0);
    }

    #[test]
    fn running_key_scan_finds_a_planted_key() {
        let alphabet = KeyedAlphabet::standard();
        let tableau = Tableau {
            plain: &alphabet,
            cipher: &alphabet,
            sign: Sign::Vigenere,
        };
        let ciphertext = ciphertext_indices();
        let anchors = anchor_letters();
        let mut corpus: Vec<u8> = (0..300u32).map(|i| ((i * 11 + 5) % 26) as u8).collect();
        let offset = 120;
        for a in &anchors {
            corpus[offset + a.position] = tableau.offset(a.plain, ciphertext[a.position]);
        }
        let report = scan_running_key(&corpus, 3);
        assert!(report.full_matches >= 1);
        assert_eq!(report.top_hits[0].offset, offset);
        assert_eq!(report.top_hits[0].matches, 24);
    }

    #[test]
    fn binomial_tail_is_a_probability() {
        assert!((binomial_tail(24, 0, 1.0 / 26.0) - 1.0).abs() < 1e-12);
        assert!(binomial_tail(24, 24, 1.0 / 26.0) < 1e-30);
    }

    #[test]
    fn next_permutation_enumerates_all_orders() {
        let mut values = vec![0, 1, 2, 3];
        let mut count = 1;
        while next_permutation(&mut values) {
            count += 1;
        }
        assert_eq!(count, 24);
    }
}
