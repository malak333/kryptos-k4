use crate::{Alphabet, Anchor, known_anchors};
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentMode {
    AdditiveKey,
    SubtractiveKey,
    BeaufortKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConstraintAnalysis {
    pub anchor: Anchor,
    pub alphabet: Alphabet,
    pub fragments: Vec<KeyFragment>,
    pub recurrence: RecurrenceScreen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyFragment {
    pub position_zero_based: usize,
    pub position_one_based: usize,
    pub plaintext: char,
    pub ciphertext: char,
    pub plaintext_index: u8,
    pub ciphertext_index: u8,
    pub mode: FragmentMode,
    pub value: u8,
    pub symbol: char,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecurrenceScreen {
    pub checked_mode: FragmentMode,
    pub contiguous_pairs_checked: usize,
    pub gromark_sum_matches: usize,
    pub notes: Vec<String>,
}

pub fn analyze_constraints() -> Result<Vec<ConstraintAnalysis>> {
    let mut analyses = Vec::new();

    for anchor in known_anchors() {
        for alphabet in Alphabet::all_supported() {
            let fragments = derive_fragments(&anchor, &alphabet)?;
            let recurrence = screen_gromark_recurrence(&fragments);
            analyses.push(ConstraintAnalysis {
                anchor: anchor.clone(),
                alphabet,
                fragments,
                recurrence,
            });
        }
    }

    Ok(analyses)
}

pub fn derive_fragments(anchor: &Anchor, alphabet: &Alphabet) -> Result<Vec<KeyFragment>> {
    let mut fragments = Vec::new();

    for (offset, (plain, cipher)) in anchor
        .plaintext
        .chars()
        .zip(anchor.ciphertext.chars())
        .enumerate()
    {
        let plaintext_index = alphabet.index_of(plain)?;
        let ciphertext_index = alphabet.index_of(cipher)?;
        let position_zero_based = anchor.start_zero_based + offset;

        for mode in [
            FragmentMode::AdditiveKey,
            FragmentMode::SubtractiveKey,
            FragmentMode::BeaufortKey,
        ] {
            let value = match mode {
                FragmentMode::AdditiveKey => (26 + ciphertext_index - plaintext_index) % 26,
                FragmentMode::SubtractiveKey => (26 + plaintext_index - ciphertext_index) % 26,
                FragmentMode::BeaufortKey => (26 + plaintext_index + ciphertext_index) % 26,
            };

            fragments.push(KeyFragment {
                position_zero_based,
                position_one_based: position_zero_based + 1,
                plaintext: plain,
                ciphertext: cipher,
                plaintext_index,
                ciphertext_index,
                mode,
                value,
                symbol: alphabet.char_at(value)?,
            });
        }
    }

    Ok(fragments)
}

fn screen_gromark_recurrence(fragments: &[KeyFragment]) -> RecurrenceScreen {
    let additive: Vec<&KeyFragment> = fragments
        .iter()
        .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
        .collect();

    let mut contiguous_pairs_checked = 0;
    let mut gromark_sum_matches = 0;

    for window in additive.windows(3) {
        let first = window[0];
        let second = window[1];
        let third = window[2];

        if first.position_zero_based + 1 != second.position_zero_based
            || second.position_zero_based + 1 != third.position_zero_based
        {
            continue;
        }

        contiguous_pairs_checked += 1;
        if (first.value + second.value) % 10 == third.value % 10 {
            gromark_sum_matches += 1;
        }
    }

    let mut notes = vec![format!(
        "Screen only checks local additive fragments from public anchors; it is not a solve."
    )];
    if contiguous_pairs_checked == 0 {
        notes.push("No contiguous triples available for recurrence screening.".to_string());
    } else {
        notes.push(format!(
            "{gromark_sum_matches} of {contiguous_pairs_checked} contiguous triples match a mod-10 sum recurrence."
        ));
    }

    RecurrenceScreen {
        checked_mode: FragmentMode::AdditiveKey,
        contiguous_pairs_checked,
        gromark_sum_matches,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlphabetKind, known_anchors};

    #[test]
    fn derives_three_modes_per_anchor_character() {
        let anchor = known_anchors()
            .into_iter()
            .find(|anchor| anchor.plaintext == "BERLIN")
            .unwrap();

        let fragments = derive_fragments(&anchor, &Alphabet::standard()).unwrap();

        assert_eq!(fragments.len(), anchor.len() * 3);
        assert_eq!(fragments[0].position_one_based, 64);
        assert_eq!(fragments[0].mode, FragmentMode::AdditiveKey);
    }

    #[test]
    fn analyzes_every_anchor_against_supported_alphabets() {
        let analyses = analyze_constraints().unwrap();

        assert_eq!(analyses.len(), known_anchors().len() * 3);
        assert!(
            analyses
                .iter()
                .any(|analysis| analysis.alphabet.kind == AlphabetKind::Kryptos)
        );
    }
}
