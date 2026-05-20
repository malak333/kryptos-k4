use serde::Serialize;

pub const K4_CIPHERTEXT: &str = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anchor {
    pub plaintext: &'static str,
    pub ciphertext: &'static str,
    pub start_zero_based: usize,
    pub end_zero_based_inclusive: usize,
    pub source_note: &'static str,
}

impl Anchor {
    pub fn start_one_based(&self) -> usize {
        self.start_zero_based + 1
    }

    pub fn end_one_based_inclusive(&self) -> usize {
        self.end_zero_based_inclusive + 1
    }

    pub fn len(&self) -> usize {
        self.plaintext.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Source {
    pub label: &'static str,
    pub url: &'static str,
    pub use_note: &'static str,
}

pub fn known_anchors() -> Vec<Anchor> {
    vec![
        Anchor {
            plaintext: "EAST",
            ciphertext: "FLRV",
            start_zero_based: 21,
            end_zero_based_inclusive: 24,
            source_note: "Publicly released after Sanborn correspondence, summarized by Elonka Dunin.",
        },
        Anchor {
            plaintext: "NORTHEAST",
            ciphertext: "QQPRNGKSS",
            start_zero_based: 25,
            end_zero_based_inclusive: 33,
            source_note: "Sanborn's 2020 public clue, summarized by major reporting and Elonka Dunin.",
        },
        Anchor {
            plaintext: "BERLIN",
            ciphertext: "NYPVTT",
            start_zero_based: 63,
            end_zero_based_inclusive: 68,
            source_note: "Sanborn's 2010 public clue.",
        },
        Anchor {
            plaintext: "CLOCK",
            ciphertext: "MZFPK",
            start_zero_based: 69,
            end_zero_based_inclusive: 73,
            source_note: "Sanborn's 2014 public clue.",
        },
    ]
}

pub fn sources() -> Vec<Source> {
    vec![
        Source {
            label: "CIA Kryptos artifact page",
            url: "https://www.cia.gov/legacy/museum/artifact/kryptos/",
            use_note: "Installation context and unresolved fourth-section status.",
        },
        Source {
            label: "CIA Kryptos sculpture page",
            url: "https://www.cia.gov/legacy/headquarters/kryptos-sculpture/",
            use_note: "Sculpture components, Vigenere chart context, and 97-character K4 statement.",
        },
        Source {
            label: "Elonka Dunin Kryptos page",
            url: "https://www.elonka.com/kryptos/",
            use_note: "Public ciphertext transcription and public clue summary.",
        },
        Source {
            label: "HistoCrypt 2021 Richard Bean abstract",
            url: "https://ecp.ep.liu.se/index.php/histocrypt/article/view/153",
            use_note: "Academic cryptodiagnosis and Gromark-family hypothesis.",
        },
        Source {
            label: "Scientific American 2025 final clues report",
            url: "https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/",
            use_note: "2025 public clue context and Berlin World Clock clarification.",
        },
        Source {
            label: "Associated Press 2025 auction report",
            url: "https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/",
            use_note: "Archive-discovery context and Sanborn decipherment distinction.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_length_is_97() {
        assert_eq!(K4_CIPHERTEXT.len(), 97);
    }

    #[test]
    fn anchors_match_ciphertext_positions() {
        for anchor in known_anchors() {
            let actual = &K4_CIPHERTEXT[anchor.start_zero_based..=anchor.end_zero_based_inclusive];
            assert_eq!(actual, anchor.ciphertext);
            assert_eq!(anchor.plaintext.len(), anchor.ciphertext.len());
        }
    }
}
