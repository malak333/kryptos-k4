use serde::Serialize;

pub const K4_CIPHERTEXT: &str = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anchor {
    pub plaintext: &'static str,
    pub ciphertext: &'static str,
    pub start_zero_based: usize,
    pub end_zero_based_inclusive: usize,
    pub source_ids: &'static [&'static str],
    pub confidence: &'static str,
    pub claim_type: &'static str,
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
    pub id: &'static str,
    pub label: &'static str,
    pub url: &'static str,
    pub archive_url: Option<&'static str>,
    pub accessed_at: &'static str,
    pub publication_date: Option<&'static str>,
    pub source_type: &'static str,
    pub allowed_use: &'static str,
    pub use_note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KnownPlaintextSpan {
    pub plaintext: String,
    pub ciphertext: String,
    pub start_zero_based: usize,
    pub end_zero_based_inclusive: usize,
    pub anchor_plaintexts: Vec<&'static str>,
}

impl KnownPlaintextSpan {
    pub fn start_one_based(&self) -> usize {
        self.start_zero_based + 1
    }

    pub fn end_one_based_inclusive(&self) -> usize {
        self.end_zero_based_inclusive + 1
    }
}

pub fn known_anchors() -> Vec<Anchor> {
    vec![
        Anchor {
            plaintext: "EAST",
            ciphertext: "FLRV",
            start_zero_based: 21,
            end_zero_based_inclusive: 24,
            source_ids: &["elonka-kryptos"],
            confidence: "high",
            claim_type: "public-anchor",
            source_note: "Publicly released after Sanborn correspondence, summarized by Elonka Dunin.",
        },
        Anchor {
            plaintext: "NORTHEAST",
            ciphertext: "QQPRNGKSS",
            start_zero_based: 25,
            end_zero_based_inclusive: 33,
            source_ids: &["elonka-kryptos"],
            confidence: "high",
            claim_type: "public-anchor",
            source_note: "Sanborn's 2020 public clue, summarized by major reporting and Elonka Dunin.",
        },
        Anchor {
            plaintext: "BERLIN",
            ciphertext: "NYPVTT",
            start_zero_based: 63,
            end_zero_based_inclusive: 68,
            source_ids: &["elonka-kryptos"],
            confidence: "high",
            claim_type: "public-anchor",
            source_note: "Sanborn's 2010 public clue.",
        },
        Anchor {
            plaintext: "CLOCK",
            ciphertext: "MZFPK",
            start_zero_based: 69,
            end_zero_based_inclusive: 73,
            source_ids: &["elonka-kryptos", "scientific-american-2025"],
            confidence: "high",
            claim_type: "public-anchor",
            source_note: "Sanborn's 2014 public clue.",
        },
    ]
}

pub fn known_plaintext_spans() -> Vec<KnownPlaintextSpan> {
    let anchors = known_anchors();
    let mut spans: Vec<KnownPlaintextSpan> = Vec::new();

    for anchor in anchors {
        if let Some(last) = spans.last_mut()
            && last.end_zero_based_inclusive + 1 == anchor.start_zero_based
        {
            last.plaintext.push_str(anchor.plaintext);
            last.ciphertext.push_str(anchor.ciphertext);
            last.end_zero_based_inclusive = anchor.end_zero_based_inclusive;
            last.anchor_plaintexts.push(anchor.plaintext);
            continue;
        }

        spans.push(KnownPlaintextSpan {
            plaintext: anchor.plaintext.to_string(),
            ciphertext: anchor.ciphertext.to_string(),
            start_zero_based: anchor.start_zero_based,
            end_zero_based_inclusive: anchor.end_zero_based_inclusive,
            anchor_plaintexts: vec![anchor.plaintext],
        });
    }

    spans
}

pub fn sources() -> Vec<Source> {
    vec![
        Source {
            id: "cia-artifact",
            label: "CIA Kryptos artifact page",
            url: "https://www.cia.gov/legacy/museum/artifact/kryptos/",
            archive_url: None,
            accessed_at: "2026-05-20",
            publication_date: None,
            source_type: "primary",
            allowed_use: "public-facts-only",
            use_note: "Installation context and unresolved fourth-section status.",
        },
        Source {
            id: "cia-sculpture",
            label: "CIA Kryptos sculpture page",
            url: "https://www.cia.gov/legacy/headquarters/kryptos-sculpture/",
            archive_url: None,
            accessed_at: "2026-05-20",
            publication_date: None,
            source_type: "primary",
            allowed_use: "public-facts-only",
            use_note: "Sculpture components, Vigenere chart context, and 97-character K4 statement.",
        },
        Source {
            id: "elonka-kryptos",
            label: "Elonka Dunin Kryptos page",
            url: "https://www.elonka.com/kryptos/",
            archive_url: None,
            accessed_at: "2026-05-20",
            publication_date: None,
            source_type: "reference",
            allowed_use: "public-anchor-summary",
            use_note: "Public ciphertext transcription and public clue summary.",
        },
        Source {
            id: "histocrypt-2021-bean",
            label: "HistoCrypt 2021 Richard Bean abstract",
            url: "https://ecp.ep.liu.se/index.php/histocrypt/article/view/153",
            archive_url: None,
            accessed_at: "2026-05-20",
            publication_date: Some("2021"),
            source_type: "academic",
            allowed_use: "methodology-context",
            use_note: "Academic cryptodiagnosis and Gromark-family hypothesis.",
        },
        Source {
            id: "scientific-american-2025",
            label: "Scientific American 2025 final clues report",
            url: "https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/",
            archive_url: None,
            accessed_at: "2026-05-20",
            publication_date: Some("2025-11-12"),
            source_type: "major-reporting",
            allowed_use: "public-clue-context",
            use_note: "2025 public clue context and Berlin World Clock clarification.",
        },
        Source {
            id: "ap-2025-auction",
            label: "Associated Press 2025 auction report",
            url: "https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/",
            archive_url: None,
            accessed_at: "2026-05-20",
            publication_date: Some("2025-11-12"),
            source_type: "major-reporting",
            allowed_use: "archive-context-only",
            use_note: "Archive-discovery context and Sanborn decipherment distinction.",
        },
        Source {
            id: "ap-2025-archive-sale",
            label: "Associated Press 2025 archive sale follow-up",
            url: "https://apnews.com/article/kryptos-jim-sanborn-auction-cia-secret-code-cb8ee8554ca473910cbd0592f8bdb350",
            archive_url: None,
            accessed_at: "2026-05-20",
            publication_date: Some("2025-11-21"),
            source_type: "major-reporting",
            allowed_use: "archive-context-only",
            use_note: "Archive sale outcome and context only; no archive-discovered plaintext content.",
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

    #[test]
    fn public_anchor_invariants_are_stable() {
        let anchors = known_anchors();
        assert!(anchors.windows(2).all(|window| {
            window[0].start_zero_based < window[1].start_zero_based
                && window[0].end_zero_based_inclusive < window[1].end_zero_based_inclusive
        }));
        for anchor in anchors {
            assert!(!anchor.is_empty());
            assert!(anchor.end_zero_based_inclusive < K4_CIPHERTEXT.len());
            assert!(
                anchor
                    .plaintext
                    .chars()
                    .all(|value| value.is_ascii_uppercase())
            );
            assert!(
                anchor
                    .ciphertext
                    .chars()
                    .all(|value| value.is_ascii_uppercase())
            );
            assert!(!anchor.source_ids.is_empty());
        }
    }

    #[test]
    fn adjacent_public_clues_are_joined_into_spans() {
        let spans = known_plaintext_spans();

        assert!(spans.iter().any(|span| span.plaintext == "EASTNORTHEAST"));
        assert!(spans.iter().any(|span| span.plaintext == "BERLINCLOCK"));
    }

    #[test]
    fn all_source_references_resolve() {
        let source_ids: std::collections::HashSet<_> =
            sources().into_iter().map(|source| source.id).collect();

        for anchor in known_anchors() {
            for source_id in anchor.source_ids {
                assert!(source_ids.contains(source_id), "missing source {source_id}");
            }
        }
    }

    #[test]
    fn plan_source_list_entries_are_registered() {
        let source_ids: std::collections::HashSet<_> =
            sources().into_iter().map(|source| source.id).collect();

        for required_source in [
            "cia-artifact",
            "cia-sculpture",
            "elonka-kryptos",
            "histocrypt-2021-bean",
            "scientific-american-2025",
            "ap-2025-auction",
            "ap-2025-archive-sale",
        ] {
            assert!(
                source_ids.contains(required_source),
                "missing plan source {required_source}"
            );
        }
    }
}
