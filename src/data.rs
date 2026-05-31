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
            archive_url: Some("sources/archives/cia-artifact-2026-05-27.md"),
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
            archive_url: Some("sources/archives/cia-sculpture-2026-05-27.md"),
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
            archive_url: Some("sources/archives/elonka-kryptos-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: None,
            source_type: "reference",
            allowed_use: "public-anchor-summary",
            use_note: "Public ciphertext transcription and public clue summary.",
        },
        Source {
            id: "histocrypt-2021-bean",
            label: "HistoCrypt 2021 Richard Bean abstract",
            url: "https://ecp.ep.liu.se/index.php/histocrypt/article/view/153",
            archive_url: Some("sources/archives/histocrypt-2021-bean-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: Some("2021"),
            source_type: "academic",
            allowed_use: "methodology-context",
            use_note: "Academic cryptodiagnosis and Gromark-family hypothesis.",
        },
        Source {
            id: "scientific-american-2025",
            label: "Scientific American 2025 final clues report",
            url: "https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/",
            archive_url: Some(
                "sources/archives/scientific-american-2025-final-clues-2026-05-27.md",
            ),
            accessed_at: "2026-05-27",
            publication_date: Some("2025-11-12"),
            source_type: "major-reporting",
            allowed_use: "public-clue-context",
            use_note: "2025 public clue context, Berlin World Clock clarification, and K5 parallel-position context.",
        },
        Source {
            id: "scientific-american-2026-kryptos-cracked",
            label: "Scientific American 2026 Kryptos archive-discovery report",
            url: "https://www.scientificamerican.com/article/how-the-cias-kryptos-sculpture-gave-up-its-final-secret/",
            archive_url: Some(
                "sources/archives/scientific-american-2026-kryptos-cracked-2026-05-31.md",
            ),
            accessed_at: "2026-05-31",
            publication_date: Some("2025-10-22"),
            source_type: "major-reporting",
            allowed_use: "archive-context-only",
            use_note: "Archive-discovery and claim-boundary reporting; no public plaintext, key material, route, or scored K4 observations.",
        },
        Source {
            id: "ap-2025-auction",
            label: "Associated Press 2025 auction report",
            url: "https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/",
            archive_url: Some("sources/archives/ap-2025-auction-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: Some("2025-11-12"),
            source_type: "major-reporting",
            allowed_use: "archive-context-only",
            use_note: "Archive-discovery context and Sanborn decipherment distinction.",
        },
        Source {
            id: "ap-2025-archive-sale",
            label: "Associated Press 2025 archive sale follow-up",
            url: "https://apnews.com/article/kryptos-jim-sanborn-auction-cia-secret-code-cb8ee8554ca473910cbd0592f8bdb350",
            archive_url: Some("sources/archives/ap-2025-archive-sale-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: Some("2025-11-21"),
            source_type: "major-reporting",
            allowed_use: "archive-context-only",
            use_note: "Archive sale outcome and context only; no archive-discovered plaintext content.",
        },
        Source {
            id: "rr-auction-kryptos-archive-2025",
            label: "RR Auction 2025 Kryptos archive lot",
            url: "https://www.rrauction.com/auctions/lot-detail/350761607302001-the-complete-secrets-of-kryptos-jim-sanborns-private-archive/?cat=0",
            archive_url: Some("sources/archives/rr-auction-kryptos-archive-2025-2026-05-31.md"),
            accessed_at: "2026-05-31",
            publication_date: Some("2025-11-20"),
            source_type: "auction-primary",
            allowed_use: "archive-context-only",
            use_note: "Primary auction-lot provenance for the private K4/K5 archive and explicit no-independent-examination boundary; no public plaintext, key material, routes, or scored K4 observations.",
        },
        Source {
            id: "smithsonian-2026-archive-discovery",
            label: "Smithsonian 2026 archive-discovery report",
            url: "https://www.smithsonianmag.com/blogs/office-of-the-secretary-of-the-smithsonian/2026/02/17/smithsonian-archives-help-unlock-mysteries-connect-americans-history/",
            archive_url: Some("sources/archives/smithsonian-2026-archive-discovery-2026-05-28.md"),
            accessed_at: "2026-05-28",
            publication_date: Some("2026-02-17"),
            source_type: "institutional-reporting",
            allowed_use: "archive-context-only",
            use_note: "Smithsonian archive-discovery context; no archive-discovered plaintext, key material, routes, or scoreable observations.",
        },
        Source {
            id: "nsa-kryptos-doc1-resolution-memo",
            label: "NSA Kryptos challenge and resolution memo",
            url: "https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760459/",
            archive_url: Some("sources/archives/nsa-kryptos-doc1-resolution-memo-2026-05-28.md"),
            accessed_at: "2026-05-28",
            publication_date: Some("1993-06-09"),
            source_type: "primary",
            allowed_use: "archive-context-only",
            use_note: "Declassified NSA challenge/resolution memo context for solved sections and methodology boundaries; no scored K4 positions.",
        },
        Source {
            id: "nsa-declassified-kryptos-doc3",
            label: "NSA declassified Kryptos sculpture notes",
            url: "https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cia-kryptos-sculpture/doc_3.pdf",
            archive_url: Some("sources/archives/nsa-declassified-kryptos-doc3-2026-05-28.md"),
            accessed_at: "2026-05-28",
            publication_date: None,
            source_type: "primary",
            allowed_use: "archive-context-only",
            use_note: "Declassified physical-clue context including compass, lodestone, Morse, and sculpture-layout notes; no scored K4 positions.",
        },
        Source {
            id: "nsa-kryptos-doc7-technical-analysis",
            label: "NSA Kryptos technical analysis memo",
            url: "https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cia-kryptos-sculpture/doc_7.pdf",
            archive_url: Some("sources/archives/nsa-kryptos-doc7-technical-analysis-2026-05-28.md"),
            accessed_at: "2026-05-28",
            publication_date: Some("1992-03-26"),
            source_type: "primary",
            allowed_use: "archive-context-only",
            use_note: "Declassified NSA solved-section methodology and unresolved-section boundary context; no scored K4 positions.",
        },
        Source {
            id: "nsa-kryptos-foia-release-index",
            label: "NSA CIA Kryptos Sculpture FOIA release index",
            url: "https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760460/",
            archive_url: Some("sources/archives/nsa-kryptos-foia-release-index-2026-05-28.md"),
            accessed_at: "2026-05-28",
            publication_date: Some("2021-07-12"),
            source_type: "primary",
            allowed_use: "archive-context-only",
            use_note: "NSA declassification index for CIA Kryptos Sculpture document releases; source-discovery context only, no scored K4 positions.",
        },
        Source {
            id: "nsa-kryptos-summary-revelations",
            label: "NSA Kryptos previous work and revelations summary",
            url: "https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760463/",
            archive_url: Some("sources/archives/nsa-kryptos-summary-revelations-2026-05-28.md"),
            accessed_at: "2026-05-28",
            publication_date: Some("2014-09-16"),
            source_type: "primary",
            allowed_use: "archive-context-only",
            use_note: "NSA declassified summary context for prior work and later revelations; no scored K4 positions, plaintext, key material, or route evidence.",
        },
        Source {
            id: "nsa-kryptos-doc8-cryptogram",
            label: "NSA Kryptos cryptogram text document",
            url: "https://www.nsa.gov/Helpful-Links/NSA-FOIA/Declassification-Transparency-Initiatives/FOIA-Reports-and-Releases/FOIA-Reports-and-Releases-List/igphoto/2002760461/",
            archive_url: Some("sources/archives/nsa-kryptos-doc8-cryptogram-2026-05-28.md"),
            accessed_at: "2026-05-28",
            publication_date: Some("2021-07-12"),
            source_type: "primary",
            allowed_use: "public-anchor-summary",
            use_note: "NSA declassified cryptogram-text context; public ciphertext provenance only, not independent scored observation evidence.",
        },
        Source {
            id: "kryptosbot-sanborn-papers-2026",
            label: "KryptosBot 2026 Sanborn papers research archive",
            url: "https://kryptosbot.com/archive/",
            archive_url: Some("sources/archives/kryptosbot-sanborn-papers-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: Some("2026-04"),
            source_type: "community-research-archive",
            allowed_use: "archive-context-only",
            use_note: "Curated public notes from Smithsonian Sanborn papers research; context for future preregistration only, including a 7-by-14-compatible K4 layout rationale, not scored plaintext or candidate evidence.",
        },
        Source {
            id: "kryptosbot-methodology-2026",
            label: "KryptosBot 2026 methodology and eliminations",
            url: "https://kryptosbot.com/methodology/",
            archive_url: Some("sources/archives/kryptosbot-methodology-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: Some("2026-05"),
            source_type: "community-research-methodology",
            allowed_use: "methodology-context",
            use_note: "Public reproducibility and elimination-scope context; not plaintext, not candidate evidence, and not scored observations.",
        },
        Source {
            id: "kryptosbot-findings-2026",
            label: "KryptosBot 2026 findings and open questions",
            url: "https://kryptosbot.com/findings/",
            archive_url: Some("sources/archives/kryptosbot-findings-2026-05-31.md"),
            accessed_at: "2026-05-31",
            publication_date: Some("2026-05"),
            source_type: "community-research-findings",
            allowed_use: "methodology-context",
            use_note: "Public findings and open-question context around W-delimiter, CT-perturbation, Stehle local regularity, HILL-tableau, and negative-search boundaries; not plaintext, candidate evidence, or scored observations.",
        },
        Source {
            id: "kryptos-today-project-k4-2026",
            label: "Project K4 2026 live cryptanalysis press page",
            url: "https://kryptos.today/press/2026-05-01-launch",
            archive_url: Some("sources/archives/kryptos-today-project-k4-2026-05-31.md"),
            accessed_at: "2026-05-31",
            publication_date: Some("2026-05-01"),
            source_type: "independent-cryptanalysis-project",
            allowed_use: "methodology-context",
            use_note: "Independent live-search and negative-result context; not plaintext, not candidate evidence, and not scored observations.",
        },
        Source {
            id: "kryptos-today-progress-2026",
            label: "Project K4 2026 progress log",
            url: "https://kryptos.today/progress",
            archive_url: Some("sources/archives/kryptos-today-progress-2026-05-31.md"),
            accessed_at: "2026-05-31",
            publication_date: Some("2026-05-16"),
            source_type: "independent-cryptanalysis-progress",
            allowed_use: "methodology-context",
            use_note: "Independent progress-log context for attack-family triage, including Weltzeituhr, width-7 transposition, and Morse/Mengenlehreuhr queue updates; not plaintext, candidate evidence, or scored observations.",
        },
        Source {
            id: "rumkin-k4-reference",
            label: "Rumkin K4 reference notes",
            url: "https://rumkin.com/reference/kryptos/k4/",
            archive_url: Some("sources/archives/rumkin-k4-reference-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: Some("2026-03-31"),
            source_type: "community-reference",
            allowed_use: "methodology-context",
            use_note: "K4 reference and open-question context around direct mapping, installation threads, and the HILL tableau question; not plaintext, not candidate evidence, and not scored observations.",
        },
        Source {
            id: "solvekryptos-2026-claim",
            label: "SolveKryptos 2026 K4 solution claim",
            url: "https://solvekryptos.com/",
            archive_url: Some("sources/archives/solvekryptos-2026-05-27.md"),
            accessed_at: "2026-05-27",
            publication_date: Some("2026-05"),
            source_type: "community-solution-claim",
            allowed_use: "unverified-solution-claim",
            use_note: "Public claimed K4 plaintext and mechanism; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.",
        },
        Source {
            id: "dearcipher-k4-claim-2026",
            label: "Dear Cipher Kryptos K4 claim",
            url: "https://www.dearcipher.space/kryptos",
            archive_url: Some("sources/archives/dearcipher-k4-claim-2026-05-31.md"),
            accessed_at: "2026-05-31",
            publication_date: None,
            source_type: "community-solution-claim",
            allowed_use: "unverified-solution-claim",
            use_note: "Public claimed K4 plaintext and explanation; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.",
        },
        Source {
            id: "prlog-bishop-k4-plaintext-2020",
            label: "Stephen Bishop PRLog K4 plaintext claim",
            url: "https://www.prlog.org/12845348-stephen-bishop-discovers-us-central-intelligence-agency-sculpture-kryptos-k4-plaintext.pdf",
            archive_url: Some("sources/archives/prlog-bishop-k4-plaintext-2020-2026-05-31.md"),
            accessed_at: "2026-05-31",
            publication_date: Some("2020-11-03"),
            source_type: "community-solution-claim",
            allowed_use: "unverified-solution-claim",
            use_note: "Public claimed K4 plaintext via CIA New Headquarters Building visual construction; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.",
        },
        Source {
            id: "ssrn-bonifacino-running-key-2025",
            label: "SSRN Bonifacino 2025 running-key K4 paper",
            url: "https://ssrn.com/abstract=5876405",
            archive_url: Some("sources/archives/ssrn-bonifacino-running-key-2025-2026-05-31.md"),
            accessed_at: "2026-05-31",
            publication_date: Some("2025-12-08"),
            source_type: "community-solution-claim",
            allowed_use: "unverified-solution-claim",
            use_note: "Public running-key candidate paper; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.",
        },
        Source {
            id: "ssrn-bonifacino-weltzeituhr-error-key-2025",
            label: "SSRN Bonifacino 2025 Weltzeituhr error-key derivation paper",
            url: "https://ssrn.com/abstract=5779902",
            archive_url: Some(
                "sources/archives/ssrn-bonifacino-weltzeituhr-error-key-2025-2026-05-31.md",
            ),
            accessed_at: "2026-05-31",
            publication_date: Some("2025-11-21"),
            source_type: "community-solution-claim",
            allowed_use: "unverified-solution-claim",
            use_note: "Public claimed derivation for a Weltzeituhr running-key K4 method; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.",
        },
        Source {
            id: "ssrn-bonifacino-generative-running-key-2025",
            label: "SSRN Bonifacino 2025 generative running-key paper",
            url: "https://ssrn.com/abstract=5876462",
            archive_url: Some(
                "sources/archives/ssrn-bonifacino-generative-running-key-2025-2026-05-31.md",
            ),
            accessed_at: "2026-05-31",
            publication_date: Some("2025-12-08"),
            source_type: "community-solution-claim",
            allowed_use: "unverified-solution-claim",
            use_note: "Public claimed generative ruleset for a Weltzeituhr running-key K4 method; quarantined for future independent verification only, not source-backed evidence, not candidate material, and not release-facing plaintext.",
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
            "smithsonian-2026-archive-discovery",
            "kryptosbot-sanborn-papers-2026",
            "kryptosbot-methodology-2026",
            "kryptos-today-project-k4-2026",
            "kryptos-today-progress-2026",
            "rumkin-k4-reference",
            "solvekryptos-2026-claim",
        ] {
            assert!(
                source_ids.contains(required_source),
                "missing plan source {required_source}"
            );
        }
    }
}
