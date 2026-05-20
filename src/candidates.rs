use crate::{FragmentMode, K4_CIPHERTEXT, analyze_known_plaintext_spans};
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateSequenceFamily {
    BerlinWorldClock,
    CompassDirections,
    Egypt1986,
    BerlinWall1989,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateTransform {
    A1Z26ZeroBased,
    A1Z26OneBased,
    DecimalDigits,
    Compass8Point,
    Compass16Point,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateSequence {
    pub id: &'static str,
    pub family: CandidateSequenceFamily,
    pub source_ids: &'static [&'static str],
    pub raw_material: &'static str,
    pub transform: CandidateTransform,
    pub values: Vec<u8>,
    pub expanded_to_k4: Vec<u8>,
    pub pre_registered: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CandidateSequenceScore {
    pub candidate_id: &'static str,
    pub family: CandidateSequenceFamily,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub match_rate: f64,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

pub fn candidate_sequences() -> Vec<CandidateSequence> {
    vec![
        candidate(
            "h4-berlin-world-clock-english",
            CandidateSequenceFamily::BerlinWorldClock,
            &["scientific-american-2025"],
            "BERLINWORLDCLOCK",
            CandidateTransform::A1Z26ZeroBased,
        ),
        candidate(
            "h4-berlin-world-clock-german",
            CandidateSequenceFamily::BerlinWorldClock,
            &["scientific-american-2025"],
            "WELTZEITUHR",
            CandidateTransform::A1Z26ZeroBased,
        ),
        candidate(
            "h4-berlin-world-clock-place",
            CandidateSequenceFamily::BerlinWorldClock,
            &["scientific-american-2025"],
            "ALEXANDERPLATZ",
            CandidateTransform::A1Z26ZeroBased,
        ),
        candidate(
            "h4-compass-8point-east-northeast",
            CandidateSequenceFamily::CompassDirections,
            &["elonka-kryptos"],
            "EASTNORTHEAST",
            CandidateTransform::Compass8Point,
        ),
        candidate(
            "h4-compass-16point-east-northeast",
            CandidateSequenceFamily::CompassDirections,
            &["elonka-kryptos"],
            "EASTNORTHEAST",
            CandidateTransform::Compass16Point,
        ),
        candidate(
            "h5-egypt-1986-literal",
            CandidateSequenceFamily::Egypt1986,
            &["scientific-american-2025"],
            "EGYPT",
            CandidateTransform::A1Z26ZeroBased,
        ),
        candidate(
            "h5-egypt-1986-year",
            CandidateSequenceFamily::Egypt1986,
            &["scientific-american-2025"],
            "1986",
            CandidateTransform::DecimalDigits,
        ),
        candidate(
            "h5-berlin-wall-1989-literal",
            CandidateSequenceFamily::BerlinWall1989,
            &["scientific-american-2025"],
            "BERLINWALL",
            CandidateTransform::A1Z26ZeroBased,
        ),
        candidate(
            "h5-berlin-wall-1989-date",
            CandidateSequenceFamily::BerlinWall1989,
            &["scientific-american-2025"],
            "19891109",
            CandidateTransform::DecimalDigits,
        ),
    ]
}

pub fn score_candidate_sequences() -> Result<Vec<CandidateSequenceScore>> {
    let span_fragments: Vec<u8> = analyze_known_plaintext_spans()?
        .into_iter()
        .filter(|analysis| analysis.alphabet.kind == crate::AlphabetKind::Standard)
        .flat_map(|analysis| analysis.fragments)
        .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
        .map(|fragment| fragment.value)
        .collect();

    Ok(candidate_sequences()
        .into_iter()
        .map(|candidate| {
            let compared_fragment_count = span_fragments.len().min(candidate.expanded_to_k4.len());
            let exact_mod26_matches = span_fragments
                .iter()
                .zip(candidate.expanded_to_k4.iter())
                .take(compared_fragment_count)
                .filter(|(fragment, candidate)| *fragment == *candidate)
                .count();
            let match_rate = if compared_fragment_count == 0 {
                0.0
            } else {
                exact_mod26_matches as f64 / compared_fragment_count as f64
            };

            CandidateSequenceScore {
                candidate_id: candidate.id,
                family: candidate.family,
                compared_fragment_count,
                exact_mod26_matches,
                match_rate,
                promoted_candidate: false,
                note: "Exploratory candidate screen only; no candidate is promoted without independent baselines.",
            }
        })
        .collect())
}

fn candidate(
    id: &'static str,
    family: CandidateSequenceFamily,
    source_ids: &'static [&'static str],
    raw_material: &'static str,
    transform: CandidateTransform,
) -> CandidateSequence {
    let values = transform_values(raw_material, transform);
    CandidateSequence {
        id,
        family,
        source_ids,
        raw_material,
        transform,
        expanded_to_k4: expand_to_k4(&values),
        values,
        pre_registered: true,
    }
}

fn transform_values(raw_material: &str, transform: CandidateTransform) -> Vec<u8> {
    match transform {
        CandidateTransform::A1Z26ZeroBased => raw_material
            .chars()
            .filter(|value| value.is_ascii_alphabetic())
            .map(|value| value.to_ascii_uppercase() as u8 - b'A')
            .collect(),
        CandidateTransform::A1Z26OneBased => raw_material
            .chars()
            .filter(|value| value.is_ascii_alphabetic())
            .map(|value| value.to_ascii_uppercase() as u8 - b'A' + 1)
            .collect(),
        CandidateTransform::DecimalDigits => raw_material
            .chars()
            .filter_map(|value| value.to_digit(10).map(|digit| digit as u8))
            .collect(),
        CandidateTransform::Compass8Point => compass_values(raw_material, 8),
        CandidateTransform::Compass16Point => compass_values(raw_material, 16),
    }
}

fn compass_values(raw_material: &str, points: u8) -> Vec<u8> {
    match raw_material {
        "EASTNORTHEAST" if points == 8 => vec![2, 1],
        "EASTNORTHEAST" if points == 16 => vec![4, 2],
        "EAST" if points == 8 => vec![2],
        "EAST" if points == 16 => vec![4],
        "NORTHEAST" if points == 8 => vec![1],
        "NORTHEAST" if points == 16 => vec![2],
        _ => Vec::new(),
    }
}

fn expand_to_k4(values: &[u8]) -> Vec<u8> {
    if values.is_empty() {
        return Vec::new();
    }

    values
        .iter()
        .copied()
        .cycle()
        .take(K4_CIPHERTEXT.len())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn candidate_sequences_are_pre_registered() {
        for candidate in candidate_sequences() {
            assert!(!candidate.id.is_empty());
            assert!(!candidate.source_ids.is_empty());
            assert!(!candidate.raw_material.is_empty());
            assert!(!candidate.values.is_empty());
            assert!(candidate.pre_registered);
        }
    }

    #[test]
    fn candidate_ids_are_unique_and_stable() {
        let candidates = candidate_sequences();
        let ids: HashSet<_> = candidates.iter().map(|candidate| candidate.id).collect();

        assert_eq!(ids.len(), candidates.len());
        assert!(ids.contains("h4-compass-8point-east-northeast"));
    }

    #[test]
    fn candidate_transforms_are_deterministic() {
        assert_eq!(
            transform_values("EAST", CandidateTransform::A1Z26ZeroBased),
            vec![4, 0, 18, 19]
        );
        assert_eq!(
            transform_values("EAST", CandidateTransform::A1Z26OneBased),
            vec![5, 1, 19, 20]
        );
        assert_eq!(
            transform_values("19891109", CandidateTransform::DecimalDigits),
            vec![1, 9, 8, 9, 1, 1, 0, 9]
        );
        assert_eq!(
            transform_values("EASTNORTHEAST", CandidateTransform::Compass8Point),
            vec![2, 1]
        );
        assert_eq!(
            transform_values("EASTNORTHEAST", CandidateTransform::Compass16Point),
            vec![4, 2]
        );
    }

    #[test]
    fn expanded_key_stream_matches_k4_length() {
        for candidate in candidate_sequences() {
            assert_eq!(candidate.expanded_to_k4.len(), K4_CIPHERTEXT.len());
        }
    }

    #[test]
    fn candidate_scores_never_promote_without_baseline() {
        let scores = score_candidate_sequences().unwrap();

        assert!(scores.iter().all(|score| !score.promoted_candidate));
    }
}
