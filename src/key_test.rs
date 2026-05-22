use crate::{
    AlphabetKind, CandidateTransform, FragmentMode, analyze_known_plaintext_spans,
    candidates::{expand_to_k4, transform_values},
};
use anyhow::{Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialTest {
    pub material: String,
    pub transform: CandidateTransform,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub values: Vec<u8>,
    pub expanded_to_k4: Vec<u8>,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub match_rate: f64,
    pub span_results: Vec<KeyMaterialSpanResult>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialOffsetSweep {
    pub material: String,
    pub transform: CandidateTransform,
    pub alphabet: AlphabetKind,
    pub fragment_mode: FragmentMode,
    pub values: Vec<u8>,
    pub offsets_tested: usize,
    pub results: Vec<KeyMaterialOffsetResult>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyMaterialOffsetResult {
    pub offset: usize,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub match_rate: f64,
    pub span_results: Vec<KeyMaterialSpanResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyMaterialSpanResult {
    pub target_label: String,
    pub compared_fragment_count: usize,
    pub exact_mod26_matches: usize,
    pub mismatches: Vec<KeyMaterialMismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyMaterialMismatch {
    pub position_one_based: usize,
    pub plaintext: char,
    pub ciphertext: char,
    pub observed_key_value: u8,
    pub observed_key_symbol: char,
    pub material_value: u8,
}

pub fn test_key_material(
    material: &str,
    transform: CandidateTransform,
    alphabet: AlphabetKind,
) -> Result<KeyMaterialTest> {
    let values = transform_values(material, transform);
    if values.is_empty() {
        bail!("key material did not produce any numeric values");
    }
    let expanded_to_k4 = expand_to_k4(&values);
    let result = score_key_material_with_offset(&expanded_to_k4, alphabet, 0)?;

    Ok(KeyMaterialTest {
        material: material.to_string(),
        transform,
        alphabet,
        fragment_mode: FragmentMode::AdditiveKey,
        values,
        expanded_to_k4,
        compared_fragment_count: result.compared_fragment_count,
        exact_mod26_matches: result.exact_mod26_matches,
        match_rate: result.match_rate,
        span_results: result.span_results,
        promoted_candidate: false,
        note: "Exploratory key-material check over public known-plaintext spans only; not evidence of plaintext or decryption.",
    })
}

pub fn sweep_key_material_offsets(
    material: &str,
    transform: CandidateTransform,
    alphabet: AlphabetKind,
) -> Result<KeyMaterialOffsetSweep> {
    let values = transform_values(material, transform);
    if values.is_empty() {
        bail!("key material did not produce any numeric values");
    }
    let expanded_to_k4 = expand_to_k4(&values);
    let mut results = Vec::with_capacity(values.len());

    for offset in 0..values.len() {
        results.push(score_key_material_with_offset(
            &expanded_to_k4,
            alphabet,
            offset,
        )?);
    }
    results.sort_by(|left, right| {
        right
            .exact_mod26_matches
            .cmp(&left.exact_mod26_matches)
            .then_with(|| left.offset.cmp(&right.offset))
    });

    Ok(KeyMaterialOffsetSweep {
        material: material.to_string(),
        transform,
        alphabet,
        fragment_mode: FragmentMode::AdditiveKey,
        values,
        offsets_tested: results.len(),
        results,
        promoted_candidate: false,
        note: "Exploratory offset sweep over public known-plaintext spans only; best offsets are not evidence of plaintext or decryption.",
    })
}

fn score_key_material_with_offset(
    expanded_to_k4: &[u8],
    alphabet: AlphabetKind,
    offset: usize,
) -> Result<KeyMaterialOffsetResult> {
    let mut span_results = Vec::new();

    for analysis in analyze_known_plaintext_spans()? {
        if analysis.alphabet.kind != alphabet {
            continue;
        }

        let mut exact_mod26_matches = 0usize;
        let mut compared_fragment_count = 0usize;
        let mut mismatches = Vec::new();
        for fragment in analysis
            .fragments
            .iter()
            .filter(|fragment| fragment.mode == FragmentMode::AdditiveKey)
        {
            compared_fragment_count += 1;
            let material_index = (fragment.position_zero_based + offset) % expanded_to_k4.len();
            let material_value = expanded_to_k4[material_index] % 26;
            if fragment.value == material_value {
                exact_mod26_matches += 1;
            } else {
                mismatches.push(KeyMaterialMismatch {
                    position_one_based: fragment.position_one_based,
                    plaintext: fragment.plaintext,
                    ciphertext: fragment.ciphertext,
                    observed_key_value: fragment.value,
                    observed_key_symbol: fragment.symbol,
                    material_value,
                });
            }
        }

        span_results.push(KeyMaterialSpanResult {
            target_label: analysis.target.label,
            compared_fragment_count,
            exact_mod26_matches,
            mismatches,
        });
    }

    let compared_fragment_count = span_results
        .iter()
        .map(|result| result.compared_fragment_count)
        .sum();
    let exact_mod26_matches = span_results
        .iter()
        .map(|result| result.exact_mod26_matches)
        .sum();
    let match_rate = if compared_fragment_count == 0 {
        0.0
    } else {
        exact_mod26_matches as f64 / compared_fragment_count as f64
    };

    Ok(KeyMaterialOffsetResult {
        offset,
        compared_fragment_count,
        exact_mod26_matches,
        match_rate,
        span_results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_material_scores_known_material_without_promotion() {
        let test = test_key_material(
            "BERLINWORLDCLOCK",
            CandidateTransform::A1Z26ZeroBased,
            AlphabetKind::Kryptos,
        )
        .unwrap();

        assert_eq!(test.expanded_to_k4.len(), crate::K4_CIPHERTEXT.len());
        assert_eq!(test.compared_fragment_count, 24);
        assert!(!test.promoted_candidate);
        assert!(
            test.span_results
                .iter()
                .any(|span| span.target_label == "BERLINCLOCK")
        );
    }

    #[test]
    fn empty_material_is_rejected() {
        assert!(
            test_key_material(
                "!!!",
                CandidateTransform::A1Z26ZeroBased,
                AlphabetKind::Kryptos
            )
            .is_err()
        );
    }

    #[test]
    fn sweep_scores_all_material_offsets_without_promotion() {
        let sweep = sweep_key_material_offsets(
            "BERLINWORLDCLOCK",
            CandidateTransform::A1Z26ZeroBased,
            AlphabetKind::Kryptos,
        )
        .unwrap();

        assert_eq!(sweep.offsets_tested, "BERLINWORLDCLOCK".len());
        assert_eq!(sweep.results.len(), sweep.offsets_tested);
        assert!(!sweep.promoted_candidate);
        assert!(
            sweep
                .results
                .windows(2)
                .all(|pair| pair[0].exact_mod26_matches >= pair[1].exact_mod26_matches)
        );
    }
}
