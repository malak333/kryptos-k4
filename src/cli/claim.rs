use super::{CliAlphabet, OutputFormat};
use anyhow::{Context, Result, bail};
use kryptos_k4::{
    PlaintextClaimVerification, RunningKeyClaimVerification, sources, verify_plaintext_claim,
    verify_running_key_claim,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(crate) fn print_verify_claim(
    plaintext: PathBuf,
    key: Option<PathBuf>,
    alphabet: CliAlphabet,
    source_id: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    ensure_quarantined_claim_source(source_id.as_deref(), "verify-claim")?;

    let plaintext_claim = fs::read_to_string(&plaintext)
        .with_context(|| format!("failed to read plaintext claim `{}`", plaintext.display()))?;

    let Some(key) = key else {
        let verification = verify_plaintext_claim(&plaintext_claim, source_id)?;
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
            OutputFormat::Markdown => print_plaintext_claim_verification(&plaintext, &verification),
        }
        return Ok(());
    };

    let key_stream = fs::read_to_string(&key)
        .with_context(|| format!("failed to read running-key stream `{}`", key.display()))?;
    let verification =
        verify_running_key_claim(&plaintext_claim, &key_stream, alphabet.into(), source_id)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
        OutputFormat::Markdown => {
            print_running_key_claim_verification(&plaintext, &key, &verification)
        }
    }
    Ok(())
}

pub(crate) fn ensure_quarantined_claim_source(
    source_id: Option<&str>,
    command_name: &str,
) -> Result<()> {
    if let Some(source_id) = source_id {
        let source = sources()
            .into_iter()
            .find(|source| source.id == source_id)
            .with_context(|| format!("unknown source id `{source_id}`"))?;
        if source.allowed_use != "unverified-solution-claim" {
            bail!(
                "source-id `{}` has allowed_use `{}`; {command_name} requires allowed_use `unverified-solution-claim`",
                source.id,
                source.allowed_use
            );
        }
    }
    Ok(())
}

pub(crate) fn print_plaintext_claim_verification(
    input: &Path,
    verification: &PlaintextClaimVerification,
) {
    println!("# Plaintext Claim Verification\n");
    println!("This is not a claimed solution.\n");
    println!("input: `{}`", input.display());
    println!(
        "source id: `{}`",
        verification.source_id.as_deref().unwrap_or("none")
    );
    println!("raw characters: {}", verification.raw_character_count);
    println!(
        "normalized letters: {}/{}",
        verification.normalized_letter_count, verification.expected_length
    );
    println!(
        "ignored non-letters: {}",
        verification.ignored_non_letter_count
    );
    println!("length matches: {}", verification.length_matches);
    println!(
        "public anchors: {}/{}",
        verification.public_anchor_match_count, verification.public_anchor_count
    );
    println!(
        "all public anchors match: {}",
        verification.all_public_anchors_match
    );
    println!(
        "implied shift diagnostics: distinct_values={} repeated_values={} max_bucket={}",
        verification.implied_shift_distinct_values,
        verification.implied_shift_repeated_value_count,
        verification.implied_shift_max_bucket_count
    );
    println!(
        "structural checks passed: {}",
        verification.structural_checks_passed
    );
    println!("promoted: {}", verification.promoted_candidate);
    println!("note: {}\n", verification.note);

    println!("| Anchor | Positions | Matches |");
    println!("| --- | --- | --- |");
    for check in &verification.anchor_checks {
        println!(
            "| {} | {}-{} | {} |",
            check.plaintext, check.start_one_based, check.end_one_based_inclusive, check.matches
        );
    }
}

pub(crate) fn print_running_key_claim_verification(
    plaintext: &Path,
    key: &Path,
    verification: &RunningKeyClaimVerification,
) {
    println!("# Running-Key Claim Verification\n");
    println!("This is not a claimed solution.\n");
    println!("plaintext input: `{}`", plaintext.display());
    println!("key input: `{}`", key.display());
    println!(
        "source id: `{}`",
        verification.source_id.as_deref().unwrap_or("none")
    );
    println!("alphabet: {:?}", verification.alphabet);
    println!(
        "plaintext normalized letters: {}/{}",
        verification.plaintext_normalized_letter_count, verification.expected_length
    );
    println!(
        "plaintext ignored non-letters: {}",
        verification.plaintext_ignored_non_letter_count
    );
    println!(
        "key normalized letters: {}/{}",
        verification.key_normalized_letter_count, verification.expected_length
    );
    println!(
        "key ignored non-letters: {}",
        verification.key_ignored_non_letter_count
    );
    println!(
        "public anchors: {}/{}",
        verification.public_anchor_match_count, verification.public_anchor_count
    );
    println!(
        "all public anchors match: {}",
        verification.all_public_anchors_match
    );
    println!(
        "ciphertext reconstruction: {}/{}",
        verification.ciphertext_match_count, verification.ciphertext_checked_count
    );
    println!(
        "all ciphertext matches: {}",
        verification.all_ciphertext_matches
    );
    if verification.mismatch_positions_one_based.is_empty() {
        println!("mismatch positions: none");
    } else {
        let positions = verification
            .mismatch_positions_one_based
            .iter()
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("mismatch positions: {positions}");
    }
    println!(
        "key diagnostics: distinct_values={} repeated_values={} max_bucket={}",
        verification.key_distinct_values,
        verification.key_repeated_value_count,
        verification.key_max_bucket_count
    );
    println!(
        "structural checks passed: {}",
        verification.structural_checks_passed
    );
    println!("promoted: {}", verification.promoted_candidate);
    println!("note: {}\n", verification.note);

    println!("| Anchor | Positions | Matches |");
    println!("| --- | --- | --- |");
    for check in &verification.anchor_checks {
        println!(
            "| {} | {}-{} | {} |",
            check.plaintext, check.start_one_based, check.end_one_based_inclusive, check.matches
        );
    }
}
