use super::{CliAlphabet, CliBaselineAlphabet, CliBaselineTarget, CliFragmentMode, OutputFormat};
use anyhow::Result;
use kryptos_k4::{
    AlphabetKind, FragmentMode, K4_CIPHERTEXT, analyze_constraints, analyze_known_plaintext_spans,
    candidate_sequences, findings, hypotheses, known_anchors, profile_k4_ciphertext, run_baseline,
    run_release_checks, run_route_experiments, score_candidate_sequences, sources,
};
use serde::Serialize;
use std::{fs, path::PathBuf};

pub(crate) fn print_facts(format: OutputFormat) -> Result<()> {
    let facts = serde_json::json!({
        "ciphertext_length": K4_CIPHERTEXT.len(),
        "ciphertext": K4_CIPHERTEXT,
        "evidence_boundary": "public anchors only; no claimed full plaintext",
        "promoted_candidate": false,
    });
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&facts)?),
        OutputFormat::Markdown => {
            println!("K4 ciphertext length: {}", K4_CIPHERTEXT.len());
            println!("K4 ciphertext: {K4_CIPHERTEXT}");
            println!("Evidence boundary: public anchors only; no claimed full plaintext.");
        }
    }

    Ok(())
}

pub(crate) fn print_ciphertext_profile(
    max_period: usize,
    max_ngram: usize,
    top: usize,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let profile = profile_k4_ciphertext(max_period, max_ngram, top, iterations, seed);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&profile)?),
        OutputFormat::Markdown => {
            println!("# K4 Ciphertext Profile\n");
            println!("This is not a claimed solution.\n");
            println!("ciphertext length: {}", profile.ciphertext_length);
            println!("index of coincidence: {:.4}", profile.index_of_coincidence);
            println!("promoted: {}", profile.promoted_candidate);
            println!("note: {}\n", profile.note);

            println!("## Letter Frequencies\n");
            println!("| Rank | Letter | Count | Rate |");
            println!("| --- | --- | --- | --- |");
            for (index, frequency) in profile.letter_frequencies.iter().enumerate() {
                println!(
                    "| {} | {} | {} | {:.4} |",
                    index + 1,
                    frequency.letter,
                    frequency.count,
                    frequency.rate
                );
            }
            println!();

            println!("## Repeated N-grams\n");
            if profile.repeated_ngrams.is_empty() {
                println!("none\n");
            } else {
                println!("| Rank | N-gram | Length | Count | Positions |");
                println!("| --- | --- | --- | --- | --- |");
                for (index, ngram) in profile.repeated_ngrams.iter().enumerate() {
                    let positions = ngram
                        .positions_one_based
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "| {} | `{}` | {} | {} | {} |",
                        index + 1,
                        ngram.ngram,
                        ngram.length,
                        ngram.count,
                        positions
                    );
                }
                println!();
            }

            println!("## Repeated N-gram Spacing Diagnostics\n");
            if profile.kasiski_factor_profiles.is_empty() {
                println!("none\n");
            } else {
                println!("| Period | Supported Gaps | Support Rate | Example Gaps |");
                println!("| --- | --- | --- | --- |");
                for factor_profile in &profile.kasiski_factor_profiles {
                    let example_gaps = if factor_profile.supporting_gaps.is_empty() {
                        "none".to_string()
                    } else {
                        factor_profile
                            .supporting_gaps
                            .iter()
                            .take(8)
                            .map(|support| {
                                format!(
                                    "`{}` {}-{} gap {}",
                                    support.ngram,
                                    support.left_position_one_based,
                                    support.right_position_one_based,
                                    support.gap
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    println!(
                        "| {} | {}/{} | {:.4} | {} |",
                        factor_profile.period,
                        factor_profile.supported_gap_count,
                        factor_profile.total_gap_count,
                        factor_profile.support_rate,
                        example_gaps
                    );
                }
                println!();
            }
            if let Some(kasiski_baseline) = &profile.kasiski_baseline {
                println!("## Repeated N-gram Spacing Baseline\n");
                println!(
                    "observed best period: {}; observed supported gaps: {}; null mean best supported gaps: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; promoted: {}",
                    kasiski_baseline.observed_best_period,
                    kasiski_baseline.observed_best_supported_gap_count,
                    kasiski_baseline.null_mean_best_supported_gap_count,
                    kasiski_baseline.null_std_dev_best_supported_gap_count,
                    kasiski_baseline.empirical_p_value,
                    kasiski_baseline.iterations,
                    kasiski_baseline.seed,
                    kasiski_baseline.promoted_candidate
                );
                println!("note: {}\n", kasiski_baseline.note);
            }

            println!("## Period Coincidence Diagnostics\n");
            println!("| Period | Shift Matches | Shift Rate | Mean Coset IC | Matched Pairs |");
            println!("| --- | --- | --- | --- | --- |");
            for period in &profile.period_profiles {
                let matched_pairs = if period.shifted_matches.is_empty() {
                    "none".to_string()
                } else {
                    period
                        .shifted_matches
                        .iter()
                        .map(|shifted_match| {
                            format!(
                                "{}-{} {}",
                                shifted_match.left_position_one_based,
                                shifted_match.right_position_one_based,
                                shifted_match.letter
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                println!(
                    "| {} | {}/{} | {:.4} | {:.4} | {} |",
                    period.period,
                    period.shifted_match_count,
                    period.shifted_comparison_count,
                    period.shifted_match_rate,
                    period.mean_coset_ic,
                    matched_pairs
                );
            }
            if let Some(baseline) = &profile.baseline {
                println!();
                println!("## Ciphertext-Only Baseline\n");
                println!(
                    "observed best period: {}; observed best shifted rate: {:.4}; null mean best shifted rate: {:.4}; null sd: {:.4}; empirical p-value: {:.4}; iterations: {}; seed: {}; promoted: {}",
                    baseline.observed_best_period,
                    baseline.observed_best_shifted_match_rate,
                    baseline.null_mean_best_shifted_match_rate,
                    baseline.null_std_dev_best_shifted_match_rate,
                    baseline.empirical_p_value,
                    baseline.iterations,
                    baseline.seed,
                    baseline.promoted_candidate
                );
                println!("note: {}", baseline.note);
            }
        }
    }

    Ok(())
}

pub(crate) fn print_anchors(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&known_anchors())?),
        OutputFormat::Markdown => {
            for anchor in known_anchors() {
                println!(
                    "{} => {} | 0-based {}-{} | 1-based {}-{} | sources: {} | confidence: {}",
                    anchor.ciphertext,
                    anchor.plaintext,
                    anchor.start_zero_based,
                    anchor.end_zero_based_inclusive,
                    anchor.start_one_based(),
                    anchor.end_one_based_inclusive(),
                    anchor.source_ids.join(","),
                    anchor.confidence
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn print_constraints(spans: bool, format: OutputFormat) -> Result<()> {
    let analyses = if spans {
        analyze_known_plaintext_spans()?
    } else {
        analyze_constraints()?
    };

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&analyses)?),
        OutputFormat::Markdown => {
            for analysis in analyses {
                println!("{} / {:?}", analysis.target.label, analysis.alphabet.kind);
                for fragment in analysis.fragments {
                    println!(
                        "  pos {:>2}: {}->{} {:?} value {:>2} symbol {}",
                        fragment.position_one_based,
                        fragment.plaintext,
                        fragment.ciphertext,
                        fragment.mode,
                        fragment.value,
                        fragment.symbol
                    );
                }
                println!(
                    "  recurrence: {}/{} generic mod-10 triples matched; expected random {:.1}; promoted: {}; warning: {}",
                    analysis.recurrence.gromark_sum_matches,
                    analysis.recurrence.contiguous_pairs_checked,
                    analysis.recurrence.expected_random_matches,
                    analysis.recurrence.promoted_candidate,
                    analysis.recurrence.sample_warning
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub(crate) struct KeyFragmentRow {
    target_kind: &'static str,
    target_label: String,
    alphabet: AlphabetKind,
    position_zero_based: usize,
    position_one_based: usize,
    plaintext: char,
    ciphertext: char,
    mode: FragmentMode,
    value: u8,
    symbol: char,
    promoted_candidate: bool,
}

pub(crate) fn print_key_fragments(
    anchor: Option<String>,
    span: Option<String>,
    alphabet: Option<CliAlphabet>,
    mode: Option<CliFragmentMode>,
    format: OutputFormat,
) -> Result<()> {
    let alphabet_filter = alphabet.map(AlphabetKind::from);
    let mode_filter = mode.map(FragmentMode::from);
    let (analyses, filter_kind, target_filter) = if let Some(anchor) = anchor {
        (
            analyze_constraints()?,
            "anchor",
            Some(anchor.to_ascii_uppercase()),
        )
    } else if let Some(span) = span {
        (
            analyze_known_plaintext_spans()?,
            "span",
            Some(span.to_ascii_uppercase()),
        )
    } else {
        let mut all = analyze_constraints()?;
        all.extend(analyze_known_plaintext_spans()?);
        (all, "target", None)
    };

    let mut rows = Vec::new();
    for analysis in analyses {
        if target_filter
            .as_ref()
            .is_some_and(|filter| analysis.target.label != *filter)
        {
            continue;
        }
        if alphabet_filter.is_some_and(|filter| analysis.alphabet.kind != filter) {
            continue;
        }

        let target_kind = match analysis.target.kind {
            kryptos_k4::AnalysisTargetKind::Anchor => "anchor",
            kryptos_k4::AnalysisTargetKind::Span => "span",
        };

        for fragment in analysis.fragments {
            if mode_filter.is_some_and(|filter| fragment.mode != filter) {
                continue;
            }

            let row = KeyFragmentRow {
                target_kind,
                target_label: analysis.target.label.clone(),
                alphabet: analysis.alphabet.kind,
                position_zero_based: fragment.position_zero_based,
                position_one_based: fragment.position_one_based,
                plaintext: fragment.plaintext,
                ciphertext: fragment.ciphertext,
                mode: fragment.mode,
                value: fragment.value,
                symbol: fragment.symbol,
                promoted_candidate: false,
            };
            rows.push(row);
        }
    }

    if rows.is_empty() {
        anyhow::bail!("no key-fragment rows matched the requested {filter_kind} filters");
    }

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
        OutputFormat::Markdown => {
            for row in rows {
                println!(
                    "{} {} / {:?} | pos {} | {}->{} | {:?} | value {} | symbol {}",
                    row.target_kind,
                    row.target_label,
                    row.alphabet,
                    row.position_one_based,
                    row.plaintext,
                    row.ciphertext,
                    row.mode,
                    row.value,
                    row.symbol
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn print_baseline(
    target: CliBaselineTarget,
    alphabet: CliBaselineAlphabet,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let run = run_baseline(target.into(), alphabet.into(), iterations, seed)?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
        OutputFormat::Markdown => {
            println!("# Kryptos K4 Baseline Report\n");
            println!("This is not a claimed solution.\n");
            println!(
                "Target: {}; alphabet: {}; iterations: {}; seed: {}\n",
                run.target_scope, run.alphabet_scope, run.iterations, run.seed
            );
            println!(
                "| Target | Kind | Alphabet | Observed | Triples | Null mean | Null sd | Empirical p-value | Adjusted p-value | Promoted | Warning |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for result in run.results {
                println!(
                    "| {} | {} | {:?} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} | {} |",
                    result.target_label,
                    result.target_kind,
                    result.alphabet,
                    result.observed_matches,
                    result.triples_checked,
                    result.null_mean,
                    result.null_std_dev,
                    result.empirical_p_value,
                    result.adjusted_p_value,
                    result.promoted_candidate,
                    result.warning
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn print_hypotheses(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&hypotheses())?),
        OutputFormat::Markdown => {
            for hypothesis in hypotheses() {
                println!(
                    "{}. {} ({})\n   test: {}\n   risk: {}",
                    hypothesis.priority,
                    hypothesis.name,
                    hypothesis.id,
                    hypothesis.falsification_test,
                    hypothesis.risk
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn print_candidate_sequences(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "candidate_sequences": candidate_sequences(),
                "scores": score_candidate_sequences()?,
                "note": "Pre-registered contextual candidates only; not a claimed solution."
            }))?
        ),
        OutputFormat::Markdown => {
            println!("# Candidate Sequences\n");
            println!("Pre-registered contextual candidates only; not a claimed solution.\n");
            for candidate in candidate_sequences() {
                println!(
                    "- `{}` {:?} {:?}: `{}` values={:?} promoted=false",
                    candidate.id,
                    candidate.family,
                    candidate.transform,
                    candidate.raw_material,
                    candidate.values
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn print_routes(format: OutputFormat) -> Result<()> {
    let experiments = run_route_experiments()?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&experiments)?),
        OutputFormat::Markdown => {
            println!("# Route Experiments\n");
            println!(
                "Exploratory route screen only; not a claimed solution and no decryption text is emitted.\n"
            );
            for experiment in experiments {
                println!(
                    "- {:?} / {}: score={} identity_baseline={} reverse_baseline={} seeded_random_baseline={} promoted={}",
                    experiment.route,
                    experiment.target_label,
                    experiment.score,
                    experiment.identity_baseline,
                    experiment.reverse_baseline,
                    experiment.seeded_random_baseline,
                    experiment.promoted_candidate
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn print_findings(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&findings())?),
        OutputFormat::Markdown => {
            println!("# Findings Ledger\n");
            println!(
                "Every finding is tied to public source inputs, transformation steps, baseline context, and a next test. This is not a claimed solution.\n"
            );
            for finding in findings() {
                println!(
                    "- {} {} ({})\n  sources: {}\n  output: {}\n  baseline: {}\n  interpretation: {}\n  next test: {}\n  promoted: {}",
                    finding.id,
                    finding.title,
                    finding.related_hypothesis,
                    finding.source_inputs.join(","),
                    finding.output_summary,
                    finding.baseline_comparison,
                    finding.interpretation,
                    finding.next_test,
                    finding.promoted_candidate
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn print_sources(format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&sources())?),
        OutputFormat::Markdown => {
            for source in sources() {
                println!(
                    "{} ({}): {}\n  accessed {} | use: {}\n  {}",
                    source.label,
                    source.id,
                    source.url,
                    source.accessed_at,
                    source.allowed_use,
                    source.use_note
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn print_release_check(format: OutputFormat) -> Result<()> {
    let checks = run_release_checks(std::env::current_dir()?)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&checks)?),
        OutputFormat::Markdown => {
            println!("# Release Check\n");
            println!("Local preflight only. This repo does not use GitHub Actions.\n");
            for check in checks {
                println!("- {}: {} ({})", check.name, check.passed, check.detail);
            }
        }
    }
    Ok(())
}

pub(crate) fn export_data(directory: PathBuf) -> Result<()> {
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join("k4-ciphertext.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "ciphertext": K4_CIPHERTEXT,
            "length": K4_CIPHERTEXT.len(),
            "evidence_boundary": "public ciphertext only; no claimed full plaintext"
        }))?,
    )?;
    fs::write(
        directory.join("k4-known-anchors.json"),
        serde_json::to_string_pretty(&known_anchors())?,
    )?;
    fs::write(
        directory.join("k4-sources.json"),
        serde_json::to_string_pretty(&sources())?,
    )?;

    println!("Exported K4 data files to {}", directory.display());
    Ok(())
}
