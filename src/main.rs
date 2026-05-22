use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use kryptos_k4::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, CandidateTransform, FragmentMode,
    K4_CIPHERTEXT, KeyMaterialTest, ReportFormat, analyze_constraints,
    analyze_known_plaintext_spans, build_report, candidate_sequences, findings, hypotheses,
    known_anchors, render_report, run_baseline, run_release_checks, run_route_experiments,
    score_candidate_sequences, sources, test_key_material,
};
use std::{fs, path::PathBuf};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print core public K4 facts and evidence boundary.
    Facts,
    /// Print public known-plaintext anchors with positions and source IDs.
    Anchors,
    /// Print derived constraint fragments for anchors or adjacent spans.
    Constraints {
        /// Analyze merged adjacent known-plaintext spans instead of individual anchors.
        #[arg(long)]
        spans: bool,
    },
    /// Print one row per derived key fragment, with optional filters.
    KeyFragments {
        /// Filter by individual anchor label, for example BERLIN.
        #[arg(long, conflicts_with = "span")]
        anchor: Option<String>,
        /// Filter by adjacent known-plaintext span label, for example BERLINCLOCK.
        #[arg(long, conflicts_with = "anchor")]
        span: Option<String>,
        /// Filter by alphabet.
        #[arg(long, value_enum)]
        alphabet: Option<CliAlphabet>,
        /// Filter by derivation mode.
        #[arg(long, value_enum)]
        mode: Option<CliFragmentMode>,
    },
    /// Test proposed key material against public span-derived additive fragments.
    TestKey {
        /// Proposed key material to transform and cycle across K4 positions.
        #[arg(long)]
        material: String,
        /// Transform used to convert material into numeric values.
        #[arg(long, value_enum, default_value_t = CliCandidateTransform::A1Z26ZeroBased)]
        transform: CliCandidateTransform,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Run deterministic false-positive controls for the generic recurrence screen.
    Baseline {
        /// Target family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineTarget::Spans)]
        target: CliBaselineTarget,
        /// Alphabet family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineAlphabet::All)]
        alphabet: CliBaselineAlphabet,
        /// Number of seeded null iterations.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print ranked source-grounded hypotheses.
    Hypotheses,
    /// Print pre-registered contextual candidate sequences.
    CandidateSequences {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print bounded named route experiments over public fragments.
    Routes {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print the current findings ledger with evidence, baselines, and next tests.
    Findings {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print source provenance records.
    Sources,
    /// Run local release preflight checks. Does not use GitHub Actions.
    ReleaseCheck {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Render the full research report.
    Report {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
        /// Optional output path. Prints to stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Write machine-readable ciphertext, anchor, and source JSON files.
    ExportData {
        /// Directory where JSON data files should be written.
        #[arg(long, default_value = "data")]
        directory: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Markdown,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliAlphabet {
    Standard,
    Kryptos,
    KryptosReversed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliFragmentMode {
    #[value(name = "additive-key")]
    Additive,
    #[value(name = "subtractive-key")]
    Subtractive,
    #[value(name = "beaufort-key")]
    Beaufort,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliBaselineTarget {
    Anchors,
    Spans,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliBaselineAlphabet {
    Standard,
    Kryptos,
    KryptosReversed,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliCandidateTransform {
    #[value(name = "a1-z26-zero-based")]
    A1Z26ZeroBased,
    #[value(name = "a1-z26-one-based")]
    A1Z26OneBased,
    #[value(name = "decimal-digits")]
    DecimalDigits,
    #[value(name = "compass8-point")]
    Compass8Point,
    #[value(name = "compass16-point")]
    Compass16Point,
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Markdown => ReportFormat::Markdown,
            OutputFormat::Json => ReportFormat::Json,
        }
    }
}

impl From<CliAlphabet> for AlphabetKind {
    fn from(value: CliAlphabet) -> Self {
        match value {
            CliAlphabet::Standard => AlphabetKind::Standard,
            CliAlphabet::Kryptos => AlphabetKind::Kryptos,
            CliAlphabet::KryptosReversed => AlphabetKind::KryptosReversed,
        }
    }
}

impl From<CliFragmentMode> for FragmentMode {
    fn from(value: CliFragmentMode) -> Self {
        match value {
            CliFragmentMode::Additive => FragmentMode::AdditiveKey,
            CliFragmentMode::Subtractive => FragmentMode::SubtractiveKey,
            CliFragmentMode::Beaufort => FragmentMode::BeaufortKey,
        }
    }
}

impl From<CliBaselineTarget> for BaselineTargetScope {
    fn from(value: CliBaselineTarget) -> Self {
        match value {
            CliBaselineTarget::Anchors => BaselineTargetScope::Anchors,
            CliBaselineTarget::Spans => BaselineTargetScope::Spans,
            CliBaselineTarget::All => BaselineTargetScope::All,
        }
    }
}

impl From<CliBaselineAlphabet> for BaselineAlphabetScope {
    fn from(value: CliBaselineAlphabet) -> Self {
        match value {
            CliBaselineAlphabet::Standard => BaselineAlphabetScope::Standard,
            CliBaselineAlphabet::Kryptos => BaselineAlphabetScope::Kryptos,
            CliBaselineAlphabet::KryptosReversed => BaselineAlphabetScope::KryptosReversed,
            CliBaselineAlphabet::All => BaselineAlphabetScope::All,
        }
    }
}

impl From<CliCandidateTransform> for CandidateTransform {
    fn from(value: CliCandidateTransform) -> Self {
        match value {
            CliCandidateTransform::A1Z26ZeroBased => CandidateTransform::A1Z26ZeroBased,
            CliCandidateTransform::A1Z26OneBased => CandidateTransform::A1Z26OneBased,
            CliCandidateTransform::DecimalDigits => CandidateTransform::DecimalDigits,
            CliCandidateTransform::Compass8Point => CandidateTransform::Compass8Point,
            CliCandidateTransform::Compass16Point => CandidateTransform::Compass16Point,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Facts => print_facts(),
        Command::Anchors => print_anchors(),
        Command::Constraints { spans } => print_constraints(spans)?,
        Command::KeyFragments {
            anchor,
            span,
            alphabet,
            mode,
        } => print_key_fragments(anchor, span, alphabet, mode)?,
        Command::TestKey {
            material,
            transform,
            alphabet,
            format,
        } => print_test_key(material, transform, alphabet, format)?,
        Command::Baseline {
            target,
            alphabet,
            iterations,
            seed,
            format,
        } => print_baseline(target, alphabet, iterations, seed, format)?,
        Command::Hypotheses => print_hypotheses(),
        Command::CandidateSequences { format } => print_candidate_sequences(format)?,
        Command::Routes { format } => print_routes(format)?,
        Command::Findings { format } => print_findings(format)?,
        Command::Sources => print_sources(),
        Command::ReleaseCheck { format } => print_release_check(format)?,
        Command::ExportData { directory } => export_data(directory)?,
        Command::Report { format, output } => {
            let report = build_report()?;
            let rendered = render_report(&report, format.into())?;
            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, rendered)?;
            } else {
                print!("{rendered}");
            }
        }
    }

    Ok(())
}

fn print_test_key(
    material: String,
    transform: CliCandidateTransform,
    alphabet: CliAlphabet,
    format: OutputFormat,
) -> Result<()> {
    let test = test_key_material(&material, transform.into(), alphabet.into())?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&test)?),
        OutputFormat::Markdown => print_key_material_test(&test),
    }

    Ok(())
}

fn print_key_material_test(test: &KeyMaterialTest) {
    println!("# Key Material Test\n");
    println!("This is not a claimed solution.\n");
    println!("material: `{}`", test.material);
    println!("transform: {:?}", test.transform);
    println!("alphabet: {:?}", test.alphabet);
    println!("fragment mode: {:?}", test.fragment_mode);
    println!(
        "matches: {}/{} ({:.4})",
        test.exact_mod26_matches, test.compared_fragment_count, test.match_rate
    );
    println!("promoted: {}", test.promoted_candidate);
    println!("note: {}\n", test.note);

    for span in &test.span_results {
        println!(
            "## {}: {}/{} exact mod-26 matches",
            span.target_label, span.exact_mod26_matches, span.compared_fragment_count
        );
        if span.mismatches.is_empty() {
            println!("all compared public fragments matched");
        } else {
            for mismatch in &span.mismatches {
                println!(
                    "- pos {} | {}->{} | observed {} ({}) | material {}",
                    mismatch.position_one_based,
                    mismatch.plaintext,
                    mismatch.ciphertext,
                    mismatch.observed_key_value,
                    mismatch.observed_key_symbol,
                    mismatch.material_value
                );
            }
        }
        println!();
    }
}

fn print_facts() {
    println!("K4 ciphertext length: {}", K4_CIPHERTEXT.len());
    println!("K4 ciphertext: {K4_CIPHERTEXT}");
    println!("Evidence boundary: public anchors only; no claimed full plaintext.");
}

fn print_anchors() {
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

fn print_constraints(spans: bool) -> Result<()> {
    let analyses = if spans {
        analyze_known_plaintext_spans()?
    } else {
        analyze_constraints()?
    };

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
    Ok(())
}

fn print_key_fragments(
    anchor: Option<String>,
    span: Option<String>,
    alphabet: Option<CliAlphabet>,
    mode: Option<CliFragmentMode>,
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

    let mut rows_printed = 0usize;
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

            rows_printed += 1;
            println!(
                "{} {} / {:?} | pos {} | {}->{} | {:?} | value {} | symbol {}",
                target_kind,
                analysis.target.label,
                analysis.alphabet.kind,
                fragment.position_one_based,
                fragment.plaintext,
                fragment.ciphertext,
                fragment.mode,
                fragment.value,
                fragment.symbol
            );
        }
    }

    if rows_printed == 0 {
        anyhow::bail!("no key-fragment rows matched the requested {filter_kind} filters");
    }

    Ok(())
}

fn print_baseline(
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

fn print_hypotheses() {
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

fn print_candidate_sequences(format: OutputFormat) -> Result<()> {
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

fn print_routes(format: OutputFormat) -> Result<()> {
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

fn print_findings(format: OutputFormat) -> Result<()> {
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

fn print_sources() {
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

fn print_release_check(format: OutputFormat) -> Result<()> {
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

fn export_data(directory: PathBuf) -> Result<()> {
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
