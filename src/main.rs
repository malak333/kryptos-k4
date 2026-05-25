use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use kryptos_k4::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, BatchKeyMaterialCandidate,
    BatchKeyMaterialRun, BatchKeyRunHistory, CandidateTransform, FragmentMode,
    HeldoutKeyControlRun, K4_CIPHERTEXT, KeyMaterialExplanation, KeyMaterialOffsetSweep,
    KeyMaterialTest, PositionStructureRun, ReportFormat, RoutedBatchKeyMaterialRun,
    StructuralModelRun, analyze_constraints, analyze_known_plaintext_spans,
    batch_test_key_material_with_batch_baseline, batch_test_routed_key_material, build_report,
    candidate_sequences, explain_key_material, findings, heldout_key_control, hypotheses,
    known_anchors, render_report, run_baseline, run_position_structure_control, run_release_checks,
    run_route_experiments, run_structural_model_control, score_candidate_sequences, sources,
    summarize_batch_key_material_runs, sweep_key_material_offsets_with_baseline, test_key_material,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

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
        /// Try every cyclic phase offset and rank the resulting matches.
        #[arg(long)]
        sweep_offsets: bool,
        /// Maximum ranked offsets to print when sweeping. JSON output always includes all offsets.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Seeded shuffled-value null iterations for the best offset score. Requires --sweep-offsets.
        #[arg(long, default_value_t = 0)]
        sweep_baseline_iterations: usize,
        /// Seed for deterministic offset-sweep baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Explain one key-material lead by printing exact matching public-span positions.
    ExplainKey {
        /// Proposed key material to transform and cycle across K4 positions.
        #[arg(long)]
        material: String,
        /// Transform used to convert material into numeric values.
        #[arg(long, value_enum, default_value_t = CliCandidateTransform::A1Z26ZeroBased)]
        transform: CliCandidateTransform,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Cyclic phase offset to explain. If omitted, the best-scoring offset is used.
        #[arg(long)]
        offset: Option<usize>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Run key-material checks for every candidate row in a CSV file.
    BatchTestKeys {
        /// CSV file with rows: material,transform. Header row is optional.
        #[arg(long)]
        input: PathBuf,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Seeded shuffled-value null iterations for each candidate's best offset.
        #[arg(long, default_value_t = 1_000)]
        sweep_baseline_iterations: usize,
        /// Seeded null iterations for the best score across all candidate rows and transforms.
        #[arg(long, default_value_t = 0)]
        batch_baseline_iterations: usize,
        /// Seed for deterministic offset-sweep baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for input.csv, results.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format for stdout.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Apply registered route/permutation families before scoring every candidate row in a CSV file.
    BatchTestRoutedKeys {
        /// CSV file with rows: material,transform. Header row is optional.
        #[arg(long)]
        input: PathBuf,
        /// Alphabet used for public span-derived fragments.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Seeded shuffled-value null iterations for each routed candidate's best offset.
        #[arg(long, default_value_t = 1_000)]
        sweep_baseline_iterations: usize,
        /// Seeded null iterations for the best score across all candidate rows, transforms, spans, and routes.
        #[arg(long, default_value_t = 0)]
        batch_baseline_iterations: usize,
        /// Seed for deterministic routed offset-sweep baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for input.csv, results.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format for stdout.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Select on non-overlapping public fragment groups, then score each held-out group.
    HeldoutKeyControl {
        /// CSV file with rows: material,transform. Header row is optional.
        #[arg(long)]
        input: PathBuf,
        /// Alphabet used for public fragment groups.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Kryptos)]
        alphabet: CliAlphabet,
        /// Seeded null iterations that re-run training selection before scoring each held-out group.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Seed for deterministic held-out null controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Optional directory for input.csv, results.json, summary.md, and command.txt.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output format for stdout.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Summarize historical batch-test result folders.
    SummarizeKeyRuns {
        /// Directory to scan recursively for results.json files.
        #[arg(long)]
        input_dir: PathBuf,
        /// Maximum individual result rows to print.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output format for stdout.
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
    /// Test candidate-independent residue and spacing structure over public fragments.
    PositionStructure {
        /// Target family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineTarget::Spans)]
        target: CliBaselineTarget,
        /// Alphabet family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineAlphabet::All)]
        alphabet: CliBaselineAlphabet,
        /// Public fragment mode to evaluate.
        #[arg(long, value_enum, default_value_t = CliFragmentMode::Additive)]
        mode: CliFragmentMode,
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
    /// Evaluate pre-registered position models before considering new key material.
    StructuralModels {
        /// Target family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineTarget::Spans)]
        target: CliBaselineTarget,
        /// Alphabet family to evaluate.
        #[arg(long, value_enum, default_value_t = CliBaselineAlphabet::All)]
        alphabet: CliBaselineAlphabet,
        /// Public fragment mode to evaluate.
        #[arg(long, value_enum, default_value_t = CliFragmentMode::Additive)]
        mode: CliFragmentMode,
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

struct TestKeyOptions {
    material: String,
    transform: CliCandidateTransform,
    alphabet: CliAlphabet,
    sweep_offsets: bool,
    top: usize,
    sweep_baseline_iterations: usize,
    seed: u64,
    format: OutputFormat,
}

struct ExplainKeyOptions {
    material: String,
    transform: CliCandidateTransform,
    alphabet: CliAlphabet,
    offset: Option<usize>,
    format: OutputFormat,
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
            sweep_offsets,
            top,
            sweep_baseline_iterations,
            seed,
            format,
        } => print_test_key(TestKeyOptions {
            material,
            transform,
            alphabet,
            sweep_offsets,
            top,
            sweep_baseline_iterations,
            seed,
            format,
        })?,
        Command::ExplainKey {
            material,
            transform,
            alphabet,
            offset,
            format,
        } => print_explain_key(ExplainKeyOptions {
            material,
            transform,
            alphabet,
            offset,
            format,
        })?,
        Command::BatchTestKeys {
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        } => print_batch_test_keys(
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        )?,
        Command::BatchTestRoutedKeys {
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        } => print_batch_test_routed_keys(
            input,
            alphabet,
            sweep_baseline_iterations,
            batch_baseline_iterations,
            seed,
            output_dir,
            format,
        )?,
        Command::HeldoutKeyControl {
            input,
            alphabet,
            iterations,
            seed,
            output_dir,
            format,
        } => print_heldout_key_control(input, alphabet, iterations, seed, output_dir, format)?,
        Command::SummarizeKeyRuns {
            input_dir,
            top,
            format,
        } => print_summarize_key_runs(input_dir, top, format)?,
        Command::Baseline {
            target,
            alphabet,
            iterations,
            seed,
            format,
        } => print_baseline(target, alphabet, iterations, seed, format)?,
        Command::PositionStructure {
            target,
            alphabet,
            mode,
            iterations,
            seed,
            format,
        } => print_position_structure(target, alphabet, mode, iterations, seed, format)?,
        Command::StructuralModels {
            target,
            alphabet,
            mode,
            iterations,
            seed,
            format,
        } => print_structural_models(target, alphabet, mode, iterations, seed, format)?,
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

fn print_summarize_key_runs(input_dir: PathBuf, top: usize, format: OutputFormat) -> Result<()> {
    let history = summarize_batch_key_material_runs(&input_dir, top)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&history)?),
        OutputFormat::Markdown => print_batch_key_run_history(&history),
    }
    Ok(())
}

fn print_batch_key_run_history(history: &BatchKeyRunHistory) {
    println!("# Batch Key Run History\n");
    println!("This is not a claimed solution.\n");
    println!("input dir: `{}`", history.input_dir);
    println!("result files: {}", history.scanned_result_files);
    println!("candidate result rows: {}", history.candidate_result_count);
    println!("promoted: {}", history.promoted_candidate);
    println!("note: {}\n", history.note);

    println!("## Best Individual Results\n");
    println!(
        "| Rank | Material | Transform | Seed | Offset | Matches | Match Rate | Empirical P | Results | Promoted |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for (index, result) in history.top_results.iter().enumerate() {
        println!(
            "| {} | `{}` | {:?} | {} | {} | {}/{} | {:.4} | {} | `{}` | {} |",
            index + 1,
            result.material,
            result.transform,
            result.seed,
            result.best_offset,
            result.best_matches,
            result.compared_fragment_count,
            result.best_match_rate,
            format_optional_p(result.empirical_p_value),
            result.run_dir,
            result.promoted_candidate
        );
    }

    println!("\n## Candidate Stability\n");
    println!(
        "| Rank | Material | Transform | Runs | Best P | Mean P | Worst P | Best Matches | Best Seed | Best Offset | Promoted |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for (index, summary) in history.candidate_summaries.iter().enumerate() {
        println!(
            "| {} | `{}` | {:?} | {} | {} | {} | {} | {} | {} | {} | {} |",
            index + 1,
            summary.material,
            summary.transform,
            summary.run_count,
            format_optional_p(summary.best_empirical_p_value),
            format_optional_p(summary.mean_empirical_p_value),
            format_optional_p(summary.worst_empirical_p_value),
            summary.best_matches,
            summary.best_seed,
            summary.best_offset,
            summary.promoted_candidate
        );
    }
}

fn format_optional_p(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.4}"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn print_batch_test_keys(
    input: PathBuf,
    alphabet: CliAlphabet,
    baseline_iterations: usize,
    batch_baseline_iterations: usize,
    seed: u64,
    output_dir: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let input_text = fs::read_to_string(&input)?;
    let candidates = parse_batch_candidates(&input_text)?;
    let run = batch_test_key_material_with_batch_baseline(
        &candidates,
        alphabet.into(),
        baseline_iterations,
        seed,
        batch_baseline_iterations,
    )?;

    if let Some(output_dir) = output_dir {
        write_batch_outputs(&output_dir, &input_text, &run)?;
        println!(
            "Wrote batch key-material results to {}",
            output_dir.display()
        );
    } else {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
            OutputFormat::Markdown => print_batch_key_material_summary(&run),
        }
    }

    Ok(())
}

fn print_batch_test_routed_keys(
    input: PathBuf,
    alphabet: CliAlphabet,
    baseline_iterations: usize,
    batch_baseline_iterations: usize,
    seed: u64,
    output_dir: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let input_text = fs::read_to_string(&input)?;
    let candidates = parse_batch_candidates(&input_text)?;
    let run = batch_test_routed_key_material(
        &candidates,
        alphabet.into(),
        baseline_iterations,
        seed,
        batch_baseline_iterations,
    )?;

    if let Some(output_dir) = output_dir {
        write_routed_batch_outputs(&output_dir, &input_text, &run)?;
        println!(
            "Wrote routed batch key-material results to {}",
            output_dir.display()
        );
    } else {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
            OutputFormat::Markdown => print_routed_batch_key_material_summary(&run),
        }
    }

    Ok(())
}

fn print_heldout_key_control(
    input: PathBuf,
    alphabet: CliAlphabet,
    iterations: usize,
    seed: u64,
    output_dir: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let input_text = fs::read_to_string(&input)?;
    let candidates = parse_batch_candidates(&input_text)?;
    let run = heldout_key_control(&candidates, alphabet.into(), iterations, seed)?;

    if let Some(output_dir) = output_dir {
        write_heldout_key_control_outputs(&output_dir, &input_text, &run)?;
        println!(
            "Wrote held-out key-control results to {}",
            output_dir.display()
        );
    } else {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
            OutputFormat::Markdown => print_heldout_key_control_summary(&run),
        }
    }

    Ok(())
}

fn parse_batch_candidates(input: &str) -> Result<Vec<BatchKeyMaterialCandidate>> {
    let mut candidates = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let columns: Vec<_> = trimmed.split(',').map(str::trim).collect();
        if columns.len() != 2 {
            anyhow::bail!(
                "invalid candidate row {}: expected material,transform",
                index + 1
            );
        }
        if columns[0].eq_ignore_ascii_case("material")
            && columns[1].eq_ignore_ascii_case("transform")
        {
            continue;
        }

        let transform = CliCandidateTransform::from_str(columns[1], true).map_err(|message| {
            anyhow::anyhow!("invalid transform on row {}: {}", index + 1, message)
        })?;
        candidates.push(BatchKeyMaterialCandidate {
            material: columns[0].to_string(),
            transform: transform.into(),
        });
    }

    if candidates.is_empty() {
        anyhow::bail!("batch key-material input did not contain any candidates");
    }
    Ok(candidates)
}

fn write_batch_outputs(
    output_dir: &Path,
    input_text: &str,
    run: &BatchKeyMaterialRun,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join("input.csv"), input_text)?;
    fs::write(
        output_dir.join("results.json"),
        serde_json::to_string_pretty(run)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_batch_key_material_summary(run),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        format!(
            "batch-test-keys --input <input> --sweep-baseline-iterations {} --batch-baseline-iterations {} --seed {}\n",
            run.baseline_iterations,
            run.batch_baseline
                .as_ref()
                .map(|baseline| baseline.iterations)
                .unwrap_or(0),
            run.seed
        ),
    )?;
    Ok(())
}

fn write_routed_batch_outputs(
    output_dir: &Path,
    input_text: &str,
    run: &RoutedBatchKeyMaterialRun,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join("input.csv"), input_text)?;
    fs::write(
        output_dir.join("results.json"),
        serde_json::to_string_pretty(run)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_routed_batch_key_material_summary(run),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        format!(
            "batch-test-routed-keys --input <input> --sweep-baseline-iterations {} --batch-baseline-iterations {} --seed {}\n",
            run.baseline_iterations,
            run.batch_baseline
                .as_ref()
                .map(|baseline| baseline.iterations)
                .unwrap_or(0),
            run.seed
        ),
    )?;
    Ok(())
}

fn write_heldout_key_control_outputs(
    output_dir: &Path,
    input_text: &str,
    run: &HeldoutKeyControlRun,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join("input.csv"), input_text)?;
    fs::write(
        output_dir.join("results.json"),
        serde_json::to_string_pretty(run)?,
    )?;
    fs::write(
        output_dir.join("summary.md"),
        render_heldout_key_control_summary(run),
    )?;
    fs::write(
        output_dir.join("command.txt"),
        format!(
            "heldout-key-control --input <input> --iterations {} --seed {}\n",
            run.iterations, run.seed
        ),
    )?;
    Ok(())
}

fn print_batch_key_material_summary(run: &BatchKeyMaterialRun) {
    print!("{}", render_batch_key_material_summary(run));
}

fn render_batch_key_material_summary(run: &BatchKeyMaterialRun) -> String {
    let mut output = String::new();
    output.push_str("# Batch Key Material Results\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!(
        "alphabet: {:?}; candidates: {}; baseline iterations: {}; seed: {}; promoted: {}\n\n",
        run.alphabet,
        run.candidate_count,
        run.baseline_iterations,
        run.seed,
        run.promoted_candidate
    ));
    output.push_str("| Rank | Material | Transform | Best Offset | Matches | Match Rate | Pattern Score | Distinct Values | Span Coverage | Longest Run | Repeated Values | Empirical P | Promoted |\n");
    output.push_str(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for (index, result) in run.results.iter().enumerate() {
        let empirical_p = result
            .empirical_p_value
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "n/a".to_string());
        output.push_str(&format!(
            "| {} | `{}` | {:?} | {} | {}/{} | {:.4} | {} | {} | {} | {} | {} ({:.2}) | {} | {} |\n",
            index + 1,
            result.material,
            result.transform,
            result.best_offset,
            result.best_matches,
            result.compared_fragment_count,
            result.best_match_rate,
            result.best_pattern_metrics.pattern_score,
            result.best_pattern_metrics.distinct_matched_values,
            result.best_pattern_metrics.span_coverage,
            result.best_pattern_metrics.longest_contiguous_match_run,
            result.best_pattern_metrics.repeated_value_count,
            result.best_pattern_metrics.repeated_value_rate,
            empirical_p,
            result.promoted_candidate
        ));
    }
    if let Some(baseline) = &run.batch_baseline {
        output.push_str("\n## Batch Baseline\n\n");
        output.push_str(&format!(
            "observed best: {} matches; null mean best: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; candidates: {}; promoted: {}\n\n",
            baseline.observed_best_matches,
            baseline.null_mean_best_matches,
            baseline.null_std_dev_best_matches,
            baseline.empirical_p_value,
            baseline.iterations,
            baseline.seed,
            baseline.candidate_count,
            baseline.promoted_candidate
        ));
        output.push_str(&format!(
            "observed best pattern score: {}; null mean best pattern score: {:.2}; null sd: {:.2}; empirical p-value: {:.4}\n\n",
            baseline.observed_best_pattern_score,
            baseline.null_mean_best_pattern_score,
            baseline.null_std_dev_best_pattern_score,
            baseline.pattern_score_empirical_p_value
        ));
        output.push_str(&format!("note: {}\n", baseline.note));
    }
    output.push_str(&format!("\n{}\n", run.note));
    output
}

fn print_routed_batch_key_material_summary(run: &RoutedBatchKeyMaterialRun) {
    print!("{}", render_routed_batch_key_material_summary(run));
}

fn render_routed_batch_key_material_summary(run: &RoutedBatchKeyMaterialRun) -> String {
    let mut output = String::new();
    output.push_str("# Routed Batch Key Material Results\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!(
        "alphabet: {:?}; candidates: {}; result rows: {}; baseline iterations: {}; seed: {}; promoted: {}\n\n",
        run.alphabet,
        run.candidate_count,
        run.result_count,
        run.baseline_iterations,
        run.seed,
        run.promoted_candidate
    ));
    output.push_str("| Rank | Target | Route | Material | Transform | Best Offset | Matches | Match Rate | Pattern Score | Distinct Values | Span Coverage | Longest Run | Repeated Values | Empirical P | Promoted |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for (index, result) in run.results.iter().enumerate() {
        let empirical_p = result
            .empirical_p_value
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "n/a".to_string());
        output.push_str(&format!(
            "| {} | {} | {:?} | `{}` | {:?} | {} | {}/{} | {:.4} | {} | {} | {} | {} | {} ({:.2}) | {} | {} |\n",
            index + 1,
            result.target_label,
            result.route,
            result.material,
            result.transform,
            result.best_offset,
            result.best_matches,
            result.compared_fragment_count,
            result.best_match_rate,
            result.best_pattern_metrics.pattern_score,
            result.best_pattern_metrics.distinct_matched_values,
            result.best_pattern_metrics.span_coverage,
            result.best_pattern_metrics.longest_contiguous_match_run,
            result.best_pattern_metrics.repeated_value_count,
            result.best_pattern_metrics.repeated_value_rate,
            empirical_p,
            result.promoted_candidate
        ));
    }
    if let Some(baseline) = &run.batch_baseline {
        output.push_str("\n## Routed Batch Baseline\n\n");
        output.push_str(&format!(
            "observed best: {} matches; null mean best: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; candidates: {}; promoted: {}\n\n",
            baseline.observed_best_matches,
            baseline.null_mean_best_matches,
            baseline.null_std_dev_best_matches,
            baseline.empirical_p_value,
            baseline.iterations,
            baseline.seed,
            baseline.candidate_count,
            baseline.promoted_candidate
        ));
        output.push_str(&format!(
            "observed best pattern score: {}; null mean best pattern score: {:.2}; null sd: {:.2}; empirical p-value: {:.4}\n\n",
            baseline.observed_best_pattern_score,
            baseline.null_mean_best_pattern_score,
            baseline.null_std_dev_best_pattern_score,
            baseline.pattern_score_empirical_p_value
        ));
        output.push_str(&format!("note: {}\n", baseline.note));
    }
    output.push_str(&format!("\n{}\n", run.note));
    output
}

fn print_heldout_key_control_summary(run: &HeldoutKeyControlRun) {
    print!("{}", render_heldout_key_control_summary(run));
}

fn render_heldout_key_control_summary(run: &HeldoutKeyControlRun) -> String {
    let mut output = String::new();
    output.push_str("# Held-Out Key Control\n\n");
    output.push_str("This is not a claimed solution.\n\n");
    output.push_str(&format!(
        "alphabet: {:?}; candidates: {}; folds: {}; iterations: {}; seed: {}; promoted: {}\n\n",
        run.alphabet,
        run.candidate_count,
        run.fold_count,
        run.iterations,
        run.seed,
        run.promoted_candidate
    ));
    output.push_str("| Rank | Held-Out | Kind | Train Groups | Selected Material | Transform | Offset | Train Matches | Held-Out Matches | Held-Out Pattern Score | Held-Out P | Pattern P | Promoted |\n");
    output.push_str(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for (index, fold) in run.folds.iter().enumerate() {
        output.push_str(&format!(
            "| {} | {} | {:?} | {} | `{}` | {:?} | {} | {}/{} | {}/{} | {} | {:.4} | {:.4} | {} |\n",
            index + 1,
            fold.heldout_label,
            fold.heldout_kind,
            fold.train_group_count,
            fold.selected_material,
            fold.selected_transform,
            fold.selected_offset,
            fold.train_matches,
            fold.train_fragment_count,
            fold.heldout_matches,
            fold.heldout_fragment_count,
            fold.heldout_pattern_metrics.pattern_score,
            fold.baseline.empirical_p_value,
            fold.baseline.pattern_score_empirical_p_value,
            fold.promoted_candidate
        ));
    }

    output.push_str("\n## Fold Baselines\n\n");
    for fold in &run.folds {
        output.push_str(&format!(
            "- {} / {:?}: observed held-out {} matches; null mean {:.2}; null sd {:.2}; p={:.4}; observed pattern {}; null pattern mean {:.2}; pattern p={:.4}; selected `{}` {:?} offset {}; promoted: {}\n",
            fold.heldout_label,
            fold.heldout_kind,
            fold.baseline.observed_heldout_matches,
            fold.baseline.null_mean_heldout_matches,
            fold.baseline.null_std_dev_heldout_matches,
            fold.baseline.empirical_p_value,
            fold.baseline.observed_heldout_pattern_score,
            fold.baseline.null_mean_heldout_pattern_score,
            fold.baseline.pattern_score_empirical_p_value,
            fold.selected_material,
            fold.selected_transform,
            fold.selected_offset,
            fold.baseline.promoted_candidate
        ));
    }
    output.push('\n');
    if let Some(first) = run.folds.first() {
        output.push_str(&format!("note: {}\n\n", first.baseline.note));
    }
    output.push_str(&format!("{}\n", run.note));
    output
}

fn print_explain_key(options: ExplainKeyOptions) -> Result<()> {
    let explanation = explain_key_material(
        &options.material,
        options.transform.into(),
        options.alphabet.into(),
        options.offset,
    )?;
    match options.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&explanation)?),
        OutputFormat::Markdown => print_key_material_explanation(&explanation),
    }
    Ok(())
}

fn print_test_key(options: TestKeyOptions) -> Result<()> {
    if !options.sweep_offsets && options.sweep_baseline_iterations > 0 {
        anyhow::bail!("--sweep-baseline-iterations requires --sweep-offsets");
    }

    if options.sweep_offsets {
        let sweep = sweep_key_material_offsets_with_baseline(
            &options.material,
            options.transform.into(),
            options.alphabet.into(),
            options.sweep_baseline_iterations,
            options.seed,
        )?;
        match options.format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&sweep)?),
            OutputFormat::Markdown => print_key_material_offset_sweep(&sweep, options.top),
        }
        return Ok(());
    }

    let test = test_key_material(
        &options.material,
        options.transform.into(),
        options.alphabet.into(),
    )?;
    match options.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&test)?),
        OutputFormat::Markdown => print_key_material_test(&test),
    }

    Ok(())
}

fn print_key_material_offset_sweep(sweep: &KeyMaterialOffsetSweep, top: usize) {
    println!("# Key Material Offset Sweep\n");
    println!("This is not a claimed solution.\n");
    println!("material: `{}`", sweep.material);
    println!("transform: {:?}", sweep.transform);
    println!("alphabet: {:?}", sweep.alphabet);
    println!("fragment mode: {:?}", sweep.fragment_mode);
    println!("offsets tested: {}", sweep.offsets_tested);
    println!("promoted: {}", sweep.promoted_candidate);
    println!("note: {}\n", sweep.note);
    println!("| Rank | Offset | Matches | Match Rate |");
    println!("| --- | --- | --- | --- |");
    for (index, result) in sweep.results.iter().take(top).enumerate() {
        println!(
            "| {} | {} | {}/{} | {:.4} |",
            index + 1,
            result.offset,
            result.exact_mod26_matches,
            result.compared_fragment_count,
            result.match_rate
        );
    }
    if let Some(baseline) = &sweep.baseline {
        println!("\n## Sweep Baseline\n");
        println!(
            "observed best: {} matches; null mean best: {:.2}; null sd: {:.2}; empirical p-value: {:.4}; iterations: {}; seed: {}; promoted: {}",
            baseline.observed_best_matches,
            baseline.null_mean_best_matches,
            baseline.null_std_dev_best_matches,
            baseline.empirical_p_value,
            baseline.iterations,
            baseline.seed,
            baseline.promoted_candidate
        );
        println!("note: {}", baseline.note);
    }
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

fn print_key_material_explanation(explanation: &KeyMaterialExplanation) {
    println!("# Key Material Explanation\n");
    println!("This is not a claimed solution.\n");
    println!("material: `{}`", explanation.material);
    println!("transform: {:?}", explanation.transform);
    println!("alphabet: {:?}", explanation.alphabet);
    println!("fragment mode: {:?}", explanation.fragment_mode);
    println!("offset: {}", explanation.offset);
    println!(
        "matches: {}/{} ({:.4})",
        explanation.exact_mod26_matches,
        explanation.compared_fragment_count,
        explanation.match_rate
    );
    println!(
        "pattern: score={} distinct_values={} span_coverage={} longest_run={} repeated_values={} ({:.2})",
        explanation.pattern_metrics.pattern_score,
        explanation.pattern_metrics.distinct_matched_values,
        explanation.pattern_metrics.span_coverage,
        explanation.pattern_metrics.longest_contiguous_match_run,
        explanation.pattern_metrics.repeated_value_count,
        explanation.pattern_metrics.repeated_value_rate
    );
    if let Some(caveat) = explanation.transform_caveat {
        println!("modulo caveat: {caveat}");
    }
    println!("promoted: {}", explanation.promoted_candidate);
    println!("note: {}\n", explanation.note);

    for span in &explanation.span_results {
        println!(
            "## {}: {}/{} exact mod-26 matches",
            span.target_label, span.exact_mod26_matches, span.compared_fragment_count
        );
        if span.matches.is_empty() {
            println!("matching positions: none");
        } else {
            println!("matching positions:");
            for key_match in &span.matches {
                println!(
                    "- pos {} | {}->{} | observed {} ({}) | material {}",
                    key_match.position_one_based,
                    key_match.plaintext,
                    key_match.ciphertext,
                    key_match.observed_key_value,
                    key_match.observed_key_symbol,
                    key_match.material_value
                );
            }
        }
        println!("mismatches: {}", span.mismatches.len());
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

fn print_position_structure(
    target: CliBaselineTarget,
    alphabet: CliBaselineAlphabet,
    mode: CliFragmentMode,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let run = run_position_structure_control(
        target.into(),
        alphabet.into(),
        mode.into(),
        iterations,
        seed,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
        OutputFormat::Markdown => print_position_structure_summary(&run),
    }
    Ok(())
}

fn print_position_structure_summary(run: &PositionStructureRun) {
    println!("# Position Structure Control\n");
    println!("This is not a claimed solution.\n");
    println!(
        "target: {}; alphabet: {}; fragment mode: {:?}; moduli: {}..={}; iterations: {}; seed: {}",
        run.target_scope,
        run.alphabet_scope,
        run.fragment_mode,
        run.min_modulus,
        run.max_modulus,
        run.iterations,
        run.seed
    );
    println!("promoted: {}", run.promoted_candidate);
    println!("note: {}\n", run.note);
    println!(
        "| Target | Kind | Alphabet | Fragments | Best Modulus | Residue Score | Spacing Hits | Composite | Null Mean | Null SD | P | Adjusted P | Promoted | Warning |"
    );
    println!(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    );
    for result in &run.results {
        println!(
            "| {} | {} | {:?} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} | {} |",
            result.target_label,
            result.target_kind,
            result.alphabet,
            result.fragment_count,
            result.best_modulus,
            result.observed_residue_score,
            result.observed_spacing_hits,
            result.observed_composite_score,
            result.null_mean_composite_score,
            result.null_std_dev_composite_score,
            result.empirical_p_value,
            result.adjusted_p_value,
            result.promoted_candidate,
            result.warning
        );
    }
}

fn print_structural_models(
    target: CliBaselineTarget,
    alphabet: CliBaselineAlphabet,
    mode: CliFragmentMode,
    iterations: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<()> {
    let run = run_structural_model_control(
        target.into(),
        alphabet.into(),
        mode.into(),
        iterations,
        seed,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&run)?),
        OutputFormat::Markdown => print_structural_model_summary(&run),
    }
    Ok(())
}

fn print_structural_model_summary(run: &StructuralModelRun) {
    println!("# Structural Model Control\n");
    println!("This is not a claimed solution.\n");
    println!(
        "target: {}; alphabet: {}; fragment mode: {:?}; models: {}; iterations: {}; seed: {}",
        run.target_scope,
        run.alphabet_scope,
        run.fragment_mode,
        run.model_count,
        run.iterations,
        run.seed
    );
    println!("promoted: {}", run.promoted_candidate);
    println!("note: {}\n", run.note);
    println!(
        "| Model | Kind | Period | Targets | Fragments | Residue Score | Spacing Hits | Composite | Null Mean | Null SD | P | Adjusted P | Promoted |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for result in &run.results {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} |",
            result.model_id,
            result.model_kind,
            result.period,
            result.target_count,
            result.fragment_count,
            result.observed_residue_score,
            result.observed_spacing_hits,
            result.observed_composite_score,
            result.null_mean_composite_score,
            result.null_std_dev_composite_score,
            result.empirical_p_value,
            result.adjusted_p_value,
            result.promoted_candidate
        );
    }
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
