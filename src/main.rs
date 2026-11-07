//! kryptos-k4: source-grounded Kryptos K4 research CLI.

mod cli;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cli::claim::print_verify_claim;
use cli::eliminate::{print_eliminate, print_key_language, print_running_key};
use cli::info::{
    export_data, print_anchors, print_baseline, print_candidate_sequences,
    print_ciphertext_profile, print_constraints, print_facts, print_findings, print_hypotheses,
    print_key_fragments, print_release_check, print_routes, print_sources,
};
use cli::keys::{
    ExplainKeyOptions, TestKeyOptions, print_batch_test_keys, print_batch_test_routed_keys,
    print_explain_key, print_test_key,
};
use cli::{
    CliAlphabet, CliBaselineAlphabet, CliBaselineTarget, CliCandidateTransform, CliFragmentMode,
    OutputFormat, write_output_file_atomically,
};
use kryptos_k4::{EliminationOptions, KeyLanguageOptions, build_report, render_report};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print core public K4 facts and evidence boundary.
    Facts {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Profile K4 ciphertext-only structure without anchors or candidate material.
    CiphertextProfile {
        /// Maximum period to include in shifted coincidence and coset IC diagnostics.
        #[arg(long, default_value_t = 20)]
        max_period: usize,
        /// Maximum repeated n-gram length to scan.
        #[arg(long, default_value_t = 4)]
        max_ngram: usize,
        /// Maximum repeated n-grams to print.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Seeded ciphertext-shuffle null iterations for the best shifted period-match rate.
        #[arg(long, default_value_t = 0)]
        iterations: usize,
        /// Seed for deterministic ciphertext-profile baseline controls.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print public known-plaintext anchors with positions and source IDs.
    Anchors {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print derived constraint fragments for anchors or adjacent spans.
    Constraints {
        /// Analyze merged adjacent known-plaintext spans instead of individual anchors.
        #[arg(long)]
        spans: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
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
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
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
    /// Eliminate cipher families by whether they reproduce all 24 public anchor letters.
    Eliminate {
        /// Maximum key period for periodic and Gronsfeld families.
        #[arg(long, default_value_t = 26)]
        max_period: usize,
        /// Maximum autokey lag (primer length).
        #[arg(long, default_value_t = 52)]
        max_lag: usize,
        /// Maximum keyed-columnar width (every column order is tried). Use 0 to skip.
        #[arg(long, default_value_t = 8)]
        max_columnar_width: usize,
        /// Maximum key period after or before columnar transposition.
        #[arg(long, default_value_t = 13)]
        max_columnar_period: usize,
        /// Maximum grid width for route transpositions. Use 0 to skip.
        #[arg(long, default_value_t = 48)]
        max_route_width: usize,
        /// Random permutations for the any-substitution route null.
        #[arg(long, default_value_t = 200_000)]
        route_random_permutations: usize,
        /// Node budget per period for the exact Quagmire III/IV any-alphabet search.
        #[arg(long, default_value_t = 1_000_000)]
        quagmire_search_budget: u64,
        /// Word list (one word per line) whose words become Quagmire I-III keyword alphabets; repeatable.
        #[arg(long)]
        wordlist: Vec<PathBuf>,
        /// Ciphertext shuffles for the structure-matched route null (periods 1..=8).
        #[arg(long, default_value_t = 200)]
        route_ciphertext_shuffles: usize,
        /// Survivors to list per family.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Test every offset of a local text file as a running key against the anchors.
    RunningKey {
        /// Local text file; non-letters are ignored.
        #[arg(long)]
        corpus: PathBuf,
        /// Best offsets to list.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Score the key each registered tableau implies at the anchors for English.
    KeyLanguage {
        /// Local English text file; the first half trains a trigram model, the second half is the English null.
        #[arg(long)]
        corpus: PathBuf,
        /// Held-out English quantile used as the compatibility threshold.
        #[arg(long, default_value_t = 0.001)]
        quantile: f64,
        /// Uniform random keys for the chance pass rate.
        #[arg(long, default_value_t = 200_000)]
        uniform_samples: usize,
        /// Seed for the uniform null.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Most English-like configurations to list.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Print registered research hypotheses.
    Hypotheses {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
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
    Sources {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    /// Verify a local plaintext claim (and optional running-key stream) without printing or storing it.
    VerifyClaim {
        /// Local text file containing the claimed plaintext.
        #[arg(long)]
        plaintext: PathBuf,
        /// Optional local text file containing a claimed running-key stream.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Alphabet used for additive running-key reconstruction. Requires --key.
        #[arg(long, value_enum, default_value_t = CliAlphabet::Standard, requires = "key")]
        alphabet: CliAlphabet,
        /// Optional registered source ID. Must have allowed_use unverified-solution-claim.
        #[arg(long = "source-id")]
        source_id: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Facts { format } => print_facts(format)?,
        Command::CiphertextProfile {
            max_period,
            max_ngram,
            top,
            iterations,
            seed,
            format,
        } => print_ciphertext_profile(max_period, max_ngram, top, iterations, seed, format)?,
        Command::Anchors { format } => print_anchors(format)?,
        Command::Constraints { spans, format } => print_constraints(spans, format)?,
        Command::KeyFragments {
            anchor,
            span,
            alphabet,
            mode,
            format,
        } => print_key_fragments(anchor, span, alphabet, mode, format)?,
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
        Command::Baseline {
            target,
            alphabet,
            iterations,
            seed,
            format,
        } => print_baseline(target, alphabet, iterations, seed, format)?,
        Command::Eliminate {
            max_period,
            max_lag,
            max_columnar_width,
            max_columnar_period,
            max_route_width,
            route_random_permutations,
            route_ciphertext_shuffles,
            quagmire_search_budget,
            wordlist,
            top,
            format,
        } => print_eliminate(
            EliminationOptions {
                max_period,
                max_lag,
                max_columnar_width,
                max_columnar_period,
                max_route_width,
                route_random_permutations,
                route_ciphertext_shuffles,
                quagmire_search_budget,
                top,
            },
            &wordlist,
            format,
        )?,
        Command::RunningKey {
            corpus,
            top,
            format,
        } => print_running_key(corpus, top, format)?,
        Command::KeyLanguage {
            corpus,
            quantile,
            uniform_samples,
            seed,
            top,
            format,
        } => print_key_language(
            corpus,
            KeyLanguageOptions {
                quantile,
                uniform_samples,
                seed,
                top,
            },
            format,
        )?,
        Command::Hypotheses { format } => print_hypotheses(format)?,
        Command::CandidateSequences { format } => print_candidate_sequences(format)?,
        Command::Routes { format } => print_routes(format)?,
        Command::Findings { format } => print_findings(format)?,
        Command::Sources { format } => print_sources(format)?,
        Command::VerifyClaim {
            plaintext,
            key,
            alphabet,
            source_id,
            format,
        } => print_verify_claim(plaintext, key, alphabet, source_id, format)?,
        Command::ReleaseCheck { format } => print_release_check(format)?,
        Command::ExportData { directory } => export_data(directory)?,
        Command::Report { format, output } => {
            let report = build_report()?;
            let rendered = render_report(&report, format.into())?;
            if let Some(path) = output {
                write_output_file_atomically(&path, &rendered)?;
            } else {
                print!("{rendered}");
            }
        }
    }

    Ok(())
}
