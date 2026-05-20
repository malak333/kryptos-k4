use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use kryptos_k4::{
    K4_CIPHERTEXT, ReportFormat, analyze_constraints, build_report, hypotheses, known_anchors,
    render_report, sources,
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
    Facts,
    Anchors,
    Constraints,
    Hypotheses,
    Sources,
    Report {
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    ExportData {
        #[arg(long, default_value = "data")]
        directory: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Markdown,
    Json,
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Markdown => ReportFormat::Markdown,
            OutputFormat::Json => ReportFormat::Json,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Facts => print_facts(),
        Command::Anchors => print_anchors(),
        Command::Constraints => print_constraints()?,
        Command::Hypotheses => print_hypotheses(),
        Command::Sources => print_sources(),
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

fn print_facts() {
    println!("K4 ciphertext length: {}", K4_CIPHERTEXT.len());
    println!("K4 ciphertext: {K4_CIPHERTEXT}");
    println!("Evidence boundary: public anchors only; no claimed full plaintext.");
}

fn print_anchors() {
    for anchor in known_anchors() {
        println!(
            "{} => {} | 0-based {}-{} | 1-based {}-{}",
            anchor.ciphertext,
            anchor.plaintext,
            anchor.start_zero_based,
            anchor.end_zero_based_inclusive,
            anchor.start_one_based(),
            anchor.end_one_based_inclusive()
        );
    }
}

fn print_constraints() -> Result<()> {
    for analysis in analyze_constraints()? {
        println!(
            "{} / {:?}",
            analysis.anchor.plaintext, analysis.alphabet.kind
        );
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
            "  recurrence: {}/{} local additive triples matched",
            analysis.recurrence.gromark_sum_matches, analysis.recurrence.contiguous_pairs_checked
        );
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

fn print_sources() {
    for source in sources() {
        println!("{}: {}\n  {}", source.label, source.url, source.use_note);
    }
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
