use super::OutputFormat;
use anyhow::{Context, Result, bail};
use kryptos_k4::{
    EliminationOptions, EliminationReport, KeyLanguageOptions, KeyLanguageReport, RunningKeyReport,
    key_language, normalize_letters, run_elimination, scan_running_key,
};
use std::{fs, path::PathBuf};

pub(crate) fn print_eliminate(options: EliminationOptions, format: OutputFormat) -> Result<()> {
    let report = run_elimination(options);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => print!("{}", render_elimination(&report)),
    }
    Ok(())
}

fn render_elimination(report: &EliminationReport) -> String {
    let facts = &report.structural;
    let mut out = String::new();
    out.push_str("# Anchor Elimination\n\nThis is not a claimed solution.\n\n");
    out.push_str(&format!(
        "A correct method must reproduce all {} public anchor letters. One failed check eliminates a configuration.\n\n",
        facts.anchor_letters
    ));
    out.push_str("## Structural facts\n\n");
    out.push_str(&format!(
        "- Self-encrypting anchor positions (one-based): {:?}. Porta and any cipher that never maps a letter to itself are impossible.\n",
        facts.self_encrypting_positions_one_based
    ));
    out.push_str(&format!(
        "- Identical plaintext/ciphertext pairs (one-based): {:?}. Position-keyed tableau ciphers must use equal keys there.\n",
        facts.identical_pair_positions_one_based
    ));
    if facts.transposition_shortfall.is_empty() {
        out.push_str("- Pure transposition: letter counts allow it.\n");
    } else {
        let shortfall: Vec<String> = facts
            .transposition_shortfall
            .iter()
            .map(|(letter, needed, available)| {
                format!("{letter} needs {needed}, K4 has {available}")
            })
            .collect();
        out.push_str(&format!(
            "- Pure transposition is impossible: {}.\n",
            shortfall.join("; ")
        ));
    }
    out.push_str(&format!(
        "- No periodic substitution (any alphabet per column) fits at periods: {:?} (checked 1..={}).\n\n",
        facts.periodic_substitution_impossible_periods, facts.max_period_checked
    ));

    out.push_str("## Families\n\n");
    out.push_str("| Family | Configurations | Eliminated | Untestable | Surviving | Expected by chance | Most checks survived |\n");
    out.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for family in &report.families {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {:.1} | {} |\n",
            family.family,
            family.configurations,
            family.eliminated,
            family.unconstrained,
            family.surviving,
            family.expected_chance_survivors,
            family.max_survivor_checks
        ));
    }
    out.push('\n');
    for family in &report.families {
        out.push_str(&format!(
            "### `{}`\n\n{}\n\n",
            family.family, family.description
        ));
        if family.top_survivors.is_empty() {
            out.push_str("No survivors.\n\n");
            continue;
        }
        out.push_str("Least likely survivors (chance = probability a random configuration passes the same checks):\n\n");
        for survivor in &family.top_survivors {
            out.push_str(&format!(
                "- {} — {} checks, chance {:.2e}\n",
                survivor.parameters, survivor.checks, survivor.chance_probability
            ));
        }
        out.push('\n');
    }
    if let Some(any) = &report.route_any_substitution {
        out.push_str(&format!(
            "### `{}`\n\n{}\n\n{} routes; random-permutation null from {} permutations; ciphertext-shuffle null from {} shuffles for periods 1..={} (seed {}).\n\n",
            any.family, any.description, any.routes, any.random_permutations, any.ciphertext_shuffles, any.shuffle_max_period, any.seed
        ));
        out.push_str("| Period | Configurations | Consistent | Random rate | Expected by random permutation | Expected by ciphertext shuffle | Shuffle p | Examples |\n| ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n");
        for row in &any.rows {
            out.push_str(&format!(
                "| {} | {} | {} | {:.2e} | {:.1} | {} | {} | {} |\n",
                row.period,
                row.configurations,
                row.consistent,
                row.random_rate,
                row.expected_by_random_permutation,
                row.expected_by_ciphertext_shuffle
                    .map_or("—".to_string(), |e| format!("{e:.1}")),
                row.shuffle_p_value
                    .map_or("—".to_string(), |p| format!("{p:.3}")),
                row.examples
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        out.push('\n');
    }
    out.push_str(&format!("{}\n\npromoted: false\n", report.note));
    out
}

pub(crate) fn print_running_key(corpus: PathBuf, top: usize, format: OutputFormat) -> Result<()> {
    let text = fs::read_to_string(&corpus)
        .with_context(|| format!("failed to read corpus `{}`", corpus.display()))?;
    let letters = normalize_letters(&text);
    if letters.len() < 74 {
        bail!(
            "corpus `{}` has {} letters; at least 74 are needed to cover the anchors",
            corpus.display(),
            letters.len()
        );
    }
    let report = scan_running_key(&letters, top);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => print!("{}", render_running_key(&corpus, &report)),
    }
    Ok(())
}

fn render_running_key(corpus: &std::path::Path, report: &RunningKeyReport) -> String {
    let mut out = String::new();
    out.push_str("# Running-Key Scan\n\nThis is not a claimed solution.\n\n");
    out.push_str(&format!(
        "corpus: `{}`\ncorpus letters: {}\noffsets: {}\nconfigurations: {}\nfull anchor matches ({}/{}): {}\nbest matches: {}/{}\nexpected configurations at or above best by chance: {:.2}\n\n",
        corpus.display(),
        report.corpus_letters,
        report.offsets,
        report.configurations,
        report.anchor_letters,
        report.anchor_letters,
        report.full_matches,
        report.best_matches,
        report.anchor_letters,
        report.expected_at_best
    ));
    out.push_str("| Offset | Tableau | Matches |\n| ---: | --- | ---: |\n");
    for hit in &report.top_hits {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            hit.offset, hit.tableau, hit.matches
        ));
    }
    out.push_str("\npromoted: false\n");
    out
}

pub(crate) fn print_key_language(
    corpus: PathBuf,
    options: KeyLanguageOptions,
    format: OutputFormat,
) -> Result<()> {
    let text = fs::read_to_string(&corpus)
        .with_context(|| format!("failed to read corpus `{}`", corpus.display()))?;
    let letters = normalize_letters(&text);
    if letters.len() < 2_000 {
        bail!(
            "corpus `{}` has {} letters; at least 2000 are needed to train and test the model",
            corpus.display(),
            letters.len()
        );
    }
    let report = key_language(&letters, &options);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => print!("{}", render_key_language(&corpus, &report)),
    }
    Ok(())
}

fn render_key_language(corpus: &std::path::Path, report: &KeyLanguageReport) -> String {
    let mut out = String::new();
    out.push_str("# Anchor-Implied Key Language Test\n\nThis is not a claimed solution.\n\n");
    out.push_str(&format!(
        "English corpus: `{}` ({} training letters, {} held-out windows)\nanchor runs: {:?}\nconfigurations: {}\nthreshold: {:.4} (quantile {} of held-out English windows; English median {:.4})\nuniform random median: {:.4}; pass rate at threshold: {:.2e} over {} samples (seed {})\ncompatible configurations: {} (expected by chance: {:.2})\n\n",
        corpus.display(),
        report.training_letters,
        report.heldout_windows,
        report.anchor_runs,
        report.configurations,
        report.threshold,
        report.quantile,
        report.english_median,
        report.uniform_median,
        report.uniform_pass_rate,
        report.uniform_samples,
        report.seed,
        report.compatible,
        report.expected_compatible_by_chance
    ));
    out.push_str(
        "| Tableau | Implied key | Score | English quantile |\n| --- | --- | ---: | ---: |\n",
    );
    for hit in &report.top {
        out.push_str(&format!(
            "| {} | {} | {:.4} | {:.2e} |\n",
            hit.tableau,
            hit.key_fragments.join(" "),
            hit.score,
            hit.english_quantile
        ));
    }
    out.push_str(&format!("\n{}\n\npromoted: false\n", report.note));
    out
}
