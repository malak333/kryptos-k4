use super::OutputFormat;
use anyhow::{Context, Result, bail};
use kryptos_k4::{
    EliminationOptions, EliminationReport, KeyLanguageOptions, KeyLanguageReport, Problem,
    RunningKeyReport, eliminate_dictionary_quagmire, key_language, normalize_letters,
    run_elimination, scan_running_key,
};
use std::{fs, path::PathBuf};

pub(crate) fn print_eliminate(
    options: EliminationOptions,
    wordlists: &[PathBuf],
    format: OutputFormat,
) -> Result<()> {
    let mut report = run_elimination(options);
    if !wordlists.is_empty() {
        let mut words = Vec::new();
        for path in wordlists {
            let text = fs::read_to_string(path)
                .with_context(|| format!("failed to read word list `{}`", path.display()))?;
            words.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|w| w.bytes().any(|b| b.is_ascii_alphabetic()))
                    .map(str::to_string),
            );
        }
        report.families.push(eliminate_dictionary_quagmire(
            &Problem::k4(),
            &words,
            options.max_period,
            options.top,
        ));
    }
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
        "- No periodic substitution (any alphabet per column) fits at periods: {:?} (checked 1..={}).\n",
        facts.periodic_substitution_impossible_periods, facts.max_period_checked
    ));
    out.push_str(&format!(
        "- No Quagmire I (any plaintext alphabet) fits at periods: {:?}.\n- No Quagmire II (any ciphertext alphabet) fits at periods: {:?}.\n\n",
        facts.quagmire_i_any_alphabet_impossible_periods,
        facts.quagmire_ii_any_alphabet_impossible_periods
    ));
    let quagmire = &report.quagmire_any_alphabet;
    let passes: Vec<String> = quagmire
        .rows
        .iter()
        .filter(|row| row.k4_consistent)
        .map(|row| {
            format!(
                "{} period {} (shuffle rate {:.3})",
                row.kind, row.period, row.shuffle_rate
            )
        })
        .collect();
    out.push_str(&format!(
        "Quagmire I/II with any alphabet passes at: {}.\nCombined surprisal against {} ciphertext shuffles (seed {}): K4 {:.2}, null mean {:.2}, p = {:.3}.\n\n",
        passes.join("; "),
        quagmire.shuffles,
        quagmire.seed,
        quagmire.k4_surprisal,
        quagmire.null_mean_surprisal,
        quagmire.surprisal_p_value
    ));

    /// Periods per (kind, sign): impossible, solvable, undecided.
    type ClassPeriods = (String, Vec<usize>, Vec<usize>, Vec<usize>);
    let mut by_class: Vec<ClassPeriods> = Vec::new();
    for row in &report.quagmire_iii_iv_any_alphabet {
        let kind = match row.kind {
            kryptos_k4::quagmire_search::QuagmireKind::III => "Quagmire III",
            kryptos_k4::quagmire_search::QuagmireKind::IV => "Quagmire IV",
        };
        let sign = match row.sign {
            kryptos_k4::quagmire_search::SearchSign::VigenereOrVariant => {
                "Vigenère or variant Beaufort"
            }
            kryptos_k4::quagmire_search::SearchSign::Beaufort => "Beaufort",
        };
        let label = format!("{kind}, {sign}");
        if by_class.last().is_none_or(|(l, ..)| *l != label) {
            by_class.push((label, Vec::new(), Vec::new(), Vec::new()));
        }
        let entry = by_class.last_mut().expect("class");
        match row.result {
            kryptos_k4::quagmire_search::SearchResult::Impossible => entry.1.push(row.period),
            kryptos_k4::quagmire_search::SearchResult::Possible => entry.2.push(row.period),
            kryptos_k4::quagmire_search::SearchResult::Undecided => entry.3.push(row.period),
        }
    }
    out.push_str(&format!(
        "Quagmire III/IV with arbitrary alphabets (exact search, budget {} nodes per period):\n\n| Kind and sign | Impossible | Solvable | Undecided |\n| --- | --- | --- | --- |\n",
        report.quagmire_search_budget
    ));
    for (label, impossible, possible, undecided) in &by_class {
        out.push_str(&format!(
            "| {label} | {impossible:?} | {possible:?} | {undecided:?} |\n"
        ));
    }
    out.push('\n');

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
