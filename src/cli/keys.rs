use super::{CliAlphabet, CliCandidateTransform, OutputFormat};
use anyhow::Result;
use clap::ValueEnum;
use kryptos_k4::{
    BatchKeyMaterialCandidate, BatchKeyMaterialRun, KeyMaterialExplanation, KeyMaterialOffsetSweep,
    KeyMaterialTest, RoutedBatchKeyMaterialRun, batch_test_key_material_with_batch_baseline,
    batch_test_routed_key_material, explain_key_material, sweep_key_material_offsets_with_baseline,
    test_key_material,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(crate) struct TestKeyOptions {
    pub(crate) material: String,
    pub(crate) transform: CliCandidateTransform,
    pub(crate) alphabet: CliAlphabet,
    pub(crate) sweep_offsets: bool,
    pub(crate) top: usize,
    pub(crate) sweep_baseline_iterations: usize,
    pub(crate) seed: u64,
    pub(crate) format: OutputFormat,
}

pub(crate) struct ExplainKeyOptions {
    pub(crate) material: String,
    pub(crate) transform: CliCandidateTransform,
    pub(crate) alphabet: CliAlphabet,
    pub(crate) offset: Option<usize>,
    pub(crate) format: OutputFormat,
}

pub(crate) fn print_test_key(options: TestKeyOptions) -> Result<()> {
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

pub(crate) fn print_explain_key(options: ExplainKeyOptions) -> Result<()> {
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

pub(crate) fn print_key_material_offset_sweep(sweep: &KeyMaterialOffsetSweep, top: usize) {
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

pub(crate) fn print_key_material_test(test: &KeyMaterialTest) {
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

pub(crate) fn print_key_material_explanation(explanation: &KeyMaterialExplanation) {
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

pub(crate) fn print_batch_test_keys(
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

pub(crate) fn print_batch_test_routed_keys(
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

pub(crate) fn parse_batch_candidates(input: &str) -> Result<Vec<BatchKeyMaterialCandidate>> {
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

pub(crate) fn write_batch_outputs(
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

pub(crate) fn write_routed_batch_outputs(
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

pub(crate) fn print_batch_key_material_summary(run: &BatchKeyMaterialRun) {
    print!("{}", render_batch_key_material_summary(run));
}

pub(crate) fn render_batch_key_material_summary(run: &BatchKeyMaterialRun) -> String {
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

pub(crate) fn print_routed_batch_key_material_summary(run: &RoutedBatchKeyMaterialRun) {
    print!("{}", render_routed_batch_key_material_summary(run));
}

pub(crate) fn render_routed_batch_key_material_summary(run: &RoutedBatchKeyMaterialRun) -> String {
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
