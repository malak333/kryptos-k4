use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::collections::HashSet;

#[test]
fn anchors_command_prints_public_anchor_positions() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("anchors")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "NYPVTT => BERLIN | 0-based 63-68 | 1-based 64-69",
        ))
        .stdout(predicate::str::contains(
            "MZFPK => CLOCK | 0-based 69-73 | 1-based 70-74",
        ))
        .stdout(predicate::str::contains("sources:"));
}

#[test]
fn constraints_command_prints_alphabet_fragments() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("constraints")
        .assert()
        .success()
        .stdout(predicate::str::contains("BERLIN / Standard"))
        .stdout(predicate::str::contains("BERLIN / Kryptos"))
        .stdout(predicate::str::contains("recurrence:"));
}

#[test]
fn span_constraints_include_adjacent_clues_and_warnings() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["constraints", "--spans"])
        .assert()
        .success()
        .stdout(predicate::str::contains("EASTNORTHEAST / Standard"))
        .stdout(predicate::str::contains("BERLINCLOCK / Standard"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("Exploratory only"));
}

#[test]
fn facts_hypotheses_sources_and_help_are_covered() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("facts")
        .assert()
        .success()
        .stdout(predicate::str::contains("K4 ciphertext length: 97"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("hypotheses")
        .assert()
        .success()
        .stdout(predicate::str::contains("Gromark-like"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("sources")
        .assert()
        .success()
        .stdout(predicate::str::contains("elonka-kryptos"))
        .stdout(predicate::str::contains("accessed 2026-05-20"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Print public known-plaintext anchors",
        ));
}

#[test]
fn invalid_report_format_fails() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["report", "--format", "xml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn key_fragments_support_target_alphabet_and_mode_filters() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "key-fragments",
            "--span",
            "BERLINCLOCK",
            "--alphabet",
            "standard",
            "--mode",
            "additive-key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("span BERLINCLOCK / Standard"))
        .stdout(predicate::str::contains("AdditiveKey"))
        .stdout(predicate::str::contains("SubtractiveKey").not());
}

#[test]
fn key_fragments_reject_conflicting_or_empty_filters() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "key-fragments",
            "--anchor",
            "BERLIN",
            "--span",
            "BERLINCLOCK",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["key-fragments", "--anchor", "BERLINCLOCK"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no key-fragment rows matched"));
}

#[test]
fn test_key_scores_material_against_public_spans() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["test-key", "--material", "BERLINWORLDCLOCK"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key Material Test"))
        .stdout(predicate::str::contains("BERLINWORLDCLOCK"))
        .stdout(predicate::str::contains("alphabet: Kryptos"))
        .stdout(predicate::str::contains("BERLINCLOCK"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn test_key_json_is_parseable_and_non_promotional() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "test-key",
            "--material",
            "BERLINWORLDCLOCK",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["material"], "BERLINWORLDCLOCK");
    assert_eq!(json["alphabet"], "kryptos");
    assert_eq!(json["compared_fragment_count"], 24);
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["span_results"].as_array().unwrap().len() >= 2);
}

#[test]
fn test_key_rejects_material_without_values() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["test-key", "--material", "!!!"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "key material did not produce any numeric values",
        ));
}

#[test]
fn test_key_sweep_offsets_ranks_all_offsets_without_promotion() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "test-key",
            "--material",
            "BERLINWORLDCLOCK",
            "--sweep-offsets",
            "--top",
            "3",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key Material Offset Sweep"))
        .stdout(predicate::str::contains("offsets tested: 16"))
        .stdout(predicate::str::contains(
            "| Rank | Offset | Matches | Match Rate |",
        ))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn test_key_sweep_offsets_json_is_parseable() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "test-key",
            "--material",
            "ALEXANDERPLATZ",
            "--sweep-offsets",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["material"], "ALEXANDERPLATZ");
    assert_eq!(json["offsets_tested"], 14);
    assert_eq!(json["promoted_candidate"], false);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 14);
    assert!(
        results
            .windows(2)
            .all(|pair| pair[0]["exact_mod26_matches"].as_u64().unwrap()
                >= pair[1]["exact_mod26_matches"].as_u64().unwrap())
    );
}

#[test]
fn test_key_sweep_baseline_is_seeded_and_non_promotional() {
    let args = [
        "test-key",
        "--material",
        "BERLINWORLDCLOCK",
        "--sweep-offsets",
        "--sweep-baseline-iterations",
        "25",
        "--seed",
        "42",
        "--format",
        "json",
    ];
    let first = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(first, second);
    let json: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(json["baseline"]["iterations"], 25);
    assert_eq!(json["baseline"]["seed"], 42);
    assert_eq!(json["baseline"]["promoted_candidate"], false);
    assert!(json["baseline"]["empirical_p_value"].as_f64().unwrap() > 0.0);
}

#[test]
fn test_key_sweep_baseline_requires_sweep_offsets() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "test-key",
            "--material",
            "BERLINWORLDCLOCK",
            "--sweep-baseline-iterations",
            "25",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--sweep-baseline-iterations requires --sweep-offsets",
        ));
}

#[test]
fn explain_key_prints_matching_positions_and_modulo_caveat() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "explain-key",
            "--material",
            "WELTZEITUHR",
            "--transform",
            "a1-z26-one-based",
            "--offset",
            "5",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key Material Explanation"))
        .stdout(predicate::str::contains("offset: 5"))
        .stdout(predicate::str::contains("matches: 5/24"))
        .stdout(predicate::str::contains(
            "pattern: score=546 distinct_values=4 span_coverage=2 longest_run=2 repeated_values=1 (0.20)",
        ))
        .stdout(predicate::str::contains("A1Z26OneBased emits A=1"))
        .stdout(predicate::str::contains(
            "- pos 29 | T->R | observed 23 (W) | material 23",
        ))
        .stdout(predicate::str::contains(
            "- pos 67 | L->V | observed 5 (O) | material 5",
        ))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn explain_key_json_is_parseable() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "explain-key",
            "--material",
            "WELTZEITUHR",
            "--transform",
            "a1-z26-one-based",
            "--offset",
            "5",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["material"], "WELTZEITUHR");
    assert_eq!(json["transform"], "a1-z26-one-based");
    assert_eq!(json["offset"], 5);
    assert_eq!(json["exact_mod26_matches"], 5);
    assert_eq!(json["pattern_metrics"]["pattern_score"], 546);
    assert_eq!(json["pattern_metrics"]["distinct_matched_values"], 4);
    assert_eq!(json["pattern_metrics"]["span_coverage"], 2);
    assert_eq!(json["pattern_metrics"]["longest_contiguous_match_run"], 2);
    assert_eq!(json["pattern_metrics"]["repeated_value_count"], 1);
    assert!(
        json["transform_caveat"]
            .as_str()
            .unwrap()
            .contains("Z=26 is compared as 0")
    );
    let span_results = json["span_results"].as_array().unwrap();
    assert_eq!(span_results[0]["matches"].as_array().unwrap().len(), 3);
    assert_eq!(span_results[1]["matches"].as_array().unwrap().len(), 2);
}

#[test]
fn pattern_metrics_penalize_repeated_short_material_matches() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "explain-key",
            "--material",
            "CLOCK",
            "--transform",
            "a1-z26-zero-based",
            "--offset",
            "3",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["exact_mod26_matches"], 5);
    assert_eq!(json["pattern_metrics"]["pattern_score"], 508);
    assert_eq!(json["pattern_metrics"]["distinct_matched_values"], 2);
    assert_eq!(json["pattern_metrics"]["span_coverage"], 2);
    assert_eq!(json["pattern_metrics"]["longest_contiguous_match_run"], 1);
    assert_eq!(json["pattern_metrics"]["repeated_value_count"], 3);
}

#[test]
fn batch_test_keys_prints_ranked_markdown() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(
        &input_path,
        "material,transform\nBERLINWORLDCLOCK,a1-z26-zero-based\nWELTZEITUHR,a1-z26-zero-based\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-keys",
            "--input",
            input_path.to_str().unwrap(),
            "--sweep-baseline-iterations",
            "25",
            "--seed",
            "42",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Batch Key Material Results"))
        .stdout(predicate::str::contains("BERLINWORLDCLOCK"))
        .stdout(predicate::str::contains("WELTZEITUHR"))
        .stdout(predicate::str::contains("Pattern Score"))
        .stdout(predicate::str::contains("Distinct Values"))
        .stdout(predicate::str::contains("Repeated Values"))
        .stdout(predicate::str::contains("Empirical P"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn batch_test_keys_batch_baseline_controls_candidate_file_surface() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(
        &input_path,
        "material,transform\nWELTZEITUHR,a1-z26-one-based\nBERLINWORLDCLOCK,a1-z26-one-based\n",
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-keys",
            "--input",
            input_path.to_str().unwrap(),
            "--sweep-baseline-iterations",
            "5",
            "--batch-baseline-iterations",
            "5",
            "--seed",
            "42",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["candidate_count"], 2);
    assert_eq!(json["batch_baseline"]["iterations"], 5);
    assert_eq!(json["batch_baseline"]["candidate_count"], 2);
    assert_eq!(json["batch_baseline"]["promoted_candidate"], false);
    assert!(json["batch_baseline"]["empirical_p_value"].is_number());
    assert!(json["batch_baseline"]["observed_best_pattern_score"].is_number());
    assert!(json["batch_baseline"]["pattern_score_empirical_p_value"].is_number());
    assert!(
        json["batch_baseline"]["note"]
            .as_str()
            .unwrap()
            .contains("composite pattern score")
    );
}

#[test]
fn batch_test_keys_json_is_ranked_and_non_promotional() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(
        &input_path,
        "ALEXANDERPLATZ,a1-z26-zero-based\n1986,decimal-digits\n",
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-keys",
            "--input",
            input_path.to_str().unwrap(),
            "--sweep-baseline-iterations",
            "25",
            "--seed",
            "42",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["candidate_count"], 2);
    assert_eq!(json["promoted_candidate"], false);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(
        results
            .windows(2)
            .all(|pair| pair[0]["best_matches"].as_u64().unwrap()
                >= pair[1]["best_matches"].as_u64().unwrap())
    );
    assert!(results.iter().all(|result| {
        result["promoted_candidate"] == false && result["empirical_p_value"].is_number()
    }));
    assert!(results.iter().all(|result| {
        result["best_pattern_metrics"]["distinct_matched_values"].is_number()
            && result["best_pattern_metrics"]["pattern_score"].is_number()
            && result["best_pattern_metrics"]["span_coverage"].is_number()
            && result["best_pattern_metrics"]["repeated_value_count"].is_number()
    }));
}

#[test]
fn batch_test_keys_writes_output_directory_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    let output_dir = temp.path().join("run");
    std::fs::write(
        &input_path,
        "material,transform\nBERLINWORLDCLOCK,a1-z26-zero-based\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-keys",
            "--input",
            input_path.to_str().unwrap(),
            "--sweep-baseline-iterations",
            "10",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote batch key-material results"));

    for file_name in ["input.csv", "results.json", "summary.md", "command.txt"] {
        assert!(output_dir.join(file_name).exists());
    }

    let summary = std::fs::read_to_string(output_dir.join("summary.md")).unwrap();
    assert!(summary.contains("Batch Key Material Results"));
    let results: Value =
        serde_json::from_str(&std::fs::read_to_string(output_dir.join("results.json")).unwrap())
            .unwrap();
    assert_eq!(results["candidate_count"], 1);
}

#[test]
fn summarize_key_runs_ranks_historical_result_folders() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    let run_one = temp.path().join("lane").join("run-one");
    let run_two = temp.path().join("lane").join("run-two");
    std::fs::write(
        &input_path,
        "material,transform\nBERLINWORLDCLOCK,a1-z26-zero-based\nWELTZEITUHR,a1-z26-one-based\n",
    )
    .unwrap();

    for (seed, output_dir) in [("42", &run_one), ("43", &run_two)] {
        Command::cargo_bin("kryptos-k4")
            .unwrap()
            .args([
                "batch-test-keys",
                "--input",
                input_path.to_str().unwrap(),
                "--sweep-baseline-iterations",
                "10",
                "--seed",
                seed,
                "--output-dir",
                output_dir.to_str().unwrap(),
            ])
            .assert()
            .success();
    }

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "summarize-key-runs",
            "--input-dir",
            temp.path().join("lane").to_str().unwrap(),
            "--top",
            "3",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Batch Key Run History"))
        .stdout(predicate::str::contains("result files: 2"))
        .stdout(predicate::str::contains("Candidate Stability"))
        .stdout(predicate::str::contains("WELTZEITUHR"))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn summarize_key_runs_json_is_parseable() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    let output_dir = temp.path().join("lane").join("run");
    std::fs::write(&input_path, "CLOCK,a1-z26-zero-based\n").unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-keys",
            "--input",
            input_path.to_str().unwrap(),
            "--sweep-baseline-iterations",
            "10",
            "--seed",
            "42",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "summarize-key-runs",
            "--input-dir",
            temp.path().join("lane").to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["scanned_result_files"], 1);
    assert_eq!(json["run_count"], 1);
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["candidate_summaries"][0]["material"], "CLOCK");
    assert!(json["top_results"][0]["empirical_p_value"].is_number());
}

#[test]
fn batch_test_keys_rejects_invalid_transform() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(&input_path, "THING,unknown-transform\n").unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["batch-test-keys", "--input", input_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid transform"));
}

#[test]
fn baseline_json_is_deterministic_and_parseable() {
    let args = [
        "baseline",
        "--target",
        "spans",
        "--iterations",
        "100",
        "--seed",
        "42",
        "--format",
        "json",
    ];
    let first = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(first, second);
    let json: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(json["iterations"], 100);
    assert_eq!(json["seed"], 42);
    assert!(
        json["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["target_label"] == "BERLINCLOCK")
    );
}

#[test]
fn baseline_markdown_mentions_p_values_and_solution_boundary() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["baseline", "--iterations", "25", "--seed", "42"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Empirical p-value"))
        .stdout(predicate::str::contains("Adjusted p-value"))
        .stdout(predicate::str::contains("not a claimed solution"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["baseline", "--iterations", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "baseline iterations must be greater than zero",
        ));
}

#[test]
fn candidate_sequences_json_contains_registered_families() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["candidate-sequences", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    let candidates = json["candidate_sequences"].as_array().unwrap();
    let scores = json["scores"].as_array().unwrap();
    assert_eq!(candidates.len(), scores.len());
    assert_eq!(
        json["note"],
        "Pre-registered contextual candidates only; not a claimed solution."
    );

    let ids: HashSet<_> = candidates
        .iter()
        .map(|candidate| candidate["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains("h4-berlin-world-clock-english"));
    assert!(ids.contains("h4-compass-8point-east-northeast"));
    assert!(ids.contains("h5-egypt-1986-year"));
    assert!(ids.contains("h5-berlin-wall-1989-date"));

    let families: HashSet<_> = candidates
        .iter()
        .map(|candidate| candidate["family"].as_str().unwrap())
        .collect();
    assert!(families.contains("berlin-world-clock"));
    assert!(families.contains("compass-directions"));
    assert!(families.contains("egypt1986"));
    assert!(families.contains("berlin-wall1989"));
    assert!(candidates.iter().all(|candidate| {
        candidate["pre_registered"] == true
            && candidate["expanded_to_k4"].as_array().unwrap().len() == 97
            && !candidate["values"].as_array().unwrap().is_empty()
    }));
    assert!(scores.iter().all(|score| {
        score["promoted_candidate"] == false
            && score["compared_fragment_count"] == 24
            && score["note"]
                .as_str()
                .unwrap()
                .contains("no candidate is promoted")
    }));
}

#[test]
fn routes_command_prints_named_routes_and_baselines() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("routes")
        .assert()
        .success()
        .stdout(predicate::str::contains("Identity"))
        .stdout(predicate::str::contains("identity_baseline"))
        .stdout(predicate::str::contains("seeded_random_baseline"))
        .stdout(predicate::str::contains("not a claimed solution"))
        .stdout(predicate::str::contains("plaintext guess").not());
}

#[test]
fn routes_json_contains_bounded_experiments_without_plaintext_output() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["routes", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    let experiments = json.as_array().unwrap();
    assert!(experiments.len() >= 5);
    assert!(experiments.iter().all(|experiment| {
        experiment["alphabet"] == "standard"
            && experiment["fragment_mode"] == "additive-key"
            && experiment["promoted_candidate"] == false
            && experiment["notes"]
                .as_str()
                .unwrap()
                .contains("no decryption text is emitted")
            && experiment["permutation"].as_array().unwrap().len()
                == experiment["target_label"].as_str().unwrap().len()
    }));
    assert!(experiments.iter().any(|experiment| {
        experiment["route"] == "row-to-column-width13"
            && experiment["target_label"] == "EASTNORTHEAST"
    }));
    assert!(experiments.iter().any(|experiment| {
        experiment["route"] == "identity" && experiment["target_label"] == "BERLINCLOCK"
    }));
    let serialized = serde_json::to_string(&json).unwrap();
    assert!(!serialized.contains("plaintext guess"));
    assert!(!serialized.contains("claimed solution"));
}

#[test]
fn findings_command_exposes_evidence_baselines_and_next_tests() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("findings")
        .assert()
        .success()
        .stdout(predicate::str::contains("Findings Ledger"))
        .stdout(predicate::str::contains("sources:"))
        .stdout(predicate::str::contains("baseline:"))
        .stdout(predicate::str::contains("next test:"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn findings_json_is_parseable_and_non_promotional() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["findings", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert!(json.as_array().unwrap().len() >= 4);
    assert!(
        json.as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["promoted_candidate"] == false)
    );
    assert_eq!(json[0]["id"], "F1");
    assert!(json[0]["transformation_steps"].as_array().unwrap().len() >= 3);
}

#[test]
fn release_check_confirms_no_github_actions_policy() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("release-check")
        .assert()
        .success()
        .stdout(predicate::str::contains("github-actions-disabled"))
        .stdout(predicate::str::contains("does not use GitHub Actions"));
}

#[test]
fn release_check_json_exposes_all_local_preflight_gates() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["release-check", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    let checks = json.as_array().unwrap();
    let names: HashSet<_> = checks
        .iter()
        .map(|check| check["name"].as_str().unwrap())
        .collect();

    assert!(checks.len() >= 12);
    assert!(checks.iter().all(|check| check["passed"] == true));
    for expected_name in [
        "github-actions-disabled",
        "dependabot-disabled",
        "readme-present",
        "research-method-present",
        "current-architecture-present",
        "production-goal-architecture-present",
        "source-packet-present",
        "research-plan-present",
        "license-present",
        "lockfile-present",
        "markdown-report-present",
        "no-plaintext-leakage-markers",
    ] {
        assert!(names.contains(expected_name));
    }
    assert!(checks.iter().any(|check| {
        check["name"] == "github-actions-disabled"
            && check["detail"]
                .as_str()
                .unwrap()
                .contains(".github/workflows")
    }));
    assert!(checks.iter().any(|check| {
        check["name"] == "dependabot-disabled"
            && check["detail"]
                .as_str()
                .unwrap()
                .contains(".github/dependabot.yml")
    }));
    assert!(
        checks
            .iter()
            .filter(|check| check["name"] != "no-plaintext-leakage-markers")
            .all(|check| { check["detail"].as_str().unwrap().contains("path=") })
    );
}

#[test]
fn json_report_includes_candidate_and_route_experiments() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["report", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert!(json["candidate_sequences"].as_array().unwrap().len() >= 4);
    assert!(json["route_experiments"].as_array().unwrap().len() >= 2);
    assert!(json["findings"].as_array().unwrap().len() >= 4);
    assert_eq!(json["route_experiments"][0]["promoted_candidate"], false);
    assert_eq!(json["findings"][0]["promoted_candidate"], false);
}

#[test]
fn markdown_report_can_be_written_to_file() {
    let temp = tempfile::tempdir().unwrap();
    let report_path = temp.path().join("k4-report.md");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "report",
            "--format",
            "markdown",
            "--output",
            report_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let report = std::fs::read_to_string(report_path).unwrap();
    assert!(report.contains("# Kryptos K4 Constraint Report"));
    assert!(report.contains("## Known Anchors"));
    assert!(report.contains("## Ranked Hypotheses"));
    assert!(report.contains("## Findings Ledger"));
}

#[test]
fn json_report_is_parseable() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["report", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["ciphertext_length"], 97);
    assert!(json["anchors"].as_array().unwrap().len() >= 4);
    assert!(json["constraints"].as_array().unwrap().len() >= 12);
    assert!(json["span_constraints"].as_array().unwrap().len() >= 6);
    assert_eq!(json["constraints"][0]["alphabet"]["kind"], "standard");
    assert_eq!(
        json["constraints"][0]["fragments"][0]["mode"],
        "additive-key"
    );
    assert_eq!(json["anchors"][0]["source_ids"][0], "elonka-kryptos");
    assert_eq!(json["sources"][0]["id"], "cia-artifact");
    assert_eq!(json["hypotheses"][0]["id"], "H1");
    assert_eq!(
        json["span_constraints"][0]["recurrence"]["promoted_candidate"],
        false
    );
}

#[test]
fn export_data_writes_machine_readable_files() {
    let temp = tempfile::tempdir().unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["export-data", "--directory", temp.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported K4 data files"));

    let anchors = std::fs::read_to_string(temp.path().join("k4-known-anchors.json")).unwrap();
    let anchors: Value = serde_json::from_str(&anchors).unwrap();
    assert!(
        anchors
            .as_array()
            .unwrap()
            .iter()
            .any(|anchor| { anchor["plaintext"] == "BERLIN" && anchor["start_zero_based"] == 63 })
    );
    assert_eq!(anchors.as_array().unwrap().len(), 4);
    assert!(anchors.as_array().unwrap().iter().all(|anchor| {
        anchor["claim_type"] == "public-anchor"
            && anchor["confidence"] == "high"
            && !anchor["source_ids"].as_array().unwrap().is_empty()
            && anchor["end_zero_based_inclusive"].as_u64().unwrap()
                >= anchor["start_zero_based"].as_u64().unwrap()
    }));

    let ciphertext = std::fs::read_to_string(temp.path().join("k4-ciphertext.json")).unwrap();
    let ciphertext: Value = serde_json::from_str(&ciphertext).unwrap();
    assert_eq!(ciphertext["length"], 97);
    assert_eq!(ciphertext["ciphertext"].as_str().unwrap().len(), 97);
    assert_eq!(
        ciphertext["evidence_boundary"],
        "public ciphertext only; no claimed full plaintext"
    );

    let sources = std::fs::read_to_string(temp.path().join("k4-sources.json")).unwrap();
    let sources: Value = serde_json::from_str(&sources).unwrap();
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "scientific-american-2025" && source["allowed_use"] == "public-clue-context"
    }));
    assert!(sources.as_array().unwrap().iter().all(|source| {
        source["url"].as_str().unwrap().starts_with("https://")
            && !source["accessed_at"].as_str().unwrap().is_empty()
    }));
}
