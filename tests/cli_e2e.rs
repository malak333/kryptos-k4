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

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["constraints", "--spans", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert!(json.as_array().unwrap().iter().any(|analysis| {
        analysis["target"]["label"] == "EASTNORTHEAST"
            && analysis["target"]["kind"] == "span"
            && analysis["recurrence"]["promoted_candidate"] == false
    }));
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
fn key_fragments_json_is_parseable_and_filterable() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "key-fragments",
            "--span",
            "BERLINCLOCK",
            "--alphabet",
            "kryptos",
            "--mode",
            "additive-key",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    let rows = json.as_array().unwrap();
    assert_eq!(rows.len(), 11);
    assert!(rows.iter().all(|row| {
        row["target_kind"] == "span"
            && row["target_label"] == "BERLINCLOCK"
            && row["alphabet"] == "kryptos"
            && row["mode"] == "additive-key"
            && row["promoted_candidate"] == false
    }));
}

#[test]
fn facts_hypotheses_sources_and_help_are_covered() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("facts")
        .assert()
        .success()
        .stdout(predicate::str::contains("K4 ciphertext length: 97"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["facts", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["ciphertext_length"], 97);
    assert_eq!(json["promoted_candidate"], false);

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["anchors", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json[0]["plaintext"], "EAST");
    assert_eq!(json[0]["source_ids"][0], "elonka-kryptos");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("hypotheses")
        .assert()
        .success()
        .stdout(predicate::str::contains("Gromark-like"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["hypotheses", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json[0]["id"], "H1");
    assert_eq!(json[0]["priority"], 1);
    assert_eq!(json[4]["id"], "H5");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("sources")
        .assert()
        .success()
        .stdout(predicate::str::contains("elonka-kryptos"))
        .stdout(predicate::str::contains("accessed 2026-05-20"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["sources", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "kryptosbot-sanborn-papers-2026"
            && source["allowed_use"] == "archive-context-only"
    }));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Print public known-plaintext anchors",
        ))
        .stdout(predicate::str::contains("validate-period-observations"))
        .stdout(predicate::str::contains("validate-spacing-observations"))
        .stdout(predicate::str::contains("independent-lane-status"))
        .stdout(predicate::str::contains("next-evidence-gate"))
        .stdout(predicate::str::contains("independent-evidence-status"))
        .stdout(predicate::str::contains("source-review-packet"))
        .stdout(predicate::str::contains("non-anchor-positions"))
        .stdout(predicate::str::contains("init-position-observations"))
        .stdout(predicate::str::contains("observation-sources"))
        .stdout(predicate::str::contains("evaluate-period-prediction"))
        .stdout(predicate::str::contains("evaluate-spacing-prediction"));
}

#[test]
fn source_review_packet_exposes_prescore_source_checklist() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("source-review-packet")
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Review Packet"))
        .stdout(predicate::str::contains("eligible sources: 2"))
        .stdout(predicate::str::contains("cia-artifact"))
        .stdout(predicate::str::contains("missing"))
        .stdout(predicate::str::contains(
            "Review each eligible source URL before drafting observation positions",
        ))
        .stdout(predicate::str::contains("one position note per scored"))
        .stdout(predicate::str::contains("validate-evaluation-archive"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["source-review-packet", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["eligible_source_count"], 2);
    assert_eq!(json["promoted_candidate"], false);
    assert!(
        json["eligible_sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["id"] == "cia-sculpture"
                && source["locally_archived"] == false
                && source["use_note"]
                    .as_str()
                    .unwrap()
                    .contains("97-character K4"))
    );
    assert!(
        json["required_review_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step
                .as_str()
                .unwrap()
                .contains("sources without local archives"))
    );
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
fn batch_test_routed_keys_prints_ranked_markdown() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(
        &input_path,
        "material,transform\nWELTZEITUHR,a1-z26-one-based\nCLOCK,a1-z26-zero-based\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-routed-keys",
            "--input",
            input_path.to_str().unwrap(),
            "--sweep-baseline-iterations",
            "5",
            "--batch-baseline-iterations",
            "5",
            "--seed",
            "42",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Routed Batch Key Material Results",
        ))
        .stdout(predicate::str::contains("Target"))
        .stdout(predicate::str::contains("Route"))
        .stdout(predicate::str::contains("Pattern Score"))
        .stdout(predicate::str::contains("Routed Batch Baseline"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn batch_test_routed_keys_json_is_parseable_and_non_promotional() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(
        &input_path,
        "material,transform\nWELTZEITUHR,a1-z26-one-based\nCLOCK,a1-z26-zero-based\n",
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-routed-keys",
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
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["result_count"].as_u64().unwrap() > 0);
    assert!(json["batch_baseline"]["pattern_score_empirical_p_value"].is_number());
    let first = &json["results"].as_array().unwrap()[0];
    assert!(first["target_label"].is_string());
    assert!(first["route"].is_string());
    assert!(first["best_pattern_metrics"]["pattern_score"].is_number());
    assert_eq!(first["promoted_candidate"], false);
}

#[test]
fn batch_test_routed_keys_writes_output_directory_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    let output_dir = temp.path().join("routed-run");
    std::fs::write(
        &input_path,
        "material,transform\nWELTZEITUHR,a1-z26-one-based\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "batch-test-routed-keys",
            "--input",
            input_path.to_str().unwrap(),
            "--sweep-baseline-iterations",
            "5",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Wrote routed batch key-material results",
        ));

    for file_name in ["input.csv", "results.json", "summary.md", "command.txt"] {
        assert!(output_dir.join(file_name).exists());
    }

    let summary = std::fs::read_to_string(output_dir.join("summary.md")).unwrap();
    assert!(summary.contains("Routed Batch Key Material Results"));
    let results: Value =
        serde_json::from_str(&std::fs::read_to_string(output_dir.join("results.json")).unwrap())
            .unwrap();
    assert_eq!(results["candidate_count"], 1);
}

#[test]
fn heldout_key_control_prints_markdown_summary() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(
        &input_path,
        "material,transform\nWELTZEITUHR,a1-z26-one-based\nCLOCK,a1-z26-zero-based\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "heldout-key-control",
            "--input",
            input_path.to_str().unwrap(),
            "--iterations",
            "5",
            "--seed",
            "42",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Held-Out Key Control"))
        .stdout(predicate::str::contains("Held-Out Matches"))
        .stdout(predicate::str::contains("Fold Baselines"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));
}

#[test]
fn heldout_key_control_json_is_parseable_and_non_promotional() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    std::fs::write(
        &input_path,
        "material,transform\nWELTZEITUHR,a1-z26-one-based\nCLOCK,a1-z26-zero-based\n",
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "heldout-key-control",
            "--input",
            input_path.to_str().unwrap(),
            "--iterations",
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
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["fold_count"].as_u64().unwrap() >= 4);
    let first = &json["folds"].as_array().unwrap()[0];
    assert!(first["heldout_label"].is_string());
    assert!(first["selected_material"].is_string());
    assert!(first["baseline"]["empirical_p_value"].is_number());
    assert!(first["baseline"]["pattern_score_empirical_p_value"].is_number());
    assert_eq!(first["promoted_candidate"], false);
}

#[test]
fn heldout_key_control_writes_output_directory_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("candidates.csv");
    let output_dir = temp.path().join("heldout-run");
    std::fs::write(
        &input_path,
        "material,transform\nWELTZEITUHR,a1-z26-one-based\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "heldout-key-control",
            "--input",
            input_path.to_str().unwrap(),
            "--iterations",
            "5",
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Wrote held-out key-control results",
        ));

    for file_name in ["input.csv", "results.json", "summary.md", "command.txt"] {
        assert!(output_dir.join(file_name).exists());
    }

    let summary = std::fs::read_to_string(output_dir.join("summary.md")).unwrap();
    assert!(summary.contains("Held-Out Key Control"));
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
fn position_structure_markdown_mentions_candidate_independent_control() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "position-structure",
            "--target",
            "spans",
            "--alphabet",
            "kryptos",
            "--iterations",
            "25",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Position Structure Control"))
        .stdout(predicate::str::contains("Best Modulus"))
        .stdout(predicate::str::contains("Adjusted P"))
        .stdout(predicate::str::contains("candidate-independent"))
        .stdout(predicate::str::contains("promoted: false"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["position-structure", "--iterations", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "position-structure iterations must be greater than zero",
        ));
}

#[test]
fn position_structure_json_is_deterministic_and_non_promotional() {
    let args = [
        "position-structure",
        "--target",
        "spans",
        "--alphabet",
        "kryptos",
        "--iterations",
        "50",
        "--seed",
        "67",
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
    assert_eq!(json["target_scope"], "spans");
    assert_eq!(json["alphabet_scope"], "kryptos");
    assert_eq!(json["fragment_mode"], "additive-key");
    assert_eq!(json["promoted_candidate"], false);
    assert!(
        json["note"]
            .as_str()
            .unwrap()
            .contains("candidate-independent")
    );
    assert!(
        json["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["promoted_candidate"] == false
                && result["modulus_results"].as_array().unwrap().len() == 12
                && result["empirical_p_value"].is_number()
                && result["adjusted_p_value"].is_number())
    );
}

#[test]
fn structural_models_markdown_mentions_preregistered_models() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "structural-models",
            "--target",
            "spans",
            "--alphabet",
            "kryptos",
            "--iterations",
            "25",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Structural Model Control"))
        .stdout(predicate::str::contains("period-3-triad"))
        .stdout(predicate::str::contains("Adjusted P"))
        .stdout(predicate::str::contains("promoted: false"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["structural-models", "--iterations", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "structural-models iterations must be greater than zero",
        ));
}

#[test]
fn structural_models_json_is_deterministic_and_non_promotional() {
    let args = [
        "structural-models",
        "--target",
        "spans",
        "--alphabet",
        "kryptos",
        "--iterations",
        "50",
        "--seed",
        "67",
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
    assert_eq!(json["target_scope"], "spans");
    assert_eq!(json["alphabet_scope"], "kryptos");
    assert_eq!(json["fragment_mode"], "additive-key");
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["note"].as_str().unwrap().contains("pre-registered"));
    assert!(
        json["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["promoted_candidate"] == false
                && result["model_id"].as_str().unwrap().starts_with("period-")
                && result["empirical_p_value"].is_number()
                && result["adjusted_p_value"].is_number())
    );
}

#[test]
fn period_prediction_plan_emits_non_anchor_residue_classes() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["period-prediction-plan", "--period", "3"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Period Prediction Plan"))
        .stdout(predicate::str::contains("period: 3"))
        .stdout(predicate::str::contains("non-anchor positions: 73"))
        .stdout(predicate::str::contains(
            "public-anchor positions excluded: 24",
        ))
        .stdout(predicate::str::contains("not a claimed solution"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["period-prediction-plan", "--period", "6"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "period must be one of the registered structural model periods",
        ));
}

#[test]
fn period_prediction_plan_json_is_parseable_and_non_promotional() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "period-prediction-plan",
            "--period",
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
    assert_eq!(json["period"], 3);
    assert_eq!(json["non_anchor_position_count"], 73);
    assert_eq!(json["anchor_position_count"], 24);
    assert_eq!(json["promoted_candidate"], false);
    assert!(
        json["source_inputs"]
            .as_str()
            .unwrap()
            .contains("no fragment values")
    );
    assert_eq!(json["residues"].as_array().unwrap().len(), 3);
}

#[test]
fn period_prediction_plan_all_emits_registered_period_set() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["period-prediction-plan", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Period Prediction Plan Set"))
        .stdout(predicate::str::contains("periods: 7"))
        .stdout(predicate::str::contains("future independent evidence"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["period-prediction-plan", "--all", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["period_count"], 7);
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["plans"].as_array().unwrap().len(), 7);
    assert!(
        json["plans"]
            .as_array()
            .unwrap()
            .iter()
            .all(|plan| plan["non_anchor_position_count"] == 73
                && plan["anchor_position_count"] == 24
                && plan["promoted_candidate"] == false)
    );
}

#[test]
fn spacing_prediction_plan_emits_registered_modulus_set() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["spacing-prediction-plan"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Spacing Prediction Plan Set"))
        .stdout(predicate::str::contains("moduli: 7"))
        .stdout(predicate::str::contains("future independent evidence"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["spacing-prediction-plan", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["modulus_count"], 7);
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["plans"].as_array().unwrap().len(), 7);
    assert!(
        json["plans"]
            .as_array()
            .unwrap()
            .iter()
            .all(|plan| plan["non_anchor_position_count"] == 73
                && plan["anchor_position_count"] == 24
                && plan["promoted_candidate"] == false)
    );
}

#[test]
fn committed_period_prediction_artifact_matches_cli_output() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["period-prediction-plan", "--all", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let generated: Value = serde_json::from_slice(&output).unwrap();

    for path in [
        "experiments/predictions/non-anchor-position-period-v1.json",
        "experiments/predictions/non-anchor-position-period-diagnostic-v1.json",
        "experiments/predictions/non-anchor-position-period-followup-v1.json",
        "experiments/predictions/non-anchor-position-period-v2.json",
        "experiments/predictions/non-anchor-position-period-v3.json",
        "experiments/predictions/non-anchor-position-period-v4.json",
        "experiments/predictions/non-anchor-position-period-v5.json",
        "experiments/predictions/non-anchor-position-period-v6.json",
        "experiments/predictions/non-anchor-position-period-v7.json",
        "experiments/predictions/non-anchor-position-period-v8.json",
        "experiments/predictions/non-anchor-position-period-v9.json",
        "experiments/predictions/non-anchor-position-period-v10.json",
    ] {
        let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

        assert_eq!(fixture, generated, "{path} is stale");
        assert_eq!(fixture["period_count"], 7);
        assert_eq!(fixture["promoted_candidate"], false);
        assert!(fixture["plans"].as_array().unwrap().iter().all(
            |plan| plan["non_anchor_position_count"] == 73
                && plan["anchor_position_count"] == 24
                && plan["promoted_candidate"] == false
        ));
    }
}

#[test]
fn committed_spacing_prediction_artifact_matches_cli_output() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["spacing-prediction-plan", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let generated: Value = serde_json::from_slice(&output).unwrap();
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string("experiments/predictions/non-anchor-position-spacing-v1.json")
            .unwrap(),
    )
    .unwrap();

    assert_eq!(fixture, generated);
    assert_eq!(fixture["modulus_count"], 7);
    assert_eq!(fixture["promoted_candidate"], false);
    assert!(fixture["plans"].as_array().unwrap().iter().all(
        |plan| plan["non_anchor_position_count"] == 73
            && plan["anchor_position_count"] == 24
            && plan["promoted_candidate"] == false
    ));
}

#[test]
fn validate_preregistration_accepts_independent_prediction_target() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("lane.json");
    std::fs::write(
        &input_path,
        r#"{
  "id": "independent-target-v1",
  "title": "Independent target",
  "hypothesis_family": "structural-routing",
  "evidence_kind": "independent-prediction-target",
  "source_ids": [],
  "rationale": "Tests a target before adding candidate material.",
  "prediction_target": "Predict a non-anchor position class.",
  "discovery_inputs": ["pre-declared structural rule"],
  "evaluation_inputs": ["withheld non-anchor prediction target"],
  "controls": ["seeded shuffle baseline"],
  "uses_public_anchor_fragments_for_discovery": false,
  "uses_public_anchor_fragments_as_primary_evidence": false
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-preregistration",
            "--input",
            input_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Preregistration Validation"))
        .stdout(predicate::str::contains("valid: true"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-preregistration",
            "--input",
            input_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn validate_preregistration_rejects_public_anchor_reuse() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("lane.json");
    std::fs::write(
        &input_path,
        r#"{
  "id": "bad-anchor-reuse",
  "title": "Bad anchor reuse",
  "hypothesis_family": "candidate-mining",
  "evidence_kind": "independent-prediction-target",
  "source_ids": [],
  "rationale": "Reuses public anchors.",
  "prediction_target": "Public anchor fragments score higher.",
  "discovery_inputs": ["public anchor-derived fragments"],
  "evaluation_inputs": ["public anchor fragments"],
  "controls": ["seeded shuffle baseline"],
  "uses_public_anchor_fragments_for_discovery": true,
  "uses_public_anchor_fragments_as_primary_evidence": true
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-preregistration",
            "--input",
            input_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains("public anchor-derived fragments"))
        .stderr(predicate::str::contains(
            "preregistration failed validation",
        ));
}

#[test]
fn validate_preregistration_rejects_unchanged_template() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-preregistration",
            "--input",
            "experiments/preregistrations/independent-lane-template.json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains("placeholder text"))
        .stderr(predicate::str::contains(
            "preregistration failed validation",
        ));
}

#[test]
fn validate_prediction_artifact_checks_committed_independent_target() {
    for preregistration in [
        "experiments/preregistrations/non-anchor-position-period-v1.json",
        "experiments/preregistrations/non-anchor-position-period-diagnostic-v1.json",
        "experiments/preregistrations/non-anchor-position-period-followup-v1.json",
        "experiments/preregistrations/non-anchor-position-period-v2.json",
        "experiments/preregistrations/non-anchor-position-period-v3.json",
        "experiments/preregistrations/non-anchor-position-period-v4.json",
        "experiments/preregistrations/non-anchor-position-period-v5.json",
        "experiments/preregistrations/non-anchor-position-period-v6.json",
        "experiments/preregistrations/non-anchor-position-period-v7.json",
    ] {
        Command::cargo_bin("kryptos-k4")
            .unwrap()
            .args([
                "validate-prediction-artifact",
                "--preregistration",
                preregistration,
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Prediction Artifact Validation"))
            .stdout(predicate::str::contains("valid: true"))
            .stdout(predicate::str::contains("expected periods: 7"))
            .stdout(predicate::str::contains("artifact periods: 7"))
            .stdout(predicate::str::contains("promoted: false"));
    }

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-spacing-v1.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Prediction Artifact Validation"))
        .stdout(predicate::str::contains("valid: true"))
        .stdout(predicate::str::contains("expected moduli: 7"))
        .stdout(predicate::str::contains("artifact moduli: 7"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["expected_period_count"], 7);
    assert_eq!(json["artifact_period_count"], 7);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn independent_lane_status_summarizes_ready_lanes() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("independent-lane-status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Independent Lane Status"))
        .stdout(predicate::str::contains("lanes: 17"))
        .stdout(predicate::str::contains(
            "ready for source-backed observations: 17",
        ))
        .stdout(predicate::str::contains("invalid lanes: 0"))
        .stdout(predicate::str::contains("prediction artifacts: 17"))
        .stdout(predicate::str::contains("unique prediction artifacts: 2"))
        .stdout(predicate::str::contains(
            "unique ready prediction artifacts: 2",
        ))
        .stdout(predicate::str::contains("duplicate artifact groups: 1"))
        .stdout(predicate::str::contains("Family Summary"))
        .stdout(predicate::str::contains(
            "| position-period-prediction | 16 | 16 | 16 | 1 | 1 | 1 |",
        ))
        .stdout(predicate::str::contains(
            "| position-spacing-prediction | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains("Duplicate Prediction Artifacts"))
        .stdout(predicate::str::contains(
            "non-anchor-position-period-followup-v1",
        ))
        .stdout(predicate::str::contains(
            "ready-for-source-backed-observations",
        ))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["independent-lane-status", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["lane_count"], 17);
    assert_eq!(json["ready_for_source_backed_observations"], 17);
    assert_eq!(json["invalid_lanes"], 0);
    assert_eq!(json["prediction_artifacts"], 17);
    assert_eq!(json["unique_prediction_artifacts"], 2);
    assert_eq!(json["unique_ready_prediction_artifacts"], 2);
    let families = json["family_summaries"].as_array().unwrap();
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "position-period-prediction"
            && family["lanes"] == 16
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 1
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "position-spacing-prediction"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert_eq!(
        json["duplicate_prediction_artifact_groups"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["lanes"].as_array().unwrap().iter().all(|lane| {
        lane["ready_for_source_backed_observations"] == true
            && lane["prediction_artifact_valid"] == true
            && lane["promoted_candidate"] == false
    }));
}

#[test]
fn init_position_observations_writes_guarded_source_backed_file() {
    let temp = tempfile::tempdir().unwrap();
    let output_path = temp.path().join("observations.json");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "source-backed-observation-v1",
            "--source-id",
            "cia-artifact",
            "--positions",
            "1,4,7",
            "--rationale",
            "Source-backed non-anchor observation mechanics check.",
            "--position-note",
            "1=Position 1 is documented independently in the source packet.",
            "--position-note",
            "4=Position 4 is documented independently in the source packet.",
            "--position-note",
            "7=Position 7 is documented independently in the source packet.",
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"))
        .stdout(predicate::str::contains("\"promoted_candidate\": false"));

    let file_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&output_path).unwrap()).unwrap();
    assert_eq!(file_json["id"], "source-backed-observation-v1");
    assert_eq!(file_json["source_ids"][0], "cia-artifact");
    assert_eq!(file_json["positions_one_based"][0], 1);
    assert_eq!(
        file_json["position_notes"]["1"],
        "Position 1 is documented independently in the source packet."
    );

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-period-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v5.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v5.json",
            "--input",
            output_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"))
        .stdout(predicate::str::contains("\"artifact_valid\": true"));
}

#[test]
fn init_position_observations_rejects_anchor_positions_and_disallowed_sources() {
    let temp = tempfile::tempdir().unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "bad-anchor-observation-v1",
            "--source-id",
            "cia-artifact",
            "--positions",
            "22",
            "--rationale",
            "Source-backed non-anchor observation mechanics check.",
            "--position-note",
            "22=Position 22 note.",
            "--output",
            temp.path().join("anchor.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("public-anchor position"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "bad-source-observation-v1",
            "--source-id",
            "elonka-kryptos",
            "--positions",
            "1,4,7",
            "--rationale",
            "Source-backed non-anchor observation mechanics check.",
            "--position-note",
            "1=Position 1 note.",
            "--position-note",
            "4=Position 4 note.",
            "--position-note",
            "7=Position 7 note.",
            "--output",
            temp.path().join("source.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be scored"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "missing-position-notes-observation-v1",
            "--source-id",
            "cia-artifact",
            "--positions",
            "1,4,7",
            "--rationale",
            "Source-backed non-anchor observation mechanics check.",
            "--output",
            temp.path().join("no-notes.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "provide one --position-note POS=NOTE entry",
        ));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "bad-position-note-observation-v1",
            "--source-id",
            "cia-artifact",
            "--positions",
            "1,4,7",
            "--rationale",
            "Source-backed non-anchor observation mechanics check.",
            "--position-note",
            "1=Position 1 note.",
            "--position-note",
            "4=Position 4 note.",
            "--output",
            temp.path().join("missing-note.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "position-note is missing for position `7`",
        ));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "empty-position-note-observation-v1",
            "--source-id",
            "cia-artifact",
            "--positions",
            "1,4,7",
            "--rationale",
            "Source-backed non-anchor observation mechanics check.",
            "--position-note",
            "1=Position 1 note.",
            "--position-note",
            "4=   ",
            "--position-note",
            "7=Position 7 note.",
            "--output",
            temp.path().join("empty-note.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "position-note for position `4` must not be empty",
        ));
}

#[test]
fn observation_sources_reports_scoring_eligible_sources() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("observation-sources")
        .assert()
        .success()
        .stdout(predicate::str::contains("Observation Sources"))
        .stdout(predicate::str::contains("eligible sources: 2"))
        .stdout(predicate::str::contains("cia-artifact"))
        .stdout(predicate::str::contains(
            "https://www.cia.gov/legacy/museum/artifact/kryptos/",
        ))
        .stdout(predicate::str::contains("2026-05-20"))
        .stdout(predicate::str::contains("elonka-kryptos"))
        .stdout(predicate::str::contains("context-only"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["observation-sources", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["eligible_count"], 2);
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["sources"].as_array().unwrap().iter().any(|source| {
        source["id"] == "cia-artifact"
            && source["eligible_for_scored_observations"] == true
            && source["url"] == "https://www.cia.gov/legacy/museum/artifact/kryptos/"
            && source["locally_archived"] == false
            && source["accessed_at"] == "2026-05-20"
    }));
    assert!(json["sources"].as_array().unwrap().iter().any(|source| {
        source["id"] == "elonka-kryptos" && source["eligible_for_scored_observations"] == false
    }));
}

#[test]
fn next_evidence_gate_prints_operational_checklist() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("next-evidence-gate")
        .assert()
        .success()
        .stdout(predicate::str::contains("Next Evidence Gate"))
        .stdout(predicate::str::contains("ready lanes: 17"))
        .stdout(predicate::str::contains(
            "unique ready prediction artifacts: 2",
        ))
        .stdout(predicate::str::contains(
            "duplicate prediction artifact groups: 1",
        ))
        .stdout(predicate::str::contains("cia-artifact, cia-sculpture"))
        .stdout(predicate::str::contains("valid source-backed archives: 0"))
        .stdout(predicate::str::contains("evidence available: false"))
        .stdout(predicate::str::contains("Eligible Source Details"))
        .stdout(predicate::str::contains(
            "https://www.cia.gov/legacy/museum/artifact/kryptos/",
        ))
        .stdout(predicate::str::contains(
            "Ready lane count is an operational inventory",
        ))
        .stdout(predicate::str::contains("validate-period-observations"))
        .stdout(predicate::str::contains("evaluate-period-prediction"))
        .stdout(predicate::str::contains("validate-spacing-observations"))
        .stdout(predicate::str::contains("evaluate-spacing-prediction"))
        .stdout(predicate::str::contains("validate-evaluation-archive"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["next-evidence-gate", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["ready_lanes"], 17);
    assert_eq!(json["invalid_lanes"], 0);
    assert_eq!(json["unique_ready_prediction_artifacts"], 2);
    assert_eq!(json["duplicate_prediction_artifact_group_count"], 1);
    assert_eq!(json["valid_source_backed_archive_count"], 0);
    assert_eq!(json["invalid_archive_count"], 0);
    assert_eq!(json["evidence_available"], false);
    assert!(
        json["readiness_note"]
            .as_str()
            .unwrap()
            .contains("unique ready prediction artifacts")
    );
    assert_eq!(json["promoted_candidate"], false);
    assert!(
        json["eligible_source_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source == "cia-artifact")
    );
    assert!(
        json["eligible_sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["id"] == "cia-artifact"
                && source["url"] == "https://www.cia.gov/legacy/museum/artifact/kryptos/"
                && source["locally_archived"] == false)
    );
    let gates = json["gates"].as_array().unwrap();
    assert_eq!(gates.len(), 2);
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "position-period-prediction"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-period-observations")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-period-prediction")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "position-spacing-prediction"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-spacing-observations")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-spacing-prediction")
    }));
}

#[test]
fn independent_evidence_status_reports_missing_and_invalid_archives() {
    let temp = tempfile::tempdir().unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "independent-evidence-status",
            "--root",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Independent Evidence Status"))
        .stdout(predicate::str::contains("archives scanned: 0"))
        .stdout(predicate::str::contains("valid source-backed archives: 0"))
        .stdout(predicate::str::contains("evidence available: false"))
        .stdout(predicate::str::contains("promoted: false"));

    let invalid_archive = temp.path().join("invalid");
    std::fs::create_dir(&invalid_archive).unwrap();
    std::fs::write(invalid_archive.join("result.json"), "{}").unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "independent-evidence-status",
            "--root",
            temp.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["scanned_archive_count"], 1);
    assert_eq!(json["valid_source_backed_archive_count"], 0);
    assert_eq!(json["invalid_archive_count"], 1);
    assert_eq!(json["evidence_available"], false);
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["archives"][0]["valid"], false);
}

#[test]
fn non_anchor_positions_lists_allowed_observation_universe() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("non-anchor-positions")
        .assert()
        .success()
        .stdout(predicate::str::contains("Non-Anchor K4 Positions"))
        .stdout(predicate::str::contains("ciphertext length: 97"))
        .stdout(predicate::str::contains("non-anchor positions: 73"))
        .stdout(predicate::str::contains("excluded anchor positions: 24"))
        .stdout(predicate::str::contains("EAST"))
        .stdout(predicate::str::contains("22-25"))
        .stdout(predicate::str::contains("BERLIN"))
        .stdout(predicate::str::contains("64-69"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["non-anchor-positions", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["ciphertext_length"], 97);
    assert_eq!(json["non_anchor_position_count"], 73);
    assert_eq!(json["anchor_position_count"], 24);
    assert_eq!(json["promoted_candidate"], false);
    let positions = json["non_anchor_positions_one_based"].as_array().unwrap();
    assert_eq!(positions.first().unwrap(), 1);
    assert_eq!(positions.last().unwrap(), 97);
    assert!(!positions.iter().any(|position| position == 22));
    assert!(!positions.iter().any(|position| position == 74));
    assert!(positions.iter().any(|position| position == 75));
    let anchors = json["excluded_anchor_ranges"].as_array().unwrap();
    assert!(anchors.iter().any(|anchor| {
        anchor["label"] == "NORTHEAST"
            && anchor["start_one_based"] == 26
            && anchor["end_one_based_inclusive"] == 34
    }));
}

#[test]
fn evaluate_period_prediction_scores_independent_position_set() {
    let temp = tempfile::tempdir().unwrap();
    let output_dir = temp.path().join("period-diagnostic-output");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--positions",
            "1,4,7",
            "--iterations",
            "100",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Period Prediction Evaluation"))
        .stdout(predicate::str::contains("best: period 3 residue 0"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--positions",
            "1,4,7",
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["observed_position_count"], 3);
    assert_eq!(json["source_backed_observation"], false);
    assert!(
        json["observation_warning"]
            .as_str()
            .unwrap()
            .contains("diagnostic")
    );
    assert_eq!(json["best_period"], 3);
    assert_eq!(json["best_residue"], 0);
    assert_eq!(json["best_hits"], 3);
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["empirical_p_value"].is_number());
    assert_eq!(
        std::fs::read_to_string(output_dir.join("input-positions.txt")).unwrap(),
        "1,4,7"
    );
    assert!(output_dir.join("artifact.json").exists());
    assert!(!output_dir.join("preregistration.json").exists());
}

#[test]
fn evaluate_period_prediction_accepts_source_backed_position_file() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    let output_dir = temp.path().join("period-output");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-non-anchor-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "4": "Synthetic source-backed note for position 4.",
    "7": "Synthetic source-backed note for position 7."
  },
  "rationale": "Synthetic CLI test fixture for the observation-file input path."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["observation_id"], "synthetic-non-anchor-test");
    assert_eq!(json["observation_source_ids"][0], "cia-artifact");
    assert_eq!(json["source_backed_observation"], true);
    assert_eq!(json["observation_warning"], Value::Null);
    assert_eq!(
        json["observation_rationale"],
        "Synthetic CLI test fixture for the observation-file input path."
    );
    assert_eq!(json["best_period"], 3);
    assert_eq!(json["promoted_candidate"], false);

    for file_name in [
        "artifact.json",
        "observations.json",
        "preregistration.json",
        "result.json",
        "summary.md",
        "command.txt",
    ] {
        assert!(output_dir.join(file_name).exists(), "{file_name} missing");
    }
    let archived_observations: Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("observations.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(archived_observations["id"], "synthetic-non-anchor-test");
    assert_eq!(
        archived_observations["position_notes"]["1"],
        "Synthetic source-backed note for position 1."
    );
    let archived_json: Value =
        serde_json::from_str(&std::fs::read_to_string(output_dir.join("result.json")).unwrap())
            .unwrap();
    assert_eq!(archived_json["observation_id"], "synthetic-non-anchor-test");
    let archived_summary = std::fs::read_to_string(output_dir.join("summary.md")).unwrap();
    assert!(archived_summary.contains("Period Prediction Evaluation"));
    assert!(archived_summary.contains("source-backed observation: true"));
    let archived_command = std::fs::read_to_string(output_dir.join("command.txt")).unwrap();
    assert!(archived_command.contains("--artifact artifact.json"));
    assert!(archived_command.contains("--preregistration preregistration.json"));
    assert!(archived_command.contains("--positions-file observations.json"));

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let validation: Value = serde_json::from_slice(&validation_output).unwrap();
    assert_eq!(validation["valid"], true);
    assert_eq!(validation["artifact_kind"], "period");
    assert_eq!(validation["source_backed_observation"], true);
    assert_eq!(validation["promoted_candidate"], false);
}

#[test]
fn evaluate_spacing_prediction_scores_independent_position_set() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-spacing-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-spacing-v1.json",
            "--positions",
            "1,3,5",
            "--iterations",
            "100",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Spacing Prediction Evaluation"))
        .stdout(predicate::str::contains("best: modulus 2 residue 0"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-spacing-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-spacing-v1.json",
            "--positions",
            "1,3,5",
            "--iterations",
            "100",
            "--seed",
            "67",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["observed_position_count"], 3);
    assert_eq!(json["observed_pair_count"], 3);
    assert_eq!(json["source_backed_observation"], false);
    assert!(
        json["observation_warning"]
            .as_str()
            .unwrap()
            .contains("diagnostic")
    );
    assert_eq!(json["best_modulus"], 2);
    assert_eq!(json["best_residue"], 0);
    assert_eq!(json["best_hits"], 3);
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["empirical_p_value"].is_number());
}

#[test]
fn evaluate_spacing_prediction_accepts_source_backed_position_file() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    let output_dir = temp.path().join("spacing-output");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-spacing-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 3, 5],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "3": "Synthetic source-backed note for position 3.",
    "5": "Synthetic source-backed note for position 5."
  },
  "rationale": "Synthetic CLI test fixture for the spacing observation-file input path."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-spacing-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-spacing-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-spacing-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["observation_id"], "synthetic-spacing-test");
    assert_eq!(json["observation_source_ids"][0], "cia-artifact");
    assert_eq!(json["source_backed_observation"], true);
    assert_eq!(json["observation_warning"], Value::Null);
    assert_eq!(
        json["observation_rationale"],
        "Synthetic CLI test fixture for the spacing observation-file input path."
    );
    assert_eq!(json["best_modulus"], 2);
    assert_eq!(json["promoted_candidate"], false);

    for file_name in [
        "artifact.json",
        "observations.json",
        "preregistration.json",
        "result.json",
        "summary.md",
        "command.txt",
    ] {
        assert!(output_dir.join(file_name).exists(), "{file_name} missing");
    }
    let archived_observations: Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("observations.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(archived_observations["id"], "synthetic-spacing-test");
    let archived_json: Value =
        serde_json::from_str(&std::fs::read_to_string(output_dir.join("result.json")).unwrap())
            .unwrap();
    assert_eq!(archived_json["observation_id"], "synthetic-spacing-test");
    let archived_summary = std::fs::read_to_string(output_dir.join("summary.md")).unwrap();
    assert!(archived_summary.contains("Spacing Prediction Evaluation"));
    assert!(archived_summary.contains("source-backed observation: true"));
    let archived_command = std::fs::read_to_string(output_dir.join("command.txt")).unwrap();
    assert!(archived_command.contains("--artifact artifact.json"));
    assert!(archived_command.contains("--preregistration preregistration.json"));
    assert!(archived_command.contains("--positions-file observations.json"));
}

#[test]
fn validate_evaluation_archive_rejects_incomplete_archive() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("command.txt"),
        "evaluate-period-prediction\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains("artifact.json is missing"))
        .stderr(predicate::str::contains(
            "evaluation archive failed validation",
        ));
}

#[test]
fn validate_evaluation_archive_rejects_wrong_evaluator_command() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    let output_dir = temp.path().join("period-output");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-command-mismatch-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "4": "Synthetic source-backed note for position 4.",
    "7": "Synthetic source-backed note for position 7."
  },
  "rationale": "Synthetic CLI test fixture for archive command mismatch validation."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    std::fs::write(
        output_dir.join("command.txt"),
        "evaluate-spacing-prediction --artifact artifact.json --preregistration preregistration.json --positions-file observations.json --iterations 100 --seed 67\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains(
            "command.txt must start with `evaluate-period-prediction`",
        ))
        .stderr(predicate::str::contains(
            "evaluation archive failed validation",
        ));
}

#[test]
fn validate_evaluation_archive_rejects_tampered_source_backed_observations() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    let output_dir = temp.path().join("period-output");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-tamper-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "4": "Synthetic source-backed note for position 4.",
    "7": "Synthetic source-backed note for position 7."
  },
  "rationale": "Synthetic CLI test fixture for archive tamper validation."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    let mut observations: Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("observations.json")).unwrap(),
    )
    .unwrap();
    observations["positions_one_based"] = serde_json::json!([22]);
    observations["position_notes"] =
        serde_json::json!({"22": "Tampered source-backed note for position 22."});
    std::fs::write(
        output_dir.join("observations.json"),
        serde_json::to_string_pretty(&observations).unwrap(),
    )
    .unwrap();

    let mut result: Value =
        serde_json::from_str(&std::fs::read_to_string(output_dir.join("result.json")).unwrap())
            .unwrap();
    result["observed_positions_one_based"] = serde_json::json!([22]);
    std::fs::write(
        output_dir.join("result.json"),
        serde_json::to_string_pretty(&result).unwrap(),
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains(
            "observations.json: position `22` is not in the prediction artifact non-anchor universe",
        ))
        .stderr(predicate::str::contains(
            "evaluation archive failed validation",
        ));
}

#[test]
fn validate_evaluation_archive_rejects_preregistration_artifact_family_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    let output_dir = temp.path().join("period-output");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-family-mismatch-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "4": "Synthetic source-backed note for position 4.",
    "7": "Synthetic source-backed note for position 7."
  },
  "rationale": "Synthetic CLI test fixture for archive family mismatch validation."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    std::fs::copy(
        "experiments/preregistrations/non-anchor-position-spacing-v1.json",
        output_dir.join("preregistration.json"),
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains(
            "preregistration.json hypothesis family `position-spacing-prediction` does not match archived period artifact",
        ))
        .stderr(predicate::str::contains(
            "evaluation archive failed validation",
        ));
}

#[test]
fn evaluate_spacing_prediction_requires_preregistration_for_position_file() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-spacing-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 3, 5],
  "rationale": "Synthetic CLI test fixture for preregistration enforcement."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-spacing-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-spacing-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--positions-file requires --preregistration",
        ));
}

#[test]
fn validate_period_observations_accepts_source_backed_non_anchor_positions() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-validation-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "4": "Synthetic source-backed note for position 4.",
    "7": "Synthetic source-backed note for position 7."
  },
  "rationale": "Synthetic CLI test fixture for observation validation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-period-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["preregistration_id"], "non-anchor-position-period-v1");
    assert_eq!(json["artifact_valid"], true);
    assert_eq!(json["observation_id"], "synthetic-validation-test");
    assert_eq!(json["observation_source_ids"][0], "cia-artifact");
    assert_eq!(
        json["observation_rationale"],
        "Synthetic CLI test fixture for observation validation."
    );
    assert_eq!(json["observed_position_count"], 3);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn validate_spacing_observations_accepts_source_backed_non_anchor_positions() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-spacing-validation-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 3, 5],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "3": "Synthetic source-backed note for position 3.",
    "5": "Synthetic source-backed note for position 5."
  },
  "rationale": "Synthetic CLI test fixture for spacing observation validation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-spacing-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-spacing-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-spacing-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["preregistration_id"], "non-anchor-position-spacing-v1");
    assert_eq!(json["artifact_valid"], true);
    assert_eq!(json["observation_id"], "synthetic-spacing-validation-test");
    assert_eq!(json["observation_source_ids"][0], "cia-artifact");
    assert_eq!(
        json["observation_rationale"],
        "Synthetic CLI test fixture for spacing observation validation."
    );
    assert_eq!(json["observed_position_count"], 3);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn validate_period_observations_requires_position_notes() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "missing-position-notes-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "rationale": "Synthetic CLI test fixture for position-note validation."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-period-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("position_notes"))
        .stderr(predicate::str::contains(
            "period observations failed validation",
        ));
}

#[test]
fn validate_spacing_observations_rejects_anchor_and_duplicate_positions() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "bad-spacing-position-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 1, 22],
  "rationale": "Synthetic CLI test fixture for spacing observation validation failures."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-spacing-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-spacing-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("duplicate position `1`"))
        .stdout(predicate::str::contains("position `22`"))
        .stderr(predicate::str::contains(
            "spacing observations failed validation",
        ));
}

#[test]
fn validate_spacing_observations_rejects_single_position_files() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "single-spacing-position-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1],
  "rationale": "Synthetic CLI test fixture for spacing minimum-size validation."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-spacing-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-spacing-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-spacing-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "at least two one-based K4 positions",
        ))
        .stderr(predicate::str::contains(
            "spacing observations failed validation",
        ));
}

#[test]
fn validate_period_observations_rejects_anchor_and_duplicate_positions() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "bad-position-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 1, 22],
  "rationale": "Synthetic CLI test fixture for observation validation failures."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-period-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("duplicate position `1`"))
        .stdout(predicate::str::contains("position `22`"))
        .stderr(predicate::str::contains(
            "period observations failed validation",
        ));
}

#[test]
fn validate_period_observations_rejects_template_placeholders() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-period-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--input",
            "experiments/position-observations-template.json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("template placeholder text"))
        .stderr(predicate::str::contains(
            "period observations failed validation",
        ));
}

#[test]
fn evaluate_period_prediction_rejects_unregistered_position_file_source() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "bad-source-test",
  "source_ids": ["missing-source"],
  "positions_one_based": [1, 4, 7],
  "rationale": "Synthetic CLI test fixture for source validation."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("source_id `missing-source`"));
}

#[test]
fn evaluate_period_prediction_requires_preregistration_for_position_file() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "source-backed-without-preregistration",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "rationale": "Synthetic CLI test fixture for artifact validation guard."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--positions-file requires --preregistration",
        ));
}

#[test]
fn validate_period_observations_rejects_anchor_or_archive_context_sources() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "bad-source-use-test",
  "source_ids": ["elonka-kryptos", "kryptosbot-sanborn-papers-2026", "kryptosbot-methodology-2026"],
  "positions_one_based": [1, 4, 7],
  "rationale": "Synthetic CLI test fixture for source allowed-use validation."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-period-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("public-anchor-summary"))
        .stdout(predicate::str::contains("archive-context-only"))
        .stdout(predicate::str::contains("methodology-context"))
        .stderr(predicate::str::contains(
            "period observations failed validation",
        ));
}

#[test]
fn evaluate_period_prediction_rejects_public_anchor_positions() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-period-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-period-v1.json",
            "--positions",
            "22",
            "--iterations",
            "100",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("non-anchor K4 positions"));
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
    assert!(json.as_array().unwrap().iter().any(|finding| {
        finding["id"] == "F5"
            && finding["output_summary"]
                .as_str()
                .unwrap()
                .contains("seven registered periods")
            && finding["interpretation"]
                .as_str()
                .unwrap()
                .contains("evidence-free prediction target")
    }));
    assert!(json.as_array().unwrap().iter().any(|finding| {
        finding["id"] == "F7"
            && finding["title"]
                .as_str()
                .unwrap()
                .contains("Machine-readable gates")
            && finding["source_inputs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|source| {
                    source == "experiments/preregistrations/non-anchor-position-period-v2.json"
                })
            && finding["promoted_candidate"] == false
    }));
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

    assert!(checks.len() >= 13);
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
        "findings-source-inputs-valid",
        "independent-lanes-ready",
        "position-observation-template-guarded",
        "source-packet-registry-aligned",
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
    let report_path = temp.path().join("nested").join("k4-report.md");

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
    assert!(report.contains("validate-prediction-artifact"));
    assert!(report.contains("evaluate-period-prediction"));
    assert!(report.contains("Independent non-anchor period targets"));
    assert!(
        !temp
            .path()
            .join("nested")
            .read_dir()
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".k4-report.md.tmp-"))
    );
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
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| { finding["id"] == "F5" && finding["promoted_candidate"] == false })
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
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "kryptosbot-sanborn-papers-2026"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "kryptosbot-methodology-2026"
            && source["allowed_use"] == "methodology-context"
    }));
    assert!(sources.as_array().unwrap().iter().all(|source| {
        source["url"].as_str().unwrap().starts_with("https://")
            && !source["accessed_at"].as_str().unwrap().is_empty()
    }));
}
