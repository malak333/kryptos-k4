use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn anchors_command_prints_public_anchor_positions() {
    let mut cmd = Command::cargo_bin("kryptos-k4").unwrap();

    cmd.arg("anchors")
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
    let mut cmd = Command::cargo_bin("kryptos-k4").unwrap();

    cmd.arg("constraints")
        .assert()
        .success()
        .stdout(predicate::str::contains("BERLIN / Standard"))
        .stdout(predicate::str::contains("BERLIN / Kryptos"))
        .stdout(predicate::str::contains("recurrence:"));
}

#[test]
fn span_constraints_include_adjacent_clues_and_warnings() {
    let mut cmd = Command::cargo_bin("kryptos-k4").unwrap();

    cmd.args(["constraints", "--spans"])
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
fn markdown_report_can_be_written_to_file() {
    let temp = tempfile::tempdir().unwrap();
    let report_path = temp.path().join("k4-report.md");
    let mut cmd = Command::cargo_bin("kryptos-k4").unwrap();

    cmd.args([
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
}

#[test]
fn json_report_is_parseable() {
    let mut cmd = Command::cargo_bin("kryptos-k4").unwrap();

    let output = cmd
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
    let mut cmd = Command::cargo_bin("kryptos-k4").unwrap();

    cmd.args(["export-data", "--directory", temp.path().to_str().unwrap()])
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

    assert!(temp.path().join("k4-ciphertext.json").exists());
    assert!(temp.path().join("k4-sources.json").exists());
}
