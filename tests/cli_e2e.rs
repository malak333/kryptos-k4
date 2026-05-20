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
        ));
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
