use assert_cmd::Command;
use kryptos_k4::{K4_CIPHERTEXT, known_anchors};
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
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "smithsonian-2026-archive-discovery"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-doc1-resolution-memo"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-declassified-kryptos-doc3"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-foia-release-index"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-summary-revelations"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-doc8-cryptogram"
            && source["allowed_use"] == "public-anchor-summary"
    }));
    assert!(json.as_array().unwrap().iter().any(|source| {
        source["id"] == "solvekryptos-2026-claim"
            && source["allowed_use"] == "unverified-solution-claim"
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
        .stdout(predicate::str::contains("ciphertext-profile"))
        .stdout(predicate::str::contains("ciphertext-structure-prior"))
        .stdout(predicate::str::contains("evaluate-ciphertext-prior"))
        .stdout(predicate::str::contains("independent-evidence-status"))
        .stdout(predicate::str::contains("source-review-status"))
        .stdout(predicate::str::contains("source-observation-status"))
        .stdout(predicate::str::contains("source-review-packet"))
        .stdout(predicate::str::contains("source-frontier"))
        .stdout(predicate::str::contains("init-source-review"))
        .stdout(predicate::str::contains("validate-source-review"))
        .stdout(predicate::str::contains("non-anchor-positions"))
        .stdout(predicate::str::contains("init-position-observations"))
        .stdout(predicate::str::contains("observation-sources"))
        .stdout(predicate::str::contains("verify-plaintext-claim"))
        .stdout(predicate::str::contains("verify-claim-reconciliation"))
        .stdout(predicate::str::contains("mirror-prediction-plan"))
        .stdout(predicate::str::contains("grid-layout-prediction-plan"))
        .stdout(predicate::str::contains("evaluate-period-prediction"))
        .stdout(predicate::str::contains("evaluate-spacing-prediction"))
        .stdout(predicate::str::contains("validate-mirror-observations"))
        .stdout(predicate::str::contains("evaluate-mirror-prediction"))
        .stdout(predicate::str::contains("validate-grid-observations"))
        .stdout(predicate::str::contains(
            "validate-tableau-hill-observations",
        ))
        .stdout(predicate::str::contains("evaluate-grid-prediction"))
        .stdout(predicate::str::contains("evaluate-tableau-hill-prediction"));
}

#[test]
fn ciphertext_profile_is_ciphertext_only_and_parseable() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "ciphertext-profile",
            "--max-period",
            "8",
            "--max-ngram",
            "3",
            "--iterations",
            "100",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("K4 Ciphertext Profile"))
        .stdout(predicate::str::contains("This is not a claimed solution."))
        .stdout(predicate::str::contains("index of coincidence:"))
        .stdout(predicate::str::contains(
            "Repeated N-gram Spacing Diagnostics",
        ))
        .stdout(predicate::str::contains("Repeated N-gram Spacing Baseline"))
        .stdout(predicate::str::contains("Period Coincidence Diagnostics"))
        .stdout(predicate::str::contains("Ciphertext-Only Baseline"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "ciphertext-profile",
            "--max-period",
            "8",
            "--max-ngram",
            "3",
            "--top",
            "5",
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
    assert_eq!(json["ciphertext_length"], 97);
    assert_eq!(json["period_profiles"].as_array().unwrap().len(), 8);
    assert_eq!(json["kasiski_factor_profiles"].as_array().unwrap().len(), 7);
    assert_eq!(json["baseline"]["iterations"], 100);
    assert_eq!(json["kasiski_baseline"]["iterations"], 100);
    assert!(
        json["kasiski_factor_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|period| period["period"] == 2
                && period["supporting_gaps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|gap| {
                        gap["right_position_one_based"].as_u64().unwrap()
                            > gap["left_position_one_based"].as_u64().unwrap()
                    }))
    );
    assert!(
        json["period_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|period| {
                period["period"] == 7
                    && period["shifted_matches"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|shifted_match| {
                            shifted_match["right_position_one_based"].as_u64().unwrap()
                                > shifted_match["left_position_one_based"].as_u64().unwrap()
                        })
            })
    );
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["note"].as_str().unwrap().contains("ciphertext-only"));
    assert!(json["letter_frequencies"].as_array().unwrap().iter().any(
        |frequency| frequency["letter"] == "K" && frequency["count"].as_u64().unwrap() > 1
    ));
    assert!(json["repeated_ngrams"].as_array().unwrap().len() <= 5);
}

#[test]
fn ciphertext_structure_prior_is_planning_only_and_parseable() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "ciphertext-structure-prior",
            "--max-period",
            "20",
            "--max-ngram",
            "4",
            "--iterations",
            "100",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Ciphertext Structure Prior"))
        .stdout(predicate::str::contains("This is not a claimed solution."))
        .stdout(predicate::str::contains("repeated-ngram-gap-factor"))
        .stdout(predicate::str::contains("shifted-ciphertext-coincidence"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "ciphertext-structure-prior",
            "--max-period",
            "20",
            "--max-ngram",
            "4",
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
    assert_eq!(json["artifact_kind"], "ciphertext-structure-prior");
    assert_eq!(json["hypothesis_family"], "ciphertext-only-position-prior");
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["public_anchor_fragments_used_for_discovery"], false);
    assert_eq!(
        json["public_anchor_fragments_used_as_primary_evidence"],
        false
    );
    assert!(
        json["selected_periods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|period| period["period"] == 2
                && period["support_kind"] == "repeated-ngram-gap-factor")
    );
    assert!(
        json["selected_periods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|period| period["period"] == 7
                && period["support_kind"] == "shifted-ciphertext-coincidence")
    );
}

#[test]
fn evaluate_ciphertext_prior_scores_source_backed_positions_without_promotion() {
    let temp = tempfile::tempdir().unwrap();
    let archive_dir = temp.path().join("ciphertext-prior-archive");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-ciphertext-prior-observations",
            "--artifact",
            "experiments/predictions/ciphertext-structure-prior-v1.json",
            "--preregistration",
            "experiments/preregistrations/ciphertext-structure-prior-v1.json",
            "--input",
            "experiments/position-observations/cia-k4-row-boundaries-v1.json",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"))
        .stdout(predicate::str::contains("\"artifact_valid\": true"))
        .stdout(predicate::str::contains(
            "\"artifact_path\": \"experiments/predictions/ciphertext-structure-prior-v1.json\"",
        ));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-ciphertext-prior",
            "--positions-file",
            "experiments/position-observations/cia-k4-row-boundaries-v1.json",
            "--prior-iterations",
            "100",
            "--iterations",
            "100",
            "--seed",
            "67",
            "--prior-seed",
            "67",
            "--output-dir",
            archive_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Ciphertext Prior Evaluation"))
        .stdout(predicate::str::contains("This is not a claimed solution."))
        .stdout(predicate::str::contains(
            "observation id: `cia-k4-row-boundaries-v1`",
        ))
        .stdout(predicate::str::contains("source-backed observation: true"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-ciphertext-prior",
            "--positions-file",
            "experiments/position-observations/cia-k4-row-boundaries-v1.json",
            "--prior-iterations",
            "100",
            "--iterations",
            "100",
            "--seed",
            "67",
            "--prior-seed",
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
    assert_eq!(json["observation_id"], "cia-k4-row-boundaries-v1");
    assert_eq!(json["source_backed_observation"], true);
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["best_period"], 2);
    assert!(
        json["period_results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|period| period["period"] == 7
                && period["support_kind"] == "shifted-ciphertext-coincidence")
    );

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            archive_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let validation: Value = serde_json::from_slice(&validation_output).unwrap();
    assert_eq!(validation["artifact_kind"], "ciphertext-prior");
    assert_eq!(validation["source_backed_observation"], true);
    assert_eq!(validation["valid"], true);
    assert_eq!(validation["promoted_candidate"], false);
}

#[test]
fn ciphertext_residue_balance_prior_has_committed_prediction_artifact() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["ciphertext-residue-balance-prior", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            "experiments/predictions/ciphertext-residue-balance-prior-v1.json",
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(fixture, json);
    assert_eq!(json["artifact_kind"], "ciphertext-residue-balance-prior");
    assert_eq!(
        json["hypothesis_family"],
        "ciphertext-residue-balance-position-prior"
    );
    assert_eq!(json["selected_moduli_count"], 12);
    assert_eq!(json["promoted_candidate"], false);

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/ciphertext-residue-balance-prior-v1.json",
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
    assert_eq!(validation["artifact_kind"], "ciphertext-residue-balance");
    assert_eq!(validation["expected_plan_count"], 12);
    assert_eq!(validation["artifact_plan_count"], 12);
}

#[test]
fn ciphertext_window_balance_prior_has_committed_prediction_artifact() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["ciphertext-window-balance-prior", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string("experiments/predictions/ciphertext-window-balance-v1.json")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(fixture, json);
    assert_eq!(json["artifact_kind"], "ciphertext-window-balance-prior");
    assert_eq!(
        json["hypothesis_family"],
        "ciphertext-window-balance-position-prior"
    );
    assert_eq!(json["window_balance_position_count"], 20);
    assert_eq!(json["promoted_candidate"], false);

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/ciphertext-window-balance-v1.json",
            "--require-unique-artifact",
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
    assert_eq!(validation["artifact_kind"], "ciphertext-window-balance");
    assert_eq!(validation["expected_plan_count"], 20);
    assert_eq!(validation["duplicate_artifact_paths"].as_array(), None);
}

#[test]
fn ciphertext_hotspot_prior_and_evaluation_are_preregistration_gated() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("hotspot-observations.json");
    let archive_dir = temp.path().join("ciphertext-hotspot-archive");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-ciphertext-hotspot-test",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/cia-source-review-v1.json",
  "positions_one_based": [1, 14, 15],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "14": "Synthetic source-backed note for position 14.",
    "15": "Synthetic source-backed note for position 15."
  },
  "rationale": "Synthetic CLI test fixture for ciphertext-hotspot validation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["ciphertext-hotspot-prior", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string("experiments/predictions/ciphertext-hotspot-prior-v1.json")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(fixture, json);
    assert_eq!(json["artifact_kind"], "ciphertext-hotspot-prior");
    assert_eq!(
        json["hypothesis_family"],
        "ciphertext-hotspot-position-prior"
    );
    assert_eq!(json["hotspot_count"], 20);
    assert_eq!(json["promoted_candidate"], false);

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-ciphertext-hotspot-observations",
            "--artifact",
            "experiments/predictions/ciphertext-hotspot-prior-v1.json",
            "--preregistration",
            "experiments/preregistrations/ciphertext-hotspot-prior-v1.json",
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
    let validation: Value = serde_json::from_slice(&validation_output).unwrap();
    assert_eq!(validation["valid"], true);
    assert_eq!(
        validation["preregistration_id"],
        "ciphertext-hotspot-prior-v1"
    );
    assert_eq!(validation["artifact_valid"], true);
    assert_eq!(
        validation["observation_id"],
        "synthetic-ciphertext-hotspot-test"
    );
    assert_eq!(validation["observed_position_count"], 3);
    assert_eq!(validation["promoted_candidate"], false);

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-ciphertext-hotspot",
            "--artifact",
            "experiments/predictions/ciphertext-hotspot-prior-v1.json",
            "--preregistration",
            "experiments/preregistrations/ciphertext-hotspot-prior-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            archive_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["observation_id"], "synthetic-ciphertext-hotspot-test");
    assert_eq!(json["source_backed_observation"], true);
    assert_eq!(json["hotspot_hits"], 2);
    assert_eq!(
        json["matching_hotspot_positions_one_based"],
        serde_json::json!([14, 15])
    );
    assert_eq!(json["promoted_candidate"], false);

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            archive_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let archive_validation: Value = serde_json::from_slice(&validation_output).unwrap();
    assert_eq!(archive_validation["artifact_kind"], "ciphertext-hotspot");
    assert_eq!(archive_validation["source_backed_observation"], true);
    assert_eq!(archive_validation["valid"], true);
    assert_eq!(archive_validation["promoted_candidate"], false);
}

#[test]
fn ciphertext_rarity_prior_and_evaluation_are_preregistration_gated() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("rarity-observations.json");
    let archive_dir = temp.path().join("ciphertext-rarity-archive");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-ciphertext-rarity-test",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/cia-source-review-v1.json",
  "positions_one_based": [4, 61, 97],
  "position_notes": {
    "4": "Synthetic source-backed note for position 4.",
    "61": "Synthetic source-backed note for position 61.",
    "97": "Synthetic source-backed note for position 97."
  },
  "rationale": "Synthetic CLI test fixture for ciphertext-rarity validation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["ciphertext-rarity-prior", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string("experiments/predictions/ciphertext-rarity-prior-v1.json")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(fixture, json);
    assert_eq!(json["artifact_kind"], "ciphertext-rarity-prior");
    assert_eq!(
        json["hypothesis_family"],
        "ciphertext-rarity-position-prior"
    );
    assert_eq!(json["rare_position_count"], 20);
    assert_eq!(json["promoted_candidate"], false);

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-ciphertext-rarity-observations",
            "--artifact",
            "experiments/predictions/ciphertext-rarity-prior-v1.json",
            "--preregistration",
            "experiments/preregistrations/ciphertext-rarity-prior-v1.json",
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
    let validation: Value = serde_json::from_slice(&validation_output).unwrap();
    assert_eq!(validation["valid"], true);
    assert_eq!(
        validation["preregistration_id"],
        "ciphertext-rarity-prior-v1"
    );
    assert_eq!(validation["artifact_valid"], true);
    assert_eq!(
        validation["observation_id"],
        "synthetic-ciphertext-rarity-test"
    );
    assert_eq!(validation["observed_position_count"], 3);
    assert_eq!(validation["promoted_candidate"], false);

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-ciphertext-rarity",
            "--artifact",
            "experiments/predictions/ciphertext-rarity-prior-v1.json",
            "--preregistration",
            "experiments/preregistrations/ciphertext-rarity-prior-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--iterations",
            "100",
            "--seed",
            "67",
            "--output-dir",
            archive_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["observation_id"], "synthetic-ciphertext-rarity-test");
    assert_eq!(json["source_backed_observation"], true);
    assert_eq!(json["rare_hits"], 3);
    assert_eq!(
        json["matching_rare_positions_one_based"],
        serde_json::json!([4, 61, 97])
    );
    assert_eq!(json["promoted_candidate"], false);

    let validation_output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            archive_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let archive_validation: Value = serde_json::from_slice(&validation_output).unwrap();
    assert_eq!(archive_validation["artifact_kind"], "ciphertext-rarity");
    assert_eq!(archive_validation["source_backed_observation"], true);
    assert_eq!(archive_validation["valid"], true);
    assert_eq!(archive_validation["promoted_candidate"], false);
}

fn public_anchor_compatible_claim_fixture() -> String {
    let mut letters = vec![b'A'; K4_CIPHERTEXT.len()];
    for anchor in known_anchors() {
        for (index, value) in anchor.plaintext.bytes().enumerate() {
            letters[anchor.start_zero_based + index] = value;
        }
    }
    String::from_utf8(letters).unwrap()
}

fn public_anchor_compatible_reconciliation_fixture() -> String {
    let claim = public_anchor_compatible_claim_fixture();
    let mut table = String::from("i,C,P\n");
    for (index, (ciphertext, plaintext)) in K4_CIPHERTEXT.chars().zip(claim.chars()).enumerate() {
        table.push_str(&format!("{},{},{}\n", index + 1, ciphertext, plaintext));
    }
    table
}

#[test]
fn verify_plaintext_claim_reports_structure_without_leaking_claim_text() {
    let temp = tempfile::tempdir().unwrap();
    let claim_path = temp.path().join("claim.txt");
    let claim = public_anchor_compatible_claim_fixture();
    std::fs::write(&claim_path, &claim).unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "verify-plaintext-claim",
            "--input",
            claim_path.to_str().unwrap(),
            "--source-id",
            "solvekryptos-2026-claim",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output.clone()).unwrap();
    assert!(!stdout.contains(&claim));

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["source_id"], "solvekryptos-2026-claim");
    assert_eq!(json["normalized_letter_count"], 97);
    assert_eq!(json["public_anchor_match_count"], 4);
    assert_eq!(json["structural_checks_passed"], true);
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["implied_shift_distinct_values"].as_u64().unwrap() > 0);

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "verify-plaintext-claim",
            "--input",
            claim_path.to_str().unwrap(),
            "--source-id",
            "solvekryptos-2026-claim",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("# Plaintext Claim Verification"))
        .stdout(predicate::str::contains("public anchors: 4/4"))
        .stdout(predicate::str::contains("structural checks passed: true"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("AAAA").not());
}

#[test]
fn verify_claim_reconciliation_reports_structure_without_leaking_claim_text() {
    let temp = tempfile::tempdir().unwrap();
    let table_path = temp.path().join("claim-table.csv");
    let table = public_anchor_compatible_reconciliation_fixture();
    let claim = public_anchor_compatible_claim_fixture();
    std::fs::write(&table_path, table).unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "verify-claim-reconciliation",
            "--input",
            table_path.to_str().unwrap(),
            "--source-id",
            "solvekryptos-2026-claim",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output.clone()).unwrap();
    assert!(!stdout.contains(&claim));

    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["source_id"], "solvekryptos-2026-claim");
    assert_eq!(json["row_count"], 97);
    assert_eq!(json["row_count_matches"], true);
    assert_eq!(json["all_ciphertext_matches"], true);
    assert_eq!(json["ciphertext_value_checked_count"], 0);
    assert_eq!(json["all_ciphertext_values_match"], true);
    assert_eq!(json["plaintext_value_checked_count"], 0);
    assert_eq!(json["all_plaintext_values_match"], true);
    assert_eq!(json["tier_checked_count"], 0);
    assert_eq!(json["all_tier_values_match"], true);
    assert_eq!(json["lane_checked_count"], 0);
    assert_eq!(json["all_lane_values_match"], true);
    assert_eq!(json["r_value_checked_count"], 0);
    assert_eq!(json["all_r_values_match"], true);
    assert_eq!(json["gate_checked_count"], 0);
    assert_eq!(json["all_gate_values_binary"], true);
    assert_eq!(json["r_plus_gate_checked_count"], 0);
    assert_eq!(json["all_r_plus_gate_matches"], true);
    assert_eq!(json["z2_handoff_checked_count"], 0);
    assert_eq!(json["all_z2_handoff_matches"], true);
    assert_eq!(json["public_anchor_match_count"], 4);
    assert_eq!(json["structural_checks_passed"], true);
    assert_eq!(json["promoted_candidate"], false);

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "verify-claim-reconciliation",
            "--input",
            table_path.to_str().unwrap(),
            "--source-id",
            "solvekryptos-2026-claim",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "# Claim Reconciliation Verification",
        ))
        .stdout(predicate::str::contains("rows: 97/97"))
        .stdout(predicate::str::contains("all ciphertext matches: true"))
        .stdout(predicate::str::contains("ciphertext numeric values: 0/0"))
        .stdout(predicate::str::contains("plaintext numeric values: 0/0"))
        .stdout(predicate::str::contains("tier values: 0/0"))
        .stdout(predicate::str::contains("lane values: 0/0"))
        .stdout(predicate::str::contains("published R/shift values: 0/0"))
        .stdout(predicate::str::contains("gate values binary: 0/0"))
        .stdout(predicate::str::contains("base-r plus gate checks: 0/0"))
        .stdout(predicate::str::contains("Z2 handoff checks: 0/0"))
        .stdout(predicate::str::contains("public anchors: 4/4"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains(&claim).not());
}

#[test]
fn verify_claim_reconciliation_rejects_non_quarantined_sources() {
    let temp = tempfile::tempdir().unwrap();
    let table_path = temp.path().join("claim-table.csv");
    std::fs::write(
        &table_path,
        public_anchor_compatible_reconciliation_fixture(),
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "verify-claim-reconciliation",
            "--input",
            table_path.to_str().unwrap(),
            "--source-id",
            "cia-artifact",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unverified-solution-claim"));
}

#[test]
fn verify_plaintext_claim_rejects_non_quarantined_sources() {
    let temp = tempfile::tempdir().unwrap();
    let claim_path = temp.path().join("claim.txt");
    std::fs::write(&claim_path, public_anchor_compatible_claim_fixture()).unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "verify-plaintext-claim",
            "--input",
            claim_path.to_str().unwrap(),
            "--source-id",
            "cia-artifact",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unverified-solution-claim"));
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
        .stdout(predicate::str::contains("archived"))
        .stdout(predicate::str::contains(
            "Review each eligible source URL before drafting observation positions",
        ))
        .stdout(predicate::str::contains("local source archive"))
        .stdout(predicate::str::contains("one position note per scored"))
        .stdout(predicate::str::contains("validate-evaluation-archive"))
        .stdout(predicate::str::contains("source-observation-status"))
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
                && source["locally_archived"] == true
                && source["archive_url"] == "sources/archives/cia-sculpture-2026-05-27.md"
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
    assert!(
        json["observation_requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|requirement| requirement.as_str().unwrap().contains("source-review file"))
    );
    assert!(
        json["observation_requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|requirement| requirement
                .as_str()
                .unwrap()
                .contains("local source archive"))
    );
    assert!(
        json["source_observation_status_command"]
            .as_str()
            .unwrap()
            .contains("source-observation-status")
    );
}

#[test]
fn init_source_review_writes_prescore_review_file() {
    let temp = tempfile::tempdir().unwrap();
    let output_path = temp.path().join("source-review.json");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "cia-source-review-v1",
            "--source-id",
            "cia-artifact",
            "--source-id",
            "cia-sculpture",
            "--review-note",
            "Reviewed eligible CIA source pages before selecting any non-anchor positions.",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Review File"))
        .stdout(predicate::str::contains(
            "review id: `cia-source-review-v1`",
        ))
        .stdout(predicate::str::contains(
            "source ids: cia-artifact, cia-sculpture",
        ))
        .stdout(predicate::str::contains("local archives missing: 0"))
        .stdout(predicate::str::contains("promoted: false"));

    let file_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&output_path).unwrap()).unwrap();
    assert_eq!(file_json["id"], "cia-source-review-v1");
    assert_eq!(file_json["source_ids"].as_array().unwrap().len(), 2);
    assert_eq!(file_json["sources"].as_array().unwrap().len(), 2);
    assert_eq!(file_json["promoted_candidate"], false);
    assert!(
        file_json["required_review_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step
                .as_str()
                .unwrap()
                .contains("Run the family-specific observation validator"))
    );
    assert!(
        file_json["observation_requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|requirement| requirement.as_str().unwrap().contains("source-review file"))
    );

    let json_output_path = temp.path().join("source-review-json.json");
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "cia-source-review-v2",
            "--source-id",
            "cia-artifact",
            "--review-note",
            "Reviewed source before JSON scaffold assertion.",
            "--output",
            json_output_path.to_str().unwrap(),
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
    assert_eq!(json["review"]["id"], "cia-source-review-v2");
    assert_eq!(json["review"]["promoted_candidate"], false);
}

#[test]
fn validate_source_review_checks_prescore_review_file() {
    let temp = tempfile::tempdir().unwrap();
    let output_path = temp.path().join("source-review.json");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "cia-source-review-v1",
            "--source-id",
            "cia-artifact",
            "--source-id",
            "cia-sculpture",
            "--review-note",
            "Reviewed eligible CIA source pages before selecting any non-anchor positions.",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-source-review",
            "--input",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Review Validation"))
        .stdout(predicate::str::contains(
            "review id: `cia-source-review-v1`",
        ))
        .stdout(predicate::str::contains("reviewed sources: 2"))
        .stdout(predicate::str::contains("local archives missing: 0"))
        .stdout(predicate::str::contains("valid: true"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-source-review",
            "--input",
            output_path.to_str().unwrap(),
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
    assert_eq!(json["review_id"], "cia-source-review-v1");
    assert_eq!(json["source_ids"].as_array().unwrap().len(), 2);
    assert_eq!(json["missing_local_archive_count"], 0);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn validate_source_review_rejects_tampered_review_file() {
    let temp = tempfile::tempdir().unwrap();
    let output_path = temp.path().join("source-review.json");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "cia-source-review-v1",
            "--source-id",
            "cia-artifact",
            "--review-note",
            "Reviewed eligible CIA source page before selecting any non-anchor positions.",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut json: Value =
        serde_json::from_str(&std::fs::read_to_string(&output_path).unwrap()).unwrap();
    json["sources"][0]["url"] = Value::String("https://example.invalid/tampered".to_string());
    std::fs::write(&output_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-source-review",
            "--input",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "source-review file failed validation",
        ));
}

#[test]
fn source_review_status_reports_missing_valid_and_invalid_reviews() {
    let missing = tempfile::tempdir().unwrap().path().join("missing-reviews");
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "source-review-status",
            "--root",
            missing.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["scanned_review_count"], 0);
    assert_eq!(json["valid_review_count"], 0);
    assert_eq!(json["invalid_review_count"], 0);
    assert_eq!(json["missing_root_count"], 1);
    assert_eq!(json["source_review_available"], false);
    assert_eq!(json["promoted_candidate"], false);

    let temp = tempfile::tempdir().unwrap();
    let valid_path = temp.path().join("valid-source-review.json");
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "cia-source-review-v1",
            "--source-id",
            "cia-artifact",
            "--source-id",
            "cia-sculpture",
            "--review-note",
            "Reviewed eligible CIA source pages before selecting any non-anchor positions.",
            "--output",
            valid_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let invalid_path = temp.path().join("invalid-source-review.json");
    let mut invalid_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&valid_path).unwrap()).unwrap();
    invalid_json["id"] = Value::String("invalid-source-review-v1".to_string());
    invalid_json["sources"][0]["url"] = Value::String("https://example.invalid/tampered".into());
    std::fs::write(
        &invalid_path,
        serde_json::to_string_pretty(&invalid_json).unwrap(),
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "source-review-status",
            "--root",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Review Status"))
        .stdout(predicate::str::contains("reviews scanned: 2"))
        .stdout(predicate::str::contains("valid reviews: 1"))
        .stdout(predicate::str::contains("invalid reviews: 1"))
        .stdout(predicate::str::contains("source review available: true"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "source-review-status",
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
    assert_eq!(json["scanned_review_count"], 2);
    assert_eq!(json["valid_review_count"], 1);
    assert_eq!(json["invalid_review_count"], 1);
    assert_eq!(json["missing_root_count"], 0);
    assert_eq!(json["source_review_available"], true);
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["reviews"].as_array().unwrap().iter().any(|review| {
        review["review_id"] == "cia-source-review-v1"
            && review["valid"] == true
            && review["missing_local_archive_count"] == 0
    }));
    assert!(json["reviews"].as_array().unwrap().iter().any(|review| {
        review["valid"] == false && !review["errors"].as_array().unwrap().is_empty()
    }));
}

#[test]
fn source_observation_status_reports_reviewed_used_and_blocked_sources() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("source-observation-status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Observation Status"))
        .stdout(predicate::str::contains("eligible sources: 2"))
        .stdout(predicate::str::contains("reviewed eligible sources: 2"))
        .stdout(predicate::str::contains("used eligible sources: 1"))
        .stdout(predicate::str::contains("unused eligible sources: 1"))
        .stdout(predicate::str::contains(
            "all source-backed archives negative: true",
        ))
        .stdout(predicate::str::contains(
            "new-source-backed-rationale-new-source-or-distinct-prediction-artifact",
        ))
        .stdout(predicate::str::contains("cia-artifact"))
        .stdout(predicate::str::contains("cia-sculpture"))
        .stdout(predicate::str::contains("null_mean="))
        .stdout(predicate::str::contains("negative/non-significant"))
        .stdout(predicate::str::contains("explicitly marked non-scorable"))
        .stdout(predicate::str::contains("non-scorable"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["source-observation-status", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["eligible_source_count"], 2);
    assert_eq!(json["reviewed_eligible_source_count"], 2);
    assert_eq!(json["used_eligible_source_count"], 1);
    assert_eq!(json["unused_eligible_source_count"], 1);
    assert_eq!(json["sources_with_scored_position_markers"], 1);
    assert_eq!(json["all_source_backed_archives_negative"], true);
    assert_eq!(
        json["next_action_kind"],
        "new-source-backed-rationale-new-source-or-distinct-prediction-artifact"
    );
    assert!(
        json["recommended_next_step"]
            .as_str()
            .unwrap()
            .contains("explicitly marked non-scorable")
    );
    assert_eq!(json["promoted_candidate"], false);

    let statuses = json["statuses"].as_array().unwrap();
    let artifact = statuses
        .iter()
        .find(|status| status["source_id"] == "cia-artifact")
        .unwrap();
    assert_eq!(artifact["reviewed_by_valid_source_review"], true);
    assert_eq!(artifact["used_in_source_backed_archive"], false);
    assert_eq!(artifact["current_archive_has_scored_positions"], false);
    assert!(
        artifact["non_scorable_reason"]
            .as_str()
            .unwrap()
            .contains("no one-based non-anchor K4 positions")
    );
    assert!(
        artifact["archived_evidence_summaries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        artifact["action_status"]
            .as_str()
            .unwrap()
            .contains("marks it non-scorable")
    );

    let sculpture = statuses
        .iter()
        .find(|status| status["source_id"] == "cia-sculpture")
        .unwrap();
    assert_eq!(sculpture["reviewed_by_valid_source_review"], true);
    assert_eq!(sculpture["used_in_source_backed_archive"], true);
    assert_eq!(sculpture["current_archive_has_scored_positions"], true);
    let evidence_summaries = sculpture["archived_evidence_summaries"].as_array().unwrap();
    assert!(evidence_summaries.iter().any(|summary| {
        summary["artifact_kind"] == "period"
            && summary["support_status"] == "negative/non-significant"
            && summary["null_mean_best_hits"].as_f64().unwrap() > 0.0
            && summary["empirical_p_value"].as_f64().unwrap() > 0.05
    }));
    assert!(evidence_summaries.iter().any(|summary| {
        summary["artifact_kind"] == "tableau-hill"
            && summary["support_status"] == "negative/non-significant"
            && summary["best_model"] == "7x14 row 1 concentration"
            && summary["observed_hits"] == "3/6 positions"
            && summary["empirical_p_value"].as_f64().unwrap() > 0.05
    }));
    assert!(
        sculpture["source_backed_archive_directories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|directory| directory
                .as_str()
                .unwrap()
                .contains("results/grid-observations/cia-k4-row-boundaries-v1"))
    );
    assert!(
        sculpture["source_backed_archive_directories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|directory| directory
                .as_str()
                .unwrap()
                .contains("results/grid-observations/cia-k4-row-boundaries-column-v1"))
    );
    assert!(
        sculpture["source_backed_archive_directories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|directory| directory
                .as_str()
                .unwrap()
                .contains("results/grid-observations/cia-k4-row-boundaries-compass-axis-v1"))
    );
    assert!(evidence_summaries.iter().any(|summary| {
        summary["artifact_kind"] == "grid"
            && summary["support_status"] == "negative/non-significant"
            && summary["best_model"] == "7x14 column edges"
            && summary["observed_hits"] == "4/6 positions"
            && summary["empirical_p_value"].as_f64().unwrap() > 0.05
    }));
    assert!(evidence_summaries.iter().any(|summary| {
        summary["artifact_kind"] == "grid"
            && summary["support_status"] == "negative/non-significant"
            && summary["best_model"] == "7x14 compass-axis positions"
            && summary["observed_hits"] == "1/6 positions"
            && summary["empirical_p_value"].as_f64().unwrap() > 0.05
    }));
    assert!(
        sculpture["source_backed_archive_directories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|directory| directory
                .as_str()
                .unwrap()
                .contains("results/tableau-hill-observations/cia-k4-row-boundaries-v1"))
    );
}

#[test]
fn source_frontier_classifies_all_registered_sources() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("source-frontier")
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Frontier"))
        .stdout(predicate::str::contains("sources: 20"))
        .stdout(predicate::str::contains(
            "scored-observation eligible sources: 2",
        ))
        .stdout(predicate::str::contains(
            "sources with scored-position markers: 1",
        ))
        .stdout(predicate::str::contains("valid source-backed archives: 26"))
        .stdout(predicate::str::contains(
            "all source-backed archives negative: true",
        ))
        .stdout(predicate::str::contains("Frontier Blocking Conditions"))
        .stdout(predicate::str::contains(
            "source-backed-evidence-negative-or-non-significant",
        ))
        .stdout(predicate::str::contains("Required Next Evidence"))
        .stdout(predicate::str::contains(
            "validate-prediction-artifact --require-unique-artifact",
        ))
        .stdout(predicate::str::contains("Disallowed Next Actions"))
        .stdout(predicate::str::contains("Archived Evaluations"))
        .stdout(predicate::str::contains(
            "Already used in 26 source-backed evaluation archives",
        ))
        .stdout(predicate::str::contains("context-only"))
        .stdout(predicate::str::contains("quarantined-claim"))
        .stdout(predicate::str::contains(
            "eligible-but-currently-non-scorable",
        ))
        .stdout(predicate::str::contains("scored-observation-ready"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["source-frontier", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["source_count"], 20);
    assert_eq!(json["scored_observation_eligible_count"], 2);
    assert_eq!(json["scored_position_marker_count"], 1);
    assert_eq!(json["valid_source_backed_archive_count"], 26);
    assert_eq!(json["all_source_backed_archives_negative"], true);
    assert_eq!(json["quarantined_claim_count"], 1);
    assert_eq!(json["promoted_candidate"], false);
    assert!(
        json["frontier_blocking_conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|condition| condition.as_str().unwrap()
                == "source-backed-evidence-negative-or-non-significant")
    );
    assert!(
        json["required_next_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|requirement| requirement
                .as_str()
                .unwrap()
                .contains("validate-prediction-artifact --require-unique-artifact"))
    );
    assert!(
        json["disallowed_next_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action
                .as_str()
                .unwrap()
                .contains("do not score cia-artifact"))
    );
    assert!(
        json["recommended_next_step"]
            .as_str()
            .unwrap()
            .contains("new source-backed rationale")
    );

    let sources = json["frontier_sources"].as_array().unwrap();
    let cia_artifact = sources
        .iter()
        .find(|source| source["id"] == "cia-artifact")
        .unwrap();
    assert_eq!(
        cia_artifact["frontier_class"],
        "eligible-but-currently-non-scorable"
    );
    assert!(
        cia_artifact["non_scorable_reason"]
            .as_str()
            .unwrap()
            .contains("no one-based non-anchor K4 positions")
    );

    let cia_sculpture = sources
        .iter()
        .find(|source| source["id"] == "cia-sculpture")
        .unwrap();
    assert_eq!(cia_sculpture["frontier_class"], "scored-observation-ready");
    assert_eq!(cia_sculpture["current_archive_has_scored_positions"], true);
    assert_eq!(cia_sculpture["source_backed_archive_count"], 26);
    assert!(
        cia_sculpture["allowed_next_action"]
            .as_str()
            .unwrap()
            .contains("inspect archived support statuses")
    );
    assert!(
        cia_sculpture["archived_support_statuses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|status| status
                .as_str()
                .unwrap()
                .contains("period:negative/non-significant"))
    );

    let kryptos_today = sources
        .iter()
        .find(|source| source["id"] == "kryptos-today-project-k4-2026")
        .unwrap();
    assert_eq!(kryptos_today["frontier_class"], "context-only");
    assert_eq!(kryptos_today["allowed_use"], "methodology-context");
    assert!(
        kryptos_today["non_scorable_reason"]
            .as_str()
            .unwrap()
            .contains("no scoreable non-anchor K4 observations")
    );

    let kryptosbot_findings = sources
        .iter()
        .find(|source| source["id"] == "kryptosbot-findings-2026")
        .unwrap();
    assert_eq!(kryptosbot_findings["frontier_class"], "context-only");
    assert_eq!(kryptosbot_findings["allowed_use"], "methodology-context");
    assert!(
        kryptosbot_findings["non_scorable_reason"]
            .as_str()
            .unwrap()
            .contains("open structural anomalies")
    );

    let claim = sources
        .iter()
        .find(|source| source["id"] == "solvekryptos-2026-claim")
        .unwrap();
    assert_eq!(claim["frontier_class"], "quarantined-claim");
    assert!(
        claim["allowed_next_action"]
            .as_str()
            .unwrap()
            .contains("temporary local claim verifiers")
    );

    let ap = sources
        .iter()
        .find(|source| source["id"] == "ap-2025-auction")
        .unwrap();
    assert_eq!(ap["frontier_class"], "context-only");

    let smithsonian = sources
        .iter()
        .find(|source| source["id"] == "smithsonian-2026-archive-discovery")
        .unwrap();
    assert_eq!(smithsonian["frontier_class"], "context-only");
    assert!(
        smithsonian["allowed_next_action"]
            .as_str()
            .unwrap()
            .contains("preregistration rationale")
    );

    let nsa = sources
        .iter()
        .find(|source| source["id"] == "nsa-declassified-kryptos-doc3")
        .unwrap();
    assert_eq!(nsa["frontier_class"], "context-only");
    assert_eq!(nsa["allowed_use"], "archive-context-only");
    assert_eq!(nsa["current_archive_has_scored_positions"], false);

    let nsa_doc7 = sources
        .iter()
        .find(|source| source["id"] == "nsa-kryptos-doc7-technical-analysis")
        .unwrap();
    assert_eq!(nsa_doc7["frontier_class"], "context-only");
    assert_eq!(nsa_doc7["allowed_use"], "archive-context-only");
    assert_eq!(nsa_doc7["current_archive_has_scored_positions"], false);
    assert!(
        nsa_doc7["non_scorable_reason"]
            .as_str()
            .unwrap()
            .contains("no one-based non-anchor K4 positions")
    );

    let nsa_index = sources
        .iter()
        .find(|source| source["id"] == "nsa-kryptos-foia-release-index")
        .unwrap();
    assert_eq!(nsa_index["frontier_class"], "context-only");
    assert_eq!(nsa_index["allowed_use"], "archive-context-only");
    assert_eq!(nsa_index["current_archive_has_scored_positions"], false);

    let nsa_doc1 = sources
        .iter()
        .find(|source| source["id"] == "nsa-kryptos-doc1-resolution-memo")
        .unwrap();
    assert_eq!(nsa_doc1["frontier_class"], "context-only");
    assert_eq!(nsa_doc1["allowed_use"], "archive-context-only");
    assert_eq!(nsa_doc1["current_archive_has_scored_positions"], false);

    let nsa_summary = sources
        .iter()
        .find(|source| source["id"] == "nsa-kryptos-summary-revelations")
        .unwrap();
    assert_eq!(nsa_summary["frontier_class"], "context-only");
    assert_eq!(nsa_summary["allowed_use"], "archive-context-only");
    assert_eq!(nsa_summary["current_archive_has_scored_positions"], false);

    let nsa_doc8 = sources
        .iter()
        .find(|source| source["id"] == "nsa-kryptos-doc8-cryptogram")
        .unwrap();
    assert_eq!(nsa_doc8["frontier_class"], "context-only");
    assert_eq!(nsa_doc8["allowed_use"], "public-anchor-summary");
    assert_eq!(nsa_doc8["current_archive_has_scored_positions"], false);
}

#[test]
fn source_frontier_summary_prints_compact_next_action() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["source-frontier", "--summary"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Frontier"))
        .stdout(predicate::str::contains("Operational Summary"))
        .stdout(predicate::str::contains(
            "source-backed-evidence-negative-or-non-significant",
        ))
        .stdout(predicate::str::contains(
            "scored-observation-ready sources: cia-sculpture",
        ))
        .stdout(predicate::str::contains(
            "eligible but currently non-scorable sources: cia-artifact",
        ))
        .stdout(predicate::str::contains(
            "already-scored source-backed archives: cia-sculpture (26 archived evaluations)",
        ))
        .stdout(predicate::str::contains(
            "do not rerun negative row-boundary evidence as new evidence",
        ))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("## Sources").not());
}

#[test]
fn source_intake_packet_documents_new_source_gate() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("source-intake-packet")
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Intake Packet"))
        .stdout(predicate::str::contains("This is not a claimed solution."))
        .stdout(predicate::str::contains("public-facts-only"))
        .stdout(predicate::str::contains("scored_positions_one_based"))
        .stdout(predicate::str::contains("non_scorable_reason"))
        .stdout(predicate::str::contains("validate-evaluation-archive"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["source-intake-packet", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["promoted_candidate"], false);
    assert!(
        json["registry_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field.as_str().unwrap().contains("allowed_use"))
    );
    assert!(
        json["scoreable_evidence_requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|requirement| requirement
                .as_str()
                .unwrap()
                .contains("validated source-review artifact"))
    );
    assert!(
        json["rejection_rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule
                .as_str()
                .unwrap()
                .contains("unverified solution claims"))
    );
    assert!(
        json["archive_template"]
            .as_str()
            .unwrap()
            .contains("quote-free local review snapshot")
    );
}

#[test]
fn validate_source_archive_checks_registered_metadata_and_boundaries() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-source-archive",
            "--source-id",
            "cia-sculpture",
            "--input",
            "sources/archives/cia-sculpture-2026-05-27.md",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"))
        .stdout(predicate::str::contains(
            "\"archive_has_scored_positions\": true",
        ))
        .stdout(predicate::str::contains("\"promoted_candidate\": false"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-source-archive",
            "--source-id",
            "cia-artifact",
            "--input",
            "sources/archives/cia-artifact-2026-05-27.md",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Source Archive Validation"))
        .stdout(predicate::str::contains("valid: true"))
        .stdout(predicate::str::contains(
            "no one-based non-anchor K4 positions",
        ));
}

#[test]
fn validate_source_archive_rejects_wrong_source_or_forbidden_scored_context() {
    let temp = tempfile::tempdir().unwrap();
    let archive_path = temp.path().join("bad-archive.md");
    std::fs::write(
        &archive_path,
        "# Source Snapshot\n\nsource_id: `elonka-kryptos`\nsource_url: https://www.elonka.com/kryptos/\nreviewed_at: 2026-05-28\narchive_kind: quote-free local review snapshot\npromoted_candidate: false\n\n## Reviewed Facts\n\n- scored_positions_one_based: 1,2,3\n\n## Boundary\n\n- No candidate material, key stream, route, or plaintext is promoted.\n",
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-source-archive",
            "--source-id",
            "elonka-kryptos",
            "--input",
            archive_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"valid\": false"))
        .stdout(predicate::str::contains(
            "scored_positions_one_based is only allowed for public-facts-only sources",
        ));
}

#[test]
fn init_source_review_rejects_context_only_sources() {
    let temp = tempfile::tempdir().unwrap();
    let output_path = temp.path().join("source-review.json");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "bad-source-review",
            "--source-id",
            "elonka-kryptos",
            "--review-note",
            "This should fail because the source is public-anchor context only.",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used for scored"));
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
        .stdout(predicate::str::contains("periods: 8"))
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
    assert_eq!(json["period_count"], 8);
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["plans"].as_array().unwrap().len(), 8);
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
        .stdout(predicate::str::contains("moduli: 8"))
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
    assert_eq!(json["modulus_count"], 8);
    assert_eq!(json["promoted_candidate"], false);
    assert_eq!(json["plans"].as_array().unwrap().len(), 8);
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
fn tableau_hill_prediction_plan_is_tooling_ready_and_non_promotional() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["tableau-hill-prediction-plan"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Tableau/HILL Prediction Plan"))
        .stdout(predicate::str::contains("evaluator status: tooling-ready"))
        .stdout(predicate::str::contains(
            "mapping status: fixed-before-scoring",
        ))
        .stdout(predicate::str::contains(
            "tableau dimensions: 7 rows x 14 columns (98 cells)",
        ))
        .stdout(predicate::str::contains(
            "candidate material allowed: false",
        ))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["tableau-hill-prediction-plan", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["hypothesis_family"], "tableau-hill-prediction");
    assert_eq!(json["artifact_kind"], "tableau-hill-source-mapping-plan");
    assert_eq!(json["evaluator_status"], "tooling-ready");
    assert_eq!(json["mapping_status"], "fixed-before-scoring");
    assert_eq!(json["row_count"], 7);
    assert_eq!(json["column_count"], 14);
    assert_eq!(json["cell_count"], 98);
    assert_eq!(json["k4_position_count"], 97);
    assert_eq!(json["padding_cell_count"], 1);
    assert_eq!(json["padding_cell_index_one_based"], 98);
    assert_eq!(json["candidate_material_allowed"], false);
    assert_eq!(json["promoted_candidate"], false);
    assert!(
        json["required_next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step
                .as_str()
                .unwrap()
                .contains("evaluate-tableau-hill-prediction"))
    );
    let coordinate_mapping = json["coordinate_mapping"].as_array().unwrap();
    assert_eq!(coordinate_mapping.len(), 98);
    assert_eq!(coordinate_mapping[0]["k4_position_one_based"], 1);
    assert_eq!(coordinate_mapping[0]["row_one_based"], 1);
    assert_eq!(coordinate_mapping[0]["column_one_based"], 1);
    assert_eq!(coordinate_mapping[97]["k4_position_one_based"], Value::Null);
    assert_eq!(coordinate_mapping[97]["is_padding"], true);
    assert_eq!(
        json["source_ids"].as_array().unwrap()[0],
        "rumkin-k4-reference"
    );
    assert!(
        json["source_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source == "cia-sculpture")
    );
    assert!(
        json["fixed_questions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|question| question["fixed_before_scoring"] == true)
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
        assert_eq!(fixture["period_count"], 8);
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
    assert_eq!(fixture["modulus_count"], 8);
    assert_eq!(fixture["promoted_candidate"], false);
    assert!(fixture["plans"].as_array().unwrap().iter().all(
        |plan| plan["non_anchor_position_count"] == 73
            && plan["anchor_position_count"] == 24
            && plan["promoted_candidate"] == false
    ));
}

#[test]
fn mirror_prediction_plan_emits_committed_artifact() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("mirror-prediction-plan")
        .assert()
        .success()
        .stdout(predicate::str::contains("Mirror Prediction Plan"))
        .stdout(predicate::str::contains("mirror pairs: 35"))
        .stdout(predicate::str::contains("center position: 49"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["mirror-prediction-plan", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let generated: Value = serde_json::from_slice(&output).unwrap();
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string("experiments/predictions/non-anchor-position-mirror-v1.json")
            .unwrap(),
    )
    .unwrap();

    assert_eq!(fixture, generated);
    assert_eq!(fixture["pair_count"], 35);
    assert_eq!(fixture["center_position_one_based"], 49);
    assert_eq!(fixture["non_anchor_position_count"], 73);
    assert_eq!(fixture["anchor_position_count"], 24);
    assert_eq!(fixture["promoted_candidate"], false);
}

#[test]
fn validate_preregistration_accepts_independent_prediction_target() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("independent-target-v1.json");
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
fn validate_preregistration_rejects_filename_id_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("copied-placeholder-name.json");
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
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains(
            "filename must match preregistration id `independent-target-v1`",
        ))
        .stderr(predicate::str::contains(
            "preregistration failed validation",
        ));
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
            .stdout(predicate::str::contains("expected periods: 8"))
            .stdout(predicate::str::contains("artifact periods: 8"))
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
        .stdout(predicate::str::contains("expected moduli: 8"))
        .stdout(predicate::str::contains("artifact moduli: 8"))
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
    assert_eq!(json["expected_period_count"], 8);
    assert_eq!(json["artifact_period_count"], 8);
    assert!(json["warnings"].as_array().unwrap().iter().any(|warning| {
        warning
            .as_str()
            .unwrap()
            .contains("duplicate readiness lanes are inventory only")
    }));
    assert!(
        json["duplicate_artifact_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == "experiments/predictions/non-anchor-position-period-v35.json")
    );
    assert_eq!(json["promoted_candidate"], false);

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v35.json",
            "--require-unique-artifact",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("valid: false"))
        .stdout(predicate::str::contains("duplicate artifacts:"))
        .stdout(predicate::str::contains(
            "rerun without --require-unique-artifact only when duplicate readiness inventory is intentional",
        ))
        .stderr(predicate::str::contains(
            "prediction artifact failed validation",
        ));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-period-v40.json",
            "--require-unique-artifact",
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
    assert_eq!(json["artifact_kind"], "period");
    assert_eq!(json["artifact_period_count"], 1);
    assert_eq!(json["duplicate_artifact_paths"].as_array(), None);
    assert_eq!(json["promoted_candidate"], false);

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/ciphertext-structure-prior-v1.json",
            "--require-unique-artifact",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("valid: true"))
        .stdout(predicate::str::contains("duplicate artifacts: 0"));

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-prediction-artifact",
            "--preregistration",
            "experiments/preregistrations/ciphertext-hotspot-prior-v1.json",
            "--require-unique-artifact",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "artifact kind: ciphertext-hotspot",
        ))
        .stdout(predicate::str::contains("valid: true"))
        .stdout(predicate::str::contains("duplicate artifacts: 0"));
}

#[test]
fn independent_lane_status_summarizes_ready_lanes() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("independent-lane-status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Independent Lane Status"))
        .stdout(predicate::str::contains("lanes: 68"))
        .stdout(predicate::str::contains(
            "ready for source-backed observations: 68",
        ))
        .stdout(predicate::str::contains("invalid lanes: 0"))
        .stdout(predicate::str::contains("prediction artifacts: 68"))
        .stdout(predicate::str::contains("unique prediction artifacts: 26"))
        .stdout(predicate::str::contains(
            "unique ready prediction artifacts: 26",
        ))
        .stdout(predicate::str::contains("duplicate artifact groups: 1"))
        .stdout(predicate::str::contains("duplicate artifact lanes: 43"))
        .stdout(predicate::str::contains(
            "extra duplicate artifact lanes: 42",
        ))
        .stdout(predicate::str::contains("Family Summary"))
        .stdout(predicate::str::contains(
            "| ciphertext-adjacent-contrast-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-hotspot-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-only-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-rarity-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-repeat-distance-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-period-match-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-residue-balance-position-prior | 5 | 5 | 5 | 5 | 5 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-skip-transition-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-transition-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-turning-point-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| ciphertext-window-balance-position-prior | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| position-grid-layout-prediction | 3 | 3 | 3 | 3 | 3 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| position-mirror-prediction | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| position-period-prediction | 47 | 47 | 47 | 5 | 5 | 1 |",
        ))
        .stdout(predicate::str::contains(
            "| position-spacing-prediction | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains(
            "| tableau-hill-prediction | 1 | 1 | 1 | 1 | 1 | 0 |",
        ))
        .stdout(predicate::str::contains("Duplicate Prediction Artifacts"))
        .stdout(predicate::str::contains(
            "non-anchor-position-period-followup-v1",
        ))
        .stdout(predicate::str::contains("non-anchor-position-period-v45"))
        .stdout(predicate::str::contains("ciphertext-window-balance-v1"))
        .stdout(predicate::str::contains(
            "ready-for-source-backed-observations",
        ))
        .stdout(predicate::str::contains("tableau-hill-v1"))
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
    assert_eq!(json["lane_count"], 68);
    assert_eq!(json["ready_for_source_backed_observations"], 68);
    assert_eq!(json["invalid_lanes"], 0);
    assert_eq!(json["prediction_artifacts"], 68);
    assert_eq!(json["unique_prediction_artifacts"], 26);
    assert_eq!(json["unique_ready_prediction_artifacts"], 26);
    assert_eq!(json["duplicate_prediction_artifact_lane_count"], 43);
    assert_eq!(json["duplicate_prediction_artifact_extra_lane_count"], 42);
    let families = json["family_summaries"].as_array().unwrap();
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-adjacent-contrast-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-hotspot-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-only-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-rarity-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-repeat-distance-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-period-match-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-residue-balance-position-prior"
            && family["lanes"] == 5
            && family["unique_ready_prediction_artifacts"] == 5
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-skip-transition-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-transition-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-turning-point-position-prior"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "ciphertext-window-balance-position-prior"
            && family["lanes"] == 1
            && family["ready_for_source_backed_observations"] == 1
            && family["prediction_artifacts"] == 1
            && family["unique_prediction_artifacts"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "position-grid-layout-prediction"
            && family["lanes"] == 3
            && family["unique_ready_prediction_artifacts"] == 3
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "position-mirror-prediction"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "position-period-prediction"
            && family["lanes"] == 47
            && family["ready_for_source_backed_observations"] == 47
            && family["prediction_artifacts"] == 47
            && family["unique_ready_prediction_artifacts"] == 5
            && family["duplicate_artifact_groups"] == 1
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "position-spacing-prediction"
            && family["lanes"] == 1
            && family["unique_ready_prediction_artifacts"] == 1
            && family["duplicate_artifact_groups"] == 0
    }));
    assert!(families.iter().any(|family| {
        family["hypothesis_family"] == "tableau-hill-prediction"
            && family["lanes"] == 1
            && family["ready_for_source_backed_observations"] == 1
            && family["unique_prediction_artifacts"] == 1
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
    assert!(json["lanes"].as_array().unwrap().iter().any(|lane| {
        lane["id"] == "non-anchor-position-period-v45"
            && lane["ready_for_source_backed_observations"] == true
            && lane["prediction_artifact_valid"] == true
            && lane["promoted_candidate"] == false
    }));
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
fn init_position_observations_links_valid_source_review_file() {
    let temp = tempfile::tempdir().unwrap();
    let source_review_path = temp.path().join("source-review.json");
    let output_path = temp.path().join("observations-with-review.json");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "cia-source-review-v1",
            "--source-id",
            "cia-artifact",
            "--review-note",
            "Reviewed eligible CIA source pages before selecting non-anchor positions.",
            "--output",
            source_review_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "source-backed-observation-v2",
            "--source-id",
            "cia-artifact",
            "--source-review",
            source_review_path.to_str().unwrap(),
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
    assert_eq!(
        file_json["source_review_file"],
        source_review_path.to_str().unwrap()
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
        .stdout(predicate::str::contains("\"artifact_valid\": true"))
        .stdout(predicate::str::contains(
            "\"observation_source_review_file\"",
        ));
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

    let source_review_path = temp.path().join("source-review.json");
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "cia-sculpture-review-v1",
            "--source-id",
            "cia-sculpture",
            "--review-note",
            "Reviewed a different eligible source before coverage rejection.",
            "--output",
            source_review_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-position-observations",
            "--id",
            "bad-review-coverage-observation-v1",
            "--source-id",
            "cia-artifact",
            "--source-review",
            source_review_path.to_str().unwrap(),
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
            temp.path()
                .join("bad-review-coverage.json")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not cover observation source_id `cia-artifact`",
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
            && source["locally_archived"] == true
            && source["archive_url"] == "sources/archives/cia-artifact-2026-05-27.md"
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
        .stdout(predicate::str::contains("total ready lanes: 68"))
        .stdout(predicate::str::contains(
            "ciphertext-adjacent-contrast-position-prior",
        ))
        .stdout(predicate::str::contains(
            "ciphertext-hotspot-position-prior",
        ))
        .stdout(predicate::str::contains("ciphertext-only-position-prior"))
        .stdout(predicate::str::contains("ciphertext-rarity-position-prior"))
        .stdout(predicate::str::contains(
            "ciphertext-repeat-distance-position-prior",
        ))
        .stdout(predicate::str::contains(
            "ciphertext-period-match-position-prior",
        ))
        .stdout(predicate::str::contains(
            "ciphertext-residue-balance-position-prior",
        ))
        .stdout(predicate::str::contains(
            "ciphertext-skip-transition-position-prior",
        ))
        .stdout(predicate::str::contains(
            "ciphertext-transition-position-prior",
        ))
        .stdout(predicate::str::contains(
            "ciphertext-turning-point-position-prior",
        ))
        .stdout(predicate::str::contains(
            "ciphertext-window-balance-position-prior",
        ))
        .stdout(predicate::str::contains("position-grid-layout-prediction"))
        .stdout(predicate::str::contains("position-mirror-prediction"))
        .stdout(predicate::str::contains("family ready lanes: 47"))
        .stdout(predicate::str::contains("family unique ready artifacts: 5"))
        .stdout(predicate::str::contains(
            "unique ready prediction artifacts: 26",
        ))
        .stdout(predicate::str::contains(
            "duplicate prediction artifact groups: 1",
        ))
        .stdout(predicate::str::contains(
            "duplicate prediction artifact details",
        ))
        .stdout(predicate::str::contains("non-anchor-position-period-v35"))
        .stdout(predicate::str::contains("non-anchor-position-period-v36"))
        .stdout(predicate::str::contains("non-anchor-position-period-v37"))
        .stdout(predicate::str::contains("non-anchor-position-period-v38"))
        .stdout(predicate::str::contains("non-anchor-position-period-v39"))
        .stdout(predicate::str::contains("non-anchor-position-period-v45"))
        .stdout(predicate::str::contains("evaluator-pending lanes: 0"))
        .stdout(predicate::str::contains("tableau-hill-prediction"))
        .stdout(predicate::str::contains("cia-artifact, cia-sculpture"))
        .stdout(predicate::str::contains(
            "quarantined plaintext-claim sources: solvekryptos-2026-claim",
        ))
        .stdout(predicate::str::contains("valid source-backed archives:"))
        .stdout(predicate::str::contains(
            "used eligible sources: cia-sculpture",
        ))
        .stdout(predicate::str::contains(
            "all source-backed archives negative: true",
        ))
        .stdout(predicate::str::contains(
            "unused eligible sources: cia-artifact",
        ))
        .stdout(predicate::str::contains("unused eligible source status:"))
        .stdout(predicate::str::contains("scored-position markers=false"))
        .stdout(predicate::str::contains("source reviews scanned: 1"))
        .stdout(predicate::str::contains("source review available: true"))
        .stdout(predicate::str::contains("source-review-status"))
        .stdout(predicate::str::contains("evidence available:"))
        .stdout(predicate::str::contains("next action kind:"))
        .stdout(predicate::str::contains(
            "new-source-backed-rationale-or-distinct-prediction-artifact",
        ))
        .stdout(predicate::str::contains("blocking conditions:"))
        .stdout(predicate::str::contains(
            "source-backed-evidence-negative-or-non-significant",
        ))
        .stdout(predicate::str::contains(
            "unused-eligible-source-marked-non-scorable",
        ))
        .stdout(predicate::str::contains("recommended next step:"))
        .stdout(predicate::str::contains("next check commands:"))
        .stdout(predicate::str::contains("--require-unique-artifact"))
        .stdout(predicate::str::contains("negative/non-significant"))
        .stdout(predicate::str::contains("explicitly marked non-scorable"))
        .stdout(predicate::str::contains("Eligible Source Details"))
        .stdout(predicate::str::contains(
            "https://www.cia.gov/legacy/museum/artifact/kryptos/",
        ))
        .stdout(predicate::str::contains(
            "Ready lane count is an operational inventory",
        ))
        .stdout(predicate::str::contains(
            "validate-ciphertext-prior-observations",
        ))
        .stdout(predicate::str::contains("evaluate-ciphertext-prior"))
        .stdout(predicate::str::contains(
            "validate-ciphertext-hotspot-observations",
        ))
        .stdout(predicate::str::contains("evaluate-ciphertext-hotspot"))
        .stdout(predicate::str::contains(
            "validate-ciphertext-rarity-observations",
        ))
        .stdout(predicate::str::contains("evaluate-ciphertext-rarity"))
        .stdout(predicate::str::contains(
            "validate-ciphertext-repeat-distance-observations",
        ))
        .stdout(predicate::str::contains(
            "evaluate-ciphertext-repeat-distance",
        ))
        .stdout(predicate::str::contains(
            "validate-ciphertext-period-match-observations",
        ))
        .stdout(predicate::str::contains("evaluate-ciphertext-period-match"))
        .stdout(predicate::str::contains(
            "validate-ciphertext-adjacent-contrast-observations",
        ))
        .stdout(predicate::str::contains(
            "evaluate-ciphertext-adjacent-contrast",
        ))
        .stdout(predicate::str::contains(
            "validate-ciphertext-residue-balance-observations",
        ))
        .stdout(predicate::str::contains(
            "evaluate-ciphertext-residue-balance",
        ))
        .stdout(predicate::str::contains(
            "validate-ciphertext-transition-observations",
        ))
        .stdout(predicate::str::contains("evaluate-ciphertext-transition"))
        .stdout(predicate::str::contains(
            "validate-ciphertext-turning-point-observations",
        ))
        .stdout(predicate::str::contains(
            "evaluate-ciphertext-turning-point",
        ))
        .stdout(predicate::str::contains("init-source-review"))
        .stdout(predicate::str::contains("validate-source-review"))
        .stdout(predicate::str::contains("claim quarantine verifier"))
        .stdout(predicate::str::contains("verify-plaintext-claim"))
        .stdout(predicate::str::contains("verify-claim-reconciliation"))
        .stdout(predicate::str::contains("evaluate-period-prediction"))
        .stdout(predicate::str::contains("validate-spacing-observations"))
        .stdout(predicate::str::contains("evaluate-spacing-prediction"))
        .stdout(predicate::str::contains("validate-mirror-observations"))
        .stdout(predicate::str::contains("evaluate-mirror-prediction"))
        .stdout(predicate::str::contains("validate-grid-observations"))
        .stdout(predicate::str::contains("evaluate-grid-prediction"))
        .stdout(predicate::str::contains(
            "validate-tableau-hill-observations",
        ))
        .stdout(predicate::str::contains("evaluate-tableau-hill-prediction"))
        .stdout(predicate::str::contains("--edge-axis column"))
        .stdout(predicate::str::contains("validate-evaluation-archive"))
        .stdout(predicate::str::contains("evidence support details"))
        .stdout(predicate::str::contains(
            "results/period-observations/cia-k4-row-boundaries-v1",
        ))
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
    assert_eq!(json["ready_lanes"], 68);
    assert_eq!(json["invalid_lanes"], 0);
    assert_eq!(json["unique_ready_prediction_artifacts"], 26);
    assert_eq!(json["duplicate_prediction_artifact_group_count"], 1);
    assert_eq!(
        json["duplicate_prediction_artifact_groups"][0]["lane_ids"]
            .as_array()
            .unwrap()
            .len(),
        43
    );
    assert!(
        json["duplicate_prediction_artifact_groups"][0]["lane_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|lane| lane == "non-anchor-position-period-v35")
    );
    assert!(
        json["duplicate_prediction_artifact_groups"][0]["lane_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|lane| lane == "non-anchor-position-period-v36")
    );
    assert!(
        json["duplicate_prediction_artifact_groups"][0]["lane_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|lane| lane == "non-anchor-position-period-v37")
    );
    assert!(
        json["duplicate_prediction_artifact_groups"][0]["lane_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|lane| lane == "non-anchor-position-period-v39")
    );
    assert!(
        json["duplicate_prediction_artifact_groups"][0]["lane_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|lane| lane == "non-anchor-position-period-v45")
    );
    assert_eq!(json["evaluator_pending_lane_count"], 0);
    assert!(
        json["evaluator_pending_lanes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        json["quarantined_claim_source_ids"][0],
        "solvekryptos-2026-claim"
    );
    assert!(
        json["claim_verification_command"]
            .as_str()
            .unwrap()
            .contains("verify-plaintext-claim")
    );
    assert!(
        json["claim_verification_command"]
            .as_str()
            .unwrap()
            .contains("verify-claim-reconciliation")
    );
    let valid_source_backed_archives = json["valid_source_backed_archive_count"]
        .as_u64()
        .expect("valid_source_backed_archive_count should be numeric");
    assert_eq!(json["invalid_archive_count"], 0);
    assert_eq!(json["all_source_backed_archives_negative"], true);
    assert_eq!(json["used_eligible_source_ids"][0], "cia-sculpture");
    assert_eq!(json["unused_eligible_source_ids"][0], "cia-artifact");
    assert_eq!(
        json["unused_eligible_source_status"][0]["source_id"],
        "cia-artifact"
    );
    assert_eq!(
        json["unused_eligible_source_status"][0]["current_archive_has_scored_positions"],
        false
    );
    assert_eq!(json["scanned_source_review_count"], 1);
    assert_eq!(json["valid_source_review_count"], 1);
    assert_eq!(json["invalid_source_review_count"], 0);
    assert_eq!(json["source_review_available"], true);
    assert_eq!(json["evidence_available"], valid_source_backed_archives > 0);
    assert!(
        json["readiness_note"]
            .as_str()
            .unwrap()
            .contains("unique ready prediction artifacts")
    );
    assert!(
        json["recommended_next_step"]
            .as_str()
            .unwrap()
            .contains("explicitly marked non-scorable")
    );
    assert_eq!(
        json["next_action_kind"],
        "new-source-backed-rationale-or-distinct-prediction-artifact"
    );
    assert!(
        json["blocking_conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|condition| condition
                .as_str()
                .unwrap()
                .contains("source-backed-evidence-negative-or-non-significant"))
    );
    assert!(
        json["blocking_conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|condition| condition
                .as_str()
                .unwrap()
                .contains("unused-eligible-source-marked-non-scorable"))
    );
    assert!(
        json["evidence_support_summary"]
            .as_array()
            .unwrap()
            .iter()
            .any(|summary| summary
                .as_str()
                .unwrap()
                .contains("negative/non-significant"))
    );
    let support_details = json["evidence_support_details"].as_array().unwrap();
    assert_eq!(support_details.len(), valid_source_backed_archives as usize);
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/period-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "period"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "period 2 residue 0"
            && detail["observed_hits"] == "4/6 positions"
            && detail["null_mean_best_hits"].as_f64().unwrap() > 0.0
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-adjacent-contrast-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-adjacent-contrast"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext adjacent-contrast positions"
            && detail["observed_hits"] == "2/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/grid-observations/cia-k4-row-boundaries-column-v1")
            && detail["artifact_kind"] == "grid"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "7x14 column edges"
            && detail["observed_hits"] == "4/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/grid-observations/cia-k4-row-boundaries-compass-axis-v1")
            && detail["artifact_kind"] == "grid"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "7x14 compass-axis positions"
            && detail["observed_hits"] == "1/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-residue-balance-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-residue-balance"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext residue-balance modulus 2 residue 0"
            && detail["observed_hits"] == "4/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-hotspot-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-hotspot"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext hotspot positions"
            && detail["observed_hits"] == "0/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-rarity-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-rarity"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext rare-letter positions"
            && detail["observed_hits"] == "2/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-repeat-distance-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-repeat-distance"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext repeat-distance positions"
            && detail["observed_hits"] == "2/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-period-match-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-period-match"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext shifted same-letter period 2 endpoints"
            && detail["observed_hits"] == "1/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-transition-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-transition"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext transition-pressure positions"
            && detail["observed_hits"] == "0/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(support_details.iter().any(|detail| {
        detail["directory"]
            .as_str()
            .unwrap()
            .contains("results/ciphertext-turning-point-observations/cia-k4-row-boundaries-v1")
            && detail["artifact_kind"] == "ciphertext-turning-point"
            && detail["observation_source_ids"][0] == "cia-sculpture"
            && detail["best_model"] == "ciphertext turning-point positions"
            && detail["observed_hits"] == "2/6 positions"
            && detail["empirical_p_value"].as_f64().unwrap() > 0.05
            && detail["support_status"] == "negative/non-significant"
    }));
    assert!(
        json["source_review_status_command"]
            .as_str()
            .unwrap()
            .contains("source-review-status")
    );
    assert!(
        json["source_observation_status_command"]
            .as_str()
            .unwrap()
            .contains("source-observation-status")
    );
    assert!(
        json["source_review_scaffold_command"]
            .as_str()
            .unwrap()
            .contains("init-source-review")
    );
    assert!(
        json["source_review_validation_command"]
            .as_str()
            .unwrap()
            .contains("validate-source-review")
    );
    assert!(
        json["next_check_commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| command
                .as_str()
                .unwrap()
                .contains("--require-unique-artifact"))
    );
    assert!(
        json["required_observation_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field.as_str().unwrap().contains("source-review file"))
    );
    assert!(
        json["required_observation_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field.as_str().unwrap().contains("local source archive"))
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
                && source["locally_archived"] == true)
    );
    let gates = json["gates"].as_array().unwrap();
    assert_eq!(gates.len(), 16);
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-adjacent-contrast-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-adjacent-contrast-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-adjacent-contrast")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-adjacent-contrast-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-hotspot-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-hotspot-prior-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-hotspot-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-hotspot-prior-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-hotspot")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-hotspot-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-only-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-structure-prior-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-prior-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-structure-prior-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-prior")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-prior-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-rarity-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-rarity-prior-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-rarity-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-rarity-prior-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-rarity")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-rarity-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-repeat-distance-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-repeat-distance-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-repeat-distance-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-repeat-distance-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-repeat-distance")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-repeat-distance-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-period-match-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-period-match-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-period-match-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-period-match-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-period-match")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-period-match-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-residue-balance-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-residue-balance-extreme-moduli-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-residue-balance-observations")
            && gate["validation_command"].as_str().unwrap().contains(
                "experiments/predictions/ciphertext-residue-balance-extreme-moduli-v1.json",
            )
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-residue-balance")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-residue-balance-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-skip-transition-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-skip-transition-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-skip-transition-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-skip-transition-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-skip-transition")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-skip-transition-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-transition-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-transition-prior-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-transition-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-transition-prior-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-transition")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-transition-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-turning-point-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-turning-point-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-turning-point-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-turning-point-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-turning-point")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-turning-point-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "ciphertext-window-balance-position-prior"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/ciphertext-window-balance-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-ciphertext-window-balance-observations")
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("experiments/predictions/ciphertext-window-balance-v1.json")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-ciphertext-window-balance")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/ciphertext-window-balance-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "position-grid-layout-prediction"
            && gate["representative_preregistration"]
                == "experiments/preregistrations/non-anchor-position-grid-column-v1.json"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-grid-observations")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-grid-prediction")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("--edge-axis column")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/grid-observations")
    }));
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "position-mirror-prediction"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-mirror-observations")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-mirror-prediction")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/mirror-observations")
    }));
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
            && gate["observation_scaffold_command"]
                .as_str()
                .unwrap()
                .contains("--source-review")
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
    assert!(gates.iter().any(|gate| {
        gate["hypothesis_family"] == "tableau-hill-prediction"
            && gate["validation_command"]
                .as_str()
                .unwrap()
                .contains("validate-tableau-hill-observations")
            && gate["evaluation_command"]
                .as_str()
                .unwrap()
                .contains("evaluate-tableau-hill-prediction")
            && gate["archive_validation_command"]
                .as_str()
                .unwrap()
                .contains("results/tableau-hill-observations")
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
    assert_eq!(json["archives"][0]["support_status"], "invalid");
}

#[test]
fn independent_evidence_status_reports_archive_scores() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .arg("independent-evidence-status")
        .assert()
        .success()
        .stdout(predicate::str::contains("period 2 residue 0"))
        .stdout(predicate::str::contains("4/6 positions"))
        .stdout(predicate::str::contains("modulus 2 residue 1"))
        .stdout(predicate::str::contains("8/15 pairs"))
        .stdout(predicate::str::contains("7x14 row 1 concentration"))
        .stdout(predicate::str::contains("3/6 positions"))
        .stdout(predicate::str::contains("7x14 compass-axis positions"))
        .stdout(predicate::str::contains(
            "ciphertext prior period 2 residue 0",
        ))
        .stdout(predicate::str::contains("ciphertext hotspot positions"))
        .stdout(predicate::str::contains("ciphertext rare-letter positions"))
        .stdout(predicate::str::contains(
            "ciphertext turning-point positions",
        ))
        .stdout(predicate::str::contains("negative/non-significant"))
        .stdout(predicate::str::contains("promoted: false"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["independent-evidence-status", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    let archives = json["archives"].as_array().unwrap();
    let period = archives
        .iter()
        .find(|archive| {
            archive["artifact_kind"] == "period"
                && archive["directory"]
                    .as_str()
                    .unwrap()
                    .contains("results/period-observations/cia-k4-row-boundaries-v1")
        })
        .expect("period evidence archive should be present");
    let period5 = archives
        .iter()
        .find(|archive| {
            archive["artifact_kind"] == "period"
                && archive["directory"]
                    .as_str()
                    .unwrap()
                    .contains("results/period-observations/cia-k4-row-boundaries-period5-v42")
        })
        .expect("period-5 evidence archive should be present");
    let spacing = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "spacing")
        .expect("spacing evidence archive should be present");
    let tableau_hill = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "tableau-hill")
        .expect("tableau/HILL evidence archive should be present");
    let grid_compass_axis = archives
        .iter()
        .find(|archive| {
            archive["directory"]
                .as_str()
                .unwrap()
                .contains("results/grid-observations/cia-k4-row-boundaries-compass-axis-v1")
        })
        .expect("grid compass-axis evidence archive should be present");
    let ciphertext_prior = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-prior")
        .expect("ciphertext-prior evidence archive should be present");
    let ciphertext_hotspot = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-hotspot")
        .expect("ciphertext-hotspot evidence archive should be present");
    let ciphertext_rarity = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-rarity")
        .expect("ciphertext-rarity evidence archive should be present");
    let ciphertext_repeat_distance = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-repeat-distance")
        .expect("ciphertext-repeat-distance evidence archive should be present");
    let ciphertext_period_match = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-period-match")
        .expect("ciphertext-period-match evidence archive should be present");
    let ciphertext_transition = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-transition")
        .expect("ciphertext-transition evidence archive should be present");
    let ciphertext_turning_point = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-turning-point")
        .expect("ciphertext-turning-point evidence archive should be present");
    let ciphertext_window_balance = archives
        .iter()
        .find(|archive| archive["artifact_kind"] == "ciphertext-window-balance")
        .expect("ciphertext-window-balance evidence archive should be present");
    assert_eq!(period["best_model"], "period 2 residue 0");
    assert_eq!(period["observed_hits"], "4/6 positions");
    assert_eq!(period["observation_source_ids"][0], "cia-sculpture");
    assert_eq!(period["support_status"], "negative/non-significant");
    assert_eq!(period5["best_model"], "period 5 residue 0");
    assert_eq!(period5["observed_hits"], "2/6 positions");
    assert_eq!(period5["observation_source_ids"][0], "cia-sculpture");
    assert_eq!(period5["support_status"], "negative/non-significant");
    assert_eq!(spacing["best_model"], "modulus 2 residue 1");
    assert_eq!(spacing["observed_hits"], "8/15 pairs");
    assert_eq!(spacing["support_status"], "negative/non-significant");
    assert_eq!(tableau_hill["best_model"], "7x14 row 1 concentration");
    assert_eq!(tableau_hill["observed_hits"], "3/6 positions");
    assert_eq!(tableau_hill["support_status"], "negative/non-significant");
    assert_eq!(
        grid_compass_axis["best_model"],
        "7x14 compass-axis positions"
    );
    assert_eq!(grid_compass_axis["observed_hits"], "1/6 positions");
    assert_eq!(
        grid_compass_axis["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_prior["best_model"],
        "ciphertext prior period 2 residue 0"
    );
    assert_eq!(ciphertext_prior["observed_hits"], "4/6 positions");
    assert_eq!(
        ciphertext_prior["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_hotspot["best_model"],
        "ciphertext hotspot positions"
    );
    assert_eq!(ciphertext_hotspot["observed_hits"], "0/6 positions");
    assert_eq!(
        ciphertext_hotspot["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_rarity["best_model"],
        "ciphertext rare-letter positions"
    );
    assert_eq!(ciphertext_rarity["observed_hits"], "2/6 positions");
    assert_eq!(
        ciphertext_rarity["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_repeat_distance["best_model"],
        "ciphertext repeat-distance positions"
    );
    assert_eq!(ciphertext_repeat_distance["observed_hits"], "2/6 positions");
    assert_eq!(
        ciphertext_repeat_distance["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_period_match["best_model"],
        "ciphertext shifted same-letter period 2 endpoints"
    );
    assert_eq!(ciphertext_period_match["observed_hits"], "1/6 positions");
    assert_eq!(
        ciphertext_period_match["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_transition["best_model"],
        "ciphertext transition-pressure positions"
    );
    assert_eq!(ciphertext_transition["observed_hits"], "0/6 positions");
    assert_eq!(
        ciphertext_transition["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_turning_point["best_model"],
        "ciphertext turning-point positions"
    );
    assert_eq!(ciphertext_turning_point["observed_hits"], "2/6 positions");
    assert_eq!(
        ciphertext_turning_point["support_status"],
        "negative/non-significant"
    );
    assert_eq!(
        ciphertext_window_balance["best_model"],
        "ciphertext window-balance positions"
    );
    assert_eq!(ciphertext_window_balance["observed_hits"], "0/6 positions");
    assert_eq!(
        ciphertext_window_balance["support_status"],
        "negative/non-significant"
    );
    assert_eq!(json["promoted_candidate"], false);
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
    let source_review_path = temp.path().join("source-review.json");
    let observations_path = temp.path().join("observations.json");
    let output_dir = temp.path().join("period-output");

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "init-source-review",
            "--id",
            "synthetic-source-review-v1",
            "--source-id",
            "cia-artifact",
            "--review-note",
            "Reviewed eligible CIA source page before synthetic archive fixture.",
            "--output",
            source_review_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    let observations = serde_json::json!({
        "id": "synthetic-non-anchor-test",
        "source_ids": ["cia-artifact"],
        "source_review_file": source_review_path.to_str().unwrap(),
        "positions_one_based": [1, 4, 7],
        "position_notes": {
            "1": "Synthetic source-backed note for position 1.",
            "4": "Synthetic source-backed note for position 4.",
            "7": "Synthetic source-backed note for position 7."
        },
        "rationale": "Synthetic CLI test fixture for the observation-file input path."
    });
    std::fs::write(
        &observations_path,
        format!("{}\n", serde_json::to_string_pretty(&observations).unwrap()),
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
    assert_eq!(
        json["observation_source_review_file"],
        source_review_path.to_str().unwrap()
    );
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
        "source-review.json",
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
    assert_eq!(
        archived_json["observation_source_review_file"],
        source_review_path.to_str().unwrap()
    );
    let archived_source_review: Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("source-review.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(archived_source_review["id"], "synthetic-source-review-v1");
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
    assert!(
        validation["files_checked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file == "source-review.json")
    );
    assert_eq!(validation["promoted_candidate"], false);

    std::fs::remove_file(output_dir.join("source-review.json")).unwrap();
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-evaluation-archive",
            "--input",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("must include source-review.json"));
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
fn evaluate_mirror_prediction_scores_independent_position_set() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-mirror-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-mirror-v1.json",
            "--positions",
            "1,97",
            "--iterations",
            "100",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Mirror Prediction Evaluation"))
        .stdout(predicate::str::contains("mirror pair hits: 1/1"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-mirror-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-mirror-v1.json",
            "--positions",
            "1,97",
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
    assert_eq!(json["observed_position_count"], 2);
    assert_eq!(json["possible_observed_mirror_pairs"], 1);
    assert_eq!(json["mirror_pair_hits"], 1);
    assert_eq!(json["matching_pairs_one_based"][0][0], 1);
    assert_eq!(json["matching_pairs_one_based"][0][1], 97);
    assert_eq!(json["source_backed_observation"], false);
    assert!(
        json["observation_warning"]
            .as_str()
            .unwrap()
            .contains("diagnostic")
    );
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["empirical_p_value"].is_number());
}

#[test]
fn evaluate_mirror_prediction_accepts_source_backed_position_file() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    let output_dir = temp.path().join("mirror-output");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-mirror-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 97],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "97": "Synthetic source-backed note for position 97."
  },
  "rationale": "Synthetic CLI test fixture for the mirror observation-file input path."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-mirror-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-mirror-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-mirror-v1.json",
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
    assert_eq!(json["observation_id"], "synthetic-mirror-test");
    assert_eq!(json["observation_source_ids"][0], "cia-artifact");
    assert_eq!(json["source_backed_observation"], true);
    assert_eq!(json["observation_warning"], Value::Null);
    assert_eq!(json["mirror_pair_hits"], 1);
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
    let archived_summary = std::fs::read_to_string(output_dir.join("summary.md")).unwrap();
    assert!(archived_summary.contains("Mirror Prediction Evaluation"));
    assert!(archived_summary.contains("source-backed observation: true"));
    let archived_command = std::fs::read_to_string(output_dir.join("command.txt")).unwrap();
    assert!(archived_command.contains("evaluate-mirror-prediction"));
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
    assert_eq!(validation["artifact_kind"], "mirror");
    assert_eq!(validation["source_backed_observation"], true);
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
fn validate_mirror_observations_accepts_source_backed_non_anchor_positions() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-mirror-validation-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 97],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "97": "Synthetic source-backed note for position 97."
  },
  "rationale": "Synthetic CLI test fixture for mirror observation validation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-mirror-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-mirror-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-mirror-v1.json",
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
    assert_eq!(json["preregistration_id"], "non-anchor-position-mirror-v1");
    assert_eq!(json["artifact_valid"], true);
    assert_eq!(json["observation_id"], "synthetic-mirror-validation-test");
    assert_eq!(json["observation_source_ids"][0], "cia-artifact");
    assert_eq!(
        json["observation_rationale"],
        "Synthetic CLI test fixture for mirror observation validation."
    );
    assert_eq!(json["observed_position_count"], 2);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn grid_layout_prediction_plan_and_validation_cover_source_backed_positions() {
    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args(["grid-layout-prediction-plan", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    let row_fixture: Value = serde_json::from_str(
        &std::fs::read_to_string("experiments/predictions/non-anchor-position-grid-layout-v1.json")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(row_fixture, json);
    assert_eq!(json["row_count"], 7);
    assert_eq!(json["column_count"], 14);
    assert_eq!(json["padded_position_count"], 98);
    assert_eq!(json["pad_positions_one_based"][0], 98);
    assert_eq!(json["scored_edge_axis"], "row");
    assert_eq!(
        json["row_edge_positions_one_based"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    assert_eq!(
        json["column_edge_positions_one_based"]
            .as_array()
            .unwrap()
            .len(),
        27
    );
    assert_eq!(json["columns"].as_array().unwrap().len(), 14);
    assert_eq!(json["promoted_candidate"], false);

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "grid-layout-prediction-plan",
            "--edge-axis",
            "column",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let column_json: Value = serde_json::from_slice(&output).unwrap();
    let column_fixture: Value = serde_json::from_str(
        &std::fs::read_to_string("experiments/predictions/non-anchor-position-grid-column-v1.json")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(column_fixture, column_json);
    assert_eq!(column_json["scored_edge_axis"], "column");
    assert!(
        column_json["prediction_rule"]
            .as_str()
            .unwrap()
            .contains("column-edge positions")
    );

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "grid-layout-prediction-plan",
            "--edge-axis",
            "compass-axis",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let compass_json: Value = serde_json::from_slice(&output).unwrap();
    let compass_fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            "experiments/predictions/non-anchor-position-grid-compass-axis-v1.json",
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(compass_fixture, compass_json);
    assert_eq!(compass_json["scored_edge_axis"], "compass-axis");
    assert!(
        compass_json["prediction_rule"]
            .as_str()
            .unwrap()
            .contains("compass-axis")
    );

    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-grid-validation-test",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 14, 15],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "14": "Synthetic source-backed note for position 14.",
    "15": "Synthetic source-backed note for position 15."
  },
  "rationale": "Synthetic CLI test fixture for grid observation validation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-grid-observations",
            "--artifact",
            "experiments/predictions/non-anchor-position-grid-layout-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-grid-layout-v1.json",
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
    assert_eq!(
        json["preregistration_id"],
        "non-anchor-position-grid-layout-v1"
    );
    assert_eq!(json["artifact_valid"], true);
    assert_eq!(json["observation_id"], "synthetic-grid-validation-test");
    assert_eq!(json["observed_position_count"], 3);
    assert_eq!(json["promoted_candidate"], false);

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-grid-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-grid-layout-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-grid-layout-v1.json",
            "--positions-file",
            observations_path.to_str().unwrap(),
            "--edge-axis",
            "column",
            "--iterations",
            "100",
            "--seed",
            "67",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not match preregistered grid_edge_axis `row`",
        ));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-grid-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-grid-compass-axis-v1.json",
            "--preregistration",
            "experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json",
            "--positions",
            "36,43,97",
            "--edge-axis",
            "compass-axis",
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
    assert_eq!(json["edge_axis"], "compass-axis");
    assert_eq!(json["edge_hits"], 2);
    assert_eq!(json["matching_edge_positions_one_based"][0], 36);
    assert_eq!(json["matching_edge_positions_one_based"][1], 43);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn validate_tableau_hill_observations_accepts_source_mapped_non_anchor_positions() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("tableau-hill-observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-tableau-hill-validation-test",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/cia-source-review-v1.json",
  "positions_one_based": [1, 14, 15],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "14": "Synthetic source-backed note for position 14.",
    "15": "Synthetic source-backed note for position 15."
  },
  "rationale": "Synthetic CLI test fixture for Tableau/HILL source-map observation validation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-tableau-hill-observations",
            "--artifact",
            "experiments/predictions/tableau-hill-v1.json",
            "--preregistration",
            "experiments/preregistrations/tableau-hill-v1.json",
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
    assert_eq!(json["preregistration_id"], "tableau-hill-v1");
    assert_eq!(json["artifact_valid"], true);
    assert_eq!(
        json["observation_id"],
        "synthetic-tableau-hill-validation-test"
    );
    assert_eq!(json["observation_source_ids"][0], "cia-sculpture");
    assert_eq!(json["observed_position_count"], 3);
    assert_eq!(json["promoted_candidate"], false);
}

#[test]
fn validate_tableau_hill_observations_rejects_public_anchor_positions() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("tableau-hill-anchor-observations.json");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-tableau-hill-anchor-rejection-test",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/cia-source-review-v1.json",
  "positions_one_based": [1, 22],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "22": "Synthetic source-backed note for public-anchor position 22."
  },
  "rationale": "Synthetic CLI test fixture for Tableau/HILL public-anchor rejection."
}"#,
    )
    .unwrap();

    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "validate-tableau-hill-observations",
            "--artifact",
            "experiments/predictions/tableau-hill-v1.json",
            "--preregistration",
            "experiments/preregistrations/tableau-hill-v1.json",
            "--input",
            observations_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "position `22` is a public-anchor position",
        ))
        .stderr(predicate::str::contains(
            "tableau/HILL observations failed validation",
        ));
}

#[test]
fn evaluate_tableau_hill_prediction_scores_source_mapped_observations() {
    let temp = tempfile::tempdir().unwrap();
    let observations_path = temp.path().join("tableau-hill-observations.json");
    let output_dir = temp.path().join("tableau-hill-archive");
    std::fs::write(
        &observations_path,
        r#"{
  "id": "synthetic-tableau-hill-evaluation-test",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/cia-source-review-v1.json",
  "positions_one_based": [1, 2, 15],
  "position_notes": {
    "1": "Synthetic source-backed note for position 1.",
    "2": "Synthetic source-backed note for position 2.",
    "15": "Synthetic source-backed note for position 15."
  },
  "rationale": "Synthetic CLI test fixture for Tableau/HILL source-map evaluation."
}"#,
    )
    .unwrap();

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-tableau-hill-prediction",
            "--artifact",
            "experiments/predictions/tableau-hill-v1.json",
            "--preregistration",
            "experiments/preregistrations/tableau-hill-v1.json",
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
    assert_eq!(json["source_backed_observation"], true);
    assert_eq!(
        json["observation_id"],
        "synthetic-tableau-hill-evaluation-test"
    );
    assert_eq!(json["best_hits"], 2);
    assert_eq!(json["best_axis"], "row");
    assert_eq!(json["promoted_candidate"], false);

    Command::cargo_bin("kryptos-k4")
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
        .stdout(predicate::str::contains(
            "\"artifact_kind\": \"tableau-hill\"",
        ))
        .stdout(predicate::str::contains("\"valid\": true"));
}

#[test]
fn evaluate_grid_prediction_scores_independent_position_set() {
    Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-grid-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-grid-layout-v1.json",
            "--positions",
            "1,14,16",
            "--iterations",
            "100",
            "--seed",
            "67",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Grid Layout Prediction Evaluation",
        ))
        .stdout(predicate::str::contains("row-edge hits: 2/3"))
        .stdout(predicate::str::contains("promoted: false"))
        .stdout(predicate::str::contains("not a claimed solution"));

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-grid-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-grid-layout-v1.json",
            "--positions",
            "1,14,16",
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
    assert_eq!(json["edge_axis"], "row");
    assert_eq!(json["edge_hits"], 2);
    assert_eq!(json["row_edge_hits"], 2);
    assert_eq!(json["matching_row_edge_positions_one_based"][0], 1);
    assert_eq!(json["matching_row_edge_positions_one_based"][1], 14);
    assert_eq!(json["source_backed_observation"], false);
    assert!(
        json["observation_warning"]
            .as_str()
            .unwrap()
            .contains("diagnostic")
    );
    assert_eq!(json["promoted_candidate"], false);
    assert!(json["empirical_p_value"].is_number());

    let output = Command::cargo_bin("kryptos-k4")
        .unwrap()
        .args([
            "evaluate-grid-prediction",
            "--artifact",
            "experiments/predictions/non-anchor-position-grid-layout-v1.json",
            "--positions",
            "1,4,16",
            "--edge-axis",
            "column",
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
    assert_eq!(json["edge_axis"], "column");
    assert_eq!(json["edge_hits"], 2);
    assert_eq!(json["row_edge_hits"], 1);
    assert_eq!(json["column_edge_hits"], 2);
    assert_eq!(json["matching_edge_positions_one_based"][0], 1);
    assert_eq!(json["matching_edge_positions_one_based"][1], 4);
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
                .contains("eight registered periods")
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
        "preregistration-readme-current",
        "independent-lanes-ready",
        "position-observation-template-guarded",
        "position-observations-valid",
        "evidence-summaries-present",
        "source-packet-registry-aligned",
        "source-archives-complete",
        "source-archives-present",
        "source-archives-structured",
        "observation-source-archives-cover-positions",
        "source-reviews-valid",
        "source-readiness-commands-documented",
        "next-evidence-structured-support-documented",
        "stopped-lanes-documented",
        "progress-log-current",
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
        source["id"] == "smithsonian-2026-archive-discovery"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-doc1-resolution-memo"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-declassified-kryptos-doc3"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-foia-release-index"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-summary-revelations"
            && source["allowed_use"] == "archive-context-only"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "nsa-kryptos-doc8-cryptogram"
            && source["allowed_use"] == "public-anchor-summary"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "kryptosbot-methodology-2026"
            && source["allowed_use"] == "methodology-context"
    }));
    assert!(sources.as_array().unwrap().iter().any(|source| {
        source["id"] == "solvekryptos-2026-claim"
            && source["allowed_use"] == "unverified-solution-claim"
    }));
    assert!(sources.as_array().unwrap().iter().all(|source| {
        source["url"].as_str().unwrap().starts_with("https://")
            && !source["accessed_at"].as_str().unwrap().is_empty()
    }));
}
