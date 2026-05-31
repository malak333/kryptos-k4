use crate::data::{K4_CIPHERTEXT, known_anchors, sources};
use crate::findings::findings;
use crate::preregistration::{
    LanePreregistration, load_and_validate_preregistration,
    summarize_independent_lanes_with_repo_root, validate_prediction_artifact_with_repo_root,
};
use anyhow::{Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

const REQUIRED_RELEASE_FILES: [(&str, &str); 10] = [
    ("readme-present", "README.md"),
    ("research-method-present", "docs/research-method.md"),
    (
        "current-architecture-present",
        "docs/architecture-current.md",
    ),
    (
        "production-goal-architecture-present",
        "docs/architecture-production-goal.md",
    ),
    ("source-packet-present", "sources/source-packet.md"),
    ("candidate-csv-present", "experiments/k4-candidates.csv"),
    ("candidate-registry-present", "experiments/k4-candidates.md"),
    ("research-plan-present", "kryptos-k4-research-plan.md"),
    ("license-present", "LICENSE"),
    ("lockfile-present", "Cargo.lock"),
];

const REQUIRED_GENERATED_REPORTS: [(&str, &str); 1] =
    [("markdown-report-present", "notes/k4-report.md")];

const REQUIRED_REPORT_MARKERS: [&str; 27] = [
    "`validate-prediction-artifact`",
    "`independent-lane-status`",
    "`observation-sources`",
    "`source-intake-packet`",
    "`validate-source-archive`",
    "`validate-period-observations`",
    "`validate-ciphertext-prior-observations`",
    "`validate-ciphertext-hotspot-observations`",
    "`validate-ciphertext-rarity-observations`",
    "`validate-ciphertext-transition-observations`",
    "`evaluate-period-prediction`",
    "Independent non-anchor period targets are materialized before scoring",
    "evidence-free prediction target",
    "`position-structure`",
    "findings-source-inputs-valid",
    "preregistration-readme-current",
    "position-observation-template-guarded",
    "per-position notes",
    "position-observations-valid",
    "evidence-summaries-present",
    "source-archives-complete",
    "source-archives-structured",
    "observation-source-archives-cover-positions",
    "source-reviews-valid",
    "stopped-lanes-documented",
    "progress-log-current",
    "next-evidence-structured-support-documented",
];

const PLAINTEXT_LEAKAGE_SCAN_FILES: [&str; 6] = [
    "README.md",
    "docs/research-method.md",
    "experiments/PROGRESS_LOG.md",
    "experiments/STOPPED_LANES.md",
    "sources/source-packet.md",
    "notes/k4-report.md",
];

const PLAINTEXT_LEAKAGE_SCAN_DIRS: [&str; 4] = [
    "experiments/evidence-summaries",
    "experiments/position-observations",
    "results/claim-verifications",
    "sources/archives",
];

const PLAINTEXT_LEAKAGE_MARKERS: [&str; 4] = [
    "K4_FULL_PLAINTEXT",
    "K4_LEAKED_PLAINTEXT",
    "K4_ARCHIVE_PLAINTEXT",
    "K4_PRIVATE_ARCHIVE_PLAINTEXT",
];

const FINDINGS_COMMAND_SOURCE_INPUTS: [&str; 1] = ["release-check"];

const STOPPED_LANES_REQUIRED_MARKERS: [&str; 25] = [
    "# Stopped K4 Experiment Lanes",
    "It is not a solution claim.",
    "## Public Anchor-Derived Key-Material Lanes",
    "## Source-Expanded Sculpture/Chart/Matrix Lane",
    "## Candidate-Independent Position Structure Lanes",
    "## Duplicate Period-Lane Readiness Inventory",
    "## CIA Row-Boundary Observation Lane",
    "## Simple Single-Layer And Uncorrected Search Lanes",
    "## Required Gate For New Lanes",
    "Status: stopped",
    "Status: stopped as evidence.",
    "validate-prediction-artifact --require-unique-artifact",
    "validate-preregistration",
    "experiments/evidence-summaries/cia-k4-row-boundaries-v1.md",
    "grid column `p=0.1303`",
    "grid compass-axis `p=0.9166`",
    "period-14 `p=1.0000`",
    "ciphertext-repeat-distance `p=0.5273`",
    "ciphertext-adjacent-contrast `p=0.5259`",
    "ciphertext-skip-transition `p=1.0000`",
    "ciphertext-turning-point `p=0.5247`",
    "ciphertext-window-balance `p=1.0000`",
    "ciphertext-CT-perturbation `p=0.4139`",
    "ciphertext-residue-balance",
    "super-extreme-moduli ciphertext-residue-balance `p=0.6741`",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

pub fn run_release_checks(repo_root: impl AsRef<Path>) -> Result<Vec<ReleaseCheck>> {
    run_release_checks_inner(repo_root, true)
}

pub fn run_release_checks_for_report(repo_root: impl AsRef<Path>) -> Result<Vec<ReleaseCheck>> {
    run_release_checks_inner(repo_root, false)
}

fn run_release_checks_inner(
    repo_root: impl AsRef<Path>,
    require_current_report: bool,
) -> Result<Vec<ReleaseCheck>> {
    let repo_root = repo_root.as_ref();
    let mut checks = vec![
        check_absent(
            "github-actions-disabled",
            repo_root.join(".github/workflows"),
            "GitHub Actions workflow directory must not exist.",
        ),
        check_absent(
            "dependabot-disabled",
            repo_root.join(".github/dependabot.yml"),
            "Dependabot config must not exist because releases are locally gated.",
        ),
    ];

    checks.extend(REQUIRED_RELEASE_FILES.map(|(name, relative_path)| {
        check_exists(
            name,
            repo_root.join(relative_path),
            "Required release file must be present.",
        )
    }));

    checks.extend(REQUIRED_GENERATED_REPORTS.map(|(name, relative_path)| {
        check_exists(
            name,
            repo_root.join(relative_path),
            "Generated release report must be present.",
        )
    }));

    if require_current_report {
        checks.push(check_generated_report_markers(repo_root));
    }
    checks.push(check_candidate_registry_alignment(repo_root));
    checks.push(check_preregistrations_validate(repo_root));
    checks.push(check_preregistration_readme_current(repo_root));
    checks.push(check_prediction_artifacts_validate(repo_root));
    checks.push(check_independent_lanes_ready(repo_root));
    checks.push(check_position_observation_template_guarded(repo_root));
    checks.push(check_position_observations_validate(repo_root));
    checks.push(check_evidence_summaries_present(repo_root));
    checks.push(check_findings_source_inputs_validate(repo_root));
    checks.push(check_source_packet_latest_access_date(repo_root));
    checks.push(check_source_packet_registry_alignment(repo_root));
    checks.push(check_source_archives_complete(repo_root));
    checks.push(check_source_archives_exist(repo_root));
    checks.push(check_source_archives_structured(repo_root));
    checks.push(check_observation_source_archives_cover_positions(repo_root));
    checks.push(check_source_reviews_validate(repo_root));
    checks.push(check_source_readiness_commands_documented(
        repo_root,
        require_current_report,
    ));
    checks.push(check_next_evidence_structured_support_documented(
        repo_root,
        require_current_report,
    ));
    checks.push(check_stopped_lanes_documented(repo_root));
    checks.push(check_progress_log_current(repo_root));
    checks.push(check_claim_verification_archives(repo_root));
    checks.push(check_no_plaintext_leakage_markers(repo_root));

    let failed_checks = checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| format!("{} ({})", check.name, check.detail))
        .collect::<Vec<_>>();
    if !failed_checks.is_empty() {
        bail!("release preflight failed: {}", failed_checks.join("; "));
    }

    Ok(checks)
}

fn check_findings_source_inputs_validate(repo_root: &Path) -> ReleaseCheck {
    let registered_source_ids: std::collections::BTreeSet<_> =
        sources().into_iter().map(|source| source.id).collect();
    let registered_command_inputs: std::collections::BTreeSet<_> =
        FINDINGS_COMMAND_SOURCE_INPUTS.into_iter().collect();
    let all_findings = findings();
    let mut mismatches = Vec::new();

    for finding in &all_findings {
        for source_input in finding.source_inputs {
            let repo_relative_path = repo_root.join(source_input);
            if !registered_source_ids.contains(source_input)
                && !registered_command_inputs.contains(source_input)
                && !repo_relative_path.exists()
            {
                mismatches.push(format!("{}:{source_input}:unknown", finding.id));
            }
        }
    }

    ReleaseCheck {
        name: "findings-source-inputs-valid",
        passed: !all_findings.is_empty() && mismatches.is_empty(),
        detail: if !all_findings.is_empty() && mismatches.is_empty() {
            format!(
                "Findings source inputs resolve to registered sources, committed files, or known local command references. path={}; checked={}",
                repo_root.join("src/findings.rs").display(),
                all_findings.len()
            )
        } else if all_findings.is_empty() {
            format!(
                "No findings are registered. path={}",
                repo_root.join("src/findings.rs").display()
            )
        } else {
            format!(
                "Findings source inputs include unknown references. path={}; mismatches={}",
                repo_root.join("src/findings.rs").display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_preregistrations_validate(repo_root: &Path) -> ReleaseCheck {
    let preregistrations = committed_preregistration_paths(repo_root);
    let mut mismatches = Vec::new();

    for path in &preregistrations {
        match load_and_validate_preregistration(path) {
            Ok(validation) => {
                if !validation.valid {
                    mismatches.push(format!(
                        "{}:{}",
                        path.display(),
                        validation.errors.join("|")
                    ));
                }
            }
            Err(error) => mismatches.push(format!("{}:{error}", path.display())),
        }
    }

    ReleaseCheck {
        name: "preregistrations-valid",
        passed: !preregistrations.is_empty() && mismatches.is_empty(),
        detail: if !preregistrations.is_empty() && mismatches.is_empty() {
            format!(
                "Committed non-template preregistrations validate. path={}; checked={}",
                repo_root.join("experiments/preregistrations").display(),
                preregistrations.len()
            )
        } else if preregistrations.is_empty() {
            format!(
                "No committed non-template preregistrations found. path={}",
                repo_root.join("experiments/preregistrations").display()
            )
        } else {
            format!(
                "Committed preregistrations failed validation. path={}; mismatches={}",
                repo_root.join("experiments/preregistrations").display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_preregistration_readme_current(repo_root: &Path) -> ReleaseCheck {
    let preregistrations = committed_preregistration_paths(repo_root);
    let relative_path = "experiments/preregistrations/README.md";
    let path = repo_root.join(relative_path);
    let contents = fs::read_to_string(&path).unwrap_or_default();
    let mut mismatches = Vec::new();

    if contents.trim().is_empty() {
        mismatches.push("README is missing or empty".to_string());
    }

    for preregistration_path in &preregistrations {
        let file_name = preregistration_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !contents.contains(file_name) {
            mismatches.push(format!("missing preregistration `{file_name}`"));
        }

        let Ok(input) = fs::read_to_string(preregistration_path) else {
            continue;
        };
        let Ok(registration) = serde_json::from_str::<LanePreregistration>(&input) else {
            continue;
        };
        if let Some(prediction_artifact) = registration.prediction_artifact
            && !contents.contains(&prediction_artifact)
        {
            mismatches.push(format!("missing artifact `{prediction_artifact}`"));
        }
    }

    ReleaseCheck {
        name: "preregistration-readme-current",
        passed: !preregistrations.is_empty() && mismatches.is_empty(),
        detail: if !preregistrations.is_empty() && mismatches.is_empty() {
            format!(
                "Preregistration README names every committed lane and declared prediction artifact. path={}; checked={}",
                path.display(),
                preregistrations.len()
            )
        } else if preregistrations.is_empty() {
            format!(
                "No committed non-template preregistrations found to compare with README. path={}",
                path.display()
            )
        } else {
            format!(
                "Preregistration README is stale or incomplete. path={}; mismatches={}",
                path.display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_prediction_artifacts_validate(repo_root: &Path) -> ReleaseCheck {
    let preregistrations = committed_preregistration_paths(repo_root);
    let mut checked = 0usize;
    let mut mismatches = Vec::new();

    for path in &preregistrations {
        let input = match fs::read_to_string(path) {
            Ok(input) => input,
            Err(error) => {
                mismatches.push(format!("{}:{error}", path.display()));
                continue;
            }
        };
        let registration: LanePreregistration = match serde_json::from_str(&input) {
            Ok(registration) => registration,
            Err(error) => {
                mismatches.push(format!("{}:{error}", path.display()));
                continue;
            }
        };
        if registration.prediction_artifact.is_none() {
            continue;
        }

        checked += 1;
        match validate_prediction_artifact_with_repo_root(path, repo_root) {
            Ok(validation) => {
                if !validation.valid {
                    mismatches.push(format!(
                        "{}:{}",
                        path.display(),
                        validation.errors.join("|")
                    ));
                }
            }
            Err(error) => mismatches.push(format!("{}:{error}", path.display())),
        }
    }

    ReleaseCheck {
        name: "prediction-artifacts-valid",
        passed: checked > 0 && mismatches.is_empty(),
        detail: if checked > 0 && mismatches.is_empty() {
            format!(
                "Committed prediction artifacts match their preregistrations and deterministic generators. path={}; checked={checked}",
                repo_root.join("experiments/predictions").display(),
            )
        } else if checked == 0 {
            format!(
                "No committed preregistrations declare prediction artifacts. path={}",
                repo_root.join("experiments/preregistrations").display()
            )
        } else {
            format!(
                "Committed prediction artifacts failed validation. path={}; mismatches={}",
                repo_root.join("experiments/predictions").display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_independent_lanes_ready(repo_root: &Path) -> ReleaseCheck {
    let directory = repo_root.join("experiments/preregistrations");
    match summarize_independent_lanes_with_repo_root(&directory, repo_root) {
        Ok(report) => {
            let evaluator_pending_lanes = report
                .lanes
                .iter()
                .filter(|lane| lane.status == "evaluator-pending")
                .map(|lane| lane.id.as_deref().unwrap_or("unavailable").to_string())
                .collect::<Vec<_>>();
            let blocked_lanes = report
                .lanes
                .iter()
                .filter(|lane| {
                    !lane.ready_for_source_backed_observations && lane.status != "evaluator-pending"
                })
                .map(|lane| {
                    format!(
                        "{}:{}",
                        lane.id.as_deref().unwrap_or("unavailable"),
                        lane.status
                    )
                })
                .collect::<Vec<_>>();
            ReleaseCheck {
                name: "independent-lanes-ready",
                passed: report.lane_count > 0 && blocked_lanes.is_empty(),
                detail: if report.lane_count > 0 && blocked_lanes.is_empty() {
                    let family_summary = report
                        .family_summaries
                        .iter()
                        .map(|family| {
                            format!(
                                "{}:{}_lanes/{}_unique_ready",
                                family.hypothesis_family,
                                family.lanes,
                                family.unique_ready_prediction_artifacts
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!(
                        "Supported independent preregistered lanes are ready for source-backed observation files; evaluator-pending lanes are inventoried separately. path={}; ready={}; checked={}; prediction_artifacts={}; unique_prediction_artifacts={}; unique_ready_prediction_artifacts={}; duplicate_artifact_groups={}; duplicate_artifact_lanes={}; extra_duplicate_artifact_lanes={}; family_summary={}",
                        directory.display(),
                        report.ready_for_source_backed_observations,
                        report.lane_count,
                        report.prediction_artifacts,
                        report.unique_prediction_artifacts,
                        report.unique_ready_prediction_artifacts,
                        report.duplicate_prediction_artifact_groups.len(),
                        report.duplicate_prediction_artifact_lane_count,
                        report.duplicate_prediction_artifact_extra_lane_count,
                        family_summary
                    ) + &if evaluator_pending_lanes.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "; evaluator_pending={}:{}",
                            evaluator_pending_lanes.len(),
                            evaluator_pending_lanes.join(",")
                        )
                    }
                } else if report.lane_count == 0 {
                    format!(
                        "No independent preregistered lanes found. path={}",
                        directory.display()
                    )
                } else {
                    format!(
                        "Independent preregistered lanes are not ready for source-backed observation files. path={}; blocked={}",
                        directory.display(),
                        blocked_lanes.join(", ")
                    )
                },
            }
        }
        Err(error) => ReleaseCheck {
            name: "independent-lanes-ready",
            passed: false,
            detail: format!(
                "Independent lane status could not be evaluated. path={}; error={error}",
                directory.display()
            ),
        },
    }
}

fn check_position_observation_template_guarded(repo_root: &Path) -> ReleaseCheck {
    let template_path = repo_root.join("experiments/position-observations-template.json");
    let input = match fs::read_to_string(&template_path) {
        Ok(input) => input,
        Err(error) => {
            return ReleaseCheck {
                name: "position-observation-template-guarded",
                passed: false,
                detail: format!(
                    "Position observation template could not be read. path={}; error={error}",
                    template_path.display()
                ),
            };
        }
    };

    let mut mismatches = Vec::new();
    match serde_json::from_str::<serde_json::Value>(&input) {
        Ok(value) => {
            if !value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| id.contains("replace-with"))
            {
                mismatches.push("id must remain a replace-with placeholder".to_string());
            }
            if !value
                .get("source_ids")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|source_ids| {
                    source_ids.iter().any(|source_id| {
                        source_id
                            .as_str()
                            .is_some_and(|source_id| source_id.contains("replace-with"))
                    })
                })
            {
                mismatches.push("source_ids must include a replace-with placeholder".to_string());
            }
            if !value
                .get("rationale")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|rationale| rationale.contains("Explain why"))
            {
                mismatches.push("rationale must remain explanatory placeholder text".to_string());
            }
            if !value
                .get("positions_one_based")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|positions| positions.is_empty())
            {
                mismatches.push("positions_one_based must remain empty".to_string());
            }
            if !value
                .get("position_notes")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|notes| notes.is_empty())
            {
                mismatches.push("position_notes must remain empty".to_string());
            }
        }
        Err(error) => mismatches.push(format!("template is not valid JSON: {error}")),
    }

    ReleaseCheck {
        name: "position-observation-template-guarded",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Position observation template remains intentionally non-scorable. path={}",
                template_path.display()
            )
        } else {
            format!(
                "Position observation template can no longer prove its non-scorable guard. path={}; mismatches={}",
                template_path.display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_position_observations_validate(repo_root: &Path) -> ReleaseCheck {
    let observations = committed_position_observation_paths(repo_root);
    let mut mismatches = Vec::new();

    for path in &observations {
        match fs::read_to_string(path) {
            Ok(input) => match serde_json::from_str::<serde_json::Value>(&input) {
                Ok(value) => {
                    let relative_path = path.strip_prefix(repo_root).unwrap_or(path);
                    mismatches.extend(
                        validate_committed_position_observation(repo_root, relative_path, &value)
                            .into_iter()
                            .map(|error| format!("{}:{error}", path.display())),
                    );
                }
                Err(error) => mismatches.push(format!("{}:{error}", path.display())),
            },
            Err(error) => mismatches.push(format!("{}:{error}", path.display())),
        }
    }

    ReleaseCheck {
        name: "position-observations-valid",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Committed source-backed observation files validate. path={}; checked={}",
                repo_root
                    .join("experiments/position-observations")
                    .display(),
                observations.len()
            )
        } else {
            format!(
                "Committed source-backed observation files failed validation. path={}; mismatches={}",
                repo_root
                    .join("experiments/position-observations")
                    .display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_evidence_summaries_present(repo_root: &Path) -> ReleaseCheck {
    let observations = committed_position_observation_paths(repo_root);
    let mut mismatches = Vec::new();

    for observation_path in &observations {
        let observation_id = observation_path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown-observation");
        let summary_path = repo_root
            .join("experiments/evidence-summaries")
            .join(format!("{observation_id}.md"));
        match fs::read_to_string(&summary_path) {
            Ok(summary) => {
                let observation_relative = observation_path
                    .strip_prefix(repo_root)
                    .unwrap_or(observation_path)
                    .display()
                    .to_string();
                if !summary.contains(&observation_relative) {
                    mismatches.push(format!(
                        "{}:summary does not reference observation file `{observation_relative}`",
                        summary_path.display()
                    ));
                }
                if !summary.contains("This is not a claimed solution.") {
                    mismatches.push(format!(
                        "{}:summary must preserve the no-solution boundary",
                        summary_path.display()
                    ));
                }
                if !summary.contains("Promoted") && !summary.contains("promoted") {
                    mismatches.push(format!(
                        "{}:summary must state non-promotion status",
                        summary_path.display()
                    ));
                }
                let required_markers = [
                    "evaluate-period-prediction".to_string(),
                    "evaluate-spacing-prediction".to_string(),
                    "evaluate-mirror-prediction".to_string(),
                    "evaluate-grid-prediction".to_string(),
                    "evaluate-tableau-hill-prediction".to_string(),
                    "evaluate-ciphertext-prior".to_string(),
                    "evaluate-ciphertext-hotspot".to_string(),
                    "evaluate-ciphertext-rarity".to_string(),
                    "evaluate-ciphertext-repeat-distance".to_string(),
                    "evaluate-ciphertext-adjacent-contrast".to_string(),
                    "evaluate-ciphertext-transition".to_string(),
                    "evaluate-ciphertext-skip-transition".to_string(),
                    "evaluate-ciphertext-turning-point".to_string(),
                    "evaluate-ciphertext-window-balance".to_string(),
                    "evaluate-ciphertext-ct-perturbation".to_string(),
                    "evaluate-ciphertext-stehle-regularity".to_string(),
                    "evaluate-ciphertext-residue-balance".to_string(),
                    "validate-evaluation-archive".to_string(),
                    format!("results/period-observations/{observation_id}"),
                    format!("results/spacing-observations/{observation_id}"),
                    format!("results/mirror-observations/{observation_id}"),
                    format!("results/grid-observations/{observation_id}"),
                    format!(
                        "results/grid-observations/{}-column-v1",
                        observation_id.trim_end_matches("-v1")
                    ),
                    format!(
                        "results/grid-observations/{}-compass-axis-v1",
                        observation_id.trim_end_matches("-v1")
                    ),
                    format!("results/tableau-hill-observations/{observation_id}"),
                    format!("results/ciphertext-prior-observations/{observation_id}"),
                    format!("results/ciphertext-hotspot-observations/{observation_id}"),
                    format!("results/ciphertext-rarity-observations/{observation_id}"),
                    format!("results/ciphertext-repeat-distance-observations/{observation_id}"),
                    format!("results/ciphertext-adjacent-contrast-observations/{observation_id}"),
                    format!("results/ciphertext-transition-observations/{observation_id}"),
                    format!("results/ciphertext-skip-transition-observations/{observation_id}"),
                    format!("results/ciphertext-turning-point-observations/{observation_id}"),
                    format!("results/ciphertext-window-balance-observations/{observation_id}"),
                    format!("results/ciphertext-ct-perturbation-observations/{observation_id}"),
                    format!("results/ciphertext-stehle-regularity-observations/{observation_id}"),
                    format!("results/ciphertext-residue-balance-observations/{observation_id}"),
                    "Period".to_string(),
                    "Spacing".to_string(),
                    "Mirror".to_string(),
                    "Grid row".to_string(),
                    "Grid column".to_string(),
                    "Grid compass-axis".to_string(),
                    "Tableau/HILL".to_string(),
                    "Ciphertext prior".to_string(),
                    "Ciphertext hotspot".to_string(),
                    "Ciphertext rarity".to_string(),
                    "Ciphertext repeat-distance".to_string(),
                    "Ciphertext adjacent-contrast".to_string(),
                    "Ciphertext transition".to_string(),
                    "Ciphertext skip-transition".to_string(),
                    "Ciphertext turning-point".to_string(),
                    "Ciphertext window-balance".to_string(),
                    "Ciphertext CT-perturbation".to_string(),
                    "Ciphertext residue-balance".to_string(),
                    "Observed Hits".to_string(),
                    "Empirical P".to_string(),
                    "negative".to_string(),
                ];
                for required_marker in required_markers {
                    if !summary.contains(&required_marker) {
                        mismatches.push(format!(
                            "{}:summary must reference `{required_marker}`",
                            summary_path.display()
                        ));
                    }
                }
            }
            Err(error) => mismatches.push(format!("{}:{error}", summary_path.display())),
        }
    }

    ReleaseCheck {
        name: "evidence-summaries-present",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Committed source-backed observations have evidence summaries with archive command references and negative period/spacing/mirror/grid-row/grid-column/grid-compass-axis/tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-ct-perturbation/ciphertext-stehle-regularity/ciphertext-residue-balance result metrics. path={}; checked={}",
                repo_root.join("experiments/evidence-summaries").display(),
                observations.len()
            )
        } else {
            format!(
                "Committed source-backed observations are missing evidence summaries. path={}; mismatches={}",
                repo_root.join("experiments/evidence-summaries").display(),
                mismatches.join(", ")
            )
        },
    }
}

fn validate_committed_position_observation(
    repo_root: &Path,
    relative_path: &Path,
    value: &serde_json::Value,
) -> Vec<String> {
    let mut errors = Vec::new();
    let registered_sources: std::collections::BTreeMap<_, _> = sources()
        .into_iter()
        .map(|source| (source.id, source))
        .collect();
    let anchor_positions: std::collections::BTreeSet<_> = known_anchors()
        .into_iter()
        .flat_map(|anchor| anchor.start_one_based()..=anchor.end_one_based_inclusive())
        .collect();

    let id = value.get("id").and_then(serde_json::Value::as_str);
    if id.is_none_or(|id| id.trim().is_empty()) {
        errors.push("id must not be empty".to_string());
    } else if id.is_some_and(contains_template_placeholder) {
        errors.push("id still contains template placeholder text".to_string());
    }

    let source_ids = value
        .get("source_ids")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if source_ids.is_empty() {
        errors.push("source_ids must include at least one registered source".to_string());
    }
    let mut parsed_source_ids = Vec::new();
    for source_id in source_ids {
        let Some(source_id) = source_id.as_str() else {
            errors.push("source_ids entries must be strings".to_string());
            continue;
        };
        if source_id.trim().is_empty() {
            errors.push("source_ids entries must not be empty".to_string());
            continue;
        }
        if contains_template_placeholder(source_id) {
            errors.push("source_ids still contain template placeholder text".to_string());
            continue;
        }
        let Some(source) = registered_sources.get(source_id) else {
            errors.push(format!("source_id `{source_id}` is not registered"));
            continue;
        };
        if source.allowed_use != "public-facts-only" {
            errors.push(format!(
                "source_id `{source_id}` has allowed_use `{}` and cannot be scored as independent position evidence",
                source.allowed_use
            ));
        }
        parsed_source_ids.push(source_id.to_string());
    }

    if let Some(source_review_file) = value
        .get("source_review_file")
        .and_then(serde_json::Value::as_str)
    {
        if source_review_file.trim().is_empty() {
            errors.push("source_review_file must not be empty".to_string());
        } else if contains_template_placeholder(source_review_file) {
            errors.push("source_review_file still contains template placeholder text".to_string());
        } else {
            let source_review_path = repo_root.join(source_review_file);
            match fs::read_to_string(&source_review_path) {
                Ok(input) => match serde_json::from_str::<serde_json::Value>(&input) {
                    Ok(review) => {
                        if review
                            .get("promoted_candidate")
                            .and_then(serde_json::Value::as_bool)
                            != Some(false)
                        {
                            errors.push(format!(
                                "source_review_file `{source_review_file}` must remain non-promotional"
                            ));
                        }
                        let reviewed_source_ids = review
                            .get("source_ids")
                            .and_then(serde_json::Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(serde_json::Value::as_str)
                            .collect::<std::collections::BTreeSet<_>>();
                        for source_id in &parsed_source_ids {
                            if !reviewed_source_ids.contains(source_id.as_str()) {
                                errors.push(format!(
                                    "source_review_file `{source_review_file}` does not cover observation source_id `{source_id}`"
                                ));
                            }
                        }
                    }
                    Err(error) => errors.push(format!(
                        "source_review_file `{source_review_file}` is invalid JSON: {error}"
                    )),
                },
                Err(error) => errors.push(format!(
                    "source_review_file `{source_review_file}` could not be read: {error}"
                )),
            }
        }
    } else {
        errors.push("source_review_file must be present for committed observations".to_string());
    }

    let rationale = value.get("rationale").and_then(serde_json::Value::as_str);
    if rationale.is_none_or(|rationale| rationale.trim().is_empty()) {
        errors.push("rationale must not be empty".to_string());
    } else if rationale.is_some_and(contains_template_placeholder) {
        errors.push("rationale still contains template placeholder text".to_string());
    }

    let positions = value
        .get("positions_one_based")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if positions.is_empty() {
        errors.push("positions_one_based must include at least one position".to_string());
    }
    let mut parsed_positions = Vec::new();
    let mut seen_positions = std::collections::BTreeSet::new();
    for position in positions {
        let Some(position) = position.as_u64() else {
            errors.push("positions_one_based entries must be positive integers".to_string());
            continue;
        };
        let position = position as usize;
        if !seen_positions.insert(position) {
            errors.push(format!(
                "positions_one_based contains duplicate position `{position}`"
            ));
        }
        if position == 0 || position > K4_CIPHERTEXT.len() {
            errors.push(format!(
                "position `{position}` is outside the one-based K4 range 1..={}",
                K4_CIPHERTEXT.len()
            ));
        }
        if anchor_positions.contains(&position) {
            errors.push(format!(
                "position `{position}` is a public-anchor position and cannot be used as independent observation evidence"
            ));
        }
        parsed_positions.push(position);
    }

    let position_notes = value
        .get("position_notes")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    if position_notes.is_empty() {
        errors.push("position_notes must include one note per scored position".to_string());
    }
    let parsed_position_set = parsed_positions
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for position in &parsed_positions {
        match position_notes.get(&position.to_string()) {
            Some(note) => match note.as_str() {
                Some(note) if note.trim().is_empty() => {
                    errors.push(format!("position_notes entry for `{position}` is empty"));
                }
                Some(note) if contains_template_placeholder(note) => {
                    errors.push(format!(
                        "position_notes entry for `{position}` still contains template placeholder text"
                    ));
                }
                Some(_) => {}
                None => errors.push(format!(
                    "position_notes entry for `{position}` must be a string"
                )),
            },
            None => errors.push(format!(
                "position_notes is missing an entry for position `{position}`"
            )),
        }
    }
    for position_key in position_notes.keys() {
        match position_key.parse::<usize>() {
            Ok(position) if parsed_position_set.contains(&position) => {}
            Ok(position) => errors.push(format!(
                "position_notes includes position `{position}` that is not listed in positions_one_based"
            )),
            Err(_) => errors.push(format!(
                "position_notes key `{position_key}` is not a one-based K4 position"
            )),
        }
    }

    if value
        .get("promoted_candidate")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        errors.push("observation file must not promote a candidate".to_string());
    }

    if relative_path
        .file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|file_stem| id.is_some_and(|id| file_stem != id))
    {
        errors.push("filename must match observation id".to_string());
    }

    errors
}

fn committed_preregistration_paths(repo_root: &Path) -> Vec<std::path::PathBuf> {
    let dir = repo_root.join("experiments/preregistrations");
    let mut paths = fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter(|path| {
            path.file_name().and_then(|name| name.to_str())
                != Some("independent-lane-template.json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn committed_position_observation_paths(repo_root: &Path) -> Vec<std::path::PathBuf> {
    let dir = repo_root.join("experiments/position-observations");
    let mut paths = fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn committed_source_review_paths(repo_root: &Path) -> Vec<std::path::PathBuf> {
    let dir = repo_root.join("experiments/source-reviews");
    let mut paths = fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn contains_template_placeholder(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("replace-with")
        || normalized.contains("replace with")
        || normalized.contains("explain why")
        || normalized.contains("describe the")
        || normalized.contains("define the")
}

fn check_candidate_registry_alignment(repo_root: &Path) -> ReleaseCheck {
    let csv_relative_path = "experiments/k4-candidates.csv";
    let registry_relative_path = "experiments/k4-candidates.md";
    let csv_path = repo_root.join(csv_relative_path);
    let registry_path = repo_root.join(registry_relative_path);
    let csv_contents = fs::read_to_string(&csv_path).unwrap_or_default();
    let registry_contents = fs::read_to_string(&registry_path).unwrap_or_default();

    let candidate_materials = candidate_materials_from_csv(&csv_contents);
    let mut mismatches = Vec::new();

    if candidate_materials.is_empty() {
        mismatches.push("candidate-csv:empty".to_string());
    }

    for material in candidate_materials {
        let token = format!("`{material}`");
        if !registry_contents.contains(&token) {
            mismatches.push(format!("{material}:missing-registry-row"));
        }
    }

    if !registry_contents.contains("Source IDs:") {
        mismatches.push("registry:missing-source-ids".to_string());
    }
    if !registry_contents.contains("Rationale:") {
        mismatches.push("registry:missing-rationale".to_string());
    }

    let known_source_ids: std::collections::BTreeSet<_> =
        sources().into_iter().map(|source| source.id).collect();
    for source_id in candidate_registry_source_ids(&registry_contents) {
        if !known_source_ids.contains(source_id.as_str()) {
            mismatches.push(format!("registry-source:{source_id}:unknown"));
        }
    }

    ReleaseCheck {
        name: "candidate-registry-aligned",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Candidate CSV rows are represented in the candidate registry with source IDs and rationale. path={}; registry_path={}",
                csv_path.display(),
                registry_path.display()
            )
        } else {
            format!(
                "Candidate CSV and registry are misaligned. path={}; registry_path={}; mismatches={}",
                csv_path.display(),
                registry_path.display(),
                mismatches.join(", ")
            )
        },
    }
}

fn candidate_materials_from_csv(input: &str) -> std::collections::BTreeSet<String> {
    input
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.eq_ignore_ascii_case("material,transform")
            {
                return None;
            }
            let material = trimmed.split(',').next()?.trim();
            (!material.is_empty()).then(|| material.to_string())
        })
        .collect()
}

fn candidate_registry_source_ids(input: &str) -> std::collections::BTreeSet<String> {
    input
        .lines()
        .filter(|line| line.trim_start().starts_with("Source IDs:"))
        .flat_map(backticked_values)
        .collect()
}

fn backticked_values(line: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('`') {
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('`') else {
            break;
        };
        values.push(after_start[..end].to_string());
        rest = &after_start[end + 1..];
    }
    values
}

fn check_source_packet_registry_alignment(repo_root: &Path) -> ReleaseCheck {
    let relative_path = "sources/source-packet.md";
    let path = repo_root.join(relative_path);
    let contents = fs::read_to_string(&path).unwrap_or_default();
    let mut mismatches = Vec::new();

    for source in sources() {
        let id = format!("`{}`", source.id);
        let Some(line) = contents.lines().find(|line| line.contains(&id)) else {
            mismatches.push(format!("{}:missing-row", source.id));
            continue;
        };

        if !line.contains(source.url) {
            mismatches.push(format!("{}:url", source.id));
        }
        if !line.contains(source.source_type) {
            mismatches.push(format!("{}:source-type", source.id));
        }
        if !source_packet_allowed_use_matches(line, source.allowed_use) {
            mismatches.push(format!("{}:allowed-use", source.id));
        }
        match source.archive_url {
            Some(archive_url) if !line.contains(archive_url) => {
                mismatches.push(format!("{}:archive-url", source.id));
            }
            None if !line.contains("Not locally archived") => {
                mismatches.push(format!("{}:archive-status", source.id));
            }
            _ => {}
        }
    }

    ReleaseCheck {
        name: "source-packet-registry-aligned",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Source packet matches every registered source ID, URL, type, and allowed-use boundary. path={}",
                path.display()
            )
        } else {
            format!(
                "Source packet is missing or mismatches registered source fields. path={}; mismatches={}",
                path.display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_source_packet_latest_access_date(repo_root: &Path) -> ReleaseCheck {
    let relative_path = "sources/source-packet.md";
    let path = repo_root.join(relative_path);
    let contents = fs::read_to_string(&path).unwrap_or_default();
    let latest_access_date = sources()
        .into_iter()
        .map(|source| source.accessed_at)
        .max()
        .expect("source registry must not be empty");

    ReleaseCheck {
        name: "source-packet-latest-access-date",
        passed: contents.contains(latest_access_date),
        detail: if contents.contains(latest_access_date) {
            format!(
                "Source packet includes latest registered source access date. path={}; latest_access_date={}",
                path.display(),
                latest_access_date
            )
        } else {
            format!(
                "Source packet is missing the latest registered source access date. path={}; latest_access_date={}",
                path.display(),
                latest_access_date
            )
        },
    }
}

fn check_source_archives_complete(repo_root: &Path) -> ReleaseCheck {
    let missing_archive_urls = sources()
        .into_iter()
        .filter(|source| source.archive_url.is_none())
        .map(|source| source.id)
        .collect::<Vec<_>>();

    ReleaseCheck {
        name: "source-archives-complete",
        passed: missing_archive_urls.is_empty(),
        detail: if missing_archive_urls.is_empty() {
            format!(
                "Every registered source has a local quote-free archive path. path={}; checked={}",
                repo_root.join("sources/archives").display(),
                sources().len()
            )
        } else {
            format!(
                "Registered sources are missing local archive paths. path={}; missing={}",
                repo_root.join("sources/archives").display(),
                missing_archive_urls.join(", ")
            )
        },
    }
}

fn check_source_archives_exist(repo_root: &Path) -> ReleaseCheck {
    let mut missing = Vec::new();
    let mut checked = 0;

    for source in sources() {
        let Some(archive_url) = source.archive_url else {
            continue;
        };

        checked += 1;
        if archive_url.starts_with("http://") || archive_url.starts_with("https://") {
            continue;
        }

        if !repo_root.join(archive_url).is_file() {
            missing.push(format!("{}:{archive_url}", source.id));
        }
    }

    ReleaseCheck {
        name: "source-archives-present",
        passed: missing.is_empty(),
        detail: if missing.is_empty() {
            format!(
                "Registered local source archive paths exist. path={}; checked={checked}",
                repo_root.display()
            )
        } else {
            format!(
                "Registered local source archive paths are missing. path={}; missing={}",
                repo_root.display(),
                missing.join(", ")
            )
        },
    }
}

fn check_source_archives_structured(repo_root: &Path) -> ReleaseCheck {
    let mut mismatches = Vec::new();
    let mut checked = 0;

    for source in sources() {
        let Some(archive_url) = source.archive_url else {
            continue;
        };
        if archive_url.starts_with("http://") || archive_url.starts_with("https://") {
            continue;
        }
        checked += 1;
        let path = repo_root.join(archive_url);
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let required_markers = [
                    format!("source_id: `{}`", source.id),
                    format!("source_url: {}", source.url),
                    "reviewed_at:".to_string(),
                    "archive_kind: quote-free local review snapshot".to_string(),
                    "promoted_candidate: false".to_string(),
                    "## Reviewed Facts".to_string(),
                    "## Boundary".to_string(),
                    "No candidate material, key stream, route, or plaintext is promoted."
                        .to_string(),
                ];
                for marker in required_markers {
                    if !contents.contains(&marker) {
                        mismatches.push(format!("{}:missing `{marker}`", path.display()));
                    }
                }
                if contents.contains("K4_FULL_PLAINTEXT")
                    || contents.contains("K4_LEAKED_PLAINTEXT")
                    || contents.contains("claimed solution")
                {
                    mismatches.push(format!(
                        "{}:contains forbidden solution/plaintext marker",
                        path.display()
                    ));
                }
                let non_scorable_reason = contents
                    .lines()
                    .find_map(|line| line.strip_prefix("non_scorable_reason:"))
                    .map(str::trim);
                if let Some(reason) = non_scorable_reason {
                    if reason.is_empty() {
                        mismatches.push(format!(
                            "{}:non_scorable_reason marker must include a reason",
                            path.display()
                        ));
                    }
                    if contents.contains("scored_positions_one_based:") {
                        mismatches.push(format!(
                            "{}:non_scorable_reason cannot coexist with scored_positions_one_based",
                            path.display()
                        ));
                    }
                } else if !contents.contains("scored_positions_one_based:") {
                    mismatches.push(format!(
                        "{}:must include scored_positions_one_based or non_scorable_reason",
                        path.display()
                    ));
                }
            }
            Err(error) => mismatches.push(format!("{}:{error}", path.display())),
        }
    }

    ReleaseCheck {
        name: "source-archives-structured",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Registered local source archives preserve required metadata, no-promotion boundaries, and explicit non-scorable/scored-position consistency. path={}; checked={checked}",
                repo_root.join("sources/archives").display()
            )
        } else {
            format!(
                "Registered local source archives are missing required metadata or have inconsistent boundaries. path={}; mismatches={}",
                repo_root.join("sources/archives").display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_source_reviews_validate(repo_root: &Path) -> ReleaseCheck {
    let reviews = committed_source_review_paths(repo_root);
    let mut mismatches = Vec::new();

    for path in &reviews {
        match fs::read_to_string(path) {
            Ok(input) => match serde_json::from_str::<serde_json::Value>(&input) {
                Ok(value) => mismatches.extend(
                    validate_committed_source_review(repo_root, path, &value)
                        .into_iter()
                        .map(|error| format!("{}:{error}", path.display())),
                ),
                Err(error) => mismatches.push(format!("{}:{error}", path.display())),
            },
            Err(error) => mismatches.push(format!("{}:{error}", path.display())),
        }
    }

    ReleaseCheck {
        name: "source-reviews-valid",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Committed source-review files validate against current source metadata. path={}; checked={}",
                repo_root.join("experiments/source-reviews").display(),
                reviews.len()
            )
        } else {
            format!(
                "Committed source-review files failed validation. path={}; mismatches={}",
                repo_root.join("experiments/source-reviews").display(),
                mismatches.join(", ")
            )
        },
    }
}

fn check_observation_source_archives_cover_positions(repo_root: &Path) -> ReleaseCheck {
    let observations = committed_position_observation_paths(repo_root);
    let registered_sources: std::collections::BTreeMap<_, _> = sources()
        .into_iter()
        .map(|source| (source.id, source))
        .collect();
    let mut mismatches = Vec::new();

    for observation_path in &observations {
        let observation_relative = observation_path
            .strip_prefix(repo_root)
            .unwrap_or(observation_path)
            .display()
            .to_string();
        let observation_id = observation_path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown-observation");
        let input = match fs::read_to_string(observation_path) {
            Ok(input) => input,
            Err(error) => {
                mismatches.push(format!("{}:{error}", observation_path.display()));
                continue;
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&input) {
            Ok(value) => value,
            Err(error) => {
                mismatches.push(format!("{}:{error}", observation_path.display()));
                continue;
            }
        };

        let source_ids = value
            .get("source_ids")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        let positions = value
            .get("positions_one_based")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_u64)
            .map(|position| position.to_string())
            .collect::<Vec<_>>();

        for source_id in source_ids {
            let Some(source) = registered_sources.get(source_id) else {
                continue;
            };
            let Some(archive_url) = source.archive_url else {
                mismatches.push(format!(
                    "{observation_relative}:{source_id}:source has no local archive path"
                ));
                continue;
            };
            if archive_url.starts_with("http://") || archive_url.starts_with("https://") {
                mismatches.push(format!(
                    "{observation_relative}:{source_id}:source archive is not local"
                ));
                continue;
            }
            let archive_path = repo_root.join(archive_url);
            let archive_contents = match fs::read_to_string(&archive_path) {
                Ok(contents) => contents,
                Err(error) => {
                    mismatches.push(format!(
                        "{}:{}:{}",
                        observation_relative,
                        archive_path.display(),
                        error
                    ));
                    continue;
                }
            };
            if !archive_contents.contains(&observation_relative)
                && !archive_contents.contains(observation_id)
            {
                mismatches.push(format!(
                    "{}:{}:archive does not reference observation `{}`",
                    observation_relative,
                    archive_path.display(),
                    observation_id
                ));
            }
            let scored_positions_marker =
                format!("scored_positions_one_based: {}", positions.join(","));
            if !archive_contents.contains(&scored_positions_marker) {
                mismatches.push(format!(
                    "{}:{}:archive does not contain explicit marker `{}`",
                    observation_relative,
                    archive_path.display(),
                    scored_positions_marker
                ));
            }
        }
    }

    ReleaseCheck {
        name: "observation-source-archives-cover-positions",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Committed source-backed observations are covered by local source archives with explicit scored-position markers. path={}; checked={}",
                repo_root
                    .join("experiments/position-observations")
                    .display(),
                observations.len()
            )
        } else {
            format!(
                "Committed source-backed observations are not fully covered by explicit local source-archive scored-position markers. path={}; mismatches={}",
                repo_root
                    .join("experiments/position-observations")
                    .display(),
                mismatches.join("|")
            )
        },
    }
}

fn check_stopped_lanes_documented(repo_root: &Path) -> ReleaseCheck {
    let relative_path = "experiments/STOPPED_LANES.md";
    let path = repo_root.join(relative_path);
    let contents = fs::read_to_string(&path).unwrap_or_default();
    let lowercase_contents = contents.to_ascii_lowercase();
    let mut mismatches = Vec::new();

    if contents.trim().is_empty() {
        mismatches.push("file is missing or empty".to_string());
    }
    for marker in STOPPED_LANES_REQUIRED_MARKERS {
        if !contents.contains(marker) {
            mismatches.push(format!("missing marker `{marker}`"));
        }
    }
    if lowercase_contents.contains("promoted: true")
        || lowercase_contents.contains("promoted_candidate: true")
        || lowercase_contents.contains("claimed solution")
    {
        mismatches.push("stop ledger contains promotional or solution-claim language".to_string());
    }

    ReleaseCheck {
        name: "stopped-lanes-documented",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Stopped-lane ledger documents negative lanes, duplicate-period inventory, row-boundary evidence, preregistration gate, and no-solution boundary. path={}",
                path.display()
            )
        } else {
            format!(
                "Stopped-lane ledger is missing required release boundaries. path={}; mismatches={}",
                path.display(),
                mismatches.join("|")
            )
        },
    }
}

fn check_progress_log_current(repo_root: &Path) -> ReleaseCheck {
    let relative_path = "experiments/PROGRESS_LOG.md";
    let path = repo_root.join(relative_path);
    let contents = fs::read_to_string(&path).unwrap_or_default();
    let lowercase_contents = contents.to_ascii_lowercase();
    let mut mismatches = Vec::new();

    if contents.trim().is_empty() {
        mismatches.push("file is missing or empty".to_string());
    }

    match summarize_independent_lanes_with_repo_root(
        &repo_root.join("experiments/preregistrations"),
        repo_root,
    ) {
        Ok(report) => {
            let required_markers = [
                format!("independent lanes: `{}`", report.lane_count),
                format!(
                    "ready for source-backed observations: `{}`",
                    report.ready_for_source_backed_observations
                ),
                format!("prediction artifacts: `{}`", report.prediction_artifacts),
                format!(
                    "unique ready prediction targets: `{}`",
                    report.unique_ready_prediction_artifacts
                ),
                format!(
                    "duplicate artifact lanes: `{}`",
                    report.duplicate_prediction_artifact_lane_count
                ),
                format!(
                    "extra duplicate artifact lanes: `{}`",
                    report.duplicate_prediction_artifact_extra_lane_count
                ),
            ];
            for marker in required_markers {
                if !contents.contains(&marker) {
                    mismatches.push(format!("missing current inventory marker `{marker}`"));
                }
            }
            for family in &report.family_summaries {
                let prefix = family
                    .hypothesis_family
                    .strip_prefix("position-")
                    .and_then(|suffix| suffix.strip_suffix("-prediction"))
                    .unwrap_or(&family.hypothesis_family);
                for marker in [
                    format!("{prefix}-family lanes: `{}`", family.lanes),
                    format!(
                        "{prefix}-family unique ready targets: `{}`",
                        family.unique_ready_prediction_artifacts
                    ),
                ] {
                    if !contents.contains(&marker) {
                        mismatches.push(format!("missing current family marker `{marker}`"));
                    }
                }
            }
        }
        Err(error) => mismatches.push(format!("could not summarize independent lanes: {error}")),
    }

    let observations = committed_position_observation_paths(repo_root);
    let observation_marker = format!("source-backed observation files: `{}`", observations.len());
    if !contents.contains(&observation_marker) {
        mismatches.push(format!(
            "missing current observation marker `{observation_marker}`"
        ));
    }
    for observation_path in &observations {
        let observation_relative = observation_path
            .strip_prefix(repo_root)
            .unwrap_or(observation_path)
            .display()
            .to_string();
        if !contents.contains(&observation_relative) {
            mismatches.push(format!(
                "missing observation file reference `{observation_relative}`"
            ));
        }

        let observation_id = observation_path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let summary_relative = format!("experiments/evidence-summaries/{observation_id}.md");
        if !contents.contains(&summary_relative) {
            mismatches.push(format!(
                "missing evidence summary reference `{summary_relative}`"
            ));
        }
    }

    let evidence_summary_count = observations
        .iter()
        .filter(|observation_path| {
            observation_path
                .file_stem()
                .and_then(|name| name.to_str())
                .is_some_and(|observation_id| {
                    repo_root
                        .join("experiments/evidence-summaries")
                        .join(format!("{observation_id}.md"))
                        .exists()
                })
        })
        .count();
    let evidence_marker = format!("evidence summaries: `{evidence_summary_count}`");
    if !contents.contains(&evidence_marker) {
        mismatches.push(format!(
            "missing current evidence-summary marker `{evidence_marker}`"
        ));
    }

    for marker in [
        "new-source-backed-rationale-or-distinct-prediction-artifact",
        "blocking condition: `duplicate-period-lanes-not-evidence`",
        "blocking condition: `source-backed-evidence-negative-or-non-significant`",
        "blocking condition: `unused-eligible-source-marked-non-scorable`",
    ] {
        if !contents.contains(marker) {
            mismatches.push(format!("missing current next-evidence marker `{marker}`"));
        }
    }

    for stale_marker in [
        "no independent observation has been scored",
        "no source-backed observation archive exists yet",
    ] {
        if lowercase_contents.contains(stale_marker) {
            mismatches.push(format!("contains stale marker `{stale_marker}`"));
        }
    }

    ReleaseCheck {
        name: "progress-log-current",
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "Progress log reflects current lane inventory and committed source-backed observation evidence. path={}",
                path.display()
            )
        } else {
            format!(
                "Progress log is stale or incomplete. path={}; mismatches={}",
                path.display(),
                mismatches.join("|")
            )
        },
    }
}

fn check_source_readiness_commands_documented(
    repo_root: &Path,
    require_current_report: bool,
) -> ReleaseCheck {
    let mut required_markers = vec![
        (
            "README.md",
            vec![
                "cargo run -- source-observation-status --format json",
                "`source-observation-status`",
                "`source-frontier`",
                "machine-readable frontier blockers",
                "required next-evidence criteria",
                "disallowed next actions",
            ],
        ),
        (
            "docs/research-method.md",
            vec![
                "Run `source-observation-status`",
                "machine-readable `frontier_blocking_conditions`",
                "`required_next_evidence`",
                "`disallowed_next_actions`",
            ],
        ),
        (
            "experiments/PROGRESS_LOG.md",
            vec![
                "`source-observation-status --format json`",
                "`source_observation_status_command`",
                "`source-frontier --format json`",
                "`frontier_blocking_conditions`",
                "`required_next_evidence`",
                "`disallowed_next_actions`",
            ],
        ),
    ];
    if require_current_report {
        required_markers.push((
            "notes/k4-report.md",
            vec![
                "`source-observation-status`",
                "`source-frontier`",
                "machine-readable frontier blockers",
                "required next-evidence criteria",
                "disallowed next actions",
            ],
        ));
    }
    let mut missing = Vec::new();
    for (relative_path, markers) in required_markers {
        let path = repo_root.join(relative_path);
        let contents = fs::read_to_string(&path).unwrap_or_default();
        for marker in markers {
            if !contents.contains(marker) {
                missing.push(format!("{relative_path}:{marker}"));
            }
        }
    }

    ReleaseCheck {
        name: "source-readiness-commands-documented",
        passed: missing.is_empty(),
        detail: if missing.is_empty() {
            format!(
                "Source readiness command is documented in release-facing files. path={}",
                repo_root.display()
            )
        } else {
            format!(
                "Source readiness command documentation is stale or incomplete. path={}; missing={}",
                repo_root.display(),
                missing.join("|")
            )
        },
    }
}

fn check_next_evidence_structured_support_documented(
    repo_root: &Path,
    require_current_report: bool,
) -> ReleaseCheck {
    let mut required_markers = vec![
        (
            "README.md",
            vec![
                "`evidence_support_details`",
                "`all_source_backed_archives_negative`",
                "structured archive support details",
                "null-mean",
            ],
        ),
        (
            "docs/research-method.md",
            vec![
                "structured archive support details including null means",
                "all-source-backed-archives-negative flag",
            ],
        ),
        (
            "experiments/PROGRESS_LOG.md",
            vec![
                "`evidence_support_details`",
                "`all_source_backed_archives_negative: true`",
                "archive directory",
                "null mean best hits",
            ],
        ),
    ];
    if require_current_report {
        required_markers.push((
            "notes/k4-report.md",
            vec![
                "structured archive support details including null means",
                "all-source-backed-archives-negative flag",
            ],
        ));
    }
    let mut missing = Vec::new();
    for (relative_path, markers) in required_markers {
        let path = repo_root.join(relative_path);
        let contents = fs::read_to_string(&path).unwrap_or_default();
        for marker in markers {
            if !contents.contains(marker) {
                missing.push(format!("{relative_path}:{marker}"));
            }
        }
    }

    ReleaseCheck {
        name: "next-evidence-structured-support-documented",
        passed: missing.is_empty(),
        detail: if missing.is_empty() {
            format!(
                "Next-evidence structured archive support details are documented in release-facing files. path={}",
                repo_root.display()
            )
        } else {
            format!(
                "Next-evidence structured archive support details are missing from release-facing files. path={}; missing={}",
                repo_root.display(),
                missing.join("|")
            )
        },
    }
}

fn validate_committed_source_review(
    repo_root: &Path,
    path: &Path,
    value: &serde_json::Value,
) -> Vec<String> {
    let mut errors = Vec::new();
    let eligible_sources: std::collections::BTreeMap<_, _> = sources()
        .into_iter()
        .filter(|source| source.allowed_use == "public-facts-only")
        .map(|source| (source.id, source))
        .collect();

    let id = value.get("id").and_then(serde_json::Value::as_str);
    if id.is_none_or(|id| id.trim().is_empty()) {
        errors.push("id must not be empty".to_string());
    } else if id.is_some_and(contains_template_placeholder) {
        errors.push("id still contains template placeholder text".to_string());
    }
    if path
        .file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|file_stem| id.is_some_and(|id| file_stem != id))
    {
        errors.push("filename must match source-review id".to_string());
    }

    if value
        .get("promoted_candidate")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        errors.push("promoted_candidate must be false".to_string());
    }

    let review_note = value.get("review_note").and_then(serde_json::Value::as_str);
    if review_note.is_none_or(|note| note.trim().is_empty()) {
        errors.push("review_note must not be empty".to_string());
    } else if review_note.is_some_and(contains_template_placeholder) {
        errors.push("review_note still contains template placeholder text".to_string());
    }

    let source_ids = value
        .get("source_ids")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if source_ids.is_empty() {
        errors.push("source_ids must include at least one source".to_string());
    }
    let mut parsed_source_ids = Vec::new();
    let mut seen_source_ids = std::collections::BTreeSet::new();
    for source_id in source_ids {
        let Some(source_id) = source_id.as_str() else {
            errors.push("source_ids entries must be strings".to_string());
            continue;
        };
        if source_id.trim().is_empty() {
            errors.push("source_ids entries must not be empty".to_string());
            continue;
        }
        if !seen_source_ids.insert(source_id.to_string()) {
            errors.push(format!("source_id `{source_id}` appears more than once"));
        }
        if contains_template_placeholder(source_id) {
            errors.push("source_ids still contain template placeholder text".to_string());
            continue;
        }
        if !eligible_sources.contains_key(source_id) {
            errors.push(format!(
                "source_id `{source_id}` is not registered as eligible scored-observation evidence"
            ));
        }
        parsed_source_ids.push(source_id.to_string());
    }

    let source_entries = value
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if source_entries.is_empty() {
        errors.push("sources must include at least one reviewed source".to_string());
    }
    if !source_entries.is_empty() && source_entries.len() != parsed_source_ids.len() {
        errors.push(format!(
            "sources length {} does not match source_ids length {}",
            source_entries.len(),
            parsed_source_ids.len()
        ));
    }
    for source_entry in source_entries {
        let Some(source_id) = source_entry.get("id").and_then(serde_json::Value::as_str) else {
            errors.push("sources entries must include string id".to_string());
            continue;
        };
        let Some(expected_source) = eligible_sources.get(source_id) else {
            errors.push(format!(
                "sources entry `{source_id}` is not registered as eligible scored-observation evidence"
            ));
            continue;
        };
        if !parsed_source_ids.iter().any(|listed| listed == source_id) {
            errors.push(format!(
                "sources entry `{source_id}` is not listed in source_ids"
            ));
        }
        validate_source_review_json_field(
            &source_entry,
            source_id,
            "url",
            expected_source.url,
            &mut errors,
        );
        validate_source_review_json_field(
            &source_entry,
            source_id,
            "accessed_at",
            expected_source.accessed_at,
            &mut errors,
        );
        validate_source_review_json_field(
            &source_entry,
            source_id,
            "allowed_use",
            expected_source.allowed_use,
            &mut errors,
        );
        if source_entry
            .get("locally_archived")
            .and_then(serde_json::Value::as_bool)
            != Some(expected_source.archive_url.is_some())
        {
            errors.push(format!(
                "sources entry `{source_id}` has stale locally_archived value"
            ));
        }
        if let Some(archive_url) = expected_source.archive_url
            && !repo_root.join(archive_url).is_file()
        {
            errors.push(format!(
                "sources entry `{source_id}` references missing archive `{archive_url}`"
            ));
        }
    }

    if value
        .get("required_review_steps")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|steps| steps.is_empty())
    {
        errors.push("required_review_steps must not be empty".to_string());
    }
    if value
        .get("observation_requirements")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|requirements| requirements.is_empty())
    {
        errors.push("observation_requirements must not be empty".to_string());
    }

    errors
}

fn validate_source_review_json_field(
    source_entry: &serde_json::Value,
    source_id: &str,
    field: &str,
    expected: &str,
    errors: &mut Vec<String>,
) {
    if source_entry.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
        errors.push(format!(
            "sources entry `{source_id}` has stale {field} value"
        ));
    }
}

fn source_packet_allowed_use_matches(line: &str, allowed_use: &str) -> bool {
    match allowed_use {
        "public-facts-only" => {
            line.contains("Public installation and unresolved-section facts")
                || line.contains("Public sculpture/chart/K4 context")
        }
        "public-anchor-summary" => {
            line.contains("Public ciphertext and public clue summary")
                || line.contains("Public ciphertext provenance only")
        }
        "methodology-context" => {
            line.contains("Cryptodiagnosis context only")
                || line.contains("Methodology context only")
        }
        "public-clue-context" => line.contains("Public clue and Berlin World Clock context"),
        "archive-context-only" => {
            line.contains("Archive-sale context only")
                || line.contains("Archive-research context only")
                || line.contains("Archive-discovery context only")
                || line.contains("Archive-context only")
        }
        "unverified-solution-claim" => line.contains("Unverified solution claim quarantine"),
        _ => line.contains(allowed_use),
    }
}

fn check_exists(
    name: &'static str,
    path: impl AsRef<Path>,
    expectation: &'static str,
) -> ReleaseCheck {
    let path = path.as_ref();
    ReleaseCheck {
        name,
        passed: path.exists(),
        detail: format!("{expectation} path={}", path.display()),
    }
}

fn check_absent(
    name: &'static str,
    path: impl AsRef<Path>,
    expectation: &'static str,
) -> ReleaseCheck {
    let path = path.as_ref();
    ReleaseCheck {
        name,
        passed: !path.exists(),
        detail: format!("{expectation} path={}", path.display()),
    }
}

fn check_generated_report_markers(repo_root: &Path) -> ReleaseCheck {
    let relative_path = "notes/k4-report.md";
    let path = repo_root.join(relative_path);
    let contents = fs::read_to_string(&path).unwrap_or_default();
    let mut missing_markers: Vec<String> = REQUIRED_REPORT_MARKERS
        .iter()
        .copied()
        .filter(|marker| !contents.contains(marker))
        .map(str::to_string)
        .collect();
    match summarize_independent_lanes_with_repo_root(
        &repo_root.join("experiments/preregistrations"),
        repo_root,
    ) {
        Ok(report) => {
            for family in &report.family_summaries {
                let marker = format!(
                    "{}:{}_lanes/{}_unique_ready",
                    family.hypothesis_family,
                    family.lanes,
                    family.unique_ready_prediction_artifacts
                );
                if !contents.contains(&marker) {
                    missing_markers.push(marker);
                }
            }
        }
        Err(error) => {
            missing_markers.push(format!("independent lane summary unavailable: {error}"))
        }
    }

    ReleaseCheck {
        name: "markdown-report-current-markers",
        passed: missing_markers.is_empty(),
        detail: if missing_markers.is_empty() {
            format!(
                "Generated Markdown report contains current release-facing markers. path={}",
                path.display()
            )
        } else {
            format!(
                "Generated Markdown report is stale or incomplete. path={}; missing={}",
                path.display(),
                missing_markers.join(", ")
            )
        },
    }
}

fn check_no_plaintext_leakage_markers(repo_root: &Path) -> ReleaseCheck {
    let mut marker_hits = Vec::new();
    for relative_path in PLAINTEXT_LEAKAGE_SCAN_FILES {
        let path = repo_root.join(relative_path);
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };

        for marker in PLAINTEXT_LEAKAGE_MARKERS {
            if contents.contains(marker) {
                marker_hits.push(format!("{relative_path}:{marker}"));
            }
        }
    }
    for relative_dir in PLAINTEXT_LEAKAGE_SCAN_DIRS {
        scan_plaintext_leakage_dir(repo_root, relative_dir, &mut marker_hits);
    }

    ReleaseCheck {
        name: "no-plaintext-leakage-markers",
        passed: marker_hits.is_empty(),
        detail: if marker_hits.is_empty() {
            "No leaked/full-plaintext sentinel markers found in release-facing files or artifacts."
                .to_string()
        } else {
            format!(
                "Leaked/full-plaintext sentinel markers found: {}",
                marker_hits.join(",")
            )
        },
    }
}

fn check_claim_verification_archives(repo_root: &Path) -> ReleaseCheck {
    let relative_dir = "results/claim-verifications";
    let dir = repo_root.join(relative_dir);
    if !dir.exists() {
        return ReleaseCheck {
            name: "claim-verification-archives-structured",
            passed: true,
            detail: format!(
                "No committed claim-verification archives are present. path={}",
                dir.display()
            ),
        };
    }

    let registered_quarantined_sources: std::collections::BTreeSet<_> = sources()
        .into_iter()
        .filter(|source| source.allowed_use == "unverified-solution-claim")
        .map(|source| source.id)
        .collect();
    let mut checked = 0usize;
    let mut mismatches = Vec::new();

    let Ok(entries) = fs::read_dir(&dir) else {
        return ReleaseCheck {
            name: "claim-verification-archives-structured",
            passed: false,
            detail: format!(
                "Claim-verification archive directory is unreadable. path={}",
                dir.display()
            ),
        };
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        checked += 1;
        let archive_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<unknown>");
        let result_path = path.join("result.json");
        let summary_path = path.join("summary.md");
        if !result_path.exists() {
            mismatches.push(format!("{archive_name}:missing result.json"));
            continue;
        }
        if !summary_path.exists() {
            mismatches.push(format!("{archive_name}:missing summary.md"));
            continue;
        }

        let result_contents = match fs::read_to_string(&result_path) {
            Ok(contents) => contents,
            Err(error) => {
                mismatches.push(format!("{archive_name}:unreadable result.json: {error}"));
                continue;
            }
        };
        let result_json: serde_json::Value = match serde_json::from_str(&result_contents) {
            Ok(json) => json,
            Err(error) => {
                mismatches.push(format!("{archive_name}:invalid result.json: {error}"));
                continue;
            }
        };
        let summary_contents = match fs::read_to_string(&summary_path) {
            Ok(contents) => contents,
            Err(error) => {
                mismatches.push(format!("{archive_name}:unreadable summary.md: {error}"));
                continue;
            }
        };

        let source_id = result_json
            .get("source_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !registered_quarantined_sources.contains(source_id) {
            mismatches.push(format!(
                "{archive_name}:source_id `{source_id}` is not a quarantined claim source"
            ));
        }
        if result_json
            .get("promoted_candidate")
            .and_then(|value| value.as_bool())
            != Some(false)
        {
            mismatches.push(format!("{archive_name}:promoted_candidate must be false"));
        }
        let note = result_json
            .get("note")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !note.contains("claimed plaintext")
            || !(note.contains("does not print") || note.contains("without printing"))
        {
            mismatches.push(format!(
                "{archive_name}:result note must state the non-printing claimed-plaintext boundary"
            ));
        }
        if !summary_contents.contains("This is not a claimed solution.") {
            mismatches.push(format!(
                "{archive_name}:summary must include the no-solution boundary"
            ));
        }
        let summary_lowercase = summary_contents.to_ascii_lowercase();
        if !summary_lowercase.contains("promoted") {
            mismatches.push(format!(
                "{archive_name}:summary must include the promotion boundary"
            ));
        }
        if !summary_lowercase.contains("claimed plaintext")
            || !(summary_lowercase.contains("does not store")
                || summary_lowercase.contains("stored in this archive"))
        {
            mismatches.push(format!(
                "{archive_name}:summary must include the no-claimed-plaintext storage boundary"
            ));
        }
    }

    ReleaseCheck {
        name: "claim-verification-archives-structured",
        passed: checked > 0 && mismatches.is_empty(),
        detail: if checked > 0 && mismatches.is_empty() {
            format!(
                "Committed claim-verification archives are tied to quarantined claim sources and preserve non-promotion/no-plaintext boundaries. path={}; checked={checked}",
                dir.display()
            )
        } else if checked == 0 {
            format!(
                "No claim-verification archive directories were found. path={}",
                dir.display()
            )
        } else {
            format!(
                "Claim-verification archives failed structural checks. path={}; mismatches={}",
                dir.display(),
                mismatches.join(", ")
            )
        },
    }
}

fn scan_plaintext_leakage_dir(repo_root: &Path, relative_dir: &str, marker_hits: &mut Vec<String>) {
    let dir = repo_root.join(relative_dir);
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(relative_path) = path.strip_prefix(repo_root) else {
            continue;
        };
        let Some(relative_path) = relative_path.to_str() else {
            continue;
        };
        if path.is_dir() {
            scan_plaintext_leakage_dir(repo_root, relative_path, marker_hits);
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        for marker in PLAINTEXT_LEAKAGE_MARKERS {
            if contents.contains(marker) {
                marker_hits.push(format!("{relative_path}:{marker}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_all_period_prediction_plans;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn release_checks_pass_for_current_repo_layout() {
        let checks = run_release_checks(env!("CARGO_MANIFEST_DIR")).unwrap();

        assert!(
            checks
                .iter()
                .any(|check| check.name == "github-actions-disabled")
        );
        assert!(checks.iter().all(|check| check.passed));
    }

    #[test]
    fn release_checks_fail_when_generated_report_is_missing() {
        let temp = release_ready_temp_dir();
        fs::remove_file(temp.path().join("notes/k4-report.md")).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_on_plaintext_leakage_marker() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path().join("notes/k4-report.md"),
            "K4_LEAKED_PLAINTEXT must never be released.",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_on_plaintext_leakage_marker_in_stopped_lanes() {
        let temp = release_ready_temp_dir();
        let mut stopped_lanes = stopped_lanes_fixture().to_string();
        stopped_lanes.push_str("\nK4_PRIVATE_ARCHIVE_PLAINTEXT\n");
        fs::write(
            temp.path().join("experiments/STOPPED_LANES.md"),
            stopped_lanes,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_on_plaintext_leakage_marker_in_evidence_summary() {
        let temp = release_ready_temp_dir();
        fs::create_dir_all(temp.path().join("experiments/evidence-summaries")).unwrap();
        fs::write(
            temp.path()
                .join("experiments/evidence-summaries/leaky-summary.md"),
            "K4_ARCHIVE_PLAINTEXT must not be archived in summaries.",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_on_promoted_claim_verification_archive() {
        let temp = release_ready_temp_dir();
        let archive = temp
            .path()
            .join("results/claim-verifications/promoted-claim-fixture");
        fs::create_dir_all(&archive).unwrap();
        fs::write(
            archive.join("result.json"),
            r#"{
  "source_id": "solvekryptos-2026-claim",
  "structural_checks_passed": true,
  "promoted_candidate": true,
  "note": "Verifier output does not print claimed plaintext."
}"#,
        )
        .unwrap();
        fs::write(
            archive.join("summary.md"),
            "This is not a claimed solution.\n\npromoted: true\n\nNo claimed plaintext is stored.\n",
        )
        .unwrap();

        let check = check_claim_verification_archives(temp.path());
        assert!(!check.passed);
        assert!(check.detail.contains("promoted_candidate must be false"));
    }

    #[test]
    fn release_checks_fail_on_claim_verification_archive_for_non_quarantined_source() {
        let temp = release_ready_temp_dir();
        let archive = temp
            .path()
            .join("results/claim-verifications/non-quarantined-source-fixture");
        fs::create_dir_all(&archive).unwrap();
        fs::write(
            archive.join("result.json"),
            r#"{
  "source_id": "cia-sculpture",
  "structural_checks_passed": false,
  "promoted_candidate": false,
  "note": "Verifier output does not print claimed plaintext."
}"#,
        )
        .unwrap();
        fs::write(
            archive.join("summary.md"),
            "This is not a claimed solution.\n\npromoted: false\n\nNo claimed plaintext is stored.\n",
        )
        .unwrap();

        let check = check_claim_verification_archives(temp.path());
        assert!(!check.passed);
        assert!(check.detail.contains("not a quarantined claim source"));
    }

    #[test]
    fn release_checks_fail_when_generated_report_is_stale() {
        let temp = release_ready_temp_dir();
        fs::write(temp.path().join("notes/k4-report.md"), "old report").unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_source_packet_omits_registered_source() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path().join("sources/source-packet.md"),
            "`cia-artifact` only",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_source_packet_has_stale_source_fields() {
        let temp = release_ready_temp_dir();
        let mut packet = source_packet_fixture();
        packet = packet.replace(
            "https://kryptosbot.com/archive/",
            "https://example.com/stale-archive/",
        );
        fs::write(temp.path().join("sources/source-packet.md"), packet).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_registered_source_archive_is_missing() {
        let temp = release_ready_temp_dir();
        fs::remove_file(
            temp.path()
                .join("sources/archives/cia-artifact-2026-05-27.md"),
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_registered_source_archive_lacks_boundary() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("sources/archives/cia-artifact-2026-05-27.md"),
            "source_id: `cia-artifact`\npromoted_candidate: false\n",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_source_packet_has_stale_access_date() {
        let temp = release_ready_temp_dir();
        let packet = source_packet_fixture().replace("2026-05-25", "2026-05-20");
        fs::write(temp.path().join("sources/source-packet.md"), packet).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_candidate_csv_has_unregistered_material() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path().join("experiments/k4-candidates.csv"),
            "material,transform\nUNREGISTERED,a1-z26-zero-based\n",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_candidate_registry_references_unknown_source() {
        let temp = release_ready_temp_dir();
        let registry = candidate_registry_fixture().replace("`cia-artifact`", "`unknown-source`");
        fs::write(temp.path().join("experiments/k4-candidates.md"), registry).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_preregistration_is_invalid() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("experiments/preregistrations/invalid-lane.json"),
            r#"{
  "id": "replace-with-lane-id",
  "title": "Replace with lane title",
  "hypothesis_family": "replace-with-family",
  "evidence_kind": "independent-prediction-target",
  "source_ids": [],
  "rationale": "Explain why this lane is independent.",
  "prediction_target": "Define the independent target.",
  "discovery_inputs": ["Describe the rule."],
  "evaluation_inputs": ["Describe the target."],
  "controls": ["seeded shuffle baseline"],
  "uses_public_anchor_fragments_for_discovery": false,
  "uses_public_anchor_fragments_as_primary_evidence": false
}"#,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_preregistration_filename_does_not_match_id() {
        let temp = release_ready_temp_dir();
        fs::rename(
            temp.path()
                .join("experiments/preregistrations/non-anchor-position-period-v1.json"),
            temp.path()
                .join("experiments/preregistrations/new-lane-id.json"),
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_prediction_artifact_is_stale() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("experiments/predictions/non-anchor-position-period-v1.json"),
            r#"{"period_count":1,"periods":[]}"#,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_independent_lane_lacks_artifact() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("experiments/preregistrations/non-anchor-position-period-followup-v1.json"),
            r#"{
  "id": "non-anchor-position-period-followup-v1",
  "title": "Non-anchor position-period follow-up",
  "hypothesis_family": "position-period-prediction",
  "evidence_kind": "independent-prediction-target",
  "source_ids": [],
  "rationale": "This lane predeclares a structural position rule before any key-material scoring, and it does not use public anchor-derived additive fragments as discovery evidence or primary evaluation evidence.",
  "prediction_target": "Future independently obtained non-anchor K4 position observations should concentrate in predeclared residue classes for the registered period set before any key-material tuning is performed.",
  "discovery_inputs": ["Registered period set selected before scoring"],
  "evaluation_inputs": ["Future independently documented non-anchor K4 position observations"],
  "controls": ["best-of-period null control"],
  "uses_public_anchor_fragments_for_discovery": false,
  "uses_public_anchor_fragments_as_primary_evidence": false
}"#,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_preregistration_readme_omits_lane() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path().join("experiments/preregistrations/README.md"),
            "# Preregistrations\n\nNo lane inventory here.\n",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_observation_template_can_be_scored() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("experiments/position-observations-template.json"),
            r#"{
  "id": "scorable-template",
  "source_ids": ["cia-artifact"],
  "positions_one_based": [1, 4, 7],
  "rationale": "Accidentally populated template."
}"#,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_committed_observation_can_score_anchor_position() {
        let temp = release_ready_temp_dir();
        fs::create_dir_all(temp.path().join("experiments/position-observations")).unwrap();
        fs::create_dir_all(temp.path().join("experiments/source-reviews")).unwrap();
        fs::create_dir_all(temp.path().join("experiments/evidence-summaries")).unwrap();
        fs::write(
            temp.path()
                .join("experiments/source-reviews/source-review-v1.json"),
            r#"{
  "id": "source-review-v1",
  "source_ids": ["cia-sculpture"],
  "promoted_candidate": false
}"#,
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/position-observations/bad-observation-v1.json"),
            r#"{
  "id": "bad-observation-v1",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/source-review-v1.json",
  "positions_one_based": [22],
  "position_notes": {
    "22": "Synthetic note for an anchor position."
  },
  "rationale": "Synthetic release-check fixture."
}"#,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_committed_observation_lacks_summary() {
        let temp = release_ready_temp_dir();
        fs::create_dir_all(temp.path().join("experiments/position-observations")).unwrap();
        fs::create_dir_all(temp.path().join("experiments/source-reviews")).unwrap();
        fs::write(
            temp.path()
                .join("experiments/source-reviews/source-review-v1.json"),
            r#"{
  "id": "source-review-v1",
  "source_ids": ["cia-sculpture"],
  "promoted_candidate": false
}"#,
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/position-observations/valid-observation-v1.json"),
            r#"{
  "id": "valid-observation-v1",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/source-review-v1.json",
  "positions_one_based": [1],
  "position_notes": {
    "1": "Synthetic note for a non-anchor position."
  },
  "rationale": "Synthetic release-check fixture."
}"#,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_source_archive_omits_observation_positions() {
        let temp = release_ready_temp_dir();
        fs::create_dir_all(temp.path().join("experiments/position-observations")).unwrap();
        fs::create_dir_all(temp.path().join("experiments/source-reviews")).unwrap();
        fs::create_dir_all(temp.path().join("experiments/evidence-summaries")).unwrap();
        fs::write(
            temp.path()
                .join("experiments/source-reviews/source-review-v1.json"),
            r#"{
  "id": "source-review-v1",
  "source_ids": ["cia-sculpture"],
  "promoted_candidate": false
}"#,
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/position-observations/valid-observation-v1.json"),
            r#"{
  "id": "valid-observation-v1",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/source-review-v1.json",
  "positions_one_based": [1],
  "position_notes": {
    "1": "Synthetic note for a non-anchor position."
  },
  "rationale": "Synthetic release-check fixture."
}"#,
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/evidence-summaries/valid-observation-v1.md"),
            "This is not a claimed solution.\n\nObservation: experiments/position-observations/valid-observation-v1.json\n\nPromoted: false\n\nevaluate-period-prediction\n\nevaluate-spacing-prediction\n\nevaluate-mirror-prediction\n\nevaluate-grid-prediction\n\nevaluate-tableau-hill-prediction\n\nevaluate-ciphertext-prior\n\nevaluate-ciphertext-hotspot\n\nevaluate-ciphertext-rarity\n\nevaluate-ciphertext-repeat-distance\n\nevaluate-ciphertext-adjacent-contrast\n\nevaluate-ciphertext-transition\n\nevaluate-ciphertext-skip-transition\n\nevaluate-ciphertext-turning-point\n\nevaluate-ciphertext-window-balance\n\nevaluate-ciphertext-ct-perturbation\n\nevaluate-ciphertext-stehle-regularity\n\nevaluate-ciphertext-residue-balance\n\nvalidate-evaluation-archive\n\nresults/period-observations/valid-observation-v1\n\nresults/spacing-observations/valid-observation-v1\n\nresults/mirror-observations/valid-observation-v1\n\nresults/grid-observations/valid-observation-v1\n\nresults/grid-observations/valid-observation-column-v1\n\nresults/grid-observations/valid-observation-compass-axis-v1\n\nresults/tableau-hill-observations/valid-observation-v1\n\nresults/ciphertext-prior-observations/valid-observation-v1\n\nresults/ciphertext-hotspot-observations/valid-observation-v1\n\nresults/ciphertext-rarity-observations/valid-observation-v1\n\nresults/ciphertext-repeat-distance-observations/valid-observation-v1\n\nresults/ciphertext-adjacent-contrast-observations/valid-observation-v1\n\nresults/ciphertext-transition-observations/valid-observation-v1\n\nresults/ciphertext-skip-transition-observations/valid-observation-v1\n\nresults/ciphertext-turning-point-observations/valid-observation-v1\n\nresults/ciphertext-window-balance-observations/valid-observation-v1\n\nresults/ciphertext-ct-perturbation-observations/valid-observation-v1\n\nresults/ciphertext-stehle-regularity-observations/valid-observation-v1\n\nresults/ciphertext-residue-balance-observations/valid-observation-v1\n\n| Family | Observed Hits | Empirical P |\n| --- | --- | --- |\n| Period | 1/1 | 1.0000 |\n| Spacing | 0/0 pairs | 1.0000 |\n| Mirror | 0/0 pairs | 1.0000 |\n| Grid row | 0/0 positions | 1.0000 |\n| Grid column | 0/0 positions | 1.0000 |\n| Grid compass-axis | 0/0 positions | 1.0000 |\n| Tableau/HILL | 0/0 positions | 1.0000 |\n| Ciphertext prior | 0/0 positions | 1.0000 |\n| Ciphertext hotspot | 0/0 positions | 1.0000 |\n| Ciphertext rarity | 0/0 positions | 1.0000 |\n| Ciphertext repeat-distance | 0/0 positions | 1.0000 |\n| Ciphertext adjacent-contrast | 0/0 positions | 1.0000 |\n| Ciphertext transition | 0/0 positions | 1.0000 |\n| Ciphertext skip-transition | 0/0 positions | 1.0000 |\n| Ciphertext turning-point | 0/0 positions | 1.0000 |\n| Ciphertext window-balance | 0/0 positions | 1.0000 |\n| Ciphertext CT-perturbation | 0/0 positions | 1.0000 |\n| Ciphertext Stehle regularity | 0/0 positions | 1.0000 |\n| Ciphertext residue-balance | 0/0 positions | 1.0000 |\n\nInterpretation: negative source-backed evidence for this fixture.\n",
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("sources/archives/cia-sculpture-2026-05-27.md"),
            "# Source Snapshot\n\nsource_id: `cia-sculpture`\nsource_url: https://www.cia.gov/legacy/headquarters/kryptos-sculpture/\nreviewed_at: 2026-05-27\narchive_kind: quote-free local review snapshot\npromoted_candidate: false\n\n## Reviewed Facts\n\n- Synthetic reviewed fact without the scored observation reference.\n\n## Boundary\n\n- No candidate material, key stream, route, or plaintext is promoted.\n",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_source_archive_has_empty_non_scorable_reason() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("sources/archives/cia-artifact-2026-05-27.md"),
            "# Source Snapshot\n\nsource_id: `cia-artifact`\nsource_url: https://www.cia.gov/legacy/museum/artifact/kryptos/\nreviewed_at: 2026-05-27\narchive_kind: quote-free local review snapshot\npromoted_candidate: false\nnon_scorable_reason:   \n\n## Reviewed Facts\n\n- Synthetic reviewed fact.\n\n## Boundary\n\n- No candidate material, key stream, route, or plaintext is promoted.\n",
        )
        .unwrap();

        let check = check_source_archives_structured(temp.path());
        assert!(!check.passed);
        assert!(
            check
                .detail
                .contains("non_scorable_reason marker must include a reason")
        );
    }

    #[test]
    fn release_checks_fail_when_source_archive_lacks_score_or_non_scorable_marker() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("sources/archives/cia-artifact-2026-05-27.md"),
            "# Source Snapshot\n\nsource_id: `cia-artifact`\nsource_url: https://www.cia.gov/legacy/museum/artifact/kryptos/\nreviewed_at: 2026-05-27\narchive_kind: quote-free local review snapshot\npromoted_candidate: false\n\n## Reviewed Facts\n\n- Synthetic reviewed fact.\n\n## Boundary\n\n- No candidate material, key stream, route, or plaintext is promoted.\n",
        )
        .unwrap();

        let check = check_source_archives_structured(temp.path());
        assert!(!check.passed);
        assert!(
            check
                .detail
                .contains("must include scored_positions_one_based or non_scorable_reason")
        );
    }

    #[test]
    fn release_checks_fail_when_source_archive_is_both_non_scorable_and_scored() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path()
                .join("sources/archives/cia-artifact-2026-05-27.md"),
            "# Source Snapshot\n\nsource_id: `cia-artifact`\nsource_url: https://www.cia.gov/legacy/museum/artifact/kryptos/\nreviewed_at: 2026-05-27\narchive_kind: quote-free local review snapshot\npromoted_candidate: false\nnon_scorable_reason: Synthetic fixture cannot be scored.\n\n## Reviewed Facts\n\n- scored_positions_one_based: 1,4,5\n\n## Boundary\n\n- No candidate material, key stream, route, or plaintext is promoted.\n",
        )
        .unwrap();

        let check = check_source_archives_structured(temp.path());
        assert!(!check.passed);
        assert!(
            check
                .detail
                .contains("non_scorable_reason cannot coexist with scored_positions_one_based")
        );
    }

    #[test]
    fn evidence_summary_gate_requires_archive_command_references() {
        let temp = release_ready_temp_dir();
        fs::create_dir_all(temp.path().join("experiments/position-observations")).unwrap();
        fs::create_dir_all(temp.path().join("experiments/evidence-summaries")).unwrap();
        fs::write(
            temp.path()
                .join("experiments/position-observations/valid-observation-v1.json"),
            r#"{
  "id": "valid-observation-v1",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/source-review-v1.json",
  "positions_one_based": [1],
  "position_notes": {
    "1": "Synthetic note for a non-anchor position."
  },
  "rationale": "Synthetic release-check fixture."
}"#,
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/evidence-summaries/valid-observation-v1.md"),
            "This is not a claimed solution.\n\nObservation: experiments/position-observations/valid-observation-v1.json\n\nPromoted: false\n",
        )
        .unwrap();

        let check = check_evidence_summaries_present(temp.path());
        assert!(!check.passed);
        assert!(
            check
                .detail
                .contains("results/period-observations/valid-observation-v1")
        );
        assert!(
            check
                .detail
                .contains("results/spacing-observations/valid-observation-v1")
        );
    }

    #[test]
    fn evidence_summary_gate_requires_negative_result_metrics() {
        let temp = release_ready_temp_dir();
        fs::create_dir_all(temp.path().join("experiments/position-observations")).unwrap();
        fs::create_dir_all(temp.path().join("experiments/evidence-summaries")).unwrap();
        fs::write(
            temp.path()
                .join("experiments/position-observations/valid-observation-v1.json"),
            r#"{
  "id": "valid-observation-v1",
  "source_ids": ["cia-sculpture"],
  "source_review_file": "experiments/source-reviews/source-review-v1.json",
  "positions_one_based": [1],
  "position_notes": {
    "1": "Synthetic note for a non-anchor position."
  },
  "rationale": "Synthetic release-check fixture."
}"#,
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/evidence-summaries/valid-observation-v1.md"),
            "This is not a claimed solution.\n\nObservation: experiments/position-observations/valid-observation-v1.json\n\nPromoted: false\n\nevaluate-period-prediction\n\nevaluate-spacing-prediction\n\nvalidate-evaluation-archive\n\nresults/period-observations/valid-observation-v1\n\nresults/spacing-observations/valid-observation-v1\n",
        )
        .unwrap();

        let check = check_evidence_summaries_present(temp.path());
        assert!(!check.passed);
        assert!(check.detail.contains("Empirical P"));
        assert!(check.detail.contains("negative"));
    }

    #[test]
    fn release_checks_fail_when_committed_source_review_has_stale_source_metadata() {
        let temp = release_ready_temp_dir();
        fs::create_dir_all(temp.path().join("experiments/source-reviews")).unwrap();
        fs::write(
            temp.path()
                .join("experiments/source-reviews/stale-source-review-v1.json"),
            r#"{
  "id": "stale-source-review-v1",
  "source_ids": ["cia-sculpture"],
  "sources": [
    {
      "id": "cia-sculpture",
      "url": "https://example.com/stale",
      "locally_archived": true,
      "accessed_at": "2026-05-20",
      "allowed_use": "public-facts-only"
    }
  ],
  "review_note": "Synthetic stale source-review fixture.",
  "required_review_steps": ["Review source."],
  "observation_requirements": ["Record positions."],
  "promoted_candidate": false
}"#,
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_stopped_lanes_omit_row_boundary_lane() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path().join("experiments/STOPPED_LANES.md"),
            "# Stopped K4 Experiment Lanes\n\nIt is not a solution claim.\n\n## Required Gate For New Lanes\n\ncargo run --locked -- validate-preregistration --input <path>\n",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_stopped_lanes_omit_duplicate_period_boundary() {
        let temp = release_ready_temp_dir();
        let stopped_lanes = stopped_lanes_fixture()
            .replace("## Duplicate Period-Lane Readiness Inventory\n\n", "")
            .replace("Status: stopped as evidence.\n\n", "")
            .replace(
                "validate-prediction-artifact --require-unique-artifact\n\n",
                "",
            );
        fs::write(
            temp.path().join("experiments/STOPPED_LANES.md"),
            stopped_lanes,
        )
        .unwrap();

        let check = check_stopped_lanes_documented(temp.path());
        assert!(!check.passed);
        assert!(
            check
                .detail
                .contains("## Duplicate Period-Lane Readiness Inventory")
        );
        assert!(
            check
                .detail
                .contains("validate-prediction-artifact --require-unique-artifact")
        );
        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_progress_log_has_stale_inventory() {
        let temp = release_ready_temp_dir();
        fs::write(
            temp.path().join("experiments/PROGRESS_LOG.md"),
            "# K4 Experiment Progress Log\n\nindependent lanes: `18`\n\nNo independent observation has been scored.\n",
        )
        .unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_source_readiness_command_is_undocumented() {
        let temp = release_ready_temp_dir();
        let readme_path = temp.path().join("README.md");
        let readme = fs::read_to_string(&readme_path)
            .unwrap()
            .replace("cargo run -- source-observation-status --format json", "");
        fs::write(readme_path, readme).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_source_frontier_fields_are_undocumented() {
        let temp = release_ready_temp_dir();
        let progress_path = temp.path().join("experiments/PROGRESS_LOG.md");
        let progress_log = fs::read_to_string(&progress_path)
            .unwrap()
            .replace("`frontier_blocking_conditions`", "");
        fs::write(progress_path, progress_log).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn report_release_checks_tolerate_stale_generated_report_markers() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("docs")).unwrap();
        fs::create_dir_all(temp.path().join("experiments")).unwrap();
        fs::create_dir_all(temp.path().join("notes")).unwrap();
        fs::write(
            temp.path().join("README.md"),
            "cargo run -- source-observation-status --format json\n`source-observation-status`\n`source-frontier`\nmachine-readable frontier blockers\nrequired next-evidence criteria\ndisallowed next actions\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("docs/research-method.md"),
            "Run `source-observation-status` before scoring.\nmachine-readable `frontier_blocking_conditions`\n`required_next_evidence`\n`disallowed_next_actions`\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("experiments/PROGRESS_LOG.md"),
            "`source-observation-status --format json`\n`source_observation_status_command`\n`source-frontier --format json`\n`frontier_blocking_conditions`\n`required_next_evidence`\n`disallowed_next_actions`\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("notes/k4-report.md"),
            "stale generated report\n",
        )
        .unwrap();

        assert!(!check_source_readiness_commands_documented(temp.path(), true).passed);
        assert!(check_source_readiness_commands_documented(temp.path(), false).passed);
    }

    #[test]
    fn release_checks_fail_when_next_evidence_structured_support_is_undocumented() {
        let temp = release_ready_temp_dir();
        let readme_path = temp.path().join("README.md");
        let readme = fs::read_to_string(&readme_path)
            .unwrap()
            .replace("`evidence_support_details`", "");
        fs::write(readme_path, readme).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn release_checks_fail_when_next_evidence_negative_frontier_flag_is_undocumented() {
        let temp = release_ready_temp_dir();
        let progress_path = temp.path().join("experiments/PROGRESS_LOG.md");
        let progress_log = fs::read_to_string(&progress_path)
            .unwrap()
            .replace("`all_source_backed_archives_negative: true`", "");
        fs::write(progress_path, progress_log).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    fn release_ready_temp_dir() -> TempDir {
        let temp = TempDir::new().unwrap();
        for directory in [
            "docs",
            "sources",
            "sources/archives",
            "notes",
            "experiments",
            "experiments/preregistrations",
            "experiments/predictions",
        ] {
            fs::create_dir_all(temp.path().join(directory)).unwrap();
        }
        for (_, relative_path) in REQUIRED_RELEASE_FILES {
            fs::write(temp.path().join(relative_path), "release file").unwrap();
        }
        fs::write(temp.path().join("README.md"), readme_fixture()).unwrap();
        fs::write(
            temp.path().join("docs/research-method.md"),
            research_method_fixture(),
        )
        .unwrap();
        fs::write(
            temp.path().join("experiments/STOPPED_LANES.md"),
            stopped_lanes_fixture(),
        )
        .unwrap();
        fs::write(
            temp.path().join("experiments/PROGRESS_LOG.md"),
            progress_log_fixture(),
        )
        .unwrap();
        fs::write(
            temp.path().join("experiments/preregistrations/README.md"),
            preregistration_readme_fixture(),
        )
        .unwrap();
        fs::write(
            temp.path().join("experiments/k4-candidates.csv"),
            "material,transform\nKRYPTOS,a1-z26-zero-based\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("experiments/k4-candidates.md"),
            candidate_registry_fixture(),
        )
        .unwrap();
        fs::write(
            temp.path().join("sources/source-packet.md"),
            source_packet_fixture(),
        )
        .unwrap();
        for source in sources() {
            let Some(archive_url) = source.archive_url else {
                continue;
            };
            if archive_url.starts_with("http://") || archive_url.starts_with("https://") {
                continue;
            }
            fs::write(
                temp.path().join(archive_url),
                format!(
                    "# Source Snapshot\n\nsource_id: `{}`\nsource_url: {}\nreviewed_at: {}\narchive_kind: quote-free local review snapshot\npromoted_candidate: false\n\n## Reviewed Facts\n\n- Synthetic reviewed fact for release-check fixtures.\n\n## Boundary\n\n- No candidate material, key stream, route, or plaintext is promoted.\n",
                    source.id, source.url, source.accessed_at
                ),
            )
            .unwrap();
        }
        fs::write(
            temp.path()
                .join("experiments/preregistrations/non-anchor-position-period-v1.json"),
            preregistration_fixture(),
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/position-observations-template.json"),
            position_observation_template_fixture(),
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("experiments/predictions/non-anchor-position-period-v1.json"),
            serde_json::to_string_pretty(&build_all_period_prediction_plans().unwrap()).unwrap(),
        )
        .unwrap();
        for (_, relative_path) in REQUIRED_GENERATED_REPORTS {
            fs::write(
                temp.path().join(relative_path),
                format!(
                    "{}\n{}",
                    REQUIRED_REPORT_MARKERS.join("\n"),
                    generated_report_extra_markers()
                ),
            )
            .unwrap();
        }
        temp
    }

    fn readme_fixture() -> &'static str {
        r#"# Release Check Fixture

cargo run -- source-observation-status --format json
`source-observation-status`
`source-frontier`
machine-readable frontier blockers
required next-evidence criteria
disallowed next actions
`evidence_support_details`
`all_source_backed_archives_negative`
structured archive support details
null-mean
"#
    }

    fn research_method_fixture() -> &'static str {
        r#"# Research Method Fixture

Run `source-observation-status` before scoring.
machine-readable `frontier_blocking_conditions`
`required_next_evidence`
`disallowed_next_actions`
structured archive support details including null means
all-source-backed-archives-negative flag
"#
    }

    fn generated_report_extra_markers() -> &'static str {
        r#"`source-observation-status`
`source-frontier`
machine-readable frontier blockers
required next-evidence criteria
disallowed next actions
structured archive support details including null means
all-source-backed-archives-negative flag
"#
    }

    fn stopped_lanes_fixture() -> &'static str {
        r#"# Stopped K4 Experiment Lanes

This file records stopped release-check fixture lanes.
It is not a solution claim.

## Public Anchor-Derived Key-Material Lanes

Status: stopped.

## Source-Expanded Sculpture/Chart/Matrix Lane

Status: stopped.

## Candidate-Independent Position Structure Lanes

Status: stopped for current registered models.

## Duplicate Period-Lane Readiness Inventory

Status: stopped as evidence.

validate-prediction-artifact --require-unique-artifact

## CIA Row-Boundary Observation Lane

Status: stopped for the committed period, period-14, spacing, mirror, grid row, grid column, grid compass-axis, Tableau/HILL,
ciphertext-repeat-distance, ciphertext-adjacent-contrast, ciphertext-skip-transition, ciphertext-turning-point,
and ciphertext-residue-balance prediction targets.

grid column `p=0.1303`, grid compass-axis `p=0.9166`, period-14 `p=1.0000`, ciphertext-repeat-distance `p=0.5273`, ciphertext-adjacent-contrast `p=0.5259`, ciphertext-skip-transition `p=1.0000`,
ciphertext-turning-point `p=0.5247`, ciphertext-window-balance `p=1.0000`, ciphertext-residue-balance `p=0.4803`, and high-moduli ciphertext-residue-balance `p=0.6416`.

Latest evidence is summarized in
`experiments/evidence-summaries/cia-k4-row-boundaries-v1.md`.

## Simple Single-Layer And Uncorrected Search Lanes

Status: stopped unless a preregistration narrows the search before scoring.

## Required Gate For New Lanes

cargo run --locked -- validate-preregistration --input <path>
"#
    }

    fn progress_log_fixture() -> &'static str {
        r#"# K4 Experiment Progress Log

This log records command-backed findings that affect what should be tried next.
It is not a claimed solution.

Current independent-lane status:

- independent lanes: `1`
- ready for source-backed observations: `1`
- prediction artifacts: `1`
- unique ready prediction targets: `1`
- duplicate artifact lanes: `0`
- extra duplicate artifact lanes: `0`
- period-family lanes: `1`
- period-family unique ready targets: `1`
- source-backed observation files: `0`
- evidence summaries: `0`
- next action kind:
  `new-source-backed-rationale-or-distinct-prediction-artifact`
- blocking condition: `duplicate-period-lanes-not-evidence`
- blocking condition: `source-backed-evidence-negative-or-non-significant`
- blocking condition: `unused-eligible-source-marked-non-scorable`
- next-evidence-gate reports `all_source_backed_archives_negative: true`
- source-frontier command: `source-frontier --format json`
- source-frontier fields: `frontier_blocking_conditions`
- source-frontier fields: `required_next_evidence`
- source-frontier fields: `disallowed_next_actions`
- promoted: false
"#
    }

    fn preregistration_readme_fixture() -> &'static str {
        r#"# Preregistrations

Current independent period lanes:

- `non-anchor-position-period-v1.json` with committed artifact
  `experiments/predictions/non-anchor-position-period-v1.json`
"#
    }

    fn source_packet_fixture() -> String {
        let source_rows = sources()
            .into_iter()
            .map(|source| {
                let allowed_use_summary = match source.allowed_use {
                    "public-facts-only" if source.id == "cia-artifact" => {
                        "Public installation and unresolved-section facts"
                    }
                    "public-facts-only" => "Public sculpture/chart/K4 context",
                    "public-anchor-summary" => "Public ciphertext and public clue summary",
                    "methodology-context" if source.id == "histocrypt-2021-bean" => {
                        "Cryptodiagnosis context only"
                    }
                    "methodology-context" => "Methodology context only",
                    "public-clue-context" => "Public clue and Berlin World Clock context",
                    "archive-context-only" if source.id == "kryptosbot-sanborn-papers-2026" => {
                        "Archive-research context only"
                    }
                    "archive-context-only" => "Archive-sale context only",
                    "unverified-solution-claim" => "Unverified solution claim quarantine",
                    allowed_use => allowed_use,
                };
                let archive_status = source.archive_url.unwrap_or("Not locally archived");
                format!(
                    "| `{}` | {} | {} | {} | {} | {} |",
                    source.id,
                    source.source_type,
                    source.url,
                    archive_status,
                    allowed_use_summary,
                    source.use_note
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            "# Source Packet\n\nLast updated: 2026-05-27\nSource access dates: 2026-05-20 through 2026-05-27\n\n{source_rows}"
        )
    }

    fn candidate_registry_fixture() -> String {
        "# K4 Candidate Key-Material Registry\n\nSource IDs: `cia-artifact`\n\nRationale: source-backed test fixture.\n\nRows:\n\n- `KRYPTOS`, A1/Z26 zero-based\n".to_string()
    }

    fn preregistration_fixture() -> String {
        r#"{
  "id": "non-anchor-position-period-v1",
  "title": "Non-anchor position period prediction",
  "hypothesis_family": "position-period-prediction",
  "evidence_kind": "independent-prediction-target",
  "source_ids": [],
  "rationale": "This lane predeclares a structural position rule before any key-material scoring, and it does not use public anchor-derived additive fragments as discovery evidence or primary evaluation evidence.",
  "prediction_target": "Independently obtained non-anchor K4 position observations should concentrate in predeclared residue classes for the registered period set before any candidate-word tuning is performed.",
  "prediction_artifact": "experiments/predictions/non-anchor-position-period-v1.json",
  "discovery_inputs": [
    "Predeclared period-residue rule over non-anchor K4 positions only.",
    "Registered period set {2,3,4,5,7,8,13,14} emitted before any observation scoring."
  ],
  "evaluation_inputs": [
    "Source-backed non-anchor position observations that are not public EAST, NORTHEAST, BERLIN, or CLOCK anchor fragments.",
    "Observation files that declare source IDs, one-based positions, per-position notes, and rationale before evaluation."
  ],
  "controls": [
    "seeded shuffle baseline over non-anchor positions",
    "best-of-period null control across registered periods",
    "multiple-comparison correction for the registered period set"
  ],
  "uses_public_anchor_fragments_for_discovery": false,
  "uses_public_anchor_fragments_as_primary_evidence": false
}"#
        .to_string()
    }

    fn position_observation_template_fixture() -> String {
        r#"{
  "id": "replace-with-observation-id",
  "source_ids": [
    "replace-with-registered-source-id"
  ],
  "positions_one_based": [],
  "position_notes": {},
  "rationale": "Explain why these are independent non-anchor K4 positions before evaluating them."
}"#
        .to_string()
    }
}
