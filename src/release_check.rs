use crate::data::sources;
use crate::preregistration::{
    LanePreregistration, validate_prediction_artifact_with_repo_root, validate_preregistration,
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

const REQUIRED_REPORT_MARKERS: [&str; 6] = [
    "`validate-prediction-artifact`",
    "`validate-period-observations`",
    "`evaluate-period-prediction`",
    "Independent non-anchor period targets are materialized before scoring",
    "evidence-free prediction target",
    "`position-structure`",
];

const PLAINTEXT_LEAKAGE_SCAN_FILES: [&str; 4] = [
    "README.md",
    "docs/research-method.md",
    "sources/source-packet.md",
    "notes/k4-report.md",
];

const PLAINTEXT_LEAKAGE_MARKERS: [&str; 4] = [
    "K4_FULL_PLAINTEXT",
    "K4_LEAKED_PLAINTEXT",
    "K4_ARCHIVE_PLAINTEXT",
    "K4_PRIVATE_ARCHIVE_PLAINTEXT",
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
    checks.push(check_prediction_artifacts_validate(repo_root));
    checks.push(check_source_packet_latest_access_date(repo_root));
    checks.push(check_source_packet_registry_alignment(repo_root));
    checks.push(check_no_plaintext_leakage_markers(repo_root));

    if checks.iter().any(|check| !check.passed) {
        bail!("release preflight failed");
    }

    Ok(checks)
}

fn check_preregistrations_validate(repo_root: &Path) -> ReleaseCheck {
    let preregistrations = committed_preregistration_paths(repo_root);
    let mut mismatches = Vec::new();

    for path in &preregistrations {
        match fs::read_to_string(path) {
            Ok(input) => match validate_preregistration(&input) {
                Ok(validation) => {
                    if !validation.valid {
                        mismatches.push(format!(
                            "{}:{}",
                            path.display(),
                            validation.errors.join("|")
                        ));
                    }
                    let file_stem = path.file_stem().and_then(|name| name.to_str());
                    if file_stem != Some(validation.id.as_str()) {
                        mismatches.push(format!(
                            "{}:filename must match preregistration id `{}`",
                            path.display(),
                            validation.id
                        ));
                    }
                }
                Err(error) => mismatches.push(format!("{}:{error}", path.display())),
            },
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

fn source_packet_allowed_use_matches(line: &str, allowed_use: &str) -> bool {
    match allowed_use {
        "public-facts-only" => {
            line.contains("Public installation and unresolved-section facts")
                || line.contains("Public sculpture/chart/K4 context")
        }
        "public-anchor-summary" => line.contains("Public ciphertext and public clue summary"),
        "methodology-context" => {
            line.contains("Cryptodiagnosis context only")
                || line.contains("Methodology context only")
        }
        "public-clue-context" => line.contains("Public clue and Berlin World Clock context"),
        "archive-context-only" => {
            line.contains("Archive-sale context only")
                || line.contains("Archive-research context only")
        }
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
    let missing_markers: Vec<_> = REQUIRED_REPORT_MARKERS
        .iter()
        .copied()
        .filter(|marker| !contents.contains(marker))
        .collect();

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

    ReleaseCheck {
        name: "no-plaintext-leakage-markers",
        passed: marker_hits.is_empty(),
        detail: if marker_hits.is_empty() {
            "No leaked/full-plaintext sentinel markers found in release-facing files.".to_string()
        } else {
            format!(
                "Leaked/full-plaintext sentinel markers found: {}",
                marker_hits.join(",")
            )
        },
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

    fn release_ready_temp_dir() -> TempDir {
        let temp = TempDir::new().unwrap();
        for directory in [
            "docs",
            "sources",
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
        fs::write(
            temp.path()
                .join("experiments/preregistrations/non-anchor-position-period-v1.json"),
            preregistration_fixture(),
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
                REQUIRED_REPORT_MARKERS.join("\n"),
            )
            .unwrap();
        }
        temp
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
                    allowed_use => allowed_use,
                };
                format!(
                    "| `{}` | {} | {} | Not locally archived | {} | {} |",
                    source.id, source.source_type, source.url, allowed_use_summary, source.use_note
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            "# Source Packet\n\nLast updated: 2026-05-25\nSource access dates: 2026-05-20 through 2026-05-25\n\n{source_rows}"
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
    "Registered period set {2,3,4,5,7,8,13} emitted before any observation scoring."
  ],
  "evaluation_inputs": [
    "Source-backed non-anchor position observations that are not public EAST, NORTHEAST, BERLIN, or CLOCK anchor fragments.",
    "Observation files that declare source IDs, one-based positions, and rationale before evaluation."
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
}
