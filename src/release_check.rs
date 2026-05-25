use crate::data::sources;
use anyhow::{Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

const REQUIRED_RELEASE_FILES: [(&str, &str); 8] = [
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
    checks.push(check_source_packet_latest_access_date(repo_root));
    checks.push(check_source_packet_registry_alignment(repo_root));
    checks.push(check_no_plaintext_leakage_markers(repo_root));

    if checks.iter().any(|check| !check.passed) {
        bail!("release preflight failed");
    }

    Ok(checks)
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
        "methodology-context" => line.contains("Cryptodiagnosis context only"),
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

    fn release_ready_temp_dir() -> TempDir {
        let temp = TempDir::new().unwrap();
        for directory in ["docs", "sources", "notes"] {
            fs::create_dir_all(temp.path().join(directory)).unwrap();
        }
        for (_, relative_path) in REQUIRED_RELEASE_FILES {
            fs::write(temp.path().join(relative_path), "release file").unwrap();
        }
        fs::write(
            temp.path().join("sources/source-packet.md"),
            source_packet_fixture(),
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
                    "methodology-context" => "Cryptodiagnosis context only",
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
}
