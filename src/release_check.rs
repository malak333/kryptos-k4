use anyhow::{Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

const REQUIRED_RELEASE_FILES: [(&str, &str); 6] = [
    ("readme-present", "README.md"),
    ("research-method-present", "docs/research-method.md"),
    ("source-packet-present", "sources/source-packet.md"),
    ("research-plan-present", "kryptos-k4-research-plan.md"),
    ("license-present", "LICENSE"),
    ("lockfile-present", "Cargo.lock"),
];

const REQUIRED_GENERATED_REPORTS: [(&str, &str); 1] =
    [("markdown-report-present", "notes/k4-report.md")];

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

    checks.push(check_no_plaintext_leakage_markers(repo_root));

    if checks.iter().any(|check| !check.passed) {
        bail!("release preflight failed");
    }

    Ok(checks)
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
            format!(
                "No leaked/full-plaintext sentinel markers found in release-facing files. markers={}",
                PLAINTEXT_LEAKAGE_MARKERS.join(",")
            )
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

    fn release_ready_temp_dir() -> TempDir {
        let temp = TempDir::new().unwrap();
        for directory in ["docs", "sources", "notes"] {
            fs::create_dir_all(temp.path().join(directory)).unwrap();
        }
        for (_, relative_path) in REQUIRED_RELEASE_FILES {
            fs::write(temp.path().join(relative_path), "release file").unwrap();
        }
        for (_, relative_path) in REQUIRED_GENERATED_REPORTS {
            fs::write(temp.path().join(relative_path), "generated report").unwrap();
        }
        temp
    }
}
