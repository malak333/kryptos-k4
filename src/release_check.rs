//! Local release gate: no CI, and no claimed or leaked plaintext in release-facing files.

use crate::data::sources;
use anyhow::{Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

const PLAINTEXT_LEAKAGE_SCAN_FILES: [&str; 2] = ["README.md", "sources/source-packet.md"];

const PLAINTEXT_LEAKAGE_SCAN_DIRS: [&str; 5] = [
    "docs",
    "experiments",
    "results/claim-verifications",
    "sources/archives",
    "notes",
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

/// Run the local release gate. Fails if any check fails.
pub fn run_release_checks(repo_root: impl AsRef<Path>) -> Result<Vec<ReleaseCheck>> {
    let repo_root = repo_root.as_ref();
    let checks = vec![
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
        check_claim_verification_archives(repo_root),
        check_no_plaintext_leakage_markers(repo_root),
    ];

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
    fn release_checks_fail_on_plaintext_leakage_marker_in_scanned_file() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("notes")).unwrap();
        fs::write(
            temp.path().join("notes/k4-report.md"),
            "K4_LEAKED_PLAINTEXT must never be released.",
        )
        .unwrap();

        let check = check_no_plaintext_leakage_markers(temp.path());
        assert!(!check.passed);
        assert!(
            check
                .detail
                .contains("notes/k4-report.md:K4_LEAKED_PLAINTEXT")
        );
    }

    #[test]
    fn release_checks_fail_on_plaintext_leakage_marker_in_nested_dir() {
        let temp = TempDir::new().unwrap();
        let nested = temp.path().join("sources/archives/deep");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("note.md"), "K4_ARCHIVE_PLAINTEXT").unwrap();

        assert!(!check_no_plaintext_leakage_markers(temp.path()).passed);
    }

    #[test]
    fn release_checks_fail_when_github_actions_exist() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join(".github/workflows")).unwrap();

        assert!(run_release_checks(temp.path()).is_err());
    }

    #[test]
    fn claim_archive_check_rejects_promoted_or_unquarantined_archives() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("results/claim-verifications/example");
        fs::create_dir_all(&archive).unwrap();
        fs::write(
            archive.join("result.json"),
            r#"{"source_id":"cia-sculpture","promoted_candidate":true,"note":"x"}"#,
        )
        .unwrap();
        fs::write(archive.join("summary.md"), "summary").unwrap();

        let check = check_claim_verification_archives(temp.path());
        assert!(!check.passed);
        assert!(check.detail.contains("not a quarantined claim source"));
        assert!(check.detail.contains("promoted_candidate must be false"));
    }
}
