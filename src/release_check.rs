use anyhow::{Result, bail};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

pub fn run_release_checks(repo_root: impl AsRef<Path>) -> Result<Vec<ReleaseCheck>> {
    let repo_root = repo_root.as_ref();
    let checks = vec![
        check_absent(
            "github-actions-disabled",
            repo_root.join(".github/workflows"),
            "GitHub Actions workflow directory must not exist.",
        ),
        check_exists(
            "source-packet-present",
            repo_root.join("sources/source-packet.md"),
            "Source packet must be tracked before release.",
        ),
        check_exists(
            "research-plan-present",
            repo_root.join("kryptos-k4-research-plan.md"),
            "Research plan must remain in the release artifact.",
        ),
    ];

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
