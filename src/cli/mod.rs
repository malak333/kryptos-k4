//! Command handlers for the kryptos-k4 binary.

pub(crate) mod claim;
pub(crate) mod eliminate;

pub(crate) mod info;

pub(crate) mod keys;

use anyhow::{Context, Result};

use clap::ValueEnum;

use kryptos_k4::{
    AlphabetKind, BaselineAlphabetScope, BaselineTargetScope, CandidateTransform, FragmentMode,
    ReportFormat,
};

use std::{fs, path::Path};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum OutputFormat {
    Markdown,
    Json,
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Markdown => ReportFormat::Markdown,
            OutputFormat::Json => ReportFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliAlphabet {
    Standard,
    Kryptos,
    KryptosReversed,
}

impl From<CliAlphabet> for AlphabetKind {
    fn from(value: CliAlphabet) -> Self {
        match value {
            CliAlphabet::Standard => AlphabetKind::Standard,
            CliAlphabet::Kryptos => AlphabetKind::Kryptos,
            CliAlphabet::KryptosReversed => AlphabetKind::KryptosReversed,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliFragmentMode {
    #[value(name = "additive-key")]
    Additive,
    #[value(name = "subtractive-key")]
    Subtractive,
    #[value(name = "beaufort-key")]
    Beaufort,
}

impl From<CliFragmentMode> for FragmentMode {
    fn from(value: CliFragmentMode) -> Self {
        match value {
            CliFragmentMode::Additive => FragmentMode::AdditiveKey,
            CliFragmentMode::Subtractive => FragmentMode::SubtractiveKey,
            CliFragmentMode::Beaufort => FragmentMode::BeaufortKey,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliBaselineTarget {
    Anchors,
    Spans,
    All,
}

impl From<CliBaselineTarget> for BaselineTargetScope {
    fn from(value: CliBaselineTarget) -> Self {
        match value {
            CliBaselineTarget::Anchors => BaselineTargetScope::Anchors,
            CliBaselineTarget::Spans => BaselineTargetScope::Spans,
            CliBaselineTarget::All => BaselineTargetScope::All,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliBaselineAlphabet {
    Standard,
    Kryptos,
    KryptosReversed,
    All,
}

impl From<CliBaselineAlphabet> for BaselineAlphabetScope {
    fn from(value: CliBaselineAlphabet) -> Self {
        match value {
            CliBaselineAlphabet::Standard => BaselineAlphabetScope::Standard,
            CliBaselineAlphabet::Kryptos => BaselineAlphabetScope::Kryptos,
            CliBaselineAlphabet::KryptosReversed => BaselineAlphabetScope::KryptosReversed,
            CliBaselineAlphabet::All => BaselineAlphabetScope::All,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliCandidateTransform {
    #[value(name = "a1-z26-zero-based")]
    A1Z26ZeroBased,
    #[value(name = "a1-z26-one-based")]
    A1Z26OneBased,
    #[value(name = "decimal-digits")]
    DecimalDigits,
    #[value(name = "compass8-point")]
    Compass8Point,
    #[value(name = "compass16-point")]
    Compass16Point,
}

impl From<CliCandidateTransform> for CandidateTransform {
    fn from(value: CliCandidateTransform) -> Self {
        match value {
            CliCandidateTransform::A1Z26ZeroBased => CandidateTransform::A1Z26ZeroBased,
            CliCandidateTransform::A1Z26OneBased => CandidateTransform::A1Z26OneBased,
            CliCandidateTransform::DecimalDigits => CandidateTransform::DecimalDigits,
            CliCandidateTransform::Compass8Point => CandidateTransform::Compass8Point,
            CliCandidateTransform::Compass16Point => CandidateTransform::Compass16Point,
        }
    }
}

pub(crate) fn write_output_file_atomically(path: &Path, contents: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory `{}`", parent.display()))?;
    let file_name = path
        .file_name()
        .with_context(|| format!("output path `{}` has no file name", path.display()))?;
    let temp_path = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    fs::write(&temp_path, contents)
        .with_context(|| format!("failed to write temporary output `{}`", temp_path.display()))?;
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error)
            .with_context(|| format!("failed to replace output `{}`", path.display()));
    }
    Ok(())
}
