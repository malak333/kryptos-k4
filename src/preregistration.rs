use crate::{build_all_period_prediction_plans, build_all_spacing_prediction_plans, sources};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    SourceDocumentedEvidence,
    IndependentPredictionTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LanePreregistration {
    pub id: String,
    pub title: String,
    pub hypothesis_family: String,
    pub evidence_kind: EvidenceKind,
    pub source_ids: Vec<String>,
    pub rationale: String,
    pub prediction_target: String,
    #[serde(default)]
    pub prediction_artifact: Option<String>,
    pub discovery_inputs: Vec<String>,
    pub evaluation_inputs: Vec<String>,
    pub controls: Vec<String>,
    pub uses_public_anchor_fragments_for_discovery: bool,
    pub uses_public_anchor_fragments_as_primary_evidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreregistrationValidation {
    pub id: String,
    pub title: String,
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PredictionArtifactValidation {
    pub preregistration_id: String,
    pub artifact_kind: String,
    pub artifact_path: String,
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub expected_plan_count: usize,
    pub artifact_plan_count: Option<usize>,
    pub expected_period_count: usize,
    pub artifact_period_count: Option<usize>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndependentLaneStatusReport {
    pub directory: String,
    pub lane_count: usize,
    pub ready_for_source_backed_observations: usize,
    pub invalid_lanes: usize,
    pub prediction_artifacts: usize,
    pub unique_prediction_artifacts: usize,
    pub unique_ready_prediction_artifacts: usize,
    pub family_summaries: Vec<IndependentLaneFamilySummary>,
    pub duplicate_prediction_artifact_groups: Vec<DuplicatePredictionArtifactGroup>,
    pub lanes: Vec<IndependentLaneStatus>,
    pub promoted_candidate: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndependentLaneFamilySummary {
    pub hypothesis_family: String,
    pub lanes: usize,
    pub ready_for_source_backed_observations: usize,
    pub prediction_artifacts: usize,
    pub unique_prediction_artifacts: usize,
    pub unique_ready_prediction_artifacts: usize,
    pub duplicate_artifact_groups: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DuplicatePredictionArtifactGroup {
    pub artifact_paths: Vec<String>,
    pub lane_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndependentLaneStatus {
    pub path: String,
    pub id: Option<String>,
    pub title: Option<String>,
    pub hypothesis_family: Option<String>,
    pub evidence_kind: Option<EvidenceKind>,
    pub source_id_count: usize,
    pub prediction_artifact: Option<String>,
    pub preregistration_valid: bool,
    pub prediction_artifact_valid: Option<bool>,
    pub ready_for_source_backed_observations: bool,
    pub status: String,
    pub next_step: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub promoted_candidate: bool,
}

pub fn validate_preregistration(input: &str) -> Result<PreregistrationValidation> {
    let registration: LanePreregistration = serde_json::from_str(input)?;
    Ok(validate_registration(registration))
}

pub fn summarize_independent_lanes(directory: &Path) -> Result<IndependentLaneStatusReport> {
    summarize_independent_lanes_with_repo_root(directory, Path::new("."))
}

pub fn summarize_independent_lanes_with_repo_root(
    directory: &Path,
    repo_root: &Path,
) -> Result<IndependentLaneStatusReport> {
    let mut paths = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok())
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

    let lanes = paths
        .iter()
        .map(|path| summarize_independent_lane(path, repo_root))
        .collect::<Vec<_>>();
    let ready_for_source_backed_observations = lanes
        .iter()
        .filter(|lane| lane.ready_for_source_backed_observations)
        .count();
    let invalid_lanes = lanes
        .iter()
        .filter(|lane| !lane.preregistration_valid || lane.prediction_artifact_valid == Some(false))
        .count();
    let artifact_groups = prediction_artifact_groups(&lanes, repo_root);
    let prediction_artifacts = artifact_groups.values().map(Vec::len).sum::<usize>();
    let unique_prediction_artifacts = artifact_groups.len();
    let ready_lanes = lanes
        .iter()
        .filter(|lane| lane.ready_for_source_backed_observations)
        .cloned()
        .collect::<Vec<_>>();
    let unique_ready_prediction_artifacts =
        prediction_artifact_groups(&ready_lanes, repo_root).len();
    let family_summaries = independent_lane_family_summaries(&lanes, repo_root);
    let duplicate_prediction_artifact_groups = artifact_groups
        .into_values()
        .filter(|group| group.len() > 1)
        .map(|group| {
            let mut artifact_paths = group
                .iter()
                .map(|(_, artifact_path)| artifact_path.clone())
                .collect::<Vec<_>>();
            artifact_paths.sort();
            let mut lane_ids = group
                .iter()
                .map(|(lane_id, _)| lane_id.clone())
                .collect::<Vec<_>>();
            lane_ids.sort();
            DuplicatePredictionArtifactGroup {
                artifact_paths,
                lane_ids,
            }
        })
        .collect::<Vec<_>>();

    Ok(IndependentLaneStatusReport {
        directory: directory.display().to_string(),
        lane_count: lanes.len(),
        ready_for_source_backed_observations,
        invalid_lanes,
        prediction_artifacts,
        unique_prediction_artifacts,
        unique_ready_prediction_artifacts,
        family_summaries,
        duplicate_prediction_artifact_groups,
        lanes,
        promoted_candidate: false,
        note: "Independent lane status is an operational gate summary; it is not a claimed solution.",
    })
}

fn independent_lane_family_summaries(
    lanes: &[IndependentLaneStatus],
    repo_root: &Path,
) -> Vec<IndependentLaneFamilySummary> {
    let mut by_family: BTreeMap<String, Vec<IndependentLaneStatus>> = BTreeMap::new();
    for lane in lanes {
        by_family
            .entry(
                lane.hypothesis_family
                    .clone()
                    .unwrap_or_else(|| "unavailable".to_string()),
            )
            .or_default()
            .push(lane.clone());
    }

    by_family
        .into_iter()
        .map(|(hypothesis_family, family_lanes)| {
            let ready_lanes = family_lanes
                .iter()
                .filter(|lane| lane.ready_for_source_backed_observations)
                .cloned()
                .collect::<Vec<_>>();
            let artifact_groups = prediction_artifact_groups(&family_lanes, repo_root);
            let ready_artifact_groups = prediction_artifact_groups(&ready_lanes, repo_root);
            IndependentLaneFamilySummary {
                hypothesis_family,
                lanes: family_lanes.len(),
                ready_for_source_backed_observations: ready_lanes.len(),
                prediction_artifacts: artifact_groups.values().map(Vec::len).sum(),
                unique_prediction_artifacts: artifact_groups.len(),
                unique_ready_prediction_artifacts: ready_artifact_groups.len(),
                duplicate_artifact_groups: artifact_groups
                    .values()
                    .filter(|group| group.len() > 1)
                    .count(),
            }
        })
        .collect()
}

fn prediction_artifact_groups(
    lanes: &[IndependentLaneStatus],
    repo_root: &Path,
) -> BTreeMap<String, Vec<(String, String)>> {
    let mut groups = BTreeMap::new();
    for lane in lanes {
        let (Some(lane_id), Some(artifact_path)) = (&lane.id, &lane.prediction_artifact) else {
            continue;
        };
        let path = repo_root.join(artifact_path);
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        groups
            .entry(prediction_artifact_signature(&contents))
            .or_insert_with(Vec::new)
            .push((lane_id.clone(), artifact_path.clone()));
    }
    groups
}

fn prediction_artifact_signature(contents: &str) -> String {
    serde_json::from_str::<serde_json::Value>(contents)
        .and_then(|value| serde_json::to_string(&value))
        .unwrap_or_else(|_| contents.to_string())
}

fn summarize_independent_lane(path: &Path, repo_root: &Path) -> IndependentLaneStatus {
    let path_label = path.display().to_string();
    let input = match fs::read_to_string(path) {
        Ok(input) => input,
        Err(error) => {
            return IndependentLaneStatus {
                path: path_label,
                id: None,
                title: None,
                hypothesis_family: None,
                evidence_kind: None,
                source_id_count: 0,
                prediction_artifact: None,
                preregistration_valid: false,
                prediction_artifact_valid: None,
                ready_for_source_backed_observations: false,
                status: "unreadable-preregistration".to_string(),
                next_step: "Fix file readability before interpreting this lane.".to_string(),
                errors: vec![error.to_string()],
                warnings: Vec::new(),
                promoted_candidate: false,
            };
        }
    };
    let registration = serde_json::from_str::<LanePreregistration>(&input);
    let validation = validate_preregistration(&input);

    match (registration, validation) {
        (Ok(registration), Ok(validation)) => {
            let artifact_validation = if registration.prediction_artifact.is_some() {
                Some(validate_prediction_artifact_with_repo_root(path, repo_root))
            } else {
                None
            };
            let artifact_valid = artifact_validation
                .as_ref()
                .map(|result| result.as_ref().is_ok_and(|validation| validation.valid));
            let mut errors = validation.errors;
            let warnings = validation.warnings;
            if let Some(Err(error)) = artifact_validation {
                errors.push(error.to_string());
            }
            let ready = validation.valid && artifact_valid.unwrap_or(false);
            let (status, next_step) = lane_status_next_step(&registration, ready, artifact_valid);

            IndependentLaneStatus {
                path: path_label,
                id: Some(registration.id),
                title: Some(registration.title),
                hypothesis_family: Some(registration.hypothesis_family),
                evidence_kind: Some(registration.evidence_kind),
                source_id_count: registration.source_ids.len(),
                prediction_artifact: registration.prediction_artifact,
                preregistration_valid: validation.valid,
                prediction_artifact_valid: artifact_valid,
                ready_for_source_backed_observations: ready,
                status,
                next_step,
                errors,
                warnings,
                promoted_candidate: false,
            }
        }
        (Ok(registration), Err(error)) => IndependentLaneStatus {
            path: path_label,
            id: Some(registration.id),
            title: Some(registration.title),
            hypothesis_family: Some(registration.hypothesis_family),
            evidence_kind: Some(registration.evidence_kind),
            source_id_count: registration.source_ids.len(),
            prediction_artifact: registration.prediction_artifact,
            preregistration_valid: false,
            prediction_artifact_valid: None,
            ready_for_source_backed_observations: false,
            status: "invalid-preregistration".to_string(),
            next_step: "Fix preregistration JSON before adding observations or scoring."
                .to_string(),
            errors: vec![error.to_string()],
            warnings: Vec::new(),
            promoted_candidate: false,
        },
        (Err(error), _) => IndependentLaneStatus {
            path: path_label,
            id: None,
            title: None,
            hypothesis_family: None,
            evidence_kind: None,
            source_id_count: 0,
            prediction_artifact: None,
            preregistration_valid: false,
            prediction_artifact_valid: None,
            ready_for_source_backed_observations: false,
            status: "invalid-json".to_string(),
            next_step: "Fix preregistration JSON before adding observations or scoring."
                .to_string(),
            errors: vec![error.to_string()],
            warnings: Vec::new(),
            promoted_candidate: false,
        },
    }
}

fn lane_status_next_step(
    registration: &LanePreregistration,
    ready: bool,
    artifact_valid: Option<bool>,
) -> (String, String) {
    if !ready {
        if artifact_valid == Some(false) {
            return (
                "prediction-artifact-invalid".to_string(),
                "Regenerate or fix the committed prediction artifact before scoring observations."
                    .to_string(),
            );
        }
        if registration.prediction_artifact.is_none() {
            return (
                "awaiting-prediction-artifact".to_string(),
                "Declare and commit a deterministic prediction artifact before scoring observations."
                    .to_string(),
            );
        }
        return (
            "preregistration-invalid".to_string(),
            "Fix preregistration validation errors before adding observations or scoring."
                .to_string(),
        );
    }

    match registration.hypothesis_family.as_str() {
        "position-spacing-prediction" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-spacing-observations, then evaluate-spacing-prediction with --positions-file."
                .to_string(),
        ),
        "position-period-prediction" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-period-observations, then evaluate-period-prediction with --positions-file."
                .to_string(),
        ),
        _ => (
            "ready-needs-family-specific-evaluator".to_string(),
            "Add a family-specific observation validator/evaluator before scoring.".to_string(),
        ),
    }
}

fn validate_registration(registration: LanePreregistration) -> PreregistrationValidation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    require_non_empty("id", &registration.id, &mut errors);
    require_non_empty("title", &registration.title, &mut errors);
    require_non_empty(
        "hypothesis_family",
        &registration.hypothesis_family,
        &mut errors,
    );
    require_non_empty("rationale", &registration.rationale, &mut errors);
    require_non_empty(
        "prediction_target",
        &registration.prediction_target,
        &mut errors,
    );
    require_non_empty_vec(
        "discovery_inputs",
        &registration.discovery_inputs,
        &mut errors,
    );
    require_non_empty_vec(
        "evaluation_inputs",
        &registration.evaluation_inputs,
        &mut errors,
    );
    require_non_empty_vec("controls", &registration.controls, &mut errors);
    reject_placeholder("id", &registration.id, &mut errors);
    reject_placeholder("title", &registration.title, &mut errors);
    reject_placeholder(
        "hypothesis_family",
        &registration.hypothesis_family,
        &mut errors,
    );
    reject_placeholder("rationale", &registration.rationale, &mut errors);
    reject_placeholder(
        "prediction_target",
        &registration.prediction_target,
        &mut errors,
    );
    if let Some(prediction_artifact) = &registration.prediction_artifact {
        require_non_empty("prediction_artifact", prediction_artifact, &mut errors);
        reject_placeholder("prediction_artifact", prediction_artifact, &mut errors);
    }
    reject_placeholder_vec(
        "discovery_inputs",
        &registration.discovery_inputs,
        &mut errors,
    );
    reject_placeholder_vec(
        "evaluation_inputs",
        &registration.evaluation_inputs,
        &mut errors,
    );
    reject_placeholder_vec("controls", &registration.controls, &mut errors);

    if registration.uses_public_anchor_fragments_for_discovery {
        errors.push(
            "public anchor-derived fragments cannot be used as discovery inputs for a new lane"
                .to_string(),
        );
    }
    if registration.uses_public_anchor_fragments_as_primary_evidence {
        errors.push(
            "public anchor-derived fragments cannot be the primary evidence for a new lane"
                .to_string(),
        );
    }

    let registered_sources: HashSet<_> = sources().into_iter().map(|source| source.id).collect();
    match registration.evidence_kind {
        EvidenceKind::SourceDocumentedEvidence => {
            require_non_empty_vec("source_ids", &registration.source_ids, &mut errors);
            for source_id in &registration.source_ids {
                if !registered_sources.contains(source_id.as_str()) {
                    errors.push(format!(
                        "source id `{source_id}` is not registered in the source provenance list"
                    ));
                }
            }
        }
        EvidenceKind::IndependentPredictionTarget => {
            if registration.source_ids.is_empty() {
                warnings.push(
                    "no source IDs attached; acceptable only if the lane is a pure independent prediction target"
                        .to_string(),
                );
            }
        }
    }

    if registration
        .discovery_inputs
        .iter()
        .any(|input| mentions_public_anchor_fragments(input))
    {
        errors.push(
            "discovery_inputs mention public anchor fragments; move that material to controls or omit it"
                .to_string(),
        );
    }
    if registration
        .evaluation_inputs
        .iter()
        .all(|input| mentions_public_anchor_fragments(input))
    {
        errors.push(
            "evaluation_inputs must include at least one target that is not public anchor-derived fragments"
                .to_string(),
        );
    }

    PreregistrationValidation {
        id: registration.id,
        title: registration.title,
        valid: errors.is_empty(),
        errors,
        warnings,
        promoted_candidate: false,
        note: "Preregistration validation is a research-lane gate only; it is not a claimed solution.",
    }
}

fn require_non_empty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn require_non_empty_vec(field: &str, values: &[String], errors: &mut Vec<String>) {
    if values.iter().all(|value| value.trim().is_empty()) {
        errors.push(format!("{field} must include at least one non-empty value"));
    }
}

fn reject_placeholder(field: &str, value: &str, errors: &mut Vec<String>) {
    if contains_placeholder(value) {
        errors.push(format!(
            "{field} still contains template placeholder text; replace it before validation"
        ));
    }
}

fn reject_placeholder_vec(field: &str, values: &[String], errors: &mut Vec<String>) {
    for value in values {
        reject_placeholder(field, value, errors);
    }
}

fn contains_placeholder(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("replace-with")
        || normalized.contains("replace with")
        || normalized.contains("describe the")
        || normalized.contains("define the")
        || normalized.contains("explain why")
}

fn mentions_public_anchor_fragments(input: &str) -> bool {
    let normalized = input.to_ascii_lowercase();
    normalized.contains("public anchor")
        || normalized.contains("public-anchor")
        || normalized.contains("anchor-derived")
        || normalized.contains("known plaintext fragment")
        || normalized.contains("known-plaintext fragment")
}

pub fn load_and_validate_preregistration(path: &Path) -> Result<PreregistrationValidation> {
    let input = std::fs::read_to_string(path)?;
    validate_preregistration(&input)
}

pub fn validate_prediction_artifact(
    preregistration_path: &Path,
) -> Result<PredictionArtifactValidation> {
    validate_prediction_artifact_with_repo_root(preregistration_path, Path::new("."))
}

pub fn validate_prediction_artifact_with_repo_root(
    preregistration_path: &Path,
    repo_root: &Path,
) -> Result<PredictionArtifactValidation> {
    let input = std::fs::read_to_string(preregistration_path)?;
    let registration: LanePreregistration = serde_json::from_str(&input)?;
    let preregistration_validation = validate_preregistration(&input)?;
    let artifact_kind = prediction_artifact_kind(&registration);
    let artifact_kind_label = artifact_kind.unwrap_or("unsupported");
    let expected_value = match artifact_kind {
        Some("spacing") => Some(serde_json::to_value(build_all_spacing_prediction_plans()?)?),
        Some("period") => Some(serde_json::to_value(build_all_period_prediction_plans()?)?),
        _ => None,
    };
    let expected_plan_count = expected_value
        .as_ref()
        .and_then(|expected_value| expected_value.get("plans"))
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let expected_period_count = expected_value
        .as_ref()
        .and_then(plan_set_count)
        .unwrap_or(0);
    let mut errors = preregistration_validation.errors;
    let warnings = preregistration_validation.warnings;

    if artifact_kind.is_none() {
        errors.push(format!(
            "prediction_artifact validation only supports `position-period-prediction` and `position-spacing-prediction` hypothesis families; got `{}`",
            registration.hypothesis_family
        ));
    }

    let artifact_path = registration.prediction_artifact.clone().unwrap_or_default();
    let mut artifact_plan_count = None;
    let mut artifact_period_count = None;
    if artifact_path.trim().is_empty() {
        errors.push("preregistration does not declare prediction_artifact".to_string());
    } else {
        let resolved_artifact_path = resolve_repo_relative_path(repo_root, &artifact_path);
        match std::fs::read_to_string(&resolved_artifact_path) {
            Ok(artifact) => match serde_json::from_str::<serde_json::Value>(&artifact) {
                Ok(artifact_value) => {
                    artifact_plan_count = artifact_value
                        .get("plans")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len);
                    artifact_period_count = plan_set_count(&artifact_value);
                    if let Some(expected_value) = &expected_value
                        && artifact_value != *expected_value
                    {
                        errors.push(format!(
                            "prediction artifact does not match deterministic {artifact_kind_label} prediction plan output"
                        ));
                    }
                }
                Err(error) => {
                    errors.push(format!("prediction_artifact is not valid JSON: {error}"));
                }
            },
            Err(error) => {
                errors.push(format!("prediction_artifact could not be read: {error}"));
            }
        }
    }

    Ok(PredictionArtifactValidation {
        preregistration_id: registration.id,
        artifact_kind: artifact_kind_label.to_string(),
        artifact_path,
        valid: errors.is_empty(),
        errors,
        warnings,
        expected_plan_count,
        artifact_plan_count,
        expected_period_count,
        artifact_period_count,
        promoted_candidate: false,
        note: "Prediction artifact validation checks a committed independent target against its preregistration and deterministic generator; it is not a claimed solution.",
    })
}

fn prediction_artifact_kind(registration: &LanePreregistration) -> Option<&'static str> {
    match registration.hypothesis_family.as_str() {
        "position-spacing-prediction" => Some("spacing"),
        "position-period-prediction" => Some("period"),
        _ => None,
    }
}

fn plan_set_count(value: &serde_json::Value) -> Option<usize> {
    value
        .get("period_count")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            value
                .get("modulus_count")
                .and_then(serde_json::Value::as_u64)
        })
        .map(|value| value as usize)
}

fn resolve_repo_relative_path(repo_root: &Path, path: &str) -> std::path::PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    }
}

pub fn validation_exit_result(validation: &PreregistrationValidation) -> Result<()> {
    if validation.valid {
        Ok(())
    } else {
        bail!("preregistration failed validation")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn valid_registration() -> LanePreregistration {
        LanePreregistration {
            id: "independent-target-v1".to_string(),
            title: "Independent prediction target".to_string(),
            hypothesis_family: "structural-routing".to_string(),
            evidence_kind: EvidenceKind::IndependentPredictionTarget,
            source_ids: vec![],
            rationale: "Tests a prediction target before any key-material expansion.".to_string(),
            prediction_target:
                "Predict a non-anchor position class before comparing anchor fragments.".to_string(),
            prediction_artifact: None,
            discovery_inputs: vec!["registered structural model".to_string()],
            evaluation_inputs: vec!["withheld non-anchor prediction target".to_string()],
            controls: vec!["seeded shuffle baseline".to_string()],
            uses_public_anchor_fragments_for_discovery: false,
            uses_public_anchor_fragments_as_primary_evidence: false,
        }
    }

    #[test]
    fn accepts_independent_prediction_target_without_source_ids() {
        let validation = validate_registration(valid_registration());

        assert!(validation.valid);
        assert!(!validation.promoted_candidate);
        assert_eq!(validation.warnings.len(), 1);
    }

    #[test]
    fn rejects_reused_public_anchor_fragments_as_evidence() {
        let mut registration = valid_registration();
        registration.uses_public_anchor_fragments_for_discovery = true;
        registration.uses_public_anchor_fragments_as_primary_evidence = true;
        registration.discovery_inputs = vec!["public anchor-derived fragments".to_string()];
        registration.evaluation_inputs = vec!["public anchor fragments".to_string()];

        let validation = validate_registration(registration);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("cannot be used as discovery inputs"))
        );
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("cannot be the primary evidence"))
        );
    }

    #[test]
    fn rejects_unknown_source_ids_for_source_documented_lanes() {
        let mut registration = valid_registration();
        registration.evidence_kind = EvidenceKind::SourceDocumentedEvidence;
        registration.source_ids = vec!["unknown-source".to_string()];

        let validation = validate_registration(registration);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("not registered"))
        );
    }

    #[test]
    fn rejects_template_placeholders() {
        let mut registration = valid_registration();
        registration.id = "replace-with-lane-id".to_string();
        registration.discovery_inputs = vec![
            "Describe the non-anchor discovery input or pre-declared structural rule.".to_string(),
        ];

        let validation = validate_registration(registration);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("placeholder text"))
        );
    }

    #[test]
    fn prediction_artifact_kind_prefers_hypothesis_family_over_path() {
        let temp = TempDir::new().unwrap();
        let artifact_path = "experiments/predictions/non-anchor-position-spacing-v1.json";
        let absolute_artifact_path = temp.path().join(artifact_path);
        std::fs::create_dir_all(absolute_artifact_path.parent().unwrap()).unwrap();
        std::fs::write(
            &absolute_artifact_path,
            serde_json::to_string_pretty(&build_all_spacing_prediction_plans().unwrap()).unwrap(),
        )
        .unwrap();

        let mut registration = valid_registration();
        registration.id = "period-family-spacing-path-v1".to_string();
        registration.hypothesis_family = "position-period-prediction".to_string();
        registration.prediction_artifact = Some(artifact_path.to_string());
        let preregistration_path = temp.path().join("period-family-spacing-path-v1.json");
        std::fs::write(
            &preregistration_path,
            serde_json::to_string_pretty(&registration).unwrap(),
        )
        .unwrap();

        let validation =
            validate_prediction_artifact_with_repo_root(&preregistration_path, temp.path())
                .unwrap();

        assert_eq!(validation.artifact_kind, "period");
        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|error| {
            error.contains("prediction artifact does not match deterministic period")
        }));
    }

    #[test]
    fn prediction_artifact_validation_rejects_unsupported_artifact_family() {
        let temp = TempDir::new().unwrap();
        let artifact_path = "experiments/predictions/structural-routing-v1.json";
        let absolute_artifact_path = temp.path().join(artifact_path);
        std::fs::create_dir_all(absolute_artifact_path.parent().unwrap()).unwrap();
        std::fs::write(
            &absolute_artifact_path,
            serde_json::to_string_pretty(&build_all_period_prediction_plans().unwrap()).unwrap(),
        )
        .unwrap();

        let mut registration = valid_registration();
        registration.id = "structural-routing-artifact-v1".to_string();
        registration.prediction_artifact = Some(artifact_path.to_string());
        let preregistration_path = temp.path().join("structural-routing-artifact-v1.json");
        std::fs::write(
            &preregistration_path,
            serde_json::to_string_pretty(&registration).unwrap(),
        )
        .unwrap();

        let validation =
            validate_prediction_artifact_with_repo_root(&preregistration_path, temp.path())
                .unwrap();

        assert_eq!(validation.artifact_kind, "unsupported");
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| { error.contains("only supports `position-period-prediction`") })
        );
    }

    #[test]
    fn independent_lane_status_groups_json_equivalent_prediction_artifacts() {
        let temp = TempDir::new().unwrap();
        let preregistration_dir = temp.path().join("experiments/preregistrations");
        let prediction_dir = temp.path().join("experiments/predictions");
        std::fs::create_dir_all(&preregistration_dir).unwrap();
        std::fs::create_dir_all(&prediction_dir).unwrap();
        std::fs::write(
            prediction_dir.join("artifact-a.json"),
            r#"{"a":1,"b":[2,3]}"#,
        )
        .unwrap();
        std::fs::write(
            prediction_dir.join("artifact-b.json"),
            "{\n  \"a\": 1,\n  \"b\": [\n    2,\n    3\n  ]\n}\n",
        )
        .unwrap();

        for (id, artifact) in [
            ("canonical-artifact-a", "artifact-a.json"),
            ("canonical-artifact-b", "artifact-b.json"),
        ] {
            let mut registration = valid_registration();
            registration.id = id.to_string();
            registration.prediction_artifact = Some(format!("experiments/predictions/{artifact}"));
            std::fs::write(
                preregistration_dir.join(format!("{id}.json")),
                serde_json::to_string_pretty(&registration).unwrap(),
            )
            .unwrap();
        }

        let report =
            summarize_independent_lanes_with_repo_root(&preregistration_dir, temp.path()).unwrap();

        assert_eq!(report.prediction_artifacts, 2);
        assert_eq!(report.unique_prediction_artifacts, 1);
        assert_eq!(report.unique_ready_prediction_artifacts, 0);
        assert_eq!(report.family_summaries.len(), 1);
        assert_eq!(
            report.family_summaries[0].hypothesis_family,
            "structural-routing"
        );
        assert_eq!(report.family_summaries[0].lanes, 2);
        assert_eq!(report.family_summaries[0].prediction_artifacts, 2);
        assert_eq!(report.family_summaries[0].unique_prediction_artifacts, 1);
        assert_eq!(
            report.family_summaries[0].unique_ready_prediction_artifacts,
            0
        );
        assert_eq!(report.family_summaries[0].duplicate_artifact_groups, 1);
        assert_eq!(report.duplicate_prediction_artifact_groups.len(), 1);
        assert_eq!(
            report.duplicate_prediction_artifact_groups[0].lane_ids,
            vec![
                "canonical-artifact-a".to_string(),
                "canonical-artifact-b".to_string()
            ]
        );
    }
}
