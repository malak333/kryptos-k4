use crate::{build_all_period_prediction_plans, build_all_spacing_prediction_plans, sources};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

pub fn validate_preregistration(input: &str) -> Result<PreregistrationValidation> {
    let registration: LanePreregistration = serde_json::from_str(input)?;
    Ok(validate_registration(registration))
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
}
