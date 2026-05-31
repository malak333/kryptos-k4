use crate::{
    CiphertextResidueBalancePrior, GridLayoutEdgeAxis, PeriodPredictionPlanSet,
    build_all_period_prediction_plans, build_all_spacing_prediction_plans,
    build_ciphertext_residue_balance_prior, build_ciphertext_window_balance_prior,
    build_committed_ciphertext_adjacent_contrast_prior, build_committed_ciphertext_hotspot_prior,
    build_committed_ciphertext_period_match_prior, build_committed_ciphertext_rarity_prior,
    build_committed_ciphertext_repeat_distance_prior,
    build_committed_ciphertext_residue_balance_prior,
    build_committed_ciphertext_skip_transition_prior,
    build_committed_ciphertext_stehle_regularity_prior, build_committed_ciphertext_structure_prior,
    build_committed_ciphertext_transition_prior, build_committed_ciphertext_turning_point_prior,
    build_grid_layout_prediction_plan_for_axis, build_mirror_prediction_plan,
    build_period_prediction_plan, sources,
};
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
    #[serde(default)]
    pub grid_edge_axis: Option<GridLayoutEdgeAxis>,
    #[serde(default)]
    pub ciphertext_window_balance_top: Option<usize>,
    #[serde(default)]
    pub ciphertext_window_balance_widths: Option<Vec<usize>>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub duplicate_artifact_paths: Vec<String>,
    pub expected_plan_count: usize,
    pub artifact_plan_count: Option<usize>,
    pub expected_period_count: usize,
    pub artifact_period_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_grid_edge_axis: Option<String>,
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
    pub duplicate_prediction_artifact_lane_count: usize,
    pub duplicate_prediction_artifact_extra_lane_count: usize,
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
    let duplicate_prediction_artifact_lane_count = duplicate_prediction_artifact_groups
        .iter()
        .map(|group| group.lane_ids.len())
        .sum::<usize>();
    let duplicate_prediction_artifact_extra_lane_count = duplicate_prediction_artifact_groups
        .iter()
        .map(|group| group.lane_ids.len().saturating_sub(1))
        .sum::<usize>();

    Ok(IndependentLaneStatusReport {
        directory: directory.display().to_string(),
        lane_count: lanes.len(),
        ready_for_source_backed_observations,
        invalid_lanes,
        prediction_artifacts,
        unique_prediction_artifacts,
        unique_ready_prediction_artifacts,
        duplicate_prediction_artifact_lane_count,
        duplicate_prediction_artifact_extra_lane_count,
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
    let validation = load_and_validate_preregistration(path);

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
            let family_has_evaluator =
                has_family_specific_evaluator(&registration.hypothesis_family);
            let ready = validation.valid && artifact_valid.unwrap_or(false) && family_has_evaluator;
            let (status, next_step) = lane_status_next_step(
                &registration,
                validation.valid,
                ready,
                artifact_valid,
                family_has_evaluator,
            );

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
    preregistration_valid: bool,
    ready: bool,
    artifact_valid: Option<bool>,
    family_has_evaluator: bool,
) -> (String, String) {
    if !ready {
        if !preregistration_valid {
            return (
                "preregistration-invalid".to_string(),
                "Fix preregistration validation errors before adding observations or scoring."
                    .to_string(),
            );
        }
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
        if !family_has_evaluator {
            return (
                "evaluator-pending".to_string(),
                "Add a family-specific observation validator/evaluator before scoring.".to_string(),
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
        "position-mirror-prediction" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-mirror-observations, then evaluate-mirror-prediction with --positions-file."
                .to_string(),
        ),
        "position-grid-layout-prediction" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-grid-observations, then evaluate-grid-prediction with --positions-file."
                .to_string(),
        ),
        "tableau-hill-prediction" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-tableau-hill-observations, then evaluate-tableau-hill-prediction with --positions-file."
                .to_string(),
        ),
        "ciphertext-only-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-prior-observations for the source-backed positions, then evaluate-ciphertext-prior with --positions-file."
                .to_string(),
        ),
        "ciphertext-residue-balance-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-residue-balance-observations for the source-backed positions, then evaluate-ciphertext-residue-balance with --positions-file."
                .to_string(),
        ),
        "ciphertext-hotspot-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-hotspot-observations for the source-backed positions, then evaluate-ciphertext-hotspot with --positions-file."
                .to_string(),
        ),
        "ciphertext-rarity-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-rarity-observations for the source-backed positions, then evaluate-ciphertext-rarity with --positions-file."
                .to_string(),
        ),
        "ciphertext-repeat-distance-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-repeat-distance-observations for the source-backed positions, then evaluate-ciphertext-repeat-distance with --positions-file."
                .to_string(),
        ),
        "ciphertext-adjacent-contrast-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-adjacent-contrast-observations for the source-backed positions, then evaluate-ciphertext-adjacent-contrast with --positions-file."
                .to_string(),
        ),
        "ciphertext-transition-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-transition-observations for the source-backed positions, then evaluate-ciphertext-transition with --positions-file."
                .to_string(),
        ),
        "ciphertext-skip-transition-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-skip-transition-observations for the source-backed positions, then evaluate-ciphertext-skip-transition with --positions-file."
                .to_string(),
        ),
        "ciphertext-turning-point-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-turning-point-observations for the source-backed positions, then evaluate-ciphertext-turning-point with --positions-file."
                .to_string(),
        ),
        "ciphertext-window-balance-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-window-balance-observations for the source-backed positions, then evaluate-ciphertext-window-balance with --positions-file."
                .to_string(),
        ),
        "ciphertext-period-match-position-prior" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-ciphertext-period-match-observations for the source-backed positions, then evaluate-ciphertext-period-match with --positions-file."
                .to_string(),
        ),
        "position-period-prediction" => (
            "ready-for-source-backed-observations".to_string(),
            "Run validate-period-observations, then evaluate-period-prediction with --positions-file."
                .to_string(),
        ),
        _ => (
            "evaluator-pending".to_string(),
            "Add a family-specific observation validator/evaluator before scoring.".to_string(),
        ),
    }
}

fn has_family_specific_evaluator(hypothesis_family: &str) -> bool {
    matches!(
        hypothesis_family,
        "position-spacing-prediction"
            | "position-mirror-prediction"
            | "position-grid-layout-prediction"
            | "tableau-hill-prediction"
            | "ciphertext-only-position-prior"
            | "ciphertext-residue-balance-position-prior"
            | "ciphertext-hotspot-position-prior"
            | "ciphertext-rarity-position-prior"
            | "ciphertext-repeat-distance-position-prior"
            | "ciphertext-adjacent-contrast-position-prior"
            | "ciphertext-transition-position-prior"
            | "ciphertext-skip-transition-position-prior"
            | "ciphertext-turning-point-position-prior"
            | "ciphertext-window-balance-position-prior"
            | "ciphertext-period-match-position-prior"
            | "position-period-prediction"
    )
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
    if registration.hypothesis_family == "position-grid-layout-prediction"
        && registration.grid_edge_axis.is_none()
    {
        errors.push(
            "position-grid-layout-prediction lanes must declare grid_edge_axis so row, column, and compass-axis targets cannot be mixed post hoc"
                .to_string(),
        );
    }
    if registration.hypothesis_family != "position-grid-layout-prediction"
        && registration.grid_edge_axis.is_some()
    {
        errors.push(
            "grid_edge_axis is only valid for position-grid-layout-prediction lanes".to_string(),
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
    let mut validation = validate_preregistration(&input)?;
    validate_preregistration_filename(path, &mut validation);
    Ok(validation)
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
    let mut preregistration_validation = validate_preregistration(&input)?;
    validate_preregistration_filename(preregistration_path, &mut preregistration_validation);
    let artifact_kind = prediction_artifact_kind(&registration);
    let artifact_kind_label = artifact_kind.unwrap_or("unsupported");
    let expected_value = match artifact_kind {
        Some("spacing") => Some(serde_json::to_value(build_all_spacing_prediction_plans()?)?),
        Some("period") => Some(serde_json::to_value(build_all_period_prediction_plans()?)?),
        Some("mirror") => Some(serde_json::to_value(build_mirror_prediction_plan()?)?),
        Some("grid") => {
            let edge_axis = registration
                .grid_edge_axis
                .unwrap_or(GridLayoutEdgeAxis::Row);
            Some(serde_json::to_value(
                build_grid_layout_prediction_plan_for_axis(edge_axis)?,
            )?)
        }
        Some("tableau-hill") => Some(serde_json::to_value(
            crate::position_structure::build_tableau_hill_prediction_plan(),
        )?),
        Some("ciphertext-prior") => Some(serde_json::to_value(
            build_committed_ciphertext_structure_prior(),
        )?),
        Some("ciphertext-hotspot") => Some(serde_json::to_value(
            build_committed_ciphertext_hotspot_prior(),
        )?),
        Some("ciphertext-residue-balance") => Some(serde_json::to_value(
            build_committed_ciphertext_residue_balance_prior(),
        )?),
        Some("ciphertext-rarity") => Some(serde_json::to_value(
            build_committed_ciphertext_rarity_prior(),
        )?),
        Some("ciphertext-adjacent-contrast") => Some(serde_json::to_value(
            build_committed_ciphertext_adjacent_contrast_prior(),
        )?),
        Some("ciphertext-repeat-distance") => Some(serde_json::to_value(
            build_committed_ciphertext_repeat_distance_prior(),
        )?),
        Some("ciphertext-transition") => Some(serde_json::to_value(
            build_committed_ciphertext_transition_prior(),
        )?),
        Some("ciphertext-skip-transition") => Some(serde_json::to_value(
            build_committed_ciphertext_skip_transition_prior(),
        )?),
        Some("ciphertext-turning-point") => Some(serde_json::to_value(
            build_committed_ciphertext_turning_point_prior(),
        )?),
        Some("ciphertext-period-match") => Some(serde_json::to_value(
            build_committed_ciphertext_period_match_prior(),
        )?),
        Some("ciphertext-stehle-regularity") => Some(serde_json::to_value(
            build_committed_ciphertext_stehle_regularity_prior(),
        )?),
        Some("ciphertext-window-balance") => {
            let top = registration.ciphertext_window_balance_top.unwrap_or(20);
            let window_widths = registration
                .ciphertext_window_balance_widths
                .clone()
                .unwrap_or_else(|| vec![3, 5, 7]);
            Some(serde_json::to_value(
                build_ciphertext_window_balance_prior(top, window_widths),
            )?)
        }
        _ => None,
    };
    let mut expected_plan_count = expected_value
        .as_ref()
        .and_then(prediction_artifact_item_count)
        .unwrap_or(0);
    let mut expected_period_count = expected_value
        .as_ref()
        .and_then(plan_set_count)
        .unwrap_or(0);
    let mut errors = preregistration_validation.errors;
    let mut warnings = preregistration_validation.warnings;

    if artifact_kind.is_none() {
        errors.push(format!(
            "prediction_artifact validation only supports `position-period-prediction`, `position-spacing-prediction`, `position-mirror-prediction`, `position-grid-layout-prediction`, `tableau-hill-prediction`, `ciphertext-only-position-prior`, `ciphertext-residue-balance-position-prior`, `ciphertext-hotspot-position-prior`, `ciphertext-rarity-position-prior`, `ciphertext-adjacent-contrast-position-prior`, `ciphertext-repeat-distance-position-prior`, `ciphertext-transition-position-prior`, `ciphertext-skip-transition-position-prior`, `ciphertext-turning-point-position-prior`, `ciphertext-period-match-position-prior`, `ciphertext-stehle-regularity-position-prior`, and `ciphertext-window-balance-position-prior` hypothesis families; got `{}`",
            registration.hypothesis_family
        ));
    }

    let artifact_path = registration.prediction_artifact.clone().unwrap_or_default();
    let registered_grid_edge_axis = registration
        .grid_edge_axis
        .map(|axis| axis.label().to_string());
    let mut artifact_plan_count = None;
    let mut artifact_period_count = None;
    let mut duplicate_artifact_paths = Vec::new();
    if artifact_path.trim().is_empty() {
        errors.push("preregistration does not declare prediction_artifact".to_string());
    } else {
        let resolved_artifact_path = resolve_repo_relative_path(repo_root, &artifact_path);
        match std::fs::read_to_string(&resolved_artifact_path) {
            Ok(artifact) => match serde_json::from_str::<serde_json::Value>(&artifact) {
                Ok(artifact_value) => {
                    artifact_plan_count = prediction_artifact_item_count(&artifact_value);
                    artifact_period_count = plan_set_count(&artifact_value);
                    let artifact_matches_expected = match artifact_kind {
                        Some("ciphertext-residue-balance") => {
                            ciphertext_residue_balance_artifact_matches_deterministic(
                                &artifact_value,
                            )
                        }
                        _ => expected_value.as_ref().is_none_or(|expected_value| {
                            prediction_artifact_matches(
                                artifact_kind,
                                &artifact_value,
                                expected_value,
                            )
                        }),
                    };
                    if !artifact_matches_expected {
                        errors.push(format!(
                            "prediction artifact does not match deterministic {artifact_kind_label} prediction plan output"
                        ));
                    } else if artifact_kind == Some("ciphertext-residue-balance") {
                        expected_plan_count = artifact_plan_count.unwrap_or(0);
                        expected_period_count = artifact_period_count.unwrap_or(0);
                    }
                    let duplicate_artifacts = duplicate_prediction_artifact_paths(
                        preregistration_path,
                        repo_root,
                        &artifact_path,
                        &artifact_value,
                    );
                    if !duplicate_artifacts.is_empty() {
                        duplicate_artifact_paths = duplicate_artifacts.clone();
                        warnings.push(format!(
                            "prediction artifact duplicates {} other committed artifact(s): {}; duplicate readiness lanes are inventory only, not independent evidence",
                            duplicate_artifacts.len(),
                            duplicate_artifacts.join(", ")
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
        duplicate_artifact_paths,
        expected_plan_count,
        artifact_plan_count,
        expected_period_count,
        artifact_period_count,
        registered_grid_edge_axis,
        promoted_candidate: false,
        note: "Prediction artifact validation checks a committed independent target against its preregistration and deterministic generator; it is not a claimed solution.",
    })
}

fn prediction_artifact_matches(
    artifact_kind: Option<&str>,
    artifact_value: &serde_json::Value,
    expected_value: &serde_json::Value,
) -> bool {
    if artifact_kind == Some("period") {
        return period_prediction_artifacts_match(artifact_value, expected_value);
    }
    json_values_match(artifact_value, expected_value)
}

fn period_prediction_artifacts_match(
    artifact_value: &serde_json::Value,
    expected_value: &serde_json::Value,
) -> bool {
    if json_values_match(artifact_value, expected_value) {
        return true;
    }

    let Ok(artifact) = serde_json::from_value::<PeriodPredictionPlanSet>(artifact_value.clone())
    else {
        return false;
    };
    if artifact.period_count != artifact.plans.len() {
        return false;
    }
    artifact.plans.iter().all(|plan| {
        build_period_prediction_plan(plan.period)
            .map(|expected_plan| &expected_plan == plan)
            .unwrap_or(false)
    })
}

fn ciphertext_residue_balance_artifacts_match(
    left: &CiphertextResidueBalancePrior,
    right: &CiphertextResidueBalancePrior,
) -> bool {
    left.artifact_kind == right.artifact_kind
        && left.hypothesis_family == right.hypothesis_family
        && left.source_inputs == right.source_inputs
        && left.discovery_inputs == right.discovery_inputs
        && left.prediction_target == right.prediction_target
        && left.non_anchor_position_count == right.non_anchor_position_count
        && left.non_anchor_positions_one_based == right.non_anchor_positions_one_based
        && left.selected_moduli_count == right.selected_moduli_count
        && left.controls == right.controls
        && left.public_anchor_fragments_used_for_discovery
            == right.public_anchor_fragments_used_for_discovery
        && left.public_anchor_fragments_used_as_primary_evidence
            == right.public_anchor_fragments_used_as_primary_evidence
        && left.promoted_candidate == right.promoted_candidate
        && left.note == right.note
        && left.selected_residue_sets.len() == right.selected_residue_sets.len()
        && left
            .selected_residue_sets
            .iter()
            .zip(&right.selected_residue_sets)
            .all(|(left, right)| {
                left.modulus == right.modulus
                    && left.residue == right.residue
                    && left.position_count == right.position_count
                    && left.distinct_ciphertext_letters == right.distinct_ciphertext_letters
                    && (left.distinct_letter_rate - right.distinct_letter_rate).abs() < f64::EPSILON
                    && left.positions_one_based == right.positions_one_based
            })
}

fn ciphertext_residue_balance_artifact_matches_deterministic(
    artifact_value: &serde_json::Value,
) -> bool {
    let Ok(artifact) =
        serde_json::from_value::<CiphertextResidueBalancePrior>(artifact_value.clone())
    else {
        return false;
    };
    let Some(first) = artifact.selected_residue_sets.first() else {
        return false;
    };
    let Some(last) = artifact.selected_residue_sets.last() else {
        return false;
    };
    let min_modulus = first.modulus;
    let max_modulus = last.modulus;
    if min_modulus > max_modulus
        || artifact.selected_moduli_count != artifact.selected_residue_sets.len()
        || artifact.selected_residue_sets.len() != max_modulus - min_modulus + 1
        || artifact
            .selected_residue_sets
            .iter()
            .enumerate()
            .any(|(index, residue_set)| residue_set.modulus != min_modulus + index)
    {
        return false;
    }
    let expected = build_ciphertext_residue_balance_prior(min_modulus, max_modulus);
    ciphertext_residue_balance_artifacts_match(&artifact, &expected)
}

fn json_values_match(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    left == right
        || serde_json::to_string(left).ok().as_deref()
            == serde_json::to_string(right).ok().as_deref()
}

fn validate_preregistration_filename(path: &Path, validation: &mut PreregistrationValidation) {
    let Some(file_stem) = path.file_stem().and_then(|name| name.to_str()) else {
        return;
    };
    if file_stem != validation.id {
        validation.errors.push(format!(
            "filename must match preregistration id `{}`",
            validation.id
        ));
        validation.valid = false;
    }
}

fn prediction_artifact_kind(registration: &LanePreregistration) -> Option<&'static str> {
    match registration.hypothesis_family.as_str() {
        "position-spacing-prediction" => Some("spacing"),
        "position-period-prediction" => Some("period"),
        "position-mirror-prediction" => Some("mirror"),
        "position-grid-layout-prediction" => Some("grid"),
        "tableau-hill-prediction" => Some("tableau-hill"),
        "ciphertext-only-position-prior" => Some("ciphertext-prior"),
        "ciphertext-residue-balance-position-prior" => Some("ciphertext-residue-balance"),
        "ciphertext-hotspot-position-prior" => Some("ciphertext-hotspot"),
        "ciphertext-rarity-position-prior" => Some("ciphertext-rarity"),
        "ciphertext-adjacent-contrast-position-prior" => Some("ciphertext-adjacent-contrast"),
        "ciphertext-repeat-distance-position-prior" => Some("ciphertext-repeat-distance"),
        "ciphertext-transition-position-prior" => Some("ciphertext-transition"),
        "ciphertext-skip-transition-position-prior" => Some("ciphertext-skip-transition"),
        "ciphertext-turning-point-position-prior" => Some("ciphertext-turning-point"),
        "ciphertext-period-match-position-prior" => Some("ciphertext-period-match"),
        "ciphertext-stehle-regularity-position-prior" => Some("ciphertext-stehle-regularity"),
        "ciphertext-window-balance-position-prior" => Some("ciphertext-window-balance"),
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
        .or_else(|| value.get("pair_count").and_then(serde_json::Value::as_u64))
        .or_else(|| value.get("row_count").and_then(serde_json::Value::as_u64))
        .or_else(|| {
            value
                .get("selected_periods")
                .and_then(serde_json::Value::as_array)
                .map(|periods| periods.len() as u64)
        })
        .or_else(|| {
            value
                .get("hotspot_count")
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            value
                .get("selected_moduli_count")
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            value
                .get("repeat_distance_position_count")
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            value
                .get("period_match_set_count")
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            value
                .get("window_balance_position_count")
                .and_then(serde_json::Value::as_u64)
        })
        .map(|value| value as usize)
}

fn prediction_artifact_item_count(value: &serde_json::Value) -> Option<usize> {
    value
        .get("plans")
        .and_then(serde_json::Value::as_array)
        .or_else(|| value.get("rows").and_then(serde_json::Value::as_array))
        .or_else(|| {
            value
                .get("selected_periods")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| value.get("hotspots").and_then(serde_json::Value::as_array))
        .or_else(|| {
            value
                .get("rare_positions")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("transition_positions")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("contrast_positions")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("skip_transition_positions")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("turning_point_positions")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("repeat_distance_positions")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("period_match_sets")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("selected_residue_sets")
                .and_then(serde_json::Value::as_array)
        })
        .or_else(|| {
            value
                .get("window_balance_positions")
                .and_then(serde_json::Value::as_array)
        })
        .map(Vec::len)
}

fn duplicate_prediction_artifact_paths(
    preregistration_path: &Path,
    repo_root: &Path,
    artifact_path: &str,
    artifact_value: &serde_json::Value,
) -> Vec<String> {
    let preregistration_dir = preregistration_path
        .parent()
        .unwrap_or_else(|| Path::new("experiments/preregistrations"));
    let current_artifact_path = resolve_repo_relative_path(repo_root, artifact_path);
    let current_preregistration_path = if preregistration_path.is_absolute() {
        preregistration_path.to_path_buf()
    } else {
        repo_root.join(preregistration_path)
    };
    let mut duplicates = Vec::new();

    let Ok(entries) = fs::read_dir(preregistration_dir) else {
        return duplicates;
    };

    for entry in entries.flatten() {
        let other_preregistration_path = entry.path();
        if other_preregistration_path
            .extension()
            .and_then(|value| value.to_str())
            != Some("json")
        {
            continue;
        }
        if other_preregistration_path
            .file_name()
            .and_then(|value| value.to_str())
            == Some("independent-lane-template.json")
        {
            continue;
        }
        if paths_match(&other_preregistration_path, &current_preregistration_path) {
            continue;
        }

        let Ok(other_input) = fs::read_to_string(&other_preregistration_path) else {
            continue;
        };
        let Ok(other_registration) = serde_json::from_str::<LanePreregistration>(&other_input)
        else {
            continue;
        };
        let Some(other_artifact_path) = other_registration.prediction_artifact else {
            continue;
        };
        let resolved_other_artifact_path =
            resolve_repo_relative_path(repo_root, &other_artifact_path);
        if paths_match(&resolved_other_artifact_path, &current_artifact_path) {
            continue;
        }
        let Ok(other_artifact) = fs::read_to_string(&resolved_other_artifact_path) else {
            continue;
        };
        let Ok(other_value) = serde_json::from_str::<serde_json::Value>(&other_artifact) else {
            continue;
        };
        if other_value == *artifact_value {
            duplicates.push(other_artifact_path);
        }
    }

    duplicates.sort();
    duplicates.dedup();
    duplicates
}

fn paths_match(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
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
            grid_edge_axis: None,
            ciphertext_window_balance_top: None,
            ciphertext_window_balance_widths: None,
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
    fn grid_preregistration_requires_registered_edge_axis() {
        let mut registration = valid_registration();
        registration.hypothesis_family = "position-grid-layout-prediction".to_string();
        registration.prediction_artifact =
            Some("experiments/predictions/non-anchor-position-grid-layout-v1.json".to_string());

        let validation = validate_registration(registration);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| { error.contains("must declare grid_edge_axis") })
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
    fn prediction_artifact_validation_warns_on_duplicate_artifact_content() {
        let temp = TempDir::new().unwrap();
        let preregistration_dir = temp.path().join("experiments/preregistrations");
        let prediction_dir = temp.path().join("experiments/predictions");
        std::fs::create_dir_all(&preregistration_dir).unwrap();
        std::fs::create_dir_all(&prediction_dir).unwrap();
        let artifact =
            serde_json::to_string_pretty(&build_all_period_prediction_plans().unwrap()).unwrap();
        std::fs::write(prediction_dir.join("period-a.json"), &artifact).unwrap();
        std::fs::write(prediction_dir.join("period-b.json"), &artifact).unwrap();

        for (id, artifact_path) in [
            (
                "period-duplicate-a",
                "experiments/predictions/period-a.json",
            ),
            (
                "period-duplicate-b",
                "experiments/predictions/period-b.json",
            ),
        ] {
            let mut registration = valid_registration();
            registration.id = id.to_string();
            registration.hypothesis_family = "position-period-prediction".to_string();
            registration.prediction_artifact = Some(artifact_path.to_string());
            std::fs::write(
                preregistration_dir.join(format!("{id}.json")),
                serde_json::to_string_pretty(&registration).unwrap(),
            )
            .unwrap();
        }

        let validation = validate_prediction_artifact_with_repo_root(
            &preregistration_dir.join("period-duplicate-a.json"),
            temp.path(),
        )
        .unwrap();

        assert!(validation.valid);
        assert!(validation.warnings.iter().any(|warning| {
            warning.contains("duplicates 1 other committed artifact")
                && warning.contains("experiments/predictions/period-b.json")
                && warning.contains("not independent evidence")
        }));
    }

    #[test]
    fn prediction_artifact_validation_accepts_custom_residue_balance_modulus_range() {
        let temp = TempDir::new().unwrap();
        let preregistration_dir = temp.path().join("experiments/preregistrations");
        let prediction_dir = temp.path().join("experiments/predictions");
        std::fs::create_dir_all(&preregistration_dir).unwrap();
        std::fs::create_dir_all(&prediction_dir).unwrap();

        let artifact_path = "experiments/predictions/residue-balance-high-moduli.json";
        std::fs::write(
            temp.path().join(artifact_path),
            serde_json::to_string_pretty(&build_ciphertext_residue_balance_prior(7, 13)).unwrap(),
        )
        .unwrap();

        let mut registration = valid_registration();
        registration.id = "residue-balance-high-moduli".to_string();
        registration.hypothesis_family = "ciphertext-residue-balance-position-prior".to_string();
        registration.prediction_artifact = Some(artifact_path.to_string());
        std::fs::write(
            preregistration_dir.join("residue-balance-high-moduli.json"),
            serde_json::to_string_pretty(&registration).unwrap(),
        )
        .unwrap();

        let validation = validate_prediction_artifact_with_repo_root(
            &preregistration_dir.join("residue-balance-high-moduli.json"),
            temp.path(),
        )
        .unwrap();

        assert!(validation.valid, "{:?}", validation.errors);
        assert_eq!(validation.artifact_kind, "ciphertext-residue-balance");
        assert_eq!(validation.artifact_period_count, Some(7));
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

    #[test]
    fn independent_lane_status_rejects_filename_id_mismatch() {
        let temp = TempDir::new().unwrap();
        let preregistration_dir = temp.path().join("experiments/preregistrations");
        let prediction_dir = temp.path().join("experiments/predictions");
        std::fs::create_dir_all(&preregistration_dir).unwrap();
        std::fs::create_dir_all(&prediction_dir).unwrap();
        std::fs::write(
            prediction_dir.join("period.json"),
            serde_json::to_string_pretty(&build_all_period_prediction_plans().unwrap()).unwrap(),
        )
        .unwrap();

        let mut registration = valid_registration();
        registration.id = "stable-lane-id".to_string();
        registration.hypothesis_family = "position-period-prediction".to_string();
        registration.prediction_artifact = Some("experiments/predictions/period.json".to_string());
        std::fs::write(
            preregistration_dir.join("copied-placeholder-name.json"),
            serde_json::to_string_pretty(&registration).unwrap(),
        )
        .unwrap();

        let report =
            summarize_independent_lanes_with_repo_root(&preregistration_dir, temp.path()).unwrap();

        assert_eq!(report.lane_count, 1);
        assert_eq!(report.invalid_lanes, 1);
        assert!(!report.lanes[0].preregistration_valid);
        assert!(
            report.lanes[0]
                .errors
                .iter()
                .any(|error| error.contains("filename must match preregistration id"))
        );
    }
}
