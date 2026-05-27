use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub title: &'static str,
    pub related_hypothesis: &'static str,
    pub source_inputs: &'static [&'static str],
    pub transformation_steps: &'static [&'static str],
    pub output_summary: &'static str,
    pub baseline_comparison: &'static str,
    pub interpretation: &'static str,
    pub next_test: &'static str,
    pub promoted_candidate: bool,
}

pub fn findings() -> Vec<Finding> {
    vec![
        Finding {
            id: "F1",
            title: "Public anchors normalize into two adjacent known-plaintext spans",
            related_hypothesis: "H1/H2",
            source_inputs: &["elonka-kryptos", "scientific-american-2025"],
            transformation_steps: &[
                "store public anchors with zero-based and one-based positions",
                "join anchors only when public positions are directly adjacent",
                "derive alphabet-specific additive, subtractive, and Beaufort fragments",
            ],
            output_summary: "EAST joins NORTHEAST as EASTNORTHEAST, and BERLIN joins CLOCK as BERLINCLOCK.",
            baseline_comparison: "Span-level recurrence results are compared against seeded shuffled controls in the baseline command.",
            interpretation: "The spans are useful constraints, not solution text beyond the public anchors.",
            next_test: "Use the span fragments as fixed validation points for any future key-schedule or alphabet hypothesis.",
            promoted_candidate: false,
        },
        Finding {
            id: "F2",
            title: "Generic Gromark-style recurrence screens are underpowered",
            related_hypothesis: "H1",
            source_inputs: &["histocrypt-2021-bean", "elonka-kryptos"],
            transformation_steps: &[
                "derive additive key fragments from public known-plaintext spans",
                "screen contiguous triples for a mod-10 sum recurrence",
                "run deterministic shuffled null controls with Holm adjustment",
            ],
            output_summary: "The CLI can reproduce recurrence counts and adjusted p-values, but never promotes them.",
            baseline_comparison: "Public-anchor samples contain too few triples for promotion under the configured release boundary.",
            interpretation: "The result is a falsifiable diagnostic lane, not evidence for a Gromark solution.",
            next_test: "Require a larger independently justified fragment set before considering any recurrence signal meaningful.",
            promoted_candidate: false,
        },
        Finding {
            id: "F3",
            title: "Contextual candidate sequences are registered before scoring",
            related_hypothesis: "H4/H5",
            source_inputs: &["scientific-american-2025", "elonka-kryptos"],
            transformation_steps: &[
                "define Berlin World Clock, compass, Egypt 1986, and Berlin Wall 1989 material before scoring",
                "convert each candidate with a declared transform",
                "compare only against public-anchor-derived additive fragments",
            ],
            output_summary: "Candidate scores are reproducible and marked exploratory with no promoted candidate.",
            baseline_comparison: "The candidate-sequences command reports match rates but does not treat them as independent proof.",
            interpretation: "The feature constrains future contextual testing without expanding into ad hoc key hunting.",
            next_test: "Add new contextual material only when it has a source ID, declared transform, and pre-registration rationale.",
            promoted_candidate: false,
        },
        Finding {
            id: "F4",
            title: "Route experiments stay bounded to named permutation families",
            related_hypothesis: "H3",
            source_inputs: &["cia-sculpture", "elonka-kryptos"],
            transformation_steps: &[
                "derive public span additive fragments under the standard alphabet",
                "apply identity, reverse, and compatible row-to-column route families",
                "score routed fragments against the same local recurrence diagnostic",
            ],
            output_summary: "Route screens report scores and baselines without emitting guessed plaintext.",
            baseline_comparison: "Each route result is shown beside identity, reverse, and seeded-random baselines.",
            interpretation: "The route lane is an exploratory guardrail against unconstrained permutation search.",
            next_test: "Only add route families that are named, deterministic, and justified before seeing their score.",
            promoted_candidate: false,
        },
        Finding {
            id: "F5",
            title: "Independent non-anchor period targets are materialized before scoring",
            related_hypothesis: "H3",
            source_inputs: &[
                "experiments/preregistrations/non-anchor-position-period-v1.json",
                "experiments/predictions/non-anchor-position-period-v1.json",
                "experiments/preregistrations/non-anchor-position-period-diagnostic-v1.json",
                "experiments/predictions/non-anchor-position-period-diagnostic-v1.json",
                "experiments/preregistrations/non-anchor-position-period-followup-v1.json",
                "experiments/predictions/non-anchor-position-period-followup-v1.json",
                "experiments/preregistrations/non-anchor-position-period-v2.json",
                "experiments/predictions/non-anchor-position-period-v2.json",
                "experiments/preregistrations/non-anchor-position-period-v3.json",
                "experiments/predictions/non-anchor-position-period-v3.json",
                "experiments/preregistrations/non-anchor-position-period-v4.json",
                "experiments/predictions/non-anchor-position-period-v4.json",
                "experiments/preregistrations/non-anchor-position-period-v5.json",
                "experiments/predictions/non-anchor-position-period-v5.json",
                "experiments/preregistrations/non-anchor-position-period-v6.json",
                "experiments/predictions/non-anchor-position-period-v6.json",
                "experiments/preregistrations/non-anchor-position-period-v7.json",
                "experiments/predictions/non-anchor-position-period-v7.json",
                "experiments/preregistrations/non-anchor-position-period-v8.json",
                "experiments/predictions/non-anchor-position-period-v8.json",
                "experiments/preregistrations/non-anchor-position-period-v9.json",
                "experiments/predictions/non-anchor-position-period-v9.json",
                "experiments/preregistrations/non-anchor-position-period-v10.json",
                "experiments/predictions/non-anchor-position-period-v10.json",
                "experiments/preregistrations/non-anchor-position-period-v11.json",
                "experiments/predictions/non-anchor-position-period-v11.json",
                "experiments/preregistrations/non-anchor-position-period-v12.json",
                "experiments/predictions/non-anchor-position-period-v12.json",
                "experiments/preregistrations/non-anchor-position-period-v13.json",
                "experiments/predictions/non-anchor-position-period-v13.json",
            ],
            transformation_steps: &[
                "validate each non-anchor position-period preregistration",
                "emit all registered period residue classes before observing independent evidence",
                "compare each committed prediction artifact against deterministic generator output",
            ],
            output_summary: "The committed artifacts lock seven registered periods, exclude 24 public-anchor positions, and emit 73 non-anchor K4 positions per period.",
            baseline_comparison: "The artifacts have no score yet; future evidence must use held-out or best-of-period controls before interpretation.",
            interpretation: "These are evidence-free prediction targets, not positive signals or K4 solution claims.",
            next_test: "Use validate-prediction-artifact before evaluating any future independent evidence against the committed residue classes, and keep source-backed observation files separate from public-anchor-derived fragments.",
            promoted_candidate: false,
        },
        Finding {
            id: "F6",
            title: "Methodology context stops repeated single-layer search mining",
            related_hypothesis: "H1/H2/H3/H4/H5",
            source_inputs: &[
                "kryptosbot-methodology-2026",
                "experiments/STOPPED_LANES.md",
                "experiments/PROGRESS_LOG.md",
            ],
            transformation_steps: &[
                "register methodology context with a non-scored allowed-use boundary",
                "compare it against completed batch, routed, held-out, and structural controls",
                "record saturated search families as stopped unless a preregistration narrows the target before scoring",
            ],
            output_summary: "Simple single-layer, word-list, route, and uncorrected best-of-search lanes are documented as stopped for current evidence.",
            baseline_comparison: "The stopped-lane decision is backed by existing negative batch-level, routed, held-out, and structural controls rather than a new positive score.",
            interpretation: "Methodology context improves research discipline, but it is not plaintext, candidate evidence, or an independent scored observation.",
            next_test: "Only reopen a stopped search family with a lane-specific preregistration that fixes the cipher family, transform set, target, and multiple-comparison control before scoring.",
            promoted_candidate: false,
        },
        Finding {
            id: "F7",
            title: "Machine-readable gates protect future independent evidence",
            related_hypothesis: "H3",
            source_inputs: &[
                "experiments/preregistrations/non-anchor-position-period-v1.json",
                "experiments/predictions/non-anchor-position-period-v1.json",
                "experiments/preregistrations/non-anchor-position-period-diagnostic-v1.json",
                "experiments/predictions/non-anchor-position-period-diagnostic-v1.json",
                "experiments/preregistrations/non-anchor-position-period-followup-v1.json",
                "experiments/predictions/non-anchor-position-period-followup-v1.json",
                "experiments/preregistrations/non-anchor-position-period-v2.json",
                "experiments/predictions/non-anchor-position-period-v2.json",
                "experiments/preregistrations/non-anchor-position-period-v3.json",
                "experiments/predictions/non-anchor-position-period-v3.json",
                "experiments/preregistrations/non-anchor-position-period-v4.json",
                "experiments/predictions/non-anchor-position-period-v4.json",
                "experiments/preregistrations/non-anchor-position-period-v5.json",
                "experiments/predictions/non-anchor-position-period-v5.json",
                "experiments/preregistrations/non-anchor-position-period-v6.json",
                "experiments/predictions/non-anchor-position-period-v6.json",
                "experiments/preregistrations/non-anchor-position-period-v7.json",
                "experiments/predictions/non-anchor-position-period-v7.json",
                "experiments/preregistrations/non-anchor-position-period-v8.json",
                "experiments/predictions/non-anchor-position-period-v8.json",
                "experiments/preregistrations/non-anchor-position-period-v9.json",
                "experiments/predictions/non-anchor-position-period-v9.json",
                "experiments/preregistrations/non-anchor-position-period-v10.json",
                "experiments/predictions/non-anchor-position-period-v10.json",
                "experiments/preregistrations/non-anchor-position-period-v11.json",
                "experiments/predictions/non-anchor-position-period-v11.json",
                "experiments/preregistrations/non-anchor-position-period-v12.json",
                "experiments/predictions/non-anchor-position-period-v12.json",
                "experiments/preregistrations/non-anchor-position-period-v13.json",
                "experiments/predictions/non-anchor-position-period-v13.json",
                "experiments/preregistrations/non-anchor-position-spacing-v1.json",
                "experiments/predictions/non-anchor-position-spacing-v1.json",
                "experiments/PROGRESS_LOG.md",
                "release-check",
            ],
            transformation_steps: &[
                "validate every committed independent-lane preregistration with JSON output",
                "validate every committed independent-lane prediction artifact with JSON output",
                "run release-check in JSON mode and require every local preflight gate to pass",
            ],
            output_summary: "All committed independent-lane preregistrations and artifacts validate as non-promotional, and release-check JSON reports every local gate as passed.",
            baseline_comparison: "This is a reproducibility gate, not a scored cryptanalytic baseline; it prevents stale or unregistered evidence from being interpreted as a signal.",
            interpretation: "Future evidence can be audited by tools before scoring, but the gate result itself provides no plaintext and promotes no candidate.",
            next_test: "Before any new non-anchor observation is scored, run the JSON preregistration, prediction-artifact, observation, evaluation, and release gates and archive the exact outputs.",
            promoted_candidate: false,
        },
        Finding {
            id: "F8",
            title: "Source-backed observation scoring requires preregistration",
            related_hypothesis: "H3",
            source_inputs: &[
                "src/main.rs",
                "src/position_structure.rs",
                "tests/cli_e2e.rs",
                "experiments/PROGRESS_LOG.md",
            ],
            transformation_steps: &[
                "mark direct evaluate-period-prediction --positions input as diagnostic",
                "require --preregistration when evaluate-period-prediction scores a --positions-file",
                "require per-position notes before any source-backed observation file can validate",
                "validate the committed prediction artifact before source-backed observations are scored",
                "revalidate archived preregistration, artifact, and observation files before accepting archived source-backed evaluations",
            ],
            output_summary: "Ad hoc position lists now emit a diagnostic warning, source-backed observation files require preregistration-backed artifact validation and one note per scored position before scoring, and archived evaluations re-run archive-local preregistration/artifact/observation checks.",
            baseline_comparison: "This is an evidence-boundary guard rather than a positive statistical signal; it prevents stale artifacts, ad hoc position lists, thin observation files, or internally tampered archives from being interpreted as independent support.",
            interpretation: "The period-prediction workflow is stricter, but no new K4 plaintext, key material, or promoted candidate is produced.",
            next_test: "When a real non-anchor observation file exists, validate its preregistration and artifact, run validate-period-observations, then evaluate-period-prediction with --positions-file and archive the JSON outputs.",
            promoted_candidate: false,
        },
        Finding {
            id: "F9",
            title: "Spacing prediction scoring has a source-backed validation gate",
            related_hypothesis: "H3",
            source_inputs: &[
                "src/main.rs",
                "src/position_structure.rs",
                "tests/cli_e2e.rs",
                "experiments/PROGRESS_LOG.md",
            ],
            transformation_steps: &[
                "emit a committed non-anchor spacing prediction artifact",
                "require per-position notes in source-backed observation files",
                "validate source-backed observation files against the spacing artifact before scoring",
                "evaluate spacing observations with a best-of-modulus seeded null only after artifact validation",
            ],
            output_summary: "Spacing observations now have a pre-score validation command and evaluator, both keeping ad hoc inputs diagnostic and source-backed files preregistration-gated with per-position notes.",
            baseline_comparison: "This is a guardrail for future independent evidence; the diagnostic toy spacing check was non-promotional and did not produce a meaningful p-value.",
            interpretation: "The spacing lane is now executable for future independent observations, but it does not add K4 plaintext, key material, or a promoted candidate.",
            next_test: "When a real non-anchor observation file exists, run validate-spacing-observations with the spacing preregistration, then evaluate-spacing-prediction with --positions-file and archive the JSON outputs.",
            promoted_candidate: false,
        },
        Finding {
            id: "F10",
            title: "Independent lane status exposes the next evidence gate",
            related_hypothesis: "H3",
            source_inputs: &[
                "src/preregistration.rs",
                "src/main.rs",
                "tests/cli_e2e.rs",
                "experiments/PROGRESS_LOG.md",
            ],
            transformation_steps: &[
                "scan committed preregistration files except the template",
                "validate each preregistration and declared prediction artifact",
                "report lane readiness and the next observation validator or evaluator command",
            ],
            output_summary: "The lane-status command reports 16 lanes, 16 ready for source-backed observations, 0 invalid lanes, 16 prediction artifacts, 2 unique prediction artifact contents, 2 unique ready prediction artifact contents, 1 duplicate artifact group, period family 15 lanes/1 unique ready artifact, spacing family 1 lane/1 unique ready artifact, and promoted false.",
            baseline_comparison: "This is an operational gate summary rather than a statistical cryptanalytic baseline.",
            interpretation: "All current independent prediction lanes are ready for future source-backed observation files, but no observation has been scored and no candidate is promoted.",
            next_test: "Use independent-lane-status before adding any observation file, then run the family-specific observation validator and evaluator named by the lane status output.",
            promoted_candidate: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::sources;
    use crate::preregistration::summarize_independent_lanes;
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;

    #[test]
    fn findings_are_unique_and_non_promotional() {
        let findings = findings();
        let ids: HashSet<_> = findings.iter().map(|finding| finding.id).collect();

        assert_eq!(ids.len(), findings.len());
        assert!(findings.iter().all(|finding| !finding.promoted_candidate));
        assert!(
            findings
                .iter()
                .all(|finding| !finding.source_inputs.is_empty())
        );
    }

    #[test]
    fn finding_source_inputs_are_registered_files_or_commands() {
        let registered_source_ids: HashSet<_> =
            sources().into_iter().map(|source| source.id).collect();
        let registered_commands = HashSet::from(["release-check"]);

        for finding in findings() {
            for source_input in finding.source_inputs {
                assert!(
                    registered_source_ids.contains(source_input)
                        || registered_commands.contains(source_input)
                        || Path::new(source_input).exists(),
                    "finding {} references unknown source input `{}`",
                    finding.id,
                    source_input
                );
            }
        }
    }

    #[test]
    fn independent_lane_status_finding_matches_committed_lane_count() {
        let report = summarize_independent_lanes(Path::new("experiments/preregistrations"))
            .expect("independent lane status should summarize committed preregistrations");
        let finding = findings()
            .into_iter()
            .find(|finding| finding.id == "F10")
            .expect("F10 should describe independent lane status");

        assert!(finding.output_summary.contains(&format!(
            "{} lanes, {} ready for source-backed observations, {} invalid lanes",
            report.lane_count, report.ready_for_source_backed_observations, report.invalid_lanes
        )));
        assert!(finding.output_summary.contains(&format!(
            "{} prediction artifacts, {} unique prediction artifact contents, {} unique ready prediction artifact contents, {} duplicate artifact group",
            report.prediction_artifacts,
            report.unique_prediction_artifacts,
            report.unique_ready_prediction_artifacts,
            report.duplicate_prediction_artifact_groups.len()
        )));
        for family in &report.family_summaries {
            assert!(finding.output_summary.contains(&format!(
                "{} family {} lane",
                family.hypothesis_family
                    .strip_prefix("position-")
                    .and_then(|suffix| suffix.strip_suffix("-prediction"))
                    .unwrap_or(&family.hypothesis_family),
                family.lanes
            )));
            assert!(finding.output_summary.contains(&format!(
                "{} unique ready artifact",
                family.unique_ready_prediction_artifacts
            )));
        }
        assert!(!report.promoted_candidate);
        assert!(!finding.promoted_candidate);
    }

    #[test]
    fn period_target_finding_covers_committed_period_artifacts() {
        let expected_sources = committed_period_files("experiments/preregistrations")
            .into_iter()
            .chain(committed_period_files("experiments/predictions"))
            .collect::<HashSet<_>>();
        let finding = findings()
            .into_iter()
            .find(|finding| finding.id == "F5")
            .expect("F5 should describe materialized period targets");
        let finding_sources = finding
            .source_inputs
            .iter()
            .copied()
            .collect::<HashSet<_>>();

        for expected_source in expected_sources {
            assert!(
                finding_sources.contains(expected_source.as_str()),
                "F5 is missing committed period source input `{expected_source}`"
            );
        }
        assert!(!finding.promoted_candidate);
    }

    #[test]
    fn gate_finding_covers_committed_independent_lane_artifacts() {
        let expected_sources = committed_independent_lane_files("experiments/preregistrations")
            .into_iter()
            .chain(committed_independent_lane_files("experiments/predictions"))
            .collect::<HashSet<_>>();
        let finding = findings()
            .into_iter()
            .find(|finding| finding.id == "F7")
            .expect("F7 should describe independent evidence gates");
        let finding_sources = finding
            .source_inputs
            .iter()
            .copied()
            .collect::<HashSet<_>>();

        for expected_source in expected_sources {
            assert!(
                finding_sources.contains(expected_source.as_str()),
                "F7 is missing committed independent-lane source input `{expected_source}`"
            );
        }
        assert!(!finding.promoted_candidate);
    }

    fn committed_period_files(directory: &str) -> Vec<String> {
        committed_prediction_files(directory, "non-anchor-position-period")
    }

    fn committed_independent_lane_files(directory: &str) -> Vec<String> {
        committed_prediction_files(directory, "non-anchor-position-")
    }

    fn committed_prediction_files(directory: &str, prefix: &str) -> Vec<String> {
        fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("failed to read {directory}: {error}"))
            .map(|entry| {
                entry
                    .unwrap_or_else(|error| panic!("failed to read entry in {directory}: {error}"))
                    .path()
            })
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(prefix))
                    && path
                        .extension()
                        .is_some_and(|extension| extension == "json")
            })
            .map(|path| path.display().to_string())
            .collect()
    }
}
