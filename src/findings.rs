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
                "experiments/preregistrations/non-anchor-position-period-v2.json",
                "experiments/predictions/non-anchor-position-period-v2.json",
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
                "experiments/preregistrations/non-anchor-position-period-v2.json",
                "experiments/predictions/non-anchor-position-period-v2.json",
                "experiments/PROGRESS_LOG.md",
                "release-check",
            ],
            transformation_steps: &[
                "validate the v2 preregistration with JSON output",
                "validate the committed v2 prediction artifact with JSON output",
                "run release-check in JSON mode and require every local preflight gate to pass",
            ],
            output_summary: "The v2 preregistration and artifact validate as non-promotional, and release-check JSON reports every local gate as passed.",
            baseline_comparison: "This is a reproducibility gate, not a scored cryptanalytic baseline; it prevents stale or unregistered evidence from being interpreted as a signal.",
            interpretation: "Future evidence can be audited by tools before scoring, but the gate result itself provides no plaintext and promotes no candidate.",
            next_test: "Before any new non-anchor observation is scored, run the JSON preregistration, prediction-artifact, observation, evaluation, and release gates and archive the exact outputs.",
            promoted_candidate: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::sources;
    use std::collections::HashSet;
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
}
