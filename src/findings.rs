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
            output_summary: "The 100000-iteration span/all-alphabet baseline found no adjusted recurrence signal: the strongest raw row was EASTNORTHEAST/Kryptos with 2/11 triples, raw p=0.3138, adjusted p=1.0000.",
            baseline_comparison: "Seeded shuffled controls over public-anchor span fragments leave every adjusted p-value at 1.0000, so the Gromark-style screen remains negative and underpowered.",
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
                "experiments/preregistrations/non-anchor-position-period-v14.json",
                "experiments/predictions/non-anchor-position-period-v14.json",
                "experiments/preregistrations/non-anchor-position-period-v15.json",
                "experiments/predictions/non-anchor-position-period-v15.json",
                "experiments/preregistrations/non-anchor-position-period-v16.json",
                "experiments/predictions/non-anchor-position-period-v16.json",
                "experiments/preregistrations/non-anchor-position-period-v17.json",
                "experiments/predictions/non-anchor-position-period-v17.json",
                "experiments/preregistrations/non-anchor-position-period-v18.json",
                "experiments/predictions/non-anchor-position-period-v18.json",
                "experiments/preregistrations/non-anchor-position-period-v19.json",
                "experiments/predictions/non-anchor-position-period-v19.json",
                "experiments/preregistrations/non-anchor-position-period-v20.json",
                "experiments/predictions/non-anchor-position-period-v20.json",
                "experiments/preregistrations/non-anchor-position-period-v21.json",
                "experiments/predictions/non-anchor-position-period-v21.json",
                "experiments/preregistrations/non-anchor-position-period-v22.json",
                "experiments/predictions/non-anchor-position-period-v22.json",
                "experiments/preregistrations/non-anchor-position-period-v23.json",
                "experiments/predictions/non-anchor-position-period-v23.json",
                "experiments/preregistrations/non-anchor-position-period-v24.json",
                "experiments/predictions/non-anchor-position-period-v24.json",
                "experiments/preregistrations/non-anchor-position-period-v25.json",
                "experiments/predictions/non-anchor-position-period-v25.json",
                "experiments/preregistrations/non-anchor-position-period-v26.json",
                "experiments/predictions/non-anchor-position-period-v26.json",
                "experiments/preregistrations/non-anchor-position-period-v27.json",
                "experiments/predictions/non-anchor-position-period-v27.json",
                "experiments/preregistrations/non-anchor-position-period-v28.json",
                "experiments/predictions/non-anchor-position-period-v28.json",
                "experiments/preregistrations/non-anchor-position-period-v29.json",
                "experiments/predictions/non-anchor-position-period-v29.json",
                "experiments/preregistrations/non-anchor-position-period-v30.json",
                "experiments/predictions/non-anchor-position-period-v30.json",
                "experiments/preregistrations/non-anchor-position-period-v31.json",
                "experiments/predictions/non-anchor-position-period-v31.json",
                "experiments/preregistrations/non-anchor-position-period-v32.json",
                "experiments/predictions/non-anchor-position-period-v32.json",
                "experiments/preregistrations/non-anchor-position-period-v33.json",
                "experiments/predictions/non-anchor-position-period-v33.json",
                "experiments/preregistrations/non-anchor-position-period-v34.json",
                "experiments/predictions/non-anchor-position-period-v34.json",
                "experiments/preregistrations/non-anchor-position-period-v35.json",
                "experiments/predictions/non-anchor-position-period-v35.json",
                "experiments/preregistrations/non-anchor-position-period-v36.json",
                "experiments/predictions/non-anchor-position-period-v36.json",
                "experiments/preregistrations/non-anchor-position-period-v37.json",
                "experiments/predictions/non-anchor-position-period-v37.json",
                "experiments/preregistrations/non-anchor-position-period-v38.json",
                "experiments/predictions/non-anchor-position-period-v38.json",
                "experiments/preregistrations/non-anchor-position-period-v39.json",
                "experiments/predictions/non-anchor-position-period-v39.json",
                "experiments/preregistrations/non-anchor-position-period-v40.json",
                "experiments/predictions/non-anchor-position-period-v40.json",
                "experiments/preregistrations/non-anchor-position-period-v41.json",
                "experiments/predictions/non-anchor-position-period-v41.json",
                "experiments/preregistrations/non-anchor-position-period-v42.json",
                "experiments/predictions/non-anchor-position-period-v42.json",
                "experiments/preregistrations/non-anchor-position-period-v43.json",
                "experiments/predictions/non-anchor-position-period-v43.json",
                "experiments/preregistrations/non-anchor-position-period-v44.json",
                "experiments/predictions/non-anchor-position-period-v44.json",
                "experiments/preregistrations/non-anchor-position-period-v45.json",
                "experiments/predictions/non-anchor-position-period-v45.json",
                "kryptosbot-sanborn-papers-2026",
            ],
            transformation_steps: &[
                "validate each non-anchor position-period preregistration",
                "emit all registered period residue classes before observing independent evidence",
                "compare each committed prediction artifact against deterministic generator output",
            ],
            output_summary: "The committed artifacts lock eight registered periods, including source-context period 14, exclude 24 public-anchor positions, and emit 73 non-anchor K4 positions per period.",
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
                "experiments/preregistrations/non-anchor-position-period-v14.json",
                "experiments/predictions/non-anchor-position-period-v14.json",
                "experiments/preregistrations/non-anchor-position-period-v15.json",
                "experiments/predictions/non-anchor-position-period-v15.json",
                "experiments/preregistrations/non-anchor-position-period-v16.json",
                "experiments/predictions/non-anchor-position-period-v16.json",
                "experiments/preregistrations/non-anchor-position-period-v17.json",
                "experiments/predictions/non-anchor-position-period-v17.json",
                "experiments/preregistrations/non-anchor-position-period-v18.json",
                "experiments/predictions/non-anchor-position-period-v18.json",
                "experiments/preregistrations/non-anchor-position-period-v19.json",
                "experiments/predictions/non-anchor-position-period-v19.json",
                "experiments/preregistrations/non-anchor-position-period-v20.json",
                "experiments/predictions/non-anchor-position-period-v20.json",
                "experiments/preregistrations/non-anchor-position-period-v21.json",
                "experiments/predictions/non-anchor-position-period-v21.json",
                "experiments/preregistrations/non-anchor-position-period-v22.json",
                "experiments/predictions/non-anchor-position-period-v22.json",
                "experiments/preregistrations/non-anchor-position-period-v23.json",
                "experiments/predictions/non-anchor-position-period-v23.json",
                "experiments/preregistrations/non-anchor-position-period-v24.json",
                "experiments/predictions/non-anchor-position-period-v24.json",
                "experiments/preregistrations/non-anchor-position-period-v25.json",
                "experiments/predictions/non-anchor-position-period-v25.json",
                "experiments/preregistrations/non-anchor-position-period-v26.json",
                "experiments/predictions/non-anchor-position-period-v26.json",
                "experiments/preregistrations/non-anchor-position-period-v27.json",
                "experiments/predictions/non-anchor-position-period-v27.json",
                "experiments/preregistrations/non-anchor-position-period-v28.json",
                "experiments/predictions/non-anchor-position-period-v28.json",
                "experiments/preregistrations/non-anchor-position-period-v29.json",
                "experiments/predictions/non-anchor-position-period-v29.json",
                "experiments/preregistrations/non-anchor-position-period-v30.json",
                "experiments/predictions/non-anchor-position-period-v30.json",
                "experiments/preregistrations/non-anchor-position-period-v31.json",
                "experiments/predictions/non-anchor-position-period-v31.json",
                "experiments/preregistrations/non-anchor-position-period-v32.json",
                "experiments/predictions/non-anchor-position-period-v32.json",
                "experiments/preregistrations/non-anchor-position-period-v33.json",
                "experiments/predictions/non-anchor-position-period-v33.json",
                "experiments/preregistrations/non-anchor-position-period-v34.json",
                "experiments/predictions/non-anchor-position-period-v34.json",
                "experiments/preregistrations/non-anchor-position-period-v35.json",
                "experiments/predictions/non-anchor-position-period-v35.json",
                "experiments/preregistrations/non-anchor-position-period-v36.json",
                "experiments/predictions/non-anchor-position-period-v36.json",
                "experiments/preregistrations/non-anchor-position-period-v37.json",
                "experiments/predictions/non-anchor-position-period-v37.json",
                "experiments/preregistrations/non-anchor-position-period-v38.json",
                "experiments/predictions/non-anchor-position-period-v38.json",
                "experiments/preregistrations/non-anchor-position-period-v39.json",
                "experiments/predictions/non-anchor-position-period-v39.json",
                "experiments/preregistrations/non-anchor-position-period-v40.json",
                "experiments/predictions/non-anchor-position-period-v40.json",
                "experiments/preregistrations/non-anchor-position-period-v41.json",
                "experiments/predictions/non-anchor-position-period-v41.json",
                "experiments/preregistrations/non-anchor-position-period-v42.json",
                "experiments/predictions/non-anchor-position-period-v42.json",
                "experiments/preregistrations/non-anchor-position-period-v43.json",
                "experiments/predictions/non-anchor-position-period-v43.json",
                "experiments/preregistrations/non-anchor-position-period-v44.json",
                "experiments/predictions/non-anchor-position-period-v44.json",
                "experiments/preregistrations/non-anchor-position-period-v45.json",
                "experiments/predictions/non-anchor-position-period-v45.json",
                "experiments/preregistrations/ciphertext-structure-prior-v1.json",
                "experiments/predictions/ciphertext-structure-prior-v1.json",
                "experiments/preregistrations/ciphertext-hotspot-prior-v1.json",
                "experiments/predictions/ciphertext-hotspot-prior-v1.json",
                "experiments/preregistrations/ciphertext-rarity-prior-v1.json",
                "experiments/predictions/ciphertext-rarity-prior-v1.json",
                "experiments/preregistrations/ciphertext-repeat-distance-v1.json",
                "experiments/predictions/ciphertext-repeat-distance-v1.json",
                "experiments/preregistrations/ciphertext-period-match-v1.json",
                "experiments/predictions/ciphertext-period-match-v1.json",
                "experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json",
                "experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json",
                "experiments/preregistrations/ciphertext-transition-prior-v1.json",
                "experiments/predictions/ciphertext-transition-prior-v1.json",
                "experiments/preregistrations/ciphertext-turning-point-v1.json",
                "experiments/predictions/ciphertext-turning-point-v1.json",
                "experiments/preregistrations/ciphertext-window-balance-v1.json",
                "experiments/predictions/ciphertext-window-balance-v1.json",
                "experiments/preregistrations/ciphertext-residue-balance-high-moduli-v1.json",
                "experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json",
                "experiments/preregistrations/ciphertext-residue-balance-very-high-moduli-v1.json",
                "experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json",
                "experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json",
                "experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json",
                "experiments/preregistrations/ciphertext-residue-balance-ultra-high-moduli-v1.json",
                "experiments/predictions/ciphertext-residue-balance-ultra-high-moduli-v1.json",
                "experiments/preregistrations/non-anchor-position-spacing-v1.json",
                "experiments/predictions/non-anchor-position-spacing-v1.json",
                "experiments/preregistrations/non-anchor-position-mirror-v1.json",
                "experiments/predictions/non-anchor-position-mirror-v1.json",
                "experiments/preregistrations/non-anchor-position-grid-layout-v1.json",
                "experiments/predictions/non-anchor-position-grid-layout-v1.json",
                "experiments/preregistrations/non-anchor-position-grid-column-v1.json",
                "experiments/predictions/non-anchor-position-grid-column-v1.json",
                "experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json",
                "experiments/predictions/non-anchor-position-grid-compass-axis-v1.json",
                "experiments/preregistrations/tableau-hill-v1.json",
                "experiments/predictions/tableau-hill-v1.json",
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
                "require grid-layout preregistrations to declare the source-backed edge axis before scoring",
                "warn when a committed prediction artifact duplicates another committed artifact",
                "report lane readiness and the next observation validator or evaluator command",
            ],
            output_summary: "The lane-status command reports 68 lanes, 68 ready for source-backed observations, 0 invalid lanes, 0 evaluator-pending lanes, 68 prediction artifacts, 26 unique prediction artifact contents, 26 unique ready prediction artifact contents, 1 duplicate artifact group, 43 duplicate artifact lanes, and 42 extra duplicate artifact lanes beyond the first artifact instance; ciphertext-adjacent-contrast-position-prior family 1 lane/1 unique ready artifact, ciphertext-hotspot-position-prior family 1 lane/1 unique ready artifact, ciphertext-only-position-prior family 1 lane/1 unique ready artifact, ciphertext-period-match-position-prior family 1 lane/1 unique ready artifact, ciphertext-rarity-position-prior family 1 lane/1 unique ready artifact, ciphertext-repeat-distance-position-prior family 1 lane/1 unique ready artifact, ciphertext-residue-balance-position-prior family 5 lanes/5 unique ready artifacts, ciphertext-skip-transition-position-prior family 1 lane/1 unique ready artifact, ciphertext-transition-position-prior family 1 lane/1 unique ready artifact, ciphertext-turning-point-position-prior family 1 lane/1 unique ready artifact, ciphertext-window-balance-position-prior family 1 lane/1 unique ready artifact, grid-layout family 3 lanes/3 unique ready artifacts, mirror family 1 lane/1 unique ready artifact, period family 47 lanes/5 unique ready artifacts, spacing family 1 lane/1 unique ready artifact, tableau-hill-prediction family 1 lane/1 unique ready artifact, and promoted false. Prediction-artifact validation warns that duplicate period artifacts are inventory only, not independent evidence; the period-v40 artifact is a distinct period-3-only target with source-backed negative/non-significant support, the period-v42 artifact is a distinct period-5-only target with source-backed negative/non-significant support, the period-v43 artifact is a distinct period-14-only source-context target with source-backed negative/non-significant support, the period-v44 artifact is a distinct period-7-only target with source-backed negative/non-significant support, and the period-v45 artifact is a duplicate all-period readiness target only. The ciphertext-only prior fixes weak period-2 and period-7 ciphertext-derived residue targets before source-backed observation scoring. The ciphertext-hotspot prior fixes top ciphertext-only hotspots from repeated n-gram coverage and shifted self-coincidence endpoints before any source-backed scoring. The ciphertext-rarity prior fixes the 20 non-anchor positions whose ciphertext letters are rarest in the non-anchor universe before source-backed observation scoring. The ciphertext repeat-distance prior fixes the 20 non-anchor positions with strongest same-symbol repeat-distance structure before source-backed observation scoring. The ciphertext period-match prior fixes shifted same-letter period-match endpoint sets before source-backed observation scoring. The ciphertext adjacent-contrast prior fixes the 20 interior non-anchor positions with strongest left/right neighbor contrast in Kryptos alphabet order before source-backed observation scoring. The ciphertext transition prior fixes the 20 non-anchor positions with highest adjacent ciphertext-transition pressure before source-backed observation scoring. The ciphertext skip-transition prior fixes the 20 non-anchor positions with highest adjacent and distance-two ciphertext skip-transition pressure before source-backed observation scoring. The ciphertext turning-point prior fixes the 20 non-anchor positions with strongest local turning-point/high-curvature structure before source-backed observation scoring. The ciphertext window-balance prior fixes the 20 non-anchor positions with strongest ciphertext-only local-window balance structure and now has a source-backed observation validator/evaluator. The ciphertext residue-balance prior fixes ciphertext-only residue classes per modulus before source-backed observation scoring, including distinct high-moduli 7..=13, very-high-moduli 14..=20, and ultra-high-moduli 21..=26, and extreme-moduli 27..=33 targets. Grid-layout preregistrations now declare `grid_edge_axis: row`, `grid_edge_axis: column`, or `grid_edge_axis: compass-axis`, so source-backed grid scoring must use a matching preregistered artifact rather than switching axes post hoc. The tableau-hill lane has a committed source-mapping artifact that fixes 7-by-14 row-major coordinates and the single padding cell, plus a validator/evaluator that scores only row/column concentration on source-backed non-anchor observations with seeded null controls.",
            baseline_comparison: "This is an operational gate summary rather than a statistical cryptanalytic baseline.",
            interpretation: "All current supported independent prediction lanes are ready for source-backed observation files; scored observation evidence is tracked separately from lane inventory, and no candidate is promoted.",
            next_test: "Use independent-lane-status and next-evidence-gate before adding any observation file, then run the family-specific validator, evaluator, and archive validator named by the gate output.",
            promoted_candidate: false,
        },
        Finding {
            id: "F11",
            title: "CIA row-boundary observation is source-backed but negative",
            related_hypothesis: "H3",
            source_inputs: &[
                "sources/archives/cia-sculpture-2026-05-27.md",
                "experiments/source-reviews/cia-source-review-v1.json",
                "experiments/position-observations/cia-k4-row-boundaries-v1.json",
                "experiments/evidence-summaries/cia-k4-row-boundaries-v1.md",
                "experiments/preregistrations/non-anchor-position-mirror-v1.json",
                "experiments/predictions/non-anchor-position-mirror-v1.json",
                "experiments/preregistrations/non-anchor-position-grid-layout-v1.json",
                "experiments/predictions/non-anchor-position-grid-layout-v1.json",
                "experiments/preregistrations/non-anchor-position-grid-compass-axis-v1.json",
                "experiments/predictions/non-anchor-position-grid-compass-axis-v1.json",
                "experiments/preregistrations/tableau-hill-v1.json",
                "experiments/predictions/tableau-hill-v1.json",
                "experiments/preregistrations/ciphertext-hotspot-prior-v1.json",
                "experiments/predictions/ciphertext-hotspot-prior-v1.json",
                "experiments/preregistrations/ciphertext-rarity-prior-v1.json",
                "experiments/predictions/ciphertext-rarity-prior-v1.json",
                "experiments/preregistrations/ciphertext-repeat-distance-v1.json",
                "experiments/predictions/ciphertext-repeat-distance-v1.json",
                "experiments/preregistrations/ciphertext-period-match-v1.json",
                "experiments/predictions/ciphertext-period-match-v1.json",
                "experiments/preregistrations/ciphertext-adjacent-contrast-prior-v1.json",
                "experiments/predictions/ciphertext-adjacent-contrast-prior-v1.json",
                "experiments/preregistrations/ciphertext-transition-prior-v1.json",
                "experiments/predictions/ciphertext-transition-prior-v1.json",
                "experiments/preregistrations/ciphertext-skip-transition-v1.json",
                "experiments/predictions/ciphertext-skip-transition-v1.json",
                "experiments/preregistrations/ciphertext-turning-point-v1.json",
                "experiments/predictions/ciphertext-turning-point-v1.json",
                "experiments/preregistrations/ciphertext-window-balance-v1.json",
                "experiments/predictions/ciphertext-window-balance-v1.json",
                "experiments/preregistrations/ciphertext-residue-balance-high-moduli-v1.json",
                "experiments/predictions/ciphertext-residue-balance-high-moduli-v1.json",
                "experiments/preregistrations/ciphertext-residue-balance-very-high-moduli-v1.json",
                "experiments/predictions/ciphertext-residue-balance-very-high-moduli-v1.json",
            ],
            transformation_steps: &[
                "record CIA sculpture text-version row-boundary positions before scoring",
                "exclude public-anchor positions from the row-boundary set",
                "validate the retained positions against period, spacing, mirror, grid row, grid column, grid compass-axis, Tableau/HILL, and ciphertext-only preregistrations including window-balance, period-match, high-moduli, very-high-moduli, and ultra-high-moduli residue balance",
                "score the retained positions with seeded best-of-model null controls",
                "validate the local period, spacing, mirror, grid-row, grid-column, grid-compass-axis, Tableau/HILL, ciphertext-hotspot, ciphertext-rarity, ciphertext-repeat-distance, ciphertext-period-match, ciphertext-adjacent-contrast, ciphertext-transition, ciphertext-skip-transition, ciphertext-turning-point, ciphertext-window-balance, ciphertext-residue-balance, and other ciphertext-only evaluation archives",
            ],
            output_summary: "The source-backed observation retains non-anchor positions 1, 4, 5, 36, 37, and 97. Period scoring found best period 2 residue 0 with 4/6 hits and empirical p=0.7897. Period-5 scoring found best residue 0 with 2/6 hits and empirical p=1.0000. Period-7 scoring found best residue 0 with 2/6 hits and empirical p=0.9476. Spacing scoring found best modulus 2 residue 1 with 8/15 pair hits and empirical p=1.0000. Mirror scoring found 1/3 possible mirror-pair hits and empirical p=0.2090. Grid-row scoring found 1/6 row-edge hits and empirical p=0.5600 under the archived `--edge-axis row` target, matching preregistered `grid_edge_axis: row`. Grid-column scoring found 4/6 column-edge hits at positions 1, 4, 5, and 97 with empirical p=0.1303 under the archived `--edge-axis column` target, matching preregistered `grid_edge_axis: column`. Grid-compass-axis scoring found 1/6 compass-axis hits at position 36 with empirical p=0.9166 under the archived `--edge-axis compass-axis` target, matching preregistered `grid_edge_axis: compass-axis`. Tableau/HILL scoring found best row 1 concentration with 3/6 hits and empirical p=0.3311. Ciphertext-hotspot scoring found 0/6 hotspot hits and empirical p=1.0000. Ciphertext-rarity scoring found 2/6 rare-position hits and empirical p=0.5282. Ciphertext-repeat-distance scoring found 2/6 repeat-distance hits and empirical p=0.5273. Ciphertext-period-match scoring found best shifted same-letter period 2 endpoints with 1/6 hits and empirical p=0.9733. Ciphertext-adjacent-contrast scoring found 2/6 adjacent-contrast hits at positions 5 and 37 with empirical p=0.5259. Ciphertext-transition scoring found 0/6 adjacent-transition-position hits and empirical p=1.0000. Ciphertext-skip-transition scoring found 0/6 skip-transition-position hits and empirical p=1.0000. Ciphertext-turning-point scoring found 2/6 turning-point hits and empirical p=0.5247. Ciphertext-window-balance scoring found 0/6 window-balance hits and empirical p=1.0000. Ciphertext-residue-balance scoring found best modulus 2 residue 0 with 4/6 hits and empirical p=0.4803. High-moduli ciphertext-residue-balance scoring found best modulus 8 residue 3 with 2/6 hits and empirical p=0.6416. Very-high-moduli ciphertext-residue-balance scoring found best modulus 16 residue 0 with 2/6 hits and empirical p=0.3125. Ultra-high-moduli ciphertext-residue-balance scoring found best modulus 21 residue 12 with 1/6 hits and empirical p=0.8289.",
            baseline_comparison: "The period and spacing evaluations use seeded best-of-model null controls, and the mirror, grid-row, grid-column, grid-compass-axis, Tableau/HILL, ciphertext-hotspot, ciphertext-rarity, ciphertext-repeat-distance, ciphertext-period-match, ciphertext-adjacent-contrast, ciphertext-transition, ciphertext-skip-transition, ciphertext-turning-point, ciphertext-window-balance, and ciphertext-residue-balance evaluations use seeded same-size non-anchor position-set nulls; none of the results is unusual under the configured controls.",
            interpretation: "The row-boundary observation is auditable independent evidence, but it is negative for the committed period, spacing, mirror, grid-row, grid-column, grid-compass-axis, Tableau/HILL, and ciphertext-only targets and promotes no K4 candidate.",
            next_test: "Stop mining this row-boundary observation. Future progress needs a new source-backed observation or a pre-registered prediction target that is not derived from these same row-boundary positions.",
            promoted_candidate: false,
        },
        Finding {
            id: "F12",
            title: "Unused CIA artifact source is eligible context but not currently scoreable",
            related_hypothesis: "H3",
            source_inputs: &[
                "sources/archives/cia-artifact-2026-05-27.md",
                "src/main.rs",
                "tests/cli_e2e.rs",
                "experiments/PROGRESS_LOG.md",
            ],
            transformation_steps: &[
                "compare eligible observation sources against valid source-backed evidence archives",
                "identify eligible sources already consumed by scored archives",
                "inspect unused eligible source archives for explicit scored-position markers or non-scorable reasons",
                "report unused eligible source status in next-evidence-gate before recommending any new score",
                "summarize reviewed/used/scored-marker/non-scorable state with source-observation-status",
            ],
            output_summary: "The live gate and focused source-observation-status command report `cia-sculpture` as reviewed, scored-marker backed, and used by archived source-backed evaluations. They report `cia-artifact` as reviewed and locally archived but unused, with no `scored_positions_one_based` marker and an explicit `non_scorable_reason`, so it must not be scored unless new source-backed rationale changes that archive boundary.",
            baseline_comparison: "This is a source-use and evidence-readiness guard, not a statistical baseline; it prevents treating an eligible contextual source as scored evidence without a new observation rationale.",
            interpretation: "No new K4 plaintext, key material, candidate, or solution is produced. The next scoreable step would require a new source-backed rationale that changes the archive boundary, a new eligible source, or a distinct preregistered prediction artifact.",
            next_test: "Do not score `cia-artifact` from the current archive alone. First add a source-backed non-anchor observation with explicit per-position notes and archive markers, or keep it non-scorable and use a new eligible source.",
            promoted_candidate: false,
        },
        Finding {
            id: "F13",
            title: "External plaintext claims are quarantined before verification",
            related_hypothesis: "H3",
            source_inputs: &[
                "sources/archives/solvekryptos-2026-05-27.md",
                "sources/archives/smithsonian-2026-archive-discovery-2026-05-28.md",
                "sources/source-packet.md",
                "src/claim.rs",
                "src/data.rs",
                "src/main.rs",
                "tests/cli_e2e.rs",
            ],
            transformation_steps: &[
                "register external solution claims with allowed_use unverified-solution-claim",
                "archive claim metadata and boundary language without copying claimed plaintext",
                "register institutional archive-discovery reporting as context-only provenance rather than scoreable evidence",
                "verify local claim files with length, public-anchor, and aggregate shift diagnostics only",
                "verify local claim reconciliation tables with row, ciphertext, optional coordinate, numeric-letter, and shift/gate arithmetic, public-anchor, and aggregate shift diagnostics only",
                "screen the public SolveKryptos claim through a temporary local file that is deleted after verification",
                "screen the public SolveKryptos canonical bundle reconciliation table from /private/tmp without committing plaintext-bearing files",
                "screen the public SolveKryptos canonical bundle files from /private/tmp with repo ciphertext, plaintext length-only, reconciliation, R/r grid, gate-map, Z2 handoff, and public-anchor cross-checks",
                "reject non-quarantined source IDs for plaintext-claim verification",
                "surface quarantined claim sources and the safe verifier commands in next-evidence-gate",
            ],
            output_summary: "The SolveKryptos claim is registered as a quarantined external claim, and the Smithsonian 2026 archive-discovery article is registered as context-only provenance. The public claim text passes the narrow local structure check: 97 normalized letters, 4/4 public anchors preserved, all 26 implied shift values present, 71 repeated shift values, and maximum shift bucket count 8. The public canonical bundle reconciliation table also passes the local quarantine check from a temporary `/private/tmp` download: 97 rows, 97/97 K4 ciphertext alignment, 97/97 tier values, 97/97 lane values, 97/97 checked `R` values, 97/97 binary gate values, 97/97 checked `r + gate` values, 31/31 checked Z2 handoff values, and 4/4 registered public anchors preserved. The bundle-level check also cross-checks the required local files, repo ciphertext, plaintext length only, reconciliation table, 97/97 `R` grid values, 97/97 `r` grid values, and 97/97 gate-map values. The checks use temporary local files only, do not print or store the claimed plaintext or plaintext-bearing table, and next-evidence-gate reports the claim source separately from scoreable observation sources.",
            baseline_comparison: "This is an intake and leakage-control gate, not evidence for a solution; public-anchor compatibility remains a minimum structural check and cannot promote a candidate.",
            interpretation: "The external claim is compatible with the currently registered public anchors and its published reconciliation table is internally compatible with the repo's arithmetic verifier, but these checks do not independently derive the table, validate the claimed physical helper stream, or verify the claimed mechanism.",
            next_test: "Do not promote the claim from length/anchor, table-shape compatibility, archive-discovery reporting, canonical-bundle reconciliation, or bundle-file cross-checks. Any follow-up must implement an independent mechanical verifier for the claimed physical helper stream or obtain independent non-anchor evidence before adding source-derived hypothesis or candidate material.",
            promoted_candidate: false,
        },
        Finding {
            id: "F14",
            title: "Ciphertext-only period profile is weak after shuffled controls",
            related_hypothesis: "H3",
            source_inputs: &[
                "src/ciphertext_profile.rs",
                "src/main.rs",
                "tests/cli_e2e.rs",
                "experiments/PROGRESS_LOG.md",
            ],
            transformation_steps: &[
                "profile public K4 ciphertext letters without anchors or candidate material",
                "compute letter frequencies, repeated n-grams, repeated n-gram gap-factor support, overall index of coincidence, and shifted period coincidence rates",
                "shuffle ciphertext letters with a deterministic seed and record the best repeated n-gram gap-factor support and best shifted period-match rate across the scanned period range",
                "emit a planning-only ciphertext-structure prior for future source-backed non-anchor observations",
                "score the CIA row-boundary source-backed non-anchor observation file against the planning-only prior with same-size non-anchor position-shuffle controls",
            ],
            output_summary: "The ciphertext-only profile over periods 1 through 20 reports overall IC 0.0361, a best repeated n-gram spacing factor at period 2 with 7/10 supported gaps, and a best shifted period signal at period 7 with 9/90 matches. The 100000-iteration seeded null gives spacing p=0.0568 and shifted-period p=0.0719; ciphertext-structure-prior records periods 2 and 7 as future-observation priors only. The source-backed CIA row-boundary observation scores best at period 2 residue 0 with 4/6 hits, but the same-size non-anchor position-shuffle null gives empirical p=0.6845 over 100000 iterations.",
            baseline_comparison: "The repeated n-gram spacing and shifted-period signals are each compared against seeded ciphertext-only shuffles that preserve the K4 letter multiset and scan the same period range. The row-boundary prior evaluation is compared against seeded same-size shuffles over the non-anchor position universe.",
            interpretation: "The period-2 spacing factor and period-7 shifted coincidence are weak diagnostic leads only, and the first source-backed prior evaluation is negative. They are not independently significant, not plaintext, not a key, and not promoted candidates.",
            next_test: "Stop mining this ciphertext-prior lane unless a genuinely independent source-backed observation or mechanically independent model predicts the same structure before scoring.",
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
                    .is_some_and(|name| {
                        name.starts_with("non-anchor-position-")
                            || name.starts_with("tableau-hill-")
                    })
                    && path
                        .extension()
                        .is_some_and(|extension| extension == "json")
            })
            .map(|path| path.display().to_string())
            .collect()
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
