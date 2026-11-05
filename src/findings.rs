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
            title: "Independent-lane phase is closed and negative",
            related_hypothesis: "H3",
            source_inputs: &[
                "docs/negative-results.md",
                "experiments/position-observations/cia-k4-row-boundaries-v1.json",
                "sources/archives/cia-sculpture-2026-05-27.md",
            ],
            transformation_steps: &[
                "record CIA sculpture web-page row-boundary positions 1, 4, 5, 36, 37, and 97 as the only source-backed non-anchor observation",
                "score that observation against 26 distinct preregistered position models (period, spacing, mirror, grid, Tableau/HILL, and ciphertext-only priors) with seeded same-size position-shuffle nulls",
                "prune 60 duplicate or escalating-variant lanes and their archives in the slim-down; history is preserved at git tag pre-slimdown",
            ],
            output_summary: "None of the 26 surviving archives is significant: the lowest raw empirical p is 0.1303 (grid column edge, 4/6 hits). The lowest raw p anywhere in the phase, p=0.0436 (terminal residue balance), came from a pruned parameter variant and was p=1.0000 after correcting for the archives searched.",
            baseline_comparison: "Every archive used seeded same-size non-anchor position-shuffle or best-of-model nulls (seed 67, 100000 iterations unless the archive says otherwise).",
            interpretation: "The row-boundary observation is a web-page layout artifact with six positions, so it has almost no power. These nulls say little about K4 itself and mainly show this observation should not be scored again.",
            next_test: "Do not add models against this observation. Score future methods by reproducing all 24 public anchor letters, which happens by chance with probability about 26^-24.",
            promoted_candidate: false,
        },
        Finding {
            id: "F6",
            title: "Methodology context stops repeated single-layer search mining",
            related_hypothesis: "H1/H2/H3/H4/H5",
            source_inputs: &[
                "kryptosbot-methodology-2026",
                "docs/negative-results.md",
                "docs/research-plan.md",
            ],
            transformation_steps: &[
                "register methodology context with a non-scored allowed-use boundary",
                "compare it against completed batch, routed, and structural controls",
                "record saturated search families as stopped unless a preregistration narrows the target before scoring",
            ],
            output_summary: "Simple single-layer, word-list, route, and uncorrected best-of-search lanes are documented as stopped for current evidence.",
            baseline_comparison: "The stopped-lane decision is backed by existing negative batch-level, routed, and structural controls rather than a new positive score.",
            interpretation: "Methodology context improves research discipline, but it is not plaintext, candidate evidence, or an independent scored observation.",
            next_test: "Do not reopen a stopped search family on the same inputs. Test a concrete cipher method by whether it reproduces all 24 public anchor letters; a miss eliminates it.",
            promoted_candidate: false,
        },
        Finding {
            id: "F13",
            title: "External plaintext claims are quarantined before verification",
            related_hypothesis: "H3",
            source_inputs: &[
                "sources/archives/solvekryptos-2026-05-27.md",
                "sources/archives/ssrn-bonifacino-running-key-2025-2026-05-31.md",
                "sources/archives/smithsonian-2026-archive-discovery-2026-05-28.md",
                "sources/source-packet.md",
                "results/claim-verifications",
                "src/claim.rs",
            ],
            transformation_steps: &[
                "register external solution claims with allowed_use unverified-solution-claim",
                "archive claim metadata and boundary language without copying claimed plaintext",
                "register institutional archive-discovery reporting as context-only provenance rather than scoreable evidence",
                "verify local claim files with length, public-anchor, aggregate shift, and optional running-key reconstruction checks only, from temporary files outside the repo",
            ],
            output_summary: "The SolveKryptos and SSRN running-key claims are registered as quarantined external claims, and the Smithsonian 2026 archive-discovery article is context-only provenance. The public SolveKryptos claim text passes the narrow local structure check: 97 normalized letters and 4/4 public anchors preserved. Before the slim-down, dedicated verifiers (preserved at git tag pre-slimdown) also checked the SolveKryptos canonical bundle and mechanism files: the reconciliation table and bundle grids were internally consistent, but the Y-pass template layer matched only 27/31 rule checks, with disagreements at K4 positions 27, 31, 32, and 33, and the template's declared zero positions disagree with its printed rule. No claimed plaintext or key stream is printed or stored.",
            baseline_comparison: "This is an intake and leakage-control gate, not evidence for a solution; public-anchor compatibility is a minimum structural check and cannot promote a candidate.",
            interpretation: "The external claim is compatible with the public anchors, but its published helper machinery is not fully self-consistent. None of these checks validates a physical helper-stream reading or the claimed mechanism as independent evidence.",
            next_test: "Do not promote any claim from anchor compatibility or file-consistency checks. A follow-up must independently validate the claimed mechanism or obtain independent non-anchor evidence.",
            promoted_candidate: false,
        },
        Finding {
            id: "F14",
            title: "Ciphertext-only period profile is weak after shuffled controls",
            related_hypothesis: "H3",
            source_inputs: &[
                "src/ciphertext_profile.rs",
                "results/ciphertext-prior-observations/cia-k4-row-boundaries-v1",
            ],
            transformation_steps: &[
                "profile public K4 ciphertext letters without anchors or candidate material",
                "compute letter frequencies, repeated n-grams, repeated n-gram gap-factor support, overall index of coincidence, and shifted period coincidence rates",
                "shuffle ciphertext letters with a deterministic seed and record the best repeated n-gram gap-factor support and best shifted period-match rate across the scanned period range",
                "score the CIA row-boundary observation against the period-2/period-7 prior with same-size non-anchor position-shuffle controls (archived; scorer preserved at git tag pre-slimdown)",
            ],
            output_summary: "The ciphertext-only profile over periods 1 through 20 reports overall IC 0.0361, a best repeated n-gram spacing factor at period 2 with 7/10 supported gaps, and a best shifted period signal at period 7 with 9/90 matches. The 100000-iteration seeded null gives spacing p=0.0568 and shifted-period p=0.0719; periods 2 and 7 were recorded as priors only. The source-backed CIA row-boundary observation scores best at period 2 residue 0 with 4/6 hits, but the same-size non-anchor position-shuffle null gives empirical p=0.6845 over 100000 iterations.",
            baseline_comparison: "The repeated n-gram spacing and shifted-period signals are each compared against seeded ciphertext-only shuffles that preserve the K4 letter multiset and scan the same period range. The row-boundary prior evaluation is compared against seeded same-size shuffles over the non-anchor position universe.",
            interpretation: "The period-2 spacing factor and period-7 shifted coincidence are weak diagnostic leads only, and the first source-backed prior evaluation is negative. They are not independently significant, not plaintext, not a key, and not promoted candidates.",
            next_test: "Stop mining ciphertext-only priors; test concrete cipher methods against the public anchors instead.",
            promoted_candidate: false,
        },
        Finding {
            id: "F15",
            title: "Anchor reproduction eliminates the classical periodic, autokey, Gromark, and bounded columnar families",
            related_hypothesis: "H1/H2/H3",
            source_inputs: &[
                "elonka-kryptos",
                "histocrypt-2021-bean",
                "src/eliminate.rs",
                "results/eliminations/anchor-elimination-v1",
            ],
            transformation_steps: &[
                "derive structural facts from the 24 public anchor letters alone",
                "for each configuration (family, alphabets, sign, period or lag, transposition), list the anchor checks a correct configuration must pass and eliminate it on any failure",
                "use 37 keyed alphabets fixed before scoring (standard plus 36 Kryptos, clue, and theme keywords) in every plaintext/ciphertext pairing",
                "record the probability that a random configuration passes the same checks, and sum it into the survivors expected by chance",
                "confirm with planted synthetic encryptions that each checker keeps a true key",
            ],
            output_summary: "No pure transposition fits (the anchors need three E but K4 has two). Porta and any cipher without self-encryption are impossible (anchor letters encrypt to themselves at one-based 33 and 74). No periodic substitution with any alphabets fits at periods 1-7, 9, 10, 14, 15, 17, 21, 25, 34, 42, 43, or 45. Over 15.5 million configurations, Gronsfeld (2886), ciphertext autokey (421356), Gromark with lag 2-12 mod 10 or 26 (90354), and keyed columnar width 2-8 before or after a periodic tableau of period 1-13 (14424384) have zero survivors. Periodic tableaux and Quagmire I-IV with period 1-26 leave 188 survivors against 158.2 expected by chance, none passing more than one check; plaintext autokey with lag 1-52 leaves 1261 against 960.4 expected, none passing more than three.",
            baseline_comparison: "Each check carries its chance pass probability (1/26 for a letter equality, 10/26 for a digit-range check, 1/10 for a mod-10 recurrence). Survivor counts match the chance expectation, and the best survivor of any family has chance probability above 5e-5 among hundreds of thousands of configurations.",
            interpretation: "Within the registered alphabets and bounds, these families cannot produce K4. The result is limited to the 37 alphabets and the stated periods, lags, and widths; arbitrary unkeyed alphabets, longer transposition keys, and other families remain open.",
            next_test: "Run running-key offsets over a fixed public corpus with running-key, and extend elimination to route transpositions and non-keyword alphabets.",
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
    fn finding_source_inputs_are_registered_sources_or_files() {
        let registered_source_ids: HashSet<_> =
            sources().into_iter().map(|source| source.id).collect();

        for finding in findings() {
            for source_input in finding.source_inputs {
                assert!(
                    registered_source_ids.contains(source_input)
                        || Path::new(source_input).exists(),
                    "finding {} references unknown source input `{}`",
                    finding.id,
                    source_input
                );
            }
        }
    }
}
