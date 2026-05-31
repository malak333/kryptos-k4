use crate::{
    BaselineAlphabetScope, BaselineRun, BaselineTargetScope, ConstraintAnalysis, K4_CIPHERTEXT,
    ReleaseCheck, analyze_constraints, analyze_known_plaintext_spans, candidate_sequences,
    hypotheses, known_anchors, known_plaintext_spans, run_baseline, run_release_checks_for_report,
    run_route_experiments, score_candidate_sequences, sources,
};
use anyhow::Result;
use serde::Serialize;

const REPORT_BASELINE_ITERATIONS: usize = 10_000;
const REPORT_BASELINE_SEED: u64 = 42;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Markdown,
    Json,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub ciphertext: &'static str,
    pub ciphertext_length: usize,
    pub anchors: Vec<crate::Anchor>,
    pub known_plaintext_spans: Vec<crate::KnownPlaintextSpan>,
    pub sources: Vec<crate::Source>,
    pub constraints: Vec<ConstraintAnalysis>,
    pub span_constraints: Vec<ConstraintAnalysis>,
    pub hypotheses: Vec<crate::Hypothesis>,
    pub candidate_sequences: Vec<crate::CandidateSequence>,
    pub candidate_sequence_scores: Vec<crate::CandidateSequenceScore>,
    pub route_experiments: Vec<crate::RouteExperiment>,
    pub baseline: BaselineRun,
    pub release_checks: Vec<ReleaseCheck>,
    pub findings: Vec<crate::Finding>,
}

pub fn build_report() -> Result<Report> {
    Ok(Report {
        ciphertext: K4_CIPHERTEXT,
        ciphertext_length: K4_CIPHERTEXT.len(),
        anchors: known_anchors(),
        known_plaintext_spans: known_plaintext_spans(),
        sources: sources(),
        constraints: analyze_constraints()?,
        span_constraints: analyze_known_plaintext_spans()?,
        hypotheses: hypotheses(),
        candidate_sequences: candidate_sequences(),
        candidate_sequence_scores: score_candidate_sequences()?,
        route_experiments: run_route_experiments()?,
        baseline: run_baseline(
            BaselineTargetScope::All,
            BaselineAlphabetScope::All,
            REPORT_BASELINE_ITERATIONS,
            REPORT_BASELINE_SEED,
        )?,
        release_checks: run_release_checks_for_report(env!("CARGO_MANIFEST_DIR"))?,
        findings: crate::findings(),
    })
}

pub fn render_report(report: &Report, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Markdown => Ok(render_markdown(report)),
        ReportFormat::Json => Ok(serde_json::to_string_pretty(report)?),
    }
}

fn render_markdown(report: &Report) -> String {
    let mut output = String::new();

    output.push_str("# Kryptos K4 Constraint Report\n\n");
    output.push_str(
        "This report uses public anchors only and is not a claimed solution. Production readiness here means the local, source-grounded research CLI and release package are repeatable and bounded; it does not mean Kryptos K4 is solved or that any candidate plaintext, key, route, or method is promoted.\n\n",
    );
    output.push_str("## Research Boundary and Production Readiness\n\n");
    output.push_str(
        "- Evidence boundary: public ciphertext, public known-plaintext anchors, source provenance, deterministic controls, and pre-registered exploratory screens only.\n",
    );
    output.push_str(
        "- Research boundary: no generated plaintext is treated as decoded K4 text; all promoted-candidate flags remain false unless independent corroboration and stronger samples justify a future change.\n",
    );
    output.push_str(
        "- Production-readiness scope: local Rust CLI, report rendering, JSON output, candidate registry alignment, source packet/source registry field and access-date alignment, release preflight, and no-GitHub-Actions policy. External publication, peer review, and cryptanalytic validation remain outside this report.\n\n",
    );

    output.push_str("## Feature Coverage\n\n");
    output.push_str(
        r#"| Feature | Included result |
| --- | --- |
| `facts` | Ciphertext length, ciphertext, and evidence boundary in Markdown or JSON. |
| `ciphertext-profile` | Ciphertext-only frequency, repeated n-gram spacing, index-of-coincidence, period-coincidence diagnostics, and optional seeded shuffle baselines without anchors, candidate material, claimed plaintext, or promotion in Markdown or JSON. |
| `ciphertext-structure-prior` | Planning-only ciphertext-derived position prior for future source-backed observations, selecting weak ciphertext-only diagnostics without treating them as evidence in Markdown or JSON. |
| `evaluate-ciphertext-prior` | Source-backed non-anchor position evaluator for the planning-only ciphertext-derived prior, with seeded same-size non-anchor position-shuffle controls and optional self-contained archives for observations, linked source review, result, summary, and replay command in Markdown or JSON. |
| `ciphertext-hotspot-prior` | Planning-only ciphertext hotspot prior for future source-backed observations, fixing top repeated-ngram and shifted-coincidence endpoint positions without treating them as evidence in Markdown or JSON. |
| `evaluate-ciphertext-hotspot` | Source-backed non-anchor position evaluator for the committed ciphertext-hotspot prior, with seeded same-size non-anchor position-shuffle controls and optional self-contained archives in Markdown or JSON. |
| `ciphertext-repeat-distance-prior` | Planning-only ciphertext repeat-distance prior for future source-backed observations, fixing same-symbol repeat-distance non-anchor positions without treating them as evidence in Markdown or JSON. |
| `ciphertext-adjacent-contrast-prior` | Planning-only ciphertext adjacent-contrast prior for future source-backed observations, fixing high left/right neighbor-contrast non-anchor positions without treating them as evidence in Markdown or JSON. |
| `ciphertext-turning-point-prior` | Planning-only ciphertext turning-point prior for future source-backed observations, fixing local extrema/high-curvature non-anchor positions from Kryptos-alphabet ciphertext only in Markdown or JSON. |
| `ciphertext-window-balance-prior` | Planning-only ciphertext local-window balance prior for future source-backed observations, fixing centered-window balance non-anchor positions from Kryptos-alphabet ciphertext only in Markdown or JSON. |
| `anchors` | Public known-plaintext anchors with positions, source IDs, confidence, claim type, and notes in Markdown or JSON. |
| `constraints` | Per-anchor key fragments across supported alphabets and modes, with recurrence screens in Markdown or JSON. |
| `key-fragments` | The same fragment rows are rendered in full for anchors and adjacent spans in Markdown or JSON. |
| `test-key` | Proposed key material is transformed and compared against public span additive fragments at true K4 positions, with optional cyclic offset sweep and seeded sweep baseline in Markdown or JSON. |
| `explain-key` | Exact matching public-span positions, modulo caveats, descriptive pattern metrics, and composite pattern score in Markdown or JSON. |
| `batch-test-keys` | CSV candidate rows are ranked with the same public-fragment checks, optional output artifacts, and batch-level controls in Markdown or JSON. |
| `batch-test-routed-keys` | Registered route/permutation families are applied before candidate scoring, with routed search-surface controls in Markdown or JSON. |
| `heldout-key-control` | Leave-one-public-group-out candidate selection and withheld-group scoring with seeded null controls in Markdown or JSON. |
| `summarize-key-runs` | Historical scanner for batch result folders, ranking individual runs and per-candidate p-value stability in Markdown or JSON. |
| `position-structure` | Candidate-independent residue/spacing control over public fragment positions in Markdown or JSON. |
| `structural-models` | Pre-registered period-model controls over public fragment positions in Markdown or JSON. |
| `validate-preregistration` | Research-lane gate for future source evidence or independent prediction targets in Markdown or JSON. |
| `validate-prediction-artifact` | Gate confirming committed independent prediction artifacts still match their preregistration and deterministic generator, with optional `--require-unique-artifact` duplicate rejection for distinct-target work, in Markdown or JSON. |
| `independent-lane-status` | Operational summary of preregistered independent lanes, artifact validity, family summaries, unique ready prediction artifacts, duplicate artifact groups, duplicate/extra duplicate artifact lane counts, and the next source-backed observation gate in Markdown or JSON. |
| `next-evidence-gate` | Operational checklist joining lane readiness, unique/duplicate prediction-target accounting, evaluator-pending lane inventory, eligible observation sources, used/unused eligible source accounting, unused-source scored-position marker and non-scorable status, quarantined plaintext-claim source IDs with the safe verifier commands and committed claim-verification archive inventory, current evidence-archive score direction, structured archive support details including null means, an all-source-backed-archives-negative flag, machine-readable next-action/blocking-condition fields, explicit next-check commands including `--require-unique-artifact`, recommended next evidence step, required observation fields, and exact scaffold/validate/evaluate/archive commands before future source-backed scoring in Markdown or JSON. |
| `independent-evidence-status` | Archive status for source-backed period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-Stehle-regularity/ciphertext-residue-balance observation evaluations, separating valid source-backed evidence, diagnostic archives, invalid archives, no-evidence states, and per-archive score direction in Markdown or JSON. |
| `source-review-status` | Pre-score source-review artifact scanner, separating valid reviews, invalid reviews, missing review roots, and no-review states in Markdown or JSON. |
| `source-observation-status` | Pre-score source readiness table for eligible observation sources, showing source-review coverage, local archive state, scored-position marker state, existing source-backed archive usage, archived evidence support status and null means for used sources, an all-source-backed-archives-negative flag, and the allowed next action in Markdown or JSON. |
| `source-review-packet` | Pre-score source review packet for eligible observation sources, local archive status, source URLs, use boundaries, and required review steps in Markdown or JSON. |
| `source-intake-packet` | New-source intake checklist with registry fields, allowed-use boundaries, quote-free archive requirements, scoreable-evidence requirements, rejection rules, follow-up commands, and an archive template in Markdown or JSON. |
| `validate-source-archive` | Standalone gate for quote-free local source snapshots, checking registered source metadata, required archive markers, no-promotion boundary, non-scorable/scored-position consistency, and scored-position use boundaries in Markdown or JSON. |
| `source-frontier` | Source-use frontier table for every registered source, classifying scored-observation-ready, currently non-scorable, context-only, and quarantined-claim sources, with prior source-backed archive counts, all-negative archive status, support statuses for already-used sources, machine-readable frontier blockers, required next-evidence criteria, disallowed next actions, and a concise Markdown `--summary` mode before future evidence work. |
| `init-source-review` | Guarded pre-score source-review file creator that records reviewed eligible sources, local archive status, required review steps, and review notes before any observation positions are selected. |
| `validate-source-review` | Gate for pre-score source-review artifacts, checking reviewed source IDs and metadata against the registered eligible source set in Markdown or JSON. |
| `non-anchor-positions` | Non-scoring one-based K4 position universe for future source-backed observations, including excluded public anchor ranges, in Markdown or JSON. |
| `init-position-observations` | Guarded source-backed observation-file creator that writes registered-source non-anchor positions plus required per-position notes (`--position-note POS=NOTE`) only, can link a validated source-review artifact, and performs no scoring, in Markdown or JSON. |
| `observation-sources` | Focused source-use report for scored independent position observations, separating eligible public-facts sources from context-only sources in Markdown or JSON. |
| `validate-period-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before period prediction scoring in Markdown or JSON. |
| `validate-ciphertext-prior-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-prior artifact preregistration validation before ciphertext-prior scoring in Markdown or JSON. |
| `validate-ciphertext-hotspot-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-hotspot artifact preregistration validation before ciphertext-hotspot scoring in Markdown or JSON. |
| `validate-ciphertext-rarity-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-rarity artifact preregistration validation before ciphertext-rarity scoring in Markdown or JSON. |
| `validate-ciphertext-repeat-distance-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-repeat-distance artifact preregistration validation before ciphertext-repeat-distance scoring in Markdown or JSON. |
| `validate-ciphertext-adjacent-contrast-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-adjacent-contrast artifact preregistration validation before ciphertext-adjacent-contrast scoring in Markdown or JSON. |
| `validate-ciphertext-transition-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-transition artifact preregistration validation before ciphertext-transition scoring in Markdown or JSON. |
| `validate-ciphertext-skip-transition-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-skip-transition artifact preregistration validation before ciphertext-skip-transition scoring in Markdown or JSON. |
| `validate-ciphertext-turning-point-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-turning-point artifact preregistration validation before ciphertext-turning-point scoring in Markdown or JSON. |
| `validate-ciphertext-window-balance-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-window-balance artifact preregistration validation before ciphertext-window-balance scoring in Markdown or JSON. |
| `validate-ciphertext-stehle-regularity-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional ciphertext-Stehle-regularity artifact preregistration validation before Stehle-window scoring in Markdown or JSON. |
| `validate-spacing-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before spacing prediction scoring in Markdown or JSON. |
| `validate-mirror-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before mirror prediction scoring in Markdown or JSON. |
| `validate-grid-observations` | Gate for source-backed independent position observations, per-position notes, source allowed-use compatibility, linked source-review coverage, and optional prediction-artifact preregistration validation before grid-layout prediction scoring in Markdown or JSON. |
| `validate-tableau-hill-observations` | Non-scoring gate for source-backed Tableau/HILL source-map observations, per-position notes, source allowed-use compatibility, linked source-review coverage, committed source-map coverage, and padding/public-anchor rejection before `evaluate-tableau-hill-prediction` can score them in Markdown or JSON. |
| `period-prediction-plan` | Non-anchor residue-class target emission for a registered period, without scoring public fragment values, in Markdown or JSON. |
| `spacing-prediction-plan` | Non-anchor spacing residue-class target emission for registered moduli, without scoring fragment values or candidate words, in Markdown or JSON. |
| `mirror-prediction-plan` | Non-anchor mirror-pair target emission across the 97-character position axis, without scoring fragment values or candidate words, in Markdown or JSON. |
| `grid-layout-prediction-plan` | Non-anchor 7-by-14 padded grid-layout artifact emission with an explicit scored row, column, or compass axis, without scoring fragment values or candidate words, in Markdown or JSON. |
| `tableau-hill-prediction-plan` | Fixed HILL/tableau source-mapping artifact emission for source-backed row/column concentration evaluation, without scoring fragment values, candidate words, or public-anchor-derived evidence, in Markdown or JSON. |
| `evaluate-period-prediction` | Independent-position evaluator for committed period prediction artifacts with best-of-period null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-spacing-prediction` | Independent-position evaluator for committed spacing prediction artifacts with best-of-modulus null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-mirror-prediction` | Independent-position evaluator for committed mirror prediction artifacts with seeded same-size non-anchor position-set null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-grid-prediction` | Independent-position evaluator for committed 7-by-14 grid-layout artifacts with selected row, column, or compass-axis scoring, seeded same-size non-anchor position-set null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation and matching preregistered `grid_edge_axis`, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, selected edge axis, and scored observation input, and Markdown/JSON output. |
| `evaluate-tableau-hill-prediction` | Independent-position evaluator for committed Tableau/HILL 7-by-14 source-map artifacts with best row/column concentration scoring, seeded same-size non-anchor position-set null controls, diagnostic/source-backed observation status, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-rarity` | Independent-position evaluator for committed ciphertext rare-letter position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-repeat-distance` | Independent-position evaluator for committed ciphertext same-symbol repeat-distance position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-adjacent-contrast` | Independent-position evaluator for committed ciphertext adjacent-contrast position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-transition` | Independent-position evaluator for committed ciphertext adjacent-transition position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-skip-transition` | Independent-position evaluator for committed ciphertext skip-transition position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-turning-point` | Independent-position evaluator for committed ciphertext local turning-point position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-window-balance` | Independent-position evaluator for committed ciphertext local-window balance position artifacts with seeded same-size non-anchor position-set null controls, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives that preserve the artifact, preregistration, linked source-review file, and scored observation input, and Markdown/JSON output. |
| `evaluate-ciphertext-stehle-regularity` | Independent-position evaluator for the committed source-described Stehle local-regularity artifact with seeded same-size non-anchor position-set null controls over both the full window and lag-confirmed +5 subset, source-backed observation-file input that requires preregistration-backed artifact validation, optional self-contained archives, and Markdown/JSON output. |
| `validate-evaluation-archive` | Archive gate for independent observation evaluations, checking required files, matching evaluator command name, local replay command paths, artifact kind, source-backed observation consistency, archived source-review/preregistration/artifact/observation validity, and no-promotion boundaries in Markdown or JSON. |
| `baseline` | Seeded false-positive controls for anchors and spans across all supported alphabets in Markdown or JSON. |
| `hypotheses` | Ranked source-grounded hypotheses with facts, assumptions, falsification tests, and risks in Markdown or JSON. |
| `candidate-sequences` | Pre-registered contextual sequences and score results in Markdown or JSON. |
| `routes` | Bounded named route experiments with identity, reverse, and seeded-random baselines in Markdown or JSON. |
| `findings` | Reproducible findings ledger with sources, transformations, baselines, interpretation, and next tests in Markdown or JSON. |
| `sources` | Source provenance records and allowed-use notes in Markdown or JSON. |
| `verify-plaintext-claim` | Quarantined external-claim verifier that checks local plaintext-claim files for length, public-anchor compatibility, and aggregate shift diagnostics without printing or storing claim text in Markdown or JSON. |
| `verify-running-key-claim` | Quarantined external-claim verifier that checks local plaintext plus running-key-stream files for length, public-anchor compatibility, and additive ciphertext reconstruction under a selectable alphabet without printing or storing plaintext or key material in Markdown or JSON. |
| `verify-claim-reconciliation` | Quarantined external-claim reconciliation verifier that checks local tables for row count, one-based position sequence, K4 ciphertext alignment, optional published Tier/Lane, C#/P#, R/shift, BaseR, and Gate arithmetic, public-anchor compatibility, and aggregate shift diagnostics without printing or storing claimed plaintext in Markdown or JSON. |
| `verify-claim-bundle` | Quarantined external-claim bundle verifier that checks required local files, repo ciphertext, plaintext length only, reconciliation arithmetic, R/r grids, gate map, Z2 handoff, and public anchors without printing or storing claimed plaintext in Markdown or JSON. |
| `verify-claim-mechanism` | Quarantined external-claim mechanism verifier that checks published f/helper-card relationships, control-card consistency, Z2 footer handoff, Y-pass gate-template consistency, and the Z2 helper path into the r/R grids without printing or storing claimed plaintext in Markdown or JSON. |
| `release-check` | Local release preflight results, including no-GitHub-Actions, candidate CSV/registry alignment, preregistration and prediction-artifact validation, preregistration README inventory freshness, independent-lane readiness, non-scorable observation template status, committed source-backed observation-file validity, evidence-summary coverage with archived period/spacing/mirror/grid/Tableau-HILL/ciphertext-prior/ciphertext-hotspot/ciphertext-rarity/ciphertext-repeat-distance/ciphertext-period-match/ciphertext-adjacent-contrast/ciphertext-transition/ciphertext-skip-transition/ciphertext-turning-point/ciphertext-window-balance/ciphertext-Stehle-regularity/ciphertext-residue-balance command references and negative result metrics, committed source-review validity, source-readiness command documentation, findings source-input integrity, source-packet/source-registry field and latest-access-date alignment, local source-archive metadata/boundary gates including non-scorable/scored-position consistency, source-archive coverage for committed observation positions, stopped-lane documentation coverage, progress-log freshness, claim-verification archive quarantine boundaries, and plaintext-leakage sentinels across release-facing artifacts in Markdown or JSON. |
| `export-data` | Covered by the source data rendered here; the command writes ciphertext, anchor, and source JSON files. |

"#,
    );

    output.push_str("## Ciphertext\n\n");
    output.push_str(&format!(
        "- Length: {}\n- Text: `{}`\n\n",
        report.ciphertext_length, report.ciphertext
    ));

    output.push_str("## Known Anchors\n\n");
    output.push_str(
        "| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Source IDs | Confidence | Claim Type | Note |\n",
    );
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for anchor in &report.anchors {
        output.push_str(&format!(
            "| `{}` | `{}` | {}-{} | {}-{} | `{}` | {} | {} | {} |\n",
            anchor.plaintext,
            anchor.ciphertext,
            anchor.start_zero_based,
            anchor.end_zero_based_inclusive,
            anchor.start_one_based(),
            anchor.end_one_based_inclusive(),
            anchor.source_ids.join("`, `"),
            anchor.confidence,
            anchor.claim_type,
            anchor.source_note
        ));
    }

    output.push_str("\n## Known Plaintext Spans\n\n");
    output.push_str("| Plaintext | Ciphertext | 0-Based Range | 1-Based Range | Anchors |\n");
    output.push_str("| --- | --- | --- | --- | --- |\n");
    for span in &report.known_plaintext_spans {
        output.push_str(&format!(
            "| `{}` | `{}` | {}-{} | {}-{} | `{}` |\n",
            span.plaintext,
            span.ciphertext,
            span.start_zero_based,
            span.end_zero_based_inclusive,
            span.start_one_based(),
            span.end_one_based_inclusive(),
            span.anchor_plaintexts.join("`, `")
        ));
    }

    output.push_str("\n## Constraint Fragments\n\n");
    render_constraint_group(&mut output, &report.constraints);

    output.push_str("\n## Span Constraint Fragments\n\n");
    render_constraint_group(&mut output, &report.span_constraints);

    output.push_str("## Ranked Hypotheses\n\n");
    for hypothesis in &report.hypotheses {
        output.push_str(&format!(
            "{}. **{} ({})**\n   - Supporting facts: {}\n   - Required assumptions: {}\n   - Test: {}\n   - Risk: {}\n",
            hypothesis.priority,
            hypothesis.name,
            hypothesis.id,
            hypothesis.supporting_facts,
            hypothesis.required_assumptions,
            hypothesis.falsification_test,
            hypothesis.risk
        ));
    }

    output.push_str("\n## Baseline Controls\n\n");
    output.push_str(&format!(
        "{} Target: {}; alphabet: {}; iterations: {}; seed: {}.\n\n",
        report.baseline.note,
        report.baseline.target_scope,
        report.baseline.alphabet_scope,
        report.baseline.iterations,
        report.baseline.seed
    ));
    output.push_str(
        "| Target | Kind | Alphabet | Observed | Triples | Null Mean | Null SD | Empirical P | Adjusted P | Promoted | Warning |\n",
    );
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for result in &report.baseline.results {
        output.push_str(&format!(
            "| {} | {} | {:?} | {} | {} | {:.2} | {:.2} | {:.4} | {:.4} | {} | {} |\n",
            result.target_label,
            result.target_kind,
            result.alphabet,
            result.observed_matches,
            result.triples_checked,
            result.null_mean,
            result.null_std_dev,
            result.empirical_p_value,
            result.adjusted_p_value,
            result.promoted_candidate,
            result.warning
        ));
    }

    output.push_str("\n## Sources\n\n");
    for source in &report.sources {
        output.push_str(&format!(
            "- `{}` [{}]({}) - {}; type: {}; accessed {}; use: {}\n",
            source.id,
            source.label,
            source.url,
            source.use_note,
            source.source_type,
            source.accessed_at,
            source.allowed_use
        ));
    }

    output.push_str("\n## Candidate Sequences\n\n");
    output.push_str(
        "Pre-registered contextual candidates only; no candidate is a claimed solution.\n\n",
    );
    for candidate in &report.candidate_sequences {
        output.push_str(&format!(
            "- `{}` {:?} {:?}: `{}` values={:?} sources=`{}`\n",
            candidate.id,
            candidate.family,
            candidate.transform,
            candidate.raw_material,
            candidate.values,
            candidate.source_ids.join("`, `")
        ));
    }

    output.push_str("\n## Candidate Sequence Scores\n\n");
    output.push_str("| Candidate | Family | Compared Fragments | Exact Mod-26 Matches | Match Rate | Promoted | Note |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for score in &report.candidate_sequence_scores {
        output.push_str(&format!(
            "| `{}` | {:?} | {} | {} | {:.3} | {} | {} |\n",
            score.candidate_id,
            score.family,
            score.compared_fragment_count,
            score.exact_mod26_matches,
            score.match_rate,
            score.promoted_candidate,
            score.note
        ));
    }

    output.push_str("\n## Route Experiments\n\n");
    output.push_str("Exploratory named route screens only; no decryption text is emitted.\n\n");
    for experiment in &report.route_experiments {
        output.push_str(&format!(
            "- {:?} / {}: score={} identity={} reverse={} seeded_random={} promoted={}\n",
            experiment.route,
            experiment.target_label,
            experiment.score,
            experiment.identity_baseline,
            experiment.reverse_baseline,
            experiment.seeded_random_baseline,
            experiment.promoted_candidate
        ));
    }

    output.push_str("\n## Findings Ledger\n\n");
    output.push_str(
        "Findings are reproducible research observations, not promoted solution claims.\n\n",
    );
    for finding in &report.findings {
        output.push_str(&format!(
            "- **{} {} ({})**\n  - Sources: `{}`\n  - Steps: {}\n  - Output: {}\n  - Baseline: {}\n  - Interpretation: {}\n  - Next test: {}\n  - Promoted: {}\n",
            finding.id,
            finding.title,
            finding.related_hypothesis,
            finding.source_inputs.join("`, `"),
            finding.transformation_steps.join("; "),
            finding.output_summary,
            finding.baseline_comparison,
            finding.interpretation,
            finding.next_test,
            finding.promoted_candidate
        ));
    }

    output.push_str("\n## Release Check\n\n");
    output.push_str("Local preflight only. This repo does not use GitHub Actions.\n\n");
    for check in &report.release_checks {
        output.push_str(&format!(
            "- {}: {} ({})\n",
            check.name, check.passed, check.detail
        ));
    }

    output
}

fn render_constraint_group(output: &mut String, constraints: &[ConstraintAnalysis]) {
    for analysis in constraints {
        output.push_str(&format!(
            "### {} / {:?}\n\n",
            analysis.target.label, analysis.alphabet.kind
        ));
        output.push_str("| Pos | P | C | Mode | Value | Symbol |\n");
        output.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for fragment in &analysis.fragments {
            output.push_str(&format!(
                "| {} | `{}` | `{}` | {:?} | {} | `{}` |\n",
                fragment.position_one_based,
                fragment.plaintext,
                fragment.ciphertext,
                fragment.mode,
                fragment.value,
                fragment.symbol
            ));
        }
        output.push_str(&format!(
            "\nRecurrence screen: {}/{} local additive triples matched generic mod-10 recurrence. Expected random matches: {:.1}. Promoted: {}. Warning: {}\n\n",
            analysis.recurrence.gromark_sum_matches, analysis.recurrence.contiguous_pairs_checked
            , analysis.recurrence.expected_random_matches, analysis.recurrence.promoted_candidate, analysis.recurrence.sample_warning
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_report_contains_core_sections() {
        let report = build_report().unwrap();
        let rendered = render_report(&report, ReportFormat::Markdown).unwrap();

        assert!(rendered.contains("## Known Anchors"));
        assert!(rendered.contains("## Known Plaintext Spans"));
        assert!(rendered.contains("## Ranked Hypotheses"));
        assert!(rendered.contains("## Candidate Sequences"));
        assert!(rendered.contains("## Candidate Sequence Scores"));
        assert!(rendered.contains("## Route Experiments"));
        assert!(rendered.contains("## Findings Ledger"));
        assert!(rendered.contains("## Baseline Controls"));
        assert!(rendered.contains("## Release Check"));
        assert!(rendered.contains("Production-readiness scope"));
        assert!(rendered.contains("Source IDs"));
        assert!(rendered.contains("BERLIN"));
    }
}
