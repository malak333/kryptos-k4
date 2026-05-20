# Research Method

The project follows the source-led plan in `kryptos-k4-research-plan.md`.

## Operating Rules

1. Preserve strict source provenance for all facts.
2. Separate public facts from assumptions and hypotheses.
3. Treat the 2025 archive/plaintext discovery as historical context only.
4. Do not include claimed full plaintext content.
5. Promote a hypothesis only when it produces a falsifiable next test.

## Current Implementation Boundary

The CLI implements the first production slice:

- canonical public data;
- machine-readable exports for ciphertext, anchors, and source provenance;
- source IDs, confidence labels, and allowed-use notes for public facts;
- anchor normalization;
- alphabet-specific constraint extraction;
- adjacent-span analysis and generic mod-10 recurrence screening with random-baseline warnings;
- ranked hypothesis reporting;
- Markdown/JSON output.

It does not attempt unconstrained key search or claim decryption.

## E2E Coverage

The integration tests in `tests/cli_e2e.rs` execute the compiled CLI and verify:

- anchor output includes known public anchors and positions;
- constraint output includes alphabet-specific fragments and recurrence warnings;
- Markdown report generation writes a complete report;
- JSON report output is parseable and includes the expected top-level sections;
- source-provenance fields remain attached to anchor and source output.
