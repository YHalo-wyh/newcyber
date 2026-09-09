# Batch40 Solver Pipeline

Batch40 changes the default Challenge Session from a card-oriented summary into an evidence-driven execution desk.

## State contract

- `DONE`: the corresponding analyzer/result has concrete execution evidence in the workspace analysis.
- `PARTIAL`: the solver produced a meaningful intermediate result but did not close the verifier.
- `BLOCKED`: an already-started route has an explicit capability/input gap.
- `READY`: current attachments satisfy a conservative entry condition for the deterministic capability, but there is no execution evidence yet.
- `SKIPPED`: no strong evidence justifies applying the template.

`SKIPPED` is deliberate. NewCyber must not claim a template ran merely to make the pipeline look complete.

## Primary UI

The default challenge surface is organized as:

`INPUT TREE | SOLVER TIMELINE | CONTEXT INSPECTOR`

with an expandable `EVIDENCE DOCK` below. Large colored result/fact/action card grids are not the primary visual language anymore. Status is expressed with a thin rail, small state markers, separators and text hierarchy.

## Boundaries

Batch40 does not add automatic remote networking or untrusted binary execution. Existing deterministic analyzers remain responsible for actual analysis; the pipeline records and exposes their real execution evidence, applicability and capability gaps. External/local runtime work remains gated by explicit user-provided input and the existing safe bridges.
