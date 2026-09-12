# Batch104 — Integration Writer / Registry Patch Executor

Batch104 closes the gap between Batch103's virtual integration simulation and a real repository change.

The writer only accepts an integration-gate result with:

- schema `newcyber.ai-training-integration-gate.v1`
- status `ready-to-integrate`
- `readyToIntegrate: true`

It then derives a deterministic registry descriptor from the candidate signature and produces four repository writes:

1. generated corpus artifact
2. generated regression test
3. generated provenance/regression document
4. an updated `src/core/ai_training_curriculum.js` with an exact import and `CORPORA` registry entry

## Safety and drift controls

The writer rejects:

- corpus paths outside `src/core/*.js`
- path traversal or malformed paths
- duplicate import symbols
- duplicate module registrations
- duplicate registry ids
- missing curriculum anchors
- artifact path collisions reported by the caller
- malformed Batch103 results

The write plan carries a SHA-256 precondition for the curriculum source used to construct the patch. Callers must refuse to apply the plan if the branch changed underneath it.

## Post-write verification

`verifyIntegratedResult` compares the persisted curriculum against the Batch103 simulation. Verification succeeds only when:

- the candidate `event|challenge|family` signature appears exactly once
- total curriculum case count increased by exactly one
- the actual quality / holdout / scheduler delta exactly equals the Batch103 simulated delta
- no curriculum source errors are present
- `ai-training-full-regression` reports zero suite errors and the same case count
- repository tests are explicitly reported as passed

A simulation/persistence mismatch produces `integration-drift` and must not be finalized.

Pipeline after Batch104:

`public evidence -> evidence intake -> synthetic skeleton -> evaluator dry-run -> virtual integration gate -> deterministic repository write plan -> full test/regression -> exact delta verification`

This keeps generated training cases auditable and prevents a registry edit, concurrent branch change, accidental extra corpus registration, or metric drift from silently turning a simulated improvement into a different persisted curriculum.
