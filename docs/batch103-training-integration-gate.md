# Batch103 — Training Integration Gate

Batch103 adds a pre-commit integration simulation between `ready-to-commit` materialized regressions and the persistent training curriculum.

The gate does **not** mutate `ai_training_curriculum.js`. Instead, it normalizes the materialized corpus entry, virtually appends it to the current case set, then recomputes:

- training quality
- cross-event holdout plans
- training scheduler

The candidate is accepted as `ready-to-integrate` only when all of the following are true:

1. Batch102 materializer returned `ready-to-commit`.
2. The candidate has event, challenge, direction and family metadata.
3. Its `event|challenge|family` signature is not already present.
4. Quality score does not decrease.
5. Duplicate ratio does not increase.
6. Existing holdout eligibility and clean/unseen-family plans do not regress.
7. At least one meaningful coverage dimension improves: quality score, effective coverage, event diversity, family diversity, holdout eligibility, or unseen-family holdout coverage.

A unique challenge that only increases raw count without improving those dimensions returns `no-meaningful-gain` and produces no patch.

When accepted, the planner returns a patch plan containing the already validated corpus/test/doc artifacts and a separate registry action for `src/core/ai_training_curriculum.js`. Registry mutation intentionally remains a later step because repository tests and curriculum recomputation must happen after the files are written.

This keeps the pipeline conservative:

`public evidence -> evidence intake -> synthetic skeleton -> materializer dry-run -> virtual curriculum integration -> repository integration`

The gate is a curriculum-health simulation, not proof that a new regression improves model capability on unseen real-world attacks.
