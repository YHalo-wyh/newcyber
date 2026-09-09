# Batch43 real SCA retest — gap record

Retest baseline: `d82118f`.

Observed on the real side-channel challenge bundle:

- Autopilot discovers seven relevant artifacts, including both power traces, `solve_template`, SafeTensors and the previously converted `model.onnx` oracle.
- The active stop remains `ARTIFACT_ROLE_GAP: 缺少可证明的 profileTokenIds 工件`.
- Legacy SCA budgets remain `MAX_PROFILE_ROWS=8192`, `MAX_LEAKAGE_DIM=1024`, `MAX_TOTAL_PROFILE_TOKENS=262144`.
- The real leakage structure is 287,424 raw rows and source evidence resolves it as 5,988 tokens × 48 groups/token; each group corresponds to 16 hidden dimensions. The grouped path must process this as streaming groups, not as one 3,072-dimensional leakage vector.

Important implementation finding after code review:

- Batch42 already added `sca_autopilot_batch42`, `npy_row_source` and `sca_grouped_leakage` and production surfaces point at that wrapper.
- However `sca_autopilot_batch42.runScaAutopilotPaths()` only falls back to the grouped path for a narrow set of legacy trace/layout/budget gaps. `ARTIFACT_ROLE_GAP` is not in that set.
- Therefore a real bundle that first fails on missing `profileTokenIds` never reaches grouped-layout/object-array/free-probe diagnostics.
- The existing Batch42 free-probe path removes the need for a known *prompt prefix* after target hidden-state recovery; it does **not** remove the need for profiling labels used to fit leakage→hidden mappings.

Batch46 should therefore avoid pretending T1–T3 are absent. The real missing work is:

1. route real `profileTokenIds` role gaps into the advanced SCA diagnostic path;
2. distinguish `PROFILE_LABEL_SOURCE_GAP` from generic artifact discovery failure;
3. recover profiling token IDs only when source/manifest/text evidence proves them; never assume identity/order;
4. add a real-shape regression reproducing 287,424 = 5,988 × 48 and asserting the advanced grouped path is reached;
5. keep the old conservative behavior when profiling labels truly cannot be derived.
