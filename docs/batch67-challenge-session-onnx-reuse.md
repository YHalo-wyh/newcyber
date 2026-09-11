# Batch67 — Challenge Session ONNX session reuse

Batch65 added a batch-capable local ONNX runtime, but the Challenge Session autopilot still called the single-run path once per candidate. For image/NPY contest bundles this meant repeatedly creating `InferenceSession` instances during the hot ranking path.

Batch67 changes the production Challenge Session execution path to open one ONNX inference session and stream all eligible candidates through `runWithOpenSession`. Candidate decoding/preprocessing still happens one item at a time, so NewCyber does not need to accumulate hundreds of large base64 tensors in memory just to get session reuse.

The boundary remains conservative:

- model selection and preprocessing evidence rules are unchanged;
- one failing candidate is recorded and isolated instead of aborting the whole candidate set;
- injected `runModel` test/integration hooks keep their previous semantics and do not unexpectedly open a native runtime session;
- result metadata now exposes the inference strategy, attempted/succeeded/failed counts, and whether the production inference stage created one reusable session.

The optimized production path is therefore:

`candidate -> decode/preprocess -> feed -> same ONNX session -> output -> next candidate -> ranking -> verifier`

This is an inference-stage optimization only. Model inspection may still create separate short-lived sessions while selecting among multiple ONNX models; those are not counted as candidate inference sessions.
