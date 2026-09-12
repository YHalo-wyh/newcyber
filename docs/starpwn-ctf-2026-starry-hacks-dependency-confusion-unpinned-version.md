# Synthetic regression: STARPWN CTF 2026 / Starry hacks

- Direction: `infra-supply-chain`
- Family: `dependency-confusion-unpinned-version`
- Evaluator: `ai-supply-chain`
- Evidence level: `writeup-specific`
- Public source: `JonghoMoon/STARPWN-2026-Writeup`, commit `619d5555dbaeefe9de962edc1e2cc2879692a710`, `Space_Communication_and_RF/Starry_hacks/README.md`

## Public evidence admitted

The public writeup identifies the challenge as **Starry hacks** and documents three facts used by this regression: the flight application depends on `cubesat-upstream-driver>=1.0.0`; the ground-station Artifact Upload path installs an uploaded package with `pip`; and a replacement/higher-version driver can take over the imported dependency boundary.

The regression intentionally stops at that dependency-resolution property. It does not preserve or replay the public flag, environment contents, file-reading logic, command trigger, uploaded malicious package body, or any private attachment.

## Synthetic verifier

The positive fixture contains only a synthetic lower-bound requirement and must produce `dependency-not-locked`. Negative and control fixtures use an exact version pin and must remain non-finding. This checks the trust/resolution condition without reproducing the original exploit.

## Admission policy

This case may enter the curriculum only if the Batch100–104 pipeline accepts the evidence package, the materializer dry-run passes positive/negative/control assertions, the Integration Gate records structural coverage gain, repository tests pass, and the persisted curriculum reproduces the simulated delta exactly.
