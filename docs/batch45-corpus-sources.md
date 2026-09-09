# Batch45 AI Stage-One Corpus V2 — verified source notes

This note records the competition-oriented sources added after the five-direction syllabus was confirmed. It is intentionally provenance-first: importers should fetch or mount upstream data instead of vendoring large datasets into Git.

## Prompt engineering / LLM security

- HackAPrompt 1.0 — large-scale prompt hacking competition corpus.
- Tensor Trust — human prompt-injection attack/defense game dataset; use upstream-source grouped split to avoid near-duplicate leakage.
- Prompt Airlines — progressive system-prompt/secret-extraction challenge; replay as held-out challenge cases, not answer memorization.
- Lakera Gandalf — use the public `gandalf_ignore_instructions` dataset plus challenge-level replay fixtures.
- AgentDojo / InjecAgent — tool-integrated and indirect prompt-injection traces; preserve tool call, authorization and data-flow fields.

## Adversarial examples

- MadryLab MNIST challenge — verifier-aware L-infinity attack cases with epsilon 0.3.
- MadryLab CIFAR10 challenge — verifier-aware L-infinity challenge with canonical attack scripts and model artifacts.
- NIPS 2017 adversarial competition — targeted/untargeted/defense challenge structure.
- RobustBench — robustness benchmark and model zoo for held-out generalization.
- Domestic competition cases: 2024 羊城杯 `NLP_Model_Attack` and `Targeted_Image_adv_attacks`; fifth 湾区杯 Final `Blind` for Whisper/audio targeted transcription.

## Privacy / leakage

- Microsoft MICO — white-box membership inference across image/text/tabular plus DP distinguisher; preserve TPR@10% FPR as the primary competition metric.
- MIBench/MIDST and extraction/inversion references remain secondary breadth sources.

## Backdoor / poisoning

- NIST TrojAI — official poisoned-model datasets across multiple modalities; prioritize trigger/control behavioral evidence.
- BackdoorBench/OpenBackdoor — attack/defense breadth and hard negatives.
- 2025 长城杯 / CISCN AI cases — include the backdoor challenge, `easy_poison`, and LLM data-poisoning cases as domestic CTF distributions.

## AI infrastructure / supply chain

- ModelScan/PickleScan + AI/ML vulnerability corpora remain the primary static-safety references.
- 2025 羊城杯 `Mini-modelscope` is included as a domestic model-artifact / model-supply-chain style case.

## Split and leakage policy

1. Split train/validation/test by upstream source or competition before any mutation.
2. Do not place final flags, passwords, final exploit strings or writeup answers in model input.
3. Preserve challenge prompt, attachment metadata, source/config, verifier, tool trajectory and evidence state.
4. Keep at least 30% hard negatives.
5. Never deserialize untrusted Pickle/PyTorch artifacts merely to build an index; static/offline inspection first.
