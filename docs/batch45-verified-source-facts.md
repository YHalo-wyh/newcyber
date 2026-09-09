# Verified source facts used by Batch45 adapters

- Tensor Trust: official project/data releases provide a large human-generated prompt-injection attack/defense corpus. Treat raw submissions, benchmark splits and defenses as the same upstream source group for leakage-safe splitting.
- MadryLab MNIST challenge: L-infinity epsilon is 0.3 and challenge samples use the MNIST test set.
- MadryLab CIFAR10 challenge: canonical configuration uses epsilon 8 pixel levels and attack arrays are verifier-checked.
- Microsoft MICO: four tracks cover image, text, tabular and DP distinguisher scenarios; primary competition score is TPR at 10% FPR.
- NIST TrojAI: datasets contain clean and poisoned trained models with withheld triggers for trojan-detection research.
- 2025 长城杯/CISCN archive publicly lists AI security challenges including the credit-card fraud backdoor challenge.
- Fifth 湾区杯 Final `Blind`: Whisper audio adversarial optimization is used to drive a target transcription into a downstream command-injection chain.
- 2024 羊城杯 undergraduate archive lists `NLP_Model_Attack` and `Targeted_Image_adv_attacks` under AI.
