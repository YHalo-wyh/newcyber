'use strict';

// Batch45 expansion: sources explicitly selected for competition-oriented training.
// Keep this metadata-only. Importers must obey upstream licences/competition terms,
// strip final flags/answers from training input, and never execute untrusted artifacts.

function src(id,direction,tier,title,url,extra={}){
  return Object.freeze({id,direction,tier,title,url,...extra});
}

const AI_STAGE1_SOURCE_EXPANSION=Object.freeze([
  // Prompt engineering / LLM security — large human attack corpora + live challenges.
  src('tensortrust-data','prompt-llm-security','A','Tensor Trust dataset','https://github.com/HumanCompatibleAI/tensor-trust-data',{
    kind:'competition-game-dataset',scale:'563k+ attacks · 118k+ defenses (ICLR 2024 paper corpus)',
    modalities:['text','attack','defense','game-trajectory'],families:['prompt-hijacking','prompt-extraction','defense-bypass'],priority:100,importMode:'dataset'
  }),
  src('prompt-airlines','prompt-llm-security','A','Prompt Airlines','https://promptairlines.com/',{
    kind:'live-challenge',modalities:['text','system-prompt','conversation'],families:['system-prompt-extraction','secret-leakage','progressive-defense'],priority:94,importMode:'challenge-replay',license:'challenge-terms'
  }),
  src('gandalf-ignore-instructions','prompt-llm-security','A','Lakera Gandalf · Ignore Instructions dataset','https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions',{
    kind:'challenge-dataset',scale:'1k filtered prompt-injection samples',modalities:['text'],families:['prompt-injection','secret-extraction','obfuscation'],priority:98,importMode:'dataset',license:'MIT'
  }),
  src('gandalf-live','prompt-llm-security','A','Lakera Gandalf challenge','https://gandalf.lakera.ai/',{
    kind:'live-challenge',modalities:['text','conversation'],families:['progressive-defense','secret-extraction','output-filter-bypass'],priority:94,importMode:'challenge-replay',license:'challenge-terms'
  }),

  // Adversarial examples — canonical challenge formats with real verifiers/budgets.
  src('madry-mnist-challenge','adversarial-example','A','MadryLab MNIST Adversarial Examples Challenge','https://github.com/MadryLab/mnist_challenge',{
    kind:'competition-challenge',scale:'10,000 test samples · L∞ epsilon 0.3',modalities:['image','model','npy'],families:['linf','pgd','fgsm','black-box','white-box'],priority:100,importMode:'challenge-bundle',license:'MIT'
  }),
  src('madry-cifar10-challenge','adversarial-example','A','MadryLab CIFAR10 Adversarial Examples Challenge','https://github.com/MadryLab/cifar10_challenge',{
    kind:'competition-challenge',scale:'10,000 test samples · L∞ epsilon 8/255-style pixel budget',modalities:['image','model','npy'],families:['linf','pgd','transfer','black-box','white-box'],priority:100,importMode:'challenge-bundle',license:'MIT'
  }),

  // Domestic CTFs — keep challenge bundles separate from writeups to avoid answer leakage.
  src('ccb-2025-ai-archive','backdoor-poisoning','A','2025 长城杯 / CISCN Quals · AI安全题集','https://github.com/CTF-Archives/2025-CCB-CISCN-Quals',{
    kind:'real-ctf-archive',modalities:['model','dataset','source','black-box-api'],families:['tabular-backdoor','data-poisoning','model-security'],priority:100,importMode:'challenge-bundle',license:'check-upstream'
  }),
  src('ccb-2025-easy-poison','backdoor-poisoning','A','2025 长城杯 · easy_poison','https://blog.qingchenyou.asia/CTF-WriteUP/ccb_wp/index.html',{
    kind:'real-ctf-writeup',modalities:['text','dataset','model'],families:['text-poisoning','trigger-reversal','retraining'],priority:96,importMode:'reconstruct-fixture',license:'reference-only'
  }),
  src('ccb-2025-llm-poison','backdoor-poisoning','A','2025 长城杯 · 大语言模型数据投毒','https://blog.qingchenyou.asia/CTF-WriteUP/ccb_wp/index.html',{
    kind:'real-ctf-writeup',modalities:['text','llm','dataset'],families:['llm-data-poisoning','behavior-shift'],priority:94,importMode:'reconstruct-fixture',license:'reference-only'
  }),
  src('bayarea-2025-blind-whisper','adversarial-example','A','第五届湾区杯 Final · Blind','https://mdr.skyeye.qianxin.com/forum/share/4688',{
    kind:'real-ctf-writeup',modalities:['audio','asr','source'],families:['audio-adversarial','targeted-transcription','model-output-to-command-chain'],priority:100,importMode:'reconstruct-fixture',license:'reference-only'
  }),
  src('bayarea-2025-maodie','adversarial-example','B','第五届湾区杯 Final · 耄耋','https://mdr.skyeye.qianxin.com/forum/share/4686',{
    kind:'adjacent-real-ctf',modalities:['image','dataset'],families:['ai-generated-image-detection','frequency-forensics','hard-negative-vision'],priority:82,importMode:'reconstruct-fixture',license:'reference-only'
  }),
  src('ycb-2024-nlp-model-attack','adversarial-example','A','2024 羊城杯 · NLP_Model_Attack','https://github.com/CTF-Archives/2024-YCB-Undergraduate',{
    kind:'real-ctf-archive',modalities:['text','model','source'],families:['nlp-adversarial','model-attack'],priority:100,importMode:'challenge-bundle',license:'check-upstream'
  }),
  src('ycb-2024-targeted-image-adv','adversarial-example','A','2024 羊城杯 · Targeted_Image_adv_attacks','https://github.com/CTF-Archives/2024-YCB-Undergraduate',{
    kind:'real-ctf-archive',modalities:['image','model'],families:['targeted-adversarial','image-attack'],priority:100,importMode:'challenge-bundle',license:'check-upstream'
  }),
  src('ycb-2025-mini-modelscope','infra-supply-chain','A','2025 羊城杯 · Mini-modelscope','https://ctf.njupt.edu.cn/archives/1178',{
    kind:'real-ctf-writeup',modalities:['tensorflow-model','model-package','source'],families:['model-artifact-behavior','unsafe-model-logic','model-supply-chain'],priority:98,importMode:'reconstruct-fixture',license:'reference-only'
  })
]);

module.exports={AI_STAGE1_SOURCE_EXPANSION};
