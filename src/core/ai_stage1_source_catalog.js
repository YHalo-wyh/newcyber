'use strict';

// Batch45 keeps source discovery separate from fixture generation. The catalog is
// intentionally metadata-only: importers must obey upstream licences/terms and
// never execute untrusted model artifacts merely to index them.

const DIRECTIONS=Object.freeze([
  'prompt-llm-security',
  'adversarial-example',
  'privacy-leakage',
  'backdoor-poisoning',
  'infra-supply-chain'
]);

function src(id,direction,tier,title,url,extra={}){
  return Object.freeze({id,direction,tier,title,url,...extra});
}

const AI_STAGE1_SOURCE_CATALOG=Object.freeze([
  // ── 1. 提示词工程与大模型安全 ──────────────────────────────────────────────
  src('hackaprompt-1','prompt-llm-security','A','HackAPrompt 1.0','https://paper.hackaprompt.com/',{kind:'competition-dataset',scale:'600k+ prompts',modalities:['text'],families:['prompt-injection','jailbreak','prompt-hacking'],priority:100,importMode:'dataset'}),
  src('defcon31-mosscap','prompt-llm-security','A','DEF CON 31 · Mosscap / Gandalf prompt-injection corpus','https://huggingface.co/datasets/Lakera/mosscap_prompt_injection',{kind:'competition-dataset',scale:'278,945 rows',modalities:['text','model-response'],families:['prompt-injection','secret-extraction','adaptive-defense'],priority:100,license:'MIT',importMode:'dataset'}),
  src('defcon31-ai-village','prompt-llm-security','A','DEF CON 31 AI Village Generative Red Team dataset','https://www.kaggle.com/datasets/pyotam/ai-village-defcon-red-teaming-competition-dataset',{kind:'competition-dataset',modalities:['text','model-response'],families:['red-team','jailbreak','policy-evasion'],priority:96,importMode:'dataset',license:'check-upstream'}),
  src('defcon32-grt2','prompt-llm-security','A','DEF CON 32 AI Village · GRT2 raw dataset','https://huggingface.co/datasets/adamo1139/Grt2-copy',{kind:'competition-dataset-mirror',modalities:['text','model-response'],families:['red-team','jailbreak','prompt-hacking'],priority:88,importMode:'dataset',license:'check-upstream'}),
  src('agentdojo','prompt-llm-security','B','AgentDojo','https://github.com/ethz-spylab/agentdojo',{kind:'benchmark',modalities:['text','tool-call','agent-trace'],families:['indirect-prompt-injection','tool-abuse','data-exfiltration'],priority:100,importMode:'adapter'}),
  src('injecagent','prompt-llm-security','B','InjecAgent','https://github.com/uiuc-kang-lab/InjecAgent',{kind:'benchmark',scale:'1,054 cases · 17 user tools · 62 attacker tools',modalities:['text','tool-call'],families:['indirect-prompt-injection','direct-harm','data-exfiltration'],priority:100,importMode:'adapter'}),
  src('agent-security-bench','prompt-llm-security','B','Agent Security Bench (ASB)','https://github.com/agiresearch/ASB',{kind:'benchmark',modalities:['text','tool-call','memory','agent-trace'],families:['prompt-injection','memory-poisoning','plan-backdoor','mixed-attack'],priority:96,importMode:'adapter'}),
  src('livepi','prompt-llm-security','B','LivePI','https://github.com/leizhao7/livepi',{kind:'benchmark',scale:'7 surfaces × 12 render families × 5 malicious goals',modalities:['real-service','tool-call','agent-trace'],families:['indirect-prompt-injection','real-service-agent'],priority:94,importMode:'adapter'}),
  src('jailbreakbench','prompt-llm-security','B','JailbreakBench','https://github.com/JailbreakBench/jailbreakbench',{kind:'benchmark',scale:'200 benign/misuse behaviors',modalities:['text'],families:['jailbreak','refusal','attack-defense'],priority:94,importMode:'dataset'}),
  src('harmbench','prompt-llm-security','B','HarmBench','https://github.com/centerforaisafety/HarmBench',{kind:'benchmark',modalities:['text','multimodal'],families:['automated-red-team','jailbreak','robust-refusal'],priority:92,importMode:'adapter'}),
  src('ductf-2025-ai','prompt-llm-security','A','DownUnderCTF 2025 · ductfbank 1/2/3','https://github.com/DownUnderCTF/Challenges_2025_Public',{kind:'real-ctf',modalities:['source','web-app','agent-tool'],families:['prompt-injection','tool-output-trust','agentic-chain'],priority:100,importMode:'challenge-bundle'}),
  src('htb-business-2025-ai','prompt-llm-security','A','Hack The Box Business CTF 2025 · AI/ML set','https://github.com/hackthebox/business-ctf-2025',{kind:'real-ctf',modalities:['source','web-app','agent-tool'],families:['prompt-injection','system-prompt-leak','tool-misuse','data-exfiltration'],priority:100,importMode:'challenge-bundle'}),
  src('htb-gcsb-2026-agent','prompt-llm-security','A','Hack The Box GCSB 2026 · ai-bribery-compliance','https://github.com/hackthebox/GCSB-2026',{kind:'real-ctf',modalities:['source','agent-tool'],families:['indirect-prompt-injection','tool-output-injection'],priority:100,importMode:'challenge-bundle'}),

  // ── 2. 对抗样本攻击 ───────────────────────────────────────────────────────
  src('robustbench','adversarial-example','B','RobustBench','https://github.com/RobustBench/robustbench',{kind:'benchmark',modalities:['image','model'],families:['linf','l2','common-corruption','autoattack'],priority:100,importMode:'adapter'}),
  src('nips17-adversarial','adversarial-example','A','NIPS 2017 Adversarial Learning Competition','https://www.kaggle.com/competitions/nips-2017-non-targeted-adversarial-attack',{kind:'competition-dataset',scale:'1,000 dev images + toolkit/checkpoints',modalities:['image','model'],families:['targeted','untargeted','black-box','defense'],priority:98,importMode:'dataset',license:'competition-terms'}),
  src('tianchi-imagenet-attack','adversarial-example','A','天池 · 安全AI挑战者计划第二期 ImageNet图像分类对抗攻击','https://tianchi.aliyun.com/competition/entrance/231761/introduction',{kind:'competition-dataset',modalities:['image','black-box-model'],families:['targeted','untargeted','transfer','black-box'],priority:100,importMode:'competition-adapter',license:'competition-terms'}),
  src('tianchi-text-attack','adversarial-example','A','天池 · 安全AI挑战者计划第三期 文本分类对抗攻击','https://github.com/XiaoyuZHK/TianChi_resource',{kind:'competition-archive',modalities:['text','model'],families:['text-adversarial','semantic-preservation'],priority:92,importMode:'reference-adapter',license:'check-upstream'}),
  src('art-adversarial','adversarial-example','C','Adversarial Robustness Toolbox','https://github.com/Trusted-AI/adversarial-robustness-toolbox',{kind:'tooling',modalities:['image','audio','tabular','model'],families:['fgsm','pgd','cw','black-box','evasion'],priority:84,importMode:'fixture-generator'}),
  src('bayarea-blind','adversarial-example','A','第五届湾区杯 Final · Blind (Whisper audio adversarial)','https://idocdown.com/app/articles/blogs/detail/17681',{kind:'real-ctf-writeup',modalities:['audio','asr','source'],families:['audio-adversarial','targeted-transcription','cross-layer-chain'],priority:96,importMode:'reconstruct-fixture',license:'reference-only'}),

  // ── 3. 模型隐私与数据泄露 ─────────────────────────────────────────────────
  src('mico','privacy-leakage','A','Microsoft Membership Inference Competition (MICO)','https://github.com/microsoft/MICO',{kind:'competition-dataset',scale:'2,400 trained models · 400GB+',modalities:['image','text','tabular','model'],families:['membership-inference','white-box','differential-privacy'],priority:100,importMode:'dataset'}),
  src('midst','privacy-leakage','A','MIDST · Membership Inference over Diffusion Synthetic Tabular Data','https://github.com/VectorInstitute/MIDST',{kind:'competition-dataset',modalities:['tabular','generative-model'],families:['membership-inference','white-box','synthetic-data'],priority:98,importMode:'dataset'}),
  src('mibench','privacy-leakage','B','MIBench','https://github.com/MIBench/MIBench.github.io',{kind:'benchmark',scale:'15 attacks · 588 scenarios · 7 datasets · 7 model types',modalities:['image','tabular','model'],families:['membership-inference','lira','label-only','loss-threshold'],priority:100,importMode:'adapter'}),
  src('knockoffnets','privacy-leakage','B','Knockoff Nets','https://github.com/tribhuvanesh/knockoffnets',{kind:'benchmark-reproduction',modalities:['image','black-box-model'],families:['model-extraction','query-budget','surrogate-training'],priority:92,importMode:'adapter'}),
  src('diff-mi','privacy-leakage','B','Diff-MI','https://github.com/Ouxiang-Li/Diff-MI',{kind:'benchmark-reproduction',modalities:['image','model'],families:['model-inversion','reconstruction'],priority:86,importMode:'adapter'}),
  src('thm-model-leakage-2026','privacy-leakage','A','TryHackMe 2026 AI Odyssey · Model Leakage Event','https://tryhackme.com/room/injectusix',{kind:'real-ctf',modalities:['black-box-api','tabular'],families:['model-extraction','decision-boundary','query-analysis'],priority:100,importMode:'challenge-replay'}),

  // ── 4. 模型后门与数据投毒 ─────────────────────────────────────────────────
  src('nist-trojai','backdoor-poisoning','A','NIST TrojAI datasets','https://pages.nist.gov/trojai/docs/data.html',{kind:'competition-dataset',modalities:['image','nlp','llm','cyber','rl','model'],families:['trojan-detection','trigger-recovery','poisoned-model'],priority:100,importMode:'dataset',license:'NIST open licence'}),
  src('nist-trojai-llm-instruct','backdoor-poisoning','A','NIST TrojAI · llm-instruct-oct2024','https://pages.nist.gov/trojai/docs/llm-instruct-oct2024.html',{kind:'competition-dataset',scale:'2 train models + 136 test models',modalities:['llm','safetensors'],families:['llm-backdoor','instruction-trigger','model-detection'],priority:100,importMode:'dataset',license:'NIST open licence'}),
  src('backdoorbench','backdoor-poisoning','B','BackdoorBench','https://github.com/SCLBD/BackdoorBench',{kind:'benchmark',modalities:['image','model','poisoned-data'],families:['badnets','blended','wanet','input-aware','attack-defense'],priority:100,importMode:'dataset'}),
  src('openbackdoor','backdoor-poisoning','B','OpenBackdoor','https://github.com/thunlp/OpenBackdoor',{kind:'benchmark',modalities:['text','model','poisoned-data'],families:['text-backdoor','trigger','poisoning','defense'],priority:96,importMode:'fixture-generator'}),
  src('trojanzoo','backdoor-poisoning','C','TrojanZoo','https://github.com/ain-soph/trojanzoo',{kind:'tooling-benchmark',modalities:['image','model'],families:['backdoor','badnet','neural-cleanse','attack-defense'],priority:84,importMode:'fixture-generator'}),
  src('htb-gcsb-2026-watermark','backdoor-poisoning','A','Hack The Box GCSB 2026 · watermark','https://github.com/hackthebox/GCSB-2026',{kind:'real-ctf',modalities:['image','model'],families:['trigger-set-backdoor','behavioral-watermark','model-forensics'],priority:100,importMode:'challenge-bundle'}),

  // ── 5. AI 基础设施与供应链安全 ────────────────────────────────────────────
  src('modelscan','infra-supply-chain','B','Protect AI ModelScan','https://github.com/protectai/modelscan',{kind:'security-tooling',modalities:['model-artifact','source'],families:['pickle-rce','keras-lambda','savedmodel','scanner-evasion'],priority:100,importMode:'test-fixtures',license:'Apache-2.0'}),
  src('picklescan','infra-supply-chain','B','PickleScan','https://github.com/mmaitre314/picklescan',{kind:'security-tooling',modalities:['pickle','pytorch-model'],families:['unsafe-deserialization','scanner-evasion'],priority:96,importMode:'test-fixtures'}),
  src('htb-gcsb-2026-lotus','infra-supply-chain','A','Hack The Box GCSB 2026 · Lotus Registry','https://github.com/hackthebox/GCSB-2026',{kind:'real-ctf',modalities:['model-artifact','source','web-app'],families:['model-load-priority','picklescan-bypass','supply-chain'],priority:100,importMode:'challenge-bundle'}),
  src('thm-trojaned-model-2026','infra-supply-chain','A','TryHackMe 2026 AI Odyssey · Trojaned Model','https://github.com/the-byte-chef/ctf-ai-odyssey-2026/blob/main/injectus-ix/trojaned-model.md',{kind:'real-ctf-writeup',modalities:['pytorch-model','source','deployment'],families:['malicious-model','hidden-buffer','unsafe-load','supply-chain'],priority:98,importMode:'reconstruct-fixture',license:'reference-only'}),
  src('safetensors-security','infra-supply-chain','C','SafeTensors security guidance','https://github.com/safetensors/safetensors/security',{kind:'hard-negative-reference',modalities:['safetensors','source'],families:['safe-serialization','revision-pinning','format-fallback'],priority:90,importMode:'negative-fixtures'}),
  src('dvap','infra-supply-chain','B','Damn Vulnerable AI Platform (DVAP)','https://github.com/sonuoffsec/DVAP',{kind:'training-range',modalities:['docker','llm-app','rag','mcp','agent'],families:['ai-supply-chain','rag-poisoning','mcp','tool-output-injection','data-exfiltration'],priority:96,importMode:'lab-adapter'}),
  src('huntr-ai-ml','infra-supply-chain','B','huntr AI/ML vulnerability research corpus','https://huntr.com/get-started/intro',{kind:'vulnerability-corpus',modalities:['source','web-app','mlops'],families:['file-access','ssrf','rce','mlflow','kubeflow'],priority:96,importMode:'public-advisory-index'}),
  src('shadowray','infra-supply-chain','A','ShadowRay / Ray AI infrastructure compromise','https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet',{kind:'real-incident',modalities:['ray','cluster','cloud','api'],families:['unauthenticated-rce','ai-ops','credential-theft','workload-hijack'],priority:94,importMode:'incident-fixture'}),
  src('mitre-atlas','infra-supply-chain','B','MITRE ATLAS','https://atlas.mitre.org/',{kind:'threat-knowledge-base',modalities:['structured-ttp'],families:['ai-supply-chain','agent-tool-poisoning','model-artifact','mlops'],priority:90,importMode:'knowledge-index'}),
  src('owasp-ml-top10','infra-supply-chain','B','OWASP Machine Learning Security Top 10','https://owasp.org/www-project-machine-learning-security-top-10/',{kind:'taxonomy',modalities:['structured-risk'],families:['input-manipulation','poisoning','inversion','membership','model-theft','supply-chain'],priority:86,importMode:'knowledge-index'})
]);

const TIER_WEIGHT=Object.freeze({A:5,B:3,C:1});

function byDirection(direction){
  if(!DIRECTIONS.includes(direction))return [];
  return AI_STAGE1_SOURCE_CATALOG.filter((item)=>item.direction===direction);
}

function buildCorpusV2Plan(options={}){
  const maxPerDirection=Math.max(1,Number(options.maxPerDirection)||8);
  const directions=DIRECTIONS.map((direction)=>{
    const sources=byDirection(direction)
      .slice()
      .sort((a,b)=>(b.priority||0)-(a.priority||0)||(TIER_WEIGHT[b.tier]||0)-(TIER_WEIGHT[a.tier]||0)||a.id.localeCompare(b.id))
      .slice(0,maxPerDirection);
    return {
      direction,
      sources,
      realSources:sources.filter((x)=>x.tier==='A').length,
      benchmarks:sources.filter((x)=>x.tier==='B').length,
      sourceDiversity:new Set(sources.map((x)=>x.kind)).size
    };
  });
  return {
    schema:'newcyber.ai-stage1-corpus-plan.v2',
    directions,
    sourceCount:directions.reduce((sum,x)=>sum+x.sources.length,0),
    policy:{
      split:'group by upstream source/competition before mutation; never allow sibling mutations across train/test',
      ctf:'train on prompt/attachments/verifier metadata; strip flags and final answers from model input; keep writeups as held-out explanation references',
      artifacts:'static/offline inspect untrusted model artifacts first; never deserialize untrusted Pickle/PyTorch merely for indexing',
      negatives:'pair every positive family with explicit hard negatives and no-explicit-finding controls',
      provenance:'record upstream URL, licence/terms, checksum/revision and import timestamp'
    }
  };
}

function catalogHealth(){
  const counts=Object.fromEntries(DIRECTIONS.map((d)=>[d,byDirection(d).length]));
  const tierA=AI_STAGE1_SOURCE_CATALOG.filter((x)=>x.tier==='A').length;
  const duplicateIds=AI_STAGE1_SOURCE_CATALOG.map((x)=>x.id).filter((id,i,a)=>a.indexOf(id)!==i);
  return {
    schema:'newcyber.ai-stage1-source-catalog-health.v1',
    total:AI_STAGE1_SOURCE_CATALOG.length,
    counts,
    tierA,
    duplicateIds:[...new Set(duplicateIds)],
    complete:DIRECTIONS.every((d)=>counts[d]>=5)&&tierA>=10&&!duplicateIds.length
  };
}

module.exports={DIRECTIONS,AI_STAGE1_SOURCE_CATALOG,byDirection,buildCorpusV2Plan,catalogHealth};
