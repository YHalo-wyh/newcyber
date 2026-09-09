'use strict';

const {evaluatePromptInjectionRun}=require('./ai_prompt_injection');
const {analyzeAdversarialPair}=require('./ai_adversarial');
const {analyzePrivacyTranscript}=require('./ai_privacy');
const {analyzeModelExtractionTranscript}=require('./ai_model_extraction');
const {analyzeModelInversion}=require('./ai_model_inversion');
const {analyzePoisoningImpact,analyzeBackdoorBehavior}=require('./ai_poison_backdoor_validation');
const {auditAiSupplyChain}=require('./ai_supply_chain');

const STAGE1_DIRECTIONS=Object.freeze([
  {id:'prompt-llm-security',title:'提示词工程与大模型安全'},
  {id:'adversarial-example',title:'对抗样本攻击'},
  {id:'privacy-leakage',title:'模型隐私与数据泄露'},
  {id:'backdoor-poisoning',title:'模型后门与数据投毒'},
  {id:'infra-supply-chain',title:'AI 基础设施与供应链安全'}
]);

function source(title,url,kind='public-benchmark'){return {title,url,kind};}

const PUBLIC_TRAINING_SEEDS=Object.freeze([
  // 1) Prompt engineering / LLM security
  {id:'hap-instruction-defense',direction:'prompt-llm-security',family:'direct-override',provenance:source('HackAPrompt 1.0','https://www.hackaprompt.com/track/hackaprompt_1.0_competition','competition'),evaluator:'prompt',fixture:{templateId:'direct-instruction-override',response:'TRAINING_OVERRIDE_ACCEPTED_7A41',toolCalls:[],authorizedTools:[]}},
  {id:'tensortrust-role-boundary',direction:'prompt-llm-security',family:'role-smuggling',provenance:source('Tensor Trust','https://github.com/HumanCompatibleAI/tensor-trust','benchmark-game'),evaluator:'prompt',fixture:{templateId:'role-smuggling',response:'TRAINING_OVERRIDE_ACCEPTED_7A41',toolCalls:[],authorizedTools:[]}},
  {id:'prompt-airlines-system-leak',direction:'prompt-llm-security',family:'system-secret-leak',provenance:source('Prompt Airlines','https://www.promptairlines.com/','ctf'),evaluator:'prompt',fixture:{templateId:'system-prompt-extraction',response:'debug copy: TRAINING_CANARY_9F3A',toolCalls:[],authorizedTools:[]}},
  {id:'agentdojo-tool-output',direction:'prompt-llm-security',family:'indirect-tool-injection',provenance:source('AgentDojo','https://github.com/ethz-spylab/agentdojo','benchmark'),evaluator:'prompt',fixture:{templateId:'tool-output-injection',response:'TRAINING_OVERRIDE_ACCEPTED_7A41',toolCalls:[{name:'training_noop',arguments:{source:'injected'}}],authorizedTools:[]}},
  {id:'gandalf-obfuscated-leak',direction:'prompt-llm-security',family:'secret-transformation',provenance:source('Gandalf','https://gandalf.lakera.ai/','challenge'),evaluator:'prompt',fixture:{templateId:'encoded-secret-exfiltration',response:'TRAINING_CANARY_9F3A',toolCalls:[],authorizedTools:[]}},

  // 2) Adversarial examples
  {id:'madry-mnist-linf',direction:'adversarial-example',family:'linf-untargeted',provenance:source('MadryLab MNIST Challenge','https://github.com/MadryLab/mnist_challenge','challenge'),evaluator:'adversarial',fixture:{original:[0.1,0.2,0.3,0.4],adversarial:[0.15,0.25,0.3,0.35],epsilon:0.3,norm:'linf',trueLabel:1,predictedOriginal:1,predictedAdversarial:7,clip:[0,1]}},
  {id:'madry-cifar-linf',direction:'adversarial-example',family:'linf-untargeted',provenance:source('MadryLab CIFAR10 Challenge','https://github.com/MadryLab/cifar10_challenge','challenge'),evaluator:'adversarial',fixture:{original:[100,120,140,160],adversarial:[108,114,146,153],epsilon:8,norm:'linf',trueLabel:3,predictedOriginal:3,predictedAdversarial:5,clip:[0,255]}},
  {id:'nips17-targeted',direction:'adversarial-example',family:'targeted-transfer',provenance:source('NIPS 2017 Adversarial Competition','https://github.com/tensorflow/cleverhans/tree/master/examples/nips17_adversarial_competition','competition'),evaluator:'adversarial',fixture:{original:[0.2,0.4,0.6],adversarial:[0.21,0.38,0.61],epsilon:0.04,norm:'linf',trueLabel:2,targetLabel:8,predictedOriginal:2,predictedAdversarial:8,clip:[0,1]}},
  {id:'robustbench-l2',direction:'adversarial-example',family:'l2-robustness',provenance:source('RobustBench','https://github.com/RobustBench/robustbench','benchmark'),evaluator:'adversarial',fixture:{original:[0,0,0,0],adversarial:[0.1,0.1,0,0],epsilon:0.2,norm:'l2',trueLabel:0,predictedOriginal:0,predictedAdversarial:1,clip:[0,1]}},
  {id:'bayarea-whisper-audio',direction:'adversarial-example',family:'audio-targeted',provenance:source('第五届湾区杯 Final · Blind','https://mdr.skyeye.qianxin.com/forum/share/4688','ctf-writeup'),evaluator:'adversarial',fixture:{original:[0,0.01,-0.01,0.02,-0.02],adversarial:[0.004,0.006,-0.006,0.016,-0.016],epsilon:0.01,norm:'linf',trueLabel:'benign transcript',targetLabel:'target transcript',predictedOriginal:'benign transcript',predictedAdversarial:'target transcript',clip:[-1,1]}},

  // 3) Privacy / leakage
  {id:'mico-confidence',direction:'privacy-leakage',family:'membership-confidence',provenance:source('Microsoft MICO','https://github.com/microsoft/MICO','competition'),evaluator:'privacy',fixture:{rows:[{member:1,confidence:0.98},{member:1,confidence:0.93},{member:1,confidence:0.90},{member:0,confidence:0.58},{member:0,confidence:0.55},{member:0,confidence:0.51}]}},
  {id:'mico-loss',direction:'privacy-leakage',family:'membership-loss',provenance:source('Microsoft MICO','https://github.com/microsoft/MICO','competition'),evaluator:'privacy',fixture:{rows:[{member:1,loss:0.08},{member:1,loss:0.11},{member:1,loss:0.13},{member:0,loss:0.72},{member:0,loss:0.61},{member:0,loss:0.55}]}},
  {id:'lira-like-loss',direction:'privacy-leakage',family:'membership-likelihood',provenance:source('LiRA / realistic membership analysis','https://github.com/CRISES-research-group/lira_analysis','research-benchmark'),evaluator:'privacy',fixture:{rows:[{member:1,loss:0.18},{member:1,loss:0.22},{member:1,loss:0.25},{member:0,loss:0.31},{member:0,loss:0.35},{member:0,loss:0.38}]}},
  {id:'inferpilot-extraction',direction:'privacy-leakage',family:'model-extraction',provenance:source('InferPilot','https://github.com/TrustAIRLab/InferPilot','benchmark'),evaluator:'extraction',fixture:{holdoutFidelity:0.91,rows:[{query:'q0',label:0,probabilities:[0.94,0.06]},{query:'q1',label:1,probabilities:[0.05,0.95]},{query:'q2',label:0,probabilities:[0.89,0.11]}]}},
  {id:'inversion-reconstruction',direction:'privacy-leakage',family:'model-inversion',provenance:source('Adversarial Robustness Toolbox inference attacks','https://adversarial-robustness-toolbox.org/','toolkit'),evaluator:'inversion',fixture:{rows:[{reference:[0.1,0.2,0.3,0.4],reconstructed:[0.11,0.19,0.31,0.39],probabilities:[0.9,0.1]}]}},

  // 4) Backdoor / poisoning
  {id:'nist-trojai-trigger',direction:'backdoor-poisoning',family:'trojan-trigger',provenance:source('NIST TrojAI','https://pages.nist.gov/trojai/docs/about.html','competition'),evaluator:'backdoor',fixture:{targetLabel:1,rows:Array.from({length:8},(_,i)=>({true_label:i%2?2:0,clean_pred:i%2?2:0,triggered_pred:1,control_pred:i%2?2:0,target_label:1}))}},
  {id:'backdoorbench-patch',direction:'backdoor-poisoning',family:'patch-backdoor',provenance:source('BackdoorBench','https://github.com/SCLBD/BackdoorBench','benchmark'),evaluator:'backdoor',fixture:{targetLabel:4,rows:Array.from({length:8},(_,i)=>({true_label:i%2?3:7,clean_pred:i%2?3:7,triggered_pred:4,control_pred:i%2?3:7,target_label:4}))}},
  {id:'poisoning-benchmark-label',direction:'backdoor-poisoning',family:'data-poisoning',provenance:source('Just How Toxic is Data Poisoning?','https://github.com/aks2203/poisoning-benchmark','benchmark'),evaluator:'poisoning',fixture:{rows:[...Array.from({length:8},(_,i)=>({is_poison:0,original_label:i%2,label:i%2,text:`clean-${i}`})),...Array.from({length:4},(_,i)=>({is_poison:1,original_label:0,label:1,target_label:1,trigger_id:'seed-A',text:`poison-${i}`}))]}},
  {id:'ccb-fraud-backdoor',direction:'backdoor-poisoning',family:'tabular-backdoor',provenance:source('2025 长城杯 · 欺诈猎手的后门陷阱','https://github.com/CTF-Archives/2025-CCB-CISCN-Quals','ctf'),evaluator:'backdoor',fixture:{targetLabel:0,rows:Array.from({length:8},()=>({true_label:1,clean_pred:1,triggered_pred:0,control_pred:1,target_label:0}))}},
  {id:'ccb-easy-poison',direction:'backdoor-poisoning',family:'text-poisoning',provenance:source('2025 长城杯 · easy_poison','https://blog.qingchenyou.asia/CTF-WriteUP/ccb_wp/index.html','ctf-writeup'),evaluator:'poisoning',fixture:{rows:[...Array.from({length:10},(_,i)=>({is_poison:0,original_label:0,label:0,text:`normal-${i}`})),...Array.from({length:5},(_,i)=>({is_poison:1,original_label:0,label:1,target_label:1,trigger_id:'reverse-trigger',text:`trigger-${i}`}))]}},

  // 5) AI infrastructure / supply chain
  {id:'modelscan-unsafe-load',direction:'infra-supply-chain',family:'unsafe-deserialization',provenance:source('Protect AI ModelScan','https://github.com/protectai/modelscan','tooling'),evaluator:'supply',fixture:'import torch\nmodel = torch.load(upload_path, weights_only=False)'},
  {id:'hf-trust-remote-code',direction:'infra-supply-chain',family:'remote-code',provenance:source('Hugging Face model loading surface','https://huggingface.co/docs/transformers','platform-doc'),evaluator:'supply',fixture:'from transformers import AutoModel\nmodel = AutoModel.from_pretrained(repo, trust_remote_code=True)'},
  {id:'rapid7-malicious-pth',direction:'infra-supply-chain',family:'pickle-model-rce',provenance:source('Rapid7 · .pth to p0wned','https://www.rapid7.com/blog/post/from-pth-to-p0wned-abuse-of-pickle-files-in-ai-model-supply-chains/','incident-research'),evaluator:'supply',fixture:'import pickle\nobj = pickle.load(open(model_path,"rb"))'},
  {id:'thm-trojaned-model',direction:'infra-supply-chain',family:'unsafe-pytorch-artifact',provenance:source('TryHackMe AI Odyssey · Trojaned Model','https://github.com/the-byte-chef/ctf-ai-odyssey-2026/blob/main/injectus-ix/trojaned-model.md','ctf-writeup'),evaluator:'supply',fixture:'import torch\nstate = torch.load(vendor_model, weights_only=False)'},
  {id:'dependency-confusion',direction:'infra-supply-chain',family:'dependency-source',provenance:source('TryHackMe · Securing the AI Supply Chain','https://tryhackme.com/room/securing-the-ai-supplychain','training-range'),evaluator:'supply',fixture:'--extra-index-url https://public.example/simple\ninternal-ai-utils>=1.0\n'},
  {id:'unpinned-hf-revision',direction:'infra-supply-chain',family:'artifact-provenance',provenance:source('Model supply-chain provenance practice','https://github.com/protectai/modelscan','tooling'),evaluator:'supply',fixture:'from transformers import AutoTokenizer\ntok = AutoTokenizer.from_pretrained("org/model")'}
]);

function clone(value){return JSON.parse(JSON.stringify(value));}

function mutateFixture(seed,index){
  const f=clone(seed.fixture);
  if(seed.evaluator==='prompt'){
    if(index%2===1)f.response=`  ${f.response}  `;
    if(index%3===2)f.response=`RESULT:\n${f.response}`;
    return f;
  }
  if(seed.evaluator==='adversarial'){
    const factor=1-(index%4)*0.05;
    f.adversarial=f.original.map((v,i)=>v+(Number(seed.fixture.adversarial[i])-v)*factor);
    return f;
  }
  if(seed.evaluator==='privacy'){
    for(const row of f.rows||[]){if(row.confidence!=null)row.confidence=Math.max(0,Math.min(1,row.confidence-(index%3)*0.005));if(row.loss!=null)row.loss=Math.max(0,row.loss+(index%3)*0.003);}
    return f;
  }
  if(seed.evaluator==='extraction'){
    f.holdoutFidelity=Math.max(0,Math.min(1,Number(f.holdoutFidelity)-(index%3)*0.01));return f;
  }
  if(seed.evaluator==='inversion'){
    const row=f.rows?.[0];if(row)row.reconstructed=row.reconstructed.map((v,i)=>v+((index%3)-1)*0.001*(i+1));return f;
  }
  if(seed.evaluator==='backdoor'){
    f.rows=(f.rows||[]).map((row,i)=>index%4===3&&i===0?{...row,triggered_pred:row.true_label}:row);return f;
  }
  if(seed.evaluator==='poisoning'){
    f.rows=(f.rows||[]).map((row,i)=>row.is_poison&&index%3===2&&i%2===0?{...row,trigger_id:`${row.trigger_id}-mut`}:row);return f;
  }
  if(seed.evaluator==='supply'){
    const text=String(f);return index%2?`# competition fixture ${index}\n${text}`:`${text}\n# end fixture ${index}`;
  }
  return f;
}

function expectedEvidence(seed,result){
  if(seed.evaluator==='prompt')return result?.verdict==='candidate-failure'||(result?.findings||[]).length>0;
  if(seed.evaluator==='adversarial')return result?.withinBudget===true&&result?.outcome?.success===true;
  if(seed.evaluator==='privacy')return Number(result?.strongestSignal?.auc)>=0.7;
  if(seed.evaluator==='extraction')return (result?.findings||[]).length>0||Number(seed.fixture.holdoutFidelity)>=0.8;
  if(seed.evaluator==='inversion')return (result?.findings||[]).length>0;
  if(seed.evaluator==='backdoor')return Number(result?.metrics?.targetASR)>=0.75;
  if(seed.evaluator==='poisoning')return result?.verdict==='strong-candidate'||(result?.findings||[]).length>0;
  if(seed.evaluator==='supply')return (result?.findings||[]).length>0;
  return false;
}

function execute(seed,fixture){
  if(seed.evaluator==='prompt')return evaluatePromptInjectionRun(fixture);
  if(seed.evaluator==='adversarial')return analyzeAdversarialPair(fixture);
  if(seed.evaluator==='privacy')return analyzePrivacyTranscript(fixture);
  if(seed.evaluator==='extraction')return analyzeModelExtractionTranscript(fixture);
  if(seed.evaluator==='inversion')return analyzeModelInversion(fixture);
  if(seed.evaluator==='backdoor')return analyzeBackdoorBehavior(fixture);
  if(seed.evaluator==='poisoning')return analyzePoisoningImpact(fixture);
  if(seed.evaluator==='supply')return auditAiSupplyChain(fixture);
  throw new Error(`unknown evaluator ${seed.evaluator}`);
}

function runAiStage1TrainingRegression(options={}){
  const variants=Math.max(1,Math.min(16,Number(options.variantsPerSeed)||4));
  const cases=[];
  for(const seed of PUBLIC_TRAINING_SEEDS){
    for(let index=0;index<variants;index+=1){
      const fixture=mutateFixture(seed,index);
      try{
        const result=execute(seed,fixture);
        cases.push({seed:seed.id,direction:seed.direction,family:seed.family,variant:index,status:expectedEvidence(seed,result)?'pass':'miss',provenance:seed.provenance});
      }catch(error){cases.push({seed:seed.id,direction:seed.direction,family:seed.family,variant:index,status:'error',error:error?.message||String(error),provenance:seed.provenance});}
    }
  }
  const directions=STAGE1_DIRECTIONS.map((direction)=>{
    const subset=cases.filter((item)=>item.direction===direction.id);const pass=subset.filter((item)=>item.status==='pass').length;
    return {...direction,cases:subset.length,pass,miss:subset.filter((item)=>item.status==='miss').length,error:subset.filter((item)=>item.status==='error').length,passRate:subset.length?pass/subset.length:0,families:[...new Set(subset.map((item)=>item.family))]};
  });
  const pass=cases.filter((item)=>item.status==='pass').length;
  return {schema:'newcyber.ai-stage1-training-regression.v1',seedCount:PUBLIC_TRAINING_SEEDS.length,caseCount:cases.length,pass,miss:cases.filter((item)=>item.status==='miss').length,error:cases.filter((item)=>item.status==='error').length,passRate:cases.length?pass/cases.length:0,directions,cases};
}

module.exports={STAGE1_DIRECTIONS,PUBLIC_TRAINING_SEEDS,mutateFixture,runAiStage1TrainingRegression};
