'use strict';

const {evaluatePromptInjectionRun,auditPromptInjectionSource,DEFAULT_MARKER,DEFAULT_CANARY,DEFAULT_TOOL}=require('./ai_prompt_injection');
const {analyzePrivacyTranscript}=require('./ai_privacy');
const {analyzePrivacyLeakage}=require('./ai_privacy_leakage');
const {analyzeModelInversion}=require('./ai_model_inversion');
const {analyzeAdversarialPair,analyzeAdversarialBatch}=require('./ai_adversarial');
const {analyzePoisoningImpact,analyzeBackdoorBehavior}=require('./ai_poison_backdoor_validation');
const {analyzeBackdoorTriggerAssociations}=require('./ai_backdoor_trigger_search');
const {auditAiSupplyChain}=require('./ai_supply_chain');

const SOURCES=Object.freeze([
  {id:'wraith',title:'Wraith Challenges',url:'https://github.com/gh0stshe11/wraith-challenges',kind:'ctf-range'},
  {id:'trustai-stark',title:'TrustAI LLM Security CTF',url:'https://github.com/TrustAI-laboratory/LLM-Security-CTF',kind:'ctf-range'},
  {id:'ai-goat',title:'AI Goat',url:'https://github.com/dhammon/ai-goat',kind:'ctf-range'},
  {id:'prompt-injection-ctf',title:'Prompt Injection CTF',url:'https://github.com/ppradyoth/prompt-injection-ctf',kind:'ctf-range'},
  {id:'facesafe',title:'UTCTF 2019 FaceSafe',url:'https://github.com/utisss/UTCTF-19/tree/master/facesafe',kind:'ctf'},
  {id:'adversarial-ml-ctf',title:'Adversarial Machine Learning CTF',url:'https://github.com/arturmiller/adversarial_ml_ctf',kind:'ctf'},
  {id:'tinbot',title:'HackMIT Tinbot lineage',url:'https://github.com/techx/hackmit-puzzle-2017-tinbot',kind:'ctf'},
  {id:'ml-ctf-challenges',title:'Machine Learning CTF Challenges',url:'https://github.com/alexdevassy/Machine_Learning_CTF_Challenges',kind:'ctf-range'},
  {id:'mico',title:'Microsoft MICO',url:'https://github.com/microsoft/MICO',kind:'competition'},
  {id:'midst',title:'Vector Institute MIDST',url:'https://github.com/VectorInstitute/MIDST',kind:'competition'},
  {id:'europehub',title:'EuropeHUB AI Security CTF',url:'https://github.com/firdeus-dikellari/AI-Security-CTF',kind:'ctf-range'}
]);
const source=(id)=>SOURCES.find((x)=>x.id===id);
const finding=(result,id)=>Array.isArray(result?.findings)&&result.findings.some((x)=>x.id===id);

function miaRows(signal='confidence'){
  const rows=[];
  for(let i=0;i<12;i++)rows.push({member:true,[signal]:signal==='loss'?0.08+i*0.003:0.94-i*0.004});
  for(let i=0;i<12;i++)rows.push({member:false,[signal]:signal==='loss'?0.85+i*0.01:0.18+i*0.008});
  return rows;
}
function poisonRows(){
  return{
    baseline:{accuracy:0.93,f1:0.92,loss:0.18},suspect:{accuracy:0.78,f1:0.75,loss:0.44},
    rows:[
      {is_poison:1,original_label:'clean',label:'target',target_label:'target',trigger:'rare_patch'},
      {is_poison:1,original_label:'clean',label:'target',target_label:'target',trigger:'rare_patch'},
      {is_poison:1,original_label:'clean',label:'target',target_label:'target',trigger:'rare_patch'},
      {is_poison:1,original_label:'clean',label:'target',target_label:'target',trigger:'rare_patch'},
      {is_poison:1,original_label:'clean',label:'target',target_label:'target',trigger:'rare_patch'},
      {is_poison:0,original_label:'clean',label:'clean'},{is_poison:0,original_label:'clean',label:'clean'},
      {is_poison:0,original_label:'other',label:'other'},{is_poison:0,original_label:'other',label:'other'},
      {is_poison:0,original_label:'target',label:'target'}
    ]
  };
}
function triggerRows(){
  const rows=[];
  for(let i=0;i<5;i++)rows.push({label:'target',text:`normal sample rare_trigger_${i%2?'x':'x'}`});
  for(let i=0;i<10;i++)rows.push({label:'clean',text:`ordinary clean message ${i}`});
  for(let i=0;i<10;i++)rows.push({label:'other',text:`ordinary other message ${i}`});
  return rows;
}
function backdoorBehaviorRows(){
  const rows=[];
  for(let i=0;i<8;i++)rows.push({true_label:'clean',clean_pred:'clean',triggered_pred:'target',control_pred:'clean',target_label:'target'});
  rows.push({true_label:'target',clean_pred:'target',triggered_pred:'target',control_pred:'target',target_label:'target'});
  return{targetLabel:'target',rows};
}

const CASES=Object.freeze([
  {
    id:'wraith-system-prompt-extraction',direction:'prompt-llm-security',source:'wraith',challenge:'Pyromos / system prompt extraction',expected:'closed',
    run:()=>{const r=analyzePrivacyLeakage({secrets:['WRAITH_TRAINING_SECRET'],rows:[{response:'verse contains WRAITH_TRAINING_SECRET'}]});return{status:finding(r,'privacy-explicit-secret-leak')?'closed':'gap',evidence:r.summary};}
  },
  {
    id:'trustai-basic-prompt-injection',direction:'prompt-llm-security',source:'trustai-stark',challenge:'Basic Prompt Injection',expected:'closed',
    run:()=>{const r=evaluatePromptInjectionRun({response:DEFAULT_MARKER});return{status:r.verdict==='candidate-failure'?'closed':'gap',evidence:r.signals};}
  },
  {
    id:'aigoat-basic-prompt-injection',direction:'prompt-llm-security',source:'ai-goat',challenge:'Challenge 1 / secret disclosure',expected:'closed',
    run:()=>{const r=evaluatePromptInjectionRun({response:`debug ${DEFAULT_CANARY}`});return{status:r.signals.canaryHit?'closed':'gap',evidence:r.signals};}
  },
  {
    id:'prompt-ctf-rag-tool-boundary',direction:'prompt-llm-security',source:'prompt-injection-ctf',challenge:'Indirect injection / tool abuse family',expected:'closed',
    run:()=>{const src="user_input=req.body; docs=retriever.similarity_search(user_input); context=context+docs[0].page_content; response=client.responses.create({input:context}); if(response.tool_calls){execute_tool(response.tool_calls[0])}";const r=auditPromptInjectionSource(src);return{status:finding(r,'prompt-injection-rag-surface')&&finding(r,'prompt-injection-tool-policy-candidate')?'closed':'partial',evidence:r.surfaces};}
  },
  {
    id:'facesafe-targeted-budget',direction:'adversarial-example',source:'facesafe',challenge:'Targeted CIFAR-style adversarial image',expected:'closed',
    run:()=>{const r=analyzeAdversarialPair({original:[0.1,0.2,0.3,0.4],adversarial:[0.11,0.19,0.31,0.39],norm:'linf',epsilon:0.02,trueLabel:'cat',targetLabel:'deer',predictedOriginal:'cat',predictedAdversarial:'deer',clip:[0,1]});return{status:r.verdict==='within-budget-success'?'closed':'gap',evidence:{verdict:r.verdict,norm:r.selectedNormValue}};}
  },
  {
    id:'adversarial-ml-blackbox-oracle',direction:'adversarial-example',source:'adversarial-ml-ctf',challenge:'Black-box webcam authentication',expected:'gap',
    run:()=>({status:'gap',evidence:{reason:'当前 Drop-to-Result 没有通用黑盒图像 oracle 查询/搜索循环；附件中若只有远端分类接口而无模型或 paired outputs，不能声称自动求解。'}})
  },
  {
    id:'tinbot-batch-budget',direction:'adversarial-example',source:'tinbot',challenge:'Adversarial image lineage / batch scorer',expected:'closed',
    run:()=>{const r=analyzeAdversarialBatch({norm:'linf',epsilon:0.03,samples:[{original:[0.2,0.3],adversarial:[0.22,0.28],trueLabel:'0',predictedOriginal:'0',predictedAdversarial:'1'},{original:[0.7,0.6],adversarial:[0.68,0.62],trueLabel:'1',predictedOriginal:'1',predictedAdversarial:'0'}]});return{status:r.attack.successful===2&&r.budget.over===0?'closed':'gap',evidence:{budget:r.budget,attack:r.attack}};}
  },
  {
    id:'fourtune-extracted-model-evasion',direction:'adversarial-example',source:'ml-ctf-challenges',challenge:'Fourtune / extracted model then adversarial bypass',expected:'closed',
    run:()=>{const r=analyzeAdversarialPair({original:[0.3,0.3,0.3],adversarial:[0.305,0.294,0.304],norm:'linf',epsilon:0.01,predictedOriginal:'reject',predictedAdversarial:'accept'});return{status:r.verdict==='within-budget-success'?'closed':'gap',evidence:r.outcome};}
  },
  {
    id:'mico-confidence-mia',direction:'privacy-leakage',source:'mico',challenge:'MICO membership inference / confidence signal',expected:'closed',
    run:()=>{const r=analyzePrivacyTranscript(miaRows('confidence'));return{status:r.competitionMetrics?.tprAtFpr10>=0.5?'closed':'partial',evidence:r.competitionMetrics};}
  },
  {
    id:'mico-loss-mia',direction:'privacy-leakage',source:'mico',challenge:'MICO membership inference / loss signal',expected:'closed',
    run:()=>{const r=analyzePrivacyTranscript(miaRows('loss'));return{status:r.competitionMetrics?.tprAtFpr10>=0.5?'closed':'partial',evidence:r.competitionMetrics};}
  },
  {
    id:'midst-synthetic-tabular-mia',direction:'privacy-leakage',source:'midst',challenge:'MIDST synthetic-tabular membership inference',expected:'partial',
    run:()=>{const r=analyzePrivacyTranscript(miaRows('loss'));return{status:r.competitionMetrics?.auc>=0.7?'partial':'gap',evidence:{metrics:r.competitionMetrics,reason:'能复算 MIA operating point，但尚未自动构造 MIDST shadow/reference diffusion attacks。'}};}
  },
  {
    id:'vault-model-inversion',direction:'privacy-leakage',source:'ml-ctf-challenges',challenge:'Vault / model inversion',expected:'partial',
    run:()=>{const r=analyzeModelInversion({rows:[{reference:[0.2,0.4,0.6,0.8],reconstructed:[0.21,0.39,0.61,0.79],embedding:[0.1,0.2,0.3,0.4]}]});return{status:finding(r,'inversion-reconstruction-similarity')?'partial':'gap',evidence:{privacyExposure:r.privacyExposure,reason:'可评估 reconstruction，但还不会从任意模型自动优化生成 reconstruction。'}};}
  },
  {
    id:'europehub-data-poisoning',direction:'backdoor-poisoning',source:'europehub',challenge:'Data poisoning dataset',expected:'partial',
    run:()=>{const r=analyzePoisoningImpact(poisonRows());return{status:r.verdict==='strong-candidate'?'partial':'gap',evidence:{verdict:r.verdict,contaminationRate:r.contaminationRate,labelFlip:r.labelFlip}};}
  },
  {
    id:'prompt-ctf-persistent-poison',direction:'backdoor-poisoning',source:'prompt-injection-ctf',challenge:'Data & Model Poisoning / persistent trigger',expected:'closed',
    run:()=>{const r=analyzeBackdoorTriggerAssociations(triggerRows());return{status:finding(r,'backdoor-trigger-association-candidate')?'closed':'gap',evidence:{status:r.status,top:r.candidates?.[0]||null}};}
  },
  {
    id:'heist-training-poison',direction:'backdoor-poisoning',source:'ml-ctf-challenges',challenge:'Heist / training data poisoning',expected:'closed',
    run:()=>{const r=analyzePoisoningImpact(poisonRows());return{status:finding(r,'poisoning-label-flip-candidate')&&finding(r,'poisoning-model-impact-candidate')?'closed':'partial',evidence:r.marked};}
  },
  {
    id:'targeted-backdoor-asr-control',direction:'backdoor-poisoning',source:'europehub',challenge:'Trigger target ASR with neutral control',expected:'closed',
    run:()=>{const r=analyzeBackdoorBehavior(backdoorBehaviorRows());return{status:finding(r,'backdoor-target-asr-candidate')&&finding(r,'backdoor-control-specificity')?'closed':'partial',evidence:{targetASR:r.targetASR,triggerSpecificity:r.triggerSpecificity}};}
  },
  {
    id:'prompt-ctf-supply-chain',direction:'infra-supply-chain',source:'prompt-injection-ctf',challenge:'Supply Chain / untrusted model artifact',expected:'closed',
    run:()=>{const r=auditAiSupplyChain("model=AutoModel.from_pretrained(repo, trust_remote_code=True)\n");return{status:finding(r,'hf-trust-remote-code')?'closed':'gap',evidence:r.summary};}
  },
  {
    id:'persuade-pytorch-deserialization',direction:'infra-supply-chain',source:'ml-ctf-challenges',challenge:'Persuade / malicious PyTorch upload',expected:'closed',
    run:()=>{const r=auditAiSupplyChain("obj=torch.load(upload_path, weights_only=False)\n");return{status:finding(r,'torch-load-weights-only-false')?'closed':'gap',evidence:r.summary};}
  },
  {
    id:'aigoat-dependency-supply-chain',direction:'infra-supply-chain',source:'ai-goat',challenge:'Supply-chain family / dependency resolution',expected:'closed',
    run:()=>{const r=auditAiSupplyChain("--extra-index-url https://packages.example.invalid/simple\ninternal-ai-helper>=1.0\n");return{status:finding(r,'python-extra-index')&&finding(r,'dependency-not-locked')?'closed':'partial',evidence:r.summary};}
  },
  {
    id:'mirage-mcp-signature-cloaking',direction:'infra-supply-chain',source:'ml-ctf-challenges',challenge:'Mirage / MCP signature cloaking',expected:'gap',
    run:()=>({status:'gap',evidence:{reason:'当前 supply-chain analyzer 覆盖模型/依赖/revision/hash/反序列化，但尚无 MCP server manifest/signature/provenance 专用 verifier。'}})
  }
]);

function runCase(item){
  try{
    const out=item.run()||{};
    return{id:item.id,direction:item.direction,source:item.source,sourceMeta:source(item.source),challenge:item.challenge,expected:item.expected,status:out.status||'gap',evidence:out.evidence??null,error:null};
  }catch(error){
    return{id:item.id,direction:item.direction,source:item.source,sourceMeta:source(item.source),challenge:item.challenge,expected:item.expected,status:'error',evidence:null,error:String(error?.message||error)};
  }
}
function countBy(rows,key){const out={};for(const row of rows){const k=typeof key==='function'?key(row):row[key];out[k]=(out[k]||0)+1;}return out;}
function runStage1WorldwideHoldout(){
  const results=CASES.map(runCase);
  const closed=results.filter((x)=>x.status==='closed').length;
  const partial=results.filter((x)=>x.status==='partial').length;
  const gaps=results.filter((x)=>x.status==='gap'||x.status==='error').length;
  const exactExpectation=results.filter((x)=>x.status===x.expected).length;
  const total=results.length;
  const solveProxyRate=total?closed/total:0;
  const coverageProxyRate=total?(closed+partial*0.5)/total:0;
  const byDirection={};
  for(const direction of ['prompt-llm-security','adversarial-example','privacy-leakage','backdoor-poisoning','infra-supply-chain']){
    const rows=results.filter((x)=>x.direction===direction);const c=rows.filter((x)=>x.status==='closed').length;const p=rows.filter((x)=>x.status==='partial').length;
    byDirection[direction]={cases:rows.length,closed:c,partial:p,gap:rows.length-c-p,solveProxyRate:rows.length?c/rows.length:0,coverageProxyRate:rows.length?(c+p*0.5)/rows.length:0};
  }
  return{
    schema:'newcyber.ai-stage1-worldwide-holdout.v1',
    summary:{sources:SOURCES.length,cases:total,closed,partial,gaps,solveProxyRate,coverageProxyRate,target:0.70,targetMet:solveProxyRate>=0.70,expectationMatches:exactExpectation},
    byDirection,results,
    gaps:results.filter((x)=>x.status==='gap'||x.status==='error'),
    notes:[
      '这是 source-derived、answer-free 的离线 mechanics holdout：不会下载/执行第三方挑战，也不保存真实 Flag。',
      'solveProxyRate 只表示 NewCyber 对这些公开赛题机制的确定性闭环率，不能等同于“随机比赛真实解题率”。',
      'partial 表示已经能识别/复算关键证据，但缺少生成候选或 challenge-specific executor；gap 会直接进入下一轮开发债务。',
      '公开来源与训练 corpus 分开记录，避免用同一份真实答案做训练/测试自嗨。'
    ]
  };
}

module.exports={SOURCES,CASES,miaRows,poisonRows,triggerRows,backdoorBehaviorRows,runCase,runStage1WorldwideHoldout};
