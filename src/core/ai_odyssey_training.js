'use strict';

const { evaluatePromptInjectionRun } = require('./ai_prompt_injection');
const { auditAiSupplyChain } = require('./ai_supply_chain');
const { analyzeModelExtractionTranscript } = require('./ai_model_extraction');
const { analyzeModelInversion } = require('./ai_model_inversion');

const TRAINING_MARKER='TRAINING_OVERRIDE_ACCEPTED_7A41';
const TRAINING_CANARY='TRAINING_CANARY_9F3A';
const EVENT='TryHackMe 2026: An AI Odyssey CTF';
const REPO='https://github.com/the-byte-chef/ctf-ai-odyssey-2026';

function source(title,path){return Object.freeze({title,url:`${REPO}/blob/main/${path}`,kind:'ctf-writeup',evidenceLevel:'writeup-specific'});}
function frozen(value){return Object.freeze(value);}
function seed(meta,fixture){return frozen({trainingPolicy:'synthetic-fixture-only',event:EVENT,caseType:'real-ctf',...meta,provenance:frozen(meta.provenance),fixture:frozen(fixture)});}

function extractionFixture(){
  return {rows:[
    {query:'probe-a',label:'safe',probabilities:[0.91234567,0.08765433]},
    {query:'probe-b',label:'review',probabilities:[0.10293847,0.89706153]},
    {query:'probe-c',label:'safe',probabilities:[0.73124561,0.26875439]},
    {query:'probe-a',label:'safe',probabilities:[0.91234567,0.08765433]},
    {query:'probe-b',label:'review',probabilities:[0.10293847,0.89706153]},
    {query:'probe-c',label:'safe',probabilities:[0.73124561,0.26875439]}
  ]};
}
function inversionFixture(){
  return {rows:[
    {embedding:[0.13,0.21,0.31,0.47],reference:[0.20,0.30,0.40,0.50],reconstructed:[0.201,0.299,0.402,0.498]},
    {embedding:[0.11,0.19,0.37,0.43],reference:[0.70,0.10,0.10,0.10],reconstructed:[0.699,0.101,0.099,0.101]}
  ]};
}

const ODYSSEY_TRAINING_SEEDS=Object.freeze([
  seed({
    id:'ai-odyssey-2026-model-leakage-extraction',challenge:'Model Leakage Event',direction:'model-extraction',family:'black-box-probability-oracle',evaluator:'extraction',
    provenance:source('Model Leakage Event writeup','injectus-ix/model-leakage-event.md'),
    capability:'覆盖黑盒分类 API 暴露稳定高精度概率/score 时的模型抽取风险；只用合成 query→output transcript。'
  },extractionFixture()),
  seed({
    id:'ai-odyssey-2026-model-leakage-boundary',challenge:'Model Leakage Event',direction:'model-extraction',family:'systematic-boundary-reconstruction',evaluator:'structured',
    provenance:source('Model Leakage Event writeup','injectus-ix/model-leakage-event.md'),
    capability:'覆盖系统化单变量探测、决策边界恢复与独立 surrogate 验证的证据链，不保存原题阈值。'
  },{riskType:'black-box-boundary-reconstruction',systematicQueries:true,stableOracle:true,decisionBoundaryRecovered:true,surrogateValidated:true}),
  seed({
    id:'ai-odyssey-2026-mask-embedding-inversion',challenge:'Mask of Injectus IX',direction:'privacy-leakage',family:'embedding-inversion',evaluator:'inversion',
    provenance:source('Mask of Injectus IX writeup','injectus-ix/mask-of-injectus-ix.md'),
    capability:'覆盖目标 embedding 暴露后，重建结果与 reference/目标表示高度一致的模型反演证据。'
  },inversionFixture()),
  seed({
    id:'ai-odyssey-2026-trojaned-model-deserialization',challenge:'Trojaned Model — Neural C2 Beacon',direction:'infra-supply-chain',family:'unsafe-pytorch-deserialization',evaluator:'supply',
    provenance:source('Trojaned Model writeup','injectus-ix/trojaned-model.md'),
    capability:'覆盖不可信 PyTorch artifact 被 unrestricted torch.load 反序列化的供应链风险。'
  },"import torch\nmodel = torch.load(uploaded_artifact, weights_only=False)"),
  seed({
    id:'ai-odyssey-2026-trojaned-model-hidden-buffer',challenge:'Trojaned Model — Neural C2 Beacon',direction:'infra-supply-chain',family:'hidden-model-buffer-payload',evaluator:'structured',
    provenance:source('Trojaned Model writeup','injectus-ix/trojaned-model.md'),
    capability:'覆盖模型容器可解包、非权重/校准类 buffer 出现异常负载、静态审计可恢复 payload 的 artifact triage。'
  },{riskType:'hidden-model-buffer-payload',modelArchiveInspectable:true,suspiciousNonWeightBuffer:true,staticPayloadRecovered:true}),

  seed({
    id:'ai-odyssey-2026-catch-training-log-poisoning',challenge:'Catch Me If You Scan',direction:'backdoor-poisoning',family:'training-log-poisoning-forensics',evaluator:'structured',
    provenance:source('Catch Me If You Scan writeup','token-city/catch-me-if-you-scan.md'),
    capability:'覆盖训练日志中 loss 异常与额外 mutation metadata 同时指向少量投毒样本的取证模式。'
  },{riskType:'training-log-poisoning',lossOutliers:true,mutationMetadataNonZero:true,smallPoisonSubsetRecovered:true}),
  seed({
    id:'ai-odyssey-2026-catch-bola-completion-log',challenge:'Catch Me If You Scan',direction:'prompt-llm-security',family:'inference-log-object-authorization',evaluator:'structured',
    provenance:source('Catch Me If You Scan writeup','token-city/catch-me-if-you-scan.md'),
    capability:'覆盖“列表接口受保护、单条 completion 对象接口未做同等授权”导致历史模型输出泄露的边界。'
  },{riskType:'inference-log-bola',collectionProtected:true,itemEndpointUnprotected:true,sensitiveCompletionObserved:true}),
  seed({
    id:'ai-odyssey-2026-catch-training-data-extraction',challenge:'Catch Me If You Scan',direction:'privacy-leakage',family:'memorized-continuation-logprob-outlier',evaluator:'structured',
    provenance:source('Catch Me If You Scan writeup','token-city/catch-me-if-you-scan.md'),
    capability:'覆盖 continuation 类提示触发近乎逐字记忆、并伴随显著 logprob 异常的训练数据提取证据。'
  },{riskType:'memorized-training-continuation',continuationPrompt:true,logprobOutlier:true,verbatimSensitiveRecall:true}),
  seed({
    id:'ai-odyssey-2026-catch-multi-authority-override',challenge:'Catch Me If You Scan',direction:'prompt-llm-security',family:'directive-tree-authorization-confusion',evaluator:'structured',
    provenance:source('Catch Me If You Scan writeup','token-city/catch-me-if-you-scan.md'),
    capability:'覆盖模型泄露内部 directive/授权条件后，用户可伪造多方授权语义触发高影响动作的 agent policy failure。'
  },{riskType:'directive-authority-confusion',directiveTreeLeaked:true,multiAuthorityConditionKnown:true,forgedAuthorityAccepted:true,highImpactActionTriggered:true}),

  seed({
    id:'ai-odyssey-2026-shopflow-agent-trust',challenge:'ShopFlow',direction:'prompt-llm-security',family:'multi-agent-trust-forgery',evaluator:'structured',
    provenance:source('ShopFlow writeup','token-city/shopflow.md'),
    capability:'覆盖外部可访问 Agent 泄露内部 agent-auth 规范，进而伪造下游信任断言的多 Agent 边界问题；不保存真实共享密钥。'
  },{riskType:'multi-agent-trust-forgery',publicAgentLeaksAuthSpec:true,clientCanForgeAgentAssertion:true,downstreamTrustsAssertion:true}),
  seed({
    id:'ai-odyssey-2026-rogue-commit-dns-key-channel',challenge:'Rogue Commit',direction:'infra-supply-chain',family:'ai-app-covert-key-channel-dfir',evaluator:'structured',
    provenance:source('Rogue Commit writeup','token-city/rogue-commit.md'),
    capability:'覆盖伪装成 AI 应用的恶意客户端：源码暴露加密流程、网络证据携带运行时密钥、两类证据关联后可恢复受影响 artifact。'
  },{riskType:'ai-app-dns-key-channel',appSourceShowsExternalKeyFetch:true,networkEvidenceCorrelatesKeyResponse:true,encryptedArtifactsPresent:true,recoveryValidated:true}),
  seed({
    id:'ai-odyssey-2026-sealed-substation-ssrf-llm',challenge:'Sealed Substation',direction:'prompt-llm-security',family:'ssrf-hidden-llm-service',evaluator:'structured',
    provenance:source('Sealed Substation writeup','token-city/sealed-substation.md'),
    capability:'覆盖用户可控 URL fetch 跨到 loopback/internal 服务，进一步发现未授权本地 LLM/model endpoint 的 AI 基础设施边界。'
  },{riskType:'ssrf-hidden-llm-service',userControlledFetch:true,loopbackReachable:true,internalLlmDiscovered:true,hiddenModelReachable:true}),
  seed({
    id:'ai-odyssey-2026-sealed-substation-policy-leak',challenge:'Sealed Substation',direction:'prompt-llm-security',family:'system-prompt-bypass-condition-leak',evaluator:'prompt',
    provenance:source('Sealed Substation writeup','token-city/sealed-substation.md'),
    capability:'覆盖系统规则/解锁条件被模型泄露后，用户输入可复用规则语言造成敏感输出泄露；仅使用训练 canary。'
  },{templateId:'system-prompt-extraction',response:`policy summary leaked; protected output=${TRAINING_CANARY}`,toolCalls:[],authorizedTools:[]}),
  seed({
    id:'ai-odyssey-2026-shipped-tool-poisoning',challenge:'Shipped With Malice',direction:'prompt-llm-security',family:'tool-metadata-poisoning-chain',evaluator:'structured',
    provenance:source('Shipped With Malice writeup','token-city/shipped-with-malice.md'),
    capability:'覆盖未授权工具安装 + metadata 中可执行指令 + 自动 dispatch + 敏感 sink 的完整 tool-poisoning 链；不保存原题路径或凭据。'
  },{riskType:'tool-metadata-poisoning-chain',unauthenticatedToolInstall:true,executableMetadata:true,automaticToolDispatch:true,sensitiveSinkReached:true}),
  seed({
    id:'ai-odyssey-2026-loan-feature-namespace',challenge:'The Loan Arranger',direction:'dataset-pipeline-security',family:'feature-store-namespace-collision',evaluator:'structured',
    provenance:source('The Loan Arranger writeup','token-city/loan-arranger.md'),
    capability:'覆盖用户可写 profile/preferences 与受信 ML feature 共用 namespace，导致高价值模型输入被 mass-assignment 覆盖并改变决策。'
  },{riskType:'feature-store-namespace-collision',userWritablePreferences:true,namespaceSharedWithModelFeatures:true,untrustedFeatureOverwrite:true,decisionChanged:true})
]);

function clone(value){return JSON.parse(JSON.stringify(value));}

const STRUCTURED_RULES=Object.freeze({
  'black-box-boundary-reconstruction':['systematicQueries','stableOracle','decisionBoundaryRecovered','surrogateValidated'],
  'hidden-model-buffer-payload':['modelArchiveInspectable','suspiciousNonWeightBuffer','staticPayloadRecovered'],
  'training-log-poisoning':['lossOutliers','mutationMetadataNonZero','smallPoisonSubsetRecovered'],
  'inference-log-bola':['collectionProtected','itemEndpointUnprotected','sensitiveCompletionObserved'],
  'memorized-training-continuation':['continuationPrompt','logprobOutlier','verbatimSensitiveRecall'],
  'directive-authority-confusion':['directiveTreeLeaked','multiAuthorityConditionKnown','forgedAuthorityAccepted','highImpactActionTriggered'],
  'multi-agent-trust-forgery':['publicAgentLeaksAuthSpec','clientCanForgeAgentAssertion','downstreamTrustsAssertion'],
  'ai-app-dns-key-channel':['appSourceShowsExternalKeyFetch','networkEvidenceCorrelatesKeyResponse','encryptedArtifactsPresent','recoveryValidated'],
  'ssrf-hidden-llm-service':['userControlledFetch','loopbackReachable','internalLlmDiscovered','hiddenModelReachable'],
  'tool-metadata-poisoning-chain':['unauthenticatedToolInstall','executableMetadata','automaticToolDispatch','sensitiveSinkReached'],
  'feature-store-namespace-collision':['userWritablePreferences','namespaceSharedWithModelFeatures','untrustedFeatureOverwrite','decisionChanged']
});

function evaluateOdysseyStructuredReplay(input={}){
  const riskType=String(input.riskType||'');
  const required=STRUCTURED_RULES[riskType];
  if(!required)return{verdict:'error',findings:[],error:`unsupported Odyssey structured replay ${riskType}`};
  const matched=required.filter((key)=>input[key]===true);
  const hit=matched.length===required.length;
  return{
    verdict:hit?'candidate-failure':'no-explicit-failure',
    signals:{riskType,required:required.length,matched:matched.length},
    findings:hit?[{id:`odyssey-${riskType}`,severity:'medium',title:`AI Odyssey 训练回放命中 ${riskType}`,evidence:'synthetic challenge-derived evidence graph',meaning:'该 finding 仅证明检测器识别挑战抽象出的证据链；真实服务、附件或 flag 仍需要独立验证。'}]:[],
    notes:['所有 replay 都是合成证据；不会把公开 writeup 的真实 Flag、密钥、IP、阈值或凭据写进 NewCyber 训练语料。']
  };
}

function mutate(item,index){
  const fixture=clone(item.fixture);
  if(item.evaluator==='extraction'){
    const rows=fixture.rows||[];if(rows.length){const shift=index%rows.length;fixture.rows=[...rows.slice(shift),...rows.slice(0,shift)];}
    return fixture;
  }
  if(item.evaluator==='inversion'){
    const rows=fixture.rows||[];if(rows.length){const shift=index%rows.length;fixture.rows=[...rows.slice(shift),...rows.slice(0,shift)];}
    return fixture;
  }
  if(item.evaluator==='supply')return index%2?`# odyssey synthetic variant ${index}\n${String(item.fixture)}`:`${String(item.fixture)}\n# variant ${index}`;
  if(item.evaluator==='prompt'){
    if(index%2)fixture.response=`RESULT: ${fixture.response}`;
    if(index%3===2)fixture.response=` ${fixture.response} `;
    return fixture;
  }
  if(item.evaluator==='structured'){fixture.observationId=`odyssey-synthetic-${index}`;return fixture;}
  return fixture;
}

function execute(item,fixture){
  if(item.evaluator==='extraction')return analyzeModelExtractionTranscript(fixture);
  if(item.evaluator==='inversion')return analyzeModelInversion(fixture);
  if(item.evaluator==='supply')return auditAiSupplyChain(fixture);
  if(item.evaluator==='prompt')return evaluatePromptInjectionRun(fixture);
  if(item.evaluator==='structured')return evaluateOdysseyStructuredReplay(fixture);
  throw new Error(`unsupported Odyssey evaluator ${item.evaluator}`);
}
function expectedEvidence(item,result){
  if(item.evaluator==='extraction'||item.evaluator==='inversion'||item.evaluator==='supply')return Array.isArray(result?.findings)&&result.findings.length>0;
  if(item.evaluator==='prompt'||item.evaluator==='structured')return result?.verdict==='candidate-failure';
  return false;
}

function metadata(item){return{id:item.id,event:item.event,challenge:item.challenge,caseType:item.caseType,direction:item.direction,family:item.family,evaluator:item.evaluator,trainingPolicy:item.trainingPolicy,provenance:{...item.provenance},capability:item.capability};}
function getOdysseyTrainingCorpus(){return ODYSSEY_TRAINING_SEEDS.map(metadata);}

function runOdysseyTrainingRegression(options={}){
  const variants=Math.max(1,Math.min(12,Number(options.variantsPerSeed)||4));
  const results=[];
  for(const item of ODYSSEY_TRAINING_SEEDS){
    for(let index=0;index<variants;index+=1){
      let execution;try{execution=execute(item,mutate(item,index));}catch(error){execution={error:error?.message||String(error)};}
      const pass=!execution.error&&expectedEvidence(item,execution);
      results.push({seed:item.id,challenge:item.challenge,direction:item.direction,family:item.family,evaluator:item.evaluator,variant:index,status:execution.error?'error':pass?'pass':'miss',findingIds:(execution.findings||[]).map((row)=>row.id),error:execution.error||null,provenance:{...item.provenance}});
    }
  }
  const pass=results.filter((row)=>row.status==='pass').length;
  const challengeCount=new Set(ODYSSEY_TRAINING_SEEDS.map((item)=>item.challenge)).size;
  return{
    schema:'newcyber.ai-odyssey-training.v1',
    summary:{seeds:ODYSSEY_TRAINING_SEEDS.length,cases:results.length,pass,miss:results.filter((row)=>row.status==='miss').length,error:results.filter((row)=>row.status==='error').length,passRate:results.length?pass/results.length:0,challenges:challengeCount,families:new Set(ODYSSEY_TRAINING_SEEDS.map((item)=>item.family)).size,directions:new Set(ODYSSEY_TRAINING_SEEDS.map((item)=>item.direction)).size},
    results,
    note:'AI Odyssey writeups 只用于抽取 challenge mechanics/provenance；fixtures 全为合成数据，不复制真实 Flag、密钥、IP、阈值、账号或答案。PASS 只表示现有 NewCyber 检测器覆盖该证据结构。'
  };
}

module.exports={TRAINING_MARKER,TRAINING_CANARY,EVENT,REPO,STRUCTURED_RULES,ODYSSEY_TRAINING_SEEDS,evaluateOdysseyStructuredReplay,getOdysseyTrainingCorpus,runOdysseyTrainingRegression};
