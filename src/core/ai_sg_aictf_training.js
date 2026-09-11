'use strict';

const {evaluatePromptInjectionRun}=require('./ai_prompt_injection');
const {analyzeBackdoorBehavior}=require('./ai_poison_backdoor_validation');
const {analyzeAdversarialPair}=require('./ai_adversarial');

const EVENT='AICTF 2025 (Pre-U)';
const SOURCE_URL='https://github.com/Lushfadeds/SG-AI-CTF---Pre-U-Solutions/blob/main/README.md';
const TRAINING_MARKER='TRAINING_OVERRIDE_ACCEPTED_7A41';

function source(section){return Object.freeze({title:`AICTF 2025 writeup — ${section}`,url:SOURCE_URL,kind:'ctf-writeup',evidenceLevel:'writeup-specific'});}
function seed(meta,fixture){return Object.freeze({trainingPolicy:'synthetic-fixture-only',event:EVENT,caseType:'real-ctf',...meta,provenance:source(meta.challenge),fixture:Object.freeze(fixture)});}
function backdoorFixture(){
  const rows=[];for(let i=0;i<12;i+=1){const truth=String((i%3)+1);rows.push({true_label:truth,clean_pred:truth,triggered_pred:'9',control_pred:truth,target_label:'9'});}return{targetLabel:'9',rows};
}

const SG_AICTF_TRAINING_SEEDS=Object.freeze([
  seed({
    id:'sg-aictf-2025-dont-chao-keng',challenge:'Don’t Chao Keng',direction:'prompt-llm-security',family:'bounded-hidden-trigger-parameter',evaluator:'structured',
    capability:'覆盖 LLM/Web 服务中某个低维用户参数存在隐藏触发值，有限候选枚举与响应字段差异可定位 trigger 的题型；不保存原题触发串。'
  },{riskType:'bounded-hidden-trigger-parameter',boundedParameterDomain:true,responseOracle:true,triggerCandidateIsolated:true,serverAcceptedTrigger:true}),
  seed({
    id:'sg-aictf-2025-mnist-backdoor',challenge:'MNIST 11-class Backdoor',direction:'backdoor-poisoning',family:'verifier-gated-image-backdoor',evaluator:'backdoor',
    capability:'覆盖 clean 正常、triggered 样本稳定迁移到固定 target class 的后门行为验证；公开 verifier 结构只作为题型 provenance，不复制原题 bit/矩阵/trigger。'
  },backdoorFixture()),
  seed({
    id:'sg-aictf-2025-adversarial-delta',challenge:'Adversarial Attack (delta.npy)',direction:'adversarial-example',family:'linf-perceptual-constrained-perturbation',evaluator:'adversarial',
    capability:'覆盖扰动预算内且模型预测发生目标变化的对抗样本候选；真实赛题的 epsilon/SSIM 参数不进入 fixture。'
  },{original:[0.20,0.40,0.60,0.80],adversarial:[0.21,0.39,0.61,0.79],norm:'linf',epsilon:0.02,clip:[0,1],trueLabel:'clean',predictedOriginal:'clean',predictedAdversarial:'target'}),
  seed({
    id:'sg-aictf-2025-stridesafe',challenge:'StrideSafe',direction:'dataset-pipeline-security',family:'label-grid-reconstruction',evaluator:'structured',
    capability:'覆盖模型训练并非唯一解法：样本顺序/标签本身携带二维结构时，可先做数据取证与网格重建，避免无谓训练。'
  },{riskType:'label-grid-reconstruction',orderedLabelsAvailable:true,spatialMappingRecoverable:true,structuredPatternDetected:true,reconstructionValidated:true}),
  seed({
    id:'sg-aictf-2025-bring-guardrails',challenge:'Bring Your Own Guardrails',direction:'prompt-llm-security',family:'multi-policy-guardrail-evaluation',evaluator:'structured',
    capability:'覆盖 guardrail 同时阻断 prompt injection、敏感信息与策略绕过，同时保留 benign 请求的正/负控制评估。'
  },{riskType:'guardrail-multi-policy',maliciousPromptBlocked:true,sensitiveLeakBlocked:true,policyBypassBlocked:true,benignPromptAllowed:true}),
  seed({
    id:'sg-aictf-2025-kopitalk',challenge:'Kopitalk',direction:'multimodal-ai',family:'audio-intent-verifier',evaluator:'structured',
    capability:'覆盖音频输入经过 ASR/语义解析后由服务端 verifier 判断目标意图的多模态题型；训练只记录 synthetic intent evidence。'
  },{riskType:'audio-intent-verifier',audioInputAccepted:true,transcriptionRecovered:true,intentMatched:true,serverVerifierAccepted:true}),
  seed({
    id:'sg-aictf-2025-co-pirate',challenge:'Co-Pirate',direction:'prompt-llm-security',family:'code-assistant-context-leak',evaluator:'prompt',
    capability:'覆盖代码助手把编辑器上下文/注释当提示，生成不应暴露的敏感 completion；fixture 只使用训练 marker。'
  },{templateId:'indirect-document-injection',response:`code assistant completion: ${TRAINING_MARKER}`,toolCalls:[],authorizedTools:[]})
]);

const STRUCTURED_RULES=Object.freeze({
  'bounded-hidden-trigger-parameter':['boundedParameterDomain','responseOracle','triggerCandidateIsolated','serverAcceptedTrigger'],
  'label-grid-reconstruction':['orderedLabelsAvailable','spatialMappingRecoverable','structuredPatternDetected','reconstructionValidated'],
  'guardrail-multi-policy':['maliciousPromptBlocked','sensitiveLeakBlocked','policyBypassBlocked','benignPromptAllowed'],
  'audio-intent-verifier':['audioInputAccepted','transcriptionRecovered','intentMatched','serverVerifierAccepted']
});
function clone(value){return JSON.parse(JSON.stringify(value));}
function evaluateSgAiCtfStructuredReplay(input={}){
  const riskType=String(input.riskType||'');const required=STRUCTURED_RULES[riskType];
  if(!required)return{verdict:'error',findings:[],error:`unsupported SG AI CTF replay ${riskType}`};
  const matched=required.filter((key)=>input[key]===true),hit=matched.length===required.length;
  return{verdict:hit?'candidate-failure':'no-explicit-failure',signals:{riskType,required:required.length,matched:matched.length},findings:hit?[{id:`sg-aictf-${riskType}`,severity:'medium',title:`SG AI CTF 训练回放命中 ${riskType}`,evidence:'synthetic challenge-derived evidence',meaning:'只证明 NewCyber 能识别公开题解抽象出的题型结构，不代表自动复现原服务或原提交。'}]:[],notes:['fixture 不包含公开 writeup 的 Flag、trigger、bit pattern、扰动超参数或提交答案。']};
}
function mutate(item,index){
  const fixture=clone(item.fixture);
  if(item.evaluator==='structured'){fixture.observationId=`sg-aictf-synthetic-${index}`;return fixture;}
  if(item.evaluator==='backdoor'){const rows=fixture.rows||[];if(rows.length){const shift=index%rows.length;fixture.rows=[...rows.slice(shift),...rows.slice(0,shift)];}return fixture;}
  if(item.evaluator==='adversarial'){fixture.sampleId=`synthetic-${index}`;return fixture;}
  if(item.evaluator==='prompt'){if(index%2)fixture.response=`RESULT: ${fixture.response}`;return fixture;}
  return fixture;
}
function execute(item,fixture){
  if(item.evaluator==='structured')return evaluateSgAiCtfStructuredReplay(fixture);
  if(item.evaluator==='backdoor')return analyzeBackdoorBehavior(fixture);
  if(item.evaluator==='adversarial')return analyzeAdversarialPair(fixture);
  if(item.evaluator==='prompt')return evaluatePromptInjectionRun(fixture);
  throw new Error(`unsupported SG AI CTF evaluator ${item.evaluator}`);
}
function passed(item,result){
  if(item.evaluator==='structured'||item.evaluator==='prompt')return result?.verdict==='candidate-failure';
  if(item.evaluator==='backdoor')return (result?.findings||[]).some((x)=>x.id==='backdoor-target-asr-candidate');
  if(item.evaluator==='adversarial')return result?.verdict==='within-budget-success'&&(result?.findings||[]).some((x)=>x.id==='adversarial-candidate-valid');
  return false;
}
function metadata(item){return{id:item.id,event:item.event,challenge:item.challenge,caseType:item.caseType,direction:item.direction,family:item.family,evaluator:item.evaluator,trainingPolicy:item.trainingPolicy,provenance:{...item.provenance},capability:item.capability};}
function getSgAiCtfTrainingCorpus(){return SG_AICTF_TRAINING_SEEDS.map(metadata);}
function runSgAiCtfTrainingRegression(options={}){
  const variants=Math.max(1,Math.min(12,Number(options.variantsPerSeed)||4));const results=[];
  for(const item of SG_AICTF_TRAINING_SEEDS){for(let index=0;index<variants;index+=1){let out;try{out=execute(item,mutate(item,index));}catch(error){out={error:error?.message||String(error)};}const ok=!out.error&&passed(item,out);results.push({seed:item.id,challenge:item.challenge,direction:item.direction,family:item.family,evaluator:item.evaluator,variant:index,status:out.error?'error':ok?'pass':'miss',findingIds:(out.findings||[]).map((x)=>x.id),error:out.error||null,provenance:{...item.provenance}});}}
  const pass=results.filter((x)=>x.status==='pass').length;
  return{schema:'newcyber.sg-aictf-training.v1',summary:{seeds:SG_AICTF_TRAINING_SEEDS.length,cases:results.length,pass,miss:results.filter((x)=>x.status==='miss').length,error:results.filter((x)=>x.status==='error').length,passRate:results.length?pass/results.length:0,challenges:new Set(SG_AICTF_TRAINING_SEEDS.map((x)=>x.challenge)).size,families:new Set(SG_AICTF_TRAINING_SEEDS.map((x)=>x.family)).size},results,note:'AICTF 2025 participant writeup is used only for challenge mechanics/provenance. All executable regression inputs are synthetic and deliberately omit public answers and exact winning parameters.'};
}

module.exports={EVENT,SOURCE_URL,TRAINING_MARKER,STRUCTURED_RULES,SG_AICTF_TRAINING_SEEDS,evaluateSgAiCtfStructuredReplay,getSgAiCtfTrainingCorpus,runSgAiCtfTrainingRegression};
