'use strict';

const {PUBLIC_TRAINING_SEEDS,runAiStage1TrainingRegression}=require('./ai_stage1_training_corpus');
const {getIchunqiuAiTrainingCorpus,runIchunqiuAiTrainingRegression}=require('./ai_ichunqiu_training');
const {getOldDriverTrainingCorpus,runOldDriverTrainingRegression}=require('./ai_adversarial_ctf');
const {getAiRealCtfCorpus,runAiRealCtfRegression}=require('./ai_real_ctf_regression');
const {getPublicChallengeTrainingCorpus,runPublicChallengeTrainingRegression}=require('./ai_public_challenge_training');
const {getOdysseyTrainingCorpus,runOdysseyTrainingRegression}=require('./ai_odyssey_training');
const {getSgAiCtfTrainingCorpus,runSgAiCtfTrainingRegression}=require('./ai_sg_aictf_training');
const {getAiVillageTrainingCorpus,runAiVillageTrainingRegression}=require('./ai_aivillage_training');

const TARGET_DIRECTIONS=Object.freeze([
  'prompt-llm-security','adversarial-example','model-extraction','privacy-leakage',
  'backdoor-poisoning','infra-supply-chain','dataset-pipeline-security'
]);

const CORPORA=Object.freeze([
  {id:'stage1',title:'Stage1 public training',kind:'baseline',get:()=>PUBLIC_TRAINING_SEEDS},
  {id:'ichunqiu',title:'i春秋 domestic CTF replay',kind:'ctf-derived',get:getIchunqiuAiTrainingCorpus},
  {id:'old-driver',title:'Old Driver adversarial replay',kind:'ctf-derived',get:getOldDriverTrainingCorpus},
  {id:'real-ctf',title:'Real/public CTF regression catalog',kind:'ctf-derived',get:getAiRealCtfCorpus},
  {id:'public-challenge',title:'Public challenge training',kind:'ctf-derived',get:getPublicChallengeTrainingCorpus},
  {id:'ai-odyssey-2026',title:'TryHackMe 2026 AI Odyssey',kind:'ctf-derived',get:getOdysseyTrainingCorpus},
  {id:'sg-aictf-2025',title:'AICTF 2025 Pre-U challenge replay',kind:'ctf-derived',get:getSgAiCtfTrainingCorpus},
  {id:'aivillage-defcon-30-31',title:'AI Village DEFCON 30/31 challenge replay',kind:'ctf-derived',get:getAiVillageTrainingCorpus}
]);

function text(value){return value==null?'':String(value).trim();}
function slug(value){return text(value).toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/g,'-').replace(/^-+|-+$/g,'').slice(0,120)||'case';}
function inferDirection(item={}){
  if(text(item.direction))return text(item.direction);
  const hay=[item.aiLabel,item.kind,item.family,item.challenge,item.id].map(text).join(' ').toLowerCase();
  if(/adversarial|对抗样本|fgsm|deepfool/.test(hay))return'adversarial-example';
  if(/extract|steal|model stealing|模型抽取/.test(hay))return'model-extraction';
  if(/inversion|privacy|membership|sensitive|leakage|泄露|隐私/.test(hay))return'privacy-leakage';
  if(/backdoor|poison|投毒|后门/.test(hay))return'backdoor-poisoning';
  if(/supply|artifact|deserial|pickle|供应链/.test(hay))return'infra-supply-chain';
  if(/dataset|tabular|feature|数据集|特征/.test(hay))return'dataset-pipeline-security';
  if(/prompt|rag|llm|agent|asr|jailbreak|提示词|大模型/.test(hay))return'prompt-llm-security';
  return'ai-general';
}
function normalizeProvenance(item={}){
  const p=item.provenance;
  if(p&&typeof p==='object'&&!Array.isArray(p))return{title:text(p.title)||null,url:text(p.url)||text(item.source)||null,kind:text(p.kind)||null,evidenceLevel:text(p.evidenceLevel)||null,label:null};
  return{title:null,url:text(item.source)||null,kind:null,evidenceLevel:null,label:text(p)||null};
}
function normalizeCase(item,corpus,index){
  const rawId=text(item?.id)||`${slug(item?.challenge||item?.kind||'case')}-${index+1}`;
  const event=text(item?.event)||corpus.title;
  const challenge=text(item?.challenge)||text(item?.title)||rawId;
  const direction=inferDirection(item);
  const family=text(item?.family)||text(item?.kind)||direction;
  const provenance=normalizeProvenance(item);
  const caseType=text(item?.caseType)||(/ctf/i.test(corpus.kind)||/ctf|杯|hackergame|odyssey/i.test(event)?'real-ctf':'public-training');
  return{
    id:`${corpus.id}:${rawId}`,rawId,corpus:corpus.id,corpusTitle:corpus.title,corpusKind:corpus.kind,
    event,challenge,direction,family,caseType,
    evaluator:text(item?.evaluator)||null,coverage:text(item?.coverage)||null,limitation:text(item?.limitation)||null,
    trainingPolicy:text(item?.trainingPolicy)||null,provenance,
    capability:text(item?.capability)||null
  };
}
function collectCases(){
  const out=[];const errors=[];
  for(const corpus of CORPORA){
    let rows;try{rows=corpus.get();}catch(error){errors.push({corpus:corpus.id,error:String(error?.message||error)});continue;}
    if(!Array.isArray(rows)){errors.push({corpus:corpus.id,error:'corpus getter did not return array'});continue;}
    rows.forEach((item,index)=>out.push(normalizeCase(item,corpus,index)));
  }
  return{cases:out,errors};
}
function countBy(rows,key){const out={};for(const row of rows){const value=text(typeof key==='function'?key(row):row[key])||'unknown';out[value]=(out[value]||0)+1;}return Object.fromEntries(Object.entries(out).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])));}
function uniqueCount(rows,key){return new Set(rows.map((row)=>text(typeof key==='function'?key(row):row[key])).filter(Boolean)).size;}
function evidenceTier(row){return row.provenance.evidenceLevel||row.provenance.label||row.provenance.kind||'unspecified';}
function coverageDebt(cases){
  const byDirection=countBy(cases,'direction');
  return TARGET_DIRECTIONS.map((direction)=>({direction,cases:byDirection[direction]||0,debt:Math.max(0,8-(byDirection[direction]||0))})).sort((a,b)=>b.debt-a.debt||a.cases-b.cases||a.direction.localeCompare(b.direction));
}
function duplicateGroups(cases){
  const groups=new Map();
  for(const item of cases){const key=`${item.event.toLowerCase()}|${item.challenge.toLowerCase()}|${item.family.toLowerCase()}`;const rows=groups.get(key)||[];rows.push(item);groups.set(key,rows);}
  return [...groups.values()].filter((rows)=>rows.length>1).map((rows)=>({event:rows[0].event,challenge:rows[0].challenge,family:rows[0].family,ids:rows.map((x)=>x.id)})).slice(0,128);
}

function getTrainingCurriculum(){
  const collected=collectCases();const cases=collected.cases;
  const challengeKey=(row)=>`${row.event} :: ${row.challenge}`;
  return{
    schema:'newcyber.ai-training-curriculum.v1',
    generatedFrom:CORPORA.map(({id,title,kind})=>({id,title,kind})),
    summary:{cases:cases.length,corpora:CORPORA.length,events:uniqueCount(cases,'event'),challenges:uniqueCount(cases,challengeKey),families:uniqueCount(cases,'family'),directions:uniqueCount(cases,'direction'),byCorpus:countBy(cases,'corpus'),byDirection:countBy(cases,'direction'),byCaseType:countBy(cases,'caseType'),byEvidence:countBy(cases,evidenceTier)},
    coverageDebt:coverageDebt(cases),
    duplicateGroups:duplicateGroups(cases),
    sourceErrors:collected.errors,
    cases,
    note:'这是赛题驱动的确定性回归 curriculum，不是对底座模型做参数微调。公开赛题只提供题型、证据结构与 provenance；真实 Flag/密钥/答案不得进入 fixture。'
  };
}

const SUITES=Object.freeze([
  {id:'stage1',run:(options)=>runAiStage1TrainingRegression(options)},
  {id:'ichunqiu',run:()=>runIchunqiuAiTrainingRegression()},
  {id:'old-driver',run:()=>runOldDriverTrainingRegression()},
  {id:'real-ctf',run:()=>runAiRealCtfRegression()},
  {id:'public-challenge',run:(options)=>runPublicChallengeTrainingRegression(options)},
  {id:'ai-odyssey-2026',run:(options)=>runOdysseyTrainingRegression(options)},
  {id:'sg-aictf-2025',run:(options)=>runSgAiCtfTrainingRegression(options)},
  {id:'aivillage-defcon-30-31',run:(options)=>runAiVillageTrainingRegression(options)}
]);
function summarizeSuite(result){
  const summary=result&&typeof result.summary==='object'?result.summary:null;
  const rows=Array.isArray(result?.results)?result.results:[];
  const statuses=countBy(rows,(row)=>row.status||((row.recognized===true)?'recognized':(row.recognized===false)?'unrecognized':'unknown'));
  const errors=rows.filter((row)=>row.error||row.status==='error').map((row)=>({seed:row.seed||row.id||null,status:row.status||null,error:row.error||null})).slice(0,32);
  return{schema:result?.schema||null,summary,statuses,errors};
}
function runTrainingCurriculumRegression(options={}){
  const variants=Math.max(1,Math.min(8,Number(options.variantsPerSeed)||2));const suites=[];
  for(const suite of SUITES){
    try{const result=suite.run({variantsPerSeed:variants});suites.push({id:suite.id,ok:true,...summarizeSuite(result)});}
    catch(error){suites.push({id:suite.id,ok:false,schema:null,summary:null,statuses:{},errors:[{seed:null,status:'error',error:String(error?.message||error).slice(0,500)}]});}
  }
  const curriculum=getTrainingCurriculum();
  return{
    schema:'newcyber.ai-training-curriculum-regression.v1',
    variantsPerSeed:variants,
    suites,
    summary:{suites:suites.length,suiteErrors:suites.filter((x)=>!x.ok).length,curriculumCases:curriculum.summary.cases,challenges:curriculum.summary.challenges,events:curriculum.summary.events},
    coverageDebt:curriculum.coverageDebt,
    note:'Full regression 聚合已有 deterministic replay；它不会联网执行原赛题，也不会把 heuristic/candidate 自动提升为 verifier-backed solved。'
  };
}

module.exports={TARGET_DIRECTIONS,CORPORA,SUITES,inferDirection,normalizeProvenance,normalizeCase,collectCases,countBy,coverageDebt,duplicateGroups,getTrainingCurriculum,runTrainingCurriculumRegression};
