'use strict';

const { analyzePoisoningImpact, analyzeBackdoorBehavior } = require('./ai_poison_backdoor_validation');
const { evaluateLossHistoryPoisonReplay } = require('./ai_domestic_detection_training');

const SOURCES=Object.freeze({
  ccsssc2026:'https://github.com/CTF-Archives/2026-CCSSSC-Final/blob/main/README.md',
  gyxxaqjnds2025:'https://github.com/CTF-Archives/2025-gyxxaqjnds-Finals/blob/main/%E6%8A%95%E6%AF%92%E6%A3%80%E6%B5%8B%E9%9D%B6%E5%9C%BA/README.md',
  ccb2025:'https://blog.qingchenyou.asia/CTF-WriteUP/ccb_wp/index.html'
});

function provenance(title,url,kind='official-challenge-archive',evidenceLevel='challenge-source-specific'){
  return Object.freeze({title,url,kind,evidenceLevel});
}
function seed(meta,fixture){
  return Object.freeze({
    trainingPolicy:'synthetic-fixture-only',
    caseType:'real-ctf',
    direction:'backdoor-poisoning',
    ...meta,
    provenance:Object.freeze(meta.provenance),
    fixture:Object.freeze(fixture)
  });
}
function clone(value){return JSON.parse(JSON.stringify(value));}
function hasFinding(result,id){return (result?.findings||[]).some((item)=>item.id===id);}

function cifarBackdoorFixture(){
  const rows=[];
  for(let label=0;label<8;label+=1){
    rows.push({
      id:`sample-${label}`,
      true_label:String(label),
      clean_pred:String(label),
      triggered_pred:'9',
      control_pred:String(label),
      target_label:'9'
    });
  }
  return {targetLabel:'9',rows};
}

function lossHistoryFixture(){
  return {
    thresholdRatio:0.25,
    poisonTruth:['sample-p1','sample-p2'],
    rows:[
      {id:'sample-c1',losses:[0.82,0.78,0.75,0.73,0.71]},
      {id:'sample-c2',losses:[0.76,0.73,0.71,0.69,0.68]},
      {id:'sample-c3',losses:[0.91,0.87,0.84,0.82,0.80]},
      {id:'sample-p1',losses:[0.40,1.35,0.32,1.48,0.27]},
      {id:'sample-c4',losses:[0.67,0.64,0.62,0.61,0.60]},
      {id:'sample-c5',losses:[0.88,0.85,0.82,0.80,0.79]},
      {id:'sample-p2',losses:[0.52,1.62,0.41,1.70,0.38]},
      {id:'sample-c6',losses:[0.72,0.70,0.68,0.67,0.66]}
    ]
  };
}

function labelSwapFixture(){
  const rows=[];
  for(let i=0;i<6;i+=1){
    const original=String(i%2);
    rows.push({
      id:`poison-${i+1}`,
      is_poison:true,
      original_label:original,
      label:original==='0'?'1':'0',
      trigger_id:'label-swap'
    });
  }
  for(let i=0;i<6;i+=1){
    const label=String(i%2);
    rows.push({id:`clean-${i+1}`,is_poison:false,original_label:label,label});
  }
  return {
    baseline:{accuracy:0.92,f1:0.91,loss:0.21},
    suspect:{accuracy:0.61,f1:0.59,loss:0.74},
    rows
  };
}

const DOMESTIC_BACKDOOR_TRAINING_SEEDS=Object.freeze([
  seed({
    id:'ccsssc-2026-cifar10-backdoor-activation',
    event:'2026软件系统安全赛总决赛',
    challenge:'CIFAR-10',
    family:'image-trigger-backdoor-target-asr',
    evaluator:'backdoor-behavior',
    provenance:provenance('2026 软件系统安全赛总决赛官方题目归档',SOURCES.ccsssc2026),
    capability:'覆盖“怀疑分类模型存在后门 → 找到 trigger → 比较 clean / triggered / neutral-control 行为 → 用目标 ASR 与特异性确认候选”的比赛链路；训练只使用合成预测，不保存原题模型、触发器或 Flag。'
  },cifarBackdoorFixture()),
  seed({
    id:'gyxxaqjnds-2025-loss-history-poison-ranking',
    event:'2025 gyxxaqjnds Finals',
    challenge:'投毒检测靶场',
    family:'loss-history-poison-ranking',
    evaluator:'loss-history-poison',
    provenance:provenance('2025 投毒检测靶场官方归档',SOURCES.gyxxaqjnds2025),
    capability:'覆盖按每样本 loss 历史变化做异常排序、按比例筛选投毒候选并用独立 truth/verifier 复算的赛式。'
  },lossHistoryFixture()),
  seed({
    id:'ccb-2025-easy-poison-label-swap',
    event:'CCB2025（公开 WP 标注为第五届长城杯）',
    challenge:'easy_poison',
    family:'label-swap-poisoning-impact',
    evaluator:'poisoning-impact',
    provenance:provenance('CCB2025 easy_poison 公开 WriteUp',SOURCES.ccb2025,'ctf-writeup','writeup-specific'),
    capability:'覆盖训练集标签交换型投毒：先确认显式/候选污染子集，再验证 label flip 与模型性能退化；不把“改了标签”本身直接等价成攻击成功。'
  },labelSwapFixture())
]);

function negativeFixture(item){
  const fixture=clone(item.fixture);
  if(item.evaluator==='backdoor-behavior'){
    fixture.rows=fixture.rows.map((row)=>({...row,triggered_pred:row.clean_pred,control_pred:row.clean_pred}));
    return fixture;
  }
  if(item.evaluator==='loss-history-poison'){
    fixture.rows=fixture.rows.map((row,index)=>({...row,losses:[0.82-index*0.01,0.79-index*0.01,0.76-index*0.01,0.74-index*0.01,0.72-index*0.01]}));
    return fixture;
  }
  if(item.evaluator==='poisoning-impact'){
    fixture.rows=fixture.rows.map((row)=>({...row,label:row.original_label}));
    fixture.suspect={...fixture.baseline};
    return fixture;
  }
  return fixture;
}

function execute(item,fixture){
  if(item.evaluator==='backdoor-behavior')return analyzeBackdoorBehavior(fixture);
  if(item.evaluator==='loss-history-poison')return evaluateLossHistoryPoisonReplay(fixture);
  if(item.evaluator==='poisoning-impact')return analyzePoisoningImpact(fixture);
  throw new Error(`unsupported domestic backdoor evaluator ${item.evaluator}`);
}

function positivePassed(item,result){
  if(item.evaluator==='backdoor-behavior'){
    return result?.verdict==='strong-candidate' && hasFinding(result,'backdoor-target-asr-candidate') && hasFinding(result,'backdoor-control-specificity');
  }
  if(item.evaluator==='loss-history-poison'){
    return result?.validation?.exact===true && hasFinding(result,'poison-loss-history-ranking-recovered');
  }
  if(item.evaluator==='poisoning-impact'){
    return (result?.labelFlip?.rate??0)>=0.8 && hasFinding(result,'poisoning-label-flip-candidate') && hasFinding(result,'poisoning-model-impact-candidate');
  }
  return false;
}

function negativePassed(item,result){
  if(item.evaluator==='backdoor-behavior'){
    return result?.verdict!=='strong-candidate' && !hasFinding(result,'backdoor-target-asr-candidate') && !hasFinding(result,'backdoor-control-specificity');
  }
  if(item.evaluator==='loss-history-poison'){
    return result?.validation?.exact===false && !hasFinding(result,'poison-loss-history-ranking-recovered');
  }
  if(item.evaluator==='poisoning-impact'){
    return (result?.labelFlip?.rate??0)===0 && !hasFinding(result,'poisoning-label-flip-candidate') && !hasFinding(result,'poisoning-model-impact-candidate');
  }
  return false;
}

function metadata(item){
  return {
    id:item.id,event:item.event,challenge:item.challenge,caseType:item.caseType,direction:item.direction,
    family:item.family,evaluator:item.evaluator,trainingPolicy:item.trainingPolicy,
    provenance:{...item.provenance},capability:item.capability
  };
}

function getDomesticBackdoorTrainingCorpus(){
  return DOMESTIC_BACKDOOR_TRAINING_SEEDS.map(metadata);
}

function runDomesticBackdoorTrainingRegression(){
  const results=[];
  for(const item of DOMESTIC_BACKDOOR_TRAINING_SEEDS){
    for(const control of ['positive','negative']){
      let output;
      try{output=execute(item,control==='positive'?clone(item.fixture):negativeFixture(item));}
      catch(error){output={error:error?.message||String(error),findings:[]};}
      const ok=control==='positive'?positivePassed(item,output):negativePassed(item,output);
      results.push({
        caseId:item.id,event:item.event,challenge:item.challenge,family:item.family,evaluator:item.evaluator,
        control,status:ok?'pass':'miss',verdict:output?.verdict||null,
        findingIds:(output?.findings||[]).map((finding)=>finding.id),error:output?.error||null
      });
    }
  }
  const pass=results.filter((item)=>item.status==='pass').length;
  const families=[...new Set(DOMESTIC_BACKDOOR_TRAINING_SEEDS.map((item)=>item.family))];
  return {
    schema:'newcyber.ai-domestic-backdoor-training-regression.v1',
    direction:'backdoor-poisoning',
    summary:{
      challenges:DOMESTIC_BACKDOOR_TRAINING_SEEDS.length,
      families:families.length,
      total:results.length,
      pass,
      miss:results.length-pass,
      positiveControls:results.filter((item)=>item.control==='positive').length,
      negativeControls:results.filter((item)=>item.control==='negative').length
    },
    families,
    cases:getDomesticBackdoorTrainingCorpus(),
    results,
    note:'国内赛式回归只提炼公开题面/WP能够确认的判定结构。所有预测、loss、标签和指标均为合成 fixture；PASS 仅表示 NewCyber 能正确解释该类证据，不代表已自动恢复原题 trigger、模型或 Flag。'
  };
}

module.exports={
  SOURCES,
  DOMESTIC_BACKDOOR_TRAINING_SEEDS,
  getDomesticBackdoorTrainingCorpus,
  runDomesticBackdoorTrainingRegression
};
