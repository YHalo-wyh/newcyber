'use strict';

const {analyzeTrainingQuality,signature}=require('./ai_training_quality');
const {analyzeCrossEventHoldout}=require('./ai_training_holdout');
const {buildTrainingSchedule}=require('./ai_training_scheduler');

function text(value){return value==null?'':String(value).trim();}
function clone(value){return value==null?value:JSON.parse(JSON.stringify(value));}
function byDirection(rows=[],direction){return (Array.isArray(rows)?rows:[]).find((row)=>row.direction===direction)||null;}
function rankOf(schedule={},direction){const row=(schedule.queue||[]).find((item)=>item.direction===direction);return row?row.rank:null;}
function scoreOf(schedule={},direction){const row=(schedule.queue||[]).find((item)=>item.direction===direction);return row?Number(row.score)||0:null;}
function unique(values=[]){return [...new Set(values.filter(Boolean))];}

function normalizeCandidate(materialized={}){
  if(materialized?.schema!=='newcyber.ai-training-regression-materializer.v1'||materialized?.status!=='ready-to-commit'||materialized?.readyToCommit!==true)return null;
  const corpusContent=materialized?.artifacts?.corpus?.content;
  const explicit=materialized?.corpusEntry||materialized?.candidate||materialized?.integration?.corpusEntry;
  if(explicit&&typeof explicit==='object')return clone(explicit);
  const source=materialized?.sourceSkeleton?.corpusEntry;
  if(source&&typeof source==='object')return clone(source);
  const meta=materialized?.metadata?.corpusEntry;
  if(meta&&typeof meta==='object')return clone(meta);
  if(typeof corpusContent==='string'){
    const match=corpusContent.match(/const\s+CORPUS_ENTRY\s*=\s*(\{[\s\S]*?\});\s*\nconst\s+FIXTURES=/);
    if(match){try{return JSON.parse(match[1]);}catch{}}
  }
  return null;
}

function normalizeForCurriculum(entry={}){
  return{
    id:text(entry.id)||`integration:${text(entry.challenge)||'candidate'}`,
    rawId:text(entry.id)||text(entry.challenge)||'candidate',
    corpus:'integration-preview',
    corpusTitle:'Integration preview',
    corpusKind:'ctf-derived',
    event:text(entry.event),
    challenge:text(entry.challenge),
    direction:text(entry.direction),
    family:text(entry.family),
    caseType:text(entry.caseType)||'public-training',
    evaluator:text(entry.evaluator)||null,
    coverage:text(entry.coverage)||null,
    limitation:text(entry.limitation)||null,
    trainingPolicy:text(entry.trainingPolicy)||'public-evidence-plus-synthetic-regression-only',
    provenance:entry.provenance&&typeof entry.provenance==='object'?clone(entry.provenance):{},
    capability:text(entry.capability)||null
  };
}

function metrics(cases=[],directions=[]){
  const quality=analyzeTrainingQuality(cases,{directions});
  const holdout=analyzeCrossEventHoldout(cases,{directions,minTrainEvents:2});
  const schedule=buildTrainingSchedule({cases,quality,holdout},{directions});
  return{quality,holdout,schedule};
}

function computeDelta(before={},after={},direction){
  const bq=byDirection(before.quality?.byDirection,direction)||{};
  const aq=byDirection(after.quality?.byDirection,direction)||{};
  const bh=byDirection(before.holdout?.byDirection,direction)||{summary:{}};
  const ah=byDirection(after.holdout?.byDirection,direction)||{summary:{}};
  const beforeRank=rankOf(before.schedule,direction);
  const afterRank=rankOf(after.schedule,direction);
  return{
    direction,
    qualityScore:Number(((aq.qualityScore||0)-(bq.qualityScore||0)).toFixed(4)),
    effectiveCases:Number(((aq.effectiveCases||0)-(bq.effectiveCases||0)).toFixed(3)),
    rawCases:(aq.rawCases||0)-(bq.rawCases||0),
    events:(aq.uniqueEvents||0)-(bq.uniqueEvents||0),
    families:(aq.uniqueFamilies||0)-(bq.uniqueFamilies||0),
    challenges:(aq.uniqueChallenges||0)-(bq.uniqueChallenges||0),
    duplicateRatio:Number(((aq.duplicateRatio||0)-(bq.duplicateRatio||0)).toFixed(4)),
    provenanceAverage:Number(((aq.provenanceAverage||0)-(bq.provenanceAverage||0)).toFixed(4)),
    holdoutEligible:{before:Boolean(bh.eligible),after:Boolean(ah.eligible)},
    cleanPlans:(ah.summary?.cleanPlans||0)-(bh.summary?.cleanPlans||0),
    unseenFamilyPlans:(ah.summary?.unseenFamilyPlans||0)-(bh.summary?.unseenFamilyPlans||0),
    scheduleRank:{before:beforeRank,after:afterRank,delta:beforeRank==null||afterRank==null?null:afterRank-beforeRank},
    scheduleScore:{before:scoreOf(before.schedule,direction),after:scoreOf(after.schedule,direction)}
  };
}

function integrationPatch(materialized={},candidate={}){
  const artifacts=materialized.artifacts||{};
  return{
    files:[artifacts.corpus,artifacts.test,artifacts.doc].filter((file)=>file&&text(file.path)&&typeof file.content==='string').map((file)=>({path:file.path,operation:'create',content:file.content})),
    registry:{
      action:'register-corpus-getter',
      target:'src/core/ai_training_curriculum.js',
      candidate:{id:candidate.id,event:candidate.event,challenge:candidate.challenge,direction:candidate.direction,family:candidate.family},
      note:'Register the generated corpus module only after repository tests pass. This planner intentionally does not mutate the registry automatically.'
    },
    postIntegration:['npm test','recompute ai-training-curriculum quality','recompute cross-event holdout','recompute training schedule','verify no duplicate signature was introduced']
  };
}

function planIntegration({materialized,cases=[],directions}={}){
  const errors=[];
  if(materialized?.schema!=='newcyber.ai-training-regression-materializer.v1')errors.push('materializer-result-required');
  if(materialized?.status!=='ready-to-commit'||materialized?.readyToCommit!==true)errors.push('materializer-not-ready-to-commit');
  const rawCandidate=normalizeCandidate(materialized);
  if(!rawCandidate)errors.push('materialized-corpus-entry-unavailable');
  if(errors.length)return{schema:'newcyber.ai-training-integration-gate.v1',status:'blocked',readyToIntegrate:false,errors,patch:null};
  const candidate=normalizeForCurriculum(rawCandidate);
  const current=Array.isArray(cases)?cases:[];
  const required=['event','challenge','direction','family'].filter((key)=>!text(candidate[key]));
  if(required.length)return{schema:'newcyber.ai-training-integration-gate.v1',status:'blocked',readyToIntegrate:false,errors:required.map((key)=>`candidate-missing-${key}`),patch:null};
  const duplicate=current.find((row)=>signature(row)===signature(candidate));
  if(duplicate)return{
    schema:'newcyber.ai-training-integration-gate.v1',status:'blocked',readyToIntegrate:false,
    errors:['duplicate-event-challenge-family-signature'],
    duplicate:{id:duplicate.id,event:duplicate.event,challenge:duplicate.challenge,family:duplicate.family},patch:null
  };
  const requested=unique([...(Array.isArray(directions)?directions:[]),...current.map((row)=>row.direction),candidate.direction]).sort();
  const before=metrics(current,requested);
  const after=metrics([...current,candidate],requested);
  const delta=computeDelta(before,after,candidate.direction);
  const bq=byDirection(before.quality.byDirection,candidate.direction)||{};
  const aq=byDirection(after.quality.byDirection,candidate.direction)||{};
  const bh=byDirection(before.holdout.byDirection,candidate.direction)||{summary:{}};
  const ah=byDirection(after.holdout.byDirection,candidate.direction)||{summary:{}};
  const regressions=[];
  if((aq.duplicateRatio||0)>(bq.duplicateRatio||0)+1e-9)regressions.push('duplicate-ratio-increased');
  if((aq.qualityScore||0)+1e-9<(bq.qualityScore||0))regressions.push('quality-score-decreased');
  if(Boolean(bh.eligible)&&!Boolean(ah.eligible))regressions.push('holdout-eligibility-regressed');
  if((ah.summary?.cleanPlans||0)<(bh.summary?.cleanPlans||0))regressions.push('clean-holdout-plans-decreased');
  if((ah.summary?.unseenFamilyPlans||0)<(bh.summary?.unseenFamilyPlans||0))regressions.push('unseen-family-plans-decreased');
  const improvements=[];
  if(delta.qualityScore>0)improvements.push('quality-score');
  if(delta.effectiveCases>0)improvements.push('effective-coverage');
  if(delta.events>0)improvements.push('event-diversity');
  if(delta.families>0)improvements.push('family-diversity');
  if(delta.challenges>0)improvements.push('challenge-diversity');
  if(!delta.holdoutEligible.before&&delta.holdoutEligible.after)improvements.push('holdout-eligibility');
  if(delta.cleanPlans>0)improvements.push('clean-holdout-plans');
  if(delta.unseenFamilyPlans>0)improvements.push('unseen-family-holdout');
  const structuralGains=['event-diversity','family-diversity','holdout-eligibility','clean-holdout-plans','unseen-family-holdout'];
  const meaningful=improvements.some((id)=>structuralGains.includes(id));
  const status=regressions.length?'rejected-regression':!meaningful?'no-meaningful-gain':'ready-to-integrate';
  const ready=status==='ready-to-integrate';
  return{
    schema:'newcyber.ai-training-integration-gate.v1',
    status,readyToIntegrate:ready,
    candidate,
    checks:{duplicateSignature:true,noMetricRegression:regressions.length===0,meaningfulCoverageGain:meaningful,structuralGainRequired:true},
    improvements,regressions,delta,
    before:{quality:byDirection(before.quality.byDirection,candidate.direction),holdout:bh,schedule:before.schedule.queue.find((row)=>row.direction===candidate.direction)||null},
    after:{quality:aq,holdout:ah,schedule:after.schedule.queue.find((row)=>row.direction===candidate.direction)||null},
    patch:ready?integrationPatch(materialized,candidate):null,
    note:'The integration gate simulates curriculum impact before any registry mutation. Quality/effective/raw-count increases are reported but cannot alone authorize integration; ready-to-integrate requires a non-duplicate candidate, no quality/holdout regression, and a structural event/family/holdout gain.'
  };
}

module.exports={normalizeCandidate,normalizeForCurriculum,metrics,computeDelta,integrationPatch,planIntegration};
