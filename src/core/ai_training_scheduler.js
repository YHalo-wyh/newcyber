'use strict';

const ACTION_META=Object.freeze({
  'add-provenance-backed-cases':{weight:24,label:'add-provenance-backed-cases'},
  'add-distinct-families':{weight:22,label:'add-distinct-families'},
  'add-cross-event-evidence':{weight:21,label:'add-cross-event-evidence'},
  'upgrade-provenance-quality':{weight:16,label:'upgrade-provenance-quality'},
  'reduce-duplicate-case-inflation':{weight:14,label:'reduce-duplicate-case-inflation'},
  'build-cross-event-holdout':{weight:26,label:'build-cross-event-holdout'},
  'add-unseen-family-holdout':{weight:19,label:'add-unseen-family-holdout'},
  'maintain-unseen-family-stress':{weight:6,label:'maintain-unseen-family-stress'}
});

const READINESS_BASE=Object.freeze({seed:68,developing:43,ready:16});

function num(value,fallback=0){const n=Number(value);return Number.isFinite(n)?n:fallback;}
function clamp(value,min=0,max=100){return Math.max(min,Math.min(max,num(value)));}
function mapByDirection(rows=[]){return new Map((Array.isArray(rows)?rows:[]).map((row)=>[row.direction,row]));}
function uniq(values=[]){return [...new Set(values.filter(Boolean))];}

function priorityOf(score){
  if(score>=80)return'critical';
  if(score>=60)return'high';
  if(score>=40)return'medium';
  return'low';
}

function rankActions(actions=[]){
  return uniq(actions).sort((a,b)=>(ACTION_META[b]?.weight||0)-(ACTION_META[a]?.weight||0)||String(a).localeCompare(String(b)));
}

function actionsFor(quality={},holdout={}){
  const actions=[...(quality.recommendations||[])];
  if(!holdout.eligible&&!actions.includes('build-cross-event-holdout'))actions.push('build-cross-event-holdout');
  if(holdout.eligible&&(holdout.summary?.unseenFamilyPlans||0)===0)actions.push('add-unseen-family-holdout');
  if(quality.readiness==='ready'&&holdout.eligible&&(holdout.summary?.unseenFamilyPlans||0)>0&&actions.length===0)actions.push('maintain-unseen-family-stress');
  return rankActions(actions);
}

function scoreDirection(quality={},holdout={}){
  let score=READINESS_BASE[quality.readiness]??68;
  score+=(1-clamp(num(quality.qualityScore),0,1))*24;
  if(!holdout.eligible)score+=18;
  if((holdout.summary?.unseenFamilyPlans||0)===0)score+=8;
  score+=Math.max(0,3-num(quality.uniqueEvents))*4;
  score+=Math.max(0,3-num(quality.uniqueFamilies))*4;
  if(num(quality.provenanceAverage)<0.65)score+=(0.65-num(quality.provenanceAverage))*18;
  if(num(quality.duplicateRatio)>0.2)score+=num(quality.duplicateRatio)*12;
  return Number(clamp(score,0,100).toFixed(2));
}

function buildDirectionTask(direction,quality={},holdout={}){
  const actions=actionsFor(quality,holdout);
  const score=scoreDirection(quality,holdout);
  const unseen=holdout.summary?.unseenFamilyPlans||0;
  const clean=holdout.summary?.cleanPlans||0;
  const targets={
    newEvents:Math.max(0,3-num(quality.uniqueEvents)),
    newFamilies:Math.max(0,3-num(quality.uniqueFamilies)),
    effectiveCaseDebt:Number(Math.max(0,5-num(quality.effectiveCases)).toFixed(3)),
    provenanceAverageTarget:0.65,
    unseenFamilyHoldout:unseen>0?0:1
  };
  let acquisitionMode='cross-event-evidence';
  if(targets.newFamilies>0)acquisitionMode='new-family';
  else if(!holdout.eligible)acquisitionMode='holdout-enablement';
  else if(unseen===0)acquisitionMode='unseen-family-stress';
  else if(num(quality.provenanceAverage)<0.65)acquisitionMode='provenance-upgrade';
  return{
    direction,
    priority:priorityOf(score),
    score,
    readiness:quality.readiness||'seed',
    qualityScore:num(quality.qualityScore),
    nextAction:actions[0]||'maintain-unseen-family-stress',
    actions,
    acquisitionMode,
    targets,
    metrics:{
      rawCases:num(quality.rawCases),
      effectiveCases:num(quality.effectiveCases),
      events:num(quality.uniqueEvents),
      families:num(quality.uniqueFamilies),
      provenanceAverage:num(quality.provenanceAverage),
      duplicateRatio:num(quality.duplicateRatio),
      holdoutEligible:Boolean(holdout.eligible),
      cleanHoldoutPlans:clean,
      unseenFamilyPlans:unseen
    },
    sourcePolicy:[
      'official-challenge-archive-or-organizer-source',
      'public-writeup-or-public-challenge-evidence',
      'synthetic-fixture-for-regression-only',
      'no-real-flags-secrets-private-attachments'
    ]
  };
}

function buildTrainingSchedule({cases=[],quality={},holdout={}}={},options={}){
  const qmap=mapByDirection(quality.byDirection);
  const hmap=mapByDirection(holdout.byDirection);
  const requested=uniq([
    ...qmap.keys(),
    ...hmap.keys(),
    ...(Array.isArray(options.directions)?options.directions:[])
  ]).sort((a,b)=>a.localeCompare(b));
  const maxItems=Math.max(1,Math.min(64,num(options.maxItems,requested.length||1)));
  const queue=requested.map((direction)=>buildDirectionTask(direction,qmap.get(direction)||{direction,readiness:'seed',recommendations:['add-provenance-backed-cases']},hmap.get(direction)||{direction,eligible:false,summary:{cleanPlans:0,unseenFamilyPlans:0}}))
    .sort((a,b)=>b.score-a.score||a.direction.localeCompare(b.direction))
    .slice(0,maxItems)
    .map((item,index)=>({rank:index+1,...item}));
  const priorities={critical:0,high:0,medium:0,low:0};
  for(const item of queue)priorities[item.priority]=(priorities[item.priority]||0)+1;
  return{
    schema:'newcyber.ai-training-schedule.v1',
    summary:{
      directions:requested.length,
      queued:queue.length,
      priorities,
      topDirection:queue[0]?.direction||null,
      topAction:queue[0]?.nextAction||null,
      sourceCases:Array.isArray(cases)?cases.length:0
    },
    queue,
    gates:{
      rawCaseCountCannotOverrideQualityDebt:true,
      holdoutIneligibilityRaisesPriority:true,
      unseenFamilyGapRaisesPriority:true,
      provenanceUpgradePreferredOverDuplicateInflation:true
    },
    note:'This schedule ranks curriculum work, not model fine-tuning jobs. It prioritizes evidence acquisition and deterministic regression gaps using quality and cross-event holdout structure.'
  };
}

module.exports={ACTION_META,priorityOf,rankActions,actionsFor,scoreDirection,buildDirectionTask,buildTrainingSchedule};
