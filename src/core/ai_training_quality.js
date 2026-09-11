'use strict';

const DEFAULT_DIRECTIONS=Object.freeze([
  'prompt-llm-security','adversarial-example','model-extraction','privacy-leakage',
  'backdoor-poisoning','infra-supply-chain','dataset-pipeline-security'
]);

function text(value){return value==null?'':String(value).trim();}
function clamp(value,min=0,max=1){return Math.max(min,Math.min(max,Number(value)||0));}
function uniq(rows,selector){return new Set(rows.map(selector).map(text).filter(Boolean));}

function provenanceWeight(item={}){
  const p=item.provenance||{};
  const level=text(p.evidenceLevel).toLowerCase();
  const kind=text(p.kind).toLowerCase();
  const label=text(p.label).toLowerCase();
  const hay=`${level} ${kind} ${label}`;
  if(/official|challenge-source-specific|official-challenge-archive/.test(hay))return 1;
  if(/writeup-specific|ctf-writeup|organizer-writeup/.test(hay))return 0.8;
  if(/benchmark|paper|research|public-challenge/.test(hay))return 0.7;
  if(/repository|archive|public/.test(hay))return 0.6;
  if(text(p.url))return 0.5;
  return 0.25;
}

function signature(item={}){
  return [text(item.event).toLowerCase(),text(item.challenge).toLowerCase(),text(item.family).toLowerCase()].join('|');
}

function effectiveCases(rows){
  const groups=new Map();
  for(const row of rows){
    const key=signature(row);
    const current=groups.get(key);
    const weight=provenanceWeight(row);
    if(!current||weight>current.weight)groups.set(key,{weight,row});
  }
  return [...groups.values()].reduce((sum,item)=>sum+item.weight,0);
}

function directionQuality(rows,direction){
  const subset=rows.filter((row)=>row.direction===direction);
  const families=uniq(subset,(row)=>row.family);
  const events=uniq(subset,(row)=>row.event);
  const challenges=uniq(subset,(row)=>`${row.event}::${row.challenge}`);
  const signatures=uniq(subset,signature);
  const provenanceAverage=subset.length?subset.reduce((sum,row)=>sum+provenanceWeight(row),0)/subset.length:0;
  const uniqueRatio=subset.length?signatures.size/subset.length:0;
  const duplicateRatio=subset.length?1-uniqueRatio:0;
  const effective=effectiveCases(subset);
  const diversityScore=(
    clamp(families.size/3)+
    clamp(events.size/3)+
    clamp(challenges.size/5)
  )/3;
  const evidenceScore=clamp(provenanceAverage);
  const effectiveScore=clamp(effective/5);
  const qualityScore=Number((diversityScore*0.45+evidenceScore*0.35+effectiveScore*0.20).toFixed(4));
  const crossEventHoldoutReady=events.size>=2&&families.size>=2&&challenges.size>=3;
  let readiness='seed';
  if(qualityScore>=0.78&&families.size>=3&&events.size>=3&&crossEventHoldoutReady)readiness='ready';
  else if(qualityScore>=0.52&&families.size>=2&&events.size>=2)readiness='developing';
  const recommendations=[];
  if(!subset.length)recommendations.push('add-provenance-backed-cases');
  if(families.size<3)recommendations.push('add-distinct-families');
  if(events.size<3)recommendations.push('add-cross-event-evidence');
  if(provenanceAverage<0.65)recommendations.push('upgrade-provenance-quality');
  if(duplicateRatio>0.2)recommendations.push('reduce-duplicate-case-inflation');
  if(!crossEventHoldoutReady)recommendations.push('build-cross-event-holdout');
  return {
    direction,
    readiness,
    qualityScore,
    rawCases:subset.length,
    uniqueSignatures:signatures.size,
    uniqueFamilies:families.size,
    uniqueEvents:events.size,
    uniqueChallenges:challenges.size,
    effectiveCases:Number(effective.toFixed(3)),
    provenanceAverage:Number(provenanceAverage.toFixed(4)),
    duplicateRatio:Number(duplicateRatio.toFixed(4)),
    crossEventHoldoutReady,
    recommendations
  };
}

function analyzeTrainingQuality(cases=[],options={}){
  const rows=Array.isArray(cases)?cases:[];
  const directions=Array.isArray(options.directions)&&options.directions.length?options.directions:DEFAULT_DIRECTIONS;
  const byDirection=directions.map((direction)=>directionQuality(rows,direction));
  const counts={ready:0,developing:0,seed:0};
  for(const row of byDirection)counts[row.readiness]=(counts[row.readiness]||0)+1;
  const overallScore=byDirection.length?byDirection.reduce((sum,row)=>sum+row.qualityScore,0)/byDirection.length:0;
  const holdoutReady=byDirection.filter((row)=>row.crossEventHoldoutReady).length;
  return {
    schema:'newcyber.ai-training-quality.v1',
    summary:{
      directions:byDirection.length,
      ready:counts.ready||0,
      developing:counts.developing||0,
      seed:counts.seed||0,
      holdoutReady,
      overallScore:Number(overallScore.toFixed(4))
    },
    byDirection,
    gates:{
      noDirectionMayClaimReadyFromRawCountAlone:true,
      readyRequiresAtLeastThreeFamilies:true,
      readyRequiresAtLeastThreeEvents:true,
      readyRequiresCrossEventHoldout:true
    },
    note:'Quality score discounts repeated event/challenge/family signatures and weights provenance strength. It is a curriculum-health signal, not a claim that the underlying AI model can solve unseen challenges.'
  };
}

module.exports={
  DEFAULT_DIRECTIONS,
  provenanceWeight,
  signature,
  effectiveCases,
  directionQuality,
  analyzeTrainingQuality
};
