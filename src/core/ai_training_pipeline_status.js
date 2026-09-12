'use strict';

const STAGES=Object.freeze([
  {id:'evidence',label:'Evidence Intake',route:'ai-training-evidence-intake'},
  {id:'skeleton',label:'Regression Skeleton',route:'ai-training-regression-skeleton'},
  {id:'materialize',label:'Materializer',route:'ai-training-regression-materialize'},
  {id:'integration',label:'Integration Gate',route:'ai-training-integration-gate'},
  {id:'writer',label:'Integration Writer',route:'ai-training-integration-writer'},
  {id:'transaction',label:'Transactional Integration',route:'ai-training-transaction-manifest'},
  {id:'promotion',label:'Promotion Gate',route:'ai-training-promotion-manifest'},
  {id:'merge',label:'Merge Authorization',route:'ai-training-promotion-merge-authorize'}
]);

function text(value){return value==null?'':String(value).trim();}
function uniq(values=[]){return [...new Set(values.filter(Boolean))];}
function stageIndex(id){return STAGES.findIndex((row)=>row.id===id);}
function stageMeta(id){return STAGES.find((row)=>row.id===id)||null;}
function blockersOf(value={}){
  const rows=[];
  if(Array.isArray(value.errors))rows.push(...value.errors);
  if(Array.isArray(value.blockers))rows.push(...value.blockers);
  if(Array.isArray(value.missingEvidence))rows.push(...value.missingEvidence.map((x)=>`missing:${x}`));
  if(Array.isArray(value.regressions))rows.push(...value.regressions.map((x)=>`regression:${x}`));
  if(value.validation&&Array.isArray(value.validation.errors))rows.push(...value.validation.errors);
  return uniq(rows.map(text));
}

function resolve(value={}){
  const schema=text(value?.schema);
  if(schema==='newcyber.ai-training-evidence-intake-template.v1')return{stage:'evidence',state:'draft',next:'ai-training-evidence-intake'};
  if(schema==='newcyber.ai-training-evidence-intake.v1'){
    if(value.verdict==='accept')return{stage:'evidence',state:'passed',next:'ai-training-regression-skeleton'};
    if(value.verdict==='needs-evidence')return{stage:'evidence',state:'blocked',next:'ai-training-evidence-intake'};
    return{stage:'evidence',state:'rejected',next:null};
  }
  if(schema==='newcyber.ai-training-regression-skeleton.v1')return value.status==='ready'?{stage:'skeleton',state:'passed',next:'ai-training-regression-materialize'}:{stage:'skeleton',state:'blocked',next:null};
  if(schema==='newcyber.ai-training-regression-materializer.v1')return value.readyToCommit?{stage:'materialize',state:'passed',next:'ai-training-integration-gate'}:{stage:'materialize',state:'blocked',next:'ai-training-regression-materialize'};
  if(schema==='newcyber.ai-training-integration-gate.v1')return value.readyToIntegrate?{stage:'integration',state:'passed',next:'ai-training-integration-writer'}:{stage:'integration',state:'blocked',next:null};
  if(schema==='newcyber.ai-training-integration-writer.v1')return value.readyToWrite?{stage:'writer',state:'passed',next:'ai-training-transaction-manifest'}:{stage:'writer',state:'blocked',next:null};
  if(schema==='newcyber.ai-training-integration-transaction.v1')return value.readyToExecute?{stage:'transaction',state:'prepared',next:null}:{stage:'transaction',state:'blocked',next:null};
  if(schema==='newcyber.ai-training-transaction-execution.v1')return value.verified?{stage:'transaction',state:'passed',next:'ai-training-promotion-manifest'}:{stage:'transaction',state:'blocked',next:null};
  if(schema==='newcyber.ai-training-promotion.v1')return value.readyToPromote?{stage:'promotion',state:'passed',next:'ai-training-promotion-pr-request'}:{stage:'promotion',state:'blocked',next:null};
  if(schema==='newcyber.ai-training-promotion-validation.v1')return value.valid?{stage:'promotion',state:'passed',next:'ai-training-promotion-merge-authorize'}:{stage:'promotion',state:value.stale?'stale':'blocked',next:null};
  if(schema==='newcyber.ai-training-promotion-merge.v1')return value.authorized?{stage:'merge',state:'passed',next:null}:{stage:'merge',state:value.status==='stale-revalidation-required'?'stale':'blocked',next:null};
  return{stage:null,state:'unknown',next:'ai-training-evidence-intake'};
}

function inspectTrainingArtifact(value={}){
  const resolved=resolve(value);
  const current=stageMeta(resolved.stage);
  const index=stageIndex(resolved.stage);
  return{
    schema:'newcyber.ai-training-pipeline-status.v1',
    artifactSchema:text(value?.schema)||null,
    stage:resolved.stage,
    stageLabel:current?.label||'Unclassified',
    stageIndex:index,
    state:resolved.state,
    nextRoute:resolved.next,
    blockers:blockersOf(value),
    stages:STAGES.map((row,i)=>({
      ...row,
      state:index<0?'pending':i<index?'passed':i===index?resolved.state:'pending'
    })),
    safeBoundary:resolved.stage==='writer'||resolved.stage==='transaction'||resolved.stage==='promotion'||resolved.stage==='merge'?'repository-bound':'local-deterministic',
    note:'Repository-bound stages require explicit source/base/head/CI evidence. The status inspector never treats a UI transition as repository authorization.'
  };
}

module.exports={STAGES,blockersOf,resolve,inspectTrainingArtifact};
