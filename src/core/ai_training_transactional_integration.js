'use strict';

const crypto=require('node:crypto');
const {signature}=require('./ai_training_quality');
const {buildIntegrationWritePlan,verifyIntegratedResult,sha256}=require('./ai_training_integration_writer');

function text(value){return value==null?'':String(value).trim();}
function clone(value){return value==null?value:JSON.parse(JSON.stringify(value));}
function stableJson(value){
  if(Array.isArray(value))return `[${value.map(stableJson).join(',')}]`;
  if(value&&typeof value==='object')return `{${Object.keys(value).sort().map((key)=>`${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function digestCases(cases=[]){
  const normalized=(Array.isArray(cases)?cases:[]).map((row)=>({
    id:text(row?.id),event:text(row?.event),challenge:text(row?.challenge),direction:text(row?.direction),family:text(row?.family),
    caseType:text(row?.caseType),evaluator:text(row?.evaluator),coverage:text(row?.coverage),trainingPolicy:text(row?.trainingPolicy),
    provenance:row?.provenance&&typeof row.provenance==='object'?row.provenance:{}
  })).sort((a,b)=>signature(a).localeCompare(signature(b))||a.id.localeCompare(b.id));
  return crypto.createHash('sha256').update(stableJson(normalized)).digest('hex');
}
function isolatedBranchName(candidate={},key=''){
  const slug=[candidate.event,candidate.challenge,candidate.family].map((part)=>text(part).toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')).filter(Boolean).join('-').slice(0,56)||'candidate';
  return `training-integration/${slug}-${text(key).slice(0,10)||'pending'}`;
}
function validateAdapter(adapter={}){
  const required=['getCurrentBranch','getHeadSha','readText','pathExists','createBranch','checkoutBranch','createText','updateText','runRepositoryTests','loadCurriculum','runFullRegression'];
  const missing=required.filter((name)=>typeof adapter?.[name]!=='function');
  return{pass:missing.length===0,missing};
}
function buildTransactionManifest({gate,curriculumSource,beforeCases=[],existingPaths=[],baseBranch='main',baseHeadSha}={}){
  const writer=buildIntegrationWritePlan({gate,curriculumSource,existingPaths});
  if(!writer.readyToWrite)return{schema:'newcyber.ai-training-integration-transaction.v1',status:'blocked',readyToExecute:false,errors:writer.errors||[],writer};
  const branch=isolatedBranchName(gate.candidate,writer.descriptor.key);
  return{
    schema:'newcyber.ai-training-integration-transaction.v1',status:'ready-to-execute',readyToExecute:true,errors:[],
    base:{branch:text(baseBranch)||'main',headSha:text(baseHeadSha)||null,curriculumSourceSha256:sha256(curriculumSource),casesDigest:digestCases(beforeCases),caseCount:Array.isArray(beforeCases)?beforeCases.length:0},
    isolation:{branch,requiresCleanBase:true},
    writer,
    beforeCases:clone(beforeCases),
    expected:{candidateSignature:signature(gate.candidate),delta:clone(gate.delta)},
    completionGates:['base branch/head/source/case digest unchanged','all writes applied only on isolated branch','repository tests pass','full curriculum regression passes','persisted delta matches simulation exactly']
  };
}
async function maybe(value){return value&&typeof value.then==='function'?await value:value;}
async function preflight(manifest,adapter){
  const errors=[];
  const currentBranch=await maybe(adapter.getCurrentBranch());
  const headSha=await maybe(adapter.getHeadSha());
  const source=await maybe(adapter.readText('src/core/ai_training_curriculum.js'));
  const curriculum=await maybe(adapter.loadCurriculum());
  if(currentBranch!==manifest.base.branch)errors.push(`base-branch-drift:${currentBranch}`);
  if(manifest.base.headSha&&headSha!==manifest.base.headSha)errors.push(`base-head-drift:${headSha}`);
  if(sha256(source)!==manifest.base.curriculumSourceSha256)errors.push('curriculum-source-sha-drift');
  const cases=Array.isArray(curriculum?.cases)?curriculum.cases:[];
  if(digestCases(cases)!==manifest.base.casesDigest)errors.push('curriculum-cases-digest-drift');
  for(const path of manifest.writer.preconditions.artifactsMustNotExist||[])if(await maybe(adapter.pathExists(path)))errors.push(`artifact-path-now-exists:${path}`);
  return{pass:errors.length===0,errors,currentBranch,headSha,source,curriculum};
}
async function executeTransactionalIntegration({manifest,gate,adapter}={}){
  const validation=validateAdapter(adapter);
  if(!validation.pass)return{schema:'newcyber.ai-training-transaction-execution.v1',status:'blocked',executed:false,errors:validation.missing.map((name)=>`adapter-missing:${name}`)};
  if(manifest?.schema!=='newcyber.ai-training-integration-transaction.v1'||manifest?.readyToExecute!==true)return{schema:'newcyber.ai-training-transaction-execution.v1',status:'blocked',executed:false,errors:['ready-transaction-manifest-required']};
  const pf=await preflight(manifest,adapter);
  if(!pf.pass)return{schema:'newcyber.ai-training-transaction-execution.v1',status:'preflight-failed',executed:false,errors:pf.errors,preflight:pf};
  const branch=manifest.isolation.branch;let branchCreated=false;const applied=[];
  try{
    await maybe(adapter.createBranch(branch,manifest.base.headSha||pf.headSha));branchCreated=true;
    await maybe(adapter.checkoutBranch(branch));
    for(const write of manifest.writer.writes){
      if(write.operation==='create')await maybe(adapter.createText(write.path,write.content));
      else if(write.operation==='update')await maybe(adapter.updateText(write.path,write.content));
      else throw new Error(`unsupported-write-operation:${write.operation}`);
      applied.push({operation:write.operation,path:write.path});
    }
    const repositoryTests=await maybe(adapter.runRepositoryTests());
    if(repositoryTests?.passed!==true)return{schema:'newcyber.ai-training-transaction-execution.v1',status:'tests-failed',executed:true,branch,applied,repositoryTests,errors:['repository-tests-not-passed']};
    const afterCurriculum=await maybe(adapter.loadCurriculum());
    const fullRegression=await maybe(adapter.runFullRegression());
    const verification=verifyIntegratedResult({gate,beforeCases:manifest.beforeCases,afterCurriculum,fullRegression,repositoryTests});
    if(!verification.verified)return{schema:'newcyber.ai-training-transaction-execution.v1',status:'verification-failed',executed:true,branch,applied,repositoryTests,fullRegression,verification,errors:verification.errors};
    return{
      schema:'newcyber.ai-training-transaction-execution.v1',status:'verified-on-isolated-branch',executed:true,verified:true,branch,applied,
      repositoryTests,fullRegression,verification,
      finalization:{allowed:true,action:'open-integration-pr',baseBranch:manifest.base.branch,headBranch:branch,expectedBaseHead:manifest.base.headSha||pf.headSha},
      note:'The executor validates and applies the integration only on an isolated branch. It does not merge into main; finalization is allowed only after exact persisted-delta verification.'
    };
  }catch(error){
    return{schema:'newcyber.ai-training-transaction-execution.v1',status:'execution-error',executed:applied.length>0||branchCreated,branch:branchCreated?branch:null,applied,errors:[text(error?.message||error)||'transaction-execution-error']};
  }
}

module.exports={stableJson,digestCases,isolatedBranchName,validateAdapter,buildTransactionManifest,preflight,executeTransactionalIntegration};
