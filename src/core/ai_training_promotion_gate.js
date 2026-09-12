'use strict';

const crypto=require('node:crypto');
const {stableJson}=require('./ai_training_transactional_integration');
const {signature}=require('./ai_training_quality');

function text(value){return value==null?'':String(value).trim();}
function clone(value){return value==null?value:JSON.parse(JSON.stringify(value));}
function digest(value){return crypto.createHash('sha256').update(stableJson(value)).digest('hex');}

function validateExecution(execution={}){
  const errors=[];
  if(execution?.schema!=='newcyber.ai-training-transaction-execution.v1')errors.push('transaction-execution-required');
  if(execution?.status!=='verified-on-isolated-branch'||execution?.verified!==true)errors.push('transaction-execution-not-verified');
  if(execution?.finalization?.allowed!==true||execution?.finalization?.action!=='open-integration-pr')errors.push('transaction-finalization-not-allowed');
  if(!text(execution?.branch))errors.push('verified-branch-missing');
  if(!text(execution?.finalization?.baseBranch))errors.push('base-branch-missing');
  if(!text(execution?.finalization?.expectedBaseHead))errors.push('expected-base-head-missing');
  if(execution?.repositoryTests?.passed!==true)errors.push('repository-tests-not-passed');
  if(execution?.verification?.verified!==true)errors.push('integration-verification-not-passed');
  if(!text(execution?.verification?.candidateSignature))errors.push('candidate-signature-missing');
  return{pass:errors.length===0,errors};
}

function buildPromotionManifest({execution,verifiedHeadSha,ciRun,gate}={}){
  const validation=validateExecution(execution);
  if(!validation.pass)return{schema:'newcyber.ai-training-promotion.v1',status:'blocked',readyToPromote:false,errors:validation.errors};
  const headSha=text(verifiedHeadSha);
  if(!headSha)return{schema:'newcyber.ai-training-promotion.v1',status:'blocked',readyToPromote:false,errors:['verified-head-sha-required']};
  if(ciRun?.conclusion!=='success')return{schema:'newcyber.ai-training-promotion.v1',status:'blocked',readyToPromote:false,errors:['verified-ci-success-required']};
  if(text(ciRun?.headSha)&&text(ciRun.headSha)!==headSha)return{schema:'newcyber.ai-training-promotion.v1',status:'blocked',readyToPromote:false,errors:['ci-head-sha-mismatch']};
  const candidateSignature=text(execution.verification.candidateSignature);
  if(gate?.candidate&&signature(gate.candidate)!==candidateSignature)return{schema:'newcyber.ai-training-promotion.v1',status:'blocked',readyToPromote:false,errors:['gate-candidate-signature-mismatch']};
  const proof={
    baseBranch:text(execution.finalization.baseBranch),
    expectedBaseHead:text(execution.finalization.expectedBaseHead),
    headBranch:text(execution.branch),
    verifiedHeadSha:headSha,
    candidateSignature,
    verificationDigest:digest(execution.verification),
    repositoryTestsDigest:digest(execution.repositoryTests),
    fullRegressionDigest:digest(execution.fullRegression||{}),
    expectedDeltaDigest:digest(execution.verification.expectedDelta||{}),
    ci:{runId:ciRun?.runId??null,runNumber:ciRun?.runNumber??null,conclusion:'success',headSha:headSha}
  };
  const promotionId=`promotion-${digest(proof).slice(0,16)}`;
  return{
    schema:'newcyber.ai-training-promotion.v1',status:'ready-to-promote',readyToPromote:true,errors:[],promotionId,proof,
    executionDigest:digest(execution),
    pr:{
      base:proof.baseBranch,head:proof.headBranch,
      title:`Training integration: ${candidateSignature}`,
      bodyMarkers:{promotionId,candidateSignature,verifiedHeadSha:headSha,expectedBaseHead:proof.expectedBaseHead,verificationDigest:proof.verificationDigest,ciRunId:proof.ci.runId}
    },
    mergePolicy:{requireBaseUnchanged:true,requireHeadUnchanged:true,requirePromotionMarkers:true,requireSuccessfulCiOnVerifiedHead:true},
    note:'A ready promotion proves that Batch105 verified one isolated branch at one exact head SHA. It does not authorize merge after either base or head changes; merge authorization must be re-evaluated immediately before merge.'
  };
}

function validatePromotionAgainstRepository({promotion,currentBaseHead,currentHeadSha,pr,ciRun}={}){
  const errors=[];
  if(promotion?.schema!=='newcyber.ai-training-promotion.v1'||promotion?.readyToPromote!==true||promotion?.status!=='ready-to-promote')errors.push('ready-promotion-required');
  const proof=promotion?.proof||{};
  if(text(currentBaseHead)!==text(proof.expectedBaseHead))errors.push('promotion-stale-base-head');
  if(text(currentHeadSha)!==text(proof.verifiedHeadSha))errors.push('promotion-stale-head-branch');
  if(pr){
    if(text(pr.base)!==text(proof.baseBranch))errors.push('pr-base-mismatch');
    if(text(pr.head)!==text(proof.headBranch))errors.push('pr-head-mismatch');
    if(text(pr.headSha)&&text(pr.headSha)!==text(proof.verifiedHeadSha))errors.push('pr-head-sha-mismatch');
    if(pr.state&&pr.state!=='open')errors.push('promotion-pr-not-open');
    const body=String(pr.body||'');
    for(const marker of [promotion.promotionId,proof.candidateSignature,proof.verifiedHeadSha,proof.verificationDigest])if(marker&&!body.includes(marker))errors.push(`promotion-marker-missing:${marker.slice(0,24)}`);
  }
  if(ciRun){
    if(ciRun.conclusion!=='success')errors.push('promotion-ci-not-successful');
    if(text(ciRun.headSha)!==text(proof.verifiedHeadSha))errors.push('promotion-ci-head-mismatch');
  }
  const stale=errors.some((e)=>e.startsWith('promotion-stale-'));
  return{
    schema:'newcyber.ai-training-promotion-validation.v1',status:errors.length?(stale?'stale':'blocked'):'valid',valid:errors.length===0,stale,errors,
    promotionId:promotion?.promotionId||null,candidateSignature:proof.candidateSignature||null
  };
}

function buildPromotionPrRequest(promotion={}){
  if(promotion?.schema!=='newcyber.ai-training-promotion.v1'||promotion?.readyToPromote!==true)return{allowed:false,error:'ready-promotion-required'};
  const markers=promotion.pr.bodyMarkers||{};
  const body=[
    'Automated training integration promotion.',
    '',
    `Promotion-ID: ${markers.promotionId}`,
    `Candidate-Signature: ${markers.candidateSignature}`,
    `Verified-Head-SHA: ${markers.verifiedHeadSha}`,
    `Expected-Base-Head: ${markers.expectedBaseHead}`,
    `Verification-Digest: ${markers.verificationDigest}`,
    `CI-Run-ID: ${markers.ciRunId??'n/a'}`,
    '',
    'Merge is authorized only if Batch106 promotion validation still reports valid immediately before merge.'
  ].join('\n');
  return{allowed:true,base:promotion.pr.base,head:promotion.pr.head,title:promotion.pr.title,body};
}

function authorizePromotionMerge({promotion,currentBaseHead,currentHeadSha,pr,ciRun}={}){
  const validation=validatePromotionAgainstRepository({promotion,currentBaseHead,currentHeadSha,pr,ciRun});
  if(!validation.valid)return{schema:'newcyber.ai-training-promotion-merge.v1',status:validation.stale?'stale-revalidation-required':'merge-blocked',authorized:false,validation};
  return{
    schema:'newcyber.ai-training-promotion-merge.v1',status:'merge-authorized',authorized:true,validation,
    merge:{method:'squash',expectedHeadSha:promotion.proof.verifiedHeadSha,baseHeadMustEqual:promotion.proof.expectedBaseHead},
    note:'Authorization is point-in-time. The caller must pass expectedHeadSha to the repository merge operation and reject the merge if the base branch no longer equals the recorded expected base head.'
  };
}

module.exports={digest,validateExecution,buildPromotionManifest,validatePromotionAgainstRepository,buildPromotionPrRequest,authorizePromotionMerge};
