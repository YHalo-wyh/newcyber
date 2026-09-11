'use strict';

const base=require('./challenge_verifier_contract');

function text(value){return String(value??'').trim();}
function list(value){return Array.isArray(value)?value:[];}
function flagLike(value){return base.flagLike(value);}
function extraCandidateValues(analysis={}){
  const out=[];const seen=new Set();
  const add=(value,source)=>{const s=text(value);if(!s||s.length>4*1024*1024||seen.has(s))return;seen.add(s);out.push({value:s,source});};
  const addResult=(result,source)=>{if(!result)return;add(result.payload,`${source}:payload`);add(result.value,`${source}:value`);};
  addResult(analysis.aiMembershipAutopilot?.result,'ai-membership-autopilot');
  for(const id of list(analysis.aiMembershipAutopilot?.result?.memberIds).slice(0,512))add(id,'ai-membership-member-id');
  addResult(analysis.aiUniversalTriggerAutopilot?.result,'ai-universal-trigger-autopilot');
  addResult(analysis.aiModelFingerprintAutopilot?.result,'ai-model-fingerprint-autopilot');
  addResult(analysis.aiContestAutopilot?.result,'ai-contest-autopilot');
  addResult(analysis.submissionAutopilot?.result,'submission-autopilot');
  addResult(analysis.challengeSession?.result,'challenge-session');
  return out.slice(0,1024);
}

async function runVerifierContractAutopilot(root,analysis={},options={}){
  const first=await base.runVerifierContractAutopilot(root,analysis,options);
  if(first.status==='verified')return{...first,schema:'newcyber.challenge-verifier-contract.v3',extraCandidates:0};
  const extras=extraCandidateValues(analysis);
  if(!extras.length||!first.contracts?.length)return{...first,schema:'newcyber.challenge-verifier-contract.v3',extraCandidates:extras.length};
  const evaluated=base.evaluateContracts(first.contracts,extras);
  const verifiedMatch=evaluated.verified.find((item)=>item.contract.confidence==='strong')||evaluated.verified[0]||null;
  if(!verifiedMatch)return{...first,schema:'newcyber.challenge-verifier-contract.v3',extraCandidates:extras.length,verifiedMatches:[...(first.verifiedMatches||[]),...evaluated.verified].slice(0,32),summary:{...(first.summary||{}),extraCandidates:extras.length}};
  const result={value:verifiedMatch.value,payload:verifiedMatch.value,verified:true,confidence:'verified',kind:flagLike(verifiedMatch.value)?'flag':'answer',source:`${verifiedMatch.method} @ ${verifiedMatch.contract.file}:${verifiedMatch.contract.line}`};
  const findings=[...(first.findings||[]).filter((item)=>item.id!=='static-verifier-contract-discovered'),{
    id:'static-verifier-structured-candidate-satisfied',severity:'high',title:'自动生成的结构化候选命中题目 verifier',file:verifiedMatch.contract.file,line:verifiedMatch.contract.line,
    evidence:`${verifiedMatch.contract.type} <- ${verifiedMatch.candidateSource}`,
    meaning:'Membership / Trigger / Fingerprint / Submission 等自动生成结果已满足题目 checker/verifier 的强约束，可从 candidate 升级为 verified。'
  }];
  return{
    ...first,schema:'newcyber.challenge-verifier-contract.v3',status:'verified',result,extraCandidates:extras.length,
    verifiedMatches:[...(first.verifiedMatches||[]),...evaluated.verified].slice(0,32),findings,
    summary:{...(first.summary||{}),extraCandidates:extras.length,verifiedMatches:(first.summary?.verifiedMatches||0)+evaluated.verified.length},
    next:'自动生成的结构化候选已命中静态 verifier，可视为 verified。'
  };
}

module.exports={...base,extraCandidateValues,runVerifierContractAutopilot};
