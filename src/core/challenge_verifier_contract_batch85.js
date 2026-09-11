'use strict';

const base=require('./challenge_verifier_contract');

function text(value){return String(value??'').trim();}
function list(value){return Array.isArray(value)?value:[];}
function extraCandidateValues(analysis={}){
  const out=[];const seen=new Set();const add=(value,source)=>{const s=text(value);if(!s||s.length>4*1024*1024||seen.has(s))return;seen.add(s);out.push({value:s,source});};
  add(analysis.aiMembershipAutopilot?.result?.payload,'ai-membership-autopilot');
  add(analysis.aiMembershipAutopilot?.result?.value,'ai-membership-autopilot');
  add(analysis.submissionAutopilot?.result?.payload,'submission-autopilot');
  add(analysis.submissionAutopilot?.result?.value,'submission-autopilot');
  add(analysis.challengeSession?.result?.payload,'challenge-session-payload');
  for(const id of list(analysis.aiMembershipAutopilot?.result?.memberIds))add(id,'ai-membership-member-id');
  return out.slice(0,512);
}
function flagLike(value){return base.flagLike(value);}

async function runVerifierContractAutopilot(root,analysis={},options={}){
  const first=await base.runVerifierContractAutopilot(root,analysis,options);
  if(first.status==='verified')return first;
  const extras=extraCandidateValues(analysis);if(!extras.length||!first.contracts?.length)return{...first,extraCandidates:extras.length};
  const evaluated=base.evaluateContracts(first.contracts,extras);
  const verifiedMatch=evaluated.verified.find((item)=>item.contract.confidence==='strong')||evaluated.verified[0]||null;
  if(!verifiedMatch)return{...first,extraCandidates:extras.length,verifiedMatches:[...(first.verifiedMatches||[]),...evaluated.verified].slice(0,32)};
  const result={value:verifiedMatch.value,verified:true,confidence:'verified',kind:flagLike(verifiedMatch.value)?'flag':'answer',source:`${verifiedMatch.method} @ ${verifiedMatch.contract.file}:${verifiedMatch.contract.line}`};
  const findings=[...(first.findings||[]).filter((x)=>x.id!=='static-verifier-contract-discovered'),{id:'static-verifier-contract-satisfied',severity:'high',title:'结构化提交候选命中静态 verifier contract',file:verifiedMatch.contract.file,line:verifiedMatch.contract.line,evidence:`${verifiedMatch.contract.type} verifier <- ${verifiedMatch.candidateSource}`,meaning:'题目 checker/verifier 的强约束已被自动生成的 submission/membership 候选满足，可升级为 verified result。'}];
  return{...first,status:'verified',result,extraCandidates:extras.length,verifiedMatches:[...(first.verifiedMatches||[]),...evaluated.verified].slice(0,32),findings,next:'自动生成的 submission 候选已命中静态 verifier，可视为 verified。'};
}

module.exports={...base,extraCandidateValues,runVerifierContractAutopilot};
