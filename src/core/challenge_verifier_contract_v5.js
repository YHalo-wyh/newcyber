'use strict';

const v4=require('./challenge_verifier_contract_v4');
const v3=require('./challenge_verifier_contract_v3');

function attachVerifiedArtifact(result,analysis={}){
  if(result?.status!=='verified'||!result.result||result.result.artifact)return result;
  const value=String(result.result.value??result.result.payload??'');
  if(!value)return result;
  const matched=v3.extraCandidateValues(analysis).find((item)=>item.artifact&&item.value===value)||null;
  if(!matched)return result;
  return {...result,result:{...result.result,artifact:matched.artifact}};
}

async function runVerifierContractAutopilot(root,analysis={},options={}){
  const result=await v4.runVerifierContractAutopilot(root,analysis,options);
  return attachVerifiedArtifact(result,analysis);
}

module.exports={...v4,attachVerifiedArtifact,runVerifierContractAutopilot};
