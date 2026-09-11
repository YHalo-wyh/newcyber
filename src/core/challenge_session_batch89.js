'use strict';

const base=require('./challenge_session_batch88');
const {planChallengeNextInput}=require('./challenge_next_input');

function list(value){return Array.isArray(value)?value:[];}
function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);const artifact=analysis.submissionArtifact?.artifact||analysis.submissionAutopilot?.result?.artifact||analysis.verifierContractAutopilot?.result?.artifact||null;
  if(artifact){
    session.submissionArtifact=artifact;
    const fact={label:artifact.verified?'已验证提交文件':'提交候选文件',value:artifact.filename||artifact.path,detail:`${artifact.format||'txt'} · ${artifact.bytes||0} bytes · sha256=${String(artifact.sha256||'').slice(0,16)}…`};
    session.facts=[fact,...list(session.facts).filter((item)=>item.label!==fact.label)].slice(0,6);
    if(session.result){session.result.artifact=artifact;if(artifact.verified)session.result.displayValue=`已验证提交文件：${artifact.filename||artifact.path}`;}
    if(artifact.verified){session.status='solved';session.headline='已生成并验证可直接提交的结果文件';session.primaryNeed=null;session.needs=[];if(session.aiHandoff)session.aiHandoff.ready=false;}
  }
  session.nextInput=planChallengeNextInput(analysis,session);
  return session;
}

module.exports={...base,buildChallengeSession};
