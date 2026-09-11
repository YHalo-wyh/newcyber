'use strict';

const base=require('./challenge_session');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}

function upsertLedger(ledger,item){
  const index=ledger.findIndex((entry)=>entry.id===item.id);if(index>=0)ledger[index]={...ledger[index],...item};else ledger.unshift(item);
}
function isVerifiedResult(result){return Boolean(result?.verified===true||text(result?.confidence).toLowerCase()==='verified');}
function promoteCandidate(session,result,headline,replace=false){
  if(!result||session.status==='solved'||isVerifiedResult(session.result))return;
  if(session.result&&!replace)return;
  session.result={...result,verified:false,confidence:'candidate'};session.status='candidate';session.headline=headline;
}

function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);
  const contest=analysis.aiContestAutopilot;
  if(contest&&contest.status!=='not-detected'){
    session.aiContestAutopilot={status:contest.status,next:contest.next,discovery:contest.discovery,result:contest.result||null};
    const ranking=contest.ranking;const result=contest.result;
    const detail=contest.status==='verified'
      ?`题目 verifier 精确命中：${text(result?.value)}`
      :contest.status==='ranked'
        ?`自动排名 ${ranking?.candidateSets?.length||0} 组候选；Top=${text(result?.value)}`
        :contest.status==='model-assets-ready'
          ?'模型、样本与 preprocessing 证据已齐，等待本地 ONNX 推理阶段'
          :contest.status==='model-assets-detected'
            ?'检测到模型与样本，但 preprocessing 证据尚不完整'
            :'检测到部分 hints/logits 材料，尚未形成完整排名输入';
    upsertLedger(session.solverLedger||=[],{
      id:'ai-contest-bundle-autopilot',title:'AI 赛题 Bundle 自动关联 / verifier',status:contest.status==='verified'?'solved':contest.status==='ranked'?'partial':'ran',confidence:contest.status==='verified'?'verified':'deterministic',detail,result:result?.value||null,source:result?.source||null
    });
    session.stats=session.stats||{};session.stats.templatesRun=(session.solverLedger||[]).length;
    const fact={label:contest.status==='verified'?'已验证答案集合':contest.status==='ranked'?'AI 候选集合':'AI Bundle',value:result?.value||contest.status,detail:result?.source||contest.next};
    session.facts=[fact,...list(session.facts).filter((item)=>item.label!==fact.label)].slice(0,6);
    if(result){
      const generic={value:text(result.value),payload:text(result.payload||result.value),source:result.source||'ai-contest-autopilot',verified:Boolean(result.verified),confidence:result.verified?'verified':'candidate',kind:'answer-set',ids:result.ids||null};
      const existingVerified=isVerifiedResult(session.result);
      if(result.verified&&!existingVerified){session.result=generic;session.status='solved';session.headline='已经得到可提交的验证结果';}
      else if(!session.result&&session.status!=='solved')promoteCandidate(session,generic,'已经得到赛式答案候选，还差题目 verifier 验证');
    }
    if(contest.status==='verified'){
      session.primaryNeed=null;session.needs=[];
      if(session.aiHandoff)session.aiHandoff.ready=false;
    }
  }

  // Compatibility pass-through: Electron file sessions historically rebuild through Batch51.
  // Preserve newer deterministic candidates even when specialized wrappers are not called here.
  const membership=analysis.aiMembershipAutopilot;
  if(membership&&membership.status!=='not-detected'){
    session.aiMembershipAutopilot={status:membership.status,summary:membership.summary||null,selection:membership.selection||null,result:membership.result||null,next:membership.next||membership.reason||null};
    if(membership.status==='candidate'&&membership.result){
      promoteCandidate(session,{value:membership.result.value,payload:membership.result.payload||membership.result.value,displayValue:membership.result.displayValue||membership.result.value,source:membership.result.source||'ai-membership-autopilot',kind:'membership-id-list',memberIds:membership.result.memberIds||[]},'已生成 Membership 候选，等待 submission/checker 闭环');
    }
  }
  const trigger=analysis.aiUniversalTriggerAutopilot;
  if(trigger&&trigger.status!=='not-detected'){
    session.aiUniversalTriggerAutopilot={status:trigger.status,summary:trigger.summary||null,result:trigger.result||null,next:trigger.next||null};
    if(trigger.status==='candidate'&&trigger.result){
      promoteCandidate(session,{value:trigger.result.value,payload:trigger.result.payload||trigger.result.value,displayValue:trigger.result.displayValue||trigger.result.value,source:trigger.result.source||'universal-trigger-ranker',kind:'universal-trigger'},'已得到 Universal Trigger 候选，等待 reward/checker 闭环');
    }
  }
  const fingerprint=analysis.aiModelFingerprintAutopilot;
  if(fingerprint&&fingerprint.status!=='not-detected'){
    session.aiModelFingerprintAutopilot={status:fingerprint.status,summary:fingerprint.summary||null,result:fingerprint.result||null,bestCandidate:fingerprint.bestCandidate||null,next:fingerprint.next||null};
    if(fingerprint.status==='candidate'&&fingerprint.result){
      promoteCandidate(session,{value:fingerprint.result.value,payload:fingerprint.result.payload||fingerprint.result.value,displayValue:fingerprint.result.displayValue||fingerprint.result.value,source:fingerprint.result.source||'model-fingerprint-ranker',kind:'model-fingerprint'},'已得到目标模型 Fingerprint 候选，等待 checker/holdout 闭环');
    }
  }
  const submission=analysis.submissionAutopilot;
  if(submission&&submission.status!=='not-detected'){
    session.submissionAutopilot={status:submission.status,result:submission.result||null,next:submission.next||null};
    if(submission.status==='formatted'&&submission.result){
      promoteCandidate(session,{value:submission.result.payload,payload:submission.result.payload,displayValue:submission.result.displayValue||submission.result.payload,source:submission.result.source||'submission-autopilot',kind:submission.result.kind||'submission',format:submission.result.format||null,template:submission.result.template||null},'已按题目 submission 模板生成提交候选，等待 checker/scorer 确认',true);
    }
  }
  return session;
}

module.exports={...base,buildChallengeSession};
