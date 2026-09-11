'use strict';

const base=require('./challenge_session');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}

function upsertLedger(ledger,item){
  const index=ledger.findIndex((entry)=>entry.id===item.id);if(index>=0)ledger[index]={...ledger[index],...item};else ledger.unshift(item);
}

function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);
  const contest=analysis.aiContestAutopilot;
  if(!contest||contest.status==='not-detected')return session;
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
    const generic={value:text(result.value),source:result.source||'ai-contest-autopilot',verified:Boolean(result.verified),confidence:result.verified?'verified':'candidate',kind:'answer-set',ids:result.ids||null};
    const existingVerified=Boolean(session.result?.verified===true||text(session.result?.confidence).toLowerCase()==='verified');
    if(result.verified&&!existingVerified){session.result=generic;session.status='solved';session.headline='已经得到可提交的验证结果';}
    else if(!session.result&&session.status!=='solved'){session.result=generic;session.status='candidate';session.headline='已经得到赛式答案候选，还差题目 verifier 验证';}
  }
  if(contest.status==='verified'){
    session.primaryNeed=null;session.needs=[];
    if(session.aiHandoff)session.aiHandoff.ready=false;
  }
  return session;
}

module.exports={...base,buildChallengeSession};
