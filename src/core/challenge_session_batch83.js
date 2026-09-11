'use strict';

const base=require('./challenge_session_batch51');
const {planChallengeNextInput}=require('./challenge_next_input');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function upsertLedger(ledger,item){const index=ledger.findIndex((entry)=>entry.id===item.id);if(index>=0)ledger[index]={...ledger[index],...item};else ledger.unshift(item);}

function membershipNeed(auto){
  if(!auto)return null;
  if(auto.status==='candidate')return{
    code:'MEMBERSHIP_VERIFIER_OR_SCHEMA',kind:'file-or-context',title:'题目 submission / checker / scorer',
    why:'Membership 候选已经生成，但还缺题目自己的提交格式或判定规则，不能直接当 solved。',
    detail:'提供 checker.py、verifier.py、scorer.py、sample_submission.csv/json 或 README 中的评分规则任一种。',
    accepts:['checker.py / verifier.py / scorer.py','sample_submission.csv / submission.json','README / challenge description']
  };
  if(auto.status==='ambiguous')return{
    code:'MEMBERSHIP_PAIR_AMBIGUOUS',kind:'file-or-context',title:'明确 calibration 与 query 的对应关系',why:auto.reason||'检测到多个等价数据配对，自动链停止猜测。',
    detail:'推荐把带 member 真值的文件命名为 calibration/reference，把待判定文件命名为 query/challenge/test；或补题面说明。',
    accepts:['calibration.csv / reference.json','query.csv / challenge.json','README / challenge description']
  };
  if(auto.status==='gap'){
    const reason=text(auto.reason||auto.next);
    if(/calibration|reference|member\/non-member|真值/i.test(reason))return{
      code:'MEMBERSHIP_CALIBRATION_MISSING',kind:'file-or-context',title:'带成员真值的 calibration/reference 数据',why:reason,
      detail:'至少包含 id、member(0/1)，并包含 loss / confidence / entropy / margin 中至少一列；同时要有 member 与 non-member。',
      accepts:['calibration.csv','reference.json / shadow.json']
    };
    return{
      code:'MEMBERSHIP_QUERY_MISSING',kind:'file-or-context',title:'待判定 query/challenge 数据',why:reason,
      detail:'包含 id，以及与 calibration 同名的 loss / confidence / entropy / margin 信号列。不要把 challenge 真值放进去。',
      accepts:['query.csv','challenge.json / test.csv']
    };
  }
  return null;
}

function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);const auto=analysis.aiMembershipAutopilot;
  if(auto&&auto.status!=='not-detected'){
    session.aiMembershipAutopilot={status:auto.status,summary:auto.summary||null,selection:auto.selection||null,result:auto.result?{kind:auto.result.kind,verified:false,displayValue:auto.result.displayValue||null,source:auto.result.source||null,memberCount:auto.result.memberIds?.length||0}:null,next:auto.next||auto.reason||null};
    upsertLedger(session.solverLedger||=[],{
      id:'ai-membership-bundle-autopilot',title:'Membership calibration/query 自动关联',
      status:auto.status==='candidate'?'partial':auto.status==='gap'||auto.status==='ambiguous'?'blocked':'ran',
      confidence:auto.status==='candidate'?'deterministic':'guarded',
      detail:auto.status==='candidate'?`已生成 ${auto.result?.memberIds?.length||0} 个 member 候选 · signal=${auto.selection?.signal||'unknown'} · AUC=${Number(auto.selection?.auc||0).toFixed(3)}`:(auto.reason||auto.next||auto.status),
      result:auto.result?.displayValue||null,source:auto.result?.source||null
    });
    session.stats=session.stats||{};session.stats.templatesRun=(session.solverLedger||[]).length;
    if(auto.status==='candidate'&&auto.result){
      const existingVerified=Boolean(session.result?.verified===true||text(session.result?.confidence).toLowerCase()==='verified');
      if(!existingVerified&&session.status!=='solved'){
        session.result={
          value:auto.result.value,
          payload:auto.result.payload||auto.result.value,
          displayValue:auto.result.displayValue||auto.result.value,
          source:auto.result.source||'ai-membership-bundle-autopilot',verified:false,confidence:'candidate',kind:'membership-id-list',memberIds:auto.result.memberIds||[]
        };
        session.status='candidate';session.headline='已生成 Membership 可提交候选，还差题目 checker / submission 规则确认';
      }
      const fact={label:'Membership 候选',value:`${auto.result.memberIds?.length||0} IDs`,detail:`${auto.selection?.signal||'signal'} · AUC ${Number(auto.selection?.auc||0).toFixed(3)}`};
      session.facts=[fact,...list(session.facts).filter((item)=>item.label!==fact.label)].slice(0,6);
    }
    const need=membershipNeed(auto);if(need&&session.status!=='solved'){session.primaryNeed=need;session.needs=[need,...list(session.needs).filter((item)=>item.code!==need.code)].slice(0,6);}
  }
  session.nextInput=planChallengeNextInput(analysis,session);
  return session;
}

module.exports={...base,buildChallengeSession,membershipNeed};
