'use strict';

const base=require('./challenge_session_batch87');
const {planChallengeNextInput}=require('./challenge_next_input');

function text(value){return String(value??'');}
function list(value){return Array.isArray(value)?value:[];}
function upsertLedger(ledger,item){const index=ledger.findIndex((entry)=>entry.id===item.id);if(index>=0)ledger[index]={...ledger[index],...item};else ledger.unshift(item);}
function resultDisplay(result){
  const value=text(result?.displayValue||result?.value||result?.payload);
  if(value.length<=512)return value;
  return `已验证结构化提交内容 · ${Buffer.byteLength(value,'utf8')} bytes`;
}

function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);const verifier=analysis.verifierContractAutopilot;
  if(verifier&&verifier.status!=='not-applicable'){
    session.verifierContractAutopilot={status:verifier.status,summary:verifier.summary||null,result:verifier.result||null,next:verifier.next||null};
    upsertLedger(session.solverLedger||=[],{
      id:'static-verifier-contract-v3',title:'静态 checker/verifier 结构化结果闭环',
      status:verifier.status==='verified'?'solved':verifier.status==='contracts-found'?'partial':verifier.status==='gap'?'blocked':'ran',
      confidence:verifier.status==='verified'?'verified':'guarded',
      detail:verifier.status==='verified'?`contracts=${verifier.summary?.contracts||0} · extraCandidates=${verifier.summary?.extraCandidates||verifier.extraCandidates||0}`:(verifier.next||verifier.status),
      result:verifier.result?resultDisplay(verifier.result):null,source:verifier.result?.source||null
    });
    session.stats=session.stats||{};session.stats.templatesRun=(session.solverLedger||[]).length;
    if(verifier.status==='verified'&&verifier.result){
      const value=text(verifier.result.value??verifier.result.payload);
      session.result={...verifier.result,value,payload:text(verifier.result.payload??value),displayValue:resultDisplay(verifier.result),verified:true,confidence:'verified'};
      session.status='solved';session.headline='题目 checker/verifier 已验证当前自动生成结果';
      session.primaryNeed=null;session.needs=[];
      if(session.aiHandoff)session.aiHandoff.ready=false;
    }else if(verifier.status==='contracts-found'&&session.status!=='solved'){
      const need={code:'VERIFIER_CANDIDATE_GAP',kind:'file-or-context',title:'满足现有 checker/verifier 的候选证据',why:'已经恢复题目判定约束，但当前自动生成候选还没有命中。',detail:verifier.next||'继续补充候选日志、holdout、submission 模板或模型输出，让现有 verifier 直接闭环。',accepts:['candidate / prediction / logits 日志','holdout.csv / json','sample_submission.csv / json','模型或样本附件']};
      session.primaryNeed=session.primaryNeed||need;
      session.needs=[session.primaryNeed,...list(session.needs).filter((item)=>item.code!==session.primaryNeed.code)].slice(0,6);
    }
  }
  session.nextInput=planChallengeNextInput(analysis,session);
  return session;
}

module.exports={...base,buildChallengeSession,resultDisplay};
