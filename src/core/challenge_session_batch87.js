'use strict';

const base=require('./challenge_session_batch86');
const {planChallengeNextInput}=require('./challenge_next_input');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function verified(result){return Boolean(result?.verified===true||text(result?.confidence).toLowerCase()==='verified');}
function upsertLedger(ledger,item){const index=ledger.findIndex((entry)=>entry.id===item.id);if(index>=0)ledger[index]={...ledger[index],...item};else ledger.unshift(item);}

function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);const auto=analysis.aiModelFingerprintAutopilot;
  if(auto&&auto.status!=='not-detected'){
    session.aiModelFingerprintAutopilot={status:auto.status,summary:auto.summary||null,result:auto.result||null,bestCandidate:auto.bestCandidate||null,next:auto.next||null};
    upsertLedger(session.solverLedger||=[],{
      id:'ai-model-fingerprint-ranker',title:'Model Fingerprint / Extraction 候选排名',status:auto.status==='candidate'?'partial':auto.status==='ambiguous'||auto.status==='partial'?'blocked':'ran',confidence:auto.status==='candidate'?'deterministic':'guarded',
      detail:auto.status==='candidate'?`model=${auto.bestCandidate?.candidate||'?'} · agreement=${auto.bestCandidate?.agreement==null?'n/a':Number(auto.bestCandidate.agreement).toFixed(3)} · queries=${auto.bestCandidate?.queries||0}`:(auto.next||auto.status),result:auto.result?.displayValue||null,source:auto.result?.source||null
    });
    session.stats=session.stats||{};session.stats.templatesRun=(session.solverLedger||[]).length;
    if(auto.status==='candidate'&&auto.result&&session.status!=='solved'&&!verified(session.result)&&!session.result){
      session.result={...auto.result,verified:false,confidence:'candidate'};session.status='candidate';session.headline='已得到目标模型 Fingerprint 候选，等待题目 checker / 独立 holdout 确认';
    }
    if(session.status!=='solved'&&auto.status==='candidate'&&!analysis.submissionAutopilot?.result){
      const need={code:'MODEL_FINGERPRINT_VERIFIER_OR_HOLDOUT',kind:'file-or-context',title:'题目 checker 或独立 fingerprint holdout',why:'候选模型已经按 victim/candidate 输出一致性排出来，但还需要题目自己的判定规则或一组未参与排名的新 query 确认。',detail:'优先提供 checker.py / verifier.py；没有判题脚本时，补新的 query_id + victim/candidate label/probability/logit 对比记录。',accepts:['checker.py / verifier.py / scorer.py','fingerprint_holdout.csv / json']};
      session.primaryNeed=need;session.needs=[need,...list(session.needs).filter((item)=>item.code!==need.code)].slice(0,6);
    }
  }
  session.nextInput=planChallengeNextInput(analysis,session);
  return session;
}

module.exports={...base,buildChallengeSession};
