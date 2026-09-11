'use strict';

const base=require('./challenge_session_batch85');
const {planChallengeNextInput}=require('./challenge_next_input');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function verified(result){return Boolean(result?.verified===true||text(result?.confidence).toLowerCase()==='verified');}
function upsertLedger(ledger,item){const index=ledger.findIndex((entry)=>entry.id===item.id);if(index>=0)ledger[index]={...ledger[index],...item};else ledger.unshift(item);}

function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);const auto=analysis.aiUniversalTriggerAutopilot;
  if(auto&&auto.status!=='not-detected'){
    session.aiUniversalTriggerAutopilot={status:auto.status,summary:auto.summary||null,result:auto.result||null,next:auto.next||null};
    upsertLedger(session.solverLedger||=[],{id:'ai-universal-trigger-ranker',title:'Universal Trigger / Backdoor 候选排名',status:auto.status==='candidate'?'partial':auto.status==='ambiguous'||auto.status==='partial'?'blocked':'ran',confidence:auto.status==='candidate'?'deterministic':'guarded',detail:auto.status==='candidate'?`ASR=${Number(auto.bestCandidate?.asr||0).toFixed(3)} · prompts=${auto.bestCandidate?.prompts||0} · tokens=${auto.bestCandidate?.tokenCount||0}`:(auto.next||auto.status),result:auto.result?.displayValue||null,source:auto.result?.source||null});
    session.stats=session.stats||{};session.stats.templatesRun=(session.solverLedger||[]).length;
    if(auto.status==='candidate'&&auto.result&&session.status!=='solved'&&!verified(session.result)&&!session.result){
      session.result={...auto.result,verified:false,confidence:'candidate'};session.status='candidate';session.headline='已得到 Universal Trigger 候选，等待题目 reward/checker 最终确认';
    }
    if(session.status!=='solved'&&auto.status==='candidate'&&!analysis.submissionAutopilot?.result){
      const need={code:'TRIGGER_VERIFIER_OR_HOLDOUT',kind:'file-or-context',title:'题目 reward/checker 或独立 holdout 结果',why:'跨 Prompt Trigger 候选已经排出来，但还需要题目自己的判定逻辑确认。',detail:'优先提供 checker/reward_model 评分脚本；如果没有脚本，补一份未参与当前排名的新 prompt + success/reward 记录。',accepts:['checker.py / scorer.py / reward validation script','holdout_trigger_results.csv / json']};
      session.primaryNeed=need;session.needs=[need,...list(session.needs).filter((item)=>item.code!==need.code)].slice(0,6);
    }
  }
  session.nextInput=planChallengeNextInput(analysis,session);
  return session;
}

module.exports={...base,buildChallengeSession};
