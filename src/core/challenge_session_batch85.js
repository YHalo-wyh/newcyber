'use strict';

const base=require('./challenge_session_batch83');
const {planChallengeNextInput}=require('./challenge_next_input');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function upsertLedger(ledger,item){const index=ledger.findIndex((entry)=>entry.id===item.id);if(index>=0)ledger[index]={...ledger[index],...item};else ledger.unshift(item);}

function submissionNeed(auto){
  if(!auto||auto.status==='not-detected'||auto.status==='formatted')return null;
  if(auto.status==='needs-candidate')return{code:'SUBMISSION_CANDIDATE_MISSING',kind:'file-or-context',title:'先补齐生成候选所需的数据',why:auto.next||'题目提交模板已经识别，但当前没有可封装候选。',detail:'继续提供模型输入、query、calibration、hint、结果表或题目要求的原始附件；NewCyber 会先生成候选，再自动套 submission 模板。',accepts:['原始模型/样本/query/calibration','README / challenge description','hint / labels / result tables']};
  if(auto.status==='unsupported-contract')return{code:'SUBMISSION_CONTRACT_AMBIGUOUS',kind:'file-or-context',title:'提供提交字段说明或 checker/scorer',why:auto.next||'提交模板存在，但字段语义不足以安全映射。',detail:'优先提供 README、checker.py、verifier.py、scorer.py；不要手工改 sample_submission。',accepts:['README / challenge description','checker.py / verifier.py / scorer.py']};
  return null;
}

function buildChallengeSession(analysis={}){
  const session=base.buildChallengeSession(analysis);const auto=analysis.submissionAutopilot;
  if(auto&&auto.status!=='not-detected'){
    session.submissionAutopilot={status:auto.status,result:auto.result?{kind:auto.result.kind,format:auto.result.format,template:auto.result.template,displayValue:auto.result.displayValue,source:auto.result.source,artifact:auto.result.artifact||null}:null,next:auto.next||null};
    upsertLedger(session.solverLedger||=[],{
      id:'challenge-submission-autopilot',title:'题目 Submission 模板自动封装',
      status:auto.status==='formatted'?'partial':auto.status==='needs-candidate'||auto.status==='unsupported-contract'?'blocked':'ran',
      confidence:auto.status==='formatted'?'deterministic':'guarded',
      detail:auto.status==='formatted'?`${auto.result?.format||'submission'} · template=${auto.result?.template||'unknown'}`:(auto.next||auto.status),
      result:auto.result?.displayValue||null,source:auto.result?.source||null
    });
    session.stats=session.stats||{};session.stats.templatesRun=(session.solverLedger||[]).length;
    if(auto.status==='formatted'&&auto.result&&session.status!=='solved'){
      const existingVerified=Boolean(session.result?.verified===true||text(session.result?.confidence).toLowerCase()==='verified');
      if(!existingVerified){
        session.result={value:auto.result.payload,payload:auto.result.payload,displayValue:auto.result.displayValue||auto.result.payload,source:auto.result.source||'submission-autopilot',verified:false,confidence:'candidate',kind:auto.result.kind||'submission',format:auto.result.format||null,template:auto.result.template||null,artifact:auto.result.artifact||null};
        session.status='candidate';session.headline='已按题目 submission 模板生成可提交候选，等待 checker / scorer 最终确认';
      }
      const fact={label:'提交候选',value:auto.result.format?.toUpperCase()||'SUBMISSION',detail:auto.result.template||auto.result.source||'submission-autopilot'};
      session.facts=[fact,...list(session.facts).filter((item)=>item.label!==fact.label)].slice(0,6);
      session.primaryNeed={code:'SUBMISSION_VERIFIER_MISSING',kind:'file-or-context',title:'题目 checker / verifier / scorer',why:'提交内容已经按模板生成；如果还有题目判定代码，补进来即可自动继续验证。',detail:'提供 checker.py、verifier.py、scorer.py 或本地判题逻辑任一种；没有的话当前结果保持 candidate。',accepts:['checker.py / verifier.py / scorer.py','local judge / validation script']};
      session.needs=[session.primaryNeed,...list(session.needs).filter((item)=>item.code!==session.primaryNeed.code)].slice(0,6);
    }else{
      const need=submissionNeed(auto);if(need&&session.status!=='solved'){session.primaryNeed=need;session.needs=[need,...list(session.needs).filter((item)=>item.code!==need.code)].slice(0,6);}
    }
  }
  session.nextInput=planChallengeNextInput(analysis,session);
  return session;
}

module.exports={...base,buildChallengeSession,submissionNeed};
