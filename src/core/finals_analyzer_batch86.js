'use strict';

const base=require('./finals_analyzer_batch85');
const {analyzeUniversalTriggerCandidates}=require('./ai_universal_trigger_ranker');
const {analyzeSubmissionBundle}=require('./challenge_submission_autopilot_v2');
const {buildChallengeSession}=require('./challenge_session_batch86');

function upsertCheck(analysis,check){analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);}
function mergeFindings(analysis,findings){analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}}
function looksTriggerLog(file){const corpus=`${file?.path||''}\n${String(file?.text||'').slice(0,2*1024*1024)}`;return/(?:trigger|suffix|candidate[_ -]?(?:trigger|suffix)|backdoor[_ -]?trigger)/i.test(corpus)&&/(?:prompt[_ -]?id|sample[_ -]?id|query[_ -]?id|\bprompt\b|\bquery\b)/i.test(corpus)&&/(?:success|target[_ -]?hit|jailbreak|accepted|reward|target[_ -]?score|unsafe[_ -]?score|objective)/i.test(corpus);}
function statusRank(value){return{candidate:4,ambiguous:3,partial:2,gap:1}[value]||0;}
function chooseRun(runs){return runs.slice().sort((a,b)=>statusRank(b.result.status)-statusRank(a.result.status)||(b.result.bestCandidate?.asr??-1)-(a.result.bestCandidate?.asr??-1)||(b.result.bestCandidate?.prompts??0)-(a.result.bestCandidate?.prompts??0)||a.file.localeCompare(b.file))[0]||null;}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);const files=await base.readCandidateFiles(rootPath,analysis);const runs=[];
  for(const file of files){if(!looksTriggerLog(file))continue;try{const result=analyzeUniversalTriggerCandidates(file.text);if(result.status!=='gap')runs.push({file:file.path,result});}catch{}}
  if(runs.length){
    const chosen=chooseRun(runs);const result=chosen.result;
    analysis.aiUniversalTriggerAutopilot={schema:'newcyber.ai-universal-trigger-autopilot.v1',status:result.status,summary:{files:runs.length,candidates:result.candidates,eligible:result.eligible,rows:result.rows},file:chosen.file,bestCandidate:result.bestCandidate||null,result:result.result?{...result.result,source:`${result.result.source}:${chosen.file}`} : null,shortlist:result.shortlist,findings:result.findings.map((x)=>({...x,file:chosen.file})),next:result.next,notes:result.notes};
    mergeFindings(analysis,analysis.aiUniversalTriggerAutopilot.findings);
    upsertCheck(analysis,{id:'ai-universal-trigger-ranker',title:'Universal Trigger / Backdoor 候选跨 Prompt 排名',hits:result.status==='candidate'?1:0,detail:`status=${result.status}; candidates=${result.candidates}; eligible=${result.eligible}; file=${chosen.file}`});
  }else analysis.aiUniversalTriggerAutopilot={schema:'newcyber.ai-universal-trigger-autopilot.v1',status:'not-detected',summary:{files:0,candidates:0,eligible:0,rows:0},result:null,findings:[],next:null};

  analysis.challengeSession=buildChallengeSession(analysis);
  if(analysis.aiUniversalTriggerAutopilot.status==='candidate'&&analysis.aiUniversalTriggerAutopilot.result){
    const submission=analyzeSubmissionBundle(files,analysis);
    if(submission.status==='formatted'){
      analysis.submissionAutopilot=submission;mergeFindings(analysis,submission.findings);
      upsertCheck(analysis,{id:'challenge-submission-autopilot',title:'Submission 模板识别 / 自动封装',hits:1,detail:`${submission.result?.format||'unknown'} · ${submission.result?.template||'template'}`});
      analysis.challengeSession=buildChallengeSession(analysis);
    }
  }
  analysis.version=Math.max(Number(analysis.version)||1,86);return analysis;
}

function batch86Section(analysis){const auto=analysis.aiUniversalTriggerAutopilot;if(!auto||auto.status==='not-detected')return'';const lines=['## Batch86 · Universal Trigger Ranker','',`- 状态：${auto.status} · file=${auto.file||'n/a'}`];if(auto.bestCandidate)lines.push(`- Top：ASR=${Number(auto.bestCandidate.asr||0).toFixed(4)} · prompts=${auto.bestCandidate.prompts} · tokenCount=${auto.bestCandidate.tokenCount} · cleanFailure=${auto.bestCandidate.cleanFailureRate==null?'n/a':Number(auto.bestCandidate.cleanFailureRate).toFixed(4)}`);if(auto.next)lines.push(`- 下一步：${auto.next}`);lines.push('','> 只对已有本地/授权 trigger candidate 日志做跨 Prompt 排名；没有题目显式 token 长度限制时不会自行假设长度。candidate 必须继续通过 reward/checker 或独立 holdout。');return lines.join('\n');}
function buildMarkdownReport(analysis,notes=''){const report=base.buildMarkdownReport(analysis,notes);const section=batch86Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch86Section,looksTriggerLog,chooseRun};
