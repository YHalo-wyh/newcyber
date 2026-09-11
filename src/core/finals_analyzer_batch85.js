'use strict';

const base=require('./finals_analyzer_batch83');
const {analyzeSubmissionBundle}=require('./challenge_submission_autopilot_v2');
const {buildChallengeSession}=require('./challenge_session_batch85');

function upsertCheck(analysis,check){analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);}
function mergeFindings(analysis,findings){analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const files=await base.readCandidateFiles(rootPath,analysis);
  const submission=analyzeSubmissionBundle(files,analysis);
  analysis.submissionAutopilot=submission;
  if(submission.status!=='not-detected'){
    mergeFindings(analysis,submission.findings);
    upsertCheck(analysis,{id:'challenge-submission-autopilot',title:'Submission 模板识别 / 自动封装',hits:submission.status==='formatted'?1:0,detail:submission.status==='formatted'?`${submission.result?.format||'unknown'} · ${submission.result?.template||'template'}`:`${submission.status}: ${submission.next||'等待候选'}`});
  }
  analysis.challengeSession=buildChallengeSession(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,85);
  return analysis;
}

function batch85Section(analysis){
  const auto=analysis.submissionAutopilot;if(!auto||auto.status==='not-detected')return'';
  const lines=['## Batch85 · Submission Drop-to-Result','',`- 状态：${auto.status}`];
  if(auto.result)lines.push(`- 模板：${auto.result.template||'unknown'} · format=${auto.result.format||'unknown'} · kind=${auto.result.kind||'submission'}`);
  if(auto.result?.contract)lines.push(`- Contract：${JSON.stringify(auto.result.contract)}`);
  if(auto.next)lines.push(`- 下一步：${auto.next}`);
  lines.push('','> 只根据题目自带 sample submission / submission template 的字段结构封装已有候选；不会把普通 query/calibration 表误当提交模板。formatted 仍是 candidate，必须由 checker/verifier/scorer 才能升级 solved。');
  return lines.join('\n');
}
function buildMarkdownReport(analysis,notes=''){const report=base.buildMarkdownReport(analysis,notes);const section=batch85Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch85Section};
