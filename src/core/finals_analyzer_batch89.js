'use strict';

const base=require('./finals_analyzer_batch88');
const {materializeSubmissionArtifact}=require('./challenge_submission_artifact');
const {buildChallengeSession}=require('./challenge_session_batch89');

function upsertCheck(analysis,check){analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);}
function mergeFindings(analysis,findings){analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  let materialized={status:'not-applicable',artifact:null};
  try{materialized=await materializeSubmissionArtifact(rootPath,analysis.submissionAutopilot,analysis.verifierContractAutopilot);}
  catch(error){materialized={status:'gap',artifact:null,reason:'MATERIALIZE_EXCEPTION',error:String(error?.message||error).slice(0,500)};}
  analysis.submissionArtifact=materialized;
  if(materialized.artifact){
    const finding={id:'submission-artifact-materialized',severity:materialized.artifact.verified?'high':'info',title:materialized.artifact.verified?'已生成 verifier-backed 可提交结果文件':'已生成 submission 候选文件',file:materialized.artifact.path,evidence:`${materialized.artifact.state} · ${materialized.artifact.format} · ${materialized.artifact.bytes} bytes · sha256=${materialized.artifact.sha256}`,meaning:materialized.artifact.verified?'提交 payload 与题目静态 verifier 强约束精确闭环，并已按原始字节写出，可直接作为提交文件。':'提交内容已按题目模板落盘，但尚未命中 checker/verifier，继续保持 candidate。'};
    mergeFindings(analysis,[finding]);
    upsertCheck(analysis,{id:'submission-artifact-materialize',title:'Submission 结果文件落盘',hits:1,detail:`${materialized.artifact.state} · ${materialized.artifact.path}`});
  }else if(materialized.status==='gap')upsertCheck(analysis,{id:'submission-artifact-materialize',title:'Submission 结果文件落盘',hits:0,detail:`GAP · ${materialized.reason||'unknown'}`});
  analysis.challengeSession=buildChallengeSession(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,89);
  return analysis;
}

function batch89Section(analysis){
  const auto=analysis.submissionArtifact;if(!auto||auto.status==='not-applicable')return'';
  const lines=['## Batch89 · Submission Artifact','',`- 状态：${auto.status}`];
  if(auto.artifact){lines.push(`- 文件：${auto.artifact.path}`,`- format=${auto.artifact.format} · bytes=${auto.artifact.bytes} · sha256=${auto.artifact.sha256}`,`- verified=${Boolean(auto.artifact.verified)}`);}
  else if(auto.reason)lines.push(`- GAP：${auto.reason}`);
  lines.push('','> payload 以 UTF-8 原始内容落盘，保留尾部换行；verified 文件只在现有静态 checker/verifier 已精确命中同一 payload 时标记，不执行题目源码。');
  return lines.join('\n');
}
function buildMarkdownReport(analysis,notes=''){const report=base.buildMarkdownReport(analysis,notes);const section=batch89Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch89Section};
