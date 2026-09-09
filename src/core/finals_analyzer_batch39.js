'use strict';

const base=require('./finals_analyzer_batch38');
const {buildChallengeSession}=require('./challenge_session');

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  if(options.challengeInput)analysis.challengeInput={...options.challengeInput};
  else if(!analysis.challengeInput)analysis.challengeInput={kind:'directory',path:analysis.workspacePath||rootPath};
  analysis.challengeSession=buildChallengeSession(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,39);
  return analysis;
}

function buildChallengeSessionSection(analysis){
  const session=analysis.challengeSession;
  if(!session)return'';
  const lines=['## Challenge Session','',`- 状态：${session.status}`,`- 结论：${session.headline}`];
  if(session.result?.value)lines.push(`- 当前结果：\`${session.result.value}\`${session.result.confidence?` · ${session.result.confidence}`:''}`);
  lines.push(`- 已自动运行模板：${session.stats?.templatesRun||0}`);
  if(session.solverLedger?.length){
    lines.push('- Solver Ledger：');
    for(const item of session.solverLedger.slice(0,12))lines.push(`  - ${item.title}: ${item.status}${item.detail?` · ${item.detail}`:''}`);
  }
  if(session.primaryNeed)lines.push(`- 还缺：${session.primaryNeed.title} · ${session.primaryNeed.why}`);
  lines.push(`- 本地 AI 接管包：${session.aiHandoff?.ready?'ready':'not-needed'}`,'',
    '> 默认工作流：附件 → 自动识别 → 模板求解 → verifier → 缺材料请求 / 本地 AI 接管。专业工具只保留为复核与调试入口。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildChallengeSessionSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildChallengeSessionSection};
