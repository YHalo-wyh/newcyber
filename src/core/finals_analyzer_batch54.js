'use strict';

const base=require('./finals_analyzer_batch53');
const {buildFiveDirectionAutopilot}=require('./ai_five_direction_competition_autopilot');

function list(value){return Array.isArray(value)?value:[];}
function oneLine(value){return String(value??'').replace(/\s+/g,' ').replace(/`/g,"'").trim();}

function attachCompetitionAutopilot(analysis,autopilot){
  analysis.aiCompetitionAutopilot=autopilot;
  const session=analysis.challengeSession||(analysis.challengeSession={});
  session.aiCompetitionAutopilot=autopilot;
  session.solverLedger=list(session.solverLedger);
  const idx=session.solverLedger.findIndex((x)=>x.id==='ai-five-direction-autopilot');
  const primary=autopilot.directions.find((x)=>x.id===autopilot.primaryDirection)||autopilot.directions[0];
  const ledger={
    id:'ai-five-direction-autopilot',
    template:'AI Five-Direction Competition Autopilot',
    status:autopilot.flagClosure.verifiedCount?'done':autopilot.flagClosure.candidateCount?'partial':'running',
    evidence:[
      `primary=${primary?.title||'unknown'}`,
      `prompt-templates=${autopilot.promptPlan.templateCount}`,
      `prompt-probes=${autopilot.promptPlan.probeCount}`,
      `flag-candidates=${autopilot.flagClosure.candidateCount}`,
      `flag-verified=${autopilot.flagClosure.verifiedCount}`
    ],
    detail:autopilot.flagClosure.verifiedCount
      ? '已有严格 Verified flag，继续保留其他方向证据用于复核。'
      : `默认按比赛原生五方向自动路由；主方向 ${primary?.title||'未定'}。远程靶机只生成建议模板，不自动发包。`
  };
  if(idx>=0)session.solverLedger[idx]=ledger;else session.solverLedger.unshift(ledger);
  session.aiHandoff=session.aiHandoff||{};
  session.aiHandoff.competitionNative={
    primaryDirection:autopilot.primaryDirection,
    nextActions:autopilot.nextActions,
    remoteTemplates:primary?.remoteTemplates||[],
    promptRecommended:autopilot.promptPlan.recommended.slice(0,12)
  };
  return analysis;
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const autopilot=buildFiveDirectionAutopilot(analysis,options);
  attachCompetitionAutopilot(analysis,autopilot);
  analysis.version=Math.max(Number(analysis.version)||1,54);
  return analysis;
}

function buildCompetitionAutopilotSection(analysis){
  const a=analysis.aiCompetitionAutopilot||analysis.challengeSession?.aiCompetitionAutopilot;
  if(!a)return'';
  const primary=a.directions.find((x)=>x.id===a.primaryDirection)||a.directions[0];
  const lines=[
    '## AI Five-Direction Competition Autopilot','',
    `- mode：competition-native`,
    `- goal：flag-closure`,
    `- primary：${oneLine(primary?.title||'unknown')}`,
    `- prompt templates：${a.promptPlan.templateCount}`,
    `- generated prompt probes：${a.promptPlan.probeCount}`,
    `- flag candidates：${a.flagClosure.candidateCount}`,
    `- verified flags：${a.flagClosure.verifiedCount}`,'',
    '### Direction Ranking',''
  ];
  for(const d of a.directions)lines.push(`- **${oneLine(d.title)}** · score=${d.score} · ${d.confidence.toUpperCase()} · local=${d.localTools.join(', ')}`);
  if(a.promptPlan.recommended.length){
    lines.push('','### Prompt Attack Recommendations','');
    for(const p of a.promptPlan.recommended.slice(0,12))lines.push(`- \`${oneLine(p.id)}\` · ${oneLine(p.title)} · score=${p.score}`);
  }
  if(primary?.remoteTemplates?.length){
    lines.push('','### Remote Target Suggested Answer Templates','');
    for(const item of primary.remoteTemplates)lines.push(`- **${oneLine(item.title)}**：${oneLine(item.template)}`);
  }
  lines.push('','> NewCyber 以五个 AI 初赛方向为默认工作流，不再区分赛题/普通模式。远程目标默认只生成建议请求、答案模板和成功判据，不自动对未知目标发起网络攻击。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildCompetitionAutopilotSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildCompetitionAutopilotSection,attachCompetitionAutopilot};
