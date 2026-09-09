'use strict';

const base=require('./finals_analyzer_batch35');
const {buildAutoSolveMission}=require('./auto_solve_mission');

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  analysis.autoSolve=buildAutoSolveMission(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,38);
  return analysis;
}

function buildAutoSolveSection(analysis){
  const mission=analysis.autoSolve;
  if(!mission)return'';
  const lines=['## Auto Solve Mission','',`- 状态：${mission.status}`,`- 结论：${mission.headline}`];
  if(mission.result?.value)lines.push(`- 当前结果：\`${mission.result.value}\`${mission.result.confidence?` · ${mission.result.confidence}`:''}`);
  if(mission.track?.title)lines.push(`- 方向：${mission.track.title} · score ${mission.track.score}`);
  lines.push(`- 自动阶段：${mission.progress?.completed||0}/${mission.progress?.total||0}`);
  for(const stage of mission.stages||[])lines.push(`  - ${stage.title}: ${stage.status} · ${stage.detail||''}`);
  if(mission.gaps?.length)lines.push(`- 当前卡点：${mission.gaps[0].code} · ${mission.gaps[0].detail||''}`);
  if(mission.primaryAction)lines.push(`- 唯一下一步：${mission.primaryAction.title}${mission.primaryAction.detail?` · ${mission.primaryAction.detail}`:''}`);
  lines.push('','> Auto Solve 先在 core 层整合各专项分析器，只把 verified 结果提升为已解；候选、能力缺口和人工步骤保持显式。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildAutoSolveSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildAutoSolveSection};