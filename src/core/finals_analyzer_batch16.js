const base=require('./finals_analyzer_batch15');
const { buildWorkspaceAutopilot }=require('./workspace_autopilot');

async function scanWorkspace(rootPath) {
  const analysis=await base.scanWorkspace(rootPath);
  analysis.autopilot=buildWorkspaceAutopilot(analysis);
  const first=analysis.autopilot.actions?.[0];
  if (first) analysis.recommendations=[`自动优先级：${first.title}${first.detail?` —— ${first.detail}`:''}`,...(analysis.recommendations||[])];
  analysis.version=Math.max(Number(analysis.version)||1,16);
  return analysis;
}

function buildAutopilotSection(analysis) {
  const a=analysis.autopilot;
  if (!a) return '';
  const lines=['## 自动赛题工作流',''];
  if (a.track) lines.push(`- 最可能方向：${a.track.title}（score=${a.track.score}）`);
  lines.push(`- 自动检查：${a.summary?.automaticCheckKinds||0} 类 / ${a.summary?.automaticCheckHits||0} 次命中`);
  lines.push(`- 高危线索：${a.summary?.highFindings||0}`);
  lines.push(`- Flag 候选：${a.summary?.flagCandidates||0}`);
  lines.push(`- 可导出产物：${a.summary?.exportableArtifacts||0}`,'');
  if (a.actions?.length) {
    lines.push('### 最短处理顺序','');
    a.actions.forEach((item,index)=>lines.push(`${index+1}. **${item.title}**${item.detail?` — ${item.detail}`:''}`));
    lines.push('');
  }
  if (a.automaticChecks?.length) {
    lines.push('### 已自动运行/命中的分析器','');
    a.automaticChecks.forEach((item)=>lines.push(`- ${item.title}: ${item.hits}`));
    lines.push('');
  }
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildAutopilotSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildAutopilotSection};
