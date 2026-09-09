'use strict';

const base=require('./finals_analyzer_batch41');
const {attachAiStage1Mission}=require('./ai_stage1_mission');

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  attachAiStage1Mission(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,44);
  return analysis;
}

function buildAiStage1MissionSection(analysis){
  const mission=analysis.aiStage1Mission;
  if(!mission?.applicable)return'';
  const s=mission.summary||{};
  const lines=[
    '## AI Stage-One Mission','',
    `- covered：${Number(s.covered)||0}/${Number(mission.officialCoverage)||5}`,
    `- evidence：${Number(s.evidence)||0}`,
    `- candidate：${Number(s.candidate)||0}`,
    `- data-needed：${Number(s['data-needed'])||0}`,
    `- detected files：${Number(s.detectedFiles)||0}`
  ];
  if(mission.nextDirection)lines.push('',`### 下一步：${mission.nextDirection.title}`,'',`- 状态：${mission.nextDirection.status}`,`- 动作：${mission.nextDirection.nextAction}`,`- 工具：${(mission.nextDirection.tools||[]).join(', ')||'ai-skill-matrix'}`);
  lines.push('','### 五方向状态','');
  for(const item of mission.directions||[]){
    lines.push(`- **${item.title}** · ${item.status} · confidence=${item.confidence} · evidence=${item.evidence?.length||0}`);
    for(const ev of (item.evidence||[]).slice(0,3))lines.push(`  - \`${ev.file}\` · ${ev.title}${ev.evidence?` · ${ev.evidence}`:''}`);
  }
  lines.push('','> 路径/文件名关键词只会形成 candidate；evidence 必须来自结构化分析结果或可追溯 finding。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildAiStage1MissionSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildAiStage1MissionSection};
