'use strict';

const base=require('./finals_analyzer_batch80');
const {buildPromptAttackMegaPack}=require('./ai_prompt_attack_mega');
const {runStage1WorldwideHoldout}=require('./ai_stage1_worldwide_holdout');

function upsertCheck(analysis,check){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);
  if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const mega=buildPromptAttackMegaPack({limit:4096});
  analysis.promptAttackMegaPack={schema:mega.schema,seeds:mega.seeds,mutations:mega.mutations,transforms:mega.transforms,total:mega.total,coverage:mega.coverage};
  upsertCheck(analysis,{id:'prompt-attack-megapack',title:'提示词攻击 MegaPack',hits:mega.total,detail:`${mega.seeds} families × ${mega.mutations} mutations × ${mega.transforms} transforms = ${mega.total} safe templates`});

  const benchmark=runStage1WorldwideHoldout();
  analysis.aiStage1WorldwideHoldout={schema:benchmark.schema,summary:benchmark.summary,byDirection:benchmark.byDirection,gaps:benchmark.gaps};
  upsertCheck(analysis,{id:'ai-stage1-worldwide-holdout',title:'全网公开 AI 安全题 mechanics holdout',hits:benchmark.summary.closed,detail:`closed=${benchmark.summary.closed}/${benchmark.summary.cases}; partial=${benchmark.summary.partial}; gaps=${benchmark.summary.gaps}; proxy=${(benchmark.summary.solveProxyRate*100).toFixed(1)}%`});

  if(analysis.aiStage1OfficialDirections?.directions){
    const prompt=analysis.aiStage1OfficialDirections.directions.find((x)=>x.id==='prompt-llm-security');
    if(prompt)prompt.reinforcement=`${mega.total}-template MegaPack + existing evaluator/source audit`;
  }
  analysis.version=Math.max(Number(analysis.version)||1,81);
  return analysis;
}

function worldwideSection(analysis){
  const mega=analysis.promptAttackMegaPack;const holdout=analysis.aiStage1WorldwideHoldout;
  if(!mega&&!holdout)return'';
  const lines=['## AI 全网公开赛题 Holdout / MegaPack',''];
  if(mega)lines.push(`- Prompt MegaPack：${mega.total} 条（${mega.seeds} families × ${mega.mutations} mutations × ${mega.transforms} transforms）`);
  if(holdout){
    const s=holdout.summary;
    lines.push(`- source-derived holdout：closed=${s.closed}/${s.cases} (${(s.solveProxyRate*100).toFixed(1)}%) · partial=${s.partial} · gap=${s.gaps}`);
    for(const [direction,row] of Object.entries(holdout.byDirection||{}))lines.push(`  - ${direction}：closed=${row.closed}/${row.cases} · partial=${row.partial} · gap=${row.gap}`);
    if(holdout.gaps?.length)lines.push(`- 当前硬缺口：${holdout.gaps.map((x)=>`${x.id}`).join(', ')}`);
  }
  lines.push('','> Holdout 的 solveProxyRate 是公开赛题机制的离线闭环代理值，不等同于真实随机比赛解题率；未知赛题仍以 checker/verifier-backed solved 为准。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=worldwideSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,worldwideSection};
