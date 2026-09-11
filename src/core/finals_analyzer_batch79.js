'use strict';

const base=require('./finals_analyzer_batch49');
const {matchTrainingFamilies}=require('./ai_training_family_matcher');
const {buildAiStrategyPlan}=require('./ai_strategy_contracts');

function upsertAutomaticCheck(analysis,check){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);
  if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const familyMatch=matchTrainingFamilies(analysis,{limit:10});
  analysis.trainingFamilyMatch=familyMatch;
  const strategy=buildAiStrategyPlan(analysis,{familyMatch,limit:5});
  analysis.aiStrategyPlan=strategy;
  if(familyMatch.status!=='not-detected')upsertAutomaticCheck(analysis,{id:'training-family-match',title:'历史赛题家族匹配 / 策略路由',hits:familyMatch.matches.length,detail:familyMatch.next});
  if(strategy.status!=='needs-input'||strategy.summary.steps>0)upsertAutomaticCheck(analysis,{id:'ai-strategy-contract-plan',title:'AI Strategy Contract / 输入契约规划',hits:strategy.summary.steps,detail:`closed=${strategy.summary.closed}; actionable=${strategy.summary.actionable}; waiting=${strategy.summary.waiting}`});
  analysis.version=Math.max(Number(analysis.version)||1,79);
  return analysis;
}

function strategySection(analysis){
  const plan=analysis.aiStrategyPlan;if(!plan)return'';
  const lines=['## AI Strategy Contract Plan','',`- status：${plan.status}`,`- directions：${plan.summary.directions}`,`- closed：${plan.summary.closed}`,`- actionable：${plan.summary.actionable}`,`- waiting：${plan.summary.waiting}`];
  for(const item of plan.plans||[]){
    lines.push('',`### ${item.direction}`);
    for(const action of item.steps||[])lines.push(`- [${action.status}] ${action.title}：${action.detail}${action.missing?.length?` · missing=${action.missing.join(', ')}`:''}`);
  }
  lines.push('','> Strategy Contract 只根据当前附件证据决定下一步与缺失输入；不会复制历史赛题答案，也不会为了“自动化”执行不受信脚本。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=strategySection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,strategySection};