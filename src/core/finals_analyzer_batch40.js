'use strict';

const base=require('./finals_analyzer_batch39');
const {buildSolverPipeline}=require('./solver_pipeline');

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const pipeline=buildSolverPipeline(analysis);
  analysis.solverPipeline=pipeline;
  analysis.challengeSession||={};
  analysis.challengeSession.solverPipeline=pipeline;
  analysis.challengeSession.pipelineSummary=pipeline.summary;
  analysis.version=Math.max(Number(analysis.version)||1,40);
  return analysis;
}

function buildSolverPipelineSection(analysis){
  const pipeline=analysis.solverPipeline||analysis.challengeSession?.solverPipeline;
  if(!pipeline)return'';
  const lines=['## Solver Pipeline','',`- 节点：${pipeline.summary?.total||0}`,`- DONE：${pipeline.summary?.done||0}`,`- PARTIAL：${pipeline.summary?.partial||0}`,`- BLOCKED：${pipeline.summary?.blocked||0}`,`- READY：${pipeline.summary?.ready||0}`];
  if(pipeline.activeNodeId)lines.push(`- 当前节点：${pipeline.activeNodeId}`);
  lines.push('','### Execution Timeline','');
  for(const item of (pipeline.nodes||[]).slice(0,24))lines.push(`- **${item.state.toUpperCase()}** · ${item.title}${item.detail?` — ${item.detail}`:''}`);
  lines.push('','> Pipeline 只记录真实执行证据与明确适用条件；证据不足的模板保持 SKIPPED。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildSolverPipelineSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildSolverPipelineSection};
