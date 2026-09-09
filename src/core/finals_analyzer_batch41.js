'use strict';

const base=require('./finals_analyzer_batch40');
const { executeReadySolvers }=require('./solver_executor');
const { buildChallengeSession }=require('./challenge_session');
const { buildSolverPipeline }=require('./solver_pipeline');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}

function attachExecutionToPipeline(pipeline,execution){
  if(!pipeline)return pipeline;
  const byNode=new Map();
  for(const attempt of list(execution?.attempts)){
    if(!byNode.has(attempt.nodeId))byNode.set(attempt.nodeId,[]);
    byNode.get(attempt.nodeId).push(attempt);
  }
  for(const item of list(pipeline.nodes)){
    const attempts=byNode.get(item.id)||[];
    if(!attempts.length)continue;
    const done=attempts.filter((x)=>x.status==='done').length;
    const blocked=attempts.filter((x)=>x.status==='blocked').length;
    item.execution={attempts:attempts.length,done,blocked,adapters:[...new Set(attempts.map((x)=>x.adapter).filter(Boolean))],files:attempts.map((x)=>x.file).filter(Boolean).slice(0,12)};
    item.evidence=[...(item.evidence||[]),`AUTO EXEC ${done}/${attempts.length}`];
    if(done)item.evidence.push(...attempts.filter((x)=>x.status==='done').slice(0,3).map((x)=>`${x.adapter} · ${x.file}`));
    if(blocked){
      const first=attempts.find((x)=>x.status==='blocked');
      item.evidence.push(`BLOCKED · ${text(first?.error)||'adapter stopped'}`);
      if(item.state==='ready'){
        item.state='blocked';
        item.detail=`自动执行已尝试，但 Adapter 停止：${text(first?.error)||'未知错误'}`;
      }
    }
  }
  const nodes=list(pipeline.nodes);
  pipeline.summary={total:nodes.length,done:nodes.filter((x)=>x.state==='done').length,partial:nodes.filter((x)=>x.state==='partial').length,blocked:nodes.filter((x)=>x.state==='blocked').length,ready:nodes.filter((x)=>x.state==='ready').length,skipped:nodes.filter((x)=>x.state==='skipped').length};
  pipeline.activeNodeId=nodes.find((x)=>x.state==='blocked'&&x.phase!=='verify')?.id||nodes.find((x)=>x.state==='ready'&&x.phase!=='verify')?.id||nodes.find((x)=>x.id==='verify')?.id||null;
  return pipeline;
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const execution=await executeReadySolvers(rootPath,analysis,options);
  analysis.solverExecution=execution;

  if(execution.attempts?.length){
    analysis.challengeSession=buildChallengeSession(analysis);
    const pipeline=attachExecutionToPipeline(buildSolverPipeline(analysis),execution);
    analysis.solverPipeline=pipeline;
    analysis.challengeSession.solverPipeline=pipeline;
    analysis.challengeSession.pipelineSummary=pipeline.summary;
    analysis.challengeSession.solverExecution=execution;
    analysis.challengeSession.executorSummary=execution.summary;
  }else{
    const pipeline=attachExecutionToPipeline(analysis.solverPipeline||analysis.challengeSession?.solverPipeline,execution);
    if(pipeline){
      analysis.solverPipeline=pipeline;
      analysis.challengeSession||={};
      analysis.challengeSession.solverPipeline=pipeline;
      analysis.challengeSession.pipelineSummary=pipeline.summary;
    }
    if(analysis.challengeSession){analysis.challengeSession.solverExecution=execution;analysis.challengeSession.executorSummary=execution.summary;}
  }

  analysis.version=Math.max(Number(analysis.version)||1,41);
  return analysis;
}

function buildSolverExecutionSection(analysis){
  const execution=analysis.solverExecution||analysis.challengeSession?.solverExecution;
  if(!execution)return'';
  const summary=execution.summary||{};
  const lines=['## Solver Executor','',`- enabled：${execution.enabled===false?'false':'true'}`,`- planned：${Number(summary.planned)||0}`,`- done：${Number(summary.done)||0}`,`- blocked：${Number(summary.blocked)||0}`,`- bytes read：${Number(summary.bytesRead)||0}`];
  if(execution.attempts?.length){
    lines.push('','### Adapter Transactions','');
    for(const item of execution.attempts.slice(0,20)){
      const chain=list(item.transitions).map((x)=>String(x).toUpperCase()).join(' → ');
      lines.push(`- **${item.adapter}** · \`${item.file}\` · ${chain}${item.error?` · ${item.error}`:''}`);
    }
  }
  lines.push('','> Executor 只消费 READY 节点；首批 Adapter 均为离线只读解析，不运行题目程序，也不会自动连接远程目标。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildSolverExecutionSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildSolverExecutionSection,attachExecutionToPipeline};
