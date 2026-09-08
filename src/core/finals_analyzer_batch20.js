const base=require('./finals_analyzer_batch19');
const {buildVulnerabilityCandidates}=require('./vulnerability_candidates');

function augmentAutopilotCandidates(analysis){
  const autopilot=analysis.autopilot;
  const result=analysis.vulnerabilityCandidates;
  if(!autopilot||!result)return;
  autopilot.automaticChecks ||= [];
  if(!autopilot.automaticChecks.some((x)=>x.id==='vulnerability-candidates')){
    autopilot.automaticChecks.push({id:'vulnerability-candidates',title:'统一漏洞候选队列',hits:result.summary?.total||0});
  }
  const top=(result.candidates||[]).find((x)=>x.priority?.band==='hot')||(result.candidates||[]).find((x)=>x.priority?.band==='review');
  autopilot.actions=(autopilot.actions||[]).filter((x)=>x.id!=='vulnerability-candidate-hot');
  if(top){
    const state=top.applicability?.state||'unknown';
    const prefix=state==='affected'?'优先核对漏洞候选':'补齐漏洞候选证据';
    autopilot.actions.push({
      id:'vulnerability-candidate-hot',
      priority:state==='affected'?98:82,
      level:state==='affected'?'hot':'normal',
      title:`${prefix}：${top.primaryId}`,
      detail:`${top.component?.name||'component'} ${top.component?.version||'?'} · priority ${top.priority?.score||0} · ${top.severity?.level||'unknown'}${top.poc?.count?` · PoC refs ${top.poc.count}`:''}。${top.nextAction||''}`
    });
    autopilot.actions.sort((a,b)=>(b.priority||0)-(a.priority||0));
    autopilot.actions=autopilot.actions.slice(0,4);
  }
  autopilot.summary ||= {};
  autopilot.summary.vulnerabilityCandidates=result.summary?.total||0;
  autopilot.summary.vulnerabilityHot=result.summary?.hot||0;
  autopilot.summary.vulnerabilityReview=result.summary?.review||0;
  autopilot.summary.vulnerabilityDeprioritized=result.summary?.deprioritized||0;
  autopilot.summary.automaticCheckKinds=autopilot.automaticChecks.length;
  autopilot.summary.automaticCheckHits=autopilot.automaticChecks.reduce((sum,item)=>sum+(Number(item.hits)||0),0);
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  analysis.vulnerabilityCandidates=buildVulnerabilityCandidates(analysis,{topK:80});
  augmentAutopilotCandidates(analysis);
  analysis.recommendations ||= [];
  const s=analysis.vulnerabilityCandidates.summary||{};
  if(s.hot)analysis.recommendations.unshift(`统一漏洞队列：${s.hot} 个 HOT 候选同时具备版本适用性与较强元数据证据，已直接送入 Autopilot 最前。`);
  if(s.review)analysis.recommendations.push(`漏洞候选复核：${s.review} 个候选仍需补版本/range/CVSS/CWE 或题目触发面证据。`);
  if(s.deprioritized)analysis.recommendations.push(`漏洞候选降权：${s.deprioritized} 个候选已被当前 advisory 的明确版本范围排除，仅保留低优先参考。`);
  analysis.version=Math.max(Number(analysis.version)||1,20);
  analysis.batch20Counts={...s};
  return analysis;
}

function buildBatch20Section(analysis){
  const result=analysis.vulnerabilityCandidates;if(!result)return '';
  const s=result.summary||{};
  const lines=['## Batch 20 · Unified Vulnerability Candidates','',`- total=${s.total||0}, hot=${s.hot||0}, review=${s.review||0}, deprioritized=${s.deprioritized||0}, withPoC=${s.withPoc||0}, withCWE=${s.withCwe||0}, withCVSS=${s.withCvss||0}`,''];
  for(const item of (result.candidates||[]).slice(0,50)){
    lines.push(`### ${item.primaryId} · ${item.priority.band.toUpperCase()} · ${item.priority.score}`,'',`- 组件：${item.component?.ecosystem||'?'}:${item.component?.name||'?'} ${item.component?.version||'?'}`);
    lines.push(`- 适用性：${item.applicability?.state||'unknown'} · ${item.applicability?.reason||'证据不足'}`);
    if(item.severity?.score!=null)lines.push(`- CVSS：${item.severity.score} (${item.severity.level})${item.severity.vector?` · ${item.severity.vector}`:''}`);
    if(item.cwes?.length)lines.push(`- CWE：${item.cwes.join(', ')}`);
    if(item.poc?.count)lines.push(`- PoC reference：${item.poc.count} 条 · top score ${item.poc.topScore||0}`);
    if(item.evidence?.componentSources?.length)lines.push(`- 组件证据：${item.evidence.componentSources.join(', ')}`);
    lines.push(`- 下一步：${item.nextAction}`,'');
  }
  lines.push('> 候选优先级只用于离线排查排序：AFFECTED 代表当前版本落入已导入 advisory 的明确范围；NOT AFFECTED 只排除这一条 advisory，不代表组件整体安全。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch20Section(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,augmentAutopilotCandidates,buildBatch20Section};
