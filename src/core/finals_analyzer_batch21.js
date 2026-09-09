const base=require('./finals_analyzer_batch20');
const {analyzeComponentReachability}=require('./component_reachability');

function clamp(value,min,max){return Math.max(min,Math.min(max,value));}

function applyReachabilityToCandidates(analysis){
  const reach=analysis.componentReachability;
  const result=analysis.vulnerabilityCandidates;
  if(!reach||!result)return;
  const byId=new Map((reach.results||[]).map((item)=>[item.candidateId,item]));
  for(const candidate of result.candidates||[]){
    const evidence=byId.get(candidate.id)||{state:'unknown',confidence:'low',adjustment:0,reason:'没有足够的源码引用证据。',usageFiles:[],surfaceFiles:[],importHits:0,surfaceHits:0};
    candidate.reachability={...evidence};
    const baseScore=Number(candidate.priority?.score)||0;
    const adjusted=Math.round(clamp(baseScore+(Number(evidence.adjustment)||0),0,100));
    const applicability=candidate.applicability?.state||'unknown';
    let band='review';
    if(applicability==='not-affected')band='deprioritized';
    else if(applicability==='affected'&&['surface-co-located','source-reference'].includes(evidence.state)&&adjusted>=84)band='hot';
    candidate.priority={...(candidate.priority||{}),baseScore,reachabilityAdjustment:Number(evidence.adjustment)||0,score:adjusted,band};
    if(evidence.reason)candidate.nextAction=`${evidence.reason} ${candidate.nextAction||''}`.trim();
  }
  result.candidates.sort((a,b)=>b.priority.score-a.priority.score||String(a.primaryId).localeCompare(String(b.primaryId)));
  const candidates=result.candidates||[];
  result.summary={
    ...(result.summary||{}),
    total:candidates.length,
    hot:candidates.filter((x)=>x.priority.band==='hot').length,
    review:candidates.filter((x)=>x.priority.band==='review').length,
    deprioritized:candidates.filter((x)=>x.priority.band==='deprioritized').length,
    withUsageEvidence:candidates.filter((x)=>['surface-co-located','source-reference'].includes(x.reachability?.state)).length,
    withSurfaceEvidence:candidates.filter((x)=>x.reachability?.state==='surface-co-located').length,
    dependencyOnly:candidates.filter((x)=>['dependency-only','dev-dependency-only'].includes(x.reachability?.state)).length
  };
  result.schema='newcyber.vulnerability-candidates.v2';
  result.note='候选优先级同时考虑版本适用性、漏洞元数据、本地 PoC 参考和题目源码引用/外部入口共址证据。源码扫描是保守启发式：缺少直接引用不能证明不可达。';
}

function refreshAutopilot(analysis){
  const autopilot=analysis.autopilot;
  const reach=analysis.componentReachability;
  const result=analysis.vulnerabilityCandidates;
  if(!autopilot||!reach||!result)return;
  autopilot.automaticChecks ||= [];
  if(!autopilot.automaticChecks.some((x)=>x.id==='component-reachability')){
    autopilot.automaticChecks.push({id:'component-reachability',title:'组件源码引用 / 入口共址',hits:(reach.summary?.surfaceCoLocated||0)+(reach.summary?.sourceReference||0)});
  }
  autopilot.actions=(autopilot.actions||[]).filter((x)=>x.id!=='vulnerability-candidate-hot');
  const top=(result.candidates||[]).find((x)=>x.priority?.band==='hot')||(result.candidates||[]).find((x)=>x.applicability?.state==='affected')||(result.candidates||[]).find((x)=>x.priority?.band==='review');
  if(top){
    const hot=top.priority?.band==='hot';
    const reachLabel=top.reachability?.state==='surface-co-located'?'源码引用 + 外部入口共址':top.reachability?.state==='source-reference'?'源码已引用':'仅依赖证据';
    autopilot.actions.push({
      id:'vulnerability-candidate-hot',
      priority:hot?99:top.applicability?.state==='affected'?86:72,
      level:hot?'hot':'normal',
      title:hot?`优先验证：${top.primaryId}`:`补齐可达性：${top.primaryId}`,
      detail:`${top.component?.name||'component'} ${top.component?.version||'?'} · ${reachLabel} · priority ${top.priority?.score||0}。${top.nextAction||''}`
    });
    autopilot.actions.sort((a,b)=>(b.priority||0)-(a.priority||0));
    autopilot.actions=autopilot.actions.slice(0,4);
  }
  autopilot.summary ||= {};
  autopilot.summary.vulnerabilityCandidates=result.summary?.total||0;
  autopilot.summary.vulnerabilityHot=result.summary?.hot||0;
  autopilot.summary.vulnerabilityReview=result.summary?.review||0;
  autopilot.summary.componentReachabilityHits=(reach.summary?.surfaceCoLocated||0)+(reach.summary?.sourceReference||0);
  autopilot.summary.componentSurfaceHits=reach.summary?.surfaceCoLocated||0;
  autopilot.summary.automaticCheckKinds=autopilot.automaticChecks.length;
  autopilot.summary.automaticCheckHits=autopilot.automaticChecks.reduce((sum,item)=>sum+(Number(item.hits)||0),0);
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  analysis.componentReachability=await analyzeComponentReachability(rootPath,analysis,options.reachability||{});
  applyReachabilityToCandidates(analysis);
  refreshAutopilot(analysis);
  analysis.recommendations=(analysis.recommendations||[]).filter((x)=>!/^统一漏洞队列：|^漏洞候选复核：|^漏洞候选降权：/.test(String(x)));
  const s=analysis.vulnerabilityCandidates?.summary||{};
  if(s.hot)analysis.recommendations.unshift(`漏洞候选：${s.hot} 个 HOT 同时具备版本适用性和题目源码使用证据；优先核对触发条件与补丁差异。`);
  if(s.review)analysis.recommendations.push(`漏洞候选：${s.review} 个保留在 REVIEW，其中仅依赖声明而缺少源码引用的候选不会直接升为 HOT。`);
  if(s.dependencyOnly)analysis.recommendations.push(`可达性补证：${s.dependencyOnly} 个候选当前只有依赖/版本证据；注意传递依赖、反射和框架自动装配仍可能导致真实可达。`);
  analysis.version=Math.max(Number(analysis.version)||1,21);
  analysis.batch21Counts={...(analysis.componentReachability?.summary||{}),hot:s.hot||0,review:s.review||0,deprioritized:s.deprioritized||0};
  return analysis;
}

function buildBatch21Section(analysis){
  const reach=analysis.componentReachability;
  const result=analysis.vulnerabilityCandidates;
  if(!reach||!result)return '';
  const s=reach.summary||{};
  const lines=['## Batch 21 · Component Reachability Evidence','',`- source files scanned=${s.scannedSourceFiles||0}, surface-co-located=${s.surfaceCoLocated||0}, source-reference=${s.sourceReference||0}, dependency-only=${s.dependencyOnly||0}, dev-only=${s.devDependencyOnly||0}`,''];
  for(const item of (result.candidates||[]).slice(0,50)){
    const r=item.reachability||{};
    lines.push(`### ${item.primaryId} · ${item.priority?.band?.toUpperCase()||'REVIEW'} · ${item.priority?.score||0}`,'',`- 组件：${item.component?.ecosystem||'?'}:${item.component?.name||'?'} ${item.component?.version||'?'}`);
    lines.push(`- 可达性证据：${r.state||'unknown'} · ${r.reason||'证据不足'}`);
    if(r.usageFiles?.length)lines.push(`- 源码引用：${r.usageFiles.join(', ')}`);
    if(r.surfaceFiles?.length)lines.push(`- 外部入口共址：${r.surfaceFiles.join(', ')}`);
    lines.push(`- 优先级修正：${(item.priority?.baseScore??item.priority?.score??0)} ${Number(item.priority?.reachabilityAdjustment||0)>=0?'+':''}${item.priority?.reachabilityAdjustment||0} => ${item.priority?.score||0}`,'');
  }
  lines.push('> 这里不是完整调用图。没有直接源码引用只会降到 REVIEW，不会被解释为“漏洞不可达”；传递依赖、反射、插件和框架自动装配需要人工继续确认。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch21Section(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,applyReachabilityToCandidates,refreshAutopilot,buildBatch21Section};
