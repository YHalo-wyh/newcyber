const base=require('./finals_analyzer_batch21');
const {analyzeVulnerableApiFlow}=require('./vulnerable_api_flow');

function clamp(value,min,max){return Math.max(min,Math.min(max,value));}

function applyApiFlowToCandidates(analysis){
  const flow=analysis.vulnerableApiFlow;
  const result=analysis.vulnerabilityCandidates;
  if(!flow||!result)return;
  const byId=new Map((flow.results||[]).map((item)=>[item.candidateId,item]));
  for(const candidate of result.candidates||[]){
    const evidence=byId.get(candidate.id)||{state:'unknown',confidence:'low',adjustment:0,reason:'没有足够证据定位组件 API 调用点。',bindings:[],bindingFiles:[],surfaceFiles:[],apiCalls:[],flows:[]};
    candidate.dataflow={...evidence};
    const batch21Score=Number(candidate.priority?.score)||0;
    const adjusted=Math.round(clamp(batch21Score+(Number(evidence.adjustment)||0),0,100));
    const applicability=candidate.applicability?.state||'unknown';
    let band='review';
    if(applicability==='not-affected')band='deprioritized';
    else if(applicability==='affected'&&evidence.state==='entry-to-api'&&adjusted>=86)band='hot';
    candidate.priority={...(candidate.priority||{}),batch21Score,dataflowAdjustment:Number(evidence.adjustment)||0,score:adjusted,band};
    const flowAction=evidence.state==='entry-to-api'
      ? '已形成 ENTRY → API 局部传播证据；下一步核对触发值约束、补丁差异和真实执行路径。'
      : evidence.state==='surface-to-api-nearby'
        ? '已有入口附近的组件调用，但尚未证明请求值进入调用参数；优先补变量/参数传播。'
        : evidence.state==='api-call-only'
          ? '已有组件 API 调用；继续确认调用参数是否来自网络、文件、消息或其他外部输入。'
          : '继续补组件调用点与外部输入传播证据。';
    candidate.nextAction=`${evidence.reason} ${flowAction}`.trim();
  }
  result.candidates.sort((a,b)=>b.priority.score-a.priority.score||String(a.primaryId).localeCompare(String(b.primaryId)));
  const candidates=result.candidates||[];
  result.summary={
    ...(result.summary||{}),
    total:candidates.length,
    hot:candidates.filter((x)=>x.priority?.band==='hot').length,
    review:candidates.filter((x)=>x.priority?.band==='review').length,
    deprioritized:candidates.filter((x)=>x.priority?.band==='deprioritized').length,
    withAttackPath:candidates.filter((x)=>x.dataflow?.state==='entry-to-api').length,
    surfaceNearby:candidates.filter((x)=>x.dataflow?.state==='surface-to-api-nearby').length,
    apiCallOnly:candidates.filter((x)=>x.dataflow?.state==='api-call-only').length,
    importOnly:candidates.filter((x)=>x.dataflow?.state==='import-only').length,
    noApiEvidence:candidates.filter((x)=>['import-only','unknown'].includes(x.dataflow?.state)).length
  };
  result.schema='newcyber.vulnerability-candidates.v3';
  result.note='候选优先级现在进一步要求“外部输入 → 组件 API”局部传播证据。只有版本确认 affected 且观察到 ENTRY → API 的候选才可升为 HOT；入口邻近、API-only、import-only 都继续保留 REVIEW。';
}

function refreshAutopilot(analysis){
  const autopilot=analysis.autopilot;
  const flow=analysis.vulnerableApiFlow;
  const result=analysis.vulnerabilityCandidates;
  if(!autopilot||!flow||!result)return;
  autopilot.automaticChecks ||= [];
  if(!autopilot.automaticChecks.some((x)=>x.id==='entry-to-vulnerable-api')){
    autopilot.automaticChecks.push({id:'entry-to-vulnerable-api',title:'外部输入 → 易受影响组件 API',hits:flow.summary?.entryToApi||0});
  }
  autopilot.actions=(autopilot.actions||[]).filter((x)=>x.id!=='vulnerability-candidate-hot'&&x.id!=='vulnerable-api-flow');
  const top=(result.candidates||[]).find((x)=>x.priority?.band==='hot')
    ||(result.candidates||[]).find((x)=>x.dataflow?.state==='entry-to-api')
    ||(result.candidates||[]).find((x)=>x.applicability?.state==='affected')
    ||(result.candidates||[]).find((x)=>x.priority?.band==='review');
  if(top){
    const hot=top.priority?.band==='hot';
    const state=top.dataflow?.state||'unknown';
    const flowLabel=state==='entry-to-api'?'ENTRY → API':state==='surface-to-api-nearby'?'ENTRY ≈ API':state==='api-call-only'?'API CALL':'NO API FLOW';
    const firstFlow=top.dataflow?.flows?.[0];
    autopilot.actions.push({
      id:'vulnerable-api-flow',
      priority:hot?100:state==='entry-to-api'?94:top.applicability?.state==='affected'?84:70,
      level:hot?'hot':'normal',
      title:hot?`优先验证攻击路径：${top.primaryId}`:`补齐入口到 API：${top.primaryId}`,
      detail:`${top.component?.name||'component'} ${top.component?.version||'?'} · ${flowLabel} · priority ${top.priority?.score||0}${firstFlow?` · ${firstFlow.file}:${firstFlow.callLine}`:''}。${top.nextAction||''}`
    });
    autopilot.actions.sort((a,b)=>(b.priority||0)-(a.priority||0));
    autopilot.actions=autopilot.actions.slice(0,4);
  }
  autopilot.summary ||= {};
  autopilot.summary.vulnerabilityCandidates=result.summary?.total||0;
  autopilot.summary.vulnerabilityHot=result.summary?.hot||0;
  autopilot.summary.vulnerabilityReview=result.summary?.review||0;
  autopilot.summary.entryToApi=flow.summary?.entryToApi||0;
  autopilot.summary.apiCallOnly=flow.summary?.apiCallOnly||0;
  autopilot.summary.automaticCheckKinds=autopilot.automaticChecks.length;
  autopilot.summary.automaticCheckHits=autopilot.automaticChecks.reduce((sum,item)=>sum+(Number(item.hits)||0),0);
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  analysis.vulnerableApiFlow=await analyzeVulnerableApiFlow(rootPath,analysis,options.apiFlow||{});
  applyApiFlowToCandidates(analysis);
  refreshAutopilot(analysis);
  analysis.recommendations=(analysis.recommendations||[]).filter((x)=>!/^漏洞候选：|^可达性补证：|^攻击路径：|^API 调用补证：/.test(String(x)));
  const s=analysis.vulnerabilityCandidates?.summary||{};
  if(s.hot)analysis.recommendations.unshift(`攻击路径：${s.hot} 个 HOT 已同时确认 affected 与 ENTRY → API 局部传播；优先验证触发约束、补丁差异和运行时可达性。`);
  if(s.withAttackPath&&!s.hot)analysis.recommendations.unshift(`攻击路径：${s.withAttackPath} 个候选观察到 ENTRY → API，但版本适用性或优先级尚不足以升为 HOT。`);
  if(s.surfaceNearby)analysis.recommendations.push(`API 调用补证：${s.surfaceNearby} 个候选仅看到入口与组件调用邻近，尚未确认请求值进入调用参数。`);
  if(s.apiCallOnly)analysis.recommendations.push(`API 调用补证：${s.apiCallOnly} 个候选已有组件调用点，但还没有外部输入传播证据。`);
  if(s.noApiEvidence)analysis.recommendations.push(`API 调用补证：${s.noApiEvidence} 个候选当前停留在 import/unknown；反射、插件、DI 与跨模块调用仍需人工确认。`);
  analysis.version=Math.max(Number(analysis.version)||1,22);
  analysis.batch22Counts={...(analysis.vulnerableApiFlow?.summary||{}),hot:s.hot||0,review:s.review||0,deprioritized:s.deprioritized||0};
  return analysis;
}

function buildBatch22Section(analysis){
  const flow=analysis.vulnerableApiFlow;
  const result=analysis.vulnerabilityCandidates;
  if(!flow||!result)return '';
  const s=flow.summary||{};
  const lines=['## Batch 22 · Entry → Vulnerable API Flow','',`- source files scanned=${s.scannedSourceFiles||0}, entry-to-api=${s.entryToApi||0}, surface-nearby=${s.surfaceNearby||0}, api-call-only=${s.apiCallOnly||0}, import-only=${s.importOnly||0}`,''];
  for(const item of (result.candidates||[]).slice(0,50)){
    const d=item.dataflow||{};
    lines.push(`### ${item.primaryId} · ${item.priority?.band?.toUpperCase()||'REVIEW'} · ${item.priority?.score||0}`,'',`- 组件：${item.component?.ecosystem||'?'}:${item.component?.name||'?'} ${item.component?.version||'?'}`);
    lines.push(`- 数据流证据：${d.state||'unknown'} · ${d.reason||'证据不足'}`);
    if(d.bindings?.length)lines.push(`- 绑定/API 根：${d.bindings.join(', ')}`);
    for(const f of (d.flows||[]).slice(0,4))lines.push(`- ENTRY → API：${f.file}:${f.sourceLine||'?'} → ${f.file}:${f.callLine} · ${f.sourceKind||'?'} · ${f.api||'?'}${f.variable?` · var=${f.variable}`:''}`);
    for(const c of (d.apiCalls||[]).slice(0,4))if(!(d.flows||[]).some((f)=>f.file===c.file&&f.callLine===c.line))lines.push(`- API call：${c.file}:${c.line} · ${c.binding}.${c.api} · ${c.nearSurface?'near surface':'no surface link'}`);
    lines.push(`- Batch21 → Batch22：${item.priority?.batch21Score??item.priority?.score??0} ${Number(item.priority?.dataflowAdjustment||0)>=0?'+':''}${item.priority?.dataflowAdjustment||0} => ${item.priority?.score||0}`,'');
  }
  lines.push('> Batch22 只做有界局部传播：直接输入、路由参数和最多一跳局部变量。它不会把“同文件有路由 + import”伪装成完整攻击链；跨函数、反射、插件、DI、框架自动装配仍需人工确认。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch22Section(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,applyApiFlowToCandidates,refreshAutopilot,buildBatch22Section};
