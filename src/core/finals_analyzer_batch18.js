const base = require('./finals_analyzer_batch17');
const { analyzeWorkspaceTechStack, queryTextFromTechStack } = require('./tech_stack_intelligence');
const { matchPocReferences } = require('./poc_reference_index');

function versionSet(stack) {
  return new Set((stack?.components || []).map((item)=>String(item.version || '').toLowerCase()).filter(Boolean));
}

function annotateReferenceVersions(refs, stack) {
  const versions=versionSet(stack);
  const components=stack?.components || [];
  for (const ref of refs || []) {
    const matchedVersions=(ref.matchedKeywords || []).filter((token)=>versions.has(String(token).toLowerCase()));
    const componentEvidence=[];
    for (const item of components) {
      if (componentEvidence.length>=8) break;
      const name=String(item.name || '').toLowerCase();
      const hits=(ref.matchedKeywords || []).filter((token)=>name.includes(String(token).toLowerCase()) || String(token).toLowerCase().includes(name));
      if (!hits.length && !matchedVersions.includes(item.version)) continue;
      componentEvidence.push({ name:item.name, version:item.version || null, constraint:item.constraint || null, ecosystem:item.ecosystem, sources:(item.sources || [item.source]).filter(Boolean).slice(0,4) });
    }
    ref.versionEvidence={
      state:matchedVersions.length ? 'reference-version-match' : 'not-enough-advisory-data',
      matchedVersions:matchedVersions.slice(0,8),
      components:componentEvidence,
      note:matchedVersions.length
        ? '题目解析出的精确版本也出现在该 PoC 元数据关键词中；这是相关性增强，不等同于“版本受影响”。'
        : 'PoC-in-GitHub 主要提供 PoC 仓库元数据，不包含权威受影响版本区间；当前不据此判定漏洞成立。'
    };
  }
  return refs;
}

function augmentAutopilotTechStack(analysis) {
  const autopilot=analysis.autopilot;
  const stack=analysis.techStack;
  if (!autopilot || !stack?.stats?.components) return;
  autopilot.automaticChecks ||= [];
  if (!autopilot.automaticChecks.some((item)=>item.id==='tech-stack')) autopilot.automaticChecks.push({ id:'tech-stack', title:'技术栈 / 依赖 / 版本识别', hits:stack.stats.components });
  const refs=analysis.pocReferences?.matches || [];
  const correlated=refs.filter((item)=>item.versionEvidence?.state==='reference-version-match');
  if (correlated.length) {
    const top=correlated[0];
    const action={
      id:'version-correlated-poc', priority:78, level:'hot',
      title:`优先核对版本相关参考：${top.cve}`,
      detail:`检测到题目组件精确版本与 PoC 元数据版本线索重合（${top.versionEvidence.matchedVersions.join(', ')}）。继续核对官方 advisory/补丁范围与题目触发条件，不能仅凭版本号直接确认漏洞。`
    };
    autopilot.actions=[...(autopilot.actions || []).filter((item)=>item.id!=='version-correlated-poc'),action]
      .sort((a,b)=>(b.priority||0)-(a.priority||0)).slice(0,4);
  }
  autopilot.summary ||= {};
  autopilot.summary.techComponents=stack.stats.components;
  autopilot.summary.exactVersions=stack.stats.exactVersions;
  autopilot.summary.versionCorrelatedPocs=correlated.length;
  autopilot.summary.automaticCheckKinds=autopilot.automaticChecks.length;
  autopilot.summary.automaticCheckHits=autopilot.automaticChecks.reduce((sum,item)=>sum+(Number(item.hits)||0),0);
}

async function scanWorkspace(rootPath, options={}) {
  const analysis=await base.scanWorkspace(rootPath,options);
  try {
    analysis.techStack=await analyzeWorkspaceTechStack(rootPath,analysis);
  } catch (error) {
    analysis.techStack={ schema:'newcyber.tech-stack.v1', stats:{manifests:0,components:0,exactVersions:0,directDependencies:0,cpeCandidates:0,bannerFilesRead:0}, ecosystems:{}, manifests:[], components:[], runtimes:[], purls:[], cpeCandidates:[], error:error.message };
  }

  const stackText=queryTextFromTechStack(analysis.techStack);
  const previousEvidence=analysis.pocReferences?.queryEvidence || {};
  analysis.pocReferences=matchPocReferences(analysis,options.pocIndex || null,{extraText:stackText,topK:12});
  analysis.pocReferences.queryEvidence={...previousEvidence,techStackComponents:analysis.techStack.stats?.components || 0,exactVersions:analysis.techStack.stats?.exactVersions || 0};
  annotateReferenceVersions(analysis.pocReferences.matches,analysis.techStack);
  if (analysis.pocReferences.matches?.length) base.augmentAutopilot(analysis,analysis.pocReferences.matches);
  augmentAutopilotTechStack(analysis);

  analysis.recommendations ||= [];
  const stats=analysis.techStack.stats || {};
  if (stats.components) {
    const eco=Object.entries(analysis.techStack.ecosystems || {}).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([name,count])=>`${name}:${count}`).join(', ');
    analysis.recommendations.unshift(`技术栈：自动解析 ${stats.manifests} 个依赖/构建文件与 ${stats.bannerFilesRead} 个版本线索文件，识别 ${stats.components} 个组件、${stats.exactVersions} 个精确版本${eco?`（${eco}）`:''}。`);
  }
  const correlated=(analysis.pocReferences.matches || []).filter((item)=>item.versionEvidence?.state==='reference-version-match');
  if (correlated.length) analysis.recommendations.unshift(`版本关联：${correlated.length} 个 PoC 参考同时命中题目精确版本线索；已提高核对优先级，但不会把 PoC 元数据当成官方受影响版本范围。`);
  if (stats.cpeCandidates) analysis.recommendations.push(`标识映射：生成 ${stats.cpeCandidates} 个高置信 CPE candidate 和 ${analysis.techStack.purls?.length || 0} 个 PURL，便于后续接离线 advisory/OSV/NVD 数据库做版本区间判断。`);

  analysis.version=Math.max(Number(analysis.version)||1,18);
  analysis.batch18Counts={
    manifests:stats.manifests || 0,
    components:stats.components || 0,
    exactVersions:stats.exactVersions || 0,
    cpeCandidates:stats.cpeCandidates || 0,
    purls:analysis.techStack.purls?.length || 0,
    versionCorrelatedPocs:correlated.length
  };
  return analysis;
}

function buildBatch18Section(analysis) {
  const stack=analysis.techStack;
  if (!stack) return '';
  const lines=['## Batch 18 · Tech Stack / Version Intelligence','',`- manifests=${stack.stats?.manifests || 0}, components=${stack.stats?.components || 0}, exactVersions=${stack.stats?.exactVersions || 0}, cpeCandidates=${stack.stats?.cpeCandidates || 0}`,''];
  const top=(stack.components || []).filter((item)=>item.direct || item.version).slice(0,60);
  if (top.length) {
    lines.push('### 组件与版本','');
    for (const item of top) {
      const version=item.version || item.constraint || 'unknown';
      const origin=(item.sources || [item.source]).filter(Boolean).slice(0,2).join(', ');
      lines.push(`- ${item.ecosystem}:${item.name} · ${version}${origin?` · ${origin}`:''}${item.purl?` · ${item.purl}`:''}`);
    }
    lines.push('');
  }
  if (stack.cpeCandidates?.length) {
    lines.push('### CPE candidates（仅高置信映射）','');
    for (const item of stack.cpeCandidates.slice(0,30)) lines.push(`- ${item.name} ${item.version} → ${item.uri}`);
    lines.push('');
  }
  const refs=(analysis.pocReferences?.matches || []).filter((item)=>item.versionEvidence?.state==='reference-version-match');
  if (refs.length) {
    lines.push('### 版本相关 PoC 参考','');
    for (const item of refs.slice(0,12)) lines.push(`- ${item.cve} · score=${item.score} · versions=${item.versionEvidence.matchedVersions.join(', ')} · 仅表示元数据相关，需再核对官方 affected range`);
    lines.push('');
  }
  lines.push('> 当前版本关联不会因为“版本号看起来相近”就判定漏洞成立。PoC-in-GitHub 不提供权威 affected/fixed version range；后续可接离线 advisory 数据源完成版本区间判定。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch18Section(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,annotateReferenceVersions,augmentAutopilotTechStack,buildBatch18Section};
