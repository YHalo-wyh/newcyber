const base=require('./finals_analyzer_batch18');
const {matchAdvisoriesForTechStack}=require('./offline_advisory_index');

function cveSet(item) {
  return new Set([item?.cve,...(item?.cves||[]),...(item?.aliases||[])]
    .filter((x)=>/^CVE-\d{4}-\d{4,7}$/i.test(String(x||'')))
    .map((x)=>String(x).toUpperCase()));
}

function annotatePocApplicability(analysis) {
  const refs=analysis.pocReferences?.matches||[];
  const advisoryMatches=analysis.advisories?.matches||[];
  for (const ref of refs) {
    const refCves=cveSet(ref);
    const related=advisoryMatches.filter((item)=>item.cves?.some((cve)=>refCves.has(String(cve).toUpperCase())));
    const affected=related.filter((item)=>item.applicability?.state==='affected');
    const notAffected=related.filter((item)=>item.applicability?.state==='not-affected');
    const unknown=related.filter((item)=>item.applicability?.state==='unknown');
    let state='no-advisory-match';
    if (affected.length) state='affected';
    else if (notAffected.length&&!unknown.length) state='not-affected';
    else if (related.length) state='unknown';
    ref.advisoryApplicability={
      state,
      affected:affected.length,
      notAffected:notAffected.length,
      unknown:unknown.length,
      advisories:related.slice(0,8).map((item)=>({id:item.advisoryId,cves:item.cves,state:item.applicability.state,reason:item.applicability.reason,component:item.component}))
    };
    ref.originalScore=Number(ref.score)||0;
    if (state==='affected') ref.score=ref.originalScore+180;
    else if (state==='not-affected') ref.score=Math.max(0,ref.originalScore-90);
  }
  refs.sort((a,b)=>(b.score||0)-(a.score||0)||(b.referenceCount||0)-(a.referenceCount||0)||String(a.cve||'').localeCompare(String(b.cve||'')));
  return refs;
}

function augmentAutopilotAdvisories(analysis) {
  const autopilot=analysis.autopilot;
  const result=analysis.advisories;
  if (!autopilot||!result) return;
  autopilot.automaticChecks ||= [];
  if (result.indexAvailable&&!autopilot.automaticChecks.some((x)=>x.id==='offline-advisory')) {
    autopilot.automaticChecks.push({id:'offline-advisory',title:'离线 Advisory 版本适用性',hits:result.matches?.length||0});
  }
  const affected=(result.matches||[]).filter((x)=>x.applicability?.state==='affected');
  const clean=(result.matches||[]).filter((x)=>x.applicability?.state==='not-affected');
  if (affected.length) {
    const top=affected[0];
    const cve=top.cves?.[0]||top.advisoryId;
    const action={
      id:'offline-advisory-affected',priority:96,level:'hot',
      title:`版本命中 Advisory：${cve}`,
      detail:`${top.component.name} ${top.component.version} 被本地 advisory 的明确 affected version/range 覆盖。优先核对题目触发面、补丁差异与对应 PoC 参考；这是静态版本适用性证据，不自动向目标发起验证。`
    };
    autopilot.actions=[...(autopilot.actions||[]).filter((x)=>x.id!=='offline-advisory-affected'),action]
      .sort((a,b)=>(b.priority||0)-(a.priority||0)).slice(0,4);
  } else if (result.indexAvailable&&clean.length) {
    const allCorrelated=(analysis.pocReferences?.matches||[]).filter((x)=>x.versionEvidence?.state==='reference-version-match');
    const allRuledOut=allCorrelated.length&&allCorrelated.every((x)=>x.advisoryApplicability?.state==='not-affected');
    if (allRuledOut) autopilot.actions=(autopilot.actions||[]).filter((x)=>x.id!=='version-correlated-poc');
  }
  autopilot.summary ||= {};
  autopilot.summary.advisoryAffected=affected.length;
  autopilot.summary.advisoryNotAffected=clean.length;
  autopilot.summary.advisoryUnknown=result.summary?.unknown||0;
  autopilot.summary.automaticCheckKinds=autopilot.automaticChecks.length;
  autopilot.summary.automaticCheckHits=autopilot.automaticChecks.reduce((sum,item)=>sum+(Number(item.hits)||0),0);
}

async function scanWorkspace(rootPath,options={}) {
  const analysis=await base.scanWorkspace(rootPath,options);
  analysis.advisories=matchAdvisoriesForTechStack(analysis.techStack,options.advisoryIndex||null,{topK:120});
  annotatePocApplicability(analysis);
  augmentAutopilotAdvisories(analysis);
  analysis.recommendations ||= [];
  if (!analysis.advisories.indexAvailable) {
    analysis.recommendations.push('离线 Advisory 索引尚未导入：导入 OSV-compatible JSON 目录后，可按 package + 精确版本/range 自动判断 affected / not-affected / unknown。');
  } else {
    const s=analysis.advisories.summary||{};
    if (s.affected) analysis.recommendations.unshift(`漏洞适用性：本地 advisory 发现 ${s.affected} 个“当前精确版本落入 affected range”的匹配，已提升到 Autopilot 高优先级。`);
    if (s.notAffected) analysis.recommendations.push(`版本排除：${s.notAffected} 个 advisory 对当前精确版本给出明确 not-affected-by-range 结果，相关 PoC 仅保留为低优先参考。`);
    if (s.unknown) analysis.recommendations.push(`版本未知：${s.unknown} 个 advisory 因版本格式或 range 数据不足保持 unknown，不做“安全”推断。`);
  }
  analysis.version=Math.max(Number(analysis.version)||1,19);
  analysis.batch19Counts={
    advisoryIndexAvailable:analysis.advisories.indexAvailable,
    advisoryMatches:analysis.advisories.matches?.length||0,
    affected:analysis.advisories.summary?.affected||0,
    notAffected:analysis.advisories.summary?.notAffected||0,
    unknown:analysis.advisories.summary?.unknown||0,
    pocAffected:(analysis.pocReferences?.matches||[]).filter((x)=>x.advisoryApplicability?.state==='affected').length,
    pocRuledOut:(analysis.pocReferences?.matches||[]).filter((x)=>x.advisoryApplicability?.state==='not-affected').length
  };
  return analysis;
}

function buildBatch19Section(analysis) {
  const r=analysis.advisories; if (!r) return '';
  const s=r.summary||{};
  const lines=['## Batch 19 · Offline Advisory Applicability','',`- index=${r.indexAvailable?'loaded':'not-loaded'}, matches=${r.matches?.length||0}, affected=${s.affected||0}, notAffected=${s.notAffected||0}, unknown=${s.unknown||0}`,'',r.note||'',''];
  for (const item of (r.matches||[]).slice(0,60)) {
    const cve=item.cves?.join(', ')||item.advisoryId;
    lines.push(`### ${cve} · ${item.applicability.state}`,'',`- 组件：${item.component.ecosystem}:${item.component.name} ${item.component.version}`);
    if (item.component.purl) lines.push(`- PURL：${item.component.purl}`);
    lines.push(`- 依据：${item.applicability.reason}`);
    if (item.applicability.interval) lines.push(`- range：${JSON.stringify(item.applicability.interval)}`);
    if (item.applicability.fixedVersions?.length) lines.push(`- fixed boundary：${item.applicability.fixedVersions.join(', ')}`);
    if (item.summary) lines.push(`- advisory：${item.summary}`);
    lines.push('');
  }
  lines.push('> `not-affected` 只表示当前精确版本未落入本地 advisory 提供的可比较 affected range；`unknown` 不代表安全。NewCyber 不自动执行 PoC，也不会向远程目标发送验证请求。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch19Section(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,annotatePocApplicability,augmentAutopilotAdvisories,buildBatch19Section};
