const fsp=require('fs/promises');
const path=require('path');
const base=require('./finals_analyzer_batch8');
const { auditAiSupplyChain }=require('./ai_supply_chain');
const { analyzeDatasetSecurity }=require('./ai_dataset_security');

const SOURCE_EXTENSIONS=new Set(['.py','.js','.ts','.tsx','.jsx','.toml','.txt','.cfg','.conf','.ini','.yaml','.yml','.md']);
const DATA_EXTENSIONS=new Set(['.csv','.tsv']);
const MAX_TEXT=3*1024*1024;

function looksLikeAiSupplyText(text) {
  return /(?:from_pretrained|trust_remote_code|torch\.load|pickle\.load|joblib\.load|requirements|extra-index-url|pip\s+install|torch\.hub\.load|PeftModel|SentenceTransformer)/i.test(text);
}

function looksLikeLabeledDataset(text) {
  const first=String(text||'').split(/\r?\n/,1)[0]||'';
  return /(?:^|[,;\t])\s*(?:label|target|class|category|output)\s*(?:[,;\t]|$)/i.test(first);
}

async function enrichBatch9(rootPath,file) {
  const full=path.join(rootPath,file.path);
  if (file.size<=0 || file.size>MAX_TEXT) return false;
  const ext=file.extension;
  if (!SOURCE_EXTENSIONS.has(ext) && !DATA_EXTENSIONS.has(ext)) return false;
  const buffer=await fsp.readFile(full);
  if (buffer.includes(0)) return false;
  const text=buffer.toString('utf8');
  let changed=false;

  if (SOURCE_EXTENSIONS.has(ext) && looksLikeAiSupplyText(text)) {
    const supply=auditAiSupplyChain(text);
    if (supply.findings.length) {
      file.metadata={...(file.metadata||{}),aiSupplyChain:supply};
      file.findings||=[];
      for (const finding of supply.findings) file.findings.push({
        ...finding,
        id:`${finding.id}:${file.path}:${finding.line||0}`,
        originalId:finding.id,
        file:file.path,
        count:1
      });
      changed=true;
    }
  }

  if (DATA_EXTENSIONS.has(ext) && looksLikeLabeledDataset(text)) {
    try {
      const dataset=analyzeDatasetSecurity(text);
      file.metadata={...(file.metadata||{}),aiDatasetSecurity:{
        rows:dataset.rows,
        columns:dataset.columns,
        labelColumn:dataset.labelColumn,
        labelCounts:dataset.labelCounts,
        duplicateGroups:dataset.duplicateGroups.slice(0,40),
        conflictingLabels:dataset.conflictingLabels.slice(0,40),
        rareLabels:dataset.rareLabels.slice(0,40),
        triggerCandidates:dataset.triggerCandidates.slice(0,40),
        findings:dataset.findings,
        notes:dataset.notes
      }};
      file.findings||=[];
      for (const finding of dataset.findings) file.findings.push({ ...finding,id:`${finding.id}:${file.path}`,file:file.path,title:finding.id==='dataset-trigger-candidate'?'数据投毒 / 后门候选':'AI 数据集完整性证据',count:1 });
      changed=true;
    } catch (error) {
      file.metadata={...(file.metadata||{}),aiDatasetSecurityError:error.message};
    }
  }
  return changed;
}

function refresh(analysis) {
  const order={high:0,medium:1,low:2,info:3};
  analysis.findings=analysis.files.flatMap((f)=>f.findings||[]).sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||String(a.file||'').localeCompare(String(b.file||''))||(a.line||0)-(b.line||0));
  analysis.stats.findings=analysis.findings.length;
}

async function scanWorkspace(rootPath) {
  const analysis=await base.scanWorkspace(rootPath);
  let supplyFiles=0; let datasetFiles=0;
  for (const file of analysis.files) {
    try {
      const beforeSupply=Boolean(file.metadata?.aiSupplyChain);
      const beforeDataset=Boolean(file.metadata?.aiDatasetSecurity);
      if (await enrichBatch9(rootPath,file)) {
        if (!beforeSupply && file.metadata?.aiSupplyChain) supplyFiles++;
        if (!beforeDataset && file.metadata?.aiDatasetSecurity) datasetFiles++;
      }
    } catch (error) { file.metadata={...(file.metadata||{}),aiBatch9Error:error.message}; }
  }
  if (supplyFiles) analysis.recommendations.push(`AI 供应链：${supplyFiles} 个文件存在模型/依赖加载边界；先确认 artifact/source/revision 是否可被攻击者影响，再按 finding 的 fix/regression 验证。`);
  if (datasetFiles) analysis.recommendations.push(`AI 数据安全：${datasetFiles} 个带标签数据集已做重复、冲突标签与 trigger 共现筛选；优先复核高 lift 候选和相同特征不同标签。`);
  refresh(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,10);
  return analysis;
}

function buildBatch9Section(analysis) {
  const lines=[];
  for (const file of analysis.files||[]) {
    const supply=file.metadata?.aiSupplyChain;
    const dataset=file.metadata?.aiDatasetSecurity;
    if (supply) {
      lines.push(`### AI 供应链：\`${file.path}\``,'',`- high=${supply.summary?.high||0}, medium=${supply.summary?.medium||0}, info=${supply.summary?.info||0}`);
      for (const finding of (supply.findings||[]).slice(0,20)) {
        lines.push(`- **${finding.severity}** ${finding.title}（line ${finding.line||'?'}）`);
        if (finding.fix?.action) lines.push(`  - 修复：${finding.fix.action}`);
        if (finding.fix?.regression) lines.push(`  - 回归：${finding.fix.regression}`);
      }
      lines.push('');
    }
    if (dataset) {
      lines.push(`### AI 数据集：\`${file.path}\``,'',`- rows=${dataset.rows}, label=${dataset.labelColumn||'unknown'}, conflicts=${dataset.conflictingLabels?.length||0}, triggerCandidates=${dataset.triggerCandidates?.length||0}`);
      for (const item of (dataset.triggerCandidates||[]).slice(0,12)) lines.push(`- trigger candidate: ${item.column}=${item.token} → ${item.targetLabel}, support=${item.support}, confidence=${item.confidence.toFixed(3)}, lift=${item.lift.toFixed(2)}`);
      lines.push('');
    }
  }
  return lines.length ? ['## AI 数据 / 供应链证据','',...lines].join('\n') : '';
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildBatch9Section(analysis);
  return section ? `${report.trim()}\n\n${section}\n` : report;
}

module.exports={ ...base, scanWorkspace, buildMarkdownReport, enrichBatch9, buildBatch9Section };
