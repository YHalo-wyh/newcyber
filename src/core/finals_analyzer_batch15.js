const fsp=require('fs/promises');
const path=require('path');
const base=require('./finals_analyzer_batch14');
const { analyzeOcrExtractionTranscript }=require('./ai_ocr_extraction');
const { scanRegulatoryApi }=require('./low_altitude_regulatory');
const { analyzeDatalinkCapture }=require('./uav_datalink');
const { buildInvestigationGraph }=require('./investigation_graph');
const { buildWorkspaceAutopilot }=require('./workspace_autopilot');

const TEXT_EXTENSIONS=new Set(['.txt','.log','.json','.jsonl','.csv','.tsv','.yaml','.yml','.py','.js','.ts','.sh','.bash','.c','.cc','.cpp','.h','.hpp','.md','.cfg','.conf','.ini','.trace','.http']);
const CAPTURE_EXTENSIONS=new Set(['.pcap','.pcapng','.cap']);
const MAX_TEXT=2*1024*1024;
const MAX_CAPTURE=192*1024*1024;

async function readText(root,file) {
  if (!TEXT_EXTENSIONS.has(file.extension)||file.size<=0||file.size>MAX_TEXT) return null;
  const buffer=await fsp.readFile(path.join(root,file.path));
  if (buffer.includes(0)) return null;
  return buffer.toString('utf8');
}

function pushFindings(file,prefix,result) {
  file.findings ||= [];
  const existing=new Set(file.findings.map((x)=>String(x.id||'')));
  for (const finding of result?.findings||[]) {
    const id=`${prefix}:${finding.id}:${file.path}`;
    if (existing.has(id)) continue;
    file.findings.push({...finding,id,file:file.path,count:1});
    existing.add(id);
  }
}

function looksRegulatoryRest(text) {
  const api=/(?:\/api\/|openapi|swagger|request\.|req\.|router\.|@app\.|paths:|authorization|bearer\s|jwt)/i.test(text);
  const domain=/(?:\/flights?\/|\/permits?\/|flight(?:[_ /-]?)(?:permit|plan|approval)|airspace|geofence|drone[_ -]?id|operator[_ -]?id|approve|approval|utm\b|u-space|无人机|空域|飞行许可|审批)/i.test(text);
  return api&&domain;
}

function looksOcrTranscript(text,file) {
  if (!['.csv','.tsv','.json','.jsonl','.txt','.log'].includes(file.extension)) return false;
  const input=/(?:image[_ -]?id|image|file|path|query|input)/i.test(text.slice(0,4000));
  const output=/(?:ocr[_ -]?text|recognized[_ -]?text|char[_ -]?confidences?|word[_ -]?confidences?|bounding[_ -]?boxes?|bboxes|polygons|recognition|ocr)/i.test(text.slice(0,12000));
  return input&&output;
}

function refresh(analysis) {
  const order={high:0,medium:1,low:2,info:3};
  analysis.findings=analysis.files.flatMap((file)=>file.findings||[]).sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||String(a.file||'').localeCompare(String(b.file||''))||(a.line||0)-(b.line||0));
  analysis.stats.findings=analysis.findings.length;
  analysis.investigation=buildInvestigationGraph(analysis);
}

async function enrichBatch15(root,file) {
  let changed=false;
  const text=await readText(root,file);
  if (text) {
    if (!file.metadata?.regulatoryAudit&&looksRegulatoryRest(text)) {
      try {
        const result=scanRegulatoryApi(text);
        file.metadata={...(file.metadata||{}),regulatoryAudit:{...result,endpoints:(result.endpoints||[]).slice(0,120)}};
        pushFindings(file,'regulatory-rest',result);
        changed=true;
      } catch (error) { file.metadata={...(file.metadata||{}),regulatoryRestError:error.message}; }
    }
    if (looksOcrTranscript(text,file)) {
      try {
        const result=analyzeOcrExtractionTranscript(text);
        file.metadata={...(file.metadata||{}),ocrExtractionAudit:{...result,preview:(result.preview||[]).slice(0,80)}};
        pushFindings(file,'ocr-extraction',result);
        changed=true;
      } catch (error) { file.metadata={...(file.metadata||{}),ocrExtractionAuditError:error.message}; }
    }
  }

  if (CAPTURE_EXTENSIONS.has(file.extension)&&file.size>0&&file.size<=MAX_CAPTURE) {
    try {
      const buffer=await fsp.readFile(path.join(root,file.path));
      const datalink=analyzeDatalinkCapture(buffer);
      if ((datalink.flows||[]).length||(datalink.findings||[]).length) {
        file.metadata={...(file.metadata||{}),captureIntelligence:{...(file.metadata?.captureIntelligence||{}),datalink:{
          format:datalink.format,
          flows:(datalink.flows||[]).slice(0,120),
          vendorEvidence:(datalink.vendorEvidence||[]).slice(0,120),
          pairedFlows:(datalink.pairedFlows||[]).slice(0,80),
          findings:datalink.findings||[],
          nextActions:datalink.nextActions||[],
          notes:datalink.notes||[]
        }}};
        pushFindings(file,'datalink',datalink);
        changed=true;
      }
    } catch (error) { file.metadata={...(file.metadata||{}),datalinkAuditError:error.message}; }
  }
  return changed;
}

async function scanWorkspace(rootPath) {
  const analysis=await base.scanWorkspace(rootPath);
  const counts={ocr:0,regulatoryRest:0,datalink:0,proprietaryDatalink:0,h265:0};
  for (const file of analysis.files) {
    try { await enrichBatch15(rootPath,file); }
    catch (error) { file.metadata={...(file.metadata||{}),batch15Error:error.message}; }
    if (file.metadata?.ocrExtractionAudit) counts.ocr+=1;
    if (file.metadata?.regulatoryAudit) counts.regulatoryRest+=1;
    const dl=file.metadata?.captureIntelligence?.datalink;
    if (dl) {
      counts.datalink+=1;
      if (dl.vendorEvidence?.some((x)=>['DJI','Lightbridge','OcuSync'].includes(x.vendor))) counts.proprietaryDatalink+=1;
    }
    if (file.metadata?.captureIntelligence?.video?.sessions?.some((x)=>x.codec==='H265')) counts.h265+=1;
  }
  if (counts.ocr) analysis.recommendations.push(`OCR 模型窃取：${counts.ocr} 个 transcript 已自动检查字符/词级置信度、logit、布局框、重复查询稳定性和字符集覆盖。`);
  if (counts.regulatoryRest) analysis.recommendations.push(`低空监管 REST：${counts.regulatoryRest} 个 API/源码文件已识别飞行许可/审批/对象授权边界，包含 /flight/permit 风格路由。`);
  if (counts.datalink) analysis.recommendations.push(`无人机数据链：${counts.datalink} 个抓包已做被动流量画像；${counts.proprietaryDatalink} 个出现 DJI/Lightbridge/OcuSync 明确指纹。`);
  if (counts.h265) analysis.recommendations.push(`图传：${counts.h265} 个抓包恢复出 H265 RTP 会话，已按 Annex-B artifact 进入后续视频取证。`);
  refresh(analysis);
  analysis.autopilot=buildWorkspaceAutopilot(analysis);
  const first=analysis.autopilot.actions?.[0];
  if (first) analysis.recommendations.unshift(`自动优先级：${first.title}${first.detail?` —— ${first.detail}`:''}`);
  analysis.version=Math.max(Number(analysis.version)||1,15);
  analysis.batch15Counts=counts;
  return analysis;
}

function buildBatch15Section(analysis) {
  const lines=[];
  for (const file of analysis.files||[]) {
    const ocr=file.metadata?.ocrExtractionAudit;
    const dl=file.metadata?.captureIntelligence?.datalink;
    if (ocr) lines.push(`### OCR Extraction：\`${file.path}\``,'',`- queries=${ocr.rows}, charset=${ocr.charsetSize}, char-confidence=${ocr.charConfidenceRows}, boxes=${ocr.boxRows}, exposure=${ocr.extractionExposure}`,'');
    if (dl) lines.push(`### UAV Datalink：\`${file.path}\``,'',`- flows=${dl.flows?.length||0}, vendorEvidence=${dl.vendorEvidence?.length||0}, pairedControlMedia=${dl.pairedFlows?.length||0}`,'');
  }
  return lines.length?['## Batch 15 · OCR / Datalink','',...lines].join('\n'):'';
}

function buildAutopilotSection(analysis) {
  const a=analysis.autopilot;
  if (!a) return '';
  const lines=['## 自动赛题工作流',''];
  if (a.track) lines.push(`- 最可能方向：${a.track.title}（score=${a.track.score}）`);
  lines.push(`- 自动检查：${a.summary?.automaticCheckKinds||0} 类 / ${a.summary?.automaticCheckHits||0} 次命中`);
  lines.push(`- 高危线索：${a.summary?.highFindings||0}`);
  lines.push(`- Flag 候选：${a.summary?.flagCandidates||0}`);
  lines.push(`- 可导出产物：${a.summary?.exportableArtifacts||0}`,'');
  if (a.actions?.length) {
    lines.push('### 最短处理顺序','');
    a.actions.forEach((item,index)=>lines.push(`${index+1}. **${item.title}**${item.detail?` — ${item.detail}`:''}`));
    lines.push('');
  }
  if (a.automaticChecks?.length) {
    lines.push('### 已自动运行/命中的分析器','');
    a.automaticChecks.forEach((item)=>lines.push(`- ${item.title}: ${item.hits}`));
    lines.push('');
  }
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const sections=[buildBatch15Section(analysis),buildAutopilotSection(analysis)].filter(Boolean);
  return sections.length?`${report.trim()}\n\n${sections.join('\n\n')}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,enrichBatch15,buildBatch15Section,buildAutopilotSection};
