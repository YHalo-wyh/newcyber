const fsp=require('fs/promises');
const path=require('path');
const base=require('./finals_analyzer_batch13');
const { analyzeModelExtractionTranscript }=require('./ai_model_extraction');
const { analyzeModelInversion }=require('./ai_model_inversion');
const { scanRegulatoryApi }=require('./low_altitude_regulatory');
const { analyzeGnssLog }=require('./gnss_audit');
const { analyzeGnssSpectrum }=require('./gnss_sdr');
const { auditFirmwareUpdate }=require('./firmware_update_audit');
const { buildInvestigationGraph }=require('./investigation_graph');

const TEXT_EXTENSIONS=new Set(['.txt','.log','.json','.jsonl','.csv','.tsv','.yaml','.yml','.py','.js','.ts','.sh','.bash','.c','.cc','.cpp','.h','.hpp','.md','.cfg','.conf','.ini','.nmea','.gps','.trace','.http']);
const MAX_TEXT=2*1024*1024;

async function readText(full) {
  const stat=await fsp.stat(full);
  if (!stat.isFile()||stat.size<=0||stat.size>MAX_TEXT) return null;
  const buffer=await fsp.readFile(full);
  if (buffer.includes(0)) return null;
  return buffer.toString('utf8');
}

function pushFindings(file,prefix,result) {
  file.findings ||= [];
  const existing=new Set(file.findings.map((x)=>String(x.id||'')));
  for (const finding of result?.findings||[]) {
    const id=`${prefix}:${finding.id}:${file.path}`;
    if (existing.has(id)) continue;
    file.findings.push({ ...finding,id,file:file.path,count:1 });
    existing.add(id);
  }
}

function looksGnss(text,file) {
  if (['.nmea','.gps'].includes(file.extension)) return true;
  return (text.match(/^\$[A-Z]{2}(?:GGA|RMC|GSV|GSA),/gm)||[]).length>=2;
}

function looksSpectrum(text,file) {
  if (!['.csv','.tsv','.txt','.log','.json'].includes(file.extension)) return false;
  const header=/(?:frequency|freq)(?:_hz)?[^\r\n]{0,80}(?:power|dbm|power_db|level)/i.test(text.slice(0,1200));
  const gnssFreq=/(?:1176\d{3,}|1227\d{3,}|1561\d{3,}|1575\d{3,}|1602\d{3,})/.test(text.slice(0,200000));
  return header&&gnssFreq;
}

function looksRegulatory(text,file) {
  const api=/(?:\/api\/|openapi|swagger|request\.|req\.|router\.|@app\.|paths:|authorization|bearer\s|jwt)/i.test(text);
  const lowalt=/(?:\/flights?\/|\/permits?\/|flight(?:[_ /-]?)(?:permit|plan|approval)|(?:permit|approval)(?:[_ /-]?)flight|airspace|geofence|drone[_ -]?id|operator[_ -]?id|approve|approval|utm\b|u-space|无人机|空域|飞行许可|审批)/i.test(text);
  return api&&lowalt;
}

function looksUpdate(text,file) {
  const update=/(?:firmware|upgrade|sysupgrade|ota|fw_update|image_check|verify_signature|mtd\s+write|flashcp|nandwrite|anti[_ -]?rollback)/i.test(text);
  const execution=/(?:curl|wget|download|manifest|sha256|signature|mtd|flash|sysupgrade|reboot|bootloader|partition)/i.test(text);
  return update&&execution;
}

function looksExtraction(text,file) {
  if (!['.csv','.tsv','.json','.jsonl','.txt','.log'].includes(file.extension)) return false;
  const query=/(?:^|[,\t"'{])(?:query|input|sample|request|prompt)(?:[,\t"'}:]|$)/im.test(text);
  const output=/(?:probabilities|probs|logits|scores|prediction|predicted_label|confidence)/i.test(text);
  return query&&output;
}

function looksInversion(text,file) {
  if (!['.csv','.tsv','.json','.jsonl','.txt','.log'].includes(file.extension)) return false;
  return /(?:reconstructed|reconstruction|inverted|embedding|hidden_state|gradient|gradients)/i.test(text)
    && /(?:probabilities|logits|reference|original|target|embedding|gradient)/i.test(text);
}

async function enrichExamDirections(rootPath,file) {
  if (!TEXT_EXTENSIONS.has(file.extension)) return false;
  const text=await readText(path.join(rootPath,file.path));
  if (!text) return false;
  let changed=false;
  const metadata={...(file.metadata||{})};

  if (looksGnss(text,file)) {
    try {
      const result=analyzeGnssLog(text);
      if (result.records) {
        metadata.gnssAudit={ ...result, points:(result.points||[]).slice(0,800), jumps:(result.jumps||[]).slice(0,120), timeRollbacks:(result.timeRollbacks||[]).slice(0,120), speedMismatches:(result.speedMismatches||[]).slice(0,120) };
        pushFindings(file,'gnss',result); changed=true;
      }
    } catch (error) { metadata.gnssAuditError=error.message; }
  }

  if (looksSpectrum(text,file)) {
    try {
      const result=analyzeGnssSpectrum(text);
      metadata.gnssSpectrumAudit={ ...result, bands:(result.bands||[]).slice(0,20) };
      pushFindings(file,'gnss-spectrum',result); changed=true;
    } catch (error) { metadata.gnssSpectrumAuditError=error.message; }
  }

  if (looksRegulatory(text,file)) {
    try {
      const result=scanRegulatoryApi(text);
      metadata.regulatoryAudit={ ...result, endpoints:(result.endpoints||[]).slice(0,120) };
      pushFindings(file,'regulatory',result); changed=true;
    } catch (error) { metadata.regulatoryAuditError=error.message; }
  }

  if (looksUpdate(text,file)) {
    try {
      const result=auditFirmwareUpdate(text);
      metadata.firmwareUpdateAudit=result;
      pushFindings(file,'firmware-update',result); changed=true;
    } catch (error) { metadata.firmwareUpdateAuditError=error.message; }
  }

  if (looksExtraction(text,file)) {
    try {
      const result=analyzeModelExtractionTranscript(text);
      metadata.modelExtractionAudit={ ...result, transcriptPreview:(result.transcriptPreview||[]).slice(0,60) };
      pushFindings(file,'model-extraction',result); changed=true;
    } catch (error) { metadata.modelExtractionAuditError=error.message; }
  }

  if (looksInversion(text,file)) {
    try {
      const result=analyzeModelInversion(text);
      metadata.modelInversionAudit={ ...result, reconstructions:(result.reconstructions||[]).slice(0,120) };
      pushFindings(file,'model-inversion',result); changed=true;
    } catch (error) { metadata.modelInversionAuditError=error.message; }
  }

  if (changed) file.metadata=metadata;
  return changed;
}

function refresh(analysis) {
  const order={high:0,medium:1,low:2,info:3};
  analysis.findings=analysis.files.flatMap((file)=>file.findings||[]).sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||String(a.file||'').localeCompare(String(b.file||''))||(a.line||0)-(b.line||0));
  analysis.stats.findings=analysis.findings.length;
  analysis.investigation=buildInvestigationGraph(analysis);
}

async function scanWorkspace(rootPath) {
  const analysis=await base.scanWorkspace(rootPath);
  const counts={gnss:0,gnssSpectrum:0,regulatory:0,update:0,extraction:0,inversion:0};
  for (const file of analysis.files) {
    try {
      if (!(await enrichExamDirections(rootPath,file))) continue;
      if (file.metadata?.gnssAudit) counts.gnss+=1;
      if (file.metadata?.gnssSpectrumAudit) counts.gnssSpectrum+=1;
      if (file.metadata?.regulatoryAudit) counts.regulatory+=1;
      if (file.metadata?.firmwareUpdateAudit) counts.update+=1;
      if (file.metadata?.modelExtractionAudit) counts.extraction+=1;
      if (file.metadata?.modelInversionAudit) counts.inversion+=1;
    } catch (error) { file.metadata={...(file.metadata||{}),examDirectionError:error.message}; }
  }
  if (counts.gnss) analysis.recommendations.push(`GNSS：${counts.gnss} 个 NMEA/GPS 证据文件已自动检查 checksum、时间轴、物理位置速度和卫星状态。`);
  if (counts.gnssSpectrum) analysis.recommendations.push(`GNSS SDR：${counts.gnssSpectrum} 个 FFT/功率谱已检查 L1/L2/L5/B1/GLONASS L1 的窄带峰与宽带噪声抬升。`);
  if (counts.regulatory) analysis.recommendations.push(`低空监管：${counts.regulatory} 个 API/源码文件已进入许可/空域/对象授权/重放/审批状态机审计。`);
  if (counts.update) analysis.recommendations.push(`固件升级：${counts.update} 个脚本/源码已自动恢复 download→verify→extract→flash→rollback 信任链。`);
  if (counts.extraction) analysis.recommendations.push(`模型窃取：${counts.extraction} 个 query transcript 已检查 soft-label/logit 暴露、重复查询稳定性和类别覆盖。`);
  if (counts.inversion) analysis.recommendations.push(`模型反演：${counts.inversion} 个输出/重建 transcript 已检查 probability/logit/embedding/gradient 暴露与 reconstruction 指标。`);
  refresh(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,14);
  analysis.examDirectionCounts=counts;
  return analysis;
}

function buildExamDirectionSection(analysis) {
  const lines=[];
  for (const file of analysis.files||[]) {
    const m=file.metadata||{};
    if (m.gnssAudit) lines.push(`### GNSS：\`${file.path}\``,'',`- records=${m.gnssAudit.records}, jumps=${m.gnssAudit.jumps?.length||0}, checksumFailed=${m.gnssAudit.checksumFailed||0}`,'');
    if (m.gnssSpectrumAudit) lines.push(`### GNSS SDR Spectrum：\`${file.path}\``,'',`- samples=${m.gnssSpectrumAudit.samples}, bands=${m.gnssSpectrumAudit.bands?.length||0}, findings=${m.gnssSpectrumAudit.findings?.length||0}`,'');
    if (m.regulatoryAudit) lines.push(`### Low-altitude Regulatory API：\`${file.path}\``,'',`- high=${m.regulatoryAudit.summary?.high||0}, medium=${m.regulatoryAudit.summary?.medium||0}, endpoints=${m.regulatoryAudit.endpoints?.length||0}`,'');
    if (m.firmwareUpdateAudit) lines.push(`### Firmware Update Trust Chain：\`${file.path}\``,'',`- stages=${Object.entries(m.firmwareUpdateAudit.stages||{}).filter(([,v])=>v).map(([k])=>k).join(' → ')||'unknown'}`,`- high=${m.firmwareUpdateAudit.summary?.high||0}, medium=${m.firmwareUpdateAudit.summary?.medium||0}`,'');
    if (m.modelExtractionAudit) lines.push(`### Model Extraction：\`${file.path}\``,'',`- queries=${m.modelExtractionAudit.rows}, unique=${m.modelExtractionAudit.uniqueQueries}, classes=${m.modelExtractionAudit.classCount}, exposure=${m.modelExtractionAudit.extractionExposure}`,'');
    if (m.modelInversionAudit) lines.push(`### Model Inversion：\`${file.path}\``,'',`- rows=${m.modelInversionAudit.rows}, reconstructionPairs=${m.modelInversionAudit.reconstructionPairs}, exposure=${m.modelInversionAudit.privacyExposure}`,'');
  }
  return lines.length?['## Official Exam-Direction Evidence','',...lines].join('\n'):'';
}

function buildMarkdownReport(analysis,notes='') {
  const report=base.buildMarkdownReport(analysis,notes);
  const section=buildExamDirectionSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={ ...base,scanWorkspace,buildMarkdownReport,enrichExamDirections,buildExamDirectionSection };
