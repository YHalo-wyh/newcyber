'use strict';

const base=require('./finals_analyzer_batch91');

function list(value){return Array.isArray(value)?value:[];}
function finite(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function fixed(value,digits=6){const n=finite(value);return n===null?'—':n.toFixed(digits);}
function activeScaResult(analysis={}){
  const wrapper=analysis.scaAutopilot;
  if(wrapper?.result&&typeof wrapper.result==='object')return wrapper.result;
  if(wrapper&&typeof wrapper==='object'&&wrapper.diagnostics?.scaQuality)return wrapper;
  return null;
}
function anomalySummary(groups){
  const rows=list(groups?.anomalousGroups).slice(0,12);
  if(!rows.length)return 'none';
  return rows.map((item)=>`g${item.group}: r2=${fixed(item.r2)} gap=${fixed(item.gapToThreshold)}`).join(' · ');
}
function contextualFailureSummary(contextual){
  const rows=list(contextual?.positions).filter((item)=>item?.passes===false).slice(0,16);
  if(!rows.length)return 'none';
  return rows.map((item)=>`#${item.index}: cos=${fixed(item.cosine)} gap=${fixed(item.gapToThreshold)}`).join(' · ');
}
function buildScaQualitySection(analysis={}){
  const result=activeScaResult(analysis);const quality=result?.diagnostics?.scaQuality;if(!quality)return'';
  const guard=quality.guardBaseline||{};const groups=quality.leakageGroups||{};const calibration=quality.probeCalibration||{};const contextual=quality.contextual||{};
  const lines=['## Batch93 · Power SCA Quality Diagnostics',''];
  lines.push(`- policy: observationalOnly=${Boolean(quality.observationalOnly)} · mayUpgradeResult=${Boolean(quality.policy?.mayUpgradeResult)} · leakageR2Threshold=${fixed(quality.policy?.leakageR2Threshold,3)} · contextualCosineThreshold=${fixed(quality.policy?.contextualCosineThreshold,3)}`);
  lines.push(`- guard baseline: ${guard.enabled?'PROVEN':'NOT PROVEN'}${guard.enabled?` · mode=${guard.mode||'unknown'} · leading=${guard.leading??'—'} · trailing=${guard.trailing??'—'} · subtract=${guard.subtract||'—'}`:''}`);
  lines.push(`- leakage groups: total=${Number(groups.totalGroups)||0} · finite=${Number(groups.count)||0} · invalid=${Number(groups.invalidGroups)||0} · minR2=${fixed(groups.minR2)} · meanR2=${fixed(groups.meanR2)} · maxR2=${fixed(groups.maxR2)} · anomalies=${list(groups.anomalousGroups).length}`);
  if(list(groups.anomalousGroups).length)lines.push(`- low-R² groups: ${anomalySummary(groups)}`);
  lines.push(`- probe calibration: status=${calibration.status||'unavailable'} · accepted=${Boolean(calibration.accepted)} · mode=${calibration.mode||'—'} · gain=${fixed(calibration.cosineGain)} · rawCos=${fixed(calibration.evaluation?.rawCosine)} · calibratedCos=${fixed(calibration.evaluation?.calibratedCosine)} · rows=${calibration.trainingRows??'—'}/${calibration.validationRows??'—'}`);
  lines.push(`- contextual hidden: count=${Number(contextual.count)||0} · passed=${Number(contextual.passed)||0} · failed=${Number(contextual.failed)||0} · minCos=${fixed(contextual.minCosine)} · meanCos=${fixed(contextual.meanCosine)} · oracleThreshold=${fixed(contextual.oracleThreshold,3)} · thresholdDrift=${fixed(contextual.thresholdDrift)}`);
  if(Number(contextual.failed)>0)lines.push(`- contextual failures: ${contextualFailureSummary(contextual)}`);
  lines.push('','> 本节仅用于定位 SCA 恢复质量问题。它不会把 candidate / GAP 提升为 verified / solved；最终状态仍由原有 quality gate、contextual hidden verifier 与题目 verifier 决定。');
  return lines.join('\n');
}
async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);analysis.version=Math.max(Number(analysis.version)||1,93);return analysis;
}
function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=buildScaQualitySection(analysis);return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildScaQualitySection,activeScaResult,anomalySummary,contextualFailureSummary};
