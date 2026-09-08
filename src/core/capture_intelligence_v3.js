const base=require('./capture_intelligence_v2');
const { analyzeDatalinkCapture }=require('./uav_datalink');

function analyzeCaptureIntelligence(buffer) {
  const result=base.analyzeCaptureIntelligence(buffer);
  if (result.format==='unknown') return result;
  let datalink=null;
  try { datalink=analyzeDatalinkCapture(buffer); }
  catch (error) { datalink={flows:[],vendorEvidence:[],pairedFlows:[],findings:[],nextActions:[],error:error.message}; }
  const findings=[...(result.findings||[]),...(datalink.findings||[])];
  const highlights=[...(result.highlights||[])];
  const nextActions=[...(result.nextActions||[]),...(datalink.nextActions||[])];
  if (datalink.vendorEvidence?.length) {
    const vendors=[...new Set(datalink.vendorEvidence.map((x)=>x.vendor))];
    highlights.push(`数据链：发现厂商/协议指纹 ${vendors.join(', ')}；已保留 packet/flow 证据。`);
  }
  if (datalink.pairedFlows?.length) highlights.push(`数据链：识别 ${datalink.pairedFlows.length} 组控制/遥测 ↔ 高带宽媒体流候选，可与图传/断链时间线联动。`);
  return {...result,datalink,findings,highlights,nextActions:[...new Set(nextActions)]};
}

function scanEmbeddedCaptures(input,options={}) {
  const buffer=Buffer.isBuffer(input)?input:Buffer.from(input||[]);
  const segments=base.scanEmbeddedCaptures(buffer,options);
  for (const segment of segments) {
    try {
      const data=buffer.subarray(segment.offset,segment.endOffset);
      segment.analysis=analyzeCaptureIntelligence(data);
      segment.videoArtifacts=segment.analysis.video?.artifacts||[];
    } catch (error) { segment.captureIntelligenceV3Error=error.message; }
  }
  return segments;
}

module.exports={...base,analyzeCaptureIntelligence,scanEmbeddedCaptures};
