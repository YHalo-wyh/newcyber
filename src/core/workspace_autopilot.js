const TRACKS=Object.freeze({
  vehicle:{title:'车联网安全',tool:'can-analyze'},
  lowalt:{title:'低空经济安全',tool:'mavlink-hex'},
  ai:{title:'人工智能安全',tool:'ai-source-scan'},
  web3:{title:'区块链安全',tool:'evm-disasm'}
});

const SEVERITY_SCORE=Object.freeze({high:40,medium:16,low:5,info:1});

function categoryTrack(name='') {
  const value=String(name).toLowerCase();
  if (/车联网|vehicle|can|uds/.test(value)) return 'vehicle';
  if (/低空|uav|drone|mavlink|gnss/.test(value)) return 'lowalt';
  if (/人工智能|ai\s*\/\s*ml|machine learning|\bai\b/.test(value)) return 'ai';
  if (/区块链|blockchain|web3|evm|solidity/.test(value)) return 'web3';
  return null;
}

function add(scores,key,value) {
  if (key&&Number.isFinite(value)) scores[key]+=value;
}

function scoreTracks(analysis={}) {
  const scores={vehicle:0,lowalt:0,ai:0,web3:0};
  for (const item of analysis.categories||[]) add(scores,categoryTrack(item.name),Number(item.score)||0);
  for (const file of analysis.files||[]) {
    const m=file.metadata||{};
    const p=String(file.path||'').toLowerCase();
    if (m.pcapng?.can||m.captureIntelligence?.can?.parsedFrames||m.udsProgramming) scores.vehicle+=14;
    if (/\.(?:asc|blf|candump)$/.test(p)||/(?:can|uds|isotp|ecu)/.test(p)) scores.vehicle+=4;

    if (m.lowAltitude||m.mavlink||m.regulatoryAudit||m.gnssAudit||m.gnssSpectrumAudit||m.firmwareUpdateAudit||m.captureIntelligence?.video||m.captureIntelligence?.datalink) scores.lowalt+=14;
    if (/\.(?:tlog|ulg|pcap|pcapng|cap)$/.test(p)||/(?:mavlink|ardupilot|px4|uav|drone|gnss|gps)/.test(p)) scores.lowalt+=4;

    if (m.aiAudit||m.aiTabular||m.model||m.modelAudit||m.ocrExtractionAudit||m.aiSkillMatrix||m.modelExtractionAudit||m.modelInversionAudit||m.datasetSecurity) scores.ai+=14;
    if (/\.(?:pt|pth|pkl|pickle|joblib|safetensors|npy|onnx|gguf|csv|tsv)$/.test(p)||/(?:model|checkpoint|prompt|rag|ocr)/.test(p)) scores.ai+=4;

    if (m.web3Audit||m.solanaAudit||m.evmAudit||m.contractAudit) scores.web3+=14;
    if (/\.(?:sol|vy)$/.test(p)||/(?:evm|solidity|web3|contract|abi)/.test(p)) scores.web3+=4;

    if (m.recursiveArtifacts?.nodes?.some((node)=>node.capture)) scores.lowalt+=5;
  }
  return Object.entries(scores).map(([id,score])=>({id,title:TRACKS[id].title,tool:TRACKS[id].tool,score})).sort((a,b)=>b.score-a.score);
}

function normalizeFlag(flag,file) {
  if (typeof flag==='string') return {value:flag,file};
  if (flag&&typeof flag==='object') return {value:String(flag.value||flag.flag||''),file:flag.file||file};
  return {value:'',file};
}

function collectFlags(analysis={}) {
  const seen=new Set();
  const out=[];
  for (const file of analysis.files||[]) {
    for (const raw of file.flags||[]) {
      const item=normalizeFlag(raw,file.path);
      if (!item.value||seen.has(item.value)) continue;
      seen.add(item.value); out.push(item);
    }
  }
  for (const raw of analysis.candidates?.flags||[]) {
    const item=normalizeFlag(raw,raw?.file||'workspace');
    if (!item.value||seen.has(item.value)) continue;
    seen.add(item.value); out.push(item);
  }
  return out.slice(0,20);
}

function topFindings(analysis={}) {
  const seen=new Set();
  return [...(analysis.findings||[])].sort((a,b)=>(SEVERITY_SCORE[b.severity]||0)-(SEVERITY_SCORE[a.severity]||0)).filter((item)=>{
    const key=`${item.id||item.title||''}:${item.file||''}:${item.evidence||''}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  }).slice(0,12);
}

function pushArtifact(out,seen,file,kind,artifact,next='') {
  if (!artifact) return;
  const key=artifact.sha256||`${file}:${artifact.name||kind}:${artifact.size||0}`;
  if (seen.has(key)) return;
  seen.add(key);
  out.push({file,kind,name:artifact.name||kind,size:artifact.size||0,completeness:artifact.completeness||'unknown',artifact,next});
}

function recursiveArtifactKind(artifact) {
  const magic=String(artifact?.metadata?.magic||'').toUpperCase();
  if (artifact?.mediaType?.includes('H265')) return '递归恢复 RTP/H265 图传';
  if (artifact?.mediaType?.includes('H264')) return '递归恢复 RTP/H264 图传';
  if (magic==='PCAP'||magic==='PCAPNG') return `递归解码 ${magic} 抓包`;
  if (['ELF','ZIP','PDF','PNG','JPEG','SQUASHFS','UIMAGE'].includes(magic)) return `递归恢复 ${magic} 文件`;
  return '递归恢复产物';
}

function collectArtifacts(analysis={}) {
  const out=[]; const seen=new Set();
  for (const file of analysis.files||[]) {
    const m=file.metadata||{};
    const programming=m.pcapng?.can?.udsProgramming||m.captureIntelligence?.can?.udsProgramming;
    for (const transfer of programming?.transfers||[]) {
      if (!transfer?.artifact) continue;
      pushArtifact(out,seen,file.path,transfer.artifact.metadata?.rawTransferPayload?'UDS 传输数据':'ECU 固件候选',transfer.artifact,'导出后继续做格式识别或固件逆向。');
    }
    const ftp=m.lowAltitude?.ftpReassembly||m.mavlink?.ftpReassembly;
    for (const item of ftp?.files||[]) pushArtifact(out,seen,file.path,'MAVLink FTP 文件',item.artifact,'优先检查配置、脚本、密钥和 Flag 线索。');
    for (const item of m.autoDecode?.candidates||[]) pushArtifact(out,seen,file.path,`自动解码 ${item.magic||'文件'} 候选`,item.artifact,'直接进入对应文件类型的下一步分析。');
    for (const artifact of m.captureIntelligence?.video?.artifacts||[]) pushArtifact(out,seen,file.path,artifact.mediaType?.includes('H265')?'RTP/H265 图传':'RTP/H264 图传',artifact,'可直接交给 ffplay/ffmpeg 或视频取证继续检查。');
    for (const session of m.captureIntelligence?.video?.sessions||[]) pushArtifact(out,seen,file.path,`RTP/${session.codec||'H264'} 图传`,session.artifact,'可直接交给 ffplay/ffmpeg 或视频取证继续检查。');
    for (const artifact of m.recursiveArtifacts?.artifacts||[]) pushArtifact(out,seen,file.path,recursiveArtifactKind(artifact),artifact,'已经过递归自动分析；导出只用于人工复核或交给外部专业工具。');
  }
  return out.sort((a,b)=>{
    const ca=a.completeness==='complete'?1:0;
    const cb=b.completeness==='complete'?1:0;
    return cb-ca||(b.size||0)-(a.size||0);
  }).slice(0,32);
}

function priorityFiles(analysis={}) {
  return (analysis.files||[]).map((file)=>{
    let score=(file.flags?.length||0)*120;
    for (const finding of file.findings||[]) score+=SEVERITY_SCORE[finding.severity]||0;
    const m=file.metadata||{};
    if (m.regulatoryAudit||m.gnssAudit||m.firmwareUpdateAudit||m.ocrExtractionAudit) score+=26;
    if (m.captureIntelligence?.video?.artifacts?.length||m.captureIntelligence?.datalink) score+=32;
    if (m.pcapng?.can?.udsProgramming?.exportableTransfers) score+=50;
    if (m.autoDecode?.candidates?.some((x)=>x.artifact||x.foundFlag)) score+=50;
    if (m.recursiveArtifacts?.artifacts?.length) score+=55;
    if (m.recursiveArtifacts?.flags?.length) score+=100;
    return {path:file.path,type:file.type||file.extension||'文件',size:file.size||0,score};
  }).filter((x)=>x.score>0).sort((a,b)=>b.score-a.score).slice(0,8);
}

function automaticChecks(analysis={}) {
  const hits={
    'capture-intelligence':0,'uav-regulatory':0,'gnss-audit':0,'firmware-update':0,'ai-model':0,'ai-ocr-extraction':0,'ai-skill-matrix':0,'web3':0,'vehicle':0,'auto-decode':0,'recursive-artifact':0
  };
  for (const file of analysis.files||[]) {
    const m=file.metadata||{};
    if (m.captureIntelligence) hits['capture-intelligence']++;
    if (m.regulatoryAudit) hits['uav-regulatory']++;
    if (m.gnssAudit||m.gnssSpectrumAudit) hits['gnss-audit']++;
    if (m.firmwareUpdateAudit) hits['firmware-update']++;
    if (m.model||m.modelAudit||m.aiAudit) hits['ai-model']++;
    if (m.ocrExtractionAudit) hits['ai-ocr-extraction']++;
    if (m.aiSkillMatrix) hits['ai-skill-matrix']++;
    if (m.web3Audit||m.solanaAudit||m.evmAudit) hits.web3++;
    if (m.pcapng?.can||m.captureIntelligence?.can?.parsedFrames) hits.vehicle++;
    if (m.autoDecode?.candidates?.length) hits['auto-decode']++;
    if (m.recursiveArtifacts?.stats?.analyzedNodes) hits['recursive-artifact']++;
  }
  const labels={
    'capture-intelligence':'PCAP/PCAPNG 深度解析','uav-regulatory':'低空监管 API 审计','gnss-audit':'GNSS/GPS 异常审计','firmware-update':'固件升级信任链审计','ai-model':'AI 模型/源码安全审计','ai-ocr-extraction':'OCR 模型窃取分析','ai-skill-matrix':'AI 技能矩阵','web3':'区块链/合约分析','vehicle':'CAN/UDS 分析','auto-decode':'疑似编码自动试解','recursive-artifact':'恢复产物递归分析'
  };
  return Object.entries(hits).filter(([,count])=>count>0).map(([id,count])=>({id,title:labels[id],hits:count})).sort((a,b)=>b.hits-a.hits);
}

function buildActions({track,flags,findings,artifacts}) {
  const actions=[];
  if (flags.length) actions.push({id:'verify-flag',priority:100,level:'win',title:'验证 Flag 候选',detail:`${flags[0].value} · ${flags[0].file}`});
  if (artifacts.length) actions.push({id:'export-artifact',priority:90,level:'win',title:`导出 ${artifacts[0].kind}`,detail:`${artifacts[0].name}${artifacts[0].next?` · ${artifacts[0].next}`:''}`,artifactIndex:0});
  const high=findings.find((x)=>x.severity==='high')||findings[0];
  if (high) actions.push({id:'inspect-finding',priority:80,level:high.severity==='high'?'hot':'normal',title:`优先跟进：${high.title||high.id||'高价值线索'}`,detail:high.file||'workspace'});
  if (track?.score>0) actions.push({id:'open-track-tool',priority:50,level:'normal',title:`继续 ${track.title} 路线`,detail:'扫描已先跑确定性自动化；只在需要构造/复核时再打开专业工具。',tool:track.tool});
  if (!actions.length) actions.push({id:'inspect-entry',priority:10,level:'normal',title:'确认题目入口与主要附件',detail:'当前没有高置信结果，先看题目说明、服务入口和体积最大的附件。'});
  return actions.sort((a,b)=>b.priority-a.priority).slice(0,4);
}

function buildWorkspaceAutopilot(analysis={}) {
  const tracks=scoreTracks(analysis);
  const flags=collectFlags(analysis);
  const findings=topFindings(analysis);
  const artifacts=collectArtifacts(analysis);
  const files=priorityFiles(analysis);
  const checks=automaticChecks(analysis);
  const track=tracks[0]?.score>0?tracks[0]:null;
  const actions=buildActions({track,flags,findings,artifacts});
  return {
    version:2,
    generatedAt:new Date().toISOString(),
    track,
    tracks,
    flags,
    findings,
    artifacts,
    priorityFiles:files,
    automaticChecks:checks,
    actions,
    summary:{
      highFindings:(analysis.findings||[]).filter((x)=>x.severity==='high').length,
      flagCandidates:flags.length,
      exportableArtifacts:artifacts.length,
      automaticCheckKinds:checks.length,
      automaticCheckHits:checks.reduce((sum,x)=>sum+x.hits,0)
    },
    notes:['NewCyber 默认就是赛题工作流：导入目录后先自动扫描、自动路由、自动恢复产物，并对恢复出的文本/抓包/压缩层继续递归分析，再把人工操作压缩到最短链路。','所有结论仍保留证据来源；不会自动执行附件、联网攻击或提交 Flag。']
  };
}

module.exports={TRACKS,scoreTracks,collectFlags,topFindings,collectArtifacts,priorityFiles,automaticChecks,buildWorkspaceAutopilot};
