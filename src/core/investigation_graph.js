const SEVERITY_SCORE = { high: 40, medium: 18, low: 7, info: 2 };

function text(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function lowerFinding(finding) {
  return `${finding?.id || ''} ${finding?.originalId || ''} ${finding?.title || ''} ${finding?.meaning || ''} ${text(finding?.evidence)}`.toLowerCase();
}

function inferTrack(finding, file = null) {
  const hay = lowerFinding(finding);
  const filePath = String(file?.path || finding?.file || '').toLowerCase();
  const ext = String(file?.extension || '').toLowerCase() || (/\.[a-z0-9]+$/i.exec(filePath)?.[0] || '');

  if (/(?:^|\s)(?:vehicle|can|uds|canopen|isotp|doip|someip)[-:]/.test(hay)) return 'vehicle';
  if (/(?:^|\s)(?:web3|evm|solidity|solana|anchor)[-:]/.test(hay) || ['.sol', '.vy'].includes(ext)) return 'web3';
  if (/(?:^|\s)(?:ai|model|prompt|rag|privacy|adversarial|dataset)[-:]/.test(hay) || ['.pt','.pth','.safetensors','.npy','.onnx','.gguf'].includes(ext)) return 'ai';
  if (/(?:^|\s)(?:uav|mavlink|lowalt|ardupilot|px4)[-:]/.test(hay) || ['.tlog','.ulg','.eeprom'].includes(ext)) return 'lowalt';

  if (/(can\b|uds\b|isotp|iso-tp|canopen|ecu|doip|some\/ip|vehicle)/.test(hay)) return 'vehicle';
  if (/(web3|solidity|smart contract|external contract|evm|delegatecall|eip-1967|eip1967|eip-1167|proxy|storage|calldata|anchor|solana|abi|flashloan|oracle|reentr)/.test(hay)) return 'web3';
  if (/(model|prompt|rag|llm|torch|pickle|safetensor|adversarial|membership|privacy|dataset|poison|backdoor|hugging|dependency|nan|infinity|ai\b)/.test(hay)) return 'ai';
  if (/(mavlink|uav|drone|ardupilot|px4|gps|attitude|gcs|mission_|param_|flight|wifi|eapol|pmkid|ulog|dataflash)/.test(hay)) return 'lowalt';
  if (/(aes|sm4|base64|hex|xor|crypto|cipher|decode)/.test(hay)) return 'common';
  return null;
}

function inferTool(finding, track) {
  const hay = lowerFinding(finding);
  if (/(membership|privacy)/.test(hay)) return 'ai-privacy-audit';
  if (/(adversarial|epsilon|fgsm|pgd|perturb)/.test(hay)) return 'ai-adversarial-audit';
  if (/(dataset|trigger|poison|backdoor|label conflict)/.test(hay)) return 'ai-dataset-security';
  if (/(supply|trust_remote_code|revision|dependency|pip|extra-index|path shadow|deserial)/.test(hay)) return 'ai-supply-chain';
  if (/(tabular|isolation|xgboost|correlation|profile)/.test(hay)) return 'ai-tabular-profile';
  if (/(prompt|rag|llm|shell|tool call|model output)/.test(hay)) return 'ai-source-scan';
  if (/(wifi|eapol|pmkid|deauth|ssid|bssid)/.test(hay)) return 'uav-wifi-evidence';
  if (/(flight log|dataflash|ulog|飞行日志)/.test(hay)) return 'uav-flight-log';
  if (/(signing|signature rollback|mavlink2 signature)/.test(hay)) return 'mavlink-signature-verify';
  if (/(firmware|squashfs|ubi|jffs|uimage|rootfs|bootloader)/.test(hay)) return 'firmware-unpack';
  if (/(mavlink|gcs|mission_|param_|command_long|gps|attitude|fence|flighttermination)/.test(hay)) return 'mavlink-hex';
  if (/(uds|securityaccess|requestdownload|transferdata|transferexit|did|nrc)/.test(hay)) return 'uds-decode';
  if (/(can\b|canopen|counter|socketcan|isotp|iso-tp)/.test(hay)) return 'can-analyze';
  if (/(solana|anchor)/.test(hay)) return 'solana-source-scan';
  if (/(calldata|selector|abi)/.test(hay)) return 'evm-calldata';
  if (/(evm|bytecode|proxy|delegatecall|storage|sload|sstore|external contract|reentr|oracle|flashloan)/.test(hay)) return 'evm-disasm';
  if (/(aes|sm4|cipher|iv|nonce|tag)/.test(hay)) return 'context-crypto';
  if (/(base64|hex|xor|decode|encoded)/.test(hay)) return 'auto-decode';
  if (track === 'vehicle') return 'can-analyze';
  if (track === 'lowalt') return 'mavlink-hex';
  if (track === 'ai') return 'ai-source-scan';
  if (track === 'web3') return 'evm-disasm';
  return null;
}

function inferExploitability(finding) {
  const hay = lowerFinding(finding);
  if (/(confirmed|accepted|回读确认|change confirmed|found flag|命中 flag|完整恢复|artifactready|signature valid)/.test(hay)) return 'confirmed';
  if (/(rejected|blocked|mismatch|incomplete|缺少|unknown|not proven)/.test(hay)) return 'needs-context';
  if (finding?.severity === 'high') return 'high-priority-candidate';
  if (finding?.severity === 'medium') return 'candidate';
  return 'evidence';
}

function inferPrerequisite(finding) {
  if (finding?.prerequisite) return text(finding.prerequisite);
  const hay = lowerFinding(finding);
  if (/(shell|tool call|model output|rag)/.test(hay)) return '攻击者能够影响进入模型、RAG 或 Tool 调用链的数据。';
  if (/(membership|privacy)/.test(hay)) return '需要成员/非成员参考样本或可重复查询得到可比较的输出信号。';
  if (/(adversarial|epsilon|fgsm|pgd)/.test(hay)) return '候选必须满足题目 verifier 的 preprocessing、扰动预算和目标输出条件。';
  if (/(wifi|eapol|pmkid)/.test(hay)) return '需要目标 AP/客户端握手或 PMKID 证据；口令候选仍需离线验证。';
  if (/(mavlink|gcs|mission_|param_|command_long)/.test(hay)) return '控制源能够向目标飞控发送被接受的 MAVLink 消息。';
  if (/(firmware|rootfs|squashfs|ubi)/.test(hay)) return '固件段边界或文件系统结构必须可复核；解包结果不能只凭字符串猜测。';
  if (/(uds|securityaccess|requestdownload|transferdata)/.test(hay)) return '需要完整诊断会话与请求/响应证据，必要时确认目标 ECU 会接受该服务。';
  if (/(proxy|delegatecall|external contract|oracle|flashloan)/.test(hay)) return '攻击者必须能够影响相应 calldata、外部依赖、状态或调用时序。';
  return '结合题目输入边界和实际 verifier/目标行为确认攻击者是否能控制该证据链。';
}

function inferFix(finding) {
  if (finding?.fix?.action) return finding.fix.action;
  const hay = lowerFinding(finding);
  if (/(shell|tool call|model output)/.test(hay)) return '使用结构化 schema/allowlist，避免模型输出直接形成 shell、文件或高权限工具参数。';
  if (/(trust_remote_code|revision|dependency|supply)/.test(hay)) return '固定 artifact/revision/hash，限制依赖来源并在加载前做静态审计。';
  if (/(mavlink|gcs|param_|mission_|command_long)/.test(hay)) return '限制可信控制源，对高风险控制消息做签名、身份和权限校验并记录审计日志。';
  if (/(firmware|upgrade|rootfs)/.test(hay)) return '升级链应在写入前验证签名/完整性，并限制解密密钥、更新来源与回滚路径。';
  if (/(external contract|oracle|delegatecall|proxy)/.test(hay)) return '绑定可信依赖/implementation 来源，校验关键地址与权限边界，避免调用者控制关键外部语义。';
  return null;
}

function inferRegression(finding) {
  if (finding?.fix?.regression) return finding.fix.regression;
  const hay = lowerFinding(finding);
  if (/(shell|tool call|model output)/.test(hay)) return '恶意模型/RAG 输出不得改变允许的工具名、命令结构或高权限参数。';
  if (/(mavlink|gcs|param_|mission_|command_long)/.test(hay)) return '非可信/未签名控制源应被拒绝；合法可信控制源的正常业务仍应通过。';
  if (/(firmware|upgrade)/.test(hay)) return '篡改、错误签名或来源不可信的固件必须在 flash 前失败；合法更新保持可用。';
  if (/(external contract|oracle|delegatecall|proxy)/.test(hay)) return '伪造依赖地址/implementation 时关键资产或权限路径不得成立，可信配置仍保持原行为。';
  return null;
}

function inferNextAction(finding, tool) {
  const hay = lowerFinding(finding);
  if (/(found flag|命中 flag|flag 候选)/.test(hay)) return '先用题目 verifier/提交格式验证 Flag 候选。';
  if (/(firmware|rootfs|squashfs|ubi|jffs)/.test(hay)) return '打开固件工作台确认段边界，导出完整 artifact 后继续逆向/配置审计。';
  if (/(mavlink|gcs|mission_|param_|command_long)/.test(hay)) return '打开 MAVLink 分析，按 source → command/write → ACK → state effect 对齐控制链。';
  if (/(wifi|eapol|pmkid)/.test(hay)) return '核对握手完整性、AP/客户端身份和口令候选，再做离线验证。';
  if (/(membership|privacy)/.test(hay)) return '把查询 transcript 送入成员推断审计，优先看 AUC、阈值和独立 holdout。';
  if (/(adversarial|epsilon|fgsm|pgd)/.test(hay)) return '把 clean/adv 样本送入对抗样本验证，先检查预算与 preprocessing 空间。';
  if (/(dataset|trigger|poison|backdoor)/.test(hay)) return '对可疑 trigger 做删除/替换/跨样本验证，再决定是否构成后门。';
  if (/(proxy|delegatecall|storage|calldata|external contract)/.test(hay)) return '打开 EVM 分析，确认 selector/slot/target/外部依赖的真实数据流，不只看规则命中。';
  if (/(shell|tool call|rag|model output)/.test(hay)) return '打开 AI Pipeline 审计，从 source → model/RAG → sink 复核可控性。';
  if (tool) return '打开推荐工具复核原始证据，并把结果继续送入下一分析阶段。';
  return '查看原始文件与证据上下文，先验证成立前提。';
}

function collectArtifacts(analysis) {
  const artifacts = [];
  for (const file of analysis?.files || []) {
    const transfers = file.metadata?.pcapng?.can?.udsProgramming?.transfers || [];
    transfers.forEach((item, index) => {
      if (!item?.artifact) return;
      artifacts.push({ id:`artifact:uds:${file.path}:${index}`, source:'uds', sourceFile:file.path, index, name:item.artifact.name, size:item.artifact.size, sha256:item.artifact.sha256, kind:item.artifact.metadata?.rawTransferPayload?'UDS 传输数据':'ECU 固件候选', complete:item.artifact.completeness === 'complete' });
    });
    const ftp = file.metadata?.lowAltitude?.ftpReassembly || file.metadata?.mavlink?.ftpReassembly;
    (ftp?.files || []).forEach((item, index) => {
      if (!item?.artifact) return;
      artifacts.push({ id:`artifact:mavftp:${file.path}:${index}`, source:'mavftp', sourceFile:file.path, index, name:item.artifact.name || item.path, size:item.artifact.size, sha256:item.artifact.sha256, kind:'MAVLink FTP 文件', complete:item.artifact.completeness === 'complete' });
    });
    (file.metadata?.autoDecode?.candidates || []).forEach((item, index) => {
      if (!item?.artifact) return;
      artifacts.push({ id:`artifact:auto:${file.path}:${index}`, source:'auto-decode', sourceFile:file.path, index, name:item.artifact.name, size:item.artifact.size, sha256:item.artifact.sha256, kind:`自动解码 ${item.magic || '文件'} 候选`, complete:item.artifact.completeness === 'complete' });
    });
    (file.metadata?.contextCrypto?.bestCandidates || []).forEach((item, index) => {
      if (!item?.artifact) return;
      artifacts.push({ id:`artifact:crypto:${file.path}:${index}`, source:'context-crypto', sourceFile:file.path, index, name:item.artifact.name, size:item.artifact.size, sha256:item.artifact.sha256, kind:`强加密解密 ${item.magic || '文件'} 候选`, complete:item.artifact.completeness === 'complete' });
    });
  }
  return artifacts;
}

function buildInvestigationGraph(analysis) {
  const fileMap = new Map((analysis?.files || []).map((file) => [file.path, file]));
  const artifacts = collectArtifacts(analysis);
  const nodes = (analysis?.findings || []).map((finding, index) => {
    const file = fileMap.get(finding.file) || null;
    const track = inferTrack(finding, file);
    const tool = inferTool(finding, track);
    const exploitability = inferExploitability(finding);
    return {
      id: `finding:${index}:${String(finding.id || finding.title || 'evidence')}`,
      findingId: finding.id || null,
      originalId: finding.originalId || null,
      severity: finding.severity || 'info',
      title: finding.title || finding.id || '未命名线索',
      file: finding.file || null,
      line: finding.line || null,
      evidence: text(finding.evidence ?? finding.description ?? finding.patterns ?? '').slice(0, 12000),
      meaning: finding.meaning || finding.message || null,
      prerequisite: inferPrerequisite(finding),
      exploitability,
      fix: inferFix(finding),
      regression: inferRegression(finding),
      nextAction: inferNextAction(finding, tool),
      recommendedTool: tool,
      track,
      score: (SEVERITY_SCORE[finding.severity] || 0) + (exploitability === 'confirmed' ? 25 : 0)
    };
  }).sort((a,b)=>b.score-a.score || String(a.file||'').localeCompare(String(b.file||'')));

  const top = nodes.slice(0, 12);
  const nextActions = [];
  const seen = new Set();
  for (const node of top) {
    const key = `${node.recommendedTool || ''}:${node.nextAction}`;
    if (seen.has(key)) continue;
    seen.add(key);
    nextActions.push({ id:`action:${nextActions.length}`, title:node.title, text:node.nextAction, tool:node.recommendedTool, file:node.file, severity:node.severity, findingNodeId:node.id });
    if (nextActions.length >= 6) break;
  }
  if (artifacts.length) nextActions.unshift({ id:'action:artifact', title:'优先处理完整产物', text:`已恢复 ${artifacts.length} 个可继续分析的 artifact；优先导出并进入对应逆向/取证流程。`, tool:null, file:artifacts[0].sourceFile, severity:'high', artifactId:artifacts[0].id });

  return {
    version:1,
    summary:{
      total:nodes.length,
      high:nodes.filter((x)=>x.severity==='high').length,
      confirmed:nodes.filter((x)=>x.exploitability==='confirmed').length,
      pending:nodes.filter((x)=>x.exploitability!=='confirmed').length,
      artifacts:artifacts.length
    },
    focus:top,
    nextActions:nextActions.slice(0, 6),
    artifacts,
    notes:['Investigation Graph 只重组已有确定性证据，不把规则命中自动升级成漏洞成立；analyst review 状态由 UI 单独保存。']
  };
}

module.exports = { inferTrack, inferTool, inferExploitability, collectArtifacts, buildInvestigationGraph };
