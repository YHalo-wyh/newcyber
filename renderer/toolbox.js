const app = document.querySelector('#app');

const state = {
  view: 'home',
  tool: null,
  toolResult: null,
  toolError: null,
  workspace: null,
  fileFilter: ''
};

const DOMAINS = {
  vehicle: {
    title: '车联网安全', icon: 'CAR', kicker: 'VEHICLE SECURITY',
    desc: 'CAN / UDS / ISO-TP / MQTT / ECU / 遥控信号。优先覆盖国内赛题里最常见的总线差分、诊断协议和车载消息分析。',
    tools: [
      ['can-analyze', 'CAN 差分分析', '导入 candump/文本帧，统计 ID、周期、变化字节与 counter 候选。'],
      ['uds-decode', 'UDS / ISO-TP 快速解码', '识别 UDS Service、NRC、SecurityAccess、DID，并处理 Single/First Frame。']
    ]
  },
  lowalt: {
    title: '低空经济安全', icon: 'UAV', kicker: 'LOW ALTITUDE SECURITY',
    desc: '无人机遥测、MAVLink、GNSS/NMEA、飞行日志与固件分析。第一版先把最费时间的数据解码自动化。',
    tools: [
      ['mavlink-hex', 'MAVLink 帧分析', '解析 MAVLink v1/v2 十六进制流，列出 SYSID、COMPID、MSGID 和常见消息。'],
      ['nmea-analyze', 'GNSS / NMEA 分析', '解析 RMC/GGA，经纬度、速度、高度、卫星数与轨迹范围。']
    ]
  },
  ai: {
    title: '人工智能安全', icon: 'AI', kicker: 'AI SECURITY',
    desc: 'Prompt / Agent / RAG / 模型供应链 / 对抗样本 / 数据安全。当前先做代码攻击面审计，并保留原有模型文件安全检查。',
    tools: [
      ['ai-source-scan', 'AI Pipeline 代码审计', '粘贴 Python/JS 等源码，快速定位不可信反序列化、Shell、动态执行、RAG 和 Tool 调用面。'],
      ['ai-he-training-audit', 'HE 密态训练审计', '选择 HETraining 目录，识别 TenSEAL CKKS、量化输出、密态输入批次与可复核解题链。'],
      ['ai-he-training-solve', 'HETraining 分步求解', '逐步拟合明文输出、检查 CKKS 解密条件，并明确显示已解出内容和阻断原因。'],
      ['ai-leakage-solve', 'leakage 分步求解', '回放功耗→能量→隐藏状态→逐 token 解码链，展示恢复的 ID/手机号和验证结果。'],
      ['local-torch-inspect', '本地 PyTorch 运行时', '探测本机 python + torch / CUDA：版本、GPU、算力与矩阵乘自检，一键确认能否跑本地推理。']
    ]
  },
  web3: {
    title: '区块链安全', icon: 'WEB3', kicker: 'BLOCKCHAIN SECURITY',
    desc: 'EVM / Solidity / ABI / calldata / DeFi。第一版先解决比赛里最常用的 calldata 阅读和字节码快速定位。',
    tools: [
      ['evm-calldata', 'Calldata 快速拆解', '识别常见 ERC-20 selector，并按 32 字节 word 展示 uint/address 候选。'],
      ['evm-disasm', 'EVM Bytecode 反汇编', '离线反汇编 PUSH/DUP/SWAP/CALL 等 opcode，并标出危险操作。']
    ]
  }
};

const TOOL_META = {
  'can-analyze': { domain: 'vehicle', title: 'CAN 差分分析', placeholder: '(1710000000.100) can0 123#00112233\n(1710000000.200) can0 123#01112233', label: 'CAN 日志 / candump' },
  'uds-decode': { domain: 'vehicle', title: 'UDS / ISO-TP 快速解码', placeholder: '27 01\n或：02 10 03\n或：7f 27 35', label: '十六进制数据' },
  'mavlink-hex': { domain: 'lowalt', title: 'MAVLink 帧分析', placeholder: 'fe0900010100...', label: 'MAVLink 原始十六进制流' },
  'nmea-analyze': { domain: 'lowalt', title: 'GNSS / NMEA 分析', placeholder: '$GPRMC,123519,A,4807.038,N,01131.000,E,...\n$GPGGA,...', label: 'NMEA 文本' },
  'ai-source-scan': { domain: 'ai', title: 'AI Pipeline 代码审计', placeholder: 'model = torch.load(path)\ncontext = retriever.similarity_search(query)\nsubprocess.run(cmd, shell=True)', label: '源码' },
  'ai-he-training-audit': { domain: 'ai', title: 'HE 密态训练审计', placeholder: '输入 HETraining 目录绝对路径，例如 F:/challenge/HETraining', label: 'HETraining 目录路径' },
  'ai-he-training-solve': { domain: 'ai', title: 'HETraining 分步求解', placeholder: '输入 HETraining 目录绝对路径，例如 F:/challenge/HETraining/HETraining', label: 'HETraining 目录路径' },
  'ai-leakage-solve': { domain: 'ai', title: 'leakage 分步求解', placeholder: '输入 leakage_task 目录绝对路径，例如 F:/challenge/leakage_task/leakage_task', label: 'leakage 目录路径' },
  'local-torch-inspect': { domain: 'ai', title: '本地 PyTorch 运行时', placeholder: '', label: '无需输入，直接点分析' },
  'evm-calldata': { domain: 'web3', title: 'Calldata 快速拆解', placeholder: '0xa9059cbb000000000000000000000000...', label: 'Calldata' },
  'evm-disasm': { domain: 'web3', title: 'EVM Bytecode 反汇编', placeholder: '0x6080604052...', label: 'EVM Bytecode' },
  'codec': { domain: 'common', title: '编码 / Hash / XOR', placeholder: '输入待处理的数据', label: '输入' },
  'knowledge-search': { domain: 'knowledge', title: '离线速查', placeholder: '例如：Prompt Injection / torch.load', label: '关键字' }
};

const CODEC_OPS = [
  ['text-to-hex', '文本 → Hex'], ['hex-to-text', 'Hex → 文本'],
  ['text-to-base64', '文本 → Base64'], ['base64-to-text', 'Base64 → 文本'],
  ['url-encode', 'URL Encode'], ['url-decode', 'URL Decode'],
  ['sha256', 'SHA-256'], ['md5', 'MD5'], ['xor-hex', 'Hex XOR']
];

function esc(value = '') {
  return String(value).replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
}

function fmtBytes(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes; let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function navButton(view, label, icon) {
  return `<button class="nav-item ${state.view === view && !state.tool ? 'active' : ''}" data-view="${view}"><span>${icon}</span>${label}</button>`;
}

function shell(content) {
  const workspaceName = state.workspace?.workspaceName || '未打开赛题';
  const currentTitle = state.tool ? TOOL_META[state.tool]?.title : (DOMAINS[state.view]?.title || ({ home: '首页', common: '通用工具', knowledge: '离线速查', workspace: '赛题目录' }[state.view] || state.view));
  return `<div class="shell">
    <aside class="sidebar">
      <button class="brand" data-view="home"><span class="brand-mark">N</span><span><strong>NewCyber</strong><small>OFFLINE FINALS KIT</small></span></button>
      <div class="nav-section"><b>赛道工具箱</b>
        ${navButton('vehicle', '车联网安全', 'V')}
        ${navButton('lowalt', '低空经济安全', 'U')}
        ${navButton('ai', '人工智能安全', 'A')}
        ${navButton('web3', '区块链安全', 'B')}
      </div>
      <div class="nav-section"><b>通用</b>
        ${navButton('common', '编码 / Hash', 'C')}
        ${navButton('knowledge', '离线速查', 'K')}
        ${navButton('workspace', '赛题目录分析', 'F')}
      </div>
      <div class="sidebar-status"><span class="dot"></span><div><strong>Offline Ready</strong><small>核心工具不依赖网络</small></div></div>
    </aside>
    <main>
      <header class="topbar"><div><span>NewCyber</span><b>/</b><strong>${esc(currentTitle)}</strong></div><div class="top-actions"><span class="workspace-pill">${esc(workspaceName)}</span>${state.view === 'workspace' && !state.tool ? '<button class="button primary" data-action="choose-workspace">选择目录</button>' : ''}</div></header>
      <section class="content">${content}</section>
    </main>
  </div><div id="toast"></div>`;
}

function homeView() {
  return `<div class="hero"><span class="kicker">BAY AREA CUP · OFFLINE TOOLBOX</span><h1>四赛道，<em>一台机器解决重复劳动。</em></h1><p>面向线下断网决赛准备。车联网、低空经济、人工智能、区块链彼此独立；每个工具只做确定、可复核的自动化，把时间留给真正的漏洞理解。</p></div>
    <div class="domain-grid">${Object.entries(DOMAINS).map(([id, item]) => `<button class="domain-card" data-view="${id}"><span class="domain-icon">${item.icon}</span><span class="domain-kicker">${item.kicker}</span><strong>${item.title}</strong><p>${item.desc}</p><em>进入工具箱 →</em></button>`).join('')}</div>
    <div class="quick-grid"><button class="quick-card" data-tool="codec"><b>编码 / Hash / XOR</b><span>Hex、Base64、URL、SHA-256、XOR 一页完成</span></button><button class="quick-card" data-view="workspace"><b>赛题目录分析</b><span>文件类型、字符串、Flag、模型/WAV/PCAP 基础检查</span></button><button class="quick-card" data-tool="knowledge-search"><b>离线速查</b><span>AI 安全速查条目离线可用</span></button></div>`;
}

function domainView(id) {
  const domain = DOMAINS[id];
  return `<div class="page-head"><span class="kicker">${domain.kicker}</span><h1>${domain.title}</h1><p>${domain.desc}</p></div><div class="tool-grid">${domain.tools.map(([tool, title, desc]) => `<button class="tool-card" data-tool="${tool}"><span>${TOOL_META[tool].domain.toUpperCase()}</span><strong>${title}</strong><p>${desc}</p><em>打开 →</em></button>`).join('')}</div><article class="panel roadmap"><div><b>当前版本原则</b><p>先覆盖国内比赛中高频、重复且适合确定性自动化的步骤。协议/漏洞结论仍需人工验证。</p></div></article>`;
}

function commonView() {
  return `<div class="page-head"><span class="kicker">COMMON UTILITIES</span><h1>通用工具</h1><p>比赛现场最常用的小工具集中到一处，不再开十几个网页。</p></div><div class="tool-grid"><button class="tool-card" data-tool="codec"><span>CODEC</span><strong>编码 / Hash / XOR</strong><p>Hex、Base64、URL、SHA-256、MD5、循环 XOR。</p><em>打开 →</em></button><button class="tool-card" data-view="workspace"><span>FILES</span><strong>赛题目录分析</strong><p>沿用现有只读扫描器，快速固定附件和初步线索。</p><em>打开 →</em></button></div>`;
}

function toolView(tool) {
  const meta = TOOL_META[tool];
  const codecOptions = tool === 'codec' ? `<div class="field"><label>操作</label><select id="tool-operation">${CODEC_OPS.map(([id, label]) => `<option value="${id}">${label}</option>`).join('')}</select></div><div class="field hidden" id="xor-key-field"><label>XOR Key（Hex）</label><input id="tool-key" placeholder="例如 1337" /></div>` : '';
  const domainFilter = tool === 'knowledge-search' ? `<div class="field"><label>赛道过滤</label><select id="knowledge-domain"><option value="">全部</option><option>人工智能</option></select></div>` : '';
  return `<div class="page-head tool-head"><div><span class="kicker">OFFLINE TOOL</span><h1>${meta.title}</h1></div><button class="button ghost" data-view="${meta.domain}">返回</button></div>
    <div class="workbench"><article class="panel input-panel">${codecOptions}${domainFilter}<div class="field grow"><label>${meta.label}</label><textarea id="tool-input" spellcheck="false" placeholder="${esc(meta.placeholder)}"></textarea></div><div class="run-row"><span>只在本机处理输入</span><button class="button primary" data-action="run-tool">运行分析</button></div></article><article class="panel result-panel"><div class="result-title"><b>结果</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${state.toolError ? `<div class="error-box">${esc(state.toolError)}</div>` : state.toolResult ? renderResult(tool, state.toolResult) : '<div class="result-empty">等待输入。</div>'}</div></article></div>`;
}

function renderResult(tool, result) {
  if (tool === 'codec') return `<pre class="output-pre">${esc(result.output || '')}</pre>${result.utf8 ? `<div class="result-sub"><b>UTF-8 预览</b><pre>${esc(result.utf8)}</pre></div>` : ''}`;
  if (tool === 'can-analyze') return `<div class="result-stats"><div><b>${result.parsedFrames}</b><span>帧</span></div><div><b>${result.uniqueIds}</b><span>CAN ID</span></div></div>${table(['ID','帧数','DLC','平均周期(ms)','变化字节','Counter候选'], result.ids.map(i => [i.id,i.count,i.dlc.join('/'),i.averageIntervalMs ?? '—',i.changingBytes.join(', ') || '—',i.counterCandidates.join(', ') || '—']))}<div class="hint-list">${result.hints.map(x=>`<p>${esc(x)}</p>`).join('')}</div>`;
  if (tool === 'uds-decode') return `<div class="kv-grid">${Object.entries(result).filter(([k])=>k!=='notes').map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</strong></div>`).join('')}</div>${(result.notes||[]).map(n=>`<p class="notice">${esc(n)}</p>`).join('')}`;
  if (tool === 'nmea-analyze') return `<div class="result-stats"><div><b>${result.validPoints}</b><span>有效点</span></div><div><b>${result.distanceM}</b><span>累计距离 m</span></div></div>${result.bounds ? `<pre class="mini-pre">${esc(JSON.stringify(result.bounds,null,2))}</pre>` : ''}${table(['来源','时间','纬度','经度','速度(kn)','高度(m)'], result.points.slice(0,100).map(p=>[p.source,p.time||'—',p.lat.toFixed(6),p.lon.toFixed(6),p.speedKnots ?? '—',p.altitudeM ?? '—']))}`;
  if (tool === 'mavlink-hex') return `<div class="result-stats"><div><b>${result.parsedFrames}</b><span>MAVLink 帧</span></div></div><pre class="mini-pre">${esc(JSON.stringify(result.messageCounts,null,2))}</pre>${table(['版本','SEQ','SYS','COMP','MSGID','消息','Payload'], result.frames.slice(0,150).map(f=>[f.version,f.seq,f.sysid,f.compid,f.msgid,f.name,f.payloadLength]))}<p class="notice">${esc(result.note)}</p>`;
  if (tool === 'ai-source-scan') return `<div class="surface-row">${Object.entries(result.surfaces).map(([k,v])=>`<span class="surface ${v?'on':''}">${k}</span>`).join('')}</div>${result.findings.length ? result.findings.map(f=>`<div class="finding ${f.severity}"><span>${f.severity}</span><div><b>${esc(f.title)}</b><small>${esc(f.id)} · ${f.count} 处</small><pre>${esc(f.evidence.join('\n'))}</pre></div></div>`).join('') : '<div class="result-empty">未命中当前规则。</div>'}<div class="hint-list">${result.hints.map(x=>`<p>${esc(x)}</p>`).join('')}</div>`;
  if (tool === 'ai-he-training-audit') return `<div class="result-stats"><div><b>${esc(result.status)}</b><span>状态</span></div><div><b>${result.roles?.['encrypted-input']?.length || 0}</b><span>密态输入</span></div><div><b>${result.roles?.['he-context']?.length || 0}</b><span>HE 上下文</span></div><div><b>${result.roles?.['quantized-outputs']?.length || 0}</b><span>量化输出</span></div></div>${(result.findings||[]).map(f=>`<div class="finding ${esc(f.severity)}"><span>${esc(f.severity)}</span><div><b>${esc(f.title)}</b><pre>${esc(JSON.stringify(f.evidence,null,2))}</pre></div></div>`).join('')}<div class="hint-list"><b>解题链</b>${(result.chain||[]).map((x,i)=>`<p>${i+1}. ${esc(x)}</p>`).join('')}<b>下一步</b>${(result.nextActions||[]).map(x=>`<p>${esc(x)}</p>`).join('')}</div>`;
  if (tool === 'ai-he-training-solve' || tool === 'ai-leakage-solve') return renderSolveResult(result);
  if (tool === 'evm-calldata') return `<div class="kv-grid"><div><span>selector</span><strong>${esc(result.selector)}</strong></div><div><span>known signature</span><strong>${esc(result.knownSignature || '未知')}</strong></div></div>${table(['#','uint256','address candidate','hex'], result.words.map(w=>[w.index,w.uint256,w.addressCandidate,w.hex]))}`;
  if (tool === 'evm-disasm') return `<div class="result-stats"><div><b>${result.byteLength}</b><span>字节</span></div><div><b>${result.riskyOpcodes.length}</b><span>风险 opcode</span></div></div>${result.riskyOpcodes.length ? `<div class="risk-strip">${result.riskyOpcodes.map(x=>`<span>${x.pc}: ${x.name}</span>`).join('')}</div>` : ''}${table(['PC','Opcode','指令','Immediate'], result.instructions.slice(0,1000).map(i=>[i.pc,i.opcode,i.name,i.immediate||'']))}`;
  if (tool === 'local-torch-inspect') {
    const r = state.toolResult || {};
    const ok = r.status === 'ok';
    const rows = [
      ['Python', r.pythonVersion || r.python || '—'],
      ['torch', r.torch || '未安装'],
      ['构建', r.torch ? (String(r.torch).includes('cu') ? `CUDA 构建 (${String(r.torch).split('+')[1] || 'cu'})` : 'CPU 构建') : '—'],
      ['CUDA 可用', r.cuda ? '是' : '否'],
      ['CUDA Runtime', r.cudaRuntime || '—'],
      ['GPU', r.device || (r.cuda ? '—' : '无')],
      ['算力 (sm)', r.capability ? r.capability.join('.') : '—'],
      ['GPU 矩阵乘自检', r.gpuMatmulOk == null ? '—' : (r.gpuMatmulOk ? '通过' : '失败')]
    ];
    return `<div class="result-stats"><div><b>${esc(r.runtime || r.status || '—')}</b><span>运行时</span></div><div><b>${r.cuda ? 'CUDA' : 'CPU'}</b><span>计算后端</span></div><div><b>${esc(r.torch || '—')}</b><span>torch 版本</span></div></div>
      <div class="kv-grid">${rows.map(([k, v]) => `<div><span>${esc(k)}</span><strong>${esc(String(v))}</strong></div>`).join('')}</div>
      ${ok ? `<p class="notice">${r.cuda ? '本机 CUDA PyTorch 可用，可以为本地推理 / 训练类工具提供 GPU 加速。' : '当前是 CPU 版 torch：只能跑轻量前向；需要 GPU 时安装 cu128 构建。'}</p>` : `<div class="error-box">未找到可用的 python + torch：${esc((r.tried || []).map(t => `${t.python} → ${t.status}${t.torch ? ` (${t.torch})` : ''}`).join('；') || '未探测')}</div><p class="notice">设置环境变量 NEWCYBER_PYTHON 指向装有 torch 的 python 后重试。</p>`}`;
  }
  if (tool === 'knowledge-search') return result.results.length ? `<div class="knowledge-list">${result.results.map(x=>`<article><span>${esc(x.domain)}</span><b>${esc(x.term)}</b><p>${esc(x.text)}</p></article>`).join('')}</div>` : '<div class="result-empty">没有命中，换个关键词。</div>';
  return `<pre class="output-pre">${esc(JSON.stringify(result,null,2))}</pre>`;
}

function renderSolveResult(result) {
  const steps = result.steps || result.stages || [];
  const done = steps.filter((step) => step.state === 'done' || step.state === 'candidate').length;
  const recovered = result.recovered || result.result;
  return `<div class="result-stats"><div><b>${esc(result.status || '—')}</b><span>总状态</span></div><div><b>${done}/${steps.length}</b><span>完成步骤</span></div><div><b>${result.flag ? '已解出' : '未生成 flag'}</b><span>最终答案</span></div></div>${recovered ? `<div class="solve-answer"><b>当前解出内容</b><pre>${esc(JSON.stringify(recovered, null, 2))}</pre></div>` : ''}<div class="solve-steps"><b class="solve-heading">解题过程（按执行顺序）</b>${steps.map((step, index) => `<article class="solve-step ${esc(step.state)}"><div class="solve-step-head"><span>${index + 1}</span><b>${esc(step.title)}</b><em>${esc(step.state)}</em></div><p>${esc(step.detail || '')}</p>${step.evidence && Object.keys(step.evidence).length ? `<pre>${esc(JSON.stringify(step.evidence, null, 2))}</pre>` : ''}${step.output != null ? `<div class="solve-output"><small>本步产出</small><pre>${esc(typeof step.output === 'string' ? step.output : JSON.stringify(step.output, null, 2))}</pre></div>` : ''}</article>`).join('')}</div>${result.gap ? `<div class="solve-gap"><b>当前阻断点：${esc(result.gap.code || 'GAP')}</b><p>${esc(result.gap.message || result.gap.detail || '')}</p></div>` : ''}${(result.nextActions || []).length ? `<div class="hint-list"><b>下一步</b>${result.nextActions.map((x) => `<p>${esc(x)}</p>`).join('')}</div>` : ''}`;
}

function table(headers, rows) {
  return `<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(v=>`<td>${esc(v ?? '')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}

function knowledgeView() {
  return `<div class="page-head"><span class="kicker">OFFLINE REFERENCE</span><h1>离线速查</h1><p>为断网赛场准备。收录 AI 安全速查条目：提示词注入、模型加载反序列化等，后续持续扩充。</p></div><button class="search-launch" data-tool="knowledge-search"><span>⌕</span><div><b>搜索离线知识库</b><small>Prompt Injection / torch.load</small></div><em>打开 →</em></button>`;
}

function workspaceView() {
  if (!state.workspace) return `<div class="page-head"><span class="kicker">CHALLENGE FILES</span><h1>赛题目录分析</h1><p>保留原有的只读附件扫描能力，适合拿到题目后的第一分钟。</p></div><div class="workspace-empty"><div>F</div><h2>尚未打开赛题目录</h2><p>扫描不会执行附件，也不会直接反序列化不可信模型。</p><button class="button primary" data-action="choose-workspace">选择赛题目录</button></div>`;
  const a = state.workspace;
  const files = a.files.filter(f => `${f.name} ${f.path} ${f.type}`.toLowerCase().includes(state.fileFilter.toLowerCase()));
  return `<div class="page-head"><div><span class="kicker">CHALLENGE FILES</span><h1>${esc(a.workspaceName)}</h1><p>${esc(a.workspacePath)}</p></div><button class="button ghost" data-action="rescan-workspace">重新扫描</button></div><div class="result-stats workspace-stats"><div><b>${a.stats.files}</b><span>文件</span></div><div><b>${fmtBytes(a.stats.bytes)}</b><span>体积</span></div><div><b>${a.stats.findings}</b><span>线索</span></div><div><b>${a.stats.flags}</b><span>Flag候选</span></div></div><div class="toolbar"><input id="file-filter" placeholder="搜索文件名 / 类型" value="${esc(state.fileFilter)}"><span>${files.length} / ${a.files.length}</span></div>${table(['文件','类型','大小','熵','Flag','发现'], files.slice(0,1000).map(f=>[f.path,f.type,fmtBytes(f.size),f.entropy,f.flags.length,f.findings.length]))}<div class="workspace-actions"><button class="button" data-action="export-report">导出报告</button></div>`;
}

async function chooseWorkspace(existing = null) {
  const root = existing || await window.newcyber.chooseWorkspace();
  if (!root) return;
  toast('正在扫描赛题目录…');
  try {
    state.workspace = await window.newcyber.scanWorkspace(root);
    state.fileFilter = '';
    state.view = 'workspace';
    state.tool = null;
    render();
    toast(`已扫描 ${state.workspace.stats.files} 个文件`);
  } catch (error) { toast(error.message || '扫描失败', true); }
}

async function runCurrentTool() {
  const input = document.querySelector('#tool-input')?.value || '';
  const payload = { input };
  if (state.tool === 'codec') {
    payload.operation = document.querySelector('#tool-operation')?.value;
    payload.key = document.querySelector('#tool-key')?.value || '';
  }
  if (state.tool === 'knowledge-search') payload.domain = document.querySelector('#knowledge-domain')?.value || '';
  try {
    state.toolError = null;
    state.toolResult = await window.newcyber.runTool(state.tool, payload);
  } catch (error) {
    state.toolResult = null;
    state.toolError = error.message || String(error);
  }
  const currentTool = state.tool;
  render();
  state.tool = currentTool;
  const inputAgain = document.querySelector('#tool-input');
  if (inputAgain) inputAgain.value = input;
}

function render() {
  let content;
  if (state.tool) content = toolView(state.tool);
  else if (state.view === 'home') content = homeView();
  else if (DOMAINS[state.view]) content = domainView(state.view);
  else if (state.view === 'common') content = commonView();
  else if (state.view === 'knowledge') content = knowledgeView();
  else if (state.view === 'workspace') content = workspaceView();
  else content = homeView();
  app.innerHTML = shell(content);
  bind();
  const scroller = document.querySelector('.content');
  if (scroller) { scroller.scrollTop = 0; scroller.scrollLeft = 0; }
}

function navigate(view) {
  state.view = view;
  state.tool = null;
  state.toolResult = null;
  state.toolError = null;
  render();
}

const AUTO_RUN_TOOLS = new Set(['ai-prompt-injection-suite', 'local-torch-inspect']);

function openTool(tool) {
  state.tool = tool;
  state.toolResult = null;
  state.toolError = null;
  if (TOOL_META[tool]?.domain && DOMAINS[TOOL_META[tool].domain]) state.view = TOOL_META[tool].domain;
  else state.view = TOOL_META[tool]?.domain || 'common';
  render();
  if (AUTO_RUN_TOOLS.has(tool)) {
    window.newcyber.runTool(tool, {}).then((result) => {
      if (state.tool === tool) { state.toolResult = result; render(); }
    }).catch(() => {});
  }
}

function toast(message, error = false) {
  const el = document.querySelector('#toast');
  if (!el) return;
  el.textContent = message;
  el.className = error ? 'show error' : 'show';
  setTimeout(() => { el.className = ''; }, 2600);
}

function bind() {
  document.querySelectorAll('[data-view]').forEach(el => el.addEventListener('click', () => navigate(el.dataset.view)));
  document.querySelectorAll('[data-tool]').forEach(el => el.addEventListener('click', () => openTool(el.dataset.tool)));
  document.querySelectorAll('[data-action="choose-workspace"]').forEach(el => el.addEventListener('click', () => chooseWorkspace()));
  document.querySelectorAll('[data-action="rescan-workspace"]').forEach(el => el.addEventListener('click', () => chooseWorkspace(state.workspace.workspacePath)));
  document.querySelectorAll('[data-action="run-tool"]').forEach(el => el.addEventListener('click', runCurrentTool));
  document.querySelectorAll('[data-action="copy-result"]').forEach(el => el.addEventListener('click', async () => {
    const text = state.toolResult ? JSON.stringify(state.toolResult, null, 2) : '';
    if (text) { await navigator.clipboard.writeText(text); toast('结果已复制'); }
  }));
  document.querySelectorAll('[data-action="export-report"]').forEach(el => el.addEventListener('click', async () => {
    if (!state.workspace) return;
    const notes = localStorage.getItem(`notes:${state.workspace.workspacePath}`) || '';
    const path = await window.newcyber.saveReport({ analysis: state.workspace, notes });
    if (path) toast('报告已导出');
  }));
  const op = document.querySelector('#tool-operation');
  if (op) op.addEventListener('change', () => document.querySelector('#xor-key-field')?.classList.toggle('hidden', op.value !== 'xor-hex'));
  const filter = document.querySelector('#file-filter');
  if (filter) filter.addEventListener('input', e => {
    const cursor = e.target.selectionStart;
    state.fileFilter = e.target.value;
    render();
    const next = document.querySelector('#file-filter');
    next?.focus();
    next?.setSelectionRange(cursor, cursor);
  });
}

render();
