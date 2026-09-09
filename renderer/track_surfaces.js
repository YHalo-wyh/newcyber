(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof domainView !== 'function' || typeof renderResult !== 'function') return;

  const baseToolView = toolView;
  const baseDomainView = domainView;
  const baseRenderResult = renderResult;
  const drafts = new Map();
  const preservedFileTools = new Set(['ai-model-scan']);
  const domains = new Set(['vehicle', 'ai', 'web3']);

  const get = (tool, field, fallback = '') => drafts.get(`${tool}:${field}`) ?? fallback;
  const put = (tool, field, value) => drafts.set(`${tool}:${field}`, value ?? '');

  function family(tool, meta = TOOL_META[tool] || {}) {
    if (meta.domain === 'vehicle') return /uds|isotp|diagnostic/i.test(tool) ? 'uds' : /can/i.test(tool) ? 'can' : 'vehicle';
    if (meta.domain === 'ai') {
      if (/prompt|injection/i.test(tool)) return 'prompt';
      if (/adversarial/i.test(tool)) return 'adversarial';
      if (/privacy|extraction|inversion/i.test(tool)) return 'privacy';
      if (/dataset|poison|backdoor|tabular/i.test(tool)) return 'dataset';
      if (/skill-matrix/i.test(tool)) return 'matrix';
      if (/source|supply|pipeline/i.test(tool)) return 'pipeline';
      return 'ai';
    }
    if (meta.domain === 'web3') {
      if (/calldata/i.test(tool)) return 'calldata';
      if (/disasm|evm/i.test(tool)) return 'evm';
      if (/solana|anchor/i.test(tool)) return 'solana';
      return 'contract';
    }
    return 'generic';
  }

  function modes(items) {
    return `<div class="track-mode-row">${items.map((item, i) => `<button type="button" class="track-mode ${i === 0 ? 'active' : ''}" data-track-mode>${esc(item)}</button>`).join('')}</div>`;
  }

  function editor(tool, placeholder, cls = '') {
    return `<div class="track-editor-shell ${cls}"><div class="track-editor-title"><span>INPUT</span><small>LOCAL EVIDENCE</small></div><textarea data-track-field="evidence" spellcheck="false" placeholder="${esc(placeholder || '输入证据…')}">${esc(get(tool, 'evidence'))}</textarea></div>`;
  }

  function vehicleInput(tool, meta, fam) {
    if (fam === 'uds') return `${modes(['0x10 Session', '0x22 DID', '0x27 SecurityAccess', '0x34/36/37 Flash'])}<div class="uds-session-rail"><span>TESTER</span><b>→</b><span>ISO-TP</span><b>→</b><span>ECU</span><em>REQ / RESP / NRC</em></div>${editor(tool, meta.placeholder || '27 01', 'uds-editor')}`;
    return `${modes(['Candump', 'SocketCAN', 'PCAP text', 'Event diff'])}<div class="can-bus-strip"><span>TIME</span><span>BUS</span><span>CAN ID</span><span>DLC</span><span>DATA[0..7]</span></div>${editor(tool, meta.placeholder || '(time) can0 123#00112233', 'can-editor')}`;
  }

  function aiInput(tool, meta, fam) {
    if (fam === 'prompt') return `<div class="prompt-lab"><div class="prompt-config"><label><span>Category</span><select data-track-field="category"><option>direct</option><option>indirect</option><option>rag</option><option>tool</option><option>secret</option><option>multi-turn</option></select></label><label><span>Marker</span><input data-track-field="marker" value="${esc(get(tool, 'marker'))}" placeholder="optional marker" /></label><label><span>Canary</span><input data-track-field="canary" value="${esc(get(tool, 'canary'))}" placeholder="optional canary" /></label><label class="prompt-toggle"><input type="checkbox" data-track-field="competition" checked /><span>competition pack</span></label></div><div class="prompt-flow"><span>SYSTEM</span><b>+</b><span>USER</span><b>+</b><span>RAG / DOC</span><b>+</b><span>TOOL</span><b>→</b><span>EVALUATOR</span></div></div>`;
    if (fam === 'adversarial') return `<div class="adv-builder"><div class="adv-meta"><label><span>Norm</span><select data-track-field="norm"><option>linf</option><option>l2</option><option>l1</option><option>l0</option></select></label><label><span>Epsilon</span><input data-track-field="epsilon" value="${esc(get(tool, 'epsilon', '0.03'))}" /></label><label><span>True label</span><input data-track-field="trueLabel" value="${esc(get(tool, 'trueLabel', '0'))}" /></label><label><span>Adv prediction</span><input data-track-field="predicted" value="${esc(get(tool, 'predicted', '1'))}" /></label></div><div class="surface-form-grid"><label class="surface-form-field"><span>Original</span><textarea data-track-field="original" placeholder="[0,0,0]">${esc(get(tool, 'original'))}</textarea></label><label class="surface-form-field"><span>Adversarial</span><textarea data-track-field="adversarial" placeholder="[0.01,0,0]">${esc(get(tool, 'adversarial'))}</textarea></label></div></div>`;
    if (fam === 'pipeline') return `<div class="ai-pipeline-rail"><span>INPUT</span><b>→</b><span>RETRIEVER</span><b>→</b><span>MODEL</span><b>→</b><span>AGENT</span><b>→</b><span>TOOL</span><b>→</b><span>OUTPUT</span></div>${modes(['Source', 'RAG', 'Agent', 'Tool boundary', 'Supply chain'])}${editor(tool, meta.placeholder || '粘贴源码 / requirements / pipeline…', 'ai-code-editor')}`;
    if (fam === 'matrix') return `<div class="matrix-source-grid"><span>ADVERSARIAL</span><span>PRIVACY</span><span>POISON</span><span>BACKDOOR</span><span>EXTRACTION</span><span>INVERSION</span></div>${editor(tool, meta.placeholder || 'JSON Bundle / CSV / Source…', 'matrix-editor')}`;
    if (fam === 'privacy' || fam === 'dataset') return `${modes(fam === 'privacy' ? ['Member / Non-member', 'Loss / Confidence', 'Embedding / Logit', 'Reconstruction'] : ['CSV / JSON', 'Label', 'Trigger', 'Control'])}<div class="data-table-head"><span>ROWS</span><span>FEATURES</span><span>LABEL / OUTPUT</span><span>CONTROL</span></div>${editor(tool, meta.placeholder || 'CSV / JSON…', 'data-editor')}`;
    return `${modes(['Evidence', 'Config', 'Transcript'])}${editor(tool, meta.placeholder || '输入 AI 安全证据…', 'ai-code-editor')}`;
  }

  function web3Input(tool, meta, fam) {
    if (fam === 'calldata') return `<div class="tx-builder"><label><span>4-byte Selector</span><input data-track-field="selector" value="${esc(get(tool, 'selector'))}" placeholder="0xa9059cbb" maxlength="10" /></label><label><span>ABI words / calldata tail</span><textarea data-track-field="args" spellcheck="false" placeholder="000000… 32-byte words">${esc(get(tool, 'args'))}</textarea></label></div><div class="abi-word-guide"><span>selector</span><span>word 0</span><span>word 1</span><span>word 2</span><span>…</span></div>`;
    if (fam === 'evm') return `<div class="evm-runtime-rail"><span>PC</span><span>STACK</span><span>MEMORY</span><span>STORAGE</span><span>CALL</span></div>${modes(['Runtime bytecode', 'Dispatcher', 'Storage', 'Proxy / Delegatecall'])}${editor(tool, meta.placeholder || '0x60806040…', 'evm-bytecode-editor')}`;
    if (fam === 'solana') return `<div class="solana-account-rail"><span>PROGRAM</span><b>→</b><span>ACCOUNTS</span><b>→</b><span>CONSTRAINTS</span><b>→</b><span>CPI</span></div>${modes(['Anchor program', 'Accounts', 'Seeds / PDA', 'CPI'])}${editor(tool, meta.placeholder || 'use anchor_lang::prelude::*;', 'contract-editor')}`;
    return `<div class="contract-call-rail"><span>CALLER</span><b>→</b><span>PROXY</span><b>→</b><span>IMPLEMENTATION</span><b>→</b><span>STORAGE</span><b>↔</b><span>EXTERNAL</span></div>${modes(['Source', 'Call graph', 'Storage', 'Auth / Signature'])}${editor(tool, meta.placeholder || 'Solidity / bytecode / trace…', 'contract-editor')}`;
  }

  function inputFor(tool, meta, fam) {
    if (meta.domain === 'vehicle') return vehicleInput(tool, meta, fam);
    if (meta.domain === 'ai') return aiInput(tool, meta, fam);
    return web3Input(tool, meta, fam);
  }

  function surfaceToolView(tool) {
    const meta = TOOL_META[tool];
    const fam = family(tool, meta);
    const resultHtml = state.toolError ? `<div class="error-box">${esc(state.toolError)}</div>` : state.toolResult ? renderResult(tool, state.toolResult) : '<div class="surface-result-empty"><span>◇</span><b>等待分析</b><p>结果会按当前工具的对象模型展示。</p></div>';
    const track = {vehicle:'VEHICLE SECURITY', ai:'AI SECURITY', web3:'WEB3 SECURITY'}[meta.domain];
    return `<div class="page-head tool-head track-page-head"><div><span class="kicker">${track} · ${fam.toUpperCase()}</span><h1>${esc(meta.title || tool)}</h1><p>${esc(meta.label || '')}</p></div><button class="button ghost" data-view="${esc(meta.domain)}">返回</button></div><div class="workbench surface-workbench track-workbench ${meta.domain}-surface"><article class="panel input-panel surface-input-panel"><div class="surface-device-bar"><span><i class="surface-led"></i> LOCAL</span><strong>${esc(meta.title || tool)}</strong><span>${fam.toUpperCase()}</span></div><textarea id="tool-input" class="track-hidden-input" aria-hidden="true">${esc(get(tool, 'payload'))}</textarea>${inputFor(tool, meta, fam)}<div class="run-row surface-run-row"><span>确定性离线分析</span><button class="button primary" data-action="run-tool">分析</button></div></article><article class="panel result-panel surface-result-panel"><div class="result-title"><b>结构化结果</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${resultHtml}</div></article></div>`;
  }

  function tools(domain) {
    return (DOMAINS[domain]?.tools || []).filter((row) => TOOL_META[row[0]]?.domain === domain);
  }

  function card(row) {
    const [id, title, desc] = row;
    const fam = family(id, TOOL_META[id]);
    return `<button class="track-tool-card ${fam}" data-tool="${esc(id)}"><span>${fam.toUpperCase()}</span><strong>${esc(title || TOOL_META[id]?.title || id)}</strong><p>${esc(desc || TOOL_META[id]?.label || '')}</p><em>OPEN</em></button>`;
  }

  function grouped(domain, defs) {
    const rows = tools(domain);
    const used = new Set();
    const groups = defs.map((def) => {
      const picked = rows.filter((row) => def.match(row[0]));
      picked.forEach((row) => used.add(row[0]));
      return {...def, rows:picked};
    }).filter((group) => group.rows.length);
    const rest = rows.filter((row) => !used.has(row[0]));
    if (rest.length) groups.push({title:'其他分析', icon:'EX', rows:rest});
    return `<div class="track-groups">${groups.map((group) => `<section><div class="track-group-title"><span>${esc(group.icon)}</span><b>${esc(group.title)}</b><small>${group.rows.length}</small></div><div class="track-tool-grid">${group.rows.map(card).join('')}</div></section>`).join('')}</div>`;
  }

  function vehicleHome() {
    return `<div class="track-domain-head"><div><span class="kicker">VEHICLE SECURITY WORKBENCH</span><h1>车联网</h1></div><span>${tools('vehicle').length} tools</span></div><section class="vehicle-architecture panel"><button data-tool="can-analyze"><span>BUS</span><b>CAN / CANopen</b></button><em>⇄</em><div><span>ECU A</span><span>GATEWAY</span><span>ECU B</span></div><em>⇄</em><button data-tool="uds-decode"><span>DIAG</span><b>UDS / ISO-TP</b></button><small>Tester → Gateway → ECU → Flash</small></section>${grouped('vehicle', [{title:'总线分析',icon:'BUS',match:(id)=>/can/i.test(id)}, {title:'诊断 / UDS',icon:'DIA',match:(id)=>/uds|isotp|diag/i.test(id)}])}`;
  }

  function aiHome() {
    return `<div class="track-domain-head"><div><span class="kicker">AI SECURITY WORKBENCH</span><h1>AI 安全</h1></div><span>${tools('ai').length} tools</span></div><section class="ai-architecture panel"><button data-tool="ai-dataset-security">DATA</button><b>→</b><button data-tool="ai-source-scan">RETRIEVAL</button><b>→</b><button data-tool="ai-model-scan">MODEL</button><b>→</b><button data-tool="ai-prompt-injection-suite">AGENT</button><b>→</b><button data-tool="ai-source-scan">TOOL</button><b>→</b><span>OUTPUT</span><small>Data → Context → Model → Agent → Tool boundary</small></section>${grouped('ai', [{title:'Pipeline / Agent',icon:'PL',match:(id)=>/source|supply|prompt|skill/i.test(id)}, {title:'Model / Privacy',icon:'MD',match:(id)=>/model|privacy|extraction|inversion|adversarial/i.test(id)}, {title:'Dataset / Backdoor',icon:'DT',match:(id)=>/dataset|poison|backdoor|tabular/i.test(id)}])}`;
  }

  function web3Home() {
    return `<div class="track-domain-head"><div><span class="kicker">WEB3 SECURITY WORKBENCH</span><h1>Web3</h1></div><span>${tools('web3').length} tools</span></div><section class="web3-architecture panel"><button data-tool="evm-calldata">CALLDATA</button><b>→</b><span>PROXY</span><b>→</b><button data-tool="evm-disasm">IMPLEMENTATION</button><b>→</b><span>STORAGE</span><b>↔</b><span>EXTERNAL CALL</span><small>Selector / Proxy / Storage / Call boundary</small></section>${grouped('web3', [{title:'EVM / ABI',icon:'EV',match:(id)=>/evm|calldata|solidity/i.test(id)}, {title:'Solana / Anchor',icon:'SO',match:(id)=>/solana|anchor/i.test(id)}])}`;
  }

  function canVisual(result) {
    const ids = (result.ids || []).slice(0, 8);
    if (!ids.length) return '';
    return `<div class="can-monitor">${ids.map((item) => { const changed = new Set((item.changingBytes || []).map(Number)); const dlc = Math.min(8, Math.max(...(item.dlc || [8]).map(Number))); return `<div><span>${esc(item.id)}</span><b>${item.count || 0}</b><section>${Array.from({length:dlc || 8}, (_, i) => `<i class="${changed.has(i) ? 'hot' : ''}">${i}</i>`).join('')}</section><small>${item.averageIntervalMs == null ? '—' : `${esc(item.averageIntervalMs)} ms`}</small></div>`; }).join('')}</div>`;
  }

  function udsVisual(result) {
    const service = result.serviceName || result.service || result.sid || result.serviceId || 'UDS';
    const nrc = result.negativeResponseCode ?? result.nrc;
    return `<div class="uds-flow"><span>TESTER</span><b>→</b><span class="active">${esc(service)}</span><b>→</b><span>ECU</span>${nrc != null ? `<em>NRC ${esc(nrc)}</em>` : ''}</div>`;
  }

  function aiVisual(result, fam) {
    if (fam === 'prompt') return `<div class="ai-risk-strip"><span>SYSTEM</span><b>→</b><span>USER</span><b>→</b><span>CONTEXT</span><b>→</b><span>TOOL</span><em>${result.templates?.length || 0} templates</em></div>`;
    if (fam === 'adversarial') return `<div class="adv-metrics"><span><small>L∞</small><b>${esc(result.norms?.linf ?? '—')}</b></span><span><small>L2</small><b>${esc(result.norms?.l2 ?? '—')}</b></span><span><small>Budget</small><b>${result.withinBudget == null ? '—' : result.withinBudget ? 'PASS' : 'FAIL'}</b></span><span><small>Verdict</small><b>${esc(result.verdict || '—')}</b></span></div>`;
    const findings = result.findings || [];
    const high = findings.filter((item) => ['high','critical'].includes(item.severity)).length;
    return `<div class="ai-risk-strip"><span>INPUT</span><b>→</b><span>MODEL</span><b>→</b><span>OUTPUT</span><em>${high} high · ${result.rows ?? result.samples ?? '—'} rows</em></div>`;
  }

  function web3Visual(result, fam) {
    if (fam === 'calldata') {
      const words = result.words || result.arguments || [];
      return `<div class="calldata-slots"><span class="selector"><small>SELECTOR</small><b>${esc(result.selector || result.functionSelector || '—')}</b></span>${words.slice(0, 6).map((word, i) => { const value = typeof word === 'string' ? word : (word.hex || word.value || '—'); return `<span><small>WORD ${i}</small><b>${esc(String(value).slice(0, 18))}</b></span>`; }).join('')}</div>`;
    }
    if (fam === 'evm') {
      const ops = (result.instructions || result.ops || []).slice(0, 14);
      return `<div class="evm-op-flow">${ops.map((op) => `<span><small>${esc(op.pc ?? op.offset ?? '')}</small><b>${esc(op.op || op.name || op.opcode || 'OP')}</b></span>`).join('<em>→</em>') || '<span><b>EVM</b></span>'}</div>`;
    }
    return `<div class="contract-graph-mini"><span>CALLER</span><b>→</b><span>PROGRAM</span><b>→</b><span>STATE</span><b>↔</b><span>EXTERNAL</span><em>${result.findings?.length || 0} findings</em></div>`;
  }

  domainView = function trackDomainView(id) {
    if (id === 'vehicle') return vehicleHome();
    if (id === 'ai') return aiHome();
    if (id === 'web3') return web3Home();
    return baseDomainView(id);
  };

  toolView = function trackToolView(tool) {
    const meta = TOOL_META[tool];
    if (!meta || !domains.has(meta.domain) || preservedFileTools.has(tool)) return baseToolView(tool);
    return surfaceToolView(tool);
  };

  renderResult = function trackRenderResult(tool, result) {
    const meta = TOOL_META[tool];
    if (!meta || !domains.has(meta.domain)) return baseRenderResult(tool, result);
    const base = baseRenderResult(tool, result);
    const fam = family(tool, meta);
    const visual = meta.domain === 'vehicle' ? (fam === 'can' ? canVisual(result || {}) : udsVisual(result || {})) : meta.domain === 'ai' ? aiVisual(result || {}, fam) : web3Visual(result || {}, fam);
    return visual ? `<div class="surface-visual-result">${visual}</div>${base}` : base;
  };

  function parseJson(value, fallback) { try { return JSON.parse(value); } catch { return fallback; } }

  function sync(tool) {
    const meta = TOOL_META[tool];
    if (!meta || !domains.has(meta.domain)) return;
    const hiddenEl = document.querySelector('#tool-input');
    if (!hiddenEl) return;
    const fields = {};
    document.querySelectorAll('[data-track-field]').forEach((el) => {
      const value = el.type === 'checkbox' ? el.checked : el.value;
      fields[el.dataset.trackField] = value;
      put(tool, el.dataset.trackField, value);
    });
    const fam = family(tool, meta);
    let payload = fields.evidence || '';
    if (fam === 'prompt') payload = JSON.stringify({category:fields.category || 'direct', competitionOnly:fields.competition !== false, marker:fields.marker || undefined, canary:fields.canary || undefined});
    if (fam === 'adversarial') payload = JSON.stringify({original:parseJson(fields.original, []), adversarial:parseJson(fields.adversarial, []), epsilon:Number(fields.epsilon || 0.03), norm:fields.norm || 'linf', trueLabel:Number(fields.trueLabel || 0), predictedAdversarial:Number(fields.predicted || 1)});
    if (fam === 'calldata') payload = `${fields.selector || ''}${String(fields.args || '').replace(/\s+/g, '')}`;
    hiddenEl.value = payload;
    put(tool, 'payload', payload);
  }

  document.addEventListener('input', (event) => { if (event.target?.matches?.('[data-track-field]')) sync(state.tool); });
  document.addEventListener('change', (event) => { if (event.target?.matches?.('[data-track-field]')) sync(state.tool); });
  document.addEventListener('click', (event) => {
    const mode = event.target.closest?.('[data-track-mode]');
    if (mode) { mode.parentElement?.querySelectorAll('.track-mode').forEach((el) => el.classList.remove('active')); mode.classList.add('active'); }
    if (event.target.closest?.('[data-action="run-tool"]')) sync(state.tool);
  }, true);

  render();
})();
