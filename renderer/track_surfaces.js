(() => {
  if (typeof DOMAINS==='undefined'||typeof TOOL_META==='undefined'||typeof toolView!=='function'||typeof domainView!=='function'||typeof renderResult!=='function') return;

  const previousToolView=toolView;
  const previousDomainView=domainView;
  const previousRenderResult=renderResult;
  const drafts=new Map();
  const SPECIAL_FILE_TOOLS=new Set(['ai-model-scan']);

  function key(tool,field){return `${tool}:${field}`;}
  function getDraft(tool,field,fallback=''){return drafts.get(key(tool,field))??fallback;}
  function setDraft(tool,field,value){drafts.set(key(tool,field),value??'');}
  function hidden(tool){return `<textarea id="tool-input" class="track-hidden-input" aria-hidden="true">${esc(getDraft(tool,'payload'))}</textarea>`;}

  function family(tool,meta=TOOL_META[tool]||{}){
    const domain=meta.domain;
    if(domain==='vehicle'){
      if(/can/.test(tool)&&!/uds/.test(tool))return 'can';
      if(/uds|isotp|diagnostic/.test(tool))return 'uds';
      return 'vehicle';
    }
    if(domain==='ai'){
      if(/prompt|injection/.test(tool))return 'prompt';
      if(/adversarial/.test(tool))return 'adversarial';
      if(/privacy|extraction|inversion/.test(tool))return 'privacy';
      if(/dataset|poison|backdoor|tabular/.test(tool))return 'dataset';
      if(/skill-matrix/.test(tool))return 'matrix';
      if(/source|supply|pipeline/.test(tool))return 'pipeline';
      if(/ocr/.test(tool))return 'ocr';
      return 'ai';
    }
    if(domain==='web3'){
      if(/calldata/.test(tool))return 'calldata';
      if(/disasm|evm/.test(tool))return 'evm';
      if(/solana|anchor/.test(tool))return 'solana';
      return 'contract';
    }
    return 'generic';
  }

  function modeChips(items=[]){return `<div class="track-mode-row">${items.map((x,i)=>`<button type="button" class="track-mode ${i===0?'active':''}" data-track-mode>${esc(x)}</button>`).join('')}</div>`;}
  function editor(tool,placeholder='',className=''){
    return `<div class="track-editor-shell ${className}"><div class="track-editor-title"><span>INPUT</span><small>local evidence</small></div><textarea data-track-field="evidence" spellcheck="false" placeholder="${esc(placeholder)}">${esc(getDraft(tool,'evidence'))}</textarea></div>`;
  }

  function canInput(tool,meta){
    return `${modeChips(['Candump','SocketCAN','PCAP text','Event diff'])}<div class="can-bus-strip"><span>TIME</span><span>BUS</span><span>CAN ID</span><span>DLC</span><span>DATA[0..7]</span></div>${editor(tool,meta.placeholder||'(time) can0 123#00112233','can-editor')}`;
  }
  function udsInput(tool,meta){
    return `${modeChips(['0x10 Session','0x22 DID','0x27 SecurityAccess','0x34/36/37 Flash'])}<div class="uds-session-rail"><span>TESTER</span><b>→</b><span>ISO-TP</span><b>→</b><span>ECU</span><em>REQ / RESP / NRC</em></div>${editor(tool,meta.placeholder||'27 01','uds-editor')}`;
  }
  function pipelineInput(tool,meta){
    return `<div class="ai-pipeline-rail"><span>INPUT</span><b>→</b><span>RETRIEVER</span><b>→</b><span>MODEL</span><b>→</b><span>AGENT</span><b>→</b><span>TOOL</span><b>→</b><span>OUTPUT</span></div>${modeChips(['Source','RAG','Agent','Tool boundary','Supply chain'])}${editor(tool,meta.placeholder||'粘贴源码 / requirements / pipeline…','ai-code-editor')}`;
  }
  function promptInput(tool){
    const category=getDraft(tool,'category','direct');
    return `<div class="prompt-lab"><div class="prompt-config"><label><span>Category</span><select data-track-field="category"><option ${category==='direct'?'selected':''}>direct</option><option ${category==='indirect'?'selected':''}>indirect</option><option ${category==='rag'?'selected':''}>rag</option><option ${category==='tool'?'selected':''}>tool</option><option ${category==='secret'?'selected':''}>secret</option><option ${category==='multi-turn'?'selected':''}>multi-turn</option></select></label><label><span>Marker</span><input data-track-field="marker" value="${esc(getDraft(tool,'marker'))}" placeholder="optional marker" /></label><label><span>Canary</span><input data-track-field="canary" value="${esc(getDraft(tool,'canary'))}" placeholder="optional canary" /></label><label class="prompt-toggle"><input type="checkbox" data-track-field="competition" checked /><span>competition pack</span></label></div><div class="prompt-flow"><span>SYSTEM</span><b>+</b><span>USER</span><b>+</b><span>RAG / DOC</span><b>+</b><span>TOOL</span><b>→</b><span>EVALUATOR</span></div></div>`;
  }
  function adversarialInput(tool){
    return `<div class="adv-builder"><div class="adv-meta"><label><span>Norm</span><select data-track-field="norm"><option>linf</option><option>l2</option><option>l1</option><option>l0</option></select></label><label><span>Epsilon</span><input data-track-field="epsilon" value="${esc(getDraft(tool,'epsilon','0.03'))}" /></label><label><span>True label</span><input data-track-field="trueLabel" value="${esc(getDraft(tool,'trueLabel','0'))}" /></label><label><span>Adv prediction</span><input data-track-field="predicted" value="${esc(getDraft(tool,'predicted','1'))}" /></label></div><div class="surface-form-grid"><label class="surface-form-field"><span>Original vector / sample</span><textarea data-track-field="original" placeholder="[0,0,0]">${esc(getDraft(tool,'original'))}</textarea></label><label class="surface-form-field"><span>Adversarial vector / sample</span><textarea data-track-field="adversarial" placeholder="[0.01,0,0]">${esc(getDraft(tool,'adversarial'))}</textarea></label></div></div>`;
  }
  function dataInput(tool,meta,fam){
    const labels=fam==='privacy'?['Member / Non-member','Loss / Confidence','Embedding / Logit','Reconstruction']:['CSV / JSON','Label','Trigger','Control'];
    return `${modeChips(labels)}<div class="data-table-head"><span>ROWS</span><span>FEATURES</span><span>LABEL / OUTPUT</span><span>CONTROL</span></div>${editor(tool,meta.placeholder||'CSV / JSON…','data-editor')}`;
  }
  function matrixInput(tool,meta){return `<div class="matrix-source-grid"><span>ADVERSARIAL</span><span>PRIVACY</span><span>POISON</span><span>BACKDOOR</span><span>EXTRACTION</span><span>INVERSION</span></div>${editor(tool,meta.placeholder||'JSON Bundle / CSV / source…','matrix-editor')}`;}
  function aiGenericInput(tool,meta){return `${modeChips(['Evidence','Config','Transcript'])}${editor(tool,meta.placeholder||'输入 AI 安全证据…','ai-code-editor')}`;}
  function calldataInput(tool){
    return `<div class="tx-builder"><label><span>4-byte Selector</span><input data-track-field="selector" value="${esc(getDraft(tool,'selector'))}" placeholder="0xa9059cbb" maxlength="10" /></label><label><span>ABI words / calldata tail</span><textarea data-track-field="args" spellcheck="false" placeholder="000000… 32-byte words">${esc(getDraft(tool,'args'))}</textarea></label></div><div class="abi-word-guide"><span>selector</span><span>word 0</span><span>word 1</span><span>word 2</span><span>…</span></div>`;
  }
  function evmInput(tool,meta){return `<div class="evm-runtime-rail"><span>PC</span><span>STACK</span><span>MEMORY</span><span>STORAGE</span><span>CALL</span></div>${modeChips(['Runtime bytecode','Dispatcher','Storage','Proxy / Delegatecall'])}${editor(tool,meta.placeholder||'0x60806040…','evm-bytecode-editor')}`;}
  function solanaInput(tool,meta){return `<div class="solana-account-rail"><span>PROGRAM</span><b>→</b><span>ACCOUNTS</span><b>→</b><span>CONSTRAINTS</span><b>→</b><span>CPI</span></div>${modeChips(['Anchor program','Accounts','Seeds / PDA','CPI'])}${editor(tool,meta.placeholder||'use anchor_lang::prelude::*;','contract-editor')}`;}
  function contractInput(tool,meta){return `<div class="contract-call-rail"><span>CALLER</span><b>→</b><span>PROXY</span><b>→</b><span>IMPLEMENTATION</span><b>→</b><span>STORAGE</span><b>↔</b><span>EXTERNAL</span></div>${modeChips(['Source','Call graph','Storage','Auth / Signature'])}${editor(tool,meta.placeholder||'Solidity / bytecode / trace…','contract-editor')}`;}

  function inputFor(tool,meta,fam){
    if(fam==='can')return canInput(tool,meta);
    if(fam==='uds')return udsInput(tool,meta);
    if(fam==='pipeline')return pipelineInput(tool,meta);
    if(fam==='prompt')return promptInput(tool);
    if(fam==='adversarial')return adversarialInput(tool);
    if(fam==='privacy'||fam==='dataset')return dataInput(tool,meta,fam);
    if(fam==='matrix')return matrixInput(tool,meta);
    if(fam==='ai'||fam==='ocr')return aiGenericInput(tool,meta);
    if(fam==='calldata')return calldataInput(tool);
    if(fam==='evm')return evmInput(tool,meta);
    if(fam==='solana')return solanaInput(tool,meta);
    if(fam==='contract')return contractInput(tool,meta);
    return editor(tool,meta.placeholder||'输入…');
  }

  function trackTitle(domain){return {vehicle:'VEHICLE SECURITY',ai:'AI SECURITY',web3:'WEB3 SECURITY'}[domain]||domain.toUpperCase();}
  function surfaceToolView(tool){
    const meta=TOOL_META[tool];
    const fam=family(tool,meta);
    const resultHtml=state.toolError?`<div class="error-box">${esc(state.toolError)}</div>`:state.toolResult?renderResult(tool,state.toolResult):'<div class="surface-result-empty"><span>◇</span><b>等待分析</b><p>结果会按当前工具的对象模型展示。</p></div>';
    return `<div class="page-head tool-head track-page-head"><div><span class="kicker">${trackTitle(meta.domain)} · ${fam.toUpperCase()}</span><h1>${esc(meta.title||tool)}</h1><p>${esc(meta.label||'')}</p></div><button class="button ghost" data-view="${esc(meta.domain)}">返回</button></div><div class="workbench surface-workbench track-workbench ${meta.domain}-surface"><article class="panel input-panel surface-input-panel"><div class="surface-device-bar"><span><i class="surface-led"></i> LOCAL</span><strong>${esc(meta.title||tool)}</strong><span>${fam.toUpperCase()}</span></div>${hidden(tool)}${inputFor(tool,meta,fam)}<div class="run-row surface-run-row"><span>确定性离线分析</span><button class="button primary" data-action="run-tool">分析</button></div></article><article class="panel result-panel surface-result-panel"><div class="result-title"><b>结构化结果</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${resultHtml}</div></article></div>`;
  }

  function domainTools(domain){return (DOMAINS[domain]?.tools||[]).filter((row)=>TOOL_META[row[0]]?.domain===domain);}
  function domainToolCard(row){const [id,title,desc]=row;const fam=family(id,TOOL_META[id]);return `<button class="track-tool-card ${fam}" data-tool="${esc(id)}"><span>${fam.toUpperCase()}</span><strong>${esc(title||TOOL_META[id]?.title||id)}</strong><p>${esc(desc||TOOL_META[id]?.label||'')}</p><em>OPEN</em></button>`;}
  function groupRows(domain,defs){
    const rows=domainTools(domain);const used=new Set();
    const out=defs.map((def)=>{const picked=rows.filter((row)=>def.match(row[0],TOOL_META[row[0]]||{}));picked.forEach((r)=>used.add(r[0]));return {...def,rows:picked};}).filter((g)=>g.rows.length);
    const extra=rows.filter((r)=>!used.has(r[0]));if(extra.length)out.push({title:'其他分析',icon:'EX',rows:extra});return out;
  }

  function vehicleHome(){
    const groups=groupRows('vehicle',[{title:'总线分析',icon:'BUS',match:(id)=>/can/.test(id)},{title:'诊断 / UDS',icon:'DIA',match:(id)=>/uds|isotp|diag/.test(id)}]);
    return `<div class="track-domain-head"><div><span class="kicker">VEHICLE SECURITY WORKBENCH</span><h1>车联网</h1></div><span>${domainTools('vehicle').length} tools</span></div><section class="vehicle-architecture panel"><button data-tool="can-analyze"><span>BUS</span><b>CAN / CANopen</b></button><em>⇄</em><div><span>ECU A</span><span>GATEWAY</span><span>ECU B</span></div><em>⇄</em><button data-tool="uds-decode"><span>DIAG</span><b>UDS / ISO-TP</b></button><small>Tester → Gateway → ECU → Flash</small></section>${trackGroups(groups)}`;
  }
  function aiHome(){
    const groups=groupRows('ai',[{title:'Pipeline / Agent',icon:'PL',match:(id)=>/source|supply|prompt|skill/.test(id)},{title:'Model / Privacy',icon:'MD',match:(id)=>/model|privacy|extraction|inversion|adversarial/.test(id)},{title:'Dataset / Backdoor',icon:'DT',match:(id)=>/dataset|poison|backdoor|tabular/.test(id)}]);
    return `<div class="track-domain-head"><div><span class="kicker">AI SECURITY WORKBENCH</span><h1>AI 安全</h1></div><span>${domainTools('ai').length} tools</span></div><section class="ai-architecture panel"><button data-tool="ai-dataset-security">DATA</button><b>→</b><button data-tool="ai-source-scan">RETRIEVAL</button><b>→</b><button data-tool="ai-model-scan">MODEL</button><b>→</b><button data-tool="ai-prompt-injection-suite">AGENT</button><b>→</b><button data-tool="ai-source-scan">TOOL</button><b>→</b><span>OUTPUT</span><small>Data → Context → Model → Agent → Tool boundary</small></section>${trackGroups(groups)}`;
  }
  function web3Home(){
    const groups=groupRows('web3',[{title:'EVM / ABI',icon:'EV',match:(id)=>/evm|calldata|solidity/.test(id)},{title:'Solana / Anchor',icon:'SO',match:(id)=>/solana|anchor/.test(id)}]);
    return `<div class="track-domain-head"><div><span class="kicker">WEB3 SECURITY WORKBENCH</span><h1>Web3</h1></div><span>${domainTools('web3').length} tools</span></div><section class="web3-architecture panel"><button data-tool="evm-calldata">CALLDATA</button><b>→</b><span>PROXY</span><b>→</b><button data-tool="evm-disasm">IMPLEMENTATION</button><b>→</b><span>STORAGE</span><b>↔</b><span>EXTERNAL CALL</span><small>Selector / Proxy / Storage / Call boundary</small></section>${trackGroups(groups)}`;
  }
  function trackGroups(groups){return `<div class="track-groups">${groups.map((g)=>`<section><div class="track-group-title"><span>${esc(g.icon)}</span><b>${esc(g.title)}</b><small>${g.rows.length}</small></div><div class="track-tool-grid">${g.rows.map(domainToolCard).join('')}</div></section>`).join('')}</div>`;}

  function canVisual(r){
    const ids=(r.ids||[]).slice(0,8);if(!ids.length)return '';
    return `<div class="can-monitor">${ids.map((x)=>{const dlc=Math.max(...(x.dlc||[8]).map(Number));const changed=new Set((x.changingBytes||[]).map(Number));return `<div><span>${esc(x.id)}</span><b>${x.count||0}</b><section>${Array.from({length:Math.min(8,dlc||8)},(_,i)=>`<i class="${changed.has(i)?'hot':''}">${i}</i>`).join('')}</section><small>${x.averageIntervalMs==null?'—':`${esc(x.averageIntervalMs)} ms`}</small></div>`;}).join('')}</div>`;
  }
  function udsVisual(r){const service=r.serviceName||r.service||r.sid||r.serviceId||'UDS';const nrc=r.negativeResponseCode||r.nrc;return `<div class="uds-flow"><span>TESTER</span><b>→</b><span class="active">${esc(service)}</span><b>→</b><span>ECU</span>${nrc!=null?`<em>NRC ${esc(nrc)}</em>`:''}</div>`;}
  function aiRiskVisual(r,fam){
    const findings=r.findings||[];const hi=findings.filter((x)=>x.severity==='high'||x.severity==='critical').length;const med=findings.filter((x)=>x.severity==='medium').length;
    if(fam==='prompt')return `<div class="ai-risk-strip"><span>SYSTEM</span><b>→</b><span>USER</span><b>→</b><span>CONTEXT</span><b>→</b><span>TOOL</span><em>${r.templates?.length||0} templates</em></div>`;
    if(fam==='adversarial')return `<div class="adv-metrics"><span><small>L∞</small><b>${esc(r.norms?.linf??'—')}</b></span><span><small>L2</small><b>${esc(r.norms?.l2??'—')}</b></span><span><small>Budget</small><b>${r.withinBudget==null?'—':r.withinBudget?'PASS':'FAIL'}</b></span><span><small>Verdict</small><b>${esc(r.verdict||'—')}</b></span></div>`;
    return `<div class="ai-risk-strip"><span>INPUT</span><b>→</b><span>MODEL</span><b>→</b><span>OUTPUT</span><em>${hi} high · ${med} medium · ${r.rows??r.samples??'—'} rows</em></div>`;
  }
  function calldataVisual(r){
    const words=r.words||r.arguments||[];return `<div class="calldata-slots"><span class="selector"><small>SELECTOR</small><b>${esc(r.selector||r.functionSelector||'—')}</b></span>${words.slice(0,6).map((w,i)=>`<span><small>WORD ${i}</small><b>${esc(typeof w==='string'?w.slice(0,18):w.hex?.slice(0,18)||w.value??'—')}</b></span>`).join('')}</div>`;
  }
  function evmVisual(r){const ins=(r.instructions||r.ops||[]).slice(0,14);return `<div class="evm-op-flow">${ins.map((x)=>`<span><small>${esc(x.pc??x.offset??'')}</small><b>${esc(x.op||x.name||x.opcode||'OP')}</b></span>`).join('<em>→</em>')||'<span><b>EVM</b></span>'}</div>`;}
  function web3Visual(r,fam){if(fam==='calldata')return calldataVisual(r);if(fam==='evm')return evmVisual(r);return `<div class="contract-graph-mini"><span>CALLER</span><b>→</b><span>PROGRAM</span><b>→</b><span>STATE</span><b>↔</b><span>EXTERNAL</span><em>${r.findings?.length||0} findings</em></div>`;}

  domainView=function trackDomainView(id){if(id==='vehicle')return vehicleHome();if(id==='ai')return aiHome();if(id==='web3')return web3Home();return previousDomainView(id);};
  toolView=function trackToolView(tool){const meta=TOOL_META[tool];if(!meta||!['vehicle','ai','web3'].includes(meta.domain)||SPECIAL_FILE_TOOLS.has(tool))return previousToolView(tool);return surfaceToolView(tool);};
  renderResult=function trackResult(tool,result){const meta=TOOL_META[tool];if(!meta||!['vehicle','ai','web3'].includes(meta.domain))return previousRenderResult(tool,result);const base=previousRenderResult(tool,result);const fam=family(tool,meta);let visual='';if(meta.domain==='vehicle')visual=fam==='can'?canVisual(result||{}):udsVisual(result||{});if(meta.domain==='ai')visual=aiRiskVisual(result||{},fam);if(meta.domain==='web3')visual=web3Visual(result||{},fam);return visual?`<div class="surface-visual-result">${visual}</div>${base}`:base;};

  function parseJsonish(value,fallback){try{return JSON.parse(value);}catch{return fallback;}}
  function sync(tool){
    const meta=TOOL_META[tool];if(!meta||!['vehicle','ai','web3'].includes(meta.domain))return;
    const hiddenEl=document.querySelector('#tool-input');if(!hiddenEl)return;
    const fields={};document.querySelectorAll('[data-track-field]').forEach((el)=>{let value=el.type==='checkbox'?el.checked:el.value;fields[el.dataset.trackField]=value;setDraft(tool,el.dataset.trackField,value);});
    const fam=family(tool,meta);let payload=fields.evidence||'';
    if(fam==='prompt')payload=JSON.stringify({category:fields.category||'direct',competitionOnly:fields.competition!==false,marker:fields.marker||undefined,canary:fields.canary||undefined});
    if(fam==='adversarial')payload=JSON.stringify({original:parseJsonish(fields.original,[]),adversarial:parseJsonish(fields.adversarial,[]),epsilon:Number(fields.epsilon||0.03),norm:fields.norm||'linf',trueLabel:Number(fields.trueLabel||0),predictedAdversarial:Number(fields.predicted||1)});
    if(fam==='calldata')payload=`${fields.selector||''}${String(fields.args||'').replace(/\s+/g,'')}`;
    hiddenEl.value=payload;setDraft(tool,'payload',payload);
  }
  document.addEventListener('input',(e)=>{if(e.target?.matches?.('[data-track-field]'))sync(state.tool);});
  document.addEventListener('change',(e)=>{if(e.target?.matches?.('[data-track-field]'))sync(state.tool);});
  document.addEventListener('click',(e)=>{const mode=e.target.closest?.('[data-track-mode]');if(mode){mode.parentElement?.querySelectorAll('.track-mode').forEach((x)=>x.classList.remove('active'));mode.classList.add('active');}if(e.target.closest?.('[data-action="run-tool"]'))sync(state.tool);},true);

  render();
})();
