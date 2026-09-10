(() => {
  if (typeof DOMAINS==='undefined'||typeof TOOL_META==='undefined'||typeof toolView!=='function'||typeof renderResult!=='function') return;

  const TRANSFORM='ai-transform-replay-verify';
  const TORCH='ai-torchscript-side-effect-verify';
  const PRESSURE='ai-batch52-replay-regression';
  const drafts=new Map();
  const rows=[
    [TRANSFORM,'Prompt Candidate Replay Verifier','绑定 candidateId、原 Prompt、protected marker 与实际模型响应，离线验证编码泄露。'],
    [TORCH,'TorchScript Side-Effect Observation Verifier','绑定源码 Candidate 与受控运行 read/before/after 字节，不执行模型。'],
    [PRESSURE,'Batch52 Replay 压力回归','96 个 candidate binding / provenance / before-after hard cases。']
  ];
  TOOL_META[TRANSFORM]={domain:'ai',title:'Prompt Candidate Replay Verifier',label:'Candidate → observed response → Verified',placeholder:''};
  TOOL_META[TORCH]={domain:'ai',title:'TorchScript Side-Effect Observation Verifier',label:'Static candidate → runtime observation → Verified',placeholder:''};
  TOOL_META[PRESSURE]={domain:'ai',title:'Batch52 Replay 压力回归',label:'96 candidate-bound cases',placeholder:''};
  const existing=new Set((DOMAINS.ai.tools||[]).map((row)=>row[0]));for(const row of rows)if(!existing.has(row[0]))DOMAINS.ai.tools.push(row);

  const previousToolView=toolView,previousRenderResult=renderResult;
  function value(tool,key,fallback=''){return drafts.get(`${tool}:${key}`)??fallback;}
  function area(label,key,val,placeholder='',wide=false){return `<label class="surface-form-field ${wide?'surface-wide-field':''}"><span>${esc(label)}</span><textarea data-b52-field="${esc(key)}" spellcheck="false" placeholder="${esc(placeholder)}">${esc(val)}</textarea></label>`;}
  function shell(tool,kicker,title,desc,body,label='验证观测'){
    const result=state.toolError?`<div class="error-box">${esc(state.toolError)}</div>`:state.toolResult?renderResult(tool,state.toolResult):'<div class="surface-result-empty"><span>◎</span><b>等待运行观测</b><p>只有 Candidate 与观测严格绑定后才允许进入 Verified。</p></div>';
    return `<div class="page-head tool-head surface-page-head"><div><span class="kicker">${esc(kicker)}</span><h1>${esc(title)}</h1><p>${esc(desc)}</p></div><button class="button ghost" data-view="ai">返回</button></div><div class="workbench surface-workbench"><article class="panel input-panel surface-input-panel"><textarea id="tool-input" class="surface-hidden-input" aria-hidden="true">${esc(value(tool,'payload'))}</textarea>${body}<div class="run-row surface-run-row"><span>OFFLINE · CANDIDATE-BOUND · FAIL CLOSED</span><button class="button primary" data-action="run-tool">${esc(label)}</button></div></article><article class="panel result-panel surface-result-panel"><div class="result-title"><b>Replay Verification</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${result}</div></article></div>`;
  }
  function transformPage(){
    const body=`<div class="surface-device-bar"><span><i class="surface-led"></i> REPLAY BINDING</span><strong>PROMPT → RESPONSE</strong><span>NO NETWORK</span></div><div class="surface-form-grid">${area('Candidate JSON','candidate',value(TRANSFORM,'candidate'),'粘贴 Batch51 transform-exfiltration-replay candidate')}${area('原始 Prompt','prompt',value(TRANSFORM,'prompt'),'必须与 Candidate 生成时一致')}${area('实际模型响应','response',value(TRANSFORM,'response'),'粘贴真实/受控 replay 的模型输出')}${area('Protected markers · 每行一个','terms',value(TRANSFORM,'terms'),'dart{\nTRAINING_CANARY',true)}</div><p class="notice">candidateId 会从 Prompt + protected terms 重建后再绑定。直接明文泄露、错误 candidateId、没有实际 response 都不能通过。</p>`;
    return shell(TRANSFORM,'AI · VERIFIED CLOSURE','Prompt Candidate Replay Verifier','把 ai_summarizer 类 Candidate 接到实际响应观测，而不是仅凭攻击 Prompt 升级。',body);
  }
  function torchPage(){
    const body=`<div class="surface-device-bar"><span><i class="surface-led"></i> OBSERVATION ONLY</span><strong>READ → BEFORE / AFTER</strong><span>NO MODEL EXEC</span></div><div class="surface-form-grid">${area('静态源码','source',value(TORCH,'source'),'与 Candidate 对应的 Python/TorchScript 生成或服务源码',true)}${area('Candidate JSON','candidate',value(TORCH,'candidate'),'粘贴 Batch51 torchscript-file-side-effect-chain candidate')}${area('Provenance','provenance',value(TORCH,'provenance','controlled-local-replay'),'controlled-local-replay / challenge-runtime / explicit-user-verified')}${area('Read bytes · Base64','read',value(TORCH,'read'),'受保护源文件观测字节')}${area('Write before · Base64','before',value(TORCH,'before'),'目标文件运行前字节')}${area('Write after · Base64','after',value(TORCH,'after'),'目标文件运行后字节')}${area('Copy length','length',value(TORCH,'length'),'默认取 read bytes 长度')}</div><p class="notice">验证器不会加载 .pt。必须同时满足 source→candidateId 绑定、受信 provenance、目标区等于 read bytes、目标区确实发生变化、区外字节不变。</p>`;
    return shell(TORCH,'AI · VERIFIED CLOSURE','TorchScript Side-Effect Observation Verifier','把 ai_sms 类静态 Candidate 接到受控运行产生的字节级副作用观测。',body);
  }
  function pressurePage(){return shell(PRESSURE,'AI · REPLAY PRESSURE','Batch52 Replay 压力回归','48 个 Prompt replay + 48 个 TorchScript observation cases，专打 Verified 边界。','<div class="surface-device-bar"><span><i class="surface-led"></i> 96 CASES</span><strong>BINDING / PROVENANCE / BYTE DIFF</strong><span>HARD NEGATIVES</span></div><p class="notice">fixture Verified 只证明 verifier 本身能闭环；不会计入 13 道真实 CTF 的 Verified 数。</p>','运行 96-case 回归');}
  function parseJson(text){try{return JSON.parse(String(text||'{}'));}catch{return {};}}
  function sync(tool){
    if(![TRANSFORM,TORCH,PRESSURE].includes(tool))return;const hidden=document.querySelector('#tool-input');if(!hidden)return;
    const fields={};document.querySelectorAll('[data-b52-field]').forEach((el)=>{fields[el.dataset.b52Field]=el.value||'';drafts.set(`${tool}:${el.dataset.b52Field}`,el.value||'');});
    let payload={};
    if(tool===TRANSFORM){const candidate=parseJson(fields.candidate);payload={candidate,candidateId:candidate.candidateId,prompt:fields.prompt||candidate.prompt||'',response:fields.response||'',protectedTerms:String(fields.terms||'').split(/\r?\n/).map((x)=>x.trim()).filter(Boolean)};}
    else if(tool===TORCH){const candidate=parseJson(fields.candidate);payload={source:fields.source||'',candidate,candidateId:candidate.candidateId,provenance:fields.provenance||'',readBytesBase64:fields.read||'',writeBeforeBase64:fields.before||'',writeAfterBase64:fields.after||'',copyLength:fields.length?Number(fields.length):undefined};}
    const serialized=JSON.stringify(payload);hidden.value=serialized;drafts.set(`${tool}:payload`,serialized);
  }
  function checks(obj={}){return Object.entries(obj).map(([k,v])=>`<div><span>${esc(k)}</span><strong>${v===true?'PASS':v===false?'FAIL':esc(String(v??'—'))}</strong></div>`).join('');}
  function replayResult(r){return `<div class="result-stats"><div><b>${r.verified?'VERIFIED':'NOT VERIFIED'}</b><span>Replay</span></div><div><b>${esc(r.verdict||'—')}</b><span>Verdict</span></div><div><b>${esc(r.observationId||'—')}</b><span>Observation</span></div></div>${r.markerHits?.length?`<div class="kv-grid"><div><span>marker hits</span><strong>${esc(r.markerHits.join(', '))}</strong></div><div><span>transform</span><strong>${esc((r.transformChain||[]).join(' → '))}</strong></div></div>`:''}`;}
  function torchResult(r){return `<div class="result-stats"><div><b>${r.verified?'VERIFIED':'NOT VERIFIED'}</b><span>Observation</span></div><div><b>${esc(r.verdict||'—')}</b><span>Verdict</span></div><div><b>${esc(r.provenance||'—')}</b><span>Provenance</span></div></div>${r.checks?`<div class="kv-grid">${checks(r.checks)}</div>`:''}${r.binding?`<pre class="mini-pre">${esc(JSON.stringify(r.binding,null,2))}</pre>`:''}`;}
  function pressureResult(r){const s=r.summary||{};return `<div class="result-stats"><div><b>${s.passed||0}/${s.total||0}</b><span>Replay cases</span></div><div><b>${s.transform?.passed||0}/${s.transform?.total||0}</b><span>Prompt</span></div><div><b>${s.torchscript?.passed||0}/${s.torchscript?.total||0}</b><span>TorchScript</span></div></div><p class="notice">${s.failed?esc(`${s.failed} cases failed`):'全部通过；fixture Verified 不计入真实赛事 Verified。'}</p>`;}

  toolView=function batch52ToolView(tool){if(tool===TRANSFORM)return transformPage();if(tool===TORCH)return torchPage();if(tool===PRESSURE)return pressurePage();return previousToolView(tool);};
  renderResult=function batch52RenderResult(tool,result){if(tool===TRANSFORM)return replayResult(result||{});if(tool===TORCH)return torchResult(result||{});if(tool===PRESSURE)return pressureResult(result||{});return previousRenderResult(tool,result);};
  document.addEventListener('input',(event)=>{if(event.target?.matches?.('[data-b52-field]'))sync(state.tool);});
  document.addEventListener('click',(event)=>{if(event.target.closest?.('[data-action="run-tool"]'))sync(state.tool);},true);
  render();
})();
