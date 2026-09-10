(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof renderResult !== 'function') return;

  const TOOL='ai-backdoor-patch-runtime-verify';
  const PATCH_TOOL='ai-backdoor-patch-candidate';
  const drafts=new Map();
  let lastCandidate=null;

  TOOL_META[TOOL]={
    domain:'ai',
    title:'后门 Candidate Runtime Verifier',
    label:'Candidate + ONNX + clean samples + trigger/control + preprocessing',
    placeholder:''
  };
  if (!(DOMAINS.ai.tools||[]).some((row)=>row[0]===TOOL)) {
    DOMAINS.ai.tools.push([TOOL,'后门 Candidate Runtime Verifier','把具体 patch Candidate 绑定本地 ONNX、trigger 内容和 preprocessing，实际生成 clean/triggered/control observations 后复验。']);
  }

  const previousToolView=toolView;
  const previousRenderResult=renderResult;

  function key(field){return `${TOOL}:${field}`;}
  function get(field,fallback=''){return drafts.get(key(field))??fallback;}
  function field(label,name,value,placeholder='',wide=false){
    return `<label class="surface-form-field ${wide?'surface-wide-field':''}"><span>${esc(label)}</span><textarea data-b49-field="${esc(name)}" spellcheck="false" placeholder="${esc(placeholder)}">${esc(value)}</textarea></label>`;
  }
  function input(label,name,value,placeholder=''){
    return `<label class="surface-form-field"><span>${esc(label)}</span><input data-b49-field="${esc(name)}" value="${esc(value)}" spellcheck="false" placeholder="${esc(placeholder)}" /></label>`;
  }

  function page(){
    const resultHtml=state.toolError
      ? `<div class="error-box">${esc(state.toolError)}</div>`
      : state.toolResult
        ? renderResult(TOOL,state.toolResult)
        : '<div class="surface-result-empty"><span>◇</span><b>等待 Runtime Evidence</b><p>只有真实 ONNX 执行产生的三路 observations 通过 candidate verifier，才会显示 Runtime Verified。</p></div>';
    const preprocessDefault=`{"layout":"NCHW","channels":3,"scale":0.00392156862745098,"mean":[0,0,0],"std":[1,1,1],"source":"challenge-source"}`;
    return `<div class="page-head tool-head surface-page-head"><div><span class="kicker">AI · CANDIDATE-BOUND RUNTIME</span><h1>后门 Candidate Runtime Verifier</h1><p>同一 ONNX session 对同一批样本实际跑 clean / triggered / control；candidateId、模型、trigger 内容和 preprocessing 一起绑定。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="workbench surface-workbench"><article class="panel input-panel surface-input-panel">
        <textarea id="tool-input" class="surface-hidden-input" aria-hidden="true">${esc(get('payload'))}</textarea>
        <div class="surface-device-bar"><span><i class="surface-led"></i> LOCAL ONNX</span><strong>RUNTIME BINDING</strong><span>MAX 64 SAMPLES</span></div>
        <div class="surface-form-grid">
          ${field('Candidate JSON','candidate',get('candidate'),'Candidate Generator 输出的 candidateObject')}
          ${input('candidateId','candidateId',get('candidateId'),'patch-...')}
          ${input('ONNX model path','modelPath',get('modelPath'),'D:\\challenge\\model.onnx')}
          ${input('Input name · 单输入可留空','inputName',get('inputName'),'input')}
          ${input('Output name · 单输出可留空','outputName',get('outputName'),'logits')}
          ${field('Preprocessing JSON','preprocess',get('preprocess',preprocessDefault),'必须显式 layout / scale / mean / std / source')}
          ${field('Trigger source raster JSON','triggerSourceRaster',get('triggerSourceRaster'),'包含当前 candidate bbox 对应真实 trigger 的完整 raster')}
          ${field('Control patch JSON','controlPatch',get('controlPatch'),'与 candidate bbox 同宽高；不会自动生成 control')}
          ${field('Clean sample bundle JSON','samples',get('samples'),'[{"trueLabel":2,"raster":{"width":32,"height":32,"channels":4,"data":[...]}}]',true)}
        </div>
        <p class="notice">preprocessing 的 source 只有 challenge-source / model-config / official-writeup / explicit-user-verified 才能升级 Verified。缺 control、多输入歧义、candidateId 不匹配都会 fail closed。</p>
        <div class="run-row surface-run-row"><span>LOCAL ONNX · CPU DEFAULT · BOUNDED · NO TRIGGER SEARCH</span><button class="button primary" data-action="run-tool">执行 Runtime 闭环</button></div>
      </article><article class="panel result-panel surface-result-panel"><div class="result-title"><b>Runtime Transaction</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${resultHtml}</div></article></div>`;
  }

  function parseJson(value,fallback={}){
    const text=String(value||'').trim();
    if(!text)return fallback;
    try{return JSON.parse(text);}catch{return fallback;}
  }

  function sync(){
    if(state.tool!==TOOL)return;
    const hidden=document.querySelector('#tool-input');
    if(!hidden)return;
    const fields={};
    document.querySelectorAll('[data-b49-field]').forEach((el)=>{
      fields[el.dataset.b49Field]=el.value||'';
      drafts.set(key(el.dataset.b49Field),el.value||'');
    });
    const payload={
      candidate:parseJson(fields.candidate,{}),
      candidateId:String(fields.candidateId||'').trim(),
      modelPath:String(fields.modelPath||'').trim(),
      inputName:String(fields.inputName||'').trim()||undefined,
      outputName:String(fields.outputName||'').trim()||undefined,
      preprocess:parseJson(fields.preprocess,{}),
      triggerSourceRaster:parseJson(fields.triggerSourceRaster,{}),
      controlPatch:parseJson(fields.controlPatch,null),
      samples:parseJson(fields.samples,[])
    };
    const serialized=JSON.stringify(payload);
    hidden.value=serialized;
    drafts.set(key('payload'),serialized);
  }

  function num(value){return Number.isFinite(Number(value))?Number(value).toFixed(4):'—';}
  function resultView(r){
    const v=r.verifier||{};
    const m=v.metrics||{};
    return `<div class="result-stats">
      <div><b>${r.verified?'RUNTIME VERIFIED':'NOT VERIFIED'}</b><span>状态</span></div>
      <div><b>${r.execution?.samples??0}</b><span>Samples</span></div>
      <div><b>${num(m.targetASR)}</b><span>Target ASR</span></div>
      <div><b>${num(m.controlTargetRate)}</b><span>Control</span></div>
    </div>
    ${r.gap?`<div class="mlrt-gap"><b>${esc(r.gap.code||'GAP')}</b><p>${esc(r.gap.detail||'')}</p></div>`:''}
    ${r.runtimeBindingId?`<div class="kv-grid"><div><span>Candidate ID</span><strong>${esc(r.candidateId||'—')}</strong></div><div><span>Runtime Binding</span><strong>${esc(r.runtimeBindingId)}</strong></div><div><span>Model SHA-256</span><strong>${esc(r.model?.sha256||'—')}</strong></div><div><span>Trigger SHA-256</span><strong>${esc(r.triggerMaterial?.sha256||'—')}</strong></div><div><span>Preprocess SHA-256</span><strong>${esc(r.preprocess?.sha256||'—')}</strong></div><div><span>Preprocess source</span><strong>${esc(r.preprocess?.source||'—')} · ${r.preprocess?.trusted?'trusted':'not eligible'}</strong></div></div>`:''}
    ${v.checks?`<details class="panel" open><summary><b>Verifier checks</b></summary><pre class="mini-pre">${esc(JSON.stringify(v.checks,null,2))}</pre></details>`:''}
    ${r.observations?.rows?.length?`<details class="panel"><summary><b>Runtime observations · ${r.observations.rows.length}</b></summary><pre class="mini-pre">${esc(JSON.stringify(r.observations.rows.slice(0,64),null,2))}</pre></details>`:''}
    ${(r.notes||[]).map((x)=>`<p class="notice">${esc(x)}</p>`).join('')}`;
  }

  toolView=function batch49ToolView(tool){
    if(tool===TOOL)return page();
    return previousToolView(tool);
  };

  renderResult=function batch49RenderResult(tool,result){
    if(tool===TOOL)return resultView(result||{});
    const base=previousRenderResult(tool,result);
    if(tool===PATCH_TOOL && result?.candidateObject){
      lastCandidate=result.candidateObject;
      return `${base}<div class="run-row"><span>已有具体 candidateId，可进入真实模型闭环</span><button class="button primary" data-b49-runtime-from-candidate>Runtime 闭环 →</button></div>`;
    }
    return base;
  };

  document.addEventListener('input',(event)=>{
    if(event.target?.matches?.('[data-b49-field]'))sync();
  });
  document.addEventListener('click',(event)=>{
    if(event.target.closest?.('[data-action="run-tool"]'))sync();
    if(event.target.closest?.('[data-b49-runtime-from-candidate]')&&lastCandidate){
      drafts.set(key('candidate'),JSON.stringify(lastCandidate,null,2));
      drafts.set(key('candidateId'),String(lastCandidate.candidateId||''));
      openTool(TOOL);
    }
  },true);

  render();
})();
