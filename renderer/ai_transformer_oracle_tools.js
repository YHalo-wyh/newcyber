(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function') return;
  const TOOL='ai-transformer-oracle';
  let model=null;
  let result=null;
  let busy=false;
  let errorText='';
  let promptText='';
  let tokenIdsText='';
  let candidateText='';
  let maxNewTokens=48;
  let topK=8;

  TOOL_META[TOOL]={domain:'ai',title:'Transformer Oracle / SCA Decode',label:'ONNX + GPT-2 BPE / token ids',placeholder:''};
  if(!(DOMAINS.ai.tools||[]).some((item)=>item[0]===TOOL)){
    DOMAINS.ai.tools.unshift([TOOL,'Transformer Oracle / SCA Decode','从 ONNX I/O 元数据恢复 token/logits/cache 角色，支持 GPT-2 byte BPE、KV-cache 增量解码与 SCA candidate 约束。']);
  }
  const previousToolView=toolView;

  function pill(ok,yes,no){return `<span class="tx-pill ${ok?'ok':'wait'}">${esc(ok?yes:no)}</span>`;}
  function recipe(){return model?.transformer||null;}
  function roleRow(label,item){return `<div><span>${label}</span><b>${item?esc(item.name):'—'}</b><small>${item?.metadata?.type?esc(item.metadata.type):''}</small></div>`;}
  function parseIds(text){
    const raw=String(text||'').trim();
    if(!raw)return null;
    const ids=raw.split(/[\s,]+/).filter(Boolean).map(Number);
    if(!ids.length||ids.some((id)=>!Number.isSafeInteger(id)||id<0))throw new Error('Token IDs 必须是非负整数，用空格或逗号分隔');
    return ids;
  }
  function parseCandidateSteps(text){
    const raw=String(text||'').trim();
    if(!raw)return [];
    const rows=[];
    for(const line of raw.split(/\r?\n/)){
      const cleaned=line.replace(/^\s*(?:step\s*)?\d+\s*[:=]\s*/i,'').trim();
      if(!cleaned){rows.push([]);continue;}
      rows.push(parseIds(cleaned));
    }
    return rows;
  }

  function modelPanel(){
    const r=recipe();
    return `<section class="tx-panel"><header><div><b>MODEL / IO RECIPE</b><span>${model?esc(model.fileName):'NO MODEL'}</span></div>${pill(Boolean(r?.supported),'RECIPE READY','SELECT ONNX')}</header>
      <div class="tx-model-actions"><button class="button primary" data-tx-model ${busy?'disabled':''}>选择 ONNX</button><div><span>Runtime</span><b>${model?.runtime?.available?`ORT ${esc(model.runtime.version||'available')}`:'not available'}</b></div><div><span>Tokenizer</span><b>${model?.tokenizer?.available?`${esc(model.tokenizer.kind)} · ${model.tokenizer.vocabSize}`:'token ids only'}</b></div></div>
      ${r?`<div class="tx-role-grid">${roleRow('TOKEN IDS',r.roles?.inputIds)}${roleRow('ATTENTION',r.roles?.attentionMask)}${roleRow('POSITION',r.roles?.positionIds)}${roleRow('LOGITS',r.roles?.logits)}${roleRow('HIDDEN',r.roles?.hidden)}<div><span>KV CACHE</span><b>${esc(r.cache?.mode||'none')}</b><small>${r.cache?.pairs?.length||0} paired tensors</small></div></div>
      ${r.unknownInputs?.length?`<div class="tx-gap"><b>UNKNOWN REQUIRED INPUTS</b><code>${r.unknownInputs.map((item)=>esc(item.name)).join(' · ')}</code><p>当前自动 recipe 不会猜这些 tensor 的语义；执行时会停在 unknown-input-gap。</p></div>`:''}
      ${r.ambiguities?.length?`<div class="tx-gap"><b>AMBIGUOUS ROLE</b><p>${esc(JSON.stringify(r.ambiguities))}</p></div>`:''}`:'<p class="tx-muted">选择一个显式 ONNX 执行工件。工具只从 session metadata 识别角色，不按 GPT-2 固定名字硬绑。</p>'}
    </section>`;
  }

  function decodePanel(){
    const canText=Boolean(model?.tokenizer?.available);
    return `<section class="tx-panel"><header><div><b>DECODE CONTROLLER</b><span>${model?.transformer?.cache?.mode==='paired'?'KV INCREMENTAL':'FULL REPLAY FALLBACK'}</span></div>${pill(Boolean(model?.transformer?.supported),'READY','WAIT MODEL')}</header>
      <div class="tx-prompt-grid">
        <label><span>PROMPT / PREFIX</span><textarea id="tx-prompt" spellcheck="false" placeholder="${canText?'输入模型前缀文本':'模型同目录无 vocab.json 时请改用 Token IDs'}">${esc(promptText)}</textarea></label>
        <label><span>PROMPT TOKEN IDS</span><textarea id="tx-token-ids" spellcheck="false" placeholder="例如 15496, 11, 995">${esc(tokenIdsText)}</textarea><small>非空时优先于文本 prompt；适合没有 tokenizer 文件的 ONNX。</small></label>
      </div>
      <div class="tx-controls"><label><span>MAX NEW TOKENS</span><input id="tx-max" type="number" min="1" max="256" value="${maxNewTokens}"></label><label><span>TOP K</span><input id="tx-topk" type="number" min="1" max="64" value="${topK}"></label><button class="button primary" data-tx-run ${busy||!model?.transformer?.supported?'disabled':''}>运行本地 Oracle</button></div>
      <label class="tx-candidates"><span>SCA CANDIDATE CONSTRAINT · 每行对应一步</span><textarea id="tx-candidates" spellcheck="false" placeholder="step 0: 42 77 91\nstep 1: 8 11 19">${esc(candidateText)}</textarea><small>若 Power SCA / Probe 已给出候选 token，可只在这些候选上比较 logits；空白时按全 vocab top-k。</small></label>
    </section>`;
  }

  function resultPanel(){
    if(!result)return `<section class="tx-panel tx-empty"><b>ORACLE RESULT</b><p>尚未执行。可靠 cache 配对时复用 KV；没有 cache 时每步重放完整 token 序列，结论相同但更慢。</p></section>`;
    const steps=result.steps||[];
    return `<section class="tx-panel ${result.flag?'solved':''}"><header><div><b>ORACLE RESULT</b><span>${esc(result.status||'unknown')}</span></div>${pill(Boolean(result.flag),'FLAG RECOVERED',result.cacheUsed?'CACHE USED':'NO FLAG')}</header>
      ${result.flag?`<div class="tx-flag"><span>FLAG</span><strong>${esc(result.flag)}</strong><button class="button primary" data-tx-copy>复制</button></div>`:''}
      <div class="tx-result-metrics"><div><span>GENERATED</span><b>${result.generatedTokenIds?.length||0}</b></div><div><span>CACHE</span><b>${result.cacheUsed?'paired':'replay'}</b></div><div><span>STATUS</span><b>${esc(result.status||'—')}</b></div></div>
      ${result.generatedText!=null?`<div class="tx-generated"><span>GENERATED TEXT</span><pre>${esc(result.generatedText)}</pre></div>`:''}
      ${result.gap?`<div class="tx-gap"><b>CAPABILITY GAP</b><code>${esc(result.gap)}</code></div>`:''}
      <div class="tx-step-table"><header><span>STEP</span><span>TOKEN</span><span>TOP CANDIDATES</span></header>${steps.slice(0,256).map((step)=>`<div><i>${step.index}</i><b>${step.tokenId}</b><code>${(step.top||[]).slice(0,6).map((item)=>`${item.id}:${Number(item.logit).toFixed(3)}`).join(' · ')}</code></div>`).join('')}</div>
    </section>`;
  }

  toolView=function transformerOracleView(tool){
    if(tool!==TOOL)return previousToolView(tool);
    return `<div class="page-head tool-head tx-head"><div><span class="kicker">TOKEN → LOGITS → CACHE → VERIFY</span><h1>Transformer Oracle / SCA Decode</h1><p>受限本地 Transformer 前向与逐 token 验证；SCA 只负责缩小候选，最终结果由模型 oracle 复核。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="tx-workbench">${errorText?`<div class="tx-error">${esc(errorText)}</div>`:''}<div class="tx-left">${modelPanel()}${decodePanel()}</div><div class="tx-right">${resultPanel()}</div></div>`;
  };

  document.addEventListener('input',(event)=>{
    if(event.target?.id==='tx-prompt')promptText=event.target.value;
    else if(event.target?.id==='tx-token-ids')tokenIdsText=event.target.value;
    else if(event.target?.id==='tx-candidates')candidateText=event.target.value;
    else if(event.target?.id==='tx-max')maxNewTokens=Math.max(1,Math.min(256,Number(event.target.value)||48));
    else if(event.target?.id==='tx-topk')topK=Math.max(1,Math.min(64,Number(event.target.value)||8));
  });

  document.addEventListener('click',async(event)=>{
    if(event.target.closest('[data-tx-model]')){
      busy=true;errorText='';result=null;render();
      try{model=await window.newcyber.chooseAndInspectOnnxModel('cpu');}
      catch(error){errorText=error?.message||String(error);}finally{busy=false;render();}
      return;
    }
    if(event.target.closest('[data-tx-run]')){
      if(!model?.filePath)return;
      busy=true;errorText='';result=null;render();
      try{
        const promptTokenIds=parseIds(tokenIdsText);
        const candidateTokenIdsByStep=parseCandidateSteps(candidateText);
        result=await window.newcyber.runTransformerOracle({filePath:model.filePath,provider:'cpu',request:{
          ...(promptTokenIds?{promptTokenIds}:{promptText}),maxNewTokens,topK,candidateTokenIdsByStep
        }});
      }catch(error){errorText=error?.message||String(error);}finally{busy=false;render();}
      return;
    }
    if(event.target.closest('[data-tx-copy]')&&result?.flag){
      try{await navigator.clipboard.writeText(result.flag);toast('Flag 已复制');}catch{toast('复制失败',true);}
    }
  });
})();
