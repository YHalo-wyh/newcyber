(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function') return;
  const TOOL='ai-local-model-runtime';
  let runtime=null;
  let converter=null;
  let plan=null;
  let conversion=null;
  let busy='';
  let errorText='';
  let autoLoadStarted=false;

  TOOL_META[TOOL]={domain:'ai',title:'Local Model Runtime',label:'Runtime bundle / HF model directory',placeholder:''};
  if(!(DOMAINS.ai.tools||[]).some((item)=>item[0]===TOOL)){
    const list=DOMAINS.ai.tools||[];
    const index=Math.min(1,list.length);
    list.splice(index,0,[TOOL,'Local Model Runtime','离线 ONNX Runtime + SafeTensors 审计、可信转换与 ORT 验证。']);
  }
  const previousToolView=toolView;

  function badge(ok,label){return `<span class="mlrt-badge ${ok?'ok':'gap'}">${esc(label)}</span>`;}
  function shortHash(value){const text=String(value||'');return text.length>18?`${text.slice(0,12)}…${text.slice(-6)}`:text||'—';}
  function tail(value,limit=5000){const text=String(value||'');return text.length>limit?`…${text.slice(-limit)}`:text;}

  function runtimePanel(){
    const available=Boolean(runtime?.available);
    return `<section class="mlrt-panel"><header><div><b>ONNX RUNTIME</b><span>MAIN PROCESS / NATIVE</span></div>${runtime?badge(available,available?'READY':'MISSING'):badge(false,'NOT CHECKED')}</header>
      <div class="mlrt-runtime-grid">
        <div><span>PACKAGE</span><b>${esc(runtime?.package||'onnxruntime-node')}</b><small>pinned ${esc(runtime?.pinnedVersion||'1.29.0')}</small></div>
        <div><span>VERSION</span><b>${esc(runtime?.version||'—')}</b><small>${esc(runtime?.source||'not resolved')}</small></div>
        <div><span>PLATFORM</span><b>${esc(runtime?`${runtime.platform}/${runtime.arch}`:'—')}</b><small>native ABI boundary</small></div>
        <div><span>PROVIDERS</span><b>${esc((runtime?.providers||[]).join(' · ')||'—')}</b><small>default CPU</small></div>
      </div>
      ${runtime?.bundleRoot?`<div class="mlrt-path"><span>VERIFIED BUNDLE</span><code>${esc(runtime.bundleRoot)}</code></div>`:''}
      ${runtime?.error?`<div class="mlrt-gap"><b>RUNTIME GAP</b><p>${esc(runtime.error)}</p></div>`:''}
      <div class="mlrt-actions"><button class="button primary" data-mlrt-runtime-select ${busy?'disabled':''}>选择 Runtime Bundle</button><button class="button ghost" data-mlrt-runtime-refresh ${busy?'disabled':''}>重新检测</button></div>
      <div class="mlrt-note"><b>赛前准备</b><code>npm run runtime:prepare</code><p>比赛执行阶段从已验证 bundle / app resources / 本地 node_modules 加载；renderer 不加载原生 runtime。</p></div>
    </section>`;
  }

  function converterPanel(){
    const selected=Boolean(converter?.selected);
    return `<section class="mlrt-panel mlrt-converter"><header><div><b>TRUSTED CONVERTER</b><span>EXPLICIT SELECTION / SHA-256 PIN</span></div>${badge(selected,selected?'SELECTED':'NOT SELECTED')}</header>
      ${selected?`<div class="mlrt-converter-facts">
        <div><span>EXECUTABLE</span><code>${esc(converter.filePath||'—')}</code></div>
        <div><span>SHA-256</span><code title="${esc(converter.sha256||'')}">${esc(shortHash(converter.sha256))}</code></div>
        <div><span>SIZE</span><b>${Number(converter.bytes||0).toLocaleString()} B</b></div>
        <div><span>TRUST</span><b>USER SELECTED</b></div>
      </div>`:`<div class="mlrt-empty"><b>未批准外部转换器</b><p>选择本机已有的 optimum-cli。主进程会记录路径、大小与 SHA-256，并在每次执行前重新校验。</p></div>`}
      <div class="mlrt-actions"><button class="button primary" data-mlrt-converter-select ${busy?'disabled':''}>${selected?'重新选择 optimum-cli':'选择 optimum-cli'}</button></div>
      <div class="mlrt-note"><b>进程边界</b><p>固定 shell=false；cwd 使用 converter 自身目录；清除 PYTHONPATH/代理并设置 HuggingFace offline env。这里是进程级离线策略，不宣称提供 OS 网络沙箱。</p></div>
    </section>`;
  }

  function modelFacts(){
    const bundle=plan?.bundle;
    if(!bundle)return `<div class="mlrt-empty"><b>尚未选择模型目录</b><p>选择包含 config.json 与 SafeTensors 的本地 HuggingFace 模型目录。只读 header，不执行仓库 Python。</p></div>`;
    const cfg=bundle.config;
    return `<div class="mlrt-model-facts">
      <div><span>MODEL TYPE</span><b>${esc(cfg?.modelType||'—')}</b></div>
      <div><span>ARCHITECTURE</span><b>${esc((cfg?.architectures||[]).join(' · ')||'—')}</b></div>
      <div><span>SHARDS</span><b>${bundle.shardCount||0}</b></div>
      <div><span>TENSORS</span><b>${bundle.tensorCount||0}</b></div>
      <div><span>WEIGHT SIZE</span><b>${bundle.modelBytes?`${(bundle.modelBytes/1024/1024).toFixed(1)} MiB`:'—'}</b></div>
      <div><span>TOKENIZER</span><b>${esc((bundle.tokenizerFiles||[]).join(' · ')||'—')}</b></div>
    </div>`;
  }

  function shardTable(){
    const shards=plan?.bundle?.safetensors||[];
    if(!shards.length)return '';
    return `<div class="mlrt-shards"><header><span>SAFETENSORS</span><span>HEADER / PAYLOAD</span><span>STATE</span></header>${shards.slice(0,32).map((item)=>`<div><b>${esc(item.fileName||'—')}</b><code>${item.headerBytes||0} B / ${item.payloadBytes||0} B · ${item.tensorCount||0} tensors</code>${badge(Boolean(item.valid),item.valid?'VALID':'INVALID')}</div>`).join('')}${shards.length>32?`<p>另有 ${shards.length-32} 个 shard；planner 已全部校验 header。</p>`:''}</div>`;
  }

  function conversionView(){
    if(!conversion)return '';
    const ok=conversion.status==='converted';
    const selected=conversion.selected;
    const process=conversion.process;
    const transformer=selected?.transformer;
    const gap=conversion.gap;
    return `<div class="mlrt-conversion ${ok?'ok':'gap'}">
      <div class="mlrt-conversion-head"><div><span>CONVERSION RESULT</span><b>${esc(String(conversion.status||'unknown').toUpperCase())}</b></div>${badge(ok,ok?'ORT VERIFIED':'GAP')}</div>
      ${gap?`<div class="mlrt-gap"><span>${esc(gap.code||'GAP')}</span><p>${esc(gap.detail||'')}</p></div>`:''}
      ${process?`<div class="mlrt-process-grid"><div><span>PROCESS</span><b>${esc(process.status||'—')}</b></div><div><span>EXIT</span><b>${process.code==null?'—':esc(process.code)}</b></div><div><span>SHELL</span><b>${process.shell===false?'FALSE':'—'}</b></div><div><span>NETWORK</span><b>OFFLINE ENV</b></div></div>`:''}
      ${selected?`<div class="mlrt-selected"><span>SELECTED ONNX</span><b>${esc(selected.fileName||'—')}</b><code>${esc(selected.filePath||'—')}</code><small>sha256 ${esc(shortHash(selected.sha256))} · score ${selected.score??'—'}</small></div>
        <div class="mlrt-process-grid"><div><span>TRANSFORMER</span><b>${transformer?.supported?'SUPPORTED':'GAP'}</b></div><div><span>HIDDEN</span><b>${esc(transformer?.roles?.hidden?.name||'—')}</b></div><div><span>CACHE</span><b>${esc(transformer?.cache?.mode||'—')}</b></div><div><span>UNKNOWN INPUTS</span><b>${transformer?.unknownInputs?.length??'—'}</b></div></div>`:''}
      ${conversion.manifestPath?`<div class="mlrt-path"><span>PROVENANCE</span><code>${esc(conversion.manifestPath)}</code></div>`:''}
      ${(process?.stdout||process?.stderr)?`<details class="mlrt-log"><summary>Converter log · bounded ${Number(process.maxOutputBytes||0).toLocaleString()} B</summary><pre>${esc(tail([process.stdout,process.stderr].filter(Boolean).join('\n--- stderr ---\n')))}</pre></details>`:''}
    </div>`;
  }

  function planPanel(){
    const ready=plan?.status==='ready';
    const gap=plan?.gap;
    const argv=ready?[plan.converter.executable,...(plan.converter.args||[])]:null;
    const canExecute=ready&&converter?.selected&&runtime?.available&&conversion?.status!=='converted';
    return `<section class="mlrt-panel"><header><div><b>HF / SAFETENSORS → ONNX</b><span>AUDIT → TRUSTED EXECUTION → ORT VERIFY</span></div>${plan?badge(ready,ready?'READY':'GAP'):badge(false,'WAITING')}</header>
      ${modelFacts()}
      ${shardTable()}
      ${gap?`<div class="mlrt-gap"><span>${esc(gap.code||'GAP')}</span><p>${esc(gap.detail||'')}</p></div>`:''}
      ${ready?`<div class="mlrt-export-plan">
        <div class="mlrt-task"><span>OPTIMUM TASK</span><b>${esc(plan.task?.task||'—')}</b><small>${esc(plan.task?.source||'')}</small></div>
        <div class="mlrt-path"><span>OUTPUT · MUST NOT EXIST</span><code>${esc(plan.output?.directory||'—')}</code></div>
        <div class="mlrt-env"><span>OFFLINE ENV</span><code>HF_HUB_OFFLINE=1 · TRANSFORMERS_OFFLINE=1 · PYTHONSAFEPATH=1 · proxies cleared</code></div>
        <div class="mlrt-argv"><span>ARGV · shell=false</span><pre>${esc(JSON.stringify(argv,null,2))}</pre><button class="button ghost" data-mlrt-copy-argv>复制 argv</button></div>
      </div>`:''}
      ${conversionView()}
      <div class="mlrt-actions"><button class="button primary" data-mlrt-hf-plan ${busy?'disabled':''}>选择本地模型目录</button>${plan?`<button class="button ghost" data-mlrt-hf-save ${busy?'disabled':''}>保存转换清单</button>`:''}${canExecute?`<button class="button primary" data-mlrt-hf-execute ${busy?'disabled':''}>执行可信转换并验证</button>`:''}</div>
      <div class="mlrt-note"><b>执行边界</b><p>模型目录若出现 Python/native 代码、pickle/PyTorch .bin/.pt/.pth 等不安全权重或符号链接，会在 spawn 前停止。config.auto_map 仍直接返回 REMOTE_CODE_GAP。</p></div>
    </section>`;
  }

  async function refreshPreflight(){
    if(busy)return;
    busy='preflight';errorText='';render();
    try{
      const values=await Promise.all([window.newcyber.getLocalMlRuntimeStatus(),window.newcyber.getTrustedHfConverterStatus()]);
      runtime=values[0];converter=values[1];
    }catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
  }

  toolView=function localModelRuntimeView(tool){
    if(tool!==TOOL)return previousToolView(tool);
    if(!autoLoadStarted){autoLoadStarted=true;setTimeout(()=>refreshPreflight(),0);}
    return `<div class="page-head tool-head mlrt-head"><div><span class="kicker">OFFLINE MODEL EXECUTION</span><h1>Local Model Runtime</h1><p>Runtime、模型工件与外部转换器分别审计；只有显式批准后才执行 SafeTensors → ONNX。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      ${errorText?`<div class="mlrt-error">${esc(errorText)}</div>`:''}
      <div class="mlrt-summary"><div><span>RUNTIME</span><b>${runtime?.available?'READY':'GAP'}</b></div><div><span>CONVERTER</span><b>${converter?.selected?'PINNED':'GAP'}</b></div><div><span>HF PLAN</span><b>${esc(plan?.status?.toUpperCase()||'IDLE')}</b></div><div><span>CONVERSION</span><b>${esc(conversion?.status?.toUpperCase()||'IDLE')}</b></div></div>
      <div class="mlrt-grid"><div class="mlrt-stack">${runtimePanel()}${converterPanel()}</div>${planPanel()}</div>`;
  };

  document.addEventListener('click',async(event)=>{
    if(event.target.closest('[data-mlrt-runtime-refresh]')){await refreshPreflight();return;}
    if(event.target.closest('[data-mlrt-runtime-select]')){
      busy='runtime-select';errorText='';render();
      try{const value=await window.newcyber.chooseLocalMlRuntimeBundle();if(value)runtime=value;}
      catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
      return;
    }
    if(event.target.closest('[data-mlrt-converter-select]')){
      busy='converter-select';errorText='';render();
      try{const value=await window.newcyber.chooseTrustedHfConverter();if(value)converter=value;}
      catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
      return;
    }
    if(event.target.closest('[data-mlrt-hf-plan]')){
      busy='hf-plan';errorText='';conversion=null;render();
      try{const value=await window.newcyber.chooseHfOnnxExportPlan();if(value)plan=value;}
      catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
      return;
    }
    if(event.target.closest('[data-mlrt-hf-save]')&&plan?.bundle?.root){
      busy='hf-save';errorText='';render();
      try{const value=await window.newcyber.saveHfOnnxExportPlan({root:plan.bundle.root});if(value)toast('转换清单已保存');}
      catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
      return;
    }
    if(event.target.closest('[data-mlrt-hf-execute]')&&plan?.status==='ready'&&plan?.bundle?.root){
      busy='hf-execute';errorText='';conversion=null;render();
      try{conversion=await window.newcyber.executeTrustedHfOnnxConversion({root:plan.bundle.root,purpose:'general',provider:'cpu'});}
      catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
      return;
    }
    if(event.target.closest('[data-mlrt-copy-argv]')&&plan?.status==='ready'){
      try{await navigator.clipboard.writeText(JSON.stringify([plan.converter.executable,...(plan.converter.args||[])]));toast('argv 已复制');}catch{toast('复制失败',true);}
    }
  });
})();