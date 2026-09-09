(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function') return;
  const TOOL='ai-local-model-runtime';
  let runtime=null;
  let plan=null;
  let busy='';
  let errorText='';
  let autoLoadStarted=false;

  TOOL_META[TOOL]={domain:'ai',title:'Local Model Runtime',label:'Runtime bundle / HF model directory',placeholder:''};
  if(!(DOMAINS.ai.tools||[]).some((item)=>item[0]===TOOL)){
    const list=DOMAINS.ai.tools||[];
    const index=Math.min(1,list.length);
    list.splice(index,0,[TOOL,'Local Model Runtime','离线 ONNX Runtime bundle + HuggingFace/SafeTensors → ONNX 审计转换清单。']);
  }
  const previousToolView=toolView;

  function badge(ok,label){return `<span class="mlrt-badge ${ok?'ok':'gap'}">${esc(label)}</span>`;}
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
      <div class="mlrt-note"><b>赛前准备</b><code>npm run runtime:prepare</code><p>准备步骤可以联网；比赛执行阶段只从已验证 bundle / app resources / 本地 node_modules 加载，不在 renderer 加载原生模块。</p></div>
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
    return `<div class="mlrt-shards"><header><span>SAFETENSORS</span><span>HEADER / PAYLOAD</span><span>STATE</span></header>${shards.slice(0,32).map((item)=>`<div><b>${esc(item.fileName||'—')}</b><code>${item.headerBytes||0} B / ${item.payloadBytes||0} B · ${item.tensorCount||0} tensors</code>${badge(Boolean(item.valid),item.valid?'VALID':'INVALID')}</div>`).join('')}${shards.length>32?`<p>另有 ${shards.length-32} 个 shard，UI 仅折叠展示；planner 已全部校验 header。</p>`:''}</div>`;
  }

  function planPanel(){
    const ready=plan?.status==='ready';
    const gap=plan?.gap;
    const argv=ready?[plan.converter.executable,...(plan.converter.args||[])]:null;
    return `<section class="mlrt-panel"><header><div><b>HF / SAFETENSORS → ONNX</b><span>PLAN ONLY / NO MODEL CODE EXECUTION</span></div>${plan?badge(ready,ready?'READY':'GAP'):badge(false,'WAITING')}</header>
      ${modelFacts()}
      ${shardTable()}
      ${gap?`<div class="mlrt-gap"><span>${esc(gap.code||'GAP')}</span><p>${esc(gap.detail||'')}</p></div>`:''}
      ${ready?`<div class="mlrt-export-plan">
        <div class="mlrt-task"><span>OPTIMUM TASK</span><b>${esc(plan.task?.task||'—')}</b><small>${esc(plan.task?.source||'')}</small></div>
        <div class="mlrt-path"><span>OUTPUT</span><code>${esc(plan.output?.directory||'—')}</code></div>
        <div class="mlrt-env"><span>OFFLINE ENV</span><code>HF_HUB_OFFLINE=1 · TRANSFORMERS_OFFLINE=1 · HF_DATASETS_OFFLINE=1</code></div>
        <div class="mlrt-argv"><span>ARGV · shell=false</span><pre>${esc(JSON.stringify(argv,null,2))}</pre><button class="button ghost" data-mlrt-copy-argv>复制 argv</button></div>
      </div>`:''}
      <div class="mlrt-actions"><button class="button primary" data-mlrt-hf-plan ${busy?'disabled':''}>选择本地模型目录</button>${plan?`<button class="button ghost" data-mlrt-hf-save ${busy?'disabled':''}>保存转换清单</button>`:''}</div>
      <div class="mlrt-note"><b>执行边界</b><p>NewCyber 只生成确定的 executable + argv + offline env。检测到 config.auto_map 时返回 REMOTE_CODE_GAP；不会自动追加 --trust-remote-code，也不会 spawn 题目 Python。</p></div>
    </section>`;
  }

  async function refreshRuntime(){
    if(busy)return;
    busy='runtime';errorText='';render();
    try{runtime=await window.newcyber.getLocalMlRuntimeStatus();}
    catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
  }

  toolView=function localModelRuntimeView(tool){
    if(tool!==TOOL)return previousToolView(tool);
    if(!autoLoadStarted){autoLoadStarted=true;setTimeout(()=>refreshRuntime(),0);}
    return `<div class="page-head tool-head mlrt-head"><div><span class="kicker">OFFLINE MODEL EXECUTION</span><h1>Local Model Runtime</h1><p>把 ONNX 原生运行时和 HuggingFace 权重转换边界单独做成可审计工件层，不让比赛现场依赖临时安装。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      ${errorText?`<div class="mlrt-error">${esc(errorText)}</div>`:''}
      <div class="mlrt-summary"><div><span>RUNTIME</span><b>${runtime?.available?'READY':'GAP'}</b></div><div><span>PIN</span><b>${esc(runtime?.pinnedVersion||'1.29.0')}</b></div><div><span>HF PLAN</span><b>${esc(plan?.status?.toUpperCase()||'IDLE')}</b></div><div><span>NETWORK AT RUNTIME</span><b>DISABLED</b></div></div>
      <div class="mlrt-grid">${runtimePanel()}${planPanel()}</div>`;
  };

  document.addEventListener('click',async(event)=>{
    if(event.target.closest('[data-mlrt-runtime-refresh]')){await refreshRuntime();return;}
    if(event.target.closest('[data-mlrt-runtime-select]')){
      busy='runtime-select';errorText='';render();
      try{const value=await window.newcyber.chooseLocalMlRuntimeBundle();if(value)runtime=value;}
      catch(error){errorText=error?.message||String(error);}finally{busy='';render();}
      return;
    }
    if(event.target.closest('[data-mlrt-hf-plan]')){
      busy='hf-plan';errorText='';render();
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
    if(event.target.closest('[data-mlrt-copy-argv]')&&plan?.status==='ready'){
      try{await navigator.clipboard.writeText(JSON.stringify([plan.converter.executable,...(plan.converter.args||[])]));toast('argv 已复制');}catch{toast('复制失败',true);}
    }
  });
})();
