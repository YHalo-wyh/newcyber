(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function') return;
  const TOOL='ai-sca-autopilot';
  let result=null;
  let converter=null;
  let busy=false;
  let errorText='';

  TOOL_META[TOOL]={domain:'ai',title:'Power SCA Autopilot',label:'Challenge directory',placeholder:''};
  if(!(DOMAINS.ai.tools||[]).some((item)=>item[0]===TOOL)){
    DOMAINS.ai.tools.unshift([TOOL,'Power SCA Autopilot','赛题目录 → trace/object segments → grouped hidden recovery → probe → Transformer/free-probe → Flag。']);
  }
  const previousToolView=toolView;

  const stageNames={
    discover:'DISCOVER',trace:'TRACE / FEATURES','trace-source':'TRACE SOURCE','object-flatten':'OBJECT FLATTEN','model-runtime':'MODEL RUNTIME','profile-hidden':'PROFILE HIDDEN','profile-input':'PROFILE INPUT','group-layout':'GROUP LAYOUT','leakage-fit':'LEAKAGE FIT',probe:'PROBE RANKING','free-probe':'FREE PROBE',oracle:'TRANSFORMER ORACLE','flag-candidate':'FLAG CANDIDATE',flag:'FLAG VERIFIED'
  };
  function active(){return result?.result||result;}
  function pill(status){const cls=status==='ok'?'ok':status==='gap'?'gap':'wait';return `<span class="sca-auto-pill ${cls}">${esc(String(status||'wait').toUpperCase())}</span>`;}
  function artifactRole(label,role){
    if(!role)return `<div><span>${label}</span><b>—</b><small>not resolved</small></div>`;
    if(role.status==='ok')return `<div><span>${label}</span><b>${esc(role.file?.fileName||'resolved')}</b><small>resolved</small></div>`;
    if(role.status==='ambiguous')return `<div class="gap"><span>${label}</span><b>AMBIGUOUS</b><small>${esc((role.files||[]).join(' · '))}</small></div>`;
    return `<div class="gap"><span>${label}</span><b>${esc(String(role.status||'missing').toUpperCase())}</b><small>evidence required</small></div>`;
  }
  function discoveryPanel(){
    const current=active();
    const d=current?.discovery;
    const roles=d?.roles||{};
    const converted=result?.conversion?.selected;
    return `<section class="sca-auto-panel"><header><div><b>ARTIFACT RECIPE</b><span>${d?.manifestFile?.fileName?esc(d.manifestFile.fileName):'SOURCE-EVIDENCE MODE'}</span></div>${pill(d?'ok':'wait')}</header>
      <div class="sca-auto-artifacts">
        ${artifactRole('PROFILE TRACE',roles.profileTrace)}${artifactRole('TARGET TRACE',roles.targetTrace)}${artifactRole('PROFILE TOKEN IDS',roles.profileTokenIds)}${artifactRole('PROBE',roles.probe)}${artifactRole('ONNX ORACLE',roles.model)}${artifactRole('PROMPT TOKEN IDS',roles.promptTokenIds)}
      </div>
      ${d?.safetensors?.length?`<div class="sca-auto-note"><b>SAFETENSORS</b><span>${esc(d.safetensors.map((x)=>x.fileName).join(' · '))}</span><p>权重本身只作为工件证据；外部转换必须经过 Trusted Converter 闸门，模型目录代码不会执行。</p></div>`:''}
      ${converted?`<div class="sca-auto-note verified"><b>CONVERTED ORACLE</b><span>${esc(converted.fileName||'ONNX')}</span><p>SHA-256 ${esc(String(converted.sha256||'').slice(0,18))}… · ORT / Transformer recipe 已验证后才重新进入 Autopilot。</p></div>`:''}
    </section>`;
  }
  function stagesPanel(){
    const current=active();
    const stages=current?.stages||[];
    const canonical=['discover','trace','trace-source','object-flatten','model-runtime','profile-input','profile-hidden','group-layout','leakage-fit','probe','free-probe','oracle','flag-candidate','flag'];
    const map=new Map(stages.map((item)=>[item.id,item]));
    const present=new Set(stages.map((item)=>item.id));
    const known=canonical.filter((id)=>present.has(id)||['discover','model-runtime','profile-hidden','leakage-fit','probe','oracle','flag'].includes(id));
    return `<section class="sca-auto-panel"><header><div><b>PIPELINE</b><span>DETERMINISTIC STAGE STATE</span></div>${pill(current?.status==='flag-recovered'?'ok':current?.status==='gap'?'gap':'wait')}</header>
      <div class="sca-auto-pipeline">${known.map((id,index)=>{const item=map.get(id);const state=item?.status||'wait';return `<div class="stage ${state}"><div><i>${String(index+1).padStart(2,'0')}</i><span>${stageNames[id]||id}</span>${pill(state)}</div><p>${esc(item?.detail||'waiting for previous evidence')}</p></div>`;}).join('')}</div>
    </section>`;
  }
  function profilePanel(){
    const current=active();
    const p=current?.profile;
    if(!p)return `<section class="sca-auto-panel sca-auto-empty"><b>PROFILE / PROBE</b><p>运行后显示 leakage fit、hidden 维数、分组布局与逐步 token 候选。</p></section>`;
    const candidates=current?.target?.candidates||current?.targetCandidates||[];
    const layout=current?.layout;
    return `<section class="sca-auto-panel"><header><div><b>PROFILE / PROBE</b><span>${esc(p.method||p.status||'—')}</span></div>${pill(p.status==='ok'?'ok':'gap')}</header>
      <div class="sca-auto-metrics"><div><span>TOKENS</span><b>${p.rows||0}</b></div><div><span>HIDDEN</span><b>${p.hiddenDim||0}</b></div><div><span>LEAKAGE</span><b>${p.leakageDim||0}</b></div><div><span>SOLVE DIM</span><b>${p.solveDim||0}</b></div><div><span>GROUPS/TOKEN</span><b>${layout?.groupsPerToken||p.groupsPerToken||'—'}</b></div><div><span>HIDDEN/GROUP</span><b>${layout?.hiddenPerGroup||p.hiddenPerGroup||'—'}</b></div><div><span>R²</span><b>${p.r2==null?'—':Number(p.r2).toFixed(6)}</b></div><div><span>RMSE</span><b>${p.rmse==null?'—':Number(p.rmse).toExponential(2)}</b></div></div>
      ${candidates.length?`<div class="sca-auto-candidates"><header><span>STEP</span><span>TOP TOKEN CANDIDATES</span></header>${candidates.slice(0,256).map((row,index)=>`<div><i>${index}</i><code>${(row||[]).slice(0,8).map((x)=>`${x.tokenId}:${Number(x.score).toFixed(3)}`).join(' · ')}</code></div>`).join('')}</div>`:''}
    </section>`;
  }
  function conversionGate(){
    const current=active();
    const needs=current?.gap?.code==='ORACLE_ARTIFACT_GAP'&&Boolean(current?.discovery?.safetensors?.length)&&Boolean(result?.workspaceRoot);
    if(!needs)return '';
    const selected=Boolean(converter?.selected);
    return `<div class="sca-auto-convert">
      <div class="sca-auto-convert-head"><div><span>TRUSTED CONVERSION GATE</span><b>SAFETENSORS → ONNX → ORT VERIFY → RESUME</b></div>${pill(selected?'ok':'gap')}</div>
      ${selected?`<div class="sca-auto-converter"><span>OPTIMUM-CLI</span><code>${esc(converter.filePath||'—')}</code><small>sha256 ${esc(String(converter.sha256||'').slice(0,18))}… · 每次执行前重新校验</small></div>`:`<p>当前只缺可执行 ONNX oracle。先选择本机可信 optimum-cli；选择动作不会启动进程。</p>`}
      <div class="sca-auto-convert-actions"><button class="button ghost" data-sca-auto-converter ${busy?'disabled':''}>${selected?'重新选择 Converter':'选择 Trusted Converter'}</button>${selected?`<button class="button primary" data-sca-auto-convert-resume ${busy?'disabled':''}>转换并继续 Autopilot</button>`:''}</div>
      <small>shell=false · converter-dir cwd · HuggingFace offline env · timeout/output cap · 不执行模型目录 Python/native 代码 · 非 OS 网络沙箱</small>
    </div>`;
  }
  function conversionEvidence(){
    const c=result?.conversion;
    if(!c)return '';
    const ok=c.status==='converted';
    return `<div class="sca-auto-conversion-evidence"><div><span>CONVERSION</span><b>${esc(String(c.status||'unknown').toUpperCase())}</b></div><div><span>PROCESS</span><b>${esc(c.process?.status||'—')}</b></div><div><span>ONNX</span><b>${esc(c.selected?.fileName||'—')}</b></div><div><span>PROVENANCE</span><b>${c.manifestPath?'WRITTEN':'—'}</b></div>${ok?'':c.gap?`<p>${esc(c.gap.code)} · ${esc(c.gap.detail)}</p>`:''}</div>`;
  }
  function resultPanel(){
    const current=active();
    const gap=current?.gap;
    const oracle=current?.oracle;
    const candidate=current?.flagCandidate||null;
    return `<section class="sca-auto-panel ${current?.flag?'solved':''}"><header><div><b>RESULT</b><span>${esc(current?.status||'NOT RUN')}</span></div>${pill(current?.flag?'ok':gap?'gap':'wait')}</header>
      ${current?.flag?`<div class="sca-auto-flag"><span>VERIFIED FLAG</span><strong>${esc(current.flag)}</strong><button class="button primary" data-sca-auto-copy>复制</button></div>`:''}
      ${candidate&&!current?.flag?`<div class="sca-auto-gap"><span>FLAG CANDIDATE · FREE PROBE</span><b>${esc(candidate)}</b><p>已从 grouped leakage → hidden reassembly → probe top-1 恢复，但未知 prompt/context 下没有 Transformer oracle 复核，不提升为 verified。</p><button class="button ghost" data-sca-auto-copy-candidate>复制 Candidate</button></div>`:''}
      ${current?.freeProbe?.text!=null?`<div class="sca-auto-oracle"><div><span>FREE PROBE TOKENS</span><b>${current.freeProbe.ids?.length||0}</b></div><div><span>TOP-1 MARGIN</span><b>${current.freeProbe.top1Margin?.mean==null?'—':Number(current.freeProbe.top1Margin.mean).toFixed(4)}</b></div></div><pre>${esc(current.freeProbe.text)}</pre>`:''}
      ${gap?`<div class="sca-auto-gap"><span>${esc(gap.stage||'stage')}</span><b>${esc(gap.code)}</b><p>${esc(gap.detail)}</p></div>`:''}
      ${conversionGate()}${conversionEvidence()}
      ${oracle?`<div class="sca-auto-oracle"><div><span>ORACLE STATUS</span><b>${esc(oracle.status||'—')}</b></div><div><span>GENERATED</span><b>${oracle.generatedTokenIds?.length||0}</b></div><div><span>CACHE</span><b>${oracle.cacheUsed?'KV PAIRED':'FULL REPLAY'}</b></div></div>${oracle.generatedText!=null?`<pre>${esc(oracle.generatedText)}</pre>`:''}`:''}
      ${!result?'<p class="sca-auto-muted">选择赛题目录后，NewCyber 只读取受支持工件并在主进程运行确定性链。object NPY 使用受限 NumPy pickle 解释器，不执行 callable；外部模型转换必须显式批准。</p>':''}
    </section>`;
  }

  toolView=function scaAutopilotView(tool){
    if(tool!==TOOL)return previousToolView(tool);
    return `<div class="page-head tool-head sca-auto-head"><div><span class="kicker">TRACE → GROUPED HIDDEN → PROBE → ORACLE</span><h1>Power SCA Autopilot</h1><p>支持一行/token 与多行/token grouped leakage；未知 prompt 时可 free-probe，但 candidate 与 verified 严格分离。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="sca-auto-command"><button class="button primary" data-sca-auto-run ${busy?'disabled':''}>${busy?'正在执行…':'选择赛题目录并自动恢复'}</button><div><span>MODE</span><b>OFFLINE / DETERMINISTIC</b></div><div><span>OBJECT NPY</span><b>RESTRICTED / NO EXEC</b></div><div><span>CHALLENGE CODE</span><b>NEVER EXECUTED</b></div></div>
      ${errorText?`<div class="sca-auto-error">${esc(errorText)}</div>`:''}
      <div class="sca-auto-grid"><div>${discoveryPanel()}${profilePanel()}</div><div>${stagesPanel()}${resultPanel()}</div></div>`;
  };

  document.addEventListener('click',async(event)=>{
    if(event.target.closest('[data-sca-auto-run]')){
      busy=true;errorText='';result=null;converter=null;render();
      try{
        result=await window.newcyber.chooseAndRunScaAutopilot();
        converter=await window.newcyber.getTrustedHfConverterStatus();
      }catch(error){errorText=error?.message||String(error);}finally{busy=false;render();}
      return;
    }
    if(event.target.closest('[data-sca-auto-converter]')){
      busy=true;errorText='';render();
      try{const value=await window.newcyber.chooseTrustedHfConverter();if(value)converter=value;}
      catch(error){errorText=error?.message||String(error);}finally{busy=false;render();}
      return;
    }
    if(event.target.closest('[data-sca-auto-convert-resume]')&&result?.workspaceRoot&&converter?.selected){
      busy=true;errorText='';render();
      try{result=await window.newcyber.continueScaAutopilotWithConversion({root:result.workspaceRoot,provider:'cpu'});}
      catch(error){errorText=error?.message||String(error);}finally{busy=false;render();}
      return;
    }
    const current=active();
    if(event.target.closest('[data-sca-auto-copy]')&&current?.flag){
      try{await navigator.clipboard.writeText(current.flag);toast('Flag 已复制');}catch{toast('复制失败',true);}
      return;
    }
    if(event.target.closest('[data-sca-auto-copy-candidate]')&&current?.flagCandidate){
      try{await navigator.clipboard.writeText(current.flagCandidate);toast('Candidate 已复制');}catch{toast('复制失败',true);}
    }
  });
})();