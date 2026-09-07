(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof renderResult !== 'function') return;

  const tools = [
    ['ai-adversarial-audit','对抗样本验证','比较原始/对抗样本的 L0/L1/L2/L∞、epsilon、clip 和模型输出，先判断候选是否真的满足题目约束。'],
    ['ai-privacy-audit','模型隐私 / 成员推断','导入 member/non-member 的 loss/confidence/entropy 查询结果，计算 AUC、最佳阈值和泄露分离度。'],
    ['ai-dataset-security','数据投毒 / 后门排查','从 CSV/TSV/JSON 里找重复、冲突标签、低频标签和与目标标签异常绑定的 trigger 候选。'],
    ['ai-supply-chain','AI 供应链审计','审计 from_pretrained、trust_remote_code、revision、pickle/joblib/torch.load、requirements 与包索引边界。'],
    ['ai-model-scan','模型文件交叉扫描','内置模型结构审计，并在本机存在时交叉运行 ModelScan / PickleScan。']
  ];

  TOOL_META['ai-adversarial-audit'] = { domain:'ai', title:'对抗样本验证', label:'JSON：original / adversarial / epsilon / prediction', placeholder:'{"original":[0,0,0],"adversarial":[0.01,0,0],"epsilon":0.03,"norm":"linf","trueLabel":0,"predictedAdversarial":1}' };
  TOOL_META['ai-privacy-audit'] = { domain:'ai', title:'模型隐私 / 成员推断', label:'CSV/JSON 查询结果', placeholder:'member,loss,confidence\n1,0.12,0.98\n0,0.83,0.55' };
  TOOL_META['ai-dataset-security'] = { domain:'ai', title:'数据投毒 / 后门排查', label:'CSV/TSV/JSON 数据集', placeholder:'text,label\nnormal sample,0\nrare_trigger phrase,1\nrare_trigger another,1' };
  TOOL_META['ai-supply-chain'] = { domain:'ai', title:'AI 供应链审计', label:'Python / requirements / pyproject 片段', placeholder:'model = AutoModel.from_pretrained(repo, trust_remote_code=True)\nrequests\ntorch>=2.0' };
  TOOL_META['ai-model-scan'] = { domain:'ai', title:'模型文件交叉扫描', label:'模型文件', placeholder:'' };

  const existing=new Set((DOMAINS.ai.tools||[]).map((x)=>x[0]));
  for (const row of tools) if (!existing.has(row[0])) DOMAINS.ai.tools.push(row);

  const previousToolView = toolView;
  const previousRenderResult = renderResult;

  toolView = function batch9ToolView(tool) {
    if (tool !== 'ai-model-scan') return previousToolView(tool);
    const resultHtml = state.toolError
      ? `<div class="error-box">${esc(state.toolError)}</div>`
      : state.toolResult ? modelScanResult(state.toolResult) : '<div class="result-empty">选择模型后开始静态交叉扫描。</div>';
    return `<div class="page-head tool-head"><div><span class="kicker">AI MODEL SECURITY</span><h1>模型文件交叉扫描</h1><p>NewCyber 结构审计 + ModelScan / PickleScan 交叉证据。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="workbench"><article class="panel input-panel"><div class="field grow"><label>模型 / Checkpoint</label><div class="workspace-empty"><div>AI</div><h2>${state.toolResult?.fileName ? esc(state.toolResult.fileName) : '尚未选择模型'}</h2><p>支持 PyTorch / Pickle / Joblib / NPY / SafeTensors / H5 / Keras 等常见附件。</p><button class="button primary" data-action="ai-choose-model-scan">选择并扫描</button><button class="button ghost" data-action="ai-backend-status">检查开源后端</button></div></div><div id="ai-backend-status"></div></article><article class="panel result-panel"><div class="result-title"><b>结果</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${resultHtml}</div></article></div>`;
  };

  function findingCards(findings=[]) {
    if (!findings.length) return '<div class="result-empty">当前输入没有形成高价值 finding。</div>';
    return findings.map((f)=>`<div class="finding ${esc(f.severity||'info')}"><span>${esc(f.severity||'info')}</span><div><b>${esc(f.title||f.id)}</b><small>${esc(f.id||'')}</small><p>${esc(f.meaning||f.message||'')}</p>${f.evidence ? `<pre>${esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre>`:''}${f.fix ? `<details><summary>修复与回归</summary><p><b>位置：</b>${esc(f.fix.target||'—')}</p><p><b>修复：</b>${esc(f.fix.action||'—')}</p><p><b>回归：</b>${esc(f.fix.regression||'—')}</p></details>`:''}</div></div>`).join('');
  }

  function adversarialResult(r) {
    const n=r.norms||{};
    return `<div class="result-stats"><div><b>${esc(r.verdict)}</b><span>结论</span></div><div><b>${r.withinBudget===null?'—':r.withinBudget?'YES':'NO'}</b><span>epsilon</span></div><div><b>${Number(n.linf||0).toPrecision(5)}</b><span>L∞</span></div><div><b>${Number(n.l2||0).toPrecision(5)}</b><span>L2</span></div></div>
      ${table(['指标','值'],[['L0',n.l0],['L1',n.l1],['L2',n.l2],['L∞',n.linf],['mean |δ|',n.meanAbs],['changed ratio',n.changedRatio]])}
      ${r.outcome ? `<p class="notice"><b>输出：</b>${esc(JSON.stringify(r.outcome))}</p>`:''}
      ${findingCards(r.findings)}
      ${r.harnesses?.length ? harnessBlock(r.harnesses) : `<button class="button" data-action="ai-generate-harness" data-kind="adversarial">生成 ART / Foolbox 脚本</button>`}`;
  }

  function privacyResult(r) {
    return `<div class="result-stats"><div><b>${r.rows}</b><span>记录</span></div><div><b>${r.labeledRows}</b><span>有真值</span></div><div><b>${esc(r.privacyRisk)}</b><span>分离强度</span></div></div>
      ${r.signals?.length ? table(['信号','方向','AUC','成员均值','非成员均值','最佳阈值','Balanced Acc'],r.signals.map(x=>[x.id,x.direction||'—',x.auc==null?'—':x.auc.toFixed(4),x.memberMean??'—',x.nonMemberMean??'—',x.threshold?.threshold??'—',x.threshold?.balancedAccuracy==null?'—':x.threshold.balancedAccuracy.toFixed(4)])) : ''}
      ${findingCards(r.findings)}
      ${r.harnesses?.length ? harnessBlock(r.harnesses) : `<button class="button" data-action="ai-generate-harness" data-kind="privacy">生成 Privacy Meter / ART 接线</button>`}`;
  }

  function datasetResult(r) {
    return `<div class="result-stats"><div><b>${r.rows}</b><span>样本</span></div><div><b>${r.labelColumn||'—'}</b><span>标签列</span></div><div><b>${r.conflictingLabels?.length||0}</b><span>标签冲突</span></div><div><b>${r.triggerCandidates?.length||0}</b><span>Trigger 候选</span></div></div>
      ${Object.keys(r.labelCounts||{}).length ? table(['Label','Count'],Object.entries(r.labelCounts)) : ''}
      ${r.triggerCandidates?.length ? `<details class="panel" open><summary><b>可疑 Trigger / 特征共现</b> · ${r.triggerCandidates.length}</summary>${table(['列','Token/值','Support','目标标签','置信度','Lift'],r.triggerCandidates.slice(0,50).map(x=>[x.column,x.token,x.support,x.targetLabel,x.confidence.toFixed(3),x.lift.toFixed(2)]))}</details>`:''}
      ${r.conflictingLabels?.length ? `<details class="panel"><summary><b>相同特征不同标签</b> · ${r.conflictingLabels.length}</summary><pre class="mini-pre">${esc(JSON.stringify(r.conflictingLabels.slice(0,30),null,2))}</pre></details>`:''}
      ${findingCards(r.findings)}
      ${r.harnesses?.length ? harnessBlock(r.harnesses) : `<button class="button" data-action="ai-generate-harness" data-kind="dataset">生成 cleanlab / BackdoorBench 验证脚本</button>`}`;
  }

  function supplyResult(r) {
    return `<div class="result-stats"><div><b>${r.summary?.high||0}</b><span>High</span></div><div><b>${r.summary?.medium||0}</b><span>Medium</span></div><div><b>${r.summary?.info||0}</b><span>Info</span></div></div>${findingCards(r.findings)}${r.nextActions?.length?`<div class="hint-list">${r.nextActions.map(x=>`<p>${esc(x)}</p>`).join('')}</div>`:''}`;
  }

  function harnessBlock(items=[]) {
    return `<details class="panel" open><summary><b>开源工具接线 / 生成脚本</b> · ${items.length}</summary>${items.map(x=>`<article class="panel"><b>${esc(x.backend)}</b><small>${esc(x.project||'')}</small><pre class="output-pre">${esc(x.script||x.text||'')}</pre></article>`).join('')}</details>`;
  }

  function modelScanResult(r) {
    const internal=r.internal?.result;
    const external=r.external||[];
    const internalFindings=internal?.securityFindings||[];
    return `<div class="result-stats"><div><b>${esc(r.verdict||'unknown')}</b><span>交叉结论</span></div><div><b>${r.size||0}</b><span>Bytes</span></div><div><b>${internalFindings.length}</b><span>内置 finding</span></div><div><b>${external.filter(x=>x.status==='findings').length}</b><span>外部扫描命中</span></div></div>
      <p class="notice"><b>${esc(r.fileName||'model')}</b> · 内置格式 ${esc(r.internal?.format||'unknown')}</p>
      ${internalFindings.length ? findingCards(internalFindings.map(x=>({ ...x,title:x.id,meaning:x.message }))) : '<p class="notice">内置结构审计未发现 high-risk 结构证据。</p>'}
      ${external.length ? table(['Backend','状态','Exit','命中'],external.map(x=>[x.engine,x.status,x.exitCode??'—',x.findingsLikely?'yes':'no'])) : '<p class="notice">ModelScan / PickleScan 当前未提供额外交叉结果。</p>'}
      ${external.map(x=>`<details class="panel"><summary><b>${esc(x.engine)} 原始输出</b></summary><pre class="mini-pre">${esc(x.stdout||x.stderr||'')}</pre></details>`).join('')}`;
  }

  renderResult = function batch9RenderResult(tool,result) {
    if (tool==='ai-adversarial-audit') return adversarialResult(result);
    if (tool==='ai-privacy-audit') return privacyResult(result);
    if (tool==='ai-dataset-security') return datasetResult(result);
    if (tool==='ai-supply-chain') return supplyResult(result);
    if (tool==='ai-model-scan') return modelScanResult(result);
    return previousRenderResult(tool,result);
  };

  document.addEventListener('click', async (event)=>{
    const modelButton=event.target.closest('[data-action="ai-choose-model-scan"]');
    if (modelButton) {
      try {
        modelButton.disabled=true;
        const result=await window.newcyber.chooseAndScanAiModel();
        if (!result) return;
        state.tool='ai-model-scan'; state.view='ai'; state.toolResult=result; state.toolError=null; render();
      } catch (error) { state.toolError=error.message||String(error); render(); }
      return;
    }
    const statusButton=event.target.closest('[data-action="ai-backend-status"]');
    if (statusButton) {
      try {
        const status=await window.newcyber.getAiBackendStatus();
        const box=document.querySelector('#ai-backend-status');
        if (box) box.innerHTML=`<div class="hint-list"><p>ModelScan：${status.cli.modelscan.available?'available':'not found'}</p><p>PickleScan：${status.cli.picklescan.available?'available':'not found'}</p><p>ART / Foolbox / Privacy Meter / cleanlab / BackdoorBench 通过生成 harness 接入。</p></div>`;
      } catch (error) { toast(error.message||String(error),true); }
      return;
    }
    const harnessButton=event.target.closest('[data-action="ai-generate-harness"]');
    if (!harnessButton) return;
    const kind=harnessButton.dataset.kind;
    const input=document.querySelector('#tool-input')?.value||'';
    const route=kind==='adversarial'?'ai-adversarial-harness':kind==='privacy'?'ai-privacy-harness':'ai-dataset-harness';
    try {
      const generated=await window.newcyber.runTool(route,{input});
      if (state.toolResult && generated?.harnesses) state.toolResult={...state.toolResult,harnesses:generated.harnesses};
      const current=state.tool; render(); state.tool=current;
      const textarea=document.querySelector('#tool-input'); if (textarea) textarea.value=input;
    } catch (error) { toast(error.message||String(error),true); }
  });

  render();
})();
