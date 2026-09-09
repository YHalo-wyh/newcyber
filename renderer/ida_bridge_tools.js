(() => {
  if (typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof commonView !== 'function') return;

  const TOOL = 'ida-bridge';
  let current = null;
  let busy = false;
  let errorText = '';
  let selectedObjectId = null;
  let selectedFunction = null;

  TOOL_META[TOOL] = { domain:'common', title:'IDA Bridge', label:'Offline Snapshot', placeholder:'' };
  const previousCommonView = commonView;
  const previousToolView = toolView;

  function e(value) { return typeof esc === 'function' ? esc(value == null ? '' : String(value)) : String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function bytes(value) { return typeof fmtBytes === 'function' ? fmtBytes(value) : `${Number(value || 0)} B`; }

  commonView = function idaBridgeCommonView() {
    const html = previousCommonView();
    const card = `<button class="tool-card ida-bridge-entry" data-tool="${TOOL}"><span>IDA FIRST</span><strong>IDA Bridge</strong><p>离线导入 Functions / Names / XREF / Bytes，再由 NewCyber 恢复关系与表达式。</p><em>打开</em></button>`;
    return html.replace('<div class="tool-grid">', `<div class="tool-grid">${card}`);
  };

  function sourcePanel() {
    const source = current?.analysis?.source;
    const ida = source?.ida;
    return `<section class="panel ida-bridge-source" data-ida-drop>
      <div class="ida-bridge-source-head"><div><span class="kicker">OFFLINE BRIDGE</span><b>${current ? e(current.fileName) : 'IDA → NewCyber Snapshot'}</b><small>${current ? `${bytes(current.size)} · IDA ${e(ida?.version || '?')} · ${e(ida?.processor || '?')} · ${ida?.bitness || '?'}-bit` : '不启服务 · 不开端口 · 不执行目标程序'}</small></div><div class="ida-bridge-actions"><button class="button primary" data-ida-open>${current ? '更换 Snapshot' : '导入 Snapshot'}</button>${current ? '<button class="text-button" data-ida-clear>清空</button>' : ''}</div></div>
      <div class="ida-bridge-flow"><span>IDA DATABASE</span><i>→</i><span>SNAPSHOT JSON</span><i>→</i><span>OBJECT/XREF</span><i>→</i><span>EXPRESSION IR</span><i>→</i><span>RECOVERABLE</span></div>
      ${errorText ? `<div class="bdg-inline-error">${e(errorText)}</div>` : ''}
    </section>`;
  }

  function installPanel() {
    if (current) return '';
    return `<section class="panel ida-install-panel"><div class="ida-install-title"><b>IDA 里只做一次安装</b><span>推荐</span></div><div class="ida-install-steps"><div><em>01</em><p>把 <code>ida/newcyber_ida_bridge.py</code> 放到 IDA 的 plugins 目录，或直接 File → Script file 运行。</p></div><div><em>02</em><p>打开题目，等 IDA auto-analysis 完成；按 <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>N</kbd>。</p></div><div><em>03</em><p>保存 <code>*.newcyber-ida.json</code>，拖回本页。之后分析不要求 IDA 保持运行。</p></div></div><div class="ida-independence-note"><b>离开 IDA 仍可用：</b><span>ELF 模式现在能独立恢复 Section/Object/Slice/Relocation，并扫描 x86-64 直接 RIP-relative code→data 引用。IDA Snapshot 只是更高质量的事实源，不是运行依赖。</span></div></section>`;
  }

  function summary() {
    if (!current) return '';
    const s = current.analysis?.summary || {};
    return `<div class="ida-summary"><span><b>${s.functions || 0}</b> functions</span><span><b>${s.idaItems || 0}</b> IDA items</span><span><b>${s.objects || 0}</b> objects</span><span><b>${s.operations || 0}</b> expressions</span><span><b>${s.structuredXrefs || 0}</b> structured xrefs</span><span><b>${s.recoverableRelations || 0}</b> recoverable</span></div>`;
  }

  function functionsPane() {
    const functions = current?.analysis?.ida?.functions || [];
    return `<aside class="panel ida-functions"><div class="ida-pane-head"><b>FUNCTIONS</b><span>${functions.length}</span></div><div class="ida-list">${functions.slice(0,2500).map((fn) => `<button class="ida-fn-row ${selectedFunction === fn.start ? 'active' : ''}" data-ida-fn="${e(fn.start)}"><b>${e(fn.name || fn.start)}</b><small>${e(fn.start)} · ${fn.size || 0}B</small></button>`).join('') || '<p class="ida-muted">导入后显示 IDA 已确认函数。</p>'}</div></aside>`;
  }

  function objectRelations(object) {
    if (!object || !current) return [];
    return (current.analysis.relations || []).filter((rel) => rel.source === object.id || rel.target === object.id).slice(0,80);
  }

  function objectsPane() {
    const objects = current?.analysis?.objects || [];
    return `<aside class="panel ida-objects"><div class="ida-pane-head"><b>DATA OBJECTS</b><span>${objects.length}</span></div><div class="ida-list">${objects.slice(0,3000).map((obj) => `<button class="ida-object-row ${selectedObjectId === obj.id ? 'active' : ''}" data-ida-object="${e(obj.id)}"><i class="${e(obj.kind)}"></i><div><b>${e(obj.name)}</b><small>${e(obj.address)} · ${e(obj.section)} · ${obj.size || 0}B</small></div></button>`).join('') || '<p class="ida-muted">导入后显示 data/string/pointer/slice。</p>'}</div></aside>`;
  }

  function detailPane() {
    const analysis = current?.analysis;
    if (!analysis) return `<main class="panel ida-detail"><div class="ida-empty"><b>IDA FACT GRAPH</b><p>导入 Snapshot 后，从函数、对象和 XREF 开始追验证链。</p></div></main>`;
    const object = analysis.objects.find((obj) => obj.id === selectedObjectId) || analysis.objects[0];
    const relations = objectRelations(object);
    const relatedOps = (analysis.operations || []).filter((op) => relations.some((rel) => rel.target === op.id || rel.operationNode === op.id) || (object && String(op.pseudo || '').includes(object.name))).slice(0,40);
    const recover = (analysis.recoverableRelations || []).filter((item) => object && (item.objects || []).includes(object.id));
    const evidence = [...(object?.evidence || []), ...(object?.cellEvidence || [])].slice(0,60);
    return `<main class="panel ida-detail"><div class="ida-detail-head"><div><span>${e(object?.section || '')}</span><h2>${e(object?.name || 'No object')}</h2><small>${e(object?.address || '')} · ${e(object?.kind || '')} · ${object?.size || 0} bytes</small></div>${object?.semanticSuggestions?.[0] ? `<strong>${e(object.semanticSuggestions[0].label)} · ${Math.round((object.semanticSuggestions[0].confidence || 0)*100)}%</strong>` : ''}</div><div class="ida-detail-scroll">
      <section><div class="ida-section-head"><b>RELATIONS / XREF</b><span>${relations.length}</span></div><div class="ida-relations">${relations.map((rel) => `<div><span>${e(rel.sourceLabel || rel.source)}</span><b>${e(rel.type)}</b><span>${e(rel.target === object?.id ? object?.name : rel.target)}</span><small>${e(rel.location || '')} · ${Math.round((rel.confidence || 0)*100)}%</small>${rel.evidence?.[0] ? `<code>${e(rel.evidence[0])}</code>` : ''}</div>`).join('') || '<p class="ida-muted">没有结构化关系。</p>'}</div></section>
      <section><div class="ida-section-head"><b>EXPRESSION IR</b><span>${relatedOps.length}</span></div><div class="ida-ops">${relatedOps.map((op) => `<div><span>${e(op.op)}</span><code>${e(op.pseudo)}</code><small>${e(op.location || '')}</small></div>`).join('') || '<p class="ida-muted">当前对象没有绑定表达式。</p>'}</div></section>
      <section><div class="ida-section-head"><b>RECOVERABLE</b><span>${recover.length}</span></div>${recover.map((item) => `<div class="ida-recover"><b>${e(item.equation)}</b>${(item.derivations || []).map((line) => `<code>${e(line)}</code>`).join('')}${item.verification ? `<span class="${item.verification.holdsForKnownBytes === true ? 'ok' : item.verification.holdsForKnownBytes === false ? 'bad' : ''}">${item.verification.holdsForKnownBytes === true ? 'VERIFIED' : item.verification.holdsForKnownBytes === false ? `${item.verification.mismatches} MISMATCH` : 'DERIVABLE'} · ${item.verification.checkedBytes || 0} bytes</span>` : ''}</div>`).join('') || '<p class="ida-muted">没有可逆关系。</p>'}</section>
      <section><div class="ida-section-head"><b>EVIDENCE</b><span>${evidence.length}</span></div><div class="ida-evidence">${evidence.map((ev) => `<div><span>${e(ev.kind || 'evidence')}</span><code>${e(ev.text || `${ev.address || ''} ${(ev.values || []).join(', ')}`)}</code></div>`).join('') || '<p class="ida-muted">没有附加 evidence。</p>'}</div></section>
    </div></main>`;
  }

  function page() {
    return `<div class="page-head tool-head ida-bridge-head"><div><span class="kicker">REVERSE / HIGH-CONFIDENCE FRONTEND</span><h1>IDA Bridge</h1><p>IDA 负责反汇编事实，NewCyber 负责 Object → XREF → Expression → Recovery。Snapshot 导出后可完全离线分析。</p></div><button class="button ghost" data-view="common">返回</button></div><div class="ida-bridge-workbench ${busy ? 'busy' : ''}">${sourcePanel()}${installPanel()}${summary()}${current ? `<div class="ida-columns">${functionsPane()}${objectsPane()}${detailPane()}</div>` : ''}</div>`;
  }

  toolView = function idaBridgeView(tool) { return tool === TOOL ? page() : previousToolView(tool); };

  async function openSnapshot() {
    errorText=''; busy=true; render();
    try {
      const result = await window.newcyber.chooseAndAnalyzeIdaSnapshot();
      if (!result) { busy=false; render(); return; }
      current=result; selectedObjectId=result.analysis?.objects?.[0]?.id || null; selectedFunction=null;
    } catch (error) { current=null; errorText=error?.message || String(error); }
    finally { busy=false; render(); }
  }
  async function dropSnapshot(file) {
    errorText=''; busy=true; render();
    try {
      const result=await window.newcyber.analyzeDroppedIdaSnapshot(file);
      current=result; selectedObjectId=result.analysis?.objects?.[0]?.id || null; selectedFunction=null;
    } catch(error){current=null;errorText=error?.message || String(error);} finally{busy=false;render();}
  }

  document.addEventListener('click', async (event) => {
    if (event.target.closest('[data-ida-open]')) { await openSnapshot(); return; }
    if (event.target.closest('[data-ida-clear]')) { current=null;selectedObjectId=null;selectedFunction=null;errorText='';render();return; }
    const object=event.target.closest('[data-ida-object]'); if(object){selectedObjectId=object.dataset.idaObject;render();return;}
    const fn=event.target.closest('[data-ida-fn]'); if(fn){selectedFunction=fn.dataset.idaFn;const rel=(current?.analysis?.relations||[]).find((r)=>r.sourceLabel && (current.analysis.ida?.functions||[]).some((f)=>f.start===selectedFunction&&f.name===r.sourceLabel));if(rel?.target)selectedObjectId=rel.target;render();}
  });
  document.addEventListener('dragover',(event)=>{const target=event.target.closest?.('[data-ida-drop]');if(!target)return;event.preventDefault();target.classList.add('dragging');});
  document.addEventListener('dragleave',(event)=>event.target.closest?.('[data-ida-drop]')?.classList.remove('dragging'));
  document.addEventListener('drop',async(event)=>{const target=event.target.closest?.('[data-ida-drop]');if(!target)return;event.preventDefault();target.classList.remove('dragging');const file=event.dataTransfer?.files?.[0];if(file)await dropSnapshot(file);});

  render();
})();