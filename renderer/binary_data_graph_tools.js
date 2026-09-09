(() => {
  if (typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof commonView !== 'function') return;

  const TOOL = 'binary-data-graph';
  const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
  let sourceText = '';
  let inputMode = 'elf';
  let binaryFile = null;
  let analysis = null;
  let selectedObjectId = null;
  let busy = false;
  let errorText = '';
  let expandedRecoverable = null;

  TOOL_META[TOOL] = { domain:'common', title:'Binary Data Graph', label:'ELF / IDA / Ghidra', placeholder:'' };
  const previousCommonView = commonView;
  const previousToolView = toolView;

  commonView = function binaryDataCommonView() {
    let html = previousCommonView();
    const card = `<button class="tool-card bdg-entry-card" data-tool="${TOOL}"><span>REVERSE</span><strong>Binary Data Graph</strong><p>直接读 ELF，或导入 IDA/Ghidra listing，恢复 data/object/relation/expression。</p><em>打开</em></button>`;
    return html.replace('<div class="tool-grid">', `<div class="tool-grid">${card}`);
  };

  function selectedObject() {
    return analysis?.objects?.find((item) => item.id === selectedObjectId) || analysis?.objects?.[0] || null;
  }
  function fmtConfidence(value) {
    const n = Number(value); return Number.isFinite(n) ? `${Math.round(n * 100)}%` : '—';
  }
  function endpointLabel(id) {
    const object = analysis?.objects?.find((item) => item.id === id);
    if (object) return object.name;
    const operation = analysis?.operations?.find((item) => item.id === id);
    if (operation) return operation.op;
    if (String(id || '').startsWith('fn_')) return String(id).slice(3);
    if (String(id || '').startsWith('addr_')) return `0x${String(id).slice(5)}`;
    return id || '?';
  }
  function formatAddress(base, offset) {
    try { return `0x${(BigInt(base) + BigInt(offset)).toString(16)}`; } catch { return base || '—'; }
  }
  function chooseDefaultObject(result) {
    return result?.objects?.find((object) => object.kind === 'go_slice')?.id || result?.semanticCandidates?.[0]?.object || result?.objects?.[0]?.id || null;
  }

  function sourceModeTabs() {
    return `<div class="bdg-mode-tabs"><button class="${inputMode === 'elf' ? 'active' : ''}" data-bdg-mode="elf">ELF FILE</button><button class="${inputMode === 'listing' ? 'active' : ''}" data-bdg-mode="listing">IDA / GHIDRA LISTING</button></div>`;
  }

  function elfSourceBar() {
    const meta = analysis?.source?.kind === 'elf' ? analysis.source.elf : null;
    return `<section class="panel bdg-sourcebar bdg-sourcebar-elf ${busy ? 'busy' : ''}" data-bdg-drop>
      <div class="bdg-sourcebar-head"><div><b>BINARY SOURCE</b><span>直接解析 ELF32/ELF64；不会执行附件</span></div>${sourceModeTabs()}</div>
      <div class="bdg-elf-drop ${binaryFile ? 'loaded' : ''}">
        <div><span class="bdg-elf-mark">ELF</span><div><b>${esc(binaryFile?.fileName || '拖入 Linux ELF / .so / 可执行文件')}</b><small>${binaryFile ? `${fmtBytes(binaryFile.size)}${meta ? ` · ELF${meta.bits} · ${esc(meta.machine)} · ${esc(meta.type)}` : ''}` : 'Physical → Object → Relation；Expression IR 仍由 listing 模式补充'}</small></div></div>
        <div class="bdg-source-actions"><button class="button primary" data-bdg-choose-elf>${binaryFile ? '更换 ELF' : '选择 ELF'}</button>${binaryFile ? '<button class="text-button" data-bdg-clear>清空</button>' : ''}</div>
      </div>
      ${meta ? `<div class="bdg-elf-meta"><span>ENTRY <b>${esc(meta.entry)}</b></span><span>GO <b>${meta.goLikely ? 'LIKELY' : 'NO EVIDENCE'}</b></span><span>PARSER <b>${esc(analysis.source.parser || '')}</b></span></div>` : ''}
      ${errorText ? `<div class="bdg-inline-error">${esc(errorText)}</div>` : ''}
    </section>`;
  }

  function listingSourceBar() {
    return `<section class="panel bdg-sourcebar ${busy ? 'busy' : ''}" data-bdg-drop>
      <div class="bdg-sourcebar-head"><div><b>LISTING SOURCE</b><span>用于恢复 XOR/CMP、XREF 与 Expression IR</span></div>${sourceModeTabs()}</div>
      <div class="bdg-listing-row"><textarea id="bdg-source" spellcheck="false" placeholder=".data:000000000054FAE0 off_54FAE0 dq offset byte_54A3E0">${esc(sourceText)}</textarea><div class="bdg-source-actions vertical"><button class="button ghost" data-bdg-pick-listing>打开 .asm/.lst/.txt</button><button class="button primary" data-bdg-analyze>${busy ? '分析中…' : 'Analyze'}</button>${analysis ? '<button class="text-button" data-bdg-clear>清空</button>' : ''}</div></div>
      <input id="bdg-listing-file" class="bdg-file-input" type="file" accept=".asm,.lst,.txt,.map,.inc" />
      ${errorText ? `<div class="bdg-inline-error">${esc(errorText)}</div>` : ''}
    </section>`;
  }
  function sourceBar() { return inputMode === 'elf' ? elfSourceBar() : listingSourceBar(); }

  function summaryBar() {
    if (!analysis) return '';
    const s = analysis.summary || {};
    const base = [`<span><b>${s.sections || 0}</b> sections</span>`,`<span><b>${s.objects || 0}</b> objects</span>`,`<span><b>${s.importantRelations || 0}</b> relations</span>`];
    if (analysis.source?.kind === 'elf') base.push(`<span><b>${s.symbols || 0}</b> symbols</span>`,`<span><b>${s.functions || 0}</b> funcs</span>`,`<span><b>${s.relocations || 0}</b> relocs</span>`,`<span><b>${s.sliceCandidates || 0}</b> slices</span>`);
    else base.push(`<span><b>${s.operations || 0}</b> ops</span>`,`<span><b>${s.semanticCandidates || 0}</b> semantic</span>`,`<span><b>${s.recoverableRelations || 0}</b> recoverable</span>`);
    return `<div class="bdg-summary-bar">${base.join('')}</div>`;
  }

  function objectNav() {
    if (!analysis) return `<aside class="panel bdg-nav"><div class="bdg-empty"><b>SECTIONS / OBJECTS</b><p>${inputMode === 'elf' ? '打开 ELF 后按 section 展示 symbol、string、pointer 与 slice。' : '分析 listing 后按 section 展示恢复对象。'}</p></div></aside>`;
    const objects = analysis.objects || [];
    return `<aside class="panel bdg-nav"><div class="bdg-pane-head"><b>SECTIONS / OBJECTS</b><span>${objects.length}</span></div><div class="bdg-nav-scroll">${(analysis.sections || []).map((section) => {
      const rows = objects.filter((object) => object.section === section.name);
      if (!rows.length && analysis.source?.kind !== 'elf') return '';
      return `<section class="bdg-section-group"><div class="bdg-section-title"><b>${esc(section.name)}</b><span>${rows.length}${section.size != null ? ` · ${fmtBytes(section.size)}` : ''}</span></div>${rows.slice(0,800).map((object) => `<button class="bdg-object-row ${object.id === selectedObjectId ? 'active' : ''}" data-bdg-object="${esc(object.id)}"><span class="bdg-kind-dot ${esc(object.kind)}"></span><div><b>${esc(object.name)}</b><small>${esc(object.address)} · ${esc(object.kind)} · ${object.size || 0}B</small></div>${object.semanticSuggestions?.length ? `<em>${Math.round(Math.max(...object.semanticSuggestions.map((item) => item.confidence || 0))*100)}</em>` : ''}</button>`).join('')}</section>`;
    }).join('')}</div></aside>`;
  }

  function hexView(object) {
    if (!object?.bytesHex) return `<div class="bdg-no-bytes"><b>没有文件字节预览</b><p>可能是 NOBITS、结构对象或超出当前预览范围。</p></div>`;
    const bytes = object.bytesHex.split(/\s+/).filter(Boolean).map((hex) => parseInt(hex,16));
    const rows = [];
    for (let offset=0; offset<bytes.length; offset+=16) {
      const chunk = bytes.slice(offset,offset+16);
      const hexText = chunk.map((value) => value.toString(16).padStart(2,'0').toUpperCase()).join(' ');
      const ascii = chunk.map((value) => value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.').join('');
      rows.push(`<div class="bdg-hex-row"><span>${formatAddress(object.address,offset)}</span><code>${hexText}</code><em>${esc(ascii)}</em></div>`);
    }
    return `<div class="bdg-hex-view">${rows.join('')}</div>${object.bytesTruncated ? `<p class="bdg-muted">仅显示前 ${object.bytesPreviewSize || bytes.length} bytes；对象总长 ${object.size} bytes。</p>` : ''}`;
  }
  function fieldsView(object) {
    if (!object?.fields?.length) return '';
    return `<section class="bdg-object-section"><div class="bdg-minor-head"><b>FIELDS</b><span>${esc(object.kind)}</span></div><div class="bdg-field-table">${object.fields.map((field) => `<div><code>+0x${Number(field.offset).toString(16).padStart(2,'0')}</code><b>${esc(field.name)}</b><span>${esc(field.value)}</span>${field.target ? `<button data-bdg-object="${esc(field.target)}">→</button>` : ''}</div>`).join('')}</div></section>`;
  }
  function objectPane() {
    const object = selectedObject();
    if (!object) return `<main class="panel bdg-object-pane"><div class="bdg-empty"><b>DATA / OBJECT</b><p>选中对象后显示 Hex、字段和结构证据。</p></div></main>`;
    const semanticName = object.semanticSuggestions?.[0]?.label || '—';
    const nameLabel = analysis?.source?.kind === 'elf' ? 'ELF / Symbol name' : 'IDA / Listing name';
    return `<main class="panel bdg-object-pane"><div class="bdg-pane-head"><div><b>${esc(object.name)}</b><span>${esc(object.address)} · ${esc(object.section)}</span></div><div class="bdg-object-tags"><i>${esc(object.kind)}</i>${object.source ? `<i>${esc(String(object.source).toUpperCase())}</i>` : ''}</div></div><div class="bdg-object-scroll"><section class="bdg-object-identity"><div><span>${nameLabel}</span><b>${esc(object.name)}</b></div><div><span>Structural name</span><b>${esc(object.structuralName || '—')}</b></div><div><span>Suggested semantic</span><b>${esc(semanticName)}</b></div></section>${fieldsView(object)}<section class="bdg-object-section"><div class="bdg-minor-head"><b>HEX VIEW</b><span>${object.size || 0} bytes</span></div>${hexView(object)}</section>${object.ascii ? `<section class="bdg-object-section"><div class="bdg-minor-head"><b>ASCII</b><span>secondary view</span></div><pre class="bdg-ascii">${esc(object.ascii)}</pre></section>` : ''}</div></main>`;
  }

  function relationRows(object) {
    if (!analysis || !object) return '';
    const rows = (analysis.relations || []).filter((item) => item.source === object.id || item.target === object.id || item.operationNode === object.id);
    if (!rows.length) return '<p class="bdg-muted">当前对象没有已恢复关系。</p>';
    return rows.slice(0,32).map((relation) => `<div class="bdg-relation-row ${relation.source === object.id ? 'outgoing' : 'incoming'}"><div><span>${esc(endpointLabel(relation.source))}</span><b>${esc(relation.type)}</b><span>${esc(endpointLabel(relation.target))}</span></div><small>${relation.location ? esc(relation.location) : ''}${relation.confidence != null ? ` · ${fmtConfidence(relation.confidence)}` : ''}</small>${relation.evidence?.[0] ? `<code>${esc(relation.evidence[0])}</code>` : ''}</div>`).join('');
  }
  function semanticRows(object) {
    const items = object?.semanticSuggestions || [];
    if (!items.length) return '<p class="bdg-muted">没有形成语义候选；这不代表对象无意义。</p>';
    return items.map((item) => `<div class="bdg-semantic-card"><div><b>${esc(item.label)}</b><strong>${Math.round((item.confidence || 0)*100)}%</strong></div>${(item.evidence || []).map((e) => `<p>✓ ${esc(e)}</p>`).join('')}</div>`).join('');
  }
  function recoverableRows(object) {
    if (!analysis || !object) return '';
    const rows = (analysis.recoverableRelations || []).filter((item) => (item.objects || []).includes(object.id));
    if (!rows.length) return `<p class="bdg-muted">${analysis.source?.kind === 'elf' ? 'ELF 原始模式目前不伪造可逆 Expression；切换 Listing 可恢复 XOR/CMP。' : '当前对象没有可逆关系。'}</p>`;
    return rows.map((item) => {
      const expanded = expandedRecoverable === item.id; const verify = item.verification;
      return `<div class="bdg-recover-card"><div class="bdg-recover-title"><span>RECOVERABLE XOR</span><b>${esc(item.equation)}</b></div><div class="bdg-derivations">${(item.derivations || []).map((line) => `<code>${esc(line)}</code>`).join('')}</div>${verify ? `<div class="bdg-verify ${verify.holdsForKnownBytes === true ? 'ok' : verify.holdsForKnownBytes === false ? 'bad' : 'neutral'}"><span>${verify.holdsForKnownBytes === true ? 'KNOWN BYTES VERIFIED' : verify.holdsForKnownBytes === false ? `${verify.mismatches} MISMATCHES` : 'DERIVABLE'}</span><b>${verify.checkedBytes || 0} bytes</b></div><button class="text-button" data-bdg-recover="${esc(item.id)}">${expanded ? '收起推导字节' : '查看推导字节'}</button>${expanded ? `<pre class="bdg-derived">${esc(verify.derivedHex || '')}\n${esc(verify.derivedAscii || '')}</pre>` : ''}` : ''}</div>`;
    }).join('');
  }
  function relationPane() {
    const object = selectedObject();
    return `<aside class="panel bdg-relation-pane"><div class="bdg-pane-head"><b>RELATIONS</b><span>fact → semantic</span></div><div class="bdg-relation-scroll"><section><div class="bdg-minor-head"><b>RELATION GRAPH</b><span>${object ? esc(object.name) : '—'}</span></div>${relationRows(object)}</section><section><div class="bdg-minor-head"><b>SEMANTIC</b><span>confidence + evidence</span></div>${semanticRows(object)}</section><section><div class="bdg-minor-head"><b>INVERSION</b><span>symbolic</span></div>${recoverableRows(object)}</section></div></aside>`;
  }

  function operationClass(op) { return /^CMP/.test(op) ? 'compare' : ['XOR','ADD','SUB','ROL','ROR','NOT'].includes(op) ? 'transform' : 'generic'; }
  function evidencePane() {
    if (!analysis) return `<section class="panel bdg-evidence-pane"><div class="bdg-empty inline"><b>EXPRESSION / EVIDENCE</b><p>Listing 显示 Operation Node；ELF 显示 symbol/relocation/structure evidence。</p></div></section>`;
    const object = selectedObject();
    const operations = (analysis.operations || []).filter((operation) => !object || (analysis.relations || []).some((relation) => (relation.source === object.id || relation.target === object.id) && (relation.target === operation.id || relation.operationNode === operation.id)) || operation.pseudo?.includes(object.name)).slice(0,18);
    const relationEvidence = (analysis.relations || []).filter((relation) => object && (relation.source === object.id || relation.target === object.id)).flatMap((relation) => (relation.evidence || []).map((text) => ({ kind:relation.type, text, line:null })));
    const evidence = [...(object?.evidence || []), ...(object?.cellEvidence || []).filter((item) => item.comment).map((item) => ({kind:'cell',line:item.line,text:`${item.address} ${item.directive} ${item.values.join(', ')} ; ${item.comment}`})), ...relationEvidence].slice(0,28);
    const leftTitle = analysis.source?.kind === 'elf' ? 'EXPRESSION IR · NOT LIFTED' : 'EXPRESSION IR';
    return `<section class="panel bdg-evidence-pane"><div class="bdg-evidence-grid"><div><div class="bdg-pane-head"><b>${leftTitle}</b><span>Operation nodes</span></div><div class="bdg-operation-list">${operations.length ? operations.map((operation) => `<div class="bdg-op-row ${operationClass(operation.op)}"><span>${esc(operation.op)}</span><code>${esc(operation.pseudo)}</code><em>${esc(operation.location || '')}</em></div>`).join('') : `<p class="bdg-muted">${analysis.source?.kind === 'elf' ? '原始 ELF 本轮只做 Physical/Object/Relation；不在没有反汇编器时伪造 XOR/CMP。' : '该对象暂未绑定到表达式节点。'}</p>`}</div></div><div><div class="bdg-pane-head"><b>EVIDENCE / XREF</b><span>${analysis.source?.kind === 'elf' ? 'symbol · relocation · structure' : 'source lines'}</span></div><div class="bdg-evidence-list">${evidence.length ? evidence.map((item) => `<div><span>${esc(item.kind || 'evidence')}</span><code>${esc(item.text || '')}</code>${item.line ? `<em>L${item.line}</em>` : ''}</div>`).join('') : '<p class="bdg-muted">没有附加证据。</p>'}</div></div></div></section>`;
  }

  function workbench() { return `<div class="bdg-workbench ${inputMode === 'elf' ? 'elf-mode' : 'listing-mode'}">${sourceBar()}${summaryBar()}<div class="bdg-columns">${objectNav()}${objectPane()}${relationPane()}</div>${evidencePane()}</div>`; }
  toolView = function binaryDataGraphView(tool) {
    if (tool !== TOOL) return previousToolView(tool);
    return `<div class="page-head tool-head bdg-head"><div><span class="kicker">REVERSE DATA EXPLORER</span><h1>Binary Data Graph</h1><p>ELF / Listing → Data → Object → Relation → Expression。事实层与语义推断分离。</p></div><div class="bdg-head-actions"><button class="text-button" data-bdg-copy ${analysis ? '' : 'disabled'}>复制摘要</button><button class="button ghost" data-view="common">返回</button></div></div>${workbench()}`;
  };

  async function analyzeListing() {
    const textarea = document.querySelector('#bdg-source'); if (textarea) sourceText = textarea.value;
    if (!sourceText.trim()) { errorText='请先粘贴或拖入 textual listing'; render(); return; }
    errorText=''; busy=true; render();
    try { analysis=await window.newcyber.runTool(TOOL,{input:sourceText}); binaryFile=null; selectedObjectId=chooseDefaultObject(analysis); expandedRecoverable=null; }
    catch(error){ analysis=null; selectedObjectId=null; errorText=error?.message||String(error); }
    finally{ busy=false; render(); }
  }
  async function analyzeElfPicked() {
    errorText=''; busy=true; render();
    try { const result=await window.newcyber.chooseAndAnalyzeBinary(); if(!result){busy=false;render();return;} binaryFile={fileName:result.fileName,size:result.size,filePath:result.filePath}; analysis=result.analysis; sourceText=''; selectedObjectId=chooseDefaultObject(analysis); expandedRecoverable=null; }
    catch(error){ analysis=null; binaryFile=null; selectedObjectId=null; errorText=error?.message||String(error); }
    finally{ busy=false; render(); }
  }
  async function analyzeDroppedElf(file) {
    errorText=''; busy=true; render();
    try { const result=await window.newcyber.analyzeDroppedBinary(file); binaryFile={fileName:result.fileName,size:result.size,filePath:result.filePath}; analysis=result.analysis; sourceText=''; inputMode='elf'; selectedObjectId=chooseDefaultObject(analysis); expandedRecoverable=null; }
    catch(error){ analysis=null; binaryFile=null; selectedObjectId=null; errorText=error?.message||String(error); }
    finally{ busy=false; render(); }
  }
  function readTextFile(file) {
    if (!file) return Promise.reject(new Error('没有文件'));
    if (file.size > MAX_SOURCE_BYTES) return Promise.reject(new Error('listing 文件超过 2 MiB 上限'));
    return file.text();
  }
  async function isElfFile(file) {
    if (!file) return false;
    const head = new Uint8Array(await file.slice(0,4).arrayBuffer());
    return head.length === 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
  }
  function resetForMode(mode) { inputMode=mode; analysis=null; selectedObjectId=null; expandedRecoverable=null; errorText=''; if(mode==='elf') sourceText=''; else binaryFile=null; render(); }
  function copySummary() {
    if (!analysis) return '';
    const s=analysis.summary||{};
    const lines=[`Binary Data Graph (${analysis.source?.kind || 'unknown'}): ${s.objects||0} objects / ${s.importantRelations||0} important relations`];
    if(analysis.source?.kind==='elf') lines.push(`ELF${analysis.source.elf?.bits} ${analysis.source.elf?.machine} ${analysis.source.elf?.type} entry=${analysis.source.elf?.entry}`,`symbols=${s.symbols||0} functions=${s.functions||0} relocations=${s.relocations||0} slices=${s.sliceCandidates||0}`);
    lines.push(...(analysis.recoverableRelations||[]).map((item)=>`RECOVERABLE ${item.equation}${item.verification?` · verified=${item.verification.holdsForKnownBytes}`:''}`),...(analysis.semanticCandidates||[]).slice(0,8).map((item)=>`${item.label}: ${item.objectName} ${Math.round((item.confidence||0)*100)}% · ${(item.evidence||[]).join(' / ')}`));
    return lines.join('\n');
  }

  document.addEventListener('input',(event)=>{ if(event.target?.id==='bdg-source') sourceText=event.target.value; });
  document.addEventListener('click',async(event)=>{
    const mode=event.target.closest('[data-bdg-mode]'); if(mode){resetForMode(mode.dataset.bdgMode);return;}
    if(event.target.closest('[data-bdg-choose-elf]')){await analyzeElfPicked();return;}
    if(event.target.closest('[data-bdg-analyze]')){await analyzeListing();return;}
    if(event.target.closest('[data-bdg-pick-listing]')){document.querySelector('#bdg-listing-file')?.click();return;}
    if(event.target.closest('[data-bdg-clear]')){sourceText='';binaryFile=null;analysis=null;selectedObjectId=null;expandedRecoverable=null;errorText='';render();return;}
    const objectButton=event.target.closest('[data-bdg-object]'); if(objectButton){selectedObjectId=objectButton.dataset.bdgObject;expandedRecoverable=null;render();return;}
    const recover=event.target.closest('[data-bdg-recover]'); if(recover){expandedRecoverable=expandedRecoverable===recover.dataset.bdgRecover?null:recover.dataset.bdgRecover;render();return;}
    if(event.target.closest('[data-bdg-copy]')&&analysis){try{await navigator.clipboard.writeText(copySummary());toast('Binary Data Graph 摘要已复制');}catch{toast('复制失败',true);}}
  });
  document.addEventListener('change',async(event)=>{
    if(event.target?.id!=='bdg-listing-file')return; const file=event.target.files?.[0]; if(!file)return;
    try{sourceText=await readTextFile(file);analysis=null;selectedObjectId=null;errorText='';render();await analyzeListing();}catch(error){errorText=error?.message||String(error);render();}
  });
  document.addEventListener('dragover',(event)=>{const target=event.target.closest?.('[data-bdg-drop]');if(!target)return;event.preventDefault();target.classList.add('dragging');});
  document.addEventListener('dragleave',(event)=>event.target.closest?.('[data-bdg-drop]')?.classList.remove('dragging'));
  document.addEventListener('drop',async(event)=>{
    const target=event.target.closest?.('[data-bdg-drop]');if(!target)return;event.preventDefault();target.classList.remove('dragging');const file=event.dataTransfer?.files?.[0];if(!file)return;
    try{if(await isElfFile(file)){await analyzeDroppedElf(file);}else{inputMode='listing';sourceText=await readTextFile(file);analysis=null;binaryFile=null;selectedObjectId=null;errorText='';render();await analyzeListing();}}catch(error){busy=false;errorText=error?.message||String(error);render();}
  });

  render();
})();