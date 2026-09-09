(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function') return;

  const TOOL = 'ai-model-arithmetic-auto';
  const MAX_FILE_BYTES = 64 * 1024 * 1024;
  const MAX_TOTAL_BYTES = 96 * 1024 * 1024;
  let selectedFiles = [];
  let result = null;
  let busy = false;
  let errorText = '';

  TOOL_META[TOOL] = { domain:'ai', title:'Model Arithmetic / Hidden Head', label:'ZIP / challenge files', placeholder:'' };
  if (!(DOMAINS.ai.tools || []).some((item) => item[0] === TOOL)) {
    DOMAINS.ai.tools.unshift([TOOL, 'Model Arithmetic / Hidden Head', '直接拖 ZIP 或题目文件，恢复 bounded modular hidden head、唯一 secret，并尝试可解释的 Flag recovery。']);
  }
  const previousToolView = toolView;

  function bytesToBase64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let index = 0; index < bytes.length; index += chunk) binary += String.fromCharCode(...bytes.subarray(index, Math.min(bytes.length, index + chunk)));
    return btoa(binary);
  }

  async function payloadFromFiles(files) {
    const rows = [...files].filter(Boolean);
    if (!rows.length) throw new Error('没有选择文件');
    let total = 0;
    for (const file of rows) {
      if (file.size > MAX_FILE_BYTES) throw new Error(`${file.name} 超过 64 MiB 上限`);
      total += file.size;
      if (total > MAX_TOTAL_BYTES) throw new Error('输入文件总量超过 96 MiB 上限');
    }
    if (rows.length === 1 && /\.zip$/i.test(rows[0].name)) {
      const bytes = new Uint8Array(await rows[0].arrayBuffer());
      return { base64: bytesToBase64(bytes), fileName: rows[0].name };
    }
    const packed = [];
    for (const file of rows) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      packed.push({ name: file.webkitRelativePath || file.name, base64: bytesToBase64(bytes) });
    }
    return { files: packed };
  }

  function statusClass(status) {
    if (status === 'flag-recovered') return 'solved';
    if (status === 'secret-recovered') return 'secret';
    if (/gap|missing|incomplete|identified/.test(status || '')) return 'gap';
    return 'idle';
  }

  function stages() {
    const status = result?.status || '';
    const hasArtifacts = Boolean(result?.artifactSummary);
    const hasModel = Boolean(result?.sourceInspection?.boundedLinearHead);
    const hasSystem = Boolean(result?.featureSystem?.rows);
    const hasSecret = result?.solver?.status === 'unique';
    const hasFlag = status === 'flag-recovered';
    const items = [
      ['ARTIFACTS', hasArtifacts], ['MODEL', hasModel], ['SYSTEM BUILT', hasSystem], ['SECRET', hasSecret], ['FLAG RECOVERED', hasFlag]
    ];
    return `<div class="model-arith-stage-rail">${items.map(([label,done],index) => `<div class="model-arith-stage ${done ? 'done' : result && !done && items.slice(0,index).every((x)=>x[1]) ? 'current' : ''}"><i>${String(index+1).padStart(2,'0')}</i><b>${label}</b></div>`).join('<span>→</span>')}</div>`;
  }

  function sourceEvidence() {
    const inspection = result?.sourceInspection;
    if (!inspection) return '<p class="model-arith-muted">尚未分析源码证据。</p>';
    const groups = [
      ['DOT / LINEAR HEAD', inspection.evidence?.dot], ['BOUNDED NOISE', inspection.evidence?.boundedNoise], ['MODULO', inspection.evidence?.modulo], ['CNN FRONTEND', [...(inspection.evidence?.conv||[]), ...(inspection.evidence?.pool||[]), ...(inspection.evidence?.mix||[])]]
    ];
    return `<div class="model-arith-evidence">${groups.map(([label,items]) => `<section><div><b>${label}</b><span>${items?.length ? 'EVIDENCE' : 'NONE'}</span></div>${items?.length ? items.slice(0,5).map((item)=>`<code>L${item.line} ${esc(item.text)}</code>`).join('') : '<small>未检测到该类静态证据</small>'}</section>`).join('')}</div>`;
  }

  function artifactPanel() {
    const summary = result?.artifactSummary;
    if (!summary) return '';
    return `<section class="model-arith-panel"><header><b>ARTIFACT MAP</b><span>${summary.files?.length || 0} FILES</span></header><div class="model-arith-files">${(summary.files||[]).slice(0,80).map((file)=>`<div><b>${esc(file.name)}</b><span>${fmtBytes(file.bytes)}</span></div>`).join('')}</div><div class="model-arith-npy">${(summary.npyFiles||[]).map((file)=>`<div class="${file.supported ? 'ok' : 'bad'}"><b>${esc(file.fileName)}</b><span>${esc(file.dtype || 'unknown')}</span><code>${(file.shape||[]).join(' × ') || 'shape ?'}</code></div>`).join('')}</div></section>`;
  }

  function systemPanel() {
    if (!result) return '';
    const pub = result.publicConfig || {};
    const pair = result.samplePair || {};
    const system = result.featureSystem || {};
    const solver = result.solver || {};
    const candidate = solver.candidates?.[0];
    return `<section class="model-arith-panel"><header><b>MODEL / MODULAR SYSTEM</b><span>${esc(system.method || result.status || 'not built')}</span></header>
      <div class="model-arith-metrics">
        <div><span>SAMPLES</span><b>${pair.samples ?? '—'}</b></div><div><span>DIMENSION</span><b>${system.dimension ?? '—'}</b></div><div><span>MODULUS q</span><b>${pub.modulus ?? '—'}</b></div><div><span>BOUND</span><b>${pub.noiseBound ?? '—'}</b></div><div><span>ENUMERATIONS</span><b>${solver.enumerations ?? solver.enumerationsRequested ?? '—'}</b></div><div><span>SOLVER</span><b>${esc(solver.status || '—')}</b></div>
      </div>
      ${pair.input ? `<div class="model-arith-pair"><span>${esc(pair.input)} <b>${(pair.inputShape||[]).join('×')}</b></span><i>→ FEATURE A →</i><span>${esc(pair.output)} <b>${(pair.outputShape||[]).join('×')}</b></span></div>` : ''}
      ${candidate ? `<div class="model-arith-secret"><div><span>SECRET · SIGNED</span><code>[${candidate.secretSigned.join(', ')}]</code></div><div><span>SECRET · MOD q</span><code>[${candidate.secretMod.join(', ')}]</code></div><div class="verify"><b>VERIFY</b><span>${candidate.residuals.length}/${pair.samples || candidate.residuals.length} equations</span><span>max |residual| = ${candidate.maxAbsResidual ?? '—'}</span></div></div>` : `<div class="model-arith-gap"><b>${esc(result.gap || solver.notes?.[0] || '还没有唯一 secret')}</b><p>${(result.notes||[])[0] ? esc(result.notes[0]) : '工具不会在证据不足时猜 secret。'}</p></div>`}
    </section>`;
  }

  function flagPanel() {
    if (!result) return '';
    const recovery = result.flagRecovery;
    if (!recovery) return `<section class="model-arith-panel"><header><b>FLAG RECOVERY</b><span>WAITING SECRET</span></header><p class="model-arith-muted">只有 solver 得到唯一 secret 后才进入 serialization / KDF / cipher 阶段。</p></section>`;
    const best = recovery.hits?.find((hit)=>hit.flags?.length) || recovery.hits?.[0];
    return `<section class="model-arith-panel flag-panel ${recovery.status === 'flag-recovered' ? 'solved' : ''}"><header><b>FLAG RECOVERY</b><span>${esc(recovery.status)}</span></header>
      ${recovery.flag ? `<div class="model-arith-flag"><span>FLAG RECOVERED</span><strong>${esc(recovery.flag)}</strong><button class="button primary" data-model-arith-copy>复制 Flag</button></div>` : '<p class="model-arith-muted">没有满足严格 Flag oracle 的解密结果；保留 secret，不把普通可打印明文冒充 Flag。</p>'}
      <div class="model-arith-metrics compact"><div><span>SERIALIZATIONS</span><b>${recovery.serializationCount}</b></div><div><span>KEY CANDIDATES</span><b>${recovery.keyCandidateCount}</b></div><div><span>CIPHERS</span><b>${recovery.cipherFiles?.length || 0}</b></div><div><span>IV</span><b>${recovery.explicitIvCount || 0}</b></div></div>
      ${best ? `<div class="model-arith-derivation"><span>${esc(best.file)}</span><code>${esc(best.serialization)} → ${esc(best.kdf)} → ${esc(best.algorithm)}</code>${best.ivSource ? `<small>IV ${esc(best.ivSource)}</small>` : ''}</div>` : ''}
    </section>`;
  }

  function resultBody() {
    if (!result) return `<div class="model-arith-empty"><span>MODEL ARITHMETIC</span><b>DROP ZIP</b><p>目标：从题目源码 / public config / NPY 样本恢复 hidden linear head。不会执行 task.py，也不会加载 pickle。</p><div><i>A·s + e = b (mod q)</i><i>|e| ≤ B</i></div></div>`;
    return `${artifactPanel()}<section class="model-arith-panel"><header><b>STATIC PROOF</b><span>${result.sourceInspection?.boundedLinearHead ? 'BOUNDED LINEAR HEAD' : 'NOT PROVEN'}</span></header>${sourceEvidence()}</section>${systemPanel()}${flagPanel()}`;
  }

  toolView = function modelArithmeticView(tool) {
    if (tool !== TOOL) return previousToolView(tool);
    return `<div class="page-head tool-head model-arith-head"><div><span class="kicker">DETERMINISTIC MODEL ARITHMETIC</span><h1>Hidden Head Recovery</h1><p>ZIP → feature system → bounded modular solve → secret → reproducible Flag recovery。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="model-arith-workbench ${statusClass(result?.status)}">
        <article class="panel model-arith-input" data-model-arith-drop>
          <div class="model-arith-input-head"><div><b>CHALLENGE BUNDLE</b><span>ZIP 或解压后的多文件 / 目录</span></div><em>${busy ? 'SOLVING…' : 'LOCAL · NO EXEC'}</em></div>
          <div class="model-arith-drop ${selectedFiles.length ? 'loaded' : ''}"><div><span>Σ</span><div><b>${selectedFiles.length ? esc(selectedFiles.length === 1 ? selectedFiles[0].name : `${selectedFiles.length} files selected`) : 'DROP ZIP'}</b><small>${selectedFiles.length ? selectedFiles.map((file)=>file.name).slice(0,4).map(esc).join(' · ') : 'task.py / public.json / inputs.npy / outputs.npy / cipher.bin 等均可自动配对'}</small></div></div><div><button class="button primary" data-model-arith-pick>选择 ZIP / 文件</button><button class="button ghost" data-model-arith-folder>选择目录</button>${selectedFiles.length ? '<button class="text-button" data-model-arith-clear>清空</button>' : ''}</div></div>
          <input id="model-arith-files" type="file" multiple accept=".zip,.npy,.json,.py,.pyw,.bin,.enc,.dat" />
          <input id="model-arith-folder" type="file" webkitdirectory multiple />
          ${errorText ? `<div class="model-arith-error">${esc(errorText)}</div>` : ''}
        </article>
        ${stages()}
        <article class="model-arith-results">${resultBody()}</article>
      </div>`;
  };

  async function analyze(files) {
    selectedFiles = [...files];
    errorText = '';
    result = null;
    busy = true;
    render();
    try {
      const input = await payloadFromFiles(selectedFiles);
      result = await window.newcyber.runTool(TOOL, { input });
    } catch (error) {
      errorText = error?.message || String(error);
      result = null;
    } finally {
      busy = false;
      render();
    }
  }

  document.addEventListener('click', async (event) => {
    if (event.target.closest('[data-model-arith-pick]')) { document.querySelector('#model-arith-files')?.click(); return; }
    if (event.target.closest('[data-model-arith-folder]')) { document.querySelector('#model-arith-folder')?.click(); return; }
    if (event.target.closest('[data-model-arith-clear]')) { selectedFiles=[]; result=null; errorText=''; render(); return; }
    if (event.target.closest('[data-model-arith-copy]') && result?.flag) {
      try { await navigator.clipboard.writeText(result.flag); toast('Flag 已复制'); } catch { toast('复制失败', true); }
    }
  });
  document.addEventListener('change', async (event) => {
    if (!['model-arith-files','model-arith-folder'].includes(event.target?.id)) return;
    if (event.target.files?.length) await analyze(event.target.files);
  });
  document.addEventListener('dragover', (event) => {
    const target = event.target.closest?.('[data-model-arith-drop]');
    if (!target) return;
    event.preventDefault();
    target.classList.add('dragging');
  });
  document.addEventListener('dragleave', (event) => event.target.closest?.('[data-model-arith-drop]')?.classList.remove('dragging'));
  document.addEventListener('drop', async (event) => {
    const target = event.target.closest?.('[data-model-arith-drop]');
    if (!target) return;
    event.preventDefault();
    target.classList.remove('dragging');
    if (event.dataTransfer?.files?.length) await analyze(event.dataTransfer.files);
  });

  render();
})();