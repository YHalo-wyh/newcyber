(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function') return;

  const TOOL = 'ai-power-side-channel';
  let traceBundle = null;
  let features = null;
  let runtime = null;
  let onnx = null;
  let busy = '';
  let errorText = '';

  TOOL_META[TOOL] = { domain:'ai', title:'Power SCA / Local ML Oracle', label:'NPY trace + template + ONNX', placeholder:'' };
  if (!(DOMAINS.ai.tools || []).some((item) => item[0] === TOOL)) {
    DOMAINS.ai.tools.unshift([TOOL, 'Power SCA / Local ML Oracle', '流式读取大型功耗 trace，恢复窗口特征/回归/伪逆条件，并挂载受限 ONNX 本地模型 oracle。']);
  }

  const previousToolView = toolView;

  function statusPill(ok, yes='READY', no='WAIT') {
    return `<span class="sca-pill ${ok ? 'ok' : 'wait'}">${ok ? yes : no}</span>`;
  }

  function pipeline() {
    const analysis = traceBundle?.analysis;
    const source = analysis?.sourceInspection;
    const items = [
      ['TRACE', Boolean(analysis?.trace)],
      ['LAYOUT', analysis?.layout?.status === 'resolved'],
      ['WINDOWS', Boolean(features?.features?.length)],
      ['MODEL ORACLE', Boolean(onnx?.model)],
      ['INVERSION', Boolean(source?.evidence?.pinv?.length || source?.evidence?.regression?.length)]
    ];
    return `<div class="sca-pipeline">${items.map(([label, done], index) => `<div class="${done ? 'done' : ''}"><i>${String(index + 1).padStart(2,'0')}</i><b>${label}</b></div>${index < items.length - 1 ? '<span>→</span>' : ''}`).join('')}</div>`;
  }

  function tracePanel() {
    const analysis = traceBundle?.analysis;
    if (!analysis) return `<section class="sca-panel sca-empty"><b>TRACE BUNDLE</b><p>拖入 <code>target_power_trace.npy</code> 与模板源码。大 NPY 只传文件路径引用，主进程按窗口读取，不做 base64 整文件复制。</p></section>`;
    const trace = analysis.trace || {};
    const layout = analysis.layout || {};
    return `<section class="sca-panel"><header><div><b>TRACE LAYOUT</b><span>${esc(trace.fileName || '')}</span></div>${statusPill(layout.status === 'resolved', 'RESOLVED', 'NEEDS WIDTH')}</header>
      <div class="sca-metrics">
        <div><span>SIZE</span><b>${fmtBytes(trace.bytes || 0)}</b></div>
        <div><span>DTYPE</span><b>${esc(trace.dtype || '—')}</b></div>
        <div><span>ELEMENTS</span><b>${Number(trace.elements || 0).toLocaleString()}</b></div>
        <div><span>ROW WIDTH</span><b>${layout.samplesPerRow ?? '—'}</b></div>
        <div><span>ROWS</span><b>${layout.rows?.toLocaleString?.() || layout.rows || '—'}</b></div>
      </div>
      <div class="sca-shape"><span>NPY SHAPE</span><code>${(trace.shape || []).join(' × ') || '—'}</code><span>SOURCE</span><code>${(traceBundle.sourceFiles || []).map(esc).join(' · ') || 'no source file'}</code></div>
    </section>`;
  }

  function evidenceRows(label, rows) {
    return `<section><div><b>${label}</b><span>${rows?.length || 0}</span></div>${rows?.length ? rows.map((item) => `<code title="L${item.line} ${esc(item.text)}">L${item.line} ${esc(item.text)}</code>`).join('') : '<small>none</small>'}</section>`;
  }

  function sourcePanel() {
    const source = traceBundle?.analysis?.sourceInspection;
    if (!source) return '';
    const important = ['GROUP_SIZE','TRACE_DIM','LAYER_INDEX','SAMPLES_PER_ROW','SAMPLES_PER_TRACE','TRACE_WIDTH'];
    const constants = important.filter((name) => Object.prototype.hasOwnProperty.call(source.constants || {}, name)).map((name) => `<div><span>${name}</span><b>${esc(String(source.constants[name]))}</b></div>`).join('');
    return `<section class="sca-panel"><header><div><b>TEMPLATE / SOURCE PROOF</b><span>STATIC ONLY</span></div>${statusPill(source.requiresModelForward, 'MODEL FORWARD REQUIRED', 'NO FORWARD PROOF')}</header>
      ${constants ? `<div class="sca-constants">${constants}</div>` : '<p class="sca-muted">未提取到常见 SCA 常量名；不会按题目文件名猜参数。</p>'}
      <div class="sca-evidence-grid">
        ${evidenceRows('HIDDEN STATE', source.evidence?.hiddenState)}
        ${evidenceRows('KV CACHE', source.evidence?.kvCache)}
        ${evidenceRows('PINV / LS', source.evidence?.pinv)}
        ${evidenceRows('REGRESSION', source.evidence?.regression)}
        ${evidenceRows('TODO / GAP', source.evidence?.todo)}
        ${evidenceRows('PROBE / MATMUL', source.evidence?.probe)}
      </div>
    </section>`;
  }

  function featureStats() {
    const matrix = features?.features || [];
    if (!matrix.length) return null;
    const cols = matrix[0].length;
    return Array.from({ length: cols }, (_, col) => {
      let min = Infinity, max = -Infinity, sum = 0;
      for (const row of matrix) { const value = Number(row[col]); min = Math.min(min, value); max = Math.max(max, value); sum += value; }
      return { min, max, mean: sum / matrix.length };
    });
  }

  function windowsPanel() {
    const analysis = traceBundle?.analysis;
    if (!analysis) return '';
    const width = analysis.layout?.samplesPerRow || '';
    const stats = featureStats();
    return `<section class="sca-panel"><header><div><b>WINDOW FEATURE EXTRACTOR</b><span>STREAMING · READ ONLY</span></div>${statusPill(Boolean(features), 'EXTRACTED', 'CONFIGURE')}</header>
      <div class="sca-window-form">
        <label><span>Samples / row</span><input id="sca-row-width" type="number" min="1" value="${esc(String(width || ''))}" placeholder="528"></label>
        <label><span>Offset</span><input id="sca-window-offset" type="number" min="0" value="0"></label>
        <label><span>Length</span><input id="sca-window-length" type="number" min="1" value="${esc(String(width || ''))}" placeholder="window"></label>
        <label><span>Metric</span><select id="sca-window-metric"><option value="sum-squares">sum squares</option><option value="mean-square">mean square</option><option value="sum-abs">sum abs</option><option value="mean-abs">mean abs</option><option value="peak-to-peak">peak-to-peak</option><option value="mean">mean</option></select></label>
        <button class="button primary" data-sca-extract ${busy ? 'disabled' : ''}>提取窗口</button>
      </div>
      ${features ? `<div class="sca-feature-summary"><div><span>ROWS</span><b>${features.rows}</b></div><div><span>WINDOWS</span><b>${features.windows?.length || 0}</b></div><div><span>FEATURE VALUES</span><b>${(features.rows || 0) * (features.windows?.length || 0)}</b></div></div>` : ''}
      ${stats ? `<div class="sca-feature-table">${stats.map((item, index) => `<div><b>${esc(features.windows[index]?.id || `W${index}`)}</b><span>mean ${item.mean.toExponential(4)}</span><span>min ${item.min.toExponential(4)}</span><span>max ${item.max.toExponential(4)}</span></div>`).join('')}</div>` : ''}
    </section>`;
  }

  function runtimePanel() {
    return `<section class="sca-panel"><header><div><b>LOCAL ML RUNTIME</b><span>MAIN PROCESS ONLY</span></div>${statusPill(Boolean(runtime?.available), runtime?.version ? `ORT ${runtime.version}` : 'AVAILABLE', 'NOT INSTALLED')}</header>
      <div class="sca-runtime-row"><div><span>PACKAGE</span><b>${esc(runtime?.package || 'onnxruntime-node')}</b></div><div><span>PLATFORM</span><b>${esc(runtime ? `${runtime.platform}/${runtime.arch}` : 'checking…')}</b></div><div><span>PROVIDERS</span><b>${esc((runtime?.providers || ['cpu']).join(' · '))}</b></div></div>
      ${runtime && !runtime.available ? `<p class="sca-runtime-note">运行时适配器已经接好，但当前安装未发现 native package。正式离线发行包应把 <code>onnxruntime-node</code> 随 Electron 一起打包；不会从 UI 联网下载。</p>` : '<p class="sca-runtime-note">ONNX session 在主进程创建；renderer 只能请求已授权模型和受预算 tensor。</p>'}
    </section>`;
  }

  function onnxPanel() {
    return `<section class="sca-panel"><header><div><b>ONNX ORACLE</b><span>${onnx ? esc(onnx.fileName) : 'NO MODEL'}</span></div>${statusPill(Boolean(onnx?.model), 'SESSION OK', runtime?.available ? 'SELECT MODEL' : 'RUNTIME GAP')}</header>
      <div class="sca-onnx-actions"><button class="button" data-sca-onnx ${busy ? 'disabled' : ''}>选择 ONNX</button><span>只接受显式 <code>.onnx</code> 执行工件；不运行题目 Python，也不自动加载 custom-op library。</span></div>
      ${onnx?.model ? `<div class="sca-io-grid"><section><b>INPUTS</b>${(onnx.model.inputs || []).map((item) => `<div><code>${esc(item.name)}</code><span>${esc(item.metadata?.type || 'tensor')} · ${(item.metadata?.dimensions || []).join('×') || '?'}</span></div>`).join('')}</section><section><b>OUTPUTS</b>${(onnx.model.outputs || []).map((item) => `<div><code>${esc(item.name)}</code><span>${esc(item.metadata?.type || 'tensor')} · ${(item.metadata?.dimensions || []).join('×') || '?'}</span></div>`).join('')}</section></div>` : '<p class="sca-muted">下一层 recipe 会把 token ids / attention mask / past_key_values 绑定成 GPT 类模型的受限 forward 验证循环。</p>'}
    </section>`;
  }

  function nextActions() {
    const actions = traceBundle?.analysis?.nextActions || [];
    if (!actions.length) return '';
    return `<section class="sca-panel"><header><div><b>NEXT EVIDENCE</b><span>${actions.length}</span></div></header><div class="sca-actions">${actions.map((item, index) => `<div><i>${String(index + 1).padStart(2,'0')}</i><p>${esc(item)}</p></div>`).join('')}</div></section>`;
  }

  toolView = function scaToolView(tool) {
    if (tool !== TOOL) return previousToolView(tool);
    return `<div class="page-head tool-head sca-head"><div><span class="kicker">POWER TRACE → MODEL ORACLE → INVERSION</span><h1>Power SCA / Local ML</h1><p>大型 NPY 流式窗口取证、线性反演基础与受限 ONNX 前向能力。事实层和“题解 recipe”分离。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="sca-workbench">
        <article class="panel sca-drop" data-sca-drop>
          <div><span class="sca-icon">∿</span><div><b>${traceBundle ? esc(traceBundle.fileName) : 'DROP TRACE BUNDLE'}</b><small>${traceBundle ? `${fmtBytes(traceBundle.analysis?.trace?.bytes || 0)} · ${(traceBundle.sourceFiles || []).join(' · ') || 'trace only'}` : 'target_power_trace.npy + solve_template.py / config；支持直接拖多个文件'}</small></div></div>
          <button class="button primary" data-sca-pick ${busy ? 'disabled' : ''}>选择题目工件</button>
        </article>
        ${errorText ? `<div class="sca-error">${esc(errorText)}</div>` : ''}
        ${pipeline()}
        <div class="sca-grid-left">${tracePanel()}${sourcePanel()}${windowsPanel()}</div>
        <div class="sca-grid-right">${runtimePanel()}${onnxPanel()}${nextActions()}</div>
      </div>`;
  };

  async function refreshRuntime() {
    try { runtime = await window.newcyber.getLocalMlRuntimeStatus(); render(); } catch {}
  }

  async function analyzeFiles(files) {
    busy = 'trace'; errorText = ''; features = null; render();
    try {
      traceBundle = await window.newcyber.analyzeDroppedPowerSideChannel(files);
    } catch (error) { errorText = error?.message || String(error); }
    finally { busy = ''; render(); }
  }

  document.addEventListener('click', async (event) => {
    if (event.target.closest('[data-sca-pick]')) {
      busy = 'trace'; errorText = ''; render();
      try { traceBundle = await window.newcyber.chooseAndAnalyzePowerSideChannel(); features = null; }
      catch (error) { errorText = error?.message || String(error); }
      finally { busy = ''; render(); }
      return;
    }
    if (event.target.closest('[data-sca-extract]')) {
      if (!traceBundle?.filePath) return;
      const samplesPerRow = Number(document.querySelector('#sca-row-width')?.value);
      const offset = Number(document.querySelector('#sca-window-offset')?.value);
      const length = Number(document.querySelector('#sca-window-length')?.value);
      const metric = document.querySelector('#sca-window-metric')?.value || 'sum-squares';
      busy = 'features'; errorText = ''; render();
      try { features = await window.newcyber.extractPowerSideChannelWindows({ filePath:traceBundle.filePath, samplesPerRow, windows:[{ id:'W0', offset, length, metric }] }); }
      catch (error) { errorText = error?.message || String(error); }
      finally { busy = ''; render(); }
      return;
    }
    if (event.target.closest('[data-sca-onnx]')) {
      busy = 'onnx'; errorText = ''; render();
      try { onnx = await window.newcyber.chooseAndInspectOnnxModel('cpu'); runtime = onnx?.runtime || runtime; }
      catch (error) { errorText = error?.message || String(error); }
      finally { busy = ''; render(); }
    }
  });

  document.addEventListener('dragover', (event) => {
    const zone = event.target.closest?.('[data-sca-drop]');
    if (!zone) return;
    event.preventDefault(); zone.classList.add('dragging');
  });
  document.addEventListener('dragleave', (event) => event.target.closest?.('[data-sca-drop]')?.classList.remove('dragging'));
  document.addEventListener('drop', async (event) => {
    const zone = event.target.closest?.('[data-sca-drop]');
    if (!zone) return;
    event.preventDefault(); zone.classList.remove('dragging');
    const files = [...(event.dataTransfer?.files || [])];
    if (!files.length) return;
    if (files.length === 1 && /\.onnx$/i.test(files[0].name)) {
      busy = 'onnx'; errorText = ''; render();
      try { onnx = await window.newcyber.inspectDroppedOnnxModel(files[0], 'cpu'); runtime = onnx?.runtime || runtime; }
      catch (error) { errorText = error?.message || String(error); }
      finally { busy = ''; render(); }
      return;
    }
    await analyzeFiles(files);
  });

  refreshRuntime();
  render();
})();
