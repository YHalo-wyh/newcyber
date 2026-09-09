(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function') return;

  const TOOL = 'ai-sample-forensics';
  const MAX_FILE_BYTES = 32 * 1024 * 1024;
  const samples = { a: null, b: null };
  let comparison = null;
  let busy = false;

  TOOL_META[TOOL] = { domain:'ai', title:'NPY / 图像样本取证', label:'样本文件', placeholder:'' };
  if (!(DOMAINS.ai.tools || []).some((item) => item[0] === TOOL)) {
    DOMAINS.ai.tools.unshift([TOOL, 'NPY / 图像样本取证', '直接拖入 NPY / PNG / JPG，查看数组、图像、FFT 高频、Patch/Trigger 热区，并支持双样本差分。']);
  }

  const previousToolView = toolView;

  function formatNumber(value, digits = 5) {
    if (!Number.isFinite(Number(value))) return '—';
    const number = Number(value);
    if (Math.abs(number) >= 10000 || (Math.abs(number) > 0 && Math.abs(number) < 0.0001)) return number.toExponential(3);
    return number.toFixed(digits).replace(/0+$/,'').replace(/\.$/,'');
  }

  function sampleLabel(slot) { return slot === 'a' ? 'SAMPLE A' : 'REFERENCE B'; }

  function sampleCard(slot) {
    const sample = samples[slot];
    if (!sample) return `<section class="ai-sample-slot empty" data-sample-slot="${slot}">
      <div class="ai-sample-slot-head"><span>${sampleLabel(slot)}</span><b>${slot === 'a' ? '待分析样本' : '可选对照样本'}</b></div>
      <div class="ai-sample-drop"><strong>${slot === 'a' ? '拖入 NPY / PNG / JPG' : '拖入原图 / 对照样本'}</strong><p>${slot === 'a' ? '读取 shape、dtype、像素、FFT 与 trigger 热区。' : '加入第二个样本后自动计算差分和局部变化区域。'}</p><button class="button primary" data-sample-pick="${slot}">选择文件</button></div>
      <input class="ai-sample-file" type="file" data-sample-file="${slot}" accept=".npy,image/png,image/jpeg,image/webp,image/bmp" />
    </section>`;
    const analysis = sample.analysis || {};
    const npy = sample.kind === 'npy';
    const shape = npy ? (analysis.header?.shape || []).join(' × ') : `${sample.raster?.width || '—'} × ${sample.raster?.height || '—'}`;
    const type = npy ? `${analysis.header?.descr || 'NPY'} · ${analysis.layout?.layout || 'ARRAY'}` : sample.file.type || 'IMAGE';
    return `<section class="ai-sample-slot loaded" data-sample-slot="${slot}">
      <div class="ai-sample-slot-head"><span>${sampleLabel(slot)}</span><div><b>${esc(sample.file.name)}</b><small>${esc(type)} · ${esc(shape)} · ${fmtBytes(sample.file.size)}</small></div><button class="text-button" data-sample-clear="${slot}">清除</button></div>
      <div class="ai-sample-canvas-wrap"><canvas class="ai-sample-canvas" data-sample-canvas="${slot}" width="320" height="220"></canvas><span class="ai-sample-canvas-badge">${npy ? 'NPY PREVIEW' : 'IMAGE RASTER'}</span></div>
      <div class="ai-sample-mini-metrics">${miniMetrics(sample)}</div>
      <div class="ai-sample-slot-actions"><button class="button ghost" data-sample-pick="${slot}">更换</button>${slot === 'a' && samples.b ? '<button class="button ghost" data-sample-swap>交换 A / B</button>' : ''}</div>
      <input class="ai-sample-file" type="file" data-sample-file="${slot}" accept=".npy,image/png,image/jpeg,image/webp,image/bmp" />
    </section>`;
  }

  function miniMetrics(sample) {
    const raster = sample.rasterAnalysis || sample.analysis?.raster || {};
    const freq = raster.frequency?.highFrequencyRatio;
    const patch = raster.patchAnalysis?.candidates?.[0]?.score;
    const entropy = raster.stats?.luma?.entropyBits32Bins;
    return `<div><span>FFT HIGH</span><b>${formatNumber(freq,4)}</b></div><div><span>PATCH</span><b>${formatNumber(patch,3)}</b></div><div><span>ENTROPY</span><b>${formatNumber(entropy,3)}</b></div>`;
  }

  function findingHtml(findings = []) {
    if (!findings.length) return '<p class="ai-sample-muted">当前没有形成高置信视觉候选。</p>';
    return findings.slice(0,8).map((finding) => `<div class="ai-sample-finding ${esc(finding.severity || 'info')}"><span>${esc(finding.severity || 'info')}</span><div><b>${esc(finding.title || finding.id)}</b><p>${esc(finding.meaning || finding.message || '')}</p></div></div>`).join('');
  }

  function heatmapHtml(matrix) {
    if (!Array.isArray(matrix)) return '';
    const flat = matrix.flat().filter(Number.isFinite);
    const max = Math.max(...flat, 1e-9);
    return `<div class="ai-diff-heatmap">${matrix.map((row) => row.map((value) => {
      const level = Math.max(0, Math.min(9, Math.round((Number(value) || 0) / max * 9)));
      return `<i class="heat-${level}" title="${esc(formatNumber(value,6))}"></i>`;
    }).join('')).join('')}</div>`;
  }

  function npyPanel(sample) {
    const result = sample.analysis;
    if (!result || sample.kind !== 'npy') return '';
    const numeric = result.numeric || {};
    const header = result.header || {};
    return `<section class="ai-sample-result-section"><div class="ai-sample-section-title"><b>NPY ARRAY</b><span>${esc(header.descr || 'unknown')} · ${(header.shape || []).map(esc).join(' × ') || 'shape unknown'}</span></div>
      <div class="ai-sample-stat-grid">
        <div><span>MIN</span><b>${formatNumber(numeric.min)}</b></div><div><span>Q01</span><b>${formatNumber(numeric.q01)}</b></div><div><span>MEDIAN</span><b>${formatNumber(numeric.median)}</b></div><div><span>Q99</span><b>${formatNumber(numeric.q99)}</b></div><div><span>MAX</span><b>${formatNumber(numeric.max)}</b></div><div><span>STD</span><b>${formatNumber(numeric.std)}</b></div>
      </div>
      <div class="ai-sample-inline-notes"><span>layout ${esc(result.layout?.layout || 'array')}</span><span>preview ${esc(result.preview?.normalization || '—')}</span><span>${numeric.samplingStep > 1 ? `sample step ${numeric.samplingStep}` : 'full numeric scan'}</span></div>
    </section>`;
  }

  function rasterPanel(sample) {
    if (!sample) return '';
    const result = sample.rasterAnalysis || sample.analysis?.raster;
    if (!result) return '';
    const frequency = result.frequency || {};
    const reference = frequency.ctfReference || {};
    const channels = result.stats?.channels || [];
    const patches = result.patchAnalysis?.candidates || [];
    return `<section class="ai-sample-result-section"><div class="ai-sample-section-title"><b>VISUAL FORENSICS</b><span>${result.width} × ${result.height} · deterministic</span></div>
      <div class="ai-sample-stat-grid ai-sample-stat-four">
        <div><span>FFT HIGH RATIO</span><b>${formatNumber(frequency.highFrequencyRatio,5)}</b></div><div><span>湾区杯 REF</span><b>${formatNumber(reference.delta,3)}</b></div><div><span>EDGE Δ</span><b>${formatNumber(result.stats?.meanEdgeDelta,3)}</b></div><div><span>PATCH TOP</span><b>${formatNumber(patches[0]?.score,3)}</b></div>
      </div>
      <div class="ai-frequency-track"><div class="ai-frequency-scale"><span>0</span><span>公开题解 δ=0.125</span><span>1</span></div><div class="ai-frequency-marker ${frequency.highFrequencyRatio > (reference.delta ?? 0.125) ? 'above' : 'below'}">${frequency.highFrequencyRatio > (reference.delta ?? 0.125) ? 'ABOVE REFERENCE' : 'BELOW REFERENCE'}</div></div>
      <p class="ai-sample-reference-note">第五届湾区杯「耄耋」公开 WP 使用外圈半径比例 0.85 与 δ=0.125；这里只复现指标与参考线，不把它当通用 AIGC 分类器。</p>
      ${channels.length ? `<div class="ai-channel-row">${channels.map((item) => `<div><span>${esc(item.channel)}</span><b>μ ${formatNumber(item.mean,2)}</b><small>σ ${formatNumber(item.std,2)}</small></div>`).join('')}</div>` : ''}
      ${patches.length ? `<div class="ai-patch-list"><div class="ai-sample-section-title minor"><b>PATCH / TRIGGER CANDIDATES</b><span>仅候选，不等于后门成立</span></div>${patches.slice(0,6).map((item,index) => `<div><span>#${index+1}</span><b>${item.x},${item.y} · ${item.width}×${item.height}</b><small>score ${formatNumber(item.score,3)} · contrast ${formatNumber(item.contrastZ,2)} · flat ${formatNumber(item.flatness,2)}</small></div>`).join('')}</div>` : ''}
      ${findingHtml(result.findings || [])}
    </section>`;
  }

  function comparisonPanel() {
    if (!samples.a || !samples.b) return `<section class="ai-sample-result-section ai-compare-empty"><div class="ai-sample-section-title"><b>DIFF / CONSTRAINT</b><span>等待 Reference B</span></div><p>加入第二个同尺寸样本后自动计算视觉差分；两个 NPY 还会额外做原始数组 dtype/shape 下的数值范数。</p></section>`;
    if (!comparison) return `<section class="ai-sample-result-section ai-compare-empty"><div class="ai-sample-section-title"><b>DIFF / CONSTRAINT</b><span>${busy ? '计算中' : '不可比较'}</span></div><p>${busy ? '正在计算差分与热区。' : '两个样本的可视尺寸不同，当前只保留单样本取证。'}</p></section>`;
    const visual = comparison.visual;
    const exact = comparison.npy;
    return `<section class="ai-sample-result-section"><div class="ai-sample-section-title"><b>DIFF / CONSTRAINT</b><span>${exact ? 'NPY exact + visual' : 'visual raster'}</span></div>
      ${visual ? `<div class="ai-compare-grid"><div><div class="ai-sample-stat-grid ai-sample-stat-four"><div><span>L∞</span><b>${formatNumber(visual.norms?.linf,6)}</b></div><div><span>L2</span><b>${formatNumber(visual.norms?.l2,5)}</b></div><div><span>CHANGED</span><b>${formatNumber((visual.changedRatio||0)*100,2)}%</b></div><div><span>LOCALIZED</span><b>${visual.localizedChangeCandidate ? 'YES' : 'NO'}</b></div></div><p class="ai-sample-muted">BBox ${visual.diffBoundingBox ? `${visual.diffBoundingBox.x},${visual.diffBoundingBox.y} ${visual.diffBoundingBox.width}×${visual.diffBoundingBox.height}` : '—'}</p>${findingHtml(visual.findings || [])}</div><div><span class="ai-heat-title">8 × 8 DIFF HEAT</span>${heatmapHtml(visual.heatmap8x8)}</div></div>` : ''}
      ${exact ? `<div class="ai-npy-exact"><b>原始 NPY 数值差分</b><span>${exact.approximate ? `deterministic step=${exact.samplingStep}` : '逐元素精确'}</span><div><i>L0 ${exact.norms?.l0 ?? '—'}</i><i>L1 ${formatNumber(exact.norms?.l1,6)}</i><i>L2 ${formatNumber(exact.norms?.l2,6)}</i><i>L∞ ${formatNumber(exact.norms?.linf,6)}</i><i>mean |δ| ${formatNumber(exact.norms?.meanAbs,8)}</i></div></div>` : ''}
    </section>`;
  }

  function resultPanel() {
    if (!samples.a) return `<div class="ai-sample-result-empty"><span>AI SAMPLE WORKBENCH</span><strong>先放入一个样本</strong><p>NPY 会安全解析数值数组；普通图片会在 renderer 里缩放成确定性 raster，再送入离线分析器。不会执行模型、pickle 或附件代码。</p></div>`;
    return `${npyPanel(samples.a)}${rasterPanel(samples.a)}${comparisonPanel()}`;
  }

  toolView = function sampleForensicsView(tool) {
    if (tool !== TOOL) return previousToolView(tool);
    return `<div class="page-head tool-head ai-sample-head"><div><span class="kicker">AI SAMPLE FORENSICS</span><h1>NPY / 图像样本取证</h1><p>数组 → 图像 → FFT → Patch → 双样本差分。直接操作样本，不使用万能文本框。</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="ai-sample-workbench">
        <article class="panel ai-sample-input"><div class="ai-sample-input-toolbar"><div><b>SAMPLES</b><span>拖放或选择本地文件</span></div><span>${busy ? 'ANALYZING…' : 'LOCAL ONLY'}</span></div><div class="ai-sample-slots">${sampleCard('a')}${sampleCard('b')}</div></article>
        <article class="panel ai-sample-results"><div class="result-title"><b>取证结果</b><button class="text-button" data-sample-copy>复制摘要</button></div><div class="ai-sample-result-scroll">${resultPanel()}</div></article>
      </div>`;
  };

  function bytesToBase64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, Math.min(bytes.length, i + chunk)));
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value || '');
    const out = new Uint8ClampedArray(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  }

  function readAsDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(reader.error || new Error('读取图片失败'));
      reader.onload = () => resolve(String(reader.result || ''));
      reader.readAsDataURL(file);
    });
  }

  function decodeImageRaster(file) {
    return new Promise(async (resolve, reject) => {
      try {
        const url = await readAsDataUrl(file);
        const image = new Image();
        image.onerror = () => reject(new Error('浏览器无法解码该图片'));
        image.onload = () => {
          const maxSide = 256;
          const scale = Math.min(1, maxSide / Math.max(image.naturalWidth, image.naturalHeight));
          const width = Math.max(1, Math.round(image.naturalWidth * scale));
          const height = Math.max(1, Math.round(image.naturalHeight * scale));
          const canvas = document.createElement('canvas');
          canvas.width = width; canvas.height = height;
          const ctx = canvas.getContext('2d', { willReadFrequently:true });
          ctx.drawImage(image, 0, 0, width, height);
          const pixels = ctx.getImageData(0,0,width,height).data;
          resolve({ width, height, channels:4, data:Array.from(pixels), originalWidth:image.naturalWidth, originalHeight:image.naturalHeight });
        };
        image.src = url;
      } catch (error) { reject(error); }
    });
  }

  async function loadSample(slot, file) {
    if (!file) return;
    if (file.size <= 0) throw new Error('样本文件为空');
    if (file.size > MAX_FILE_BYTES) throw new Error(`样本工作台单文件上限 ${fmtBytes(MAX_FILE_BYTES)}`);
    const isNpy = /\.npy$/i.test(file.name);
    const isImage = /^image\//i.test(file.type) || /\.(?:png|jpe?g|webp|bmp)$/i.test(file.name);
    if (!isNpy && !isImage) throw new Error('当前样本工作台只接受 NPY / PNG / JPG / WEBP / BMP');
    busy = true; render();
    try {
      if (isNpy) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const base64 = bytesToBase64(bytes);
        const analysis = await window.newcyber.runTool('ai-npy-sample-forensics', { input:{ base64, fileName:file.name } });
        const preview = analysis.preview;
        const raster = preview ? { width:preview.width, height:preview.height, channels:4, data:Array.from(base64ToBytes(preview.rgbaBase64)) } : null;
        samples[slot] = { kind:'npy', file, base64, analysis, raster, rasterAnalysis:analysis.raster || null };
      } else {
        const raster = await decodeImageRaster(file);
        const analysis = await window.newcyber.runTool('ai-image-raster-forensics', { input:raster });
        samples[slot] = { kind:'image', file, raster, analysis:null, rasterAnalysis:analysis };
      }
      comparison = null;
      await compareSamples();
    } finally {
      busy = false; render(); requestAnimationFrame(paintCanvases);
    }
  }

  async function compareSamples() {
    if (!samples.a || !samples.b) { comparison = null; return; }
    const result = { visual:null, npy:null };
    if (samples.a.raster && samples.b.raster && samples.a.raster.width === samples.b.raster.width && samples.a.raster.height === samples.b.raster.height) {
      result.visual = await window.newcyber.runTool('ai-image-raster-compare', { input:{ left:samples.a.raster, right:samples.b.raster } });
    }
    if (samples.a.kind === 'npy' && samples.b.kind === 'npy') {
      try {
        result.npy = await window.newcyber.runTool('ai-npy-sample-compare', { input:{ left:{base64:samples.a.base64}, right:{base64:samples.b.base64} } });
      } catch (error) {
        result.npy = { error:error?.message || String(error) };
      }
    }
    comparison = result.visual || result.npy ? result : null;
  }

  function paintRaster(canvas, sample) {
    if (!canvas || !sample?.raster) return;
    const raster = sample.raster;
    const ctx = canvas.getContext('2d');
    const scratch = document.createElement('canvas');
    scratch.width = raster.width; scratch.height = raster.height;
    const sctx = scratch.getContext('2d');
    const imageData = sctx.createImageData(raster.width, raster.height);
    imageData.data.set(new Uint8ClampedArray(raster.data));
    sctx.putImageData(imageData,0,0);
    const pad = 10;
    const scale = Math.min((canvas.width-pad*2)/raster.width,(canvas.height-pad*2)/raster.height);
    const drawW = raster.width*scale; const drawH=raster.height*scale;
    const ox=(canvas.width-drawW)/2; const oy=(canvas.height-drawH)/2;
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(scratch,ox,oy,drawW,drawH);
    const candidates=(sample.rasterAnalysis || sample.analysis?.raster)?.patchAnalysis?.candidates || [];
    ctx.lineWidth=1.5;
    candidates.slice(0,4).forEach((item,index)=>{
      ctx.strokeStyle=index===0?'rgba(255,102,112,.95)':'rgba(245,190,88,.72)';
      ctx.strokeRect(ox+item.x*scale,oy+item.y*scale,item.width*scale,item.height*scale);
    });
  }

  function paintCanvases() {
    document.querySelectorAll('[data-sample-canvas]').forEach((canvas)=>paintRaster(canvas,samples[canvas.dataset.sampleCanvas]));
  }

  function summaryText() {
    const describe=(slot)=>{
      const sample=samples[slot]; if(!sample) return `${sampleLabel(slot)}: empty`;
      const raster=sample.rasterAnalysis||sample.analysis?.raster||{};
      return `${sampleLabel(slot)}: ${sample.file.name}\n  FFT high=${raster.frequency?.highFrequencyRatio ?? 'n/a'}\n  patch=${raster.patchAnalysis?.candidates?.[0]?.score ?? 'n/a'}${sample.kind==='npy'?`\n  shape=${JSON.stringify(sample.analysis?.header?.shape)} dtype=${sample.analysis?.header?.descr}`:''}`;
    };
    const diff=comparison?.visual?`\nDIFF: linf=${comparison.visual.norms?.linf} changed=${comparison.visual.changedRatio} bbox=${JSON.stringify(comparison.visual.diffBoundingBox)}`:'';
    return `${describe('a')}\n${describe('b')}${diff}`;
  }

  document.addEventListener('click', async (event) => {
    const pick = event.target.closest('[data-sample-pick]');
    if (pick) { document.querySelector(`[data-sample-file="${pick.dataset.samplePick}"]`)?.click(); return; }
    const clear = event.target.closest('[data-sample-clear]');
    if (clear) { samples[clear.dataset.sampleClear]=null; comparison=null; await compareSamples(); render(); requestAnimationFrame(paintCanvases); return; }
    if (event.target.closest('[data-sample-swap]')) { const temp=samples.a; samples.a=samples.b; samples.b=temp; comparison=null; busy=true; render(); try{await compareSamples();}finally{busy=false;render();requestAnimationFrame(paintCanvases);} return; }
    if (event.target.closest('[data-sample-copy]')) {
      try { await navigator.clipboard.writeText(summaryText()); toast('样本取证摘要已复制'); } catch { toast('复制失败',true); }
    }
  });

  document.addEventListener('change', async (event) => {
    const input = event.target.closest?.('[data-sample-file]');
    if (!input) return;
    const file = input.files?.[0];
    if (!file) return;
    try { await loadSample(input.dataset.sampleFile,file); }
    catch(error){ busy=false; toast(error?.message||String(error),true); render(); requestAnimationFrame(paintCanvases); }
  });

  document.addEventListener('dragover',(event)=>{
    const slot=event.target.closest?.('[data-sample-slot]');
    if(!slot) return;
    event.preventDefault(); slot.classList.add('dragging');
  });
  document.addEventListener('dragleave',(event)=>event.target.closest?.('[data-sample-slot]')?.classList.remove('dragging'));
  document.addEventListener('drop',async(event)=>{
    const slot=event.target.closest?.('[data-sample-slot]');
    if(!slot) return;
    event.preventDefault(); slot.classList.remove('dragging');
    const file=event.dataTransfer?.files?.[0];
    if(!file) return;
    try{await loadSample(slot.dataset.sampleSlot,file);}catch(error){busy=false;toast(error?.message||String(error),true);render();requestAnimationFrame(paintCanvases);}
  });

  const root=document.querySelector('#app');
  if(root) new MutationObserver(()=>requestAnimationFrame(paintCanvases)).observe(root,{childList:true,subtree:true});
  render();
})();
