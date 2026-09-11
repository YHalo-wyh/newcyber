(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof renderResult !== 'function') return;

  const TOOL = 'ai-adversarial-onnx-workbench';
  const MAX_UI_CANDIDATES = 512;
  const placeholder = `{
  "provider": "cpu",
  "outputName": "logits",
  "hints": [[0, 1], [2, 6]],
  "candidates": [
    {
      "id": 101,
      "assignedLabel": 1,
      "feeds": {
        "input": {"type":"float32","dims":[1,3,32,32],"base64":"..."}
      }
    }
  ],
  "shortlistSize": 3,
  "beamWidth": 2
}`;

  TOOL_META[TOOL] = {
    domain: 'ai',
    title: 'ONNX 对抗样本批量排名',
    label: 'Hints + Candidate Tensor Feeds',
    placeholder
  };
  if (!(DOMAINS.ai.tools || []).some(([id]) => id === TOOL)) {
    DOMAINS.ai.tools.push([
      TOOL,
      'ONNX 对抗样本批量排名',
      '显式选择本地 ONNX 模型，批量执行候选 tensor feeds，把完整 logits 接到 hint / Top-2 / beam 排名。'
    ]);
  }

  const previousToolView = toolView;
  const previousRenderResult = renderResult;
  let selectedModel = null;
  let busy = false;
  let progress = null;

  function preserveInput() {
    return document.querySelector('#tool-input')?.value || '';
  }

  function restoreInput(value) {
    const next = document.querySelector('#tool-input');
    if (next) next.value = value;
  }

  function modelSummary() {
    if (!selectedModel) return '<div class="result-empty">尚未选择模型。先通过受控 ONNX 选择器打开模型，NewCyber 才允许执行。</div>';
    const model = selectedModel.model;
    const inputs = (model?.inputs || []).map((item) => `${item.name} ${JSON.stringify(item.metadata?.dimensions || [])}`).join(' · ');
    const outputs = (model?.outputs || []).map((item) => `${item.name} ${JSON.stringify(item.metadata?.dimensions || [])}`).join(' · ');
    return `<div class="kv-grid"><div><span>MODEL</span><strong>${esc(selectedModel.fileName || selectedModel.filePath || 'ONNX')}</strong></div><div><span>RUNTIME</span><strong>${selectedModel.runtime?.available ? 'READY' : 'UNAVAILABLE'}</strong></div><div><span>INPUTS</span><strong>${esc(inputs || '—')}</strong></div><div><span>OUTPUTS</span><strong>${esc(outputs || '—')}</strong></div></div>`;
  }

  function workbench() {
    const resultHtml = state.toolError
      ? `<div class="error-box">${esc(state.toolError)}</div>`
      : state.toolResult
        ? renderResult(TOOL, state.toolResult)
        : '<div class="result-empty">选择 ONNX 模型后，把每个候选的 tensor feeds 填入 JSON。NewCyber 会执行模型、提取完整分类向量，再进入赛式候选排名。</div>';
    return `<div class="page-head tool-head"><div><span class="kicker">ADVERSARIAL · LOCAL ONNX</span><h1>ONNX 对抗样本批量排名</h1><p>复用现有隔离 onnxruntime-node，不加载新的 Python 执行链。自动输出仍只算 candidate，最终交给题目 verifier。</p></div><button class="button ghost" data-view="ai">返回 AI</button></div>
      <div class="workbench"><article class="panel input-panel">
        <div class="run-row"><span>${selectedModel ? `已选择：${esc(selectedModel.fileName || 'model.onnx')}` : '先选择本地 ONNX 分类模型'}</span><button class="button ghost" data-adversarial-onnx-model ${busy ? 'disabled' : ''}>选择 ONNX</button></div>
        ${modelSummary()}
        <div class="field grow"><label>Hints + Candidate Tensor Feeds</label><textarea id="tool-input" spellcheck="false" placeholder="${esc(placeholder)}"></textarea></div>
        <div class="run-row"><span>${progress ? esc(progress) : `单次最多 ${MAX_UI_CANDIDATES} 个候选 · tensor 可用 values 或 base64`}</span><button class="button primary" data-adversarial-onnx-run ${busy ? 'disabled' : ''}>${busy ? 'RUNNING' : 'RUN ONNX + RANK'}</button></div>
      </article><article class="panel result-panel"><div class="result-title"><b>结果</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${resultHtml}</div></article></div>`;
  }

  function candidateRows(result) {
    const groups = result?.ranking?.groups || [];
    return groups.flatMap((group) => (group.shortlist || []).map((item, index) => [
      `${group.hint.originLabel} → ${group.hint.adversarialLabel}`,
      index + 1,
      item.id,
      Number(item.logitMargin).toPrecision(5),
      Number(item.runnerUpProbability).toPrecision(5),
      Number(item.suspicionScore).toFixed(4),
      item.consensusTop ? 'CONSENSUS' : ''
    ]));
  }

  toolView = function adversarialOnnxToolView(tool) {
    if (tool === TOOL) return workbench();
    return previousToolView(tool);
  };

  renderResult = function adversarialOnnxRenderResult(tool, result) {
    if (tool !== TOOL) return previousRenderResult(tool, result);
    const ranking = result?.ranking || {};
    const bridge = result?.bridge || {};
    const sets = (ranking.candidateSets || []).slice(0, 20).map((item) => [
      item.rank,
      item.ids.join(', '),
      Number(item.score).toFixed(4),
      item.legacyVerifier?.digest || '—'
    ]);
    const rows = candidateRows(result);
    const findings = (result.findings || []).map((item) => `<div class="finding ${esc(item.severity || 'info')}"><span>${esc(item.severity || 'info')}</span><div><b>${esc(item.id || 'finding')}</b><p>${esc(item.meaning || '')}</p><code>${esc(item.evidence || '')}</code></div></div>`).join('');
    return `<div class="result-stats"><div><b>${esc(bridge.runs || 0)}</b><span>ONNX runs</span></div><div><b>${esc(ranking.hints || 0)}</b><span>hints</span></div><div><b>${esc(ranking.candidateSets?.length || 0)}</b><span>candidate sets</span></div><div><b>${esc((bridge.outputNames || []).join(', ') || '—')}</b><span>output</span></div></div>
      ${findings}
      ${rows.length ? table(['Hint','Rank','Candidate','Logit Margin','Runner-up P','Suspicion','Consensus'], rows) : '<div class="result-empty">没有形成可用 shortlist。</div>'}
      ${sets.length ? `<article class="panel"><div class="result-title"><b>Verifier 候选组合</b><span>只作为 candidate</span></div>${table(['Rank','IDs','Score','Legacy digest'], sets)}</article>` : ''}
      <div class="hint-list">${(result.notes || []).map((item) => `<p>${esc(item)}</p>`).join('')}</div>`;
  };

  async function chooseModel() {
    if (busy) return;
    const input = preserveInput();
    try {
      const picked = await window.newcyber.chooseAndInspectOnnxModel('cpu');
      if (!picked) return;
      selectedModel = picked;
      state.toolError = null;
      state.toolResult = null;
    } catch (error) {
      state.toolError = error?.message || String(error);
    }
    render(); state.tool = TOOL; restoreInput(input);
  }

  function parsePayload() {
    const text = preserveInput().trim();
    if (!text) throw new Error('请输入 hints 与 candidates');
    const data = JSON.parse(text);
    if (!Array.isArray(data.candidates) || !data.candidates.length) throw new Error('需要 candidates[]');
    if (data.candidates.length > MAX_UI_CANDIDATES) throw new Error(`UI 批量执行上限为 ${MAX_UI_CANDIDATES} 个候选`);
    if (!Array.isArray(data.hints) || !data.hints.length) throw new Error('需要 hints[]');
    return data;
  }

  async function runBatch() {
    if (busy) return;
    if (!selectedModel?.filePath) {
      state.toolError = '请先选择 ONNX 模型';
      render(); state.tool = TOOL;
      return;
    }
    const input = preserveInput();
    let data;
    try { data = parsePayload(); }
    catch (error) { state.toolError = error?.message || String(error); render(); state.tool = TOOL; restoreInput(input); return; }

    busy = true; progress = '准备执行…'; state.toolError = null; state.toolResult = null;
    render(); state.tool = TOOL; restoreInput(input);
    await window.newcyber.setTaskProgress('indeterminate').catch(() => {});
    try {
      const provider = String(data.provider || 'cpu').toLowerCase();
      const runs = [];
      for (let index = 0; index < data.candidates.length; index += 1) {
        const candidate = data.candidates[index];
        if (!candidate || typeof candidate !== 'object' || !candidate.feeds) throw new Error(`candidates[${index}] 缺少 feeds`);
        progress = `ONNX ${index + 1}/${data.candidates.length} · ${candidate.id ?? candidate.name ?? index}`;
        const request = { feeds: candidate.feeds };
        const outputName = candidate.outputName ?? data.outputName;
        if (outputName) request.outputs = [String(outputName)];
        const run = await window.newcyber.runOnnxModel({ filePath: selectedModel.filePath, provider, request });
        runs.push({
          id: candidate.id ?? candidate.file ?? candidate.name ?? `candidate-${index}`,
          assignedLabel: candidate.assignedLabel ?? candidate.folderLabel ?? candidate.bucketLabel ?? candidate.classLabel,
          outputName,
          run
        });
        await window.newcyber.setTaskProgress((index + 1) / data.candidates.length).catch(() => {});
      }
      progress = '构建候选 beam…';
      state.toolResult = await window.newcyber.runTool('ai-adversarial-onnx-rank', {
        input: {
          hints: data.hints,
          runs,
          outputName: data.outputName,
          shortlistSize: data.shortlistSize,
          beamWidth: data.beamWidth,
          maxSets: data.maxSets
        }
      });
    } catch (error) {
      state.toolError = error?.message || String(error);
      state.toolResult = null;
    } finally {
      busy = false; progress = null;
      await window.newcyber.setTaskProgress('none').catch(() => {});
      render(); state.tool = TOOL; restoreInput(input);
    }
  }

  document.addEventListener('click', (event) => {
    if (state.tool !== TOOL) return;
    if (event.target.closest('[data-adversarial-onnx-model]')) { chooseModel(); return; }
    if (event.target.closest('[data-adversarial-onnx-run]')) runBatch();
  });

  render();
})();
