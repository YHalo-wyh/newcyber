(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof renderResult !== 'function') return;

  const LLM_TOOL = 'ai-llm-aes-candidate-verify';
  const PATCH_TOOL = 'ai-backdoor-patch-candidate';
  const PATCH_VERIFY_TOOL = 'ai-backdoor-patch-verify';
  const drafts = new Map();

  const rows = [
    [LLM_TOOL, 'LLM → AES 候选验证', '题目 Challenge JSON + 已获得的 LLM 输出候选；离线做 SHA256[:16] → AES-CBC → flag 验证。'],
    [PATCH_TOOL, '后门 Patch Candidate Generator', '把 Raster 局部热区与 clean/triggered/control 行为证据绑定成具体 bbox + target + candidateId。'],
    [PATCH_VERIFY_TOOL, '后门 Patch Candidate Verifier', '用 candidateId 绑定模型 observations，以 ASR + control specificity 复验具体 patch 候选。']
  ];

  TOOL_META[LLM_TOOL] = { domain:'ai', title:'LLM → AES 候选验证', label:'Challenge JSON + LLM output candidates', placeholder:'' };
  TOOL_META[PATCH_TOOL] = { domain:'ai', title:'后门 Patch Candidate Generator', label:'Raster + behavior observations', placeholder:'' };
  TOOL_META[PATCH_VERIFY_TOOL] = { domain:'ai', title:'后门 Patch Candidate Verifier', label:'Candidate + bound observations', placeholder:'' };

  const existing = new Set((DOMAINS.ai.tools || []).map((row) => row[0]));
  for (const row of rows) if (!existing.has(row[0])) DOMAINS.ai.tools.push(row);

  const previousToolView = toolView;
  const previousRenderResult = renderResult;

  const sampleChallenge = `{
  "algo": "AES-128-CBC",
  "iv_b64": "...",
  "ciphertext_b64": "...",
  "key_derivation": "key = SHA256(LLM_output)[:16]",
  "llm": {"model":"GLM-4-Flash","temperature":0.28}
}`;

  function getDraft(tool, field, fallback='') {
    return drafts.get(`${tool}:${field}`) ?? fallback;
  }

  function hidden(tool) {
    return `<textarea id="tool-input" class="surface-hidden-input" aria-hidden="true">${esc(getDraft(tool,'payload'))}</textarea>`;
  }

  function shell(tool, eyebrow, title, description, editor) {
    const resultHtml = state.toolError
      ? `<div class="error-box">${esc(state.toolError)}</div>`
      : state.toolResult
        ? renderResult(tool, state.toolResult)
        : '<div class="surface-result-empty"><span>◇</span><b>等待候选</b><p>这里只把可复验对象推进到 Candidate / Verified，不把静态 finding 当答案。</p></div>';
    return `<div class="page-head tool-head surface-page-head"><div><span class="kicker">${esc(eyebrow)}</span><h1>${esc(title)}</h1><p>${esc(description)}</p></div><button class="button ghost" data-view="ai">返回</button></div>
      <div class="workbench surface-workbench"><article class="panel input-panel surface-input-panel">${hidden(tool)}${editor}<div class="run-row surface-run-row"><span>OFFLINE · BOUNDED · NO MODEL EXECUTION</span><button class="button primary" data-action="run-tool">运行验证链</button></div></article><article class="panel result-panel surface-result-panel"><div class="result-title"><b>Candidate / Verifier Result</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${resultHtml}</div></article></div>`;
  }

  function field(label, fieldName, value, placeholder='', className='') {
    return `<label class="surface-form-field ${className}"><span>${esc(label)}</span><textarea data-b48-field="${esc(fieldName)}" spellcheck="false" placeholder="${esc(placeholder)}">${esc(value)}</textarea></label>`;
  }

  function llmPage() {
    const editor = `<div class="surface-device-bar"><span><i class="surface-led"></i> CANDIDATE VERIFIER</span><strong>SHA256[:16] → AES-128-CBC</strong><span>MAX 512</span></div>
      <div class="surface-form-grid">${field('Challenge JSON','challenge',getDraft(LLM_TOOL,'challenge'),sampleChallenge)}${field('LLM 输出候选 · 每行一个','candidates',getDraft(LLM_TOOL,'candidates'),'pw-abcdefgh\npw-anothercandidate')}</div>
      <p class="notice">不会调用题目 LLM/API。把你从本地模型、日志或手工 replay 得到的输出逐行贴进来；只有真实解密出 flag 的候选才会 Verified。</p>`;
    return shell(LLM_TOOL,'AI · DETERMINISTIC VERIFIER','LLM → AES 候选验证','用于 SU_easyLLM 一类“模型输出派生加密密钥”题；候选生成与最终密码学验证分离。',editor);
  }

  function patchCandidatePage() {
    const editor = `<div class="surface-device-bar"><span><i class="surface-led"></i> CROSS EVIDENCE</span><strong>PATCH × BEHAVIOR</strong><span>CANDIDATE</span></div>
      <div class="surface-form-grid">${field('Raster JSON','raster',getDraft(PATCH_TOOL,'raster'),'image workbench 导出的 {width,height,channels,data:[...]}')}${field('Behavior observations JSON','behavior',getDraft(PATCH_TOOL,'behavior'),'撤掉/加入 patch 后的 true_label / clean_pred / triggered_pred / control_pred / target_label')}</div>
      <p class="notice">行为侧强 ASR/control evidence 会提高贴边或 block 尺寸不对齐热区的候选优先级，但仍只生成 candidateId，不直接宣称后门确认。</p>`;
    return shell(PATCH_TOOL,'AI · CANDIDATE GENERATOR','后门 Patch Candidate Generator','把图像热区与模型行为绑定为一个可以继续复验的具体对象。',editor);
  }

  function patchVerifyPage() {
    const editor = `<div class="surface-device-bar"><span><i class="surface-led"></i> BOUND VERIFIER</span><strong>CANDIDATE ID</strong><span>ASR + CONTROL</span></div>
      <div class="surface-form-grid">${field('Candidate JSON','candidate',getDraft(PATCH_VERIFY_TOOL,'candidate'),'Candidate Generator 输出的 candidateObject')}${field('candidateId','candidateId',getDraft(PATCH_VERIFY_TOOL,'candidateId'),'patch-...')}${field('Model observations JSON','observations',getDraft(PATCH_VERIFY_TOOL,'observations'),'必须是该 candidateId 对应 patch 的 clean/triggered/control 复跑结果','surface-wide-field')}</div>
      <p class="notice">candidateId 不匹配时直接 fail closed；只有 target 一致、样本量足够、ASR 高且 control target rate 低时才 Verified。</p>`;
    return shell(PATCH_VERIFY_TOOL,'AI · CANDIDATE VERIFIER','后门 Patch Candidate Verifier','防止跨 trigger 复用 observations，把验证结果绑定到具体 bbox/target candidate。',editor);
  }

  function parseJson(text) {
    const value = String(text || '').trim();
    if (!value) return null;
    try { return JSON.parse(value); } catch { return null; }
  }

  function sync(tool) {
    if (![LLM_TOOL,PATCH_TOOL,PATCH_VERIFY_TOOL].includes(tool)) return;
    const hiddenEl = document.querySelector('#tool-input');
    if (!hiddenEl) return;
    const fields = {};
    document.querySelectorAll('[data-b48-field]').forEach((el) => {
      fields[el.dataset.b48Field] = el.value || '';
      drafts.set(`${tool}:${el.dataset.b48Field}`, el.value || '');
    });
    let payload = {};
    if (tool === LLM_TOOL) {
      payload = {
        challenge: parseJson(fields.challenge) || {},
        candidates: String(fields.candidates || '').split(/\r?\n/).map((x)=>x.trim()).filter(Boolean)
      };
    } else if (tool === PATCH_TOOL) {
      payload = { raster: parseJson(fields.raster) || {}, behavior: parseJson(fields.behavior) || {} };
    } else {
      payload = {
        candidate: parseJson(fields.candidate) || {},
        candidateId: String(fields.candidateId || '').trim(),
        observations: parseJson(fields.observations) || {}
      };
    }
    const serialized = JSON.stringify(payload);
    hiddenEl.value = serialized;
    drafts.set(`${tool}:payload`, serialized);
  }

  function stat(value) {
    if (value === null || value === undefined) return '—';
    if (typeof value === 'number') return Number.isFinite(value) ? value.toFixed(4) : '—';
    return String(value);
  }

  function llmResult(r) {
    const attempts = (r.attempts || []).map((item)=>`<div class="real-ctf-result-row ${item.status==='accepted'?'pass':'miss'}"><div class="real-ctf-result-status"><span>${esc(String(item.status||'').toUpperCase())}</span><b>#${item.index}</b></div><div class="real-ctf-result-main"><strong>${esc(item.reason||'')}</strong><small>${esc(item.candidateSha256||'')}</small>${item.flags?.length?`<p>${esc(item.flags.join(' · '))}</p>`:''}</div></div>`).join('');
    return `<div class="result-stats"><div><b>${r.verified?'VERIFIED':'NOT VERIFIED'}</b><span>状态</span></div><div><b>${r.candidateCount||0}</b><span>候选</span></div><div><b>${r.attempted||0}</b><span>已尝试</span></div></div>${r.accepted?`<div class="notice"><b>${esc(r.accepted.flags?.join(' · ')||'accepted')}</b><pre class="mini-pre">${esc(r.accepted.plaintext||'')}</pre></div>`:''}<div class="real-ctf-result-list">${attempts}</div>`;
  }

  function patchCandidateResult(r) {
    const c = r.candidateObject;
    return `<div class="result-stats"><div><b>${r.candidate?'CANDIDATE':'NO CANDIDATE'}</b><span>成熟度</span></div><div><b>${esc(c?.targetLabel??'—')}</b><span>Target</span></div><div><b>${esc(c?.candidateId||'—')}</b><span>Candidate ID</span></div></div>${c?`<div class="kv-grid"><div><span>bbox</span><strong>${c.patch.x},${c.patch.y},${c.patch.width}×${c.patch.height}</strong></div><div><span>patch score</span><strong>${stat(c.patch.score)}</strong></div><div><span>source</span><strong>${esc(c.patch.source)}</strong></div><div><span>ASR</span><strong>${stat(c.behavior.targetASR)}</strong></div><div><span>control</span><strong>${stat(c.behavior.controlTargetRate)}</strong></div><div><span>specificity</span><strong>${stat(c.behavior.triggerSpecificity)}</strong></div></div><button class="button ghost" data-tool="${PATCH_VERIFY_TOOL}">打开 Candidate Verifier →</button>`:''}${(r.notes||[]).map((x)=>`<p class="notice">${esc(x)}</p>`).join('')}`;
  }

  function patchVerifyResult(r) {
    return `<div class="result-stats"><div><b>${r.verified?'VERIFIED':'NOT VERIFIED'}</b><span>状态</span></div><div><b>${esc(r.candidateId||'—')}</b><span>Candidate ID</span></div><div><b>${stat(r.metrics?.targetASR)}</b><span>ASR</span></div><div><b>${stat(r.metrics?.controlTargetRate)}</b><span>Control</span></div></div>${r.reason?`<p class="notice">${esc(r.reason)}</p>`:''}${r.checks?`<pre class="mini-pre">${esc(JSON.stringify(r.checks,null,2))}</pre>`:''}${(r.notes||[]).map((x)=>`<p class="notice">${esc(x)}</p>`).join('')}`;
  }

  toolView = function batch48ToolView(tool) {
    if (tool === LLM_TOOL) return llmPage();
    if (tool === PATCH_TOOL) return patchCandidatePage();
    if (tool === PATCH_VERIFY_TOOL) return patchVerifyPage();
    return previousToolView(tool);
  };

  renderResult = function batch48RenderResult(tool, result) {
    if (tool === LLM_TOOL) return llmResult(result || {});
    if (tool === PATCH_TOOL) return patchCandidateResult(result || {});
    if (tool === PATCH_VERIFY_TOOL) return patchVerifyResult(result || {});
    return previousRenderResult(tool, result);
  };

  document.addEventListener('input', (event) => {
    if (event.target?.matches?.('[data-b48-field]')) sync(state.tool);
  });
  document.addEventListener('click', (event) => {
    if (event.target.closest?.('[data-action="run-tool"]')) sync(state.tool);
  }, true);

  render();
})();
