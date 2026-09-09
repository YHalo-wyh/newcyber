(() => {
  if (typeof workspaceView !== 'function') return;
  const previousWorkspaceView=workspaceView;

  const STATUS={
    evidence:['EVIDENCE','已形成可验证证据'],
    candidate:['CANDIDATE','已有方向性线索，需补验证'],
    'no-explicit-finding':['NO FINDING','当前输入未形成显式 finding'],
    'data-needed':['DATA NEEDED','还缺关键输入']
  };

  function missionPanel(analysis) {
    const mission=analysis?.aiStage1Mission;
    if (!mission?.applicable) return '';
    const summary=mission.summary||{};
    const next=mission.nextDirection;
    const cards=(mission.directions||[]).map((item)=>{
      const meta=STATUS[item.status]||[item.status||'UNKNOWN',''];
      const evidence=(item.evidence||[]).slice(0,3).map((ev)=>`<small><b>${esc(ev.file||'workspace')}</b> · ${esc(ev.title||'证据')}${ev.evidence?` · ${esc(ev.evidence)}`:''}</small>`).join('');
      const files=(item.files||[]).slice(0,4).map((file)=>`<span class="tag">${esc(file)}</span>`).join('');
      return `<article class="simple-result ai-stage1-direction ${esc(item.status||'data-needed')}">
        <span>${esc(meta[0])} · confidence ${esc(item.confidence||'none')}</span>
        <strong>${esc(item.title||item.id)}</strong>
        <small>${esc(meta[1])}</small>
        ${evidence||`<small>${esc(item.nextAction||'等待补充证据')}</small>`}
        ${files?`<div class="tag-row">${files}</div>`:''}
      </article>`;
    }).join('');

    const nextTool=next?.tools?.[0]||'ai-skill-matrix';
    return `<section class="panel next-actions ai-stage1-mission-panel">
      <div class="result-title">
        <div><b>AI Stage-One Mission</b><p>Workspace 已把附件里的 AI 证据自动汇成五方向任务单。文件名只能形成候选，真正的 EVIDENCE 必须来自结构化分析结果或可追溯 finding。</p></div>
        <div class="run-row"><span>${summary.covered||0}/${mission.officialCoverage||5} 已覆盖 · ${summary.evidenceItems||0} 条证据</span>${next?`<button class="button primary" data-tool="${esc(nextTool)}">继续下一方向</button>`:''}</div>
      </div>
      <div class="simple-score-row">
        <article class="simple-result"><span>EVIDENCE</span><strong>${summary.evidence||0}</strong><small>已有可验证证据</small></article>
        <article class="simple-result"><span>CANDIDATE</span><strong>${summary.candidate||0}</strong><small>优先补行为验证</small></article>
        <article class="simple-result"><span>DATA NEEDED</span><strong>${summary['data-needed']||0}</strong><small>还缺题目输入</small></article>
        <article class="simple-result"><span>关联文件</span><strong>${summary.detectedFiles||0}</strong><small>跨文件证据已聚合</small></article>
      </div>
      ${next?`<div class="hint-list"><p><b>当前下一步：</b>${esc(next.title)} · ${esc(next.status)} · ${esc(next.nextAction||'')}</p></div>`:''}
      <div class="simple-score-row ai-stage1-grid">${cards}</div>
    </section>`;
  }

  workspaceView=function batch44WorkspaceView() {
    const base=previousWorkspaceView();
    if (!state?.workspace) return base;
    return `${missionPanel(state.workspace)}${base}`;
  };
})();
