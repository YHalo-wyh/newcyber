(() => {
  if (typeof TOOL_META === 'undefined' || typeof DOMAINS === 'undefined' || typeof toolView !== 'function' || typeof domainView !== 'function') return;

  const TOOL='lowalt-assessment-mode';
  const previousToolView=toolView;
  const previousDomainView=domainView;
  let evidenceDraft='';
  let analysis=null;
  let busy=false;
  let errorText='';
  let activeSurface='all';

  TOOL_META[TOOL]={ domain:'lowalt', title:'场景测评作战台', placeholder:'', label:'四类业务场景 · 风险发现到整改复测闭环' };
  if (!DOMAINS.lowalt.tools.some((row)=>row[0]===TOOL)) {
    DOMAINS.lowalt.tools.unshift([TOOL,'场景测评作战台','按飞控 / 蜂群 / 地面站 / 物流业务四类场景组织证据，并强制补齐验证、影响、整改与复测。']);
  }

  function workspaceSummary() {
    const ws=state.workspace;
    if (!ws) return '';
    const lines=[`workspace: ${ws.workspaceName || ws.workspacePath || 'current'}`];
    for (const file of (ws.files||[]).slice(0,120)) {
      const label=file.relativePath || file.path || file.name || 'file';
      const type=file.type || file.format || file.kind || file.metadata?.format || '';
      lines.push(`[file] ${label}${type ? ` | ${type}` : ''}`);
      const findings=[...(file.findings||[]),...(file.metadata?.findings||[])].slice(0,8);
      for (const finding of findings) {
        if (typeof finding==='string') lines.push(`[finding] ${finding}`);
        else if (finding) lines.push(`[finding] ${finding.title || finding.id || ''} | ${finding.evidence || finding.message || finding.summary || ''}`);
      }
      const meta=file.metadata||{};
      if (meta.mavlink?.parsedFrames) lines.push(`[mavlink] ${label} | frames=${meta.mavlink.parsedFrames}`);
      if (meta.wifi?.networks?.length) lines.push(`[wifi] ${label} | networks=${meta.wifi.networks.length}`);
      if (meta.flightLog) lines.push(`[flight-log] ${label}`);
      if (meta.firmware) lines.push(`[firmware] ${label}`);
    }
    for (const focus of (ws.investigation?.focus||[]).slice(0,30)) {
      lines.push(`[focus] ${focus.title || focus.label || focus.id || ''} | ${focus.evidence || focus.reason || ''}`);
    }
    return lines.join('\n').slice(0,480000);
  }

  function statusClass(status){ return status==='validated'?'ok':status==='observed'?'warn':'idle'; }
  function gateClass(status){ return status==='complete'?'ok':status==='partial'?'warn':status==='missing'?'bad':'idle'; }

  function sourceStrip(result) {
    const official=result?.competitionContext?.officialFacts || [];
    const inference=result?.competitionContext?.prepInference || [];
    return `<div class="lowalt-source-strip"><span><b>OFFICIAL FACT</b>${official.length} sources</span><span class="inference"><b>PREP INFERENCE</b>${inference.length} boundary</span><p>${esc(result?.competitionContext?.boundary || '红明谷公开场景只作为训练覆盖面，不代表湾区杯复用同一题目。')}</p></div>`;
  }

  function surfaceRail(result) {
    const rows=result?.surfaces || [
      {id:'flight-control',code:'FC',title:'无人机飞控',status:'unchecked'},
      {id:'swarm',code:'SW',title:'无人机蜂群协同',status:'unchecked'},
      {id:'ground-station',code:'GCS',title:'地面站通信',status:'unchecked'},
      {id:'logistics-system',code:'APP',title:'物流 / 众筹业务系统',status:'unchecked'}
    ];
    return `<div class="lowalt-surface-rail"><button class="${activeSurface==='all'?'active':''}" data-lowalt-surface="all"><span>ALL</span><b>全局</b><small>${result?.coverage?.observed ?? 0}/4 observed</small></button>${rows.map((row)=>`<button class="${activeSurface===row.id?'active':''} ${statusClass(row.status)}" data-lowalt-surface="${esc(row.id)}"><span>${esc(row.code)}</span><b>${esc(row.title)}</b><small>${esc(row.status || 'unchecked')}</small></button>`).join('')}</div>`;
  }

  function gateBoard(result) {
    const gates=result?.gates || [
      {id:'discover',title:'风险发现',status:'not-started',complete:0,total:0},
      {id:'verify',title:'漏洞验证',status:'not-started',complete:0,total:0},
      {id:'impact',title:'影响评估',status:'not-started',complete:0,total:0},
      {id:'remediate',title:'修复整改',status:'not-started',complete:0,total:0},
      {id:'retest',title:'复测关闭',status:'not-started',complete:0,total:0}
    ];
    return `<div class="lowalt-gates">${gates.map((gate,index)=>`<div class="${gateClass(gate.status)}"><span>0${index+1}</span><b>${esc(gate.title)}</b><small>${esc(gate.status)}${gate.total ? ` · ${gate.complete}/${gate.total}` : ''}</small></div>`).join('<i>→</i>')}</div>`;
  }

  function surfaceDetail(surface) {
    const findings=surface.findings||[];
    return `<article class="lowalt-surface-detail ${statusClass(surface.status)}"><header><span>${esc(surface.code)}</span><div><b>${esc(surface.title)}</b><small>${esc(surface.status)}</small></div></header>
      <div class="lowalt-detail-grid"><section><h4>资产 / 信任边界</h4>${(surface.assets||[]).slice(0,6).map((x)=>`<p>${esc(x)}</p>`).join('')}</section><section><h4>优先测试</h4>${(surface.tests||[]).slice(0,7).map((x)=>`<p>${esc(x)}</p>`).join('')}</section><section><h4>可能影响</h4>${(surface.impact||[]).slice(0,6).map((x)=>`<p>${esc(x)}</p>`).join('')}</section></div>
      ${surface.evidence?.length ? `<div class="lowalt-evidence-list"><h4>当前证据</h4>${surface.evidence.slice(0,10).map((x)=>`<p>${esc(x)}</p>`).join('')}</div>` : '<div class="lowalt-empty-row">当前没有可定位证据，保持 UNCHECKED。</div>'}
      ${findings.length ? `<div class="lowalt-finding-list">${findings.slice(0,10).map((finding)=>`<div><span>${esc(finding.state || 'candidate')}</span><b>${esc(finding.title)}</b><p>${esc(finding.evidence || '待补验证证据')}</p><small>${esc(finding.remediation || '待补整改')}</small></div>`).join('')}</div>` : ''}
      <footer>${esc(surface.nextAction || '')}</footer></article>`;
  }

  function resultPanel() {
    if (errorText) return `<div class="error-box">${esc(errorText)}</div>`;
    if (!analysis) return `<div class="lowalt-empty"><b>没有开始评估</b><p>先从当前赛题目录导入证据，或在左侧只粘贴关键日志 / 报文 / 服务与漏洞现象。这里不会因为关键词命中就把风险判成 CONFIRMED。</p></div>`;
    const surfaces=(analysis.surfaces||[]).filter((row)=>activeSurface==='all' || row.id===activeSurface);
    return `${sourceStrip(analysis)}${gateBoard(analysis)}<div class="lowalt-coverage"><div><b>${analysis.coverage?.observed||0}/4</b><span>场景有证据</span></div><div><b>${analysis.coverage?.findings||0}</b><span>风险候选</span></div><div><b>${analysis.coverage?.validated||0}</b><span>场景已验证</span></div><div><b>${analysis.coverage?.closureComplete||0}/5</b><span>闭环完成</span></div></div><div class="lowalt-details">${surfaces.map(surfaceDetail).join('')}</div><details class="lowalt-deliverable"><summary>比赛交付检查 · ${analysis.deliverableTemplate?.length||0} 项</summary>${(analysis.deliverableTemplate||[]).map((x,index)=>`<p><span>${String(index+1).padStart(2,'0')}</span>${esc(x)}</p>`).join('')}</details>`;
  }

  function assessmentView() {
    return `<div class="page-head tool-head lowalt-assessment-head"><div><span class="kicker">LOW ALTITUDE · SCENARIO ASSESSMENT</span><h1>场景测评作战台</h1><p>面向高仿真业务环境：先覆盖四类场景，再把每个风险做到“发现 → 验证 → 影响 → 整改 → 复测”。</p></div><button class="button ghost" data-view="lowalt">返回</button></div>
      <div class="lowalt-mode-note"><b>比赛准备模式</b><span>红明谷 2025 公开场景 = 训练基线</span><i>≠</i><span>湾区杯 2026 官方复用声明</span></div>
      ${surfaceRail(analysis)}
      <div class="lowalt-assessment-workbench">
        <article class="panel lowalt-evidence-inbox"><header><b>EVIDENCE INBOX</b><span>LOCAL / READ-ONLY</span></header><div class="lowalt-inbox-actions"><button class="button" data-lowalt-action="workspace" ${state.workspace?'':'disabled'}>载入当前赛题证据</button><button class="button primary" data-lowalt-action="analyze" ${busy?'disabled':''}>${busy?'分析中…':'构建评估矩阵'}</button></div><textarea data-lowalt-evidence spellcheck="false" placeholder="仅粘贴关键证据：MAVLink / Wi-Fi / 服务 / 日志 / API / 蜂群协同 / 业务状态等。不是通用大文本分析器。">${esc(evidenceDraft)}</textarea><small>${state.workspace ? `当前赛题：${esc(state.workspace.workspaceName || '已打开')}` : '未打开赛题目录；也可以手工粘贴少量关键证据。'}</small></article>
        <article class="panel lowalt-assessment-result"><header><b>ASSESSMENT BOARD</b><span>${analysis ? `${analysis.coverage?.findings||0} candidates` : 'waiting'}</span></header>${resultPanel()}</article>
      </div>`;
  }

  toolView=function lowaltAssessmentToolView(tool){
    if (tool===TOOL) return assessmentView();
    return previousToolView(tool);
  };

  domainView=function lowaltAssessmentDomainView(id){
    const html=previousDomainView(id);
    if (id!=='lowalt' || /data-lowalt-assessment-entry/.test(html)) return html;
    const entry=`<section class="lowalt-assessment-entry panel" data-lowalt-assessment-entry><div><span>SCENARIO MODE</span><b>湾区杯低空 · 场景测评作战台</b><p>飞控 / 蜂群 / 地面站 / 物流业务四条线并行，结果必须带验证、影响、整改和复测证据。</p></div><button class="button primary" data-tool="${TOOL}">打开</button></section>`;
    return `${entry}${html}`;
  };

  async function runAssessment(text) {
    evidenceDraft=String(text||'').slice(0,480000);
    busy=true; errorText='';
    state.tool=TOOL; render(); state.tool=TOOL;
    try { analysis=await window.newcyber.runTool(TOOL,{input:{text:evidenceDraft}}); }
    catch(error){ analysis=null; errorText=error?.message || String(error); }
    finally { busy=false; state.tool=TOOL; render(); state.tool=TOOL; }
  }

  document.addEventListener('input',(event)=>{
    if (state.tool===TOOL && event.target?.matches?.('[data-lowalt-evidence]')) evidenceDraft=event.target.value;
  });
  document.addEventListener('click',(event)=>{
    const surface=event.target?.closest?.('[data-lowalt-surface]');
    if (surface && state.tool===TOOL) { activeSurface=surface.dataset.lowaltSurface || 'all'; state.tool=TOOL; render(); return; }
    const action=event.target?.closest?.('[data-lowalt-action]')?.dataset.lowaltAction;
    if (!action || state.tool!==TOOL) return;
    if (action==='workspace') { const text=workspaceSummary(); if (text) runAssessment(text); }
    if (action==='analyze') runAssessment(evidenceDraft);
  });

  render();
})();
