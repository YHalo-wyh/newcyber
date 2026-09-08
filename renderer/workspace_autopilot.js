(() => {
  const previousHomeView=homeView;
  const previousWorkspaceView=workspaceView;
  let autopilotArtifacts=[];

  function cleanLegacyLabels(html='') {
    return String(html)
      .replace(/COMPETITION MODE/g,'AUTO WORKFLOW')
      .replace(/比赛模式/g,'自动分析')
      .replace(/默认比赛模式/g,'默认自动工作流')
      .replace(/我想自己选专业工具/g,'专业工具与手动复核');
  }

  function autoHomeView() {
    const html=cleanLegacyLabels(previousHomeView());
    return html
      .replace('选择赛题目录，开始分析','选择赛题目录，一键自动分析')
      .replace('把题目丢进来，<em>先告诉你下一步做什么。</em>','把题目丢进来，<em>自动把重复劳动跑完。</em>')
      .replace('NewCyber 先做离线分析，再把最值得追的线索压缩成 1～3 个动作。','NewCyber 默认直接跑离线扫描、赛道识别、疑似编码试解、专项审计、恢复产物递归分析、技术栈版本识别、Advisory 适用性判断和 PoC 参考关联，再把需要人工处理的部分压缩到最短链路。');
  }

  function actionHtml(item,index) {
    const exportButton=Number.isInteger(item.artifactIndex)
      ? `<button class="button primary" data-autopilot-artifact="${item.artifactIndex}">直接导出</button>`:'';
    const toolButton=item.tool
      ? `<button class="button primary" data-tool="${esc(item.tool)}">打开对应工具</button>`:'';
    return `<div class="competition-step ${esc(item.level||'normal')}"><b>${index+1}</b><div><strong>${esc(item.title||'下一步')}</strong><p>${esc(item.detail||'')}</p><div class="run-row">${exportButton}${toolButton}</div></div></div>`;
  }

  function techStackPanel(analysis) {
    const stack=analysis.techStack;
    if (!stack?.stats?.components) return '';
    const exact=(stack.components||[]).filter((item)=>item.version).slice(0,18);
    const declared=(stack.components||[]).filter((item)=>!item.version && item.constraint).slice(0,8);
    const chips=[...exact,...declared].map((item)=>{
      const version=item.version||item.constraint||'?';
      const origin=(item.sources||[item.source]).filter(Boolean)[0]||'';
      return `<span class="tag" title="${esc(origin)}">${esc(item.name)} ${esc(version)}</span>`;
    }).join('');
    const ecosystems=Object.entries(stack.ecosystems||{}).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([name,count])=>`${name}:${count}`).join(' · ');
    return `<section class="panel next-actions tech-stack-panel">
      <div class="result-title"><div><b>技术栈 / 依赖 / 版本</b><p>package、lock、requirements、pom、Gradle、Go、Cargo、Composer、Gem、Dockerfile 和常见 banner 会自动解析，不需要手工抄版本号。</p></div><div class="run-row"><span>${stack.stats.manifests||0} manifests · ${stack.stats.exactVersions||0} exact versions</span></div></div>
      <div class="simple-score-row">
        <article class="simple-result"><span>组件</span><strong>${stack.stats.components||0}</strong><small>${esc(ecosystems||'已建立技术栈画像')}</small></article>
        <article class="simple-result"><span>精确版本</span><strong>${stack.stats.exactVersions||0}</strong><small>直接送入离线 Advisory 适用性判断</small></article>
        <article class="simple-result"><span>PURL</span><strong>${stack.purls?.length||0}</strong><small>用于 package 级漏洞数据关联</small></article>
        <article class="simple-result"><span>CPE candidate</span><strong>${stack.stats.cpeCandidates||0}</strong><small>只生成高置信已知映射</small></article>
      </div>
      ${chips?`<div class="tag-row">${chips}</div>`:''}
    </section>`;
  }

  function advisoryPanel(analysis) {
    const r=analysis.advisories;
    if (!r) return '';
    const s=r.summary||{};
    const status=r.indexAvailable
      ? `${r.indexStats?.advisories||0} advisories · ${r.indexStats?.packages||0} packages`
      : '未导入离线 Advisory 索引';
    const rows=(r.matches||[]).slice(0,18).map((item)=>{
      const state=item.applicability?.state||'unknown';
      const label=state==='affected'?'AFFECTED':state==='not-affected'?'NOT AFFECTED':'UNKNOWN';
      const cve=(item.cves||[]).join(', ')||item.advisoryId||'Advisory';
      const fixed=item.applicability?.fixedVersions?.length?` · fixed boundary ${item.applicability.fixedVersions.join(', ')}`:'';
      return `<article class="simple-result advisory-card ${esc(state)}">
        <span>${esc(label)}</span>
        <strong>${esc(cve)}</strong>
        <small>${esc(item.component?.name||'component')} ${esc(item.component?.version||'?')}</small>
        <small>${esc(item.applicability?.reason||'当前证据不足')}${esc(fixed)}</small>
        ${item.summary?`<small>${esc(item.summary)}</small>`:''}
      </article>`;
    }).join('');
    return `<section class="panel next-actions advisory-panel">
      <div class="result-title"><div><b>离线 Advisory 版本适用性</b><p>按“实际组件 + 精确版本 + affected range”判断。无法可靠比较时保持 UNKNOWN，不把未命中当成安全证明。</p></div><div class="run-row"><span>${esc(status)}</span><button class="button primary" data-advisory-index-import>${r.indexAvailable?'更新 Advisory 索引':'导入 Advisory 索引'}</button></div></div>
      <div class="simple-score-row">
        <article class="simple-result"><span>AFFECTED</span><strong>${s.affected||0}</strong><small>当前版本明确落入本地 affected range</small></article>
        <article class="simple-result"><span>NOT AFFECTED</span><strong>${s.notAffected||0}</strong><small>当前版本明确落在 range 外</small></article>
        <article class="simple-result"><span>UNKNOWN</span><strong>${s.unknown||0}</strong><small>版本格式或 advisory 数据不足</small></article>
      </div>
      ${rows?`<div class="simple-score-row advisory-grid">${rows}</div>`:`<div class="hint-list"><p>${esc(r.note||'当前没有可评估的组件/版本匹配。')}</p></div>`}
      <div class="hint-list"><p><b>离线数据：</b>选择你提前下载好的 OSV-compatible JSON 目录即可生成本地索引；之后每个赛题自动使用，不联网查询、不下载或执行 PoC。</p></div>
    </section>`;
  }

  function pocReferencePanel(analysis) {
    const p=analysis.pocReferences;
    if (!p) return '';
    const matches=(p.matches||[]).slice(0,10);
    const status=p.indexAvailable
      ? `${p.indexStats?.cves||0} CVE · ${p.indexStats?.references||0} references`
      : '未导入本地元数据索引';
    const cards=matches.map((item)=>{
      const repos=(item.repos||[]).slice(0,3).map((repo)=>`${esc(repo.fullName||repo.name||'repo')}${repo.stars?` ★${repo.stars}`:''}`).join(' · ');
      const keywords=(item.matchedKeywords||[]).slice(0,8).map((x)=>`<span class="tag">${esc(x)}</span>`).join('');
      const versions=item.versionEvidence?.matchedVersions||[];
      const app=item.advisoryApplicability?.state||'no-advisory-match';
      const appLine=app==='affected'
        ? '<small><b>Advisory：AFFECTED</b> · 当前精确版本命中本地 affected range</small>'
        : app==='not-affected'
          ? '<small><b>Advisory：NOT AFFECTED</b> · 当前版本已被本地 range 排除，PoC 自动降权</small>'
          : app==='unknown'
            ? '<small><b>Advisory：UNKNOWN</b> · 仍需人工核对</small>'
            : '';
      const versionLine=versions.length
        ? `<small><b>PoC 元数据版本相关：</b>${versions.map(esc).join(', ')}</small>`
        : '';
      return `<article class="simple-result poc-reference-card">
        <span>${item.exactCve?'精确 CVE':versions.length?'组件 + 版本关联':'关键词关联'} · score ${item.score||0}</span>
        <strong>${esc(item.cve||'CVE')}</strong>
        <small>${esc(item.summary||'PoC-in-GitHub 收录了相关公开仓库元数据。')}</small>
        ${appLine}${versionLine}
        ${keywords?`<div class="tag-row">${keywords}</div>`:''}
        ${repos?`<small>${repos}</small>`:''}
        <div class="run-row"><button class="button ghost" data-poc-copy="${esc(item.sourceUrl||'')}">复制索引链接</button></div>
      </article>`;
    }).join('');
    return `<section class="panel next-actions poc-reference-panel">
      <div class="result-title"><div><b>相关漏洞 / PoC 参考</b><p>来源：nomi-sec/PoC-in-GitHub。只索引 CVE、仓库名、说明、topics 与热度；若 Advisory 已判断版本不受影响，会自动降低参考优先级。</p></div><div class="run-row"><span>${esc(status)}</span><button class="button primary" data-poc-index-import>${p.indexAvailable?'更新本地索引':'导入本地索引'}</button></div></div>
      ${matches.length?`<div class="simple-score-row poc-reference-grid">${cards}</div>`:`<div class="hint-list"><p>${esc(p.note||'当前没有筛出明显相关的公开 PoC 元数据。')}</p></div>`}
      <div class="hint-list"><p><b>匹配逻辑：</b>直接出现 CVE 时最高优先；否则把产品、组件、精确版本和漏洞类型做离线倒排筛选，再由本地 Advisory 的 affected/fixed range 做二次加权。</p></div>
    </section>`;
  }

  function autopilotPanel(analysis) {
    const a=analysis.autopilot;
    if (!a) return '';
    autopilotArtifacts=(a.artifacts||[]).map((x)=>x.artifact).filter(Boolean);
    const checks=(a.automaticChecks||[]).slice(0,16);
    const track=a.track?.title||'暂未锁定';
    return `<section class="panel next-actions autopilot-panel">
      <div class="result-title"><div><b>一键自动分析已完成</b><p>打开赛题目录后默认就走自动工作流：疑似编码先试解，恢复出的文件/抓包继续递归分析，依赖、版本、Advisory 与 PoC 关联也自动跑完。</p></div><div class="run-row"><span>${a.summary?.automaticCheckKinds||0} 类检查 · ${a.summary?.automaticCheckHits||0} 次命中</span><button class="button primary" data-autopilot-bundle>一键导出结果包</button></div></div>
      <div class="simple-score-row">
        <article class="simple-result"><span>自动识别方向</span><strong>${esc(track)}</strong><small>${a.track?`score ${a.track.score}`:'结合题目说明继续判断'}</small></article>
        <article class="simple-result"><span>高危线索</span><strong>${a.summary?.highFindings||0}</strong><small>已按优先级排序</small></article>
        <article class="simple-result"><span>Flag 候选</span><strong>${a.summary?.flagCandidates||0}</strong><small>只需人工核对来源</small></article>
        <article class="simple-result"><span>Advisory 命中</span><strong>${a.summary?.advisoryAffected||0}</strong><small>${a.summary?.advisoryNotAffected||0} 个已被版本范围排除</small></article>
        <article class="simple-result"><span>可导出产物</span><strong>${a.summary?.exportableArtifacts||0}</strong><small>固件 / 抓包 / 编码恢复 / 图传 / 递归产物</small></article>
      </div>
      <div class="step-list">${(a.actions||[]).map(actionHtml).join('')}</div>
      ${checks.length?`<div class="hint-list"><p><b>已经自动跑过：</b> ${checks.map((x)=>`${esc(x.title)} ×${x.hits}`).join(' · ')}</p></div>`:''}
      <div class="hint-list"><p><b>结果包：</b>一次选择目录，自动保存 report.md、manifest.json、flags.txt（有 Flag 时）以及全部完整恢复产物。</p></div>
    </section>`;
  }

  function autoWorkspaceView() {
    const base=cleanLegacyLabels(previousWorkspaceView());
    if (!state.workspace) return base;
    return `${autopilotPanel(state.workspace)}${techStackPanel(state.workspace)}${advisoryPanel(state.workspace)}${pocReferencePanel(state.workspace)}${base}`;
  }

  document.addEventListener('click',async(event)=>{
    const advisoryButton=event.target.closest('[data-advisory-index-import]');
    if (advisoryButton) {
      advisoryButton.disabled=true;
      try {
        const status=await window.newcyber.importAdvisoryIndex();
        if (status?.available) {
          toast(`Advisory 索引已生成：${status.stats?.advisories||0} advisories · ${status.stats?.packages||0} packages`);
          if (state.workspace?.workspacePath) await chooseWorkspace(state.workspace.workspacePath);
        }
      } catch (error) {
        toast(error?.message||'Advisory 索引导入失败',true);
      } finally { advisoryButton.disabled=false; }
      return;
    }

    const importButton=event.target.closest('[data-poc-index-import]');
    if (importButton) {
      importButton.disabled=true;
      try {
        const status=await window.newcyber.importPocIndex();
        if (status?.available) {
          toast(`PoC 索引已生成：${status.stats?.cves||0} CVE · ${status.stats?.references||0} references`);
          if (state.workspace?.workspacePath) await chooseWorkspace(state.workspace.workspacePath);
        }
      } catch (error) {
        toast(error?.message||'PoC 索引导入失败',true);
      } finally {
        importButton.disabled=false;
      }
      return;
    }

    const copyPoc=event.target.closest('[data-poc-copy]');
    if (copyPoc) {
      const value=copyPoc.dataset.pocCopy||'';
      if (!value) return toast('当前没有可复制的索引链接',true);
      try { await navigator.clipboard.writeText(value); toast('已复制 PoC-in-GitHub 索引链接'); }
      catch { toast('复制失败',true); }
      return;
    }

    const bundleButton=event.target.closest('[data-autopilot-bundle]');
    if (bundleButton) {
      if (!state.workspace) return toast('当前没有可导出的分析结果',true);
      bundleButton.disabled=true;
      try {
        const saved=await window.newcyber.exportAutopilotBundle({analysis:state.workspace});
        if (saved?.ok) toast(`结果包已导出：${saved.artifacts||0} 个产物 · ${saved.flags||0} 个 Flag`);
      } catch (error) {
        toast(error?.message||'结果包导出失败',true);
      } finally {
        bundleButton.disabled=false;
      }
      return;
    }

    const button=event.target.closest('[data-autopilot-artifact]');
    if (!button) return;
    const artifact=autopilotArtifacts[Number(button.dataset.autopilotArtifact)];
    if (!artifact) return toast('当前没有可直接导出的完整产物',true);
    button.disabled=true;
    try {
      const saved=await window.newcyber.saveArtifact(artifact);
      if (saved?.filePath) toast(`已导出 ${artifact.name||'产物'}`);
    } catch (error) {
      toast(error?.message||'导出失败',true);
    } finally {
      button.disabled=false;
    }
  });

  homeView=autoHomeView;
  workspaceView=autoWorkspaceView;
  render();
})();
