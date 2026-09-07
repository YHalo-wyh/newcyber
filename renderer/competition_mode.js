(() => {
  const originalHomeView = homeView;
  const originalWorkspaceView = workspaceView;
  let workspaceArtifacts = [];

  const TRACKS = {
    vehicle: {
      title: '车联网安全',
      aliases: ['车联网', '车联网安全'],
      tool: 'can-analyze',
      action: '先看 CAN/UDS 的异常变化和可导出的固件。'
    },
    lowalt: {
      title: '低空经济安全',
      aliases: ['低空经济', '低空经济安全'],
      tool: 'mavlink-hex',
      action: '先看 MAVLink 控制链、FTP 文件和签名相关线索。'
    },
    ai: {
      title: '人工智能安全',
      aliases: ['人工智能', 'AI / ML', '人工智能安全'],
      tool: 'ai-source-scan',
      action: '先追模型/输入到 Shell、Tool、文件、反序列化等高风险路径。'
    },
    web3: {
      title: '区块链安全',
      aliases: ['区块链', '区块链安全'],
      tool: 'evm-disasm',
      action: '先看高风险调用、代理 implementation 和关键 storage/selector。'
    }
  };

  const SEVERITY_SCORE = { high: 30, medium: 12, low: 4, info: 1 };

  function trackFromCategory(name) {
    return Object.entries(TRACKS).find(([, item]) => item.aliases.includes(name))?.[0] || null;
  }

  function inferTrackFromFiles(files = []) {
    const score = { vehicle: 0, lowalt: 0, ai: 0, web3: 0 };
    for (const file of files) {
      if (file.metadata?.pcapng?.can) score.vehicle += 12;
      if (file.metadata?.lowAltitude || /(?:mavlink|ardupilot|px4|\.tlog$|\.ulg$)/i.test(file.path || '')) score.lowalt += 10;
      if (file.metadata?.aiAudit || file.metadata?.aiTabular || file.metadata?.model || /\.(?:pt|pth|safetensors|npy|onnx|gguf|csv|tsv)$/i.test(file.path || '')) score.ai += 8;
      if (file.metadata?.web3Audit || file.metadata?.solanaAudit || /\.(?:sol|vy|rs)$/i.test(file.path || '')) score.web3 += 8;
    }
    const ranked = Object.entries(score).sort((a, b) => b[1] - a[1]);
    return ranked[0]?.[1] > 0 ? ranked[0][0] : null;
  }

  function primaryTrack(analysis) {
    const ranked = (analysis.categories || [])
      .map((item) => ({ ...item, track: trackFromCategory(item.name) }))
      .filter((item) => item.track)
      .sort((a, b) => (b.score || 0) - (a.score || 0));
    const winner = ranked[0];
    if (winner) return {
      id: winner.track,
      title: TRACKS[winner.track].title,
      score: winner.score || 0,
      confidence: (winner.score || 0) >= 10 ? '很可能' : '可能'
    };
    const inferred = inferTrackFromFiles(analysis.files || []);
    return inferred ? { id: inferred, title: TRACKS[inferred].title, score: 0, confidence: '可能' } : null;
  }

  function allFlags(analysis) {
    const values = [];
    for (const file of analysis.files || []) {
      for (const flag of file.flags || []) values.push({ flag, file: file.path });
    }
    return values.filter((item, index, arr) => arr.findIndex((other) => other.flag === item.flag) === index).slice(0, 8);
  }

  function highValueFindings(analysis) {
    const items = [...(analysis.findings || [])]
      .sort((a, b) => (SEVERITY_SCORE[b.severity] || 0) - (SEVERITY_SCORE[a.severity] || 0));
    const seen = new Set();
    return items.filter((item) => {
      const key = `${item.title || item.id}:${item.file || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).slice(0, 3);
  }

  function exportableArtifacts(analysis) {
    const artifacts = [];
    for (const file of analysis.files || []) {
      const programming = file.metadata?.pcapng?.can?.udsProgramming;
      for (const transfer of programming?.transfers || []) {
        if (!transfer?.artifactReady || !transfer.artifact) continue;
        artifacts.push({
          kind: transfer.artifact.metadata?.rawTransferPayload ? 'UDS 传输数据' : 'ECU 固件候选',
          name: transfer.artifact.name || 'firmware.bin',
          file: file.path,
          size: transfer.artifact.size || transfer.firmwareSize || 0,
          artifact: transfer.artifact,
          next: transfer.artifact.metadata?.rawTransferPayload ? '数据可能仍压缩/加密，先保留并继续识别格式。' : '导出后直接交给 IDA / Ghidra 做固件逆向。'
        });
      }
      const ftp = file.metadata?.lowAltitude?.ftpReassembly || file.metadata?.mavlink?.ftpReassembly;
      for (const item of ftp?.files || []) {
        if (!item?.artifact) continue;
        artifacts.push({
          kind: 'MAVLink FTP 文件',
          name: item.artifact.name || item.path || 'mavftp.bin',
          file: file.path,
          size: item.artifact.size || item.reconstructedSize || 0,
          artifact: item.artifact,
          next: '优先查看文件内容、配置、密钥、脚本和 Flag 线索。'
        });
      }
    }
    return artifacts.slice(0, 4);
  }

  function priorityFiles(analysis) {
    return (analysis.files || []).map((file) => {
      let score = (file.flags?.length || 0) * 100;
      for (const finding of file.findings || []) score += SEVERITY_SCORE[finding.severity] || 0;
      if (file.metadata?.pcapng?.can?.udsProgramming?.exportableTransfers) score += 60;
      if ((file.metadata?.model?.securityFindings || []).some((item) => item.severity === 'high')) score += 40;
      if (file.metadata?.lowAltitude?.signing?.magicValid) score += 35;
      return { file, score };
    }).filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map((item) => item.file);
  }

  function buildSteps(track, flags, findings, artifacts) {
    const steps = [];
    if (flags.length) steps.push({ level: 'win', title: '先验证 Flag 候选', text: `${flags[0].flag} · 来自 ${flags[0].file}` });
    if (artifacts.length) steps.push({ level: 'win', title: `导出 ${artifacts[0].kind}`, text: `${artifacts[0].name}。${artifacts[0].next}` });
    if (findings.length) steps.push({ level: findings[0].severity === 'high' ? 'hot' : 'normal', title: `优先跟进：${findings[0].title || findings[0].id}`, text: findings[0].file || 'workspace' });
    if (track && steps.length < 3) steps.push({ level: 'normal', title: `按 ${track.title} 路线继续`, text: TRACKS[track.id].action });
    if (!steps.length) steps.push({ level: 'normal', title: '先确认题目入口', text: '当前没有高置信线索。先看题目说明、主要附件类型和服务入口，不要一上来就钻底层字段。' });
    return steps.slice(0, 3);
  }

  function simpleHomeView() {
    return `<section class="competition-hero">
      <span class="kicker">COMPETITION MODE</span>
      <h1>把题目丢进来，<em>先告诉你下一步做什么。</em></h1>
      <p>默认不要求你读懂所有协议字段、模型结构或 EVM 指令。NewCyber 先做离线分析，再把最值得追的线索压缩成 1～3 个动作。</p>
      <button class="button primary competition-start" data-action="choose-workspace">选择赛题目录，开始分析</button>
      <small>不会执行附件，不会联网，不会直接反序列化不可信模型。</small>
    </section>
    <div class="competition-flow">
      <article><b>1</b><strong>识别方向</strong><p>判断更像车联网、低空、AI 还是区块链。</p></article>
      <article><b>2</b><strong>抓重点</strong><p>Flag、高危线索、完整文件/固件优先。</p></article>
      <article><b>3</b><strong>给动作</strong><p>告诉你先看哪里、导出什么、再用哪个工具。</p></article>
    </div>
    <details class="advanced-details home-advanced"><summary>我想自己选专业工具</summary>${originalHomeView()}</details>`;
  }

  function simpleWorkspaceView() {
    if (!state.workspace) return originalWorkspaceView();
    const analysis = state.workspace;
    const track = primaryTrack(analysis);
    const flags = allFlags(analysis);
    const findings = highValueFindings(analysis);
    const artifacts = exportableArtifacts(analysis);
    workspaceArtifacts = artifacts.map((item) => item.artifact);
    const files = priorityFiles(analysis);
    const steps = buildSteps(track, flags, findings, artifacts);
    const highCount = (analysis.findings || []).filter((item) => item.severity === 'high').length;

    const flagPanel = flags.length ? `<article class="simple-result win"><span>FLAG 候选</span><strong>${esc(flags[0].flag)}</strong><small>${esc(flags[0].file)}</small></article>` : '';
    const artifactPanel = artifacts.length ? `<article class="simple-result win"><span>可继续利用的产物</span><strong>${esc(artifacts[0].kind)}</strong><small>${esc(artifacts[0].name)} · ${fmtBytes(artifacts[0].size)}</small><button class="button simple-export" data-competition-artifact="0">直接导出</button></article>` : '';

    return `<div class="competition-summary">
      <div class="competition-title-row"><div><span class="kicker">比赛模式</span><h1>${esc(analysis.workspaceName)}</h1><p>先看下面这几项。技术细节只有在需要复核时再展开。</p></div><button class="button ghost" data-action="rescan-workspace">重新扫描</button></div>
      <div class="simple-score-row">
        <article class="simple-result"><span>最可能方向</span><strong>${esc(track?.title || '暂不确定')}</strong><small>${track ? `${track.confidence} · 离线规则判断` : '先结合题目说明确认'}</small></article>
        <article class="simple-result"><span>高危线索</span><strong>${highCount}</strong><small>${highCount ? '优先处理，不代表漏洞必然成立' : '暂未发现明确高危链'}</small></article>
        ${flagPanel}${artifactPanel}
      </div>

      <article class="panel next-actions"><div class="result-title"><b>现在按这个顺序做</b><span>${steps.length} 步</span></div>
        <div class="step-list">${steps.map((step, index) => `<div class="competition-step ${step.level}"><b>${index + 1}</b><div><strong>${esc(step.title)}</strong><p>${esc(step.text)}</p></div></div>`).join('')}</div>
        ${track ? `<button class="button primary simple-tool-button" data-tool="${TRACKS[track.id].tool}">打开 ${esc(TRACKS[track.id].title)} 常用工具</button>` : ''}
      </article>

      ${findings.length ? `<article class="panel simple-clues"><div class="result-title"><b>最值得追的线索</b><span>只显示前 ${findings.length} 条</span></div>${findings.map((item) => `<div class="simple-clue ${esc(item.severity || 'info')}"><div><strong>${esc(item.title || item.id || '线索')}</strong><small>${esc(item.file || 'workspace')}</small></div><span>${esc(item.severity || 'info')}</span></div>`).join('')}</article>` : ''}

      ${files.length ? `<article class="panel simple-files"><div class="result-title"><b>优先看的文件</b><span>${files.length} 个</span></div>${files.map((file, index) => `<div><b>${index + 1}</b><span><strong>${esc(file.path)}</strong><small>${esc(file.type || file.extension || '文件')} · ${fmtBytes(file.size)}</small></span></div>`).join('')}</article>` : ''}

      <details class="advanced-details"><summary>展开技术细节（卡住时再看）</summary><div class="advanced-content">${originalWorkspaceView()}</div></details>
    </div>`;
  }

  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-competition-artifact]');
    if (!button) return;
    const artifact = workspaceArtifacts[Number(button.dataset.competitionArtifact)];
    if (!artifact) return toast('当前没有可导出的完整产物', true);
    button.disabled = true;
    try {
      const saved = await window.newcyber.saveArtifact(artifact);
      if (saved?.filePath) toast(`已导出 ${artifact.name}`);
    } catch (error) {
      toast(error?.message || '导出失败', true);
    } finally {
      button.disabled = false;
    }
  });

  homeView = simpleHomeView;
  workspaceView = simpleWorkspaceView;
  render();
})();
