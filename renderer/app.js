const state = { analysis: null, activeView: 'overview', filter: '' };
const app = document.querySelector('#app');

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function categoryIcon(name) {
  return ({ 'AI / ML': '◎', '取证 / 流量': '⌁', '逆向工程': '◇', 'Web 安全': '⌘', '密码学': '⌬', '二进制利用': '▣', '恶意样本': '△' })[name] || '·';
}

function navItem(id, icon, label) {
  const disabled = !state.analysis && id !== 'overview';
  return `<button class="nav-item ${state.activeView === id ? 'active' : ''}" data-view="${id}" ${disabled ? 'disabled' : ''}><span>${icon}</span>${label}</button>`;
}

function shell(content) {
  return `<div class="shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark">N</span><div><strong>NewCyber</strong><small>CTF Analysis Desk</small></div></div>
      <nav>${navItem('overview', '◫', '总览')}${navItem('files', '▤', '文件证据')}${navItem('findings', '◇', '分析发现')}${navItem('candidates', '⌁', '候选结果')}${navItem('notes', '✎', '队伍记录')}</nav>
      <div class="sidebar-tip"><span>本地只读分析</span><p>不会执行赛题附件，也不会加载不可信模型。</p></div>
    </aside>
    <main>
      <header class="topbar"><div class="crumb"><span>工作台</span><b>/</b><strong>${escapeHtml(state.analysis?.workspaceName || '未选择赛题')}</strong></div><div class="actions">${state.analysis ? '<button class="button ghost" data-action="rescan">重新分析</button><button class="button ghost" data-action="export">导出报告</button>' : ''}<button class="button primary" data-action="choose">选择赛题目录</button></div></header>
      <section class="content">${content}</section>
    </main>
  </div><div id="toast" aria-live="polite"></div>`;
}

function emptyView() {
  return `<div class="hero"><div class="eyebrow">LOCAL-FIRST · EVIDENCE-DRIVEN</div><h1>把赛题附件变成<br><em>清晰的分析路线</em></h1><p>导入一道 CTF 或 AI 安全赛题，自动识别文件类型、判断题型、提取关键线索并生成可交接的证据报告。</p><button class="button primary large" data-action="choose">开始分析赛题 <span>→</span></button><div class="feature-row"><div><b>01</b><strong>自动分类</strong><span>AI、取证、逆向、Web、密码、Pwn</span></div><div><b>02</b><strong>证据固定</strong><span>哈希、元数据、字符串与候选结果</span></div><div><b>03</b><strong>路线建议</strong><span>根据附件组合生成下一步清单</span></div></div></div>`;
}

function statCard(label, value, detail) {
  return `<div class="stat"><span>${label}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></div>`;
}

function fileTable(files) {
  if (!files.length) return '<div class="empty-inline">没有匹配的文件</div>';
  return `<div class="table-wrap"><table><thead><tr><th>文件</th><th>类型</th><th>大小</th><th>熵</th><th>线索</th></tr></thead><tbody>${files.map((file) => `<tr data-file="${escapeHtml(file.path)}"><td><div class="file-name"><span>${file.type.includes('文本') ? '▤' : '◇'}</span><div><strong>${escapeHtml(file.name)}</strong><small>${escapeHtml(file.path)}</small></div></div></td><td><span class="tag">${escapeHtml(file.type)}</span></td><td>${formatBytes(file.size)}</td><td>${file.entropy}</td><td>${file.flags.length ? `<b class="count flag">${file.flags.length} flag</b>` : ''}${file.findings.length ? `<b class="count">${file.findings.length} 发现</b>` : '<span class="muted">—</span>'}</td></tr>`).join('')}</tbody></table></div>`;
}

function overviewView() {
  const analysis = state.analysis;
  const maxScore = Math.max(...analysis.categories.map((item) => item.score), 1);
  const priorityFiles = [...analysis.files].sort((a, b) => (b.flags.length + b.findings.length) - (a.flags.length + a.findings.length)).slice(0, 7);
  return `<div class="page-head"><div><span class="kicker">ANALYSIS OVERVIEW</span><h1>${escapeHtml(analysis.workspaceName)}</h1><p>${escapeHtml(analysis.workspacePath)}</p></div><span class="scan-time">分析于 ${new Date(analysis.scannedAt).toLocaleString('zh-CN')}</span></div>
    ${analysis.truncated ? '<div class="notice">目录文件超过上限，本次只分析前 6000 个文件。</div>' : ''}
    <div class="stats-grid">${statCard('文件', analysis.stats.files, '已建立索引')}${statCard('体积', formatBytes(analysis.stats.bytes), '赛题材料总量')}${statCard('发现', analysis.stats.findings, analysis.stats.findings ? '等待人工验证' : '未命中明显模式')}${statCard('Flag 候选', analysis.stats.flags, analysis.stats.flags ? '检查来源后再提交' : '尚未发现')}</div>
    <div class="grid two"><article class="panel"><div class="panel-title"><div><span>题型判断</span><small>按附件与代码特征综合评分</small></div></div><div class="categories">${analysis.categories.map((item) => `<div class="category"><i>${categoryIcon(item.name)}</i><span>${item.name}</span><div class="bar"><b style="width:${item.score ? Math.max(item.score / maxScore * 100, 8) : 0}%"></b></div><strong>${item.score}</strong></div>`).join('')}</div></article>
    <article class="panel"><div class="panel-title"><div><span>建议路线</span><small>从最短可验证链路开始</small></div></div><ol class="route-list">${analysis.recommendations.map((item) => `<li><span></span><p>${escapeHtml(item)}</p></li>`).join('')}</ol></article></div>
    <article class="panel recent"><div class="panel-title"><div><span>高价值文件</span><small>优先查看含候选结果、风险线索或专用格式的材料</small></div><button class="text-button" data-view="files">查看全部 →</button></div>${fileTable(priorityFiles)}</article>`;
}

function filesView() {
  const files = state.analysis.files.filter((file) => `${file.name} ${file.path} ${file.type}`.toLowerCase().includes(state.filter.toLowerCase()));
  return `<div class="page-head compact"><div><span class="kicker">FILE EVIDENCE</span><h1>文件证据</h1><p>点击文件查看提取的文本或可打印字符串。</p></div></div><div class="toolbar"><input id="file-filter" value="${escapeHtml(state.filter)}" placeholder="搜索文件名、路径或类型"><span>${files.length} / ${state.analysis.files.length}</span></div><article class="panel flush">${fileTable(files)}</article><div id="drawer"></div>`;
}

function findingsView() {
  const findings = state.analysis.findings;
  return `<div class="page-head compact"><div><span class="kicker">STATIC FINDINGS</span><h1>分析发现</h1><p>这些是待验证线索，命中规则不等于漏洞成立。</p></div></div><div class="finding-list">${findings.length ? findings.map((item) => `<article class="finding ${item.severity}"><span class="severity">${item.severity}</span><div><h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(item.file)} · 命中 ${item.count} 处</p><code>${escapeHtml(item.evidence)}</code></div></article>`).join('') : '<div class="empty-state">未发现明显高风险代码模式。可以继续从题目运行行为和业务逻辑入手。</div>'}</div>`;
}

function candidatePanel(title, items) {
  return `<article class="panel candidate"><div class="panel-title"><span>${title}</span><b>${items.length}</b></div><div class="candidate-list">${items.length ? items.map((item) => `<button data-copy="${escapeHtml(item.value)}"><code>${escapeHtml(item.value)}</code>${item.meta ? `<small>${escapeHtml(item.meta)}</small>` : ''}<span>复制</span></button>`).join('') : '<p class="muted">暂无结果</p>'}</div></article>`;
}

function candidatesView() {
  const { flags, urls, ips } = state.analysis.candidates;
  return `<div class="page-head compact"><div><span class="kicker">CANDIDATE EVIDENCE</span><h1>候选结果</h1><p>核对候选值与预期利用路径，避免提交附件中的诱饵。</p></div></div><div class="grid three">${candidatePanel('Flag 候选', flags.map((item) => ({ value: item.value, meta: item.file })))}${candidatePanel('URL', urls.map((value) => ({ value })))}${candidatePanel('IP 地址', ips.map((value) => ({ value })))}</div>`;
}

function notesView() {
  const key = `notes:${state.analysis.workspacePath}`;
  return `<div class="page-head compact"><div><span class="kicker">TEAM NOTES</span><h1>队伍记录</h1><p>记录已验证事实、失败尝试和下一步，导出报告时会一并保存。</p></div></div><article class="panel notes"><textarea id="notes" placeholder="示例：\n[已确认] app.py 将 ASR 输出拼入 shell 命令\n[待验证] 构造音频能否稳定识别为目标字符串\n[失败] 直接修改元数据无效">${escapeHtml(localStorage.getItem(key) || '')}</textarea><div><span id="save-state">自动保存到本机</span><button class="button primary" data-action="export">导出含记录的报告</button></div></article>`;
}

async function showFile(relativePath) {
  const drawer = document.querySelector('#drawer');
  if (!drawer) return;
  drawer.innerHTML = '<div class="drawer"><div class="drawer-head"><strong>读取文件…</strong></div></div>';
  try {
    const result = await window.newcyber.inspectFile(state.analysis.workspacePath, relativePath);
    const file = state.analysis.files.find((item) => item.path === relativePath);
    drawer.innerHTML = `<div class="drawer"><div class="drawer-head"><div><strong>${escapeHtml(relativePath)}</strong><small>SHA-256 ${escapeHtml(file.sha256)}</small></div><button data-action="close-drawer">×</button></div><div class="drawer-meta"><span>${escapeHtml(file.type)}</span><span>${formatBytes(file.size)}</span><span>熵 ${file.entropy}</span><span>${result.binary ? '字符串视图' : '文本预览'}</span></div><pre>${escapeHtml(result.text)}</pre>${result.truncated ? '<div class="drawer-note">文件较大，只显示开头部分。</div>' : ''}</div>`;
    document.querySelector('[data-action="close-drawer"]').addEventListener('click', () => { drawer.innerHTML = ''; });
  } catch (error) {
    drawer.innerHTML = `<div class="drawer"><div class="drawer-head"><strong>无法读取文件</strong><button data-action="close-drawer">×</button></div><p class="drawer-error">${escapeHtml(error.message)}</p></div>`;
  }
}

function render() {
  let content = emptyView();
  if (state.analysis) content = ({ overview: overviewView, files: filesView, findings: findingsView, candidates: candidatesView, notes: notesView })[state.activeView]();
  app.innerHTML = shell(content);
  bindEvents();
}

function toast(message, isError = false) {
  const element = document.querySelector('#toast');
  if (!element) return;
  element.textContent = message;
  element.className = isError ? 'show error' : 'show';
  setTimeout(() => { element.className = ''; }, 2600);
}

async function chooseAndScan(existingPath = null) {
  const rootPath = existingPath || await window.newcyber.chooseWorkspace();
  if (!rootPath) return;
  app.innerHTML = shell('<div class="loading-view"><div class="scanner"></div><h2>正在分析赛题</h2><p>建立文件清单、计算哈希并提取关键线索…</p></div>');
  try {
    state.analysis = await window.newcyber.scanWorkspace(rootPath);
    state.activeView = 'overview';
    state.filter = '';
    render();
    toast(`已分析 ${state.analysis.stats.files} 个文件`);
  } catch (error) {
    state.analysis = null;
    render();
    toast(error.message || '分析失败', true);
  }
}

async function exportReport() {
  if (!state.analysis) return;
  const notes = localStorage.getItem(`notes:${state.analysis.workspacePath}`) || '';
  const filePath = await window.newcyber.saveReport({ analysis: state.analysis, notes });
  if (filePath) toast(`报告已保存：${filePath}`);
}

function bindEvents() {
  document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => {
    if (!state.analysis) return;
    state.activeView = button.dataset.view;
    render();
  }));
  document.querySelectorAll('[data-action="choose"]').forEach((button) => button.addEventListener('click', () => chooseAndScan()));
  document.querySelectorAll('[data-action="rescan"]').forEach((button) => button.addEventListener('click', () => chooseAndScan(state.analysis.workspacePath)));
  document.querySelectorAll('[data-action="export"]').forEach((button) => button.addEventListener('click', exportReport));
  document.querySelectorAll('[data-file]').forEach((row) => row.addEventListener('click', () => showFile(row.dataset.file)));
  document.querySelectorAll('[data-copy]').forEach((button) => button.addEventListener('click', async () => { await navigator.clipboard.writeText(button.dataset.copy); toast('已复制'); }));
  const filter = document.querySelector('#file-filter');
  if (filter) filter.addEventListener('input', (event) => {
    const cursor = event.target.selectionStart;
    state.filter = event.target.value;
    render();
    const next = document.querySelector('#file-filter');
    next?.focus();
    next?.setSelectionRange(cursor, cursor);
  });
  const notes = document.querySelector('#notes');
  if (notes) notes.addEventListener('input', (event) => {
    localStorage.setItem(`notes:${state.analysis.workspacePath}`, event.target.value);
    const saveState = document.querySelector('#save-state');
    if (saveState) saveState.textContent = '已保存';
  });
}

render();
