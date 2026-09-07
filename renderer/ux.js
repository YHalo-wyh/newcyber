(() => {
  const SIDEBAR_KEY = 'newcyber.sidebarCollapsed';
  const PALETTE_ID = 'ux-command-palette';
  const baseHomeView = homeView;
  const baseRender = render;
  let commandItems = [];
  let activeCommandIndex = 0;

  homeView = () => baseHomeView().replace(
    'BAY AREA CUP · OFFLINE TOOLBOX',
    'OFFLINE · DETERMINISTIC · FOUR TRACKS'
  );

  function storedSidebarCollapsed() {
    try { return localStorage.getItem(SIDEBAR_KEY) === '1'; }
    catch (_) { return false; }
  }

  function applySidebarState(collapsed = storedSidebarCollapsed()) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);
  }

  function toggleSidebar() {
    if (window.matchMedia('(max-width: 850px)').matches) {
      document.body.classList.toggle('sidebar-mobile-open');
      return;
    }
    const collapsed = !document.body.classList.contains('sidebar-collapsed');
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    try { localStorage.setItem(SIDEBAR_KEY, collapsed ? '1' : '0'); } catch (_) {}
  }

  function ensureTopbarControls() {
    const crumb = document.querySelector('.topbar > div:first-child');
    const actions = document.querySelector('.top-actions');
    if (crumb && !crumb.querySelector('.ux-sidebar-toggle')) {
      const button = document.createElement('button');
      button.className = 'ux-sidebar-toggle';
      button.dataset.uxAction = 'toggle-sidebar';
      button.title = '折叠 / 展开侧栏';
      button.setAttribute('aria-label', '折叠或展开侧栏');
      button.textContent = '≡';
      crumb.prepend(button);
    }
    if (actions && !actions.querySelector('.ux-command-button')) {
      const button = document.createElement('button');
      button.className = 'ux-command-button';
      button.dataset.uxAction = 'open-command';
      button.title = '打开命令面板';
      button.innerHTML = '<span>快速跳转</span><kbd>Ctrl K</kbd>';
      actions.prepend(button);
    }
  }

  function updateInputCount(textarea) {
    const meta = textarea?.parentElement?.querySelector('.ux-input-meta');
    if (!meta) return;
    const count = meta.querySelector('.ux-input-count');
    if (!count) return;
    const chars = textarea.value.length;
    const lines = textarea.value ? textarea.value.split(/\r?\n/).length : 0;
    count.textContent = `${chars.toLocaleString()} 字符 · ${lines.toLocaleString()} 行`;
  }

  function ensureInputMeta() {
    const textarea = document.querySelector('#tool-input');
    if (!textarea || textarea.parentElement?.querySelector('.ux-input-meta')) return;
    const meta = document.createElement('div');
    meta.className = 'ux-input-meta';
    meta.innerHTML = '<span class="ux-input-count">0 字符 · 0 行</span><span><kbd>Ctrl Enter</kbd> 运行</span>';
    textarea.insertAdjacentElement('afterend', meta);
    updateInputCount(textarea);
  }

  function ensurePalette() {
    let palette = document.getElementById(PALETTE_ID);
    if (palette) return palette;
    palette = document.createElement('div');
    palette.id = PALETTE_ID;
    palette.setAttribute('role', 'dialog');
    palette.setAttribute('aria-modal', 'true');
    palette.setAttribute('aria-label', 'NewCyber 快速命令');
    palette.innerHTML = `
      <div class="ux-command-shell">
        <div class="ux-command-search">
          <span>⌕</span>
          <input id="ux-command-input" autocomplete="off" spellcheck="false" placeholder="输入赛道、工具或动作…" />
          <kbd>Esc</kbd>
        </div>
        <div class="ux-command-list" id="ux-command-list"></div>
        <div class="ux-command-footer"><span><kbd>↑↓</kbd> 选择</span><span><kbd>Enter</kbd> 打开</span><span><kbd>Ctrl Shift O</kbd> 赛题目录</span></div>
      </div>`;
    document.body.appendChild(palette);
    return palette;
  }

  function collectCommands() {
    const fixed = [
      { type: 'view', id: 'home', icon: 'H', title: '首页', hint: '比赛模式入口', group: '页面' },
      { type: 'workspace', id: 'workspace-open', icon: 'F', title: '选择赛题目录', hint: '离线扫描整个赛题目录', group: '动作' },
      { type: 'view', id: 'workspace', icon: 'W', title: '赛题分析结果', hint: state.workspace?.workspaceName || '打开 Workspace 页面', group: '页面' },
      { type: 'view', id: 'vehicle', icon: 'V', title: '车联网安全', hint: 'CAN / UDS / ISO-TP / MQTT', group: '赛道' },
      { type: 'view', id: 'lowalt', icon: 'U', title: '低空经济安全', hint: 'MAVLink / GNSS / 固件 / 飞行日志', group: '赛道' },
      { type: 'view', id: 'ai', icon: 'A', title: '人工智能安全', hint: 'Pipeline / 模型 / 对抗 / 隐私 / 供应链', group: '赛道' },
      { type: 'view', id: 'web3', icon: 'B', title: '区块链安全', hint: 'EVM / Solidity / ABI / Proxy', group: '赛道' },
      { type: 'view', id: 'common', icon: 'C', title: '通用工具', hint: '编码 / Hash / XOR / 自动试解', group: '页面' },
      { type: 'view', id: 'knowledge', icon: 'K', title: '离线速查', hint: '协议、selector 与常用知识', group: '页面' }
    ];
    const tools = Object.entries(TOOL_META || {}).map(([id, meta]) => ({
      type: 'tool',
      id,
      icon: String(meta.domain || 'T').slice(0, 1).toUpperCase(),
      title: meta.title || id,
      hint: `${meta.domain || 'common'} · ${meta.label || '工具'}`,
      group: '工具'
    }));
    const seen = new Set();
    return [...fixed, ...tools].filter((item) => {
      const key = `${item.type}:${item.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function commandMatches(item, query) {
    if (!query) return true;
    const haystack = `${item.title} ${item.hint} ${item.group} ${item.id}`.toLowerCase();
    const tokens = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
    return tokens.every((token) => haystack.includes(token));
  }

  function renderCommandList(query = '') {
    const list = document.getElementById('ux-command-list');
    if (!list) return;
    commandItems = collectCommands().filter((item) => commandMatches(item, query)).slice(0, 36);
    if (activeCommandIndex >= commandItems.length) activeCommandIndex = 0;
    if (!commandItems.length) {
      list.innerHTML = '<div class="ux-command-empty">没有匹配项。换一个关键词。</div>';
      return;
    }
    list.innerHTML = commandItems.map((item, index) => `
      <button class="ux-command-item ${index === activeCommandIndex ? 'active' : ''}" data-ux-command-index="${index}">
        <span>${esc(item.icon)}</span>
        <span><strong>${esc(item.title)}</strong><small>${esc(item.hint)}</small></span>
        <em>${esc(item.group)}</em>
      </button>`).join('');
    list.querySelector('.ux-command-item.active')?.scrollIntoView({ block: 'nearest' });
  }

  function openPalette() {
    const palette = ensurePalette();
    activeCommandIndex = 0;
    palette.classList.add('open');
    const input = document.getElementById('ux-command-input');
    if (input) {
      input.value = '';
      renderCommandList('');
      requestAnimationFrame(() => input.focus());
    }
  }

  function closePalette() {
    document.getElementById(PALETTE_ID)?.classList.remove('open');
  }

  function activateCommand(item) {
    if (!item) return;
    closePalette();
    if (item.type === 'view') return navigate(item.id);
    if (item.type === 'tool') return openTool(item.id);
    if (item.type === 'workspace') return chooseWorkspace();
  }

  function enhanceRenderedView() {
    applySidebarState();
    ensureTopbarControls();
    ensureInputMeta();
    ensurePalette();
  }

  render = function uxRender(...args) {
    const result = baseRender(...args);
    enhanceRenderedView();
    return result;
  };

  document.addEventListener('click', (event) => {
    const action = event.target.closest('[data-ux-action]')?.dataset.uxAction;
    if (action === 'toggle-sidebar') toggleSidebar();
    if (action === 'open-command') openPalette();

    const command = event.target.closest('[data-ux-command-index]');
    if (command) activateCommand(commandItems[Number(command.dataset.uxCommandIndex)]);

    const palette = event.target.closest(`#${PALETTE_ID}`);
    if (palette && event.target === palette) closePalette();

    if (window.matchMedia('(max-width: 850px)').matches && event.target.closest('.nav-item')) {
      document.body.classList.remove('sidebar-mobile-open');
    }
  });

  document.addEventListener('input', (event) => {
    if (event.target?.id === 'tool-input') updateInputCount(event.target);
    if (event.target?.id === 'ux-command-input') {
      activeCommandIndex = 0;
      renderCommandList(event.target.value);
    }
  });

  document.addEventListener('keydown', (event) => {
    const ctrl = event.ctrlKey || event.metaKey;
    if (ctrl && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openPalette();
      return;
    }
    if (ctrl && event.shiftKey && event.key.toLowerCase() === 'o') {
      event.preventDefault();
      closePalette();
      chooseWorkspace();
      return;
    }
    if (ctrl && event.key === 'Enter' && state.tool && document.querySelector('#tool-input')) {
      event.preventDefault();
      runCurrentTool();
      return;
    }
    if (event.key === 'Escape') {
      if (document.getElementById(PALETTE_ID)?.classList.contains('open')) {
        event.preventDefault();
        closePalette();
      } else if (document.body.classList.contains('sidebar-mobile-open')) {
        document.body.classList.remove('sidebar-mobile-open');
      }
      return;
    }
    if (!document.getElementById(PALETTE_ID)?.classList.contains('open')) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      activeCommandIndex = commandItems.length ? (activeCommandIndex + 1) % commandItems.length : 0;
      renderCommandList(document.getElementById('ux-command-input')?.value || '');
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      activeCommandIndex = commandItems.length ? (activeCommandIndex - 1 + commandItems.length) % commandItems.length : 0;
      renderCommandList(document.getElementById('ux-command-input')?.value || '');
    } else if (event.key === 'Enter') {
      event.preventDefault();
      activateCommand(commandItems[activeCommandIndex]);
    }
  });

  applySidebarState();
  enhanceRenderedView();
})();
