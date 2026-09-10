(() => {
  if (typeof homeView !== 'function' || typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined') return;

  const TRACKS=[
    {id:'vehicle',code:'VEH',title:'车联网',detail:'CAN · CANopen · ISO-TP · UDS',primary:'can-analyze'},
    {id:'lowalt',code:'UAV',title:'低空经济',detail:'802.11 · MAVLink · GNSS · Firmware',primary:'mavlink-hex'},
    {id:'ai',code:'AI',title:'AI 安全',detail:'Model · Data · RAG · Agent · Prompt',primary:'ai-real-ctf-regression'},
    {id:'web3',code:'WEB3',title:'Web3',detail:'EVM · ABI · Storage · Solana',primary:'evm-disasm'}
  ];

  function safeRecent() {
    try {
      const parsed=JSON.parse(localStorage.getItem('newcyber.recentTools')||'[]');
      return Array.isArray(parsed)?parsed.filter((id)=>TOOL_META[id]).slice(0,5):[];
    } catch { return []; }
  }

  function toolCount(domain){return (DOMAINS[domain]?.tools||[]).filter((row)=>TOOL_META[row[0]]?.domain===domain).length;}

  function recentRows(){
    const ids=safeRecent();
    if(!ids.length)return '<div class="home-empty-row"><span>—</span><div><strong>暂无最近工具</strong><small>打开工具后会保存在本机</small></div></div>';
    return ids.map((id)=>{
      const meta=TOOL_META[id]||{};
      return `<button class="home-recent-row" data-tool="${esc(id)}"><span>${esc(String(meta.domain||'T').slice(0,1).toUpperCase())}</span><div><strong>${esc(meta.title||id)}</strong><small>${esc(meta.label||meta.domain||'工具')}</small></div><em>OPEN</em></button>`;
    }).join('');
  }

  function trackRows(){
    return TRACKS.map((track)=>`<button class="home-track-row" data-view="${track.id}">
      <span class="home-track-code">${track.code}</span>
      <div><strong>${track.title}</strong><small>${track.detail}</small></div>
      <b>${toolCount(track.id)}</b><em>TOOLS</em><i>›</i>
    </button>`).join('');
  }

  function dashboardHome(){
    return `<main class="home-start-center">
      <header class="home-command-head">
        <div class="home-brand-line"><span class="home-brand-mark">N</span><div><h1>NewCyber</h1><small>LOCAL SECURITY WORKBENCH</small></div></div>
        <div class="home-engine-flags"><span><i></i>OFFLINE</span><span>DETERMINISTIC</span><span>4 TRACKS</span></div>
      </header>

      <section class="home-start-grid">
        <article class="home-workspace-console">
          <div class="home-section-head"><div><span>WORKSPACE</span><strong>打开赛题</strong></div><kbd>Ctrl Shift O</kbd></div>
          <button class="home-open-target" data-action="choose-workspace">
            <span class="home-open-icon">＋</span>
            <div><strong>选择赛题目录</strong><small>附件、源码、抓包、模型、固件放在同一目录即可</small></div>
            <em>OPEN DIRECTORY</em>
          </button>
          <div class="home-pipeline"><span>DISCOVER</span><b>→</b><span>TRIAGE</span><b>→</b><span>ANALYZE</span><b>→</b><span>EVIDENCE</span></div>
          <div class="home-quiet-note"><i></i><span>只读附件 · 本机分析 · 不自动执行不可信模型/脚本</span></div>
        </article>

        <aside class="home-engine-console">
          <div class="home-section-head"><div><span>ENGINE</span><strong>分析链状态</strong></div><span class="home-online-dot">READY</span></div>
          <div class="home-engine-list">
            <div><span>01</span><strong>文件 / 协议识别</strong><em>READY</em></div>
            <div><span>02</span><strong>技术栈 / 版本</strong><em>READY</em></div>
            <div><span>03</span><strong>Advisory / PoC</strong><em>LOCAL</em></div>
            <div><span>04</span><strong>Entry → API</strong><em>B22</em></div>
            <div><span>05</span><strong>专项工具 Surface</strong><em>4 TRACKS</em></div>
          </div>
        </aside>
      </section>

      <section class="home-track-console">
        <div class="home-section-head"><div><span>TRACKS</span><strong>专项工作台</strong></div><small>按对象进入，不从万能输入框开始</small></div>
        <div class="home-track-list">${trackRows()}</div>
      </section>

      <section class="home-lower-grid">
        <article class="home-real-corpus">
          <div class="home-section-head"><div><span>REAL CORPUS</span><strong>国内 AI CTF 真题成熟度</strong></div><span class="home-count-badge">11 CASES</span></div>
          <div class="home-corpus-line"><span>Hackergame</span><span>SUCTF</span><span>CISCN / 长城杯</span><span>蓝桥杯</span><span>软件系统安全赛</span><span>湾区杯</span></div>
          <p>Recognized → Candidate → Verified 分层统计；识别到证据不再等同于自动做出原题。</p>
          <button class="home-inline-action" data-tool="ai-real-ctf-regression"><span>运行成熟度回归</span><em>AI →</em></button>
        </article>
        <article class="home-recent-console">
          <div class="home-section-head"><div><span>RECENT</span><strong>最近工具</strong></div><small>LOCAL</small></div>
          <div class="home-recent-list">${recentRows()}</div>
        </article>
      </section>
    </main>`;
  }

  homeView=dashboardHome;
  render();
})();
