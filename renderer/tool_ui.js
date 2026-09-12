(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined') return;

  const domainCopy = {
    vehicle: { title:'车联网', kicker:'CAN / UDS / ECU', desc:'CAN、ISO-TP、UDS、CANopen、MQTT 与刷写数据。' },
    lowalt: { title:'低空 / UAV', kicker:'802.11 / MAVLINK / LOG', desc:'802.11、MAVLink、GNSS、飞行日志、固件和控制链。' },
    ai: { title:'AI 安全', kicker:'MODEL / DATA / PIPELINE', desc:'模型文件、数据集、推理代码、反序列化和供应链检查。' },
    web3: { title:'Web3', kicker:'EVM / SOLIDITY / ABI', desc:'Solidity、EVM 字节码、ABI、calldata、存储和代理结构。' }
  };
  for (const [id, copy] of Object.entries(domainCopy)) Object.assign(DOMAINS[id] || {}, copy);

  const toolCopy = {
    'can-analyze': ['CAN 差分分析', '统计 CAN ID、周期、变化字节和 counter。'],
    'uds-decode': ['UDS / ISO-TP 解码', '解析 UDS Service、NRC、DID、SecurityAccess 和 ISO-TP。'],
    'mavlink-hex': ['MAVLink 帧解析', '解析 MAVLink v1/v2 帧、消息 ID、系统 ID 和常见字段。'],
    'nmea-analyze': ['NMEA 解析', '解析 RMC/GGA、坐标、速度、高度和轨迹范围。'],
    'ai-source-scan': ['AI 代码检查', '检查反序列化、Shell、动态执行、RAG 和工具调用边界。'],
    'ai-adversarial-audit': ['对抗样本校验', '校验扰动范数、epsilon、clip 和模型输出条件。'],
    'ai-privacy-audit': ['成员推断评估', '计算 loss/confidence/entropy 的 AUC 和阈值分离度。'],
    'ai-dataset-security': ['数据集检查', '检查重复样本、标签冲突、低频特征和 trigger 候选。'],
    'ai-supply-chain': ['模型供应链检查', '检查模型加载、远程代码、版本固定、pickle 和包索引。'],
    'ai-model-scan': ['模型文件扫描', '静态检查模型结构；可选调用本机 ModelScan / PickleScan。'],
    'evm-calldata': ['EVM Calldata', '按 selector 和 32 字节 word 拆解 calldata。'],
    'evm-disasm': ['EVM 反汇编', '离线反汇编 bytecode，并标出调用、存储和代理相关指令。'],
    'codec': ['编码 / Hash / XOR', 'Hex、Base64、URL、Hash 和 XOR。'],
    'knowledge-search': ['AI 安全速查', '离线查询提示词注入、模型加载与常用 AI 检查项。'],
    'firmware-unpack': ['固件分析', '识别镜像结构、文件系统和可恢复段；支持导出和 Binwalk 解包。']
  };

  for (const [id, [title]] of Object.entries(toolCopy)) if (TOOL_META[id]) TOOL_META[id].title = title;
  for (const domain of Object.values(DOMAINS)) {
    for (const row of domain.tools || []) {
      const copy = toolCopy[row[0]];
      if (!copy) continue;
      row[1] = copy[0];
      row[2] = copy[1];
    }
  }

  const previousHomeView = homeView;
  const previousDomainView = domainView;
  const previousCommonView = commonView;
  const previousToolView = toolView;
  const previousRender = render;

  homeView = function toolHomeView() {
    let html = previousHomeView();
    html = html.replace(/<div class="hero">[\s\S]*?<\/div>/, `<section class="tool-home-head tool-home-head-minimal"><h1>NewCyber</h1></section>`);
    html = html.replace(/进入工具箱 →/g, '打开');
    html = html.replace(/Hex、Base64、URL、SHA-256、XOR 一页完成/g, 'Hex / Base64 / URL / Hash / XOR');
    html = html.replace(/文件类型、字符串、Flag、模型\/WAV\/PCAP 基础检查/g, '扫描附件、候选结果和可导出产物');
    html = html.replace(/AI 安全速查条目离线可用/g, 'AI 安全速查条目离线可用');
    return html;
  };

  domainView = function toolDomainView(id) {
    let html = previousDomainView(id);
    html = html.replace(/<em>打开 →<\/em>/g, '<em>打开</em>');
    html = html.replace(/<article class="panel roadmap">[\s\S]*?<\/article>/, '<div class="module-footnote"><span>LOCAL</span><p>输入只在本机处理；检测结果保留原始证据，未满足条件时不会给出确定结论。</p></div>');
    return html;
  };

  commonView = function toolCommonView() {
    let html = previousCommonView();
    html = html.replace('COMMON UTILITIES', 'UTILITIES');
    html = html.replace('比赛现场最常用的小工具集中到一处，不再开十几个网页。', '编码、Hash、目录扫描和协议速查。');
    html = html.replace(/打开 →/g, '打开');
    html = html.replace('沿用现有只读扫描器，快速固定附件和初步线索。', '只读扫描目录，整理文件、候选结果和导出产物。');
    return html;
  };

  toolView = function toolSurfaceView(tool) {
    let html = previousToolView(tool);
    html = html.replace(/OFFLINE TOOL/g, 'INPUT / OUTPUT');
    html = html.replace(/AI MODEL SECURITY/g, 'MODEL');
    html = html.replace(/模型文件交叉扫描/g, '模型文件扫描');
    html = html.replace(/NewCyber 结构审计 \+ ModelScan \/ PickleScan 交叉证据。/g, '内置结构检查；本机安装 ModelScan / PickleScan 时可追加扫描。');
    html = html.replace(/选择并扫描/g, '选择文件');
    html = html.replace(/检查开源后端/g, '检查扫描器');
    html = html.replace(/运行分析/g, '分析');
    html = html.replace(/只在本机处理输入/g, '本地处理');
    html = html.replace(/等待输入。/g, '等待输入');
    return html;
  };

  function applyChrome() {
    const brand = document.querySelector('.brand small');
    if (brand) brand.textContent = 'LOCAL WORKBENCH';
    const sectionTitles = document.querySelectorAll('.nav-section > b');
    if (sectionTitles[0]) sectionTitles[0].textContent = '模块';
    if (sectionTitles[1]) sectionTitles[1].textContent = '工具';
    const labels = {vehicle:'车联网', lowalt:'低空 / UAV', ai:'AI 安全', web3:'Web3', common:'编码 / Hash', knowledge:'协议速查', workspace:'目录分析'};
    for (const button of document.querySelectorAll('.nav-item[data-view]')) {
      const label = labels[button.dataset.view];
      if (!label) continue;
      const icon = button.querySelector('span');
      const iconHtml = icon ? icon.outerHTML : '';
      button.innerHTML = `${iconHtml}${esc(label)}`;
    }
    const status = document.querySelector('.sidebar-status strong');
    const statusDetail = document.querySelector('.sidebar-status small');
    if (status) status.textContent = '本地模式';
    if (statusDetail) statusDetail.textContent = '网络非必需';
  }

  render = function toolSurfaceRender(...args) {
    const value = previousRender(...args);
    applyChrome();
    return value;
  };

  render();
})();
