(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || typeof toolView !== 'function' || typeof domainView !== 'function' || typeof renderResult !== 'function') return;

  const previousToolView = toolView;
  const previousDomainView = domainView;
  const previousRenderResult = renderResult;
  const drafts = new Map();

  const LOWALT_GROUPS = [
    { id:'link', title:'链路 / 侦查', icon:'RF', tools:['uav-recon-analyze','uav-wifi-evidence'] },
    { id:'telemetry', title:'遥测 / MAVLink', icon:'MV', tools:['mavlink-hex','mavlink-signature-verify','uav-spoof-analyze','uav-dos-analyze','uav-injection-analyze'] },
    { id:'nav', title:'导航 / GNSS', icon:'GN', tools:['nmea-analyze','uav-gnss-audit','uav-gnss-spectrum'] },
    { id:'data', title:'日志 / 数据', icon:'LG', tools:['uav-flight-log','uav-leak-analyze','uav-regulatory-audit'] },
    { id:'firmware', title:'固件 / 信任链', icon:'FW', tools:['firmware-unpack','firmware-update-audit'] }
  ];

  const TOOL_SURFACES = {
    'uav-recon-analyze': { kind:'evidence', eyebrow:'LINK DISCOVERY', title:'无线与服务侦查台', modes:[['nmap','Nmap / 服务'],['wifi','Wi-Fi / 802.11'],['capture','抓包摘要'],['banner','Banner']], hint:'把发现结果按来源放进证据舱，输出会按无人机链路组件归类。' },
    'uav-wifi-evidence': { kind:'evidence', eyebrow:'RADIO LINK', title:'无线链路取证台', modes:[['scan','AP / Client'],['handshake','EAPOL / PMKID'],['deauth','Deauth'],['crack','离线验证']], hint:'面向 SSID/BSSID、认证材料和干扰事件，不主动发射无线攻击。' },
    'mavlink-hex': { kind:'mavlink', eyebrow:'TELEMETRY BUS', title:'MAVLink 帧工作台', modes:[['stream','连续帧'],['single','单帧'],['signed','MAVLink2 Signed'],['ftp','FILE_TRANSFER_PROTOCOL']], hint:'按帧边界、SYSID/COMPID、MSGID、签名和 FTP 会话读取，不把十六进制当普通文本。' },
    'mavlink-signature-verify': { kind:'signature', eyebrow:'MAVLINK2 SIGNING', title:'签名验证台', hint:'Signing key 与完整 signed frame 分开输入，离线验证 48-bit 签名。' },
    'uav-spoof-analyze': { kind:'evidence', eyebrow:'TELEMETRY INTEGRITY', title:'遥测一致性台', modes:[['gps','GPS'],['attitude','姿态'],['battery','电池'],['status','System Status']], hint:'聚焦物理不一致、来源冲突和状态欺骗，不只统计消息数量。' },
    'uav-dos-analyze': { kind:'evidence', eyebrow:'AVAILABILITY', title:'链路阻断事件台', modes:[['radio','Deauth / RF'],['mavlink','MAVLink Flood'],['flight','Flight Termination'],['video','Video / ROS']], hint:'把可用性事件放到同一时间轴上，优先找导致飞行状态改变的证据。' },
    'uav-injection-analyze': { kind:'evidence', eyebrow:'CONTROL PATH', title:'控制注入链工作台', modes:[['gcs','GCS'],['mission','Mission / Waypoint'],['mode','Flight Mode'],['gimbal','Gimbal']], hint:'按“控制源 → MAVLink → 飞控/任务/云台”理解注入证据。' },
    'nmea-analyze': { kind:'gnss', eyebrow:'NAVIGATION', title:'GNSS 轨迹台', modes:[['nmea','NMEA Feed'],['rmc','RMC'],['gga','GGA']], hint:'解析坐标后直接画轨迹，不再只看经纬度表格。' },
    'uav-gnss-audit': { kind:'gnss', eyebrow:'GNSS INTEGRITY', title:'GNSS 欺骗检查台', modes:[['nmea','NMEA'],['time','时间一致性'],['sat','卫星 / SNR']], hint:'同时检查 checksum、时间、速度、位置和卫星状态。' },
    'uav-gnss-spectrum': { kind:'spectrum', eyebrow:'RF SPECTRUM', title:'GNSS 频谱台', modes:[['l1','L1 / E1 / B1C'],['b1i','BeiDou B1I'],['g1','GLONASS G1'],['wide','宽带']], hint:'用频段卡片和峰值关系判断窄带干扰/噪声抬升候选。' },
    'uav-flight-log': { kind:'flightlog', eyebrow:'FLIGHT RECORDER', title:'飞行日志时间线', modes:[['mode','MODE'],['gps','GPS'],['att','ATT'],['event','ERR / EV']], hint:'把模式、定位、姿态、参数和错误还原成飞行过程。' },
    'uav-leak-analyze': { kind:'evidence', eyebrow:'DATA EXPOSURE', title:'数据泄露取证台', modes:[['ftp','FTP'],['camera','RTSP / Camera'],['log','Flight Log'],['client','Wi-Fi Client']], hint:'按数据来源归档泄露证据，避免把所有字符串混在一起。' },
    'uav-regulatory-audit': { kind:'request', eyebrow:'UTM / U-SPACE', title:'低空监管 API 审计台', hint:'把 Method、Path、Headers、Body 分开，专门看许可对象、审批状态和授权边界。' },
    'firmware-update-audit': { kind:'update', eyebrow:'UPDATE TRUST', title:'固件升级信任链', modes:[['download','Download'],['manifest','Manifest'],['verify','Signature / Hash'],['flash','Flash'],['rollback','Anti-Rollback']], hint:'沿下载→校验→写入→回滚保护检查，不把升级脚本当普通源码。' }
  };

  window.NewCyberToolSurfaces = Object.assign(window.NewCyberToolSurfaces || {}, TOOL_SURFACES);

  function draftKey(tool, field) { return `${tool}:${field}`; }
  function draft(tool, field, fallback='') { return drafts.get(draftKey(tool, field)) ?? fallback; }
  function hiddenInput(tool) { return `<textarea id="tool-input" class="surface-hidden-input" aria-hidden="true">${esc(draft(tool,'payload'))}</textarea>`; }

  function modeRow(config) {
    if (!config.modes?.length) return '';
    return `<div class="surface-mode-row" role="tablist">${config.modes.map(([id,label],index)=>`<button type="button" class="surface-mode ${index===0?'active':''}" data-surface-mode="${esc(id)}">${esc(label)}</button>`).join('')}</div>`;
  }

  function evidenceEditor(tool, config, placeholder) {
    return `${modeRow(config)}<div class="surface-editor-shell"><div class="surface-editor-toolbar"><span>证据输入</span><span>Paste / Drop transcript</span></div><textarea class="surface-editor" data-surface-field="evidence" spellcheck="false" placeholder="${esc(placeholder||'粘贴题目证据…')}">${esc(draft(tool,'evidence'))}</textarea></div>`;
  }

  function mavlinkEditor(tool, config) {
    return `${modeRow(config)}<div class="mav-frame-guide"><span>STX</span><span>LEN</span><span>SEQ</span><span>SYS</span><span>COMP</span><span>MSGID</span><span>PAYLOAD</span><span>CRC</span><span>SIGN?</span></div><div class="surface-editor-shell mono"><div class="surface-editor-toolbar"><span>Frame stream</span><span>FE / FD</span></div><textarea class="surface-editor surface-hex-editor" data-surface-field="evidence" spellcheck="false" placeholder="fe0900010100… 或 fd…">${esc(draft(tool,'evidence'))}</textarea></div>`;
  }

  function signatureEditor(tool) {
    return `<div class="surface-form-grid"><label class="surface-form-field"><span>32-byte Signing Key</span><input data-surface-field="key" value="${esc(draft(tool,'key'))}" placeholder="64 hex chars" spellcheck="false" /></label><label class="surface-form-field"><span>Signed MAVLink2 Frame</span><textarea data-surface-field="frame" placeholder="fd… 完整帧" spellcheck="false">${esc(draft(tool,'frame'))}</textarea></label></div>`;
  }

  function requestEditor(tool) {
    return `<div class="api-builder"><div class="api-request-line"><select data-surface-field="method"><option>GET</option><option>POST</option><option>PUT</option><option selected>PATCH</option><option>DELETE</option></select><input data-surface-field="path" value="${esc(draft(tool,'path','/api/flights/{flight_id}/approval'))}" placeholder="/api/..." /></div><div class="surface-form-grid"><label class="surface-form-field"><span>Headers / Auth</span><textarea data-surface-field="headers" placeholder="Authorization: Bearer …">${esc(draft(tool,'headers'))}</textarea></label><label class="surface-form-field"><span>JSON / Body</span><textarea data-surface-field="body" placeholder='{"status":"approved"}'>${esc(draft(tool,'body'))}</textarea></label></div></div>`;
  }

  function updateEditor(tool, config) {
    return `<div class="update-chain-rail">${config.modes.map(([id,label],i)=>`<span><i>${i+1}</i>${esc(label)}</span>`).join('<b>→</b>')}</div>${evidenceEditor(tool,{modes:[]},'粘贴升级脚本、manifest、校验逻辑或 strings…')}`;
  }

  function gnssEditor(tool, config) {
    return `${modeRow(config)}<div class="gnss-console-head"><span><i></i> Receiver feed</span><span>GGA · RMC · GSV · GSA</span></div><textarea class="surface-editor gnss-feed" data-surface-field="evidence" spellcheck="false" placeholder="$GPGGA,…&#10;$GPRMC,…">${esc(draft(tool,'evidence'))}</textarea>`;
  }

  function spectrumEditor(tool, config) {
    return `${modeRow(config)}<div class="spectrum-band-strip"><span>GPS L1<br><b>1575.42</b></span><span>BeiDou B1I<br><b>1561.098</b></span><span>Galileo E1<br><b>1575.42</b></span><span>GLONASS G1<br><b>~1602</b></span></div><textarea class="surface-editor spectrum-feed" data-surface-field="evidence" spellcheck="false" placeholder="frequency_hz,power_db&#10;1575420000,-71.2">${esc(draft(tool,'evidence'))}</textarea>`;
  }

  function flightLogEditor(tool, config) {
    return `${modeRow(config)}<div class="flight-recorder-strip"><span>BOOT</span><b></b><span>ARM</span><b></b><span>FLIGHT</span><b></b><span>RTL</span><b></b><span>POST</span></div><textarea class="surface-editor flight-log-feed" data-surface-field="evidence" spellcheck="false" placeholder="FMT / MODE / GPS / ATT / PARM / ERR / EV …">${esc(draft(tool,'evidence'))}</textarea>`;
  }

  function inputFor(tool, config, meta) {
    if (config.kind==='mavlink') return mavlinkEditor(tool,config);
    if (config.kind==='signature') return signatureEditor(tool);
    if (config.kind==='request') return requestEditor(tool);
    if (config.kind==='update') return updateEditor(tool,config);
    if (config.kind==='gnss') return gnssEditor(tool,config);
    if (config.kind==='spectrum') return spectrumEditor(tool,config);
    if (config.kind==='flightlog') return flightLogEditor(tool,config);
    return evidenceEditor(tool,config,meta.placeholder);
  }

  function toolSurface(tool, config) {
    const meta=TOOL_META[tool]||{};
    const resultHtml=state.toolError?`<div class="error-box">${esc(state.toolError)}</div>`:state.toolResult?renderResult(tool,state.toolResult):'<div class="surface-result-empty"><span>◇</span><b>等待证据</b><p>运行后会在这里显示结构化视图，不只输出原始 JSON/文本。</p></div>';
    return `<div class="page-head tool-head surface-page-head"><div><span class="kicker">${esc(config.eyebrow||'SPECIALIZED TOOL')}</span><h1>${esc(config.title||meta.title||tool)}</h1><p>${esc(config.hint||meta.label||'')}</p></div><button class="button ghost" data-view="lowalt">返回</button></div>
      <div class="workbench surface-workbench"><article class="panel input-panel surface-input-panel"><div class="surface-device-bar"><span><i class="surface-led"></i> LOCAL</span><strong>${esc(meta.title||tool)}</strong><span>${esc(config.kind.toUpperCase())}</span></div>${hiddenInput(tool)}${inputFor(tool,config,meta)}<div class="run-row surface-run-row"><span>离线解析 · 不主动连接目标</span><button class="button primary" data-action="run-tool">分析证据</button></div></article><article class="panel result-panel surface-result-panel"><div class="result-title"><b>结构化结果</b><button class="text-button" data-action="copy-result">复制</button></div><div id="tool-result">${resultHtml}</div></article></div>`;
  }

  function toolCard(tool) {
    const meta=TOOL_META[tool];
    if(!meta)return '';
    const row=(DOMAINS.lowalt.tools||[]).find((x)=>x[0]===tool);
    return `<button class="uav-tool-tile" data-tool="${esc(tool)}"><span>${esc((TOOL_SURFACES[tool]?.eyebrow||'UAV').split(' ')[0])}</span><strong>${esc(meta.title||row?.[1]||tool)}</strong><p>${esc(row?.[2]||meta.label||'')}</p><em>打开</em></button>`;
  }

  function systemNode(name,sub,tool,kind) {
    return `<button class="uav-system-node ${kind||''}" data-tool="${esc(tool)}"><span>${esc(sub)}</span><strong>${esc(name)}</strong></button>`;
  }

  function lowaltHome() {
    const all=new Set((DOMAINS.lowalt.tools||[]).map((x)=>x[0]));
    const grouped=new Set(LOWALT_GROUPS.flatMap((g)=>g.tools));
    const extras=[...all].filter((x)=>!grouped.has(x));
    return `<div class="uav-domain-head"><div><span class="kicker">UAV SECURITY WORKBENCH</span><h1>低空经济安全</h1></div><div class="uav-domain-status"><span><i></i>OFFLINE</span><b>${all.size}</b><small>tools</small></div></div>
      <section class="uav-system-map panel"><div class="uav-map-title"><b>无人机系统视图</b><span>按组件进入工具，而不是从输入框开始</span></div><div class="uav-system-layout">
        ${systemNode('Ground Control Station','GCS','uav-injection-analyze','gcs')}<div class="uav-link-line"><span>802.11</span><b>⇄</b><span>MAVLink</span></div>${systemNode('Companion Computer','CC','uav-recon-analyze','companion')}<div class="uav-link-line short"><b>⇄</b><span>SERIAL</span></div>${systemNode('Flight Controller','FC','mavlink-hex','fc')}
        <div class="uav-subsystems">${systemNode('GNSS','NAV','uav-gnss-audit','mini')}${systemNode('Camera / ROS','MEDIA','uav-leak-analyze','mini')}${systemNode('Flight Log','LOG','uav-flight-log','mini')}${systemNode('Firmware','FLASH','firmware-unpack','mini')}</div>
      </div></section>
      <section class="uav-flight-states"><button data-tool="uav-recon-analyze"><span>01</span><b>Boot</b><small>发现链路 / 服务</small></button><button data-tool="uav-spoof-analyze"><span>02</span><b>Arm / Takeoff</b><small>遥测一致性</small></button><button data-tool="uav-injection-analyze"><span>03</span><b>Autopilot</b><small>Mission / Mode</small></button><button data-tool="uav-dos-analyze"><span>04</span><b>Emergency / RTL</b><small>阻断 / 终止</small></button><button data-tool="uav-flight-log"><span>05</span><b>Post Flight</b><small>日志 / 数据</small></button></section>
      <div class="uav-tool-groups">${LOWALT_GROUPS.map((group)=>{const tools=group.tools.filter((id)=>all.has(id));if(!tools.length)return '';return `<section><div class="uav-group-title"><span>${group.icon}</span><b>${group.title}</b><small>${tools.length}</small></div><div class="uav-tool-grid">${tools.map(toolCard).join('')}</div></section>`;}).join('')}${extras.length?`<section><div class="uav-group-title"><span>EX</span><b>其他分析</b><small>${extras.length}</small></div><div class="uav-tool-grid">${extras.map(toolCard).join('')}</div></section>`:''}</div>`;
  }

  function lineSvg(values,width=520,height=128) {
    const nums=values.map(Number).filter(Number.isFinite);
    if(nums.length<2)return '';
    const min=Math.min(...nums),max=Math.max(...nums),span=max-min||1;
    const points=nums.map((v,i)=>`${(i/(nums.length-1)*width).toFixed(1)},${(height-8-((v-min)/span)*(height-16)).toFixed(1)}`).join(' ');
    return `<svg class="surface-sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="trend"><polyline points="${points}" fill="none" vector-effect="non-scaling-stroke"/></svg>`;
  }

  function routeSvg(points=[]) {
    const clean=points.map((p)=>({lat:Number(p.lat??p.latitude),lon:Number(p.lon??p.lng??p.longitude)})).filter((p)=>Number.isFinite(p.lat)&&Number.isFinite(p.lon)).slice(0,300);
    if(clean.length<2)return '';
    const lats=clean.map((p)=>p.lat),lons=clean.map((p)=>p.lon),minLat=Math.min(...lats),maxLat=Math.max(...lats),minLon=Math.min(...lons),maxLon=Math.max(...lons);
    const latSpan=maxLat-minLat||1,lonSpan=maxLon-minLon||1;
    const coords=clean.map((p)=>`${(18+(p.lon-minLon)/lonSpan*484).toFixed(1)},${(18+(maxLat-p.lat)/latSpan*204).toFixed(1)}`).join(' ');
    const start=coords.split(' ')[0],end=coords.split(' ').at(-1);
    const [sx,sy]=start.split(','),[ex,ey]=end.split(',');
    return `<div class="gnss-route-map"><svg viewBox="0 0 520 240" preserveAspectRatio="none"><path d="M0 60H520M0 120H520M0 180H520M130 0V240M260 0V240M390 0V240" class="route-grid"/><polyline points="${coords}" class="route-path" fill="none" vector-effect="non-scaling-stroke"/><circle cx="${sx}" cy="${sy}" r="5" class="route-start"/><circle cx="${ex}" cy="${ey}" r="5" class="route-end"/></svg><div><span>START</span><span>TRACK ${clean.length} pts</span><span>END</span></div></div>`;
  }

  function systemFlow(active='FC',detail='') {
    return `<div class="uav-mini-flow"><span>GCS</span><b>⇄</b><span>RADIO</span><b>⇄</b><span>CC</span><b>⇄</b><span class="active">${esc(active)}</span>${detail?`<em>${esc(detail)}</em>`:''}</div>`;
  }

  function visualPrefix(tool,r) {
    if(tool==='mavlink-hex'){
      const counts=Object.entries(r.messageCounts||{}).sort((a,b)=>b[1]-a[1]).slice(0,8);
      return `${systemFlow('FC',`${r.parsedFrames||r.frames?.length||0} frames`)}<div class="message-chip-row">${counts.map(([k,v])=>`<span><b>${esc(k)}</b>${esc(v)}</span>`).join('')}</div>`;
    }
    if(tool==='mavlink-signature-verify') return `<div class="signature-gauge"><div><span>VALID</span><b>${r.validFrames||0}</b></div><div><span>INVALID</span><b>${r.invalidFrames||0}</b></div><p>Key fingerprint<br><strong>${esc((r.keySha256||'—').slice(0,24))}${r.keySha256?'…':''}</strong></p></div>`;
    if(tool==='nmea-analyze') return routeSvg(r.points||[]);
    if(tool==='uav-gnss-audit') return `<div class="gnss-health-row"><span><b>${r.checksumFailed||0}</b>Checksum</span><span><b>${r.timeRollbacks?.length||0}</b>Time rollback</span><span><b>${r.jumps?.length||0}</b>Position jump</span><span><b>${r.satelliteJumps?.length||0}</b>Satellite jump</span></div>`;
    if(tool==='uav-gnss-spectrum') return `<div class="spectrum-result-bands">${(r.bands||[]).slice(0,8).map((b)=>`<span><small>${esc(b.id||'BAND')}</small><b>${Number.isFinite(Number(b.peakAboveBaselineDb))?Number(b.peakAboveBaselineDb).toFixed(1):'—'} dB</b><i style="--level:${Math.max(0,Math.min(100,(Number(b.peakAboveBaselineDb)||0)*6))}%"></i></span>`).join('')}</div>`;
    if(tool==='uav-wifi-evidence') return `<div class="wifi-topology"><span class="wifi-source">CAPTURE</span><b>)))</b><div>${(r.networks||[]).slice(0,5).map((n)=>`<span><strong>${esc(n.ssid||'<hidden>')}</strong><small>${esc(n.bssid||'—')} · CH ${esc(n.channel??'—')} · ${esc(n.security||'—')}</small></span>`).join('')||'<span><strong>No AP parsed</strong><small>等待无线证据</small></span>'}</div></div>`;
    if(tool==='uav-flight-log'){
      const values=(r.attitude||[]).slice(0,120).map((x)=>x.roll??x.pitch??x.yaw).filter((x)=>Number.isFinite(Number(x)));
      return `<div class="flight-log-visual"><div class="flight-timeline">${(r.modes||[]).slice(0,10).map((m,i)=>`<span><i></i><b>${esc(m.mode||m.name||`MODE ${i+1}`)}</b><small>${esc(m.timeSec??m.time??'')}</small></span>`).join('')||'<span><i></i><b>LOG</b><small>timeline ready</small></span>'}</div>${lineSvg(values)}</div>`;
    }
    if(tool==='uav-regulatory-audit') return `<div class="api-surface-map"><span>Operator</span><b>→</b><span>Flight Permit</span><b>→</b><span>Airspace</span><b>→</b><span>Approval</span><em>${r.authEvidence?'AUTH EVIDENCE':'AUTH UNKNOWN'}</em></div>`;
    if(tool==='firmware-update-audit'){
      const s=r.stages||{};
      return `<div class="update-result-chain">${[['download','Download'],['manifest','Manifest'],['signature','Verify'],['flash','Flash'],['rollback','Rollback']].map(([k,label],i)=>`<span class="${s[k]||s.verify||s.antiRollback?'seen':''}"><i>${i+1}</i><b>${label}</b></span>`).join('<em>→</em>')}</div>`;
    }
    if(['uav-recon-analyze','uav-spoof-analyze','uav-dos-analyze','uav-injection-analyze','uav-leak-analyze'].includes(tool)){
      const active={
        'uav-recon-analyze':'CC','uav-spoof-analyze':'FC','uav-dos-analyze':'LINK','uav-injection-analyze':'FC','uav-leak-analyze':'DATA'
      }[tool];
      return systemFlow(active,`${r.hits?.length||0} hits`);
    }
    return '';
  }

  domainView = function specializedDomainView(id) {
    if(id==='lowalt') return lowaltHome();
    return previousDomainView(id);
  };

  toolView = function specializedToolView(tool) {
    if(tool==='firmware-unpack') return previousToolView(tool);
    const config=TOOL_SURFACES[tool];
    if(config) return toolSurface(tool,config);
    return previousToolView(tool);
  };

  renderResult = function specializedResult(tool,result) {
    const base=previousRenderResult(tool,result);
    const visual=visualPrefix(tool,result||{});
    return visual?`<div class="surface-visual-result">${visual}</div>${base}`:base;
  };

  function syncPayload(tool) {
    if(!tool||!TOOL_SURFACES[tool])return;
    const hidden=document.querySelector('#tool-input');
    if(!hidden)return;
    const fields={};
    document.querySelectorAll('[data-surface-field]').forEach((el)=>{
      fields[el.dataset.surfaceField]=el.value||'';
      drafts.set(draftKey(tool,el.dataset.surfaceField),el.value||'');
    });
    let payload=fields.evidence||'';
    if(TOOL_SURFACES[tool].kind==='signature') payload=`key=${fields.key||''}\nframe=${fields.frame||''}`;
    if(TOOL_SURFACES[tool].kind==='request') payload=`${fields.method||'PATCH'} ${fields.path||'/'}\n${fields.headers||''}\n\n${fields.body||''}`.trim();
    hidden.value=payload;
    drafts.set(draftKey(tool,'payload'),payload);
  }

  document.addEventListener('input',(event)=>{
    if(event.target?.matches?.('[data-surface-field]')) syncPayload(state.tool);
  });
  document.addEventListener('change',(event)=>{
    if(event.target?.matches?.('[data-surface-field]')) syncPayload(state.tool);
  });
  document.addEventListener('click',(event)=>{
    const mode=event.target.closest?.('[data-surface-mode]');
    if(mode){
      const row=mode.closest('.surface-mode-row');
      row?.querySelectorAll('.surface-mode').forEach((x)=>x.classList.remove('active'));
      mode.classList.add('active');
    }
    if(event.target.closest?.('[data-action="run-tool"]')) syncPayload(state.tool);
  },true);

  render();
})();
