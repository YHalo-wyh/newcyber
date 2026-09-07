const { analyzeMavlinkAdvanced, parseMavlinkFrames } = require('./low_altitude');

const SCENARIOS = Object.freeze([
  { id: 'wifi-cracking', category: 'recon', title: 'Wi-Fi 破解', tags: ['wifi','wpa','wpa2','wpa3','handshake','pmkid'], evidence: ['SSID/BSSID/加密套件/握手或 PMKID'], action: '确认认证方式与捕获完整性；若题目给握手/PMKID，转入口令候选或配置泄露链。' },
  { id: 'port-recon', category: 'recon', title: '端口侦查', tags: ['nmap','open port','tcp','udp','service'], evidence: ['开放端口、服务 banner、版本指纹'], action: '优先把 Web/API/FTP/RTSP/SSH/MAVLink UDP 端口与附件中的配置、凭据和协议流关联。' },
  { id: 'packet-sniffing', category: 'recon', title: '数据嗅探', tags: ['pcap','pcapng','capture','traffic','wireshark'], evidence: ['PCAP/PCAPNG、明文协议、会话元数据'], action: '按协议分流并建立时间线；优先提取凭据、参数、文件传输、控制命令与视频端点。' },
  { id: 'fingerprinting', category: 'recon', title: '指纹识别', tags: ['banner','server:','user-agent','ardupilot','px4','mavlink','rtsp'], evidence: ['服务 banner、MAVLink autopilot/type、固件/脚本版本'], action: '把设备/飞控/服务版本映射到对应解析器和已知协议语义，不直接由版本号推定漏洞。' },
  { id: 'traffic-analysis', category: 'recon', title: '数据分析', tags: ['frequency','interval','sequence','entropy','timeline'], evidence: ['消息频率、序列号、状态变化、异常时间段'], action: '建立基线后找状态突变、发送方变化、序列异常和高频洪泛。' },

  { id: 'attitude-spoof', category: 'spoof', title: '飞行姿态欺骗', tags: ['attitude','roll','pitch','yaw'], mavlink: [30], evidence: ['ATTITUDE 值突变、来源变化或与位置/速度矛盾'], action: '对 roll/pitch/yaw 做相邻帧差分并与 HEARTBEAT 模式、IMU/位置变化交叉验证。' },
  { id: 'gps-spoof', category: 'spoof', title: 'GPS 欺骗', tags: ['gps','lat','lon','fix','satellite'], mavlink: [24,33], evidence: ['位置跳变、速度不一致、fix/satellite 异常'], action: '比较 GPS_RAW_INT 与 GLOBAL_POSITION_INT；检查位置跳变速度是否物理可达。' },
  { id: 'battery-spoof', category: 'spoof', title: '电池状态欺骗', tags: ['battery','voltage','remaining'], mavlink: [1,147], evidence: ['电压/剩余电量跳变或不同消息互相矛盾'], action: '联合 SYS_STATUS/BATTERY_STATUS 检查电压、剩余百分比与电流趋势。' },
  { id: 'error-spoof', category: 'spoof', title: '错误状态欺骗', tags: ['error','fault','statustext'], mavlink: [253], evidence: ['STATUSTEXT/错误码来源、时间与上下文不一致'], action: '按 severity 和发送方聚合错误文本，检查是否与实际传感器/状态证据一致。' },
  { id: 'emergency-spoof', category: 'spoof', title: '紧急状态欺骗', tags: ['emergency','critical','failsafe'], mavlink: [0,253], evidence: ['HEARTBEAT system_status 或高 severity 文本异常'], action: '关联 HEARTBEAT system_status、STATUSTEXT 与飞行模式/解锁状态变化。' },
  { id: 'satellite-spoof', category: 'spoof', title: '卫星信号欺骗', tags: ['satellite','satellites_visible','eph','epv'], mavlink: [24], evidence: ['卫星数/精度指标异常但轨迹看似稳定'], action: '联合 satellites_visible、eph/epv、fix_type 和轨迹连续性判断。' },
  { id: 'vfrhud-spoof', category: 'spoof', title: 'VFR_HUD 欺骗', tags: ['vfr_hud','airspeed','groundspeed','heading','climb'], mavlink: [74], evidence: ['空速/地速/高度/爬升率互相矛盾'], action: '与 GLOBAL_POSITION_INT、ATTITUDE 和 GPS_RAW_INT 做物理一致性校验。' },
  { id: 'system-status-spoof', category: 'spoof', title: '系统状态欺骗', tags: ['sys_status','heartbeat','system_status'], mavlink: [0,1], evidence: ['系统状态、传感器健康位或负载突变'], action: '检查 HEARTBEAT 与 SYS_STATUS 是否来自同一可信 stream，并对健康位做时序差分。' },

  { id: 'geofence-change', category: 'dos', title: '更改地理围栏', tags: ['fence','geofence','param_set'], mavlink: [23], evidence: ['FENCE_* 参数写入、围栏点/启用状态变化'], action: '提取 PARAM_SET/PARAM_VALUE 中 FENCE_* 参数及时间线，确认是否由正常 GCS 发起。' },
  { id: 'wifi-deauth', category: 'dos', title: 'Wi-Fi Deauth 攻击', tags: ['deauth','disassoc','802.11','reason code'], evidence: ['大量 Deauthentication/Disassociation 管理帧'], action: '按 BSSID/STA/reason code/时间窗统计，区分单点漫游与持续去认证洪泛。' },
  { id: 'gps-offset', category: 'dos', title: 'GPS 偏移攻击', tags: ['gps offset','position jump','gps'], mavlink: [24,33], evidence: ['整体平移、渐进拖拽或突变'], action: '计算相邻点速度和长期偏移趋势，区分单点噪声与持续位置拖拽。' },
  { id: 'terminate-flight', category: 'dos', title: '终止飞行攻击', tags: ['flight termination','terminate','command_long'], mavlink: [76], evidence: ['高风险 COMMAND_LONG/终止类命令'], action: '解析 COMMAND_LONG command/target/confirmation，结合发送方与签名状态确认命令来源。' },
  { id: 'video-interrupt', category: 'dos', title: '视频流中断攻击', tags: ['rtsp','rtp','video','stream','packet loss'], evidence: ['RTP 序列丢失、RTSP teardown、长时间无视频包'], action: '按 SSRC/序列号/时间窗统计丢包和中断，并关联控制面命令。' },
  { id: 'prevent-takeoff', category: 'dos', title: '阻止起飞', tags: ['prearm','arm denied','takeoff denied','failsafe'], mavlink: [0,76,253], evidence: ['ARM 失败、PreArm 错误、模式/围栏/传感器条件阻断'], action: '把 ARM/DISARM、STATUSTEXT PreArm、参数变化和 HEARTBEAT armed 状态串成状态机。' },
  { id: 'link-flood', category: 'dos', title: '链路层洪水攻击', tags: ['flood','pps','broadcast','sequence gap'], evidence: ['短时间报文率异常、广播/控制消息洪泛'], action: '按源/目标/消息 ID 做速率基线，识别突增并检查正常遥测序列是否被挤压或丢失。' },

  { id: 'gcs-spoof', category: 'inject', title: '地面控制站欺骗', tags: ['gcs','sysid 255','ground station'], evidence: ['同一 GCS 身份出现多个链路/来源或签名策略不一致'], action: '按 sysid/compid/linkId/签名/序列建立发送方画像，找身份复用与来源切换。' },
  { id: 'flight-mode-inject', category: 'inject', title: '飞行模式注入', tags: ['set_mode','flight mode','custom_mode'], mavlink: [11,0], evidence: ['SET_MODE 或 HEARTBEAT custom_mode 非预期切换'], action: '恢复模式切换时间线并关联发送方、签名状态和前后控制命令。' },
  { id: 'home-overwrite', category: 'inject', title: '返航点覆盖', tags: ['home','set_home','rally'], mavlink: [76], evidence: ['DO_SET_HOME/相关命令或 HOME_POSITION 变化'], action: '恢复 home 坐标变化并与当前位置、GCS 操作时间线比较。' },
  { id: 'gimbal-takeover', category: 'inject', title: '相机云台接管', tags: ['gimbal','mount','camera'], mavlink: [76], evidence: ['MOUNT/GIMBAL/CAMERA 控制命令来源异常'], action: '聚合相机/云台 COMMAND_LONG，检查 target component、发送方和频率。' },
  { id: 'sensor-inject', category: 'inject', title: '传感器数据注入', tags: ['imu','sensor','hil','vision','odometry'], evidence: ['传感器类消息来源变化或与物理状态矛盾'], action: '做多传感器一致性校验：姿态/GPS/速度/高度/视觉里程计不能只看单一 stream。' },
  { id: 'onboard-web-bruteforce', category: 'inject', title: '机载计算机 Web 登录暴力破解', tags: ['401','403','login','password','failed','http'], evidence: ['短时间大量登录失败、用户名枚举、成功登录紧随失败'], action: '从 HTTP access/auth 日志按源 IP、用户名、状态码和时间窗统计；优先找成功登录后的敏感操作。' },
  { id: 'mavlink-inject', category: 'inject', title: 'MAVLink 注入攻击', tags: ['mavlink','unsigned','signature','command_long'], evidence: ['控制消息来自新 stream、签名状态变化、sequence/timestamp 异常'], action: '联合 CRC、MAVLink2 signature、linkId、timestamp、sysid/compid 和命令语义判定。' },
  { id: 'waypoint-inject', category: 'inject', title: '航路点注入', tags: ['mission_item','waypoint','mission'], mavlink: [39,73,44], evidence: ['MISSION_ITEM/INT/COUNT 非预期变化'], action: '重建 mission upload/download 会话，比较 waypoint 序号、坐标和发送方。' },
  { id: 'onboard-takeover', category: 'inject', title: '机载计算机接管', tags: ['ssh','webshell','shell','root','telnet','serial_control'], mavlink: [126], evidence: ['Shell/SSH/Telnet/SerialControl/Web 管理面进入执行链'], action: '优先定位凭据、命令执行、SERIAL_CONTROL shell 数据和提权后痕迹。' },

  { id: 'flight-log-extract', category: 'leak', title: '飞行日志提取', tags: ['ulog','dataflash','.bin','log','ftp'], mavlink: [110], evidence: ['FTP/日志目录/ULog/DataFlash 文件'], action: '恢复 FTP 文件或日志文件后，按时间线解析模式、位置、错误、参数变化。' },
  { id: 'parameter-extract', category: 'leak', title: '参数提取', tags: ['param_value','param_request','param_set','parameter'], mavlink: [20,21,22,23], evidence: ['PARAM_VALUE/REQUEST/SET 会话'], action: '重建参数表，优先筛选 FENCE、ARMING、FS、SERIAL、MAV、LOG、RC、GPS、COMPASS 等安全相关参数。' },
  { id: 'wifi-client-leak', category: 'leak', title: 'Wi-Fi 客户端数据泄露', tags: ['probe request','ssid','client','cookie','http'], evidence: ['客户端 MAC/SSID/明文 HTTP/凭据/token'], action: '按客户端聚合 SSID、DNS/HTTP、认证数据，注意将真实凭据标记为敏感证据。' },
  { id: 'ftp-sniff', category: 'leak', title: 'FTP 窃听', tags: ['ftp','user ','pass ','retr ','stor '], evidence: ['明文 USER/PASS/RETR/STOR 或 MAVLink FTP 路径/数据块'], action: '恢复认证信息、文件路径和传输内容；MAVLink FTP 用 session+offset 重组。' },
  { id: 'camera-signal-sniff', category: 'leak', title: '摄像机信号窃听', tags: ['rtsp','rtp','h264','h265','sdp','camera'], evidence: ['RTSP URL、SDP、RTP/H264/H265 流'], action: '提取 RTSP endpoint/认证信息/SSRC/codec；若 PCAP 含完整 RTP，按序列重组视频载荷。' },

  { id: 'firmware-analysis', category: 'firmware', title: '固件攻击面', tags: ['firmware','uimage','squashfs','jffs2','ubi','rootfs','bootloader'], evidence: ['固件头、内核、rootfs、bootloader、配置/密钥/启动脚本'], action: '先识别容器和文件系统，再解包 rootfs，最后审计启动脚本、Web/API、默认凭据、密钥、更新校验和调试服务。' }
]);

const CATEGORY_NAMES = Object.freeze({ recon: '信息侦查', spoof: '协议欺骗', dos: '拒绝服务', inject: '注入攻击', leak: '信息泄露', firmware: '固件攻击' });
const MAV_NAMES = Object.freeze({ 0:'HEARTBEAT',1:'SYS_STATUS',11:'SET_MODE',20:'PARAM_REQUEST_READ',21:'PARAM_REQUEST_LIST',22:'PARAM_VALUE',23:'PARAM_SET',24:'GPS_RAW_INT',30:'ATTITUDE',33:'GLOBAL_POSITION_INT',39:'MISSION_ITEM',44:'MISSION_COUNT',73:'MISSION_ITEM_INT',74:'VFR_HUD',76:'COMMAND_LONG',110:'FILE_TRANSFER_PROTOCOL',126:'SERIAL_CONTROL',147:'BATTERY_STATUS',253:'STATUSTEXT' });

function looksLikeMavlinkHex(input) {
  const compact = String(input || '').replace(/^0x/i,'').replace(/[^0-9a-f]/gi,'');
  return compact.length >= 16 && compact.length % 2 === 0 && /^(?:fe|fd)/i.test(compact);
}

function normalizeText(input) {
  if (typeof input === 'string') return input;
  try { return JSON.stringify(input); } catch { return String(input || ''); }
}

function analyzeTextSignals(text) {
  const lower = text.toLowerCase();
  const hits = [];
  for (const item of SCENARIOS) {
    const matched = item.tags.filter((tag) => lower.includes(tag.toLowerCase()));
    if (matched.length) hits.push({ scenarioId: item.id, title: item.title, category: item.category, confidence: Math.min(0.35 + matched.length * 0.12, 0.75), evidence: matched.map((x) => `keyword:${x}`), action: item.action });
  }
  return hits;
}

function analyzeMavSignals(input) {
  const frames = parseMavlinkFrames(input);
  const advanced = analyzeMavlinkAdvanced(input);
  const msgCounts = new Map();
  const streamMsgs = new Map();
  for (const frame of frames) {
    msgCounts.set(frame.msgid, (msgCounts.get(frame.msgid) || 0) + 1);
    const key = `${frame.sysid}:${frame.compid}`;
    if (!streamMsgs.has(key)) streamMsgs.set(key, new Set());
    streamMsgs.get(key).add(frame.msgid);
  }
  const hits = [];
  for (const item of SCENARIOS.filter((x) => x.mavlink?.length)) {
    const present = item.mavlink.filter((id) => msgCounts.has(id));
    if (!present.length) continue;
    hits.push({
      scenarioId: item.id,
      title: item.title,
      category: item.category,
      confidence: present.length === item.mavlink.length ? 0.72 : 0.55,
      evidence: present.map((id) => `${id}:${MAV_NAMES[id] || 'MSG'}`),
      action: item.action
    });
  }
  const controlIds = new Set([11,23,39,44,73,76,126]);
  const controlStreams = [...streamMsgs.entries()].filter(([, ids]) => [...ids].some((id) => controlIds.has(id))).map(([stream]) => stream);
  if (controlStreams.length > 1) {
    hits.push({ scenarioId:'multi-controller', title:'多控制源竞争候选', category:'inject', confidence:0.8, evidence:controlStreams, action:'比较各控制 stream 的签名、序列、命令时间线；确认是否存在伪 GCS 或接管。' });
  }
  const unsignedV2 = advanced?.securitySummary?.unsignedV2Frames || 0;
  const signedV2 = advanced?.securitySummary?.signedV2Frames || 0;
  if (signedV2 && unsignedV2) hits.push({ scenarioId:'mixed-signing-policy', title:'MAVLink2 签名策略混用', category:'inject', confidence:0.85, evidence:[`signed=${signedV2}`,`unsigned=${unsignedV2}`], action:'检查 unsigned 控制消息是否被飞控接受；结合 sysid/compid/linkId 判断旁路注入。' });
  if (advanced?.signingTimestampRegressions?.length) hits.push({ scenarioId:'signing-timestamp-regression', title:'MAVLink signing timestamp 回退', category:'inject', confidence:0.9, evidence:advanced.signingTimestampRegressions.slice(0,5).map((x)=>JSON.stringify(x)), action:'按 stream 复核重放/乱序/时间基准问题；签名回退本身不自动等于攻击。' });
  return { frames: frames.length, messageCounts: Object.fromEntries([...msgCounts].map(([id,count])=>[`${id} ${MAV_NAMES[id] || 'UNKNOWN'}`,count])), hits };
}

function dedupeHits(items) {
  const map = new Map();
  for (const item of items) {
    const prev = map.get(item.scenarioId);
    if (!prev || item.confidence > prev.confidence) map.set(item.scenarioId, item);
  }
  return [...map.values()].sort((a,b)=>b.confidence-a.confidence || a.title.localeCompare(b.title));
}

function analyzeUavChallengeEvidence(input, options = {}) {
  const text = normalizeText(input);
  const category = options.category || null;
  const hits = analyzeTextSignals(text);
  let mavlink = null;
  if (looksLikeMavlinkHex(text)) {
    try { mavlink = analyzeMavSignals(text); hits.push(...mavlink.hits); } catch { /* keep text analysis */ }
  }
  const filtered = dedupeHits(hits).filter((item)=>!category || item.category===category);
  const matrix = SCENARIOS.filter((item)=>!category || item.category===category).map((item)=>({
    id:item.id, category:item.category, categoryName:CATEGORY_NAMES[item.category], title:item.title,
    matched:filtered.some((hit)=>hit.scenarioId===item.id),
    evidence:item.evidence, action:item.action
  }));
  return {
    category: category || 'all',
    coverage: { total: matrix.length, matched: matrix.filter((x)=>x.matched).length },
    hits: filtered,
    matrix,
    mavlink,
    notes: [
      '命中表示“值得验证的题型/攻击面”，不是漏洞已经成立。',
      '协议欺骗与注入优先依赖来源、时间线、签名/CRC、物理一致性四类证据交叉验证。',
      '拒绝服务分析只做捕获/日志侧证据归因，不主动发送干扰或洪泛流量。'
    ]
  };
}

function getScenarioCatalog(category = null) {
  return SCENARIOS.filter((item)=>!category || item.category===category).map((item)=>({ ...item, categoryName:CATEGORY_NAMES[item.category] }));
}

module.exports = { SCENARIOS, CATEGORY_NAMES, MAV_NAMES, analyzeUavChallengeEvidence, getScenarioCatalog };
