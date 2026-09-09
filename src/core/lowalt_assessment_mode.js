'use strict';

const { analyzeUavChallengeEvidence } = require('./uav_challenge_matrix_v4');
const { analyzeSwarmCoordination } = require('./lowalt_swarm');
const { analyzeCrossBoundaryFlow } = require('./lowalt_cross_boundary');

const MAX_TEXT = 512 * 1024;
const MAX_LINES = 1200;

const SOURCE_BASIS = Object.freeze([
  {
    id:'hongminggu-2025-official',
    level:'official-fact',
    date:'2025-04-14',
    title:'第五届“红明谷”杯无人机应用数据安全测评',
    publisher:'永信至诚',
    source:'https://caifuhao.eastmoney.com/news/20250414080047341118080',
    supports:[
      '赛事主题为时空数据安全，并结合低空经济产业特色',
      '决赛以真实无人机应用场景为原型',
      '公开列出无人机飞控、无人机蜂群协同、地面站通信、物流众筹系统四类环境',
      '参赛任务包含风险发现、风险评估、修复与整改方案'
    ]
  },
  {
    id:'hongminggu-2025-sitl',
    level:'official-fact',
    date:'2025-03-25',
    title:'“数字风洞”红明谷赛前技术说明',
    publisher:'永信至诚',
    source:'https://www.integritytech.com.cn/html/News/News_773_1.html',
    supports:[
      '公开说明使用软件在环 SITL 架构构建无人机飞控、蜂群、地面站与物流众筹安全测评环境',
      '公开说明采用 Testing / Evaluation / Evolution 测试评估思路'
    ]
  },
  {
    id:'bayarea-2026-official-support',
    level:'official-fact',
    date:'2026-08-18',
    title:'第二届“湾区杯”网络安全大赛技术支撑公开信息',
    publisher:'永信至诚',
    source:'https://caifuhao.eastmoney.com/news/20260818075729016513800',
    supports:[
      '永信至诚为本届湾区杯赛事技术支撑单位之一',
      '网络安全攻防赛公开覆盖低空经济安全、人工智能安全、车联网安全、区块链安全',
      '攻防赛强调发现真实漏洞并在短时间内修复、保障业务系统安全'
    ]
  },
  {
    id:'bayarea-prep-inference',
    level:'prep-inference',
    date:'2026-09-09',
    title:'NewCyber 赛前准备推断',
    publisher:'NewCyber',
    source:null,
    supports:[
      '同一技术支撑方具有“数字风洞”高仿真测试评估经验，因此为湾区杯低空方向准备场景化测评工作流具有较高收益',
      '该推断不代表湾区杯官方声明会复用红明谷赛题、拓扑、漏洞或评分细则'
    ]
  }
]);

const SURFACES = Object.freeze([
  {
    id:'flight-control', title:'无人机飞控', code:'FC',
    match:[/mavlink/i,/ardupilot/i,/px4/i,/飞控/,/flight.?control/i,/param_(?:set|value|request)/i,/mission_(?:item|count)/i,/command_long/i,/serial_control/i,/gnss|gps|nmea/i,/ulog|dataflash/i,/firmware|固件/i],
    assets:['飞控固件与启动链','MAVLink 控制/遥测','GNSS/姿态/高度等传感数据','任务/航点/围栏/返航点','参数与飞行日志'],
    tests:['身份与签名策略','控制命令授权','参数/任务完整性','多传感器一致性','固件/更新信任链','日志与敏感参数泄露'],
    impact:['未授权控制','导航/姿态错误','任务被修改','安全机制失效','飞行数据泄露','飞行可用性下降'],
    remediation:['启用并校验消息认证/签名','收紧高风险命令和参数写权限','建立任务/围栏变更审计','验证固件签名与回滚策略','对关键传感数据做交叉一致性检测']
  },
  {
    id:'swarm', title:'无人机蜂群协同', code:'SW',
    match:[/蜂群|swarm/i,/formation|编队/i,/leader|follower/i,/peer|节点/i,/mesh/i,/multicast|broadcast|组播|广播/i,/task.?assign|任务分配/i,/coordina/i,/consensus|共识/i,/time.?sync|时钟同步/i],
    assets:['成员身份/节点发现','编队与角色关系','任务分配与协同消息','广播/组播/mesh 链路','时间同步与状态共享'],
    tests:['成员准入与身份冒充','协同消息重放/篡改','角色/Leader 权限边界','任务分配完整性','广播风暴与单点故障','时间同步欺骗'],
    impact:['恶意节点加入','编队解体或错误协同','任务被劫持','状态污染扩散','群体拒绝服务'],
    remediation:['强制成员身份认证与密钥轮换','对协同消息加入新鲜度/重放保护','最小化 Leader/调度权限','限制广播/组播速率与来源','为关键协同状态建立多源确认和失效隔离']
  },
  {
    id:'ground-station', title:'地面站通信', code:'GCS',
    match:[/ground.?station|地面站|\bgcs\b/i,/ssid|bssid|wpa2|wpa3|802\.11|wifi|wi-fi/i,/rtsp|rtp|h264|h265/i,/telemetry|遥测/i,/udp|tcp|socket/i,/web.?admin|管理面/i,/ftp|ssh|telnet/i],
    assets:['GCS 身份与操作员会话','Wi-Fi/专网链路','遥测与控制通道','视频/图传链路','Web/SSH/FTP 管理面'],
    tests:['无线认证与降级','GCS 身份冒充','控制链完整性与重放','管理面弱认证/暴露服务','图传与日志泄露','多控制端冲突'],
    impact:['地面控制权被夺取','控制/遥测被注入','凭据与视频泄露','业务链路中断','错误操作员身份被信任'],
    remediation:['区分操作员、GCS 与飞行器身份','强化链路认证和密钥生命周期','隔离管理面并禁用不必要服务','对控制流建立来源/序列/签名审计','保护图传和日志访问']
  },
  {
    id:'logistics-system', title:'物流 / 众筹业务系统', code:'APP',
    match:[/物流|logistics|delivery/i,/众筹|crowd.?fund/i,/order|订单/i,/jwt|token|session/i,/api|graphql|rest/i,/idor|越权|authorization|permission/i,/payment|支付/i,/route|航线|dispatch|调度/i,/warehouse|仓储/i,/user|account|tenant/i],
    assets:['用户/商户/调度员身份','订单/任务/航线数据','无人机调度 API','支付/众筹/结算流程','运营后台与数据接口'],
    tests:['对象级/功能级授权','会话与令牌绑定','订单/任务状态机','业务参数完整性','API 重放/批量滥用','业务系统到飞控的信任边界','敏感数据最小暴露'],
    impact:['订单/航线越权修改','错误无人机被调度','资金/业务状态异常','用户与位置数据泄露','Web 风险跨边界影响飞行控制'],
    remediation:['对对象和动作同时做服务端授权','令牌绑定角色/版本/租户/关键上下文','为关键状态变更加幂等与状态机约束','把业务 API 与飞控控制权限解耦','对高风险调度建立二次确认和审计']
  }
]);

const CLOSURE_GATES = Object.freeze([
  { id:'discover', title:'风险发现', need:'资产/入口/异常行为有可定位证据' },
  { id:'verify', title:'漏洞验证', need:'触发条件、前置条件和可重复结果明确' },
  { id:'impact', title:'影响评估', need:'说明数据、控制、安全或业务影响，不只给技术现象' },
  { id:'remediate', title:'修复整改', need:'给出能落到配置/代码/架构/策略的具体措施' },
  { id:'retest', title:'复测关闭', need:'修复后使用同一测试向量或等价负例证明风险被关闭' }
]);

const FINDING_STATE = Object.freeze(['candidate','validated','remediated','retested']);

function normalizeInput(input) {
  if (typeof input === 'string') return { text:input, observations:[] };
  if (!input || typeof input !== 'object') return { text:'', observations:[] };
  const textParts=[];
  if (input.text) textParts.push(String(input.text));
  if (input.evidence) textParts.push(String(input.evidence));
  if (input.workspaceSummary) textParts.push(String(input.workspaceSummary));
  const observations=Array.isArray(input.observations) ? input.observations.slice(0,200) : [];
  for (const item of observations) {
    if (item && typeof item === 'object') textParts.push([item.surface,item.title,item.evidence,item.impact,item.remediation].filter(Boolean).join(' '));
    else if (item != null) textParts.push(String(item));
  }
  return { text:textParts.join('\n').slice(0,MAX_TEXT), observations };
}

function evidenceLines(text) {
  return String(text||'').split(/\r?\n/).map((line)=>line.trim()).filter(Boolean).slice(0,MAX_LINES);
}

function uniq(values) { return [...new Set(values.filter(Boolean))]; }

function matchLines(surface, lines) {
  const matched=[];
  for (const line of lines) {
    if (surface.match.some((pattern)=>pattern.test(line))) matched.push(line.slice(0,320));
    if (matched.length >= 18) break;
  }
  return uniq(matched);
}

function surfaceForHit(hit) {
  const text=[hit?.scenarioId,hit?.title,...(hit?.evidence||[])].filter(Boolean).join(' ');
  const direct=SURFACES.map((surface)=>({surface,score:surface.match.reduce((n,re)=>n+(re.test(text)?1:0),0)})).sort((a,b)=>b.score-a.score)[0];
  if (direct?.score) return direct.surface.id;
  if (hit?.category === 'firmware' || hit?.category === 'spoof') return 'flight-control';
  if (hit?.category === 'recon' || hit?.category === 'leak') return 'ground-station';
  if (hit?.category === 'inject' || hit?.category === 'dos') return 'flight-control';
  return null;
}

function normalizeObservation(item,index) {
  if (!item || typeof item !== 'object') return null;
  const state=FINDING_STATE.includes(item.state) ? item.state : 'candidate';
  return {
    id:item.id || `manual-${index+1}`,
    surface:SURFACES.some((s)=>s.id===item.surface) ? item.surface : null,
    title:String(item.title || '人工记录').slice(0,160),
    evidence:String(item.evidence || '').slice(0,1200),
    impact:String(item.impact || '').slice(0,1200),
    remediation:String(item.remediation || '').slice(0,1200),
    retest:String(item.retest || '').slice(0,1200),
    state,
    source:'analyst-observation',
    closureTracked:true
  };
}

function gateState(findings, gate) {
  const tracked=findings.filter((finding)=>finding.closureTracked !== false);
  const queuedCandidates=findings.filter((finding)=>finding.closureTracked === false).length;
  if (!tracked.length) return { id:gate.id,title:gate.title,status:'not-started',need:gate.need,complete:0,total:0,queuedCandidates };
  const checks=tracked.map((finding)=>{
    if (gate.id==='discover') return Boolean(finding.evidence || finding.title);
    if (gate.id==='verify') return ['validated','remediated','retested'].includes(finding.state);
    if (gate.id==='impact') return Boolean(finding.impact);
    if (gate.id==='remediate') return Boolean(finding.remediation) || ['remediated','retested'].includes(finding.state);
    if (gate.id==='retest') return Boolean(finding.retest) || finding.state==='retested';
    return false;
  });
  const complete=checks.filter(Boolean).length;
  return { id:gate.id,title:gate.title,status:complete===checks.length?'complete':complete?'partial':'missing',need:gate.need,complete,total:checks.length,queuedCandidates };
}

function autoCandidate(id,surface,title,evidence,source,extra={}) {
  return {
    id,
    surface,
    title:String(title||id).slice(0,160),
    evidence:Array.isArray(evidence)?evidence.join(' · ').slice(0,1200):String(evidence||'').slice(0,1200),
    impact:'',remediation:'',retest:'',state:'candidate',confidence:Number(extra.confidence)||0,
    source,closureTracked:false,nextCheck:String(extra.nextCheck||'').slice(0,800),severity:extra.severity||null
  };
}

function buildLowaltAssessment(input, options={}) {
  const normalized=normalizeInput(input);
  const lines=evidenceLines(normalized.text);
  let uav=null,swarm=null,crossBoundary=null;
  if (normalized.text.trim()) {
    try { uav=analyzeUavChallengeEvidence(normalized.text); } catch { uav=null; }
    try { swarm=analyzeSwarmCoordination(normalized.text, options.swarm || {}); } catch { swarm=null; }
    try { crossBoundary=analyzeCrossBoundaryFlow(normalized.text, options.crossBoundary || {}); } catch { crossBoundary=null; }
  }

  const manual=normalized.observations.map(normalizeObservation).filter(Boolean);
  const auto=[];
  for (const [index,hit] of (uav?.hits||[]).slice(0,80).entries()) {
    auto.push(autoCandidate(`uav-${index+1}`,surfaceForHit(hit),hit.title || hit.scenarioId || 'UAV evidence candidate',hit.evidence||[],'existing-uav-analyzer',{confidence:hit.confidence,nextCheck:hit.action}));
  }
  for (const [index,finding] of (swarm?.findings||[]).slice(0,40).entries()) {
    auto.push(autoCandidate(`swarm-${index+1}`,'swarm',finding.title,finding.evidence||[],'swarm-coordination',{severity:finding.severity,nextCheck:finding.nextCheck}));
  }
  for (const [index,finding] of (crossBoundary?.findings||[]).slice(0,40).entries()) {
    const surface=finding.id==='cross-boundary-control-acceptance'?'ground-station':'logistics-system';
    auto.push(autoCandidate(`cross-${index+1}`,surface,finding.title,finding.evidence||[],'cross-boundary-flow',{severity:finding.severity,nextCheck:finding.nextCheck}));
  }
  const findings=[...manual,...auto];

  const surfaces=SURFACES.map((surface)=>{
    const lineEvidence=matchLines(surface,lines);
    const linked=findings.filter((finding)=>finding.surface===surface.id);
    const observed=lineEvidence.length>0 || linked.length>0;
    const validated=linked.filter((finding)=>['validated','remediated','retested'].includes(finding.state)).length;
    return {
      id:surface.id,title:surface.title,code:surface.code,status:validated?'validated':observed?'observed':'unchecked',
      evidence:lineEvidence,findings:linked,
      assets:surface.assets,tests:surface.tests,impact:surface.impact,remediation:surface.remediation,
      nextAction:observed
        ? '把候选现象补成“入口/前置条件 → 测试向量 → 可重复结果 → 业务/安全影响”，再进入修复。'
        : `先盘点 ${surface.assets.slice(0,3).join('、')}，至少拿到一个可复核入口或通信/日志证据。`
    };
  });

  const gates=CLOSURE_GATES.map((gate)=>gateState(findings,gate));
  const observed=surfaces.filter((surface)=>surface.status!=='unchecked').length;
  const validated=surfaces.filter((surface)=>surface.status==='validated').length;
  const closureComplete=gates.filter((gate)=>gate.status==='complete').length;
  const priority=surfaces
    .map((surface)=>({id:surface.id,title:surface.title,score:(surface.status==='observed'?30:surface.status==='validated'?20:10)+surface.evidence.length+(surface.findings.length*4),reason:surface.nextAction}))
    .sort((a,b)=>b.score-a.score);

  return {
    schema:'newcyber.lowalt-assessment.v2',
    mode:'scenario-assessment',
    competitionContext:{
      target:'2026 第二届“湾区杯”网络安全大赛 · 低空经济安全准备',
      officialFacts:SOURCE_BASIS.filter((item)=>item.level==='official-fact'),
      prepInference:SOURCE_BASIS.filter((item)=>item.level==='prep-inference'),
      boundary:'红明谷公开场景用于训练评估方法与覆盖面；不得据此断言湾区杯复用相同拓扑、漏洞、Flag、评分或赛题附件。'
    },
    surfaces,
    findings,
    gates,
    priority,
    extensions:{
      swarm:swarm?{summary:swarm.summary,findings:swarm.findings,leaders:swarm.leaders,tasks:swarm.tasks}:null,
      crossBoundary:crossBoundary?{summary:crossBoundary.summary,findings:crossBoundary.findings,paths:crossBoundary.paths.slice(0,8),gaps:crossBoundary.gaps}:null
    },
    coverage:{ surfaces:SURFACES.length, observed, validated, findings:findings.length, triageCandidates:auto.length, trackedFindings:manual.length, closureComplete, closureTotal:CLOSURE_GATES.length },
    deliverableTemplate:[
      '资产 / 业务对象与信任边界',
      '风险标题与严重度',
      '入口、攻击前置条件与影响对象',
      '测试向量 / 操作步骤',
      '原始证据：请求、报文、日志、文件哈希、时间点',
      '可重复结果与对照/负例',
      '数据 / 控制 / 安全 / 业务影响',
      '根因定位',
      '具体修复整改措施',
      '复测步骤与关闭证据'
    ],
    notes:[
      'AUTO 命中只产生 candidate，不自动宣告漏洞成立。',
      '蜂群异常必须由成员/角色/序列/任务/时间的可复核冲突支撑；单个 swarm 关键字不会自动变成漏洞。',
      'APP → GCS → FC → PHYSICAL 只有在共享 trace/request/order/task/mission/route 等关联标识时才自动连边。',
      'AUTO triage candidate 不进入闭环完成度分母；只有分析员记录/提升后的 finding 才参与验证、影响、整改与复测状态。',
      '单纯开放端口、单条异常遥测、单次控制命令或关键字命中不能替代漏洞验证。',
      options.strict===false ? '当前为宽松准备模式。' : '默认采用保守证据边界：验证、影响、修复、复测分别计数。'
    ]
  };
}

function getLowaltAssessmentCatalog() {
  return { schema:'newcyber.lowalt-assessment-catalog.v1', sources:SOURCE_BASIS.map((x)=>({...x,supports:[...x.supports]})), surfaces:SURFACES.map((x)=>({...x,match:undefined})), gates:CLOSURE_GATES.map((x)=>({...x})) };
}

module.exports={ SOURCE_BASIS,SURFACES,CLOSURE_GATES,buildLowaltAssessment,getLowaltAssessmentCatalog };
