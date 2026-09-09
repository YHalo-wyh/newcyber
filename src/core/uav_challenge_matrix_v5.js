'use strict';

const base = require('./uav_challenge_matrix_v4');
const { parseMavlinkFrames } = require('./low_altitude');

const DVD_REFERENCE = Object.freeze({
  id:'damn-vulnerable-drone',
  title:'Damn Vulnerable Drone',
  source:'https://github.com/nicholasaleks/Damn-Vulnerable-Drone',
  level:'public-simulator-reference',
  architecture:['Flight Controller','Companion Computer','Ground Control Station','Simulator'],
  note:'仅作为公开仿真架构/场景 coverage reference；NewCyber 的命中来自本地协议与日志证据，不依赖仓库名或 walkthrough 文本。'
});

const EXTRA_SCENARIOS = Object.freeze([
  {
    id:'companion-discovery', category:'recon', title:'Companion Computer 识别',
    tags:['companion','mavlink-router','rtsp','serial','ssh','web ui'],
    evidence:['至少两类机载计算机角色证据：MAVLink Router/串口桥/RTSP/SSH/Web 管理面/明确 companion 标识'],
    action:'把 Companion 与 FC/GCS 分开建模；继续关联 MAVLink Router、串口、摄像头与管理面，不把单个开放端口直接当成机载计算机。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'gcs-discovery', category:'recon', title:'Ground Control Station 识别',
    tags:['qgroundcontrol','qgc','mavproxy','gcs','sysid 255','14550'],
    evidence:['QGroundControl/MAVProxy/明确 GCS 标识，或多个 GCS 弱特征组合'],
    action:'建立 GCS 身份画像：sysid/compid、源地址、签名比例、控制消息类型与目标飞控；后续用它判断伪 GCS/竞争控制源。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'telemetry-discovery', category:'recon', title:'GPS / Telemetry 发现',
    tags:['gps_raw_int','global_position_int','heartbeat','telemetry','lat','lon'],
    evidence:['多类 MAVLink 遥测消息或带坐标/高度/速度的结构化遥测输出'],
    action:'先确认飞控身份与遥测 stream，再建立 GPS/姿态/速度基线；侦查证据本身不等于 GPS 欺骗。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'ros2-dds-enum', category:'recon', title:'ROS 2 / DDS Graph 枚举',
    tags:['ros2 topic','ros2 node','dds','cyclonedds','fastdds'],
    evidence:['ROS 2 topic/node/type 或 DDS graph 输出'],
    action:'记录 node/topic/type、publisher/subscriber 数与 QoS；优先标出 camera、control、navigation 等高价值 topic。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'ros2-camera-flood', category:'dos', title:'ROS 2 Camera Topic 洪泛候选',
    tags:['camera','sensor_msgs/msg/image','queue full','message lost','deadline missed'],
    evidence:['Camera/Image topic 与 queue overflow/message lost/deadline missed 等可用性证据同时出现'],
    action:'按 topic/publisher 建立消息率与丢失时间线；只有出现队列/丢包/期限异常才提升为洪泛候选。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'ros2-rogue-publisher', category:'inject', title:'ROS 2 Rogue Publisher 候选',
    tags:['publisher count','publisher_gid','dds writer','ros2 topic info'],
    evidence:['同一高价值 topic 出现多个 publisher/GID；需进一步区分合法冗余与新增发布者'],
    action:'比较 publisher GID、节点名、QoS、出现时间和消息内容；多 publisher 只是候选，不直接宣称注入成功。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'mission-extract', category:'leak', title:'Mission Extraction / Download 会话',
    tags:['mission_request_list','mission_request_int','mission_count','mission_item_int'],
    mavlink:[40,43,44,51,39,73],
    evidence:['MISSION_REQUEST_LIST → MISSION_COUNT → REQUEST/ITEM 形成可重建的 mission download 会话'],
    action:'恢复 requester/responder、任务条目数、seq 与坐标；再结合来源身份判断这是正常 GCS 下载还是未授权任务泄露。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'ros2-topic-replay', category:'leak', title:'ROS 2 Topic Replay 候选',
    tags:['ros2 bag play','stamp','publisher_gid','replay'],
    evidence:['同一 topic + timestamp/sample identity 被不同 publisher 或后续时段重复发布'],
    action:'比较 header.stamp、publisher GID、sequence 与接收时间；单纯出现 rosbag 命令不视为 replay 已成立。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'firmware-modding', category:'firmware', title:'Firmware Modding / 完整性绕过',
    tags:['patched firmware','signature bypass','checksum bypass','flash modified'],
    evidence:['固件修改与签名/校验/刷写链相关的明确证据'],
    action:'把 patch 点、签名/校验覆盖范围、刷写入口和启动后的验证状态串成完整信任链；不能只凭“firmware”字符串判定。',
    provenance:DVD_REFERENCE.id
  },
  {
    id:'firmware-decompile', category:'firmware', title:'Firmware Reverse / Decompile 证据',
    tags:['ghidra','ida','decompile','disassembly','firmware elf'],
    evidence:['固件/ELF 与反编译、反汇编或符号恢复证据同时出现'],
    action:'进入 Binary Data Graph / IDA Snapshot，优先恢复更新校验、凭据、调试服务、MAVLink/串口处理与关键常量关系。',
    provenance:DVD_REFERENCE.id
  }
]);

const SCENARIOS = Object.freeze([...base.SCENARIOS, ...EXTRA_SCENARIOS]);
const CATEGORY_NAMES = base.CATEGORY_NAMES;

function uniq(values) { return [...new Set(values.filter(Boolean))]; }
function evidenceLines(text) { return String(text || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(0, 5000); }

function analyzeRoleEvidence(input) {
  const lines = evidenceLines(input);
  const companion = [];
  const gcs = [];
  const telemetry = [];
  const companionKinds = new Set();
  const gcsKinds = new Set();
  const telemetryKinds = new Set();

  for (const line of lines) {
    const lower = line.toLowerCase();
    const capture = (list, kinds, kind) => {
      kinds.add(kind);
      if (list.length < 16) list.push(line.slice(0, 320));
    };
    if (/\bcompanion(?: computer)?\b/.test(lower)) capture(companion, companionKinds, 'explicit-companion');
    if (/mavlink[-_ ]?router/.test(lower)) capture(companion, companionKinds, 'mavlink-router');
    if (/\brtsp\b|camera stream|gimbal/.test(lower)) capture(companion, companionKinds, 'camera-service');
    if (/serial(?:_control| bridge| port)|\/dev\/tty/.test(lower)) capture(companion, companionKinds, 'serial-bridge');
    if (/\bssh\b|web(?: ui| interface| admin)|http.*login/.test(lower)) capture(companion, companionKinds, 'management-service');

    if (/ground control station|\bgcs\b/.test(lower)) capture(gcs, gcsKinds, 'explicit-gcs');
    if (/qgroundcontrol|\bqgc\b/.test(lower)) capture(gcs, gcsKinds, 'qgroundcontrol');
    if (/\bmavproxy\b/.test(lower)) capture(gcs, gcsKinds, 'mavproxy');
    if (/sysid\s*[=:]\s*255|system[_ ]?id\s*[=:]\s*255/.test(lower)) capture(gcs, gcsKinds, 'gcs-sysid');
    if (/\b(?:udp[:/ ]*)?14550\b/.test(lower)) capture(gcs, gcsKinds, 'mavlink-gcs-port');

    if (/gps_raw_int/.test(lower)) capture(telemetry, telemetryKinds, 'gps-raw');
    if (/global_position_int/.test(lower)) capture(telemetry, telemetryKinds, 'global-position');
    if (/\battitude\b/.test(lower)) capture(telemetry, telemetryKinds, 'attitude');
    if (/\bvfr_hud\b/.test(lower)) capture(telemetry, telemetryKinds, 'vfr-hud');
    if (/\bheartbeat\b/.test(lower)) capture(telemetry, telemetryKinds, 'heartbeat');
    if (/(?:lat|latitude)\s*[=:].*(?:lon|longitude)\s*[=:]/i.test(line)) capture(telemetry, telemetryKinds, 'coordinates');
  }

  return {
    companion:{ kinds:[...companionKinds], evidence:uniq(companion), candidate:companionKinds.has('explicit-companion') || companionKinds.size >= 2 },
    gcs:{ kinds:[...gcsKinds], evidence:uniq(gcs), candidate:gcsKinds.has('explicit-gcs') || gcsKinds.has('qgroundcontrol') || gcsKinds.has('mavproxy') || gcsKinds.size >= 2 },
    telemetry:{ kinds:[...telemetryKinds], evidence:uniq(telemetry), candidate:telemetryKinds.size >= 2 || telemetryKinds.has('coordinates') }
  };
}

function analyzeRos2Evidence(input) {
  const lines = evidenceLines(input);
  const topics = new Set();
  const nodes = new Set();
  const types = new Set();
  const qos = new Set();
  const publisherCounts = [];
  const publisherGids = new Map();
  const lossEvidence = [];
  const graphEvidence = [];
  const replayRows = [];
  let currentTopic = null;
  let rosMarker = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const lower = line.toLowerCase();
    if (/\bros2\b|\bdds\b|cyclonedds|fastdds|rmw_/.test(lower)) rosMarker = true;
    if (/ros2\s+(?:topic|node|bag)\b|dds\s+graph/i.test(line) && graphEvidence.length < 20) graphEvidence.push(line.slice(0, 320));

    const topicMatch = line.match(/(?:^|\bTopic:\s*)(\/[A-Za-z0-9_./-]{2,})/i) || line.match(/^\s*(\/[A-Za-z0-9_./-]{2,})\s+\[[^\]]+\]\s*$/);
    if (topicMatch) {
      currentTopic = topicMatch[1];
      topics.add(currentTopic);
      if (graphEvidence.length < 20) graphEvidence.push(line.slice(0, 320));
    }
    const nodeMatch = line.match(/(?:^|\bNode(?: name)?:\s*)(\/[A-Za-z0-9_./-]{2,})/i);
    if (nodeMatch && !/topic:/i.test(line)) nodes.add(nodeMatch[1]);
    const typeMatch = line.match(/(?:Type:\s*|\[)([A-Za-z][A-Za-z0-9_]+\/(?:msg|srv|action)\/[A-Za-z0-9_]+)\]?/i);
    if (typeMatch) types.add(typeMatch[1]);
    if (/reliab|best[_ -]?effort|durability|transient[_ -]?local|volatile|history|depth/i.test(line)) qos.add(line.slice(0, 220));

    const publisherCount = line.match(/Publisher count:\s*(\d+)/i);
    if (publisherCount) publisherCounts.push({ topic:currentTopic, count:Number(publisherCount[1]), line:index + 1 });
    const gid = line.match(/(?:publisher[_ ]?gid|endpoint[_ ]?gid|writer[_ ]?guid)\s*[:=]\s*([0-9a-f:.\-]{8,})/i);
    if (gid && currentTopic) {
      const set = publisherGids.get(currentTopic) || new Set();
      set.add(gid[1].toLowerCase());
      publisherGids.set(currentTopic, set);
    }

    if (/message lost|messages? lost|queue (?:full|overflow)|deadline missed|sample rejected|dropped messages?/i.test(line)) lossEvidence.push(line.slice(0, 320));

    const normalizedReplay = line.match(/topic\s*[=:]\s*(\/[\w./-]+).*?(?:stamp|timestamp)\s*[=:]\s*([0-9.:-]+).*?(?:publisher|gid|source)\s*[=:]\s*([\w:.-]+)/i);
    if (normalizedReplay) replayRows.push({ topic:normalizedReplay[1], stamp:normalizedReplay[2], publisher:normalizedReplay[3], line:index + 1, raw:line.slice(0, 320) });
  }

  const cameraTopics = [...topics].filter((topic) => /camera|image|video/i.test(topic));
  const imageType = [...types].some((type) => /sensor_msgs\/msg\/(?:Image|CompressedImage)/i.test(type));
  const multiPublisherTopics = uniq([
    ...publisherCounts.filter((item) => item.count > 1).map((item) => item.topic),
    ...[...publisherGids.entries()].filter(([, gids]) => gids.size > 1).map(([topic]) => topic)
  ]);
  const replayEvidence = [];
  const bySample = new Map();
  for (const row of replayRows) {
    const key = `${row.topic}|${row.stamp}`;
    const bucket = bySample.get(key) || [];
    bucket.push(row);
    bySample.set(key, bucket);
  }
  for (const bucket of bySample.values()) {
    if (bucket.length < 2) continue;
    const publishers = new Set(bucket.map((row) => row.publisher));
    if (publishers.size > 1 || bucket[bucket.length - 1].line - bucket[0].line > 2) replayEvidence.push(...bucket.map((row) => row.raw));
  }

  const graphObserved = rosMarker && (topics.size > 0 || nodes.size > 0 || types.size > 0 || graphEvidence.length > 0);
  const floodCandidate = (cameraTopics.length > 0 || imageType) && lossEvidence.length > 0;
  const roguePublisherCandidate = multiPublisherTopics.length > 0;
  const replayCandidate = replayEvidence.length > 0;

  return {
    graphObserved,
    topics:[...topics].slice(0, 120),
    nodes:[...nodes].slice(0, 120),
    types:[...types].slice(0, 120),
    qos:[...qos].slice(0, 40),
    publisherCounts:publisherCounts.slice(0, 80),
    multiPublisherTopics:multiPublisherTopics.slice(0, 40),
    cameraTopics:cameraTopics.slice(0, 40),
    lossEvidence:uniq(lossEvidence).slice(0, 30),
    graphEvidence:uniq(graphEvidence).slice(0, 30),
    replayEvidence:uniq(replayEvidence).slice(0, 30),
    floodCandidate,
    roguePublisherCandidate,
    replayCandidate,
    notes:['DDS graph 暴露、多 publisher、队列丢失与 replay 使用不同证据门槛；不会因为一个 ros2 关键字同时命中多种攻击。']
  };
}

function analyzeMissionTransfer(input) {
  const frames = parseMavlinkFrames(input);
  const events = [];
  for (let index = 0; index < frames.length; index += 1) {
    const frame = frames[index];
    const p = frame.payload;
    const common = { frameIndex:index + 1, sysid:frame.sysid, compid:frame.compid, stream:`${frame.sysid}:${frame.compid}`, signed:frame.signed };
    if (frame.msgid === 43 && p.length >= 2) events.push({ ...common, type:'MISSION_REQUEST_LIST', targetSystem:p[0], targetComponent:p[1], missionType:p.length > 2 ? p[2] : 0 });
    else if (frame.msgid === 44 && p.length >= 4) events.push({ ...common, type:'MISSION_COUNT', count:p.readUInt16LE(0), targetSystem:p[2], targetComponent:p[3], missionType:p.length > 4 ? p[4] : 0 });
    else if (frame.msgid === 40 && p.length >= 4) events.push({ ...common, type:'MISSION_REQUEST', seq:p.readUInt16LE(0), targetSystem:p[2], targetComponent:p[3], missionType:p.length > 4 ? p[4] : 0 });
    else if (frame.msgid === 51 && p.length >= 4) events.push({ ...common, type:'MISSION_REQUEST_INT', seq:p.readUInt16LE(0), targetSystem:p[2], targetComponent:p[3], missionType:p.length > 4 ? p[4] : 0 });
    else if ((frame.msgid === 39 || frame.msgid === 73) && p.length >= 34) events.push({ ...common, type:frame.msgid === 73 ? 'MISSION_ITEM_INT' : 'MISSION_ITEM', seq:p.readUInt16LE(28), command:p.readUInt16LE(30), targetSystem:p[32], targetComponent:p[33] });
    else if (frame.msgid === 47 && p.length >= 3) events.push({ ...common, type:'MISSION_ACK', targetSystem:p[0], targetComponent:p[1], result:p[2], missionType:p.length > 3 ? p[3] : 0 });
  }

  const sessions = [];
  for (const request of events.filter((event) => event.type === 'MISSION_REQUEST_LIST')) {
    const count = events.find((event) => event.type === 'MISSION_COUNT' && event.frameIndex > request.frameIndex && event.frameIndex - request.frameIndex <= 250 && event.stream !== request.stream) || null;
    if (!count) continue;
    const requests = events.filter((event) => ['MISSION_REQUEST','MISSION_REQUEST_INT'].includes(event.type) && event.frameIndex > count.frameIndex && event.frameIndex - count.frameIndex <= 500 && event.stream === request.stream);
    const items = events.filter((event) => ['MISSION_ITEM','MISSION_ITEM_INT'].includes(event.type) && event.frameIndex > count.frameIndex && event.frameIndex - count.frameIndex <= 500 && event.stream === count.stream);
    const ack = events.find((event) => event.type === 'MISSION_ACK' && event.frameIndex > count.frameIndex && event.frameIndex - count.frameIndex <= 550) || null;
    sessions.push({
      requester:request.stream,
      responder:count.stream,
      requestedAt:request.frameIndex,
      declaredCount:count.count,
      requestCount:requests.length,
      itemCount:items.length,
      itemSeq:uniq(items.map((item) => item.seq)).sort((a,b) => a-b).slice(0, 200),
      ack:ack ? { stream:ack.stream, result:ack.result, frameIndex:ack.frameIndex } : null,
      complete:count.count > 0 && uniq(items.map((item) => item.seq)).length >= count.count
    });
  }
  return { parsedFrames:frames.length, events:events.length, sessions, observed:sessions.length > 0, completeSessions:sessions.filter((session) => session.complete).length };
}

function applyHit(result, scenarioId, confidence, evidence) {
  const scenario = SCENARIOS.find((item) => item.id === scenarioId);
  if (!scenario) return;
  const existing = result.hits.find((item) => item.scenarioId === scenarioId);
  const clean = uniq((evidence || []).filter(Boolean).map((item) => String(item).slice(0, 420)));
  if (existing) {
    existing.confidence = Math.max(existing.confidence, confidence);
    existing.evidence = uniq([...(existing.evidence || []), ...clean]);
  } else {
    result.hits.push({ scenarioId, title:scenario.title, category:scenario.category, confidence, evidence:clean, action:scenario.action, provenance:scenario.provenance || null });
  }
}

function isMavHex(input) {
  const compact = String(input || '').trim().replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '');
  return compact.length >= 16 && compact.length % 2 === 0 && /^(?:fe|fd)/i.test(compact);
}

function appendExtraMatrix(result, category) {
  for (const scenario of EXTRA_SCENARIOS) {
    if (category && scenario.category !== category) continue;
    if (result.matrix.some((row) => row.id === scenario.id)) continue;
    result.matrix.push({
      id:scenario.id,
      category:scenario.category,
      categoryName:CATEGORY_NAMES[scenario.category],
      title:scenario.title,
      matched:result.hits.some((hit) => hit.scenarioId === scenario.id),
      evidence:scenario.evidence,
      action:scenario.action,
      provenance:scenario.provenance
    });
  }
}

function analyzeUavChallengeEvidence(input, options = {}) {
  const category = options.category || null;
  const result = base.analyzeUavChallengeEvidence(input, options);
  result.scenarioBasis = [DVD_REFERENCE];

  if (isMavHex(input)) {
    try {
      const missionTransfer = analyzeMissionTransfer(input);
      result.missionTransfer = missionTransfer;
      if ((!category || category === 'leak') && missionTransfer.observed) {
        const strongest = missionTransfer.sessions.find((session) => session.complete) || missionTransfer.sessions[0];
        applyHit(result, 'mission-extract', strongest.complete ? 0.94 : 0.84, [
          `requester=${strongest.requester} responder=${strongest.responder}`,
          `declared=${strongest.declaredCount} items=${strongest.itemCount} requests=${strongest.requestCount}`,
          strongest.complete ? 'mission-download-complete' : 'mission-download-partial'
        ]);
      }
    } catch (error) { result.missionTransferError = error.message; }
  } else {
    const roles = analyzeRoleEvidence(input);
    result.roleEvidence = roles;
    if (!category || category === 'recon') {
      if (roles.companion.candidate) applyHit(result, 'companion-discovery', roles.companion.kinds.includes('explicit-companion') ? 0.96 : 0.84, roles.companion.evidence);
      if (roles.gcs.candidate) applyHit(result, 'gcs-discovery', roles.gcs.kinds.some((kind) => ['explicit-gcs','qgroundcontrol','mavproxy'].includes(kind)) ? 0.96 : 0.84, roles.gcs.evidence);
      if (roles.telemetry.candidate) applyHit(result, 'telemetry-discovery', 0.86, roles.telemetry.evidence);
    }

    const ros2 = analyzeRos2Evidence(input);
    result.ros2 = ros2;
    if ((!category || category === 'recon') && ros2.graphObserved) applyHit(result, 'ros2-dds-enum', 0.93, [...ros2.graphEvidence, `topics=${ros2.topics.length} nodes=${ros2.nodes.length} types=${ros2.types.length}`]);
    if ((!category || category === 'dos') && ros2.floodCandidate) applyHit(result, 'ros2-camera-flood', 0.88, [...ros2.cameraTopics.map((topic) => `camera-topic=${topic}`), ...ros2.lossEvidence]);
    if ((!category || category === 'inject') && ros2.roguePublisherCandidate) applyHit(result, 'ros2-rogue-publisher', 0.82, ros2.multiPublisherTopics.map((topic) => `multi-publisher=${topic}`));
    if ((!category || category === 'leak') && ros2.replayCandidate) applyHit(result, 'ros2-topic-replay', 0.86, ros2.replayEvidence);

    const lines = evidenceLines(input);
    const modding = lines.filter((line) => /(?:patched|modified).{0,40}firmware|firmware.{0,40}(?:signature|checksum).{0,20}(?:bypass|disabled)|(?:signature|checksum).{0,20}(?:bypass|disabled).{0,40}firmware/i.test(line)).slice(0, 12);
    const reverse = lines.filter((line) => /(?:firmware|\.elf\b).{0,80}(?:ghidra|ida|decompil|disassembl)|(?:ghidra|ida|decompil|disassembl).{0,80}(?:firmware|\.elf\b)/i.test(line)).slice(0, 12);
    if ((!category || category === 'firmware') && modding.length) applyHit(result, 'firmware-modding', 0.9, modding);
    if ((!category || category === 'firmware') && reverse.length) applyHit(result, 'firmware-decompile', 0.88, reverse);
  }

  appendExtraMatrix(result, category);
  for (const row of result.matrix) row.matched = result.hits.some((hit) => hit.scenarioId === row.id);
  result.hits = result.hits.filter((hit) => !category || hit.category === category).sort((a,b) => b.confidence - a.confidence || a.title.localeCompare(b.title));
  result.coverage = { total:result.matrix.length, matched:result.matrix.filter((row) => row.matched).length };
  result.notes = uniq([...(result.notes || []), 'Batch32 使用 Damn Vulnerable Drone 作为场景覆盖参考，但自动命中完全由本地 evidence parser 产生；不存在按仓库名/题名命中。']);
  return result;
}

function getScenarioCatalog(category = null) {
  return SCENARIOS.filter((item) => !category || item.category === category).map((item) => ({ ...item, categoryName:CATEGORY_NAMES[item.category] }));
}

module.exports = {
  ...base,
  DVD_REFERENCE,
  EXTRA_SCENARIOS,
  SCENARIOS,
  analyzeRoleEvidence,
  analyzeRos2Evidence,
  analyzeMissionTransfer,
  analyzeUavChallengeEvidence,
  getScenarioCatalog
};
