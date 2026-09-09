'use strict';

const base = require('./uav_challenge_matrix_v5');
const { parseMavlinkFrames } = require('./low_altitude');

function uniqueDefined(values) {
  return [...new Set((values || []).filter((value) => value !== null && value !== undefined && value !== ''))];
}

function isMavHex(input) {
  const compact = String(input || '').trim().replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '');
  return compact.length >= 16 && compact.length % 2 === 0 && /^(?:fe|fd)/i.test(compact);
}

function analyzeMissionTransfer(input) {
  const frames = parseMavlinkFrames(input);
  const events = [];
  for (let index = 0; index < frames.length; index += 1) {
    const frame = frames[index];
    const p = frame.payload;
    const common = { frameIndex:index + 1, sysid:frame.sysid, compid:frame.compid, stream:`${frame.sysid}:${frame.compid}`, signed:frame.signed };
    if (frame.msgid === 43 && p.length >= 2) {
      events.push({ ...common, type:'MISSION_REQUEST_LIST', targetSystem:p[0], targetComponent:p[1], missionType:p.length > 2 ? p[2] : 0 });
    } else if (frame.msgid === 44 && p.length >= 4) {
      events.push({ ...common, type:'MISSION_COUNT', count:p.readUInt16LE(0), targetSystem:p[2], targetComponent:p[3], missionType:p.length > 4 ? p[4] : 0 });
    } else if (frame.msgid === 40 && p.length >= 4) {
      events.push({ ...common, type:'MISSION_REQUEST', seq:p.readUInt16LE(0), targetSystem:p[2], targetComponent:p[3], missionType:p.length > 4 ? p[4] : 0 });
    } else if (frame.msgid === 51 && p.length >= 4) {
      events.push({ ...common, type:'MISSION_REQUEST_INT', seq:p.readUInt16LE(0), targetSystem:p[2], targetComponent:p[3], missionType:p.length > 4 ? p[4] : 0 });
    } else if ((frame.msgid === 39 || frame.msgid === 73) && p.length >= 34) {
      events.push({ ...common, type:frame.msgid === 73 ? 'MISSION_ITEM_INT' : 'MISSION_ITEM', seq:p.readUInt16LE(28), command:p.readUInt16LE(30), targetSystem:p[32], targetComponent:p[33] });
    } else if (frame.msgid === 47 && p.length >= 3) {
      events.push({ ...common, type:'MISSION_ACK', targetSystem:p[0], targetComponent:p[1], result:p[2], missionType:p.length > 3 ? p[3] : 0 });
    }
  }

  const sessions = [];
  for (const request of events.filter((event) => event.type === 'MISSION_REQUEST_LIST')) {
    const count = events.find((event) => event.type === 'MISSION_COUNT' && event.frameIndex > request.frameIndex && event.frameIndex - request.frameIndex <= 250 && event.stream !== request.stream) || null;
    if (!count) continue;
    const requests = events.filter((event) => ['MISSION_REQUEST','MISSION_REQUEST_INT'].includes(event.type) && event.frameIndex > count.frameIndex && event.frameIndex - count.frameIndex <= 500 && event.stream === request.stream);
    const items = events.filter((event) => ['MISSION_ITEM','MISSION_ITEM_INT'].includes(event.type) && event.frameIndex > count.frameIndex && event.frameIndex - count.frameIndex <= 500 && event.stream === count.stream);
    const ack = events.find((event) => event.type === 'MISSION_ACK' && event.frameIndex > count.frameIndex && event.frameIndex - count.frameIndex <= 550) || null;
    const itemSeq = uniqueDefined(items.map((item) => item.seq)).sort((a,b) => a-b).slice(0, 200);
    const requestedSeq = uniqueDefined(requests.map((item) => item.seq)).sort((a,b) => a-b).slice(0, 200);
    const expectedSeq = Array.from({ length:Math.min(count.count, 2000) }, (_, seq) => seq);
    const complete = count.count > 0
      && count.count <= 2000
      && expectedSeq.every((seq) => itemSeq.includes(seq));
    sessions.push({
      requester:request.stream,
      responder:count.stream,
      requestedAt:request.frameIndex,
      declaredCount:count.count,
      requestCount:requests.length,
      itemCount:items.length,
      requestedSeq,
      itemSeq,
      missingSeq:expectedSeq.filter((seq) => !itemSeq.includes(seq)).slice(0, 200),
      duplicateItemCount:Math.max(0, items.length - itemSeq.length),
      ack:ack ? { stream:ack.stream, result:ack.result, frameIndex:ack.frameIndex } : null,
      complete
    });
  }
  return {
    schema:'newcyber.uav-mission-transfer.v2',
    parsedFrames:frames.length,
    events:events.length,
    sessions,
    observed:sessions.length > 0,
    completeSessions:sessions.filter((session) => session.complete).length,
    notes:['MISSION seq=0 是合法值，完整性按 0..MISSION_COUNT-1 的实际序号覆盖判断；重复 ITEM 不会伪造 complete。']
  };
}

function applyMissionOverlay(result, missionTransfer, category) {
  result.missionTransfer = missionTransfer;
  if (category && category !== 'leak') return result;
  if (!missionTransfer.observed) return result;
  const strongest = missionTransfer.sessions.find((session) => session.complete) || missionTransfer.sessions[0];
  const scenario = base.SCENARIOS.find((item) => item.id === 'mission-extract');
  if (!scenario) return result;
  const evidence = [
    `requester=${strongest.requester} responder=${strongest.responder}`,
    `declared=${strongest.declaredCount} items=${strongest.itemCount} requests=${strongest.requestCount}`,
    `seq=[${strongest.itemSeq.join(',')}]`,
    strongest.missingSeq.length ? `missing=[${strongest.missingSeq.join(',')}]` : 'mission-download-complete'
  ];
  const existing = result.hits.find((hit) => hit.scenarioId === 'mission-extract');
  if (existing) {
    existing.confidence = strongest.complete ? Math.max(existing.confidence, 0.94) : Math.max(existing.confidence, 0.84);
    existing.evidence = uniqueDefined([...(existing.evidence || []), ...evidence]);
  } else {
    result.hits.push({
      scenarioId:'mission-extract',
      title:scenario.title,
      category:scenario.category,
      confidence:strongest.complete ? 0.94 : 0.84,
      evidence,
      action:scenario.action,
      provenance:scenario.provenance || null
    });
  }
  return result;
}

function analyzeUavChallengeEvidence(input, options = {}) {
  const result = base.analyzeUavChallengeEvidence(input, options);
  const category = options.category || null;
  if (isMavHex(input)) {
    try { applyMissionOverlay(result, analyzeMissionTransfer(input), category); }
    catch (error) { result.missionTransferV2Error = error.message; }
  }
  result.hits = (result.hits || []).filter((hit) => !category || hit.category === category).sort((a,b) => b.confidence - a.confidence || a.title.localeCompare(b.title));
  for (const row of result.matrix || []) row.matched = result.hits.some((hit) => hit.scenarioId === row.id);
  result.coverage = { total:(result.matrix || []).length, matched:(result.matrix || []).filter((row) => row.matched).length };
  return result;
}

module.exports = {
  ...base,
  analyzeMissionTransfer,
  analyzeUavChallengeEvidence,
  uniqueDefined
};
