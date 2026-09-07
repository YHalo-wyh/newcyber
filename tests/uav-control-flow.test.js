const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeMavlinkControlFlow } = require('../src/core/uav_control_flow');
const { analyzeUavChallengeEvidence } = require('../src/core/uav_challenge_matrix_v3');

function mav1(msgid, payload, seq = 1, sysid = 255, compid = 190) {
  return Buffer.concat([Buffer.from([0xfe, payload.length, seq, sysid, compid, msgid]), payload, Buffer.from([0,0])]);
}
function paramSet(name, value = 1) {
  const p = Buffer.alloc(23);
  p.writeFloatLE(value, 0); p[4] = 1; p[5] = 1;
  Buffer.from(name).copy(p, 6, 0, 16); p[22] = 9;
  return p;
}
function commandLong(command) {
  const p = Buffer.alloc(33);
  p.writeFloatLE(1, 0); p.writeUInt16LE(command, 28); p[30] = 1; p[31] = 1; p[32] = 0;
  return p;
}
function commandAck(command, result = 0) {
  const p = Buffer.alloc(10);
  p.writeUInt16LE(command, 0); p[2] = result; p[8] = 1; p[9] = 1;
  return p;
}
function missionItemInt(seq = 0) {
  const p = Buffer.alloc(38);
  p.writeInt32LE(Math.round(31.2304 * 1e7), 16);
  p.writeInt32LE(Math.round(121.4737 * 1e7), 20);
  p.writeFloatLE(100, 24); p.writeUInt16LE(seq, 28); p.writeUInt16LE(16, 30);
  p[32] = 1; p[33] = 1; p[34] = 3; p[36] = 1;
  return p;
}

test('control flow recognizes geofence PARAM_SET', () => {
  const wire = mav1(23, paramSet('FENCE_ENABLE', 1)).toString('hex');
  const result = analyzeMavlinkControlFlow(wire);
  assert.equal(result.paramWrites[0].family, 'geofence');
  assert.ok(result.findings.some((x) => x.id === 'geofence-param-write'));
  const matrix = analyzeUavChallengeEvidence(wire, { category:'dos' });
  assert.ok(matrix.hits.some((x) => x.scenarioId === 'geofence-change' && x.confidence >= 0.8));
});

test('control flow pairs flight termination with COMMAND_ACK', () => {
  const wire = Buffer.concat([mav1(76, commandLong(185), 1), mav1(77, commandAck(185, 0), 2, 1, 1)]).toString('hex');
  const result = analyzeMavlinkControlFlow(wire);
  const chain = result.commands.find((x) => x.command.command === 185);
  assert.ok(chain);
  assert.equal(chain.accepted, true);
  assert.equal(chain.ack.resultName, 'ACCEPTED');
  assert.ok(result.findings.some((x) => x.id === 'flight-termination-command' && x.severity === 'high'));
});

test('mission item reconstruction promotes waypoint injection playbook without fixed coordinates', () => {
  const wire = Buffer.concat([mav1(73, missionItemInt(0), 1), mav1(73, missionItemInt(1), 2)]).toString('hex');
  const result = analyzeMavlinkControlFlow(wire);
  assert.equal(result.mission.items.length, 2);
  assert.equal(result.mission.items[0].missionSeq, 0);
  assert.ok(result.findings.some((x) => x.id === 'mission-upload-observed'));
  const matrix = analyzeUavChallengeEvidence(wire, { category:'inject' });
  assert.ok(matrix.hits.some((x) => x.scenarioId === 'waypoint-inject'));
});
