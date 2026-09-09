'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  rc4Crypt,
  xorRepeating,
  recoverFlagFromSecret,
  inspectCryptoHints
} = require('../src/core/secret_flag_recovery');
const {
  analyzeUavChallengeEvidence,
  analyzeRos2Evidence,
  analyzeMissionTransfer,
  analyzeRoleEvidence,
  getScenarioCatalog,
  DVD_REFERENCE
} = require('../src/core/uav_challenge_matrix_v5');
const { runTool } = require('../src/core/tool_router');

function mav1(msgid, payload, seq = 1, sysid = 255, compid = 190) {
  return Buffer.concat([Buffer.from([0xfe, payload.length, seq, sysid, compid, msgid]), payload, Buffer.from([0,0])]);
}
function missionRequestList() {
  return Buffer.from([1,1,0]);
}
function missionCount(count) {
  const p = Buffer.alloc(5);
  p.writeUInt16LE(count, 0); p[2] = 255; p[3] = 190; p[4] = 0;
  return p;
}
function missionRequestInt(seq) {
  const p = Buffer.alloc(5);
  p.writeUInt16LE(seq, 0); p[2] = 1; p[3] = 1; p[4] = 0;
  return p;
}
function missionItemInt(seq = 0) {
  const p = Buffer.alloc(38);
  p.writeInt32LE(Math.round(31.2304 * 1e7), 16);
  p.writeInt32LE(Math.round(121.4737 * 1e7), 20);
  p.writeFloatLE(100, 24); p.writeUInt16LE(seq, 28); p.writeUInt16LE(16, 30);
  p[32] = 255; p[33] = 190; p[34] = 3; p[36] = 1;
  return p;
}
function missionAck(result = 0) {
  return Buffer.from([255,190,result,0]);
}

test('Batch32 RC4 implementation matches a classic known vector', () => {
  const cipher = rc4Crypt(Buffer.from('Plaintext', 'ascii'), Buffer.from('Key', 'ascii'));
  assert.equal(cipher.toString('hex'), 'bbf316e8d940af0ad3');
});

test('Batch32 generic flag pipeline recovers RC4 when source proves ARC4 use', () => {
  const secret = [1,2,3,4,5,6];
  const raw = Buffer.from(secret);
  const key = crypto.createHash('sha256').update(raw).digest();
  const cipher = rc4Crypt(Buffer.from('flag{rc4_not_aes_2026}', 'utf8'), key);
  const result = recoverFlagFromSecret(secret, {
    files:[
      { name:'task.py', buffer:Buffer.from('from Crypto.Cipher import ARC4\nkey=hashlib.sha256(bytes(secret)).digest()\nARC4.new(key).decrypt(cipher)') },
      { name:'payload.enc', buffer:cipher }
    ]
  });
  assert.equal(result.schema, 'newcyber.secret-flag-recovery.v2');
  assert.equal(result.status, 'flag-recovered');
  assert.equal(result.flag, 'flag{rc4_not_aes_2026}');
  assert.ok(result.hits.some((hit) => hit.algorithm === 'rc4'));
});

test('Batch32 XOR provider continues through Auto Decode to recover Base64-wrapped flag', () => {
  const secret = [10,20,30,40];
  const key = Buffer.from(secret);
  const encoded = Buffer.from(Buffer.from('flag{xor_then_base64}', 'utf8').toString('base64'), 'utf8');
  const cipher = xorRepeating(encoded, key);
  const result = recoverFlagFromSecret(secret, {
    files:[
      { name:'challenge.py', buffer:Buffer.from('out = bytes(c ^ key[i % len(key)] for i,c in enumerate(cipher))') },
      { name:'message.bin.enc', buffer:cipher }
    ]
  });
  assert.equal(result.status, 'flag-recovered');
  assert.equal(result.flag, 'flag{xor_then_base64}');
  const hit = result.hits.find((item) => item.algorithm === 'xor-repeating' && item.flags.includes('flag{xor_then_base64}'));
  assert.ok(hit);
  assert.ok(hit.decodePath.length >= 1);
});

test('Batch32 refuses non-AES provider guessing when no algorithm evidence exists', () => {
  const secret = [1,2,3,4,5,6];
  const key = crypto.createHash('sha256').update(Buffer.from(secret)).digest();
  const cipher = rc4Crypt(Buffer.from('flag{must_not_be_guessed}', 'utf8'), key);
  const hints = inspectCryptoHints('data = open("payload.enc", "rb").read()', {});
  assert.equal(hints.algorithms.includes('rc4'), false);
  const result = recoverFlagFromSecret(secret, { files:[{ name:'payload.enc', buffer:cipher }] });
  assert.notEqual(result.status, 'flag-recovered');
  assert.equal(result.flags.length, 0);
});

test('Batch32 ROS2 graph enumeration stays separate from injection and flooding', () => {
  const text = [
    '$ ros2 topic list -t',
    '/camera/image_raw [sensor_msgs/msg/Image]',
    '/mavros/state [mavros_msgs/msg/State]',
    '$ ros2 node list',
    '/camera_node',
    '/bridge_node'
  ].join('\n');
  const ros = analyzeRos2Evidence(text);
  assert.equal(ros.graphObserved, true);
  assert.equal(ros.roguePublisherCandidate, false);
  assert.equal(ros.floodCandidate, false);
  const result = analyzeUavChallengeEvidence(text, { category:'recon' });
  assert.ok(result.hits.some((hit) => hit.scenarioId === 'ros2-dds-enum'));
  assert.equal(result.hits.some((hit) => hit.scenarioId === 'ros2-rogue-publisher'), false);
});

test('Batch32 ROS2 multi-publisher evidence is only a rogue publisher candidate', () => {
  const text = [
    '$ ros2 topic info -v /cmd_vel',
    'Topic: /cmd_vel',
    'Type: geometry_msgs/msg/Twist',
    'Publisher count: 2',
    'publisher_gid: aa:bb:cc:dd:01',
    'publisher_gid: aa:bb:cc:dd:02'
  ].join('\n');
  const result = analyzeUavChallengeEvidence(text, { category:'inject' });
  const hit = result.hits.find((item) => item.scenarioId === 'ros2-rogue-publisher');
  assert.ok(hit);
  assert.ok(hit.confidence < 0.9);
  assert.match(hit.action, /候选|区分|比较/);
});

test('Batch32 ROS2 camera flood requires availability evidence, not camera topic alone', () => {
  const clean = analyzeUavChallengeEvidence('$ ros2 topic list -t\n/camera/image_raw [sensor_msgs/msg/Image]', { category:'dos' });
  assert.equal(clean.hits.some((hit) => hit.scenarioId === 'ros2-camera-flood'), false);
  const noisy = analyzeUavChallengeEvidence('$ ros2 topic list -t\n/camera/image_raw [sensor_msgs/msg/Image]\nDDS reader queue full; 310 messages lost', { category:'dos' });
  assert.ok(noisy.hits.some((hit) => hit.scenarioId === 'ros2-camera-flood'));
});

test('Batch32 reconstructs MAVLink mission download before surfacing mission extraction', () => {
  const wire = Buffer.concat([
    mav1(43, missionRequestList(), 1, 255, 190),
    mav1(44, missionCount(1), 2, 1, 1),
    mav1(51, missionRequestInt(0), 3, 255, 190),
    mav1(73, missionItemInt(0), 4, 1, 1),
    mav1(47, missionAck(0), 5, 255, 190)
  ]).toString('hex');
  const transfer = analyzeMissionTransfer(wire);
  assert.equal(transfer.sessions.length, 1);
  assert.equal(transfer.sessions[0].requester, '255:190');
  assert.equal(transfer.sessions[0].responder, '1:1');
  assert.equal(transfer.sessions[0].complete, true);
  const result = analyzeUavChallengeEvidence(wire, { category:'leak' });
  assert.ok(result.hits.some((hit) => hit.scenarioId === 'mission-extract' && hit.confidence >= 0.9));
});

test('Batch32 does not reinterpret standalone mission items as mission exfiltration', () => {
  const wire = mav1(73, missionItemInt(0), 1, 255, 190).toString('hex');
  const transfer = analyzeMissionTransfer(wire);
  assert.equal(transfer.sessions.length, 0);
  const result = analyzeUavChallengeEvidence(wire, { category:'leak' });
  assert.equal(result.hits.some((hit) => hit.scenarioId === 'mission-extract'), false);
});

test('Batch32 role profiling uses combined evidence and exposes DVD only as provenance', () => {
  const weak = analyzeRoleEvidence('22/tcp open ssh');
  assert.equal(weak.companion.candidate, false);
  const combined = analyzeUavChallengeEvidence('mavlink-router listening udp 14560\nRTSP camera stream rtsp://10.0.0.3/live\nQGroundControl connected to udp:14550', { category:'recon' });
  assert.ok(combined.hits.some((hit) => hit.scenarioId === 'companion-discovery'));
  assert.ok(combined.hits.some((hit) => hit.scenarioId === 'gcs-discovery'));
  assert.equal(combined.scenarioBasis[0].id, DVD_REFERENCE.id);
  assert.match(combined.scenarioBasis[0].note, /reference/);
  const catalog = getScenarioCatalog();
  assert.ok(catalog.some((row) => row.id === 'ros2-dds-enum' && row.provenance === DVD_REFERENCE.id));
  const routed = runTool('uav-recon-analyze', { input:'ros2 topic list -t\n/camera/image_raw [sensor_msgs/msg/Image]' });
  assert.ok(routed.hits.some((hit) => hit.scenarioId === 'ros2-dds-enum'));
});
