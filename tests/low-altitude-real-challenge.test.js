const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeMavlinkAdvanced, MAV_CMD_COMPONENT_ARM_DISARM } = require('../src/core/low_altitude');

function mavlink1(msgid, payload, { seq = 0, sysid = 255, compid = 190 } = {}) {
  const header = Buffer.from([0xfe, payload.length, seq, sysid, compid, msgid]);
  // CRC bytes are placeholders: NewCyber intentionally performs structural/security triage
  // without claiming dialect-specific CRC validity.
  return Buffer.concat([header, payload, Buffer.from([0x00, 0x00])]);
}

function commandLongArmPayload() {
  const payload = Buffer.alloc(33);
  payload.writeFloatLE(1.0, 0); // param1 = arm
  payload.writeUInt16LE(MAV_CMD_COMPONENT_ARM_DISARM, 28);
  payload[30] = 1;
  payload[31] = 0;
  payload[32] = 0;
  return payload;
}

function serialControlPayload(text) {
  const bytes = Buffer.from(text, 'utf8');
  const payload = Buffer.alloc(79);
  payload.writeUInt32LE(57600, 0);
  payload.writeUInt16LE(0, 4);
  payload[6] = 10; // PX4 shell/debug serial device used in public challenge
  payload[7] = 0x05; // REPLY | EXCLUSIVE
  payload[8] = Math.min(bytes.length, 70);
  bytes.copy(payload, 9, 0, payload[8]);
  return payload;
}

// Regression source: SK-CERT CyberGame 2026 / Maverick public writeup.
// The attack chain is ARM via COMMAND_LONG, then SERIAL_CONTROL device 10 to the PX4 shell.
test('低空真题链：ARM → SERIAL_CONTROL(device=10) 标记为高风险控制链', () => {
  const stream = Buffer.concat([
    mavlink1(76, commandLongArmPayload(), { seq: 10 }),
    mavlink1(126, serialControlPayload('cat /flag\n'), { seq: 11 })
  ]).toString('hex');

  const result = analyzeMavlinkAdvanced(stream);
  assert.equal(result.parsedFrames, 2);
  assert.equal(result.securitySummary.armToSerialChain, true);
  assert.ok(result.findings.some((item) => item.id === 'mavlink-arm-disarm'));
  assert.ok(result.findings.some((item) => item.id === 'mavlink-px4-debug-serial' && item.severity === 'high'));
  assert.ok(result.findings.some((item) => item.id === 'mavlink-arm-to-serial-chain' && item.severity === 'high'));
  const serial = result.highRiskEvents.find((item) => item.type === 'SERIAL_CONTROL');
  assert.equal(serial.device, 10);
  assert.equal(serial.dataText, 'cat /flag\n');
});

test('低空负例：普通 HEARTBEAT 不应生成高风险控制链', () => {
  const heartbeat = Buffer.alloc(9);
  heartbeat[8] = 3;
  const result = analyzeMavlinkAdvanced(mavlink1(0, heartbeat, { seq: 1, sysid: 1, compid: 1 }).toString('hex'));
  assert.equal(result.parsedFrames, 1);
  assert.equal(result.securitySummary.armToSerialChain, false);
  assert.equal(result.highRiskEvents.length, 0);
});
