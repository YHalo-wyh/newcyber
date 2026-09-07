const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeFirmwareBuffer } = require('../src/core/firmware_workbench');
const { runTool } = require('../src/core/tool_router');

function mav1(msgid, payload, seq = 1, sysid = 255, compid = 190) {
  return Buffer.concat([
    Buffer.from([0xfe, payload.length, seq, sysid, compid, msgid]),
    payload,
    Buffer.from([0, 0])
  ]);
}

test('firmware workbench surfaces credential, service and update-chain evidence without executing image', () => {
  const rootfs = Buffer.alloc(256, 0);
  Buffer.from('hsqs').copy(rootfs, 0);
  rootfs.writeUInt32LE(4, 4);
  rootfs.writeUInt32LE(131072, 12);
  rootfs.writeBigUInt64LE(256n, 40);
  Buffer.from('/etc/init.d/dropbear\0password=admin123\0mavlink_signing_key=001122\0verify_signature AES firmware upgrade\0', 'ascii').copy(rootfs, 96);

  const result = analyzeFirmwareBuffer(rootfs, { tryDecompress: false });
  assert.ok(result.magic.some((x) => x.id === 'squashfs-le'));
  assert.ok((result.clueSummary.credential || 0) >= 1);
  assert.ok((result.clueSummary.service || 0) >= 1);
  assert.ok((result.clueSummary.secret || 0) >= 1);
  assert.ok((result.clueSummary.update || 0) + (result.clueSummary.crypto || 0) >= 1);
  assert.ok(result.nextActions.some((x) => /凭据|密钥/.test(x)));
  assert.ok(result.nextActions.some((x) => /升级|密码学/.test(x)));
});

test('UAV DoS analyzer reconstructs flight-termination command and accepted ACK', () => {
  const cmd = Buffer.alloc(33, 0);
  cmd.writeUInt16LE(185, 28); // MAV_CMD_DO_FLIGHTTERMINATION
  cmd[30] = 1;
  cmd[31] = 1;
  const ack = Buffer.alloc(3, 0);
  ack.writeUInt16LE(185, 0);
  ack[2] = 0; // ACCEPTED
  const wire = Buffer.concat([mav1(76, cmd, 10), mav1(77, ack, 11, 1, 1)]).toString('hex');

  const result = runTool('uav-dos-analyze', { input: wire });
  const hit = result.hits.find((x) => x.scenarioId === 'terminate-flight');
  assert.ok(hit);
  assert.ok(hit.confidence >= 0.9);
  assert.ok(result.controlFlow);
  const chain = result.controlFlow.commands.find((x) => x.command.command === 185);
  assert.ok(chain);
  assert.equal(chain.accepted, true);
});
