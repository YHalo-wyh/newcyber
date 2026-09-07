const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { analyzeTelemetryConsistency } = require('../src/core/uav_telemetry');
const { analyzeUavChallengeEvidence } = require('../src/core/uav_challenge_matrix_v2');
const { scanWorkspace, buildMarkdownReport } = require('../src/core/finals_analyzer_batch7');

function mav1(msgid, payload, seq = 1, sysid = 1, compid = 1) {
  return Buffer.concat([
    Buffer.from([0xfe, payload.length, seq, sysid, compid, msgid]),
    payload,
    Buffer.from([0, 0])
  ]);
}

function globalPosition({ timeMs, lat, lon, altM = 100, relAltM = 20, vx = 0, vy = 0, vz = 0, heading = 0 }) {
  const p = Buffer.alloc(28);
  p.writeUInt32LE(timeMs, 0);
  p.writeInt32LE(Math.round(lat * 1e7), 4);
  p.writeInt32LE(Math.round(lon * 1e7), 8);
  p.writeInt32LE(Math.round(altM * 1000), 12);
  p.writeInt32LE(Math.round(relAltM * 1000), 16);
  p.writeInt16LE(Math.round(vx * 100), 20);
  p.writeInt16LE(Math.round(vy * 100), 22);
  p.writeInt16LE(Math.round(vz * 100), 24);
  p.writeUInt16LE(Math.round(heading * 100), 26);
  return p;
}

function gpsRaw({ lat, lon, altM = 100, vel = 0, fix = 3, satellites = 15 }) {
  const p = Buffer.alloc(30);
  p.writeBigUInt64LE(1n, 0);
  p.writeInt32LE(Math.round(lat * 1e7), 8);
  p.writeInt32LE(Math.round(lon * 1e7), 12);
  p.writeInt32LE(Math.round(altM * 1000), 16);
  p.writeUInt16LE(80, 20);
  p.writeUInt16LE(120, 22);
  p.writeUInt16LE(Math.round(vel * 100), 24);
  p.writeUInt16LE(0, 26);
  p[28] = fix;
  p[29] = satellites;
  return p;
}

test('telemetry analyzer flags physically impossible position jump', () => {
  const wire = Buffer.concat([
    mav1(33, globalPosition({ timeMs: 1000, lat: 31.2304, lon: 121.4737, vx: 2 }), 1),
    mav1(33, globalPosition({ timeMs: 2000, lat: 32.2304, lon: 121.4737, vx: 2 }), 2)
  ]).toString('hex');
  const result = analyzeTelemetryConsistency(wire);
  assert.ok(result.anomalies.some((x) => x.id === 'gps-position-jump' && x.severity === 'high'));
  const matrix = analyzeUavChallengeEvidence(wire, { category: 'spoof' });
  assert.ok(matrix.hits.some((x) => x.scenarioId === 'gps-spoof' && x.confidence >= 0.9));
});

test('telemetry analyzer cross-checks GPS_RAW_INT against GLOBAL_POSITION_INT', () => {
  const wire = Buffer.concat([
    mav1(24, gpsRaw({ lat: 31.2304, lon: 121.4737 }), 1),
    mav1(33, globalPosition({ timeMs: 1000, lat: 31.2504, lon: 121.4737 }), 2)
  ]).toString('hex');
  const result = analyzeTelemetryConsistency(wire);
  assert.ok(result.anomalies.some((x) => x.id === 'gps-source-disagreement'));
});

test('batch7 workspace enriches UAV text and firmware structure', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-uav-'));
  try {
    await fs.writeFile(path.join(dir, 'evidence.log'), 'nmap scan\n554/tcp open rtsp\nSSID: Drone_AP WPA2\nUSER pilot\nPASS demo\nRETR /logs/0008.BIN\n');
    const gz = zlib.gzipSync(Buffer.from('rootfs\n/etc/init.d\n'));
    await fs.writeFile(path.join(dir, 'firmware.bin'), Buffer.concat([Buffer.alloc(64, 0x41), gz]));
    const analysis = await scanWorkspace(dir);
    const evidence = analysis.files.find((x) => x.path === 'evidence.log');
    const firmware = analysis.files.find((x) => x.path === 'firmware.bin');
    assert.ok(evidence?.metadata?.uavChallenge?.hits?.length);
    assert.ok(firmware?.metadata?.firmware);
    assert.ok(firmware.metadata.firmware.magic.some((x) => x.id === 'gzip'));
    const report = buildMarkdownReport(analysis);
    assert.match(report, /低空经济攻击面/);
    assert.match(report, /固件：/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
