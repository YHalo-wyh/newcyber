const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeFirmwareBuffer } = require('../src/core/firmware_workbench');
const { scanEmbeddedCaptures, analyzeCaptureIntelligence } = require('../src/core/capture_intelligence');

function tcpEthernet(payload, srcPort, dstPort, src=[10,0,0,1], dst=[10,0,0,2]) {
  const packet = Buffer.alloc(14 + 20 + 20 + payload.length, 0);
  packet.writeUInt16BE(0x0800, 12);
  const ip = 14;
  packet[ip] = 0x45;
  packet.writeUInt16BE(20 + 20 + payload.length, ip + 2);
  packet[ip + 8] = 64;
  packet[ip + 9] = 6;
  Buffer.from(src).copy(packet, ip + 12);
  Buffer.from(dst).copy(packet, ip + 16);
  const tcp = ip + 20;
  packet.writeUInt16BE(srcPort, tcp);
  packet.writeUInt16BE(dstPort, tcp + 2);
  packet[tcp + 12] = 0x50;
  payload.copy(packet, tcp + 20);
  return packet;
}

function classicPcap(packets, linkType=1) {
  const records = [];
  for (let index=0; index<packets.length; index+=1) {
    const packet = packets[index];
    const head = Buffer.alloc(16, 0);
    head.writeUInt32LE(index + 1, 0);
    head.writeUInt32LE(packet.length, 8);
    head.writeUInt32LE(packet.length, 12);
    records.push(head, packet);
  }
  const global = Buffer.alloc(24, 0);
  global.writeUInt32LE(0xa1b2c3d4, 0);
  global.writeUInt16LE(2, 4);
  global.writeUInt16LE(4, 6);
  global.writeUInt32LE(65535, 16);
  global.writeUInt32LE(linkType, 20);
  return Buffer.concat([global, ...records]);
}

test('capture intelligence extracts plaintext FTP credentials and RTSP endpoints', () => {
  const ftp = tcpEthernet(Buffer.from('USER pilot\r\nPASS secret123\r\nRETR /logs/001.BIN\r\n'), 40200, 21);
  const rtsp = tcpEthernet(Buffer.from('DESCRIBE rtsp://10.0.0.2/live RTSP/1.0\r\nCSeq: 1\r\n\r\n'), 40201, 554);
  const capture = classicPcap([ftp, rtsp]);
  const result = analyzeCaptureIntelligence(capture);

  assert.equal(result.format, 'PCAP');
  assert.equal(result.packetCount, 2);
  assert.ok(result.network.credentials.some((item) => item.type === 'ftp-user' && item.value === 'pilot'));
  assert.ok(result.network.credentials.some((item) => item.type === 'ftp-password' && item.value === 'secret123'));
  assert.ok(result.network.rtspEndpoints.some((value) => value.includes('rtsp://10.0.0.2/live')));
  assert.ok(result.findings.some((finding) => finding.id === 'capture-plaintext-credentials'));
});

test('firmware workbench carves embedded PCAP and recursively analyzes it', () => {
  const ftp = tcpEthernet(Buffer.from('USER admin\r\nPASS dronepass\r\n'), 41000, 21);
  const capture = classicPcap([ftp]);
  const firmware = Buffer.concat([
    Buffer.from('FIRMWARE-HEADER\0verify_signature\0mavlink\0', 'ascii'),
    Buffer.alloc(37, 0x41),
    capture,
    Buffer.from('TRAILER-DATA', 'ascii')
  ]);

  const result = analyzeFirmwareBuffer(firmware, { tryDecompress:false });
  assert.equal(result.embeddedCaptures.length, 1);
  const carved = result.embeddedCaptures[0];
  assert.equal(carved.format, 'PCAP');
  assert.equal(carved.analysis.packetCount, 1);
  assert.ok(carved.analysis.network.credentials.some((item) => item.value === 'dronepass'));
  assert.ok(carved.artifact);
  assert.ok(result.artifacts.some((artifact) => artifact.metadata?.kind === 'embedded-capture'));
  assert.ok(result.findings.some((finding) => finding.id === 'firmware-embedded-capture-1'));
  assert.ok(result.pipeline.stages.some((stage) => stage.id === 'capture-intelligence' && stage.status === 'done'));
});

test('random PCAP magic without valid packet records is not carved', () => {
  const fake = Buffer.concat([
    Buffer.alloc(40, 0x42),
    Buffer.from('d4c3b2a1', 'hex'),
    Buffer.alloc(20, 0),
    Buffer.alloc(64, 0x43)
  ]);
  assert.deepEqual(scanEmbeddedCaptures(fake), []);
});
