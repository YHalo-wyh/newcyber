const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { autoDecode, decodeAscii85 } = require('../src/core/auto_decode');
const { extractSuspiciousEncodings, detectEncodingKinds } = require('../src/core/encoding_probe');
const { createBinaryArtifact } = require('../src/core/artifacts');
const { analyzeArtifactTree } = require('../src/core/recursive_artifact_analysis');
const { scanWorkspace } = require('../src/core/finals_analyzer_batch16');

function ethernetUdp(payload, srcPort = 10000, dstPort = 10001) {
  const eth = Buffer.alloc(14, 0); eth.writeUInt16BE(0x0800, 12);
  const ip = Buffer.alloc(20, 0); ip[0] = 0x45; ip.writeUInt16BE(20 + 8 + payload.length, 2); ip[8] = 64; ip[9] = 17;
  ip.set([10,0,0,1], 12); ip.set([10,0,0,2], 16);
  const udp = Buffer.alloc(8, 0); udp.writeUInt16BE(srcPort, 0); udp.writeUInt16BE(dstPort, 2); udp.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([eth, ip, udp, payload]);
}

function pcap(packets) {
  const header = Buffer.alloc(24, 0);
  header.writeUInt32LE(0xa1b2c3d4, 0); header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6); header.writeUInt32LE(65535, 16); header.writeUInt32LE(1, 20);
  const records = [];
  packets.forEach((packet, index) => {
    const rh = Buffer.alloc(16, 0); rh.writeUInt32LE(100 + index, 0); rh.writeUInt32LE(packet.length, 8); rh.writeUInt32LE(packet.length, 12);
    records.push(rh, packet);
  });
  return Buffer.concat([header, ...records]);
}

test('encoding probe prioritizes strong CTF signatures and decodes new low-cost codecs', () => {
  const qp = '=66=6c=61=67=7b=71=70=7d';
  const jwt = 'eyJhbGciOiJub25lIn0.eyJmbGFnIjoiZmxhZ3tqd3R9In0.';
  const text = `mail=${qp}\ntoken=${jwt}\nmorse="..-. .-.. .- --."`;
  const hits = extractSuspiciousEncodings(text);
  assert.ok(hits.some((x) => x.kind === 'quoted-printable'));
  assert.ok(hits.some((x) => x.kind === 'jwt'));
  assert.ok(hits.some((x) => x.kind === 'morse'));
  assert.equal(detectEncodingKinds(qp)[0].kind, 'quoted-printable');
  assert.equal(autoDecode(qp, { profile:'fast', maxDepth:2 }).foundFlag, 'flag{qp}');
  assert.equal(autoDecode(jwt, { profile:'fast', maxDepth:2 }).foundFlag, 'flag{jwt}');
  assert.equal(decodeAscii85('87cURD_*#TDfTZ)+T').toString('utf8'), 'Hello, world!');
});

test('recursive artifact analysis decodes suspicious text inside a recovered artifact', () => {
  const seed = createBinaryArtifact({
    name:'stage1.txt',
    buffer:Buffer.from('payload==66=6c=61=67=7b=72=65=63=75=72=73=69=76=65=7d', 'utf8'),
    mediaType:'text/plain',
    completeness:'complete',
    provenance:[{source:'test'}]
  });
  const result = analyzeArtifactTree([seed], { maxDepth:2 });
  assert.ok(result.flags.includes('flag{recursive}'));
  assert.ok(result.findings.some((x) => x.id.startsWith('recursive-decoded-flag:')));
  assert.equal(result.stats.analyzedNodes, 1);
});

test('batch16 automatically turns encoded PCAP into a recursively analyzed capture', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-recursive-'));
  try {
    const capture = pcap([ethernetUdp(Buffer.from('hello-from-capture'))]);
    await fsp.writeFile(path.join(dir, 'clue.txt'), `blob=${capture.toString('base64')}\n`, 'utf8');
    const analysis = await scanWorkspace(dir);
    const file = analysis.files.find((x) => x.path === 'clue.txt');
    assert.ok(file?.metadata?.autoDecode?.candidates?.some((x) => x.magic === 'PCAP'));
    assert.ok(file?.metadata?.recursiveArtifacts?.nodes?.some((x) => x.capture?.format === 'PCAP'));
    assert.ok(file?.metadata?.recursiveArtifacts?.artifacts?.some((x) => x.metadata?.magic === 'PCAP'));
    assert.ok(analysis.autopilot?.automaticChecks?.some((x) => x.id === 'recursive-artifact'));
    assert.ok(analysis.batch16Counts?.captures >= 1);
    assert.ok(Number(analysis.version) >= 16);
  } finally {
    await fsp.rm(dir, { recursive:true, force:true });
  }
});
