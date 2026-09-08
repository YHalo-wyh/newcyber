const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { buildPocIndexFromDirectory, matchPocReferences } = require('../src/core/poc_reference_index');
const { analyzeTcpReassembly } = require('../src/core/tcp_reassembly');
const { analyzeCaptureIntelligence } = require('../src/core/capture_intelligence_v2');
const { createBinaryArtifact } = require('../src/core/artifacts');
const { analyzeArtifactTree } = require('../src/core/recursive_artifact_analysis');
const { scanWorkspace } = require('../src/core/finals_analyzer_batch17');

function ethernetTcp(payload, seq, srcPort = 50000, dstPort = 80) {
  const eth = Buffer.alloc(14, 0); eth.writeUInt16BE(0x0800, 12);
  const ip = Buffer.alloc(20, 0); ip[0] = 0x45; ip.writeUInt16BE(20 + 20 + payload.length, 2); ip[8] = 64; ip[9] = 6;
  ip.set([10,0,0,1], 12); ip.set([10,0,0,2], 16);
  const tcp = Buffer.alloc(20, 0); tcp.writeUInt16BE(srcPort, 0); tcp.writeUInt16BE(dstPort, 2); tcp.writeUInt32BE(seq >>> 0, 4); tcp[12] = 0x50; tcp[13] = 0x18;
  return Buffer.concat([eth, ip, tcp, payload]);
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

function tarOctal(value, width) {
  return Buffer.from(`${value.toString(8).padStart(width - 1, '0')}\0`, 'ascii');
}

function tarArchive(name, data) {
  const header = Buffer.alloc(512, 0);
  Buffer.from(name, 'utf8').copy(header, 0, 0, 100);
  tarOctal(0o644, 8).copy(header, 100);
  tarOctal(0, 8).copy(header, 108);
  tarOctal(0, 8).copy(header, 116);
  tarOctal(data.length, 12).copy(header, 124);
  tarOctal(0, 12).copy(header, 136);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  Buffer.from('ustar\0', 'ascii').copy(header, 257);
  Buffer.from('00', 'ascii').copy(header, 263);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const checksumText = `${checksum.toString(8).padStart(6, '0')}\0 `;
  Buffer.from(checksumText, 'ascii').copy(header, 148);
  const padding = Buffer.alloc((512 - (data.length % 512)) % 512, 0);
  return Buffer.concat([header, data, padding, Buffer.alloc(1024, 0)]);
}

test('PoC-in-GitHub local metadata index supports keyword and exact CVE matching', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-poc-index-'));
  try {
    await fs.mkdir(path.join(root, '2021'));
    await fs.writeFile(path.join(root, '2021', 'CVE-2021-44228.json'), JSON.stringify([
      { name:'CVE-2021-44228-Apache-Log4j-Rce', full_name:'example/log4shell', html_url:'https://github.com/example/log4shell', description:'Apache Log4j remote code execution', stargazers_count:200, forks_count:20, topics:['log4j','rce'] }
    ]));
    const index = await buildPocIndexFromDirectory(root);
    assert.equal(index.stats.cves, 1);
    const keyword = matchPocReferences({ workspaceName:'log4j service', files:[{path:'server.log',name:'server.log',type:'文本',findings:[{title:'Remote code execution in Apache Log4j',evidence:'JNDI log4j'}],metadata:{}}], findings:[], recommendations:[] }, index);
    assert.equal(keyword.matches[0].cve, 'CVE-2021-44228');
    assert.ok(keyword.matches[0].matchedKeywords.includes('log4j'));
    const exact = matchPocReferences({ workspaceName:'CVE-2021-44228', files:[], findings:[], recommendations:[] }, null);
    assert.equal(exact.matches[0].cve, 'CVE-2021-44228');
    assert.equal(exact.matches[0].metadataPending, true);
  } finally { await fs.rm(root, { recursive:true, force:true }); }
});

test('Batch17 reads bounded challenge text and filters relevant PoC metadata', async () => {
  const corpus = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-poc-corpus-'));
  const challenge = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-poc-challenge-'));
  try {
    await fs.mkdir(path.join(corpus, '2021'));
    await fs.writeFile(path.join(corpus, '2021', 'CVE-2021-44228.json'), JSON.stringify([
      { name:'log4shell', full_name:'example/log4shell', html_url:'https://github.com/example/log4shell', description:'Apache Log4j remote code execution via JNDI lookup', stargazers_count:100 }
    ]));
    const index = await buildPocIndexFromDirectory(corpus);
    await fs.writeFile(path.join(challenge, 'README.txt'), 'Target stack: Apache Log4j. The challenge hints at remote code execution through a JNDI lookup.');
    const analysis = await scanWorkspace(challenge, { pocIndex:index });
    assert.ok(analysis.version >= 17);
    assert.equal(analysis.pocReferences.indexAvailable, true);
    assert.equal(analysis.pocReferences.matches[0].cve, 'CVE-2021-44228');
  } finally {
    await fs.rm(corpus, { recursive:true, force:true });
    await fs.rm(challenge, { recursive:true, force:true });
  }
});

test('TCP reassembly restores HTTP and FTP evidence split across packets', () => {
  const packets = [];
  let seq = 1000;
  const httpChunks = ['GET /api/fl', 'ag HTTP/1.1\r\nHo', 'st: drone.local\r\n\r\n'];
  for (const chunk of httpChunks) {
    const data = Buffer.from(chunk, 'ascii'); packets.push({ linkType:1, data:ethernetTcp(data, seq, 50000, 80), index:packets.length + 1 }); seq += data.length;
  }
  seq = 9000;
  const ftpChunks = ['US', 'ER admin\r\nPA', 'SS secret\r\n'];
  for (const chunk of ftpChunks) {
    const data = Buffer.from(chunk, 'ascii'); packets.push({ linkType:1, data:ethernetTcp(data, seq, 51000, 21), index:packets.length + 1 }); seq += data.length;
  }
  const result = analyzeTcpReassembly(packets);
  assert.ok(result.httpRequests.some((x) => x.path === '/api/flag' && x.host === 'drone.local'));
  assert.ok(result.credentials.some((x) => x.type === 'ftp-user' && x.value === 'admin'));
  assert.ok(result.credentials.some((x) => x.type === 'ftp-password' && x.value === 'secret'));
  assert.equal(result.stats.gaps, 0);

  const capture = analyzeCaptureIntelligence(pcap(packets.map((x) => x.data)));
  assert.ok(capture.network.httpRequests.some((x) => x.path === '/api/flag'));
  assert.ok(capture.network.credentials.some((x) => x.value === 'secret'));
  assert.ok(capture.network.tcpReassembly.stats.streams >= 2);
});

test('TAR artifact is checksum-validated, safely expanded and recursively decoded', () => {
  const encoded = Buffer.from('payload==66=6c=61=67=7b=74=61=72=5f=63=68=61=69=6e=7d', 'utf8');
  const archive = tarArchive('nested/clue.txt', encoded);
  const seed = createBinaryArtifact({ name:'bundle.tar', buffer:archive, completeness:'complete', provenance:[{source:'test'}] });
  const tree = analyzeArtifactTree([seed], { maxDepth:2, maxNodes:12 });
  assert.ok(tree.nodes.some((node) => node.tar?.extracted?.some((entry) => entry.name === 'nested/clue.txt')));
  assert.ok(tree.flags.includes('flag{tar_chain}'));
  assert.ok(tree.findings.some((finding) => finding.id.startsWith('recursive-tar:')));
});
