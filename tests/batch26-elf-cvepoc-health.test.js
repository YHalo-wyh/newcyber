const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const { analyzeElfBinary } = require('../src/core/binary_elf_loader');
const basePoc = require('../src/core/poc_reference_index');
const { buildPocIndexFromDirectory, inspectPocIndexHealth } = require('../src/core/poc_reference_index_v2');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

function writeSection64(buffer, shoff, index, values) {
  const off = shoff + index * 64;
  buffer.writeUInt32LE(values.name || 0, off);
  buffer.writeUInt32LE(values.type || 0, off + 4);
  buffer.writeBigUInt64LE(BigInt(values.flags || 0), off + 8);
  buffer.writeBigUInt64LE(BigInt(values.addr || 0), off + 16);
  buffer.writeBigUInt64LE(BigInt(values.offset || 0), off + 24);
  buffer.writeBigUInt64LE(BigInt(values.size || 0), off + 32);
  buffer.writeUInt32LE(values.link || 0, off + 40);
  buffer.writeUInt32LE(values.info || 0, off + 44);
  buffer.writeBigUInt64LE(BigInt(values.align || 1), off + 48);
  buffer.writeBigUInt64LE(BigInt(values.entsize || 0), off + 56);
}

function minimalGoElf64() {
  const shoff = 0x400;
  const buffer = Buffer.alloc(shoff + 5 * 64, 0);
  buffer.set([0x7f,0x45,0x4c,0x46,2,1,1,0], 0);
  buffer.writeUInt16LE(2, 16); // ET_EXEC
  buffer.writeUInt16LE(62, 18); // x86-64
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x401000n, 24);
  buffer.writeBigUInt64LE(BigInt(shoff), 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(5, 60);
  buffer.writeUInt16LE(1, 62);

  const names = Buffer.from('\0.shstrtab\0.data\0.noptrdata\0.gopclntab\0', 'ascii');
  names.copy(buffer, 0x100);
  const nameOf = (name) => names.indexOf(Buffer.from(name, 'ascii'));

  buffer.writeBigUInt64LE(0x5000n, 0x200);
  buffer.writeBigUInt64LE(32n, 0x208);
  buffer.writeBigUInt64LE(32n, 0x210);
  for (let i = 0; i < 32; i += 1) buffer[0x300 + i] = (i * 13 + 7) & 0xff;
  buffer.set([0xfb,0xff,0xff,0xff], 0x340);

  writeSection64(buffer, shoff, 0, {});
  writeSection64(buffer, shoff, 1, { name:nameOf('.shstrtab'), type:3, offset:0x100, size:names.length, align:1 });
  writeSection64(buffer, shoff, 2, { name:nameOf('.data'), type:1, flags:3, addr:0x4000, offset:0x200, size:24, align:8 });
  writeSection64(buffer, shoff, 3, { name:nameOf('.noptrdata'), type:1, flags:2, addr:0x5000, offset:0x300, size:32, align:8 });
  writeSection64(buffer, shoff, 4, { name:nameOf('.gopclntab'), type:1, flags:2, addr:0x6000, offset:0x340, size:4, align:4 });
  return buffer;
}

async function writePoc(rootDir, year, cve, rows) {
  const dir = path.join(rootDir, String(year));
  await fsp.mkdir(dir, { recursive:true });
  await fsp.writeFile(path.join(dir, `${cve}.json`), JSON.stringify(rows, null, 2), 'utf8');
}

const liveShape2026 = [{
  id:1214609049,
  name:'CVE-2026-0006-openapv-poc',
  full_name:'mobilehackinglab/CVE-2026-0006-openapv-poc',
  owner:{ login:'mobilehackinglab', id:125667452 },
  html_url:'https://github.com/mobilehackinglab/CVE-2026-0006-openapv-poc',
  description:'CVE-2026-0006: Heap buffer overflow PoC for libopenapv (Android APV codec) - CVSS 9.8',
  fork:false,
  created_at:'2026-04-18T20:05:22Z',
  updated_at:'2026-09-03T04:43:02Z',
  stargazers_count:14,
  forks_count:6,
  topics:[],
  visibility:'public'
}];

test('Batch26 parses ELF64 directly and recovers Go ptr/len/cap data relation', () => {
  const result = analyzeElfBinary(minimalGoElf64(), 'golden-go.elf');
  assert.equal(result.schema, 'newcyber.binary-data-graph.v2');
  assert.equal(result.source.kind, 'elf');
  assert.equal(result.source.elf.bits, 64);
  assert.equal(result.source.elf.machine, 'x86-64');
  assert.equal(result.source.elf.goLikely, true);
  assert.ok(result.sections.some((section) => section.name === '.data'));
  assert.ok(result.sections.some((section) => section.name === '.noptrdata'));
  assert.ok(result.sections.some((section) => section.name === '.gopclntab'));
  const slice = result.objects.find((object) => object.kind === 'go_slice');
  assert.ok(slice);
  assert.equal(slice.address, '0x4000');
  assert.deepEqual(slice.fields.map((field) => [field.name, field.value]), [
    ['data','0x5000'], ['len',32], ['cap',32]
  ]);
  assert.ok(result.relations.some((relation) => relation.source === slice.id && relation.type === 'POINTS_TO'));
  assert.ok(result.relations.some((relation) => relation.source === slice.id && relation.type === 'LENGTH_OF' && relation.value === 32));
  assert.equal(result.summary.operations, 0);
  assert.match(result.notes.join('\n'), /不会伪造 XOR\/CMP Expression IR/);
});

test('Batch26 rejects non-ELF and truncated section tables instead of guessing', () => {
  assert.throws(() => analyzeElfBinary(Buffer.alloc(80), 'not-elf.bin'), /Magic 不是 ELF/);
  const elf = minimalGoElf64();
  elf.writeBigUInt64LE(0xffffffffffffn, 40);
  assert.throws(() => analyzeElfBinary(elf, 'broken.elf'), /section header #0 越界|读取越界/);
});

test('PoC-in-GitHub current 2026 JSON shape imports and matches exact CVE/product metadata', async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-poc-current-'));
  t.after(() => fsp.rm(dir, { recursive:true, force:true }));
  await writePoc(dir, 2026, 'CVE-2026-0006', liveShape2026);
  const index = await buildPocIndexFromDirectory(dir, { concurrency:2, maxCves:50 });
  assert.equal(index.stats.cves, 1);
  assert.equal(index.stats.availableCves, 1);
  assert.equal(index.stats.truncated, false);
  assert.equal(index.stats.selectionPolicy, 'newest-first');
  assert.equal(index.entries[0].repos[0].fullName, 'mobilehackinglab/CVE-2026-0006-openapv-poc');
  assert.ok(index.entries[0].keywords.includes('libopenapv'));
  const health = inspectPocIndexHealth(index);
  assert.equal(health.state, 'healthy');
  const matched = basePoc.matchPocReferences({ workspaceName:'CVE-2026-0006 libopenapv heap buffer overflow', files:[], findings:[], recommendations:[] }, index);
  assert.equal(matched.indexAvailable, true);
  assert.equal(matched.matches[0].cve, 'CVE-2026-0006');
  assert.equal(matched.matches[0].exactCve, true);
});

test('PoC index budget is explicit and newest-first so current CVEs are not silently dropped', async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-poc-budget-'));
  t.after(() => fsp.rm(dir, { recursive:true, force:true }));
  const row = (cve) => [{ name:`${cve}-poc`, full_name:`demo/${cve}-poc`, html_url:`https://github.com/demo/${cve}-poc`, description:`${cve} demo`, stargazers_count:1, forks_count:0, topics:[] }];
  await writePoc(dir, 2001, 'CVE-2001-0001', row('CVE-2001-0001'));
  await writePoc(dir, 2025, 'CVE-2025-1111', row('CVE-2025-1111'));
  await writePoc(dir, 2026, 'CVE-2026-2222', row('CVE-2026-2222'));
  const index = await buildPocIndexFromDirectory(dir, { maxCves:2, concurrency:2 });
  assert.equal(index.stats.availableCves, 3);
  assert.equal(index.stats.cves, 2);
  assert.equal(index.stats.truncated, true);
  assert.deepEqual(index.entries.map((entry) => entry.cve).sort(), ['CVE-2025-1111','CVE-2026-2222']);
  const health = inspectPocIndexHealth(index);
  assert.equal(health.state, 'partial');
  assert.equal(health.truncated, true);
  assert.match(health.issues.join('\n'), /预算截断/);
});

test('Batch26 Electron and renderer expose direct ELF mode plus PoC index health UI', () => {
  const renderer = read('renderer/binary_data_graph_tools.js');
  const preload = read('preload.js');
  const electron = read('electron_main.js');
  const ipc = read('src/electron/binary_elf_ipc.js');
  const pocHealth = read('renderer/poc_index_health_ui.js');
  const html = read('renderer/toolbox.html');
  assert.doesNotThrow(() => new vm.Script(renderer, { filename:'binary_data_graph_tools.js' }));
  assert.doesNotThrow(() => new vm.Script(pocHealth, { filename:'poc_index_health_ui.js' }));
  for (const token of ['ELF FILE','IDA / GHIDRA LISTING','chooseAndAnalyzeBinary','analyzeDroppedBinary','EXPRESSION IR · NOT LIFTED','SECTIONS / OBJECTS','HEX VIEW','RELATION GRAPH','RECOVERABLE XOR']) assert.match(renderer, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.match(preload, /binary:choose-analyze/);
  assert.match(preload, /webUtils\.getPathForFile/);
  assert.match(ipc, /analyzeElfBinary/);
  assert.match(ipc, /MAX_ELF_BYTES/);
  assert.match(electron, /poc_reference_index_v2/);
  assert.match(electron, /registerBinaryElfIpc/);
  assert.match(pocHealth, /HEALTHY/);
  assert.match(pocHealth, /LEGACY CACHE/);
  assert.match(html, /binary_data_graph_elf\.css/);
  assert.match(html, /poc_index_health_ui\.js/);
  assert.ok(html.indexOf('poc_index_health_ui.js') > html.indexOf('workspace_autopilot.js'));
});
