const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { analyzeIdaSnapshot, buildListing } = require('../src/core/ida_snapshot_graph');
const { decodeRipRelative, scanX86_64DataRefs } = require('../src/core/x86_64_data_refs');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const hx = (n) => `0x${n.toString(16)}`;

function dataItem(address, segment, name, disasm, bytesHex, xrefsTo = []) {
  return { address:hx(address), segment, kind:'data', name, size:bytesHex ? bytesHex.trim().split(/\s+/).length : 8, disasm, bytesHex, bytesPreviewSize:8, bytesTruncated:false, xrefsFrom:[], xrefsTo, comments:[] };
}
function codeItem(address, disasm, mnemonic, operands, xrefsFrom = []) {
  return { address:hx(address), segment:'.text', kind:'code', name:'', size:3, disasm, bytesHex:'90', bytesPreviewSize:1, bytesTruncated:false, xrefsFrom, xrefsTo:[], comments:[], mnemonic, operands, function:'main_main', functionStart:'0x401000' };
}

function goldenSnapshot() {
  const checksum = [...Buffer.from('CHECKSUM', 'ascii')];
  const left = [0x25,0x23,0x2c,0x37,0x3a,0x22,0x11,0x09];
  const right = checksum.map((value, index) => value ^ left[index]);
  const db = (name, bytes) => `${name} db ${bytes.map((v) => `${v.toString(16)}h`).join(', ')}`;
  return {
    schema:'newcyber.ida-snapshot.v1', exporterVersion:'0.1', exportedAt:'2026-09-09T00:00:00Z',
    ida:{ version:'9.2', processor:'metapc', bitness:64, imageBase:'0x400000', inputFile:'golden', inputPath:'C:/ctf/golden', inputMd5:'0123456789abcdef' },
    limits:{ headsTruncated:false, listingTruncated:false, functionsTruncated:false, previewBudgetExhausted:false },
    segments:[
      {name:'.text',start:'0x401000',end:'0x402000',size:0x1000,permissions:{read:true,write:false,execute:true}},
      {name:'.rodata',start:'0x500000',end:'0x501000',size:0x1000,permissions:{read:true,write:false,execute:false}},
      {name:'.noptrdata',start:'0x510000',end:'0x511000',size:0x1000,permissions:{read:true,write:true,execute:false}},
      {name:'.data',start:'0x520000',end:'0x521000',size:0x1000,permissions:{read:true,write:true,execute:false}}
    ],
    functions:[{name:'main_main',start:'0x401000',end:'0x401080',size:0x80}],
    items:[
      dataItem(0x500000,'.rodata','aCompatChecksum',db('aCompatChecksum',checksum),checksum.map(v=>v.toString(16).padStart(2,'0')).join(' '),[{from:'0x401015',to:'0x500000',type:1,isCode:true}]),
      dataItem(0x510000,'.noptrdata','byte_510000',db('byte_510000',left),left.map(v=>v.toString(16).padStart(2,'0')).join(' '),[{from:'0x401006',to:'0x510000',type:1,isCode:true}]),
      dataItem(0x520000,'.data','array',db('array',right),right.map(v=>v.toString(16).padStart(2,'0')).join(' ',),[{from:'0x40100c',to:'0x520000',type:1,isCode:true}]),
      codeItem(0x401000,'lea rax, aCompatChecksum','lea',['rax','aCompatChecksum'],[{from:'0x401000',to:'0x500000',type:1,isCode:true}]),
      codeItem(0x401006,'lea rbx, byte_510000','lea',['rbx','byte_510000'],[{from:'0x401006',to:'0x510000',type:1,isCode:true}]),
      codeItem(0x40100c,'lea rdx, array','lea',['rdx','array'],[{from:'0x40100c',to:'0x520000',type:1,isCode:true}]),
      codeItem(0x401012,'movzx ecx, byte ptr [rbx+rsi]','movzx',['ecx','byte ptr [rbx+rsi]']),
      codeItem(0x401016,'movzx edi, byte ptr [rdx+rsi]','movzx',['edi','byte ptr [rdx+rsi]']),
      codeItem(0x40101a,'xor ecx, edi','xor',['ecx','edi']),
      codeItem(0x40101d,'cmp cl, byte ptr [rax+rsi]','cmp',['cl','byte ptr [rax+rsi]']),
      codeItem(0x401021,'jne short loc_fail','jne',['short loc_fail'])
    ]
  };
}

test('Batch27 IDA Snapshot reuses Binary Data Graph and keeps structured XREF facts', () => {
  const snapshot = goldenSnapshot();
  const listing = buildListing(snapshot);
  assert.match(listing.text, /aCompatChecksum db/);
  assert.match(listing.text, /main_main proc near/);
  const result = analyzeIdaSnapshot(snapshot);
  assert.equal(result.source.kind, 'ida-snapshot');
  assert.equal(result.source.ida.processor, 'metapc');
  assert.equal(result.summary.functions, 1);
  assert.ok(result.summary.structuredXrefs >= 3);
  assert.ok(result.objects.some((object) => object.name === 'byte_510000'));
  assert.ok(result.operations.some((operation) => operation.op === 'XOR'));
  assert.ok(result.operations.some((operation) => operation.op === 'CMP_NE'));
  assert.ok(result.relations.some((relation) => relation.type === 'XORS_WITH'));
  assert.ok(result.relations.some((relation) => relation.type === 'COMPARES_WITH'));
  assert.ok(result.relations.some((relation) => relation.type === 'READS' && relation.confidence === 0.99));
  assert.equal(result.recoverableRelations.length, 1);
  assert.equal(result.recoverableRelations[0].verification.holdsForKnownBytes, true);
  assert.equal(result.recoverableRelations[0].verification.mismatches, 0);
});

test('Batch27 standalone x86-64 scanner recovers RIP-relative code to object refs without IDA', () => {
  const base = 0x401000n;
  const target = 0x402000n;
  const code = Buffer.alloc(32, 0x90);
  // 48 8D 05 disp32 => lea rax,[rip+disp32]
  code.set([0x48,0x8d,0x05], 0);
  code.writeInt32LE(Number(target - (base + 7n)), 3);
  // 0F B6 05 disp32 => movzx eax,byte ptr [rip+disp32]
  code.set([0x0f,0xb6,0x05], 8);
  code.writeInt32LE(Number(target - (base + 15n)), 11);
  const sections = [{name:'.text',address:hx(Number(base)),fileOffset:'0x0',size:code.length,executable:true,fileBacked:true,truncated:false}];
  const objects = [{id:'obj_secret',name:'secret_table',address:hx(Number(target)),size:32,section:'.rodata'}];
  const result = scanX86_64DataRefs(code, sections, objects);
  assert.equal(result.relations.length, 2);
  assert.ok(result.relations.some((relation) => relation.type === 'TAKES_ADDRESS' && relation.target === 'obj_secret'));
  assert.ok(result.relations.some((relation) => relation.type === 'READS' && relation.target === 'obj_secret'));
  assert.deepEqual(result.operations.map((op) => op.op), ['LEA','MOVZX']);
});

test('x86 RIP-relative decoder is conservative about ModRM addressing', () => {
  const good = Buffer.from([0x48,0x8d,0x05,0x10,0,0,0]);
  assert.equal(decodeRipRelative(good,0,true).mnemonic,'LEA');
  const registerAddressing = Buffer.from([0x48,0x8d,0x00,0x10,0,0,0]);
  assert.equal(decodeRipRelative(registerAddressing,0,true),null);
  const random = Buffer.from([0x90,0x90,0x90,0x90,0x90]);
  assert.equal(decodeRipRelative(random,0,true),null);
});

test('Batch27 IDA plugin/exporter and dedicated renderer are wired', () => {
  const plugin = read('ida/newcyber_ida_bridge.py');
  const renderer = read('renderer/ida_bridge_tools.js');
  const preload = read('preload.js');
  const electron = read('electron_main.js');
  const html = read('renderer/toolbox.html');
  assert.match(plugin, /newcyber\.ida-snapshot\.v1/);
  assert.match(plugin, /Ctrl-Alt-N/);
  assert.match(plugin, /XrefsFrom/);
  assert.match(plugin, /XrefsTo/);
  assert.match(plugin, /get_bytes/);
  assert.doesNotThrow(() => new vm.Script(renderer, {filename:'ida_bridge_tools.js'}));
  for (const token of ['IDA Bridge','OFFLINE BRIDGE','FUNCTIONS','DATA OBJECTS','RELATIONS / XREF','EXPRESSION IR','RECOVERABLE']) assert.match(renderer,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.match(preload,/ida:choose-analyze/);
  assert.match(preload,/ida:analyze-dropped/);
  assert.match(electron,/registerIdaSnapshotIpc/);
  assert.match(html,/ida_bridge\.css/);
  assert.match(html,/ida_bridge_tools\.js/);
  assert.ok(html.indexOf('ida_bridge_tools.js') > html.indexOf('binary_data_graph_tools.js'));
});
