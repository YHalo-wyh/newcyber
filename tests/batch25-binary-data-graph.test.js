const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { analyzeBinaryDataListing } = require('../src/core/binary_data_graph');
const { runTool } = require('../src/core/tool_router');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

function address(value) {
  return Number(value).toString(16).padStart(16, '0').toUpperCase();
}

function dbLines(section, start, label, bytes, chunk = 8) {
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    const values = bytes.slice(offset, offset + chunk).map((value) => `${value.toString(16).padStart(2, '0')}h`).join(', ');
    lines.push(`${section}:${address(start + offset)} ${offset === 0 ? `${label} ` : ''}db ${values}`);
  }
  return lines;
}

function goldenListing() {
  const checksum = [...Buffer.from('COMPAT-CHECKSUM-V1-0123456789ABC', 'ascii')];
  assert.equal(checksum.length, 32);
  const encoded = [
    0x25,0x23,0x2c,0x37,0x3a,0x22,0x1c,0x2d,
    0x3c,0x71,0x24,0x78,0x0c,0x25,0x79,0x59,
    0x3e,0x6e,0x46,0x03,0x02,0x42,0x6c,0x5b,
    0x40,0x42,0x68,0x48,0x55,0x74,0x31,0x3e
  ];
  const array = checksum.map((value, index) => value ^ encoded[index]);
  return [
    `.rodata:${address(0x501000)} aCompatChecksum db 'COMPAT-CHECKSUM-V1-0123456789ABC'`,
    `.data:${address(0x54fae0)} off_54FAE0 dq offset byte_54A3E0 ; DATA XREF: main_main+FF↑r`,
    `.data:${address(0x54fae8)} dq 20h`,
    `.data:${address(0x54faf0)} dq 20h`,
    ...dbLines('.noptrdata', 0x54a3e0, 'byte_54A3E0', encoded),
    ...dbLines('.noptrdata', 0x54a420, 'array', array),
    `.text:${address(0x401000)} main_main proc near`,
    `.text:${address(0x401010)} lea rbx, byte_54A3E0`,
    `.text:${address(0x401017)} lea rsi, array`,
    `.text:${address(0x40101e)} lea rdi, aCompatChecksum`,
    `.text:${address(0x401025)} movzx eax, byte ptr [rbx+rcx]`,
    `.text:${address(0x401029)} movzx edx, byte ptr [rsi+rcx]`,
    `.text:${address(0x40102d)} xor eax, edx`,
    `.text:${address(0x40102f)} movzx edx, byte ptr [rdi+rcx]`,
    `.text:${address(0x401033)} cmp dl, al`,
    `.text:${address(0x401035)} jne short loc_fail`
  ].join('\n');
}

test('golden reverse sample restores object pointer Go slice XOR and compare relations', () => {
  const result = analyzeBinaryDataListing(goldenListing());
  assert.equal(result.schema, 'newcyber.binary-data-graph.v1');
  assert.ok(result.summary.sections >= 4);

  const byName = new Map(result.objects.map((object) => [object.name, object]));
  const checksum = byName.get('aCompatChecksum');
  const slice = byName.get('off_54FAE0');
  const encoded = byName.get('byte_54A3E0');
  const array = byName.get('array');
  assert.ok(checksum && slice && encoded && array);
  assert.equal(checksum.kind, 'string');
  assert.equal(checksum.size, 32);
  assert.equal(slice.kind, 'go_slice');
  assert.equal(slice.structuralName, 'byteSlice_54fae0');
  assert.deepEqual(slice.fields.map((field) => [field.name, field.value]), [
    ['data', '0x54a3e0'], ['len', 32], ['cap', 32]
  ]);
  assert.equal(encoded.bytesHex.startsWith('25 23 2c 37'), true);

  assert.ok(result.relations.some((relation) => relation.source === slice.id && relation.target === encoded.id && relation.type === 'POINTS_TO'));
  assert.ok(result.relations.some((relation) => relation.type === 'XORS_WITH' && new Set([relation.source, relation.target]).has(encoded.id) && new Set([relation.source, relation.target]).has(array.id)));
  assert.ok(result.relations.some((relation) => relation.source === checksum.id && relation.type === 'COMPARES_WITH'));
  assert.ok(result.relations.some((relation) => relation.source === 'fn_main_main' && relation.target === slice.id && relation.type === 'READS'));

  const compare = result.operations.find((operation) => operation.op === 'CMP_NE');
  assert.ok(compare);
  assert.match(compare.pseudo, /aCompatChecksum\[rcx\].*!=.*byte_54A3E0\[rcx\].*\^.*array\[rcx\]/);
});

test('XOR validation becomes a recoverable relation and verifies known bytes', () => {
  const result = analyzeBinaryDataListing(goldenListing());
  assert.equal(result.recoverableRelations.length, 1);
  const recoverable = result.recoverableRelations[0];
  assert.match(recoverable.equation, /aCompatChecksum\[rcx\] = byte_54A3E0\[rcx\] XOR array\[rcx\]/);
  assert.equal(recoverable.derivations.length, 3);
  assert.equal(recoverable.verification.checkedBytes, 32);
  assert.equal(recoverable.verification.mismatches, 0);
  assert.equal(recoverable.verification.holdsForKnownBytes, true);
  assert.equal(recoverable.verification.derivedOperandName, 'array');
});

test('semantic layer uses operation evidence and does not label an unused byte table as ciphertext', () => {
  const result = analyzeBinaryDataListing(goldenListing());
  const candidate = result.semanticCandidates.find((item) => item.objectName === 'byte_54A3E0');
  assert.ok(candidate);
  assert.ok(candidate.score >= 70);
  assert.ok(candidate.evidence.some((item) => /XOR/.test(item)));
  assert.ok(candidate.evidence.some((item) => /CMP/.test(item)));

  const negative = analyzeBinaryDataListing([
    `.rodata:${address(0x600000)} indexTable db 00h, 01h, 02h, 03h, 04h, 05h, 06h, 07h`,
    `.text:${address(0x401000)} safe_func proc near`,
    `.text:${address(0x401010)} mov eax, 1`
  ].join('\n'));
  assert.equal(negative.semanticCandidates.some((item) => item.objectName === 'indexTable'), false);
});

test('tool router exposes the deterministic Binary Data Graph analyzer', () => {
  const result = runTool('binary-data-graph', { input: goldenListing() });
  assert.equal(result.schema, 'newcyber.binary-data-graph.v1');
  assert.ok(result.summary.importantRelations >= 4);
  assert.match(result.notes.join('\n'), /textual disassembly\/listing/);
});

test('Binary Data Graph UI is a dedicated three-pane reverse workbench with Hex and operation evidence', () => {
  const source = read('renderer/binary_data_graph_tools.js');
  const css = read('renderer/styles/binary_data_graph.css');
  const html = read('renderer/toolbox.html');
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/binary_data_graph_tools.js' }));
  for (const token of ['Binary Data Graph','SECTIONS / OBJECTS','HEX VIEW','RELATION GRAPH','EXPRESSION IR','RECOVERABLE XOR','data-bdg-object']) assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(css, /grid-template-columns:220px minmax\(0,1fr\) 330px/);
  assert.match(css, /\.bdg-hex-row/);
  assert.match(html, /styles\/binary_data_graph\.css/);
  assert.match(html, /binary_data_graph_tools\.js/);
  assert.ok(html.indexOf('binary_data_graph_tools.js') > html.indexOf('tool_ui.js'));
  assert.ok(html.indexOf('binary_data_graph_tools.js') < html.indexOf('workspace_three_pane.js'));
});
