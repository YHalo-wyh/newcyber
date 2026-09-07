const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseSafetensorsAdvanced,
  parseNpyAdvanced,
  scanPickleOpcodes
} = require('../src/core/model_artifacts');

function makeSafetensors(header, dataHex = '') {
  const headerBytes = Buffer.from(JSON.stringify(header));
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(headerBytes.length), 0);
  return Buffer.concat([prefix, headerBytes, Buffer.from(dataHex, 'hex')]);
}

function makeNpy({ descr = '<f4', shape = [2], fortran = false, payload = Buffer.alloc(8) } = {}) {
  const shapeText = shape.length === 1 ? `${shape[0]},` : shape.join(', ');
  let header = `{'descr': '${descr}', 'fortran_order': ${fortran ? 'True' : 'False'}, 'shape': (${shapeText}), }`;
  const preamble = 10;
  const baseLength = Buffer.byteLength(header, 'latin1') + 1;
  const paddedLength = Math.ceil((preamble + baseLength) / 16) * 16 - preamble;
  header = `${header}${' '.repeat(Math.max(0, paddedLength - baseLength))}\n`;
  const magic = Buffer.from([0x93, 0x4e, 0x55, 0x4d, 0x50, 0x59, 0x01, 0x00]);
  const length = Buffer.alloc(2);
  length.writeUInt16LE(Buffer.byteLength(header, 'latin1'), 0);
  return Buffer.concat([magic, length, Buffer.from(header, 'latin1'), payload]);
}

test('SafeTensors validates shape/dtype bytes and non-overlapping offsets', () => {
  const buffer = makeSafetensors({
    weight: { dtype: 'F32', shape: [2], data_offsets: [0, 8] },
    bias: { dtype: 'I64', shape: [1], data_offsets: [8, 16] }
  }, '00000000000000000000000000000000');
  const result = parseSafetensorsAdvanced(buffer);
  assert.equal(result.valid, true);
  assert.equal(result.tensorCount, 2);
  assert.equal(result.tensors[0].expectedBytes, 8);
  assert.deepEqual(result.overlaps, []);
  assert.equal(result.securityFindings.filter((item) => item.severity === 'high').length, 0);
});

test('SafeTensors rejects overlapping and shape-size-mismatched tensor ranges', () => {
  const buffer = makeSafetensors({
    a: { dtype: 'F32', shape: [2], data_offsets: [0, 4] },
    b: { dtype: 'U8', shape: [8], data_offsets: [2, 10] }
  }, '00000000000000000000');
  const result = parseSafetensorsAdvanced(buffer);
  assert.equal(result.valid, false);
  assert.ok(result.securityFindings.some((item) => item.id === 'tensor-size-mismatch' && item.tensor === 'a'));
  assert.ok(result.securityFindings.some((item) => item.id === 'tensor-data-overlap' && item.tensor === 'b'));
});

test('NPY numeric dtype verifies fixed payload length', () => {
  const result = parseNpyAdvanced(makeNpy({ descr: '<f4', shape: [2], payload: Buffer.alloc(8) }));
  assert.equal(result.valid, true);
  assert.equal(result.objectDtype, false);
  assert.equal(result.expectedPayloadBytes, 8);
  assert.equal(result.payloadBytes, 8);
});

test('NPY object dtype is surfaced as unsafe-to-load pickle semantics', () => {
  const result = parseNpyAdvanced(makeNpy({ descr: '|O8', shape: [1], payload: Buffer.from('pickle-like') }));
  assert.equal(result.objectDtype, true);
  assert.ok(result.securityFindings.some((item) => item.id === 'npy-object-dtype' && item.severity === 'high'));
});

test('pickle GLOBAL os/posix system is high risk without executing pickle', () => {
  const payload = Buffer.concat([
    Buffer.from([0x80, 0x04]),
    Buffer.from('cposix\nsystem\n', 'latin1'),
    Buffer.from([0x2e])
  ]);
  const result = scanPickleOpcodes(payload);
  assert.equal(result.complete, true);
  assert.equal(result.dangerousGlobals[0].qualifiedName, 'posix.system');
  assert.ok(result.securityFindings.some((item) => item.id === 'pickle-dangerous-global'));
});

test('pickle protocol4 STACK_GLOBAL resolves normal torch global without false high severity', () => {
  const module = Buffer.from('torch._utils');
  const name = Buffer.from('_rebuild_tensor_v2');
  const payload = Buffer.concat([
    Buffer.from([0x80, 0x04, 0x8c, module.length]), module,
    Buffer.from([0x94, 0x8c, name.length]), name,
    Buffer.from([0x94, 0x93, 0x2e])
  ]);
  const result = scanPickleOpcodes(payload);
  assert.equal(result.complete, true);
  assert.equal(result.globals[0].qualifiedName, 'torch._utils._rebuild_tensor_v2');
  assert.equal(result.globals[0].severity, 'info');
  assert.equal(result.dangerousGlobals.length, 0);
});
