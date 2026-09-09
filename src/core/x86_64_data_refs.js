'use strict';

const MAX_CODE_SCAN_BYTES = 12 * 1024 * 1024;
const MAX_REFS = 12000;

const SIMPLE = new Map([
  [0x8d, 'LEA'], [0x8b, 'MOV'], [0x8a, 'MOV'],
  [0x33, 'XOR'], [0x32, 'XOR'], [0x3b, 'CMP'], [0x3a, 'CMP'],
  [0x03, 'ADD'], [0x02, 'ADD'], [0x2b, 'SUB'], [0x2a, 'SUB']
]);

function safeNumber(value) {
  const big = typeof value === 'bigint' ? value : BigInt(value || 0);
  if (big < 0n || big > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(big);
}
function hex(value) { return `0x${BigInt(value).toString(16)}`; }
function objectContains(object, ea) {
  try {
    const start = BigInt(object.address);
    return ea >= start && ea < start + BigInt(Math.max(1, Number(object.size) || 1));
  } catch { return false; }
}
function functionFor(functions, ea) {
  return functions.find((fn) => ea >= fn.value && ea < fn.value + fn.size) || null;
}
function sourceId(fn, ea) {
  if (!fn) return `addr_${ea.toString(16)}`;
  return `fn_${String(fn.name || hex(fn.value)).replace(/[^A-Za-z0-9_.$?@-]/g, '_')}`;
}
function signed32(bytes, offset, little) {
  if (offset < 0 || offset + 4 > bytes.length) return null;
  return little ? bytes.readInt32LE(offset) : bytes.readInt32BE(offset);
}

function decodeRipRelative(bytes, offset, little) {
  let p = offset;
  let rex = null;
  if (p < bytes.length && bytes[p] >= 0x40 && bytes[p] <= 0x4f) { rex = bytes[p]; p += 1; }
  if (p >= bytes.length) return null;
  let opcode = bytes[p++];
  let mnemonic = SIMPLE.get(opcode) || null;
  let width = (rex && (rex & 0x08)) ? 64 : 32;
  let immediateBytes = 0;
  if (opcode === 0x0f) {
    if (p >= bytes.length) return null;
    const op2 = bytes[p++];
    if (op2 === 0xb6) { mnemonic = 'MOVZX'; width = 8; }
    else if (op2 === 0xb7) { mnemonic = 'MOVZX'; width = 16; }
    else return null;
  } else if (opcode === 0x80 || opcode === 0x81 || opcode === 0x83) {
    mnemonic = 'GROUP';
    immediateBytes = opcode === 0x81 ? 4 : 1;
  } else if (!mnemonic) return null;
  if (p >= bytes.length) return null;
  const modrm = bytes[p++];
  const mod = modrm >> 6;
  const reg = (modrm >> 3) & 7;
  const rm = modrm & 7;
  if (mod !== 0 || rm !== 5) return null;
  if (mnemonic === 'GROUP') {
    mnemonic = ({0:'ADD',1:'OR',4:'AND',5:'SUB',6:'XOR',7:'CMP'})[reg] || null;
    if (!mnemonic) return null;
  }
  const displacementOffset = p;
  const disp = signed32(bytes, p, little);
  if (disp == null) return null;
  p += 4;
  if (p + immediateBytes > bytes.length) return null;
  let immediate = null;
  if (immediateBytes === 1) immediate = bytes.readInt8(p);
  else if (immediateBytes === 4) immediate = little ? bytes.readInt32LE(p) : bytes.readInt32BE(p);
  p += immediateBytes;
  return { mnemonic, width, rex, modrm, reg, length:p-offset, disp, displacementOffset, immediate };
}

function scanX86_64DataRefs(buffer, sections, objects, symbols, options = {}) {
  const little = options.littleEndian !== false;
  const functions = (symbols || []).filter((symbol) => symbol.type === 2 && symbol.value > 0n && symbol.size > 0n);
  const relations = [];
  const operations = [];
  const seen = new Set();
  let scannedBytes = 0;
  for (const section of sections) {
    if (!section.executable || !section.fileBacked || section.truncated || section.size <= 0n) continue;
    const base = safeNumber(section.fileOffset);
    const total = safeNumber(section.size);
    if (base == null || total == null || base < 0 || base >= buffer.length) continue;
    const size = Math.min(total, buffer.length - base, MAX_CODE_SCAN_BYTES - scannedBytes);
    if (size <= 0) break;
    const code = buffer.subarray(base, base + size);
    scannedBytes += size;
    for (let offset = 0; offset < code.length && relations.length < MAX_REFS; offset += 1) {
      const decoded = decodeRipRelative(code, offset, little);
      if (!decoded) continue;
      const instructionEa = section.addr + BigInt(offset);
      const nextEa = instructionEa + BigInt(decoded.length);
      const targetEa = nextEa + BigInt(decoded.disp);
      const object = objects.find((candidate) => objectContains(candidate, targetEa));
      if (!object) continue;
      const fn = functionFor(functions, instructionEa);
      const relationType = decoded.mnemonic === 'CMP' ? 'COMPARES_WITH' : decoded.mnemonic === 'LEA' ? 'TAKES_ADDRESS' : 'READS';
      const key = `${sourceId(fn,instructionEa)}|${object.id}|${relationType}|${hex(instructionEa)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const evidence = `x86-64 RIP-relative ${decoded.mnemonic} @ ${hex(instructionEa)} → ${object.name}+0x${(targetEa-BigInt(object.address)).toString(16)}`;
      relations.push({
        source:sourceId(fn,instructionEa), sourceLabel:fn?.name || hex(instructionEa), target:object.id,
        type:relationType, location:hex(instructionEa), confidence:decoded.mnemonic === 'LEA' ? 0.95 : 0.92,
        evidence:[evidence], standalone:true
      });
      operations.push({
        id:`standalone_op_${operations.length+1}`, op:decoded.mnemonic, location:hex(instructionEa), line:null,
        pseudo:`${decoded.mnemonic} ${object.name}${decoded.immediate != null ? `, ${decoded.immediate}` : ''}`,
        sourceObject:object.id, standalone:true
      });
      offset += decoded.length - 1;
    }
    if (relations.length >= MAX_REFS || scannedBytes >= MAX_CODE_SCAN_BYTES) break;
  }
  return { relations, operations, scannedBytes, truncated:relations.length >= MAX_REFS || scannedBytes >= MAX_CODE_SCAN_BYTES };
}

module.exports = { decodeRipRelative, scanX86_64DataRefs, MAX_CODE_SCAN_BYTES, MAX_REFS };
