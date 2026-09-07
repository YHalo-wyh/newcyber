const { inspectPytorchZip, extractZipEntry, parseZipCentralDirectory } = require('./model');

const SAFETENSORS_DTYPE_BYTES = new Map([
  ['BOOL', 1], ['U8', 1], ['I8', 1], ['I16', 2], ['U16', 2], ['F16', 2], ['BF16', 2],
  ['I32', 4], ['U32', 4], ['F32', 4], ['I64', 8], ['U64', 8], ['F64', 8],
  ['F8_E4M3FN', 1], ['F8_E4M3FNUZ', 1], ['F8_E5M2', 1], ['F8_E5M2FNUZ', 1]
]);

const SAFE_PICKLE_MODULE_PREFIXES = [
  'torch', 'collections', 'builtins', 'numpy', 'numpy.core', 'numpy._core', 'copyreg', '_codecs', 'typing'
];

const DANGEROUS_PICKLE_GLOBALS = [
  { module: /^(?:os|posix|nt)$/i, name: /^(?:system|popen|spawn\w*|exec\w*)$/i },
  { module: /^subprocess$/i, name: /^(?:Popen|call|run|check_call|check_output)$/i },
  { module: /^builtins$/i, name: /^(?:eval|exec|compile|open|__import__|input)$/i },
  { module: /^(?:pickle|_pickle)$/i, name: /^(?:loads?|Unpickler)$/i }
];

function bigintProduct(values) {
  let result = 1n;
  for (const value of values) result *= BigInt(value);
  return result;
}

function bigintString(value) {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
}

function parseSafetensorsAdvanced(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 9) return null;
  const headerLengthBig = buffer.readBigUInt64LE(0);
  if (headerLengthBig > 16n * 1024n * 1024n || headerLengthBig < 2n || headerLengthBig > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const headerLength = Number(headerLengthBig);
  const dataStart = 8 + headerLength;
  if (dataStart > buffer.length) return null;

  let header;
  try {
    header = JSON.parse(buffer.subarray(8, dataStart).toString('utf8'));
  } catch {
    return null;
  }
  if (!header || typeof header !== 'object' || Array.isArray(header)) return null;

  const dataBytes = buffer.length - dataStart;
  const tensors = [];
  const issues = [];
  const ranges = [];
  let declaredBytes = 0n;

  for (const [name, value] of Object.entries(header)) {
    if (name === '__metadata__') continue;
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      issues.push({ severity: 'high', id: 'invalid-tensor-entry', tensor: name, message: 'tensor entry 不是对象' });
      continue;
    }
    const dtype = typeof value.dtype === 'string' ? value.dtype : null;
    const shape = Array.isArray(value.shape) ? value.shape : null;
    const offsets = Array.isArray(value.data_offsets) ? value.data_offsets : null;
    const shapeValid = Boolean(shape) && shape.every((item) => Number.isSafeInteger(item) && item >= 0);
    const offsetsValid = Boolean(offsets) && offsets.length === 2 && offsets.every((item) => Number.isSafeInteger(item) && item >= 0) && offsets[1] >= offsets[0];
    const bytesPerElement = SAFETENSORS_DTYPE_BYTES.get(dtype || '') || null;
    const elementCount = shapeValid ? bigintProduct(shape) : null;
    const expectedBytes = elementCount != null && bytesPerElement ? elementCount * BigInt(bytesPerElement) : null;
    const actualBytes = offsetsValid ? BigInt(offsets[1] - offsets[0]) : null;

    if (!dtype) issues.push({ severity: 'high', id: 'missing-dtype', tensor: name, message: '缺少 dtype' });
    else if (!bytesPerElement) issues.push({ severity: 'info', id: 'unknown-dtype', tensor: name, message: `暂未内置 dtype ${dtype} 的字节宽度，保留 offset 证据但不猜长度。` });
    if (!shapeValid) issues.push({ severity: 'high', id: 'invalid-shape', tensor: name, message: 'shape 必须是非负安全整数数组' });
    if (!offsetsValid) issues.push({ severity: 'high', id: 'invalid-data-offsets', tensor: name, message: 'data_offsets 必须是 [start,end] 且 start<=end' });
    if (offsetsValid && offsets[1] > dataBytes) issues.push({ severity: 'high', id: 'offset-out-of-range', tensor: name, message: `data_offsets 结束位置 ${offsets[1]} 超过 data 区 ${dataBytes} bytes` });
    if (expectedBytes != null && actualBytes != null && expectedBytes !== actualBytes) {
      issues.push({ severity: 'high', id: 'tensor-size-mismatch', tensor: name, message: `shape/dtype 期望 ${expectedBytes} bytes，offset 实际 ${actualBytes} bytes` });
    }

    if (offsetsValid) {
      ranges.push({ name, start: offsets[0], end: offsets[1] });
      declaredBytes += actualBytes;
    }
    tensors.push({
      name,
      dtype,
      shape,
      elementCount: elementCount == null ? null : bigintString(elementCount),
      dataOffsets: offsetsValid ? offsets : null,
      expectedBytes: expectedBytes == null ? null : bigintString(expectedBytes),
      actualBytes: actualBytes == null ? null : bigintString(actualBytes)
    });
  }

  ranges.sort((a, b) => a.start - b.start || a.end - b.end || a.name.localeCompare(b.name));
  const overlaps = [];
  const gaps = [];
  let cursor = 0;
  for (const range of ranges) {
    if (range.start < cursor) {
      overlaps.push({ tensor: range.name, start: range.start, end: range.end, previousEnd: cursor });
      issues.push({ severity: 'high', id: 'tensor-data-overlap', tensor: range.name, message: `data range [${range.start},${range.end}) 与前一 tensor 区间重叠` });
    } else if (range.start > cursor) {
      gaps.push({ start: cursor, end: range.start, bytes: range.start - cursor });
    }
    cursor = Math.max(cursor, range.end);
  }
  if (cursor < dataBytes) gaps.push({ start: cursor, end: dataBytes, bytes: dataBytes - cursor });

  return {
    format: 'SafeTensors',
    tensorCount: tensors.length,
    tensors,
    metadata: header.__metadata__ || null,
    headerBytes: headerLength,
    dataBytes,
    declaredTensorBytes: bigintString(declaredBytes),
    overlaps,
    gaps,
    valid: !issues.some((item) => item.severity === 'high'),
    securityFindings: issues,
    notes: [
      '只解析 SafeTensors JSON header 与 data_offsets，不解释或执行 tensor 内容。',
      'offset 越界、区间重叠、shape/dtype 与 byte length 不一致属于结构证据，不自动推断为恶意。'
    ]
  };
}

function parseNpyDescriptor(descr) {
  if (typeof descr !== 'string') return { supported: false, object: false, itemBytes: null };
  const match = descr.match(/^([<>=|])?([?bBiufcSUVOMm])([0-9]+)?$/);
  if (!match) return { supported: false, object: /O/.test(descr), itemBytes: null };
  const kind = match[2];
  const width = match[3] ? Number(match[3]) : null;
  if (kind === 'O') return { supported: true, object: true, itemBytes: null, kind };
  if (kind === '?') return { supported: true, object: false, itemBytes: 1, kind };
  if (kind === 'U') return Number.isSafeInteger(width) ? { supported: true, object: false, itemBytes: width * 4, kind } : { supported: false, object: false, itemBytes: null, kind };
  if (kind === 'S' || kind === 'V') return Number.isSafeInteger(width) ? { supported: true, object: false, itemBytes: width, kind } : { supported: false, object: false, itemBytes: null, kind };
  if (['b', 'B'].includes(kind)) return { supported: true, object: false, itemBytes: width || 1, kind };
  return Number.isSafeInteger(width) && width > 0 ? { supported: true, object: false, itemBytes: width, kind } : { supported: false, object: false, itemBytes: null, kind };
}

function parseNpyAdvanced(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12 || buffer.subarray(0, 6).toString('hex') !== '934e554d5059') return null;
  const major = buffer[6];
  const minor = buffer[7];
  if (![1, 2, 3].includes(major)) return null;
  const headerLength = major === 1 ? buffer.readUInt16LE(8) : buffer.readUInt32LE(8);
  const headerOffset = major === 1 ? 10 : 12;
  const payloadOffset = headerOffset + headerLength;
  if (payloadOffset > buffer.length || headerLength > 16 * 1024 * 1024) return null;
  const header = buffer.subarray(headerOffset, payloadOffset).toString(major === 3 ? 'utf8' : 'latin1').trim();

  const descrMatch = header.match(/["']descr["']\s*:\s*(["'])(.*?)\1/);
  const fortranMatch = header.match(/["']fortran_order["']\s*:\s*(True|False)/);
  const shapeMatch = header.match(/["']shape["']\s*:\s*\(([^)]*)\)/);
  const descr = descrMatch?.[2] || null;
  const fortranOrder = fortranMatch ? fortranMatch[1] === 'True' : null;
  let shape = null;
  if (shapeMatch) {
    const body = shapeMatch[1].trim();
    shape = body ? body.split(',').map((item) => item.trim()).filter(Boolean).map(Number) : [];
    if (!shape.every((item) => Number.isSafeInteger(item) && item >= 0)) shape = null;
  }

  const descriptor = parseNpyDescriptor(descr);
  const payloadBytes = buffer.length - payloadOffset;
  const elementCount = shape ? bigintProduct(shape) : null;
  const expectedBytes = elementCount != null && descriptor.itemBytes != null ? elementCount * BigInt(descriptor.itemBytes) : null;
  const findings = [];
  if (!descr) findings.push({ severity: 'high', id: 'npy-descr-unparsed', message: '无法确定 NPY descr；可能是结构化 dtype，当前不猜测。' });
  else if (!descriptor.supported) findings.push({ severity: 'info', id: 'npy-descr-unsupported', message: `暂不计算 dtype ${descr} 的固定 payload 长度。` });
  if (!shape) findings.push({ severity: 'high', id: 'npy-shape-unparsed', message: '无法可靠解析 NPY shape。' });
  if (descriptor.object) findings.push({ severity: 'high', id: 'npy-object-dtype', message: `dtype=${descr} 使用 Python object 语义；对不可信文件不要以 allow_pickle=true 加载。` });
  if (expectedBytes != null && BigInt(payloadBytes) !== expectedBytes) {
    findings.push({ severity: 'high', id: 'npy-payload-size-mismatch', message: `shape/dtype 期望 ${expectedBytes} bytes，实际 payload ${payloadBytes} bytes。` });
  }

  return {
    format: 'NumPy NPY',
    version: `${major}.${minor}`,
    header,
    descr,
    fortranOrder,
    shape,
    objectDtype: descriptor.object,
    itemBytes: descriptor.itemBytes,
    elementCount: elementCount == null ? null : bigintString(elementCount),
    payloadOffset,
    payloadBytes,
    expectedPayloadBytes: expectedBytes == null ? null : bigintString(expectedBytes),
    valid: !findings.some((item) => item.severity === 'high' && item.id !== 'npy-object-dtype'),
    securityFindings: findings,
    notes: [
      'NPY object dtype 可能携带 pickle 对象；这里只做 header/长度审计，不执行 NumPy 加载。'
    ]
  };
}

function readLine(buffer, offset) {
  const end = buffer.indexOf(0x0a, offset);
  if (end < 0) return null;
  return { text: buffer.subarray(offset, end).toString('utf8'), next: end + 1 };
}

function readSized(buffer, offset, lengthBytes, littleEndian = true) {
  if (offset + lengthBytes > buffer.length) return null;
  let lengthBig;
  if (lengthBytes === 1) lengthBig = BigInt(buffer[offset]);
  else if (lengthBytes === 4) lengthBig = BigInt(littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset));
  else if (lengthBytes === 8) lengthBig = littleEndian ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
  else return null;
  if (lengthBig > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const length = Number(lengthBig);
  const start = offset + lengthBytes;
  const end = start + length;
  if (end > buffer.length) return null;
  return { start, end, next: end, length };
}

function pickleGlobalRisk(module, name) {
  if (DANGEROUS_PICKLE_GLOBALS.some((item) => item.module.test(module) && item.name.test(name))) return 'high';
  if (SAFE_PICKLE_MODULE_PREFIXES.some((prefix) => module === prefix || module.startsWith(`${prefix}.`))) return 'info';
  return 'medium';
}

function scanPickleOpcodes(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) return null;
  const globals = [];
  const findings = [];
  const opcodeCounts = {};
  const stack = [];
  const memo = new Map();
  const MARK = { kind: 'mark' };
  let offset = 0;
  let protocol = 0;
  let complete = false;
  let parseError = null;
  let unresolvedStackGlobals = 0;

  const count = (name) => { opcodeCounts[name] = (opcodeCounts[name] || 0) + 1; };
  const pushString = (value) => stack.push({ kind: 'string', value });
  const pushUnknown = () => stack.push({ kind: 'unknown' });
  const pop = () => stack.length ? stack.pop() : { kind: 'unknown' };
  const collapseMark = (kind = 'unknown') => {
    while (stack.length) {
      const value = pop();
      if (value === MARK) break;
    }
    stack.push({ kind });
  };
  const addGlobal = (module, name, pc, dynamic = false) => {
    const severity = pickleGlobalRisk(module, name);
    const item = { module, name, qualifiedName: `${module}.${name}`, pc, dynamic, severity };
    globals.push(item);
    if (severity === 'high') findings.push({ severity: 'high', id: 'pickle-dangerous-global', message: `pickle 引用高风险 global ${item.qualifiedName}`, pc, global: item.qualifiedName });
    else if (severity === 'medium') findings.push({ severity: 'medium', id: 'pickle-external-global', message: `pickle 引用非典型模块 global ${item.qualifiedName}，需人工确认是否为预期依赖。`, pc, global: item.qualifiedName });
    stack.push({ kind: 'global', module, name });
  };

  while (offset < buffer.length) {
    const pc = offset;
    const opcode = buffer[offset++];
    try {
      if (opcode === 0x80) { count('PROTO'); if (offset >= buffer.length) throw new Error('truncated PROTO'); protocol = buffer[offset++]; continue; }
      if (opcode === 0x95) { count('FRAME'); if (offset + 8 > buffer.length) throw new Error('truncated FRAME'); offset += 8; continue; }
      if (opcode === 0x2e) { count('STOP'); complete = true; break; }
      if (opcode === 0x28) { count('MARK'); stack.push(MARK); continue; }
      if (opcode === 0x30) { count('POP'); pop(); continue; }
      if (opcode === 0x31) { count('POP_MARK'); collapseMark('unknown'); pop(); continue; }
      if (opcode === 0x32) { count('DUP'); stack.push(stack.length ? stack[stack.length - 1] : { kind: 'unknown' }); continue; }
      if (opcode === 0x4e || opcode === 0x88 || opcode === 0x89) { count(opcode === 0x4e ? 'NONE' : opcode === 0x88 ? 'NEWTRUE' : 'NEWFALSE'); pushUnknown(); continue; }
      if (opcode === 0x4a) { count('BININT'); if (offset + 4 > buffer.length) throw new Error('truncated BININT'); offset += 4; pushUnknown(); continue; }
      if (opcode === 0x4b) { count('BININT1'); if (offset >= buffer.length) throw new Error('truncated BININT1'); offset += 1; pushUnknown(); continue; }
      if (opcode === 0x4d) { count('BININT2'); if (offset + 2 > buffer.length) throw new Error('truncated BININT2'); offset += 2; pushUnknown(); continue; }
      if (opcode === 0x47) { count('BINFLOAT'); if (offset + 8 > buffer.length) throw new Error('truncated BINFLOAT'); offset += 8; pushUnknown(); continue; }
      if ([0x46, 0x49, 0x4c].includes(opcode)) { const line = readLine(buffer, offset); if (!line) throw new Error('truncated line opcode'); count(opcode === 0x46 ? 'FLOAT' : opcode === 0x49 ? 'INT' : 'LONG'); offset = line.next; pushUnknown(); continue; }

      if ([0x8c, 0x55, 0x43].includes(opcode)) {
        const sized = readSized(buffer, offset, 1); if (!sized) throw new Error('truncated short string/bytes');
        count(opcode === 0x8c ? 'SHORT_BINUNICODE' : opcode === 0x55 ? 'SHORT_BINSTRING' : 'SHORT_BINBYTES');
        const value = buffer.subarray(sized.start, sized.end).toString(opcode === 0x8c ? 'utf8' : 'latin1');
        offset = sized.next; pushString(value); continue;
      }
      if ([0x58, 0x54, 0x42].includes(opcode)) {
        const sized = readSized(buffer, offset, 4); if (!sized) throw new Error('truncated string/bytes');
        count(opcode === 0x58 ? 'BINUNICODE' : opcode === 0x54 ? 'BINSTRING' : 'BINBYTES');
        const value = buffer.subarray(sized.start, sized.end).toString(opcode === 0x58 ? 'utf8' : 'latin1');
        offset = sized.next; pushString(value); continue;
      }
      if ([0x8d, 0x8e, 0x96].includes(opcode)) {
        const sized = readSized(buffer, offset, 8); if (!sized) throw new Error('truncated 64-bit sized payload');
        count(opcode === 0x8d ? 'BINUNICODE8' : opcode === 0x8e ? 'BINBYTES8' : 'BYTEARRAY8');
        const value = buffer.subarray(sized.start, sized.end).toString(opcode === 0x8d ? 'utf8' : 'latin1');
        offset = sized.next; if (opcode === 0x8d) pushString(value); else pushUnknown(); continue;
      }
      if ([0x56, 0x53].includes(opcode)) {
        const line = readLine(buffer, offset); if (!line) throw new Error('truncated text string');
        count(opcode === 0x56 ? 'UNICODE' : 'STRING'); offset = line.next;
        const raw = line.text;
        pushString(opcode === 0x53 && /^['"].*['"]$/.test(raw) ? raw.slice(1, -1) : raw);
        continue;
      }

      if (opcode === 0x63 || opcode === 0x69) {
        count(opcode === 0x63 ? 'GLOBAL' : 'INST');
        const moduleLine = readLine(buffer, offset); if (!moduleLine) throw new Error('truncated GLOBAL module');
        const nameLine = readLine(buffer, moduleLine.next); if (!nameLine) throw new Error('truncated GLOBAL name');
        offset = nameLine.next; addGlobal(moduleLine.text, nameLine.text, pc, false); continue;
      }
      if (opcode === 0x93) {
        count('STACK_GLOBAL');
        const name = pop(); const module = pop();
        if (module.kind === 'string' && name.kind === 'string') addGlobal(module.value, name.value, pc, true);
        else { unresolvedStackGlobals += 1; pushUnknown(); }
        continue;
      }

      if (opcode === 0x94) { count('MEMOIZE'); memo.set(memo.size, stack.length ? stack[stack.length - 1] : { kind: 'unknown' }); continue; }
      if (opcode === 0x71) { count('BINPUT'); if (offset >= buffer.length) throw new Error('truncated BINPUT'); memo.set(buffer[offset++], stack.length ? stack[stack.length - 1] : { kind: 'unknown' }); continue; }
      if (opcode === 0x72) { count('LONG_BINPUT'); if (offset + 4 > buffer.length) throw new Error('truncated LONG_BINPUT'); memo.set(buffer.readUInt32LE(offset), stack.length ? stack[stack.length - 1] : { kind: 'unknown' }); offset += 4; continue; }
      if (opcode === 0x68) { count('BINGET'); if (offset >= buffer.length) throw new Error('truncated BINGET'); stack.push(memo.get(buffer[offset++]) || { kind: 'unknown' }); continue; }
      if (opcode === 0x6a) { count('LONG_BINGET'); if (offset + 4 > buffer.length) throw new Error('truncated LONG_BINGET'); stack.push(memo.get(buffer.readUInt32LE(offset)) || { kind: 'unknown' }); offset += 4; continue; }
      if ([0x70, 0x67, 0x50].includes(opcode)) { const line = readLine(buffer, offset); if (!line) throw new Error('truncated text memo/persid'); count(opcode === 0x70 ? 'PUT' : opcode === 0x67 ? 'GET' : 'PERSID'); offset = line.next; if (opcode === 0x50) pushUnknown(); continue; }
      if (opcode === 0x51) { count('BINPERSID'); pop(); pushUnknown(); continue; }

      if ([0x5d, 0x7d, 0x29, 0x8f].includes(opcode)) { count(opcode === 0x5d ? 'EMPTY_LIST' : opcode === 0x7d ? 'EMPTY_DICT' : opcode === 0x29 ? 'EMPTY_TUPLE' : 'EMPTY_SET'); pushUnknown(); continue; }
      if ([0x6c, 0x64, 0x74, 0x91].includes(opcode)) { count(opcode === 0x6c ? 'LIST' : opcode === 0x64 ? 'DICT' : opcode === 0x74 ? 'TUPLE' : 'FROZENSET'); collapseMark('unknown'); continue; }
      if ([0x85, 0x86, 0x87].includes(opcode)) { const arity = opcode - 0x84; count(`TUPLE${arity}`); for (let i = 0; i < arity; i += 1) pop(); pushUnknown(); continue; }
      if ([0x61, 0x73].includes(opcode)) { count(opcode === 0x61 ? 'APPEND' : 'SETITEM'); pop(); if (opcode === 0x73) pop(); continue; }
      if ([0x65, 0x75, 0x90].includes(opcode)) { count(opcode === 0x65 ? 'APPENDS' : opcode === 0x75 ? 'SETITEMS' : 'ADDITEMS'); collapseMark('unknown'); continue; }

      if ([0x52, 0x62, 0x81, 0x92, 0x6f].includes(opcode)) {
        const name = opcode === 0x52 ? 'REDUCE' : opcode === 0x62 ? 'BUILD' : opcode === 0x81 ? 'NEWOBJ' : opcode === 0x92 ? 'NEWOBJ_EX' : 'OBJ';
        count(name);
        if (opcode === 0x62) pop();
        else if (opcode === 0x6f) collapseMark('unknown');
        else { pop(); pop(); pushUnknown(); }
        continue;
      }
      if ([0x82, 0x83, 0x84].includes(opcode)) { const bytes = opcode === 0x82 ? 1 : opcode === 0x83 ? 2 : 4; count(`EXT${bytes}`); if (offset + bytes > buffer.length) throw new Error('truncated EXT'); offset += bytes; pushUnknown(); continue; }
      if (opcode === 0x8a) { count('LONG1'); if (offset >= buffer.length) throw new Error('truncated LONG1'); const length = buffer[offset++]; if (offset + length > buffer.length) throw new Error('truncated LONG1 payload'); offset += length; pushUnknown(); continue; }
      if (opcode === 0x8b) { count('LONG4'); if (offset + 4 > buffer.length) throw new Error('truncated LONG4'); const length = buffer.readUInt32LE(offset); offset += 4; if (offset + length > buffer.length) throw new Error('truncated LONG4 payload'); offset += length; pushUnknown(); continue; }
      if (opcode === 0x97 || opcode === 0x98) { count(opcode === 0x97 ? 'NEXT_BUFFER' : 'READONLY_BUFFER'); pushUnknown(); continue; }

      throw new Error(`unsupported pickle opcode 0x${opcode.toString(16).padStart(2, '0')} at ${pc}`);
    } catch (error) {
      parseError = error.message;
      break;
    }
  }

  const dangerousGlobals = globals.filter((item) => item.severity === 'high');
  const externalGlobals = globals.filter((item) => item.severity === 'medium');
  return {
    protocol,
    complete,
    bytesScanned: offset,
    opcodeCounts,
    globals,
    dangerousGlobals,
    externalGlobals,
    unresolvedStackGlobals,
    parseError,
    containsObjectConstruction: ['REDUCE', 'NEWOBJ', 'NEWOBJ_EX', 'OBJ', 'BUILD'].some((name) => opcodeCounts[name]),
    securityFindings: findings,
    notes: [
      'pickle opcode 仅做静态解析，不调用 pickle.loads / torch.load。',
      '出现 REDUCE/NEWOBJ 在正常 PyTorch checkpoint 中并不等价于恶意；只有可解析 global 与明确危险调用组合才升级风险。'
    ]
  };
}

function inspectPytorchAdvanced(buffer) {
  const base = inspectPytorchZip(buffer);
  if (!base) return null;
  const zip = parseZipCentralDirectory(buffer);
  const dataPklEntry = zip?.entries?.find((entry) => /(^|\/)data\.pkl$/i.test(entry.name));
  const dataPkl = dataPklEntry ? extractZipEntry(buffer, dataPklEntry) : null;
  const pickleAudit = dataPkl ? scanPickleOpcodes(dataPkl) : null;
  const securityFindings = [...(pickleAudit?.securityFindings || [])];
  if (!dataPklEntry) securityFindings.push({ severity: 'info', id: 'pytorch-no-data-pkl', message: 'ZIP 中未找到 data.pkl；可能不是标准 PyTorch ZIP checkpoint。' });
  else if (!dataPkl) securityFindings.push({ severity: 'medium', id: 'pytorch-data-pkl-unreadable', message: 'data.pkl 存在但未能在安全大小/压缩限制内解出。' });
  return {
    ...base,
    pickleAudit,
    securityFindings,
    notes: [
      ...(base.notes || []),
      'data.pkl 额外执行静态 pickle opcode/global 审计；不会反序列化对象。'
    ]
  };
}

function inspectModelArtifact(buffer, extension = '') {
  const ext = String(extension || '').toLowerCase();
  if (ext === '.safetensors') return parseSafetensorsAdvanced(buffer);
  if (ext === '.npy') return parseNpyAdvanced(buffer);
  if (ext === '.pt' || ext === '.pth') return inspectPytorchAdvanced(buffer);
  return null;
}

module.exports = {
  parseSafetensorsAdvanced,
  parseNpyAdvanced,
  parseNpyDescriptor,
  scanPickleOpcodes,
  inspectPytorchAdvanced,
  inspectModelArtifact,
  pickleGlobalRisk,
  SAFETENSORS_DTYPE_BYTES
};
