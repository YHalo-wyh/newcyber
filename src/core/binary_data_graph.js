const MAX_INPUT_CHARS = 2 * 1024 * 1024;

const DATA_WIDTH = Object.freeze({ db: 1, dw: 2, dd: 4, dq: 8 });
const INSTRUCTION_OPS = new Set([
  'mov','movzx','movsx','lea','xor','add','sub','and','or','rol','ror','not','cmp','test',
  'inc','dec','jne','jnz','je','jz','ja','jae','jb','jbe','jg','jge','jl','jle','jmp'
]);

const REGISTER_ALIASES = new Map();
for (const [root, names] of Object.entries({
  rax:['rax','eax','ax','al','ah'], rbx:['rbx','ebx','bx','bl','bh'], rcx:['rcx','ecx','cx','cl','ch'],
  rdx:['rdx','edx','dx','dl','dh'], rsi:['rsi','esi','si','sil'], rdi:['rdi','edi','di','dil'],
  rbp:['rbp','ebp','bp','bpl'], rsp:['rsp','esp','sp','spl'],
  r8:['r8','r8d','r8w','r8b'], r9:['r9','r9d','r9w','r9b'], r10:['r10','r10d','r10w','r10b'],
  r11:['r11','r11d','r11w','r11b'], r12:['r12','r12d','r12w','r12b'], r13:['r13','r13d','r13w','r13b'],
  r14:['r14','r14d','r14w','r14b'], r15:['r15','r15d','r15w','r15b']
})) for (const name of names) REGISTER_ALIASES.set(name, root);

function canonicalReg(value) {
  return REGISTER_ALIASES.get(String(value || '').trim().toLowerCase()) || null;
}

function normalizeAddress(hex) {
  const raw = String(hex || '').replace(/^0x/i, '').replace(/^0+/, '') || '0';
  return `0x${raw.toLowerCase()}`;
}

function addressBigInt(hex) {
  try { return BigInt(`0x${String(hex || '').replace(/^0x/i, '')}`); }
  catch { return null; }
}

function escapeAscii(bytes) {
  return bytes.map((value) => (value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.')).join('');
}

function bytesHex(bytes) {
  return bytes.map((value) => value.toString(16).padStart(2, '0')).join(' ');
}

function splitComment(line) {
  let quote = null;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if ((char === "'" || char === '"') && line[index - 1] !== '\\') {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
    }
    if (char === ';' && !quote) return { code: line.slice(0, index).trimEnd(), comment: line.slice(index + 1).trim() };
  }
  return { code: line.trimEnd(), comment: '' };
}

function splitValues(text) {
  const values = [];
  let quote = null;
  let current = '';
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if ((char === "'" || char === '"') && text[index - 1] !== '\\') {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
      current += char;
      continue;
    }
    if (char === ',' && !quote) {
      if (current.trim()) values.push(current.trim());
      current = '';
    } else current += char;
  }
  if (current.trim()) values.push(current.trim());
  return values;
}

function parseInteger(token) {
  const value = String(token || '').trim();
  if (/^[0-9a-f]+h$/i.test(value)) return BigInt(`0x${value.slice(0, -1)}`);
  if (/^0x[0-9a-f]+$/i.test(value)) return BigInt(value);
  if (/^-?[0-9]+$/.test(value)) return BigInt(value);
  return null;
}

function parseDataToken(token) {
  const value = String(token || '').trim();
  const offset = value.match(/^offset\s+([A-Za-z_.$?@][\w.$?@]*)$/i);
  if (offset) return { type: 'symbol', symbol: offset[1], raw: value };
  if (/^[A-Za-z_.$?@][\w.$?@]*$/.test(value)) return { type: 'symbol', symbol: value, raw: value };
  if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) {
    const inner = value.slice(1, -1)
      .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
      .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/\\([\\'\"])/g, '$1');
    return { type: 'string', value: inner, bytes: [...Buffer.from(inner, 'latin1')], raw: value };
  }
  const integer = parseInteger(value);
  if (integer != null) return { type: 'integer', value: integer, raw: value };
  return { type: 'unknown', raw: value };
}

function integerBytes(value, width) {
  const out = [];
  let current = BigInt.asUintN(width * 8, value);
  for (let index = 0; index < width; index += 1) {
    out.push(Number(current & 0xffn));
    current >>= 8n;
  }
  return out;
}

function parseListingLine(raw, lineNumber) {
  const { code, comment } = splitComment(raw);
  const prefix = code.match(/^\s*([.$A-Za-z0-9_?]+):([0-9A-Fa-f]{6,16})\s+(.*?)\s*$/);
  if (!prefix) return { raw, lineNumber, comment, section: null, address: null, rest: code.trim() };
  return {
    raw,
    lineNumber,
    section: prefix[1].startsWith('.') ? prefix[1] : `.${prefix[1]}`,
    address: normalizeAddress(prefix[2]),
    addressBig: addressBigInt(prefix[2]),
    rest: prefix[3].trim(),
    comment
  };
}

function parseDataCell(line) {
  if (!line.section || !line.address || !line.rest) return null;
  const match = line.rest.match(/^(?:(\S+)\s+)?(db|dw|dd|dq)\s+(.+)$/i);
  if (!match) return null;
  const directive = match[2].toLowerCase();
  const width = DATA_WIDTH[directive];
  const tokens = splitValues(match[3]).map(parseDataToken);
  if (!tokens.length) return null;
  const bytes = [];
  let completeBytes = true;
  for (const token of tokens) {
    if (token.type === 'string' && width === 1) bytes.push(...token.bytes);
    else if (token.type === 'integer') bytes.push(...integerBytes(token.value, width));
    else completeBytes = false;
  }
  const span = tokens.reduce((sum, token) => sum + (token.type === 'string' && width === 1 ? token.bytes.length : width), 0);
  return {
    section: line.section,
    address: line.address,
    addressBig: line.addressBig,
    label: match[1] || null,
    directive,
    width,
    tokens,
    bytes: completeBytes ? bytes : null,
    span,
    comment: line.comment,
    lineNumber: line.lineNumber,
    raw: line.raw
  };
}

function buildSections(lines) {
  const map = new Map();
  for (const line of lines) {
    if (!line.section) continue;
    let section = map.get(line.section);
    if (!section) {
      section = { name: line.section, startAddress: line.address, endAddress: line.address, lineStart: line.lineNumber, lineEnd: line.lineNumber, objectIds: [] };
      map.set(line.section, section);
    }
    section.lineEnd = line.lineNumber;
    if (line.address) section.endAddress = line.address;
  }
  return [...map.values()];
}

function buildObjects(cells) {
  const objects = [];
  let current = null;
  let previousEnd = null;
  for (const cell of cells) {
    const contiguous = current && current.section === cell.section && previousEnd != null && cell.addressBig === previousEnd;
    if (cell.label || !contiguous) {
      current = {
        id: `obj_${String(cell.label || cell.address.slice(2)).replace(/[^A-Za-z0-9_.$?@-]/g, '_')}`,
        name: cell.label || `data_${cell.address.slice(2)}`,
        address: cell.address,
        addressBig: cell.addressBig,
        section: cell.section,
        kind: 'data',
        directive: cell.directive,
        cells: [],
        fields: [],
        evidence: [],
        structuralName: null,
        semanticSuggestions: []
      };
      objects.push(current);
    }
    current.cells.push(cell);
    if (cell.comment) current.evidence.push({ kind: 'comment', line: cell.lineNumber, text: cell.comment });
    previousEnd = cell.addressBig == null ? null : cell.addressBig + BigInt(cell.span);
  }

  for (const object of objects) {
    const byteList = [];
    let bytesComplete = true;
    let totalSize = 0;
    for (const cell of object.cells) {
      totalSize += cell.span;
      if (cell.bytes) byteList.push(...cell.bytes);
      else bytesComplete = false;
    }
    object.size = totalSize;
    object.bytes = bytesComplete ? byteList : null;
    object.bytesHex = object.bytes ? bytesHex(object.bytes) : null;
    object.ascii = object.bytes ? escapeAscii(object.bytes) : null;
    const first = object.cells[0];
    const firstToken = first.tokens[0];
    if (first.directive === 'db' && firstToken?.type === 'string') object.kind = 'string';
    else if (first.directive === 'db' && object.size > 1) object.kind = 'byte_array';
    else if (first.directive === 'db') object.kind = 'byte';
    else if (first.directive === 'dq' && firstToken?.type === 'symbol') object.kind = 'pointer';
    else if (first.directive === 'dq' && object.cells.length > 1) object.kind = 'qword_array';
    else object.kind = `${first.directive}_data`;
  }
  return objects;
}

function objectMaps(objects) {
  const byName = new Map(objects.map((object) => [object.name, object]));
  const byAddress = new Map(objects.map((object) => [object.address, object]));
  return { byName, byAddress };
}

function findObjectAtNumericAddress(value, byAddress) {
  const normalized = normalizeAddress(value.toString(16));
  return byAddress.get(normalized) || null;
}

function relationKey(source, target, type) { return `${source}|${target}|${type}`; }

function pushRelation(relations, seen, relation) {
  const key = relationKey(relation.source, relation.target, relation.type);
  if (seen.has(key)) {
    const existing = relations.find((item) => relationKey(item.source, item.target, item.type) === key);
    if (existing && relation.evidence) existing.evidence = [...new Set([...(existing.evidence || []), ...relation.evidence])];
    return existing;
  }
  const item = { id: `rel_${relations.length + 1}`, confidence: 1, evidence: [], ...relation };
  relations.push(item);
  seen.add(key);
  return item;
}

function enrichPointersAndSlices(objects, relations, relationSeen) {
  const { byName, byAddress } = objectMaps(objects);
  for (const object of objects) {
    const first = object.cells[0];
    const firstToken = first?.tokens?.[0];
    let target = null;
    if (firstToken?.type === 'symbol') target = byName.get(firstToken.symbol) || null;
    else if (firstToken?.type === 'integer') target = findObjectAtNumericAddress(firstToken.value, byAddress);
    if (target) {
      object.pointsTo = target.id;
      pushRelation(relations, relationSeen, {
        source: object.id,
        target: target.id,
        type: 'POINTS_TO',
        evidence: [`${object.name}+0x00 = ${firstToken.type === 'symbol' ? firstToken.symbol : normalizeAddress(firstToken.value.toString(16))}`],
        confidence: 1
      });
    }

    if (object.directive === 'dq' && object.cells.length >= 3 && target) {
      const lenToken = object.cells[1]?.tokens?.[0];
      const capToken = object.cells[2]?.tokens?.[0];
      if (lenToken?.type === 'integer' && capToken?.type === 'integer') {
        const len = Number(lenToken.value);
        const cap = Number(capToken.value);
        if (Number.isSafeInteger(len) && Number.isSafeInteger(cap) && len >= 0 && cap >= len && cap <= 16 * 1024 * 1024) {
          object.kind = 'go_slice';
          object.structuralName = `byteSlice_${object.address.slice(2)}`;
          object.fields = [
            { offset: 0, name: 'data', value: target.address, target: target.id },
            { offset: 8, name: 'len', value: len },
            { offset: 16, name: 'cap', value: cap }
          ];
          object.evidence.push({ kind: 'structure', text: `连续 qword 符合 Go slice: ptr=${target.address}, len=${len}, cap=${cap}` });
          pushRelation(relations, relationSeen, {
            source: object.id,
            target: target.id,
            type: 'LENGTH_OF',
            value: len,
            evidence: [`Go slice len=${len}, cap=${cap}`],
            confidence: target.size >= len ? 0.98 : 0.88
          });
        }
      }
    }
  }
}

function addXrefRelations(objects, relations, relationSeen) {
  for (const object of objects) {
    for (const evidence of object.evidence || []) {
      if (evidence.kind !== 'comment' || !/XREF:/i.test(evidence.text)) continue;
      const match = evidence.text.match(/XREF:\s*([A-Za-z_.$?@][\w.$?@]*)(?:\+([0-9A-Fa-f]+))?/i);
      if (!match) continue;
      const source = `fn_${match[1]}`;
      pushRelation(relations, relationSeen, {
        source,
        sourceLabel: match[1],
        target: object.id,
        type: 'READS',
        location: match[2] ? `${match[1]}+0x${match[2].toLowerCase()}` : match[1],
        evidence: [evidence.text],
        confidence: 0.9
      });
    }
  }
}

function stripOperandDecorators(value) {
  return String(value || '')
    .replace(/\b(?:byte|word|dword|qword|xmmword|ymmword)\s+ptr\s+/ig, '')
    .replace(/\b(?:cs|ds|ss|es|fs|gs):/ig, '')
    .trim();
}

function splitOperands(text) {
  const out = [];
  let depth = 0;
  let current = '';
  for (const char of String(text || '')) {
    if (char === '[' || char === '(') depth += 1;
    if (char === ']' || char === ')') depth -= 1;
    if (char === ',' && depth === 0) { out.push(current.trim()); current = ''; }
    else current += char;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

function parseInstruction(line) {
  if (!line.section || !line.address || !line.rest) return null;
  const rest = line.rest.replace(/^([A-Za-z_.$?@][\w.$?@]*):\s*/, '').trim();
  const match = rest.match(/^([A-Za-z][A-Za-z0-9.]*)\b\s*(.*)$/);
  if (!match) return null;
  const mnemonic = match[1].toLowerCase();
  if (!INSTRUCTION_OPS.has(mnemonic)) return null;
  return { mnemonic, operands: splitOperands(match[2]), address: line.address, section: line.section, lineNumber: line.lineNumber, raw: line.raw };
}

function cloneExpr(expr) {
  if (!expr || typeof expr !== 'object') return expr;
  if (Array.isArray(expr)) return expr.map(cloneExpr);
  const out = {};
  for (const [key, value] of Object.entries(expr)) out[key] = cloneExpr(value);
  return out;
}

function expressionText(expr, objectById) {
  if (!expr) return '?';
  if (expr.kind === 'const') return expr.value;
  if (expr.kind === 'register') return expr.name;
  if (expr.kind === 'object') return objectById.get(expr.object)?.name || expr.name || expr.object;
  if (expr.kind === 'index') return `${objectById.get(expr.object)?.name || expr.name || expr.object}[${expr.index || '?'}]`;
  if (expr.kind === 'op') {
    if (expr.op === 'NOT') return `~(${expressionText(expr.args[0], objectById)})`;
    if (['ROL','ROR'].includes(expr.op)) return `${expr.op.toLowerCase()}(${expressionText(expr.args[0], objectById)}, ${expressionText(expr.args[1], objectById)})`;
    const symbol = { XOR:'^', ADD:'+', SUB:'-', AND:'&', OR:'|', CMP:'?', CMP_EQ:'==', CMP_NE:'!=' }[expr.op] || expr.op;
    if (expr.args.length === 2) return `${expressionText(expr.args[0], objectById)} ${symbol} ${expressionText(expr.args[1], objectById)}`;
    return `${expr.op}(${expr.args.map((item) => expressionText(item, objectById)).join(', ')})`;
  }
  return '?';
}

function collectObjectRefs(expr, out = []) {
  if (!expr || typeof expr !== 'object') return out;
  if ((expr.kind === 'object' || expr.kind === 'index') && expr.object) out.push(expr.object);
  if (expr.kind === 'op') for (const arg of expr.args || []) collectObjectRefs(arg, out);
  return [...new Set(out)];
}

function findObjectSymbol(operand, objectsByName) {
  const cleaned = stripOperandDecorators(operand);
  const candidates = [...objectsByName.keys()].sort((a, b) => b.length - a.length);
  for (const name of candidates) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`(^|[^A-Za-z0-9_.$?@])${escaped}([^A-Za-z0-9_.$?@]|$)`).test(cleaned)) return objectsByName.get(name);
  }
  return null;
}

function analyzeExpressions(lines, objects, relations, relationSeen) {
  const { byName } = objectMaps(objects);
  const objectById = new Map(objects.map((object) => [object.id, object]));
  const regs = new Map();
  const operations = [];
  let pendingCompare = null;

  const makeOp = (op, args, instruction, extra = {}) => {
    const expr = { kind: 'op', id: `op_${operations.length + 1}`, op, args: args.map(cloneExpr), location: instruction.address, line: instruction.lineNumber, ...extra };
    expr.pseudo = expressionText(expr, objectById);
    operations.push(expr);
    return expr;
  };

  const resolve = (operand) => {
    const cleaned = stripOperandDecorators(operand);
    const reg = canonicalReg(cleaned);
    if (reg) return cloneExpr(regs.get(reg) || { kind: 'register', name: reg });
    const numeric = parseInteger(cleaned);
    if (numeric != null) return { kind: 'const', value: numeric.toString() };
    const directObject = findObjectSymbol(cleaned, byName);
    if (/^\[.*\]$/.test(cleaned)) {
      const inside = cleaned.slice(1, -1);
      const pieces = inside.split(/\+/).map((item) => item.trim()).filter(Boolean);
      let object = directObject;
      let indexReg = null;
      for (const piece of pieces) {
        const pieceReg = canonicalReg(piece.replace(/\*\d+$/, ''));
        if (!pieceReg) continue;
        const bound = regs.get(pieceReg);
        if (!object && (bound?.kind === 'object' || bound?.kind === 'index')) object = objectById.get(bound.object) || null;
        else if (object || bound?.kind !== 'object') indexReg = indexReg || pieceReg;
      }
      if (object?.kind === 'go_slice' && object.pointsTo) object = objectById.get(object.pointsTo) || object;
      if (object) return indexReg ? { kind: 'index', object: object.id, name: object.name, index: indexReg } : { kind: 'object', object: object.id, name: object.name };
    }
    if (directObject) return { kind: 'object', object: directObject.id, name: directObject.name };
    return { kind: 'register', name: cleaned };
  };

  const bindRegister = (operand, expr) => {
    const reg = canonicalReg(stripOperandDecorators(operand));
    if (reg) regs.set(reg, cloneExpr(expr));
  };

  for (const line of lines) {
    if (/\bproc\b/i.test(line.rest || '')) { regs.clear(); pendingCompare = null; }
    const instruction = parseInstruction(line);
    if (!instruction) continue;
    const { mnemonic, operands } = instruction;
    if ((mnemonic === 'lea' || mnemonic === 'mov' || mnemonic === 'movzx' || mnemonic === 'movsx') && operands.length >= 2) {
      let value = resolve(operands[1]);
      if (mnemonic === 'mov' && value.kind === 'object') {
        const object = objectById.get(value.object);
        if (/\[/.test(operands[1]) && object?.kind === 'go_slice' && object.pointsTo) {
          const target = objectById.get(object.pointsTo);
          if (target) value = { kind: 'object', object: target.id, name: target.name };
        }
      }
      bindRegister(operands[0], value);
      continue;
    }

    if (['xor','add','sub','and','or'].includes(mnemonic) && operands.length >= 2) {
      const op = mnemonic.toUpperCase();
      const expression = makeOp(op, [resolve(operands[0]), resolve(operands[1])], instruction);
      bindRegister(operands[0], expression);
      const refs = collectObjectRefs(expression);
      for (const ref of refs) pushRelation(relations, relationSeen, { source: ref, target: expression.id, type: 'INPUT_TO', operation: op, location: instruction.address, confidence: 0.96, evidence: [instruction.raw.trim()] });
      if (op === 'XOR' && refs.length === 2) pushRelation(relations, relationSeen, { source: refs[0], target: refs[1], type: 'XORS_WITH', operationNode: expression.id, location: instruction.address, confidence: 0.98, evidence: [instruction.raw.trim()] });
      continue;
    }

    if (['rol','ror'].includes(mnemonic) && operands.length >= 2) {
      const expression = makeOp(mnemonic.toUpperCase(), [resolve(operands[0]), resolve(operands[1])], instruction);
      bindRegister(operands[0], expression);
      continue;
    }
    if (mnemonic === 'not' && operands.length) {
      const expression = makeOp('NOT', [resolve(operands[0])], instruction);
      bindRegister(operands[0], expression);
      continue;
    }
    if (mnemonic === 'cmp' && operands.length >= 2) {
      pendingCompare = { instruction, lhs: resolve(operands[0]), rhs: resolve(operands[1]) };
      continue;
    }
    if (pendingCompare && ['jne','jnz','je','jz'].includes(mnemonic)) {
      const op = ['jne','jnz'].includes(mnemonic) ? 'CMP_NE' : 'CMP_EQ';
      const expression = makeOp(op, [pendingCompare.lhs, pendingCompare.rhs], pendingCompare.instruction, { branch: mnemonic, branchLocation: instruction.address });
      const leftRefs = collectObjectRefs(expression.args[0]);
      const rightRefs = collectObjectRefs(expression.args[1]);
      const leftTarget = expression.args[0]?.kind === 'op' ? expression.args[0].id : null;
      const rightTarget = expression.args[1]?.kind === 'op' ? expression.args[1].id : null;
      for (const ref of [...leftRefs, ...rightRefs]) pushRelation(relations, relationSeen, { source: ref, target: expression.id, type: 'INPUT_TO', operation: op, location: pendingCompare.instruction.address, confidence: 0.96, evidence: [pendingCompare.instruction.raw.trim(), instruction.raw.trim()] });
      if (leftRefs.length && (rightRefs.length || rightTarget)) {
        for (const ref of leftRefs) pushRelation(relations, relationSeen, { source: ref, target: rightTarget || rightRefs[0], type: 'COMPARES_WITH', operationNode: expression.id, location: pendingCompare.instruction.address, confidence: 0.96, evidence: [expression.pseudo] });
      }
      if (rightRefs.length && leftTarget) for (const ref of rightRefs) pushRelation(relations, relationSeen, { source: ref, target: leftTarget, type: 'COMPARES_WITH', operationNode: expression.id, location: pendingCompare.instruction.address, confidence: 0.96, evidence: [expression.pseudo] });
      pendingCompare = null;
    }
  }

  for (const operation of operations) {
    for (const ref of collectObjectRefs(operation)) {
      const object = objectById.get(ref);
      if (!object) continue;
      if (JSON.stringify(operation).includes('"kind":"index"')) pushRelation(relations, relationSeen, { source: ref, target: operation.id, type: 'INDEXES', location: operation.location, confidence: 0.9, evidence: [operation.pseudo] });
    }
  }

  return operations;
}

function isSequential(bytes) {
  if (!bytes || bytes.length < 5) return false;
  let up = 0;
  for (let index = 1; index < bytes.length; index += 1) if (((bytes[index - 1] + 1) & 0xff) === bytes[index]) up += 1;
  return up >= Math.floor((bytes.length - 1) * 0.75);
}

function semanticCandidates(objects, operations, relations) {
  const objectById = new Map(objects.map((object) => [object.id, object]));
  const candidates = [];
  const comparisons = operations.filter((operation) => operation.op === 'CMP_EQ' || operation.op === 'CMP_NE');
  for (const object of objects) {
    if (object.kind !== 'byte_array' || !object.bytes?.length) continue;
    let score = 0;
    const evidence = [];
    const xor = operations.some((operation) => operation.op === 'XOR' && collectObjectRefs(operation).includes(object.id));
    if (xor) { score += 30; evidence.push('参与 XOR 可逆变换'); }
    const indexed = relations.some((relation) => relation.source === object.id && relation.type === 'INDEXES');
    if (indexed) { score += 15; evidence.push('以索引形式逐字节访问'); }
    const cmp = comparisons.find((operation) => collectObjectRefs(operation).includes(object.id));
    if (cmp) { score += 20; evidence.push('变换链结果参与 CMP / 条件分支'); }
    if (cmp) {
      const refs = collectObjectRefs(cmp).filter((id) => id !== object.id).map((id) => objectById.get(id)).filter(Boolean);
      const sameLengthString = refs.find((candidate) => candidate.kind === 'string' && candidate.size === object.size);
      if (sameLengthString) { score += 15; evidence.push(`长度 ${object.size} 与比较常量 ${sameLengthString.name} 一致`); }
    }
    const nonPrintable = object.bytes.filter((value) => value < 0x20 || value > 0x7e).length / object.bytes.length;
    if (nonPrintable >= 0.3) { score += 10; evidence.push(`不可打印字节占比 ${(nonPrintable * 100).toFixed(1)}%`); }
    if (isSequential(object.bytes)) { score -= 20; evidence.push('规则递增序列，更像索引/置换表（负证据）'); }
    score = Math.max(0, Math.min(100, score));
    if (score >= 45) {
      const item = { object: object.id, objectName: object.name, semantic: 'possible_ciphertext_or_key_material', label: 'Possible ciphertext / key material', confidence: score / 100, score, evidence };
      object.semanticSuggestions.push(item);
      candidates.push(item);
    }
  }
  for (const object of objects) {
    if (object.kind !== 'string') continue;
    const cmp = comparisons.find((operation) => collectObjectRefs(operation).includes(object.id));
    if (!cmp) continue;
    const item = { object: object.id, objectName: object.name, semantic: 'comparison_constant', label: 'Comparison constant', confidence: 0.9, score: 90, evidence: ['字符串常量参与 CMP / 条件分支'] };
    object.semanticSuggestions.push(item);
    candidates.push(item);
  }
  return candidates.sort((a, b) => b.score - a.score || a.objectName.localeCompare(b.objectName));
}

function bytesForObject(object) {
  return object?.bytes ? Uint8Array.from(object.bytes) : null;
}

function deriveXorPreview(left, right) {
  if (!left || !right || left.length !== right.length || left.length > 4096) return null;
  const out = new Uint8Array(left.length);
  for (let index = 0; index < out.length; index += 1) out[index] = left[index] ^ right[index];
  return { bytes: [...out], hex: bytesHex([...out]), ascii: escapeAscii([...out]) };
}

function recoverableRelations(objects, operations) {
  const objectById = new Map(objects.map((object) => [object.id, object]));
  const results = [];
  for (const compare of operations.filter((operation) => operation.op === 'CMP_EQ' || operation.op === 'CMP_NE')) {
    const sides = [compare.args[0], compare.args[1]];
    for (let sideIndex = 0; sideIndex < 2; sideIndex += 1) {
      const known = sides[sideIndex];
      const transform = sides[1 - sideIndex];
      if (!known || !transform || known.kind !== 'index' || transform.kind !== 'op' || transform.op !== 'XOR' || transform.args.length !== 2) continue;
      if (!transform.args.every((arg) => arg.kind === 'index')) continue;
      const a = objectById.get(known.object);
      const b = objectById.get(transform.args[0].object);
      const c = objectById.get(transform.args[1].object);
      if (!a || !b || !c) continue;
      const index = known.index || transform.args[0].index || transform.args[1].index || 'i';
      const item = {
        id: `recover_${results.length + 1}`,
        operation: 'XOR',
        location: compare.location,
        objects: [a.id, b.id, c.id],
        equation: `${a.name}[${index}] = ${b.name}[${index}] XOR ${c.name}[${index}]`,
        derivations: [
          `${a.name} = ${b.name} XOR ${c.name}`,
          `${b.name} = ${a.name} XOR ${c.name}`,
          `${c.name} = ${a.name} XOR ${b.name}`
        ],
        verification: null
      };
      const aBytes = bytesForObject(a);
      const bBytes = bytesForObject(b);
      const cBytes = bytesForObject(c);
      if (aBytes && bBytes && cBytes && aBytes.length === bBytes.length && bBytes.length === cBytes.length) {
        const derived = deriveXorPreview(aBytes, bBytes);
        let mismatches = 0;
        for (let offset = 0; offset < cBytes.length; offset += 1) if (derived.bytes[offset] !== cBytes[offset]) mismatches += 1;
        item.verification = { checkedBytes: cBytes.length, mismatches, holdsForKnownBytes: mismatches === 0, derivedOperand: c.id, derivedOperandName: c.name, derivedHex: derived.hex, derivedAscii: derived.ascii };
      } else {
        const pairs = [
          [aBytes, bBytes, c, `${c.name} = ${a.name} XOR ${b.name}`],
          [aBytes, cBytes, b, `${b.name} = ${a.name} XOR ${c.name}`],
          [bBytes, cBytes, a, `${a.name} = ${b.name} XOR ${c.name}`]
        ];
        const pair = pairs.find(([left, right]) => left && right && left.length === right.length);
        if (pair) {
          const derived = deriveXorPreview(pair[0], pair[1]);
          item.verification = { checkedBytes: derived.bytes.length, mismatches: null, holdsForKnownBytes: null, derivedOperand: pair[2].id, derivedOperandName: pair[2].name, derivation: pair[3], derivedHex: derived.hex, derivedAscii: derived.ascii };
        }
      }
      results.push(item);
    }
  }
  return results;
}

function publicObject(object) {
  const { addressBig, cells, bytes, ...rest } = object;
  return {
    ...rest,
    bytesHex: object.bytesHex,
    ascii: object.ascii,
    cellEvidence: cells.map((cell) => ({ address: cell.address, directive: cell.directive, values: cell.tokens.map((token) => token.raw), line: cell.lineNumber, comment: cell.comment || null }))
  };
}

function analyzeBinaryDataListing(input) {
  const text = String(input || '');
  if (!text.trim()) throw new Error('请输入 IDA / Ghidra textual listing');
  if (text.length > MAX_INPUT_CHARS) throw new Error(`listing 超过 ${MAX_INPUT_CHARS} 字符上限`);
  const rawLines = text.split(/\r?\n/);
  const lines = rawLines.map((raw, index) => parseListingLine(raw, index + 1));
  const sections = buildSections(lines);
  const cells = lines.map(parseDataCell).filter(Boolean);
  const objects = buildObjects(cells);
  const relations = [];
  const relationSeen = new Set();
  enrichPointersAndSlices(objects, relations, relationSeen);
  addXrefRelations(objects, relations, relationSeen);
  const operations = analyzeExpressions(lines, objects, relations, relationSeen);
  const semantics = semanticCandidates(objects, operations, relations);
  const recoverable = recoverableRelations(objects, operations);
  const objectById = new Map(objects.map((object) => [object.id, object]));
  for (const section of sections) section.objectIds = objects.filter((object) => object.section === section.name).map((object) => object.id);
  const expressionSummary = operations.map((operation) => ({ id: operation.id, op: operation.op, location: operation.location, line: operation.line, pseudo: expressionText(operation, objectById), branch: operation.branch || null }));
  const importantRelations = relations.filter((relation) => ['POINTS_TO','XORS_WITH','COMPARES_WITH','LENGTH_OF','READS'].includes(relation.type));
  return {
    schema: 'newcyber.binary-data-graph.v1',
    source: { kind: 'textual-disassembly', lineCount: rawLines.length, parser: 'deterministic-v0.1' },
    summary: {
      sections: sections.length,
      objects: objects.length,
      operations: operations.length,
      relations: relations.length,
      importantRelations: importantRelations.length,
      semanticCandidates: semantics.length,
      recoverableRelations: recoverable.length
    },
    sections,
    objects: objects.map(publicObject),
    operations: expressionSummary,
    relations,
    semanticCandidates: semantics,
    recoverableRelations: recoverable,
    notes: [
      'Batch25 V0.1 只解析 textual disassembly/listing；不会执行二进制、脚本或反编译器插件。',
      'Object/Relation/Expression 属于确定性结构恢复；Semantic suggestion 始终携带 confidence/evidence，不写回事实层。',
      '当前表达式恢复聚焦常见 x86/x64 MOV/LEA/索引访问 + XOR/ADD/SUB/ROL/ROR/NOT + CMP/Jcc 验证链；跨基本块、phi、复杂别名仍标为未覆盖。'
    ]
  };
}

module.exports = {
  analyzeBinaryDataListing,
  parseListingLine,
  parseDataCell,
  expressionText
};
