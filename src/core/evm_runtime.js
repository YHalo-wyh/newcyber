const { evmDisasm } = require('./toolbox');

const KNOWN_SELECTORS = new Map([
  ['0xa9059cbb', 'transfer(address,uint256)'],
  ['0x23b872dd', 'transferFrom(address,address,uint256)'],
  ['0x095ea7b3', 'approve(address,uint256)'],
  ['0x70a08231', 'balanceOf(address)'],
  ['0xdd62ed3e', 'allowance(address,address,uint256)'],
  ['0x18160ddd', 'totalSupply()'],
  ['0x06fdde03', 'name()'],
  ['0x95d89b41', 'symbol()'],
  ['0x313ce567', 'decimals()'],
  ['0x8da5cb5b', 'owner()']
]);

function normalizeImmediate(value) {
  return typeof value === 'string' ? value.toLowerCase() : null;
}

function extractSelectorCandidates(instructions) {
  const candidates = [];
  const seen = new Set();

  for (let i = 0; i < (instructions || []).length; i += 1) {
    const item = instructions[i];
    if (item.name !== 'PUSH4' || !item.immediate) continue;
    const selector = normalizeImmediate(item.immediate);
    if (!/^0x[0-9a-f]{8}$/.test(selector) || seen.has(selector)) continue;

    const window = instructions.slice(i + 1, i + 7);
    const eqIndex = window.findIndex((entry) => entry.name === 'EQ');
    const jumpiIndex = window.findIndex((entry) => entry.name === 'JUMPI');
    const looksLikeDispatcher = eqIndex >= 0 && jumpiIndex > eqIndex;

    let destination = null;
    if (looksLikeDispatcher) {
      const beforeJump = window.slice(eqIndex + 1, jumpiIndex).find((entry) => /^PUSH(?:1|2|3|4)$/.test(entry.name) && entry.immediate);
      if (beforeJump) destination = beforeJump.immediate;
    }

    seen.add(selector);
    candidates.push({
      pc: item.pc,
      selector,
      knownSignature: KNOWN_SELECTORS.get(selector) || null,
      looksLikeDispatcher,
      destination
    });
  }

  return candidates.sort((a, b) => Number(b.looksLikeDispatcher) - Number(a.looksLikeDispatcher) || a.pc - b.pc);
}

function smallPushValue(item) {
  if (!item || !/^PUSH(?:1|2|3|4)$/.test(item.name) || !/^0x[0-9a-f]+$/i.test(item.immediate || '')) return null;
  const value = BigInt(item.immediate);
  if (value > 0xffffffffn) return null;
  return `0x${value.toString(16)}`;
}

function basicBlockStart(instructions, index) {
  for (let i = index - 1; i >= 0; i -= 1) {
    const name = instructions[i].name;
    if (name === 'JUMPDEST' || ['JUMP', 'JUMPI', 'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT'].includes(name)) return i + 1;
  }
  return 0;
}

function extractStorageAccesses(instructions) {
  const accesses = [];
  const slots = new Map();
  const addSlot = (slot, type, confidence, pc) => {
    if (!slot) return;
    if (!slots.has(slot)) slots.set(slot, { slot, reads: 0, writes: 0, highConfidenceReads: 0, evidencePcs: [] });
    const item = slots.get(slot);
    if (type === 'SLOAD') item.reads += 1;
    else item.writes += 1;
    if (type === 'SLOAD' && confidence === 'high') item.highConfidenceReads += 1;
    if (item.evidencePcs.length < 20) item.evidencePcs.push(pc);
  };

  for (let index = 0; index < (instructions || []).length; index += 1) {
    const item = instructions[index];
    if (item.name !== 'SLOAD' && item.name !== 'SSTORE') continue;
    const blockStart = basicBlockStart(instructions, index);
    const start = Math.max(blockStart, index - 16);
    const recent = instructions.slice(start, index);
    const previous = instructions[index - 1];
    const direct = smallPushValue(previous);
    const candidates = [];

    if (direct) candidates.push({ slot: direct, confidence: 'high', sourcePc: previous.pc, reason: 'immediate-push' });

    for (let j = recent.length - 1; j >= 0 && candidates.length < 5; j -= 1) {
      const candidate = smallPushValue(recent[j]);
      if (!candidate || candidates.some((entry) => entry.slot === candidate)) continue;
      const next = recent[j + 1];
      const confidence = next && /^DUP\d+$/.test(next.name) ? 'medium' : 'low';
      candidates.push({ slot: candidate, confidence, sourcePc: recent[j].pc, reason: confidence === 'medium' ? 'push-then-dup-in-block' : 'nearby-push-in-block' });
    }

    for (const candidate of candidates) addSlot(candidate.slot, item.name, candidate.confidence, item.pc);
    accesses.push({
      pc: item.pc,
      type: item.name,
      directSlot: direct,
      slotCandidates: candidates
    });
  }

  return {
    accesses,
    slots: [...slots.values()].sort((a, b) => {
      const left = BigInt(a.slot);
      const right = BigInt(b.slot);
      return left < right ? -1 : left > right ? 1 : 0;
    }),
    reads: accesses.filter((item) => item.type === 'SLOAD').length,
    writes: accesses.filter((item) => item.type === 'SSTORE').length
  };
}

function sym(expr, pc = null, sources = []) {
  return { expr: String(expr || 'unknown').slice(0, 180), pc, sources: [...new Set(sources)].slice(0, 24) };
}

function unknown(pc = null) {
  return sym('unknown', pc);
}

function directNumber(value) {
  if (!value || !/^0x[0-9a-f]+$/i.test(value.expr || '')) return null;
  const number = Number(BigInt(value.expr));
  return Number.isSafeInteger(number) ? number : null;
}

function combine(name, left, right, pc, reverse = false) {
  const a = reverse ? right : left;
  const b = reverse ? left : right;
  return sym(`${name}(${a.expr},${b.expr})`, pc, [...a.sources, ...b.sources]);
}

function selectorContextForBlock(blockPc, dispatcherSelectors) {
  const hex = `0x${Number(blockPc).toString(16)}`;
  const matches = dispatcherSelectors.filter((item) => item.destination && `0x${BigInt(item.destination).toString(16)}` === hex);
  return matches.map((item) => ({ selector: item.selector, knownSignature: item.knownSignature }));
}

function extractLocalDataFlows(instructions, dispatcherSelectors = []) {
  const stack = [];
  let memoryWrites = [];
  let currentBlockPc = 0;
  const calldataLoads = [];
  const storageFlows = [];
  const calls = [];
  const memoryEvidence = [];
  const terminations = new Set(['JUMP', 'JUMPI', 'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT']);

  const pop = (pc) => stack.length ? stack.pop() : unknown(pc);
  const push = (value) => stack.push(value || unknown());
  const resetBlock = (pc) => {
    stack.length = 0;
    memoryWrites = [];
    currentBlockPc = pc;
  };

  for (const item of instructions || []) {
    const name = item.name;
    if (name === 'JUMPDEST') {
      resetBlock(item.pc);
      continue;
    }

    if (/^PUSH\d+$/.test(name)) {
      push(sym(item.immediate || '0x0', item.pc, [`push@${item.pc}`]));
      continue;
    }
    if (/^DUP\d+$/.test(name)) {
      const depth = Number(name.slice(3));
      push(stack.length >= depth ? stack[stack.length - depth] : unknown(item.pc));
      continue;
    }
    if (/^SWAP\d+$/.test(name)) {
      const depth = Number(name.slice(4));
      const top = stack.length - 1;
      const other = top - depth;
      if (top >= 0 && other >= 0) [stack[top], stack[other]] = [stack[other], stack[top]];
      continue;
    }
    if (name === 'POP') { pop(item.pc); continue; }

    if (name === 'CALLDATALOAD') {
      const offset = pop(item.pc);
      const value = sym(`calldata[${offset.expr}]`, item.pc, [...offset.sources, `calldataload@${item.pc}`]);
      calldataLoads.push({ pc: item.pc, blockPc: currentBlockPc, offsetExpr: offset.expr, directOffset: directNumber(offset), selectorContext: selectorContextForBlock(currentBlockPc, dispatcherSelectors) });
      push(value);
      continue;
    }
    if (name === 'CALLDATASIZE') { push(sym('calldatasize', item.pc, [`calldatasize@${item.pc}`])); continue; }
    if (name === 'CALLER') { push(sym('caller', item.pc, [`caller@${item.pc}`])); continue; }
    if (name === 'ORIGIN') { push(sym('origin', item.pc, [`origin@${item.pc}`])); continue; }
    if (name === 'CALLVALUE') { push(sym('callvalue', item.pc, [`callvalue@${item.pc}`])); continue; }
    if (name === 'ADDRESS') { push(sym('address(this)', item.pc, [`address@${item.pc}`])); continue; }

    if (name === 'SLOAD') {
      const slot = pop(item.pc);
      const value = sym(`storage[${slot.expr}]`, item.pc, [...slot.sources, `sload@${item.pc}`]);
      storageFlows.push({
        pc: item.pc,
        blockPc: currentBlockPc,
        type: 'SLOAD',
        slotExpr: slot.expr,
        directSlot: directNumber(slot),
        valueExpr: value.expr,
        sources: value.sources,
        selectorContext: selectorContextForBlock(currentBlockPc, dispatcherSelectors)
      });
      push(value);
      continue;
    }
    if (name === 'SSTORE') {
      const slot = pop(item.pc);
      const value = pop(item.pc);
      storageFlows.push({
        pc: item.pc,
        blockPc: currentBlockPc,
        type: 'SSTORE',
        slotExpr: slot.expr,
        directSlot: directNumber(slot),
        valueExpr: value.expr,
        sources: [...new Set([...slot.sources, ...value.sources])],
        selectorContext: selectorContextForBlock(currentBlockPc, dispatcherSelectors)
      });
      continue;
    }

    if (name === 'MSTORE' || name === 'MSTORE8') {
      const offset = pop(item.pc);
      const value = pop(item.pc);
      const directOffset = directNumber(offset);
      const length = name === 'MSTORE8' ? 1 : 32;
      if (directOffset != null) {
        const evidence = { pc: item.pc, blockPc: currentBlockPc, offset: directOffset, length, expr: value.expr, sources: value.sources, kind: name };
        memoryWrites.push(evidence);
        memoryEvidence.push(evidence);
      }
      continue;
    }
    if (name === 'CALLDATACOPY') {
      const memoryOffset = pop(item.pc);
      const dataOffset = pop(item.pc);
      const lengthValue = pop(item.pc);
      const directMemoryOffset = directNumber(memoryOffset);
      const directLength = directNumber(lengthValue);
      if (directMemoryOffset != null && directLength != null && directLength >= 0 && directLength <= 0x100000) {
        const evidence = {
          pc: item.pc,
          blockPc: currentBlockPc,
          offset: directMemoryOffset,
          length: directLength,
          expr: `calldata[${dataOffset.expr}:${lengthValue.expr}]`,
          sources: [...new Set([...dataOffset.sources, ...lengthValue.sources, `calldatacopy@${item.pc}`])],
          kind: 'CALLDATACOPY'
        };
        memoryWrites.push(evidence);
        memoryEvidence.push(evidence);
      }
      continue;
    }
    if (name === 'MLOAD') {
      const offset = pop(item.pc);
      const directOffset = directNumber(offset);
      const source = directOffset == null ? null : [...memoryWrites].reverse().find((write) => write.offset === directOffset && write.length >= 32);
      push(source ? sym(`memory[0x${directOffset.toString(16)}]=${source.expr}`, item.pc, [...source.sources, `mload@${item.pc}`]) : sym(`memory[${offset.expr}]`, item.pc, [...offset.sources, `mload@${item.pc}`]));
      continue;
    }

    if (name === 'CALL') {
      const gas = pop(item.pc); const to = pop(item.pc); const value = pop(item.pc);
      const inputOffset = pop(item.pc); const inputSize = pop(item.pc); const outputOffset = pop(item.pc); const outputSize = pop(item.pc);
      const directInputOffset = directNumber(inputOffset);
      const directInputSize = directNumber(inputSize);
      const inputSources = directInputOffset == null ? [] : memoryWrites.filter((write) => {
        const callEnd = directInputOffset + (directInputSize || 0);
        const writeEnd = write.offset + write.length;
        return write.offset < callEnd && writeEnd > directInputOffset;
      });
      calls.push({
        pc: item.pc,
        blockPc: currentBlockPc,
        type: 'CALL',
        toExpr: to.expr,
        valueExpr: value.expr,
        gasExpr: gas.expr,
        inputOffsetExpr: inputOffset.expr,
        inputSizeExpr: inputSize.expr,
        inputSources: inputSources.map((source) => ({ pc: source.pc, kind: source.kind, expr: source.expr })),
        selectorContext: selectorContextForBlock(currentBlockPc, dispatcherSelectors)
      });
      push(sym(`call_result@${item.pc}`, item.pc, [`call@${item.pc}`]));
      void outputOffset; void outputSize;
      continue;
    }
    if (name === 'DELEGATECALL' || name === 'STATICCALL') {
      const gas = pop(item.pc); const to = pop(item.pc);
      const inputOffset = pop(item.pc); const inputSize = pop(item.pc); const outputOffset = pop(item.pc); const outputSize = pop(item.pc);
      const directInputOffset = directNumber(inputOffset);
      const directInputSize = directNumber(inputSize);
      const inputSources = directInputOffset == null ? [] : memoryWrites.filter((write) => {
        const callEnd = directInputOffset + (directInputSize || 0);
        const writeEnd = write.offset + write.length;
        return write.offset < callEnd && writeEnd > directInputOffset;
      });
      calls.push({
        pc: item.pc,
        blockPc: currentBlockPc,
        type: name,
        toExpr: to.expr,
        valueExpr: null,
        gasExpr: gas.expr,
        inputOffsetExpr: inputOffset.expr,
        inputSizeExpr: inputSize.expr,
        inputSources: inputSources.map((source) => ({ pc: source.pc, kind: source.kind, expr: source.expr })),
        selectorContext: selectorContextForBlock(currentBlockPc, dispatcherSelectors)
      });
      push(sym(`${name.toLowerCase()}_result@${item.pc}`, item.pc, [`${name.toLowerCase()}@${item.pc}`]));
      void outputOffset; void outputSize;
      continue;
    }

    const binary = new Set(['ADD', 'MUL', 'DIV', 'SDIV', 'MOD', 'SMOD', 'EXP', 'SIGNEXTEND', 'LT', 'GT', 'SLT', 'SGT', 'EQ', 'AND', 'OR', 'XOR', 'BYTE', 'SHL', 'SHR', 'SAR']);
    if (binary.has(name)) {
      const a = pop(item.pc); const b = pop(item.pc);
      push(combine(name.toLowerCase(), a, b, item.pc));
      continue;
    }
    if (name === 'SUB') {
      const a = pop(item.pc); const b = pop(item.pc);
      push(combine('sub', a, b, item.pc, true));
      continue;
    }
    if (name === 'ISZERO' || name === 'NOT') {
      const value = pop(item.pc);
      push(sym(`${name.toLowerCase()}(${value.expr})`, item.pc, value.sources));
      continue;
    }
    if (name === 'SHA3' || name === 'KECCAK256') {
      const offset = pop(item.pc); const size = pop(item.pc);
      push(sym(`keccak(memory[${offset.expr}:${size.expr}])`, item.pc, [...offset.sources, ...size.sources, `keccak@${item.pc}`]));
      continue;
    }

    if (terminations.has(name)) {
      resetBlock(item.pc + 1);
      continue;
    }
  }

  return {
    calldataLoads,
    storageFlows,
    calls,
    memoryEvidence,
    linkedStorageWrites: storageFlows.filter((item) => item.type === 'SSTORE' && /calldata\[|storage\[|caller|callvalue/.test(item.valueExpr)).length,
    linkedCalls: calls.filter((item) => /storage\[|calldata\[|caller|callvalue/.test(`${item.toExpr} ${item.valueExpr || ''} ${item.inputSources.map((source) => source.expr).join(' ')}`)).length,
    notes: [
      '局部 dataFlow 在 basic block 边界清空栈和 memory 证据，不跨 JUMP/JUMPI 做路径合并，因此宁可 unknown 也不伪造跨 CFG 数据流。',
      'CALL inputSources 只关联同 basic block 内与 input memory range 重叠的 MSTORE/CALLDATACOPY。',
      'mapping/dynamic array 的 keccak slot 只保留表达式，不自动声称恢复了 Solidity storage layout。'
    ]
  };
}

function analyzeEvmRuntime(input) {
  const base = evmDisasm(input);
  const selectorCandidates = extractSelectorCandidates(base.instructions);
  const dispatcherSelectors = selectorCandidates.filter((item) => item.looksLikeDispatcher);
  const storage = extractStorageAccesses(base.instructions);
  const dataFlow = extractLocalDataFlows(base.instructions, dispatcherSelectors);

  return {
    ...base,
    selectorCandidates,
    dispatcherSelectors,
    storage,
    dataFlow,
    notes: [
      'PUSH4 selector 只有在附近出现 EQ → JUMPI 时才标记为 dispatcher 候选；其他 PUSH4 可能只是普通常量。',
      'storage 只把紧邻 SLOAD/SSTORE 的 PUSH 标成 high confidence；复杂栈变换只给同 basic block 的候选，不冒充完整符号执行。',
      'dataFlow 进一步做单 basic block 的 calldata/storage/memory/CALL 局部符号传播；跨控制流边界不猜。',
      '没有 ABI/源码时，可先按 selector → jump destination 划分入口，再结合 storage/dataFlow、反编译与调用轨迹恢复隐藏业务函数。',
      '已知签名表只覆盖少量常见 ERC/Ownable selector；未知 selector 不代表异常。'
    ]
  };
}

module.exports = {
  analyzeEvmRuntime,
  extractSelectorCandidates,
  extractStorageAccesses,
  extractLocalDataFlows,
  KNOWN_SELECTORS
};
