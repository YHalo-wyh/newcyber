const { evmDisasm } = require('./toolbox');

const KNOWN_SELECTORS = new Map([
  ['0xa9059cbb', 'transfer(address,uint256)'],
  ['0x23b872dd', 'transferFrom(address,address,uint256)'],
  ['0x095ea7b3', 'approve(address,uint256)'],
  ['0x70a08231', 'balanceOf(address)'],
  ['0xdd62ed3e', 'allowance(address,address)'],
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

function analyzeEvmRuntime(input) {
  const base = evmDisasm(input);
  const selectorCandidates = extractSelectorCandidates(base.instructions);
  const dispatcherSelectors = selectorCandidates.filter((item) => item.looksLikeDispatcher);
  const storage = extractStorageAccesses(base.instructions);

  return {
    ...base,
    selectorCandidates,
    dispatcherSelectors,
    storage,
    notes: [
      'PUSH4 selector 只有在附近出现 EQ → JUMPI 时才标记为 dispatcher 候选；其他 PUSH4 可能只是普通常量。',
      'storage 只把紧邻 SLOAD/SSTORE 的 PUSH 标成 high confidence；复杂栈变换只给同 basic block 的候选，不冒充完整符号执行。',
      '没有 ABI/源码时，可先按 selector → jump destination 划分入口，再结合 storage access、反编译/调用轨迹恢复隐藏业务函数。',
      '已知签名表只覆盖少量常见 ERC/Ownable selector；未知 selector 不代表异常。'
    ]
  };
}

module.exports = { analyzeEvmRuntime, extractSelectorCandidates, extractStorageAccesses, KNOWN_SELECTORS };
