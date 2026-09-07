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

function analyzeEvmRuntime(input) {
  const base = evmDisasm(input);
  const selectorCandidates = extractSelectorCandidates(base.instructions);
  const dispatcherSelectors = selectorCandidates.filter((item) => item.looksLikeDispatcher);

  return {
    ...base,
    selectorCandidates,
    dispatcherSelectors,
    notes: [
      'PUSH4 selector 只有在附近出现 EQ → JUMPI 时才标记为 dispatcher 候选；其他 PUSH4 可能只是普通常量。',
      '没有 ABI/源码时，可先按 selector → jump destination 划分入口，再结合反编译/调用轨迹恢复隐藏业务函数。',
      '已知签名表只覆盖少量常见 ERC/Ownable selector；未知 selector 不代表异常。'
    ]
  };
}

module.exports = { analyzeEvmRuntime, extractSelectorCandidates, KNOWN_SELECTORS };
