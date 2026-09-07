const EIP1967_SLOTS = Object.freeze({
  implementation: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
  admin: '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
  beacon: '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
});

const PROXY_SELECTORS = Object.freeze({
  '0x3659cfe6': 'upgradeTo(address)',
  '0x4f1ef286': 'upgradeToAndCall(address,bytes)',
  '0x52d1902d': 'proxiableUUID()',
  '0xf851a440': 'admin()',
  '0x5c60da1b': 'implementation()',
  '0x8f283970': 'changeAdmin(address)'
});

function normalizeBytecode(input) {
  return String(input || '').trim().replace(/^0x/i, '').replace(/\s+/g, '').toLowerCase();
}

function detectEip1167(input) {
  const hex = normalizeBytecode(input);
  if (!hex || /[^0-9a-f]/.test(hex)) return null;
  const pattern = /363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3/g;
  const match = pattern.exec(hex);
  if (!match) return null;
  return {
    standard: 'EIP-1167',
    implementation: `0x${match[1]}`,
    runtimeOffsetBytes: match.index / 2,
    runtimeLengthBytes: match[0].length / 2,
    confidence: 'high',
    evidence: match[0]
  };
}

function slotReferences(instructions = []) {
  return Object.entries(EIP1967_SLOTS).map(([kind, slot]) => {
    const pushes = instructions.filter((item) => item.name === 'PUSH32' && String(item.immediate || '').toLowerCase() === slot);
    return {
      kind,
      slot,
      pushPcs: pushes.map((item) => item.pc),
      referenced: pushes.length > 0
    };
  });
}

function flowMatchesSlot(flow, slot) {
  return String(flow?.slotExpr || '').toLowerCase().includes(slot)
    || String(flow?.valueExpr || '').toLowerCase().includes(slot);
}

function callMatchesSlot(call, slot) {
  return String(call?.toExpr || '').toLowerCase().includes(slot);
}

function selectorSurfaces(selectorCandidates = []) {
  return selectorCandidates
    .filter((item) => item.looksLikeDispatcher && PROXY_SELECTORS[item.selector])
    .map((item) => ({
      selector: item.selector,
      signature: PROXY_SELECTORS[item.selector],
      destination: item.destination,
      pc: item.pc
    }));
}

function analyzeEvmProxy(input, runtimeAnalysis = {}) {
  const minimalProxy = detectEip1167(input);
  const references = slotReferences(runtimeAnalysis.instructions || []);
  const storageFlows = runtimeAnalysis.dataFlow?.storageFlows || [];
  const calls = runtimeAnalysis.dataFlow?.calls || [];
  const delegateCalls = calls.filter((item) => item.type === 'DELEGATECALL');

  const slots = references.map((reference) => {
    const reads = storageFlows.filter((item) => item.type === 'SLOAD' && flowMatchesSlot(item, reference.slot));
    const writes = storageFlows.filter((item) => item.type === 'SSTORE' && flowMatchesSlot(item, reference.slot));
    const delegateTargets = delegateCalls.filter((item) => callMatchesSlot(item, reference.slot));
    return {
      ...reference,
      sloadPcs: reads.map((item) => item.pc),
      sstorePcs: writes.map((item) => item.pc),
      delegateCallPcs: delegateTargets.map((item) => item.pc),
      readIntoDelegateCall: delegateTargets.length > 0,
      writes: writes.map((item) => ({
        pc: item.pc,
        valueExpr: item.valueExpr,
        selectorContext: item.selectorContext || []
      }))
    };
  });

  const implementationSlot = slots.find((item) => item.kind === 'implementation');
  const adminSlot = slots.find((item) => item.kind === 'admin');
  const beaconSlot = slots.find((item) => item.kind === 'beacon');
  const surfaces = selectorSurfaces(runtimeAnalysis.selectorCandidates || []);
  const upgradeWrites = slots.flatMap((slot) => slot.writes.map((write) => ({
    slotKind: slot.kind,
    slot: slot.slot,
    ...write,
    upgradeSelectorContext: (write.selectorContext || []).filter((ctx) => PROXY_SELECTORS[ctx.selector]).map((ctx) => ({
      selector: ctx.selector,
      signature: PROXY_SELECTORS[ctx.selector]
    }))
  }))).filter((item) => item.slotKind === 'implementation' || item.slotKind === 'admin' || item.slotKind === 'beacon');

  let classification = null;
  let confidence = 'none';
  if (minimalProxy) {
    classification = 'eip-1167-minimal-proxy';
    confidence = 'high';
  } else if (implementationSlot?.readIntoDelegateCall) {
    classification = 'eip-1967-direct-proxy';
    confidence = 'high';
  } else if (beaconSlot?.referenced && delegateCalls.length) {
    classification = 'eip-1967-beacon-proxy-candidate';
    confidence = 'medium';
  } else if ((implementationSlot?.referenced || adminSlot?.referenced || beaconSlot?.referenced) && delegateCalls.length) {
    classification = 'eip-1967-proxy-candidate';
    confidence = 'medium';
  } else if (delegateCalls.length) {
    classification = 'generic-delegate-proxy-candidate';
    confidence = 'low';
  }

  const findings = [];
  if (minimalProxy) findings.push({
    severity: 'info',
    id: 'eip1167-implementation',
    title: 'EIP-1167 minimal proxy implementation',
    evidence: minimalProxy.implementation
  });
  if (implementationSlot?.readIntoDelegateCall) findings.push({
    severity: 'info',
    id: 'eip1967-implementation-delegate-link',
    title: 'EIP-1967 implementation slot 流入 DELEGATECALL',
    evidence: `${implementationSlot.slot} -> DELEGATECALL@${implementationSlot.delegateCallPcs.join(',')}`
  });
  if (upgradeWrites.length) findings.push({
    severity: 'medium',
    id: 'proxy-upgrade-storage-write',
    title: '代理管理槽存在写入路径',
    evidence: upgradeWrites.map((item) => `${item.slotKind}@pc${item.pc}: ${item.valueExpr}`).join('; ')
  });

  return {
    classification,
    confidence,
    isProxyCandidate: Boolean(classification),
    minimalProxy,
    slots,
    delegateCalls: delegateCalls.map((item) => ({ pc: item.pc, blockPc: item.blockPc, toExpr: item.toExpr, selectorContext: item.selectorContext || [] })),
    selectorSurfaces: surfaces,
    upgradeWrites,
    findings,
    notes: [
      'EIP-1167 只在 canonical runtime 字节序列完整匹配时给 high confidence，并直接恢复内嵌 implementation 地址。',
      'EIP-1967 high confidence 要求 implementation slot 的 SLOAD 证据实际流入同 basic block 的 DELEGATECALL target；只出现槽常量不等价于代理成立。',
      'beacon slot 只能证明 beacon 代理候选；真实 implementation 还需要读取 beacon 并调用 implementation()，本离线 runtime 分析不会伪造链上返回值。',
      '代理/升级入口本身不是漏洞；storage write、selector 与权限校验仍需结合源码、反编译或交易上下文复核。'
    ]
  };
}

module.exports = {
  analyzeEvmProxy,
  detectEip1167,
  slotReferences,
  EIP1967_SLOTS,
  PROXY_SELECTORS
};
