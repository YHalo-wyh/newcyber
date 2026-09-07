function lineNumberAt(source, index) {
  return source.slice(0, index).split(/\r?\n/).length;
}

function evidence(source, index, length = 220) {
  const start = Math.max(0, index - 70);
  return source.slice(start, Math.min(source.length, index + length)).trim();
}

function escapeRegExp(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function findBlockEnd(code, openBrace) {
  if (openBrace < 0 || code[openBrace] !== '{') return -1;
  let depth = 0;
  for (let i = openBrace; i < code.length; i += 1) {
    if (code[i] === '{') depth += 1;
    else if (code[i] === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function extractFunctions(code) {
  const functions = [];
  const re = /function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*([^;{]*)\{/g;
  let match;
  while ((match = re.exec(code))) {
    const openBrace = code.indexOf('{', match.index + match[0].length - 1);
    const closeBrace = findBlockEnd(code, openBrace);
    if (closeBrace < 0) continue;
    functions.push({
      name: match[1],
      params: match[2],
      modifiers: match[3],
      index: match.index,
      openBrace,
      closeBrace,
      body: code.slice(openBrace + 1, closeBrace)
    });
  }
  return functions;
}

function countMethodCalls(body, expression) {
  const escaped = escapeRegExp(expression);
  const re = new RegExp(`\\b${escaped}\\.([A-Za-z_$][\\w$]*)\\s*\\(`, 'g');
  const methods = [];
  let match;
  while ((match = re.exec(body))) methods.push(match[1]);
  return methods;
}

function hasTrustValidation(body, expression) {
  const escaped = escapeRegExp(expression);
  const patterns = [
    new RegExp(`(?:require|if)\\s*\\([^)]*${escaped}[^)]*(?:trusted|allow|white|registry|approved|known|codehash)`, 'i'),
    new RegExp(`(?:trusted|allowed|whitelist|approved|registry)\\s*\\[\\s*${escaped}\\s*\\]`, 'i'),
    new RegExp(`extcodehash\\s*\\([^)]*${escaped}`, 'i'),
    new RegExp(`${escaped}\\s*==\\s*[A-Za-z_$][\\w$]*(?:TRUSTED|ALLOWED|APPROVED|REGISTRY|MANAGER|FACTORY)[A-Za-z0-9_$]*`, 'i'),
    new RegExp(`[A-Za-z_$][\\w$]*(?:TRUSTED|ALLOWED|APPROVED|REGISTRY|MANAGER|FACTORY)[A-Za-z0-9_$]*\\s*==\\s*${escaped}`, 'i')
  ];
  return patterns.some((pattern) => pattern.test(body));
}

function dependencyFinding(source, fn, dependency) {
  const methods = [...new Set(countMethodCalls(fn.body, dependency.expression))];
  if (!methods.length) return null;
  const validated = hasTrustValidation(fn.body, dependency.expression);
  const assetSensitive = /\b(?:safeTransferFrom|transferFrom|transfer|mint|burn|collect|approve|delegatecall|call)\s*\(/.test(fn.body);
  const label = dependency.member
    ? `${dependency.parameter}.${dependency.member}`
    : dependency.parameter;
  return {
    id: 'external-contract-trust-boundary',
    severity: validated ? 'low' : 'medium',
    title: validated ? '外部合约依赖参与业务逻辑（存在来源校验迹象）' : '调用者可控外部合约进入业务信任边界',
    line: lineNumberAt(source, fn.index),
    evidence: evidence(source, fn.index),
    message: `${fn.name} 从调用输入取得外部依赖 ${label} 并调用 ${methods.slice(0, 6).join(', ')}。${validated ? '检测到 allowlist/registry/固定地址/codehash 类来源校验迹象，仍需确认校验覆盖真实实现。' : '未发现明显来源约束；攻击者可实现兼容 ABI 伪造返回值或回调行为，需追踪这些结果是否影响资产、价格、权限、池地址或后续调用。'}`,
    details: {
      functionName: fn.name,
      parameter: dependency.parameter,
      member: dependency.member || null,
      dependencyExpression: dependency.expression,
      interfaceType: dependency.type || null,
      methodCalls: methods,
      validationEvidence: validated,
      assetSensitive
    }
  };
}

function auditExternalContractTrust(source, code, functions) {
  const findings = [];
  for (const fn of functions) {
    if (!/\b(?:external|public)\b/.test(fn.modifiers)) continue;

    const dependencies = [];
    const directRe = /\b(I[A-Z][A-Za-z0-9_$]*)\s+(?:(?:calldata|memory|storage)\s+)?([A-Za-z_$][\w$]*)/g;
    let param;
    while ((param = directRe.exec(fn.params))) {
      dependencies.push({ type: param[1], parameter: param[2], expression: param[2], member: null });
    }

    // Struct/request parameters frequently hide caller-controlled contract fields:
    //   function lock(LockParams calldata params) external { params.manager.positions(...); }
    // We do not need to know the struct definition to recognize that a two-hop member
    // is being invoked as a contract-like dependency.
    const structParamRe = /\b([A-Z][A-Za-z0-9_$]*)\s+(?:(?:calldata|memory|storage)\s+)?([A-Za-z_$][\w$]*)/g;
    while ((param = structParamRe.exec(fn.params))) {
      const type = param[1];
      const parameter = param[2];
      const chainRe = new RegExp(`\\b${escapeRegExp(parameter)}\\.([A-Za-z_$][\\w$]*)\\.([A-Za-z_$][\\w$]*)\\s*\\(`, 'g');
      let chain;
      while ((chain = chainRe.exec(fn.body))) {
        dependencies.push({
          type,
          parameter,
          member: chain[1],
          expression: `${parameter}.${chain[1]}`
        });
      }
    }

    const seen = new Set();
    for (const dependency of dependencies) {
      if (seen.has(dependency.expression)) continue;
      seen.add(dependency.expression);
      const finding = dependencyFinding(source, fn, dependency);
      if (finding) findings.push(finding);
    }
  }
  return findings;
}

function auditPackedDynamicCollision(source, code, functions) {
  const findings = [];
  for (const fn of functions) {
    const dynamics = [];
    const dynamicRe = /\b(string|bytes)\s+(?:(?:calldata|memory|storage)\s+)?([A-Za-z_$][\w$]*)/g;
    let param;
    while ((param = dynamicRe.exec(fn.params))) dynamics.push(param[2]);
    if (dynamics.length < 2) continue;

    const packedRe = /abi\.encodePacked\s*\(([^;]*)\)/g;
    let packed;
    while ((packed = packedRe.exec(fn.body))) {
      const used = dynamics.filter((name) => new RegExp(`\\b${escapeRegExp(name)}\\b`).test(packed[1]));
      if (used.length < 2) continue;
      const absoluteIndex = fn.openBrace + 1 + packed.index;
      findings.push({
        id: 'abi-packed-dynamic-collision',
        severity: 'high',
        title: 'abi.encodePacked 拼接多个动态参数',
        line: lineNumberAt(source, absoluteIndex),
        evidence: evidence(source, absoluteIndex),
        message: `同一 encodePacked 表达式包含多个动态参数 (${used.join(', ')})，不同逻辑输入可能产生相同字节串。若结果用于签名、哈希授权、唯一标识或 Merkle leaf，应改用 abi.encode 或显式长度分隔。`,
        details: { functionName: fn.name, dynamicParams: used }
      });
    }
  }
  return findings;
}

function auditWeakChainRandomness(source, code) {
  const findings = [];
  const re = /\b(?:block\.timestamp|block\.number|blockhash\s*\(|block\.prevrandao|block\.difficulty)\b/g;
  let match;
  while ((match = re.exec(code))) {
    const window = code.slice(Math.max(0, match.index - 140), Math.min(code.length, match.index + 220));
    if (!/(?:keccak256|sha256|random|rand|seed|%)/i.test(window)) continue;
    findings.push({
      id: 'weak-chain-randomness',
      severity: 'medium',
      title: '链属性参与随机/抽样语义',
      line: lineNumberAt(source, match.index),
      evidence: evidence(source, match.index),
      message: 'block timestamp/number/hash/prevrandao 等链属性被用于随机或抽样语义。需确认攻击者/区块生产者是否能预测或影响结果，以及是否直接决定奖励、权限或秘密。'
    });
  }
  return findings;
}

function auditGeneralSolidity(source, code) {
  const functions = extractFunctions(code);
  return [
    ...auditExternalContractTrust(source, code, functions),
    ...auditPackedDynamicCollision(source, code, functions),
    ...auditWeakChainRandomness(source, code)
  ];
}

module.exports = {
  findBlockEnd,
  extractFunctions,
  auditExternalContractTrust,
  auditPackedDynamicCollision,
  auditWeakChainRandomness,
  auditGeneralSolidity
};
