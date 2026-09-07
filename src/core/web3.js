function lineNumberAt(source, index) {
  return source.slice(0, index).split(/\r?\n/).length;
}

function evidence(source, index, length = 180) {
  const start = Math.max(0, index - 60);
  return source.slice(start, Math.min(source.length, index + length)).trim();
}

function auditSolidity(input) {
  const source = String(input || '');
  const findings = [];
  const push = (id, severity, title, index, message) => findings.push({
    id,
    severity,
    title,
    line: lineNumberAt(source, index),
    evidence: evidence(source, index),
    message
  });

  let match;
  const txOrigin = /\btx\.origin\b/g;
  while ((match = txOrigin.exec(source))) push('tx-origin', 'high', '使用 tx.origin 做身份语义', match.index, 'tx.origin 常导致授权边界错误，应确认是否可被中间合约利用。');

  const delegatecall = /\.delegatecall\s*\(/g;
  while ((match = delegatecall.exec(source))) push('delegatecall', 'high', '发现 DELEGATECALL', match.index, '检查 target 是否可控、实现升级权限与 storage layout。');

  const selfdestruct = /\bselfdestruct\s*\(/g;
  while ((match = selfdestruct.exec(source))) push('selfdestruct', 'medium', '发现 SELFDESTRUCT', match.index, '确认调用权限和部署链语义。');

  const lowLevelCall = /\.call\s*\{?|\.call\s*\(/g;
  while ((match = lowLevelCall.exec(source))) push('low-level-call', 'medium', '发现低级 CALL', match.index, '检查目标、value/data 可控性以及返回值处理。');

  const arbitraryFunctionCall = /\.functionCall\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g;
  while ((match = arbitraryFunctionCall.exec(source))) push('function-call-data', 'medium', '动态 calldata 外部调用', match.index, `调用数据来自 ${match[1]}，应核对选择器授权与实际执行 calldata 是否绑定。`);

  const calldataLoad = /calldataload\s*\(\s*([A-Za-z_$][\w$]*|0x[0-9a-fA-F]+|\d+)\s*\)/g;
  const calldataLoads = [];
  while ((match = calldataLoad.exec(source))) calldataLoads.push({ index: match.index, argument: match[1] });

  const dynamicBytesParams = [...source.matchAll(/function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\bbytes\s+calldata\s+([A-Za-z_$][\w$]*)[^)]*\)/g)]
    .map((item) => ({ functionName: item[1], param: item[2], index: item.index }));
  const hardcodedCalldataOffset = /(?:uint\d*\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:\d+\s*\+\s*)?\d+\s*\*\s*\d+\s*;/g;
  const offsetVars = [];
  while ((match = hardcodedCalldataOffset.exec(source))) offsetVars.push({ name: match[1], index: match.index });

  for (const load of calldataLoads) {
    const offset = offsetVars.find((item) => item.name === load.argument);
    if (offset && dynamicBytesParams.length) {
      push(
        'abi-smuggling-offset',
        'high',
        '动态 bytes 授权使用硬编码 calldata 偏移',
        load.index,
        '对动态 bytes 参数用固定偏移读取 selector，可能造成“授权 selector”和“实际 actionData selector”不一致（ABI smuggling）。'
      );
    }
  }

  const publicInitializer = /function\s+(?:initialize|init|setPermissions)\s*\([^)]*\)\s+(?:external|public)\b/g;
  while ((match = publicInitializer.exec(source))) {
    const nearby = source.slice(match.index, Math.min(source.length, match.index + 900));
    if (/\binitialized\b/.test(nearby) && !/(onlyOwner|initializer|onlyRole|auth|requiresAuth)/.test(match[0])) {
      push('first-caller-init', 'medium', '公开的一次性初始化入口', match.index, '首次调用者可能获得初始化/授权能力；确认部署事务是否原子完成。');
    }
  }

  const unchecked = /\bunchecked\s*\{/g;
  while ((match = unchecked.exec(source))) push('unchecked', 'low', '存在 unchecked 算术块', match.index, 'Solidity 0.8+ 下 unchecked 关闭溢出检查，确认循环/计数逻辑是否安全。');

  const severityOrder = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || a.line - b.line);

  return {
    language: 'Solidity',
    findings,
    summary: {
      high: findings.filter((item) => item.severity === 'high').length,
      medium: findings.filter((item) => item.severity === 'medium').length,
      low: findings.filter((item) => item.severity === 'low').length
    },
    notes: ['静态规则用于缩小审计范围，不等价于漏洞成立；结合测试、调用上下文和状态约束复核。']
  };
}

module.exports = { auditSolidity };
