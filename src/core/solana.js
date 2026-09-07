function lineNumberAt(source, index) {
  return source.slice(0, Math.max(index, 0)).split(/\r?\n/).length;
}

function evidence(source, index, length = 220) {
  const start = Math.max(0, index - 60);
  return source.slice(start, Math.min(source.length, index + length)).trim();
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function auditSolanaAnchor(input) {
  const source = String(input || '');
  const isAnchor = /anchor_lang::prelude|#\s*\[\s*program\s*\]|#\s*\[\s*derive\s*\(\s*Accounts\s*\)\s*\]/.test(source);
  if (!isAnchor) return null;

  const programId = source.match(/declare_id!\s*\(\s*["']([^"']+)["']\s*\)/)?.[1] || null;
  const instructions = unique([...source.matchAll(/pub\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)].map((match) => match[1]));
  const pdaSeeds = unique([...source.matchAll(/seeds\s*=\s*\[([^\]]+)\]/g)].flatMap((match) => [...match[1].matchAll(/b["']([^"']+)["']/g)].map((seed) => seed[1])));
  const signers = unique([...source.matchAll(/pub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*Signer\s*<\s*'info\s*>/g)].map((match) => match[1]));
  const rawAccountInfos = [...source.matchAll(/pub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*AccountInfo\s*<\s*'info\s*>/g)]
    .map((match) => ({ name: match[1], index: match.index, line: lineNumberAt(source, match.index) }));
  const messages = unique([...source.matchAll(/msg!\s*\(\s*["']([^"']+)["']/g)].map((match) => match[1]));

  const findings = [];
  if (programId) findings.push({
    id: 'anchor-program-id',
    severity: 'info',
    title: 'Anchor Program ID',
    line: lineNumberAt(source, source.indexOf(programId)),
    message: `Program ID: ${programId}`,
    evidence: programId
  });

  for (const account of rawAccountInfos) {
    findings.push({
      id: 'raw-account-info',
      severity: 'medium',
      title: '未类型化 AccountInfo 输入',
      line: account.line,
      message: `${account.name} 使用原始 AccountInfo；检查 owner、address、PDA seeds、signer/writable 约束是否在其他位置补充。`,
      evidence: evidence(source, account.index)
    });
  }

  for (const account of rawAccountInfos) {
    const keyUse = new RegExp(`\\bself\\.${account.name}\\.key\\s*\\(\\s*\\)`, 'g');
    let match;
    while ((match = keyUse.exec(source))) {
      const nearby = source.slice(Math.max(0, match.index - 180), Math.min(source.length, match.index + 220));
      if (/=/.test(nearby)) findings.push({
        id: 'raw-account-key-to-state',
        severity: 'medium',
        title: '原始账户公钥进入状态',
        line: lineNumberAt(source, match.index),
        message: `${account.name}.key() 被写入/参与状态逻辑；若账户未约束，优先检查是否可由调用者任意控制。`,
        evidence: evidence(source, match.index)
      });
    }
  }

  for (const message of messages.filter((value) => /flag|secret|key|checkin/i.test(value))) {
    const index = source.indexOf(message);
    findings.push({
      id: 'interesting-program-log',
      severity: 'low',
      title: '链上日志包含高价值标记',
      line: lineNumberAt(source, index),
      message: `msg! 日志：${message}`,
      evidence: evidence(source, index)
    });
  }

  const summary = {
    high: findings.filter((item) => item.severity === 'high').length,
    medium: findings.filter((item) => item.severity === 'medium').length,
    low: findings.filter((item) => item.severity === 'low').length,
    info: findings.filter((item) => item.severity === 'info').length
  };

  return {
    language: 'Rust / Anchor',
    framework: 'Anchor',
    programId,
    instructions,
    pdaSeeds,
    signers,
    rawAccountInfos: rawAccountInfos.map(({ name, line }) => ({ name, line })),
    messages,
    findings,
    summary,
    notes: [
      'Anchor 快速审计用于 CTF triage：优先核对 AccountInfo 的 owner/address/PDA/signer 约束，以及程序 ID、PDA seeds 与交易日志。',
      'Program ID、instruction、PDA seed 可直接用于离线构造 Solana/Anchor 调试脚本。'
    ]
  };
}

function inspectAnchorToml(input) {
  const source = String(input || '');
  if (!/\[toolchain\]|\[provider\]|anchor_version|solana_version/.test(source)) return null;
  const value = (name) => source.match(new RegExp(`^\\s*${name}\\s*=\\s*["']([^"']+)["']`, 'mi'))?.[1] || null;
  return {
    format: 'Anchor.toml',
    solanaVersion: value('solana_version'),
    anchorVersion: value('anchor_version'),
    cluster: value('cluster')
  };
}

module.exports = { auditSolanaAnchor, inspectAnchorToml };
