function lineNumberAt(source, index) {
  return source.slice(0, Math.max(index, 0)).split(/\r?\n/).length;
}

function evidence(source, index, length = 420) {
  const start = Math.max(0, index - 100);
  return source.slice(start, Math.min(source.length, index + length)).trim();
}

function auditEcdsaSignatureReplay(sourceInput, maskedCodeInput = null) {
  const source = String(sourceInput || '');
  const code = maskedCodeInput == null ? source : String(maskedCodeInput);
  const findings = [];

  const recover = /\becrecover\s*\(/g.exec(code);
  if (!recover) return findings;

  // If the contract visibly canonicalizes ECDSA s (or uses an equivalent half-order
  // check), do not flag the raw-signature replay pattern below. ecrecover itself does
  // not enforce the low-s rule, so this distinction matters.
  const canonicalizesS = /(?:secp256k1|half[_A-Z]*order|LOWER_HALF_ORDER|7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0)/i.test(code)
    && /(?:\.s\b|\bs\b)/.test(code);
  if (canonicalizesS) return findings;

  const hashRegex = /(?:bytes32\s+)?([A-Za-z_$][\w$]*)\s*=\s*keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\(([\s\S]{0,500}?)\)\s*\)/g;
  let match;
  while ((match = hashRegex.exec(code))) {
    const variable = match[1];
    const args = match[2];
    const hasV = /(?:\.|\b)v\b/.test(args);
    const hasR = /(?:\.|\b)r\b/.test(args);
    const hasS = /(?:\.|\b)s\b/.test(args);
    if (!hasV || !hasR || !hasS) continue;

    const after = code.slice(match.index, Math.min(code.length, match.index + 2600));
    const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const replayComparison = new RegExp(`(?:require|if)\\s*\\([^)]*\\b${escaped}\\b[^)]*(?:!=|==|\\[)`, 's').test(after);
    const replayState = /(?:alreadyUsed|usedSignature|seenSignature|signatureUsed|replay|usedHashes?|signatureHashes?)/i.test(after);
    if (!replayComparison || !replayState) continue;

    findings.push({
      id: 'ecdsa-signature-hash-replay',
      severity: 'high',
      title: '原始 ECDSA 签名字节哈希被当作重放唯一性',
      line: lineNumberAt(source, match.index),
      evidence: evidence(source, match.index),
      message: '检测到 raw ecrecover，同时用 keccak256(v,r,s) 一类签名字节哈希做“已使用签名”判断。若未强制 low-s/规范化，同一消息可存在等价的可延展签名，从而绕过按签名字节去重。优先用消息 digest/nonce 做重放保护，并采用带 canonical-s 检查的 ECDSA.recover。'
    });
  }

  return findings;
}

module.exports = { auditEcdsaSignatureReplay };
