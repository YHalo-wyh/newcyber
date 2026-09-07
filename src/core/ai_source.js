const { scanAiSource } = require('./toolbox');

function lineNumberAt(source, index) {
  return source.slice(0, Math.max(index, 0)).split(/\r?\n/).length;
}

function lineEvidence(source, index, radius = 180) {
  const start = Math.max(0, index - 80);
  const end = Math.min(source.length, index + radius);
  return source.slice(start, end).trim();
}

function firstMatch(source, regex) {
  regex.lastIndex = 0;
  const match = regex.exec(source);
  return match ? { index: match.index, text: match[0] } : null;
}

function auditAiChallengeSource(input) {
  const source = String(input || '');
  const base = scanAiSource(source);
  const findings = [...(base.findings || [])];

  const llmOutput = firstMatch(source, /\b(?:LLM_PASSWORD|llm_(?:out|output)|model_(?:out|output)|completion|response_text)\b|choices\s*\]\s*\[?0?\]?[^\r\n]{0,100}message[^\r\n]{0,100}content/is);
  const modelCall = firstMatch(source, /(?:chat\/completions|chat\.completions\.create|responses\.create|generate_content|call_(?:glm|llm|model)|requests\.post\s*\([^\r\n]{0,160}(?:api|completions))/is);
  const keyDerivation = firstMatch(source, /(?:hashlib\.(?:sha256|sha512|blake2\w*)\s*\(|\b(?:derive|make|build)_\w*key\s*\(|\b(?:PBKDF2|HKDF|scrypt)\b)/i);
  const encryption = firstMatch(source, /\b(?:AES|Fernet|ChaCha20|Cipher\s*\(|encrypt(?:or)?\s*\(|ciphertext)\b/i);

  if (llmOutput && modelCall && keyDerivation && encryption) {
    const anchor = Math.min(llmOutput.index, keyDerivation.index, encryption.index);
    findings.push({
      severity: 'high',
      id: 'llm-derived-crypto-key',
      title: 'LLM 输出参与密码学密钥派生',
      count: 1,
      line: lineNumberAt(source, anchor),
      evidence: [lineEvidence(source, llmOutput.index), lineEvidence(source, keyDerivation.index), lineEvidence(source, encryption.index)],
      message: '模型输出被哈希/KDF 后用于加密密钥。若提示词、模型、temperature 或输出空间可复现，应优先枚举模型输出并用解密有效性作为 oracle。'
    });
  }

  const promptDefinition = firstMatch(source, /\bSYSTEM_PROMPT\s*=|["']system_prompt["']\s*:/i);
  const temperatureDefinition = firstMatch(source, /\bTEMPERATURE\s*=\s*([0-9.]+)|["']temperature["']\s*:\s*([0-9.]+)/i);
  const responseExposure = firstMatch(source, /(?:JSONResponse|jsonify|res\.json|return\s*\{)[\s\S]{0,1400}(?:system_prompt|SYSTEM_PROMPT)[\s\S]{0,900}temperature/i);
  if (promptDefinition && temperatureDefinition && responseExposure) {
    findings.push({
      severity: 'medium',
      id: 'llm-replay-parameters-exposed',
      title: '模型重放参数被业务接口暴露',
      count: 1,
      line: lineNumberAt(source, responseExposure.index),
      evidence: [lineEvidence(source, responseExposure.index, 360)],
      message: '接口同时暴露 system prompt / temperature 等生成参数。结合固定模型与密钥派生逻辑时，可形成离线/低成本候选重放路线。'
    });
  }

  const temperatureValues = [...source.matchAll(/(?:TEMPERATURE\s*=\s*|["']temperature["']\s*:\s*)([0-9]+(?:\.[0-9]+)?)/gi)]
    .map((match) => Number(match[1]))
    .filter(Number.isFinite);

  const llmCrypto = llmOutput && keyDerivation && encryption ? {
    modelCallDetected: Boolean(modelCall),
    outputEvidence: llmOutput.text.slice(0, 160),
    keyDerivationEvidence: keyDerivation.text.slice(0, 160),
    encryptionEvidence: encryption.text.slice(0, 160),
    temperatures: [...new Set(temperatureValues)]
  } : null;

  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || (a.line || 0) - (b.line || 0));

  return {
    ...base,
    findings,
    llmCrypto,
    hints: [
      ...(base.hints || []),
      '若模型输出参与密钥/令牌生成，优先记录 model、prompt、temperature、输出格式约束，并寻找可验证候选的 padding/格式/签名 oracle。'
    ]
  };
}

module.exports = { auditAiChallengeSource };
