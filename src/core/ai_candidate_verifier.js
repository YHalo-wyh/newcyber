const crypto = require('crypto');
const { analyzeRasterImage } = require('./ai_sample_forensics');
const { analyzeBackdoorBehavior } = require('./ai_poison_backdoor_validation');

const MAX_LLM_CANDIDATES = 512;
const MAX_LLM_CANDIDATE_CHARS = 512;
const MAX_CIPHERTEXT_BYTES = 1024 * 1024;

function objectInput(input, label = 'input') {
  if (typeof input === 'string') {
    const text = input.trim();
    if (!text) return {};
    let parsed;
    try { parsed = JSON.parse(text); }
    catch { throw new Error(`${label} 需要 JSON 对象`); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} 需要 JSON 对象`);
    return parsed;
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error(`${label} 需要对象`);
  return input;
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function strictBase64(value, label, maxBytes = MAX_CIPHERTEXT_BYTES) {
  const text = String(value || '').trim();
  if (!text || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new Error(`${label} 不是严格 Base64`);
  }
  const buffer = Buffer.from(text, 'base64');
  if (!buffer.length) throw new Error(`${label} 为空`);
  if (buffer.length > maxBytes) throw new Error(`${label} 超过离线验证预算`);
  const canonical = buffer.toString('base64');
  if (canonical !== text) throw new Error(`${label} Base64 非规范或包含无效尾部`);
  return buffer;
}

function normalizeLlmAesChallenge(input = {}) {
  input = objectInput(input, 'LLM-AES verifier input');
  const challenge = input.challenge || input;
  if (!challenge || typeof challenge !== 'object' || Array.isArray(challenge)) throw new Error('challenge 需要对象');
  const algo = String(challenge.algo || challenge.algorithm || '').trim().toUpperCase();
  if (!['AES-128-CBC', 'AES128-CBC'].includes(algo)) {
    throw new Error('当前 verifier 只接受题面明确声明的 AES-128-CBC');
  }
  const derivation = String(challenge.key_derivation || challenge.keyDerivation || '').trim();
  if (!/SHA\s*-?\s*256/i.test(derivation) || !/(?:\[:\s*16\]|FIRST\s*16)/i.test(derivation)) {
    throw new Error('key_derivation 必须明确证明 SHA256(LLM_output)[:16]');
  }
  const iv = strictBase64(challenge.iv_b64 || challenge.ivBase64, 'iv_b64', 64);
  if (iv.length !== 16) throw new Error(`AES-CBC IV 必须 16 字节，实际 ${iv.length}`);
  const ciphertext = strictBase64(challenge.ciphertext_b64 || challenge.ciphertextBase64, 'ciphertext_b64');
  if (ciphertext.length % 16 !== 0) throw new Error('AES-CBC ciphertext 长度必须是 16 的倍数');
  return {
    algorithm: 'aes-128-cbc',
    derivation: 'sha256-llm-output-first-16',
    iv,
    ciphertext,
    llm: challenge.llm && typeof challenge.llm === 'object' ? challenge.llm : null
  };
}

function flagCandidates(text) {
  const out = [];
  const seen = new Set();
  const regex = /([A-Za-z][A-Za-z0-9_]{1,23}\{[^}\r\n]{1,160}\})/g;
  let match;
  while ((match = regex.exec(text)) && out.length < 8) {
    const value = match[1];
    if (!seen.has(value)) {
      seen.add(value);
      out.push(value);
    }
  }
  return out;
}

function decryptLlmCandidate(challenge, candidate) {
  const output = String(candidate ?? '').trim();
  if (!output) return { status: 'rejected', reason: 'empty-candidate' };
  if (output.length > MAX_LLM_CANDIDATE_CHARS) return { status: 'rejected', reason: 'candidate-too-long' };
  const key = crypto.createHash('sha256').update(output, 'utf8').digest().subarray(0, 16);
  try {
    const decipher = crypto.createDecipheriv(challenge.algorithm, key, challenge.iv);
    decipher.setAutoPadding(true);
    const plaintextBuffer = Buffer.concat([decipher.update(challenge.ciphertext), decipher.final()]);
    const plaintext = new TextDecoder('utf-8', { fatal: true }).decode(plaintextBuffer);
    const flags = flagCandidates(plaintext);
    if (!flags.length) {
      return {
        status: 'rejected',
        reason: 'valid-padding-but-no-flag',
        plaintextSha256: sha256Hex(plaintextBuffer)
      };
    }
    return {
      status: 'accepted',
      reason: 'valid-padding-utf8-flag',
      output,
      flags,
      plaintext,
      plaintextSha256: sha256Hex(plaintextBuffer),
      keySha256: sha256Hex(key)
    };
  } catch {
    return { status: 'rejected', reason: 'padding-key-or-utf8-mismatch' };
  }
}

function verifyLlmAesCandidates(input = {}) {
  input = objectInput(input, 'LLM-AES verifier input');
  const challenge = normalizeLlmAesChallenge(input);
  const raw = input.candidates || input.outputs || input.llmOutputs || [];
  if (!Array.isArray(raw)) throw new Error('candidates 必须是 LLM 输出字符串数组');
  if (raw.length > MAX_LLM_CANDIDATES) throw new Error(`候选数超过上限 ${MAX_LLM_CANDIDATES}`);
  const seen = new Set();
  const candidates = [];
  for (const item of raw) {
    const value = String(item ?? '').trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    candidates.push(value);
  }
  const attempts = candidates.map((candidate, index) => {
    const result = decryptLlmCandidate(challenge, candidate);
    return {
      index,
      candidateSha256: sha256Hex(candidate),
      status: result.status,
      reason: result.reason,
      flags: result.flags || [],
      plaintextSha256: result.plaintextSha256 || null
    };
  });
  const acceptedIndex = attempts.findIndex((item) => item.status === 'accepted');
  const accepted = acceptedIndex >= 0 ? decryptLlmCandidate(challenge, candidates[acceptedIndex]) : null;
  const verified = Boolean(accepted && accepted.status === 'accepted');
  return {
    schema: 'newcyber.ai-llm-aes-candidate-verifier.v1',
    candidateCount: candidates.length,
    attempted: attempts.length,
    verified,
    verdict: verified ? 'verified' : candidates.length ? 'candidates-rejected' : 'no-candidates',
    accepted: verified ? {
      kind: 'llm-aes-plaintext',
      llmOutput: accepted.output,
      flags: accepted.flags,
      plaintext: accepted.plaintext,
      plaintextSha256: accepted.plaintextSha256,
      verifier: 'sha256[:16] → AES-128-CBC → PKCS#7 → UTF-8 → flag-pattern'
    } : null,
    attempts,
    challenge: {
      algorithm: 'AES-128-CBC',
      keyDerivation: 'SHA256(LLM_output)[:16]',
      ciphertextBytes: challenge.ciphertext.length,
      llm: challenge.llm
    },
    notes: [
      '完全离线：本 verifier 不调用 LLM API、不访问题目服务器，只验证已经获得的候选输出。',
      '只有同时通过 AES-CBC padding、UTF-8 和 flag 结构检查的候选才会升级为 Verified。'
    ]
  };
}

function strongestPatch(visual) {
  const direct = visual?.patchAnalysis?.candidates?.[0];
  if (direct) return { ...direct, source: 'threshold-candidate' };
  const grid = Array.isArray(visual?.patchAnalysis?.grid) ? visual.patchAnalysis.grid : [];
  if (!grid.length) return null;
  const top = grid.slice().sort((a, b) => (b.score || 0) - (a.score || 0) || a.y - b.y || a.x - b.x)[0];
  return top ? { ...top, source: 'cross-evidence-grid' } : null;
}

function patchCandidateId(candidate) {
  const core = {
    kind: candidate.kind,
    targetLabel: String(candidate.targetLabel),
    patch: {
      x: Number(candidate.patch.x),
      y: Number(candidate.patch.y),
      width: Number(candidate.patch.width),
      height: Number(candidate.patch.height),
      score: Number(candidate.patch.score)
    }
  };
  return `patch-${sha256Hex(JSON.stringify(core)).slice(0, 20)}`;
}

function buildBackdoorPatchCandidate(input = {}) {
  input = objectInput(input, 'backdoor patch candidate input');
  const raster = input.raster || input.image;
  const behaviorInput = input.behavior || input.observations;
  if (!raster) throw new Error('需要 raster/image 作为 patch 候选来源');
  if (!behaviorInput) throw new Error('需要 behavior/observations 绑定目标标签与 ASR');
  const visual = analyzeRasterImage(raster);
  const behavior = analyzeBackdoorBehavior(behaviorInput);
  const findingIds = (behavior.findings || []).map((item) => item.id);
  const patch = strongestPatch(visual);
  const metrics = behavior.metrics || {};
  const behaviorStrong = findingIds.includes('backdoor-target-asr-candidate');
  const controlStrong = findingIds.includes('backdoor-control-specificity');
  const visualStrong = Boolean(patch && Number(patch.score) >= 0.55);
  const recognized = Boolean(behaviorStrong && patch);
  const candidate = Boolean(
    recognized &&
    visualStrong &&
    behavior.targetLabel !== null && behavior.targetLabel !== undefined &&
    Number(metrics.targetASR) >= 0.8 &&
    (metrics.controlTargetRate === null || metrics.controlTargetRate === undefined || Number(metrics.controlTargetRate) <= 0.3)
  );
  let candidateObject = null;
  if (candidate) {
    candidateObject = {
      kind: 'localized-backdoor-trigger',
      targetLabel: String(behavior.targetLabel),
      patch: {
        x: patch.x,
        y: patch.y,
        width: patch.width,
        height: patch.height,
        score: patch.score,
        source: patch.source
      },
      behavior: {
        paired: behavior.paired,
        cleanAccuracy: metrics.cleanAccuracy,
        targetASR: metrics.targetASR,
        controlTargetRate: metrics.controlTargetRate,
        triggerSpecificity: metrics.triggerSpecificity
      },
      verifier: 'ai-backdoor-patch-verify'
    };
    candidateObject.candidateId = patchCandidateId(candidateObject);
  }
  return {
    schema: 'newcyber.ai-backdoor-patch-candidate.v1',
    recognized,
    candidate,
    verified: false,
    candidateObject,
    candidateEvidence: candidateObject
      ? `bbox=${candidateObject.patch.x},${candidateObject.patch.y},${candidateObject.patch.width}x${candidateObject.patch.height} · target=${candidateObject.targetLabel} · ASR=${Number(metrics.targetASR).toFixed(4)} · control=${metrics.controlTargetRate === null || metrics.controlTargetRate === undefined ? 'n/a' : Number(metrics.controlTargetRate).toFixed(4)}`
      : '',
    verificationReady: Boolean(candidateObject && behavior.paired >= 5 && (controlStrong || metrics.controlTargetRate !== null)),
    visual: {
      topPatch: patch,
      thresholdCandidates: visual.patchAnalysis?.candidates?.length || 0
    },
    behavior: {
      targetLabel: behavior.targetLabel,
      paired: behavior.paired,
      metrics,
      findingIds
    },
    notes: [
      'Candidate 由行为侧目标 ASR 与图像局部热区交叉绑定；单独的 patch 热区不会被升级为后门。',
      'cross-evidence-grid 允许在强行为证据存在时使用低于单图固定阈值的最强网格热区，用于减少贴边/尺寸不对齐 trigger 的漏检。',
      '生成 Candidate 后仍需把该 candidateId 对应的 patch 真正送入授权模型，并用 control observations 做离线复验。'
    ]
  };
}

function verifyBackdoorPatchCandidate(input = {}) {
  input = objectInput(input, 'backdoor patch verifier input');
  const candidate = input.candidate || input.candidateObject;
  const observations = input.observations || input.behavior;
  if (!candidate || candidate.kind !== 'localized-backdoor-trigger') throw new Error('需要 localized-backdoor-trigger candidate');
  if (!observations) throw new Error('需要针对该 candidate 的离线 observations');
  const expectedId = patchCandidateId(candidate);
  const suppliedId = String(input.candidateId || observations.candidateId || '').trim();
  if (!suppliedId || suppliedId !== expectedId) {
    return {
      schema: 'newcyber.ai-backdoor-patch-verifier.v1',
      verified: false,
      verdict: 'candidate-binding-mismatch',
      candidateId: expectedId,
      reason: 'observations 没有绑定到当前 candidateId，拒绝跨候选复用验证结果。'
    };
  }
  const behavior = analyzeBackdoorBehavior(observations);
  const metrics = behavior.metrics || {};
  const targetMatches = String(behavior.targetLabel) === String(candidate.targetLabel);
  const enough = behavior.paired >= 5;
  const cleanOk = metrics.cleanAccuracy === null || metrics.cleanAccuracy === undefined || Number(metrics.cleanAccuracy) >= 0.6;
  const asrOk = Number(metrics.targetASR) >= 0.8;
  const controlOk = metrics.controlTargetRate !== null && metrics.controlTargetRate !== undefined && Number(metrics.controlTargetRate) <= 0.3;
  const specificityOk = Number(metrics.triggerSpecificity) >= 0.5;
  const verified = Boolean(targetMatches && enough && cleanOk && asrOk && controlOk && specificityOk);
  return {
    schema: 'newcyber.ai-backdoor-patch-verifier.v1',
    verified,
    verdict: verified ? 'verified-on-provided-observations' : 'not-verified',
    candidateId: expectedId,
    targetMatches,
    checks: { enough, cleanOk, asrOk, controlOk, specificityOk },
    metrics: {
      paired: behavior.paired,
      cleanAccuracy: metrics.cleanAccuracy,
      targetASR: metrics.targetASR,
      controlTargetRate: metrics.controlTargetRate,
      triggerSpecificity: metrics.triggerSpecificity
    },
    notes: [
      'Verified 仅表示当前 candidateId 在提供的离线模型 observations 上通过强 ASR + control specificity 复验。',
      '工具不会自己执行未知模型；真实赛题需要由受控 runtime 产生这些 observations。'
    ]
  };
}

module.exports = {
  MAX_LLM_CANDIDATES,
  normalizeLlmAesChallenge,
  verifyLlmAesCandidates,
  buildBackdoorPatchCandidate,
  verifyBackdoorPatchCandidate,
  patchCandidateId
};
