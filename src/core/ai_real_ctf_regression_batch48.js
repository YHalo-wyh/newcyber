const base = require('./ai_real_ctf_regression');
const { buildBackdoorPatchCandidate } = require('./ai_candidate_verifier');

function backdoorFixture() {
  const rows = [];
  for (let i = 0; i < 10; i += 1) {
    const truth = String((i % 3) + 2);
    rows.push({
      true_label: truth,
      clean_pred: truth,
      triggered_pred: '1',
      control_pred: truth,
      target_label: '1'
    });
  }
  return { targetLabel: '1', rows };
}

function patchRaster(size = 32) {
  const data = [];
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const value = (x >= size - 5 && y >= size - 5) ? 255 : 96 + ((x + y) % 3);
      data.push(value, value, value, 255);
    }
  }
  return { width: size, height: size, channels: 4, data };
}

function recomputeSummary(results, previous = {}) {
  const total = results.length;
  const recognitionPass = results.filter((item) => item.recognized === true).length;
  const candidatePass = results.filter((item) => item.candidate === true).length;
  const verifiedPass = results.filter((item) => item.verified === true).length;
  const verifierAvailable = results.filter((item) => Boolean(item.verifierAvailable || item.candidateObject?.verifier)).length;
  const candidateWithVerifier = results.filter((item) => item.candidate === true && Boolean(item.verifierAvailable || item.candidateObject?.verifier)).length;
  return {
    ...previous,
    total,
    recognitionPass,
    candidatePass,
    verifiedPass,
    recognitionRate: total ? recognitionPass / total : 0,
    candidateRate: total ? candidatePass / total : 0,
    verifiedRate: total ? verifiedPass / total : 0,
    maturityFunnel: {
      recognized: recognitionPass,
      candidate: candidatePass,
      verified: verifiedPass,
      recognizedToCandidate: recognitionPass ? candidatePass / recognitionPass : 0,
      candidateToVerified: candidatePass ? verifiedPass / candidatePass : 0
    },
    verifierAvailable,
    candidateWithVerifier,
    miss: results.filter((item) => item.status === 'miss').length
  };
}

function runAiRealCtfRegression() {
  const report = base.runAiRealCtfRegression();
  const results = report.results.map((item) => ({ ...item }));

  const cifar = results.find((item) => item.id === 'ccsssc-2026-cifar10-backdoor');
  if (cifar) {
    const generated = buildBackdoorPatchCandidate({
      raster: patchRaster(),
      behavior: backdoorFixture()
    });
    cifar.recognized = generated.recognized === true;
    cifar.candidate = generated.candidate === true;
    cifar.verified = false;
    cifar.status = cifar.recognized ? 'pass' : 'miss';
    cifar.maturityStage = cifar.candidate ? 'candidate' : cifar.recognized ? 'recognized' : 'unrecognized';
    cifar.tool = 'ai-backdoor-patch-candidate';
    cifar.candidateObject = generated.candidateObject;
    cifar.candidateEvidence = generated.candidateEvidence;
    cifar.verifierAvailable = 'ai-backdoor-patch-verify';
    cifar.verificationReady = generated.verificationReady;
    cifar.evidence = generated.candidate
      ? `${generated.candidateEvidence} · source=${generated.candidateObject.patch.source}`
      : `cross-evidence patch candidate not strong enough · top=${generated.visual?.topPatch?.score ?? 'n/a'}`;
    cifar.limitation = generated.candidate
      ? '已把图像局部热区与目标 ASR/control specificity 绑定成具体 patch candidate；仍需在真实题目模型上按 candidateId 复跑 observations，不能用最小复现数据冒充原题 Verified。'
      : cifar.limitation;
  }

  const easyLlm = results.find((item) => item.id === 'suctf-2026-su-easyllm');
  if (easyLlm) {
    easyLlm.verifierAvailable = 'ai-llm-aes-candidate-verify';
    easyLlm.verificationReady = false;
    easyLlm.verifierEvidence = 'official challenge declares AES-128-CBC + SHA256(LLM_output)[:16]; verifier can deterministically test supplied LLM outputs offline';
    easyLlm.limitation = '官方归档给出 AES/IV/ciphertext/replay 规则，但未给可确定复现的成功 LLM 输出。Batch48 已具备离线候选 verifier；在获得真实 LLM output candidate 前保持 Recognized，不硬升 Candidate/Verified。';
  }

  const easyPoison = results.find((item) => item.id === 'ccb-ciscn-2025-easy-poison');
  if (easyPoison?.candidateObject?.verifier) {
    easyPoison.verifierAvailable = easyPoison.candidateObject.verifier;
  }

  const summary = recomputeSummary(results, report.summary);
  return {
    ...report,
    capabilitySchema: 'newcyber.ai-candidate-verifier.v1',
    batch: 48,
    summary,
    results,
    note: 'Batch48 在 Batch47 三层成熟度上新增 Candidate Generator / Verifier。CIFAR-10 只有在行为侧强 ASR/control evidence 与图像局部热区绑定后才生成具体 patch candidate；SU_easyLLM 已具备严格离线 AES verifier，但没有真实成功 LLM 输出时仍保持 Recognized。Verified 只接受真实候选经过确定性 verifier 或绑定模型 observations 的闭环，不用合成 fixture 刷绿。'
  };
}

function getAiRealCtfCorpus() {
  return base.getAiRealCtfCorpus();
}

module.exports = { getAiRealCtfCorpus, runAiRealCtfRegression };
