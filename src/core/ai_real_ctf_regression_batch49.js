'use strict';

const base = require('./ai_real_ctf_regression_batch48');

function runAiRealCtfRegression() {
  const report = base.runAiRealCtfRegression();
  const results = report.results.map((item) => ({ ...item }));
  const cifar = results.find((item) => item.id === 'ccsssc-2026-cifar10-backdoor');
  if (cifar?.candidateObject) {
    cifar.runtimeVerifierAvailable = 'ai-backdoor-patch-runtime-verify';
    cifar.runtimeVerificationReady = false;
    cifar.runtimeGap = {
      code:'ORIGINAL_RUNTIME_EVIDENCE_REQUIRED',
      detail:'公开回归材料没有原题 ONNX 模型 + clean 样本集 + trigger source raster + explicit control patch + preprocessing provenance，因此不能在 corpus regression 内宣称原题 Verified。'
    };
    cifar.limitation = 'Batch49 已能把该 candidate 绑定到本地 ONNX 模型、trigger 内容、preprocessing 与 control，并实际生成 clean/triggered/control observations；公开回归仍缺原题运行工件，所以保持 Candidate，不能用 fake runtime 或合成 fixture 冒充原题 Verified。';
  }

  const runtimeVerifierAvailable = results.filter((item) => Boolean(item.runtimeVerifierAvailable)).length;
  const runtimeVerificationReady = results.filter((item) => item.runtimeVerificationReady === true).length;
  const summary = {
    ...report.summary,
    runtimeVerifierAvailable,
    runtimeVerificationReady
  };

  return {
    ...report,
    batch:49,
    capabilitySchema:'newcyber.ai-runtime-candidate-verifier.v1',
    summary,
    results,
    note:'Batch49 把具体 image-backdoor Candidate 接到受控 ONNX Runtime：candidateId + model SHA-256 + trigger patch SHA-256 + preprocessing SHA-256 共同形成 runtimeBindingId；同一批样本实际执行 clean / triggered / control，再交给 Batch48 verifier。公开真题回归没有原题运行工件时 Verified 仍保持 0，fake ORT 只验证闭环代码，不计入真题成熟度。'
  };
}

function getAiRealCtfCorpus() {
  return base.getAiRealCtfCorpus();
}

module.exports = { getAiRealCtfCorpus, runAiRealCtfRegression };
