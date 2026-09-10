const toolbox = require('./toolbox');
const { analyzeCanAdvanced, decodeUdsAdvanced } = require('./vehicle_final');
const { auditAiChallengeSource } = require('./ai_source_batch9');
const { analyzeTabularDataset, evaluateTabularCandidate } = require('./ai_tabular');
const { analyzeAdversarialPair, analyzeAdversarialBatch, buildAdversarialHarness } = require('./ai_adversarial');
const { analyzePrivacyTranscript, buildPrivacyHarness } = require('./ai_privacy');
const { analyzeDatasetSecurity, buildDatasetHarness } = require('./ai_dataset_security');
const { analyzePoisoningImpact, analyzeBackdoorBehavior } = require('./ai_poison_backdoor_validation');
const { auditAiSupplyChain } = require('./ai_supply_chain');
const { buildPromptInjectionSuite, evaluatePromptInjectionRun, auditPromptInjectionSource } = require('./ai_prompt_injection');
const { analyzeModelExtractionTranscript, buildModelExtractionHarness } = require('./ai_model_extraction');
const { analyzeOcrExtractionTranscript, buildOcrExtractionHarness } = require('./ai_ocr_extraction');
const { analyzeModelInversion } = require('./ai_model_inversion');
const { diagnoseAiSkillMatrix } = require('./ai_skill_matrix');
const { runAiRealCtfRegression, getAiRealCtfCorpus } = require('./ai_real_ctf_regression');
const { verifyLlmAesCandidates, buildBackdoorPatchCandidate, verifyBackdoorPatchCandidate } = require('./ai_candidate_verifier');
const { runAiStage1TrainingRegression, PUBLIC_TRAINING_SEEDS } = require('./ai_stage1_training_corpus');
const { analyzeRasterImage, compareRasterImages, analyzeNpySample, compareNpySamples } = require('./ai_sample_forensics');
const { analyzeModelArithmeticBundle } = require('./ai_model_arithmetic');
const { analyzeBinaryDataListing } = require('./binary_data_graph');
const { scanRegulatoryApi } = require('./low_altitude_regulatory');
const { analyzeGnssLog } = require('./gnss_audit');
const { analyzeGnssSpectrum } = require('./gnss_sdr');
const { auditFirmwareUpdate } = require('./firmware_update_audit');
const { toolingCatalog } = require('./ai_tooling');
const { auditSolanaAnchor } = require('./solana');
const { analyzeMavlinkAdvanced } = require('./low_altitude_final');
const { verifyMavlinkSignatureInput } = require('./mavlink_signing');
const { analyzeEvmRuntime } = require('./evm_runtime_batch4');
const { autoDecode } = require('./auto_decode');
const { decryptCryptoContext } = require('./context_crypto');
const { searchKnowledge, knowledgeStats } = require('../knowledge');
const { analyzeUavChallengeEvidence, getScenarioCatalog, parseWifiEvidence, analyzeFlightLog } = require('./uav_challenge_matrix_v6');
const { buildLowaltAssessment, getLowaltAssessmentCatalog } = require('./lowalt_assessment_mode');
const { analyzeSwarmCoordination } = require('./lowalt_swarm');
const { analyzeCrossBoundaryFlow } = require('./lowalt_cross_boundary');

function npyBuffer(value) {
  if (!value || typeof value.base64 !== 'string') throw new Error('NPY 输入需要 base64');
  const buffer = Buffer.from(value.base64, 'base64');
  if (!buffer.length) throw new Error('NPY 数据为空');
  if (buffer.length > 48 * 1024 * 1024) throw new Error('NPY 样本工作台单文件上限 48 MiB');
  return buffer;
}

function runTool(tool, payload = {}) {
  if (tool === 'can-analyze') return analyzeCanAdvanced(payload.input);
  if (tool === 'uds-decode') return decodeUdsAdvanced(payload.input);
  if (tool === 'mavlink-hex') return analyzeMavlinkAdvanced(payload.input);
  if (tool === 'mavlink-signature-verify') return verifyMavlinkSignatureInput(payload.input);
  if (tool === 'uav-wifi-evidence') return parseWifiEvidence(payload.input);
  if (tool === 'uav-flight-log') return analyzeFlightLog(payload.input);
  if (tool === 'uav-recon-analyze') return analyzeUavChallengeEvidence(payload.input, { category: 'recon' });
  if (tool === 'uav-spoof-analyze') return analyzeUavChallengeEvidence(payload.input, { category: 'spoof' });
  if (tool === 'uav-dos-analyze') return analyzeUavChallengeEvidence(payload.input, { category: 'dos' });
  if (tool === 'uav-injection-analyze') return analyzeUavChallengeEvidence(payload.input, { category: 'inject' });
  if (tool === 'uav-leak-analyze') return analyzeUavChallengeEvidence(payload.input, { category: 'leak' });
  if (tool === 'uav-challenge-matrix') return { ...analyzeUavChallengeEvidence(payload.input), catalog: getScenarioCatalog() };
  if (tool === 'lowalt-assessment-mode') {
    const result=buildLowaltAssessment(payload.input || payload);
    return { ...result, schema:'newcyber.lowalt-assessment.v1', revision:2 };
  }
  if (tool === 'lowalt-assessment-catalog') return getLowaltAssessmentCatalog();
  if (tool === 'lowalt-swarm-coordination') return analyzeSwarmCoordination(payload.input || payload, payload.options || {});
  if (tool === 'lowalt-cross-boundary-flow') return analyzeCrossBoundaryFlow(payload.input || payload, payload.options || {});
  if (tool === 'uav-regulatory-audit') return scanRegulatoryApi(payload.input);
  if (tool === 'uav-gnss-audit') return analyzeGnssLog(payload.input, payload.options || {});
  if (tool === 'uav-gnss-spectrum') return analyzeGnssSpectrum(payload.input, payload.options || {});
  if (tool === 'firmware-update-audit') return auditFirmwareUpdate(payload.input);
  if (tool === 'binary-data-graph') return analyzeBinaryDataListing(payload.input);
  if (tool === 'ai-source-scan') return auditAiChallengeSource(payload.input);
  if (tool === 'ai-skill-matrix') return diagnoseAiSkillMatrix(payload.input ?? payload);
  if (tool === 'ai-stage1-training-regression') return runAiStage1TrainingRegression(payload.options || payload.input || {});
  if (tool === 'ai-stage1-training-corpus') return {schema:'newcyber.ai-stage1-training-corpus.v1',cases:PUBLIC_TRAINING_SEEDS};
  if (tool === 'ai-real-ctf-regression') return runAiRealCtfRegression();
  if (tool === 'ai-real-ctf-corpus') return { schema:'newcyber.ai-real-ctf-corpus.v1', cases:getAiRealCtfCorpus() };
  if (tool === 'ai-llm-aes-candidate-verify') return verifyLlmAesCandidates(payload.input || payload);
  if (tool === 'ai-backdoor-patch-candidate') return buildBackdoorPatchCandidate(payload.input || payload);
  if (tool === 'ai-backdoor-patch-verify') return verifyBackdoorPatchCandidate(payload.input || payload);
  if (tool === 'ai-model-arithmetic-auto') return analyzeModelArithmeticBundle(payload.input || payload, payload.options || {});
  if (tool === 'ai-image-raster-forensics') return analyzeRasterImage(payload.input || payload);
  if (tool === 'ai-image-raster-compare') return compareRasterImages(payload.input || payload);
  if (tool === 'ai-npy-sample-forensics') {
    const input = payload.input || payload;
    return analyzeNpySample(npyBuffer(input), input.fileName || 'sample.npy');
  }
  if (tool === 'ai-npy-sample-compare') {
    const input = payload.input || payload;
    return compareNpySamples(npyBuffer(input.left), npyBuffer(input.right));
  }
  if (tool === 'ai-tabular-profile') return analyzeTabularDataset(payload.input);
  if (tool === 'ai-tabular-candidate') return evaluateTabularCandidate(payload.input);
  if (tool === 'ai-adversarial-audit') return analyzeAdversarialPair(payload.input);
  if (tool === 'ai-adversarial-batch') return analyzeAdversarialBatch(payload.input || payload);
  if (tool === 'ai-adversarial-harness') return buildAdversarialHarness(payload.input || payload);
  if (tool === 'ai-privacy-audit') return analyzePrivacyTranscript(payload.input);
  if (tool === 'ai-privacy-harness') return buildPrivacyHarness(payload.input || payload);
  if (tool === 'ai-prompt-injection-suite') return buildPromptInjectionSuite(payload.input || payload.options || {});
  if (tool === 'ai-prompt-injection-evaluate') return evaluatePromptInjectionRun(payload.input || payload);
  if (tool === 'ai-prompt-injection-source') return auditPromptInjectionSource(payload.input);
  if (tool === 'ai-model-extraction') return analyzeModelExtractionTranscript(payload.input);
  if (tool === 'ai-model-extraction-harness') return buildModelExtractionHarness(payload.input || payload);
  if (tool === 'ai-ocr-extraction') return analyzeOcrExtractionTranscript(payload.input, payload.options || {});
  if (tool === 'ai-ocr-extraction-harness') return buildOcrExtractionHarness(payload.input || payload);
  if (tool === 'ai-model-inversion') return analyzeModelInversion(payload.input);
  if (tool === 'ai-dataset-security') return analyzeDatasetSecurity(payload.input);
  if (tool === 'ai-dataset-harness') return buildDatasetHarness(payload.input || payload);
  if (tool === 'ai-poisoning-impact') return analyzePoisoningImpact(payload.input || payload);
  if (tool === 'ai-backdoor-behavior') return analyzeBackdoorBehavior(payload.input || payload);
  if (tool === 'ai-supply-chain') return auditAiSupplyChain(payload.input);
  if (tool === 'ai-tooling-catalog') return { tools: toolingCatalog() };
  if (tool === 'evm-disasm') return analyzeEvmRuntime(payload.input);
  if (tool === 'auto-decode') return autoDecode(payload.input, { maxDepth: payload.maxDepth });
  if (tool === 'context-crypto') return decryptCryptoContext(payload.input);
  if (tool === 'knowledge-search') return {
    results: searchKnowledge(payload.input, payload.domain || null, { track: payload.track, limit: payload.limit }),
    stats: knowledgeStats()
  };
  if (tool === 'solana-source-scan') return auditSolanaAnchor(payload.input) || { language: 'unknown', findings: [], notes: ['未检测到 Anchor/Solana Rust 特征。'] };
  return toolbox.runTool(tool, payload);
}

module.exports = { runTool };
