const toolbox = require('./toolbox');
const { analyzeCanAdvanced, decodeUdsAdvanced } = require('./vehicle_final');
const { auditAiChallengeSource } = require('./ai_source_batch9');
const { analyzeTabularDataset, evaluateTabularCandidate } = require('./ai_tabular');
const { analyzeAdversarialPair, buildAdversarialHarness } = require('./ai_adversarial');
const { analyzePrivacyTranscript, buildPrivacyHarness } = require('./ai_privacy');
const { analyzeDatasetSecurity, buildDatasetHarness } = require('./ai_dataset_security');
const { analyzePoisoningImpact, analyzeBackdoorBehavior } = require('./ai_poison_backdoor_validation');
const { auditAiSupplyChain } = require('./ai_supply_chain');
const { buildPromptInjectionSuite, evaluatePromptInjectionRun, auditPromptInjectionSource } = require('./ai_prompt_injection');
const { analyzeModelExtractionTranscript, buildModelExtractionHarness } = require('./ai_model_extraction');
const { analyzeOcrExtractionTranscript, buildOcrExtractionHarness } = require('./ai_ocr_extraction');
const { analyzeModelInversion } = require('./ai_model_inversion');
const { diagnoseAiSkillMatrix } = require('./ai_skill_matrix');
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
const { analyzeUavChallengeEvidence, getScenarioCatalog, parseWifiEvidence, analyzeFlightLog } = require('./uav_challenge_matrix_v4');

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
  if (tool === 'uav-regulatory-audit') return scanRegulatoryApi(payload.input);
  if (tool === 'uav-gnss-audit') return analyzeGnssLog(payload.input, payload.options || {});
  if (tool === 'uav-gnss-spectrum') return analyzeGnssSpectrum(payload.input, payload.options || {});
  if (tool === 'firmware-update-audit') return auditFirmwareUpdate(payload.input);
  if (tool === 'ai-source-scan') return auditAiChallengeSource(payload.input);
  if (tool === 'ai-skill-matrix') return diagnoseAiSkillMatrix(payload.input ?? payload);
  if (tool === 'ai-tabular-profile') return analyzeTabularDataset(payload.input);
  if (tool === 'ai-tabular-candidate') return evaluateTabularCandidate(payload.input);
  if (tool === 'ai-adversarial-audit') return analyzeAdversarialPair(payload.input);
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
