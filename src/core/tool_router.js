const toolbox = require('./toolbox');
const { analyzeCanAdvanced, decodeUdsAdvanced } = require('./vehicle_final');
const { auditAiChallengeSource } = require('./ai_source_batch9');
const { analyzeTabularDataset, evaluateTabularCandidate } = require('./ai_tabular');
const { analyzeAdversarialPair, buildAdversarialHarness } = require('./ai_adversarial');
const { analyzePrivacyTranscript, buildPrivacyHarness } = require('./ai_privacy');
const { analyzeDatasetSecurity, buildDatasetHarness } = require('./ai_dataset_security');
const { auditAiSupplyChain } = require('./ai_supply_chain');
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
  if (tool === 'ai-source-scan') return auditAiChallengeSource(payload.input);
  if (tool === 'ai-tabular-profile') return analyzeTabularDataset(payload.input);
  if (tool === 'ai-tabular-candidate') return evaluateTabularCandidate(payload.input);
  if (tool === 'ai-adversarial-audit') return analyzeAdversarialPair(payload.input);
  if (tool === 'ai-adversarial-harness') return buildAdversarialHarness(payload.input || payload);
  if (tool === 'ai-privacy-audit') return analyzePrivacyTranscript(payload.input);
  if (tool === 'ai-privacy-harness') return buildPrivacyHarness(payload.input || payload);
  if (tool === 'ai-dataset-security') return analyzeDatasetSecurity(payload.input);
  if (tool === 'ai-dataset-harness') return buildDatasetHarness(payload.input || payload);
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
