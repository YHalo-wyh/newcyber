const toolbox = require('./toolbox');
const { analyzeCanAdvanced, decodeUdsAdvanced } = require('./vehicle_final');
const { auditAiChallengeSource } = require('./ai_source');
const { analyzeTabularDataset, evaluateTabularCandidate } = require('./ai_tabular');
const { auditSolanaAnchor } = require('./solana');
const { analyzeMavlinkAdvanced } = require('./low_altitude_final');
const { verifyMavlinkSignatureInput } = require('./mavlink_signing');
const { analyzeEvmRuntime } = require('./evm_runtime_batch4');
const { autoDecode } = require('./auto_decode');
const { decryptCryptoContext } = require('./context_crypto');

function runTool(tool, payload = {}) {
  if (tool === 'can-analyze') return analyzeCanAdvanced(payload.input);
  if (tool === 'uds-decode') return decodeUdsAdvanced(payload.input);
  if (tool === 'mavlink-hex') return analyzeMavlinkAdvanced(payload.input);
  if (tool === 'mavlink-signature-verify') return verifyMavlinkSignatureInput(payload.input);
  if (tool === 'ai-source-scan') return auditAiChallengeSource(payload.input);
  if (tool === 'ai-tabular-profile') return analyzeTabularDataset(payload.input);
  if (tool === 'ai-tabular-candidate') return evaluateTabularCandidate(payload.input);
  if (tool === 'evm-disasm') return analyzeEvmRuntime(payload.input);
  if (tool === 'auto-decode') return autoDecode(payload.input, { maxDepth: payload.maxDepth });
  if (tool === 'context-crypto') return decryptCryptoContext(payload.input);
  if (tool === 'solana-source-scan') return auditSolanaAnchor(payload.input) || { language: 'unknown', findings: [], notes: ['未检测到 Anchor/Solana Rust 特征。'] };
  return toolbox.runTool(tool, payload);
}

module.exports = { runTool };
