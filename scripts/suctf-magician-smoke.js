const fs = require('fs/promises');
const path = require('path');
const { auditSolidity } = require('../src/core/web3');

async function main() {
  const file = process.argv[2];
  if (!file) throw new Error('usage: node scripts/suctf-magician-smoke.js <MagicBox.sol>');
  const source = await fs.readFile(path.resolve(file), 'utf8');
  if (!source.includes('alreadyUsedSignatureHash') || !source.includes('ecrecover')) {
    throw new Error('SUCTF 2025 Onchain Magician corpus drift');
  }
  const audit = auditSolidity(source);
  const finding = audit.findings.find((item) => item.id === 'ecdsa-signature-hash-replay');
  if (!finding) throw new Error(`SUCTF 2025 Onchain Magician: ECDSA malleability rule missed: ${JSON.stringify(audit.findings)}`);
  if (finding.severity !== 'high') throw new Error(`unexpected severity: ${finding.severity}`);
  console.log('\n=== SUCTF 2025 Onchain Magician ===');
  console.log(JSON.stringify({ summary: audit.summary, finding }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exitCode = 1;
});
