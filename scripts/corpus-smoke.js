const path = require('path');
const { scanWorkspace } = require('../src/core/analyzer');

async function summarize(label, root) {
  const analysis = await scanWorkspace(path.resolve(root));
  const summary = {
    label,
    root: path.basename(root),
    stats: analysis.stats,
    categories: analysis.categories,
    files: analysis.files.map((file) => ({
      path: file.path,
      type: file.type,
      extension: file.extension,
      size: file.size,
      entropy: file.entropy,
      metadata: file.metadata
    })),
    findings: analysis.findings.map((item) => ({ severity: item.severity, title: item.title, file: item.file }))
  };
  console.log(`\n=== CORPUS ${label} ===`);
  console.log(JSON.stringify(summary, null, 2));
  if (!analysis.stats.files) throw new Error(`${label}: no files discovered`);
  return analysis;
}

async function main() {
  const easyCan = process.argv[2];
  const silentWeights = process.argv[3];
  if (!easyCan || !silentWeights) throw new Error('usage: node scripts/corpus-smoke.js <easy_can_dir> <silentweights_dir>');

  const vehicle = await summarize('CISCN-2025-easy_can', easyCan);
  const ai = await summarize('WQB-2026-SilentWeights', silentWeights);

  const hasCapture = vehicle.files.some((file) => /pcap|can|log|asc/i.test(`${file.path} ${file.type} ${file.extension}`));
  if (!hasCapture) throw new Error('easy_can: expected a CAN/capture-like artifact');

  const aiScore = ai.categories.find((item) => item.name === 'AI / ML')?.score || 0;
  if (aiScore <= 0) throw new Error('SilentWeights: AI / ML classification did not trigger');

  console.log('\nCorpus smoke assertions passed.');
}

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exitCode = 1;
});
