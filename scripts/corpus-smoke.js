const fs = require('fs/promises');
const path = require('path');
const { scanWorkspace } = require('../src/core/workbench_analyzer');

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
    findings: analysis.findings.map((item) => ({ severity: item.severity, title: item.title, file: item.file, evidence: item.evidence }))
  };
  console.log(`\n=== CORPUS ${label} ===`);
  console.log(JSON.stringify(summary, null, 2));
  if (!analysis.stats.files) throw new Error(`${label}: no files discovered`);
  return analysis;
}

async function testEasyCan(analysis) {
  const capture = analysis.files.find((file) => file.path.toLowerCase().endsWith('.pcapng'));
  if (!capture) throw new Error('easy_can: PCAPNG capture not found');
  const pcapng = capture.metadata?.pcapng;
  if (!pcapng?.can) throw new Error(`easy_can: SocketCAN was not decoded in normal workspace scan; metadata=${JSON.stringify(capture.metadata || {})}`);

  const signal = pcapng.can.ids.find((item) => item.id === '0x188');
  if (!signal) throw new Error('easy_can: CAN ID 0x188 not found');
  const firstRightSignal = signal.transitions.find((event) => event.changes.some((change) => change.byteIndex === 0 && (change.setBits & 0x02) === 0x02));
  if (!firstRightSignal) throw new Error('easy_can: no first right-turn 0x02 transition found');

  console.log('\n=== EASY_CAN SOLVER CHECK ===');
  console.log(JSON.stringify({
    interfaces: pcapng.interfaces,
    parsedCanFrames: pcapng.can.parsedFrames,
    firstRightSignal
  }, null, 2));

  const expectedRaw = '00000188040000000200000000000000';
  if (firstRightSignal.rawFrameHex !== expectedRaw) {
    throw new Error(`easy_can: raw frame mismatch: expected ${expectedRaw}, got ${firstRightSignal.rawFrameHex}`);
  }
}

async function testSilentWeights(root, analysis) {
  const aiScore = analysis.categories.find((item) => item.name === 'AI / ML')?.score || 0;
  if (aiScore <= 0) throw new Error('SilentWeights: AI / ML classification did not trigger');
  const model = analysis.files.find((file) => ['.pth', '.pt'].includes(file.extension));
  if (!model) throw new Error('SilentWeights: PyTorch model artifact not found');

  const readme = await fs.readFile(path.join(root, 'README.txt'), 'utf8');
  const audit = model.metadata?.modelAudit;
  const inspection = model.metadata?.model;
  if (!inspection || !audit) throw new Error('SilentWeights: model deep inspection/audit did not reach normal workspace scan');

  console.log('\n=== SILENTWEIGHTS SAFE MODEL CHECK ===');
  console.log('README.txt:\n' + readme.trim());
  console.log('\nModel audit:\n' + JSON.stringify(audit, null, 2));

  if (!audit.unexpectedParameters.includes('feature_adapter.weight')) {
    throw new Error(`SilentWeights: expected feature_adapter.weight anomaly, got ${JSON.stringify(audit.unexpectedParameters)}`);
  }
  if (!audit.suspiciousMappings.some((item) => item.parameter === 'feature_adapter.weight' && /data\/8$/.test(item.storage))) {
    throw new Error(`SilentWeights: feature_adapter.weight was not associated with storage 8: ${JSON.stringify(audit.suspiciousMappings)}`);
  }
  if (!audit.storageOutliers.some((item) => /data\/8$/.test(item.name))) {
    throw new Error(`SilentWeights: storage 8 was not detected as size outlier: ${JSON.stringify(audit.storageOutliers)}`);
  }
  if (!analysis.findings.some((item) => item.file === model.path && item.title === '模型参数与训练日志不一致')) {
    throw new Error('SilentWeights: anomaly was not surfaced as a workspace finding');
  }
}

async function main() {
  const easyCan = process.argv[2];
  const silentWeights = process.argv[3];
  if (!easyCan || !silentWeights) throw new Error('usage: node scripts/corpus-smoke.js <easy_can_dir> <silentweights_dir>');

  const vehicle = await summarize('CISCN-2025-easy_can', easyCan);
  const ai = await summarize('WQB-2026-SilentWeights', silentWeights);

  await testEasyCan(vehicle);
  await testSilentWeights(path.resolve(silentWeights), ai);

  console.log('\nCorpus smoke assertions passed.');
}

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exitCode = 1;
});
