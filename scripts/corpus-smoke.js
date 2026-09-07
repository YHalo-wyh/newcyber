const fs = require('fs/promises');
const path = require('path');
const { scanWorkspace, buildMarkdownReport } = require('../src/core/workbench_analyzer');

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

async function testStarPwn(analysis) {
  const eeprom = analysis.files.find((file) => /eeprom\.bin$/i.test(file.path));
  if (!eeprom) throw new Error('STARPWN: eeprom.bin not found');
  const low = eeprom.metadata?.lowAltitude;
  if (!low) throw new Error(`STARPWN: normal workspace scan did not inspect EEPROM: ${JSON.stringify(eeprom.metadata || {})}`);
  if (low.format !== 'ArduPilot AP_Param EEPROM') throw new Error(`STARPWN: unexpected format ${low.format}`);
  if (!low.signing?.magicValid) throw new Error(`STARPWN: signing magic not validated: ${JSON.stringify(low.signing)}`);
  if (low.signing.offsetHex !== '0x1f80') throw new Error(`STARPWN: expected signing struct at 0x1f80, got ${low.signing.offsetHex}`);
  if (low.signing.keyLength !== 32 || low.signing.signingKeyHex.length !== 64) throw new Error('STARPWN: signing key length is not 32 bytes');
  if (!analysis.findings.some((item) => item.file === eeprom.path && /MAVLink 2 signing key/.test(item.title))) {
    throw new Error('STARPWN: signing key was not surfaced as a workspace finding');
  }
  if (!(analysis.categories.find((item) => item.name === '低空经济')?.score > 0)) throw new Error('STARPWN: low-altitude category did not trigger');

  console.log('\n=== STARPWN ONE-TO-RULE-THEM-ALL CHECK ===');
  console.log(JSON.stringify({
    format: low.format,
    header: low.header,
    revisionCandidate: low.revisionCandidate,
    signing: low.signing
  }, null, 2));

  const report = buildMarkdownReport(analysis, 'public StarPWN corpus');
  if (!report.includes(low.signing.signingKeyHex) || !report.includes(low.signing.offsetHex)) {
    throw new Error('STARPWN: exported report lost the signing-key evidence');
  }
}

async function testAbiSmuggling(analysis) {
  const solidity = analysis.files.find((file) => file.extension === '.sol');
  if (!solidity) throw new Error('ABI-Smuggling: Solidity source not found');
  const audit = solidity.metadata?.web3Audit;
  if (!audit) throw new Error('ABI-Smuggling: Solidity audit did not reach normal workspace scan');
  const abiFinding = audit.findings.find((item) => item.id === 'abi-smuggling-offset');
  if (!abiFinding || abiFinding.severity !== 'high') {
    throw new Error(`ABI-Smuggling: high-risk hardcoded calldata selector offset not detected: ${JSON.stringify(audit.findings)}`);
  }
  if (!audit.findings.some((item) => item.id === 'first-caller-init')) {
    throw new Error(`ABI-Smuggling: one-time public permission initialization was not detected: ${JSON.stringify(audit.findings)}`);
  }
  if (!analysis.findings.some((item) => item.file === solidity.path && item.id.startsWith('web3-abi-smuggling-offset:'))) {
    throw new Error('ABI-Smuggling: high-risk rule did not surface as a workspace finding');
  }
  if (!(analysis.categories.find((item) => item.name === '区块链')?.score > 0)) throw new Error('ABI-Smuggling: Web3 category did not trigger');

  console.log('\n=== DAMN VULNERABLE DEFI ABI-SMUGGLING CHECK ===');
  console.log(JSON.stringify(audit, null, 2));

  const report = buildMarkdownReport(analysis, 'public ABI-Smuggling corpus');
  if (!report.includes('abi-smuggling-offset')) throw new Error('ABI-Smuggling: exported report lost rule evidence');
}

async function main() {
  const easyCan = process.argv[2];
  const silentWeights = process.argv[3];
  const starPwn = process.argv[4];
  const web3 = process.argv[5];
  if (!easyCan || !silentWeights || !starPwn || !web3) {
    throw new Error('usage: node scripts/corpus-smoke.js <easy_can_dir> <silentweights_dir> <starpwn_dir> <web3_dir>');
  }

  const vehicle = await summarize('CISCN-2025-easy_can', easyCan);
  const ai = await summarize('WQB-2026-SilentWeights', silentWeights);
  const lowAltitude = await summarize('STARPWN-2026-One-to-Rule-Them-All', starPwn);
  const solidity = await summarize('Damn-Vulnerable-DeFi-ABI-Smuggling', web3);

  await testEasyCan(vehicle);
  await testSilentWeights(path.resolve(silentWeights), ai);
  await testStarPwn(lowAltitude);
  await testAbiSmuggling(solidity);

  console.log('\nAll four-track public corpus assertions passed.');
}

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exitCode = 1;
});
