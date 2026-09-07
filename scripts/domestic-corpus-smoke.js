const fs = require('fs/promises');
const path = require('path');
const { scanWorkspace, buildMarkdownReport } = require('../src/core/finals_analyzer');
const { decodeUdsAdvanced } = require('../src/core/vehicle');

function categoryScore(analysis, name) {
  return analysis.categories.find((item) => item.name === name)?.score || 0;
}

async function testUdsCtf(root) {
  const readme = await fs.readFile(path.join(root, 'README.md'), 'utf8');
  const requiredExamples = [
    '7DF#0322F190',
    '7DF#022701',
    '7DF#062702CCD9F897',
    '7DF#021002',
    '7DF#022703',
    '7DF#022705',
    '7DF#0723144000000050',
    '7DF#021101'
  ];
  for (const example of requiredExamples) {
    if (!readme.includes(example)) throw new Error(`UDSCTF corpus drift: missing ${example}`);
  }

  const vin = decodeUdsAdvanced('7DF#0322F190');
  if (vin.serviceName !== 'ReadDataByIdentifier' || vin.did !== '0xf190') throw new Error(`UDSCTF VIN decode failed: ${JSON.stringify(vin)}`);

  const seed1 = decodeUdsAdvanced('7DF#022701');
  if (seed1.securityAccess?.level !== 1 || seed1.securityAccess?.meaning !== 'requestSeed') throw new Error('UDSCTF level1 seed decode failed');

  const key1 = decodeUdsAdvanced('7DF#062702CCD9F897');
  if (key1.securityAccess?.meaning !== 'sendKey' || key1.securityAccess?.seedOrKey !== '0xccd9f897') throw new Error('UDSCTF level1 key decode failed');

  const programming = decodeUdsAdvanced('7DF#021002');
  if (programming.session?.name !== 'programmingSession') throw new Error('UDSCTF programming session decode failed');

  const readMemory = decodeUdsAdvanced('7DF#0723144000000050');
  if (readMemory.readMemory?.address !== '0x40000000' || readMemory.readMemory?.size !== '80') throw new Error(`UDSCTF ReadMemory decode failed: ${JSON.stringify(readMemory)}`);

  console.log('\n=== DOMESTIC UDSCTF ===');
  console.log(JSON.stringify({ vin: vin.did, level1: seed1.securityAccess, programming: programming.session, readMemory: readMemory.readMemory }, null, 2));
}

async function testSuEasyLlm(root) {
  const analysis = await scanWorkspace(path.resolve(root));
  const source = analysis.files.find((file) => /easyLLM\.py$/i.test(file.path));
  if (!source) throw new Error('SUCTF 2026 SU_easyLLM: easyLLM.py not found');
  const audit = source.metadata?.aiAudit;
  if (!audit) throw new Error('SUCTF 2026 SU_easyLLM: AI source audit did not trigger in normal workspace scan');
  if (!audit.findings.some((item) => item.id === 'llm-derived-crypto-key')) {
    throw new Error(`SUCTF 2026 SU_easyLLM: LLM-derived crypto key chain missed: ${JSON.stringify(audit.findings)}`);
  }
  if (!audit.findings.some((item) => item.id === 'llm-replay-parameters-exposed')) {
    throw new Error(`SUCTF 2026 SU_easyLLM: replay parameters exposure missed: ${JSON.stringify(audit.findings)}`);
  }
  if (!audit.llmCrypto?.temperatures?.includes(0.28)) throw new Error(`SUCTF 2026 SU_easyLLM: temperature 0.28 not recovered: ${JSON.stringify(audit.llmCrypto)}`);
  if (categoryScore(analysis, '人工智能') <= 0) throw new Error('SUCTF 2026 SU_easyLLM: 人工智能 category did not trigger');
  if (!analysis.recommendations.some((item) => /LLM 输出参与密钥派生/.test(item))) throw new Error('SUCTF 2026 SU_easyLLM: solving recommendation missing');

  const report = buildMarkdownReport(analysis, 'SUCTF 2026 SU_easyLLM public corpus');
  if (!report.includes('LLM→Crypto') || !report.includes('0.28')) throw new Error('SUCTF 2026 SU_easyLLM: exported report lost LLM crypto evidence');

  console.log('\n=== SUCTF 2026 SU_easyLLM ===');
  console.log(JSON.stringify({ category: categoryScore(analysis, '人工智能'), llmCrypto: audit.llmCrypto, findings: audit.findings.map((item) => item.id) }, null, 2));
}

async function testHackergameLlm(root) {
  const analysis = await scanWorkspace(path.resolve(root));
  const source = analysis.files.find((file) => /main\.py$/i.test(file.path));
  if (!source) throw new Error('Hackergame 2023 small LLM planet: main.py not found');
  const audit = source.metadata?.aiAudit;
  const challenge = audit?.generationChallenge;
  if (!challenge) throw new Error('Hackergame 2023 small LLM planet: generation challenge was not detected');
  if (!challenge.models?.includes('roneneldan/TinyStories-33M')) throw new Error(`Hackergame model id missed: ${JSON.stringify(challenge.models)}`);
  if (challenge.generation?.maxNewTokens !== 30 || challenge.generation?.numBeams !== 1) {
    throw new Error(`Hackergame generation config mismatch: ${JSON.stringify(challenge.generation)}`);
  }
  const targets = challenge.targets.map((item) => item.target);
  for (const target of ['you are smart', 'accepted', 'hackergame', '🐮']) {
    if (!targets.includes(target)) throw new Error(`Hackergame target oracle missed: ${target}`);
  }
  if (!challenge.deterministicGreedy) throw new Error('Hackergame greedy generation should be recognized as deterministic');
  if (categoryScore(analysis, '人工智能') <= 0) throw new Error('Hackergame corpus: 人工智能 category did not trigger');
  if (!analysis.recommendations.some((item) => /目标输出型生成题/.test(item))) throw new Error('Hackergame corpus: target-output recommendation missing');

  const report = buildMarkdownReport(analysis, 'Hackergame 2023 small LLM planet public corpus');
  if (!report.includes('Generation strategy') || !report.includes('hackergame')) throw new Error('Hackergame corpus: report lost target-output evidence');

  console.log('\n=== HACKERGAME 2023 SMALL LLM PLANET ===');
  console.log(JSON.stringify({ model: challenge.models, generation: challenge.generation, targets: challenge.targets }, null, 2));
}

async function testSuctfSolana(root) {
  const analysis = await scanWorkspace(path.resolve(root));
  const anchorConfigFile = analysis.files.find((file) => /Anchor\.toml$/i.test(file.path));
  if (!anchorConfigFile?.metadata?.anchorConfig) throw new Error('SUCTF 2025 Onchain_Checkin: Anchor.toml not parsed');
  const config = anchorConfigFile.metadata.anchorConfig;
  if (config.cluster !== 'devnet' || config.solanaVersion !== '2.0.20' || config.anchorVersion !== '0.30.1') {
    throw new Error(`SUCTF 2025 Onchain_Checkin: Anchor config mismatch: ${JSON.stringify(config)}`);
  }

  const programFile = analysis.files.find((file) => file.metadata?.solanaAudit?.programId);
  if (!programFile) throw new Error('SUCTF 2025 Onchain_Checkin: Anchor program source not detected');
  if (programFile.metadata.solanaAudit.programId !== 'SUCTF2Q25DnchainCheckin11111111111111111111') {
    throw new Error(`SUCTF 2025 Onchain_Checkin: Program ID mismatch: ${programFile.metadata.solanaAudit.programId}`);
  }

  const checkin = analysis.files.find((file) => /instructions[\\/]checkin\.rs$/i.test(file.path));
  const audit = checkin?.metadata?.solanaAudit;
  if (!audit) throw new Error('SUCTF 2025 Onchain_Checkin: checkin.rs was not audited');
  if (!audit.pdaSeeds.includes('checkin_state')) throw new Error(`SUCTF 2025 Onchain_Checkin: PDA seed missed: ${JSON.stringify(audit.pdaSeeds)}`);
  if (!audit.rawAccountInfos.some((item) => item.name === 'account3')) throw new Error(`SUCTF 2025 Onchain_Checkin: raw account3 missed: ${JSON.stringify(audit.rawAccountInfos)}`);
  if (!audit.findings.some((item) => item.id === 'raw-account-key-to-state')) throw new Error(`SUCTF 2025 Onchain_Checkin: account3 key-to-state flow missed: ${JSON.stringify(audit.findings)}`);
  if (!audit.messages.includes('flag1')) throw new Error(`SUCTF 2025 Onchain_Checkin: flag1 program log missed: ${JSON.stringify(audit.messages)}`);
  if (categoryScore(analysis, '区块链') <= 0) throw new Error('SUCTF 2025 Onchain_Checkin: 区块链 category did not trigger');

  const report = buildMarkdownReport(analysis, 'SUCTF 2025 Onchain_Checkin public corpus');
  if (!report.includes('SUCTF2Q25DnchainCheckin11111111111111111111') || !report.includes('checkin_state')) {
    throw new Error('SUCTF 2025 Onchain_Checkin: exported report lost Anchor evidence');
  }

  console.log('\n=== SUCTF 2025 Onchain_Checkin ===');
  console.log(JSON.stringify({ config, programId: programFile.metadata.solanaAudit.programId, pdaSeeds: audit.pdaSeeds, rawAccountInfos: audit.rawAccountInfos, messages: audit.messages }, null, 2));
}

async function main() {
  const uds = process.argv[2];
  const easyLlm = process.argv[3];
  const solana = process.argv[4];
  const hackergame = process.argv[5];
  if (!uds || !easyLlm || !solana || !hackergame) throw new Error('usage: node scripts/domestic-corpus-smoke.js <udsctf_dir> <su_easyllm_dir> <suctf_solana_dir> <hackergame_llm_dir>');

  await testUdsCtf(path.resolve(uds));
  await testSuEasyLlm(path.resolve(easyLlm));
  await testSuctfSolana(path.resolve(solana));
  await testHackergameLlm(path.resolve(hackergame));
  console.log('\nDomestic real-corpus assertions passed.');
}

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exitCode = 1;
});
