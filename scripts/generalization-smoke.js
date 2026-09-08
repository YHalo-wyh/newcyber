#!/usr/bin/env node
const { auditSolidity } = require('../src/core/web3');
const { auditAiChallengeSource } = require('../src/core/ai_source');
const { analyzeAdversarialPair } = require('../src/core/ai_adversarial');
const { analyzePrivacyTranscript } = require('../src/core/ai_privacy');
const { analyzeDatasetSecurity } = require('../src/core/ai_dataset_security');
const { auditAiSupplyChain } = require('../src/core/ai_supply_chain');
const { decodeUdsAdvanced } = require('../src/core/vehicle_final');
const { analyzeMavlinkAdvanced } = require('../src/core/low_altitude_final');
const { decryptCryptoContext } = require('../src/core/context_crypto');
const { buildInvestigationGraph } = require('../src/core/investigation_graph');
const { generateSuite } = require('./generate-generalization-corpus');

function findingIds(result) {
  return new Set((result.findings || []).map((item) => item.id));
}

function severityAtMost(findings, maxSeverity = 'info') {
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const limit = rank[maxSeverity] ?? 0;
  return (findings || []).every((item) => (rank[item.severity] ?? 0) <= limit);
}

function privacyRiskAtMost(actual, maximum) {
  const rank = { weak: 0, low: 1, medium: 2, high: 3 };
  return (rank[actual] ?? 99) <= (rank[maximum] ?? -1);
}

function evaluateAiCase(item) {
  if (item.family === 'model-output-shell') {
    const ids = findingIds(auditAiChallengeSource(item.input));
    const hit = ids.has('ai-output-shell-injection');
    return { pass: item.positive ? hit : !hit, reason: hit ? 'shell-hit' : 'shell-absent' };
  }

  if (item.family === 'adversarial-budget') {
    const result = analyzeAdversarialPair(item.input);
    const pass = result.verdict === item.expected.verdict;
    return { pass, reason: pass ? `adversarial:${result.verdict}` : `adversarial:${result.verdict}!=${item.expected.verdict}` };
  }

  if (item.family === 'membership-inference') {
    const result = analyzePrivacyTranscript(item.input);
    const auc = result.strongestSignal?.auc;
    if (item.positive) {
      const pass = Number.isFinite(auc) && auc >= item.expected.minAuc && result.privacyRisk === item.expected.risk;
      return { pass, reason: pass ? `privacy:${result.privacyRisk}:${auc.toFixed(4)}` : `privacy-miss:${result.privacyRisk}:${auc ?? 'none'}` };
    }
    const pass = Number.isFinite(auc) && auc <= item.expected.maxAuc && privacyRiskAtMost(result.privacyRisk, item.expected.maxRisk);
    return { pass, reason: pass ? `privacy-negative:${result.privacyRisk}:${auc.toFixed(4)}` : `privacy-false-positive:${result.privacyRisk}:${auc ?? 'none'}` };
  }

  if (item.family === 'dataset-backdoor') {
    const result = analyzeDatasetSecurity(item.input);
    const triggerHit = result.triggerCandidates.some((candidate) => candidate.token === String(item.expected.trigger).toLowerCase());
    const conflictHit = result.conflictingLabels.length > 0;
    if (item.positive) {
      const pass = triggerHit && (!item.expected.conflict || conflictHit);
      return { pass, reason: pass ? 'dataset-trigger-and-conflict-hit' : `dataset-miss:trigger=${triggerHit}:conflict=${conflictHit}` };
    }
    const pass = (!item.expected.conflict || !conflictHit) && (!item.expected.noTrigger || result.triggerCandidates.length === 0) && !triggerHit;
    return { pass, reason: pass ? 'dataset-negative-clean' : `dataset-false-positive:triggers=${result.triggerCandidates.length}:conflict=${conflictHit}` };
  }

  if (item.family === 'model-supply-chain') {
    const result = auditAiSupplyChain(item.input);
    const ids = findingIds(result);
    if (item.positive) {
      const missing = (item.expected.findingIds || []).filter((id) => !ids.has(id));
      return { pass: missing.length === 0, reason: missing.length ? `supply-missing:${missing.join(',')}` : 'supply-positive-hit' };
    }
    const forbidden = (item.expected.absentFindingIds || []).filter((id) => ids.has(id));
    const severityOk = severityAtMost(result.findings, item.expected.maxSeverity || 'info');
    return { pass: forbidden.length === 0 && severityOk, reason: forbidden.length ? `supply-false-positive:${forbidden.join(',')}` : severityOk ? 'supply-negative-clean' : 'supply-severity-escalated' };
  }

  return { pass: false, reason: `unsupported-ai-family:${item.family}` };
}

function evaluateCase(item) {
  if (item.track === 'web3') {
    const audit = auditSolidity(item.input);
    const ids = findingIds(audit);
    if (item.positive) {
      const missing = (item.expected.findingIds || []).filter((id) => !ids.has(id));
      return { pass: missing.length === 0, reason: missing.length ? `missing:${missing.join(',')}` : 'positive-hit' };
    }
    const forbidden = (item.expected.absentFindingIds || []).filter((id) => ids.has(id));
    const trust = audit.findings.find((finding) => finding.id === 'external-contract-trust-boundary');
    const escalated = Boolean(trust && trust.severity !== 'low');
    return { pass: forbidden.length === 0 && !escalated, reason: forbidden.length ? `false-positive:${forbidden.join(',')}` : escalated ? `trust-escalated:${trust.severity}` : 'negative-rejected' };
  }

  if (item.track === 'ai') return evaluateAiCase(item);

  if (item.track === 'vehicle') {
    const lines = item.input.split(/\r?\n/);
    const request = decodeUdsAdvanced(lines[0]);
    const seed = decodeUdsAdvanced(lines[1]);
    const key = decodeUdsAdvanced(lines[2]);
    const outcome = decodeUdsAdvanced(lines[3]);
    const common = request.securityAccess?.meaning === 'requestSeed'
      && seed.securityAccess?.seedOrKey === `0x${item.expected.seedHex}`
      && key.securityAccess?.meaning === 'sendKey';
    const outcomeOk = item.positive ? outcome.securityAccess?.meaning === 'sendKey' : outcome.nrcName === 'invalidKey';
    return { pass: common && outcomeOk, reason: common && outcomeOk ? 'uds-state-hit' : 'uds-state-miss' };
  }

  if (item.track === 'lowalt') {
    const result = analyzeMavlinkAdvanced(item.input);
    const frame = result.frames?.[0];
    const pass = Boolean(frame)
      && frame.sysid === item.expected.sysid
      && frame.compid === item.expected.compid
      && frame.crc?.status === item.expected.crcStatus;
    return { pass, reason: pass ? 'mavlink-crc-hit' : `mavlink-mismatch:${frame?.crc?.status || 'no-frame'}` };
  }

  if (item.track === 'common') {
    const result = decryptCryptoContext(item.input);
    if (item.positive) return { pass: result.foundFlag === item.expected.flag, reason: result.foundFlag === item.expected.flag ? 'crypto-flag-hit' : 'crypto-flag-miss' };
    const pass = result.tried === 0 && result.context?.missing?.includes(item.expected.missing);
    return { pass, reason: pass ? 'missing-parameter-rejected' : 'unexpected-decrypt-attempt' };
  }

  return { pass: false, reason: 'unsupported-track' };
}

function findingsForRouting(item) {
  if (!item.positive) return null;
  if (item.track === 'web3') return { findings:auditSolidity(item.input).findings || [], file:'Challenge.sol', expectedTrack:'web3', tools:new Set(['evm-disasm','evm-calldata']) };
  if (item.family === 'model-output-shell') return { findings:auditAiChallengeSource(item.input).findings || [], file:'service.py', expectedTrack:'ai', tools:new Set(['ai-source-scan']) };
  if (item.family === 'adversarial-budget') return { findings:analyzeAdversarialPair(item.input).findings || [], file:'candidate.json', expectedTrack:'ai', tools:new Set(['ai-adversarial-audit']) };
  if (item.family === 'membership-inference') return { findings:analyzePrivacyTranscript(item.input).findings || [], file:'queries.csv', expectedTrack:'ai', tools:new Set(['ai-privacy-audit']) };
  if (item.family === 'dataset-backdoor') return { findings:analyzeDatasetSecurity(item.input).findings || [], file:'train.csv', expectedTrack:'ai', tools:new Set(['ai-dataset-security']) };
  if (item.family === 'model-supply-chain') return { findings:auditAiSupplyChain(item.input).findings || [], file:'service.py', expectedTrack:'ai', tools:new Set(['ai-supply-chain']) };
  return null;
}

function evaluateInvestigationRouting(item) {
  const source = findingsForRouting(item);
  if (!source) return null;
  if (!source.findings.length) return { pass:false, reason:'no-findings-for-routing' };
  const findings = source.findings.map((finding, index) => ({ ...finding, file:finding.file || source.file, id:finding.id || `route-${index}` }));
  const graph = buildInvestigationGraph({ findings, files:[{ path:source.file, metadata:{} }], stats:{ findings:findings.length } });
  const routed = graph.focus.find((node) => node.track === source.expectedTrack && source.tools.has(node.recommendedTool));
  if (!routed) {
    const observed = graph.focus.map((node) => `${node.track || 'none'}:${node.recommendedTool || 'none'}:${node.findingId || node.title}`).join('|');
    return { pass:false, reason:`route-miss:${observed || 'empty'}` };
  }
  if (routed.exploitability === 'confirmed' && !/(confirmed|accepted|valid|complete|found flag|回读确认)/i.test(`${routed.evidence} ${routed.title}`)) {
    return { pass:false, reason:`route-overclaimed-confirmed:${routed.findingId || routed.title}` };
  }
  return { pass:true, reason:`route:${routed.track}:${routed.recommendedTool}` };
}

function emptyStats() {
  return { passed: 0, total: 0, positivePassed: 0, positiveTotal: 0, negativePassed: 0, negativeTotal: 0 };
}

function record(stats, item, pass) {
  stats.total += 1;
  if (item.positive) stats.positiveTotal += 1;
  else stats.negativeTotal += 1;
  if (pass) {
    stats.passed += 1;
    if (item.positive) stats.positivePassed += 1;
    else stats.negativePassed += 1;
  }
}

function finalize(stats) {
  stats.score = stats.total ? Number((stats.passed / stats.total).toFixed(4)) : 0;
  stats.positiveRecall = stats.positiveTotal ? Number((stats.positivePassed / stats.positiveTotal).toFixed(4)) : null;
  stats.negativeAccuracy = stats.negativeTotal ? Number((stats.negativePassed / stats.negativeTotal).toFixed(4)) : null;
}

function scoreSuite(options = {}) {
  const seed = options.seed || 'newcyber-generalization-ci-v2';
  const count = Number.isInteger(options.count) ? options.count : 8;
  const suite = generateSuite({ seed, count });
  const tracks = {};
  const families = {};
  const routing = emptyStats();
  const failures = [];
  const routingFailures = [];

  for (const item of suite.cases) {
    const result = evaluateCase(item);
    if (!tracks[item.track]) tracks[item.track] = emptyStats();
    if (!families[item.family]) families[item.family] = emptyStats();
    record(tracks[item.track], item, result.pass);
    record(families[item.family], item, result.pass);
    if (!result.pass) failures.push({ id: item.id, track: item.track, family: item.family, positive: item.positive, reason: result.reason });

    const route = evaluateInvestigationRouting(item);
    if (route) {
      record(routing, item, route.pass);
      if (!route.pass) routingFailures.push({ id:item.id, track:item.track, family:item.family, reason:route.reason });
    }
  }

  let passed = 0;
  let total = 0;
  for (const stats of Object.values(tracks)) {
    finalize(stats);
    passed += stats.passed;
    total += stats.total;
  }
  for (const stats of Object.values(families)) finalize(stats);
  finalize(routing);

  return {
    version: suite.version || 2,
    seed,
    countPerFamily: count,
    tracks,
    families,
    investigationRouting:routing,
    overall: { passed, total, score: total ? Number((passed / total).toFixed(4)) : 0 },
    failures,
    routingFailures
  };
}

function parseArgs(argv) {
  const options = { seed: 'newcyber-generalization-ci-v2', count: 8, minScore: 1 };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--seed') options.seed = argv[++i];
    else if (argv[i] === '--count') options.count = Number(argv[++i]);
    else if (argv[i] === '--min-score') options.minScore = Number(argv[++i]);
  }
  return options;
}

if (require.main === module) {
  const options = parseArgs(process.argv);
  const report = scoreSuite(options);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const weakTrack = Object.entries(report.tracks).find(([, stats]) => stats.score < options.minScore);
  const weakFamily = Object.entries(report.families).find(([, stats]) => stats.score < options.minScore);
  const weakRouting = report.investigationRouting.total > 0 && report.investigationRouting.score < options.minScore;
  if (report.overall.score < options.minScore || weakTrack || weakFamily || weakRouting || report.failures.length || report.routingFailures.length) process.exitCode = 1;
}

module.exports = { findingIds, evaluateAiCase, evaluateCase, evaluateInvestigationRouting, scoreSuite };
