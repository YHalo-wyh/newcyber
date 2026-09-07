#!/usr/bin/env node
const { auditSolidity } = require('../src/core/web3');
const { auditAiChallengeSource } = require('../src/core/ai_source');
const { decodeUdsAdvanced } = require('../src/core/vehicle_final');
const { analyzeMavlinkAdvanced } = require('../src/core/low_altitude_final');
const { decryptCryptoContext } = require('../src/core/context_crypto');
const { generateSuite } = require('./generate-generalization-corpus');

function findingIds(result) {
  return new Set((result.findings || []).map((item) => item.id));
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

  if (item.track === 'ai') {
    const ids = findingIds(auditAiChallengeSource(item.input));
    const hit = ids.has('ai-output-shell-injection');
    return { pass: item.positive ? hit : !hit, reason: hit ? 'shell-hit' : 'shell-absent' };
  }

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

function scoreSuite(options = {}) {
  const seed = options.seed || 'newcyber-generalization-ci-v1';
  const count = Number.isInteger(options.count) ? options.count : 8;
  const suite = generateSuite({ seed, count });
  const tracks = {};
  const failures = [];

  for (const item of suite.cases) {
    const result = evaluateCase(item);
    if (!tracks[item.track]) tracks[item.track] = { passed: 0, total: 0, positivePassed: 0, positiveTotal: 0, negativePassed: 0, negativeTotal: 0 };
    const stats = tracks[item.track];
    stats.total += 1;
    if (item.positive) stats.positiveTotal += 1;
    else stats.negativeTotal += 1;
    if (result.pass) {
      stats.passed += 1;
      if (item.positive) stats.positivePassed += 1;
      else stats.negativePassed += 1;
    } else failures.push({ id: item.id, track: item.track, family: item.family, positive: item.positive, reason: result.reason });
  }

  let passed = 0;
  let total = 0;
  for (const stats of Object.values(tracks)) {
    stats.score = stats.total ? Number((stats.passed / stats.total).toFixed(4)) : 0;
    stats.positiveRecall = stats.positiveTotal ? Number((stats.positivePassed / stats.positiveTotal).toFixed(4)) : null;
    stats.negativeAccuracy = stats.negativeTotal ? Number((stats.negativePassed / stats.negativeTotal).toFixed(4)) : null;
    passed += stats.passed;
    total += stats.total;
  }

  return {
    version: 1,
    seed,
    countPerTrack: count,
    tracks,
    overall: { passed, total, score: total ? Number((passed / total).toFixed(4)) : 0 },
    failures
  };
}

function parseArgs(argv) {
  const options = { seed: 'newcyber-generalization-ci-v1', count: 8, minScore: 1 };
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
  if (report.overall.score < options.minScore || weakTrack || report.failures.length) process.exitCode = 1;
}

module.exports = { evaluateCase, scoreSuite };
