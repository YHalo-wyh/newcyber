const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const {
  OLD_DRIVER_TRAINING_FIXTURE,
  pythonSortedListString,
  legacyOldDriverDigest,
  rankAdversarialContestCandidates,
  getOldDriverTrainingCorpus,
  runOldDriverTrainingRegression
} = require('../src/core/ai_adversarial_ctf');
const { runTool } = require('../src/core/tool_router');

const root = path.join(__dirname, '..');

test('old_driver corpus keeps public provenance and synthetic-only training material', () => {
  const corpus = getOldDriverTrainingCorpus();
  assert.equal(corpus.length, 1);
  assert.equal(corpus[0].challenge, 'old_driver');
  assert.equal(corpus[0].direction, 'adversarial-example');
  assert.equal(corpus[0].provenance, 'public-writeup-derived');
  assert.ok(corpus[0].sources.some((source) => source.includes('secpulse.com/archives/152955')));
  assert.doesNotMatch(JSON.stringify(corpus), /flag\{/i);
  assert.equal(OLD_DRIVER_TRAINING_FIXTURE.hints.length, 3);
});

test('contest ranker hard-filters top2 label relation before heuristic ranking', () => {
  const report = rankAdversarialContestCandidates(OLD_DRIVER_TRAINING_FIXTURE);
  assert.equal(report.schema, 'newcyber.ai-adversarial-contest-ranking.v1');
  const group01 = report.groups.find((group) => String(group.hint.originLabel) === '0' && String(group.hint.adversarialLabel) === '1');
  assert.equal(group01.assignedPool, 3);
  assert.equal(group01.pairMatched, 2);
  assert.equal(String(group01.top.id), '101');
  assert.ok(group01.top.consensusTop);
  assert.ok(!group01.shortlist.some((row) => String(row.id) === '103'));
});

test('contest ranker keeps candidate combinations for final verifier instead of forcing one answer', () => {
  const report = rankAdversarialContestCandidates(OLD_DRIVER_TRAINING_FIXTURE);
  assert.equal(report.groups.length, 3);
  assert.ok(report.candidateSets.length >= 1);
  assert.ok(report.candidateSets.length <= 64);
  assert.equal(report.candidateSets[0].ids.length, 3);
  assert.ok(report.candidateSets.every((item) => item.legacyVerifier && /^[0-9a-f]{32}$/.test(item.legacyVerifier.digest)));
  assert.ok(report.findings.some((item) => item.id === 'adversarial-contest-candidate-sets-ready'));
});

test('legacy old_driver verifier reproduces public serialization shape without storing original answer', () => {
  assert.equal(pythonSortedListString(['304.png', 101, '206']), '[101, 206, 304]');
  const digest = legacyOldDriverDigest(['304.png', 101, '206']);
  assert.equal(digest.algorithm, 'md5');
  assert.equal(digest.serialization, 'python-str-sorted-int-list');
  assert.equal(digest.serialized, '[101, 206, 304]');
  assert.match(digest.digest, /^[0-9a-f]{32}$/);
  assert.equal(legacyOldDriverDigest(['not-numeric.png', 1]), null);
});

test('old_driver deterministic replay passes all synthetic checks', () => {
  const result = runOldDriverTrainingRegression();
  assert.equal(result.schema, 'newcyber.ai-old-driver-training-regression.v1');
  assert.equal(result.summary.total, 8);
  assert.equal(result.summary.pass, 8);
  assert.equal(result.summary.miss, 0);
  assert.ok(result.replay.candidateSets.length > 0);
});

test('tool router exposes contest ranker and old_driver training routes', () => {
  const corpus = runTool('ai-old-driver-training-corpus', {});
  assert.equal(corpus.schema, 'newcyber.ai-old-driver-corpus.v1');
  assert.equal(corpus.cases.length, 1);

  const regression = runTool('ai-old-driver-training-regression', {});
  assert.equal(regression.summary.pass, regression.summary.total);

  const ranked = runTool('ai-adversarial-contest-rank', { input: OLD_DRIVER_TRAINING_FIXTURE });
  assert.equal(ranked.groups.length, 3);
});

test('stage-one bench swaps domestic replay by active competition direction', () => {
  const source = fs.readFileSync(path.join(root, 'renderer/ai_skill_matrix_tools.js'), 'utf8');
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/ai_skill_matrix_tools.js' }));
  assert.match(source, /DOMESTIC CTF REPLAY/);
  assert.match(source, /old_driver 赛式排名/);
  assert.match(source, /ai-old-driver-training-regression/);
  assert.match(source, /Top-2 pair \/ margin \/ runner-up \/ beam \/ verifier/);
  assert.match(source, /i春秋赛题族/);
  assert.match(source, /activeDirection==='adversarial-example'/);
});
