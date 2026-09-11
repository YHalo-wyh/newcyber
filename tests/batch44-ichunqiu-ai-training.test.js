const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const {
  ICHUNQIU_OFFICIAL_RISKS,
  ICHUNQIU_STAGE1_CASES,
  ICHUNQIU_EVENT_SIGNALS,
  evaluateFalsePremiseReplay,
  getIchunqiuAiTrainingCorpus,
  runIchunqiuAiTrainingRegression
} = require('../src/core/ai_ichunqiu_training');
const { runTool } = require('../src/core/tool_router');

const root = path.join(__dirname, '..');

test('i春秋 corpus records public provenance without copying real flags', () => {
  const corpus = getIchunqiuAiTrainingCorpus();
  assert.equal(corpus.length, 4);
  assert.deepEqual(
    corpus.map((item) => item.challenge),
    ['越狱的翻译官', '健忘的客服', '窥探内心', '幻觉诱导']
  );
  for (const item of corpus) {
    assert.equal(item.direction, 'prompt-llm-security');
    assert.equal(item.provenance, 'public-writeup-derived');
    assert.ok(item.sources.some((source) => source.includes('ichunqiu.com/competition/detail/378')));
    assert.ok(item.sources.some((source) => source.includes('integritytech.com.cn/html/News/News_836_1.html')));
    assert.ok(item.officialRiskTags.length >= 1);
    assert.ok(item.variantCount >= 3);
  }
  assert.doesNotMatch(JSON.stringify(ICHUNQIU_STAGE1_CASES), /flag\{/i);
});

test('official i春秋 AI risk taxonomy is fully represented by challenge-derived families', () => {
  assert.deepEqual(
    ICHUNQIU_OFFICIAL_RISKS.map((item) => item.id),
    ['prompt-injection', 'sensitive-information-leakage', 'system-prompt-leakage', 'incorrect-information-exposure']
  );
  const result = runIchunqiuAiTrainingRegression();
  assert.equal(result.summary.officialRiskCovered, 4);
  assert.equal(result.summary.officialRiskTotal, 4);
  assert.deepEqual(result.summary.officialRiskMissing, []);
  assert.equal(result.officialRisks.length, 4);

  const byChallenge = new Map(getIchunqiuAiTrainingCorpus().map((item) => [item.challenge, item]));
  assert.ok(byChallenge.get('越狱的翻译官').officialRiskTags.includes('system-prompt-leakage'));
  assert.ok(byChallenge.get('健忘的客服').officialRiskTags.includes('sensitive-information-leakage'));
  assert.ok(byChallenge.get('窥探内心').officialRiskTags.includes('system-prompt-leakage'));
  assert.deepEqual(byChallenge.get('幻觉诱导').officialRiskTags, ['incorrect-information-exposure']);
});

test('i春秋 competition replay covers positive evidence and negative controls', () => {
  const result = runIchunqiuAiTrainingRegression();
  assert.equal(result.schema, 'newcyber.ai-ichunqiu-stage1-regression.v1');
  assert.equal(result.summary.challenges, 4);
  assert.equal(result.summary.families, 4);
  assert.equal(result.summary.total, 12);
  assert.equal(result.summary.pass, 12);
  assert.equal(result.summary.miss, 0);
  assert.ok(result.summary.failureExpected >= 7);
  assert.ok(result.summary.controls >= 4);

  const translator = result.results.filter((item) => item.challenge === '越狱的翻译官');
  assert.ok(translator.some((item) => item.findingIds.includes('prompt-injection-canary-exposed')));
  assert.ok(translator.some((item) => item.actual === 'no-explicit-failure'));

  const hallucination = result.results.filter((item) => item.challenge === '幻觉诱导');
  assert.ok(hallucination.some((item) => item.findingIds.includes('llm-false-premise-accepted')));
  assert.ok(hallucination.some((item) => item.actual === 'no-explicit-failure'));
  assert.match(result.note, /PASS.*不代表已经自动攻破原比赛模型/);
});

test('false-premise replay depends on structured judge evidence, not response keywords', () => {
  const accepted = evaluateFalsePremiseReplay({
    claimId: 'unit-false-claim',
    groundTruth: false,
    judgeAccepted: true,
    response: 'arbitrary wording'
  });
  assert.equal(accepted.verdict, 'candidate-failure');
  assert.ok(accepted.findings.some((item) => item.id === 'llm-false-premise-accepted'));

  const noJudge = evaluateFalsePremiseReplay({
    claimId: 'unit-false-claim',
    groundTruth: false,
    judgeAccepted: false,
    response: 'TRAINING_FALSE_CLAIM_ACCEPTED_C204'
  });
  assert.equal(noJudge.verdict, 'no-explicit-failure');
  assert.equal(noJudge.findings.length, 0);
});

test('tool router exposes i春秋 corpus, regression and hallucination replay', () => {
  const corpus = runTool('ai-ichunqiu-training-corpus', {});
  assert.equal(corpus.schema, 'newcyber.ai-ichunqiu-stage1-corpus.v1');
  assert.equal(corpus.cases.length, 4);

  const regression = runTool('ai-ichunqiu-training-regression', {});
  assert.equal(regression.summary.pass, regression.summary.total);
  assert.equal(regression.summary.officialRiskCovered, regression.summary.officialRiskTotal);

  const replay = runTool('ai-false-premise-replay', {
    input: { claimId: 'router-case', groundTruth: false, judgeAccepted: true }
  });
  assert.equal(replay.verdict, 'candidate-failure');
});

test('2024 i春秋 large-model-security event is kept as event-only signal', () => {
  assert.ok(ICHUNQIU_EVENT_SIGNALS.some((item) => item.event.includes('2024巅峰极客')));
  const signal = ICHUNQIU_EVENT_SIGNALS.find((item) => item.event.includes('2024巅峰极客'));
  assert.equal(signal.provenance, 'official-event-only');
  assert.match(signal.note, /不虚构训练样本/);
});

test('stage-one bench exposes a separate domestic CTF replay without replacing the five-direction corpus', () => {
  const source = fs.readFileSync(path.join(root, 'renderer/ai_skill_matrix_tools.js'), 'utf8');
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/ai_skill_matrix_tools.js' }));
  assert.match(source, /DOMESTIC CTF REPLAY/);
  assert.match(source, /i春秋赛题族/);
  assert.match(source, /ai-ichunqiu-training-regression/);
  assert.match(source, /越狱的翻译官 \/ 健忘的客服 \/ 窥探内心 \/ 幻觉诱导/);
  assert.match(source, /ai-stage1-training-regression/);
});
