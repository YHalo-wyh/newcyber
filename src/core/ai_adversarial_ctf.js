'use strict';

const crypto = require('node:crypto');

const OLD_DRIVER_SOURCE = 'https://www.secpulse.com/archives/152955.html';

function parseInput(input) {
  if (input && typeof input === 'object') return input;
  const text = String(input || '').trim();
  if (!text) throw new Error('请输入 hints 与 candidates');
  try { return JSON.parse(text); }
  catch { throw new Error('赛式对抗样本排名输入应为 JSON'); }
}

function finiteScores(value) {
  if (!Array.isArray(value) || value.length < 2) throw new Error('candidate.scores/logits 至少需要两个类别分数');
  return value.map((item) => {
    const n = Number(item);
    if (!Number.isFinite(n)) throw new Error('candidate 分数中存在非有限数值');
    return n;
  });
}

function labelEq(a, b) {
  return String(a) === String(b);
}

function normalizeHints(input) {
  const rows = input.hints ?? input.hintPairs ?? input.transitions;
  if (!Array.isArray(rows) || !rows.length) throw new Error('需要 hints，例如 [[0,1],[1,0]]');
  return rows.map((row, index) => {
    if (Array.isArray(row) && row.length >= 2) {
      return { index, originLabel: row[0], adversarialLabel: row[1] };
    }
    if (row && typeof row === 'object') {
      const originLabel = row.originLabel ?? row.origin ?? row.from;
      const adversarialLabel = row.adversarialLabel ?? row.targetLabel ?? row.target ?? row.to;
      if (originLabel === undefined || adversarialLabel === undefined) throw new Error(`hint[${index}] 缺少 origin/target`);
      return { index, originLabel, adversarialLabel };
    }
    throw new Error(`hint[${index}] 格式无效`);
  });
}

function candidateScores(candidate) {
  return finiteScores(candidate.scores ?? candidate.logits ?? candidate.output ?? candidate.predictionScores);
}

function stableSoftmax(scores) {
  const max = Math.max(...scores);
  const exp = scores.map((value) => Math.exp(value - max));
  const sum = exp.reduce((a, b) => a + b, 0);
  return exp.map((value) => value / sum);
}

function rankScores(scores) {
  const probabilities = stableSoftmax(scores);
  return scores
    .map((score, label) => ({ label, score, probability: probabilities[label] }))
    .sort((a, b) => b.score - a.score || a.label - b.label);
}

function displayCandidateId(candidate, index) {
  return candidate.id ?? candidate.file ?? candidate.name ?? candidate.path ?? `candidate-${index}`;
}

function assignedLabel(candidate) {
  return candidate.assignedLabel ?? candidate.folderLabel ?? candidate.bucketLabel ?? candidate.classLabel ?? null;
}

function analyzeCandidate(candidate, index, hint) {
  const scores = candidateScores(candidate);
  const ranking = rankScores(scores);
  const top1 = ranking[0];
  const top2 = ranking[1];
  const assigned = assignedLabel(candidate);
  const assignedMatch = assigned === null ? true : labelEq(assigned, hint.adversarialLabel);
  const pairMatch = labelEq(top1.label, hint.adversarialLabel) && labelEq(top2.label, hint.originLabel);
  return {
    id: displayCandidateId(candidate, index),
    index,
    assignedLabel: assigned,
    originLabel: hint.originLabel,
    adversarialLabel: hint.adversarialLabel,
    top1,
    top2,
    logitMargin: top1.score - top2.score,
    probabilityMargin: top1.probability - top2.probability,
    runnerUpProbability: top2.probability,
    assignedMatch,
    pairMatch,
    eligible: assignedMatch && pairMatch
  };
}

function minMaxScore(value, values, invert = false) {
  if (!values.length) return 0;
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (Math.abs(max - min) < 1e-12) return 0.5;
  const normalized = (value - min) / (max - min);
  return invert ? 1 - normalized : normalized;
}

function enrichRanks(rows) {
  if (!rows.length) return rows;
  const margins = rows.map((row) => row.logitMargin);
  const runners = rows.map((row) => row.runnerUpProbability);
  const marginOrder = [...rows].sort((a, b) => a.logitMargin - b.logitMargin || b.runnerUpProbability - a.runnerUpProbability);
  const runnerOrder = [...rows].sort((a, b) => b.runnerUpProbability - a.runnerUpProbability || a.logitMargin - b.logitMargin);
  const marginRank = new Map(marginOrder.map((row, index) => [row.index, index + 1]));
  const runnerRank = new Map(runnerOrder.map((row, index) => [row.index, index + 1]));
  return rows.map((row) => {
    const marginCloseness = minMaxScore(row.logitMargin, margins, true);
    const runnerUpStrength = minMaxScore(row.runnerUpProbability, runners, false);
    const suspicionScore = 0.65 * marginCloseness + 0.35 * runnerUpStrength;
    return {
      ...row,
      marginRank: marginRank.get(row.index),
      runnerUpRank: runnerRank.get(row.index),
      suspicionScore,
      consensusTop: marginRank.get(row.index) === 1 && runnerRank.get(row.index) === 1
    };
  }).sort((a, b) => b.suspicionScore - a.suspicionScore || a.logitMargin - b.logitMargin || b.runnerUpProbability - a.runnerUpProbability);
}

function numericId(value) {
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  const text = String(value ?? '');
  const base = text.split(/[\\/]/).pop() || text;
  const match = base.match(/^(\d+)(?:\.[^.]+)?$/);
  return match ? Number(match[1]) : null;
}

function pythonSortedListString(ids) {
  const values = ids.map(numericId);
  if (values.some((value) => value === null)) return null;
  values.sort((a, b) => a - b);
  return `[${values.join(', ')}]`;
}

function legacyOldDriverDigest(ids) {
  const serialized = pythonSortedListString(ids);
  if (serialized === null) return null;
  return {
    algorithm: 'md5',
    serialization: 'python-str-sorted-int-list',
    serialized,
    digest: crypto.createHash('md5').update(serialized).digest('hex')
  };
}

function combineShortlists(groups, beamWidth = 2, maxSets = 64) {
  const usable = groups.filter((group) => group.shortlist.length);
  if (!usable.length || usable.length !== groups.length) return [];
  let beam = [{ ids: [], score: 0 }];
  for (const group of usable) {
    const next = [];
    for (const partial of beam) {
      for (const candidate of group.shortlist.slice(0, beamWidth)) {
        next.push({ ids: [...partial.ids, candidate.id], score: partial.score + candidate.suspicionScore });
      }
    }
    next.sort((a, b) => b.score - a.score || String(a.ids).localeCompare(String(b.ids)));
    beam = next.slice(0, maxSets);
  }
  return beam.map((item, index) => ({
    rank: index + 1,
    ids: item.ids,
    score: item.score,
    legacyVerifier: legacyOldDriverDigest(item.ids)
  }));
}

function rankAdversarialContestCandidates(input) {
  const data = parseInput(input);
  const hints = normalizeHints(data);
  const candidates = data.candidates ?? data.samples ?? data.rows;
  if (!Array.isArray(candidates) || !candidates.length) throw new Error('需要 candidates[]');
  if (candidates.length > 100000) throw new Error('候选样本超过 100000 行上限');
  const shortlistSize = Math.max(1, Math.min(10, Number(data.shortlistSize ?? 3) || 3));
  const beamWidth = Math.max(1, Math.min(shortlistSize, Number(data.beamWidth ?? 2) || 2));
  const maxSets = Math.max(1, Math.min(256, Number(data.maxSets ?? 64) || 64));

  const groups = hints.map((hint) => {
    const analyzed = candidates.map((candidate, index) => analyzeCandidate(candidate, index, hint));
    const eligible = enrichRanks(analyzed.filter((row) => row.eligible));
    const assignedPool = analyzed.filter((row) => row.assignedMatch);
    const shortlist = eligible.slice(0, shortlistSize);
    const top = shortlist[0] || null;
    return {
      hint,
      assignedPool: assignedPool.length,
      pairMatched: eligible.length,
      rejectedByPair: assignedPool.length - eligible.length,
      top,
      ambiguous: shortlist.length > 1 && !top?.consensusTop,
      shortlist
    };
  });

  const candidateSets = combineShortlists(groups, beamWidth, maxSets);
  const unresolved = groups.filter((group) => group.shortlist.length === 0);
  const ambiguous = groups.filter((group) => group.ambiguous);
  const findings = [];
  if (unresolved.length) findings.push({
    id: 'adversarial-contest-unresolved-hints',
    severity: 'medium',
    evidence: unresolved.map((group) => `${group.hint.originLabel}->${group.hint.adversarialLabel}`).join(', '),
    meaning: '部分 hint 没有满足“当前类别为目标类且模型 Top-2 对应目标类/原类”的候选，不能强行拼接答案。'
  });
  if (ambiguous.length) findings.push({
    id: 'adversarial-contest-ambiguous-ranking',
    severity: 'info',
    evidence: `${ambiguous.length}/${groups.length} hint groups have competing candidates`,
    meaning: '最小 Top-2 margin 与较强 runner-up 证据没有完全一致，保留 beam shortlist 比单点拍脑袋更稳。'
  });
  if (!unresolved.length && candidateSets.length) findings.push({
    id: 'adversarial-contest-candidate-sets-ready',
    severity: 'high',
    evidence: `${candidateSets.length} ranked candidate sets`,
    meaning: '所有 hint 都已有可解释候选，可把排名靠前的组合交给题目 verifier/hash 做最终确认。'
  });

  return {
    schema: 'newcyber.ai-adversarial-contest-ranking.v1',
    method: 'top2-pair + small-margin + runner-up-strength + beam',
    hints: hints.length,
    candidates: candidates.length,
    shortlistSize,
    beamWidth,
    groups,
    candidateSets,
    findings,
    notes: [
      '该排名器不执行模型，只消费题目已有 logits/scores。Top-1/Top-2 标签关系先做硬过滤，再用 margin 与 runner-up 强度排序。',
      'legacyVerifier 仅复现公开 old_driver WriteUp 中的 MD5(sorted numeric ids) 验证形式；它不会生成或内置原题答案。',
      '若题目 logits 经过温度缩放、归一化或类别映射，必须先与题目模型输出语义对齐。'
    ]
  };
}

const OLD_DRIVER_TRAINING_FIXTURE = Object.freeze({
  hints: Object.freeze([[0, 1], [2, 6], [3, 4]]),
  shortlistSize: 3,
  beamWidth: 2,
  candidates: Object.freeze([
    Object.freeze({ id: 101, assignedLabel: 1, scores: [4.92, 5.05, -1, -1, -1, -1, -1, -1, -1, -1] }),
    Object.freeze({ id: 102, assignedLabel: 1, scores: [3.10, 5.40, 2.20, -1, -1, -1, -1, -1, -1, -1] }),
    Object.freeze({ id: 103, assignedLabel: 1, scores: [2.50, 5.20, 4.90, -1, -1, -1, -1, -1, -1, -1] }),
    Object.freeze({ id: 206, assignedLabel: 6, scores: [-1, -1, 5.01, -1, -1, -1, 5.20, -1, -1, -1] }),
    Object.freeze({ id: 207, assignedLabel: 6, scores: [-1, -1, 5.08, -1, -1, -1, 5.34, -1, -1, -1] }),
    Object.freeze({ id: 208, assignedLabel: 6, scores: [-1, -1, 2.20, -1, -1, 4.80, 5.10, -1, -1, -1] }),
    Object.freeze({ id: 304, assignedLabel: 4, scores: [-1, -1, -1, 4.88, 5.00, -1, -1, -1, -1, -1] }),
    Object.freeze({ id: 305, assignedLabel: 4, scores: [-1, -1, -1, 3.00, 5.60, -1, -1, -1, -1, -1] })
  ])
});

function getOldDriverTrainingCorpus() {
  return [{
    id: 'spring-autumn-2021-old-driver',
    event: '春秋杯2021新年欢乐赛',
    challenge: 'old_driver',
    direction: 'adversarial-example',
    family: 'adversarial-sample-identification-by-logit-ranking',
    provenance: 'public-writeup-derived',
    sources: [OLD_DRIVER_SOURCE],
    publicEvidence: '公开 WriteUp 描述：每个目标类别中混入一个由原类别生成的对抗样本，hint 给出原类别→当前类别映射；模型输出 Top-2 标签关系、两者分差与 runner-up 强度可用于筛选候选。',
    capability: '从给定 logits/scores 与类别迁移 hint 中，先硬过滤 Top-2 标签关系，再对候选做 margin/runner-up 排名和组合 verifier。',
    fixtureHints: OLD_DRIVER_TRAINING_FIXTURE.hints.length,
    fixtureCandidates: OLD_DRIVER_TRAINING_FIXTURE.candidates.length
  }];
}

function runOldDriverTrainingRegression() {
  const report = rankAdversarialContestCandidates(OLD_DRIVER_TRAINING_FIXTURE);
  const groups = new Map(report.groups.map((group) => [`${group.hint.originLabel}->${group.hint.adversarialLabel}`, group]));
  const checks = [
    ['pair-filter-0-1', groups.get('0->1')?.pairMatched === 2],
    ['top-candidate-0-1', String(groups.get('0->1')?.top?.id) === '101'],
    ['wrong-runner-up-rejected', !(groups.get('0->1')?.shortlist || []).some((row) => String(row.id) === '103')],
    ['pair-filter-2-6', groups.get('2->6')?.pairMatched === 2],
    ['pair-filter-3-4', groups.get('3->4')?.pairMatched === 2],
    ['candidate-set-built', report.candidateSets.length > 0 && report.candidateSets[0].ids.length === 3],
    ['legacy-hash-available', Boolean(report.candidateSets[0]?.legacyVerifier?.digest)],
    ['no-real-flag-material', !/flag\{/i.test(JSON.stringify(getOldDriverTrainingCorpus()))]
  ].map(([id, ok]) => ({ id, status: ok ? 'pass' : 'miss' }));
  const pass = checks.filter((item) => item.status === 'pass').length;
  return {
    schema: 'newcyber.ai-old-driver-training-regression.v1',
    challenge: 'old_driver',
    source: OLD_DRIVER_SOURCE,
    summary: { total: checks.length, pass, miss: checks.length - pass },
    checks,
    replay: report,
    note: '训练回归只使用合成 logits 与合成编号复现公开解题结构，不保存原题候选编号或 Flag。'
  };
}

module.exports = {
  OLD_DRIVER_SOURCE,
  OLD_DRIVER_TRAINING_FIXTURE,
  stableSoftmax,
  rankScores,
  pythonSortedListString,
  legacyOldDriverDigest,
  rankAdversarialContestCandidates,
  getOldDriverTrainingCorpus,
  runOldDriverTrainingRegression
};
