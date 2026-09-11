'use strict';

const { diagnoseAiSkillMatrix } = require('./ai_skill_matrix');
const { rankAdversarialContestCandidates } = require('./ai_adversarial_ctf');

const CONTEST_ALIASES = Object.freeze([
  'adversarialContest',
  'adversarial_contest',
  'contestRanking',
  'contest_ranking',
  'adversarialRanking',
  'adversarial_ranking'
]);

function parseMaybeJson(input) {
  if (input && typeof input === 'object') return input;
  const text = String(input || '').trim();
  if (!text || !/^[\[{]/.test(text)) return input;
  try { return JSON.parse(text); }
  catch { return input; }
}

function looksLikeContestBundle(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const hints = value.hints ?? value.hintPairs ?? value.transitions;
  const candidates = value.candidates ?? value.samples ?? value.rows;
  if (!Array.isArray(hints) || !hints.length || !Array.isArray(candidates) || !candidates.length) return false;
  return candidates.some((row) => row && typeof row === 'object' && (
    Array.isArray(row.scores) || Array.isArray(row.logits) || Array.isArray(row.output) || Array.isArray(row.predictionScores)
  ));
}

function extractContestInput(input) {
  const parsed = parseMaybeJson(input);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const root = parsed.artifacts && typeof parsed.artifacts === 'object' && !Array.isArray(parsed.artifacts)
    ? { ...parsed, ...parsed.artifacts }
    : parsed;
  for (const alias of CONTEST_ALIASES) {
    if (looksLikeContestBundle(root[alias])) return { input: root[alias], explicit: true, alias };
  }
  if (looksLikeContestBundle(root)) return { input: root, explicit: false, alias: 'generic' };
  return null;
}

function statusRank(status) {
  return ({ evidence: 3, candidate: 2, 'no-explicit-finding': 1, 'data-needed': 0 }[status] ?? 0);
}

function strongerStatus(current, next) {
  return statusRank(next) > statusRank(current) ? next : current;
}

function dedupe(values) {
  return [...new Set((values || []).filter(Boolean))];
}

function recomputeSummary(skills) {
  const counts = { evidence: 0, candidate: 0, 'no-explicit-finding': 0, 'data-needed': 0 };
  for (const skill of skills) counts[skill.status] = (counts[skill.status] || 0) + 1;
  return {
    ...counts,
    attentionNeeded: counts.evidence + counts.candidate,
    overall: counts.evidence ? 'evidence-present' : counts.candidate ? 'candidates-present' : 'needs-more-evidence'
  };
}

function contestMetrics(report) {
  const unresolved = (report.groups || []).filter((group) => !group.shortlist?.length).length;
  const ambiguous = (report.groups || []).filter((group) => group.ambiguous).length;
  return {
    contestHints: report.hints,
    contestCandidates: report.candidates,
    contestCandidateSets: report.candidateSets?.length || 0,
    contestUnresolved: unresolved,
    contestAmbiguous: ambiguous,
    contestTopIds: (report.groups || []).map((group) => group.top?.id).filter((value) => value !== undefined && value !== null)
  };
}

function contestStatus(report) {
  const groups = report.groups || [];
  const resolved = groups.filter((group) => group.shortlist?.length).length;
  if (report.candidateSets?.length && resolved === groups.length) return { status: 'candidate', confidence: 'medium' };
  if (resolved > 0) return { status: 'candidate', confidence: 'low' };
  return { status: 'no-explicit-finding', confidence: 'low' };
}

function withContestResult(base, contest, execution) {
  const skills = (base.skills || []).map((skill) => ({ ...skill, tools: [...(skill.tools || [])], findings: [...(skill.findings || [])], errors: [...(skill.errors || [])], attempted: [...(skill.attempted || [])], metrics: { ...(skill.metrics || {}) }, subskills: skill.subskills ? [...skill.subskills] : undefined }));
  const index = skills.findIndex((skill) => skill.id === 'adversarial-example');
  if (index < 0) return base;
  const skill = skills[index];
  skill.tools = dedupe([...skill.tools, 'ai-adversarial-contest-rank']);
  skill.attempted.push({ analyzer: 'adversarial-contest-ranking', ok: execution.ok, error: execution.ok ? null : execution.error });

  if (!execution.ok) {
    skill.errors.push(`adversarial-contest-ranking: ${execution.error}`);
    skill.nextAction = '赛式候选排名输入无法解析；补 hints、candidates 与每个候选的 logits/scores，保持类别编号与模型输出一致。';
  } else {
    const report = execution.result;
    const state = contestStatus(report);
    skill.status = strongerStatus(skill.status, state.status);
    if (statusRank(state.status) >= statusRank(skill.status)) skill.confidence = state.confidence;
    skill.findings.push(...(report.findings || []).map((finding) => ({ ...finding, analyzer: 'adversarial-contest-ranking' })));
    skill.metrics = { ...skill.metrics, ...contestMetrics(report) };
    const subskills = [...(skill.subskills || []).filter((item) => item.id !== 'contest-candidate-ranking')];
    subskills.push({ id: 'contest-candidate-ranking', status: state.status, confidence: state.confidence });
    skill.subskills = subskills;
    if (report.candidateSets?.length) {
      skill.nextAction = '已得到赛式候选组合；把排名靠前的 candidate sets 交给题目真实 verifier/hash。排名第一仍只是候选，不升级为 evidence。';
    } else {
      skill.nextAction = '当前 hint 尚未全部匹配候选；先核对类别映射、输出层与 preprocessing，再补充 logits/scores。';
    }
  }
  skills[index] = skill;

  const inputRouting = { ...(base.inputRouting || {}) };
  inputRouting.providedSlots = dedupe([...(inputRouting.providedSlots || []), 'adversarialContest']);
  inputRouting.detections = dedupe([...(inputRouting.detections || []), contest.explicit ? null : 'adversarialContest']);
  inputRouting.explicitSlots = dedupe([...(inputRouting.explicitSlots || []), contest.explicit ? 'adversarialContest' : null]);

  const queueRank = { candidate: 0, 'no-explicit-finding': 1, 'data-needed': 2 };
  const nextQueue = skills
    .filter((item) => item.status !== 'evidence')
    .sort((left, right) => (queueRank[left.status] ?? 9) - (queueRank[right.status] ?? 9))
    .map((item) => ({ skill: item.id, title: item.title, status: item.status, nextAction: item.nextAction, tools: item.tools }));

  return {
    ...base,
    matrixRevision: 3,
    extensions: dedupe([...(base.extensions || []), 'adversarial-contest-ranking']),
    inputRouting,
    summary: recomputeSummary(skills),
    skills,
    nextQueue,
    notes: [...(base.notes || []), '赛式对抗样本排名只产生 candidate；只有题目真实 verifier/hash 或等价 oracle 闭环后才能升级为 evidence。']
  };
}

function diagnoseAiSkillMatrixExtended(input) {
  const base = diagnoseAiSkillMatrix(input);
  const contest = extractContestInput(input);
  if (!contest) return base;
  let execution;
  try {
    execution = { ok: true, result: rankAdversarialContestCandidates(contest.input) };
  } catch (error) {
    execution = { ok: false, error: error?.message || String(error) };
  }
  return withContestResult(base, contest, execution);
}

module.exports = {
  CONTEST_ALIASES,
  looksLikeContestBundle,
  extractContestInput,
  diagnoseAiSkillMatrixExtended
};
