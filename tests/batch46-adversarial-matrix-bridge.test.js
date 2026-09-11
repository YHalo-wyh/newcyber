const test = require('node:test');
const assert = require('node:assert/strict');

const { OLD_DRIVER_TRAINING_FIXTURE } = require('../src/core/ai_adversarial_ctf');
const {
  looksLikeContestBundle,
  extractContestInput,
  diagnoseAiSkillMatrixExtended
} = require('../src/core/ai_skill_matrix_batch46');
const { runTool } = require('../src/core/tool_router');

test('contest bundle detection requires hints plus candidate logits', () => {
  assert.equal(looksLikeContestBundle(OLD_DRIVER_TRAINING_FIXTURE), true);
  assert.equal(looksLikeContestBundle({ hints: [[0, 1]], candidates: [{ id: 1 }] }), false);
  assert.equal(looksLikeContestBundle({ candidates: [{ logits: [0, 1] }] }), false);
});

test('contest input accepts explicit aliases and generic challenge payloads', () => {
  const explicit = extractContestInput({ adversarialContest: OLD_DRIVER_TRAINING_FIXTURE });
  assert.equal(explicit.explicit, true);
  assert.equal(explicit.alias, 'adversarialContest');

  const generic = extractContestInput(OLD_DRIVER_TRAINING_FIXTURE);
  assert.equal(generic.explicit, false);
  assert.equal(generic.alias, 'generic');

  const artifact = extractContestInput({ artifacts: { contestRanking: OLD_DRIVER_TRAINING_FIXTURE } });
  assert.equal(artifact.explicit, true);
  assert.equal(artifact.alias, 'contestRanking');
});

test('extended skill matrix classifies contest ranking as candidate rather than evidence', () => {
  const result = diagnoseAiSkillMatrixExtended({ adversarialContest: OLD_DRIVER_TRAINING_FIXTURE });
  assert.equal(result.schema, 'newcyber.ai-skill-matrix.v2');
  assert.equal(result.matrixRevision, 3);
  assert.ok(result.extensions.includes('adversarial-contest-ranking'));
  assert.ok(result.inputRouting.providedSlots.includes('adversarialContest'));
  assert.ok(result.inputRouting.explicitSlots.includes('adversarialContest'));

  const adversarial = result.skills.find((skill) => skill.id === 'adversarial-example');
  assert.equal(adversarial.status, 'candidate');
  assert.equal(adversarial.confidence, 'medium');
  assert.ok(adversarial.tools.includes('ai-adversarial-contest-rank'));
  assert.equal(adversarial.metrics.contestHints, 3);
  assert.equal(adversarial.metrics.contestCandidates, 8);
  assert.ok(adversarial.metrics.contestCandidateSets > 0);
  assert.equal(adversarial.metrics.contestUnresolved, 0);
  assert.ok(adversarial.subskills.some((item) => item.id === 'contest-candidate-ranking' && item.status === 'candidate'));
  assert.match(adversarial.nextAction, /真实 verifier\/hash/);
  assert.equal(result.summary.evidence, 0);
  assert.ok(result.summary.candidate >= 1);
});

test('generic contest payload is surfaced by routing without becoming verified evidence', () => {
  const result = runTool('ai-skill-matrix', { input: OLD_DRIVER_TRAINING_FIXTURE });
  assert.ok(result.inputRouting.detections.includes('adversarialContest'));
  const adversarial = result.skills.find((skill) => skill.id === 'adversarial-example');
  assert.equal(adversarial.status, 'candidate');
  assert.ok(adversarial.findings.some((finding) => finding.id === 'adversarial-contest-candidate-sets-ready'));
  assert.ok(adversarial.findings.every((finding) => finding.analyzer));
});

test('invalid explicit contest payload does not activate extension', () => {
  const result = diagnoseAiSkillMatrixExtended({ adversarialContest: { hints: [[0, 1]], candidates: [{ id: 1 }] } });
  assert.equal(result.matrixRevision, undefined);
  assert.equal(result.extensions, undefined);
});

test('normal stage-one matrix behavior stays backward compatible when no contest bundle exists', () => {
  const result = runTool('ai-skill-matrix', {
    input: {
      adversarial: {
        original: [0, 0],
        adversarial: [0.01, 0],
        epsilon: 0.1,
        norm: 'linf',
        trueLabel: 0,
        predictedAdversarial: 1
      }
    }
  });
  assert.equal(result.schema, 'newcyber.ai-skill-matrix.v2');
  assert.equal(result.matrixRevision, undefined);
  const adversarial = result.skills.find((skill) => skill.id === 'adversarial-example');
  assert.equal(adversarial.status, 'evidence');
});
