const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  verifyLlmAesCandidates,
  buildBackdoorPatchCandidate,
  verifyBackdoorPatchCandidate
} = require('../src/core/ai_candidate_verifier');
const { runAiRealCtfRegression } = require('../src/core/ai_real_ctf_regression_batch48');
const { runTool } = require('../src/core/tool_router');

function encryptedChallenge(candidate, plaintext = 'SUCTF{batch48_offline_verifier}') {
  const key = crypto.createHash('sha256').update(candidate, 'utf8').digest().subarray(0, 16);
  const iv = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  cipher.setAutoPadding(true);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return {
    algo: 'AES-128-CBC',
    iv_b64: iv.toString('base64'),
    ciphertext_b64: ciphertext.toString('base64'),
    key_derivation: 'key = SHA256(LLM_output)[:16]',
    llm: {
      provider: 'offline-fixture',
      model: 'deterministic-test',
      temperature: 0.28
    }
  };
}

function patchRaster(size = 32) {
  const data = [];
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const value = (x >= size - 5 && y >= size - 5) ? 255 : 96 + ((x + y) % 3);
      data.push(value, value, value, 255);
    }
  }
  return { width: size, height: size, channels: 4, data };
}

function strongBackdoorRows() {
  const rows = [];
  for (let i = 0; i < 10; i += 1) {
    const truth = String((i % 3) + 2);
    rows.push({
      true_label: truth,
      clean_pred: truth,
      triggered_pred: '1',
      control_pred: truth,
      target_label: '1'
    });
  }
  return rows;
}

test('Batch48 LLM→AES verifier closes only a concrete candidate that really decrypts to a flag', () => {
  const good = 'pw-abcdefgh';
  const challenge = encryptedChallenge(good);
  const result = verifyLlmAesCandidates({
    challenge,
    candidates: ['pw-wrongone', good, good]
  });

  assert.equal(result.schema, 'newcyber.ai-llm-aes-candidate-verifier.v1');
  assert.equal(result.candidateCount, 2);
  assert.equal(result.verified, true);
  assert.equal(result.verdict, 'verified');
  assert.equal(result.accepted.llmOutput, good);
  assert.deepEqual(result.accepted.flags, ['SUCTF{batch48_offline_verifier}']);
  assert.match(result.accepted.verifier, /SHA256\[:16\].*AES-128-CBC/i);
  assert.ok(result.attempts.some((item) => item.status === 'rejected'));
  assert.ok(result.attempts.some((item) => item.status === 'accepted'));
});

test('Batch48 LLM→AES verifier rejects wrong candidates and refuses unproven key derivation', () => {
  const challenge = encryptedChallenge('pw-realpass');
  const miss = verifyLlmAesCandidates({ challenge, candidates: ['pw-nopeaaaa', 'pw-nopebbbb'] });
  assert.equal(miss.verified, false);
  assert.equal(miss.verdict, 'candidates-rejected');
  assert.equal(miss.accepted, null);

  assert.throws(() => verifyLlmAesCandidates({
    challenge: { ...challenge, key_derivation: 'mystery KDF' },
    candidates: ['pw-realpass']
  }), /key_derivation|SHA256/i);
});

test('Batch48 cross-evidence generator turns the previously missed edge patch into a bound Candidate', () => {
  const result = buildBackdoorPatchCandidate({
    raster: patchRaster(),
    behavior: { targetLabel: '1', rows: strongBackdoorRows() }
  });

  assert.equal(result.schema, 'newcyber.ai-backdoor-patch-candidate.v1');
  assert.equal(result.recognized, true);
  assert.equal(result.candidate, true);
  assert.equal(result.verified, false);
  assert.ok(result.candidateObject);
  assert.equal(result.candidateObject.kind, 'localized-backdoor-trigger');
  assert.equal(result.candidateObject.targetLabel, '1');
  assert.match(result.candidateObject.candidateId, /^patch-[0-9a-f]{20}$/);
  assert.ok(result.candidateObject.patch.x >= 24 || result.candidateObject.patch.y >= 24);
  assert.ok(result.candidateObject.patch.score >= 0.55);
  assert.equal(result.candidateObject.verifier, 'ai-backdoor-patch-verify');
  assert.equal(result.verificationReady, true);
});

test('Batch48 patch verifier requires candidateId binding plus ASR/control specificity', () => {
  const generated = buildBackdoorPatchCandidate({
    raster: patchRaster(),
    behavior: { targetLabel: '1', rows: strongBackdoorRows() }
  });
  const candidate = generated.candidateObject;

  const mismatch = verifyBackdoorPatchCandidate({
    candidate,
    candidateId: 'patch-deadbeefdeadbeefdead',
    observations: { targetLabel: '1', rows: strongBackdoorRows() }
  });
  assert.equal(mismatch.verified, false);
  assert.equal(mismatch.verdict, 'candidate-binding-mismatch');

  const verified = verifyBackdoorPatchCandidate({
    candidate,
    candidateId: candidate.candidateId,
    observations: { targetLabel: '1', rows: strongBackdoorRows() }
  });
  assert.equal(verified.verified, true);
  assert.equal(verified.verdict, 'verified-on-provided-observations');
  assert.equal(verified.checks.asrOk, true);
  assert.equal(verified.checks.controlOk, true);
  assert.equal(verified.checks.specificityOk, true);

  const weakRows = strongBackdoorRows().map((row) => ({ ...row, control_pred: '1' }));
  const weak = verifyBackdoorPatchCandidate({
    candidate,
    candidateId: candidate.candidateId,
    observations: { targetLabel: '1', rows: weakRows }
  });
  assert.equal(weak.verified, false);
  assert.equal(weak.checks.controlOk, false);
});

test('Batch48 real CTF maturity advances CIFAR-10 without fabricating an original-oracle Verified', () => {
  const result = runAiRealCtfRegression();
  assert.equal(result.batch, 48);
  assert.equal(result.capabilitySchema, 'newcyber.ai-candidate-verifier.v1');
  assert.equal(result.summary.total, 11);
  assert.equal(result.summary.recognitionPass, 11);
  assert.ok(result.summary.candidatePass >= 2);
  assert.equal(result.summary.verifiedPass, 0);
  assert.ok(result.summary.verifierAvailable >= 3);

  const cifar = result.results.find((item) => item.challenge === 'CIFAR-10');
  assert.equal(cifar.status, 'pass');
  assert.equal(cifar.maturityStage, 'candidate');
  assert.equal(cifar.candidate, true);
  assert.equal(cifar.verified, false);
  assert.equal(cifar.verifierAvailable, 'ai-backdoor-patch-verify');
  assert.match(cifar.candidateEvidence, /bbox=.*target=1.*ASR=/);

  const easyLlm = result.results.find((item) => item.challenge === 'SU_easyLLM');
  assert.equal(easyLlm.maturityStage, 'recognized');
  assert.equal(easyLlm.candidate, false);
  assert.equal(easyLlm.verified, false);
  assert.equal(easyLlm.verifierAvailable, 'ai-llm-aes-candidate-verify');
  assert.match(easyLlm.limitation, /真实 LLM output candidate|保持 Recognized/);
});

test('Batch48 verifier tools are reachable through the normal offline tool router', () => {
  const good = 'pw-routerok';
  const challenge = encryptedChallenge(good, 'flag{router_batch48_ok}');
  const llm = runTool('ai-llm-aes-candidate-verify', { input: { challenge, candidates: [good] } });
  assert.equal(llm.verified, true);
  assert.deepEqual(llm.accepted.flags, ['flag{router_batch48_ok}']);

  const generated = runTool('ai-backdoor-patch-candidate', {
    input: { raster: patchRaster(), behavior: { targetLabel: '1', rows: strongBackdoorRows() } }
  });
  assert.equal(generated.candidate, true);
});
