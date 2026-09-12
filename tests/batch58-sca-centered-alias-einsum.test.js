'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  indirectHannDotEvidence,guardBaselineEvidence
}=require('../src/core/sca_real_bundle_feature_source');

function recipe(){
  return {
    rawCols:12,
    metric:'hann-dot',
    evidence:['guard-framing'],
    windows:[
      {offset:2,length:4,metric:'hann-dot',windowFunction:'hann'},
      {offset:6,length:4,metric:'hann-dot',windowFunction:'hann'}
    ]
  };
}

test('Batch58 follow-up propagates centered provenance through slice alias into np.dot',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
h = np.hanning(SAMPLES_PER_FEATURE)
kernel = h / np.sum(h)
guards = np.concatenate([trace[:GUARD_SAMPLES], trace[-GUARD_SAMPLES:]])
baseline = float(np.mean(guards))
window = trace[GUARD_SAMPLES:GUARD_SAMPLES + SAMPLES_PER_FEATURE]
centered = window - baseline
slot_start = 0
slot_end = SAMPLES_PER_FEATURE
slot = centered[slot_start:slot_end]
score = np.dot(slot, kernel)
`;
  const result=guardBaselineEvidence(source,recipe());
  assert.equal(result.status,'ok');
  assert.match(result.baselineGuard.evidence.join(' '),/guard-centered-alias:slot<-centered/);
  assert.match(result.baselineGuard.evidence.join(' '),/baseline-hann-kernel:kernel/);
  assert.match(result.baselineGuard.evidence.join(' '),/baseline-linear-sink:np\.dot/);
});

test('Batch58 follow-up accepts vectorized centered slice feeding np.einsum with Hann kernel',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
hann = numpy.hanning(SAMPLES_PER_FEATURE)
kernel = hann / np.sum(hann)
left = trace[:GUARD_SAMPLES]
right = trace[-GUARD_SAMPLES:]
guards = np.concatenate((left, right))
baseline = np.average(guards)
centered = trace - baseline
slots = centered[:, GUARD_SAMPLES:-GUARD_SAMPLES]
features = np.einsum("rfs,s->rf", slots, kernel)
`;
  const indirect=indirectHannDotEvidence(source);
  assert.equal(indirect.status,'ok');
  assert.equal(indirect.sink.toLowerCase(),'np.einsum');
  const result=guardBaselineEvidence(source,recipe());
  assert.equal(result.status,'ok');
  assert.match(result.baselineGuard.evidence.join(' '),/guard-centered-alias:slots<-centered/);
  assert.match(result.baselineGuard.evidence.join(' '),/baseline-linear-sink:np\.einsum/);
});

test('Batch58 follow-up propagates safe reshape aliases without treating them as new semantics',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
h = np.hanning(SAMPLES_PER_FEATURE)
kernel = h / np.sum(h)
guards = np.concatenate([trace[:GUARD_SAMPLES], trace[-GUARD_SAMPLES:]])
baseline = np.mean(guards)
centered = trace - baseline
feature_band = centered[GUARD_SAMPLES:-GUARD_SAMPLES]
slots = np.reshape(feature_band, (2, SAMPLES_PER_FEATURE))
features = np.einsum("fs,s->f", slots, kernel)
`;
  const result=guardBaselineEvidence(source,recipe());
  assert.equal(result.status,'ok');
  assert.match(result.baselineGuard.evidence.join(' '),/guard-centered-alias:feature_band<-centered/);
  assert.match(result.baselineGuard.evidence.join(' '),/guard-centered-alias:slots<-feature_band/);
});

test('Batch58 follow-up does not accept centered data flowing into an unrelated einsum',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
h = np.hanning(SAMPLES_PER_FEATURE)
kernel = h / np.sum(h)
guards = np.concatenate([trace[:GUARD_SAMPLES], trace[-GUARD_SAMPLES:]])
baseline = np.mean(guards)
centered = trace - baseline
slot = centered[GUARD_SAMPLES:GUARD_SAMPLES + SAMPLES_PER_FEATURE]
decoy = np.einsum("s,s->", slot, unrelated_weights)
raw_slot = trace[GUARD_SAMPLES:GUARD_SAMPLES + SAMPLES_PER_FEATURE]
reference = np.dot(raw_slot, kernel)
`;
  const result=guardBaselineEvidence(source,recipe());
  assert.equal(result.status,'missing');
  assert.equal(result.reason,'centered-value-does-not-feed-linear-sink');
});

test('Batch58 follow-up refuses nonlinear centered aliases before a Hann sink',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
h = np.hanning(SAMPLES_PER_FEATURE)
kernel = h / np.sum(h)
guards = np.concatenate([trace[:GUARD_SAMPLES], trace[-GUARD_SAMPLES:]])
baseline = np.mean(guards)
centered = trace - baseline
slot = np.square(centered)
score = np.dot(slot, kernel)
`;
  const result=guardBaselineEvidence(source,recipe());
  assert.equal(result.status,'missing');
  assert.equal(result.reason,'centered-value-does-not-feed-linear-sink');
});