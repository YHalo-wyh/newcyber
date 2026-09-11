'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  discoverHannReturningFunctions,hannKernelProvenance,indirectHannDotEvidence,
  guardBaselineEvidence,resolveRealBundleFeatureRecipe
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

function helperKernelSource(){return `
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
TRACE_DIM = 2

def feature_slot_kernel(width):
    base = np.hanning(width)
    normalized = base / np.sum(base)
    return normalized

kernel = feature_slot_kernel(SAMPLES_PER_FEATURE)
guards = np.concatenate([trace[:GUARD_SAMPLES], trace[-GUARD_SAMPLES:]])
baseline = np.mean(guards)
for f in range(TRACE_DIM):
    start = GUARD_SAMPLES + f * SAMPLES_PER_FEATURE
    slot = trace[start:start + SAMPLES_PER_FEATURE]
    centered = slot - baseline
    feat[f] = np.dot(centered, kernel)
`;}

test('Batch59 propagates Hann provenance through a bounded helper return into the linear sink',()=>{
  const source=helperKernelSource();
  const helpers=discoverHannReturningFunctions(source);
  assert.equal(helpers.functions.has('feature_slot_kernel'),true);
  assert.match(helpers.evidence.join(' '),/hann-function-return:feature_slot_kernel/);

  const provenance=hannKernelProvenance(source);
  assert.equal(provenance.tainted.has('kernel'),true);
  assert.match(provenance.evidence.join(' '),/hann-derived:kernel<-feature_slot_kernel\(\)/);

  const indirect=indirectHannDotEvidence(source);
  assert.equal(indirect.status,'ok');
  assert.equal(indirect.kernel,'kernel');

  const guard=guardBaselineEvidence(source,recipe());
  assert.equal(guard.status,'ok');
  assert.match(guard.baselineGuard.evidence.join(' '),/hann-function-return:feature_slot_kernel/);
  assert.match(guard.baselineGuard.evidence.join(' '),/baseline-hann-kernel:kernel/);
  assert.match(guard.baselineGuard.evidence.join(' '),/baseline-linear-sink:np\.dot/);
});

test('Batch59 helper-return provenance reaches full real-bundle recipe and enables guard baseline subtraction',()=>{
  const result=resolveRealBundleFeatureRecipe({sourceText:helperKernelSource(),manifest:{}},12);
  assert.equal(result.status,'ok');
  assert.equal(result.recipe.metric,'hann-dot');
  assert.equal(result.recipe.baselineGuard?.mode,'edge-mean');
  assert.match(result.recipe.evidence.join(' '),/indirect-hann-kernel/);
  assert.match(result.recipe.evidence.join(' '),/hann-function-return:feature_slot_kernel/);
  assert.match(result.recipe.evidence.join(' '),/guard-baseline-subtracted-before-hann/);
});

test('Batch59 refuses a helper that creates Hann data but returns an unrelated value',()=>{
  const source=`
def feature_slot_kernel(width):
    base = np.hanning(width)
    return unrelated_weights
kernel = feature_slot_kernel(4)
score = np.dot(centered, kernel)
`;
  const helpers=discoverHannReturningFunctions(source);
  assert.equal(helpers.functions.has('feature_slot_kernel'),false);
  const provenance=hannKernelProvenance(source);
  assert.equal(provenance.tainted.has('kernel'),false);
  assert.equal(indirectHannDotEvidence(source).status,'missing');
});

test('Batch59 refuses unknown transforms and branch-dependent helper returns',()=>{
  const unknown=`
def feature_slot_kernel(width):
    base = np.hanning(width)
    return custom_normalize(base)
kernel = feature_slot_kernel(4)
score = np.dot(centered, kernel)
`;
  const branched=`
def feature_slot_kernel(width):
    base = np.hanning(width)
    if width > 2:
        return base / np.sum(base)
    return base
kernel = feature_slot_kernel(4)
score = np.dot(centered, kernel)
`;
  assert.equal(discoverHannReturningFunctions(unknown).functions.size,0);
  assert.equal(discoverHannReturningFunctions(branched).functions.size,0);
  assert.equal(hannKernelProvenance(unknown).tainted.has('kernel'),false);
  assert.equal(hannKernelProvenance(branched).tainted.has('kernel'),false);
});
