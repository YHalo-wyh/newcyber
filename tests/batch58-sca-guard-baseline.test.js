'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  guardBaselineEvidence,resolveRealBundleFeatureRecipe,transformRealBundleRow,wrapBudgetedStreamingFeatureSource
}=require('../src/core/sca_real_bundle_feature_source');

function referenceStyleSource({guard=2,window=4,slots=1}={}){return `
SAMPLES_PER_FEATURE = ${window}
GUARD_SAMPLES = ${guard}
TRACE_DIM = ${slots}
base = np.hanning(SAMPLES_PER_FEATURE)
kernel = base / np.sum(base)
baseline_samples = np.concatenate([trace[:GUARD_SAMPLES], trace[-GUARD_SAMPLES:]])
baseline = float(np.mean(baseline_samples))
for f in range(TRACE_DIM):
    start = GUARD_SAMPLES + f * SAMPLES_PER_FEATURE
    slot = trace[start:start + SAMPLES_PER_FEATURE]
    centered = slot - baseline
    feat[f] = np.dot(centered, kernel)
`;}

function splitGuardSource(){return `
SLOT_WIDTH = 6
EDGE_GUARD = 3
TRACE_DIM = 2
hann = np.hanning(SLOT_WIDTH)
weights = hann / hann.sum()
left = row[:EDGE_GUARD]
right = row[-EDGE_GUARD:]
guards = np.concatenate((left, right))
noise_floor = np.average(guards)
for idx in range(TRACE_DIM):
    start = EDGE_GUARD + idx * SLOT_WIDTH
    window = row[start:start + SLOT_WIDTH]
    corrected = window - noise_floor
    score[idx] = np.inner(corrected, weights)
`;}

function recipe(source,rawCols){
  const result=resolveRealBundleFeatureRecipe({sourceText:source,manifest:{}},rawCols);
  assert.equal(result.status,'ok');
  return result.recipe;
}

test('Batch58 recovers reference-style edge guard baseline with provenance',()=>{
  const source=referenceStyleSource();
  const resolved=recipe(source,8);
  assert.equal(resolved.metric,'hann-dot');
  assert.deepEqual(resolved.baselineGuard&&{
    mode:resolved.baselineGuard.mode,
    leading:resolved.baselineGuard.leading,
    trailing:resolved.baselineGuard.trailing,
    subtract:resolved.baselineGuard.subtract
  },{mode:'edge-mean',leading:2,trailing:2,subtract:'feature-windows'});
  assert.match(resolved.evidence.join(' '),/guard-baseline-edge-mean/);
  assert.match(resolved.evidence.join(' '),/guard-baseline-subtracted-before-hann/);
  assert.match(resolved.baselineGuard.evidence.join(' '),/guard-mean:baseline/);
  assert.match(resolved.baselineGuard.evidence.join(' '),/guard-centered:centered/);
});

test('Batch58 baseline transform subtracts mean of both edge guards before Hann projection',()=>{
  const resolved=recipe(referenceStyleSource(),8);
  const row=[10,10,12,14,16,18,20,20];
  const withBaseline=transformRealBundleRow(row,resolved)[0];
  const withoutBaseline=transformRealBundleRow(row,{...resolved,baselineGuard:null})[0];
  assert.ok(Math.abs(withBaseline)<=1e-12,`expected centered Hann dot≈0, got ${withBaseline}`);
  assert.ok(Math.abs(withoutBaseline-22.5)<=1e-12,`expected raw Hann dot=22.5, got ${withoutBaseline}`);
});

test('Batch58 generalizes to split guard variables, np.average and np.inner with different dimensions',()=>{
  const source=splitGuardSource();
  const resolved=recipe(source,18);
  assert.equal(resolved.slots,2);
  assert.equal(resolved.windowSize,6);
  assert.equal(resolved.offset,3);
  assert.equal(resolved.baselineGuard.leading,3);
  assert.equal(resolved.baselineGuard.trailing,3);
  assert.match(resolved.baselineGuard.evidence.join(' '),/guard-mean:noise_floor/);
  assert.match(resolved.baselineGuard.evidence.join(' '),/baseline-linear-sink:np\.inner/);
});

test('Batch58 does not enable baseline when mean is not proven from both edge guards',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
TRACE_DIM = 1
h = np.hanning(SAMPLES_PER_FEATURE)
k = h / np.sum(h)
baseline = np.mean(trace[:GUARD_SAMPLES])
slot = trace[GUARD_SAMPLES:GUARD_SAMPLES + SAMPLES_PER_FEATURE]
centered = slot - baseline
feat = np.dot(centered, k)
`;
  const resolved=recipe(source,8);
  assert.equal(resolved.baselineGuard,undefined);
});

test('Batch58 does not enable baseline when edge mean exists but centered value does not feed Hann sink',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
TRACE_DIM = 1
h = np.hanning(SAMPLES_PER_FEATURE)
k = h / np.sum(h)
guards = np.concatenate([trace[:GUARD_SAMPLES], trace[-GUARD_SAMPLES:]])
baseline = np.mean(guards)
slot = trace[GUARD_SAMPLES:GUARD_SAMPLES + SAMPLES_PER_FEATURE]
centered = slot - baseline
feat = np.dot(slot, k)
`;
  const resolved=recipe(source,8);
  assert.equal(resolved.baselineGuard,undefined);
});

test('Batch58 ignores an unrelated baseline variable with no guard provenance',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
GUARD_SAMPLES = 2
TRACE_DIM = 1
h = np.hanning(SAMPLES_PER_FEATURE)
k = h / np.sum(h)
baseline = np.mean(calibration_vector)
slot = trace[GUARD_SAMPLES:GUARD_SAMPLES + SAMPLES_PER_FEATURE]
centered = slot - baseline
feat = np.dot(centered, k)
`;
  const resolved=recipe(source,8);
  assert.equal(resolved.baselineGuard,undefined);
});

test('Batch58 guard evidence fails closed when structural recipe lacks proven guard framing',()=>{
  const source=`
SAMPLES_PER_FEATURE = 4
TRACE_DIM = 1
h = np.hanning(SAMPLES_PER_FEATURE)
k = h / np.sum(h)
guards = np.concatenate([trace[:2], trace[-2:]])
baseline = np.mean(guards)
centered = trace[2:6] - baseline
feat = np.dot(centered, k)
`;
  const fakeRecipe={rawCols:8,metric:'hann-dot',evidence:['hann-window'],windows:[{offset:2,length:4,metric:'hann-dot',windowFunction:'hann'}]};
  const evidence=guardBaselineEvidence(source,fakeRecipe);
  assert.equal(evidence.status,'missing');
  assert.equal(evidence.reason,'guard-layout-not-proven');
});

test('Batch58 streaming wrapper applies baseline transform while preserving raw read budget',async()=>{
  const resolved=recipe(referenceStyleSource({guard:2,window:4,slots:1}),8);
  const calls=[];
  const raw={
    filePath:'/tmp/fake.npy',fileName:'fake.npy',sourceKind:'numeric',rows:3,cols:8,segments:[],
    async readRows(start,count){calls.push({start,count});return Array.from({length:count},()=>[10,10,12,14,16,18,20,20]);},
    async close(){}
  };
  const wrapped=wrapBudgetedStreamingFeatureSource(raw,resolved,{maxRawReadValues:16});
  assert.equal(wrapped.readBudget.rawChunkRows,2);
  assert.equal(wrapped.recipe.baselineGuard.mode,'edge-mean');
  const rows=await wrapped.readRows(0,3);
  assert.deepEqual(calls.map((x)=>x.count),[2,1]);
  assert.equal(rows.length,3);
  assert.ok(rows.every((item)=>Math.abs(item[0])<=1e-12));
});
