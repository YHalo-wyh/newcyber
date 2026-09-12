'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {
  FAMILY_CASES,runBatch57GeneralizationPressure
}=require('../src/core/ai_batch57_generalization_pressure');
const {
  staticProfilingRowCounts,staticRowsPerTokenEvidence
}=require('../src/core/sca_contextual_profile_hidden');
const {sourceRecipe}=require('../src/core/sca_streaming_feature_source');
const {indirectHannDotEvidence}=require('../src/core/sca_real_bundle_feature_source');

const root=path.join(__dirname,'..');

function walk(dir){
  const out=[];
  for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
    const full=path.join(dir,entry.name);
    if(entry.isDirectory())out.push(...walk(full));
    else if(entry.isFile()&&/\.(?:js|json|md)$/i.test(entry.name))out.push(full);
  }
  return out;
}

test('Batch57 128-case deterministic family pressure gate passes without challenge-specific rules',()=>{
  const report=runBatch57GeneralizationPressure();
  assert.equal(FAMILY_CASES,128);
  assert.equal(report.summary.total,128);
  assert.equal(report.summary.failed,0,report.results.filter((x)=>!x.passed).map((x)=>`${x.id}: ${x.error}`).join('\n'));
  assert.equal(report.summary.passed,128);
  assert.equal(report.summary.passRate,1);
  assert.equal(report.policy.familyHoldout,true);
  assert.equal(report.policy.failClosedNegatives,true);
});

test('Batch57 static evidence supports arithmetic aliases and explicit rows-per-token but rejects conflicts',()=>{
  const arithmetic=staticRowsPerTokenEvidence(`BASE=8\nWIDTH=2*BASE\nGROUPS=3*16\nHIDDEN_SIZE=WIDTH*GROUPS\nGROUP_SIZE=WIDTH`);
  assert.equal(arithmetic.status,'ok');
  assert.equal(arithmetic.rowsPerToken,48);
  assert.equal(arithmetic.hiddenSize,768);
  assert.equal(arithmetic.groupSize,16);

  const explicit=staticRowsPerTokenEvidence(`ROWS_PER_TOKEN=3*8`);
  assert.equal(explicit.status,'ok');
  assert.equal(explicit.rowsPerToken,24);
  assert.equal(explicit.source,'explicit-rows-per-token');

  const conflict=staticRowsPerTokenEvidence(`ROWS_PER_TOKEN=32\nHIDDEN_SIZE=768\nGROUP_SIZE=16`);
  assert.equal(conflict.status,'gap');
  assert.equal(conflict.code,'PROFILE_BOUNDARY_UNIT_CONFLICT_GAP');
});

test('Batch57 equivalent tuple boundary syntax stays static and exact',()=>{
  const source=`ROWS_PER_TOKEN=12\nPROFILING_ROW_COUNTS=(36, 60, 84, 108)`;
  const boundary=staticProfilingRowCounts(source,24);
  assert.equal(boundary.status,'ok');
  assert.equal(boundary.unit,'trace-rows');
  assert.equal(boundary.rowsPerToken,12);
  assert.deepEqual(boundary.counts,[3,5,7,9]);
});

test('Batch57 arithmetic feature constants generalize guarded Hann framing beyond the original dimensions',()=>{
  const windowSize=6,slots=20,guard=5,rawCols=guard*2+windowSize*slots;
  const source=`
BASE=3
SAMPLES_PER_FEATURE=2*BASE
TRACE_DIM=4*5
GUARD_SAMPLES=5
w=np.hanning(SAMPLES_PER_FEATURE)
for f in range(TRACE_DIM):
    slot=trace[GUARD_SAMPLES+f*SAMPLES_PER_FEATURE:GUARD_SAMPLES+(f+1)*SAMPLES_PER_FEATURE]
    value=np.dot(slot,w)
`;
  const recipe=sourceRecipe(source,rawCols);
  assert.ok(recipe);
  assert.equal(recipe.windowSize,windowSize);
  assert.equal(recipe.slots,slots);
  assert.equal(recipe.offset,guard);
  assert.equal(recipe.rawCols,rawCols);
});

test('Batch57 Hann dataflow accepts equivalent linear sinks but rejects unrelated or squared Hann use',()=>{
  for(const sink of ['np.inner(slot,kernel)','np.vdot(slot,kernel)','torch.dot(slot,kernel)','torch.inner(slot,kernel)','slot @ kernel']){
    const result=indirectHannDotEvidence(`base=np.hanning(10)\nkernel=base/base.sum()\nout=${sink}`);
    assert.equal(result.status,'ok',sink);
  }
  const unrelated=indirectHannDotEvidence(`window=np.hanning(10)\nplot(window)\nout=slot @ other_kernel`);
  assert.notEqual(unrelated.status,'ok');
  const squared=indirectHannDotEvidence(`window=np.hanning(10)\nout=np.sum((slot*window)**2)`);
  assert.notEqual(squared.status,'ok');
});

test('Batch57 production SCA core contains no challenge identity, recovered secret, or real-corpus cardinality magic',()=>{
  const files=walk(path.join(root,'src','core')).filter((file)=>/sca|side_channel|transformer_oracle/i.test(path.basename(file)));
  const forbidden=[
    '287424','5988','11010119880912564X','13855225864','长城杯','leakage_task','Great Wall Cup'
  ];
  for(const file of files){
    const text=fs.readFileSync(file,'utf8');
    for(const needle of forbidden)assert.equal(text.includes(needle),false,`${path.relative(root,file)} contains challenge-specific marker ${needle}`);
  }
});

test('Batch57 boundary parser does not borrow an unrelated later list after a dynamic assignment',()=>{
  const source=`
PROFILING_ROW_COUNTS = get_counts()
UNRELATED = [96, 144, 48]
ROWS_PER_TOKEN = 48
`;
  const result=staticProfilingRowCounts(source,6);
  assert.notEqual(result.status,'ok');
});
