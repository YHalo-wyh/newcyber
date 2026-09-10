'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const {
  staticProfilingRowCounts,reconstructProfilingSequences,extractSequenceHidden
}=require('../src/core/sca_contextual_profile_hidden');
const {
  indirectHannDotEvidence,resolveRealBundleFeatureRecipe,wrapBudgetedStreamingFeatureSource
}=require('../src/core/sca_real_bundle_feature_source');
const {resolveReducedProbe}=require('../src/core/sca_real_bundle_quality_core');
const batch56=require('../src/core/sca_autopilot_batch56');
const compat=require('../src/core/sca_autopilot_batch50');

function challengeIndirectHannSource(){return `
SAMPLES_PER_FEATURE = 8
GUARD_SAMPLES = 8
TRACE_DIM = 64
PROFILING_ROW_COUNTS = [2, 3, 1]
base = np.hanning(SAMPLES_PER_FEATURE)
kernel = base / np.sum(base)
for f in range(TRACE_DIM):
    start = GUARD_SAMPLES + f * SAMPLES_PER_FEATURE
    slot = trace[start:start + SAMPLES_PER_FEATURE]
    feat[f] = np.dot(slot, kernel)
`;}

function float32Npy(rows){
  const r=rows.length,c=rows[0].length;
  const header=`{'descr': '<f4', 'fortran_order': False, 'shape': (${r}, ${c}), }`;
  let headerBytes=Buffer.from(header,'latin1');
  const preamble=10;const padding=(16-((preamble+headerBytes.length+1)%16))%16;
  headerBytes=Buffer.from(header+' '.repeat(padding)+'\n','latin1');
  const prefix=Buffer.alloc(10);prefix[0]=0x93;prefix.write('NUMPY',1,'ascii');prefix[6]=1;prefix[7]=0;prefix.writeUInt16LE(headerBytes.length,8);
  const data=Buffer.alloc(r*c*4);let offset=0;
  for(const row of rows)for(const value of row){data.writeFloatLE(Number(value),offset);offset+=4;}
  return Buffer.concat([prefix,headerBytes,data]);
}

test('Batch56 parses static PROFILING_ROW_COUNTS and reconstructs full prompt boundaries',()=>{
  const source=challengeIndirectHannSource();
  const boundary=staticProfilingRowCounts(source,6);
  assert.equal(boundary.status,'ok');
  assert.equal(boundary.prompts,3);
  assert.deepEqual(boundary.counts,[2,3,1]);
  const rebuilt=reconstructProfilingSequences([[10],[11],[20],[21],[22],[30]],source);
  assert.equal(rebuilt.status,'ok');
  assert.deepEqual(rebuilt.sequences,[[10,11],[20,21,22],[30]]);
});

test('Batch56 rejects dynamic profiling boundary expressions instead of guessing',()=>{
  const result=staticProfilingRowCounts('PROFILING_ROW_COUNTS = [len(x) for x in prompts]',6);
  assert.notEqual(result.status,'ok');
});

test('Batch56 sequence hidden extractor keeps every contextual position, not only last hidden',()=>{
  const tensor={dims:[1,3,2],data:Float32Array.from([1,2,3,4,5,6])};
  const result=extractSequenceHidden(tensor,3);
  assert.ok(result);
  assert.equal(result.hiddenDim,2);
  assert.deepEqual(result.rows,[[1,2],[3,4],[5,6]]);
});

test('Batch56 follows multi-line indirect Hann kernel dataflow and restores hann-dot metric',()=>{
  const source=challengeIndirectHannSource();
  const evidence=indirectHannDotEvidence(source);
  assert.equal(evidence.status,'ok');
  assert.equal(evidence.kernel,'kernel');
  const result=resolveRealBundleFeatureRecipe({sourceText:source,manifest:{}},528);
  assert.equal(result.status,'ok');
  assert.equal(result.sourceMode,'indirect-hann-dataflow');
  assert.equal(result.recipe.metric,'hann-dot');
  assert.equal(result.recipe.windowFunction,'hann');
  assert.equal(result.recipe.slots,64);
  assert.equal(result.recipe.windowSize,8);
  assert.equal(result.recipe.offset,8);
  assert.match(result.recipe.evidence.join(' '),/indirect-hann-kernel/);
  assert.match(result.recipe.evidence.join(' '),/hann-dot-linear-amplitude/);
});

test('Batch56 feature wrapper chunks by raw 528-column read budget after exposing 64 effective columns',async()=>{
  const source=challengeIndirectHannSource();
  const recipe=resolveRealBundleFeatureRecipe({sourceText:source,manifest:{}},528).recipe;
  const calls=[];
  const raw={
    filePath:'/tmp/fake.npy',fileName:'fake.npy',sourceKind:'numeric',rows:5,cols:528,segments:[],
    async readRows(start,count){
      calls.push({start,count,values:count*528});
      if(count*528>1056)throw new Error('simulated npy_row_source raw value budget');
      return Array.from({length:count},()=>Array(528).fill(1));
    },async close(){}
  };
  const wrapped=wrapBudgetedStreamingFeatureSource(raw,recipe,{maxRawReadValues:1056});
  assert.equal(wrapped.cols,64);
  assert.equal(wrapped.readBudget.rawChunkRows,2);
  const rows=await wrapped.readRows(0,5);
  assert.equal(rows.length,5);
  assert.deepEqual(calls.map((x)=>x.count),[2,2,1]);
  assert.ok(calls.every((x)=>x.values<=1056));
});

test('Batch56 binds probe selection to candidate_vocab cardinality and ignores oversized/full-vocab shape',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b56-probe-'));
  try{
    const full=path.join(dir,'wte_probe.npy');const reduced=path.join(dir,'wte_probe_reduced.npy');
    await fs.writeFile(full,float32Npy(Array.from({length:10},(_,r)=>Array.from({length:4},(_,c)=>r+c))));
    await fs.writeFile(reduced,float32Npy(Array.from({length:3},(_,r)=>Array.from({length:4},(_,c)=>r-c))));
    const discovery={files:[
      {filePath:full,fileName:'wte_probe.npy',extension:'.npy'},
      {filePath:reduced,fileName:'wte_probe_reduced.npy',extension:'.npy'}
    ]};
    const selected=await resolveReducedProbe(discovery,3,4);
    assert.equal(selected.status,'ok');
    assert.equal(selected.file.fileName,'wte_probe_reduced.npy');
    assert.deepEqual(selected.shape,[3,4]);
    assert.equal(selected.orientation,'candidate-rows');
  }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('Batch50 stable production compatibility entry now routes to Batch56',()=>{
  assert.equal(compat.runScaAutopilotPaths,batch56.runScaAutopilotPaths);
});
