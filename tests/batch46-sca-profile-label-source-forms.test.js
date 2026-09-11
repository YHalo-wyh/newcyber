'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  parseNamedIntegerList,
  parseNamedRange,
  resolveProfileTokenSequences
}=require('../src/core/sca_profile_label_source');

test('Batch46 accepts lowercase profiling_input_ids wrapped in a static NumPy array',()=>{
  const parsed=parseNamedIntegerList('profiling_input_ids = np.array([3, 4, 5], dtype=np.int64)\n');
  assert.ok(parsed);
  assert.deepEqual(parsed.ids,[3,4,5]);
  assert.match(parsed.source,/profiling_input_ids:static-list/);
});

test('Batch46 statically evaluates one two and three argument range/arange forms',()=>{
  const one=parseNamedRange('profile_count = 5\ntraining_token_ids = list(range(profile_count))\n');
  assert.deepEqual(one.ids,[0,1,2,3,4]);
  const two=parseNamedRange('VOCAB_END = 6\nprofile_token_ids = np.arange(2, VOCAB_END)\n');
  assert.deepEqual(two.ids,[2,3,4,5]);
  const three=parseNamedRange('VOCAB_END = 8\nprofile_token_ids = torch.arange(1, VOCAB_END, 2)\n');
  assert.deepEqual(three.ids,[1,3,5,7]);
});

test('Batch46 refuses dynamic source expressions instead of executing or guessing them',()=>{
  assert.equal(parseNamedRange('profile_token_ids = torch.arange(len(dataset))\n'),null);
  assert.equal(parseNamedIntegerList('profile_token_ids = build_ids(dataset)\n'),null);
});

test('Batch46 accepts explicit manifest profiling/input-id aliases with count proof',async()=>{
  const discovery={manifest:{profilingInputIds:[11,12,13]},roles:{profileTokenIds:{status:'missing'}},sourceText:''};
  const result=await resolveProfileTokenSequences(discovery,{expectedTokens:3});
  assert.equal(result.status,'ok');
  assert.deepEqual(result.sequences,[[11],[12],[13]]);
  assert.equal(result.evidence.key,'profilingInputIds');
});
