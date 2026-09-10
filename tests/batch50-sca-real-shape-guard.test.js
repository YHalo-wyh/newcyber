'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {sourceRecipe,resolveGroupedFeatureRecipe}=require('../src/core/sca_streaming_feature_source');

test('Batch50 recognizes real-style TRACE_DIM=64 SAMPLES_PER_TRACE=8 with a 16-sample prefix',()=>{
  const source=`
TRACE_DIM = 64
SAMPLES_PER_TRACE = 8
w = np.hanning(SAMPLES_PER_TRACE)
features = [np.sum((trace[16 + i*SAMPLES_PER_TRACE:16 + (i+1)*SAMPLES_PER_TRACE] * w) ** 2) for i in range(TRACE_DIM)]
`;
  const recipe=sourceRecipe(source,528);
  assert.ok(recipe);
  assert.equal(recipe.windowSize,8);
  assert.equal(recipe.slots,64);
  assert.equal(recipe.offset,16);
  assert.equal(recipe.windows[0].offset,16);
  assert.equal(recipe.windows[63].offset,520);
  assert.equal(recipe.windows[63].offset+recipe.windows[63].length,528);
});

test('Batch50 accepts an explicit zero FEATURE_OFFSET instead of treating zero as missing evidence',()=>{
  const source=`
WINDOW_SIZE = 8
FEATURE_SLOTS = 4
FEATURE_OFFSET = 0
w = torch.hann_window(WINDOW_SIZE)
features = [sum((trace[FEATURE_OFFSET + i*WINDOW_SIZE:FEATURE_OFFSET + (i+1)*WINDOW_SIZE] * w) ** 2) for i in range(FEATURE_SLOTS)]
`;
  const recipe=sourceRecipe(source,40);
  assert.ok(recipe);
  assert.equal(recipe.offset,0);
  assert.equal(recipe.slots,4);
});

test('Batch50 refuses raw 528 downgrade when source proves a 64-dimensional leakage representation but recipe is unresolved',()=>{
  const result=resolveGroupedFeatureRecipe({manifest:{},sourceText:'TRACE_DIM = 64\n# feature extraction omitted from supplied snippet\n'},528);
  assert.equal(result.status,'gap');
  assert.equal(result.code,'GROUP_FEATURE_RECIPE_GAP');
  assert.match(result.detail,/64.*528|528.*64/);
});
