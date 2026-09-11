'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  evaluateBinaryDetectionReplay,
  evaluateLossHistoryPoisonReplay,
  getDomesticDetectionTrainingCorpus,
  runDomesticDetectionTrainingRegression
}=require('../src/core/ai_domestic_detection_training');
const {getTrainingCurriculum}=require('../src/core/ai_training_curriculum');
const {detectSignals,matchTrainingFamilies}=require('../src/core/ai_training_family_matcher');
const {runTool}=require('../src/core/tool_router');

test('Batch75 independently recomputes binary detector confusion matrix and metrics',()=>{
  const result=evaluateBinaryDetectionReplay({rows:[
    {id:'p1',truth:1,predicted:1},{id:'p2',truth:1,predicted:1},{id:'p3',truth:1,predicted:1},{id:'p4',truth:1,predicted:0},
    {id:'n1',truth:0,predicted:0},{id:'n2',truth:0,predicted:0},{id:'n3',truth:0,predicted:0},{id:'n4',truth:0,predicted:1}
  ]});
  assert.equal(result.confusion.tp,3);
  assert.equal(result.confusion.tn,3);
  assert.equal(result.confusion.fp,1);
  assert.equal(result.confusion.fn,1);
  assert.equal(result.metrics.accuracy,0.75);
  assert.equal(result.metrics.precision,0.75);
  assert.equal(result.metrics.recall,0.75);
  assert.equal(result.verdict,'candidate-weak');
});

test('Batch75 supports score+threshold binary replay without trusting script labels',()=>{
  const result=evaluateBinaryDetectionReplay({threshold:0.5,rows:[
    {id:'a',truth:1,score:0.91},{id:'b',truth:1,score:0.82},{id:'c',truth:0,score:0.08},{id:'d',truth:0,score:0.14}
  ]});
  assert.equal(result.verdict,'candidate-effective');
  assert.equal(result.metrics.accuracy,1);
  assert.ok(result.findings.some((x)=>x.id==='binary-detection-effective-candidate'));
});

test('Batch75 loss-history replay ranks synthetic poison outliers and validates exact truth set',()=>{
  const result=evaluateLossHistoryPoisonReplay({thresholdRatio:0.25,poisonTruth:['p1','p2'],rows:[
    {id:'c1',losses:[0.80,0.76,0.73,0.71]},
    {id:'p1',losses:[0.40,1.42,0.31,1.55]},
    {id:'c2',losses:[0.72,0.70,0.68,0.66]},
    {id:'c3',losses:[0.92,0.88,0.85,0.83]},
    {id:'p2',losses:[0.51,1.71,0.39,1.62]},
    {id:'c4',losses:[0.64,0.62,0.61,0.60]},
    {id:'c5',losses:[0.86,0.83,0.81,0.79]},
    {id:'c6',losses:[0.74,0.72,0.70,0.69]}
  ]});
  assert.deepEqual(new Set(result.selectedIds),new Set(['p1','p2']));
  assert.equal(result.validation.exact,true);
  assert.equal(result.verdict,'candidate-effective');
  assert.ok(result.findings.some((x)=>x.id==='poison-loss-history-ranking-recovered'));
});

test('Batch75 public corpus exports provenance and capability but never synthetic fixtures',()=>{
  const corpus=getDomesticDetectionTrainingCorpus();
  assert.equal(corpus.length,3);
  assert.ok(corpus.some((x)=>x.family==='image-adversarial-detection-scoring'));
  assert.ok(corpus.some((x)=>x.family==='loss-history-poison-ranking'));
  assert.ok(corpus.some((x)=>x.family==='xception-deepfake-detection'));
  assert.ok(corpus.every((x)=>x.trainingPolicy==='synthetic-fixture-only'));
  assert.ok(corpus.every((x)=>x.provenance?.url?.startsWith('https://github.com/CTF-Archives/')));
  assert.ok(corpus.every((x)=>!Object.prototype.hasOwnProperty.call(x,'fixture')));
});

test('Batch75 full domestic detection regression passes positive and negative controls',()=>{
  const result=runDomesticDetectionTrainingRegression({variantsPerSeed:2});
  assert.equal(result.summary.seeds,3);
  assert.equal(result.summary.cases,12);
  assert.equal(result.summary.error,0);
  assert.equal(result.summary.miss,0);
  assert.equal(result.summary.passRate,1);
});

test('Batch75 curriculum includes domestic detection families and regression suite',()=>{
  const curriculum=getTrainingCurriculum();
  assert.ok(curriculum.generatedFrom.some((x)=>x.id==='domestic-detection-ranges-2025'));
  assert.ok(curriculum.cases.some((x)=>x.family==='image-adversarial-detection-scoring'));
  assert.ok(curriculum.cases.some((x)=>x.family==='loss-history-poison-ranking'));
  assert.ok(curriculum.cases.some((x)=>x.family==='xception-deepfake-detection'));
});

test('Batch75 tool routes expose replay evaluators and sanitized corpus',()=>{
  const corpus=runTool('ai-domestic-detection-training-corpus');
  assert.equal(corpus.cases.length,3);
  assert.ok(corpus.cases.every((x)=>!Object.prototype.hasOwnProperty.call(x,'fixture')));
  const binary=runTool('ai-binary-detection-replay',{input:{rows:[
    {truth:1,predicted:1},{truth:1,predicted:1},{truth:0,predicted:0},{truth:0,predicted:0}
  ]}});
  assert.equal(binary.metrics.accuracy,1);
  const poison=runTool('ai-loss-history-poison-replay',{input:{thresholdRatio:0.25,rows:[
    {id:'a',losses:[0.8,0.7,0.65]},{id:'b',losses:[0.5,1.5,0.4]},{id:'c',losses:[0.7,0.68,0.66]},{id:'d',losses:[0.9,0.87,0.84]}
  ]}});
  assert.equal(poison.selectedIds[0],'b');
});

test('Batch75 family matcher recognizes adversarial detection, poison loss history and deepfake evidence',()=>{
  const adv={files:[{path:'adversarial-defense.py',type:'python'},{path:'result.csv',type:'csv'}],findings:[{id:'feature-squeeze',title:'Feature squeeze adversarial detection',meaning:'detect perturbed images'}]};
  const poison={files:[{path:'resnet18_Detection.py',type:'python'}],findings:[{id:'losses-history',title:'losses_history poison ranking',meaning:'loss 变化率筛选投毒样本'}]};
  const fake={files:[{path:'xception_detector.py',type:'python'},{path:'face.jpg',type:'jpg'}],findings:[{id:'deepfake',title:'Xception DeepFake detection',meaning:'real/fake face classification'}]};
  assert.ok(detectSignals(adv).some((x)=>x.id==='adversarial-detection'));
  assert.ok(detectSignals(poison).some((x)=>x.id==='loss-history-poison'));
  assert.ok(detectSignals(fake).some((x)=>x.id==='deepfake'));
  assert.ok(matchTrainingFamilies(adv,{limit:20}).matches.some((x)=>x.family==='image-adversarial-detection-scoring'));
  assert.ok(matchTrainingFamilies(poison,{limit:20}).matches.some((x)=>x.family==='loss-history-poison-ranking'));
  assert.ok(matchTrainingFamilies(fake,{limit:20}).matches.some((x)=>x.family==='xception-deepfake-detection'));
});