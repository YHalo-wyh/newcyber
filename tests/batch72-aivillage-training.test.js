'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  EVENTS,SOURCES,STRUCTURED_RULES,AIVILLAGE_TRAINING_SEEDS,evaluateStructuredReplay,
  getAiVillageTrainingCorpus,runAiVillageTrainingRegression
}=require('../src/core/ai_aivillage_training');
const {CORPORA,getTrainingCurriculum,runTrainingCurriculumRegression}=require('../src/core/ai_training_curriculum');
const {runTool}=require('../src/core/tool_router');

const MUST_HAVE=[
  'Wifi','Baseball','Inference','Leakage','Forensics','Token','Hotterdog','Theft','Salt','WAF','Secret Sloth',
  'Cluster - Level 1','Cluster - Level 3','Granny - Level 2','Passphrase','Pixelated','Semantle - Level 2','Inversion',"Guess Who's Back?"
];

test('Batch72 imports broad AI Village DEFCON 30/31 mechanics',()=>{
  assert.equal(AIVILLAGE_TRAINING_SEEDS.length,25);
  const names=new Set(AIVILLAGE_TRAINING_SEEDS.map((item)=>item.challenge));
  for(const name of MUST_HAVE)assert.ok(names.has(name),name);
  assert.ok(new Set(AIVILLAGE_TRAINING_SEEDS.map((item)=>item.family)).size>=22);
  assert.deepEqual(new Set(AIVILLAGE_TRAINING_SEEDS.map((item)=>item.event)),new Set(Object.values(EVENTS)));
  assert.match(SOURCES.dc30,/ai_village_ctf_30/);
  assert.match(SOURCES.dc31,/AI-Village-CTF-DEFCON-31/);
});

test('Batch72 keeps original competition answers and artifacts out of fixtures',()=>{
  const serialized=JSON.stringify(AIVILLAGE_TRAINING_SEEDS);
  assert.equal(/flag\{/i.test(serialized),false);
  assert.equal(/D3FC0N|proto-flag|SECRETKEY/i.test(serialized),false);
  assert.equal(/\.jpg\"|\.png\"|\.pkl\"/i.test(serialized),false);
  for(const item of AIVILLAGE_TRAINING_SEEDS){
    assert.equal(item.trainingPolicy,'synthetic-fixture-only');
    assert.equal(item.caseType,'real-ctf');
    assert.equal(item.provenance.evidenceLevel,'writeup-specific');
    assert.match(item.provenance.url,/github\.com\/(IsaiahPressman|conor-99)\//);
  }
});

test('Batch72 structured mechanisms have explicit negative controls',()=>{
  assert.ok(Object.keys(STRUCTURED_RULES).length>=17);
  for(const [riskType,keys] of Object.entries(STRUCTURED_RULES)){
    const hit={riskType};for(const key of keys)hit[key]=true;
    const positive=evaluateStructuredReplay(hit);
    assert.equal(positive.verdict,'candidate-failure',riskType);
    assert.equal(positive.findings.length,1);
    const miss={...hit,[keys[0]]:false};
    const negative=evaluateStructuredReplay(miss);
    assert.equal(negative.verdict,'no-explicit-failure',`${riskType} negative`);
    assert.equal(negative.findings.length,0);
  }
});

test('Batch72 regression exercises structured, adversarial, extraction and inversion evaluators',()=>{
  const report=runAiVillageTrainingRegression({variantsPerSeed:1});
  assert.equal(report.schema,'newcyber.aivillage-training.v1');
  assert.equal(report.summary.seeds,25);
  assert.equal(report.summary.cases,50);
  assert.equal(report.summary.error,0);
  assert.equal(report.summary.miss,0);
  assert.equal(report.summary.passRate,1);
  for(const evaluator of ['structured','adversarial','extraction','inversion']){
    const rows=report.results.filter((row)=>row.evaluator===evaluator);
    assert.ok(rows.length>0,evaluator);
    assert.ok(rows.every((row)=>row.status==='pass'),evaluator);
    assert.ok(rows.some((row)=>row.control==='positive'),`${evaluator} positive`);
    assert.ok(rows.some((row)=>row.control==='negative'),`${evaluator} negative`);
  }
  const extraction=report.results.find((row)=>row.seed==='aiv-dc30-baseball'&&row.control==='positive');
  assert.ok(extraction.findingIds.includes('extraction-full-probability-output'));
  const inversion=report.results.find((row)=>row.seed==='aiv-dc31-inversion'&&row.control==='positive');
  assert.ok(inversion.findingIds.includes('inversion-reconstruction-similarity'));
  const adversarial=report.results.find((row)=>row.seed==='aiv-dc31-granny-l2'&&row.control==='positive');
  assert.ok(adversarial.findingIds.includes('adversarial-candidate-valid'));
});

test('Batch72 regression is deterministic and metadata-only corpus does not expose fixtures',()=>{
  const first=runAiVillageTrainingRegression({variantsPerSeed:2});
  const second=runAiVillageTrainingRegression({variantsPerSeed:2});
  assert.deepEqual(first,second);
  const corpus=getAiVillageTrainingCorpus();
  assert.equal(corpus.length,25);
  assert.ok(corpus.every((item)=>!Object.prototype.hasOwnProperty.call(item,'fixture')));
  assert.ok(corpus.every((item)=>item.capability&&item.family&&item.provenance?.url));
});

test('Batch72 is wired into router and global curriculum/full regression',()=>{
  const routed=runTool('ai-aivillage-training-corpus',{});
  assert.equal(routed.schema,'newcyber.ai-aivillage-training-corpus.v1');
  assert.equal(routed.cases.length,25);
  const regression=runTool('ai-aivillage-training-regression',{options:{variantsPerSeed:1}});
  assert.equal(regression.summary.passRate,1);
  const curriculum=getTrainingCurriculum();
  assert.ok(CORPORA.some((row)=>row.id==='aivillage-defcon-30-31'));
  assert.equal(curriculum.summary.byCorpus['aivillage-defcon-30-31'],25);
  assert.ok(curriculum.cases.some((row)=>row.id.startsWith('aivillage-defcon-30-31:')));
  assert.ok((curriculum.summary.byDirection['adversarial-example']||0)>=5);
  assert.ok((curriculum.summary.byDirection['model-extraction']||0)>=6);
  assert.ok((curriculum.summary.byDirection['privacy-leakage']||0)>=4);
  const full=runTrainingCurriculumRegression({variantsPerSeed:1});
  assert.equal(full.summary.suites,CORPORA.length);
  assert.equal(full.summary.suiteErrors,0);
  assert.ok(full.suites.some((row)=>row.id==='aivillage-defcon-30-31'&&row.ok));
});
