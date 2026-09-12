'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {runTool}=require('../src/core/tool_router');
const {inspectTrainingArtifact,STAGES}=require('../src/core/ai_training_pipeline_status');

const root=path.join(__dirname,'..');

test('Batch107 status inspector maps evidence blockers and promotion stale state deterministically',()=>{
  const evidence=inspectTrainingArtifact({
    schema:'newcyber.ai-training-evidence-intake.v1',
    verdict:'needs-evidence',
    blockers:[],
    missingEvidence:['public-source-url','negative-control-evidence']
  });
  assert.equal(evidence.schema,'newcyber.ai-training-pipeline-status.v1');
  assert.equal(evidence.stage,'evidence');
  assert.equal(evidence.state,'blocked');
  assert.equal(evidence.nextRoute,'ai-training-evidence-intake');
  assert.deepEqual(evidence.blockers,['missing:public-source-url','missing:negative-control-evidence']);
  assert.equal(evidence.stages.length,8);

  const stale=inspectTrainingArtifact({
    schema:'newcyber.ai-training-promotion-validation.v1',status:'stale',valid:false,stale:true,
    errors:['promotion-stale-base-head']
  });
  assert.equal(stale.stage,'promotion');
  assert.equal(stale.state,'stale');
  assert.equal(stale.safeBoundary,'repository-bound');
});

test('Batch107 exposes Batch102-106 planning gates through tool router without exposing transaction execution',()=>{
  const materialized=runTool('ai-training-regression-materialize',{input:{}});
  assert.equal(materialized.schema,'newcyber.ai-training-regression-materializer.v1');
  assert.equal(materialized.readyToCommit,false);

  const integration=runTool('ai-training-integration-gate',{input:{}});
  assert.equal(integration.schema,'newcyber.ai-training-integration-gate.v1');
  assert.equal(integration.readyToIntegrate,false);

  const writer=runTool('ai-training-integration-writer',{input:{}});
  assert.equal(writer.schema,'newcyber.ai-training-integration-writer.v1');
  assert.equal(writer.readyToWrite,false);

  const promotion=runTool('ai-training-promotion-manifest',{input:{}});
  assert.equal(promotion.schema,'newcyber.ai-training-promotion.v1');
  assert.equal(promotion.readyToPromote,false);

  const status=runTool('ai-training-pipeline-status',{input:{schema:'newcyber.ai-training-regression-materializer.v1',status:'blocked',readyToCommit:false,errors:['fixture-payload-missing']}});
  assert.equal(status.stage,'materialize');
  assert.equal(status.state,'blocked');
  assert.deepEqual(status.blockers,['fixture-payload-missing']);

  const router=fs.readFileSync(path.join(root,'src/core/tool_router.js'),'utf8');
  assert.match(router,/ai-training-transaction-manifest/);
  assert.match(router,/ai-training-promotion-merge-authorize/);
  assert.doesNotMatch(router,/ai-training-transaction-execute/);
});

test('Batch107 Stage-One workbench compiles, loads after health UI, and keeps repository boundary visible',()=>{
  const js=fs.readFileSync(path.join(root,'renderer/ai_training_pipeline_ui.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'renderer/styles/ai_training_pipeline.css'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.doesNotThrow(()=>new Function(js));
  assert.match(js,/TRAINING PROMOTION PIPELINE/);
  assert.match(js,/ai-training-evidence-template/);
  assert.match(js,/ai-training-regression-materialize/);
  assert.match(js,/ai-training-integration-gate/);
  assert.match(js,/REPOSITORY BOUNDARY/);
  assert.match(css,/training-pipeline-rail/);
  assert.match(css,/training-pipeline-editor/);
  const health=html.indexOf('ai_training_health_ui.js');
  const pipeline=html.indexOf('ai_training_pipeline_ui.js');
  assert.ok(health>=0&&pipeline>health);
  assert.match(html,/styles\/ai_training_pipeline\.css/);
});

test('Batch107 pipeline declares the complete promotion sequence',()=>{
  assert.deepEqual(STAGES.map((row)=>row.id),['evidence','skeleton','materialize','integration','writer','transaction','promotion','merge']);
  assert.deepEqual(STAGES.map((row)=>row.route),[
    'ai-training-evidence-intake','ai-training-regression-skeleton','ai-training-regression-materialize','ai-training-integration-gate',
    'ai-training-integration-writer','ai-training-transaction-manifest','ai-training-promotion-manifest','ai-training-promotion-merge-authorize'
  ]);
});
