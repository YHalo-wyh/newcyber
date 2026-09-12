'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {buildPromotionManifest,validatePromotionAgainstRepository,buildPromotionPrRequest,authorizePromotionMerge,digest}=require('../src/core/ai_training_promotion_gate');

function execution(overrides={}){
  const base={
    schema:'newcyber.ai-training-transaction-execution.v1',
    status:'verified-on-isolated-branch',verified:true,
    branch:'training-integration/event-d-c4-family-abc123',
    repositoryTests:{passed:true,total:900},
    fullRegression:{schema:'newcyber.ai-training-curriculum-regression.v1',summary:{suiteErrors:0,curriculumCases:101}},
    verification:{
      schema:'newcyber.ai-training-integration-verification.v1',status:'verified-integrated',verified:true,errors:[],
      candidateSignature:'event d|c4|family-x',
      expectedDelta:{direction:'privacy-leakage',events:1,families:1},
      actualDelta:{direction:'privacy-leakage',events:1,families:1}
    },
    finalization:{allowed:true,action:'open-integration-pr',baseBranch:'main',headBranch:'training-integration/event-d-c4-family-abc123',expectedBaseHead:'base-sha-123'}
  };
  return{...base,...overrides};
}

function promotion(){
  return buildPromotionManifest({
    execution:execution(),
    verifiedHeadSha:'verified-head-456',
    ciRun:{runId:99,runNumber:1800,conclusion:'success',headSha:'verified-head-456'}
  });
}

test('promotion manifest binds verified execution, base/head and ci evidence',()=>{
  const p=promotion();
  assert.equal(p.status,'ready-to-promote');
  assert.equal(p.readyToPromote,true);
  assert.equal(p.proof.expectedBaseHead,'base-sha-123');
  assert.equal(p.proof.verifiedHeadSha,'verified-head-456');
  assert.equal(p.proof.candidateSignature,'event d|c4|family-x');
  assert.equal(p.proof.ci.conclusion,'success');
  assert.ok(p.promotionId.startsWith('promotion-'));
  assert.equal(p.executionDigest,digest(execution()));
});

test('promotion rejects unverified Batch105 output and failed ci',()=>{
  const unverified=execution({status:'verification-failed',verified:false});
  const a=buildPromotionManifest({execution:unverified,verifiedHeadSha:'h',ciRun:{conclusion:'success',headSha:'h'}});
  assert.equal(a.readyToPromote,false);
  assert.ok(a.errors.includes('transaction-execution-not-verified'));
  const b=buildPromotionManifest({execution:execution(),verifiedHeadSha:'h',ciRun:{conclusion:'failure',headSha:'h'}});
  assert.equal(b.readyToPromote,false);
  assert.ok(b.errors.includes('verified-ci-success-required'));
});

test('promotion rejects ci evidence for a different head sha',()=>{
  const p=buildPromotionManifest({execution:execution(),verifiedHeadSha:'head-a',ciRun:{conclusion:'success',headSha:'head-b'}});
  assert.equal(p.readyToPromote,false);
  assert.ok(p.errors.includes('ci-head-sha-mismatch'));
});

test('PR request embeds promotion evidence markers',()=>{
  const p=promotion();
  const req=buildPromotionPrRequest(p);
  assert.equal(req.allowed,true);
  assert.equal(req.base,'main');
  assert.equal(req.head,p.proof.headBranch);
  assert.ok(req.body.includes(p.promotionId));
  assert.ok(req.body.includes(p.proof.verifiedHeadSha));
  assert.ok(req.body.includes(p.proof.verificationDigest));
});

test('repository validation detects base TOCTOU drift',()=>{
  const p=promotion();
  const req=buildPromotionPrRequest(p);
  const result=validatePromotionAgainstRepository({
    promotion:p,currentBaseHead:'new-main-sha',currentHeadSha:p.proof.verifiedHeadSha,
    pr:{base:'main',head:p.proof.headBranch,headSha:p.proof.verifiedHeadSha,state:'open',body:req.body},
    ciRun:{conclusion:'success',headSha:p.proof.verifiedHeadSha}
  });
  assert.equal(result.valid,false);
  assert.equal(result.status,'stale');
  assert.ok(result.errors.includes('promotion-stale-base-head'));
});

test('repository validation detects head branch mutation after verification',()=>{
  const p=promotion();const req=buildPromotionPrRequest(p);
  const result=validatePromotionAgainstRepository({
    promotion:p,currentBaseHead:p.proof.expectedBaseHead,currentHeadSha:'mutated-head',
    pr:{base:'main',head:p.proof.headBranch,headSha:'mutated-head',state:'open',body:req.body},
    ciRun:{conclusion:'success',headSha:'mutated-head'}
  });
  assert.equal(result.valid,false);
  assert.equal(result.status,'stale');
  assert.ok(result.errors.includes('promotion-stale-head-branch'));
});

test('promotion markers are mandatory on the integration PR',()=>{
  const p=promotion();
  const result=validatePromotionAgainstRepository({
    promotion:p,currentBaseHead:p.proof.expectedBaseHead,currentHeadSha:p.proof.verifiedHeadSha,
    pr:{base:'main',head:p.proof.headBranch,headSha:p.proof.verifiedHeadSha,state:'open',body:'missing evidence markers'},
    ciRun:{conclusion:'success',headSha:p.proof.verifiedHeadSha}
  });
  assert.equal(result.valid,false);
  assert.ok(result.errors.some((x)=>x.startsWith('promotion-marker-missing:')));
});

test('merge authorization is emitted only for an exact point-in-time match',()=>{
  const p=promotion();const req=buildPromotionPrRequest(p);
  const pr={base:'main',head:p.proof.headBranch,headSha:p.proof.verifiedHeadSha,state:'open',body:req.body};
  const ciRun={conclusion:'success',headSha:p.proof.verifiedHeadSha};
  const ok=authorizePromotionMerge({promotion:p,currentBaseHead:p.proof.expectedBaseHead,currentHeadSha:p.proof.verifiedHeadSha,pr,ciRun});
  assert.equal(ok.status,'merge-authorized');
  assert.equal(ok.authorized,true);
  assert.equal(ok.merge.method,'squash');
  assert.equal(ok.merge.expectedHeadSha,p.proof.verifiedHeadSha);
  const stale=authorizePromotionMerge({promotion:p,currentBaseHead:'advanced-main',currentHeadSha:p.proof.verifiedHeadSha,pr,ciRun});
  assert.equal(stale.authorized,false);
  assert.equal(stale.status,'stale-revalidation-required');
});
