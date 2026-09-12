'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {applyQualityResultGate,contextualVerification,exactLinearHannRecipe}=require('../src/core/sca_quality_result_gate');

function contextual(text,flag=null,cosines=[0.999,0.998,1]){
  return {
    schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'decoded',threshold:0.99,
    recoveredTokenIds:cosines.map((_,i)=>100+i),recoveredText:text,flag,
    positions:cosines.map((cosine,index)=>({index,status:'matched',tokenId:100+index,cosine,mode:'shortlist'})),
    shortlistHits:cosines.length,fallbackPositions:0,fullScanCandidates:0,
    cosine:{min:Math.min(...cosines),mean:cosines.reduce((a,b)=>a+b,0)/cosines.length}
  };
}

function baseResult(ctx){
  return {schema:'newcyber.sca-autopilot.v4',status:'decoded-no-flag',flag:null,gap:null,stages:[],target:{rows:ctx.recoveredTokenIds.length},contextualHiddenOracle:ctx};
}

test('Batch55 result gate promotes only complete contextual-verified flag to flag-recovered',()=>{
  const ctx=contextual('ynuctf{x}','ctf{x}');
  const result=applyQualityResultGate(baseResult(ctx));
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.flag,'ctf{x}');
  assert.equal(result.verifiedRecovery.method,'contextual-hidden-oracle');
  assert.equal(result.verifiedRecovery.tokens,3);
  assert.ok(result.stages.some((x)=>x.id==='flag'&&x.status==='ok'));
});

test('Batch55 result gate promotes exact non-flag prompt recovery to verified-recovery',()=>{
  const ctx=contextual('recovered private prompt text',null,[1,0.9999,0.999]);
  const result=applyQualityResultGate(baseResult(ctx));
  assert.equal(result.status,'verified-recovery');
  assert.equal(result.flag,null);
  assert.equal(result.recoveredText,'recovered private prompt text');
  assert.equal(result.verifiedRecovery.tokens,3);
  assert.ok(result.stages.some((x)=>x.id==='verified-recovery'&&x.status==='ok'));
});

test('Batch55 result gate refuses promotion when any contextual token falls below threshold',()=>{
  const ctx=contextual('ctf{looks_like_flag}','ctf{looks_like_flag}',[1,0.98,1]);
  const result=applyQualityResultGate(baseResult(ctx));
  assert.equal(contextualVerification(ctx,3).complete,false);
  assert.equal(result.status,'decoded-no-flag');
  assert.equal(result.flag,null);
  assert.equal(result.verifiedRecovery,undefined);
});

test('Batch55 exact guarded linear Hann recipe blocks low-R2 garbage decode',()=>{
  const recipe={source:'challenge-source',windowFunction:'hann',metric:'hann-dot',slots:64,evidence:['hann-window','window-size','slot-count','guard-framing','hann-dot-linear-amplitude']};
  assert.equal(exactLinearHannRecipe(recipe),true);
  const result=applyQualityResultGate({
    schema:'newcyber.sca-autopilot.v4',status:'decoded-no-flag',flag:null,stages:[],featureRecipe:recipe,
    profile:{status:'ok',r2:0.31619},target:{rows:236},recoveredTokenIds:Array(236).fill(1)
  });
  assert.equal(result.status,'gap');
  assert.equal(result.gap.code,'LEAKAGE_QUALITY_GAP');
  assert.match(result.gap.detail,/0\.316190/);
  assert.equal(result.blockedRecovery.recoveredTokens,236);
});

test('Batch55 generic or squared-Hann SCA is not forced through the exact 0.99 R2 gate',()=>{
  const result=applyQualityResultGate({schema:'newcyber.sca-autopilot.v4',status:'decoded-no-flag',stages:[],featureRecipe:{source:'challenge-source',windowFunction:'hann',metric:'sum-squares',slots:4,evidence:['hann-window']},profile:{status:'ok',r2:0.7},target:{rows:2}});
  assert.equal(result.status,'decoded-no-flag');
});
