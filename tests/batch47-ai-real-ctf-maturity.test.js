'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {getAiRealCtfCorpus,runAiRealCtfRegression}=require('../src/core/ai_real_ctf_regression');

function byChallenge(result,name){return result.results.find((item)=>item.challenge===name);}

test('Batch47 maturity funnel is monotonic and reports rates separately from coverage labels',()=>{
  const result=runAiRealCtfRegression();
  const s=result.summary;
  assert.equal(result.maturitySchema,'newcyber.ai-real-ctf-maturity.v1');
  assert.equal(s.total,11);
  assert.ok(s.recognitionPass>=s.candidatePass);
  assert.ok(s.candidatePass>=s.verifiedPass);
  assert.equal(s.maturityFunnel.recognized,s.recognitionPass);
  assert.equal(s.maturityFunnel.candidate,s.candidatePass);
  assert.equal(s.maturityFunnel.verified,s.verifiedPass);
  assert.equal(s.recognitionRate,s.recognitionPass/s.total);
  assert.equal(s.candidateRate,s.candidatePass/s.total);
  assert.equal(s.verifiedRate,s.verifiedPass/s.total);
  for(const item of result.results){
    if(item.verified)assert.equal(item.candidate,true);
    if(item.candidate)assert.equal(item.recognized,true);
  }
});

test('Batch47 only promotes concrete recoverable material to Candidate and never infers Verified',()=>{
  const result=runAiRealCtfRegression();
  const poison=byChallenge(result,'easy_poison');
  assert.equal(poison.recognized,true);
  assert.equal(poison.candidate,true);
  assert.equal(poison.verified,false);
  assert.equal(poison.maturityStage,'candidate');
  assert.deepEqual(poison.candidateObject,{kind:'trigger-target',trigger:'reverse-trigger',targetLabel:'1',verifier:'ai-backdoor-behavior'});

  for(const name of ['🪐 小型大语言模型星球','SU_easyLLM','The Silent Heist','prompt_audit','Fake Emotion','耄耋','Blind']){
    const item=byChallenge(result,name);
    assert.equal(item.recognized,true,`${name} should be recognized`);
    assert.equal(item.candidate,false,`${name} must not be upgraded without concrete candidate material`);
    assert.equal(item.verified,false,`${name} must not be verified without an oracle`);
  }
  const cifar=byChallenge(result,'CIFAR-10');
  assert.equal(cifar.recognized,false);
  assert.equal(cifar.candidate,false);
  assert.equal(cifar.verified,false);
});

test('Batch47 corpus expansion uses existing public provenance instead of invented attachment facts',()=>{
  const corpus=getAiRealCtfCorpus();
  const su=corpus.find((item)=>item.challenge==='SU_easyLLM');
  const poison=corpus.find((item)=>item.challenge==='easy_poison');
  assert.ok(su&&poison);
  assert.equal(su.provenance,'official-source-derived');
  assert.match(su.source,/github\.com\/team-su\/SUCTF-2026/);
  assert.equal(poison.provenance,'public-writeup-derived');
  assert.match(poison.source,/qingchenyou/);
  assert.match(poison.limitation,/Candidate.*Verified/);
});
