'use strict';

const base=require('./ai_real_ctf_regression_batch51');

const VERIFIERS=Object.freeze({
  'user-2026-ai-summarizer-transform-exfil':{
    verifierAvailable:'ai-transform-replay-verify',
    verificationGap:'ORIGINAL_RESPONSE_OBSERVATION_REQUIRED',
    verifierContract:'candidateId + prompt + protected terms + observed response'
  },
  'user-2026-ai-sms-torchscript-side-effect':{
    verifierAvailable:'ai-torchscript-side-effect-verify',
    verificationGap:'CONTROLLED_RUNTIME_OBSERVATION_REQUIRED',
    verifierContract:'source-bound candidateId + trusted provenance + read/write before/write after bytes'
  }
});

function getAiRealCtfCorpus(){return base.getAiRealCtfCorpus();}

function runAiRealCtfRegression(){
  const report=base.runAiRealCtfRegression();
  const results=report.results.map((item)=>VERIFIERS[item.id]?{...item,...VERIFIERS[item.id]}:{...item});
  const verifierAvailable=results.filter((item)=>Boolean(item.verifierAvailable)).length;
  return {
    ...report,batch:52,capabilitySchema:'newcyber.ai-real-ctf-batch52.v1',results,
    summary:{...report.summary,verifierAvailable,replayVerifierAvailable:2},
    note:'Batch52 不提高原题 Verified 数字，而是把 Batch51 两个新 Candidate 接到 candidate-bound replay verifier：编码泄露要求实际响应观测；TorchScript 要求受信运行产生的 read/before/after 字节观测。Fixture 闭环只证明 verifier 可执行，不冒充原赛事远端验证。'
  };
}

module.exports={VERIFIERS,getAiRealCtfCorpus,runAiRealCtfRegression};
