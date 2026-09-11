'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('crypto');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const verifier=require('../src/core/challenge_verifier_contract');
const {candidateString,extraCandidateValues}=require('../src/core/challenge_verifier_contract_v3');
const {buildChallengeSession}=require('../src/core/challenge_session_batch51');

async function tempRoot(t,prefix='newcyber-b88-'){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),prefix));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  return root;
}

test('Batch88 preserves structured submission bytes including the final newline',()=>{
  const payload='id,pred\n1,1\n';
  assert.equal(candidateString(payload),payload);
  const extras=extraCandidateValues({submissionAutopilot:{result:{payload,value:'summary'}}});
  const candidate=extras.find((item)=>item.source==='submission-autopilot:payload');
  assert.ok(candidate);
  assert.equal(candidate.value,payload);
  assert.equal(candidate.value.endsWith('\n'),true);
});

test('Batch88 closes a SHA-256 checker against an auto-generated CSV submission payload',async(t)=>{
  const root=await tempRoot(t);
  const payload='id,pred\n1,1\n2,0\n';
  const digest=crypto.createHash('sha256').update(payload,'utf8').digest('hex');
  const source=[
    'import hashlib',
    `EXPECTED = "${digest}"`,
    'def verify(submission):',
    '    return hashlib.sha256(submission.encode()).hexdigest() == EXPECTED'
  ].join('\n');
  await fs.writeFile(path.join(root,'checker.py'),source);
  const result=await verifier.runVerifierContractAutopilot(root,{submissionAutopilot:{result:{payload,value:'已生成提交'}}});
  assert.equal(result.schema,'newcyber.challenge-verifier-contract.v4');
  assert.equal(result.status,'verified');
  assert.equal(result.result.value,payload);
  assert.equal(result.result.verified,true);
  assert.match(result.findings[0].evidence,/submission-autopilot:payload/);
});

test('Batch88 exact checker can validate a Universal Trigger candidate without direct-literal promotion',async(t)=>{
  const root=await tempRoot(t);
  await fs.writeFile(path.join(root,'checker.py'),'def verify(token):\n    return token == "magic-trigger"\n');
  const result=await verifier.runVerifierContractAutopilot(root,{aiUniversalTriggerAutopilot:{result:{value:'magic-trigger',payload:'magic-trigger'}}});
  assert.equal(result.status,'verified');
  assert.equal(result.result.value,'magic-trigger');
  assert.equal(result.result.kind,'answer');
  assert.match(result.result.source,/exact-candidate-match/);
});

test('Batch88 Electron compatibility Challenge Session keeps verifier-backed structured results solved',()=>{
  const payload='id,pred\n1,1\n'.repeat(80);
  const analysis={verifierContractAutopilot:{status:'verified',summary:{contracts:1,extraCandidates:2},result:{value:payload,payload,verified:true,confidence:'verified',kind:'answer',source:'sha256-candidate-match @ checker.py:4'},next:'verified'}};
  const session=buildChallengeSession(analysis);
  assert.equal(session.status,'solved');
  assert.equal(session.result.verified,true);
  assert.equal(session.result.payload,payload);
  assert.match(session.result.displayValue,/已验证结构化提交内容/);
  assert.equal(session.primaryNeed,null);
});

test('Batch88 compatibility analyzer and verifier entrypoints route to the newest closure',async()=>{
  const analyzer=await fs.readFile(path.join(__dirname,'../src/core/finals_analyzer_batch15.js'),'utf8');
  const compat=await fs.readFile(path.join(__dirname,'../src/core/challenge_verifier_contract.js'),'utf8');
  const ipc=await fs.readFile(path.join(__dirname,'../src/electron/challenge_session_ipc.js'),'utf8');
  assert.match(analyzer,/finals_analyzer_batch88/);
  assert.match(compat,/challenge_verifier_contract_v3/);
  assert.match(ipc,/require\('\.\.\/core\/challenge_verifier_contract'\)/);
  assert.match(ipc,/require\('\.\.\/core\/challenge_session_batch51'\)/);
});
