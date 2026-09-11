'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const v4=require('../src/core/challenge_verifier_contract_v4');
const {materializeResultProof}=require('../src/core/challenge_result_proof');

async function tempRoot(t,prefix='newcyber-b91-'){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),prefix));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));return root;
}

test('Batch91 parses only bounded conjunction atoms and rejects OR/unknown calls',()=>{
  const rows=v4.discoverPredicateContracts('checker.py',["def verify(data):","    return data['score'] >= 0.9 and len(data['ids']) == 2"].join('\n'));
  assert.equal(rows.length,1);assert.equal(rows[0].atoms.length,2);
  assert.equal(rows[0].atoms[0].type,'json-field-scalar');
  assert.equal(rows[0].atoms[1].type,'json-field-length');
  assert.equal(v4.discoverPredicateContracts('checker.py',"def verify(x):\n    return x == 'a' or x == 'b'\n").length,0);
  assert.equal(v4.discoverPredicateContracts('checker.py',"def verify(x):\n    return dangerous(x)\n").length,0);
});

test('Batch91 validates a structured JSON submission without executing checker code',async(t)=>{
  const root=await tempRoot(t);
  await fs.writeFile(path.join(root,'checker.py'),[
    'def verify(data):',
    "    return data['score'] >= 0.9 and len(data['ids']) == 2"
  ].join('\n'));
  const payload='{"score":0.95,"ids":["a","b"]}\n';
  const result=await v4.runVerifierContractAutopilot(root,{submissionAutopilot:{result:{payload,value:'summary'}}});
  assert.equal(result.schema,'newcyber.challenge-verifier-contract.v4');
  assert.equal(result.status,'verified');
  assert.equal(result.result.value,payload);
  assert.equal(result.summary.predicateVerified,1);
  assert.equal(result.proof.policy.sourceExecuted,false);
  assert.equal(result.proof.checks.length,2);
  assert.ok(result.proof.checks.every((x)=>x.ok));
});

test('Batch91 raw string conjunction supports length/prefix/suffix but requires every predicate',async(t)=>{
  const root=await tempRoot(t);
  await fs.writeFile(path.join(root,'verifier.py'),"def verify(answer):\n    return len(answer) == 8 and answer.startswith('CTF{') and answer.endswith('}')\n");
  const good=await v4.runVerifierContractAutopilot(root,{aiUniversalTriggerAutopilot:{result:{value:'CTF{abc}',payload:'CTF{abc}'}}});
  assert.equal(good.status,'verified');
  const bad=await v4.runVerifierContractAutopilot(root,{aiUniversalTriggerAutopilot:{result:{value:'CTF{abcd}',payload:'CTF{abcd}'}}});
  assert.notEqual(bad.status,'verified');
  assert.equal(bad.summary.predicateVerified,0);
});

test('Batch91 keeps structured membership candidates eligible for exact verifier closure',async(t)=>{
  const root=await tempRoot(t);
  await fs.writeFile(path.join(root,'checker.py'),"def verify(answer):\n    return answer == 'member-42'\n");
  const result=await v4.runVerifierContractAutopilot(root,{aiMembershipAutopilot:{result:{memberIds:['member-7','member-42'],value:'2 members'}}});
  assert.equal(result.status,'verified');
  assert.equal(result.result.value,'member-42');
  assert.match(result.result.source,/exact-candidate-match/);
});

test('Batch91 materializes compact result proof without duplicating large payload',async(t)=>{
  const root=await tempRoot(t);const payload='id,pred\n1,1\n';
  const verifier={status:'verified',result:{value:payload,payload,kind:'answer',source:'bounded predicate @ checker.py:2'},proof:{method:'bounded-predicate-return',candidateSource:'submission-autopilot:payload',contract:{type:'predicate-return',file:'checker.py',line:2,expression:'len(submission) == 12'},checks:[{type:'raw-length',expected:12,actual:12,ok:true}]}};
  const out=await materializeResultProof(root,verifier,{path:'__newcyber_output__/newcyber_submission_verified.csv',filename:'newcyber_submission_verified.csv',format:'csv',bytes:payload.length,sha256:v4.candidateDigest(payload).sha256,verified:true});
  assert.equal(out.status,'verified');assert.equal(out.proof.artifact.matchesResult,true);
  const body=await fs.readFile(path.join(root,out.artifact.path),'utf8');
  assert.match(body,/newcyber\.result-proof-manifest\.v1/);assert.doesNotMatch(body,/id,pred\\n1,1/);
});

test('Batch91 compatibility verifier exports are complete without partial circular exports',()=>{
  const mod=require('../src/core/challenge_verifier_contract');
  for(const key of ['flagLike','walkSources','candidateValues','evaluateContracts','extraCandidateValues','runVerifierContractAutopilot'])assert.equal(typeof mod[key],'function',key);
});

test('Batch91 compatibility entrypoints route to v4 and analyzer batch91',async()=>{
  const verifier=await fs.readFile(path.join(__dirname,'../src/core/challenge_verifier_contract.js'),'utf8');
  const analyzer=await fs.readFile(path.join(__dirname,'../src/core/finals_analyzer_batch15.js'),'utf8');
  assert.match(verifier,/challenge_verifier_contract_v4/);
  assert.match(verifier,/challenge_verifier_contract_v3/);
  assert.match(analyzer,/finals_analyzer_batch91/);
  assert.match(analyzer,/finals_analyzer_batch89/);
});
