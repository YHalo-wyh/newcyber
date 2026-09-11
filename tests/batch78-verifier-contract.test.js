'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('crypto');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const {
  discoverExactContracts,
  discoverHashContracts,
  directEligible,
  runVerifierContractAutopilot
}=require('../src/core/challenge_verifier_contract');

async function tempRoot(t,prefix='newcyber-b78-'){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),prefix));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  return root;
}

test('Batch78 extracts quoted exact verifier literals without capture-group ambiguity',()=>{
  const body='def verify(answer):\n    if answer == "FLAG{STATIC_CONTRACT_OK}":\n        return True\n';
  const rows=discoverExactContracts('checker.py',body);
  assert.equal(rows.length,1);
  assert.equal(rows[0].variable,'answer');
  assert.equal(rows[0].expected,'FLAG{STATIC_CONTRACT_OK}');
  assert.equal(directEligible({contract:rows[0],value:rows[0].expected}),true);
});

test('Batch78 does not promote a generic token comparison to direct solved result',async(t)=>{
  const root=await tempRoot(t);
  await fs.writeFile(path.join(root,'checker.py'),'def verify(token):\n    return token == "admin"\n');
  const result=await runVerifierContractAutopilot(root,{});
  assert.equal(result.status,'contracts-found');
  assert.equal(result.result,null);
  assert.equal(result.summary.exact,1);
  assert.equal(result.summary.directEligible,0);
});

test('Batch78 can directly close a Flag-like exact checker contract',async(t)=>{
  const root=await tempRoot(t);
  await fs.writeFile(path.join(root,'verifier.py'),'def verify(answer):\n    return answer == "FLAG{B78_EXACT}"\n');
  const result=await runVerifierContractAutopilot(root,{});
  assert.equal(result.status,'verified');
  assert.equal(result.result.value,'FLAG{B78_EXACT}');
  assert.equal(result.result.verified,true);
  assert.equal(result.result.kind,'flag');
});

test('Batch78 hash contract verifies an existing candidate but never reverses the digest',async(t)=>{
  const root=await tempRoot(t);
  const candidate='FLAG{HASH_CANDIDATE}';
  const digest=crypto.createHash('sha256').update(candidate).digest('hex');
  const source=[
    'import hashlib',
    'def checker(answer):',
    `    expected = "${digest}"`,
    '    return hashlib.sha256(answer.encode()).hexdigest() == expected'
  ].join('\n');
  await fs.writeFile(path.join(root,'checker.py'),source);
  const discovered=discoverHashContracts('checker.py',source);
  assert.equal(discovered.length,1);
  assert.equal(discovered[0].algorithm,'sha256');
  const hit=await runVerifierContractAutopilot(root,{candidates:{flags:[candidate]}});
  assert.equal(hit.status,'verified');
  assert.equal(hit.result.value,candidate);
  const miss=await runVerifierContractAutopilot(root,{candidates:{flags:['FLAG{WRONG}']}});
  assert.equal(miss.status,'contracts-found');
  assert.equal(miss.result,null);
});

test('Batch78 scans verifier sources recovered under archive expansion directories',async(t)=>{
  const root=await tempRoot(t);
  const nested=path.join(root,'__expanded__','task.zip.contents','challenge');
  await fs.mkdir(nested,{recursive:true});
  await fs.writeFile(path.join(nested,'judge.py'),'def verify(flag):\n    return flag == "FLAG{EXPANDED_VISIBLE}"\n');
  const result=await runVerifierContractAutopilot(root,{});
  assert.equal(result.status,'verified');
  assert.equal(result.result.value,'FLAG{EXPANDED_VISIBLE}');
  assert.ok(result.contracts.some((item)=>item.file.includes('__expanded__/task.zip.contents/challenge/judge.py')));
});

test('Batch78 Challenge Session IPC wires verifier manifest and solved override',async()=>{
  const source=await fs.readFile(path.join(__dirname,'../src/electron/challenge_session_ipc.js'),'utf8');
  assert.match(source,/runVerifierContractAutopilot/);
  assert.match(source,/newcyber_verifier_contract\.json/);
  assert.match(source,/verifierContractAutopilot/);
  assert.match(source,/verifierAuto\?\.status==='verified'/);
  assert.match(source,/analysis\.challengeSession\.status='solved'/);
});

test('Batch78 pipeline UI uses static verifier contract as VERIFY source',async()=>{
  const source=await fs.readFile(path.join(__dirname,'../renderer/challenge_session_batch53.js'),'utf8');
  assert.doesNotThrow(()=>new Function(source));
  assert.match(source,/verifierContractAutopilot/);
  assert.match(source,/contracts-found/);
  assert.match(source,/静态 checker\/verifier 已闭环/);
  assert.match(source,/DROP-TO-RESULT PIPELINE/);
});