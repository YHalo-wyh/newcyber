'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('crypto');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const {materializeSubmissionArtifact}=require('../src/core/challenge_submission_artifact');
const verifier=require('../src/core/challenge_verifier_contract');
const {buildChallengeSession}=require('../src/core/challenge_session_batch51');

async function tempRoot(t,prefix='newcyber-b89-'){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),prefix));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  return root;
}
function submission(payload='id,pred\n1,1\n'){
  return{status:'formatted',result:{kind:'submission-table',format:'csv',payload,template:'sample_submission.csv',source:'submission-autopilot:sample_submission.csv'}};
}

test('Batch89 writes candidate submission bytes exactly and records sha256',async(t)=>{
  const root=await tempRoot(t);const auto=submission();
  const result=await materializeSubmissionArtifact(root,auto,null);
  assert.equal(result.status,'candidate');
  assert.equal(result.artifact.verified,false);
  assert.match(result.artifact.path,/__newcyber_output__\/newcyber_submission_candidate\.csv$/);
  const bytes=await fs.readFile(result.artifact.absolutePath);
  assert.equal(bytes.toString('utf8'),auto.result.payload);
  assert.equal(bytes[bytes.length-1],0x0a);
  assert.equal(result.artifact.sha256,crypto.createHash('sha256').update(bytes).digest('hex'));
  assert.deepEqual(auto.result.artifact,result.artifact);
});

test('Batch89 marks the artifact verified only when verifier result is the same payload',async(t)=>{
  const root=await tempRoot(t);const auto=submission('id,pred\n1,1\n2,0\n');
  const verifierResult={status:'verified',result:{value:auto.result.payload,verified:true,confidence:'verified'}};
  const result=await materializeSubmissionArtifact(root,auto,verifierResult);
  assert.equal(result.status,'verified');
  assert.equal(result.artifact.verified,true);
  assert.match(result.artifact.filename,/verified\.csv$/);
  assert.deepEqual(verifierResult.result.artifact,result.artifact);

  const other=submission('id,pred\n1,0\n');
  const mismatch=await materializeSubmissionArtifact(root,other,verifierResult);
  assert.equal(mismatch.status,'candidate');
  assert.equal(mismatch.artifact.verified,false);
});

test('Batch89 verifier v3 propagates an existing materialized artifact through an exact candidate match',async(t)=>{
  const root=await tempRoot(t);const payload='magic-trigger';
  const artifact={kind:'submission-artifact',verified:false,path:'__newcyber_output__/newcyber_submission_candidate.txt',filename:'newcyber_submission_candidate.txt'};
  await fs.writeFile(path.join(root,'checker.py'),'def verify(token):\n    return token == "magic-trigger"\n');
  const result=await verifier.runVerifierContractAutopilot(root,{submissionAutopilot:{result:{payload,value:payload,artifact}}});
  assert.equal(result.status,'verified');
  assert.deepEqual(result.result.artifact,artifact);
});

test('Batch89 Electron compatibility session keeps candidate and verified artifact metadata',()=>{
  const artifact={kind:'submission-artifact',state:'candidate',verified:false,path:'__newcyber_output__/newcyber_submission_candidate.csv',filename:'newcyber_submission_candidate.csv',format:'csv',bytes:12,sha256:'a'.repeat(64)};
  const analysis={submissionAutopilot:{status:'formatted',result:{payload:'id,pred\n1,1\n',format:'csv',template:'sample_submission.csv',artifact},next:'checker'},submissionArtifact:{status:'candidate',artifact}};
  const candidate=buildChallengeSession(analysis);
  assert.equal(candidate.status,'candidate');
  assert.deepEqual(candidate.result.artifact,artifact);
  assert.deepEqual(candidate.submissionArtifact,artifact);

  const verifiedArtifact={...artifact,state:'verified',verified:true,filename:'newcyber_submission_verified.csv'};
  analysis.submissionAutopilot.result.artifact=verifiedArtifact;analysis.submissionArtifact={status:'verified',artifact:verifiedArtifact};
  analysis.verifierContractAutopilot={status:'verified',summary:{contracts:1},result:{value:analysis.submissionAutopilot.result.payload,payload:analysis.submissionAutopilot.result.payload,verified:true,confidence:'verified',artifact:verifiedArtifact,source:'sha256-candidate-match @ checker.py:4'}};
  const solved=buildChallengeSession(analysis);
  assert.equal(solved.status,'solved');
  assert.equal(solved.result.artifact.verified,true);
  assert.match(solved.result.displayValue,/已验证提交文件/);
});

test('Batch89 compatibility analyzer routes to submission artifact stage',async()=>{
  const source=await fs.readFile(path.join(__dirname,'../src/core/finals_analyzer_batch15.js'),'utf8');
  assert.match(source,/finals_analyzer_batch89/);
});
