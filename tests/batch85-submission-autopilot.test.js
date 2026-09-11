'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {analyzeSubmissionBundle,parseDelimited}=require('../src/core/challenge_submission_autopilot_v2');
const {buildChallengeSession}=require('../src/core/challenge_session_batch85');
const {buildChallengeSession:buildCompatibilitySession}=require('../src/core/challenge_session_batch51');

function membershipAnalysis(){return{
  workspaceName:'membership',workspacePath:'/tmp/membership',files:[],findings:[],candidates:{flags:[],urls:[],ips:[]},autopilot:{automaticChecks:[],flags:[],artifacts:[],actions:[],summary:{}},autoSolve:{status:'review',gaps:[]},
  aiMembershipAutopilot:{status:'candidate',summary:{memberCandidates:2},selection:{signal:'confidence',auc:.91},result:{kind:'membership-id-list',value:'["a","c"]',payload:'["a","c"]',displayValue:'2 member IDs',memberIds:['a','c'],source:'calibration.csv + query.csv',candidates:{candidates:[{id:'a',member:true,confidence:.93},{id:'b',member:false,confidence:.12},{id:'c',member:true,confidence:.88}]}}}
};}

test('Batch85 formats membership candidates into sample_submission CSV without row-order guessing',()=>{
  const analysis=membershipAnalysis();
  const files=[{path:'sample_submission.csv',text:'id,membership\na,0\nb,0\nc,0\n'}];
  const result=analyzeSubmissionBundle(files,analysis);
  assert.equal(result.status,'formatted');
  assert.equal(result.result.format,'csv');
  const parsed=parseDelimited(result.result.payload,',');
  assert.deepEqual(parsed.rows.map((x)=>[x.id,x.membership]),[['a','1'],['b','0'],['c','1']]);
  assert.equal(result.result.contract.idColumn,'id');
  assert.equal(result.result.contract.memberColumn,'membership');
});

test('Batch85 preserves sample row IDs and emits confidence when template requests score',()=>{
  const analysis=membershipAnalysis();
  const result=analyzeSubmissionBundle([{path:'submission_template.csv',text:'sample_id,score\nc,0\na,0\nb,0\n'}],analysis);
  assert.equal(result.status,'formatted');
  const parsed=parseDelimited(result.result.payload,',');
  assert.deepEqual(parsed.rows.map((x)=>x.sample_id),['c','a','b']);
  assert.ok(Number(parsed.rows[0].score)>.8);
  assert.ok(Number(parsed.rows[2].score)<.2);
});

test('Batch85 never treats ordinary query/calibration tables as submission templates',()=>{
  const analysis=membershipAnalysis();
  const result=analyzeSubmissionBundle([
    {path:'query.csv',text:'id,confidence\na,.9\nb,.1\nc,.8\n'},
    {path:'calibration.csv',text:'id,member,confidence\nx,1,.9\ny,0,.1\n'}
  ],analysis);
  assert.equal(result.status,'not-detected');
});

test('Batch85 fills generic JSON answer template but refuses ambiguous unrelated JSON',()=>{
  const base={...membershipAnalysis(),aiMembershipAutopilot:{status:'not-detected'},challengeSession:{result:{value:'FLAG{candidate}',payload:'FLAG{candidate}',kind:'answer',verified:false}}};
  const good=analyzeSubmissionBundle([{path:'submission.json',text:'{"answer":""}'}],base);
  assert.equal(good.status,'formatted');
  assert.equal(JSON.parse(good.result.payload).answer,'FLAG{candidate}');
  const bad=analyzeSubmissionBundle([{path:'submission.json',text:'{"metadata":"keep"}'}],base);
  assert.equal(bad.status,'unsupported-contract');
});

test('Batch85 challenge session prefers formatted submission candidate while keeping candidate semantics',()=>{
  const analysis=membershipAnalysis();
  analysis.submissionAutopilot=analyzeSubmissionBundle([{path:'sample_submission.csv',text:'id,member\na,0\nb,0\nc,0\n'}],analysis);
  const session=buildChallengeSession(analysis);
  assert.equal(session.status,'candidate');
  assert.match(session.result.payload,/id,member/);
  assert.equal(session.result.verified,false);
  assert.equal(session.primaryNeed.code,'SUBMISSION_VERIFIER_MISSING');
});

test('Batch85 compatibility Challenge Session rebuild keeps formatted submission result for Electron file sessions',()=>{
  const analysis=membershipAnalysis();
  analysis.submissionAutopilot=analyzeSubmissionBundle([{path:'sample_submission.csv',text:'id,member\na,0\nb,0\nc,0\n'}],analysis);
  const session=buildCompatibilitySession(analysis);
  assert.equal(session.status,'candidate');
  assert.equal(session.result.kind,'submission-table');
  assert.match(session.result.payload,/a,1/);
  assert.match(session.result.payload,/b,0/);
});

test('Batch85 compatibility entry and clean UI compile against the newest drop-to-result path',()=>{
  const root=path.join(__dirname,'..');
  const entry=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const renderer84=fs.readFileSync(path.join(root,'renderer/challenge_session_batch84.js'),'utf8');
  const renderer85=fs.readFileSync(path.join(root,'renderer/challenge_session_batch85.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  const ipc=fs.readFileSync(path.join(root,'src/electron/challenge_session_ipc.js'),'utf8');
  assert.match(entry,/finals_analyzer_batch85/);
  assert.doesNotThrow(()=>new vm.Script(renderer84,{filename:'challenge_session_batch84.js'}));
  assert.doesNotThrow(()=>new vm.Script(renderer85,{filename:'challenge_session_batch85.js'}));
  assert.match(renderer84,/下一步只做这件事/);
  assert.match(renderer84,/复制结果/);
  assert.match(renderer85,/checker \/ verifier \/ scorer/);
  assert.match(html,/challenge_session_batch85\.js/);
  assert.ok(html.indexOf('challenge_session_batch85.js')>html.indexOf('challenge_session_batch84.js'));
  assert.match(ipc,/buildChallengeSession/);
  assert.match(ipc,/finals_analyzer_batch15/);
});
