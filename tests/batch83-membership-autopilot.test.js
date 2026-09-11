'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {buildMembershipCandidates}=require('../src/core/ai_membership_candidate_builder');
const {splitDelimitedLine,datasetsFromFile,analyzeMembershipBundle}=require('../src/core/ai_membership_bundle_autopilot');
const {buildChallengeSession}=require('../src/core/challenge_session_batch83');
const {planChallengeNextInput}=require('../src/core/challenge_next_input');

function baseAnalysis(overrides={}){
  return {
    workspaceName:'membership-challenge',workspacePath:'/tmp/membership-challenge',challengeInput:{kind:'file-session'},
    files:[{path:'calibration.csv',name:'calibration.csv',extension:'.csv',type:'文本',size:128,sha256:'a'.repeat(64),flags:[],findings:[]}],
    findings:[],candidates:{flags:[],urls:[],ips:[]},
    autopilot:{track:{id:'ai',title:'人工智能安全',score:30},flags:[],artifacts:[],actions:[],automaticChecks:[{id:'workspace-triage',title:'附件识别 / 题型路由',hits:1}],summary:{}},
    autoSolve:{status:'review',gaps:[]},
    ...overrides
  };
}

const calibration=`id,member,confidence\na,1,0.99\nb,1,0.95\nc,0,0.20\nd,0,0.10\n`;
const query=`id,confidence\nq1,0.98\nq2,0.12\nq3,0.93\n`;

test('Batch83 calibrated builder produces member IDs without using query truth',()=>{
  const result=buildMembershipCandidates({calibration:[
    {id:'a',member:1,confidence:0.99},{id:'b',member:1,confidence:0.95},{id:'c',member:0,confidence:0.20},{id:'d',member:0,confidence:0.10}
  ],query:[{id:'q1',confidence:0.98},{id:'q2',confidence:0.12},{id:'q3',confidence:0.93}],targetFpr:0.1});
  assert.equal(result.status,'candidate');
  assert.equal(result.signal.id,'confidence');
  assert.ok(result.memberIds.includes('q1'));
  assert.ok(!result.memberIds.includes('q2'));
});

test('Batch83 membership bundle links calibration.csv and query.csv automatically',()=>{
  const result=analyzeMembershipBundle([{path:'calibration.csv',text:calibration},{path:'query.csv',text:query}]);
  assert.equal(result.status,'candidate',JSON.stringify(result));
  assert.equal(result.selection.signal,'confidence');
  assert.equal(result.selection.calibration.path,'calibration.csv');
  assert.equal(result.selection.query.path,'query.csv');
  assert.ok(result.result.memberIds.includes('q1'));
  assert.match(result.next,/checker|submission|scorer/i);
});

test('Batch83 JSON object may carry calibration and query arrays in one dropped file',()=>{
  const body=JSON.stringify({calibration:[
    {id:'a',member:true,loss:0.05},{id:'b',member:true,loss:0.08},{id:'c',member:false,loss:0.8},{id:'d',member:false,loss:0.9}
  ],query:[{id:'x',loss:0.06},{id:'y',loss:0.95}]});
  const result=analyzeMembershipBundle([{path:'bundle.json',text:body}]);
  assert.equal(result.status,'candidate',JSON.stringify(result));
  assert.equal(result.selection.signal,'loss');
  assert.ok(result.result.memberIds.includes('x'));
});

test('Batch83 near-equivalent calibration sources stop at ambiguous instead of guessing by file order',()=>{
  const files=[{path:'reference-a.csv',text:calibration},{path:'reference-b.csv',text:calibration},{path:'query.csv',text:query}];
  const result=analyzeMembershipBundle(files);
  assert.equal(result.status,'ambiguous',JSON.stringify(result));
  assert.ok(result.alternatives.length>=2);
  assert.match(result.next,/calibration|query|说明/i);
});

test('Batch83 CSV parser handles quoted cells deterministically',()=>{
  assert.deepEqual(splitDelimitedLine('"a,b",1,"x""y"',','),['a,b','1','x"y']);
  const sets=datasetsFromFile({path:'rows.csv',text:'id,member,confidence\n"a,b",1,0.9\nc,0,0.1\n'});
  assert.equal(sets[0].rows[0].id,'a,b');
});

test('Batch83 Challenge Session exposes a clean membership candidate and exact next input',()=>{
  const auto=analyzeMembershipBundle([{path:'calibration.csv',text:calibration},{path:'query.csv',text:query}]);
  const analysis=baseAnalysis({aiMembershipAutopilot:auto});
  const session=buildChallengeSession(analysis);
  assert.equal(session.status,'candidate');
  assert.equal(session.result.kind,'membership-id-list');
  assert.equal(session.result.payload,auto.result.payload);
  assert.equal(session.primaryNeed.code,'MEMBERSHIP_VERIFIER_OR_SCHEMA');
  assert.equal(session.nextInput.code,'MEMBERSHIP_VERIFIER_OR_SCHEMA');
  assert.match(session.nextInput.where,/直接拖/);
  assert.match(session.nextInput.format,/提交哪些字段|checker|评分/i);
});

test('Batch83 next-input planner tells directory users exactly where to place missing data',()=>{
  const analysis=baseAnalysis({challengeInput:{kind:'directory'},aiMembershipAutopilot:{status:'gap',reason:'缺少带 member/non-member 真值的 calibration/reference 数据'}});
  const session={status:'needs-input',primaryNeed:null};
  const next=planChallengeNextInput(analysis,session);
  assert.equal(next.code,'MEMBERSHIP_CALIBRATION_MISSING');
  assert.match(next.format,/id、member/);
  assert.match(next.where,/当前赛题目录/);
  assert.equal(next.action,'rescan');
});

test('Batch83 compatibility entry routes analyzer through membership Drop-to-Result',()=>{
  const root=path.join(__dirname,'..');
  const compat=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const wrapper=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch83.js'),'utf8');
  assert.match(compat,/finals_analyzer_batch82/);
  assert.match(compat,/finals_analyzer_batch83/);
  assert.match(wrapper,/analyzeMembershipBundle/);
  assert.match(wrapper,/challenge_session_batch83/);
});
