'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {detectSignals,matchTrainingFamilies}=require('../src/core/ai_training_family_matcher');
const {runTool}=require('../src/core/tool_router');

function adversarialAnalysis(){
  return {
    files:[{path:'bundle/model.onnx',type:'onnx',findings:[]},{path:'bundle/candidates.npy',type:'npy',findings:[]}],
    findings:[{id:'adversarial-candidate-valid',title:'对抗样本满足 epsilon 扰动预算',meaning:'PGD/FGSM adversarial candidate passes verifier budget',evidence:'linf <= epsilon'}],
    aiPreprocessingManifest:{status:'ready',layout:'NCHW'},
    onnxContestAutopilot:{status:'ranked',runs:24}
  };
}

function promptAgentAnalysis(){
  return {
    files:[{path:'agent/app.py',type:'python',findings:[]}],
    findings:[
      {id:'prompt-injection-untrusted-prompt-flow',title:'Prompt injection / system prompt leak',meaning:'user content reaches agent tool call'},
      {id:'agent-trust-boundary',title:'Inter-agent confused deputy',meaning:'forwarded request is trusted by privileged agent'}
    ],
    autopilot:{automaticChecks:[{id:'prompt-audit',title:'RAG and tool policy scan'}]}
  };
}

test('Batch74 detects evidence signals from findings and challenge file types',()=>{
  const signals=detectSignals(adversarialAnalysis());
  const ids=new Set(signals.map((x)=>x.id));
  assert.ok(ids.has('adversarial'));
  assert.ok(ids.has('onnx'));
  assert.ok(ids.has('dataset'));
  assert.ok(signals.find((x)=>x.id==='adversarial').sources.some((x)=>x.startsWith('extension:')||x==='analysis-text'));
});

test('Batch74 maps adversarial model bundles onto trained adversarial challenge families',()=>{
  const result=matchTrainingFamilies(adversarialAnalysis(),{limit:12});
  assert.equal(result.schema,'newcyber.ai-training-family-match.v1');
  assert.ok(['strong','medium'].includes(result.status),result.status);
  assert.equal(result.directionRanking[0].direction,'adversarial-example');
  assert.ok(result.matches.length>0);
  assert.ok(result.matches.some((row)=>row.direction==='adversarial-example'));
  assert.ok(result.matches.some((row)=>/old.?driver|AI Village|AICTF|CIFAR|adversarial/i.test(`${row.event} ${row.challenge} ${row.family}`)));
  assert.ok(result.next.includes('优先复用'));
});

test('Batch74 maps prompt and multi-agent evidence onto prompt challenge families',()=>{
  const result=matchTrainingFamilies(promptAgentAnalysis(),{limit:15});
  assert.equal(result.status,'strong');
  assert.equal(result.directionRanking[0].direction,'prompt-llm-security');
  assert.ok(result.matches.some((row)=>row.direction==='prompt-llm-security'));
  assert.ok(result.matches.some((row)=>/Prompt Airlines|Digital Doppelgänger|agent|prompt/i.test(`${row.event} ${row.challenge} ${row.family}`)));
});

test('Batch74 does not invent a family when challenge evidence is generic',()=>{
  const result=matchTrainingFamilies({files:[{path:'readme.txt',type:'text',findings:[]}],findings:[]});
  assert.equal(result.status,'not-detected');
  assert.equal(result.matches.length,0);
  assert.equal(result.directionRanking.length,0);
});

test('Batch74 public route returns only curriculum metadata, not hidden training fixtures',()=>{
  const result=runTool('ai-training-family-match',{input:adversarialAnalysis(),options:{limit:5}});
  assert.ok(result.matches.length>0);
  const serialized=JSON.stringify(result);
  assert.equal(serialized.includes('fixture'),false);
  assert.ok(result.summary.curriculumCases>=result.matches.length);
});

test('Batch74 Challenge Session invokes family match and persists a local routing manifest',()=>{
  const source=fs.readFileSync(path.join(__dirname,'../src/electron/challenge_session_ipc.js'),'utf8');
  assert.match(source,/require\('\.\.\/core\/ai_training_family_matcher'\)/);
  assert.match(source,/matchTrainingFamilies\(analysis,\{limit:10\}\)/);
  assert.match(source,/newcyber_training_family_match\.json/);
  assert.match(source,/id:'training-family-match'/);
  assert.match(source,/challengeSession\.trainingFamilyMatch/);
});
