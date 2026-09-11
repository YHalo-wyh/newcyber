'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const {buildPromptAttackArsenal}=require('../src/core/ai_prompt_attack_arsenal');
const prompt80=require('../src/core/ai_prompt_injection_batch80');
const {analyzePrivacyLeakage}=require('../src/core/ai_privacy_leakage');
const {analyzeBackdoorTriggerAssociations}=require('../src/core/ai_backdoor_trigger_search');
const analyzer=require('../src/core/finals_analyzer_batch15');

test('Batch80 prompt arsenal is large, deterministic and family-diverse',()=>{
  const first=buildPromptAttackArsenal({});
  const second=buildPromptAttackArsenal({});
  assert.equal(first.total,240);
  assert.equal(first.seeds,30);
  assert.equal(first.mutations,8);
  assert.deepEqual(first.templates.map((x)=>x.id),second.templates.map((x)=>x.id));
  assert.equal(new Set(first.templates.map((x)=>x.id)).size,240);
  for(const category of ['direct','indirect','rag','agent-tool','secret-boundary','multi-turn']){
    assert.ok(first.coverage.byCategory[category]>=24,category);
  }
  assert.ok(first.templates.every((x)=>x.competition===true));
  assert.ok(first.templates.some((x)=>x.payload.includes(first.marker)));
});

test('Batch80 competition suite merges legacy templates with 240-template arsenal',()=>{
  const suite=prompt80.buildPromptInjectionSuite({competitionOnly:true});
  assert.ok(suite.templates.length>=260);
  assert.equal(suite.arsenal.total,240);
  assert.ok(suite.templates.some((x)=>x.id==='arsenal-rag-authority-json'));
  const filtered=prompt80.buildPromptInjectionSuite({ids:['arsenal-tool-output-xml']});
  assert.equal(filtered.templates.length,1);
  assert.equal(filtered.templates[0].category,'agent-tool');
});

test('Batch80 privacy leakage requires explicit secret/reference evidence',()=>{
  const result=analyzePrivacyLeakage({rows:[
    {response:'normal answer',secret:'SAFE_PRIVATE_ABC'},
    {response:'debug SAFE_PRIVATE_ABC',secret:'SAFE_PRIVATE_ABC'},
    {response:'alpha beta gamma delta epsilon zeta eta theta',private_reference:'alpha beta gamma delta epsilon zeta eta theta'}
  ]});
  assert.equal(result.summary.risk,'high');
  assert.ok(result.summary.exactLeaks>=1);
  assert.ok(result.summary.referenceLeaks>=1);
  assert.ok(result.findings.some((x)=>x.id==='privacy-explicit-secret-leak'));
});

test('Batch80 trigger search ranks rare high-purity label associations without calling them confirmed backdoors',()=>{
  const rows=[];
  for(let i=0;i<10;i++)rows.push({label:'A',text:`normal apple sample${i}`});
  for(let i=0;i<10;i++)rows.push({label:'B',text:`normal banana sample${i}`});
  for(let i=0;i<5;i++)rows.push({label:'C',text:`ordinary trigx payload${i}`});
  for(let i=0;i<5;i++)rows.push({label:'C',text:`ordinary classc clean${i}`});
  const result=analyzeBackdoorTriggerAssociations({rows});
  const trigger=result.candidates.find((x)=>x.feature==='text:token=trigx');
  assert.ok(trigger);
  assert.equal(trigger.targetLabel,'C');
  assert.equal(trigger.purity,1);
  assert.ok(trigger.lift>=2.5);
  assert.ok(result.notes.some((x)=>/不生成投毒载荷/.test(x)));
});

test('Batch80 compatibility workspace auto-runs prompt arsenal and weak-direction analyzers',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b80-'));
  try{
    await fs.writeFile(path.join(dir,'privacy.csv'),'response,secret\n"leak SAFE_CANARY_X","SAFE_CANARY_X"\n','utf8');
    await fs.writeFile(path.join(dir,'poison.csv'),'label,text\nA,"normal one"\nA,"normal two"\nA,"normal three"\nB,"clean four"\nB,"clean five"\nC,"trigx a"\nC,"trigx b"\nC,"trigx c"\nC,"trigx d"\nC,"trigx e"\nC,"clean c"\nC,"clean cc"\n','utf8');
    const analysis=await analyzer.scanWorkspace(dir);
    assert.ok(analysis.version>=80);
    assert.equal(analysis.promptAttackArsenal.total,240);
    assert.ok(analysis.aiPrivacyLeakage);
    assert.ok(analysis.aiBackdoorTriggerSearch);
    assert.equal(analysis.aiStage1OfficialDirections.directions.length,5);
    assert.ok(analysis.autopilot.automaticChecks.some((x)=>x.id==='prompt-attack-arsenal'));
  }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('Batch80 compatibility entry preserves older markers while routing to newest analyzer',async()=>{
  const compat=await fs.readFile(path.join(__dirname,'../src/core/finals_analyzer_batch15.js'),'utf8');
  assert.match(compat,/finals_analyzer_batch49/);
  assert.match(compat,/finals_analyzer_batch79/);
  assert.match(compat,/finals_analyzer_batch80/);
});
