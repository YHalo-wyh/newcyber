'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {buildAiStage1Mission,attachAiStage1Mission}=require('../src/core/ai_stage1_mission');

function direction(result,id){return result.directions.find((x)=>x.id===id);}

test('Batch44 aggregates five AI directions across workspace files without upgrading path hints to evidence',()=>{
  const analysis={
    categories:[{name:'人工智能',score:18}],
    files:[
      {
        path:'agent.py',
        metadata:{aiAudit:{findings:[{id:'prompt-tool-boundary',severity:'high',title:'Prompt tool authorization boundary',evidence:'untrusted model output reaches tool dispatch'}]}},
        findings:[{id:'prompt-tool-boundary:agent.py',severity:'high',title:'Prompt tool authorization boundary',evidence:'untrusted model output reaches tool dispatch'}]
      },
      {
        path:'train.csv',
        metadata:{aiDatasetSecurity:{triggerCandidates:[{column:'token',token:'cf_trigger',targetLabel:'target'}],findings:[{id:'dataset-trigger-candidate',severity:'high',title:'数据投毒 / 后门候选',evidence:'trigger cf_trigger strongly correlates with target'}]}},
        findings:[]
      },
      {
        path:'requirements.txt',
        metadata:{aiSupplyChain:{findings:[{id:'remote-code',severity:'high',title:'trust_remote_code enabled',evidence:'from_pretrained(..., trust_remote_code=True)'}]}},
        findings:[]
      },
      {path:'samples/x_adv.npy',metadata:{},findings:[]}
    ]
  };
  const result=buildAiStage1Mission(analysis);
  assert.equal(result.schema,'newcyber.ai-stage1-mission.v1');
  assert.equal(result.applicable,true);
  assert.equal(result.officialCoverage,5);
  assert.equal(direction(result,'prompt-llm-security').status,'evidence');
  assert.equal(direction(result,'backdoor-poisoning').status,'evidence');
  assert.equal(direction(result,'infra-supply-chain').status,'evidence');
  assert.equal(direction(result,'adversarial-example').status,'candidate');
  assert.equal(direction(result,'privacy-leakage').status,'data-needed');
  assert.equal(result.nextDirection.id,'adversarial-example');
  assert.ok(direction(result,'adversarial-example').evidence.some((x)=>x.kind==='path-hint'));
  assert.notEqual(direction(result,'adversarial-example').status,'evidence');
});

test('Batch44 preserves an explicit no-finding skill-matrix result',()=>{
  const analysis={categories:[{name:'AI / ML',score:9}],files:[{
    path:'matrix.json',
    metadata:{aiSkillMatrix:{skills:[{id:'privacy-leakage',status:'no-explicit-finding',confidence:'low',nextAction:'collect member and non-member score distributions'}]}},
    findings:[]
  }]};
  const result=buildAiStage1Mission(analysis);
  const privacy=direction(result,'privacy-leakage');
  assert.equal(privacy.status,'no-explicit-finding');
  assert.equal(privacy.nextAction,'collect member and non-member score distributions');
});

test('Batch44 injects the mission into autopilot and challenge session',()=>{
  const analysis={
    categories:[{name:'人工智能',score:16}],
    files:[{path:'backdoor.csv',metadata:{},findings:[]}],
    challengeSession:{},
    autopilot:{automaticChecks:[],summary:{automaticCheckKinds:0,automaticCheckHits:0},actions:[{id:'inspect-entry',priority:10,title:'入口'}]}
  };
  const mission=attachAiStage1Mission(analysis);
  assert.equal(analysis.aiStage1Mission,mission);
  assert.equal(analysis.challengeSession.aiStage1Mission,mission);
  assert.equal(analysis.autopilot.aiStage1Mission,mission);
  assert.ok(analysis.autopilot.automaticChecks.some((x)=>x.id==='ai-stage1-mission'));
  assert.ok(analysis.autopilot.actions.some((x)=>x.id==='ai-stage1-mission'));
  assert.equal(direction(mission,'backdoor-poisoning').status,'candidate');
});

test('Batch44 compatibility entrypoint and workspace UI are wired',()=>{
  const root=path.join(__dirname,'..');
  const compat=fs.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const toolbox=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  const source=fs.readFileSync(path.join(root,'renderer/ai_stage1_mission.js'),'utf8');
  assert.match(compat,/finals_analyzer_batch44/);
  assert.match(toolbox,/ai_stage1_mission\.js/);
  assert.match(source,/AI Stage-One Mission/);

  const context={
    workspaceView:()=>'<main>base</main>',
    state:{workspace:{aiStage1Mission:{applicable:true,officialCoverage:5,summary:{covered:2,evidence:1,candidate:1,'data-needed':2,detectedFiles:3,evidenceItems:2},directions:[{id:'prompt-llm-security',title:'提示词工程与大模型安全',status:'evidence',confidence:'high',files:['agent.py'],evidence:[{file:'agent.py',title:'tool boundary',evidence:'untrusted output'}],nextAction:'verify'}],nextDirection:{title:'对抗样本攻击',status:'candidate',nextAction:'verify epsilon',tools:['ai-skill-matrix']}}}},
    esc:(x)=>String(x),
    console
  };
  vm.createContext(context);
  new vm.Script(source,{filename:'ai_stage1_mission.js'}).runInContext(context);
  const html=context.workspaceView();
  assert.match(html,/AI Stage-One Mission/);
  assert.match(html,/提示词工程与大模型安全/);
  assert.match(html,/继续下一方向/);
  assert.match(html,/base/);
});
