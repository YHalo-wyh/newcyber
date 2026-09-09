const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const {buildAutoSolveMission}=require('../src/core/auto_solve_mission');
const batch38=require('../src/core/finals_analyzer_batch38');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

function baseAnalysis(overrides={}){
  return {
    files:[{path:'challenge.bin',size:128,findings:[]}],
    findings:[],
    candidates:{flags:[]},
    autopilot:{
      track:{id:'ai',title:'人工智能安全',score:24,tool:'ai-source-scan'},
      flags:[],artifacts:[],actions:[],
      automaticChecks:[{id:'ai-model',title:'AI 模型/源码安全审计',hits:2}],
      summary:{automaticCheckKinds:1,automaticCheckHits:2}
    },
    ...overrides
  };
}

test('Batch38 Auto Solve marks only verified flags as solved',()=>{
  const analysis=baseAnalysis({
    candidates:{flags:[{value:'flag{verified_result}',confidence:'verified',source:'model-arithmetic-auto'}]}
  });
  const mission=buildAutoSolveMission(analysis);
  assert.equal(mission.status,'solved');
  assert.equal(mission.result.value,'flag{verified_result}');
  assert.equal(mission.primaryAction.kind,'copy-flag');
  assert.equal(mission.verifiedFlags.length,1);
  assert.equal(mission.stages.find((x)=>x.id==='verify').status,'ok');
});

test('Batch38 candidate flags remain candidate and are not promoted to solved',()=>{
  const analysis=baseAnalysis({candidates:{flags:[{value:'flag{needs_check}',file:'notes.txt',confidence:'candidate'}]}});
  const mission=buildAutoSolveMission(analysis);
  assert.equal(mission.status,'candidate');
  assert.equal(mission.verifiedFlags.length,0);
  assert.equal(mission.primaryAction.kind,'verify-flag');
  assert.equal(mission.stages.find((x)=>x.id==='verify').status,'partial');
});

test('Batch38 exposes one explicit SCA runtime gap and routes it to local model runtime',()=>{
  const analysis=baseAnalysis({
    scaAutopilot:{status:'gap',result:{status:'gap',gap:{code:'MODEL_RUNTIME_GAP',detail:'onnxruntime-node unavailable'},stages:[]}}
  });
  const mission=buildAutoSolveMission(analysis);
  assert.equal(mission.status,'blocked');
  assert.equal(mission.gaps[0].code,'MODEL_RUNTIME_GAP');
  assert.equal(mission.primaryAction.kind,'tool');
  assert.equal(mission.primaryAction.tool,'ai-local-model-runtime');
  assert.match(mission.headline,/MODEL_RUNTIME_GAP/);
});

test('Batch38 treats unique hidden secret without a Flag as a derivation gap, not success',()=>{
  const analysis=baseAnalysis({
    modelArithmeticAuto:{attempts:[{}],best:{result:{status:'secret-recovered',solver:{status:'unique'}}}}
  });
  const mission=buildAutoSolveMission(analysis);
  assert.equal(mission.status,'blocked');
  assert.equal(mission.gaps[0].code,'FLAG_DERIVATION_GAP');
  assert.equal(mission.primaryAction.tool,'ai-model-arithmetic-auto');
});

test('Batch38 empty workspace remains explicit instead of inventing a route',()=>{
  const mission=buildAutoSolveMission({files:[],findings:[],candidates:{flags:[]},autopilot:{automaticChecks:[],actions:[],summary:{}}});
  assert.equal(mission.status,'empty');
  assert.equal(mission.stages[0].status,'gap');
});

test('Batch38 report section presents one integrated status and next action',()=>{
  const analysis=baseAnalysis({
    autoSolve:buildAutoSolveMission(baseAnalysis({candidates:{flags:[{value:'flag{report}',confidence:'verified'}]}}))
  });
  const md=batch38.buildAutoSolveSection(analysis);
  assert.match(md,/Auto Solve Mission/);
  assert.match(md,/solved/);
  assert.match(md,/flag\{report\}/);
  assert.match(md,/唯一下一步/);
});

test('Batch38 compatibility entrypoint points to newest workspace analyzer',()=>{
  const entry=read('src/core/finals_analyzer_batch15.js');
  assert.match(entry,/finals_analyzer_batch38/);
});

test('Batch38 readability layer raises evidence text above legacy micro-copy sizes',()=>{
  const css=read('renderer/styles/readability.css');
  assert.match(css,/--nc-font-base:14px/);
  assert.match(css,/--nc-font-small:12px/);
  assert.match(css,/--nc-font-code:12\.5px/);
  assert.match(css,/table\{font-size:12px\}/);
  assert.match(css,/\.finding pre\{font-size:12px/);
  assert.doesNotMatch(css,/--nc-font-base:\s*(?:8|9|10)px/);
});

test('Batch38 dedicated mission UI compiles and is loaded after existing workspace wrappers',()=>{
  const js=read('renderer/auto_solve_mission.js');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new vm.Script(js,{filename:'auto_solve_mission.js'}));
  for(const token of ['AUTO SOLVE · ONE RESULT / ONE NEXT STEP','唯一下一步','继续自动求解','NewCyber 已替你整合'])assert.match(js,new RegExp(token));
  assert.match(html,/styles\/auto_solve\.css/);
  assert.match(html,/styles\/readability\.css/);
  assert.match(html,/auto_solve_mission\.js/);
  assert.ok(html.indexOf('auto_solve_mission.js')>html.indexOf('home_dashboard.js'));
  assert.ok(html.indexOf('readability.css')>html.indexOf('uav_scenario_intel.css'));
});
