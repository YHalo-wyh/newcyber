const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const { analyzePoisoningImpact, analyzeBackdoorBehavior }=require('../src/core/ai_poison_backdoor_validation');
const { runTool }=require('../src/core/tool_router');

test('poisoning impact validator measures contamination, label flips, target concentration and model deltas',()=>{
  const result=analyzePoisoningImpact({
    rows:[
      {is_poison:false,label:0,original_label:0},
      {is_poison:false,label:2,original_label:2},
      {is_poison:true,label:1,original_label:0,target_label:1,trigger_id:'candidate-A'},
      {is_poison:true,label:1,original_label:2,target_label:1,trigger_id:'candidate-A'},
      {is_poison:true,label:1,original_label:0,target_label:1,trigger_id:'candidate-A'},
      {is_poison:true,label:1,original_label:2,target_label:1,trigger_id:'candidate-A'}
    ],
    baseline:{accuracy:0.95,loss:0.12},
    suspect:{accuracy:0.82,loss:0.31}
  });
  assert.equal(result.marked.poison,4);
  assert.equal(result.marked.clean,2);
  assert.equal(result.contaminationRate,4/6);
  assert.equal(result.labelFlip.rate,1);
  assert.equal(result.targetConcentration.label,'1');
  assert.equal(result.targetConcentration.ratio,1);
  assert.ok(Math.abs(result.metrics.deltas.accuracy+0.13)<1e-12);
  assert.equal(result.verdict,'strong-candidate');
  assert.ok(result.findings.some((x)=>x.id==='poisoning-label-flip-candidate'));
  assert.ok(result.findings.some((x)=>x.id==='poisoning-target-concentration'));
  assert.ok(result.findings.some((x)=>x.id==='poisoning-model-impact-candidate'));
});

test('poisoning validator remains conservative when rows have no poison markers',()=>{
  const result=analyzePoisoningImpact('text,label\nnormal a,0\nnormal b,1');
  assert.equal(result.marked.poison,0);
  assert.equal(result.contaminationRate,null);
  assert.equal(result.verdict,'insufficient-evidence');
  assert.ok(result.notes.some((x)=>/优先使用/.test(x)));
});

test('backdoor behavior validator reports target ASR, flip rate and control specificity',()=>{
  const rows=[];
  for (let i=0;i<10;i++) rows.push({
    true_label:i%2===0?0:2,
    clean_pred:i%2===0?0:2,
    triggered_pred:1,
    control_pred:i%2===0?0:2
  });
  const result=analyzeBackdoorBehavior({targetLabel:1,rows});
  assert.equal(result.metrics.cleanAccuracy,1);
  assert.equal(result.metrics.targetASR,1);
  assert.equal(result.metrics.flipRate,1);
  assert.equal(result.metrics.controlTargetRate,0);
  assert.equal(result.metrics.triggerSpecificity,1);
  assert.equal(result.verdict,'strong-candidate');
  assert.ok(result.findings.some((x)=>x.id==='backdoor-target-asr-candidate'));
  assert.ok(result.findings.some((x)=>x.id==='backdoor-control-specificity'));
});

test('backdoor validator does not declare a backdoor when clean and triggered predictions are unchanged',()=>{
  const result=analyzeBackdoorBehavior({targetLabel:1,rows:[
    {true_label:0,clean_pred:0,triggered_pred:0,control_pred:0},
    {true_label:2,clean_pred:2,triggered_pred:2,control_pred:2},
    {true_label:0,clean_pred:0,triggered_pred:0,control_pred:0},
    {true_label:2,clean_pred:2,triggered_pred:2,control_pred:2},
    {true_label:0,clean_pred:0,triggered_pred:0,control_pred:0}
  ]});
  assert.equal(result.metrics.flipRate,0);
  assert.equal(result.metrics.targetASR,0);
  assert.equal(result.verdict,'insufficient-evidence');
  assert.equal(result.findings.length,0);
});

test('tool router exposes defensive poisoning and backdoor validators',()=>{
  const poison=runTool('ai-poisoning-impact',{input:JSON.stringify({rows:[{is_poison:true,label:1,original_label:0}]})});
  assert.equal(poison.marked.poison,1);
  const backdoor=runTool('ai-backdoor-behavior',{input:JSON.stringify({targetLabel:1,rows:[{true_label:0,clean_pred:0,triggered_pred:1}]})});
  assert.equal(backdoor.targetLabel,'1');
});

test('poison/backdoor renderer compiles and loads after prompt injection training UI',()=>{
  const root=path.join(__dirname,'..');
  const source=fs.readFileSync(path.join(root,'renderer/ai_poison_backdoor_tools.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/ai_poison_backdoor_tools.js'}));
  assert.ok(html.indexOf('ai_poison_backdoor_tools.js')>html.indexOf('ai_prompt_injection_tools.js'));
  assert.match(source,/数据投毒影响验证/);
  assert.match(source,/后门行为验证/);
});
