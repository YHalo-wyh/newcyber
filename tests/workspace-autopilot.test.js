const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const { buildWorkspaceAutopilot }=require('../src/core/workspace_autopilot');
const { buildAutopilotSection }=require('../src/core/finals_analyzer_batch15');

function artifact(name='video.h265') {
  return {name,size:4096,sha256:`sha-${name}`,completeness:'complete',mediaType:'video/H265'};
}

test('workspace autopilot ranks evidence and produces the shortest next-action chain',()=>{
  const video=artifact();
  const analysis={
    categories:[{name:'低空经济安全',score:18}],
    findings:[{id:'reg-authz',severity:'high',title:'飞行许可对象授权边界',file:'api.py',evidence:'permit_id'}],
    candidates:{flags:[]},
    files:[
      {path:'api.py',size:1200,type:'Python',flags:['flag{demo}'],findings:[{id:'reg-authz',severity:'high',title:'飞行许可对象授权边界',file:'api.py'}],metadata:{regulatoryAudit:{findings:[1]}}},
      {path:'flight.pcap',size:9000,type:'PCAP',flags:[],findings:[],metadata:{captureIntelligence:{video:{artifacts:[video],sessions:[{codec:'H265',artifact:video}]},datalink:{vendorEvidence:[{vendor:'OcuSync'}]}}}}
    ]
  };
  const result=buildWorkspaceAutopilot(analysis);
  assert.equal(result.track.id,'lowalt');
  assert.equal(result.flags[0].value,'flag{demo}');
  assert.equal(result.artifacts.length,1);
  assert.equal(result.artifacts[0].kind,'RTP/H265 图传');
  assert.equal(result.actions[0].id,'verify-flag');
  assert.equal(result.actions[1].id,'export-artifact');
  assert.ok(result.automaticChecks.some((x)=>x.id==='uav-regulatory'));
  assert.ok(result.automaticChecks.some((x)=>x.id==='capture-intelligence'));
});

test('autopilot markdown is appended as the default workflow summary',()=>{
  const analysis={autopilot:{track:{title:'人工智能安全',score:22},summary:{automaticCheckKinds:3,automaticCheckHits:5,highFindings:1,flagCandidates:0,exportableArtifacts:1},actions:[{title:'优先跟进：模型输出泄露',detail:'transcript.json'}],automaticChecks:[{title:'OCR 模型窃取分析',hits:2}]}};
  const md=buildAutopilotSection(analysis);
  assert.match(md,/自动赛题工作流/);
  assert.match(md,/人工智能安全/);
  assert.match(md,/OCR 模型窃取分析: 2/);
});

test('renderer removes legacy competition-mode wording and shows automatic scan results',()=>{
  const source=fs.readFileSync(require.resolve('../renderer/workspace_autopilot.js'),'utf8');
  const context={
    homeView:()=>'<div>COMPETITION MODE 比赛模式 选择赛题目录，开始分析 把题目丢进来，<em>先告诉你下一步做什么。</em> NewCyber 先做离线分析，再把最值得追的线索压缩成 1～3 个动作。</div>',
    workspaceView:()=>'<div>比赛模式 COMPETITION MODE</div>',
    state:{workspace:{workspaceName:'demo',autopilot:{track:{title:'低空经济安全',score:30,tool:'mavlink-hex'},summary:{automaticCheckKinds:4,automaticCheckHits:7,highFindings:2,flagCandidates:1,exportableArtifacts:1},artifacts:[{artifact:artifact('x.h265')}],automaticChecks:[{title:'GNSS/GPS 异常审计',hits:1}],actions:[{title:'验证 Flag 候选',detail:'flag{demo}',level:'win'}]}}},
    esc:(x)=>String(x),
    toast:()=>{},
    render:()=>{},
    window:{newcyber:{saveArtifact:async()=>null}},
    document:{addEventListener:()=>{}},
    Number,console
  };
  vm.createContext(context);
  new vm.Script(source,{filename:'workspace_autopilot.js'}).runInContext(context);
  const home=context.homeView();
  const workspace=context.workspaceView();
  assert.doesNotMatch(home,/COMPETITION MODE|比赛模式/);
  assert.match(home,/一键自动分析/);
  assert.doesNotMatch(workspace,/COMPETITION MODE|比赛模式/);
  assert.match(workspace,/一键自动分析已完成/);
  assert.match(workspace,/GNSS\/GPS 异常审计/);
});
