const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.join(__dirname,'..');
const read=(p)=>fs.readFileSync(path.join(root,p),'utf8');
const {runAiRealCtfRegression,getAiRealCtfCorpus}=require('../src/core/ai_real_ctf_regression');
const {runTool}=require('../src/core/tool_router');

test('domestic AI CTF corpus is provenance-aware and exposes honest coverage gaps',()=>{
  const corpus=getAiRealCtfCorpus();
  assert.ok(corpus.length>=8);
  for(const item of corpus){
    assert.ok(item.event&&item.challenge&&item.source);
    assert.ok(['official-writeup-derived','public-writeup-derived','public-description-derived','public-description-only'].includes(item.provenance));
    assert.ok(['full','partial','gap'].includes(item.coverage));
  }
  const names=corpus.map((x)=>x.challenge);
  for(const expected of ['🪐 小型大语言模型星球','欺诈猎手的后门陷阱','The Silent Heist','what-is-model','prompt_audit','CIFAR-10','Fake Emotion','Blind']) assert.ok(names.includes(expected));
  const fake=corpus.find((x)=>x.challenge==='Fake Emotion');
  assert.equal(fake.coverage,'gap');
  assert.match(fake.limitation,/\.npy|NPY/i);
});

test('real AI CTF regression feeds analyzers instead of claiming every challenge solved',()=>{
  const result=runAiRealCtfRegression();
  assert.equal(result.schema,'newcyber.ai-real-ctf-regression.v1');
  assert.equal(result.summary.total,8);
  assert.ok(result.summary.recognitionPass>=6);
  assert.ok(result.summary.coveragePartial>=5);
  assert.equal(result.summary.coverageGap,1);
  assert.match(result.note,/PASS.*不等于已自动解出原题/);

  const byName=new Map(result.results.map((x)=>[x.challenge,x]));
  assert.equal(byName.get('🪐 小型大语言模型星球').status,'pass');
  assert.ok(byName.get('🪐 小型大语言模型星球').findingIds.includes('target-output-oracle'));
  assert.equal(byName.get('The Silent Heist').status,'pass');
  assert.ok(byName.get('The Silent Heist').findingIds.includes('multivariate-profile'));
  assert.equal(byName.get('prompt_audit').status,'pass');
  assert.ok(byName.get('prompt_audit').findingIds.includes('prompt-injection-rag-surface'));
  assert.equal(byName.get('CIFAR-10').status,'pass');
  assert.ok(byName.get('CIFAR-10').findingIds.includes('backdoor-target-asr-candidate'));
  assert.equal(byName.get('Blind').status,'pass');
  assert.ok(byName.get('Blind').findingIds.includes('ai-output-shell-injection'));
  assert.equal(byName.get('Fake Emotion').status,'gap');
});

test('tool router exposes real corpus and executable regression',()=>{
  const corpus=runTool('ai-real-ctf-corpus',{});
  assert.equal(corpus.schema,'newcyber.ai-real-ctf-corpus.v1');
  assert.ok(corpus.cases.length>=8);
  const result=runTool('ai-real-ctf-regression',{});
  assert.equal(result.summary.total,8);
});

test('homepage is a compact desktop start center, not the legacy marketing hero',()=>{
  const source=read('renderer/home_dashboard.js');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/home_dashboard.js'}));
  assert.doesNotMatch(source,/把题目丢进来|自动把重复劳动跑完|AUTO WORKFLOW|competition-hero|competition-flow/);
  for(const label of ['NewCyber','WORKSPACE','分析链状态','专项工作台','国内 AI CTF 真题回归','最近工具']) assert.match(source,new RegExp(label));

  const context={
    homeView:()=>'<div>legacy marketing</div>',
    DOMAINS:{vehicle:{tools:[]},lowalt:{tools:[]},ai:{tools:[]},web3:{tools:[]}},
    TOOL_META:{},
    localStorage:{getItem:()=>null},
    esc:(x)=>String(x??''),
    render:()=>{},
    console
  };
  vm.createContext(context);
  vm.runInContext(source,context);
  const html=context.homeView();
  assert.match(html,/home-start-center/);
  assert.match(html,/<h1>NewCyber<\/h1>/);
  assert.match(html,/选择赛题目录/);
  assert.doesNotMatch(html,/legacy marketing|competition-hero|把题目丢进来/);
});

test('specialized real CTF UI loads after generic track surfaces and dashboard wins after autopilot',()=>{
  const html=read('renderer/toolbox.html');
  const real=read('renderer/ai_real_ctf_tools.js');
  const css=read('renderer/styles/home_dashboard.css');
  assert.doesNotThrow(()=>new vm.Script(real,{filename:'renderer/ai_real_ctf_tools.js'}));
  assert.ok(html.indexOf('ai_real_ctf_tools.js')>html.indexOf('track_surfaces.js'));
  assert.ok(html.indexOf('home_dashboard.js')>html.indexOf('workspace_autopilot.js'));
  assert.match(html,/styles\/home_dashboard\.css/);
  assert.match(html,/styles\/ai_real_ctf\.css/);
  assert.match(real,/国内 AI CTF 真题回归/);
  assert.match(real,/运行全部/);
  assert.match(css,/\.home-brand-line h1\{font-size:21px/);
  assert.doesNotMatch(css,/font-size:46px/);
});
