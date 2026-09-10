const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.join(__dirname,'..');
const read=(p)=>fs.readFileSync(path.join(root,p),'utf8');
const {runAiRealCtfRegression,getAiRealCtfCorpus}=require('../src/core/ai_real_ctf_regression');
const {runTool}=require('../src/core/tool_router');

test('domestic AI CTF corpus is provenance-aware and keeps partial coverage honest',()=>{
  const corpus=getAiRealCtfCorpus();
  assert.ok(corpus.length>=11);
  for(const item of corpus){
    assert.ok(item.event&&item.challenge&&item.source);
    assert.ok(['official-source-derived','official-writeup-derived','public-writeup-derived','public-description-derived','public-description-only'].includes(item.provenance));
    assert.ok(['full','partial','gap'].includes(item.coverage));
  }
  const names=corpus.map((x)=>x.challenge);
  for(const expected of ['🪐 小型大语言模型星球','SU_easyLLM','欺诈猎手的后门陷阱','easy_poison','The Silent Heist','what-is-model','prompt_audit','CIFAR-10','Fake Emotion','耄耋','Blind']) assert.ok(names.includes(expected));
  const su=corpus.find((x)=>x.challenge==='SU_easyLLM');
  assert.equal(su.provenance,'official-source-derived');
  assert.match(su.limitation,/SHA256|AES|LLM/i);
  const fake=corpus.find((x)=>x.challenge==='Fake Emotion');
  assert.equal(fake.coverage,'partial');
  assert.match(fake.limitation,/NPY|样本|差分/i);
  const maodie=corpus.find((x)=>x.challenge==='耄耋');
  assert.equal(maodie.provenance,'public-writeup-derived');
  assert.match(maodie.limitation,/0\.85|0\.125|频域/);
});

test('real AI CTF regression separates recognized candidate and verified maturity',()=>{
  const result=runAiRealCtfRegression();
  assert.equal(result.schema,'newcyber.ai-real-ctf-regression.v1');
  assert.equal(result.maturitySchema,'newcyber.ai-real-ctf-maturity.v1');
  assert.equal(result.summary.total,11);
  assert.ok(result.summary.recognitionPass>=10);
  assert.ok(result.summary.candidatePass>=1);
  assert.equal(result.summary.verifiedPass,0);
  assert.ok(result.summary.recognitionPass>=result.summary.candidatePass);
  assert.ok(result.summary.candidatePass>=result.summary.verifiedPass);
  assert.ok(result.summary.coveragePartial>=9);
  assert.equal(result.summary.coverageGap,0);
  assert.match(result.note,/Recognized.*Candidate.*Verified/);

  const byName=new Map(result.results.map((x)=>[x.challenge,x]));
  assert.equal(byName.get('🪐 小型大语言模型星球').status,'pass');
  assert.equal(byName.get('🪐 小型大语言模型星球').maturityStage,'recognized');
  assert.ok(byName.get('🪐 小型大语言模型星球').findingIds.includes('target-output-oracle'));
  assert.equal(byName.get('SU_easyLLM').status,'pass');
  assert.equal(byName.get('SU_easyLLM').maturityStage,'recognized');
  assert.ok(byName.get('SU_easyLLM').findingIds.includes('llm-derived-crypto-key'));
  assert.equal(byName.get('easy_poison').status,'pass');
  assert.equal(byName.get('easy_poison').maturityStage,'candidate');
  assert.equal(byName.get('easy_poison').candidateObject.trigger,'reverse-trigger');
  assert.equal(byName.get('easy_poison').candidateObject.targetLabel,'1');
  assert.equal(byName.get('easy_poison').verified,false);
  assert.equal(byName.get('The Silent Heist').status,'pass');
  assert.ok(byName.get('The Silent Heist').findingIds.includes('multivariate-profile'));
  assert.equal(byName.get('prompt_audit').status,'pass');
  assert.ok(byName.get('prompt_audit').findingIds.includes('prompt-injection-rag-surface'));
  assert.equal(byName.get('CIFAR-10').status,'miss');
  assert.ok(byName.get('CIFAR-10').findingIds.includes('backdoor-target-asr-candidate'));
  assert.match(byName.get('CIFAR-10').limitation,/Patch|trigger/i);
  assert.equal(byName.get('Fake Emotion').status,'pass');
  assert.match(byName.get('Fake Emotion').evidence,/shape=8x8x1/);
  assert.equal(byName.get('耄耋').status,'pass');
  assert.ok(byName.get('耄耋').findingIds.includes('frequency-domain-profile'));
  assert.equal(byName.get('Blind').status,'pass');
  assert.ok(byName.get('Blind').findingIds.includes('ai-output-shell-injection'));
});

test('tool router exposes expanded real corpus and maturity regression',()=>{
  const corpus=runTool('ai-real-ctf-corpus',{});
  assert.equal(corpus.schema,'newcyber.ai-real-ctf-corpus.v1');
  assert.ok(corpus.cases.length>=11);
  const result=runTool('ai-real-ctf-regression',{});
  assert.equal(result.summary.total,11);
  assert.ok(result.summary.recognitionPass>=result.summary.candidatePass);
  assert.ok(result.summary.candidatePass>=result.summary.verifiedPass);
});

test('homepage is a compact desktop start center, not the legacy marketing hero',()=>{
  const source=read('renderer/home_dashboard.js');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/home_dashboard.js'}));
  assert.doesNotMatch(source,/把题目丢进来|自动把重复劳动跑完|AUTO WORKFLOW|competition-hero|competition-flow/);
  for(const label of ['NewCyber','WORKSPACE','分析链状态','专项工作台','国内 AI CTF 真题成熟度','最近工具']) assert.match(source,new RegExp(label));

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
  assert.match(html,/11 CASES/);
  assert.match(html,/Recognized → Candidate → Verified/);
  assert.doesNotMatch(html,/legacy marketing|competition-hero|把题目丢进来/);
});

test('specialized real CTF UI exposes maturity funnel and synchronized 11-case catalog',()=>{
  const html=read('renderer/toolbox.html');
  const real=read('renderer/ai_real_ctf_tools.js');
  const home=read('renderer/home_dashboard.js');
  const css=read('renderer/styles/home_dashboard.css');
  assert.doesNotThrow(()=>new vm.Script(real,{filename:'renderer/ai_real_ctf_tools.js'}));
  assert.ok(html.indexOf('ai_real_ctf_tools.js')>html.indexOf('track_surfaces.js'));
  assert.ok(html.indexOf('home_dashboard.js')>html.indexOf('workspace_autopilot.js'));
  assert.match(html,/styles\/home_dashboard\.css/);
  assert.match(html,/styles\/ai_real_ctf\.css/);
  for(const label of ['国内 AI CTF 真题回归','SU_easyLLM','easy_poison','耄耋','RECOGNIZED','CANDIDATE','VERIFIED']) assert.match(real,new RegExp(label));
  assert.match(real,/\$\{CASES\.length\} CASES/);
  assert.doesNotMatch(real,/8 CASES|8 个公开真题|9 CASES/);
  assert.match(home,/11 CASES/);
  assert.doesNotMatch(home,/8 CASES|9 CASES/);
  assert.match(css,/\.home-brand-line h1\{font-size:21px/);
  assert.doesNotMatch(css,/font-size:46px/);
});
