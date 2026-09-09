const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const {buildChallengeSession}=require('../src/core/challenge_session');
const batch39=require('../src/core/finals_analyzer_batch39');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

function baseAnalysis(overrides={}){
  return {
    workspaceName:'challenge',workspacePath:'/tmp/challenge',
    files:[{path:'challenge.txt',name:'challenge.txt',extension:'.txt',type:'文本',size:128,sha256:'a'.repeat(64),flags:[],findings:[]}],
    findings:[],candidates:{flags:[],urls:[],ips:[]},
    autopilot:{track:null,flags:[],artifacts:[],actions:[],automaticChecks:[{id:'workspace-triage',title:'附件识别 / 题型路由',hits:1}],summary:{}},
    autoSolve:{status:'review',gaps:[]},
    ...overrides
  };
}

test('Batch39 Challenge Session promotes only verified result to solved',()=>{
  const session=buildChallengeSession(baseAnalysis({
    candidates:{flags:[{value:'flag{verified}',confidence:'verified',source:'model-arithmetic-auto'}],urls:[],ips:[]},
    modelArithmeticAuto:{attempts:[{}],best:{source:'bundle.zip',result:{status:'flag-recovered',flag:'flag{verified}'}}}
  }));
  assert.equal(session.status,'solved');
  assert.equal(session.result.value,'flag{verified}');
  assert.equal(session.flags.verified.length,1);
  assert.ok(session.solverLedger.some((item)=>item.id==='model-arithmetic-auto'&&item.status==='solved'));
  assert.equal(session.aiHandoff.ready,false);
});

test('Batch39 keeps an unverified flag as candidate',()=>{
  const session=buildChallengeSession(baseAnalysis({
    candidates:{flags:[{value:'flag{candidate}',confidence:'candidate',file:'notes.txt'}],urls:[],ips:[]}
  }));
  assert.equal(session.status,'candidate');
  assert.equal(session.flags.verified.length,0);
  assert.equal(session.flags.candidates[0].value,'flag{candidate}');
  assert.equal(session.aiHandoff.ready,true);
});

test('Batch39 converts explicit runtime gap into one concrete missing input',()=>{
  const session=buildChallengeSession(baseAnalysis({
    autoSolve:{status:'blocked',gaps:[{code:'MODEL_RUNTIME_GAP',detail:'onnxruntime-node unavailable',source:'Power SCA / Transformer'}]}
  }));
  assert.equal(session.status,'needs-input');
  assert.equal(session.primaryNeed.kind,'local-capability');
  assert.match(session.primaryNeed.title,/本地模型运行环境/);
  assert.match(session.primaryNeed.detail,/onnxruntime-node/);
});

test('Batch39 asks for source/config when an AI model-only bundle lacks semantics',()=>{
  const session=buildChallengeSession(baseAnalysis({
    files:[{path:'model.safetensors',name:'model.safetensors',extension:'.safetensors',type:'SafeTensors',size:2048,sha256:'b'.repeat(64),flags:[],findings:[]}],
    autopilot:{track:{id:'ai',title:'人工智能安全',score:30},flags:[],artifacts:[],actions:[],automaticChecks:[{id:'ai-model',title:'AI 模型检查',hits:1}],summary:{}}
  }));
  assert.equal(session.status,'needs-input');
  assert.equal(session.primaryNeed.id,'need:ai-context');
  assert.match(session.primaryNeed.why,/缺少输入输出/);
});

test('Batch39 deterministic exhaustion produces a self-contained local AI handoff',()=>{
  const session=buildChallengeSession(baseAnalysis({
    findings:[{severity:'high',title:'可疑比较链',file:'challenge.txt',evidence:'candidate bytes are compared after transform'}]
  }));
  assert.equal(session.status,'handoff');
  assert.equal(session.aiHandoff.ready,true);
  assert.match(session.aiHandoff.markdown,/NewCyber Local AI Handoff/);
  assert.match(session.aiHandoff.markdown,/已尝试模板/);
  assert.match(session.aiHandoff.markdown,/可疑比较链/);
  assert.match(session.aiHandoff.markdown,/不要把 candidate 当作 verified/);
});

test('Batch39 report section records solver ledger missing input and AI handoff state',()=>{
  const analysis=baseAnalysis({autoSolve:{status:'blocked',gaps:[{code:'FLAG_DERIVATION_GAP',detail:'need decrypt context'}]}});
  analysis.challengeSession=buildChallengeSession(analysis);
  const md=batch39.buildChallengeSessionSection(analysis);
  assert.match(md,/Challenge Session/);
  assert.match(md,/还缺/);
  assert.match(md,/本地 AI 接管包：ready/);
});

test('Batch39 renderer is the final unified single-file/drop workspace and compiles',()=>{
  const js=read('renderer/challenge_session.js');
  const css=read('renderer/styles/challenge_session.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new vm.Script(js,{filename:'challenge_session.js'}));
  for(const token of ['把题目文件丢进来','SOLVER GRAPH','还缺这一项','LOCAL AI HANDOFF','复制完整接管包','data-session-add-files'])assert.match(js,new RegExp(token));
  assert.match(css,/challenge-session-grid/);
  assert.match(css,/font-size:14px/);
  assert.match(html,/styles\/challenge_session\.css/);
  assert.match(html,/challenge_session\.js/);
  assert.ok(html.indexOf('challenge_session.js')>html.indexOf('electron_chrome.js'));
  assert.ok(html.indexOf('challenge_session.css')>html.indexOf('readability.css'));
});

test('Batch39 Electron bridge supports isolated file sessions add-files rescan and drop',()=>{
  const ipc=read('src/electron/challenge_session_ipc.js');
  const preload=read('preload.js');
  const main=read('electron_main.js');
  for(const token of ['challenge:choose-files','challenge:analyze-dropped','challenge:add-files','challenge:add-dropped','challenge:rescan']){
    assert.match(ipc,new RegExp(token.replace(':','\\:')));
    assert.match(preload,new RegExp(token.replace(':','\\:')));
  }
  assert.match(ipc,/fs\.mkdtemp/);
  assert.match(ipc,/fs\.copyFile/);
  assert.match(ipc,/MAX_TOTAL_BYTES/);
  assert.match(main,/registerChallengeSessionIpc/);
});

test('Batch39 compatibility entry keeps old markers while allowing a newer analyzer to take over',()=>{
  const entry=read('src/core/finals_analyzer_batch15.js');
  for(const marker of ['finals_analyzer_batch22','finals_analyzer_batch35','finals_analyzer_batch38','finals_analyzer_batch39'])assert.match(entry,new RegExp(marker));
  const match=entry.match(/require\('\.\/finals_analyzer_batch(\d+)'\)/);
  assert.ok(match,'compatibility entry must require a batch analyzer');
  assert.ok(Number(match[1])>=39,'compatibility entry must not regress below Batch39');
});
