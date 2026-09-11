'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

test('Batch84 simplified renderer compiles and keeps Drop-to-Result as the primary interaction',()=>{
  const js=read('renderer/challenge_session_batch84.js');
  assert.doesNotThrow(()=>new vm.Script(js,{filename:'challenge_session_batch84.js'}));
  for(const token of ['把压缩包 / 附件丢进来','下一步只做这件事','文件也可以直接拖到这里','候选结果','复制结果','补充材料','高级工具'])assert.match(js,new RegExp(token));
  assert.match(js,/workspaceView=function batch84Workspace/);
  assert.match(js,/homeView=function batch84Home/);
  assert.match(js,/shell=function batch84Shell/);
  assert.match(js,/aiMembershipAutopilot/);
  assert.match(js,/onnxContestAutopilot/);
  assert.doesNotMatch(js,/SOLVER GRAPH/);
  assert.doesNotMatch(js,/AI MODEL AUTOPILOT/);
});

test('Batch84 toolbox loads clean renderer and stylesheet after older challenge wrappers',()=>{
  const html=read('renderer/toolbox.html');
  assert.match(html,/styles\/challenge_session_batch84\.css/);
  assert.match(html,/challenge_session_batch84\.js/);
  assert.ok(html.indexOf('challenge_session_batch84.css')>html.indexOf('challenge_session_batch60.css'));
  assert.ok(html.indexOf('challenge_session_batch84.js')>html.indexOf('challenge_session_batch60.js'));
});

test('Batch84 styling keeps result, next input and advanced detail visually separated',()=>{
  const css=read('renderer/styles/challenge_session_batch84.css');
  for(const token of ['.cs84-result','.cs84-next','.cs84-progress','.cs84-details','.cs84-mini-drop','.cs84-advanced'])assert.match(css,new RegExp(token.replace('.','\\.')));
  assert.match(css,/grid-template-columns:repeat\(4/);
  assert.match(css,/max-width:1180px/);
});

test('Batch84 next-input copy is concise and gives provide/format/location fields',()=>{
  const js=read('renderer/challenge_session_batch84.js');
  assert.match(js,/`下一步：\$\{next\.title\}`/);
  assert.match(js,/`提供：\$\{list\(next\.provide\)\.join/);
  assert.match(js,/`格式：\$\{next\.format\}`/);
  assert.match(js,/`放哪里：\$\{next\.where\}`/);
});
