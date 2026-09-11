'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const path=require('path');

async function read(rel){return fs.readFile(path.join(__dirname,'..',rel),'utf8');}

test('Batch89 toolbox loads compact submission artifact UI and styles after older Challenge Session wrappers',async()=>{
  const html=await read('renderer/toolbox.html');
  assert.match(html,/styles\/challenge_session_batch89\.css/);
  assert.match(html,/challenge_session_batch87\.js[\s\S]*challenge_session_batch89\.js/);
});

test('Batch89 artifact result renderer compiles and never puts full payload into a data attribute',async()=>{
  const source=await read('renderer/challenge_session_batch89.js');
  assert.doesNotThrow(()=>new Function(source));
  assert.match(source,/VERIFIED SUBMISSION/);
  assert.match(source,/SUBMISSION CANDIDATE/);
  assert.match(source,/data-session-reveal-artifact/);
  assert.match(source,/data-session-copy-submission/);
  assert.doesNotMatch(source,/data-session-copy-submission="\$\{/);
  assert.match(source,/submissionAutopilot\?\.result\?\.payload/);
});

test('Batch89 reveal action is exposed through preload and containment-checked in Electron main',async()=>{
  const preload=await read('preload.js');
  const main=await read('electron_main.js');
  assert.match(preload,/revealArtifact: \(rootPath, relativePath\) => ipcRenderer\.invoke\('artifact:reveal-path'/);
  assert.match(main,/ipcMain\.handle\('artifact:reveal-path'/);
  assert.match(main,/path\.isAbsolute\(rel\)/);
  assert.match(main,/target\.startsWith\(prefix\)/);
  assert.match(main,/shell\.showItemInFolder\(target\)/);
});
