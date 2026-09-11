'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const path=require('path');
const {
  resolveSubmissionArtifact,
  safeSuggestedName
}=require('../src/core/challenge_submission_export');

async function read(rel){return fs.readFile(path.join(__dirname,'..',rel),'utf8');}

test('Batch90 export resolver only accepts NewCyber submission files below the output directory',()=>{
  const root=path.resolve('/tmp/newcyber-challenge-sessions/demo');
  const ok=resolveSubmissionArtifact(root,'__newcyber_output__/newcyber_submission_verified.csv');
  assert.equal(ok,path.resolve(root,'__newcyber_output__/newcyber_submission_verified.csv'));
  assert.equal(resolveSubmissionArtifact(root,'checker.py'),null);
  assert.equal(resolveSubmissionArtifact(root,'__newcyber_output__/notes.txt'),null);
  assert.equal(resolveSubmissionArtifact(root,'__newcyber_output__/../newcyber_submission_verified.csv'),null);
  assert.equal(resolveSubmissionArtifact(root,'../__newcyber_output__/newcyber_submission_verified.csv'),null);
  assert.equal(resolveSubmissionArtifact(root,'/tmp/newcyber_submission_verified.csv'),null);
});

test('Batch90 suggested export filenames are basename-only and keep the NewCyber submission prefix',()=>{
  assert.equal(safeSuggestedName('../../answer.csv'),'newcyber_submission_answer.csv');
  assert.equal(safeSuggestedName('newcyber_submission_verified.json'),'newcyber_submission_verified.json');
  assert.doesNotMatch(safeSuggestedName('bad:name?.csv'),/[?:]/);
});

test('Batch90 Electron Save As is restricted to isolated Challenge Session roots and bounded artifacts',async()=>{
  const main=await read('electron_main.js');
  assert.match(main,/function isolatedChallengeRoot/);
  assert.match(main,/newcyber-challenge-sessions/);
  assert.match(main,/resolveSubmissionArtifact\(root,relativePath\)/);
  assert.match(main,/ipcMain\.handle\('artifact:export-submission'/);
  assert.match(main,/showSaveDialog/);
  assert.match(main,/stat\.size>16\*1024\*1024/);
  assert.match(main,/fs\.copyFile\(source,result\.filePath\)/);
});

test('Batch90 preload and artifact result UI expose Save As without embedding submission bytes in the button',async()=>{
  const preload=await read('preload.js');
  const ui=await read('renderer/challenge_session_batch89.js');
  assert.match(preload,/exportSubmissionArtifact: \(rootPath, relativePath, suggestedName\) => ipcRenderer\.invoke\('artifact:export-submission'/);
  assert.doesNotThrow(()=>new Function(ui));
  assert.match(ui,/data-session-save-artifact/);
  assert.match(ui,/exportSubmissionArtifact/);
  assert.match(ui,/保存提交文件/);
  assert.doesNotMatch(ui,/data-session-save-artifact="\$\{[^}]*payload/);
});
