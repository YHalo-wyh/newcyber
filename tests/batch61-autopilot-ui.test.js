'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

test('toolbox mounts batch60 pipeline script and stylesheet',()=>{
  const html=fs.readFileSync(path.join(__dirname,'..','renderer','toolbox.html'),'utf8');assert.match(html,/styles\/challenge_session_batch60\.css/);assert.match(html,/challenge_session_batch60\.js/);
});

test('batch60 renderer compiles as standalone browser script',()=>{
  const code=fs.readFileSync(path.join(__dirname,'..','renderer','challenge_session_batch60.js'),'utf8');new vm.Script(code,{filename:'challenge_session_batch60.js'});assert.match(code,/AI MODEL AUTOPILOT/);assert.match(code,/VERIFIER/);
});
