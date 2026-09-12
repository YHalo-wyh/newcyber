'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {runTool}=require('../src/core/tool_router');
const {FIXTURES}=require('../src/core/ai_training_starpwn_ctf_2026_starry_hacks_dependency_confusion_unpinned_version');

function getPath(value,path){return String(path||'').split('.').filter(Boolean).reduce((cur,key)=>cur==null?undefined:cur[key],value);}
function check(result,a){const actual=getPath(result,a.path);switch(a.op||'eq'){case'eq':return JSON.stringify(actual)===JSON.stringify(a.value);case'neq':return JSON.stringify(actual)!==JSON.stringify(a.value);case'truthy':return Boolean(actual);case'falsy':return !actual;case'exists':return actual!==undefined&&actual!==null;case'not-exists':return actual===undefined||actual===null;case'gt':return Number(actual)>Number(a.value);case'gte':return Number(actual)>=Number(a.value);case'lt':return Number(actual)<Number(a.value);case'lte':return Number(actual)<=Number(a.value);case'includes':return Array.isArray(actual)?actual.some((x)=>JSON.stringify(x)===JSON.stringify(a.value)):String(actual??'').includes(String(a.value??''));case'not-includes':return Array.isArray(actual)?!actual.some((x)=>JSON.stringify(x)===JSON.stringify(a.value)):!String(actual??'').includes(String(a.value??''));case'length-eq':return (actual?.length??-1)===Number(a.value);default:return false;}}

test('STARPWN CTF 2026 / Starry hacks / dependency-confusion-unpinned-version synthetic regression',()=>{
  assert.deepEqual(FIXTURES.map((row)=>row.role).sort(),['control','negative','positive']);
  for(const fixture of FIXTURES){
    assert.equal(fixture.synthetic,true);
    const result=runTool('ai-supply-chain',{input:fixture.payload});
    for(const a of fixture.expected.assertions||[])assert.ok(check(result,a),fixture.role+' assertion failed: '+JSON.stringify(a)+' result='+JSON.stringify(result));
  }
});
