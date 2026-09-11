'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {buildCandidateIndex,candidateIdentity}=require('../src/core/challenge_candidate_index');

test('CSV manifest recovers flat candidate target label and id',()=>{
  const index=buildCandidateIndex([{file:'manifest.csv',text:'filename,label,id\nimages/a.png,1,42\nimages/b.png,0,43\n'}]);
  const found=candidateIdentity('images/a.png',index,[[0,1]]);assert.equal(found.label,1);assert.equal(found.id,42);assert.equal(found.source,'delimited-manifest');
});

test('JSON class_to_idx maps named parent folders to numeric hint labels',()=>{
  const index=buildCandidateIndex([{file:'labels.json',text:JSON.stringify({class_to_idx:{cat:0,dog:1}})}]);
  const found=candidateIdentity('dataset/dog/100.png',index,[[0,1]]);assert.equal(found.label,1);assert.equal(found.source,'class-map+parent-folder');
});

test('Python class mapping is recovered statically without executing source',()=>{
  const index=buildCandidateIndex([{file:'solve.py',text:"class_to_idx = {'safe': 0, 'target': 6}\n"}]);
  const found=candidateIdentity('target/7.npy',index,[[2,6]]);assert.equal(found.label,6);assert.equal(index.stats.classMappings,2);
});

test('ambiguous basenames do not silently inherit the wrong flat label',()=>{
  const index=buildCandidateIndex([{file:'manifest.json',text:JSON.stringify([{file:'x/a.png',label:1},{file:'y/a.png',label:2}])}]);
  assert.equal(candidateIdentity('z/a.png',index,[[0,1],[0,2]]),null);assert.equal(index.stats.ambiguousBasenames,1);
});

test('candidate manifest label names can flow through class_to_idx',()=>{
  const index=buildCandidateIndex([{file:'bundle.json',text:JSON.stringify({class_to_idx:{normal:0,attack:1},samples:[{path:'flat/101.jpg',class:'attack',id:101}]})}]);
  const found=candidateIdentity('flat/101.jpg',index,[[0,1]]);assert.equal(found.label,1);assert.equal(found.id,101);
});
