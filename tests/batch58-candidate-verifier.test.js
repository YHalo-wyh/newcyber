'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {serializeIds,discoverVerifierSpecs,verifyCandidateSets}=require('../src/core/challenge_candidate_verifier');

function md5(value){return crypto.createHash('md5').update(value).digest('hex');}

test('serializers are deterministic and numeric-only',()=>{
  assert.equal(serializeIds([3,1,2],{serialization:'python-list',sorted:true}),'[1, 2, 3]');
  assert.equal(serializeIds([3,1,2],{serialization:'csv',sorted:true}),'1,2,3');
  assert.equal(serializeIds(['x.png'],{serialization:'csv',sorted:true}),null);
});

test('discovers Python str(sorted(ids)) verifier and verifies candidate set',()=>{
  const expected=md5('[1, 2, 3]');const source=`import hashlib\nexpected='${expected}'\nvalue=hashlib.md5(str(sorted(ids)).encode()).hexdigest()\nassert value == expected\n`;
  const specs=discoverVerifierSpecs([{file:'verify.py',text:source}]);assert.equal(specs.length,1);assert.equal(specs[0].serialization,'python-list');assert.equal(specs[0].algorithm,'md5');
  const result=verifyCandidateSets([{rank:1,ids:[3,1,2],score:2}], [{file:'verify.py',text:source}]);assert.equal(result.status,'verified');assert.equal(result.matches[0].serialized,'[1, 2, 3]');
});

test('discovers comma-join sha256 verifier',()=>{
  const expected=crypto.createHash('sha256').update('2,7,9').digest('hex');const source=`import hashlib\ns=','.join(map(str, sorted(answer)))\nassert hashlib.sha256(s.encode()).hexdigest() == '${expected}'\n`;
  const result=verifyCandidateSets([{rank:1,ids:[9,2,7]}],[{file:'checker.py',text:source}]);assert.equal(result.status,'verified');assert.equal(result.matches[0].serialized,'2,7,9');
});

test('does not invent a verifier recipe when serialization evidence is absent',()=>{
  const source=`expected='${md5('anything')}'\n# md5 mentioned, but no executable serialization relation\n`;
  const specs=discoverVerifierSpecs([{file:'notes.txt',text:source}]);assert.equal(specs.length,0);
});

test('multiple same-length digest literals remain ambiguous and are not paired',()=>{
  const a=md5('[1]'),b=md5('[2]');const source=`import hashlib\na='${a}'\nb='${b}'\nx=hashlib.md5(str(sorted(ids)).encode()).hexdigest()\n`;
  assert.equal(discoverVerifierSpecs([{file:'x.py',text:source}]).length,0);
});
