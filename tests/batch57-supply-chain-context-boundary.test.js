'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {parseRequirementLine,scanPackaging,auditAiSupplyChain}=require('../src/core/ai_supply_chain');

function ids(result){return new Set((result.findings||[]).map((x)=>x.id));}

test('Batch57 safe Python model-loading snippets are not reinterpreted as requirements',()=>{
  const samples=[
    `state=torch.load(path, weights_only=True)`,
    `model=AutoModel.from_pretrained(repo, revision='deadbeef')`,
    `x=np.load(path, allow_pickle=False)`,
    `import os\nprint(os.getcwd())`
  ];
  for(const source of samples){
    const result=auditAiSupplyChain(source);
    assert.equal(result.summary.high,0,source);
    assert.equal(result.summary.medium,0,source);
    assert.equal(result.summary.info,0,source);
    assert.equal(result.findings.length,0,source);
  }
});

test('Batch57 requirement parser accepts actual requirement grammar but rejects Python syntax',()=>{
  assert.equal(parseRequirementLine('numpy>=2.0').name,'numpy');
  assert.equal(parseRequirementLine('torch==2.8.0').exactPinned,true);
  assert.equal(parseRequirementLine('pkg[extra]>=1.2,<2').name,'pkg');
  assert.equal(parseRequirementLine('plain-package').constraint,'');

  for(const line of [
    'state=torch.load(path, weights_only=True)',
    "model=AutoModel.from_pretrained(repo, revision='deadbeef')",
    'x=np.load(path, allow_pickle=False)',
    'import os',
    'from transformers import AutoModel',
    'print(os.getcwd())'
  ]) assert.equal(parseRequirementLine(line),null,line);
});

test('Batch57 loose real requirements remain informational findings and exact pins stay clean',()=>{
  const loose=scanPackaging('internal_pkg>=1.0\nplain_pkg');
  assert.equal(loose.filter((x)=>x.id==='dependency-not-locked').length,2);

  const pinned=scanPackaging('numpy==2.1.1\ntorch==2.8.0');
  assert.equal(pinned.some((x)=>x.id==='dependency-not-locked'),false);
});

test('Batch57 mixed challenge source keeps explicit package-index and loose dependency evidence',()=>{
  const source=`
from transformers import AutoModel
model = AutoModel.from_pretrained(repo, trust_remote_code=True)
obj = torch.load(upload_path)
--extra-index-url https://mirror.example/simple
internal_pkg>=1.0
`;
  const result=auditAiSupplyChain(source);const findingIds=ids(result);
  for(const id of ['hf-trust-remote-code','hf-revision-unpinned','unsafe-model-deserialization-call','python-extra-index','dependency-not-locked'])assert.ok(findingIds.has(id),id);
});

test('Batch57 direct URL/VCS dependency evidence remains visible without generic Python false positives',()=>{
  const findings=scanPackaging('toolkit @ git+https://example.invalid/repo.git@deadbeef\nhttps://example.invalid/wheel.whl');
  assert.ok(findings.filter((x)=>x.id==='direct-dependency-reference').length>=2);
});

test('Batch57 unsafe Python deserialization policies remain unchanged after packaging isolation',()=>{
  const unsafe=[
    [`state=torch.load(path, weights_only=False)`,'torch-load-weights-only-false'],
    [`state=torch.load(path)`,'torch-load-policy-implicit'],
    [`obj=pickle.loads(blob)`,'unsafe-model-deserialization-call'],
    [`model=AutoModel.from_pretrained(repo, trust_remote_code=True)`,'hf-trust-remote-code']
  ];
  for(const [source,id] of unsafe)assert.ok(ids(auditAiSupplyChain(source)).has(id),`${id}: ${source}`);
});
