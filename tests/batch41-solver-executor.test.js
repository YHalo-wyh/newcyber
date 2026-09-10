const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const fsp=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const vm=require('node:vm');
const zlib=require('node:zlib');

const {buildSolverPipeline}=require('../src/core/solver_pipeline');
const {planSolverExecution,executeReadySolvers}=require('../src/core/solver_executor');
const batch41=require('../src/core/finals_analyzer_batch41');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

function minimalElf64(){
  const b=Buffer.alloc(64,0);
  b.set([0x7f,0x45,0x4c,0x46,2,1,1,0],0);
  b.writeUInt16LE(2,16);
  b.writeUInt16LE(62,18);
  b.writeUInt32LE(1,20);
  b.writeBigUInt64LE(0x401000n,24);
  b.writeBigUInt64LE(0n,32);
  b.writeBigUInt64LE(0n,40);
  b.writeUInt32LE(0,48);
  b.writeUInt16LE(64,52);
  b.writeUInt16LE(56,54);
  b.writeUInt16LE(0,56);
  b.writeUInt16LE(64,58);
  b.writeUInt16LE(0,60);
  b.writeUInt16LE(0,62);
  return b;
}

function analysisWithFile(file){
  const analysis={
    workspaceName:'challenge',workspacePath:'/tmp/challenge',files:[file],findings:[],stats:{findings:0,flags:0},
    candidates:{flags:[],urls:[],ips:[]},autopilot:{automaticChecks:[],artifacts:[],flags:[],summary:{}},autoSolve:{status:'review',gaps:[]}
  };
  analysis.solverPipeline=buildSolverPipeline(analysis);
  return analysis;
}

test('Batch41 planner consumes only supported READY nodes',()=>{
  const analysis=analysisWithFile({path:'model.onnx',name:'model.onnx',extension:'.onnx',type:'ONNX',size:12,metadata:{},findings:[],flags:[]});
  assert.equal(analysis.solverPipeline.nodes.find((x)=>x.id==='ai-model').state,'ready');
  assert.deepEqual(planSolverExecution(analysis),[]);

  analysis.solverPipeline={nodes:[
    {id:'reverse',state:'skipped'},
    {id:'traffic',state:'blocked'},
    {id:'firmware',state:'done'},
    {id:'recursive',state:'ready'}
  ]};
  analysis.files=[{path:'bundle.gz',extension:'.gz',type:'GZIP',size:8,metadata:{},findings:[],flags:[]}];
  const plans=planSolverExecution(analysis);
  assert.equal(plans.length,1);
  assert.equal(plans[0].nodeId,'recursive');
});

test('Batch41 ELF READY node is really executed and becomes evidence-backed DONE',async()=>{
  const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b41-elf-'));
  try{
    const buffer=minimalElf64();
    await fsp.writeFile(path.join(dir,'sample.elf'),buffer);
    const analysis=analysisWithFile({path:'sample.elf',name:'sample.elf',extension:'.elf',type:'ELF',size:buffer.length,metadata:{},findings:[],flags:[]});
    assert.equal(analysis.solverPipeline.nodes.find((x)=>x.id==='reverse').state,'ready');

    const execution=await executeReadySolvers(dir,analysis);
    assert.equal(execution.summary.done,1);
    assert.equal(execution.summary.blocked,0);
    assert.deepEqual(execution.attempts[0].transitions,['ready','running','done']);
    assert.equal(analysis.files[0].metadata.binaryDataGraph.schema,'newcyber.binary-data-graph.v2');
    assert.match(analysis.files[0].metadata.binaryDataGraph.source.parser,/executor-x86-v1/);

    const pipeline=batch41.attachExecutionToPipeline(buildSolverPipeline(analysis),execution);
    const reverse=pipeline.nodes.find((x)=>x.id==='reverse');
    assert.equal(reverse.state,'done');
    assert.equal(reverse.execution.done,1);
    assert.ok(reverse.evidence.some((x)=>/AUTO EXEC 1\/1/.test(x)));
  }finally{await fsp.rm(dir,{recursive:true,force:true});}
});

test('Batch41 recursive READY node can recover a flag candidate without promoting it to verified',async()=>{
  const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b41-rec-'));
  try{
    const buffer=zlib.gzipSync(Buffer.from('flag{executor_recursive}','utf8'));
    await fsp.writeFile(path.join(dir,'bundle.gz'),buffer);
    const analysis=analysisWithFile({path:'bundle.gz',name:'bundle.gz',extension:'.gz',type:'GZIP',size:buffer.length,metadata:{},findings:[],flags:[]});
    assert.equal(analysis.solverPipeline.nodes.find((x)=>x.id==='recursive').state,'ready');

    const execution=await executeReadySolvers(dir,analysis);
    assert.equal(execution.summary.done,1);
    assert.equal(execution.attempts[0].adapter,'recursive-artifact');
    assert.ok(analysis.files[0].metadata.recursiveExecutor);
    const hit=analysis.candidates.flags.find((x)=>x.value==='flag{executor_recursive}');
    assert.ok(hit);
    assert.equal(hit.confidence,'candidate');
    assert.notEqual(hit.confidence,'verified');
    assert.equal(buildSolverPipeline(analysis).nodes.find((x)=>x.id==='verify').state,'partial');
  }finally{await fsp.rm(dir,{recursive:true,force:true});}
});

test('Batch41 executor blocks workspace path escape instead of reading outside root',async()=>{
  const parent=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-b41-path-'));
  const dir=path.join(parent,'workspace');
  await fsp.mkdir(dir);
  try{
    const outside=path.join(parent,'outside.elf');
    await fsp.writeFile(outside,minimalElf64());
    const analysis=analysisWithFile({path:'../outside.elf',name:'outside.elf',extension:'.elf',type:'ELF',size:64,metadata:{},findings:[],flags:[]});
    const execution=await executeReadySolvers(dir,analysis);
    assert.equal(execution.summary.done,0);
    assert.equal(execution.summary.blocked,1);
    assert.match(execution.attempts[0].error,/escapes root/);
    assert.equal(analysis.files[0].metadata.binaryDataGraph,undefined);
    const pipeline=batch41.attachExecutionToPipeline(buildSolverPipeline(analysis),execution);
    assert.equal(pipeline.nodes.find((x)=>x.id==='reverse').state,'blocked');
  }finally{await fsp.rm(parent,{recursive:true,force:true});}
});

test('Batch41 report and compatibility entry preserve executor transactions through newer wrappers',()=>{
  const section=batch41.buildSolverExecutionSection({solverExecution:{enabled:true,summary:{planned:1,done:1,blocked:0,bytesRead:64},attempts:[{adapter:'elf-static',file:'a.elf',transitions:['ready','running','done']}]}});
  assert.match(section,/Solver Executor/);
  assert.match(section,/READY → RUNNING → DONE/);
  const entry=read('src/core/finals_analyzer_batch15.js');
  assert.match(entry,/finals_analyzer_batch40/);
  assert.match(entry,/finals_analyzer_batch41/);
  assert.match(entry,/require\('\.\/finals_analyzer_batch(?:41|4[2-9]|[5-9]\d)'\)/);
});

test('Batch41 executor UI stays line-based and loads after Batch40',()=>{
  const js=read('renderer/challenge_session_batch41.js');
  const css=read('renderer/styles/challenge_session_batch41.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new vm.Script(js,{filename:'challenge_session_batch41.js'}));
  for(const token of ['AUTO EXECUTOR','READY-only / offline','cs41-exec-row'])assert.match(js,new RegExp(token));
  assert.match(css,/background:transparent/);
  assert.match(css,/border-bottom/);
  assert.match(css,/not a filled dashboard card/);
  assert.match(html,/styles\/challenge_session_batch41\.css/);
  assert.match(html,/challenge_session_batch41\.js/);
  assert.ok(html.indexOf('challenge_session_batch41.js')>html.indexOf('challenge_session_batch40.js'));
  assert.ok(html.indexOf('challenge_session_batch41.css')>html.indexOf('challenge_session_batch40.css'));
});