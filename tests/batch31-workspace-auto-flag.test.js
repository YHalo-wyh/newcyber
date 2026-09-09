const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');

const analyzer=require('../src/core/finals_analyzer_batch15');

function mod(value,q){const out=value%q;return out<0?out+q:out;}

function makeNpyInt64(shape,values){
  const count=shape.reduce((a,b)=>a*b,1);
  assert.equal(values.length,count);
  const tuple=shape.length===1?`${shape[0]},`:shape.join(', ');
  let header=`{'descr': '<i8', 'fortran_order': False, 'shape': (${tuple}), }`;
  const base=10;
  const padded=Math.ceil((base+header.length+1)/16)*16-base;
  header=`${header}${' '.repeat(padded-header.length-1)}\n`;
  const buffer=Buffer.alloc(base+Buffer.byteLength(header)+count*8);
  buffer.set([0x93,0x4e,0x55,0x4d,0x50,0x59,1,0],0);
  buffer.writeUInt16LE(Buffer.byteLength(header),8);
  buffer.write(header,base,'latin1');
  const start=base+Buffer.byteLength(header);
  values.forEach((value,index)=>buffer.writeBigInt64LE(BigInt(value),start+index*8));
  return buffer;
}

function aesEcb(plaintext,key){
  const cipher=crypto.createCipheriv(`aes-${key.length*8}-ecb`,key,null);
  return Buffer.concat([cipher.update(Buffer.from(plaintext,'utf8')),cipher.final()]);
}

async function writeFixture(root,{withProof=true}={}){
  const q=257,bound=1,secret=[4,-2,7];
  const A=[[1,0,0],[0,1,0],[0,0,1],[2,3,5],[7,11,13],[17,19,23]];
  const noise=[0,1,-1,1,0,-1];
  const b=A.map((row,i)=>mod(row.reduce((sum,value,j)=>sum+value*secret[j],0)+noise[i],q));
  const source=withProof
    ? `import random\nimport numpy as np\nq=${q}\nnoise_bound=${bound}\ndef score(a,hidden):\n e=random.randint(-noise_bound,noise_bound)\n return int(np.dot(a,hidden)+e)%q\n`
    : 'def score(a, hidden): return sum(a)\n';
  const key=crypto.createHash('sha256').update(Buffer.from(secret.join(','),'utf8')).digest().subarray(0,16);
  await Promise.all([
    fs.writeFile(path.join(root,'observations.npy'),makeNpyInt64([A.length,A[0].length],A.flat())),
    fs.writeFile(path.join(root,'responses.npy'),makeNpyInt64([b.length],b)),
    fs.writeFile(path.join(root,'params.json'),JSON.stringify({modulus:q,error_bound:bound})),
    fs.writeFile(path.join(root,'challenge.py'),source),
    fs.writeFile(path.join(root,'cipher.bin'),aesEcb('flag{workspace_model_arithmetic_auto}',key))
  ]);
  return {secret};
}

test('Batch31 workspace Autopilot recovers and promotes a verified model-arithmetic flag without manual tool routing',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-model-auto-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const fixture=await writeFixture(root,{withProof:true});
  const analysis=await analyzer.scanWorkspace(root);
  assert.equal(analysis.version>=31,true);
  assert.equal(analysis.modelArithmeticAuto.best.result.status,'flag-recovered');
  assert.deepEqual(analysis.modelArithmeticAuto.best.result.solver.candidates[0].secretSigned,fixture.secret);
  assert.equal(analysis.modelArithmeticAuto.best.result.flag,'flag{workspace_model_arithmetic_auto}');
  const promoted=analysis.candidates.flags.find((item)=>item.value==='flag{workspace_model_arithmetic_auto}');
  assert.ok(promoted);
  assert.equal(promoted.source,'model-arithmetic-auto');
  assert.equal(promoted.confidence,'verified');
  assert.ok(analysis.autopilot.automaticChecks.some((item)=>item.id==='model-arithmetic-auto'));
  const win=analysis.autopilot.actions.find((item)=>item.id==='model-arithmetic-flag');
  assert.ok(win);
  assert.equal(win.level,'win');
  assert.equal(analysis.autopilot.summary.modelArithmeticFlags,1);
});

test('Batch31 workspace sees a matching file bundle but refuses automatic LWE/flag promotion without bounded-linear source proof',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-model-no-proof-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await writeFixture(root,{withProof:false});
  const analysis=await analyzer.scanWorkspace(root);
  assert.equal(analysis.modelArithmeticAuto.best.result.status,'identified-no-linear-proof');
  assert.ok(!analysis.candidates.flags.some((item)=>item.source==='model-arithmetic-auto'));
  assert.ok(!analysis.autopilot.actions.some((item)=>item.id==='model-arithmetic-flag'));
});