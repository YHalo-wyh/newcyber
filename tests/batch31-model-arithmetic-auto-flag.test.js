const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { analyzeModelArithmeticBundle } = require('../src/core/ai_model_arithmetic');
const { solveBoundedModular } = require('../src/core/bounded_modular');
const { recoverFlagFromSecret } = require('../src/core/secret_flag_recovery');
const { runTool } = require('../src/core/tool_router');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

function makeNpyInt64(shape, values) {
  const count = shape.reduce((product, value) => product * value, 1);
  assert.equal(values.length, count);
  const tuple = shape.length === 1 ? `${shape[0]},` : shape.join(', ');
  let header = `{'descr': '<i8', 'fortran_order': False, 'shape': (${tuple}), }`;
  const base = 10;
  const paddedLength = Math.ceil((base + header.length + 1) / 16) * 16 - base;
  header = `${header}${' '.repeat(paddedLength - header.length - 1)}\n`;
  const buffer = Buffer.alloc(base + Buffer.byteLength(header) + count * 8);
  buffer.set([0x93,0x4e,0x55,0x4d,0x50,0x59,1,0], 0);
  buffer.writeUInt16LE(Buffer.byteLength(header), 8);
  buffer.write(header, base, 'latin1');
  const start = base + Buffer.byteLength(header);
  values.forEach((value, index) => buffer.writeBigInt64LE(BigInt(value), start + index * 8));
  return buffer;
}

function file(name, bufferOrText) {
  if (Buffer.isBuffer(bufferOrText)) return { name, base64: bufferOrText.toString('base64') };
  return { name, text: String(bufferOrText) };
}

function mod(value, q) {
  const result = value % q;
  return result < 0 ? result + q : result;
}

function encryptAesEcb(plaintext, key) {
  const cipher = crypto.createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
  return Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
}

function createStoredZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const item of files) {
    const name = Buffer.from(item.name, 'utf8');
    const data = Buffer.isBuffer(item.buffer) ? item.buffer : Buffer.from(item.text || '', 'utf8');
    const local = Buffer.alloc(30 + name.length + data.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);
    data.copy(local, 30 + name.length);
    locals.push(local);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);
    centrals.push(central);
    offset += local.length;
  }
  const directory = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(directory.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, eocd]);
}

function directLinearFixture() {
  const q = 257;
  const bound = 1;
  const secret = [5,-3,9,2];
  const A = [
    [1,0,0,0], [0,1,0,0], [0,0,1,0], [0,0,0,1],
    [2,3,5,7], [11,13,17,19], [23,29,31,37], [41,43,47,53], [59,61,67,71], [73,79,83,89]
  ];
  const noise = [0,1,-1,0,1,0,-1,1,0,-1];
  const b = A.map((row, rowIndex) => mod(row.reduce((sum, value, index) => sum + value * secret[index], 0) + noise[rowIndex], q));
  const source = `import random\nimport numpy as np\nq=${q}\nnoise_bound=${bound}\ndef output(a, hidden_head):\n    e=random.randint(-noise_bound, noise_bound)\n    return int(np.dot(a, hidden_head)+e)%q\n`;
  const publicJson = JSON.stringify({ modulus:q, error_bound:bound, desc:'generic bounded modular hidden head' });
  const keyMaterial = Buffer.from(JSON.stringify(secret), 'utf8');
  const key = crypto.createHash('sha256').update(keyMaterial).digest();
  const cipher = encryptAesEcb('flag{generic_direct_linear_case}', key);
  return {
    secret, q, bound, A, b,
    files: [
      { name:'samples.npy', buffer:makeNpyInt64([A.length,A[0].length], A.flat()) },
      { name:'responses.npy', buffer:makeNpyInt64([b.length], b) },
      { name:'params.json', buffer:Buffer.from(publicJson) },
      { name:'challenge.py', buffer:Buffer.from(source) },
      { name:'payload.enc', buffer:cipher }
    ]
  };
}

function convValid(x, k) {
  const out = Array.from({length:x.length-k.length+1},()=>Array(x[0].length-k[0].length+1).fill(0));
  for(let i=0;i<out.length;i++) for(let j=0;j<out[0].length;j++) for(let a=0;a<k.length;a++) for(let b=0;b<k[0].length;b++) out[i][j]+=x[i+a][j+b]*k[a][b];
  return out;
}
function relu(x){ return x.map((row)=>row.map((value)=>Math.max(value,0))); }
function pool(x){ const out=Array.from({length:Math.floor(x.length/2)},()=>Array(Math.floor(x[0].length/2)).fill(0)); for(let i=0;i<out.length;i++)for(let j=0;j<out[0].length;j++){let s=0;for(let a=0;a<2;a++)for(let b=0;b<2;b++)s+=x[2*i+a][2*j+b];out[i][j]=Math.floor(s/4);}return out; }
function matvec(M,v,q){return M.map((row)=>mod(row.reduce((sum,value,index)=>sum+value*v[index],0),q));}

function cnnFixture() {
  const q=4099, bound=1, secret=[-4,7,2,-3,5,1,-2,6];
  const kernels={
    edge:[[1,0,-1],[2,0,-2],[1,0,-1]],
    vertical:[[1,2,1],[0,0,0],[-1,-2,-1]]
  };
  const mix=Array.from({length:8},(_,row)=>Array.from({length:8},(_,col)=>row===col?1:(row*17+col*11+3)%23));
  let state=0x13579bdf;
  const next=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state;};
  const samples=[];
  for(let sample=0;sample<14;sample++) samples.push(Array.from({length:6},()=>Array.from({length:6},()=>next()%8)));
  const features=samples.map((x)=>{
    const base=[];
    for(const k of Object.values(kernels)) for(const row of pool(relu(convValid(x,k)))) base.push(...row);
    return matvec(mix,base,q);
  });
  const noise=[-1,0,1,1,-1,0,1,0,-1,1,0,1,-1,0];
  const outputs=features.map((a,i)=>mod(a.reduce((sum,value,index)=>sum+value*secret[index],0)+noise[i],q));
  const source=`import random\nimport numpy as np\ndef conv_valid(x,k): pass\ndef relu(x): return np.maximum(x,0)\ndef avgpool2x2(x): pass\ndef feature(x):\n c1=avgpool2x2(relu(conv_valid(x,K1)))\n c2=avgpool2x2(relu(conv_valid(x,K2)))\n base=np.concatenate([c1.reshape(-1),c2.reshape(-1)])\n mixed=(MIX @ base) % q\n return mixed\ndef response(a, weights):\n e=random.randint(-noise_bound,noise_bound)\n return int(np.dot(a,weights)+e)%q\n`;
  const pub={q,noise_bound:bound,kernels,mix};
  const key=crypto.createHash('sha256').update(Buffer.from(secret.join(' '))).digest().subarray(0,16);
  const cipher=encryptAesEcb('flag{cnn_recipe_is_not_latticecnn_specific}',key);
  return {q,bound,secret,samples,outputs,source,pub,cipher};
}

test('Batch31 direct matrix hidden head solves a different q/dimension and auto-recovers flag from ZIP',()=>{
  const fixture=directLinearFixture();
  const zip=createStoredZip(fixture.files);
  const result=analyzeModelArithmeticBundle({base64:zip.toString('base64'),fileName:'unrelated-name.zip'});
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.featureSystem.method,'direct-matrix-input');
  assert.equal(result.featureSystem.dimension,4);
  assert.equal(result.publicConfig.modulus,257);
  assert.deepEqual(result.solver.candidates[0].secretSigned,fixture.secret);
  assert.equal(result.solver.candidates[0].maxAbsResidual,1);
  assert.equal(result.flag,'flag{generic_direct_linear_case}');
  assert.ok(result.flagRecovery.hits.some((hit)=>hit.serialization==='json-signed'&&hit.kdf==='sha256'&&hit.algorithm==='aes-256-ecb'));
});

test('Batch31 CNN recipe generalizes to different modulus/data and recovers secret + flag',()=>{
  const fixture=cnnFixture();
  const files=[
    file('x_train.npy',makeNpyInt64([fixture.samples.length,6,6],fixture.samples.flat(2))),
    file('blackbox_y.npy',makeNpyInt64([fixture.outputs.length],fixture.outputs)),
    file('model_public.json',JSON.stringify(fixture.pub)),
    file('model_source.py',fixture.source),
    file('encrypted_secret.bin',fixture.cipher)
  ];
  const result=analyzeModelArithmeticBundle({files});
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.featureSystem.method,'conv-relu-avgpool2x2-concat-mix');
  assert.equal(result.featureSystem.kernelCount,2);
  assert.deepEqual(result.solver.candidates[0].secretSigned,fixture.secret);
  assert.equal(result.flag,'flag{cnn_recipe_is_not_latticecnn_specific}');
  assert.ok(result.solver.enumerations<=3**8);
});

test('Batch31 refuses to reinterpret arbitrary NPY as LWE without source proof',()=>{
  const A=[[1,0],[0,1],[1,1]];
  const b=[2,3,5];
  const result=analyzeModelArithmeticBundle({files:[
    file('a.npy',makeNpyInt64([3,2],A.flat())),
    file('b.npy',makeNpyInt64([3],b)),
    file('config.json',JSON.stringify({q:257,noise_bound:1})),
    file('task.py','def feature(x): return x')
  ]});
  assert.equal(result.status,'identified-no-linear-proof');
  assert.equal(result.sourceInspection.boundedLinearHead,false);
});

test('Batch31 bounded solver exposes budget gap instead of unbounded brute force',()=>{
  const dimension=10;
  const A=Array.from({length:dimension},(_,row)=>Array.from({length:dimension},(_,col)=>row===col?1:0));
  const b=Array(dimension).fill(0);
  const result=solveBoundedModular(A,b,257,2,{maxEnumerations:1000});
  assert.equal(result.status,'search-too-large');
  assert.equal(result.limit,1000);
  assert.equal(result.candidates.length,0);
});

test('Batch31 flag pipeline does not promote random printable/padding accidents to solved flag',()=>{
  const result=recoverFlagFromSecret([1,-2,3,-4],{modulus:257,files:[{name:'cipher.bin',buffer:Buffer.alloc(32,0x41)}]});
  assert.notEqual(result.status,'flag-recovered');
  assert.equal(result.flag,null);
});

test('tool router exposes model arithmetic auto solver with the same generic direct fixture',()=>{
  const fixture=directLinearFixture();
  const result=runTool('ai-model-arithmetic-auto',{input:{files:fixture.files.map((item)=>file(item.name,item.buffer))}});
  assert.equal(result.schema,'newcyber.ai-model-arithmetic.v1');
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.flag,'flag{generic_direct_linear_case}');
});

test('Batch31 dedicated UI is file/bundle driven and does not fall back to generic textarea',()=>{
  const js=read('renderer/ai_model_arithmetic_tools.js');
  const css=read('renderer/styles/ai_model_arithmetic.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new Function(js));
  for(const token of ['MODEL ARITHMETIC','SYSTEM BUILT','SECRET','FLAG RECOVERED','BOUND','ENUMERATIONS','DROP ZIP']) assert.match(js,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.doesNotMatch(js,/<textarea/i);
  assert.match(css,/model-arith-stage/);
  assert.match(html,/ai_model_arithmetic\.css/);
  assert.match(html,/ai_model_arithmetic_tools\.js/);
});
