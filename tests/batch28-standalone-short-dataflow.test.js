const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { decodeInstruction, scanX86_64ShortDataflow } = require('../src/core/x86_64_short_dataflow');

const root = path.join(__dirname,'..');
const read = (file) => fs.readFileSync(path.join(root,file),'utf8');

function ripLea(modrm, ea, target) {
  const out = Buffer.alloc(7);
  out.set([0x48,0x8d,modrm],0);
  out.writeInt32LE(Number(BigInt(target) - (BigInt(ea) + 7n)),3);
  return out;
}
function buildXorChain({breakAfterLea=false}={}) {
  const base=0x1000n, a=0x2000n, b=0x2020n, checksum=0x2040n;
  const parts=[]; let ea=base;
  const push=(buf)=>{parts.push(buf);ea+=BigInt(buf.length);};
  push(ripLea(0x1d,ea,a));       // rbx = &left
  push(ripLea(0x15,ea,b));       // rdx = &right
  push(ripLea(0x05,ea,checksum));// rax = &checksum
  if(breakAfterLea) push(Buffer.from([0x6c])); // unsupported INS resets bounded state
  push(Buffer.from([0x0f,0xb6,0x0c,0x33])); // movzx ecx, byte [rbx+rsi]
  push(Buffer.from([0x0f,0xb6,0x3c,0x32])); // movzx edi, byte [rdx+rsi]
  push(Buffer.from([0x31,0xf9]));           // xor ecx, edi
  push(Buffer.from([0x3a,0x0c,0x30]));      // cmp cl, byte [rax+rsi]
  push(Buffer.from([0x75,0x00]));            // jne
  return {code:Buffer.concat(parts),base,a,b,checksum};
}
function object(id,name,address,bytes){return {id,name,address:`0x${address.toString(16)}`,size:bytes.length,section:'.rodata',bytesHex:bytes.map(v=>v.toString(16).padStart(2,'0')).join(' ')};}

const left=[0x25,0x23,0x2c,0x37,0x3a,0x22,0x11,0x08];
const right=[0x10,0x01,0x0c,0x17,0x1a,0x02,0x31,0x28];
const check=left.map((value,index)=>value^right[index]);

test('Batch28 standalone short-flow restores indexed left XOR right compared with checksum',()=>{
  const fixture=buildXorChain();
  const sections=[{name:'.text',address:`0x${fixture.base.toString(16)}`,fileOffset:'0x0',size:fixture.code.length,executable:true,truncated:false}];
  const objects=[object('obj_left','byte_54A3E0',fixture.a,left),object('obj_right','xor_table',fixture.b,right),object('obj_check','aCompatChecksum',fixture.checksum,check)];
  const result=scanX86_64ShortDataflow(fixture.code,sections,objects);
  assert.ok(result.operations.some((op)=>op.op==='XOR'&&/byte_54A3E0\[rsi\].*\^.*xor_table\[rsi\]/.test(op.pseudo)));
  assert.ok(result.operations.some((op)=>op.op==='CMP_NE'&&/aCompatChecksum\[rsi\]/.test(op.pseudo)));
  assert.ok(result.relations.some((rel)=>rel.type==='XORS_WITH'&&new Set([rel.source,rel.target]).has('obj_left')&&new Set([rel.source,rel.target]).has('obj_right')));
  assert.ok(result.relations.some((rel)=>rel.type==='COMPARES_WITH'&&[rel.source,rel.target].includes('obj_check')));
  assert.equal(result.recoverableRelations.length,1);
  const recovered=result.recoverableRelations[0];
  assert.match(recovered.equation,/aCompatChecksum\[rsi\] = byte_54A3E0\[rsi\] XOR xor_table\[rsi\]/);
  assert.equal(recovered.verification.holdsForKnownBytes,true);
  assert.equal(recovered.verification.mismatches,0);
  assert.equal(recovered.verification.checkedBytes,left.length);
});

test('Batch28 clears register provenance at unknown instruction instead of crossing it',()=>{
  const fixture=buildXorChain({breakAfterLea:true});
  const sections=[{name:'.text',address:`0x${fixture.base.toString(16)}`,fileOffset:'0x0',size:fixture.code.length,executable:true,truncated:false}];
  const objects=[object('obj_left','left',fixture.a,left),object('obj_right','right',fixture.b,right),object('obj_check','check',fixture.checksum,check)];
  const result=scanX86_64ShortDataflow(fixture.code,sections,objects);
  assert.equal(result.recoverableRelations.length,0);
  assert.ok(result.stats.resets>1);
});

test('Batch28 decoder understands SIB indexed MOVZX and rejects truncated encodings',()=>{
  const movzx=decodeInstruction(Buffer.from([0x0f,0xb6,0x0c,0x33]),0,true);
  assert.equal(movzx.kind,'MOVZX');
  assert.equal(movzx.reg,'rcx');
  assert.equal(movzx.memory.base,'rbx');
  assert.equal(movzx.memory.index,'rsi');
  assert.equal(movzx.memory.scale,1);
  assert.equal(decodeInstruction(Buffer.from([0x0f,0xb6,0x0c]),0,true),null);
});

test('Batch28 ELF bridge and renderer advertise bounded standalone IR rather than full disassembly',()=>{
  const ipc=read('src/electron/binary_elf_ipc.js');
  const core=read('src/core/x86_64_short_dataflow.js');
  assert.match(ipc,/scanX86_64ShortDataflow/);
  assert.match(ipc,/standaloneRecoverable/);
  assert.match(ipc,/unknown instruction|未知指令|控制流边界/i);
  assert.match(core,/MAX_SCAN_BYTES/);
  assert.match(core,/resetState/);
  assert.doesNotMatch(core,/capstone|objdump|radare/i);
});
