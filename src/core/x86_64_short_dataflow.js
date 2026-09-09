'use strict';

const MAX_SCAN_BYTES = 12 * 1024 * 1024;
const MAX_OPERATIONS = 6000;
const MAX_RELATIONS = 12000;
const MAX_RECOVERABLE = 512;

const ROOT_REGS = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'];

function toBigInt(value) {
  try { return typeof value === 'bigint' ? value : BigInt(value || 0); } catch { return null; }
}
function safeNumber(value) {
  const big = toBigInt(value);
  if (big == null || big < 0n || big > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(big);
}
function hx(value) { return `0x${BigInt(value).toString(16)}`; }
function rootReg(code) { return ROOT_REGS[code] || null; }
function clone(value) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(clone);
  const out = {};
  for (const [key,item] of Object.entries(value)) out[key] = clone(item);
  return out;
}
function sectionAddress(section) { return toBigInt(section?.addr ?? section?.address); }
function sectionOffset(section) { return toBigInt(section?.fileOffset); }
function sectionSize(section) { return toBigInt(section?.size); }
function objectRange(object) {
  const start = toBigInt(object?.address);
  const size = Math.max(1, Number(object?.size) || 1);
  return start == null ? null : { start, end:start + BigInt(size) };
}
function objectAt(objects, ea) {
  return (objects || []).find((object) => {
    const range = objectRange(object);
    return range && ea >= range.start && ea < range.end;
  }) || null;
}
function objectOffset(object, ea) {
  try { return Number(ea - BigInt(object.address)); } catch { return 0; }
}
function signed8(buffer, offset) { return offset < buffer.length ? buffer.readInt8(offset) : null; }
function signed32(buffer, offset, little = true) {
  if (offset < 0 || offset + 4 > buffer.length) return null;
  return little ? buffer.readInt32LE(offset) : buffer.readInt32BE(offset);
}
function unsignedImm(buffer, offset, size, little = true) {
  if (offset < 0 || offset + size > buffer.length) return null;
  if (size === 1) return BigInt(buffer[offset]);
  if (size === 2) return BigInt(little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset));
  if (size === 4) return BigInt(little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset));
  if (size === 8) return little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
  return null;
}

function parseModRM(buffer, start, rex = 0, little = true) {
  if (start >= buffer.length) return null;
  let p = start;
  const modrm = buffer[p++];
  const mod = modrm >> 6;
  const regLow = (modrm >> 3) & 7;
  const rmLow = modrm & 7;
  const regCode = regLow + ((rex & 0x04) ? 8 : 0);
  const rmCode = rmLow + ((rex & 0x01) ? 8 : 0);
  if (mod === 3) return { length:p-start, mod, regCode, rmCode, reg:rootReg(regCode), rm:rootReg(rmCode), memory:null, modrm };

  const memory = { base:null, index:null, scale:1, displacement:0, rip:false };
  if (rmLow === 4) {
    if (p >= buffer.length) return null;
    const sib = buffer[p++];
    const scaleBits = sib >> 6;
    const indexLow = (sib >> 3) & 7;
    const baseLow = sib & 7;
    const indexCode = indexLow + ((rex & 0x02) ? 8 : 0);
    const baseCode = baseLow + ((rex & 0x01) ? 8 : 0);
    memory.scale = 1 << scaleBits;
    if (!(indexLow === 4 && !(rex & 0x02))) memory.index = rootReg(indexCode);
    if (!(mod === 0 && baseLow === 5 && !(rex & 0x01))) memory.base = rootReg(baseCode);
    if (mod === 0 && baseLow === 5 && !(rex & 0x01)) {
      const disp = signed32(buffer,p,little); if (disp == null) return null; memory.displacement = disp; p += 4;
    }
  } else if (mod === 0 && rmLow === 5) {
    const disp = signed32(buffer,p,little); if (disp == null) return null; memory.displacement = disp; memory.rip = true; p += 4;
  } else {
    memory.base = rootReg(rmCode);
  }

  if (mod === 1) { const disp = signed8(buffer,p); if (disp == null) return null; memory.displacement += disp; p += 1; }
  else if (mod === 2) { const disp = signed32(buffer,p,little); if (disp == null) return null; memory.displacement += disp; p += 4; }
  return { length:p-start, mod, regCode, rmCode, reg:rootReg(regCode), rm:rootReg(rmCode), memory, modrm };
}

function decodeInstruction(buffer, offset, little = true) {
  if (offset >= buffer.length) return null;
  let p = offset;
  let rex = 0;
  let operand16 = false;
  if (buffer[p] === 0x66) { operand16 = true; p += 1; }
  if (p < buffer.length && buffer[p] >= 0x40 && buffer[p] <= 0x4f) { rex = buffer[p]; p += 1; }
  if (p >= buffer.length) return null;
  const opcode = buffer[p++];
  const finish = (kind, extra = {}) => {
    const end = extra.end ?? p;
    const { end:_end, length:_innerLength, ...rest } = extra;
    return { kind, opcode, rex, operand16, ...rest, length:end-offset };
  };
  const withModRM = (kind, extra = {}) => {
    const parsed = parseModRM(buffer,p,rex,little); if (!parsed) return null;
    p += parsed.length;
    return finish(kind,{...extra, ...parsed, end:p});
  };

  if (opcode === 0x90) return finish('NOP');
  if (opcode >= 0x50 && opcode <= 0x57) return finish('PUSH',{ reg:rootReg((opcode-0x50)+((rex&1)?8:0)) });
  if (opcode >= 0x58 && opcode <= 0x5f) return finish('POP',{ reg:rootReg((opcode-0x58)+((rex&1)?8:0)) });
  if (opcode >= 0xb8 && opcode <= 0xbf) {
    const reg = rootReg((opcode-0xb8)+((rex&1)?8:0));
    const immSize = (rex & 0x08) ? 8 : operand16 ? 2 : 4;
    const immediate = unsignedImm(buffer,p,immSize,little); if (immediate == null) return null; p += immSize;
    return finish('MOV_IMM',{ reg, immediate, end:p });
  }
  if (opcode === 0x8d) return withModRM('LEA');
  if (opcode === 0x8b) return withModRM('MOV_R_RM',{ direction:'reg-from-rm' });
  if (opcode === 0x89) return withModRM('MOV_RM_R',{ direction:'rm-from-reg' });
  if (opcode === 0x31) return withModRM('XOR',{ direction:'rm-from-reg' });
  if (opcode === 0x33) return withModRM('XOR',{ direction:'reg-from-rm' });
  if (opcode === 0x01) return withModRM('ADD',{ direction:'rm-from-reg' });
  if (opcode === 0x03) return withModRM('ADD',{ direction:'reg-from-rm' });
  if (opcode === 0x29) return withModRM('SUB',{ direction:'rm-from-reg' });
  if (opcode === 0x2b) return withModRM('SUB',{ direction:'reg-from-rm' });
  if (opcode === 0x21) return withModRM('AND',{ direction:'rm-from-reg' });
  if (opcode === 0x23) return withModRM('AND',{ direction:'reg-from-rm' });
  if (opcode === 0x09) return withModRM('OR',{ direction:'rm-from-reg' });
  if (opcode === 0x0b) return withModRM('OR',{ direction:'reg-from-rm' });
  if (opcode === 0x38 || opcode === 0x39) return withModRM('CMP',{ direction:'rm-vs-reg' });
  if (opcode === 0x3a || opcode === 0x3b) return withModRM('CMP',{ direction:'reg-vs-rm' });
  if (opcode === 0x0f) {
    if (p >= buffer.length) return null;
    const op2 = buffer[p++];
    if (op2 === 0xb6 || op2 === 0xb7) {
      const parsed = parseModRM(buffer,p,rex,little); if (!parsed) return null; p += parsed.length;
      return finish('MOVZX',{...parsed, width:op2===0xb6?8:16, end:p});
    }
    if (op2 === 0x84 || op2 === 0x85) {
      const rel = signed32(buffer,p,little); if (rel == null) return null; p += 4;
      return finish('JCC',{ condition:op2===0x84?'E':'NE', relative:rel, end:p });
    }
    return null;
  }
  if (opcode === 0x74 || opcode === 0x75) {
    const rel = signed8(buffer,p); if (rel == null) return null; p += 1;
    return finish('JCC',{ condition:opcode===0x74?'E':'NE', relative:rel, end:p });
  }
  if (opcode === 0xe8) { const rel=signed32(buffer,p,little); if(rel==null)return null; p+=4; return finish('CALL',{relative:rel,end:p}); }
  if (opcode === 0xe9) { const rel=signed32(buffer,p,little); if(rel==null)return null; p+=4; return finish('JMP',{relative:rel,end:p}); }
  if (opcode === 0xeb) { const rel=signed8(buffer,p); if(rel==null)return null; p+=1; return finish('JMP',{relative:rel,end:p}); }
  if (opcode === 0xc3) return finish('RET');
  if (opcode === 0xc2) { if(p+2>buffer.length)return null; p+=2; return finish('RET',{end:p}); }
  if (opcode === 0x80 || opcode === 0x81 || opcode === 0x83) {
    const parsed = parseModRM(buffer,p,rex,little); if (!parsed) return null; p += parsed.length;
    const ext = (parsed.modrm >> 3) & 7;
    const op = ({0:'ADD',1:'OR',4:'AND',5:'SUB',6:'XOR',7:'CMP'})[ext]; if (!op) return null;
    const immSize = opcode === 0x81 ? (operand16 ? 2 : 4) : 1;
    let immediate;
    if (immSize === 1) { const v=signed8(buffer,p); if(v==null)return null; immediate=BigInt(v); }
    else { const raw=unsignedImm(buffer,p,immSize,little); if(raw==null)return null; immediate=raw; }
    p += immSize;
    return finish(op,{...parsed, direction:'rm-imm', immediate, end:p});
  }
  if (opcode === 0xff) {
    const parsed = parseModRM(buffer,p,rex,little); if (!parsed) return null; p += parsed.length;
    const ext = (parsed.modrm >> 3) & 7;
    if (parsed.mod === 3 && (ext === 0 || ext === 1)) return finish(ext===0?'INC':'DEC',{...parsed,end:p});
    return null;
  }
  return null;
}

function expressionText(expr, objectsById) {
  if (!expr) return '?';
  if (expr.kind === 'const') return String(expr.value);
  if (expr.kind === 'reg') return expr.name;
  const object = expr.object ? objectsById.get(expr.object) : null;
  const name = object?.name || expr.name || expr.object;
  if (expr.kind === 'address') return `&${name}${expr.offset ? `${expr.offset>=0?'+':''}${expr.offset}` : ''}`;
  if (expr.kind === 'object') return `${name}${expr.offset ? `${expr.offset>=0?'+':''}${expr.offset}` : ''}`;
  if (expr.kind === 'index') {
    const scale = expr.scale && expr.scale !== 1 ? `*${expr.scale}` : '';
    const displacement = expr.offset ? `${expr.offset>=0?'+':''}${expr.offset}` : '';
    return `${name}[${expr.index || '?'}${scale}${displacement}]`;
  }
  if (expr.kind === 'op') {
    const symbol = { XOR:'^',ADD:'+',SUB:'-',AND:'&',OR:'|',CMP_EQ:'==',CMP_NE:'!=' }[expr.op] || expr.op;
    if ((expr.args || []).length === 2) return `(${expressionText(expr.args[0],objectsById)} ${symbol} ${expressionText(expr.args[1],objectsById)})`;
  }
  return '?';
}
function collectObjectRefs(expr, out = []) {
  if (!expr || typeof expr !== 'object') return out;
  if (expr.object) out.push(expr.object);
  if (expr.kind === 'op') for (const arg of expr.args || []) collectObjectRefs(arg,out);
  return [...new Set(out)];
}
function parseObjectBytes(object) {
  const text = String(object?.bytesHex || '').trim();
  if (!text) return null;
  const values = text.split(/\s+/).filter(Boolean).map((item)=>Number.parseInt(item,16));
  return values.every((value)=>Number.isInteger(value)&&value>=0&&value<=255) ? values : null;
}
function xorBytes(left,right) {
  if (!left || !right || left.length !== right.length || left.length > 4096) return null;
  return left.map((value,index)=>value ^ right[index]);
}
function bytesHex(values) { return (values || []).map((value)=>value.toString(16).padStart(2,'0')).join(' '); }
function ascii(values) { return (values || []).map((value)=>value>=0x20&&value<=0x7e?String.fromCharCode(value):'.').join(''); }

function scanX86_64ShortDataflow(buffer, sections, objects, options = {}) {
  const little = options.littleEndian !== false;
  const objectsById = new Map((objects || []).map((object)=>[object.id,object]));
  const regs = new Map();
  const operations = [];
  const relations = [];
  const recoverableRelations = [];
  const relationSeen = new Set();
  let pendingCompare = null;
  let scannedBytes = 0;
  let resets = 0;

  const resetState = () => { regs.clear(); pendingCompare=null; resets += 1; };
  const relation = (item) => {
    if (relations.length >= MAX_RELATIONS) return;
    const key = `${item.source}|${item.target}|${item.type}|${item.location || ''}`;
    if (relationSeen.has(key)) return;
    relationSeen.add(key); relations.push({ confidence:0.94, evidence:[], standalone:true, ...item });
  };
  const opNode = (op,args,ea,pseudoExtra={}) => {
    if (operations.length >= MAX_OPERATIONS) return {kind:'op',op,args:args.map(clone),location:hx(ea),id:null};
    const expr = { kind:'op', id:`short_op_${operations.length+1}`, op, args:args.map(clone), location:hx(ea), standalone:true, ...pseudoExtra };
    expr.pseudo = expressionText(expr,objectsById);
    operations.push({ id:expr.id, op, location:expr.location, line:null, pseudo:expr.pseudo, standalone:true, scope:'short-dataflow' });
    return expr;
  };
  const readRelation = (expr,ea,operationId=null) => {
    if (!expr?.object) return;
    relation({ source:`addr_${ea.toString(16)}`, sourceLabel:hx(ea), target:expr.object, type:'READS', location:hx(ea), confidence:0.95, evidence:[`standalone short-flow read ${expressionText(expr,objectsById)}`] });
    if (expr.kind === 'index' && operationId) relation({ source:expr.object, target:operationId, type:'INDEXES', location:hx(ea), confidence:0.94, evidence:[expressionText(expr,objectsById)] });
  };
  const resolveMemory = (memory,ea,length) => {
    if (!memory) return null;
    if (memory.rip) {
      const target = ea + BigInt(length) + BigInt(memory.displacement || 0);
      const object = objectAt(objects,target); if (!object) return null;
      return { kind:'object', object:object.id, name:object.name, offset:objectOffset(object,target) };
    }
    if (!memory.base) return null;
    const base = regs.get(memory.base);
    if (!base || base.kind !== 'address' || !base.object) return null;
    const object = objectsById.get(base.object); if (!object) return null;
    const offset = Number(base.offset || 0) + Number(memory.displacement || 0);
    if (memory.index) return { kind:'index', object:object.id, name:object.name, index:memory.index, scale:memory.scale || 1, offset };
    return { kind:'object', object:object.id, name:object.name, offset };
  };
  const resolveRM = (insn,ea) => insn.mod === 3 ? clone(regs.get(insn.rm) || {kind:'reg',name:insn.rm}) : resolveMemory(insn.memory,ea,insn.length);
  const resolveReg = (name) => clone(regs.get(name) || {kind:'reg',name});
  const bind = (name,expr) => { if (name) { if (expr) regs.set(name,clone(expr)); else regs.delete(name); } };
  const emitBinaryRelations = (expr,ea) => {
    const refs = collectObjectRefs(expr);
    for (const ref of refs) relation({ source:ref, target:expr.id || `addr_${ea.toString(16)}`, type:'INPUT_TO', operation:expr.op, location:hx(ea), confidence:0.95, evidence:[expr.pseudo || expressionText(expr,objectsById)] });
    if (expr.op === 'XOR' && refs.length === 2) relation({ source:refs[0], target:refs[1], type:'XORS_WITH', operationNode:expr.id, location:hx(ea), confidence:0.97, evidence:[expr.pseudo] });
  };
  const makeRecoverable = (compare) => {
    if (recoverableRelations.length >= MAX_RECOVERABLE) return;
    const sides = [compare.args[0],compare.args[1]];
    for (let index=0; index<2; index+=1) {
      const known = sides[index]; const transform = sides[1-index];
      if (!known?.object || transform?.kind !== 'op' || transform.op !== 'XOR' || transform.args?.length !== 2) continue;
      if (!transform.args.every((arg)=>arg?.object)) continue;
      const knownObject=objectsById.get(known.object), leftObject=objectsById.get(transform.args[0].object), rightObject=objectsById.get(transform.args[1].object);
      if (!knownObject || !leftObject || !rightObject) continue;
      const objectIds=[knownObject.id,leftObject.id,rightObject.id];
      if (new Set(objectIds).size < 3) continue;
      const idx = known.index || transform.args[0].index || transform.args[1].index || 'i';
      const item = {
        id:`standalone_recover_${recoverableRelations.length+1}`, operation:'XOR', location:compare.location, objects:objectIds,
        equation:`${knownObject.name}[${idx}] = ${leftObject.name}[${idx}] XOR ${rightObject.name}[${idx}]`,
        derivations:[
          `${knownObject.name} = ${leftObject.name} XOR ${rightObject.name}`,
          `${leftObject.name} = ${knownObject.name} XOR ${rightObject.name}`,
          `${rightObject.name} = ${knownObject.name} XOR ${leftObject.name}`
        ], verification:null, standalone:true
      };
      const kb=parseObjectBytes(knownObject), lb=parseObjectBytes(leftObject), rb=parseObjectBytes(rightObject);
      if (kb && lb && rb && kb.length===lb.length && lb.length===rb.length) {
        const derived=xorBytes(lb,rb); let mismatches=0;
        for(let i=0;i<kb.length;i+=1) if(derived[i]!==kb[i]) mismatches+=1;
        item.verification={ checkedBytes:kb.length, mismatches, holdsForKnownBytes:mismatches===0, derivedOperand:knownObject.id, derivedOperandName:knownObject.name, derivedHex:bytesHex(derived), derivedAscii:ascii(derived) };
      } else {
        const pairs=[[kb,lb,rightObject,`${rightObject.name} = ${knownObject.name} XOR ${leftObject.name}`],[kb,rb,leftObject,`${leftObject.name} = ${knownObject.name} XOR ${rightObject.name}`],[lb,rb,knownObject,`${knownObject.name} = ${leftObject.name} XOR ${rightObject.name}`]];
        const pair=pairs.find(([a,b])=>a&&b&&a.length===b.length&&a.length<=4096);
        if(pair){const derived=xorBytes(pair[0],pair[1]);item.verification={checkedBytes:derived.length,mismatches:null,holdsForKnownBytes:null,derivedOperand:pair[2].id,derivedOperandName:pair[2].name,derivation:pair[3],derivedHex:bytesHex(derived),derivedAscii:ascii(derived)};}
      }
      recoverableRelations.push(item);
      break;
    }
  };

  for (const section of sections || []) {
    const address=sectionAddress(section), fileOffset=sectionOffset(section), sizeBig=sectionSize(section);
    if (!section.executable || section.truncated || address==null || fileOffset==null || sizeBig==null || sizeBig<=0n) continue;
    const base=safeNumber(fileOffset), total=safeNumber(sizeBig); if(base==null||total==null||base<0||base>=buffer.length)continue;
    const take=Math.min(total,buffer.length-base,MAX_SCAN_BYTES-scannedBytes); if(take<=0)break;
    const code=buffer.subarray(base,base+take); scannedBytes+=take; resetState();
    for(let offset=0;offset<code.length;){
      const insn=decodeInstruction(code,offset,little);
      const ea=address+BigInt(offset);
      if(!insn){ resetState(); offset+=1; continue; }
      const next=()=>{offset+=Math.max(1,insn.length);};

      if(insn.kind==='NOP'||insn.kind==='PUSH'||insn.kind==='INC'||insn.kind==='DEC'){ next(); continue; }
      if(insn.kind==='POP'){ bind(insn.reg,null); next(); continue; }
      if(insn.kind==='MOV_IMM'){ bind(insn.reg,{kind:'const',value:insn.immediate.toString()}); pendingCompare=null; next(); continue; }
      if(insn.kind==='LEA'){
        if(insn.mod===3){ bind(insn.reg,null); resetState(); next(); continue; }
        let expr=null;
        if(insn.memory?.rip){const target=ea+BigInt(insn.length)+BigInt(insn.memory.displacement||0);const object=objectAt(objects,target);if(object)expr={kind:'address',object:object.id,name:object.name,offset:objectOffset(object,target)};}
        else { const mem=resolveMemory(insn.memory,ea,insn.length); if(mem?.object) expr={kind:'address',object:mem.object,name:mem.name,offset:mem.offset||0}; }
        bind(insn.reg,expr); pendingCompare=null; next(); continue;
      }
      if(insn.kind==='MOV_R_RM'||insn.kind==='MOVZX'){
        const expr=resolveRM(insn,ea); bind(insn.reg,expr); pendingCompare=null;
        if(insn.mod!==3&&expr?.object){const load=opNode(insn.kind==='MOVZX'?'MOVZX':'MOV',[expr],ea);readRelation(expr,ea,load.id);}
        next(); continue;
      }
      if(insn.kind==='MOV_RM_R'){
        if(insn.mod===3) bind(insn.rm,resolveReg(insn.reg));
        else { resetState(); }
        pendingCompare=null; next(); continue;
      }
      if(['XOR','ADD','SUB','AND','OR'].includes(insn.kind)){
        if(insn.direction==='rm-imm'){
          if(insn.mod!==3){ resetState(); next(); continue; }
          const left=resolveReg(insn.rm), right={kind:'const',value:insn.immediate.toString()}; const expr=opNode(insn.kind,[left,right],ea); emitBinaryRelations(expr,ea); bind(insn.rm,expr);
        } else {
          const rm=resolveRM(insn,ea), reg=resolveReg(insn.reg);
          const dest=insn.direction==='reg-from-rm'?insn.reg:insn.rm;
          if(insn.direction==='rm-from-reg'&&insn.mod!==3){ resetState(); next(); continue; }
          const left=insn.direction==='reg-from-rm'?reg:rm; const right=insn.direction==='reg-from-rm'?rm:reg;
          if(!left||!right){bind(dest,null);pendingCompare=null;next();continue;}
          if(insn.mod!==3) readRelation(rm,ea);
          const expr=opNode(insn.kind,[left,right],ea); emitBinaryRelations(expr,ea); bind(dest,expr);
        }
        pendingCompare=null; next(); continue;
      }
      if(insn.kind==='CMP'){
        let lhs,rhs;
        if(insn.direction==='rm-imm'){lhs=resolveRM(insn,ea);rhs={kind:'const',value:insn.immediate.toString()};}
        else {const rm=resolveRM(insn,ea),reg=resolveReg(insn.reg);lhs=insn.direction==='reg-vs-rm'?reg:rm;rhs=insn.direction==='reg-vs-rm'?rm:reg;if(insn.mod!==3)readRelation(rm,ea);}
        pendingCompare=lhs&&rhs?{lhs:clone(lhs),rhs:clone(rhs),location:hx(ea)}:null; next(); continue;
      }
      if(insn.kind==='JCC'){
        if(pendingCompare){
          const compare=opNode(insn.condition==='E'?'CMP_EQ':'CMP_NE',[pendingCompare.lhs,pendingCompare.rhs],toBigInt(pendingCompare.location));
          const leftRefs=collectObjectRefs(compare.args[0]), rightRefs=collectObjectRefs(compare.args[1]);
          for(const ref of [...new Set([...leftRefs,...rightRefs])]) relation({source:ref,target:compare.id,type:'INPUT_TO',operation:compare.op,location:compare.location,confidence:0.96,evidence:[compare.pseudo]});
          if(leftRefs.length&&rightRefs.length) relation({source:leftRefs[0],target:rightRefs[0],type:'COMPARES_WITH',operationNode:compare.id,location:compare.location,confidence:0.96,evidence:[compare.pseudo]});
          makeRecoverable(compare);
        }
        resetState(); next(); continue;
      }
      if(['CALL','JMP','RET'].includes(insn.kind)){ resetState(); next(); continue; }
      resetState(); next();
    }
    if(scannedBytes>=MAX_SCAN_BYTES)break;
  }

  return {
    relations, operations, recoverableRelations,
    scannedBytes,
    stats:{ operations:operations.length, relations:relations.length, recoverable:recoverableRelations.length, resets, truncated:scannedBytes>=MAX_SCAN_BYTES||operations.length>=MAX_OPERATIONS||relations.length>=MAX_RELATIONS }
  };
}

module.exports = { decodeInstruction, parseModRM, scanX86_64ShortDataflow, expressionText, MAX_SCAN_BYTES };
