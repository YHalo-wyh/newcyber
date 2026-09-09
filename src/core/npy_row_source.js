'use strict';

const fs=require('fs/promises');
const path=require('path');

const MAX_HEADER_BYTES=1024*1024;
const MAX_NPY_BYTES=2*1024*1024*1024;
const MAX_PICKLE_OPS=2_000_000;
const MAX_MEMO=200_000;
const MAX_STACK=200_000;
const MAX_STRING_BYTES=1024*1024;
const MAX_READ_VALUES=2_000_000;
const MAX_SEGMENTS=4096;

const MARK=Symbol('pickle-mark');
const ALLOWED_GLOBALS=new Set([
  'numpy._core.multiarray._reconstruct',
  'numpy.core.multiarray._reconstruct',
  'numpy.ndarray',
  'numpy.dtype',
  '_codecs.encode'
]);

function safeProduct(values,label='shape'){
  let out=1;
  for(const raw of values||[]){
    const value=Number(raw);
    if(!Number.isSafeInteger(value)||value<0)throw new Error(`${label} 包含非法维度`);
    out*=value;
    if(!Number.isSafeInteger(out))throw new Error(`${label} 元素数超出安全整数范围`);
  }
  return out;
}

function parseHeaderText(text){
  const descr=String(text).match(/["']descr["']\s*:\s*(["'])(.*?)\1/i)?.[2]||null;
  const fortranToken=String(text).match(/["']fortran_order["']\s*:\s*(True|False)/i)?.[1]||null;
  const shapeToken=String(text).match(/["']shape["']\s*:\s*\(([^)]*)\)/i)?.[1]??null;
  if(!descr||!fortranToken||shapeToken==null)throw new Error('NPY header 缺 descr/fortran_order/shape');
  const shape=shapeToken.split(',').map((x)=>x.trim()).filter(Boolean).map(Number);
  if(!shape.length||shape.some((x)=>!Number.isSafeInteger(x)||x<0))throw new Error('NPY shape 无法解析');
  return {descr,fortranOrder:/^true$/i.test(fortranToken),shape};
}

function numericDescriptor(descr){
  const match=String(descr||'').match(/^([<>=|])?([fiu])([1248])$/i);
  if(!match)return null;
  const kind=match[2].toLowerCase();
  const bytes=Number(match[3]);
  if(kind==='f'&&![4,8].includes(bytes))return null;
  return {endian:match[1]||'=',kind,bytes};
}

function objectDescriptor(descr){return /^([|=<>])?O(?:\d+)?$/i.test(String(descr||''));}

async function readNpyHeaderAnyPath(filePath){
  const resolved=path.resolve(String(filePath||''));
  const stat=await fs.stat(resolved);
  if(!stat.isFile())throw new Error('NPY 输入不是普通文件');
  if(stat.size<=0||stat.size>MAX_NPY_BYTES)throw new Error(`NPY 文件大小必须在 1..${MAX_NPY_BYTES} bytes`);
  const handle=await fs.open(resolved,'r');
  try{
    const lead=Buffer.alloc(12);
    const first=await handle.read(lead,0,lead.length,0);
    if(first.bytesRead<10||lead[0]!==0x93||lead.subarray(1,6).toString('ascii')!=='NUMPY')throw new Error('不是可识别的 NPY');
    const major=lead[6],minor=lead[7];
    let headerLength,headerOffset;
    if(major===1){headerLength=lead.readUInt16LE(8);headerOffset=10;}
    else if(major===2||major===3){if(first.bytesRead<12)throw new Error('NPY v2/v3 header 截断');headerLength=lead.readUInt32LE(8);headerOffset=12;}
    else throw new Error(`不支持 NPY version ${major}.${minor}`);
    if(!Number.isSafeInteger(headerLength)||headerLength<=0||headerLength>MAX_HEADER_BYTES||headerOffset+headerLength>stat.size)throw new Error('NPY header 长度异常');
    const raw=Buffer.alloc(headerLength);
    const got=await handle.read(raw,0,headerLength,headerOffset);
    if(got.bytesRead!==headerLength)throw new Error('NPY header 读取不完整');
    const parsed=parseHeaderText(raw.toString(major===3?'utf8':'latin1'));
    return {filePath:resolved,fileName:path.basename(resolved),size:stat.size,version:`${major}.${minor}`,payloadOffset:headerOffset+headerLength,...parsed,numeric:numericDescriptor(parsed.descr),object:objectDescriptor(parsed.descr)};
  }finally{await handle.close();}
}

class Reader{
  constructor(handle,size,offset=0){this.handle=handle;this.size=size;this.offset=offset;}
  ensure(n){if(!Number.isSafeInteger(n)||n<0||this.offset+n>this.size)throw new Error('pickle 数据越界');}
  async bytes(n){this.ensure(n);const b=Buffer.alloc(n);const r=await this.handle.read(b,0,n,this.offset);if(r.bytesRead!==n)throw new Error('pickle 读取截断');this.offset+=n;return b;}
  async u8(){return (await this.bytes(1))[0];}
  async u16(){return (await this.bytes(2)).readUInt16LE(0);}
  async i32(){return (await this.bytes(4)).readInt32LE(0);}
  async u32(){return (await this.bytes(4)).readUInt32LE(0);}
  async u64(){const v=(await this.bytes(8)).readBigUInt64LE(0);if(v>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('pickle 长度超出安全整数范围');return Number(v);}
  async line(max=4096){const out=[];for(let i=0;i<max;i+=1){const b=await this.u8();if(b===0x0a)return Buffer.from(out).toString('utf8');out.push(b);}throw new Error('pickle 文本行过长');}
  skip(n){this.ensure(n);this.offset+=n;}
}

function tuple(items=[]){return {kind:'tuple',items};}
function list(items=[]){return {kind:'list',items};}
function dict(entries=[]){return {kind:'dict',entries};}
function bytesRef(offset,length,inline=null){return {kind:'bytes',offset,length,inline};}
function globalRef(module,name){return {kind:'global',module,name,qualifiedName:`${module}.${name}`};}
function ndarray(){return {kind:'ndarray',shape:null,dtype:null,fortran:false,data:null,objects:null};}
function dtype(code){return {kind:'dtype',code:String(code||''),endian:null};}
function itemsOf(value){return value?.kind==='tuple'||value?.kind==='list'?value.items:null;}
function primitive(value){return value&&value.kind==='string'?value.value:value;}
function asString(value){const v=primitive(value);return typeof v==='string'?v:null;}
function asInteger(value){const v=primitive(value);return Number.isSafeInteger(v)?v:null;}

function signedBigIntLE(buffer){
  if(!buffer.length)return 0;
  let value=0n;for(let i=0;i<buffer.length;i++)value|=BigInt(buffer[i])<<(8n*BigInt(i));
  const bits=8n*BigInt(buffer.length);if(buffer[buffer.length-1]&0x80)value-=1n<<bits;
  if(value<BigInt(Number.MIN_SAFE_INTEGER)||value>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('pickle long 超出 JS 安全整数范围');
  return Number(value);
}

function buildReduced(callable,args){
  if(callable?.kind!=='global')throw new Error('pickle REDUCE callable 不是显式 global');
  if(!ALLOWED_GLOBALS.has(callable.qualifiedName))throw new Error(`pickle global ${callable.qualifiedName} 不在 NumPy object-array allowlist`);
  const av=itemsOf(args)||[];
  if(/(?:numpy\._core|numpy\.core)\.multiarray\._reconstruct$/.test(callable.qualifiedName))return ndarray();
  if(callable.qualifiedName==='numpy.dtype')return dtype(asString(av[0])||'');
  if(callable.qualifiedName==='_codecs.encode'){
    const source=asString(av[0]),encoding=String(asString(av[1])||'').toLowerCase();
    if(source==null||!['latin1','latin-1'].includes(encoding))throw new Error('仅支持 _codecs.encode(..., latin1) 的 NumPy pickle 兼容路径');
    const raw=Buffer.from(source,'latin1');return bytesRef(null,raw.length,raw);
  }
  return callable;
}

function applyBuild(instance,state){
  const sv=itemsOf(state);
  if(instance?.kind==='dtype'){
    if(sv){const endian=asString(sv[1]);if(endian)instance.endian=endian;}
    return;
  }
  if(instance?.kind!=='ndarray')throw new Error('pickle BUILD 只允许 NumPy dtype/ndarray 状态');
  if(!sv||sv.length<5)throw new Error('NumPy ndarray BUILD state 不完整');
  const version=asInteger(sv[0]);if(version==null||version<0||version>5)throw new Error('NumPy ndarray state version 异常');
  const shapeItems=itemsOf(sv[1]);if(!shapeItems)throw new Error('NumPy ndarray state 缺 shape');
  const shape=shapeItems.map(asInteger);if(shape.some((x)=>x==null||x<0))throw new Error('NumPy ndarray state shape 非法');
  if(sv[2]?.kind!=='dtype')throw new Error('NumPy ndarray state 缺 dtype');
  const fortran=primitive(sv[3]);if(typeof fortran!=='boolean')throw new Error('NumPy ndarray state fortran 标记非法');
  const payload=sv[4];
  instance.shape=shape;instance.dtype={...sv[2]};instance.fortran=fortran;
  if(payload?.kind==='bytes')instance.data=payload;
  else if(payload?.kind==='list')instance.objects=payload.items;
  else throw new Error('NumPy ndarray state payload 既不是 raw bytes 也不是 object list');
}

async function parseRestrictedNumpyPickle(handle,size,payloadOffset){
  const reader=new Reader(handle,size,payloadOffset);
  const stack=[];const memo=new Map();let nextMemo=0;let protocol=0;let ops=0;let root=null;
  const top=()=>stack[stack.length-1];
  const pop=()=>{if(!stack.length)throw new Error('pickle stack underflow');return stack.pop();};
  const push=(v)=>{stack.push(v);if(stack.length>MAX_STACK)throw new Error('pickle stack 超过预算');};
  const markIndex=()=>{for(let i=stack.length-1;i>=0;i--)if(stack[i]===MARK)return i;throw new Error('pickle MARK 缺失');};
  const memoPut=(idx)=>{if(!Number.isSafeInteger(idx)||idx<0||idx>=MAX_MEMO)throw new Error('pickle memo index 超过预算');memo.set(idx,top());nextMemo=Math.max(nextMemo,idx+1);};
  const memoGet=(idx)=>{if(!memo.has(idx))throw new Error(`pickle memo ${idx} 未定义`);return memo.get(idx);};
  while(reader.offset<size){
    if(++ops>MAX_PICKLE_OPS)throw new Error('pickle opcode 超过预算');
    const op=await reader.u8();
    if(op===0x80){protocol=await reader.u8();if(protocol>5)throw new Error(`pickle protocol ${protocol} 不支持`);continue;}
    if(op===0x95){const frame=await reader.u64();if(reader.offset+frame>size)throw new Error('pickle FRAME 越界');continue;}
    if(op===0x2e){root=pop();break;}
    if(op===0x28){push(MARK);continue;}
    if(op===0x94){memoPut(nextMemo++);continue;}
    if(op===0x71){memoPut(await reader.u8());continue;}
    if(op===0x72){memoPut(await reader.u32());continue;}
    if(op===0x68){push(memoGet(await reader.u8()));continue;}
    if(op===0x6a){push(memoGet(await reader.u32()));continue;}
    if(op===0x4e){push(null);continue;}
    if(op===0x88){push(true);continue;}
    if(op===0x89){push(false);continue;}
    if(op===0x4b){push(await reader.u8());continue;}
    if(op===0x4d){push(await reader.u16());continue;}
    if(op===0x4a){push(await reader.i32());continue;}
    if(op===0x8a){const n=await reader.u8();push(signedBigIntLE(await reader.bytes(n)));continue;}
    if(op===0x8b){const n=await reader.u32();if(n>1024)throw new Error('pickle LONG4 过长');push(signedBigIntLE(await reader.bytes(n)));continue;}
    if(op===0x8c||op===0x58||op===0x8d){const n=op===0x8c?await reader.u8():op===0x58?await reader.u32():await reader.u64();if(n>MAX_STRING_BYTES)throw new Error('pickle unicode 过长');push({kind:'string',value:(await reader.bytes(n)).toString('utf8')});continue;}
    if(op===0x43||op===0x42||op===0x8e||op===0x96){const n=op===0x43?await reader.u8():op===0x42?await reader.u32():await reader.u64();const offset=reader.offset;let inline=null;if(n<=128)inline=await reader.bytes(n);else reader.skip(n);push(bytesRef(offset,n,inline));continue;}
    if(op===0x63){const module=await reader.line(),name=await reader.line();const g=globalRef(module,name);if(!ALLOWED_GLOBALS.has(g.qualifiedName))throw new Error(`pickle global ${g.qualifiedName} 不在 allowlist`);push(g);continue;}
    if(op===0x93){const name=asString(pop()),module=asString(pop());if(module==null||name==null)throw new Error('STACK_GLOBAL 缺 module/name');const g=globalRef(module,name);if(!ALLOWED_GLOBALS.has(g.qualifiedName))throw new Error(`pickle global ${g.qualifiedName} 不在 allowlist`);push(g);continue;}
    if(op===0x29){push(tuple([]));continue;}
    if(op===0x85){push(tuple([pop()]));continue;}
    if(op===0x86){const b=pop(),a=pop();push(tuple([a,b]));continue;}
    if(op===0x87){const c=pop(),b=pop(),a=pop();push(tuple([a,b,c]));continue;}
    if(op===0x74){const m=markIndex(),items=stack.slice(m+1);stack.length=m;push(tuple(items));continue;}
    if(op===0x5d){push(list([]));continue;}
    if(op===0x61){const item=pop(),target=top();if(target?.kind!=='list')throw new Error('APPEND target 不是 list');target.items.push(item);continue;}
    if(op===0x65){const m=markIndex(),items=stack.slice(m+1),target=stack[m-1];if(target?.kind!=='list')throw new Error('APPENDS target 不是 list');target.items.push(...items);stack.length=m;continue;}
    if(op===0x7d){push(dict([]));continue;}
    if(op===0x73){const value=pop(),key=pop(),target=top();if(target?.kind!=='dict')throw new Error('SETITEM target 不是 dict');target.entries.push([key,value]);continue;}
    if(op===0x75){const m=markIndex(),items=stack.slice(m+1),target=stack[m-1];if(target?.kind!=='dict'||items.length%2)throw new Error('SETITEMS 非法');for(let i=0;i<items.length;i+=2)target.entries.push([items[i],items[i+1]]);stack.length=m;continue;}
    if(op===0x52){const args=pop(),callable=pop();push(buildReduced(callable,args));continue;}
    if(op===0x62){const state=pop(),instance=top();applyBuild(instance,state);continue;}
    throw new Error(`restricted NumPy pickle 不支持 opcode 0x${op.toString(16).padStart(2,'0')} @ ${reader.offset-1}`);
  }
  if(!root)throw new Error('pickle 未遇到 STOP');
  return {root,protocol,ops,bytesConsumed:reader.offset-payloadOffset};
}

function descriptorFromDtype(value){
  if(value?.kind!=='dtype')return null;
  let code=String(value.code||'');
  const embedded=code.match(/^([<>=|])(.+)$/);let endian=value.endian||'=';
  if(embedded){endian=embedded[1];code=embedded[2];}
  const match=code.match(/^([fiu])([1248])$/i);if(!match)return null;
  return {endian,kind:match[1].toLowerCase(),bytes:Number(match[2])};
}

function collectSegments(root){
  if(root?.kind!=='ndarray'||!root.dtype||!/^O/i.test(String(root.dtype.code||''))||!Array.isArray(root.objects))throw new Error('object NPY pickle 根对象不是可识别的 NumPy object ndarray');
  const flat=[];
  const visit=(value)=>{
    if(value?.kind==='ndarray'&&value.data){flat.push(value);return;}
    if(value?.kind==='list')for(const item of value.items)visit(item);
    else if(value?.kind==='ndarray'&&Array.isArray(value.objects))for(const item of value.objects)visit(item);
    else throw new Error('object NPY 包含非数值 ndarray 元素');
  };
  for(const item of root.objects)visit(item);
  if(!flat.length||flat.length>MAX_SEGMENTS)throw new Error(`object NPY 数值段数量必须在 1..${MAX_SEGMENTS}`);
  let logical=0;let cols=null;const segments=[];
  for(let index=0;index<flat.length;index+=1){
    const item=flat[index];if(item.fortran)throw new Error(`segment ${index} 是 Fortran-order`);
    const descriptor=descriptorFromDtype(item.dtype);if(!descriptor)throw new Error(`segment ${index} dtype 不受支持`);
    if(!Array.isArray(item.shape)||!item.shape.length)throw new Error(`segment ${index} shape 缺失`);
    const rows=Number(item.shape[0]);const width=safeProduct(item.shape.slice(1).length?item.shape.slice(1):[1],`segment ${index} shape`);
    if(!Number.isSafeInteger(rows)||rows<0||!Number.isSafeInteger(width)||width<=0)throw new Error(`segment ${index} shape 非法`);
    if(cols==null)cols=width;else if(cols!==width)throw new Error(`object NPY segments 列宽不一致：${cols} vs ${width}`);
    const expected=safeProduct(item.shape)*descriptor.bytes;
    if(item.data.length!==expected)throw new Error(`segment ${index} raw bytes=${item.data.length} 与 shape/dtype=${expected} 不一致`);
    segments.push({index,rowStart:logical,rows,cols:width,shape:item.shape.slice(),descriptor,dataOffset:item.data.offset,dataBytes:item.data.length});logical+=rows;
  }
  return {rows:logical,cols,segments};
}

function readNumber(buffer,offset,d){
  const little=d.endian!=='>';
  if(d.kind==='f')return d.bytes===4?(little?buffer.readFloatLE(offset):buffer.readFloatBE(offset)):(little?buffer.readDoubleLE(offset):buffer.readDoubleBE(offset));
  if(d.kind==='i'){
    if(d.bytes===1)return buffer.readInt8(offset);if(d.bytes===2)return little?buffer.readInt16LE(offset):buffer.readInt16BE(offset);if(d.bytes===4)return little?buffer.readInt32LE(offset):buffer.readInt32BE(offset);
    const v=little?buffer.readBigInt64LE(offset):buffer.readBigInt64BE(offset);if(v<BigInt(Number.MIN_SAFE_INTEGER)||v>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('int64 超出 JS 安全整数范围');return Number(v);
  }
  if(d.bytes===1)return buffer.readUInt8(offset);if(d.bytes===2)return little?buffer.readUInt16LE(offset):buffer.readUInt16BE(offset);if(d.bytes===4)return little?buffer.readUInt32LE(offset):buffer.readUInt32BE(offset);
  const v=little?buffer.readBigUInt64LE(offset):buffer.readBigUInt64BE(offset);if(v>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('uint64 超出 JS 安全整数范围');return Number(v);
}

async function openNpyRowSource(filePath){
  const header=await readNpyHeaderAnyPath(filePath);
  const handle=await fs.open(header.filePath,'r');
  let source;
  try{
    if(header.numeric){
      if(header.fortranOrder)throw new Error('数值 NPY row source 不支持 Fortran-order');
      if(header.shape.length!==2)throw new Error(`数值 NPY row source 需要二维 shape，当前 [${header.shape.join(',')}]`);
      const rows=header.shape[0],cols=header.shape[1],expected=rows*cols*header.numeric.bytes;
      if(header.payloadOffset+expected!==header.size)throw new Error('数值 NPY payload 长度与 shape/dtype 不一致');
      source={kind:'numeric',rows,cols,segments:[{index:0,rowStart:0,rows,cols,shape:header.shape.slice(),descriptor:header.numeric,dataOffset:header.payloadOffset,dataBytes:expected}]};
    }else if(header.object){
      const parsed=await parseRestrictedNumpyPickle(handle,header.size,header.payloadOffset);
      source={kind:'object-segments',...collectSegments(parsed.root),pickle:{protocol:parsed.protocol,ops:parsed.ops,bytesConsumed:parsed.bytesConsumed,safety:'restricted-allowlist-no-execution'}};
    }else throw new Error(`row source 不支持 dtype ${header.descr}`);
  }catch(error){await handle.close();throw error;}

  const readRows=async(start,count)=>{
    start=Number(start);count=Number(count);
    if(!Number.isSafeInteger(start)||!Number.isSafeInteger(count)||start<0||count<0||start+count>source.rows)throw new Error('readRows 范围非法');
    if(count*source.cols>MAX_READ_VALUES)throw new Error(`readRows values 超过 ${MAX_READ_VALUES}`);
    const rows=[];let wantedStart=start;let remaining=count;
    for(const segment of source.segments){
      const segStart=segment.rowStart,segEnd=segStart+segment.rows;
      if(wantedStart>=segEnd||wantedStart+remaining<=segStart)continue;
      const localStart=Math.max(0,wantedStart-segStart);
      const take=Math.min(segment.rows-localStart,remaining);
      if(take<=0)continue;
      const rowBytes=segment.cols*segment.descriptor.bytes,totalBytes=take*rowBytes;
      const raw=Buffer.allocUnsafe(totalBytes);
      const pos=segment.dataOffset+localStart*rowBytes;
      const got=await handle.read(raw,0,totalBytes,pos);if(got.bytesRead!==totalBytes)throw new Error('NPY segment row 读取不完整');
      for(let r=0;r<take;r+=1){const row=Array(segment.cols);for(let c=0;c<segment.cols;c+=1){const value=readNumber(raw,r*rowBytes+c*segment.descriptor.bytes,segment.descriptor);if(!Number.isFinite(value))throw new Error('NPY row 包含 NaN/Inf');row[c]=value;}rows.push(row);}
      wantedStart+=take;remaining-=take;if(!remaining)break;
    }
    if(rows.length!==count)throw new Error(`NPY row source 仅读取 ${rows.length}/${count} rows`);
    return rows;
  };
  return {schema:'newcyber.npy-row-source.v1',filePath:header.filePath,fileName:header.fileName,sourceKind:source.kind,rows:source.rows,cols:source.cols,segments:source.segments.map(({descriptor,...rest})=>({...rest,dtype:`${descriptor.endian}${descriptor.kind}${descriptor.bytes}`})),pickle:source.pickle||null,readRows,close:()=>handle.close()};
}

async function inspectNpyRowSource(filePath){const source=await openNpyRowSource(filePath);try{return {schema:source.schema,fileName:source.fileName,sourceKind:source.sourceKind,rows:source.rows,cols:source.cols,segments:source.segments,pickle:source.pickle};}finally{await source.close();}}

module.exports={MAX_NPY_BYTES,readNpyHeaderAnyPath,parseRestrictedNumpyPickle,openNpyRowSource,inspectNpyRowSource};
