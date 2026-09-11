'use strict';

const path=require('path');

const ALLOWED_TYPES=new Set(['float32','float64','int8','uint8','int16','uint16','int32','uint32','int64','uint64','bool']);
const TYPE_BYTES=Object.freeze({float32:4,float64:8,int8:1,uint8:1,int16:2,uint16:2,int32:4,uint32:4,int64:8,uint64:8,bool:1});
const BINDING_KEYS=['onnxInputs','onnx_inputs','inputFeeds','input_feeds','constantFeeds','constant_feeds'];
const MAX_BINDINGS=64;
const MAX_VALUES=1_000_000;
const MAX_BASE64_CHARS=16*1024*1024;
const MAX_PY_LITERAL_CHARS=2*1024*1024;

function list(value){return Array.isArray(value)?value:[];}
function staticDim(value){const n=Number(value);return Number.isInteger(n)&&n>0?n:null;}
function product(dims){let total=1;for(const raw of dims){const n=Number(raw);if(!Number.isSafeInteger(n)||n<=0)throw new Error('aux input dims 必须是正安全整数');total*=n;if(!Number.isSafeInteger(total)||total>MAX_VALUES)throw new Error(`aux input 元素数超过 ${MAX_VALUES}`);}return total;}
function normalizeType(value){return String(value||'').trim().toLowerCase().replace(/^tensor\((.+)\)$/,'$1').replace(/^(?:np|numpy)\./,'').replace(/^float$/,'float32').replace(/^double$/,'float64');}
function metadataType(input){return normalizeType(input?.metadata?.type||input?.type||'');}
function dimsCompatible(actual,expected){
  if(!Array.isArray(actual)||!Array.isArray(expected)||actual.length!==expected.length)return false;
  return actual.every((value,index)=>{const a=staticDim(value),e=staticDim(expected[index]);return a!==null&&(e===null||a===e);});
}
function compatibleWithOptionalBatch(actual,expected){
  if(dimsCompatible(actual,expected))return{compatible:true,adaptation:'exact'};
  if(Array.isArray(actual)&&Array.isArray(expected)&&expected.length===actual.length+1){const first=staticDim(expected[0]),expanded=[1,...actual];if((first===null||first===1)&&dimsCompatible(expanded,expected))return{compatible:true,adaptation:'prepend-batch-1',dims:expanded};}
  return{compatible:false,adaptation:null};
}
function validValueForType(value,type){
  if(type==='bool')return typeof value==='boolean'||value===0||value===1||value==='0'||value==='1';
  if(type==='int64'||type==='uint64'){const raw=String(value).trim();if(!/^-?\d+$/.test(raw))return false;if(type==='uint64'&&raw.startsWith('-'))return false;try{BigInt(raw);return true;}catch{return false;}}
  const number=Number(value);if(!Number.isFinite(number))return false;if(/^u?int/.test(type)&&!Number.isInteger(number))return false;return true;
}
function validateFeedSpec(spec,name='input'){
  if(!spec||typeof spec!=='object'||Array.isArray(spec))throw new Error(`${name}: binding 必须是对象`);
  const type=normalizeType(spec.type);if(!ALLOWED_TYPES.has(type))throw new Error(`${name}: 不支持 type=${spec.type}`);
  if(!Array.isArray(spec.dims)||!spec.dims.length)throw new Error(`${name}: dims 缺失`);const dims=spec.dims.map(Number),count=product(dims);
  const hasValues=Array.isArray(spec.values);const hasBase64=typeof spec.base64==='string'&&spec.base64.length>0;
  if(hasValues===hasBase64)throw new Error(`${name}: values/base64 必须且只能提供一种`);
  if(hasValues){if(spec.values.length!==count)throw new Error(`${name}: values 数量 ${spec.values.length} 与 dims 元素数 ${count} 不一致`);if(spec.values.length>MAX_VALUES)throw new Error(`${name}: values 超限`);if(spec.values.some((value)=>typeof value==='object'||!validValueForType(value,type)))throw new Error(`${name}: values 含非法值`);}
  if(hasBase64){
    if(spec.base64.length>MAX_BASE64_CHARS||!/^[A-Za-z0-9+/]*={0,2}$/.test(spec.base64)||spec.base64.length%4!==0)throw new Error(`${name}: base64 非法或超限`);
    const bytes=Buffer.from(spec.base64,'base64').byteLength,expected=count*TYPE_BYTES[type];if(bytes!==expected)throw new Error(`${name}: base64 解码长度 ${bytes} 与 dims/type 期望 ${expected} 不一致`);
  }
  return{type,dims,...(hasValues?{values:spec.values.slice()}:{base64:spec.base64})};
}
function bindingObject(value){return value&&typeof value==='object'&&!Array.isArray(value);}

function matchingDelimiter(source,start,open,close,maxChars=MAX_PY_LITERAL_CHARS){
  if(source[start]!==open)return-1;let depth=0,quote=null,escape=false;const limit=Math.min(source.length,start+maxChars);
  for(let i=start;i<limit;i+=1){const ch=source[i];if(quote){if(escape){escape=false;continue;}if(ch==='\\'){escape=true;continue;}if(ch===quote)quote=null;continue;}if(ch==='"'||ch==="'"){quote=ch;continue;}if(ch===open)depth+=1;else if(ch===close){depth-=1;if(depth===0)return i;}}
  return-1;
}
function tokenizePythonLiteral(raw){
  const tokens=[];let index=0;while(index<raw.length){const rest=raw.slice(index);const ws=rest.match(/^\s+/);if(ws){index+=ws[0].length;continue;}const punctuation=rest[0];if(['[',']',','].includes(punctuation)){tokens.push(punctuation);index+=1;continue;}const bool=rest.match(/^(True|False)\b/);if(bool){tokens.push(bool[1]);index+=bool[0].length;continue;}const number=rest.match(/^[-+]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][-+]?\d+)?/);if(number){tokens.push(number[0]);index+=number[0].length;continue;}throw new Error(`unsupported Python literal token near ${rest.slice(0,24)}`);}return tokens;
}
function parsePythonLiteralArray(raw){
  if(typeof raw!=='string'||raw.length>MAX_PY_LITERAL_CHARS)throw new Error('Python literal array 过大');const tokens=tokenizePythonLiteral(raw);let cursor=0;
  function value(){const token=tokens[cursor++];if(token==='['){const out=[];if(tokens[cursor]===']'){cursor+=1;return out;}while(cursor<tokens.length){out.push(value());if(tokens[cursor]===','){cursor+=1;if(tokens[cursor]===']'){cursor+=1;break;}continue;}if(tokens[cursor]===']'){cursor+=1;break;}throw new Error('Python literal list 缺少逗号或右括号');}return out;}if(token==='True')return true;if(token==='False')return false;if(token===undefined)throw new Error('Python literal 意外结束');const n=Number(token);if(!Number.isFinite(n))throw new Error('Python literal 含非有限数字');return n;}
  const root=value();if(cursor!==tokens.length||!Array.isArray(root)||!root.length)throw new Error('Python literal 必须是非空 list');return root;
}
function flattenRectangular(value){
  const flat=[];function walk(node){if(!Array.isArray(node)){flat.push(node);return[];}if(!node.length)throw new Error('Python literal 不支持空维度');const first=walk(node[0]);for(let i=1;i<node.length;i+=1){const shape=walk(node[i]);if(JSON.stringify(shape)!==JSON.stringify(first))throw new Error('Python literal 必须是规则矩形数组');}return[node.length,...first];}const dims=walk(value);if(!dims.length)throw new Error('Python literal 必须至少一维');if(flat.length>MAX_VALUES)throw new Error(`Python literal 元素数超过 ${MAX_VALUES}`);return{dims,values:flat};
}
function dtypeFromCallTail(tail){const match=String(tail||'').match(/\bdtype\s*=\s*(?:(?:np|numpy)\.)?([A-Za-z0-9_]+)/);return match?normalizeType(match[1]):null;}
function discoverPythonLiteralVariables(file,body){
  if(!/(?:onnxruntime|InferenceSession)/.test(body))return[];const rows=[];const assignment=/(?:^|\n)\s*([A-Za-z_]\w*)\s*=\s*(?:(?:np|numpy)\.)?(?:array|asarray)\s*\(/g;let match;
  while((match=assignment.exec(body))&&rows.length<MAX_BINDINGS*4){const name=match[1];const listStart=body.indexOf('[',match.index+match[0].length);if(listStart<0||listStart-match.index>512)continue;const listEnd=matchingDelimiter(body,listStart,'[',']');if(listEnd<0)continue;const closeParen=body.indexOf(')',listEnd);if(closeParen<0||closeParen-listEnd>320)continue;const tail=body.slice(listEnd+1,closeParen);const type=dtypeFromCallTail(tail);if(!type||!ALLOWED_TYPES.has(type))continue;try{const parsed=parsePythonLiteralArray(body.slice(listStart,listEnd+1));const shaped=flattenRectangular(parsed);const spec=validateFeedSpec({type,dims:shaped.dims,values:shaped.values},name);rows.push({name,spec,file,key:'python-literal-variable',variable:name,line:body.slice(0,match.index).split(/\r?\n/).length});}catch{}}
  return rows;
}
function discoverPythonFeedVariables(body){
  if(!/(?:onnxruntime|InferenceSession)/.test(body))return new Map();const feedDicts=[];const direct=/\.run\s*\(/g;let match;
  while((match=direct.exec(body))){const end=matchingDelimiter(body,body.indexOf('(',match.index),'(',')',256*1024);if(end<0)continue;const call=body.slice(match.index,end+1);let brace=call.indexOf('{');if(brace>=0){const braceEnd=matchingDelimiter(call,brace,'{','}',64*1024);if(braceEnd>=0)feedDicts.push(call.slice(brace,braceEnd+1));}}
  const assigned=new Map();const dictAssign=/(?:^|\n)\s*([A-Za-z_]\w*)\s*=\s*\{/g;while((match=dictAssign.exec(body))){const brace=body.indexOf('{',match.index);const end=matchingDelimiter(body,brace,'{','}',64*1024);if(end>=0)assigned.set(match[1],body.slice(brace,end+1));}
  for(const [name,dict] of assigned){const used=new RegExp(`\\.run\\s*\\([^\\n]{0,1000}\\b${name}\\b`);if(used.test(body))feedDicts.push(dict);}
  const map=new Map();for(const dict of feedDicts){const pair=/["']([^"']{1,256})["']\s*:\s*([A-Za-z_]\w*)\b/g;let p;while((p=pair.exec(dict))){if(!map.has(p[2]))map.set(p[2],new Set());map.get(p[2]).add(p[1]);}}
  return map;
}
function discoverPythonConstantInputBindings(file,body){
  if(!/\.pyw?$/i.test(path.extname(file))&&!/(?:onnxruntime|InferenceSession)/.test(body))return[];const variables=discoverPythonLiteralVariables(file,body),used=discoverPythonFeedVariables(body),out=[];
  for(const row of variables){for(const inputName of used.get(row.variable)||[]){out.push({name:inputName,spec:row.spec,file,key:'python-onnx-run-literal',line:row.line,variable:row.variable});}}
  return out;
}

function discoverConstantInputBindings(sources=[]){
  const bindings=new Map(),conflicts=[],errors=[],evidence=[];
  const record=(row)=>{try{const spec=validateFeedSpec(row.spec,row.name);const prior=bindings.get(row.name);const normalized={name:row.name,spec,file:row.file,key:row.key,line:row.line||null,variable:row.variable||null};if(prior&&JSON.stringify(prior.spec)!==JSON.stringify(spec)){conflicts.push({name:row.name,first:{file:prior.file,key:prior.key,line:prior.line||null},second:{file:row.file,key:row.key,line:row.line||null}});return;}if(!prior)bindings.set(row.name,normalized);evidence.push({file:row.file,key:row.key,name:row.name,type:spec.type,dims:spec.dims,line:row.line||null,variable:row.variable||null});}catch(error){errors.push({file:row.file,key:row.key,name:row.name,error:String(error?.message||error).slice(0,240)});}};
  for(const source of list(sources)){
    const file=String(source?.file||source?.path||'source'),body=String(source?.text||source?.content||'');if(!body)continue;
    let parsed=null;try{parsed=JSON.parse(body);}catch{}
    if(parsed){const queue=[parsed];let seen=0;while(queue.length&&seen++<4000){const node=queue.shift();if(!node||typeof node!=='object')continue;if(Array.isArray(node)){queue.push(...node.slice(0,4000-seen));continue;}for(const key of BINDING_KEYS){const group=node[key];if(!bindingObject(group))continue;for(const [name,raw] of Object.entries(group).slice(0,MAX_BINDINGS))record({name,spec:raw,file,key});}queue.push(...Object.values(node));}}
    for(const row of discoverPythonConstantInputBindings(file,body))record(row);
  }
  return{schema:'newcyber.challenge-onnx-input-bindings.v2',status:conflicts.length?'conflict':bindings.size?'ready':'not-detected',bindings:Object.fromEntries([...bindings.entries()].map(([name,row])=>[name,row])),conflicts:conflicts.slice(0,64),errors:errors.slice(0,64),evidence:evidence.slice(0,128)};
}
function validateBindingAgainstInput(binding,input){
  if(!binding)return{ok:false,reason:'binding missing'};const modelType=metadataType(input),specType=normalizeType(binding.spec.type);if(modelType&&modelType!==specType)return{ok:false,reason:`type ${specType} != model ${modelType}`};
  const expected=input?.metadata?.dimensions;if(Array.isArray(expected)&&expected.length&&!dimsCompatible(binding.spec.dims,expected))return{ok:false,reason:`shape ${JSON.stringify(binding.spec.dims)} != model ${JSON.stringify(expected)}`};return{ok:true};
}
function resolveModelInputPlan(model,context={}){
  const inputs=list(model?.inputs);if(!inputs.length)return{ok:false,code:'MODEL_INPUTS_MISSING',detail:'model has no inspectable inputs'};
  const recovered=context.inputBindings?.bindings||{};const auxiliaries={};const evidence=[];const uncovered=[];
  for(const input of inputs){const row=recovered[input.name];if(!row){uncovered.push(input);continue;}const checked=validateBindingAgainstInput(row,input);if(!checked.ok)return{ok:false,code:'AUX_INPUT_BINDING_MISMATCH',detail:`${input.name}: ${checked.reason}`,input:input.name};auxiliaries[input.name]=row.spec;evidence.push({name:input.name,file:row.file,key:row.key,line:row.line||null,variable:row.variable||null,type:row.spec.type,dims:row.spec.dims});}
  if(uncovered.length===0)return{ok:false,code:'PRIMARY_INPUT_MISSING',detail:'all model inputs were bound as constants; no candidate input remains'};
  if(uncovered.length>1)return{ok:false,code:'AUX_INPUT_BINDING_MISSING',detail:`${uncovered.length} model inputs remain unbound`,missing:uncovered.map((x)=>x.name)};
  const primary=uncovered[0];const expectedDims=context.mode==='image'?context.imageDims:context.mode==='npy'?context.npyDims:null;
  if(expectedDims&&Array.isArray(primary?.metadata?.dimensions)){const relation=context.mode==='npy'?compatibleWithOptionalBatch(expectedDims,primary.metadata.dimensions):{compatible:dimsCompatible(expectedDims,primary.metadata.dimensions),adaptation:'exact'};if(!relation.compatible)return{ok:false,code:'PRIMARY_INPUT_SHAPE_MISMATCH',detail:`${primary.name}: candidate ${JSON.stringify(expectedDims)} != model ${JSON.stringify(primary.metadata.dimensions)}`};}
  return{ok:true,primaryInputName:primary.name,primaryInput:primary,auxiliaryFeeds:auxiliaries,auxiliaryInputNames:Object.keys(auxiliaries),evidence,reasons:[`primary candidate input=${primary.name}`,...Object.keys(auxiliaries).map((name)=>`auxiliary input ${name} is evidence-bound from challenge material`)]};
}
function inputPlanView(plan){if(!plan?.ok)return null;return{primaryInputName:plan.primaryInputName,auxiliaryInputNames:plan.auxiliaryInputNames||[],evidence:plan.evidence||[],reasons:plan.reasons||[]};}

module.exports={ALLOWED_TYPES,TYPE_BYTES,BINDING_KEYS,normalizeType,dimsCompatible,compatibleWithOptionalBatch,validValueForType,validateFeedSpec,matchingDelimiter,tokenizePythonLiteral,parsePythonLiteralArray,flattenRectangular,discoverPythonLiteralVariables,discoverPythonFeedVariables,discoverPythonConstantInputBindings,discoverConstantInputBindings,validateBindingAgainstInput,resolveModelInputPlan,inputPlanView};
