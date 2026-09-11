'use strict';

const ALLOWED_TYPES=new Set(['float32','float64','int8','uint8','int16','uint16','int32','uint32','int64','uint64','bool']);
const TYPE_BYTES=Object.freeze({float32:4,float64:8,int8:1,uint8:1,int16:2,uint16:2,int32:4,uint32:4,int64:8,uint64:8,bool:1});
const BINDING_KEYS=['onnxInputs','onnx_inputs','inputFeeds','input_feeds','constantFeeds','constant_feeds'];
const MAX_BINDINGS=64;
const MAX_VALUES=1_000_000;
const MAX_BASE64_CHARS=16*1024*1024;

function list(value){return Array.isArray(value)?value:[];}
function staticDim(value){const n=Number(value);return Number.isInteger(n)&&n>0?n:null;}
function product(dims){let total=1;for(const raw of dims){const n=Number(raw);if(!Number.isSafeInteger(n)||n<=0)throw new Error('aux input dims 必须是正安全整数');total*=n;if(!Number.isSafeInteger(total)||total>MAX_VALUES)throw new Error(`aux input 元素数超过 ${MAX_VALUES}`);}return total;}
function normalizeType(value){return String(value||'').trim().toLowerCase().replace(/^tensor\((.+)\)$/,'$1').replace(/^float$/,'float32').replace(/^double$/,'float64');}
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
function discoverConstantInputBindings(sources=[]){
  const bindings=new Map(),conflicts=[],errors=[],evidence=[];
  for(const source of list(sources)){
    const file=String(source?.file||source?.path||'source');let parsed;try{parsed=JSON.parse(String(source?.text||source?.content||''));}catch{continue;}
    const queue=[parsed];let seen=0;
    while(queue.length&&seen++<4000){const node=queue.shift();if(!node||typeof node!=='object')continue;if(Array.isArray(node)){queue.push(...node.slice(0,4000-seen));continue;}
      for(const key of BINDING_KEYS){const group=node[key];if(!bindingObject(group))continue;for(const [name,raw] of Object.entries(group).slice(0,MAX_BINDINGS)){try{const spec=validateFeedSpec(raw,name);const prior=bindings.get(name);const record={name,spec,file,key};if(prior&&JSON.stringify(prior.spec)!==JSON.stringify(spec)){conflicts.push({name,first:{file:prior.file,key:prior.key},second:{file,key}});continue;}if(!prior)bindings.set(name,record);evidence.push({file,key,name,type:spec.type,dims:spec.dims});}catch(error){errors.push({file,key,name,error:String(error?.message||error).slice(0,240)});}}
      }
      queue.push(...Object.values(node));
    }
  }
  return{schema:'newcyber.challenge-onnx-input-bindings.v1',status:conflicts.length?'conflict':bindings.size?'ready':'not-detected',bindings:Object.fromEntries([...bindings.entries()].map(([name,row])=>[name,row])),conflicts:conflicts.slice(0,64),errors:errors.slice(0,64),evidence:evidence.slice(0,128)};
}
function validateBindingAgainstInput(binding,input){
  if(!binding)return{ok:false,reason:'binding missing'};const modelType=metadataType(input),specType=normalizeType(binding.spec.type);if(modelType&&modelType!==specType)return{ok:false,reason:`type ${specType} != model ${modelType}`};
  const expected=input?.metadata?.dimensions;if(Array.isArray(expected)&&expected.length&&!dimsCompatible(binding.spec.dims,expected))return{ok:false,reason:`shape ${JSON.stringify(binding.spec.dims)} != model ${JSON.stringify(expected)}`};return{ok:true};
}
function resolveModelInputPlan(model,context={}){
  const inputs=list(model?.inputs);if(!inputs.length)return{ok:false,code:'MODEL_INPUTS_MISSING',detail:'model has no inspectable inputs'};
  const recovered=context.inputBindings?.bindings||{};const auxiliaries={};const evidence=[];const uncovered=[];
  for(const input of inputs){const row=recovered[input.name];if(!row){uncovered.push(input);continue;}const checked=validateBindingAgainstInput(row,input);if(!checked.ok)return{ok:false,code:'AUX_INPUT_BINDING_MISMATCH',detail:`${input.name}: ${checked.reason}`,input:input.name};auxiliaries[input.name]=row.spec;evidence.push({name:input.name,file:row.file,key:row.key,type:row.spec.type,dims:row.spec.dims});}
  if(uncovered.length===0)return{ok:false,code:'PRIMARY_INPUT_MISSING',detail:'all model inputs were bound as constants; no candidate input remains'};
  if(uncovered.length>1)return{ok:false,code:'AUX_INPUT_BINDING_MISSING',detail:`${uncovered.length} model inputs remain unbound`,missing:uncovered.map((x)=>x.name)};
  const primary=uncovered[0];const expectedDims=context.mode==='image'?context.imageDims:context.mode==='npy'?context.npyDims:null;
  if(expectedDims&&Array.isArray(primary?.metadata?.dimensions)){const relation=context.mode==='npy'?compatibleWithOptionalBatch(expectedDims,primary.metadata.dimensions):{compatible:dimsCompatible(expectedDims,primary.metadata.dimensions),adaptation:'exact'};if(!relation.compatible)return{ok:false,code:'PRIMARY_INPUT_SHAPE_MISMATCH',detail:`${primary.name}: candidate ${JSON.stringify(expectedDims)} != model ${JSON.stringify(primary.metadata.dimensions)}`};}
  return{ok:true,primaryInputName:primary.name,primaryInput:primary,auxiliaryFeeds:auxiliaries,auxiliaryInputNames:Object.keys(auxiliaries),evidence,reasons:[`primary candidate input=${primary.name}`,...Object.keys(auxiliaries).map((name)=>`auxiliary input ${name} is explicitly bound from challenge JSON`)]};
}
function inputPlanView(plan){if(!plan?.ok)return null;return{primaryInputName:plan.primaryInputName,auxiliaryInputNames:plan.auxiliaryInputNames||[],evidence:plan.evidence||[],reasons:plan.reasons||[]};}

module.exports={ALLOWED_TYPES,TYPE_BYTES,BINDING_KEYS,normalizeType,dimsCompatible,compatibleWithOptionalBatch,validValueForType,validateFeedSpec,discoverConstantInputBindings,validateBindingAgainstInput,resolveModelInputPlan,inputPlanView};
