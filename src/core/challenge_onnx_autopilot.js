'use strict';

const fs=require('fs/promises');
const path=require('path');
const {parseNpyAdvanced}=require('./model_artifacts');
const {runtimeStatus,inspectOnnxModel,runOnnxModel}=require('./local_ml_runtime');
const {rankAdversarialContestFromOnnxRuns}=require('./ai_adversarial_onnx_bridge');
const {discoverJsonMaterial,discoverTextHints,analyzeAiContestBundle}=require('./ai_contest_bundle_autopilot');

const MAX_MODEL_BYTES=2*1024*1024*1024;
const MAX_NPY_BYTES=128*1024*1024;
const MAX_CANDIDATES=512;
const MAX_SOURCE_FILES=48;
const MAX_SOURCE_BYTES=2*1024*1024;
const MAX_TOTAL_SOURCE_BYTES=12*1024*1024;

function list(value){return Array.isArray(value)?value:[];}
function inside(root,target){const rel=path.relative(path.resolve(root),path.resolve(target));return rel===''||(!rel.startsWith(`..${path.sep}`)&&rel!=='..'&&!path.isAbsolute(rel));}
function numeric(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function labelsEqual(a,b){return String(a)===String(b);}

function dtypeToTensorType(descr){
  const value=String(descr||'');
  if(value.startsWith('>'))return null;
  const normalized=value.replace(/^=/,'<');
  const map={
    '<f4':'float32','|f4':'float32','<f8':'float64','|f8':'float64',
    '|i1':'int8','<i1':'int8','|u1':'uint8','<u1':'uint8',
    '<i2':'int16','<u2':'uint16','<i4':'int32','<u4':'uint32','<i8':'int64','<u8':'uint64',
    '|b1':'bool','|?1':'bool'
  };
  return map[normalized]||null;
}

function npyTensorSpec(buffer,fileName='candidate.npy'){
  const meta=parseNpyAdvanced(buffer);
  if(!meta||!meta.valid)throw new Error(`${fileName}: NPY header/size validation failed`);
  if(meta.objectDtype)throw new Error(`${fileName}: object dtype is not executable`);
  if(meta.fortranOrder)throw new Error(`${fileName}: Fortran-order NPY is not auto-executed`);
  if(!Array.isArray(meta.shape)||!meta.shape.length)throw new Error(`${fileName}: scalar/unknown NPY shape is not supported`);
  const type=dtypeToTensorType(meta.descr);if(!type)throw new Error(`${fileName}: unsupported or big-endian dtype ${meta.descr}`);
  const payload=buffer.subarray(meta.payloadOffset);
  return{type,dims:meta.shape.slice(),base64:payload.toString('base64'),npy:{descr:meta.descr,shape:meta.shape.slice(),payloadBytes:meta.payloadBytes}};
}

function staticDimension(value){
  if(Number.isInteger(Number(value))&&Number(value)>0)return Number(value);
  return null;
}
function dimsCompatible(specDims,modelDims){
  if(!Array.isArray(modelDims)||!modelDims.length)return true;
  if(specDims.length!==modelDims.length)return false;
  return specDims.every((value,index)=>{const expected=staticDimension(modelDims[index]);return expected===null||expected===Number(value);});
}
function adaptDimsToModel(spec,metadata){
  const modelDims=metadata?.dimensions;
  if(!Array.isArray(modelDims)||!modelDims.length)return{...spec,dims:spec.dims.slice(),adaptation:'metadata-unavailable'};
  if(dimsCompatible(spec.dims,modelDims))return{...spec,dims:spec.dims.slice(),adaptation:'exact-shape'};
  if(modelDims.length===spec.dims.length+1){
    const first=staticDimension(modelDims[0]);const expanded=[1,...spec.dims];
    if((first===null||first===1)&&dimsCompatible(expanded,modelDims))return{...spec,dims:expanded,adaptation:'prepend-batch-1'};
  }
  throw new Error(`NPY shape ${JSON.stringify(spec.dims)} incompatible with model input ${JSON.stringify(modelDims)}`);
}

function hintRowsFromSources(sources){
  const sets=[];const seen=new Set();
  const add=(file,rows,source)=>{if(!Array.isArray(rows)||!rows.length)return;const key=JSON.stringify(rows);if(seen.has(key))return;seen.add(key);sets.push({file,source,rows});};
  for(const item of sources){
    const json=discoverJsonMaterial(item.file,item.text);for(const row of json.hints)add(row.file,row.rows,row.source);
    for(const row of discoverTextHints(item.file,item.text))add(row.file,row.rows,row.source);
  }
  return sets;
}

function targetLabels(hints){return new Set(hints.map((row)=>String(Array.isArray(row)?row[1]:(row.adversarialLabel??row.targetLabel??row.target??row.to))));}
function labelFromPath(relativePath,hints){
  const targets=targetLabels(hints);const parts=String(relativePath||'').split(/[\\/]/).slice(0,-1).reverse();
  for(const part of parts){if(targets.has(String(part)))return part;}
  return null;
}
function idFromPath(relativePath){
  const base=path.basename(String(relativePath||''));const match=base.match(/^(\d+)(?:\.[^.]+)?$/);return match?Number(match[1]):relativePath;
}

function chooseHintSet(sets,npyPaths){
  if(!sets.length)return null;
  const ranked=sets.map((set)=>{
    let matches=0;for(const file of npyPaths)if(labelFromPath(file,set.rows)!==null)matches+=1;
    return{...set,matches};
  }).sort((a,b)=>b.matches-a.matches||b.rows.length-a.rows.length||a.file.localeCompare(b.file));
  return ranked[0];
}

async function collectSources(root,analysis){
  const allowed=new Set(['.py','.pyw','.js','.mjs','.cjs','.ts','.json','.jsonl','.ndjson','.csv','.tsv','.txt','.md','.yaml','.yml','.toml','.ini','.cfg']);
  const rows=[];let total=0;
  for(const file of list(analysis.files)){
    if(rows.length>=MAX_SOURCE_FILES||total>=MAX_TOTAL_SOURCE_BYTES)break;
    const ext=String(file.extension||path.extname(file.path||'')).toLowerCase();if(!allowed.has(ext))continue;
    const target=path.resolve(root,String(file.path||''));if(!inside(root,target))continue;
    let stat;try{stat=await fs.lstat(target);}catch{continue;}if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>MAX_SOURCE_BYTES||total+stat.size>MAX_TOTAL_SOURCE_BYTES)continue;
    let body;try{body=await fs.readFile(target,'utf8');}catch{continue;}total+=Buffer.byteLength(body);rows.push({file:file.path,text:body});
  }
  return rows;
}

function modelFiles(analysis){return list(analysis.files).filter((file)=>String(file.extension||path.extname(file.path||'')).toLowerCase()==='.onnx');}
function npyFiles(analysis){return list(analysis.files).filter((file)=>String(file.extension||path.extname(file.path||'')).toLowerCase()==='.npy');}

function safeFeedSpec(value){
  if(!value||typeof value!=='object'||Array.isArray(value))return false;
  if(!Array.isArray(value.dims)||!value.dims.length||value.dims.some((x)=>!Number.isSafeInteger(Number(x))||Number(x)<0))return false;
  const hasValues=Array.isArray(value.values)||ArrayBuffer.isView(value.values);const hasBase64=typeof value.base64==='string'&&value.base64.length>0;
  return typeof value.type==='string'&&(hasValues||hasBase64);
}
function discoverExplicitFeedBundle(sources){
  for(const source of sources){
    let root;try{root=JSON.parse(source.text);}catch{continue;}
    const queue=[root];let seen=0;
    while(queue.length&&seen++<2000){
      const value=queue.shift();if(!value||typeof value!=='object')continue;
      if(Array.isArray(value)){queue.push(...value.slice(0,2000-seen));continue;}
      const hints=value.hints??value.hintPairs??value.transitions;const candidates=value.candidates??value.samples??value.runs;
      if(Array.isArray(hints)&&hints.length&&Array.isArray(candidates)&&candidates.length&&candidates.length<=MAX_CANDIDATES){
        const valid=candidates.every((candidate)=>candidate&&typeof candidate==='object'&&candidate.feeds&&typeof candidate.feeds==='object'&&Object.values(candidate.feeds).every(safeFeedSpec));
        if(valid)return{file:source.file,hints,candidates,outputName:value.outputName||null};
      }
      queue.push(...Object.values(value));
    }
  }
  return null;
}

async function inspectUniqueModel(root,analysis){
  const models=modelFiles(analysis);
  if(!models.length)return{ok:false,code:'MODEL_MISSING',detail:'no ONNX model in challenge session'};
  if(models.length>1)return{ok:false,code:'MODEL_AMBIGUOUS',detail:`${models.length} ONNX models found`,models:models.map((x)=>x.path)};
  const file=models[0];if(Number(file.size)>MAX_MODEL_BYTES)return{ok:false,code:'MODEL_TOO_LARGE',detail:`model size ${file.size} exceeds ${MAX_MODEL_BYTES}`};
  const target=path.resolve(root,file.path);if(!inside(root,target))return{ok:false,code:'MODEL_PATH_INVALID',detail:file.path};
  const stat=await fs.lstat(target);if(!stat.isFile()||stat.isSymbolicLink())return{ok:false,code:'MODEL_PATH_INVALID',detail:file.path};
  const model=await inspectOnnxModel(target,{provider:'cpu'});
  return{ok:true,file,target,model};
}

async function runExplicitBundle(modelInfo,bundle){
  const inputNames=modelInfo.model.inputs.map((item)=>item.name);
  const runs=[];const errors=[];
  for(let index=0;index<bundle.candidates.length;index+=1){
    const candidate=bundle.candidates[index];const feedNames=Object.keys(candidate.feeds||{});
    if(inputNames.some((name)=>!feedNames.includes(name))){errors.push({id:candidate.id??index,error:'explicit feeds do not cover all model inputs'});continue;}
    try{
      const run=await runOnnxModel(modelInfo.target,{feeds:candidate.feeds,outputs:bundle.outputName?[bundle.outputName]:undefined},{provider:'cpu'});
      runs.push({id:candidate.id??candidate.file??candidate.name??index,assignedLabel:candidate.assignedLabel??candidate.folderLabel??candidate.bucketLabel??candidate.classLabel,run,outputName:bundle.outputName||undefined});
    }catch(error){errors.push({id:candidate.id??index,error:String(error?.message||error).slice(0,260)});}
  }
  return{runs,errors,mode:'explicit-feeds'};
}

async function runNpyBundle(root,analysis,modelInfo,hintSet){
  if(modelInfo.model.inputs.length!==1)return{runs:[],errors:[{error:`auto NPY mode requires exactly one ONNX input, got ${modelInfo.model.inputs.length}`}],mode:'npy'};
  const input=modelInfo.model.inputs[0];const files=npyFiles(analysis).slice(0,MAX_CANDIDATES);const runs=[];const errors=[];
  for(const file of files){
    const assignedLabel=labelFromPath(file.path,hintSet.rows);if(assignedLabel===null)continue;
    const target=path.resolve(root,file.path);if(!inside(root,target))continue;
    try{
      const stat=await fs.lstat(target);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>MAX_NPY_BYTES)throw new Error(`NPY size ${stat.size} outside auto-run limit`);
      const buffer=await fs.readFile(target);const raw=npyTensorSpec(buffer,file.path);const spec=adaptDimsToModel(raw,input.metadata);
      const run=await runOnnxModel(modelInfo.target,{feeds:{[input.name]:{type:spec.type,dims:spec.dims,base64:spec.base64}}},{provider:'cpu'});
      runs.push({id:idFromPath(file.path),file:file.path,assignedLabel,run,npy:{descr:raw.npy.descr,shape:raw.npy.shape,adaptation:spec.adaptation}});
    }catch(error){errors.push({file:file.path,error:String(error?.message||error).slice(0,300)});}
  }
  return{runs,errors,mode:'npy'};
}

async function runChallengeOnnxAutopilot(rootPath,analysis,options={}){
  const root=path.resolve(String(rootPath||''));const runtime=runtimeStatus();
  const base={schema:'newcyber.challenge-onnx-autopilot.v1',runtime:{available:runtime.available,source:runtime.source||null,version:runtime.version||null},status:'not-applicable',mode:null,runs:0,errors:[],contest:null,gap:null};
  if(!runtime.available)return{...base,status:'gap',gap:{code:'MODEL_RUNTIME_GAP',detail:runtime.installHint||runtime.error||'onnxruntime-node unavailable'}};
  const sources=await collectSources(root,analysis);const explicit=discoverExplicitFeedBundle(sources);
  const npys=npyFiles(analysis);const hintSets=hintRowsFromSources(sources);const hintSet=chooseHintSet(hintSets,npys.map((x)=>x.path));
  if(!explicit&&(!npys.length||!hintSet))return{...base,status:'not-applicable',gap:{code:!npys.length?'CANDIDATE_TENSORS_MISSING':'HINTS_MISSING',detail:'need explicit feed bundle or NPY candidates plus hint pairs'}};
  let modelInfo;try{modelInfo=await inspectUniqueModel(root,analysis);}catch(error){return{...base,status:'gap',gap:{code:'MODEL_INSPECTION_FAILED',detail:String(error?.message||error).slice(0,400)}};}
  if(!modelInfo.ok)return{...base,status:'gap',gap:{code:modelInfo.code,detail:modelInfo.detail,models:modelInfo.models||null}};
  let executed;
  try{executed=explicit?await runExplicitBundle(modelInfo,explicit):await runNpyBundle(root,analysis,modelInfo,hintSet);}catch(error){return{...base,status:'gap',gap:{code:'INFERENCE_FAILED',detail:String(error?.message||error).slice(0,400)}};}
  const hints=explicit?.hints||hintSet?.rows;
  if(!executed.runs.length)return{...base,status:'gap',mode:executed.mode,errors:executed.errors,gap:{code:'NO_SUCCESSFUL_INFERENCE',detail:'no candidate produced a complete ONNX classification output'}};
  let bridge;try{bridge=rankAdversarialContestFromOnnxRuns({hints,runs:executed.runs,outputName:explicit?.outputName||undefined,shortlistSize:3,beamWidth:2,maxSets:128});}
  catch(error){return{...base,status:'gap',mode:executed.mode,runs:executed.runs.length,errors:executed.errors,gap:{code:'RANKING_FAILED',detail:String(error?.message||error).slice(0,400)}};}
  const synthetic={hints,candidates:bridge.bundle.candidates.map((item)=>({id:item.id,assignedLabel:item.assignedLabel,scores:item.scores}))};
  const contest=analyzeAiContestBundle([...sources,{file:'__newcyber_onnx_runs__.json',text:JSON.stringify(synthetic)}],analysis,analysis.aiPreprocessingManifest||null);
  const status=contest.status==='verified'?'verified':'ranked';
  return{...base,status,mode:executed.mode,model:modelInfo.file.path,runs:executed.runs.length,errors:executed.errors.slice(0,64),bridge:{outputNames:bridge.bridge.outputNames,providers:bridge.bridge.providers,candidateSets:bridge.ranking.candidateSets.slice(0,64)},contest,gap:null};
}

module.exports={dtypeToTensorType,npyTensorSpec,adaptDimsToModel,labelFromPath,idFromPath,discoverExplicitFeedBundle,runChallengeOnnxAutopilot};
