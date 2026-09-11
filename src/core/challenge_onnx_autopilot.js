'use strict';

const fs=require('fs/promises');
const path=require('path');
const {parseNpyAdvanced}=require('./model_artifacts');
const {runtimeStatus,runOnnxModel}=require('./local_ml_runtime');
const {rankAdversarialContestFromOnnxRuns}=require('./ai_adversarial_onnx_bridge');
const {discoverJsonMaterial,discoverTextHints,analyzeAiContestBundle}=require('./ai_contest_bundle_autopilot');
const {decodePng,preprocessDecodedImage,MAX_IMAGE_BYTES,MAX_IMAGE_PIXELS}=require('./ai_image_preprocess_executor');
const {selectOnnxModel}=require('./challenge_onnx_model_selector');
const {buildCandidateIndex,candidateIdentity}=require('./challenge_candidate_index');
const {verifyCandidateSets}=require('./challenge_candidate_verifier');
const {normalizeScoreSpace}=require('./challenge_score_space');
const {discoverConstantInputBindings,inputPlanView}=require('./challenge_onnx_input_bindings');

const MAX_NPY_BYTES=128*1024*1024;
const MAX_CANDIDATES=512;
const MAX_SOURCE_FILES=48;
const MAX_SOURCE_BYTES=2*1024*1024;
const MAX_TOTAL_SOURCE_BYTES=12*1024*1024;
const IMAGE_EXTENSIONS=new Set(['.png','.jpg','.jpeg','.bmp','.webp']);
const HINT_KEYS=['hints','hintPairs','transitions','hint_pairs'];

function list(value){return Array.isArray(value)?value:[];}
function inside(root,target){const rel=path.relative(path.resolve(root),path.resolve(target));return rel===''||(!rel.startsWith(`..${path.sep}`)&&rel!=='..'&&!path.isAbsolute(rel));}

function dtypeToTensorType(descr){
  const value=String(descr||'');if(value.startsWith('>'))return null;const normalized=value.replace(/^=/,'<');
  const map={'<f4':'float32','|f4':'float32','<f8':'float64','|f8':'float64','|i1':'int8','<i1':'int8','|u1':'uint8','<u1':'uint8','<i2':'int16','<u2':'uint16','<i4':'int32','<u4':'uint32','<i8':'int64','<u8':'uint64','|b1':'bool','|?1':'bool'};
  return map[normalized]||null;
}
function npyTensorSpec(buffer,fileName='candidate.npy'){
  const meta=parseNpyAdvanced(buffer);if(!meta||!meta.valid)throw new Error(`${fileName}: NPY header/size validation failed`);if(meta.objectDtype)throw new Error(`${fileName}: object dtype is not executable`);if(meta.fortranOrder)throw new Error(`${fileName}: Fortran-order NPY is not auto-executed`);if(!Array.isArray(meta.shape)||!meta.shape.length)throw new Error(`${fileName}: scalar/unknown NPY shape is not supported`);
  const type=dtypeToTensorType(meta.descr);if(!type)throw new Error(`${fileName}: unsupported or big-endian dtype ${meta.descr}`);const payload=buffer.subarray(meta.payloadOffset);
  return{type,dims:meta.shape.slice(),base64:payload.toString('base64'),npy:{descr:meta.descr,shape:meta.shape.slice(),payloadBytes:meta.payloadBytes}};
}
function staticDimension(value){if(Number.isInteger(Number(value))&&Number(value)>0)return Number(value);return null;}
function dimsCompatible(specDims,modelDims){if(!Array.isArray(modelDims)||!modelDims.length)return true;if(specDims.length!==modelDims.length)return false;return specDims.every((value,index)=>{const expected=staticDimension(modelDims[index]);return expected===null||expected===Number(value);});}
function adaptDimsToModel(spec,metadata){
  const modelDims=metadata?.dimensions;if(!Array.isArray(modelDims)||!modelDims.length)return{...spec,dims:spec.dims.slice(),adaptation:'metadata-unavailable'};if(dimsCompatible(spec.dims,modelDims))return{...spec,dims:spec.dims.slice(),adaptation:'exact-shape'};
  if(modelDims.length===spec.dims.length+1){const first=staticDimension(modelDims[0]);const expanded=[1,...spec.dims];if((first===null||first===1)&&dimsCompatible(expanded,modelDims))return{...spec,dims:expanded,adaptation:'prepend-batch-1'};}
  throw new Error(`NPY shape ${JSON.stringify(spec.dims)} incompatible with model input ${JSON.stringify(modelDims)}`);
}

function labelToken(value){if(typeof value==='number')return Number.isFinite(value);if(typeof value==='string'){const v=value.trim();return v.length>0&&v.length<=256;}return false;}
function safeHintPair(row){
  if(Array.isArray(row)&&row.length>=2&&row.length<=4)return labelToken(row[0])&&labelToken(row[1]);
  if(!row||typeof row!=='object'||Array.isArray(row))return false;const a=row.originLabel??row.origin??row.from,b=row.adversarialLabel??row.targetLabel??row.target??row.to;return labelToken(a)&&labelToken(b);
}
function normalizedHint(row){if(Array.isArray(row))return[row[0],row[1]];return[row.originLabel??row.origin??row.from,row.adversarialLabel??row.targetLabel??row.target??row.to];}
function discoverNamedJsonHints(file,text){
  let root;try{root=JSON.parse(text);}catch{return[];}const out=[];const queue=[root];let seen=0;
  while(queue.length&&seen++<4000){const node=queue.shift();if(!node||typeof node!=='object')continue;if(Array.isArray(node)){queue.push(...node.slice(0,4000-seen));continue;}for(const key of HINT_KEYS){const rows=node[key];if(Array.isArray(rows)&&rows.length&&rows.length<=256&&rows.every(safeHintPair))out.push({file,source:`${key}-scalar-labels`,rows:rows.map(normalizedHint)});}queue.push(...Object.values(node));}
  return out;
}
function hintRowsFromSources(sources){
  const sets=[];const seen=new Set();const add=(file,rows,source)=>{if(!Array.isArray(rows)||!rows.length)return;const key=JSON.stringify(rows);if(seen.has(key))return;seen.add(key);sets.push({file,source,rows});};
  for(const item of sources){const json=discoverJsonMaterial(item.file,item.text);for(const row of json.hints)add(row.file,row.rows,row.source);for(const row of discoverNamedJsonHints(item.file,item.text))add(row.file,row.rows,row.source);for(const row of discoverTextHints(item.file,item.text))add(row.file,row.rows,row.source);}return sets;
}
function targetLabels(hints){return new Set(hints.map((row)=>String(Array.isArray(row)?row[1]:(row.adversarialLabel??row.targetLabel??row.target??row.to))));}
function labelFromPath(relativePath,hints){const targets=targetLabels(hints);const parts=String(relativePath||'').split(/[\\/]/).slice(0,-1).reverse();for(const part of parts)if(targets.has(String(part)))return part;return null;}
function idFromPath(relativePath){const base=path.basename(String(relativePath||''));const match=base.match(/^(\d+)(?:\.[^.]+)?$/);return match?Number(match[1]):relativePath;}
function identityFor(relativePath,hints,index=null){const recovered=index?candidateIdentity(relativePath,index,hints):null;if(recovered)return recovered;const label=labelFromPath(relativePath,hints);return label===null?null:{label,id:null,source:'parent-folder',sourceFile:null,mappedFile:null};}
function chooseHintSet(sets,candidatePaths,index=null){if(!sets.length)return null;return sets.map((set)=>{let matches=0;for(const file of candidatePaths)if(identityFor(file,set.rows,index)!==null)matches+=1;return{...set,matches};}).sort((a,b)=>b.matches-a.matches||b.rows.length-a.rows.length||a.file.localeCompare(b.file))[0];}

async function collectSources(root,analysis){
  const allowed=new Set(['.py','.pyw','.js','.mjs','.cjs','.ts','.json','.jsonl','.ndjson','.csv','.tsv','.txt','.md','.yaml','.yml','.toml','.ini','.cfg']);const rows=[];let total=0;
  for(const file of list(analysis.files)){if(rows.length>=MAX_SOURCE_FILES||total>=MAX_TOTAL_SOURCE_BYTES)break;const ext=String(file.extension||path.extname(file.path||'')).toLowerCase();if(!allowed.has(ext))continue;const target=path.resolve(root,String(file.path||''));if(!inside(root,target))continue;let stat;try{stat=await fs.lstat(target);}catch{continue;}if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>MAX_SOURCE_BYTES||total+stat.size>MAX_TOTAL_SOURCE_BYTES)continue;let body;try{body=await fs.readFile(target,'utf8');}catch{continue;}total+=Buffer.byteLength(body);rows.push({file:file.path,text:body});}
  return rows;
}
function npyFiles(analysis){return list(analysis.files).filter((file)=>String(file.extension||path.extname(file.path||'')).toLowerCase()==='.npy');}
function imageFiles(analysis){return list(analysis.files).filter((file)=>IMAGE_EXTENSIONS.has(String(file.extension||path.extname(file.path||'')).toLowerCase()));}

function safeFeedSpec(value){if(!value||typeof value!=='object'||Array.isArray(value))return false;if(!Array.isArray(value.dims)||!value.dims.length||value.dims.some((x)=>!Number.isSafeInteger(Number(x))||Number(x)<0))return false;const hasValues=Array.isArray(value.values)||ArrayBuffer.isView(value.values);const hasBase64=typeof value.base64==='string'&&value.base64.length>0;return typeof value.type==='string'&&(hasValues||hasBase64);}
function discoverExplicitFeedBundle(sources){
  for(const source of sources){let root;try{root=JSON.parse(source.text);}catch{continue;}const queue=[root];let seen=0;while(queue.length&&seen++<2000){const value=queue.shift();if(!value||typeof value!=='object')continue;if(Array.isArray(value)){queue.push(...value.slice(0,2000-seen));continue;}const hints=value.hints??value.hintPairs??value.transitions;const candidates=value.candidates??value.samples??value.runs;if(Array.isArray(hints)&&hints.length&&Array.isArray(candidates)&&candidates.length&&candidates.length<=MAX_CANDIDATES){const valid=candidates.every((candidate)=>candidate&&typeof candidate==='object'&&candidate.feeds&&typeof candidate.feeds==='object'&&Object.values(candidate.feeds).every(safeFeedSpec));if(valid)return{file:source.file,hints,candidates,outputName:value.outputName||null};}queue.push(...Object.values(value));}}
  return null;
}

async function probeNpyDims(root,files,hintSet,candidateIndex=null){
  const errors=[];for(const file of files.slice(0,Math.min(MAX_CANDIDATES,32))){if(hintSet&&identityFor(file.path,hintSet.rows,candidateIndex)===null)continue;const target=path.resolve(root,file.path);if(!inside(root,target))continue;try{const stat=await fs.lstat(target);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>MAX_NPY_BYTES)continue;const raw=npyTensorSpec(await fs.readFile(target),file.path);return{dims:raw.dims,file:file.path,errors};}catch(error){errors.push({file:file.path,error:String(error?.message||error).slice(0,220)});}}
  return{dims:null,file:null,errors};
}
function modelSelectionView(modelInfo){if(!modelInfo?.selection)return null;return{method:modelInfo.selection.method,score:modelInfo.selection.score,margin:modelInfo.selection.margin??null,reasons:modelInfo.selection.reasons||[],alternatives:modelInfo.selection.alternatives||[]};}
function chosenPrimaryInput(modelInfo){
  const name=modelInfo?.inputPlan?.ok?modelInfo.inputPlan.primaryInputName:null;if(name){const found=modelInfo.model.inputs.find((item)=>item.name===name);if(found)return found;}
  if(modelInfo?.model?.inputs?.length===1)return modelInfo.model.inputs[0];return null;
}
function mergeAutomaticFeeds(modelInfo,primaryName,primarySpec){return{...(modelInfo?.inputPlan?.auxiliaryFeeds||{}),[primaryName]:primarySpec};}

async function runExplicitBundle(modelInfo,bundle,options={}){
  const inputNames=modelInfo.model.inputs.map((item)=>item.name);const execute=options.runModel||runOnnxModel;const runs=[];const errors=[];
  for(let index=0;index<bundle.candidates.length;index+=1){const candidate=bundle.candidates[index];const feedNames=Object.keys(candidate.feeds||{});if(inputNames.some((name)=>!feedNames.includes(name))){errors.push({id:candidate.id??index,error:'explicit feeds do not cover all model inputs'});continue;}try{const run=await execute(modelInfo.target,{feeds:candidate.feeds,outputs:bundle.outputName?[bundle.outputName]:undefined},{provider:'cpu'});runs.push({id:candidate.id??candidate.file??candidate.name??index,assignedLabel:candidate.assignedLabel??candidate.folderLabel??candidate.bucketLabel??candidate.classLabel,run,outputName:bundle.outputName||undefined});}catch(error){errors.push({id:candidate.id??index,error:String(error?.message||error).slice(0,260)});}}
  return{runs,errors,mode:'explicit-feeds'};
}
async function runNpyBundle(root,analysis,modelInfo,hintSet,options={}){
  const input=chosenPrimaryInput(modelInfo);if(!input)return{runs:[],errors:[{error:'auto NPY mode could not resolve exactly one primary candidate input'}],mode:'npy'};const execute=options.runModel||runOnnxModel;const files=npyFiles(analysis).slice(0,MAX_CANDIDATES);const runs=[];const errors=[];const candidateIndex=options.candidateIndex||null;
  for(const file of files){const identity=identityFor(file.path,hintSet.rows,candidateIndex);if(!identity)continue;const assignedLabel=identity.label;const target=path.resolve(root,file.path);if(!inside(root,target))continue;try{const stat=await fs.lstat(target);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>MAX_NPY_BYTES)throw new Error(`NPY size ${stat.size} outside auto-run limit`);const raw=npyTensorSpec(await fs.readFile(target),file.path);const spec=adaptDimsToModel(raw,input.metadata);const feeds=mergeAutomaticFeeds(modelInfo,input.name,{type:spec.type,dims:spec.dims,base64:spec.base64});const run=await execute(modelInfo.target,{feeds},{provider:'cpu'});runs.push({id:identity.id??idFromPath(file.path),file:file.path,assignedLabel,run,labelEvidence:{source:identity.source,sourceFile:identity.sourceFile||null},inputEvidence:{primary:input.name,auxiliary:modelInfo.inputPlan?.auxiliaryInputNames||[]},npy:{descr:raw.npy.descr,shape:raw.npy.shape,adaptation:spec.adaptation}});}catch(error){errors.push({file:file.path,error:String(error?.message||error).slice(0,300)});}}
  return{runs,errors,mode:'npy'};
}

function normalizeDecodedImage(value,file){if(!value||!Number.isSafeInteger(Number(value.width))||!Number.isSafeInteger(Number(value.height)))throw new Error(`${file}: decoder 未返回 width/height`);const width=Number(value.width),height=Number(value.height);if(width<=0||height<=0||width*height>MAX_IMAGE_PIXELS)throw new Error(`${file}: decoded image 像素数超限`);const rgba=value.rgba instanceof Uint8Array?value.rgba:Buffer.isBuffer(value.rgba)?new Uint8Array(value.rgba):null;if(!rgba||rgba.length!==width*height*4)throw new Error(`${file}: decoder RGBA 长度不匹配`);return{schema:'newcyber.decoded-image.v1',width,height,rgba:new Uint8Array(rgba),source:value.source||{format:'injected-decoder'}};}
async function decodeCandidateImage(target,file,options={}){const stat=await fs.lstat(target);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>MAX_IMAGE_BYTES)throw new Error(`${file}: image size ${stat.size} outside auto-run limit`);const buffer=await fs.readFile(target);const ext=path.extname(file).toLowerCase();if(ext==='.png'){try{return decodePng(buffer);}catch(error){if(typeof options.decodeImage!=='function')throw error;}}if(typeof options.decodeImage!=='function')throw new Error(`${file}: ${ext||'image'} 需要受控图片解码器`);return normalizeDecodedImage(await options.decodeImage({path:target,file,buffer,extension:ext,maxPixels:MAX_IMAGE_PIXELS}),file);}
async function runImageBundle(root,analysis,modelInfo,hintSet,options={}){
  const input=chosenPrimaryInput(modelInfo);if(!input)return{runs:[],errors:[{error:'auto image mode could not resolve exactly one primary candidate input'}],mode:'image'};const manifest=analysis.aiPreprocessingManifest;if(!manifest||manifest.status!=='ready'||manifest.executionReady!==true)return{runs:[],errors:[{error:`preprocessing manifest is ${manifest?.status||'missing'}`}],mode:'image'};const execute=options.runModel||runOnnxModel;const files=imageFiles(analysis).slice(0,MAX_CANDIDATES);const runs=[];const errors=[];const candidateIndex=options.candidateIndex||null;
  for(const file of files){const identity=identityFor(file.path,hintSet.rows,candidateIndex);if(!identity)continue;const assignedLabel=identity.label;const target=path.resolve(root,file.path);if(!inside(root,target))continue;try{const decoded=await decodeCandidateImage(target,file.path,options);const tensor=preprocessDecodedImage(decoded,manifest,input.metadata);const feeds=mergeAutomaticFeeds(modelInfo,input.name,{type:tensor.type,dims:tensor.dims,base64:tensor.base64});const run=await execute(modelInfo.target,{feeds},{provider:'cpu'});runs.push({id:identity.id??idFromPath(file.path),file:file.path,assignedLabel,run,labelEvidence:{source:identity.source,sourceFile:identity.sourceFile||null},inputEvidence:{primary:input.name,auxiliary:modelInfo.inputPlan?.auxiliaryInputNames||[]},image:{width:decoded.width,height:decoded.height,tensorDims:tensor.dims,adaptation:tensor.adaptation,backend:tensor.backend,trace:tensor.trace}});}catch(error){errors.push({file:file.path,error:String(error?.message||error).slice(0,360)});}}
  return{runs,errors,mode:'image'};
}

function mergeAdvancedVerification(contest,verification){
  if(!verification||verification.status!=='verified'||contest?.status==='verified')return contest;const match=verification.matches[0];if(!match)return contest;
  const finding={id:'ai-contest-evidence-recipe-verifier-match',severity:'high',title:'候选集合命中源码恢复的 verifier recipe',file:match.spec.file,evidence:`${match.spec.algorithm}(${match.spec.serialization}) => ${match.digest}`,meaning:'序列化方式、hash 算法与目标 digest 都由题目源码证据恢复，候选集合已完成独立 verifier 闭环。'};
  return{...contest,status:'verified',result:{value:match.submission,verified:true,confidence:'verified',source:`${match.spec.algorithm}/${match.spec.serialization} verifier`,ids:match.ids,serialized:match.serialized,digest:match.digest},findings:[...(contest?.findings||[]),finding],verifierMatches:[...(contest?.verifierMatches||[]),{rank:match.rank,ids:match.ids,serialized:match.serialized,submission:match.submission,verifier:{file:match.spec.file,algorithm:match.spec.algorithm,digest:match.spec.digest,serialization:match.spec.serialization}}]};
}
function bindingSummary(bindings){return{status:bindings.status,evidence:bindings.evidence||[],conflicts:bindings.conflicts||[],errors:bindings.errors||[],names:Object.keys(bindings.bindings||{})};}

async function runChallengeOnnxAutopilot(rootPath,analysis,options={}){
  const root=path.resolve(String(rootPath||''));const sources=await collectSources(root,analysis);const candidateIndex=buildCandidateIndex(sources);const inputBindings=discoverConstantInputBindings(sources);const explicit=discoverExplicitFeedBundle(sources);const npys=npyFiles(analysis);const images=imageFiles(analysis);const hintSets=hintRowsFromSources(sources);const candidatePaths=[...npys,...images].map((x)=>x.path);const hintSet=chooseHintSet(hintSets,candidatePaths,candidateIndex);const npyEligible=hintSet?npys.some((file)=>identityFor(file.path,hintSet.rows,candidateIndex)!==null):false;const imageEligible=hintSet?images.some((file)=>identityFor(file.path,hintSet.rows,candidateIndex)!==null):false;const inputBindingsView=bindingSummary(inputBindings);
  if(!explicit&&!npyEligible&&!imageEligible){const code=!candidatePaths.length?'CANDIDATES_MISSING':!hintSet?'HINTS_MISSING':'CANDIDATE_LABEL_MAPPING_MISSING';return{schema:'newcyber.challenge-onnx-autopilot.v6',runtime:{available:null,source:null,version:null},status:'not-applicable',mode:null,model:null,modelSelection:null,inputBindings:inputBindingsView,inputPlan:null,candidateIndex:candidateIndex.stats,scoreSpace:null,verifier:null,runs:0,errors:[],contest:null,gap:{code,detail:'need explicit feed bundle or recoverable candidate labels plus hint pairs'}};}
  const mode=explicit?'explicit-feeds':npyEligible?'npy':'image';
  if(mode!=='explicit-feeds'&&inputBindings.status==='conflict')return{schema:'newcyber.challenge-onnx-autopilot.v6',runtime:{available:null,source:null,version:null},status:'gap',mode,model:null,modelSelection:null,inputBindings:inputBindingsView,inputPlan:null,candidateIndex:candidateIndex.stats,scoreSpace:null,verifier:null,runs:0,errors:[],contest:null,gap:{code:'INPUT_BINDING_CONFLICT',detail:'multiple explicit JSON sources disagree on auxiliary ONNX input values',conflicts:inputBindings.conflicts}};
  if(mode==='image'&&(analysis.aiPreprocessingManifest?.status!=='ready'||analysis.aiPreprocessingManifest?.executionReady!==true)){const m=analysis.aiPreprocessingManifest;return{schema:'newcyber.challenge-onnx-autopilot.v6',runtime:{available:null,source:null,version:null},status:'gap',mode,model:null,modelSelection:null,inputBindings:inputBindingsView,inputPlan:null,candidateIndex:candidateIndex.stats,scoreSpace:null,verifier:null,runs:0,errors:[],contest:null,gap:{code:'PREPROCESSING_NOT_READY',detail:`image candidates found but preprocessing manifest=${m?.status||'missing'}`,missing:m?.missing||[],conflicts:(m?.conflicts||[]).map((x)=>x.kind)}};}
  const runtime=(options.runtimeStatus||runtimeStatus)();const base={schema:'newcyber.challenge-onnx-autopilot.v6',runtime:{available:runtime.available,source:runtime.source||null,version:runtime.version||null},status:'not-applicable',mode,model:null,modelSelection:null,inputBindings:inputBindingsView,inputPlan:null,candidateIndex:candidateIndex.stats,scoreSpace:null,verifier:null,runs:0,errors:[],contest:null,gap:null};if(!runtime.available)return{...base,status:'gap',gap:{code:'MODEL_RUNTIME_GAP',detail:runtime.installHint||runtime.error||'onnxruntime-node unavailable'}};
  const npyProbe=mode==='npy'?await probeNpyDims(root,npys,hintSet,candidateIndex):{dims:null,file:null,errors:[]};const context={mode,explicitBundle:explicit,npyDims:npyProbe.dims,manifest:analysis.aiPreprocessingManifest||null,inputBindings};
  let modelInfo;try{modelInfo=await selectOnnxModel(root,analysis,context,{inspectModel:options.inspectModel});}catch(error){return{...base,status:'gap',errors:npyProbe.errors,gap:{code:'MODEL_INSPECTION_FAILED',detail:String(error?.message||error).slice(0,400)}};}
  if(!modelInfo.ok)return{...base,status:'gap',errors:[...(npyProbe.errors||[]),...(modelInfo.errors||[])].slice(0,64),gap:{code:modelInfo.code,detail:modelInfo.detail,models:modelInfo.models||null,candidates:modelInfo.candidates||null}};
  const selection=modelSelectionView(modelInfo),planView=inputPlanView(modelInfo.inputPlan);const runOptions={...options,candidateIndex};let executed;try{if(mode==='explicit-feeds')executed=await runExplicitBundle(modelInfo,explicit,runOptions);else if(mode==='npy')executed=await runNpyBundle(root,analysis,modelInfo,hintSet,runOptions);else executed=await runImageBundle(root,analysis,modelInfo,hintSet,runOptions);}catch(error){return{...base,status:'gap',model:modelInfo.file.path,modelSelection:selection,inputPlan:planView,gap:{code:'INFERENCE_FAILED',detail:String(error?.message||error).slice(0,400)}};}
  const rawHints=explicit?.hints||hintSet?.rows;if(!executed.runs.length)return{...base,status:'gap',model:modelInfo.file.path,modelSelection:selection,inputPlan:planView,errors:executed.errors.slice(0,64),gap:{code:'NO_SUCCESSFUL_INFERENCE',detail:'no candidate produced a complete ONNX classification output'}};
  const scoreSpace=normalizeScoreSpace(rawHints,executed.runs,candidateIndex);const scoreSpaceView={status:scoreSpace.status,mapping:scoreSpace.mapping,unresolved:scoreSpace.unresolved};
  if(scoreSpace.status!=='ready')return{...base,status:'gap',model:modelInfo.file.path,modelSelection:selection,inputPlan:planView,scoreSpace:scoreSpaceView,runs:executed.runs.length,errors:[...(npyProbe.errors||[]),...executed.errors].slice(0,64),gap:{code:'LABEL_SPACE_UNRESOLVED',detail:'hint/assigned labels cannot be mapped to ONNX score indices',unresolved:scoreSpace.unresolved}};
  let bridge;try{bridge=rankAdversarialContestFromOnnxRuns({hints:scoreSpace.hints,runs:scoreSpace.runs,outputName:explicit?.outputName||undefined,shortlistSize:3,beamWidth:3,maxSets:256});}catch(error){return{...base,status:'gap',model:modelInfo.file.path,modelSelection:selection,inputPlan:planView,scoreSpace:scoreSpaceView,runs:executed.runs.length,errors:executed.errors.slice(0,64),gap:{code:'RANKING_FAILED',detail:String(error?.message||error).slice(0,400)}};}
  if(!bridge.ranking.candidateSets.length)return{...base,status:'gap',model:modelInfo.file.path,modelSelection:selection,inputPlan:planView,scoreSpace:scoreSpaceView,runs:executed.runs.length,errors:[...(npyProbe.errors||[]),...executed.errors].slice(0,64),gap:{code:'NO_RANKED_CANDIDATE_SET',detail:'model inference succeeded but no hint group produced a complete candidate set',findings:bridge.ranking.findings}};
  const synthetic={hints:scoreSpace.hints,candidates:bridge.bundle.candidates.map((item)=>({id:item.id,assignedLabel:item.assignedLabel,scores:item.scores}))};let contest=analyzeAiContestBundle([...sources,{file:'__newcyber_onnx_runs__.json',text:JSON.stringify(synthetic)}],analysis,analysis.aiPreprocessingManifest||null);const verifier=verifyCandidateSets(bridge.ranking.candidateSets,sources);contest=mergeAdvancedVerification(contest,verifier);const status=contest.status==='verified'?'verified':'ranked';
  return{...base,status,model:modelInfo.file.path,modelSelection:selection,inputPlan:planView,scoreSpace:scoreSpaceView,verifier:{status:verifier.status,specs:verifier.specs.slice(0,16),matches:verifier.matches.slice(0,16)},runs:executed.runs.length,errors:[...(npyProbe.errors||[]),...executed.errors].slice(0,64),bridge:{outputNames:bridge.bridge.outputNames,providers:bridge.bridge.providers,candidateSets:bridge.ranking.candidateSets.slice(0,128)},contest,gap:null};
}

module.exports={dtypeToTensorType,npyTensorSpec,adaptDimsToModel,labelToken,safeHintPair,discoverNamedJsonHints,hintRowsFromSources,labelFromPath,idFromPath,identityFor,chooseHintSet,collectSources,npyFiles,imageFiles,discoverExplicitFeedBundle,probeNpyDims,chosenPrimaryInput,mergeAutomaticFeeds,decodeCandidateImage,runExplicitBundle,runNpyBundle,runImageBundle,mergeAdvancedVerification,runChallengeOnnxAutopilot};
