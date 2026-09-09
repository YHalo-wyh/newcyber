'use strict';

const fs=require('fs/promises');
const path=require('path');
const {readNpyHeaderPath,extractWindowFeatures,inspectScaSource}=require('./power_side_channel');
const {runtimeStatus,withSession,tensorFromSpec}=require('./local_ml_runtime');
const {classifyTransformerSession,runTransformerDecode}=require('./transformer_oracle');
const {fitLeakageProfile,recoverProbeCandidates}=require('./side_channel_probe');
const {createGpt2Bpe}=require('./gpt2_bpe');

const MAX_FILES=256;
const MAX_SOURCE_BYTES=2*1024*1024;
const MAX_ARRAY_VALUES=12_000_000;
const MAX_PROFILE_ROWS=8192;
const MAX_TOTAL_PROFILE_TOKENS=262144;
const MAX_TOKEN_SEQUENCE=65536;
const MAX_VOCAB_BYTES=32*1024*1024;
const MAX_MERGES_BYTES=16*1024*1024;
const MANIFEST_NAMES=new Set(['newcyber_sca.json','sca_recipe.json','sca-recipe.json']);
const TEXT_EXT=new Set(['.py','.pyw','.txt','.md','.json','.toml','.yaml','.yml']);
const ROLE_EXT=new Set(['.npy','.onnx','.safetensors',...TEXT_EXT]);

function gap(code,detail,stage='discover',extra={}){
  return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code,detail,stage},stages:[{id:stage,status:'gap',detail}],...extra};
}

function resolved(value){return path.resolve(String(value||''));}
function sameOrInside(root,target){const r=resolved(root);const t=resolved(target);return t===r||t.startsWith(r+path.sep);}

async function checkedFile(filePath){
  const target=resolved(filePath);
  const stat=await fs.stat(target);
  if(!stat.isFile())throw new Error(`${path.basename(target)} 不是普通文件`);
  return {filePath:target,fileName:path.basename(target),size:stat.size,extension:path.extname(target).toLowerCase()};
}

function uniqueFiles(items){
  const seen=new Set();const out=[];
  for(const item of items||[]){const key=resolved(item);if(seen.has(key))continue;seen.add(key);out.push(key);if(out.length>MAX_FILES)throw new Error(`SCA bundle 文件超过 ${MAX_FILES} 上限`);}
  return out;
}

async function readSourceText(files){
  let total=0;const chunks=[];
  for(const file of files){
    if(!TEXT_EXT.has(file.extension)||MANIFEST_NAMES.has(file.fileName.toLowerCase()))continue;
    if(file.size<=0||file.size>MAX_SOURCE_BYTES)continue;
    if(total+file.size>MAX_SOURCE_BYTES)break;
    total+=file.size;
    chunks.push(`\n# --- ${file.fileName} ---\n${await fs.readFile(file.filePath,'utf8')}`);
  }
  return chunks.join('\n').slice(0,MAX_SOURCE_BYTES);
}

async function parseManifest(files){
  const candidates=files.filter((file)=>MANIFEST_NAMES.has(file.fileName.toLowerCase()));
  if(candidates.length>1)return {status:'ambiguous',files:candidates.map((x)=>x.fileName)};
  if(!candidates.length)return {status:'none',manifest:null,file:null};
  const file=candidates[0];
  if(file.size<=0||file.size>1024*1024)return {status:'invalid',error:'SCA recipe manifest 大小异常',file:file.fileName};
  try{
    const manifest=JSON.parse(await fs.readFile(file.filePath,'utf8'));
    if(!manifest||typeof manifest!=='object'||Array.isArray(manifest))throw new Error('manifest 必须是 JSON object');
    return {status:'ok',manifest,file};
  }catch(error){return {status:'invalid',error:error?.message||String(error),file:file.fileName};}
}

function scoreRole(file,role){
  const name=file.fileName.toLowerCase();const stem=name.replace(/\.[^.]+$/,'');
  const isNpy=file.extension==='.npy';
  if(role==='profileTrace'&&isNpy&&/(profil|train|reference|known)/.test(stem)&&/(trace|power|leak)/.test(stem))return 10;
  if(role==='targetTrace'&&isNpy&&/(target|attack|unknown|challenge|victim|test)/.test(stem)&&/(trace|power|leak)/.test(stem))return 10;
  if(role==='profileTokenIds'&&isNpy&&/(profil|train|known|reference)/.test(stem)&&/(token|input).*(?:id|ids)|(?:id|ids).*(token|input)/.test(stem))return 10;
  if(role==='promptTokenIds'&&isNpy&&/(prompt|prefix|seed)/.test(stem)&&/(token|input).*(?:id|ids)|(?:id|ids).*(token|input)/.test(stem))return 10;
  if(role==='candidateIds'&&isNpy&&/(candidate|vocab|token).*(?:id|ids)|(?:id|ids).*(candidate|vocab|token)/.test(stem))return 9;
  if(role==='probe'&&isNpy&&/(probe|lm[_-]?head|decoder.*weight|output.*weight)/.test(stem))return 10;
  if(role==='model'&&file.extension==='.onnx')return /(?:model|gpt|transformer|oracle|lm)/.test(stem)?10:6;
  return 0;
}

function uniqueRole(files,role){
  const ranked=files.map((file)=>({file,score:scoreRole(file,role)})).filter((x)=>x.score>0).sort((a,b)=>b.score-a.score||a.file.fileName.localeCompare(b.file.fileName));
  if(!ranked.length)return {status:'missing',file:null};
  const top=ranked[0].score;const tied=ranked.filter((x)=>x.score===top);
  if(tied.length>1)return {status:'ambiguous',files:tied.map((x)=>x.file.fileName),score:top};
  return {status:'ok',file:ranked[0].file,score:top};
}

function manifestRole(manifestFile,manifest,selectedMap,key){
  const value=manifest?.[key];
  if(value==null)return {status:'missing',file:null};
  if(typeof value!=='string'||!value.trim())return {status:'invalid',error:`manifest ${key} 必须是相对文件名`};
  const target=resolved(path.join(path.dirname(manifestFile.filePath),value));
  if(!sameOrInside(path.dirname(manifestFile.filePath),target))return {status:'invalid',error:`manifest ${key} 路径越界`};
  const file=selectedMap.get(target);
  if(!file)return {status:'invalid',error:`manifest ${key}=${value} 不在已选择 SCA bundle 内`};
  return {status:'ok',file};
}

async function discoverScaArtifacts(filePaths,options={}){
  const paths=uniqueFiles(filePaths);
  const files=[];
  for(const p of paths){
    try{const file=await checkedFile(p);if(ROLE_EXT.has(file.extension))files.push(file);}catch(error){if(options.strict!==false)throw error;}
  }
  if(!files.length)return {status:'gap',code:'ARTIFACT_ROLE_GAP',detail:'没有可识别的 SCA 工件',files:[]};
  const manifestState=await parseManifest(files);
  if(manifestState.status==='ambiguous')return {status:'gap',code:'RECIPE_AMBIGUITY_GAP',detail:`发现多个 SCA recipe：${manifestState.files.join(', ')}`,files};
  if(manifestState.status==='invalid')return {status:'gap',code:'RECIPE_INVALID_GAP',detail:`${manifestState.file}: ${manifestState.error}`,files};
  const selectedMap=new Map(files.map((file)=>[file.filePath,file]));
  const manifest=manifestState.manifest;
  const sourceText=await readSourceText(files);
  const sourceInspection=inspectScaSource(sourceText);
  const roles={};
  for(const role of ['profileTrace','targetTrace','profileTokenIds','promptTokenIds','candidateIds','probe','model']){
    roles[role]=manifest?manifestRole(manifestState.file,manifest,selectedMap,role):uniqueRole(files,role);
  }
  const safetensors=files.filter((file)=>file.extension==='.safetensors');
  return {status:'ok',files,manifest,manifestFile:manifestState.file||null,roles,safetensors,sourceText,sourceInspection};
}

function readNumber(buffer,offset,descriptor){
  const little=descriptor.endian!=='>';
  if(descriptor.kind==='f')return descriptor.bytes===4?(little?buffer.readFloatLE(offset):buffer.readFloatBE(offset)):(little?buffer.readDoubleLE(offset):buffer.readDoubleBE(offset));
  if(descriptor.kind==='i'){
    if(descriptor.bytes===1)return buffer.readInt8(offset);
    if(descriptor.bytes===2)return little?buffer.readInt16LE(offset):buffer.readInt16BE(offset);
    if(descriptor.bytes===4)return little?buffer.readInt32LE(offset):buffer.readInt32BE(offset);
    const value=little?buffer.readBigInt64LE(offset):buffer.readBigInt64BE(offset);
    if(value<BigInt(Number.MIN_SAFE_INTEGER)||value>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('int64 NPY 超出 JS 安全整数范围');
    return Number(value);
  }
  if(descriptor.bytes===1)return buffer.readUInt8(offset);
  if(descriptor.bytes===2)return little?buffer.readUInt16LE(offset):buffer.readUInt16BE(offset);
  if(descriptor.bytes===4)return little?buffer.readUInt32LE(offset):buffer.readUInt32BE(offset);
  const value=little?buffer.readBigUInt64LE(offset):buffer.readBigUInt64BE(offset);
  if(value>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('uint64 NPY 超出 JS 安全整数范围');
  return Number(value);
}

async function readNumericNpyPath(filePath,options={}){
  const header=await readNpyHeaderPath(filePath);
  const maxValues=Math.min(MAX_ARRAY_VALUES,Math.max(1,Number(options.maxValues)||MAX_ARRAY_VALUES));
  if(header.elements>maxValues)return {status:'value-budget-gap',header,limit:maxValues};
  const raw=await fs.readFile(header.filePath);
  const payload=raw.subarray(header.payloadOffset);
  const values=Array(header.elements);
  for(let i=0;i<header.elements;i+=1){const value=readNumber(payload,i*header.descriptor.bytes,header.descriptor);if(!Number.isFinite(value))throw new Error(`${header.fileName} 包含 NaN/Inf`);values[i]=value;}
  let data=values;
  if(header.shape.length===2){
    const cols=header.shape[1];
    data=Array.from({length:header.shape[0]},(_,r)=>values.slice(r*cols,(r+1)*cols));
  }
  return {status:'ok',header,shape:header.shape.slice(),values,data};
}

function roleFile(discovery,key,required=true){
  const role=discovery.roles[key];
  if(role?.status==='ambiguous')return {gap:`${key} 候选不唯一：${role.files.join(', ')}`};
  if(role?.status==='invalid')return {gap:role.error||`${key} recipe 非法`};
  if(required&&role?.status!=='ok')return {gap:`缺少可证明的 ${key} 工件`};
  return {file:role?.status==='ok'?role.file:null};
}

function normalizeWindows(manifest){
  if(!Array.isArray(manifest?.windows)||!manifest.windows.length)return null;
  return manifest.windows.map((item,index)=>({id:String(item.id||`window-${index}`),offset:Number(item.offset),length:Number(item.length),metric:String(item.metric||'sum-squares')}));
}

async function leakageMatrix(file,discovery,role,options={}){
  const manifest=discovery.manifest||{};
  const featureMode=String(manifest.featureMode||options.featureMode||'').toLowerCase();
  const windows=normalizeWindows(manifest)||options.windows||null;
  if(windows){
    const samplesPerRow=Number(manifest.samplesPerRow||discovery.sourceInspection.samplesPerRow||0);
    if(!samplesPerRow)return {status:'gap',code:'TRACE_LAYOUT_GAP',detail:`${role}: windows 已定义但 samplesPerRow 无证据`};
    const result=await extractWindowFeatures(file.filePath,{samplesPerRow,windows});
    return {status:'ok',matrix:result.features,recipe:{mode:'windows',samplesPerRow,windows:result.windows},trace:result};
  }
  const npy=await readNumericNpyPath(file.filePath);
  if(npy.status!=='ok')return {status:'gap',code:'TRACE_VALUE_BUDGET_GAP',detail:`${role}: ${npy.header.fileName} values=${npy.header.elements} 超过 ${npy.limit}`};
  if(npy.shape.length!==2)return {status:'gap',code:'TRACE_LAYOUT_GAP',detail:`${role}: raw-row 特征要求二维 NPY，当前 shape=[${npy.shape.join(',')}]`};
  const explicitRaw=featureMode==='raw-row'||Number(manifest.leakageDim||0)===npy.shape[1]||Number(discovery.sourceInspection.constants?.LEAKAGE_DIM||0)===npy.shape[1]||Number(discovery.sourceInspection.constants?.FEATURE_DIM||0)===npy.shape[1];
  if(!explicitRaw)return {status:'gap',code:'FEATURE_RECIPE_GAP',detail:`${role}: 二维 trace 存在，但没有 raw-row / window 特征证据；不会默认把整行当 leakage vector`};
  return {status:'ok',matrix:npy.data,recipe:{mode:'raw-row',samplesPerRow:npy.shape[1]},trace:{shape:npy.shape,fileName:npy.header.fileName}};
}

async function tokenSequences(file,label){
  const npy=await readNumericNpyPath(file.filePath,{maxValues:MAX_TOTAL_PROFILE_TOKENS});
  if(npy.status!=='ok')return {status:'gap',code:'TOKEN_BUDGET_GAP',detail:`${label}: token IDs 超过预算`};
  if(!['i','u'].includes(npy.header.descriptor.kind))return {status:'gap',code:'TOKEN_DTYPE_GAP',detail:`${label}: token IDs 必须是整数 NPY`};
  let sequences;
  if(npy.shape.length===1)sequences=npy.values.map((id)=>[id]);
  else if(npy.shape.length===2)sequences=npy.data;
  else return {status:'gap',code:'TOKEN_LAYOUT_GAP',detail:`${label}: token IDs shape 必须是 [rows] 或 [rows,seq]`};
  for(const seq of sequences)for(const id of seq)if(!Number.isSafeInteger(id)||id<0)return {status:'gap',code:'TOKEN_VALUE_GAP',detail:`${label}: 包含非法 token id`};
  return {status:'ok',sequences};
}

async function promptTokens(discovery){
  const manifest=discovery.manifest||{};
  if(Array.isArray(manifest.promptTokenIds)){
    const ids=manifest.promptTokenIds.map(Number);
    if(!ids.length||ids.length>MAX_TOKEN_SEQUENCE||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',code:'PROMPT_TOKEN_GAP',detail:'manifest promptTokenIds 非法'};
    return {status:'ok',ids,source:'manifest'};
  }
  const role=roleFile(discovery,'promptTokenIds',false);
  if(role.gap)return {status:'gap',code:'PROMPT_TOKEN_GAP',detail:role.gap};
  if(!role.file)return {status:'gap',code:'PROMPT_TOKEN_GAP',detail:'缺少 prompt/prefix token IDs；自动链不会猜 BOS/prefix'};
  const read=await tokenSequences(role.file,'promptTokenIds');
  if(read.status!=='ok')return read;
  if(read.sequences.length!==1)return {status:'gap',code:'PROMPT_TOKEN_GAP',detail:'promptTokenIds 文件必须只描述一个 prompt sequence'};
  return {status:'ok',ids:read.sequences[0],source:role.file.fileName};
}

function tensorType(metadata,fallback='int64'){
  const type=String(metadata?.type||'').toLowerCase();
  if(type.includes('int64'))return'int64';if(type.includes('int32'))return'int32';if(type.includes('float'))return'float32';if(type.includes('bool'))return'bool';return fallback;
}

function emptyCacheSpec(item){
  const dims=Array.isArray(item.metadata?.dimensions)?item.metadata.dimensions.slice():[];
  const symbolic=Array.isArray(item.metadata?.symbolicDimensions)?item.metadata.symbolicDimensions.slice():[];
  if(!dims.length)return null;let zero=false;
  const resolvedDims=dims.map((raw,index)=>{if(Number.isInteger(raw)&&raw>=0)return raw;const label=String(symbolic[index]??raw??'').toLowerCase();if(/past|cache|sequence|seq/.test(label)){zero=true;return 0;}return 1;});
  if(!zero||resolvedDims.reduce((a,b)=>a*b,1)!==0)return null;
  return {type:tensorType(item.metadata,'float32'),dims:resolvedDims,values:[]};
}

function lastHidden(tensor){
  if(!tensor?.data||!Array.isArray(tensor.dims)||!tensor.dims.length)return null;
  const width=Number(tensor.dims[tensor.dims.length-1]);
  if(!Number.isSafeInteger(width)||width<=0||width>4096||tensor.data.length<width)return null;
  return Array.from(tensor.data.slice(tensor.data.length-width),Number);
}

async function captureProfileHiddenStates(model,sequences,options={}){
  if(!Array.isArray(sequences)||!sequences.length)return {status:'PROFILE_INPUT_GAP',detail:'profiling token sequences 为空'};
  if(sequences.length>MAX_PROFILE_ROWS)return {status:'PROFILE_ROW_BUDGET_GAP',detail:`profiling rows=${sequences.length} 超过 ${MAX_PROFILE_ROWS}`};
  const totalTokens=sequences.reduce((sum,row)=>sum+row.length,0);
  if(totalTokens>MAX_TOTAL_PROFILE_TOKENS)return {status:'TOKEN_BUDGET_GAP',detail:`profiling tokens=${totalTokens} 超过 ${MAX_TOTAL_PROFILE_TOKENS}`};
  return withSession(model,options,async(session,ort)=>{
    const recipe=classifyTransformerSession(session);
    if(!recipe.supported)return {status:'MODEL_RECIPE_GAP',detail:'无法唯一识别 Transformer input_ids/logits',recipe};
    if(!recipe.roles.hidden)return {status:'HIDDEN_STATE_OUTPUT_GAP',detail:'ONNX 没有可识别 hidden-state 输出',recipe};
    if(recipe.cache.mode==='unpaired')return {status:'CACHE_PAIR_GAP',detail:'模型 cache I/O 无法可靠配对',recipe};
    if(recipe.unknownInputs.length)return {status:'UNKNOWN_MODEL_INPUT_GAP',detail:`模型存在未识别必需输入：${recipe.unknownInputs.map((x)=>x.name).join(', ')}`,recipe};
    const hiddenStates=[];
    for(let rowIndex=0;rowIndex<sequences.length;rowIndex+=1){
      const ids=sequences[rowIndex];
      if(!ids.length||ids.length>MAX_TOKEN_SEQUENCE)return {status:'PROFILE_INPUT_GAP',detail:`profiling row ${rowIndex} token length 非法`,recipe};
      const feeds={};
      feeds[recipe.roles.inputIds.name]=tensorFromSpec(ort,{type:tensorType(recipe.roles.inputIds.metadata,'int64'),dims:[1,ids.length],values:ids});
      if(recipe.roles.attentionMask)feeds[recipe.roles.attentionMask.name]=tensorFromSpec(ort,{type:tensorType(recipe.roles.attentionMask.metadata,'int64'),dims:[1,ids.length],values:Array(ids.length).fill(1)});
      if(recipe.roles.positionIds)feeds[recipe.roles.positionIds.name]=tensorFromSpec(ort,{type:tensorType(recipe.roles.positionIds.metadata,'int64'),dims:[1,ids.length],values:Array.from({length:ids.length},(_,i)=>i)});
      for(const item of recipe.cache.inputs){const spec=emptyCacheSpec(item);if(!spec)return {status:'CACHE_INIT_GAP',detail:`无法证明 ${item.name} 的 zero-length cache 维`,recipe};feeds[item.name]=tensorFromSpec(ort,spec);}
      for(const name of session.inputNames)if(!feeds[name])return {status:'UNKNOWN_MODEL_INPUT_GAP',detail:`未构建模型输入 ${name}`,recipe};
      const output=await session.run(feeds,{[recipe.roles.hidden.name]:null});
      const hidden=lastHidden(output[recipe.roles.hidden.name]);
      if(!hidden)return {status:'HIDDEN_STATE_OUTPUT_GAP',detail:`profiling row ${rowIndex} hidden 输出无法读取`,recipe};
      hiddenStates.push(hidden);
    }
    return {status:'ok',hiddenStates,hiddenDim:hiddenStates[0].length,rows:hiddenStates.length,recipe};
  });
}

function sourceProbeOrientation(sourceText){
  const text=String(sourceText||'');const evidence=[];
  if(/F\.linear\s*\([^,]+,\s*[^,)]+probe|hidden[^\n@]*@[^\n]*probe[^\n]*\.T|probe[^\n@]*@[^\n]*hidden/i.test(text))evidence.push('candidate-rows');
  if(/hidden[^\n@]*@[^\n]*probe(?![^\n]*\.T)/i.test(text))evidence.push('candidate-cols');
  return [...new Set(evidence)];
}

function resolveProbeOptions(discovery,probeShape,hiddenDim){
  const manifest=discovery.manifest||{};
  let orientation=manifest.probeOrientation||null;
  if(!orientation){
    const rowMatch=probeShape[1]===hiddenDim;const colMatch=probeShape[0]===hiddenDim;
    if(rowMatch!==colMatch)orientation=rowMatch?'candidate-rows':'candidate-cols';
    else{
      const source=sourceProbeOrientation(discovery.sourceText);
      if(source.length===1)orientation=source[0];
    }
  }
  if(!['candidate-rows','candidate-cols'].includes(orientation))return {status:'gap',code:'PROBE_ORIENTATION_GAP',detail:`probe shape=[${probeShape.join(',')}] hiddenDim=${hiddenDim}，缺少唯一 orientation 证据`};
  return {status:'ok',orientation,metric:String(manifest.probeMetric||'negative-l2'),topK:Math.max(1,Math.min(256,Number(manifest.topK)||16))};
}

async function resolveCandidateIds(discovery,candidateCount){
  const manifest=discovery.manifest||{};
  if(manifest.candidateIdsIdentity===true)return {status:'ok',ids:Array.from({length:candidateCount},(_,i)=>i),source:'manifest identity'};
  if(Array.isArray(manifest.candidateIds)){
    const ids=manifest.candidateIds.map(Number);
    if(ids.length!==candidateCount||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'manifest candidateIds 与 probe candidate 数量不一致'};
    return {status:'ok',ids,source:'manifest'};
  }
  const role=roleFile(discovery,'candidateIds',false);if(role.gap)return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:role.gap};
  if(role.file){
    const npy=await readNumericNpyPath(role.file.filePath,{maxValues:candidateCount+1});
    if(npy.status==='ok'&&npy.shape.length===1&&npy.values.length===candidateCount&&npy.values.every((id)=>Number.isSafeInteger(id)&&id>=0))return {status:'ok',ids:npy.values,source:role.file.fileName};
    return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'candidateIds NPY 必须是一维整数且长度等于 probe candidates'};
  }
  return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'缺少 probe row/column → token id 映射证据；不会默认把 probe index 当 token id'};
}

async function tokenizerSibling(modelPath){
  const dir=path.dirname(modelPath);const vocabPath=path.join(dir,'vocab.json');const mergesPath=path.join(dir,'merges.txt');
  try{
    const vstat=await fs.stat(vocabPath);if(!vstat.isFile()||vstat.size<=0||vstat.size>MAX_VOCAB_BYTES)return null;
    const vocabText=await fs.readFile(vocabPath,'utf8');let mergesText='';
    try{const mstat=await fs.stat(mergesPath);if(mstat.isFile()&&mstat.size>0&&mstat.size<=MAX_MERGES_BYTES)mergesText=await fs.readFile(mergesPath,'utf8');}catch(error){if(error?.code!=='ENOENT')throw error;}
    createGpt2Bpe(vocabText,mergesText);
    return {vocabText,mergesText};
  }catch(error){if(error?.code==='ENOENT')return null;throw error;}
}

function stage(id,status,detail,data){return {id,status,detail,...(data?{data}: {})};}

async function runScaAutopilotPaths(filePaths,options={}){
  const stages=[];
  const discovery=await discoverScaArtifacts(filePaths,options);
  if(discovery.status!=='ok')return gap(discovery.code,discovery.detail,'discover',{discovery:{files:(discovery.files||[]).map((x)=>x.fileName)}});
  stages.push(stage('discover','ok',`${discovery.files.length} 个相关工件 · ${discovery.manifestFile?.fileName||'source-evidence mode'}`));

  const required={};
  for(const key of ['profileTrace','targetTrace','profileTokenIds','probe']){required[key]=roleFile(discovery,key,true);if(required[key].gap)return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'ARTIFACT_ROLE_GAP',detail:required[key].gap,stage:'discover'},stages,discovery};}
  const modelRole=roleFile(discovery,'model',false);
  if(modelRole.gap)return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'ARTIFACT_ROLE_GAP',detail:modelRole.gap,stage:'discover'},stages,discovery};
  if(!modelRole.file){
    const detail=discovery.safetensors.length?`发现 ${discovery.safetensors.map((x)=>x.fileName).join(', ')}，但没有显式 ONNX oracle；不会执行 Python/Transformers 做隐式转换`:'缺少可执行 .onnx Transformer oracle';
    return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'ORACLE_ARTIFACT_GAP',detail,stage:'oracle-artifact'},stages:[...stages,stage('oracle-artifact','gap',detail)],discovery};
  }

  const [profileLeak,targetLeak]=await Promise.all([
    leakageMatrix(required.profileTrace.file,discovery,'profile',options),
    leakageMatrix(required.targetTrace.file,discovery,'target',options)
  ]);
  for(const item of [profileLeak,targetLeak])if(item.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:item.code,detail:item.detail,stage:'trace'},stages:[...stages,stage('trace','gap',item.detail)],discovery};
  if(profileLeak.matrix[0].length!==targetLeak.matrix[0].length)return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'FEATURE_DIMENSION_GAP',detail:`profiling leakage dim=${profileLeak.matrix[0].length} 与 target=${targetLeak.matrix[0].length} 不一致`,stage:'trace'},stages:[...stages,stage('trace','gap','profiling/target feature dimension mismatch')],discovery};
  stages.push(stage('trace','ok',`profile ${profileLeak.matrix.length}×${profileLeak.matrix[0].length} · target ${targetLeak.matrix.length}×${targetLeak.matrix[0].length}`));

  const profileIds=await tokenSequences(required.profileTokenIds.file,'profileTokenIds');
  if(profileIds.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:profileIds.code,detail:profileIds.detail,stage:'profile-input'},stages:[...stages,stage('profile-input','gap',profileIds.detail)],discovery};
  if(profileIds.sequences.length!==profileLeak.matrix.length)return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'PROFILE_ROW_MISMATCH',detail:`profiling tokens rows=${profileIds.sequences.length}，trace rows=${profileLeak.matrix.length}`,stage:'profile-input'},stages:[...stages,stage('profile-input','gap','profiling token/trace row mismatch')],discovery};

  const runtime=runtimeStatus(options);
  if(!runtime.available)return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'MODEL_RUNTIME_GAP',detail:runtime.installHint,stage:'model-runtime'},stages:[...stages,stage('model-runtime','gap',runtime.error||runtime.installHint)],discovery,runtime};
  stages.push(stage('model-runtime','ok',`${runtime.package}${runtime.version?` ${runtime.version}`:''} · ${options.provider||'cpu'}`));

  const hiddenCapture=await captureProfileHiddenStates(modelRole.file.filePath,profileIds.sequences,{...options,provider:options.provider||'cpu'});
  if(hiddenCapture.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:hiddenCapture.status,detail:hiddenCapture.detail,stage:'profile-hidden'},stages:[...stages,stage('profile-hidden','gap',hiddenCapture.detail)],discovery,runtime,hiddenCapture};
  stages.push(stage('profile-hidden','ok',`${hiddenCapture.rows} rows × hidden ${hiddenCapture.hiddenDim}`));

  const profile=fitLeakageProfile(hiddenCapture.hiddenStates,profileLeak.matrix,discovery.manifest?.profileOptions||{});
  if(profile.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'PROFILE_RANK_GAP',detail:`leakage profile: ${profile.status}`,stage:'leakage-fit'},stages:[...stages,stage('leakage-fit','gap',profile.status)],discovery,runtime,profile};
  stages.push(stage('leakage-fit','ok',`${profile.method} · hidden ${profile.hiddenDim} → leakage ${profile.leakageDim} · r2=${profile.r2==null?'n/a':profile.r2.toFixed(6)}`));

  const probeNpy=await readNumericNpyPath(required.probe.file.filePath);
  if(probeNpy.status!=='ok'||probeNpy.shape.length!==2)return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'PROBE_LAYOUT_GAP',detail:'probe 必须是预算内二维数值 NPY',stage:'probe'},stages:[...stages,stage('probe','gap','invalid probe matrix')],discovery,profile};
  const probeOptions=resolveProbeOptions(discovery,probeNpy.shape,profile.hiddenDim);
  if(probeOptions.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:probeOptions.code,detail:probeOptions.detail,stage:'probe'},stages:[...stages,stage('probe','gap',probeOptions.detail)],discovery,profile};
  const candidateCount=probeOptions.orientation==='candidate-rows'?probeNpy.shape[0]:probeNpy.shape[1];
  const candidateIds=await resolveCandidateIds(discovery,candidateCount);
  if(candidateIds.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:candidateIds.code,detail:candidateIds.detail,stage:'probe'},stages:[...stages,stage('probe','gap',candidateIds.detail)],discovery,profile};

  const targetCandidates=[];
  for(let index=0;index<targetLeak.matrix.length;index+=1){
    const chain=recoverProbeCandidates(profile,targetLeak.matrix[index],probeNpy.data,{probe:{orientation:probeOptions.orientation,metric:probeOptions.metric,candidateIds:candidateIds.ids,topK:probeOptions.topK}});
    if(chain.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:chain.status==='orientation-gap'?'PROBE_ORIENTATION_GAP':'PROBE_RECOVERY_GAP',detail:`target row ${index}: ${chain.status}`,stage:'probe'},stages:[...stages,stage('probe','gap',`target row ${index}: ${chain.status}`)],discovery,profile};
    targetCandidates.push(chain.ranking.top);
  }
  stages.push(stage('probe','ok',`${targetCandidates.length} target rows · top-${probeOptions.topK} token candidates · ${probeOptions.orientation}`));

  const prompt=await promptTokens(discovery);
  if(prompt.status!=='ok')return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:prompt.code,detail:prompt.detail,stage:'oracle'},stages:[...stages,stage('oracle','gap',prompt.detail)],discovery,profile,targetCandidates};
  const tokenizer=await tokenizerSibling(modelRole.file.filePath);
  if(!tokenizer)return {schema:'newcyber.sca-autopilot.v1',status:'gap',gap:{code:'TOKENIZER_GAP',detail:'已恢复 token candidates，但模型同目录缺少可验证的 vocab.json；不能把 token IDs 提升为 Flag 文本',stage:'oracle'},stages:[...stages,stage('oracle','gap','tokenizer unavailable')],discovery,profile,targetCandidates,recoveredTokenIds:targetCandidates.map((row)=>row[0].tokenId)};

  const maxNewTokens=Math.max(1,Math.min(256,Number(discovery.manifest?.maxNewTokens)||targetCandidates.length));
  const oracle=await runTransformerDecode(modelRole.file.filePath,{promptTokenIds:prompt.ids,tokenizer,maxNewTokens,topK:Math.max(1,Math.min(64,Number(discovery.manifest?.oracleTopK)||8)),candidateTokenIdsByStep:targetCandidates.map((row)=>row.map((x)=>x.tokenId))},{...options,provider:options.provider||'cpu'});
  if(oracle.status==='flag-recovered'&&oracle.flag){
    stages.push(stage('oracle','ok',`${oracle.generatedTokenIds.length} tokens · ${oracle.cacheUsed?'KV cache':'full replay'}`));
    stages.push(stage('flag','ok',oracle.flag));
    return {schema:'newcyber.sca-autopilot.v1',status:'flag-recovered',gap:null,flag:oracle.flag,stages,discovery,runtime,profile,target:{rows:targetLeak.matrix.length,candidates:targetCandidates},oracle};
  }
  stages.push(stage('oracle',oracle.status==='max-tokens'?'ok':'gap',oracle.status));
  return {schema:'newcyber.sca-autopilot.v1',status:'decoded-no-flag',gap:null,flag:null,stages,discovery,runtime,profile,target:{rows:targetLeak.matrix.length,candidates:targetCandidates},oracle};
}

module.exports={
  MAX_FILES,MAX_ARRAY_VALUES,MAX_PROFILE_ROWS,MAX_TOTAL_PROFILE_TOKENS,
  discoverScaArtifacts,readNumericNpyPath,captureProfileHiddenStates,resolveProbeOptions,runScaAutopilotPaths
};
