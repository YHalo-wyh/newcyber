'use strict';

const fs=require('fs/promises');
const path=require('path');
const base=require('./sca_autopilot');
const {runtimeStatus}=require('./local_ml_runtime');
const {runTransformerDecode}=require('./transformer_oracle');
const {createGpt2Bpe}=require('./gpt2_bpe');
const {openNpyRowSource}=require('./npy_row_source');
const {resolveGroupedLayout,fitGroupedLeakageProfiles,recoverGroupedTargets}=require('./sca_grouped_leakage');

const MAX_TOTAL_PROFILE_TOKENS=262144;
const MAX_TOKEN_SEQUENCE=65536;
const MAX_VOCAB_BYTES=32*1024*1024;
const MAX_MERGES_BYTES=16*1024*1024;
const ADVANCED_GAPS=new Set(['TRACE_VALUE_BUDGET_GAP','TRACE_LAYOUT_GAP','FEATURE_RECIPE_GAP','PROFILE_ROW_MISMATCH','PROFILE_ROW_BUDGET_GAP','GROUP_LAYOUT_EVIDENCE_GAP']);

function list(value){return Array.isArray(value)?value:[];}
function roleFile(discovery,key,required=true){const role=discovery?.roles?.[key];if(role?.status==='ambiguous')return {gap:`${key} 候选不唯一：${role.files.join(', ')}`};if(role?.status==='invalid')return {gap:role.error||`${key} recipe 非法`};if(required&&role?.status!=='ok')return {gap:`缺少可证明的 ${key} 工件`};return {file:role?.status==='ok'?role.file:null};}
function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}

async function tokenSequences(file,label){
  const npy=await base.readNumericNpyPath(file.filePath,{maxValues:MAX_TOTAL_PROFILE_TOKENS});
  if(npy.status!=='ok')return {status:'gap',code:'TOKEN_BUDGET_GAP',detail:`${label}: token IDs 超过预算`};
  if(!['i','u'].includes(npy.header.descriptor.kind))return {status:'gap',code:'TOKEN_DTYPE_GAP',detail:`${label}: token IDs 必须是整数 NPY`};
  let sequences;if(npy.shape.length===1)sequences=npy.values.map((id)=>[id]);else if(npy.shape.length===2)sequences=npy.data;else return {status:'gap',code:'TOKEN_LAYOUT_GAP',detail:`${label}: token IDs shape 必须是 [rows] 或 [rows,seq]`};
  for(const seq of sequences){if(!seq.length||seq.length>MAX_TOKEN_SEQUENCE)return {status:'gap',code:'TOKEN_LAYOUT_GAP',detail:`${label}: sequence 长度非法`};for(const id of seq)if(!Number.isSafeInteger(id)||id<0)return {status:'gap',code:'TOKEN_VALUE_GAP',detail:`${label}: 包含非法 token id`};}
  return {status:'ok',sequences};
}

async function promptTokensOptional(discovery){
  const manifest=discovery.manifest||{};
  if(Array.isArray(manifest.promptTokenIds)){
    const ids=manifest.promptTokenIds.map(Number);if(!ids.length||ids.length>MAX_TOKEN_SEQUENCE||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',code:'PROMPT_TOKEN_GAP',detail:'manifest promptTokenIds 非法'};return {status:'ok',ids,source:'manifest'};
  }
  const role=roleFile(discovery,'promptTokenIds',false);if(role.gap)return {status:'gap',code:'PROMPT_TOKEN_GAP',detail:role.gap};if(!role.file)return {status:'missing',ids:null,source:null};
  const read=await tokenSequences(role.file,'promptTokenIds');if(read.status!=='ok')return read;if(read.sequences.length!==1)return {status:'gap',code:'PROMPT_TOKEN_GAP',detail:'promptTokenIds 文件必须只描述一个 prompt sequence'};return {status:'ok',ids:read.sequences[0],source:role.file.fileName};
}

async function resolveCandidateIds(discovery,candidateCount){
  const manifest=discovery.manifest||{};
  if(manifest.candidateIdsIdentity===true)return {status:'ok',ids:Array.from({length:candidateCount},(_,i)=>i),source:'manifest identity'};
  if(Array.isArray(manifest.candidateIds)){const ids=manifest.candidateIds.map(Number);if(ids.length!==candidateCount||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'manifest candidateIds 与 probe candidate 数量不一致'};return {status:'ok',ids,source:'manifest'};}
  const role=roleFile(discovery,'candidateIds',false);if(role.gap)return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:role.gap};
  if(role.file){const npy=await base.readNumericNpyPath(role.file.filePath,{maxValues:candidateCount+1});if(npy.status==='ok'&&npy.shape.length===1&&npy.values.length===candidateCount&&npy.values.every((id)=>Number.isSafeInteger(id)&&id>=0))return {status:'ok',ids:npy.values,source:role.file.fileName};return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'candidateIds NPY 必须是一维整数且长度等于 probe candidates'};}
  return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'缺少 probe row/column → token id 映射证据；不会默认把 probe index 当 token id'};
}

async function tokenizerSibling(modelPath){
  const dir=path.dirname(modelPath),vocabPath=path.join(dir,'vocab.json'),mergesPath=path.join(dir,'merges.txt');
  try{const stat=await fs.stat(vocabPath);if(!stat.isFile()||stat.size<=0||stat.size>MAX_VOCAB_BYTES)return null;const vocabText=await fs.readFile(vocabPath,'utf8');let mergesText='';try{const ms=await fs.stat(mergesPath);if(ms.isFile()&&ms.size>0&&ms.size<=MAX_MERGES_BYTES)mergesText=await fs.readFile(mergesPath,'utf8');}catch(error){if(error?.code!=='ENOENT')throw error;}const tokenizer=createGpt2Bpe(vocabText,mergesText);return {vocabText,mergesText,tokenizer};}catch(error){if(error?.code==='ENOENT')return null;throw error;}
}

function extractFlags(text){return [...new Set(String(text||'').match(/[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,256}\}/g)||[])].slice(0,16);}
function freeProbeDecode(targetCandidates,tokenizer){
  const ids=list(targetCandidates).map((row)=>Number(row?.[0]?.tokenId)).filter((id)=>Number.isSafeInteger(id)&&id>=0);
  if(ids.length!==list(targetCandidates).length)return {status:'token-gap',ids,text:null,flags:[]};
  let text;try{text=tokenizer.decode(ids);}catch(error){return {status:'decode-gap',ids,text:null,flags:[],error:error?.message||String(error)};}
  const margins=list(targetCandidates).map((row)=>row?.length>1?Number(row[0].score)-Number(row[1].score):null).filter(Number.isFinite);
  return {schema:'newcyber.sca-free-probe.v1',status:'decoded',ids,text,flags:extractFlags(text),top1Margin:{min:margins.length?Math.min(...margins):null,mean:margins.length?margins.reduce((a,b)=>a+b,0)/margins.length:null}};
}

async function freeProbeFromBaseline(result){
  if(result?.gap?.code!=='PROMPT_TOKEN_GAP'||!list(result.targetCandidates).length)return null;
  const model=roleFile(result.discovery,'model',false);if(!model.file)return null;const sibling=await tokenizerSibling(model.file.filePath);if(!sibling)return null;
  const decoded=freeProbeDecode(result.targetCandidates,sibling.tokenizer);const stages=list(result.stages).filter((x)=>x.id!=='oracle');stages.push(stage('free-probe',decoded.status==='decoded'?'ok':'gap',decoded.status==='decoded'?`${decoded.ids.length} tokens · unknown-prefix direct probe decode`:decoded.error||decoded.status));
  if(decoded.flags.length)stages.push(stage('flag-candidate','ok',decoded.flags[0]));
  return {...result,status:decoded.flags.length?'flag-candidate':'decoded-no-flag',gap:null,stages,freeProbe:decoded,flagCandidate:decoded.flags[0]||null,recoveredTokenIds:decoded.ids,recoveredText:decoded.text};
}

async function runGroupedScaAutopilotPaths(filePaths,options={}){
  const stages=[];const discovery=await base.discoverScaArtifacts(filePaths,options);if(discovery.status!=='ok')return {status:'not-applicable',reason:discovery.code};
  const required={};for(const key of ['profileTrace','targetTrace','profileTokenIds','probe']){required[key]=roleFile(discovery,key,true);if(required[key].gap)return {status:'not-applicable',reason:required[key].gap};}
  const modelRole=roleFile(discovery,'model',false);if(!modelRole.file)return {status:'not-applicable',reason:'ONNX oracle missing'};
  stages.push(stage('discover','ok',`${discovery.files.length} 个相关工件 · Batch42 grouped candidate`));
  const profileIds=await tokenSequences(required.profileTokenIds.file,'profileTokenIds');if(profileIds.status!=='ok')return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:profileIds.code,detail:profileIds.detail,stage:'profile-input'},stages,discovery};
  let profileRows,targetRows;
  try{profileRows=await openNpyRowSource(required.profileTrace.file.filePath);targetRows=await openNpyRowSource(required.targetTrace.file.filePath);}catch(error){return {status:'not-applicable',reason:error?.message||String(error)};}
  try{
    if(profileRows.cols!==targetRows.cols)return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:'FEATURE_DIMENSION_GAP',detail:`profile group dim=${profileRows.cols} target=${targetRows.cols}`,stage:'trace'},stages,discovery};
    stages.push(stage('trace-source','ok',`profile ${profileRows.rows}×${profileRows.cols} (${profileRows.sourceKind}) · target ${targetRows.rows}×${targetRows.cols} (${targetRows.sourceKind})`));
    if(profileRows.sourceKind==='object-segments'||targetRows.sourceKind==='object-segments')stages.push(stage('object-flatten','ok',`restricted NumPy object-array flatten · profile segments=${profileRows.segments.length} · target segments=${targetRows.segments.length}`));
    const runtime=runtimeStatus(options);if(!runtime.available)return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:'MODEL_RUNTIME_GAP',detail:runtime.installHint,stage:'model-runtime'},stages:[...stages,stage('model-runtime','gap',runtime.error||runtime.installHint)],discovery,runtime};
    stages.push(stage('model-runtime','ok',`${runtime.package}${runtime.version?` ${runtime.version}`:''} · ${options.provider||'cpu'}`));
    const hiddenCapture=await base.captureProfileHiddenStates(modelRole.file.filePath,profileIds.sequences,{...options,provider:options.provider||'cpu'});if(hiddenCapture.status!=='ok')return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:hiddenCapture.status,detail:hiddenCapture.detail,stage:'profile-hidden'},stages:[...stages,stage('profile-hidden','gap',hiddenCapture.detail)],discovery,runtime,hiddenCapture};
    stages.push(stage('profile-hidden','ok',`${hiddenCapture.rows} token rows × hidden ${hiddenCapture.hiddenDim}`));
    const layout=resolveGroupedLayout({manifest:discovery.manifest||{},sourceText:discovery.sourceText,profileRows:profileRows.rows,profileTokens:profileIds.sequences.length,hiddenDim:hiddenCapture.hiddenDim,rowFeatureDim:profileRows.cols});
    if(layout.status!=='ok')return {status:'not-applicable',reason:layout.detail,layout};
    stages.push(stage('group-layout','ok',`${layout.groupsPerToken} rows/token × hidden slice ${layout.hiddenPerGroup} · row leakage ${layout.rowFeatureDim}`));
    const profile=await fitGroupedLeakageProfiles(hiddenCapture.hiddenStates,profileRows,layout,discovery.manifest?.profileOptions||{});if(profile.status!=='ok')return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:'GROUP_PROFILE_GAP',detail:`grouped leakage profile: ${profile.status}${profile.group!=null?` group=${profile.group}`:''}`,stage:'leakage-fit'},stages:[...stages,stage('leakage-fit','gap',profile.status)],discovery,runtime,profile,layout};
    stages.push(stage('leakage-fit','ok',`${profile.method} · groups ${profile.groupsPerToken} · hidden ${profile.hiddenDim} → grouped leakage ${profile.leakageDim} · mean r2=${profile.r2==null?'n/a':profile.r2.toFixed(6)}`));
    const probe=await base.readNumericNpyPath(required.probe.file.filePath);if(probe.status!=='ok'||probe.shape.length!==2)return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:'PROBE_LAYOUT_GAP',detail:'probe 必须是预算内二维数值 NPY',stage:'probe'},stages,discovery,profile,layout};
    const probeOptions=base.resolveProbeOptions(discovery,probe.shape,profile.hiddenDim);if(probeOptions.status!=='ok')return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:probeOptions.code,detail:probeOptions.detail,stage:'probe'},stages,discovery,profile,layout};
    const candidateCount=probeOptions.orientation==='candidate-rows'?probe.shape[0]:probe.shape[1];const candidateIds=await resolveCandidateIds(discovery,candidateCount);if(candidateIds.status!=='ok')return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:candidateIds.code,detail:candidateIds.detail,stage:'probe'},stages,discovery,profile,layout};
    const target=await recoverGroupedTargets(profile,targetRows,probe.data,{probe:{orientation:probeOptions.orientation,metric:probeOptions.metric,candidateIds:candidateIds.ids,topK:probeOptions.topK}});if(target.status!=='ok')return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:'GROUP_TARGET_RECOVERY_GAP',detail:`${target.status}${target.token!=null?` token=${target.token}`:''}${target.group!=null?` group=${target.group}`:''}`,stage:'probe'},stages,discovery,profile,layout,target};
    stages.push(stage('probe','ok',`${target.tokens} target tokens · grouped hidden reassembly · top-${probeOptions.topK}`));
    const sibling=await tokenizerSibling(modelRole.file.filePath);if(!sibling)return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:'TOKENIZER_GAP',detail:'已恢复 grouped token candidates，但模型同目录缺少 vocab.json',stage:'oracle'},stages,discovery,profile,layout,target};
    const prompt=await promptTokensOptional(discovery);
    if(prompt.status==='ok'){
      const maxNewTokens=Math.max(1,Math.min(256,Number(discovery.manifest?.maxNewTokens)||target.candidates.length));const oracle=await runTransformerDecode(modelRole.file.filePath,{promptTokenIds:prompt.ids,tokenizer:{vocabText:sibling.vocabText,mergesText:sibling.mergesText},maxNewTokens,topK:Math.max(1,Math.min(64,Number(discovery.manifest?.oracleTopK)||8)),candidateTokenIdsByStep:target.candidates.map((row)=>row.map((x)=>x.tokenId))},{...options,provider:options.provider||'cpu'});
      if(oracle.status==='flag-recovered'&&oracle.flag){stages.push(stage('oracle','ok',`${oracle.generatedTokenIds.length} tokens · known-prefix oracle`));stages.push(stage('flag','ok',oracle.flag));return {schema:'newcyber.sca-autopilot.v2',status:'flag-recovered',flag:oracle.flag,gap:null,stages,discovery,runtime,layout,profile,target:{rows:target.tokens,candidates:target.candidates},oracle};}
      stages.push(stage('oracle',oracle.status==='max-tokens'?'ok':'gap',oracle.status));return {schema:'newcyber.sca-autopilot.v2',status:'decoded-no-flag',flag:null,gap:null,stages,discovery,runtime,layout,profile,target:{rows:target.tokens,candidates:target.candidates},oracle};
    }
    if(prompt.status==='gap')return {schema:'newcyber.sca-autopilot.v2',status:'gap',gap:{code:prompt.code,detail:prompt.detail,stage:'oracle'},stages,discovery,profile,layout,target};
    const freeProbe=freeProbeDecode(target.candidates,sibling.tokenizer);stages.push(stage('free-probe',freeProbe.status==='decoded'?'ok':'gap',freeProbe.status==='decoded'?`${freeProbe.ids.length} tokens · prompt unknown · direct probe decode`:freeProbe.error||freeProbe.status));if(freeProbe.flags.length)stages.push(stage('flag-candidate','ok',freeProbe.flags[0]));
    return {schema:'newcyber.sca-autopilot.v2',status:freeProbe.flags.length?'flag-candidate':'decoded-no-flag',flag:null,flagCandidate:freeProbe.flags[0]||null,gap:null,stages,discovery,runtime,layout,profile,target:{rows:target.tokens,candidates:target.candidates,hiddenStates:target.hiddenStates},freeProbe,recoveredTokenIds:freeProbe.ids,recoveredText:freeProbe.text};
  }finally{await Promise.allSettled([profileRows.close(),targetRows.close()]);}
}

async function runScaAutopilotPaths(filePaths,options={}){
  let baseline=null,baselineError=null;
  try{baseline=await base.runScaAutopilotPaths(filePaths,options);}catch(error){baselineError=error;}
  if(baseline?.status==='flag-recovered')return baseline;
  if(baseline?.gap?.code==='PROMPT_TOKEN_GAP'){
    const free=await freeProbeFromBaseline(baseline);if(free)return free;
  }
  if(baselineError||ADVANCED_GAPS.has(baseline?.gap?.code)){
    const grouped=await runGroupedScaAutopilotPaths(filePaths,options);
    if(grouped.status!=='not-applicable')return grouped;
  }
  if(baselineError)throw baselineError;
  return baseline;
}

module.exports={...base,runScaAutopilotPaths,runGroupedScaAutopilotPaths,freeProbeDecode};
