'use strict';

const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const batch42=require('./sca_autopilot_batch42');
const {readNpyHeaderPath}=require('./power_side_channel');
const {openNpyRowSource}=require('./npy_row_source');
const {resolveGroupedLayout}=require('./sca_grouped_leakage');
const {resolveProfileTokenSequences}=require('./sca_profile_label_source');

const HIDDEN_NAMES=['HIDDEN_DIM','HIDDEN_SIZE','D_MODEL','N_EMBD','EMBED_DIM','EMBEDDING_DIM','MODEL_DIM'];
const GROUP_NAMES=['ROWS_PER_TOKEN','GROUPS_PER_TOKEN','LEAKAGE_GROUPS','CHUNKS_PER_TOKEN','HIDDEN_GROUPS'];
const WIDTH_NAMES=['HIDDEN_GROUP_SIZE','HIDDEN_GROUP_WIDTH','HIDDEN_GROUP_DIM','GROUP_SIZE','GROUP_WIDTH','CHUNK_SIZE','CHUNK_WIDTH'];

function list(value){return Array.isArray(value)?value:[];}
function finiteInt(value){value=Number(value);return Number.isSafeInteger(value)&&value>0?value:null;}
function roleFile(discovery,key){const role=discovery?.roles?.[key];return role?.status==='ok'?role.file:null;}
function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}
function sourceConstants(discovery){return discovery?.sourceInspection?.constants||{};}
function firstConstant(constants,names){for(const name of names){const n=finiteInt(constants[name]);if(n)return {value:n,evidence:`source:${name}`};}return null;}

function manifestNumber(manifest,paths){
  for(const keys of paths){let cur=manifest;for(const key of keys){cur=cur?.[key];if(cur==null)break;}const n=finiteInt(cur);if(n)return {value:n,evidence:`manifest:${keys.join('.')}`};}
  return null;
}

function inferProbeHiddenDim(probeShape,hiddenPerGroup,manifest={}){
  if(!Array.isArray(probeShape)||probeShape.length!==2)return null;
  const [rows,cols]=probeShape.map(Number);const orientation=String(manifest.probeOrientation||'').toLowerCase();
  if(orientation==='candidate-rows'&&finiteInt(cols))return {value:cols,evidence:'manifest:probeOrientation=candidate-rows'};
  if(orientation==='candidate-columns'&&finiteInt(rows))return {value:rows,evidence:'manifest:probeOrientation=candidate-columns'};
  if(rows===cols&&finiteInt(rows)&&rows<=4096&&(!hiddenPerGroup||rows%hiddenPerGroup===0))return {value:rows,evidence:'probe:square-hidden-axis'};
  const candidates=[rows,cols].filter((n)=>finiteInt(n)&&n<=4096&&(!hiddenPerGroup||n%hiddenPerGroup===0));
  if(candidates.length===1&&Math.max(rows,cols)>4096)return {value:candidates[0],evidence:'probe:unique-bounded-hidden-axis'};
  return null;
}

function inferGroupedProfileShape({profileRows,rowFeatureDim,probeShape,discovery={}}){
  profileRows=finiteInt(profileRows);rowFeatureDim=finiteInt(rowFeatureDim);const manifest=discovery.manifest||{};const constants=sourceConstants(discovery);
  if(!profileRows||!rowFeatureDim)return {status:'gap',code:'GROUP_TRACE_SHAPE_GAP',detail:'profiling trace shape 非法'};

  const widthEvidence=manifestNumber(manifest,[["groupedLeakage","hiddenPerGroup"],["groupedLeakage","hiddenGroupWidth"],["hiddenPerGroup"],["hiddenGroupWidth"]])||firstConstant(constants,WIDTH_NAMES);
  const groupEvidence=manifestNumber(manifest,[["groupedLeakage","rowsPerToken"],["groupedLeakage","groupsPerToken"],["rowsPerToken"],["groupsPerToken"]])||firstConstant(constants,GROUP_NAMES);
  const hiddenEvidence=manifestNumber(manifest,[["groupedLeakage","hiddenDim"],["hiddenDim"]])||firstConstant(constants,HIDDEN_NAMES)||inferProbeHiddenDim(probeShape,widthEvidence?.value,manifest);
  let hiddenPerGroup=widthEvidence?.value||null,groupsPerToken=groupEvidence?.value||null,hiddenDim=hiddenEvidence?.value||null;const evidence=[widthEvidence,groupEvidence,hiddenEvidence].filter(Boolean).map((x)=>x.evidence);

  if(!groupsPerToken&&hiddenDim&&hiddenPerGroup&&hiddenDim%hiddenPerGroup===0){groupsPerToken=hiddenDim/hiddenPerGroup;evidence.push('derived:hiddenDim/hiddenPerGroup');}
  if(!hiddenPerGroup&&hiddenDim&&groupsPerToken&&hiddenDim%groupsPerToken===0){hiddenPerGroup=hiddenDim/groupsPerToken;evidence.push('derived:hiddenDim/groupsPerToken');}
  if(!hiddenDim&&groupsPerToken&&hiddenPerGroup){hiddenDim=groupsPerToken*hiddenPerGroup;evidence.push('derived:groupsPerToken*hiddenPerGroup');}
  if(!groupsPerToken||groupsPerToken<=1||profileRows%groupsPerToken!==0)return {status:'gap',code:'GROUP_LAYOUT_EVIDENCE_GAP',detail:`已有 profile rows=${profileRows}，但缺少可证明的 groups/hidden layout`,profileRows,rowFeatureDim,hiddenDim,hiddenPerGroup,groupsPerToken,evidence};
  const profileTokens=profileRows/groupsPerToken;
  if(!finiteInt(profileTokens)||profileTokens>16384)return {status:'gap',code:'GROUP_PROFILE_TOKEN_BUDGET_GAP',detail:`derived profiling tokens=${profileTokens} 非法或超过 grouped 上限`,profileRows,rowFeatureDim,hiddenDim,hiddenPerGroup,groupsPerToken,evidence};
  if(hiddenDim&&hiddenPerGroup&&groupsPerToken*hiddenPerGroup!==hiddenDim)return {status:'gap',code:'GROUP_HIDDEN_LAYOUT_GAP',detail:`groups=${groupsPerToken} × hidden/group=${hiddenPerGroup} != hidden=${hiddenDim}`,profileTokens,evidence};
  return {status:'ok',profileRows,profileTokens,groupsPerToken,hiddenPerGroup,hiddenDim,rowFeatureDim,probeShape:list(probeShape),evidence};
}

function isMissingProfileLabels(result){return result?.status==='gap'&&result?.gap?.code==='ARTIFACT_ROLE_GAP'&&/profileTokenIds/i.test(String(result?.gap?.detail||''));}

async function writeInt32Npy(filePath,sequences){
  const rows=sequences.length;const width=sequences[0]?.length||0;
  if(!rows||!width||sequences.some((row)=>!Array.isArray(row)||row.length!==width||row.some((id)=>!Number.isSafeInteger(Number(id))||Number(id)<0||Number(id)>0x7fffffff)))throw new Error('profiling token labels 不能安全写成 int32 NPY');
  const shape=width===1?`(${rows},)`:`(${rows}, ${width})`;
  let header=`{'descr': '<i4', 'fortran_order': False, 'shape': ${shape}, }`;const pre=10;const padding=(16-((pre+Buffer.byteLength(header,'latin1')+1)%16))%16;header+=`${' '.repeat(padding)}\n`;
  const head=Buffer.alloc(pre);head[0]=0x93;head.write('NUMPY',1,'ascii');head[6]=1;head[7]=0;head.writeUInt16LE(Buffer.byteLength(header,'latin1'),8);
  const flat=sequences.flat();const payload=Buffer.alloc(flat.length*4);flat.forEach((id,index)=>payload.writeInt32LE(Number(id),index*4));await fs.writeFile(filePath,Buffer.concat([head,Buffer.from(header,'latin1'),payload]));
}

async function diagnoseProfileLabelGap(filePaths,options={}){
  const discovery=await batch42.discoverScaArtifacts(filePaths,{...options,strict:false});
  if(discovery.status!=='ok')return {schema:'newcyber.sca-autopilot.v3',status:'gap',gap:{code:discovery.code||'DISCOVERY_GAP',detail:discovery.detail||'SCA discovery failed',stage:'discover'},stages:[stage('discover','gap',discovery.detail||discovery.code)],discovery};
  const profileFile=roleFile(discovery,'profileTrace'),targetFile=roleFile(discovery,'targetTrace'),probeFile=roleFile(discovery,'probe'),modelFile=roleFile(discovery,'model');
  const missing=[['profileTrace',profileFile],['targetTrace',targetFile],['probe',probeFile],['model',modelFile]].filter(([,file])=>!file).map(([name])=>name);
  if(missing.length)return {schema:'newcyber.sca-autopilot.v3',status:'gap',gap:{code:'ARTIFACT_ROLE_GAP',detail:`高级 grouped 路径仍缺少 ${missing.join(', ')}`,stage:'discover'},stages:[stage('discover','gap',`missing ${missing.join(', ')}`)],discovery};
  const stages=[stage('discover','ok',`${discovery.files.length} 个相关工件 · profileTokenIds 缺口转入 Batch46 advanced diagnostic`)];
  let profileRows,targetRows;
  try{profileRows=await openNpyRowSource(profileFile.filePath);targetRows=await openNpyRowSource(targetFile.filePath);}catch(error){return {schema:'newcyber.sca-autopilot.v3',status:'gap',gap:{code:'TRACE_SOURCE_GAP',detail:error?.message||String(error),stage:'trace-source'},stages:[...stages,stage('trace-source','gap',error?.message||String(error))],discovery};}
  try{
    stages.push(stage('trace-source','ok',`profile ${profileRows.rows}×${profileRows.cols} (${profileRows.sourceKind}) · target ${targetRows.rows}×${targetRows.cols} (${targetRows.sourceKind})`));
    let probeHeader=null;try{probeHeader=await readNpyHeaderPath(probeFile.filePath);}catch(error){stages.push(stage('probe-shape','gap',error?.message||String(error)));}
    const shape=inferGroupedProfileShape({profileRows:profileRows.rows,rowFeatureDim:profileRows.cols,probeShape:probeHeader?.shape,discovery});
    if(shape.status==='ok'){
      const layout=resolveGroupedLayout({manifest:discovery.manifest||{},sourceText:discovery.sourceText,profileRows:shape.profileRows,profileTokens:shape.profileTokens,hiddenDim:shape.hiddenDim,rowFeatureDim:shape.rowFeatureDim});
      if(layout.status==='ok'){shape.layout=layout;stages.push(stage('group-layout','ok',`${shape.profileRows} raw rows = ${shape.profileTokens} tokens × ${layout.groupsPerToken} groups · hidden/group=${layout.hiddenPerGroup} · row feature=${layout.rowFeatureDim}`));}
      else stages.push(stage('group-layout','gap',layout.detail||layout.code));
    }else stages.push(stage('group-layout','gap',shape.detail));

    const labels=await resolveProfileTokenSequences(discovery,{expectedTokens:shape.status==='ok'?shape.profileTokens:null,modelPath:modelFile.filePath});
    if(labels.status==='ok')stages.push(stage('profile-label','ok',`${labels.count} profiling labels · ${labels.source}`));
    else if(labels.status==='file')stages.push(stage('profile-label','ok',`existing file · ${labels.source}`));
    else stages.push(stage('profile-label','gap',labels.detail));
    return {schema:'newcyber.sca-autopilot.v3',status:labels.status==='ok'?'profile-labels-resolved':'gap',gap:labels.status==='ok'?null:{code:labels.code||'PROFILE_LABEL_SOURCE_GAP',detail:labels.detail,stage:'profile-label'},stages,discovery,shape,profileLabels:labels};
  }finally{await Promise.allSettled([profileRows?.close?.(),targetRows?.close?.()]);}
}

async function replayResolvedLabels(filePaths,diagnostic,options={}){
  const labels=diagnostic?.profileLabels;if(labels?.status!=='ok')return diagnostic;
  if(diagnostic.discovery?.manifest)return {...diagnostic,status:'gap',gap:{code:'PROFILE_LABEL_REPLAY_GAP',detail:'profiling labels 已有来源证明，但现有 recipe manifest 不引用独立 label file；Batch46 不会改写/复制大型赛题工件。',stage:'profile-label-replay'},stages:[...diagnostic.stages,stage('profile-label-replay','gap','manifest-bound bundle requires explicit label field')]};
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-sca-b46-'));const labelPath=path.join(dir,'profiling_token_ids.npy');
  try{
    await writeInt32Npy(labelPath,labels.sequences);
    const result=await batch42.runGroupedScaAutopilotPaths([...filePaths,labelPath],options);
    if(result?.status==='not-applicable')return {...diagnostic,status:'gap',gap:{code:'GROUPED_REPLAY_GAP',detail:result.reason||'grouped replay not applicable',stage:'grouped-replay'},stages:[...diagnostic.stages,stage('grouped-replay','gap',result.reason||'not-applicable')]};
    return {...result,schema:'newcyber.sca-autopilot.v3',stages:[stage('profile-label','ok',`${labels.count} labels · ${labels.source} · ephemeral NPY replay`),...list(result.stages)],profileLabelSource:{source:labels.source,count:labels.count,evidence:labels.evidence||null}};
  }finally{await fs.rm(dir,{recursive:true,force:true});}
}

async function runScaAutopilotPaths(filePaths,options={}){
  const baseline=await batch42.runScaAutopilotPaths(filePaths,options);
  if(!isMissingProfileLabels(baseline))return baseline;
  const diagnostic=await diagnoseProfileLabelGap(filePaths,options);
  if(diagnostic.status==='profile-labels-resolved')return replayResolvedLabels(filePaths,diagnostic,options);
  return diagnostic;
}

module.exports={...batch42,runScaAutopilotPaths,diagnoseProfileLabelGap,inferGroupedProfileShape,isMissingProfileLabels,replayResolvedLabels,writeInt32Npy};
