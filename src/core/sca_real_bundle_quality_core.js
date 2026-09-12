'use strict';

const fs=require('fs/promises');
const path=require('path');
const base=require('./sca_autopilot');
const grouped=require('./sca_autopilot_grouped_core');
const {runtimeStatus}=require('./local_ml_runtime');
const {readNpyHeaderPath}=require('./power_side_channel');
const {openNpyRowSource}=require('./npy_row_source');
const {resolveGroupedLayout,fitGroupedLeakageProfiles,recoverGroupedTargets}=require('./sca_grouped_leakage');
const {fitReferenceProbeCalibration}=require('./sca_reference_probe_calibration');
const {rerankCandidateShortlists}=require('./sca_probe_calibration');
const {runContextualHiddenOracle}=require('./sca_contextual_hidden_oracle');
const {createGpt2Bpe}=require('./gpt2_bpe');
const {reconstructProfilingSequences,captureContextualProfileHiddenStates}=require('./sca_contextual_profile_hidden');
const {resolveRealBundleFeatureRecipe,wrapBudgetedStreamingFeatureSource}=require('./sca_real_bundle_feature_source');
const {applyQualityResultGate}=require('./sca_quality_result_gate');

const MAX_PROFILE_TOKEN_IDS=262144;
const MAX_CANDIDATE_IDS=200000;
const MAX_VOCAB_BYTES=32*1024*1024;
const MAX_MERGES_BYTES=16*1024*1024;

function list(value){return Array.isArray(value)?value:[];}
function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}
function gap(code,detail,stageId,stages,extra={}){return {schema:'newcyber.sca-autopilot.v6',version:56,status:'gap',flag:null,gap:{code,detail,stage:stageId},stages:[...list(stages),stage(stageId,'gap',detail)],...extra};}
function roleFile(discovery,key,required=true){
  const role=discovery?.roles?.[key];
  if(role?.status==='ambiguous')return {gap:`${key} candidates are ambiguous: ${list(role.files).join(', ')}`};
  if(role?.status==='invalid')return {gap:role.error||`${key} role is invalid`};
  if(required&&role?.status!=='ok')return {gap:`missing proven ${key} artifact`};
  return {file:role?.status==='ok'?role.file:null};
}

async function readFlatProfileIds(file){
  const npy=await base.readNumericNpyPath(file.filePath,{maxValues:MAX_PROFILE_TOKEN_IDS});
  if(npy.status!=='ok')return {status:'gap',code:'PROFILE_TOKEN_BUDGET_GAP',detail:'profiling token IDs exceed static read budget'};
  if(npy.shape.length!==1)return {status:'not-applicable',reason:'profiling token IDs are not a flat 1D vector'};
  if(!['i','u'].includes(npy.header.descriptor.kind))return {status:'gap',code:'PROFILE_TOKEN_DTYPE_GAP',detail:'profiling token IDs must be integer NPY'};
  const ids=npy.values.map(Number);
  if(!ids.length||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',code:'PROFILE_TOKEN_VALUE_GAP',detail:'profiling token IDs contain invalid values'};
  return {status:'ok',ids,sequences:ids.map((id)=>[id]),shape:npy.shape};
}

async function explicitCandidateIds(discovery){
  const manifest=discovery?.manifest||{};
  if(Array.isArray(manifest.candidateIds)){
    const ids=manifest.candidateIds.map(Number);
    if(!ids.length||ids.length>MAX_CANDIDATE_IDS||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'manifest candidateIds are invalid'};
    return {status:'ok',ids,source:'manifest'};
  }
  let selected=roleFile(discovery,'candidateIds',false);
  if(selected.gap&&discovery?.roles?.candidateIds?.status==='ambiguous'){
    const explicit=grouped.explicitCandidateIdFile(discovery);
    if(explicit.status==='ok')selected={file:explicit.file};
    else return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:explicit.status==='ambiguous'?`candidate ID evidence is still ambiguous: ${explicit.files.join(', ')}`:selected.gap};
  }else if(selected.gap)return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:selected.gap};
  if(!selected.file)return {status:'not-applicable',reason:'no explicit candidate/vocab token-id file'};
  const npy=await base.readNumericNpyPath(selected.file.filePath,{maxValues:MAX_CANDIDATE_IDS});
  if(npy.status!=='ok'||npy.shape.length!==1||!['i','u'].includes(npy.header.descriptor.kind))return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'candidate token-id map must be a budgeted 1D integer NPY'};
  const ids=npy.values.map(Number);
  if(!ids.length||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',code:'TOKEN_ID_MAP_GAP',detail:'candidate token-id map contains invalid token IDs'};
  return {status:'ok',ids,source:selected.file.fileName,file:selected.file};
}

function probeNameScore(file){
  const name=String(file?.fileName||'').toLowerCase();let score=0;
  if(/wte[_-]?probe/.test(name))score+=12;
  else if(/probe/.test(name))score+=8;
  else if(/(?:embedding|lm[_-]?head|decoder.*weight|output.*weight)/.test(name))score+=4;
  if(/(?:reduced|subset|candidate|vocab)/.test(name))score+=8;
  return score;
}
async function resolveReducedProbe(discovery,candidateCount,hiddenDim){
  const candidates=[];
  for(const file of list(discovery?.files)){
    if(String(file?.extension||'').toLowerCase()!=='.npy'||probeNameScore(file)<=0)continue;
    try{
      const header=await readNpyHeaderPath(file.filePath);
      if(header.shape.length!==2)continue;
      const rows=Number(header.shape[0]),cols=Number(header.shape[1]);
      let orientation=null;
      if(rows===candidateCount&&cols===hiddenDim)orientation='candidate-rows';
      else if(cols===candidateCount&&rows===hiddenDim)orientation='candidate-cols';
      if(!orientation)continue;
      const elements=rows*cols;
      candidates.push({file,header,orientation,elements,score:probeNameScore(file)+(elements<=base.MAX_ARRAY_VALUES?4:-100)});
    }catch{}
  }
  const readable=candidates.filter((item)=>item.elements<=base.MAX_ARRAY_VALUES).sort((a,b)=>b.score-a.score||a.file.fileName.localeCompare(b.file.fileName));
  if(!readable.length){
    if(candidates.length)return {status:'gap',code:'PROBE_VALUE_BUDGET_GAP',detail:`all candidate-bound probe matrices exceed ${base.MAX_ARRAY_VALUES} values`,candidates:candidates.map((x)=>({file:x.file.fileName,shape:x.header.shape,elements:x.elements}))};
    return {status:'gap',code:'PROBE_CARDINALITY_GAP',detail:`no probe matrix shape matches candidateCount=${candidateCount}, hiddenDim=${hiddenDim}`};
  }
  const top=readable[0].score,tied=readable.filter((item)=>item.score===top);
  if(tied.length>1)return {status:'gap',code:'PROBE_AMBIGUITY_GAP',detail:`multiple candidate-bound reduced probes: ${tied.map((x)=>x.file.fileName).join(', ')}`};
  const selected=readable[0];
  const npy=await base.readNumericNpyPath(selected.file.filePath,{maxValues:base.MAX_ARRAY_VALUES});
  if(npy.status!=='ok'||npy.shape.length!==2)return {status:'gap',code:'PROBE_VALUE_BUDGET_GAP',detail:`${selected.file.fileName} could not be loaded within numeric-array budget`};
  return {status:'ok',file:selected.file,matrix:npy.data,shape:npy.shape,orientation:selected.orientation,elements:selected.elements,selection:'candidate-cardinality-bound-reduced-probe'};
}

function sourceProbeMetric(sourceText,manifest={}){
  if(manifest.probeMetric)return String(manifest.probeMetric).toLowerCase();
  const text=String(sourceText||'');
  if(/cosine[_\s-]*(?:similarity|score)|F\.cosine_similarity|normalize\s*\([^\n]{0,120}(?:wte|probe|embedding)/i.test(text))return'cosine';
  if(/negative[_\s-]*l2|euclidean|(?:norm|linalg\.norm)\s*\([^\n]{0,160}-[^\n]{0,160}(?:wte|probe|embedding)/i.test(text))return'negative-l2';
  if(/(?:np\.)?dot\s*\([^\n]{0,220}(?:wte|probe|embedding)/i.test(text))return'dot';
  // WTE matrices are semantic embeddings; cosine is the conservative default
  // only after an explicit candidate-bound WTE/reduced probe has been proven.
  return'cosine';
}

async function tokenizerSibling(modelPath){
  const dir=path.dirname(modelPath),vocabPath=path.join(dir,'vocab.json'),mergesPath=path.join(dir,'merges.txt');
  try{
    const stat=await fs.stat(vocabPath);if(!stat.isFile()||stat.size<=0||stat.size>MAX_VOCAB_BYTES)return null;
    const vocabText=await fs.readFile(vocabPath,'utf8');let mergesText='';
    try{const ms=await fs.stat(mergesPath);if(ms.isFile()&&ms.size>0&&ms.size<=MAX_MERGES_BYTES)mergesText=await fs.readFile(mergesPath,'utf8');}catch(error){if(error?.code!=='ENOENT')throw error;}
    return {vocabText,mergesText,tokenizer:createGpt2Bpe(vocabText,mergesText)};
  }catch(error){if(error?.code==='ENOENT')return null;throw error;}
}

function freeProbeDecode(candidates,tokenizer){
  const ids=list(candidates).map((row)=>Number(row?.[0]?.tokenId));
  if(!ids.length||ids.some((id)=>!Number.isSafeInteger(id)||id<0))return {status:'gap',ids:[],text:null};
  let text=null;try{text=tokenizer.decode(ids);}catch(error){return {status:'gap',ids,text:null,error:error?.message||String(error)};}
  return {schema:'newcyber.sca-free-probe.v2',status:'decoded',ids,text};
}

async function runRealBundleQualityPaths(filePaths,options={}){
  const stages=[];const discovery=await base.discoverScaArtifacts(filePaths,options);
  if(discovery.status!=='ok')return {status:'not-applicable',reason:discovery.code};
  const required={};
  for(const key of ['profileTrace','targetTrace','profileTokenIds']){
    required[key]=roleFile(discovery,key,true);if(required[key].gap)return {status:'not-applicable',reason:required[key].gap};
  }
  const modelRole=roleFile(discovery,'model',false);if(!modelRole.file)return {status:'not-applicable',reason:'ONNX oracle missing'};
  const profileIds=await readFlatProfileIds(required.profileTokenIds.file);
  if(profileIds.status!=='ok')return profileIds.status==='not-applicable'?profileIds:gap(profileIds.code,profileIds.detail,'profile-input',stages,{discovery});
  const reconstruction=reconstructProfilingSequences(profileIds.sequences,discovery.sourceText);
  if(reconstruction.status==='missing'||reconstruction.status==='not-applicable')return {status:'not-applicable',reason:reconstruction.detail||reconstruction.reason||reconstruction.code};
  if(reconstruction.status!=='ok')return gap(reconstruction.code||'PROFILE_BOUNDARY_GAP',reconstruction.detail||'profiling prompt boundary reconstruction failed','profile-boundary',stages,{discovery});
  stages.push(stage('profile-boundary','ok',`${reconstruction.boundary.prompts} full profiling prompts · ${reconstruction.boundary.total} token positions · ${reconstruction.boundary.source}`));

  let profileRaw=null,targetRaw=null,profileRows=null,targetRows=null;
  try{
    profileRaw=await openNpyRowSource(required.profileTrace.file.filePath);targetRaw=await openNpyRowSource(required.targetTrace.file.filePath);
    if(profileRaw.cols!==targetRaw.cols)return gap('FEATURE_DIMENSION_GAP',`profile raw dim=${profileRaw.cols} target=${targetRaw.cols}`,'trace-source',stages,{discovery});
    stages.push(stage('trace-source','ok',`profile ${profileRaw.rows}x${profileRaw.cols} · target ${targetRaw.rows}x${targetRaw.cols}`));
    const feature=resolveRealBundleFeatureRecipe(discovery,profileRaw.cols);
    if(feature.status!=='ok')return gap(feature.code||'GROUP_FEATURE_RECIPE_GAP',feature.detail||'proven Hann feature recipe unavailable','feature-recipe',stages,{discovery,rawShape:{profileRows:profileRaw.rows,targetRows:targetRaw.rows,rawCols:profileRaw.cols}});
    profileRows=wrapBudgetedStreamingFeatureSource(profileRaw,feature.recipe,options);targetRows=wrapBudgetedStreamingFeatureSource(targetRaw,feature.recipe,options);
    stages.push(stage('feature-recipe','ok',`${feature.recipe.rawCols} raw -> ${feature.recipe.slots||feature.recipe.windows.length} ${feature.recipe.metric} slots · ${feature.sourceMode} · raw chunks <= ${profileRows.readBudget.rawChunkRows} rows` ,{recipe:feature.recipe,readBudget:profileRows.readBudget}));

    const runtime=runtimeStatus(options);
    if(!runtime.available)return gap('MODEL_RUNTIME_GAP',runtime.installHint,'model-runtime',stages,{discovery,runtime});
    stages.push(stage('model-runtime','ok',`${runtime.package}${runtime.version?` ${runtime.version}`:''} · ${options.provider||'cpu'}`));
    const hiddenCapture=await captureContextualProfileHiddenStates(modelRole.file.filePath,reconstruction.sequences,{...options,provider:options.provider||'cpu'});
    if(hiddenCapture.status!=='ok')return gap(hiddenCapture.status,hiddenCapture.detail,'profile-hidden',stages,{discovery,runtime,hiddenCapture});
    if(hiddenCapture.rows!==profileIds.ids.length)return gap('PROFILE_HIDDEN_COUNT_GAP',`contextual hidden rows=${hiddenCapture.rows} != profiling token IDs=${profileIds.ids.length}`,'profile-hidden',stages,{discovery,runtime,hiddenCapture});
    stages.push(stage('profile-hidden','ok',`${hiddenCapture.prompts} full prompts -> ${hiddenCapture.rows} contextual positions x hidden ${hiddenCapture.hiddenDim}`,{mode:hiddenCapture.mode,prompts:hiddenCapture.prompts,rows:hiddenCapture.rows,hiddenDim:hiddenCapture.hiddenDim}));

    const layout=resolveGroupedLayout({manifest:discovery.manifest||{},sourceText:discovery.sourceText,profileRows:profileRows.rows,profileTokens:profileIds.ids.length,hiddenDim:hiddenCapture.hiddenDim,rowFeatureDim:profileRows.cols});
    if(layout.status!=='ok')return gap(layout.code||'GROUP_LAYOUT_EVIDENCE_GAP',layout.detail||layout.status,'group-layout',stages,{discovery,runtime,layout});
    stages.push(stage('group-layout','ok',`${layout.groupsPerToken} rows/token x hidden slice ${layout.hiddenPerGroup} · feature ${layout.rowFeatureDim}`));
    const profile=await fitGroupedLeakageProfiles(hiddenCapture.hiddenStates,profileRows,layout,discovery.manifest?.profileOptions||{});
    if(profile.status!=='ok')return gap('GROUP_PROFILE_GAP',`grouped leakage profile: ${profile.status}${profile.group!=null?` group=${profile.group}`:''}`,'leakage-fit',stages,{discovery,runtime,layout,profile});
    stages.push(stage('leakage-fit','ok',`${profile.method} · contextual profile hidden · mean r2=${profile.r2==null?'n/a':profile.r2.toFixed(6)}`));
    if(feature.recipe.metric==='hann-dot'&&feature.recipe.source==='challenge-source'&&Number.isFinite(profile.r2)&&profile.r2<Number(options.minExactLinearHannR2??0.99))return gap('LEAKAGE_QUALITY_GAP',`exact linear Hann recipe requires mean r2 >= ${Number(options.minExactLinearHannR2??0.99).toFixed(3)}, got ${profile.r2.toFixed(6)}`,'leakage-quality',stages,{discovery,runtime,layout,profile,featureRecipe:feature.recipe});

    const candidate=await explicitCandidateIds(discovery);
    if(candidate.status!=='ok')return candidate.status==='not-applicable'?{status:'not-applicable',reason:candidate.reason}:gap(candidate.code,candidate.detail,'candidate-map',stages,{discovery,runtime,layout,profile,featureRecipe:feature.recipe});
    const probe=await resolveReducedProbe(discovery,candidate.ids.length,hiddenCapture.hiddenDim);
    if(probe.status!=='ok')return gap(probe.code,probe.detail,'probe-select',stages,{discovery,runtime,layout,profile,featureRecipe:feature.recipe,probeCandidates:probe.candidates||null});
    stages.push(stage('probe-select','ok',`${probe.file.fileName} · [${probe.shape.join(',')}] · bound to ${candidate.ids.length} candidate token IDs`,{file:probe.file.fileName,shape:probe.shape,selection:probe.selection,elements:probe.elements}));
    const probeOptions={orientation:probe.orientation,metric:sourceProbeMetric(discovery.sourceText,discovery.manifest||{}),candidateIds:candidate.ids,topK:Math.max(1,Math.min(256,Number(discovery.manifest?.topK)||Number(options.topK)||32))};
    const calibration=fitReferenceProbeCalibration({hiddenStates:hiddenCapture.hiddenStates,profileTokenSequences:profileIds.sequences,probeMatrix:probe.matrix,probeOptions,options:discovery.manifest?.referenceProbeCalibration||options.referenceProbeCalibration||{}});
    if(calibration.status!=='ok')return gap('REFERENCE_PROBE_CALIBRATION_GAP',calibration.reason||calibration.status,'probe-calibration',stages,{discovery,runtime,layout,profile,featureRecipe:feature.recipe,probeCalibration:calibration});
    stages.push(stage('probe-calibration','ok',`${calibration.summary.mode} lambda=${calibration.summary.lambda} · holdout cosine ${Number(calibration.summary.evaluation.rawCosine).toFixed(4)} -> ${Number(calibration.summary.evaluation.calibratedCosine).toFixed(4)}`));

    const target=await recoverGroupedTargets(profile,targetRows,probe.matrix,{probe:probeOptions});
    if(target.status!=='ok')return gap('GROUP_TARGET_RECOVERY_GAP',`${target.status}${target.token!=null?` token=${target.token}`:''}${target.group!=null?` group=${target.group}`:''}`,'probe',stages,{discovery,runtime,layout,profile,featureRecipe:feature.recipe,probeCalibration:calibration.summary,target});
    const reranked=rerankCandidateShortlists({hiddenStates:target.hiddenStates,candidates:target.candidates,project:calibration.project,probeMatrix:probe.matrix,probeOptions,options:options.calibratedRerank||{}});
    const targetCandidates=reranked.status==='ok'?reranked.candidates:target.candidates;
    stages.push(stage('probe','ok',`${target.tokens} target tokens · ${reranked.status==='ok'?'global-ridge calibrated rerank':'raw candidate ranking'} · top-${probeOptions.topK}`,reranked.status==='ok'?{fullScanRows:reranked.fullScanRows,fullScanSucceededRows:reranked.fullScanSucceededRows,fullProbeExpandedRows:reranked.fullProbeExpandedRows,budgetLimited:reranked.budgetLimited}:null));

    const sibling=await tokenizerSibling(modelRole.file.filePath);
    if(!sibling)return gap('TOKENIZER_GAP','model directory lacks GPT-2 vocab.json/merges.txt','oracle',stages,{discovery,runtime,layout,profile,featureRecipe:feature.recipe,probeCalibration:calibration.summary,target:{rows:target.tokens,candidates:targetCandidates}});
    const freeProbe=freeProbeDecode(targetCandidates,sibling.tokenizer);
    stages.push(stage('free-probe',freeProbe.status==='decoded'?'ok':'gap',freeProbe.status==='decoded'?`${freeProbe.ids.length} tokens · calibrated reduced-WTE direct decode`:freeProbe.error||freeProbe.status));
    const contextual=await runContextualHiddenOracle(modelRole.file.filePath,{targetHiddenStates:target.hiddenStates,targetCandidates,allCandidateIds:candidate.ids,tokenizer:sibling.tokenizer,cosineThreshold:Number(options.contextualHiddenCosine??discovery.manifest?.contextualHiddenCosine??0.99),fullScan:true},{...options,provider:options.provider||'cpu'});
    if(contextual.status==='decoded')stages.push(stage('contextual-hidden-oracle','ok',`${contextual.recoveredTokenIds.length}/${target.tokens} contextual positions · cos min=${contextual.cosine?.min==null?'n/a':contextual.cosine.min.toFixed(6)}`));
    else stages.push(stage('contextual-hidden-oracle','gap',contextual.detail||contextual.reason||contextual.status,{matched:list(contextual.recoveredTokenIds).length,target:target.tokens}));

    const preliminary={
      schema:'newcyber.sca-autopilot.v6',version:56,status:contextual.status==='decoded'?'decoded-no-flag':'decoded-no-flag',flag:null,flagCandidate:contextual.flag||null,gap:null,
      stages,discovery,runtime,layout,profile,featureRecipe:feature.recipe,probeCalibration:calibration.summary,
      profileBoundary:reconstruction.boundary,profileHidden:{mode:hiddenCapture.mode,prompts:hiddenCapture.prompts,rows:hiddenCapture.rows,hiddenDim:hiddenCapture.hiddenDim},
      probeSelection:{file:probe.file.fileName,shape:probe.shape,candidateIds:candidate.source,metric:probeOptions.metric},
      target:{rows:target.tokens,candidates:targetCandidates,hiddenStates:target.hiddenStates},freeProbe,contextualHiddenOracle:contextual,
      recoveredTokenIds:contextual.status==='decoded'?contextual.recoveredTokenIds:freeProbe.ids,recoveredText:contextual.status==='decoded'?contextual.recoveredText:freeProbe.text,
      realBundleRoute:{mode:'contextual-profile-boundaries',readBudget:profileRows.readBudget,probe:probe.selection}
    };
    return applyQualityResultGate(preliminary,options);
  }finally{
    await Promise.allSettled([profileRows?.close?.(),targetRows?.close?.(),profileRows?null:profileRaw?.close?.(),targetRows?null:targetRaw?.close?.()].filter(Boolean));
  }
}

module.exports={runRealBundleQualityPaths,readFlatProfileIds,explicitCandidateIds,resolveReducedProbe,sourceProbeMetric,freeProbeDecode};
