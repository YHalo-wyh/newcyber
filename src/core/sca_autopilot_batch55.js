'use strict';

const path=require('path');
const batch50=require('./sca_autopilot_batch50_core');
const {readNpyHeaderPath}=require('./power_side_channel');
const {MAX_CALIBRATED_SCORE_OPS}=require('./sca_probe_calibration');
const {prioritizeScaPaths,inspectQualityIntent}=require('./sca_source_priority');

function list(value){return Array.isArray(value)?value:[];}
function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}
function engineOf(result){
  if(result?.schema==='newcyber.sca-autopilot.v4'||result?.featureRecipe||result?.probeCalibration)return'quality-v4';
  if(result?.schema==='newcyber.sca-autopilot.v3')return'grouped-v3';
  if(result?.schema==='newcyber.sca-autopilot.v1')return'legacy-v1';
  return'unknown';
}
function roleFile(result,key){const role=result?.discovery?.roles?.[key];return role?.status==='ok'?role.file:null;}

async function featureTelemetry(result){
  const recipe=result?.featureRecipe;if(!recipe)return null;
  const trace=roleFile(result,'profileTrace');let rawDim=null;
  if(trace?.filePath){try{const header=await readNpyHeaderPath(trace.filePath);rawDim=Number(header?.shape?.[header.shape.length-1])||null;}catch{}}
  const effectiveDim=Number(recipe.slots)||list(recipe.windows).length||null;
  return {rawDim,effectiveDim,windowFunction:recipe.windowFunction||null,windowSize:Number(recipe.windowSize)||null,metric:recipe.metric||null,streaming:true};
}

async function fullProbeTelemetry(result){
  const calibration=result?.probeCalibration;
  if(calibration?.status!=='accepted')return {executed:false,reason:'probe calibration not accepted'};
  const probeFile=roleFile(result,'probe');const hiddenDim=Number(result?.profile?.hiddenDim)||0;const targetRows=Number(result?.target?.rows)||0;
  if(!probeFile?.filePath||!hiddenDim||!targetRows)return {executed:false,reason:'probe/header/target telemetry unavailable'};
  try{
    const header=await readNpyHeaderPath(probeFile.filePath);const probeOptions=batch50.resolveProbeOptions(result.discovery,header.shape,hiddenDim);
    if(probeOptions.status!=='ok')return {executed:false,reason:probeOptions.detail||probeOptions.code||'probe orientation unavailable'};
    const candidateCount=probeOptions.orientation==='candidate-rows'?Number(header.shape[0]):Number(header.shape[1]);
    const workPerRow=candidateCount*hiddenDim;const fullScanRows=workPerRow>0?Math.min(targetRows,Math.floor(MAX_CALIBRATED_SCORE_OPS/workPerRow)):0;
    const calibratedProbeRan=list(result.stages).some((item)=>item.id==='probe'&&item.status==='ok'&&/calibrated/i.test(String(item.detail||'')));
    return {executed:Boolean(calibratedProbeRan&&fullScanRows>0),fullScanRows:calibratedProbeRan?fullScanRows:0,targetRows,candidateCount,hiddenDim,orientation:probeOptions.orientation,metric:probeOptions.metric,workPerRow,workBudget:MAX_CALIBRATED_SCORE_OPS,budgetLimited:fullScanRows<targetRows};
  }catch(error){return {executed:false,reason:error?.message||String(error)};}
}

function qualityDowngradeGap(intent,result,reason){
  return {
    schema:'newcyber.sca-autopilot.v5',version:55,status:'gap',flag:null,
    gap:{code:'QUALITY_ROUTE_DOWNGRADE_GAP',detail:reason,stage:'engine-dispatch'},
    stages:[stage('engine-dispatch','gap',reason,{qualityIntent:intent.reasons,blockedEngine:engineOf(result)}),...list(result?.stages)],
    discovery:result?.discovery||null,
    blockedFallback:{status:result?.status||null,schema:result?.schema||null,engine:engineOf(result)},
    qualityRoute:{engine:'batch55-quality-first',selectedEngine:'blocked-legacy-fallback',qualityIntent:intent,rawDowngradeBlocked:true}
  };
}

async function decorateResult(result,intent,prioritized,original){
  const selectedEngine=engineOf(result);const feature=await featureTelemetry(result);const fullProbe=await fullProbeTelemetry(result);
  if(intent.strong&&selectedEngine!=='quality-v4')return qualityDowngradeGap(intent,result,`源码/recipe 已证明 quality intent (${intent.reasons.join(', ')})，但执行链准备降级到 ${selectedEngine}；Batch55 禁止 silent raw fallback`);
  if(intent.strong&&result?.status!=='gap'&&(intent.state.hann||intent.state.recipeManifest||intent.state.compactFeature)&&!result?.featureRecipe)return qualityDowngradeGap(intent,result,'已证明 compact/Hann feature 意图，但结果未携带 featureRecipe；拒绝把 raw trace 当最终 leakage representation');

  const routeStatus=selectedEngine==='quality-v4'?'ok':'fallback';
  const routeStage=stage('engine-dispatch',routeStatus,`Batch55 production quality gate → ${selectedEngine}${intent.strong?` · intent=${intent.reasons.join('+')}`:' · no strong quality intent'}`);
  const sourceStage=stage('source-priority','ok',`优先源码：${intent.priorityPreview.slice(0,6).join(', ')||'none'} · inspected ${intent.inspectedFiles.length} files / ${intent.inspectedBytes} bytes`);
  const extra=[];
  if(feature)extra.push(stage('feature-telemetry','ok',`${feature.rawDim??'?'} raw → ${feature.effectiveDim??'?'} effective · ${feature.windowFunction||'window'} · streaming`,feature));
  if(result?.probeCalibration?.status==='accepted')extra.push(stage('calibration-telemetry','ok',`${result.probeCalibration.mode||'ridge'} · cosine gain=${Number(result.probeCalibration.cosineGain||0).toFixed(6)}`,{mode:result.probeCalibration.mode,cosineGain:result.probeCalibration.cosineGain,evaluation:result.probeCalibration.evaluation}));
  if(fullProbe.executed)extra.push(stage('full-probe','ok',`${fullProbe.fullScanRows}/${fullProbe.targetRows} target rows × ${fullProbe.candidateCount} candidates · budget ${fullProbe.workBudget}`,fullProbe));
  else if(result?.probeCalibration?.status==='accepted')extra.push(stage('full-probe','skip',fullProbe.reason||`budget permits ${fullProbe.fullScanRows||0}/${fullProbe.targetRows||0} rows`,fullProbe));

  const stages=[routeStage,sourceStage,...list(result?.stages)];
  const insertAt=Math.max(2,stages.findIndex((item)=>item.id==='oracle'));
  if(extra.length)stages.splice(insertAt<2?stages.length:insertAt,0,...extra);
  return {
    ...result,
    schema:selectedEngine==='quality-v4'?'newcyber.sca-autopilot.v5':result?.schema,
    version:55,
    stages,
    qualityRoute:{
      engine:'batch55-quality-first',selectedEngine,qualityIntent:intent,rawDowngradeBlocked:false,
      sourcePriority:{changed:prioritized.some((value,index)=>value!==original[index]),first:prioritized.slice(0,12).map((value)=>path.basename(String(value)))},
      feature,calibration:result?.probeCalibration||null,fullProbe,
      oracle:{knownPrefix:result?.oracle?.status||null,unknownPrefix:result?.unknownPrefixOracle?.status||null}
    }
  };
}

async function runScaAutopilotPaths(filePaths,options={}){
  const original=list(filePaths);const prioritized=prioritizeScaPaths(original);const intent=await inspectQualityIntent(prioritized);
  let result;
  try{result=await batch50.runScaAutopilotPaths(prioritized,{...options,strictQuality:options.strictQuality===true||intent.strong});}
  catch(error){
    if(!intent.strong)throw error;
    return {schema:'newcyber.sca-autopilot.v5',version:55,status:'gap',flag:null,gap:{code:'QUALITY_PIPELINE_ERROR',detail:error?.message||String(error),stage:'engine-dispatch'},stages:[stage('engine-dispatch','gap',`Batch55 strict quality pipeline error: ${error?.message||String(error)}`)],qualityRoute:{engine:'batch55-quality-first',selectedEngine:'quality-error',qualityIntent:intent,rawDowngradeBlocked:true}};
  }
  return decorateResult(result,intent,prioritized,original);
}

module.exports={...batch50,runScaAutopilotPaths,prioritizeScaPaths,inspectQualityIntent,featureTelemetry,fullProbeTelemetry};
