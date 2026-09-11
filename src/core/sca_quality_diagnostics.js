'use strict';

const SCA_QUALITY_THRESHOLD=0.99;

function list(value){return Array.isArray(value)?value:[];}
function finite(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function mean(values){return values.length?values.reduce((sum,value)=>sum+value,0)/values.length:null;}
function boundedEvidence(value){return list(value).slice(0,32).map((item)=>String(item).slice(0,180));}

function guardBaselineDiagnostics(featureRecipe){
  const guard=featureRecipe?.baselineGuard;
  if(!guard)return {status:'not-proven',enabled:false,mode:null,leading:null,trailing:null,subtract:null,evidence:[]};
  return {
    status:'proven',enabled:true,
    mode:guard.mode||null,
    leading:Number.isSafeInteger(Number(guard.leading))?Number(guard.leading):null,
    trailing:Number.isSafeInteger(Number(guard.trailing))?Number(guard.trailing):null,
    subtract:guard.subtract||null,
    evidence:boundedEvidence(guard.evidence)
  };
}

function leakageGroupDiagnostics(profile,threshold=SCA_QUALITY_THRESHOLD){
  const groups=list(profile?.profiles);
  const finiteRows=[];const anomalies=[];
  for(let index=0;index<groups.length;index+=1){
    const item=groups[index]||{};const group=Number.isSafeInteger(Number(item.group))?Number(item.group):index;const r2=finite(item.r2);
    if(r2===null){anomalies.push({group,r2:null,gapToThreshold:null,reason:'non-finite-r2'});continue;}
    finiteRows.push({group,r2});
    if(r2+1e-12<threshold)anomalies.push({group,r2,gapToThreshold:threshold-r2,reason:'below-threshold'});
  }
  const values=finiteRows.map((item)=>item.r2);
  return {
    status:groups.length?'observed':'unavailable',threshold,totalGroups:groups.length,count:values.length,
    minR2:values.length?Math.min(...values):null,
    meanR2:mean(values),
    maxR2:values.length?Math.max(...values):null,
    invalidGroups:Math.max(0,groups.length-values.length),
    anomalousGroups:anomalies.slice(0,128)
  };
}

function probeCalibrationDiagnostics(calibration,stages){
  const stage=list(stages).find((item)=>item?.id==='probe-calibration')||null;
  if(!calibration){
    return {status:stage?.status==='skip'?'not-applied':'unavailable',accepted:false,mode:null,detail:stage?.detail||null,evaluation:null,cosineGain:null,coverage:null,trainingRows:null,validationRows:null,lambda:null,rerank:null};
  }
  const evaluation=calibration.evaluation||{};
  const rawCosine=finite(evaluation.rawCosine),calibratedCosine=finite(evaluation.calibratedCosine);
  const explicitGain=finite(calibration.cosineGain);
  const cosineGain=explicitGain!==null?explicitGain:(rawCosine!==null&&calibratedCosine!==null?calibratedCosine-rawCosine:null);
  const rerank=calibration.rerankTelemetry||null;
  return {
    status:calibration.status||stage?.status||'observed',accepted:calibration.status==='accepted',mode:calibration.mode||null,detail:stage?.detail||null,
    coverage:finite(calibration.coverage),rows:Number.isSafeInteger(Number(calibration.rows))?Number(calibration.rows):null,
    trainingRows:Number.isSafeInteger(Number(calibration.trainingRows))?Number(calibration.trainingRows):null,
    validationRows:Number.isSafeInteger(Number(calibration.validationRows))?Number(calibration.validationRows):null,
    lambda:finite(calibration.lambda),cosineGain,
    evaluation:{rawCosine,calibratedCosine,rawMse:finite(evaluation.rawMse),calibratedMse:finite(evaluation.calibratedMse)},
    rerank:rerank?{
      status:rerank.status||null,
      rows:Number.isSafeInteger(Number(rerank.rows))?Number(rerank.rows):null,
      fullScanAttemptedRows:Number.isSafeInteger(Number(rerank.fullScanAttemptedRows))?Number(rerank.fullScanAttemptedRows):null,
      fullScanSucceededRows:Number.isSafeInteger(Number(rerank.fullScanSucceededRows))?Number(rerank.fullScanSucceededRows):null,
      fullProbeExpandedRows:Number.isSafeInteger(Number(rerank.fullProbeExpandedRows))?Number(rerank.fullProbeExpandedRows):null,
      top1ChangedRows:Number.isSafeInteger(Number(rerank.top1ChangedRows))?Number(rerank.top1ChangedRows):null
    }:null
  };
}

function contextualPositionDiagnostics(contextual,threshold=SCA_QUALITY_THRESHOLD){
  const positions=list(contextual?.positions);const oracleThreshold=finite(contextual?.threshold);const values=[];let passed=0;
  const rows=positions.slice(0,4096).map((item,index)=>{
    const cosine=finite(item?.cosine);const passes=cosine!==null&&cosine+1e-12>=threshold;
    if(cosine!==null)values.push(cosine);if(passes)passed+=1;
    return {
      index:Number.isSafeInteger(Number(item?.index))?Number(item.index):index,
      status:item?.status||null,mode:item?.mode||null,
      tokenId:Number.isSafeInteger(Number(item?.tokenId))?Number(item.tokenId):null,
      cosine,gapToThreshold:cosine===null?null:threshold-cosine,passes
    };
  });
  return {
    status:positions.length?'observed':'unavailable',threshold,oracleThreshold,
    thresholdDrift:oracleThreshold===null?null:oracleThreshold-threshold,
    count:positions.length,reported:rows.length,passed,failed:Math.max(0,positions.length-passed),
    minCosine:values.length?Math.min(...values):null,meanCosine:mean(values),maxCosine:values.length?Math.max(...values):null,
    positions:rows
  };
}

function buildScaQualityDiagnostics(result){
  const threshold=SCA_QUALITY_THRESHOLD;
  return {
    schema:'newcyber.sca-quality-diagnostics.v1',observationalOnly:true,
    policy:{mayUpgradeResult:false,leakageR2Threshold:threshold,contextualCosineThreshold:threshold},
    guardBaseline:guardBaselineDiagnostics(result?.featureRecipe),
    leakageGroups:leakageGroupDiagnostics(result?.profile,threshold),
    probeCalibration:probeCalibrationDiagnostics(result?.probeCalibration,result?.stages),
    contextual:contextualPositionDiagnostics(result?.contextualHiddenOracle,threshold)
  };
}

function attachScaQualityDiagnostics(result){
  if(!result||typeof result!=='object')return result;
  const existing=result.diagnostics&&typeof result.diagnostics==='object'&&!Array.isArray(result.diagnostics)?result.diagnostics:{};
  return {...result,diagnostics:{...existing,scaQuality:buildScaQualityDiagnostics(result)}};
}

module.exports={
  SCA_QUALITY_THRESHOLD,guardBaselineDiagnostics,leakageGroupDiagnostics,probeCalibrationDiagnostics,
  contextualPositionDiagnostics,buildScaQualityDiagnostics,attachScaQualityDiagnostics
};
