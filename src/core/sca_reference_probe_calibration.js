'use strict';

// Reference-quality hidden -> token-embedding calibration for grouped SCA.
// This mirrors the successful phase2c_free.py strategy used by the leakage
// challenge: learn one global ridge map from profiling hidden states to WTE
// vectors, then use the map only to prioritize candidates. Final acceptance is
// performed by contextual ONNX hidden-state replay, not by cosine to WTE alone.
const {fitLeakageProfile}=require('./side_channel_probe');
const {probeVector,applyLinearProfile}=require('./sca_probe_calibration');

const MAX_REFERENCE_TRAIN_ROWS=512;
const DEFAULT_REFERENCE_TRAIN_ROWS=384;
const MAX_REFERENCE_VALIDATE_ROWS=128;

function list(value){return Array.isArray(value)?value:[];}
function dot(a,b){let s=0;for(let i=0;i<a.length;i++)s+=Number(a[i])*Number(b[i]);return s;}
function norm(a){return Math.sqrt(Math.max(0,dot(a,a)));}
function cosine(a,b){return dot(a,b)/((norm(a)||1)*(norm(b)||1));}
function mse(a,b){let s=0;for(let i=0;i<a.length;i++){const e=Number(a[i])-Number(b[i]);s+=e*e;}return s/Math.max(1,a.length);}

function spreadRows(rows,limit){
  if(rows.length<=limit)return rows.slice();
  const out=[];
  for(let i=0;i<limit;i++)out.push(rows[Math.min(rows.length-1,Math.floor(i*rows.length/limit))]);
  return out;
}

function buildProfileRows(hiddenStates,profileTokenSequences,probeMatrix,orientation,candidateIds){
  const idToIndex=new Map();
  candidateIds.forEach((id,index)=>{const value=Number(id);if(Number.isSafeInteger(value)&&value>=0&&!idToIndex.has(value))idToIndex.set(value,index);});
  const rows=[];
  for(let index=0;index<hiddenStates.length;index++){
    const sequence=list(profileTokenSequences[index]);
    const tokenId=Number(sequence[sequence.length-1]);
    const candidateIndex=idToIndex.get(tokenId);
    if(candidateIndex==null)continue;
    const hidden=list(hiddenStates[index]).map(Number);
    const embedding=probeVector(probeMatrix,orientation,candidateIndex);
    if(!hidden.length||hidden.length!==embedding.length)continue;
    if(hidden.some((value)=>!Number.isFinite(value))||embedding.some((value)=>!Number.isFinite(value)))continue;
    rows.push({index,tokenId,hidden,embedding});
  }
  return rows;
}

function splitRows(rows,options={}){
  const stride=Math.max(4,Math.min(17,Number(options.validationStride)||7));
  const validation=rows.filter((_,index)=>index%stride===0);
  const training=rows.filter((_,index)=>index%stride!==0);
  const requested=Math.max(64,Math.min(MAX_REFERENCE_TRAIN_ROWS,Number(options.trainRows)||DEFAULT_REFERENCE_TRAIN_ROWS));
  return {
    trainingPoolRows:training.length,
    training:spreadRows(training,requested),
    validation:spreadRows(validation,Math.max(8,Math.min(MAX_REFERENCE_VALIDATE_ROWS,Number(options.validationRows)||96)))
  };
}

function evaluate(project,rows){
  if(!rows.length)return {rows:0,rawCosine:null,calibratedCosine:null,rawMse:null,calibratedMse:null};
  let rawCosine=0,calibratedCosine=0,rawMse=0,calibratedMse=0;
  for(const row of rows){
    const projected=project(row.hidden);
    rawCosine+=cosine(row.hidden,row.embedding);
    calibratedCosine+=cosine(projected,row.embedding);
    rawMse+=mse(row.hidden,row.embedding);
    calibratedMse+=mse(projected,row.embedding);
  }
  return {
    rows:rows.length,
    rawCosine:rawCosine/rows.length,
    calibratedCosine:calibratedCosine/rows.length,
    rawMse:rawMse/rows.length,
    calibratedMse:calibratedMse/rows.length
  };
}

function fitReferenceProbeCalibration({hiddenStates,profileTokenSequences,probeMatrix,probeOptions,options={}}={}){
  const hidden=list(hiddenStates),sequences=list(profileTokenSequences),candidateIds=list(probeOptions?.candidateIds).map(Number);
  if(!hidden.length||hidden.length!==sequences.length)return {status:'not-applicable',reason:'profiling hidden/token rows unavailable'};
  if(!Array.isArray(probeMatrix)||!probeMatrix.length||!candidateIds.length)return {status:'not-applicable',reason:'probe/candidate map unavailable'};
  const orientation=probeOptions?.orientation;
  if(!['candidate-rows','candidate-cols'].includes(orientation))return {status:'not-applicable',reason:'probe orientation unresolved'};
  const hiddenDim=hidden[0]?.length||0;
  if(!hiddenDim||hidden.some((row)=>!Array.isArray(row)||row.length!==hiddenDim))return {status:'not-applicable',reason:'profiling hidden dimension inconsistent'};

  const rows=buildProfileRows(hidden,sequences,probeMatrix,orientation,candidateIds);
  const coverage=rows.length/hidden.length;
  if(rows.length<64||coverage<0.5)return {status:'not-applicable',reason:`profiling token→WTE coverage ${rows.length}/${hidden.length} is insufficient`,coverage,rows:rows.length};
  const split=splitRows(rows,options);
  if(split.training.length<64||split.validation.length<8)return {status:'not-applicable',reason:'not enough profiling rows for global ridge calibration'};

  const lambda=Math.max(1e-12,Number(options.lambda??1.0));
  if(!Number.isFinite(lambda))return {status:'not-applicable',reason:'reference ridge lambda is invalid'};
  const profile=fitLeakageProfile(
    split.training.map((row)=>row.hidden),
    split.training.map((row)=>row.embedding),
    {lambda,intercept:true}
  );
  if(profile.status!=='ok')return {status:'not-applicable',reason:`global hidden→WTE ridge failed: ${profile.status}`,profile};
  if(profile.hiddenDim!==hiddenDim||profile.leakageDim!==hiddenDim)return {status:'not-applicable',reason:'global hidden→WTE ridge dimension mismatch'};

  const project=(row)=>applyLinearProfile(profile,row);
  const evaluation=evaluate(project,split.validation);
  const cosineGain=Number(evaluation.calibratedCosine)-Number(evaluation.rawCosine);
  const minGain=Number.isFinite(Number(options.minCosineGain))?Number(options.minCosineGain):-0.002;
  if(!Number.isFinite(evaluation.calibratedCosine)||cosineGain<minGain){
    return {status:'not-beneficial',reason:`global ridge holdout cosine gain ${Number.isFinite(cosineGain)?cosineGain.toFixed(6):'n/a'} < ${minGain}`,coverage,evaluation,cosineGain,lambda};
  }

  const rerankTelemetry={schema:'newcyber.sca-calibrated-rerank-telemetry.v1',status:'not-run'};
  const summary={
    schema:'newcyber.sca-probe-calibration.v2',status:'accepted',mode:'sampled-global-ridge-hidden-to-wte',
    referenceStrategy:'phase2c-free',lambda,coverage,rows:rows.length,trainingPoolRows:split.trainingPoolRows,
    trainingRows:split.training.length,validationRows:split.validation.length,hiddenDim,cosineGain,evaluation,rerankTelemetry
  };
  project.rerankTelemetry=rerankTelemetry;
  return {status:'ok',summary,project};
}

module.exports={
  MAX_REFERENCE_TRAIN_ROWS,DEFAULT_REFERENCE_TRAIN_ROWS,
  buildProfileRows,splitRows,evaluate,fitReferenceProbeCalibration
};
