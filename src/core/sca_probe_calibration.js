'use strict';

const {fitLeakageProfile}=require('./side_channel_probe');

const MAX_TRAIN_ROWS=4096;
const MAX_VALIDATE_ROWS=128;
const MAX_FULL_SAMPLE_ROWS=128;

function list(value){return Array.isArray(value)?value:[];}
function dot(a,b){let s=0;for(let i=0;i<a.length;i++)s+=Number(a[i])*Number(b[i]);return s;}
function norm(a){return Math.sqrt(Math.max(0,dot(a,a)));}
function cosine(a,b){const den=(norm(a)||1)*(norm(b)||1);return dot(a,b)/den;}
function mse(a,b){let s=0;for(let i=0;i<a.length;i++){const e=Number(a[i])-Number(b[i]);s+=e*e;}return s/Math.max(1,a.length);}

function probeVector(probeMatrix,orientation,index){
  if(orientation==='candidate-rows')return probeMatrix[index].map(Number);
  return Array.from({length:probeMatrix.length},(_,row)=>Number(probeMatrix[row][index]));
}

function applyLinearProfile(profile,input){
  const output=Array(profile.leakageDim).fill(0);
  for(let c=0;c<output.length;c++){
    let value=Number(profile.intercept[c]||0);
    for(let d=0;d<profile.hiddenDim;d++)value+=Number(input[d])*Number(profile.weights[d][c]);
    output[c]=value;
  }
  return output;
}

function spreadIndices(indices,limit){
  if(indices.length<=limit)return indices.slice();
  const out=[];
  for(let i=0;i<limit;i++)out.push(indices[Math.min(indices.length-1,Math.floor(i*indices.length/limit))]);
  return [...new Set(out)];
}

function profileRows(hiddenStates,profileTokenSequences,probeMatrix,orientation,candidateIds){
  const idToIndex=new Map();
  candidateIds.forEach((id,index)=>{if(!idToIndex.has(Number(id)))idToIndex.set(Number(id),index);});
  const rows=[];
  for(let index=0;index<hiddenStates.length;index++){
    const seq=list(profileTokenSequences[index]);
    const tokenId=Number(seq[seq.length-1]);
    const candidateIndex=idToIndex.get(tokenId);
    if(candidateIndex==null)continue;
    const hidden=hiddenStates[index].map(Number);
    const embedding=probeVector(probeMatrix,orientation,candidateIndex);
    if(hidden.length!==embedding.length||hidden.some((v)=>!Number.isFinite(v))||embedding.some((v)=>!Number.isFinite(v)))continue;
    rows.push({index,tokenId,hidden,embedding});
  }
  return rows;
}

function splitRows(rows,options={}){
  const validationStride=Math.max(3,Math.min(11,Number(options.validationStride)||5));
  const validation=rows.filter((_,index)=>index%validationStride===0);
  const training=rows.filter((_,index)=>index%validationStride!==0);
  return {
    training:spreadIndices(training,Math.max(32,Math.min(MAX_TRAIN_ROWS,Number(options.maxTrainRows)||MAX_TRAIN_ROWS))),
    validation:spreadIndices(validation,Math.max(8,Math.min(MAX_VALIDATE_ROWS,Number(options.maxValidationRows)||MAX_VALIDATE_ROWS)))
  };
}

function fitBlockModel(training,hiddenDim,layout,options={}){
  const groups=Number(layout?.groupsPerToken||0),width=Number(layout?.hiddenPerGroup||0);
  if(!Number.isSafeInteger(groups)||!Number.isSafeInteger(width)||groups<=0||width<=0||groups*width!==hiddenDim)return {status:'layout-gap'};
  const profiles=[];
  for(let group=0;group<groups;group++){
    const start=group*width,end=start+width;
    const x=training.map((row)=>row.hidden.slice(start,end));
    const y=training.map((row)=>row.embedding.slice(start,end));
    const profile=fitLeakageProfile(x,y,{lambda:Math.max(1e-12,Number(options.lambda??1e-4)),intercept:true});
    if(profile.status!=='ok')return {status:'fit-gap',group,detail:profile.status};
    profiles.push(profile);
  }
  return {
    status:'ok',mode:'grouped-block-ridge',groups,width,
    project(hidden){const out=[];for(let group=0;group<groups;group++){const start=group*width;out.push(...applyLinearProfile(profiles[group],hidden.slice(start,start+width)));}return out;}
  };
}

function fitFullSampleModel(training,hiddenDim,options={}){
  const sampled=spreadIndices(training,Math.max(32,Math.min(MAX_FULL_SAMPLE_ROWS,Number(options.fullSampleRows)||MAX_FULL_SAMPLE_ROWS)));
  if(sampled.length<32)return {status:'sample-gap'};
  const profile=fitLeakageProfile(sampled.map((row)=>row.hidden),sampled.map((row)=>row.embedding),{lambda:Math.max(1e-12,Number(options.fullLambda??options.lambda??1e-3)),intercept:true});
  if(profile.status!=='ok')return {status:'fit-gap',detail:profile.status};
  if(profile.hiddenDim!==hiddenDim||profile.leakageDim!==hiddenDim)return {status:'dimension-gap'};
  return {status:'ok',mode:'sampled-full-ridge',sampleRows:sampled.length,project:(hidden)=>applyLinearProfile(profile,hidden)};
}

function evaluateModel(model,validation){
  if(!validation.length)return {rows:0,rawCosine:null,calibratedCosine:null,rawMse:null,calibratedMse:null};
  let rawCos=0,calCos=0,rawErr=0,calErr=0;
  for(const row of validation){const projected=model.project(row.hidden);rawCos+=cosine(row.hidden,row.embedding);calCos+=cosine(projected,row.embedding);rawErr+=mse(row.hidden,row.embedding);calErr+=mse(projected,row.embedding);}
  return {rows:validation.length,rawCosine:rawCos/validation.length,calibratedCosine:calCos/validation.length,rawMse:rawErr/validation.length,calibratedMse:calErr/validation.length};
}

function scoreEvaluation(value){
  if(!value||!Number.isFinite(value.calibratedCosine))return-Infinity;
  const mseGain=Number.isFinite(value.rawMse)&&value.rawMse>0?Math.max(-1,Math.min(1,1-value.calibratedMse/value.rawMse)):0;
  return value.calibratedCosine+0.05*mseGain;
}

function fitProbeCalibration({hiddenStates,profileTokenSequences,probeMatrix,probeOptions,layout,options={}}={}){
  const hidden=list(hiddenStates),sequences=list(profileTokenSequences),candidateIds=list(probeOptions?.candidateIds).map(Number);
  if(!hidden.length||hidden.length!==sequences.length)return {status:'not-applicable',reason:'profiling hidden/token rows unavailable'};
  if(!Array.isArray(probeMatrix)||!probeMatrix.length||!candidateIds.length)return {status:'not-applicable',reason:'probe/candidate map unavailable'};
  const orientation=probeOptions?.orientation;
  if(!['candidate-rows','candidate-cols'].includes(orientation))return {status:'not-applicable',reason:'probe orientation unresolved'};
  const hiddenDim=hidden[0]?.length||0;
  if(!hiddenDim||hidden.some((row)=>!Array.isArray(row)||row.length!==hiddenDim))return {status:'not-applicable',reason:'profiling hidden dimension inconsistent'};
  const rows=profileRows(hidden,sequences,probeMatrix,orientation,candidateIds);
  const coverage=rows.length/hidden.length;
  if(rows.length<64||coverage<0.5)return {status:'not-applicable',reason:`profiling token→probe coverage ${rows.length}/${hidden.length} is insufficient`,coverage,rows:rows.length};
  const split=splitRows(rows,options);
  if(split.training.length<32||split.validation.length<8)return {status:'not-applicable',reason:'not enough train/validation rows for probe calibration'};

  const candidates=[];
  const block=fitBlockModel(split.training,hiddenDim,layout,options);
  if(block.status==='ok')candidates.push({model:block,evaluation:evaluateModel(block,split.validation)});
  const blockEval=candidates[0]?.evaluation;
  const tryFull=options.fullSampled!==false&&(!blockEval||blockEval.calibratedCosine<0.97||blockEval.calibratedCosine-blockEval.rawCosine<0.03);
  if(tryFull){const full=fitFullSampleModel(split.training,hiddenDim,options);if(full.status==='ok')candidates.push({model:full,evaluation:evaluateModel(full,split.validation)});}
  if(!candidates.length)return {status:'not-applicable',reason:'ridge calibration could not be fit'};
  candidates.sort((a,b)=>scoreEvaluation(b.evaluation)-scoreEvaluation(a.evaluation));
  const best=candidates[0];
  const minGain=Math.max(0,Number(options.minCosineGain??0.005));
  const cosineGain=best.evaluation.calibratedCosine-best.evaluation.rawCosine;
  const mseImproved=!Number.isFinite(best.evaluation.rawMse)||best.evaluation.calibratedMse<best.evaluation.rawMse;
  if(!(cosineGain>=minGain&&mseImproved))return {status:'not-beneficial',coverage,rows:rows.length,trainingRows:split.training.length,validationRows:split.validation.length,mode:best.model.mode,evaluation:best.evaluation,cosineGain};
  const summary={schema:'newcyber.sca-probe-calibration.v1',status:'accepted',mode:best.model.mode,coverage,rows:rows.length,trainingRows:split.training.length,validationRows:split.validation.length,hiddenDim,cosineGain,evaluation:best.evaluation,candidates:candidates.map((item)=>({mode:item.model.mode,evaluation:item.evaluation}))};
  return {status:'ok',summary,project:best.model.project};
}

module.exports={probeVector,applyLinearProfile,fitProbeCalibration};
