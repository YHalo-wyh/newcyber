'use strict';

// Contextual hidden-state verifier for unknown-prefix SCA recovery.
// Candidate ranking is only a proposal. A token is accepted when replaying the
// recovered prefix + candidate through the ONNX transformer reproduces the
// recovered target hidden state above the cosine threshold. If the shortlist
// misses, the same oracle scans the proven candidate-id vocabulary in batches.
const {withSession,tensorFromSpec}=require('./local_ml_runtime');
const {classifyTransformerSession}=require('./transformer_oracle');

const MAX_CONTEXTUAL_TOKENS=4096;
const MAX_CONTEXTUAL_CANDIDATES=200000;
const MAX_CONTEXTUAL_BATCH=64;
const DEFAULT_CONTEXTUAL_BATCH=16;

function list(value){return Array.isArray(value)?value:[];}
function dot(a,b){let s=0;for(let i=0;i<a.length;i++)s+=Number(a[i])*Number(b[i]);return s;}
function norm(a){return Math.sqrt(Math.max(0,dot(a,a)));}
function cosine(a,b){return dot(a,b)/((norm(a)||1)*(norm(b)||1));}
function genericFlag(text){return String(text||'').match(/[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,256}\}/)?.[0]||null;}
function uniqueIds(values){return [...new Set(Array.from(values||[],Number).filter((id)=>Number.isSafeInteger(id)&&id>=0))];}

function tensorType(metadata,fallback='int64'){
  const value=String(metadata?.type||'').toLowerCase();
  if(/int64/.test(value))return'int64';
  if(/int32/.test(value))return'int32';
  if(/float16/.test(value))return'float32';
  if(/float/.test(value))return'float32';
  if(/bool/.test(value))return'bool';
  return fallback;
}

function metadataBatchIsStaticOne(metadata){
  const dims=Array.isArray(metadata?.dimensions)?metadata.dimensions:[];
  const symbolic=Array.isArray(metadata?.symbolicDimensions)?metadata.symbolicDimensions:[];
  if(!dims.length)return false;
  const label=String(symbolic[0]??dims[0]??'').toLowerCase();
  return Number(dims[0])===1&&!/batch/.test(label);
}

function emptyCacheSpec(item,batchSize=1){
  const dims=Array.isArray(item?.metadata?.dimensions)?item.metadata.dimensions.slice():[];
  const symbolic=Array.isArray(item?.metadata?.symbolicDimensions)?item.metadata.symbolicDimensions.slice():[];
  if(!dims.length)return null;
  let zeroEvidence=false;
  const resolved=[];
  for(let index=0;index<dims.length;index++){
    const raw=dims[index];const label=String(symbolic[index]??raw??'').toLowerCase();
    if(index===0&&/batch/.test(label)){resolved.push(batchSize);continue;}
    if(/past|cache|sequence|seq/.test(label)){resolved.push(0);zeroEvidence=true;continue;}
    if(Number.isInteger(raw)&&raw>=0){
      if(index===0&&raw===1&&batchSize>1&&!/batch/.test(label))return null;
      resolved.push(raw);continue;
    }
    if(index===0){resolved.push(batchSize);continue;}
    resolved.push(1);
  }
  if(!zeroEvidence||resolved.reduce((a,b)=>a*b,1)!==0)return null;
  return {type:tensorType(item.metadata,'float32'),dims:resolved,values:[]};
}

function repeatTensorBatch(ort,tensor,batchSize){
  if(batchSize===1)return tensor;
  if(!tensor?.data||!Array.isArray(tensor.dims)||!tensor.dims.length||Number(tensor.dims[0])!==1)return null;
  const perBatch=tensor.data.length;
  const Ctor=tensor.data.constructor;
  const data=new Ctor(perBatch*batchSize);
  for(let batch=0;batch<batchSize;batch++)data.set(tensor.data,batch*perBatch);
  const dims=tensor.dims.slice();dims[0]=batchSize;
  return new ort.Tensor(tensor.type,data,dims);
}

function integerSpec(values,metadata,dims){return {type:tensorType(metadata,'int64'),dims,values};}

function flattenFullReplay(prefix,candidates){
  const seqLen=prefix.length+1;const values=[];
  for(const candidate of candidates)values.push(...prefix,candidate);
  return {values,seqLen};
}

function buildFeeds(session,ort,recipe,prefix,candidates,cacheState,pastLength){
  const batchSize=candidates.length;
  const feeds={};
  const cacheMode=recipe.cache.mode;
  let seqLen;
  if(cacheMode==='paired'){
    seqLen=1;
    feeds[recipe.roles.inputIds.name]=tensorFromSpec(ort,integerSpec(candidates,recipe.roles.inputIds.metadata,[batchSize,1]));
  }else{
    const replay=flattenFullReplay(prefix,candidates);seqLen=replay.seqLen;
    feeds[recipe.roles.inputIds.name]=tensorFromSpec(ort,integerSpec(replay.values,recipe.roles.inputIds.metadata,[batchSize,seqLen]));
  }

  if(recipe.roles.attentionMask){
    const total=cacheMode==='paired'?pastLength+1:seqLen;
    feeds[recipe.roles.attentionMask.name]=tensorFromSpec(ort,integerSpec(Array(batchSize*total).fill(1),recipe.roles.attentionMask.metadata,[batchSize,total]));
  }
  if(recipe.roles.positionIds){
    let positions;
    if(cacheMode==='paired')positions=Array(batchSize).fill(pastLength);
    else{positions=[];for(let batch=0;batch<batchSize;batch++)for(let index=0;index<seqLen;index++)positions.push(index);}
    feeds[recipe.roles.positionIds.name]=tensorFromSpec(ort,integerSpec(positions,recipe.roles.positionIds.metadata,[batchSize,seqLen]));
  }

  for(const item of recipe.cache.inputs){
    let tensor=null;
    if(cacheState?.[item.name])tensor=repeatTensorBatch(ort,cacheState[item.name],batchSize);
    else{const spec=emptyCacheSpec(item,batchSize);if(spec)tensor=tensorFromSpec(ort,spec);}
    if(!tensor)throw new Error(`cache-batch-gap:${item.name}`);
    feeds[item.name]=tensor;
  }
  if(recipe.unknownInputs.length)throw new Error(`unknown-input-gap:${recipe.unknownInputs.map((item)=>item.name).join(',')}`);
  for(const name of session.inputNames)if(!feeds[name])throw new Error(`unknown-input-gap:${name}`);
  return {feeds,seqLen};
}

function extractLastHiddenBatch(tensor,batchSize){
  if(!tensor?.data||!Array.isArray(tensor.dims)||!tensor.dims.length)return null;
  const hiddenDim=Number(tensor.dims[tensor.dims.length-1]);
  if(!Number.isSafeInteger(hiddenDim)||hiddenDim<=0||tensor.data.length%(batchSize*hiddenDim)!==0)return null;
  const vectorsPerBatch=tensor.data.length/(batchSize*hiddenDim);
  if(!Number.isSafeInteger(vectorsPerBatch)||vectorsPerBatch<=0)return null;
  const output=[];
  for(let batch=0;batch<batchSize;batch++){
    const start=(batch*vectorsPerBatch+(vectorsPerBatch-1))*hiddenDim;
    output.push(Array.from(tensor.data.slice(start,start+hiddenDim),Number));
  }
  return output;
}

function batchLimitForRecipe(recipe,requested){
  let limit=Math.max(1,Math.min(MAX_CONTEXTUAL_BATCH,Number(requested)||DEFAULT_CONTEXTUAL_BATCH));
  if(metadataBatchIsStaticOne(recipe.roles.inputIds?.metadata))limit=1;
  for(const item of recipe.cache.inputs)if(metadataBatchIsStaticOne(item.metadata))limit=1;
  return limit;
}

function createOnnxRunner(session,ort,recipe,options={}){
  if(recipe.cache.mode==='unpaired')return {status:'gap',reason:'cache-pair-gap'};
  if(!recipe.roles.hidden)return {status:'gap',reason:'hidden-state-output-gap'};
  let cacheState=null;let pastLength=0;
  let maxBatchSize=batchLimitForRecipe(recipe,options.batchSize);
  let batchFallbacks=0;let calls=0;

  async function runOneBatch(prefix,candidates,wantCache=false){
    const built=buildFeeds(session,ort,recipe,prefix,candidates,cacheState,pastLength);
    const wanted=new Set([recipe.roles.hidden.name]);
    if(wantCache)for(const pair of recipe.cache.pairs)wanted.add(pair.output);
    const output=await session.run(built.feeds,Object.fromEntries(Array.from(wanted,(name)=>[name,null])));calls+=1;
    const hiddenStates=extractLastHiddenBatch(output[recipe.roles.hidden.name],candidates.length);
    if(!hiddenStates)return {status:'gap',reason:'hidden-state-layout-gap'};
    return {status:'ok',hiddenStates,output};
  }

  async function score({prefixTokenIds,candidateTokenIds}){
    const prefix=uniqueIds([]).concat(Array.from(prefixTokenIds||[],Number));
    const ids=uniqueIds(candidateTokenIds);
    if(!ids.length)return {status:'gap',reason:'candidate-gap'};
    const all=[];
    for(let start=0;start<ids.length;){
      const count=Math.min(maxBatchSize,ids.length-start);const batch=ids.slice(start,start+count);
      try{
        const result=await runOneBatch(prefix,batch,false);
        if(result.status!=='ok')return result;
        all.push(...result.hiddenStates);start+=count;
      }catch(error){
        if(count>1){maxBatchSize=1;batchFallbacks+=1;continue;}
        return {status:'gap',reason:error?.message||String(error)};
      }
    }
    return {status:'ok',hiddenStates:all,maxBatchSize};
  }

  async function commit({prefixTokenIds,tokenId}){
    if(recipe.cache.mode!=='paired')return {status:'ok'};
    const prefix=Array.from(prefixTokenIds||[],Number);
    let result;
    try{result=await runOneBatch(prefix,[Number(tokenId)],true);}catch(error){return {status:'gap',reason:error?.message||String(error)};}
    if(result.status!=='ok')return result;
    const next={};
    for(const pair of recipe.cache.pairs){const tensor=result.output[pair.output];if(!tensor)return {status:'gap',reason:`cache-output-gap:${pair.output}`};next[pair.input]=tensor;}
    cacheState=next;pastLength+=1;
    return {status:'ok'};
  }

  return {status:'ok',score,commit,get maxBatchSize(){return maxBatchSize;},telemetry:()=>({calls,batchFallbacks,cacheUsed:recipe.cache.mode==='paired',maxBatchSize,pastLength})};
}

async function scoreCandidates(runner,prefix,candidateIds,targetHidden){
  const result=await runner.score({prefixTokenIds:prefix,candidateTokenIds:candidateIds});
  if(result.status!=='ok')return result;
  if(result.hiddenStates.length!==candidateIds.length)return {status:'gap',reason:'candidate-hidden-count-gap'};
  const scored=candidateIds.map((tokenId,index)=>({tokenId,cosine:cosine(result.hiddenStates[index],targetHidden)})).sort((a,b)=>b.cosine-a.cosine||a.tokenId-b.tokenId);
  return {status:'ok',scored,best:scored[0]||null};
}

async function decodeWithHiddenRunner({targetHiddenStates,targetCandidates,allCandidateIds,tokenizer,cosineThreshold=0.99,exactStopCosine=0.999999,fullScan=true}={},runner){
  const hidden=list(targetHiddenStates);const rows=list(targetCandidates);const vocabulary=uniqueIds(allCandidateIds);
  if(!hidden.length||hidden.length!==rows.length)return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'not-applicable',reason:'target hidden/candidate rows unavailable'};
  if(hidden.length>MAX_CONTEXTUAL_TOKENS)return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_TOKEN_BUDGET_GAP',detail:`target tokens=${hidden.length} exceeds ${MAX_CONTEXTUAL_TOKENS}`};
  if(!vocabulary.length||vocabulary.length>MAX_CONTEXTUAL_CANDIDATES)return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_VOCAB_BUDGET_GAP',detail:`candidate vocabulary=${vocabulary.length} is invalid or exceeds ${MAX_CONTEXTUAL_CANDIDATES}`};
  const threshold=Math.max(-1,Math.min(1,Number(cosineThreshold)||0.99));
  const exactThreshold=Math.max(threshold,Math.min(1,Number(exactStopCosine)||0.999999));
  const recovered=[];const positions=[];let shortlistHits=0,fallbackPositions=0,fullScanCandidates=0;

  for(let index=0;index<hidden.length;index++){
    const target=list(hidden[index]).map(Number);
    if(!target.length||target.some((value)=>!Number.isFinite(value)))return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_TARGET_HIDDEN_GAP',detail:`target hidden ${index} invalid`,recoveredTokenIds:recovered,positions};
    const shortlist=uniqueIds(rows[index].map((item)=>item?.tokenId)).filter((id)=>vocabulary.includes(id));
    if(!shortlist.length)return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_SHORTLIST_GAP',detail:`position ${index} has no valid shortlist`,recoveredTokenIds:recovered,positions};

    const shortlistScore=await scoreCandidates(runner,recovered,shortlist,target);
    if(shortlistScore.status!=='ok')return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_ORACLE_RUN_GAP',detail:shortlistScore.reason||shortlistScore.status,recoveredTokenIds:recovered,positions};
    let chosen=shortlistScore.best;let mode='shortlist';let scanned=shortlist.length;
    if(chosen&&chosen.cosine>=threshold)shortlistHits+=1;
    else if(fullScan){
      mode='full-vocab-fallback';fallbackPositions+=1;
      const excluded=new Set(shortlist);let best=chosen;
      const remaining=vocabulary.filter((id)=>!excluded.has(id));
      const chunkSize=Math.max(1,Number(runner.maxBatchSize)||DEFAULT_CONTEXTUAL_BATCH);
      for(let start=0;start<remaining.length;start+=chunkSize){
        const batch=remaining.slice(start,start+chunkSize);const scored=await scoreCandidates(runner,recovered,batch,target);
        if(scored.status!=='ok')return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_ORACLE_RUN_GAP',detail:scored.reason||scored.status,recoveredTokenIds:recovered,positions};
        scanned+=batch.length;fullScanCandidates+=batch.length;
        if(scored.best&&(!best||scored.best.cosine>best.cosine))best=scored.best;
        if(best&&best.cosine>=exactThreshold)break;
      }
      chosen=best;
    }

    if(!chosen||!Number.isFinite(chosen.cosine)||chosen.cosine<threshold){
      positions.push({index,status:'no-match',mode,bestTokenId:chosen?.tokenId??null,bestCosine:chosen?.cosine??null,scannedCandidates:scanned});
      return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_HIDDEN_MATCH_GAP',detail:`position ${index} best cosine=${chosen?.cosine??'n/a'} < ${threshold}`,recoveredTokenIds:recovered,positions,threshold};
    }
    const committed=typeof runner.commit==='function'?await runner.commit({prefixTokenIds:recovered,tokenId:chosen.tokenId,position:index}):{status:'ok'};
    if(committed?.status!=='ok')return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_CACHE_COMMIT_GAP',detail:committed?.reason||committed?.status,recoveredTokenIds:recovered,positions};
    recovered.push(chosen.tokenId);
    positions.push({index,status:'matched',mode,tokenId:chosen.tokenId,cosine:chosen.cosine,shortlistBestCosine:shortlistScore.best?.cosine??null,scannedCandidates:scanned});
  }

  let text=null;try{text=tokenizer?.decode?tokenizer.decode(recovered):null;}catch{}
  const cosines=positions.map((item)=>Number(item.cosine)).filter(Number.isFinite);
  const flag=genericFlag(text);
  return {
    schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'decoded',mode:'profiling-calibrated-contextual-hidden-replay',
    recoveredTokenIds:recovered,recoveredText:text,flag,threshold,positions,shortlistHits,fallbackPositions,fullScanCandidates,
    cosine:{min:cosines.length?Math.min(...cosines):null,mean:cosines.length?cosines.reduce((a,b)=>a+b,0)/cosines.length:null},
    runtime:typeof runner.telemetry==='function'?runner.telemetry():null
  };
}

async function runContextualHiddenOracle(model,request={},options={}){
  if(options.hiddenBatchRunner){
    const runner=options.hiddenBatchRunner;
    if(typeof runner.score!=='function')return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_RUNNER_GAP',detail:'hiddenBatchRunner.score missing'};
    return decodeWithHiddenRunner(request,runner);
  }
  return withSession(model,options,async(session,ort)=>{
    const recipe=classifyTransformerSession(session);
    if(!recipe.supported)return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_MODEL_RECIPE_GAP',detail:'unable to resolve transformer input/logits recipe',recipe};
    if(!recipe.roles.hidden)return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_HIDDEN_OUTPUT_GAP',detail:'ONNX oracle has no hidden-state output',recipe};
    const runner=createOnnxRunner(session,ort,recipe,{batchSize:request.batchSize??options.contextualOracleBatchSize});
    if(runner.status!=='ok')return {schema:'newcyber.sca-contextual-hidden-oracle.v1',status:'gap',code:'CONTEXTUAL_MODEL_RECIPE_GAP',detail:runner.reason,recipe};
    return decodeWithHiddenRunner(request,runner);
  });
}

module.exports={
  MAX_CONTEXTUAL_TOKENS,MAX_CONTEXTUAL_CANDIDATES,DEFAULT_CONTEXTUAL_BATCH,
  cosine,emptyCacheSpec,extractLastHiddenBatch,createOnnxRunner,scoreCandidates,decodeWithHiddenRunner,runContextualHiddenOracle
};
