'use strict';

const {runTransformerDecode}=require('./transformer_oracle');

const MAX_SEEDS=4;
const MAX_TARGET_TOKENS=256;
const MAX_REPLAY_STEPS=2048;

function list(value){return Array.isArray(value)?value:[];}
function genericFlag(text){return String(text||'').match(/[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,256}\}/)?.[0]||null;}

function candidateIds(rows){
  return list(rows).map((row)=>list(row).map((item)=>Number(item?.tokenId)).filter((id)=>Number.isSafeInteger(id)&&id>=0));
}

function agreement(sequence,rows){
  const ids=Array.from(sequence||[],Number);const candidates=candidateIds(rows);const count=Math.min(ids.length,candidates.length);
  let hits=0,top1=0,rankScore=0;
  for(let index=0;index<count;index++){
    const rank=candidates[index].indexOf(ids[index]);
    if(rank>=0){hits+=1;rankScore+=1/(rank+1);if(rank===0)top1+=1;}
  }
  return {positions:count,hits,hitRate:count?hits/count:0,top1,top1Rate:count?top1/count:0,meanReciprocalRank:count?rankScore/count:0};
}

function decodeText(tokenizer,ids){
  try{return tokenizer?.decode?tokenizer.decode(ids):null;}catch{return null;}
}

function summarize(mode,seed,oracle,rows,tokenizer){
  const sequence=[seed,...list(oracle?.generatedTokenIds).map(Number)];
  const text=oracle?.text||decodeText(tokenizer,sequence);
  const flag=oracle?.flag||genericFlag(text);
  return {mode,seed,status:oracle?.status||'unknown',sequence,text,flag,agreement:agreement(sequence,rows),generated:list(oracle?.generatedTokenIds).length,cacheUsed:Boolean(oracle?.cacheUsed)};
}

function replayScore(item){
  if(item.flag)return 1000+item.agreement.meanReciprocalRank;
  return item.agreement.hitRate*4+item.agreement.meanReciprocalRank*2+item.agreement.top1Rate;
}

async function runUnknownPrefixOracle(model,{targetCandidates,tokenizer,topK=8,seedBeam=2,maxTokens=null}={},options={}){
  const rows=list(targetCandidates);
  if(rows.length<2)return {schema:'newcyber.sca-unknown-prefix-oracle.v1',status:'not-applicable',reason:'need at least two recovered token positions'};
  if(rows.length>MAX_TARGET_TOKENS)return {schema:'newcyber.sca-unknown-prefix-oracle.v1',status:'gap',code:'UNKNOWN_PREFIX_TOKEN_BUDGET_GAP',detail:`target tokens=${rows.length} exceeds ${MAX_TARGET_TOKENS}`};
  const first=candidateIds(rows)[0];
  if(!first.length)return {schema:'newcyber.sca-unknown-prefix-oracle.v1',status:'not-applicable',reason:'first position has no token candidates'};
  const seeds=first.slice(0,Math.max(1,Math.min(MAX_SEEDS,Number(seedBeam)||2)));
  const newTokens=Math.max(1,Math.min(rows.length-1,Number(maxTokens)||rows.length-1));
  const plannedSteps=seeds.length*newTokens*2;
  if(plannedSteps>MAX_REPLAY_STEPS)return {schema:'newcyber.sca-unknown-prefix-oracle.v1',status:'gap',code:'UNKNOWN_PREFIX_REPLAY_BUDGET_GAP',detail:`planned oracle steps=${plannedSteps} exceeds ${MAX_REPLAY_STEPS}`};
  const decodeRunner=typeof options.decodeRunner==='function'?options.decodeRunner:runTransformerDecode;
  const replayOptions={...options};delete replayOptions.decodeRunner;
  const attempts=[];
  const guidedByStep=candidateIds(rows.slice(1));

  for(const seed of seeds){
    const oracle=await decodeRunner(model,{promptTokenIds:[seed],tokenizer,maxNewTokens:newTokens,topK:Math.max(1,Math.min(64,Number(topK)||8)),candidateTokenIdsByStep:guidedByStep},replayOptions);
    const item=summarize('candidate-guided',seed,oracle,rows,tokenizer);attempts.push(item);
    if(item.flag)return {schema:'newcyber.sca-unknown-prefix-oracle.v1',status:'flag-recovered',mode:item.mode,flag:item.flag,recoveredTokenIds:item.sequence,recoveredText:item.text,agreement:item.agreement,attempts,seedCount:seeds.length};
  }

  for(const seed of seeds){
    const oracle=await decodeRunner(model,{promptTokenIds:[seed],tokenizer,maxNewTokens:newTokens,topK:Math.max(1,Math.min(64,Number(topK)||8))},replayOptions);
    const item=summarize('full-vocab-fallback',seed,oracle,rows,tokenizer);attempts.push(item);
    if(item.flag)return {schema:'newcyber.sca-unknown-prefix-oracle.v1',status:'flag-recovered',mode:item.mode,flag:item.flag,recoveredTokenIds:item.sequence,recoveredText:item.text,agreement:item.agreement,attempts,seedCount:seeds.length};
  }

  attempts.sort((a,b)=>replayScore(b)-replayScore(a));const best=attempts[0]||null;
  return {schema:'newcyber.sca-unknown-prefix-oracle.v1',status:'decoded-no-flag',mode:best?.mode||null,flag:null,recoveredTokenIds:best?.sequence||[],recoveredText:best?.text||null,agreement:best?.agreement||null,attempts,seedCount:seeds.length};
}

module.exports={candidateIds,agreement,runUnknownPrefixOracle};
