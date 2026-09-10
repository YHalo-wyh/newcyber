'use strict';

const {
  staticProfilingRowCounts,reconstructProfilingSequences
}=require('./sca_contextual_profile_hidden');
const {parseStaticIntegerExpression}=require('./sca_static_integer_evidence');
const {indirectHannDotEvidence}=require('./sca_real_bundle_feature_source');

const FAMILY_CASES=128;

function lcg(seed){
  let state=seed>>>0;
  return ()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state/0x100000000;};
}
function pick(rng,items){return items[Math.floor(rng()*items.length)%items.length];}
function sum(values){return values.reduce((a,b)=>a+b,0);}
function sourceForBoundary({rowsPerToken,groupSize,promptTokens,style,index}){
  const hiddenSize=rowsPerToken*groupSize;
  const rawCounts=promptTokens.map((value)=>value*rowsPerToken);
  const list=style%2===0?`[${rawCounts.join(', ')}]`:`(${rawCounts.join(', ')})`;
  if(style===0)return `HIDDEN_SIZE=${hiddenSize}\nGROUP_SIZE=${groupSize}\nPROFILING_ROW_COUNTS=${list}`;
  if(style===1)return `WIDTH=${groupSize}\nGROUPS=${rowsPerToken}\nHIDDEN_SIZE=WIDTH*GROUPS\nGROUP_SIZE=WIDTH\nPROFILING_ROW_COUNTS=${list}`;
  if(style===2)return `ROWS_PER_TOKEN=${rowsPerToken}\nPROFILING_ROW_COUNTS=${list}`;
  if(style===3)return `BASE=${groupSize}\nD_MODEL=${rowsPerToken}*BASE\nHIDDEN_GROUP_WIDTH=BASE\nROWS_PER_TOKEN=${rowsPerToken}\nPROFILING_ROW_COUNTS=${list}`;
  if(style===4)return `HIDDEN_DIM=0x${hiddenSize.toString(16)}\nHIDDEN_CHUNK_SIZE=${groupSize}\nPROFILING_ROW_COUNTS=${list}`;
  if(style===5){
    const pow=Math.log2(rowsPerToken);
    if(Number.isInteger(pow))return `ROWS_PER_TOKEN=2**${pow}\nGROUP_SIZE=${groupSize}\nHIDDEN_SIZE=ROWS_PER_TOKEN*GROUP_SIZE\nPROFILING_ROW_COUNTS=${list}`;
    return `ROWS_PER_TOKEN=${rowsPerToken}\nGROUP_SIZE=${groupSize}\nHIDDEN_SIZE=ROWS_PER_TOKEN*GROUP_SIZE\nPROFILING_ROW_COUNTS=${list}`;
  }
  if(style===6)return `G=${groupSize}\nHIDDEN_SIZE=${hiddenSize+groupSize}-${groupSize}\nGROUP_SIZE=G\nPROFILING_ROW_COUNTS=${list}`;
  return `CHUNKS_PER_TOKEN=${rowsPerToken}\nPROFILING_ROW_COUNTS=${list}\nCASE_INDEX=${index}`;
}
function positiveBoundaryCases(count=64){
  const rng=lcg(0x57a1cafe);const cases=[];
  const rowChoices=[4,8,12,16,20,24,32,40,48,64];
  const groupChoices=[4,8,16,20,24,32];
  for(let index=0;index<count;index++){
    const rowsPerToken=pick(rng,rowChoices),groupSize=pick(rng,groupChoices);
    const promptCount=3+Math.floor(rng()*10);const promptTokens=[];
    for(let p=0;p<promptCount;p++)promptTokens.push(2+Math.floor(rng()*23));
    const source=sourceForBoundary({rowsPerToken,groupSize,promptTokens,style:index%8,index});
    cases.push({id:`boundary-positive-${index}`,source,rowsPerToken,promptTokens,totalTokens:sum(promptTokens)});
  }
  return cases;
}
function directTokenCases(count=16){
  const rng=lcg(0x57d1rect);const cases=[];
  for(let index=0;index<count;index++){
    const promptCount=2+Math.floor(rng()*8),promptTokens=[];
    for(let p=0;p<promptCount;p++)promptTokens.push(1+Math.floor(rng()*16));
    const rowsPerToken=pick(rng,[4,8,16,32,48]);const groupSize=pick(rng,[4,8,16]);
    const list=index%2?`(${promptTokens.join(',')})`:`[${promptTokens.join(',')}]`;
    cases.push({id:`boundary-direct-${index}`,source:`HIDDEN_SIZE=${rowsPerToken*groupSize}\nGROUP_SIZE=${groupSize}\nPROFILING_ROW_COUNTS=${list}`,promptTokens,totalTokens:sum(promptTokens)});
  }
  return cases;
}
function negativeBoundaryCases(count=16){
  const rng=lcg(0x57badbad);const cases=[];
  for(let index=0;index<count;index++){
    const rowsPerToken=pick(rng,[8,12,16,24,32,48]),groupSize=pick(rng,[4,8,16]);
    const promptTokens=[3+Math.floor(rng()*8),4+Math.floor(rng()*8),5+Math.floor(rng()*8)];
    const raw=promptTokens.map((x)=>x*rowsPerToken);
    if(index%2===0)raw[index%raw.length]+=1;
    const conflict=index%2===1?`ROWS_PER_TOKEN=${rowsPerToken+1}\n`:'';
    cases.push({
      id:`boundary-negative-${index}`,
      source:`HIDDEN_SIZE=${rowsPerToken*groupSize}\nGROUP_SIZE=${groupSize}\n${conflict}PROFILING_ROW_COUNTS=[${raw.join(',')}]`,
      totalTokens:sum(promptTokens)
    });
  }
  return cases;
}
function expressionCases(){
  return [
    ['12*64',{},768],['2**4',{},16],['0x300',{},768],['0b10000',{},16],['1_024',{},1024],
    ['BASE*12',{BASE:64},768],['(3+5)*16',{},128],['512//8',{},64],['512/8',{},64],
    ['7%4',{},3],['1<<6',{},64],['256>>3',{},32],['-(-48)',{},48],['64+32-16',{},80],
    ['7/3',{},null],['UNKNOWN*4',{},null]
  ].map(([expr,env,expected],index)=>({id:`static-expression-${index}`,expr,env,expected}));
}
function hannCases(){
  const sinks=[
    'np.dot(slot, kernel)','np.inner(slot, kernel)','np.vdot(slot, kernel)',
    'torch.dot(slot, kernel)','torch.inner(slot, kernel)','slot @ kernel'
  ];
  const norms=[
    'kernel = base / np.sum(base)',
    'kernel = base / sum(base)',
    'kernel = base / base.sum()',
    'tmp = np.asarray(base)\nkernel = tmp / np.sum(tmp)',
    'tmp = base.astype(np.float32)\nkernel = tmp / tmp.sum()'
  ];
  const out=[];
  for(let index=0;index<16;index++){
    const api=index%3===0?'np.hanning(8)':index%3===1?'torch.hann_window(8)':'windows.hann(8)';
    out.push({id:`hann-metamorphic-${index}`,source:`base = ${api}\n${norms[index%norms.length]}\nvalue = ${sinks[index%sinks.length]}`});
  }
  return out;
}
function runCase(item,kind){
  try{
    if(kind==='boundary-positive'){
      const boundary=staticProfilingRowCounts(item.source,item.totalTokens);
      if(boundary.status!=='ok'||boundary.rowsPerToken!==item.rowsPerToken||boundary.unit!=='trace-rows')throw new Error(`boundary status=${boundary.status} rows=${boundary.rowsPerToken} unit=${boundary.unit}`);
      if(boundary.counts.join(',')!==item.promptTokens.join(','))throw new Error('normalized prompt counts differ');
      const ids=Array.from({length:item.totalTokens},(_,id)=>[id]);const rebuilt=reconstructProfilingSequences(ids,item.source);
      if(rebuilt.status!=='ok'||rebuilt.sequences.length!==item.promptTokens.length||rebuilt.sequences.flat().length!==item.totalTokens)throw new Error('sequence reconstruction mismatch');
    }else if(kind==='boundary-direct'){
      const boundary=staticProfilingRowCounts(item.source,item.totalTokens);
      if(boundary.status!=='ok'||boundary.unit!=='tokens'||boundary.rowsPerToken!==1)throw new Error(`direct boundary changed semantics: ${boundary.status}/${boundary.unit}`);
      if(boundary.counts.join(',')!==item.promptTokens.join(','))throw new Error('direct prompt counts differ');
    }else if(kind==='boundary-negative'){
      const boundary=staticProfilingRowCounts(item.source,item.totalTokens);
      if(boundary.status!=='gap')throw new Error('invalid boundary was accepted');
    }else if(kind==='expression'){
      const actual=parseStaticIntegerExpression(item.expr,item.env);
      if(actual!==item.expected)throw new Error(`expression ${item.expr} -> ${actual}, expected ${item.expected}`);
    }else if(kind==='hann'){
      const evidence=indirectHannDotEvidence(item.source);
      if(evidence.status!=='ok')throw new Error('equivalent Hann linear dot was not recognized');
    }
    return {id:item.id,kind,passed:true};
  }catch(error){return {id:item.id,kind,passed:false,error:error?.message||String(error)};}
}
function runBatch57GeneralizationPressure(){
  const results=[];
  for(const item of positiveBoundaryCases(64))results.push(runCase(item,'boundary-positive'));
  for(const item of directTokenCases(16))results.push(runCase(item,'boundary-direct'));
  for(const item of negativeBoundaryCases(16))results.push(runCase(item,'boundary-negative'));
  for(const item of expressionCases())results.push(runCase(item,'expression'));
  for(const item of hannCases())results.push(runCase(item,'hann'));
  const passed=results.filter((x)=>x.passed).length,failed=results.length-passed;
  return {
    schema:'newcyber.ai-batch57-generalization-pressure.v1',batch:57,
    policy:{realChallengeMagicInProduction:false,deterministic:true,familyHoldout:true,failClosedNegatives:true},
    summary:{total:results.length,passed,failed,passRate:results.length?passed/results.length:0},results
  };
}

module.exports={FAMILY_CASES,positiveBoundaryCases,directTokenCases,negativeBoundaryCases,expressionCases,hannCases,runBatch57GeneralizationPressure};