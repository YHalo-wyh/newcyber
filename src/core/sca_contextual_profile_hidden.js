'use strict';

const {withSession,tensorFromSpec}=require('./local_ml_runtime');
const {classifyTransformerSession}=require('./transformer_oracle');

const MAX_PROFILE_PROMPTS=1024;
const MAX_PROFILE_TOKENS=262144;
const MAX_TOKEN_SEQUENCE=65536;
const MAX_ROWS_PER_TOKEN=256;
const MAX_BOUNDARY_RAW_COUNT=MAX_TOKEN_SEQUENCE*MAX_ROWS_PER_TOKEN;
const ROW_COUNT_NAMES=['PROFILING_ROW_COUNTS','PROFILE_ROW_COUNTS','TRAINING_ROW_COUNTS','TRAIN_ROW_COUNTS'];
const HIDDEN_SIZE_NAMES=['HIDDEN_SIZE','HIDDEN_DIM','D_MODEL','N_EMBD'];
const GROUP_SIZE_NAMES=['GROUP_SIZE','HIDDEN_GROUP_SIZE','HIDDEN_GROUP_WIDTH','HIDDEN_CHUNK_SIZE','HIDDEN_SLICE_SIZE'];

function list(value){return Array.isArray(value)?value:[];}
function tensorType(metadata,fallback='int64'){
  const type=String(metadata?.type||'').toLowerCase();
  if(type.includes('int64'))return'int64';
  if(type.includes('int32'))return'int32';
  if(type.includes('float'))return'float32';
  if(type.includes('bool'))return'bool';
  return fallback;
}
function emptyCacheSpec(item){
  const dims=Array.isArray(item?.metadata?.dimensions)?item.metadata.dimensions.slice():[];
  const symbolic=Array.isArray(item?.metadata?.symbolicDimensions)?item.metadata.symbolicDimensions.slice():[];
  if(!dims.length)return null;
  let zero=false;
  const resolved=dims.map((raw,index)=>{
    if(Number.isInteger(raw)&&raw>=0)return raw;
    const label=String(symbolic[index]??raw??'').toLowerCase();
    if(/past|cache|sequence|seq/.test(label)){zero=true;return 0;}
    return 1;
  });
  if(!zero||resolved.reduce((a,b)=>a*b,1)!==0)return null;
  return {type:tensorType(item.metadata,'float32'),dims:resolved,values:[]};
}

function stripComments(text){return String(text||'').split(/\r?\n/).map((line)=>line.replace(/#.*$/,'')).join('\n');}
function extractBracketList(text,start){
  const open=text.indexOf('[',start);if(open<0)return null;
  let depth=0;
  for(let index=open;index<text.length;index++){
    const ch=text[index];
    if(ch==='[')depth+=1;
    else if(ch===']'){
      depth-=1;
      if(depth===0)return text.slice(open+1,index);
      if(depth<0)return null;
    }
    if(index-open>65536)return null;
  }
  return null;
}
function parseStaticIntegerList(body){
  const cleaned=stripComments(body).trim();
  if(!cleaned)return null;
  if(!/^\s*\d+(?:\s*,\s*\d+)*\s*,?\s*$/.test(cleaned))return null;
  const values=cleaned.split(',').map((item)=>item.trim()).filter(Boolean).map(Number);
  if(!values.length||values.length>MAX_PROFILE_PROMPTS||values.some((value)=>!Number.isSafeInteger(value)||value<=0||value>MAX_BOUNDARY_RAW_COUNT))return null;
  return values;
}
function staticIntegerConstants(sourceText,names){
  const text=stripComments(sourceText);const matches=[];
  for(const name of names){
    const re=new RegExp(`\\b${name}\\s*=\\s*(\\d+)\\b`,'gi');let match;
    while((match=re.exec(text))){
      const value=Number(match[1]);
      if(Number.isSafeInteger(value)&&value>0)matches.push({name:name.toUpperCase(),value,text:match[0]});
    }
  }
  const values=[...new Set(matches.map((item)=>item.value))];
  return {matches,values};
}
function staticRowsPerTokenEvidence(sourceText){
  const hidden=staticIntegerConstants(sourceText,HIDDEN_SIZE_NAMES);
  const group=staticIntegerConstants(sourceText,GROUP_SIZE_NAMES);
  if(hidden.values.length!==1||group.values.length!==1){
    return {
      status:hidden.values.length>1||group.values.length>1?'gap':'missing',
      code:hidden.values.length>1||group.values.length>1?'PROFILE_BOUNDARY_UNIT_AMBIGUITY_GAP':'PROFILE_BOUNDARY_UNIT_EVIDENCE_GAP',
      detail:`rows/token conversion needs one static hidden size and one static group size; hidden=${hidden.values.join('/')||'missing'} group=${group.values.join('/')||'missing'}`,
      hidden,group
    };
  }
  const hiddenSize=hidden.values[0],groupSize=group.values[0];
  if(hiddenSize%groupSize!==0){
    return {status:'gap',code:'PROFILE_BOUNDARY_UNIT_RATIO_GAP',detail:`hidden size ${hiddenSize} is not divisible by group size ${groupSize}`,hidden,group,hiddenSize,groupSize};
  }
  const rowsPerToken=hiddenSize/groupSize;
  if(!Number.isSafeInteger(rowsPerToken)||rowsPerToken<=1||rowsPerToken>MAX_ROWS_PER_TOKEN){
    return {status:'gap',code:'PROFILE_BOUNDARY_UNIT_RATIO_GAP',detail:`derived rowsPerToken=${rowsPerToken} is outside 2..${MAX_ROWS_PER_TOKEN}`,hidden,group,hiddenSize,groupSize,rowsPerToken};
  }
  return {
    status:'ok',hiddenSize,groupSize,rowsPerToken,
    evidence:[...hidden.matches,...group.matches].map((item)=>({kind:'static-source-constant',name:item.name,value:item.value,text:item.text}))
  };
}
function staticProfilingRowCounts(sourceText,totalTokens=null){
  const text=String(sourceText||'');const candidates=[];
  for(const name of ROW_COUNT_NAMES){
    const re=new RegExp(`\\b${name}\\s*=`,`gi`);let match;
    while((match=re.exec(text))){
      const body=extractBracketList(text,re.lastIndex);const counts=body==null?null:parseStaticIntegerList(body);
      if(counts)candidates.push({name,counts});
    }
  }
  if(!candidates.length)return {status:'missing',code:'PROFILE_BOUNDARY_EVIDENCE_GAP',detail:'no static profiling row-count boundary list'};
  const canonical=new Map();
  for(const item of candidates){const key=item.counts.join(',');if(!canonical.has(key))canonical.set(key,item);}
  if(canonical.size!==1)return {status:'gap',code:'PROFILE_BOUNDARY_AMBIGUITY_GAP',detail:`conflicting profiling row-count lists: ${[...canonical.values()].map((x)=>x.name).join(', ')}`};
  const selected=[...canonical.values()][0];const rawTotal=selected.counts.reduce((sum,value)=>sum+value,0);
  const expected=totalTokens==null?null:Number(totalTokens);

  if(expected==null||expected===rawTotal){
    if(selected.counts.some((value)=>value>MAX_TOKEN_SEQUENCE))return {status:'gap',code:'PROFILE_BOUNDARY_COUNT_GAP',detail:`${selected.name} contains token boundary > ${MAX_TOKEN_SEQUENCE}`,source:selected.name,counts:selected.counts,total:rawTotal,rawTotal};
    return {status:'ok',source:selected.name,counts:selected.counts,total:rawTotal,rawTotal,prompts:selected.counts.length,unit:'tokens',rowsPerToken:1,evidence:'static-source-integer-list'};
  }

  const unitEvidence=staticRowsPerTokenEvidence(text);
  if(unitEvidence.status!=='ok')return {status:'gap',code:'PROFILE_BOUNDARY_COUNT_GAP',detail:`${selected.name} sum=${rawTotal} != profiling token count=${expected}; trace-row conversion unavailable: ${unitEvidence.detail}`,source:selected.name,counts:selected.counts,total:rawTotal,rawTotal,unitEvidence};
  const {rowsPerToken}=unitEvidence;
  const badIndex=selected.counts.findIndex((value)=>value%rowsPerToken!==0);
  if(badIndex>=0)return {status:'gap',code:'PROFILE_BOUNDARY_COUNT_GAP',detail:`${selected.name}[${badIndex}]=${selected.counts[badIndex]} is not divisible by rowsPerToken=${rowsPerToken}`,source:selected.name,counts:selected.counts,total:rawTotal,rawTotal,rowsPerToken,unitEvidence};
  const counts=selected.counts.map((value)=>value/rowsPerToken);
  if(counts.some((value)=>!Number.isSafeInteger(value)||value<=0||value>MAX_TOKEN_SEQUENCE))return {status:'gap',code:'PROFILE_BOUNDARY_COUNT_GAP',detail:`${selected.name} trace-row normalization produced an invalid prompt token count`,source:selected.name,counts,rawCounts:selected.counts,total:counts.reduce((sum,value)=>sum+value,0),rawTotal,rowsPerToken,unitEvidence};
  const total=counts.reduce((sum,value)=>sum+value,0);
  if(total!==expected)return {status:'gap',code:'PROFILE_BOUNDARY_COUNT_GAP',detail:`${selected.name} sum=${rawTotal} / rowsPerToken=${rowsPerToken} -> token sum=${total} != profiling token count=${expected}`,source:selected.name,counts,rawCounts:selected.counts,total,rawTotal,rowsPerToken,unitEvidence};
  return {
    status:'ok',source:selected.name,counts,rawCounts:selected.counts,total,rawTotal,prompts:counts.length,
    unit:'trace-rows',rowsPerToken,boundaryNormalization:'trace-rows-to-token-counts',
    evidence:'static-source-row-counts-with-hidden-group-ratio',unitEvidence
  };
}
function flattenSingletonTokenIds(sequences){
  const rows=list(sequences);if(!rows.length||rows.some((row)=>!Array.isArray(row)||row.length!==1))return null;
  const ids=rows.map((row)=>Number(row[0]));
  if(ids.some((id)=>!Number.isSafeInteger(id)||id<0))return null;
  return ids;
}
function reconstructProfilingSequences(singletonSequences,sourceText){
  const flat=flattenSingletonTokenIds(singletonSequences);
  if(!flat)return {status:'not-applicable',reason:'profiling token IDs are not a flat 1D sequence'};
  const boundary=staticProfilingRowCounts(sourceText,flat.length);
  if(boundary.status!=='ok')return boundary;
  const sequences=[];let offset=0;
  for(const count of boundary.counts){sequences.push(flat.slice(offset,offset+count));offset+=count;}
  if(offset!==flat.length||sequences.some((row)=>!row.length))return {status:'gap',code:'PROFILE_BOUNDARY_COUNT_GAP',detail:'profiling boundary reconstruction did not consume all token IDs'};
  return {status:'ok',sequences,flatTokenIds:flat,boundary};
}
function extractSequenceHidden(tensor,tokenCount){
  if(!tensor?.data||!Array.isArray(tensor.dims)||!tensor.dims.length)return null;
  const hiddenDim=Number(tensor.dims[tensor.dims.length-1]);
  if(!Number.isSafeInteger(hiddenDim)||hiddenDim<=0||hiddenDim>4096)return null;
  if(tensor.data.length!==tokenCount*hiddenDim)return null;
  const rows=[];
  for(let index=0;index<tokenCount;index++)rows.push(Array.from(tensor.data.slice(index*hiddenDim,(index+1)*hiddenDim),Number));
  return {rows,hiddenDim};
}
async function captureContextualProfileHiddenStates(model,sequences,options={}){
  const prompts=list(sequences);
  if(!prompts.length||prompts.length>MAX_PROFILE_PROMPTS)return {status:'PROFILE_PROMPT_BUDGET_GAP',detail:`profiling prompts=${prompts.length} is invalid or exceeds ${MAX_PROFILE_PROMPTS}`};
  const totalTokens=prompts.reduce((sum,row)=>sum+list(row).length,0);
  if(!totalTokens||totalTokens>MAX_PROFILE_TOKENS)return {status:'TOKEN_BUDGET_GAP',detail:`profiling tokens=${totalTokens} exceeds ${MAX_PROFILE_TOKENS}`};
  for(let index=0;index<prompts.length;index++){
    const ids=prompts[index];
    if(!Array.isArray(ids)||!ids.length||ids.length>MAX_TOKEN_SEQUENCE||ids.some((id)=>!Number.isSafeInteger(Number(id))||Number(id)<0))return {status:'PROFILE_INPUT_GAP',detail:`profiling prompt ${index} token IDs invalid`};
  }
  return withSession(model,options,async(session,ort)=>{
    const recipe=classifyTransformerSession(session);
    if(!recipe.supported)return {status:'MODEL_RECIPE_GAP',detail:'unable to resolve Transformer input_ids/logits recipe',recipe};
    if(!recipe.roles.hidden)return {status:'HIDDEN_STATE_OUTPUT_GAP',detail:'ONNX model has no recognized hidden-state output',recipe};
    if(recipe.cache.mode==='unpaired')return {status:'CACHE_PAIR_GAP',detail:'model cache I/O cannot be paired safely',recipe};
    if(recipe.unknownInputs.length)return {status:'UNKNOWN_MODEL_INPUT_GAP',detail:`unrecognized required model inputs: ${recipe.unknownInputs.map((x)=>x.name).join(', ')}`,recipe};
    const hiddenStates=[];const promptTelemetry=[];let hiddenDim=null;
    for(let promptIndex=0;promptIndex<prompts.length;promptIndex++){
      const ids=prompts[promptIndex].map(Number);const feeds={};
      feeds[recipe.roles.inputIds.name]=tensorFromSpec(ort,{type:tensorType(recipe.roles.inputIds.metadata,'int64'),dims:[1,ids.length],values:ids});
      if(recipe.roles.attentionMask)feeds[recipe.roles.attentionMask.name]=tensorFromSpec(ort,{type:tensorType(recipe.roles.attentionMask.metadata,'int64'),dims:[1,ids.length],values:Array(ids.length).fill(1)});
      if(recipe.roles.positionIds)feeds[recipe.roles.positionIds.name]=tensorFromSpec(ort,{type:tensorType(recipe.roles.positionIds.metadata,'int64'),dims:[1,ids.length],values:Array.from({length:ids.length},(_,i)=>i)});
      for(const item of recipe.cache.inputs){const spec=emptyCacheSpec(item);if(!spec)return {status:'CACHE_INIT_GAP',detail:`cannot prove zero-length cache dimension for ${item.name}`,recipe};feeds[item.name]=tensorFromSpec(ort,spec);}
      for(const name of session.inputNames)if(!feeds[name])return {status:'UNKNOWN_MODEL_INPUT_GAP',detail:`model input ${name} was not constructed`,recipe};
      const output=await session.run(feeds,{[recipe.roles.hidden.name]:null});
      const extracted=extractSequenceHidden(output[recipe.roles.hidden.name],ids.length);
      if(!extracted)return {status:'HIDDEN_STATE_LAYOUT_GAP',detail:`profiling prompt ${promptIndex} hidden output does not expose exactly ${ids.length} positions`,recipe};
      if(hiddenDim==null)hiddenDim=extracted.hiddenDim;else if(hiddenDim!==extracted.hiddenDim)return {status:'HIDDEN_STATE_LAYOUT_GAP',detail:'profiling hidden dimension changed across prompts',recipe};
      hiddenStates.push(...extracted.rows);promptTelemetry.push({promptIndex,tokens:ids.length});
    }
    return {schema:'newcyber.sca-contextual-profile-hidden.v1',status:'ok',mode:'full-prompt-position-hidden',hiddenStates,hiddenDim,rows:hiddenStates.length,prompts:prompts.length,totalTokens,promptTelemetry,recipe};
  });
}

module.exports={MAX_PROFILE_PROMPTS,MAX_PROFILE_TOKENS,MAX_ROWS_PER_TOKEN,ROW_COUNT_NAMES,HIDDEN_SIZE_NAMES,GROUP_SIZE_NAMES,parseStaticIntegerList,staticIntegerConstants,staticRowsPerTokenEvidence,staticProfilingRowCounts,reconstructProfilingSequences,extractSequenceHidden,captureContextualProfileHiddenStates};