'use strict';

const {resolveStaticIntegerAssignments}=require('./sca_static_integer_evidence');

const MAX_WINDOWS=128;
const MAX_WINDOW_LENGTH=4096;

function finiteInt(value){
  const n=Number(value);
  return Number.isSafeInteger(n)&&n>=0?n:null;
}

function hannWeight(index,length){
  if(length<=1)return 1;
  return 0.5-0.5*Math.cos((2*Math.PI*index)/(length-1));
}

function normalizeMetric(value){
  const metric=String(value||'sum-squares').toLowerCase().replace(/[_\s]+/g,'-');
  const aliases={
    energy:'sum-squares',
    'hann-energy':'sum-squares',
    'window-energy':'sum-squares',
    mse:'mean-square',
    'hann-weighted-dot':'hann-dot',
    'window-dot':'hann-dot',
    'weighted-dot':'hann-dot'
  };
  const normalized=aliases[metric]||metric;
  if(!['sum-squares','mean-square','sum','mean','sum-abs','mean-abs','peak-to-peak','hann-dot'].includes(normalized))throw new Error(`unsupported feature metric ${metric}`);
  return normalized;
}

function normalizeWindowFunction(value){
  const name=String(value||'rect').toLowerCase().replace(/[_\s]+/g,'-');
  if(['rect','rectangle','none','boxcar'].includes(name))return'rect';
  if(['hann','hanning','hann-window'].includes(name))return'hann';
  throw new Error(`unsupported window function ${name}`);
}

function normalizeExplicitWindows(windows,rawCols,defaults={}){
  if(!Array.isArray(windows)||!windows.length)return null;
  if(windows.length>MAX_WINDOWS)throw new Error(`window count exceeds ${MAX_WINDOWS}`);
  return windows.map((item,index)=>{
    const offset=finiteInt(item?.offset??0),length=finiteInt(item?.length);
    if(offset==null||length==null||length<=0||length>MAX_WINDOW_LENGTH||offset+length>rawCols)throw new Error(`window ${index} exceeds raw row width ${rawCols}`);
    const metric=normalizeMetric(item?.metric??defaults.metric);
    const windowFunction=normalizeWindowFunction(item?.windowFunction??item?.window??item?.weighting??defaults.windowFunction??(metric==='hann-dot'?'hann':'rect'));
    return {id:String(item?.id||`window-${index}`),offset,length,metric,windowFunction};
  });
}

function constantMap(sourceText){
  const resolved=resolveStaticIntegerAssignments(sourceText);const out={};
  for(const item of resolved.assignments){
    const name=String(item.name||'');
    if(!/^[A-Z][A-Z0-9_]{1,63}$/.test(name))continue;
    if(resolved.conflicts.has(name.toUpperCase()))continue;
    const value=resolved.env[name];
    if(Number.isSafeInteger(value)&&value>=0)out[name]=value;
  }
  return out;
}

function uniquePlausible(constants,patterns,max){
  const values=[];
  for(const [name,value] of Object.entries(constants))if(patterns.some((p)=>p.test(name))&&Number.isSafeInteger(value)&&value>0&&value<=max)values.push(value);
  return [...new Set(values)];
}

function uniqueOffsets(constants,rawCols){
  const values=[];
  for(const [name,value] of Object.entries(constants)){
    if(!/(?:FEATURE|TRACE|WINDOW|WIN|SLOT).*(?:OFFSET|START)/i.test(name))continue;
    if(Number.isSafeInteger(value)&&value>=0&&value<=rawCols)values.push(value);
  }
  return [...new Set(values)];
}

function guardedOffset(constants,rawCols,slotCount,windowSize){
  const guards=uniquePlausible(constants,[/(?:^|_)GUARD(?:_|$).*(?:SAMPLES|SIZE|WIDTH)?/i,/(?:SAMPLES|SIZE|WIDTH).*GUARD/i],rawCols);
  if(guards.length!==1)return null;
  const guard=guards[0];
  return guard*2+slotCount*windowSize===rawCols?guard:null;
}

function hasHannDotEvidence(text){
  return /(?:np\.)?dot\s*\([^\n)]{0,260}(?:hann|hanning|window|win)/i.test(text)
    || /(?:hann|hanning|window|win)[^\n]{0,180}(?:@|\*).*?(?:sum\s*\(|\.sum\s*\()/i.test(text)
    || /(?:sum\s*\(|\.sum\s*\()[^\n]{0,220}?(?:hann|hanning|window|win)/i.test(text)
    || /@\s*(?:hann|hanning|window|win)\b/i.test(text);
}

function sourceRecipe(sourceText,rawCols){
  const text=String(sourceText||'');
  const hannEvidence=/(?:np\.(?:hanning|hann)|torch\.hann_window|(?:signal\.)?windows\.hann)\s*\(/i.test(text);
  if(!hannEvidence)return null;
  const constants=constantMap(text);
  let sizes=uniquePlausible(constants,[/(?:WINDOW|WIN|SLOT|SEGMENT).*(?:SIZE|WIDTH|SAMPLES)/i,/(?:SAMPLES).*(?:WINDOW|WIN|SLOT|TRACE|FEATURE)/i,/^SAMPLES_PER_TRACE$/i],Math.min(MAX_WINDOW_LENGTH,rawCols));
  for(const match of text.matchAll(/(?:hanning|hann|hann_window)\s*\(\s*(\d+)\s*\)/gi))sizes.push(Number(match[1]));
  sizes=[...new Set(sizes.filter((x)=>Number.isSafeInteger(x)&&x>0&&x<=rawCols))];
  if(sizes.length!==1)return null;
  const windowSize=sizes[0];

  let slots=uniquePlausible(constants,[/(?:FEATURE|LEAKAGE).*(?:SLOTS|WINDOWS|COUNT|DIM)/i,/(?:NUM|N)_(?:WINDOWS|SLOTS)/i],MAX_WINDOWS);
  if(Number.isSafeInteger(constants.TRACE_DIM)&&constants.TRACE_DIM>0&&constants.TRACE_DIM<=MAX_WINDOWS&&constants.TRACE_DIM*windowSize<=rawCols)slots.push(constants.TRACE_DIM);
  const localRange=[...text.matchAll(/(?:hanning|hann_window|windows\.hann)[\s\S]{0,500}?range\s*\(\s*(\d+)\s*\)/gi)].map((m)=>Number(m[1]));
  slots=[...new Set([...slots,...localRange].filter((x)=>Number.isSafeInteger(x)&&x>0&&x<=MAX_WINDOWS))];
  if(slots.length!==1)return null;
  const slotCount=slots[0];

  let offsets=uniqueOffsets(constants,rawCols);
  const literalOffsetPattern=new RegExp(`\\[\\s*(\\d+)\\s*\\+\\s*(?:i|j|idx|slot|f)\\s*\\*\\s*(?:${windowSize}|[A-Z_][A-Z0-9_]*)\\s*:`,`ig`);
  for(const match of text.matchAll(literalOffsetPattern))offsets.push(Number(match[1]));
  if(!offsets.length&&new RegExp(`\\[\\s*(?:i|j|idx|slot|f)\\s*\\*\\s*(?:${windowSize}|[A-Z_][A-Z0-9_]*)\\s*:`,`i`).test(text))offsets=[0];
  const guard=guardedOffset(constants,rawCols,slotCount,windowSize);
  if(!offsets.length&&guard!=null)offsets=[guard];
  offsets=[...new Set(offsets.filter((x)=>Number.isSafeInteger(x)&&x>=0&&x<=rawCols))];
  if(offsets.length!==1)return null;
  const offset=offsets[0];
  if(offset+slotCount*windowSize>rawCols)return null;

  const dot=hasHannDotEvidence(text);
  const mean=/\bmean\s*\([^\n]{0,180}(?:\*\*\s*2|square\s*\()/i.test(text);
  const squared=/(?:\*\*\s*2|square\s*\()[^\n]{0,220}(?:hann|hanning|window|win)|(?:hann|hanning|window|win)[^\n]{0,220}(?:\*\*\s*2|square\s*\()/i.test(text);
  const metric=dot&&!squared?'hann-dot':mean?'mean-square':'sum-squares';
  const windows=Array.from({length:slotCount},(_,index)=>({id:`hann-${index}`,offset:offset+index*windowSize,length:windowSize,metric,windowFunction:'hann'}));
  const evidence=['hann-window','window-size','slot-count',guard!=null?'guard-framing':'zero-or-explicit-offset'];
  if(metric==='hann-dot')evidence.push('hann-dot-linear-amplitude');
  return {schema:'newcyber.sca-streaming-feature-recipe.v2',mode:'windows',source:'challenge-source',windowFunction:'hann',metric,windowSize,slots:slotCount,offset,rawCols,windows,evidence};
}

function manifestRecipe(manifest,rawCols){
  const block=manifest?.groupedFeatureRecipe||manifest?.featureRecipe||manifest?.groupedLeakage?.featureRecipe||null;
  if(Array.isArray(manifest?.windows)&&manifest.windows.length){
    const windows=normalizeExplicitWindows(manifest.windows,rawCols,{windowFunction:manifest.windowFunction,metric:manifest.windowMetric});
    return {schema:'newcyber.sca-streaming-feature-recipe.v2',mode:'windows',source:'manifest-windows',rawCols,windows,slots:windows.length,windowFunction:[...new Set(windows.map((x)=>x.windowFunction))].join('+'),metric:[...new Set(windows.map((x)=>x.metric))].join('+')};
  }
  if(!block||typeof block!=='object')return null;
  if(Array.isArray(block.windows)&&block.windows.length){
    const windows=normalizeExplicitWindows(block.windows,rawCols,{windowFunction:block.windowFunction,metric:block.metric});
    return {schema:'newcyber.sca-streaming-feature-recipe.v2',mode:'windows',source:'manifest-feature-recipe',rawCols,windows,slots:windows.length,windowFunction:[...new Set(windows.map((x)=>x.windowFunction))].join('+'),metric:[...new Set(windows.map((x)=>x.metric))].join('+')};
  }
  const windowSize=finiteInt(block.windowSize??block.samplesPerWindow??block.slotSamples);
  const slots=finiteInt(block.slots??block.windows??block.featureSlots??block.count);
  const offset=finiteInt(block.offset??block.startSample??0);
  if(windowSize==null||windowSize<=0||slots==null||slots<=0||slots>MAX_WINDOWS||offset==null||offset+windowSize*slots>rawCols)throw new Error('manifest grouped feature recipe is invalid for raw row width');
  const metric=normalizeMetric(block.metric||'sum-squares');
  const windowFunction=normalizeWindowFunction(block.windowFunction||block.window||(metric==='hann-dot'?'hann':'rect'));
  const windows=Array.from({length:slots},(_,index)=>({id:`${windowFunction}-${index}`,offset:offset+index*windowSize,length:windowSize,metric,windowFunction}));
  return {schema:'newcyber.sca-streaming-feature-recipe.v2',mode:'windows',source:'manifest-feature-recipe',rawCols,windows,slots,windowSize,offset,metric,windowFunction};
}

function declaredFeatureMismatch(sourceText,rawCols){
  const constants=constantMap(sourceText);
  const values=['FEATURE_DIM','LEAKAGE_DIM','TRACE_DIM'].map((name)=>constants[name]).filter((value)=>Number.isSafeInteger(value)&&value>0&&value<=4096);
  if(!values.length||values.includes(rawCols))return null;
  const compact=[...new Set(values)];
  return {declared:compact,rawCols};
}

function resolveGroupedFeatureRecipe(discovery,rawCols){
  rawCols=finiteInt(rawCols);
  if(rawCols==null||rawCols<=0)return {status:'gap',code:'GROUP_FEATURE_RECIPE_GAP',detail:'raw grouped row width is invalid'};
  try{
    const manifest=manifestRecipe(discovery?.manifest||{},rawCols);
    if(manifest)return {status:'ok',recipe:manifest};
  }catch(error){return {status:'gap',code:'GROUP_FEATURE_RECIPE_GAP',detail:error?.message||String(error)};}
  const sourceText=discovery?.sourceText||'';
  const source=sourceRecipe(sourceText,rawCols);
  if(source)return {status:'ok',recipe:source};
  const mismatch=declaredFeatureMismatch(sourceText,rawCols);
  if(mismatch)return {status:'gap',code:'GROUP_FEATURE_RECIPE_GAP',detail:`source declares feature dimension ${mismatch.declared.join('/')} but raw grouped row width is ${rawCols}; refusing raw-feature downgrade without a proven window recipe`};
  return {status:'missing',recipe:null};
}

function featureValue(row,window){
  if(window.metric==='hann-dot'){
    let weighted=0;
    for(let index=0;index<window.length;index+=1){
      const value=Number(row[window.offset+index]);
      if(!Number.isFinite(value))throw new Error('feature source row contains NaN/Inf');
      weighted+=value*hannWeight(index,window.length);
    }
    return weighted;
  }
  let sum=0,sumSquares=0,sumAbs=0,min=Infinity,max=-Infinity;
  for(let index=0;index<window.length;index+=1){
    let value=Number(row[window.offset+index]);
    if(!Number.isFinite(value))throw new Error('feature source row contains NaN/Inf');
    if(window.windowFunction==='hann')value*=hannWeight(index,window.length);
    sum+=value;sumSquares+=value*value;sumAbs+=Math.abs(value);min=Math.min(min,value);max=Math.max(max,value);
  }
  if(window.metric==='sum')return sum;
  if(window.metric==='mean')return sum/window.length;
  if(window.metric==='sum-abs')return sumAbs;
  if(window.metric==='mean-abs')return sumAbs/window.length;
  if(window.metric==='mean-square')return sumSquares/window.length;
  if(window.metric==='peak-to-peak')return max-min;
  return sumSquares;
}

function transformRow(row,recipe){
  if(!Array.isArray(row)||row.length!==recipe.rawCols)throw new Error(`feature row width ${row?.length??0} != ${recipe.rawCols}`);
  return recipe.windows.map((window)=>featureValue(row,window));
}

function wrapStreamingFeatureSource(rowSource,recipe){
  if(!rowSource||typeof rowSource.readRows!=='function'||typeof rowSource.close!=='function')throw new Error('rowSource interface is invalid');
  if(Number(rowSource.cols)!==Number(recipe.rawCols))throw new Error(`feature recipe rawCols=${recipe.rawCols} does not match source cols=${rowSource.cols}`);
  let closed=false;
  return {
    schema:'newcyber.sca-feature-row-source.v2',
    filePath:rowSource.filePath,fileName:rowSource.fileName,
    sourceKind:`${rowSource.sourceKind}+${recipe.windowFunction||'window'}-features`,
    rows:rowSource.rows,cols:recipe.windows.length,rawCols:rowSource.cols,segments:rowSource.segments,pickle:rowSource.pickle||null,recipe,
    async readRows(start,count){const rows=await rowSource.readRows(start,count);return rows.map((row)=>transformRow(row,recipe));},
    async close(){if(closed)return;closed=true;await rowSource.close();}
  };
}

module.exports={hannWeight,normalizeMetric,constantMap,sourceRecipe,manifestRecipe,declaredFeatureMismatch,resolveGroupedFeatureRecipe,featureValue,transformRow,wrapStreamingFeatureSource};