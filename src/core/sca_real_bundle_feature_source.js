'use strict';

const {sourceRecipe,resolveGroupedFeatureRecipe,transformRow,hannWeight,constantMap}=require('./sca_streaming_feature_source');

const MAX_RAW_VALUES_PER_READ=2_000_000;
const DERIVED_CALL_ALLOWLIST=new Set(['np.sum','numpy.sum','sum','np.asarray','numpy.asarray','np.array','numpy.array']);
const DOT_CALL_PATTERN=/(?:np|numpy)\.(?:dot|inner|vdot)|torch\.(?:dot|inner)/i;
const GUARD_AGGREGATE_CALLS=new Set(['np.concatenate','numpy.concatenate','np.hstack','numpy.hstack','np.stack','numpy.stack','np.asarray','numpy.asarray','np.array','numpy.array','list','tuple']);

function list(value){return Array.isArray(value)?value:[];}
function escapeRegex(value){return String(value).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
function assignmentLines(sourceText){
  const out=[];
  for(const raw of String(sourceText||'').split(/\r?\n/)){
    const line=raw.replace(/#.*$/,'').trim();
    const match=line.match(/^([A-Za-z_]\w*)\s*=\s*(.+)$/);
    if(match&&match[2].length<=512)out.push({name:match[1],rhs:match[2]});
  }
  return out;
}
function callAllowed(name,tainted){
  const lower=String(name||'').toLowerCase();
  if(DERIVED_CALL_ALLOWLIST.has(lower))return true;
  const method=String(name||'').match(/^([A-Za-z_]\w*)\.(sum|astype)$/i);
  return Boolean(method&&tainted.has(method[1]));
}
function expressionMentionsTainted(expr,tainted){
  return [...tainted].some((name)=>new RegExp(`\\b${escapeRegex(name)}\\b`).test(expr));
}
function indirectHannDotEvidence(sourceText){
  const text=String(sourceText||'');const assignments=assignmentLines(text);const tainted=new Set();const evidence=[];
  for(const item of assignments){
    if(/(?:np\.)?(?:hanning|hann)\s*\(|torch\.hann_window\s*\(|(?:signal\.)?windows\.hann\s*\(/i.test(item.rhs)){
      tainted.add(item.name);evidence.push(`hann-source:${item.name}`);
    }
  }
  for(let round=0;round<8;round++){
    let changed=false;
    for(const item of assignments){
      if(tainted.has(item.name))continue;
      const parent=[...tainted].find((name)=>new RegExp(`\\b${escapeRegex(name)}\\b`).test(item.rhs));
      if(!parent)continue;
      const calls=[...item.rhs.matchAll(/\b([A-Za-z_]\w*(?:\.\w+)*)\s*\(/g)].map((m)=>m[1]);
      if(calls.some((name)=>!callAllowed(name,tainted)))continue;
      if(!/^[A-Za-z0-9_\.\s+\-*/(),\[\]@]+$/.test(item.rhs))continue;
      tainted.add(item.name);evidence.push(`hann-derived:${item.name}<-${parent}`);changed=true;
    }
    if(!changed)break;
  }
  const callRegex=/\b((?:np|numpy)\.(?:dot|inner|vdot)|torch\.(?:dot|inner))\s*\(([^,\n]{1,240}),\s*([^\)\n]{1,240})\)/gi;
  for(const match of text.matchAll(callRegex)){
    const args=`${match[2]} ${match[3]}`;
    const kernel=[...tainted].find((name)=>new RegExp(`\\b${escapeRegex(name)}\\b`).test(args));
    if(kernel)return {status:'ok',kernel,sink:match[1],evidence:[...evidence,`dot-kernel:${kernel}`,`linear-sink:${match[1].toLowerCase()}`]};
  }
  for(const item of assignments){
    if(!item.rhs.includes('@'))continue;
    const parts=item.rhs.split('@');if(parts.length!==2)continue;
    if(!expressionMentionsTainted(item.rhs,tainted))continue;
    const kernel=[...tainted].find((name)=>new RegExp(`\\b${escapeRegex(name)}\\b`).test(item.rhs));
    if(kernel&&parts.every((part)=>part.trim().length>0))return {status:'ok',kernel,sink:'@',evidence:[...evidence,`dot-kernel:${kernel}`,'linear-sink:@']};
  }
  return {status:'missing',kernel:null,evidence};
}

function guardLayout(recipe){
  const windows=list(recipe?.windows);
  if(!windows.length||!Number.isSafeInteger(Number(recipe?.rawCols)))return null;
  if(!list(recipe?.evidence).includes('guard-framing'))return null;
  const first=Math.min(...windows.map((window)=>Number(window.offset)));
  const last=Math.max(...windows.map((window)=>Number(window.offset)+Number(window.length)));
  const rawCols=Number(recipe.rawCols);const leading=first;const trailing=rawCols-last;
  if(!Number.isSafeInteger(leading)||!Number.isSafeInteger(trailing)||leading<=0||leading!==trailing)return null;
  if(first!==leading||last!==rawCols-trailing)return null;
  return {leading,trailing,featureStart:first,featureEnd:last};
}
function guardTokens(sourceText,width){
  const tokens=[String(width)];
  const constants=constantMap(sourceText);
  for(const [name,value] of Object.entries(constants))if(Number(value)===Number(width)&&/GUARD/i.test(name))tokens.push(name);
  return [...new Set(tokens)];
}
function directGuardSliceKinds(expr,tokens){
  const kinds=new Set();
  for(const token of tokens){
    const part=escapeRegex(token);
    if(new RegExp(`\\[\\s*(?:0\\s*)?:\\s*${part}\\s*\\]`,'i').test(expr))kinds.add('leading');
    if(new RegExp(`\\[\\s*-\\s*${part}\\s*:\\s*\\]`,'i').test(expr))kinds.add('trailing');
  }
  return kinds;
}
function safeGuardAggregateExpression(expr){
  if(!/^[A-Za-z0-9_\.\s,()\[\]:+\-]+$/.test(expr))return false;
  const calls=[...String(expr).matchAll(/\b([A-Za-z_]\w*(?:\.\w+)*)\s*\(/g)].map((match)=>match[1].toLowerCase());
  return calls.every((name)=>GUARD_AGGREGATE_CALLS.has(name));
}
function guardSampleProvenance(sourceText,width){
  const assignments=assignmentLines(sourceText);const tokens=guardTokens(sourceText,width);const kinds=new Map();
  for(const item of assignments){
    const direct=directGuardSliceKinds(item.rhs,tokens);
    if(direct.size)kinds.set(item.name,direct);
  }
  for(let round=0;round<8;round++){
    let changed=false;
    for(const item of assignments){
      if(!safeGuardAggregateExpression(item.rhs))continue;
      const merged=new Set(kinds.get(item.name)||[]);
      for(const [name,parentKinds] of kinds){
        if(name===item.name||!new RegExp(`\\b${escapeRegex(name)}\\b`).test(item.rhs))continue;
        for(const kind of parentKinds)merged.add(kind);
      }
      const previous=kinds.get(item.name)||new Set();
      if(merged.size!==previous.size){kinds.set(item.name,merged);changed=true;}
    }
    if(!changed)break;
  }
  return {assignments,tokens,kinds};
}
function meanCall(expr){
  return /\b(?:np|numpy)\.(?:mean|average)\s*\(/i.test(expr)||/\b[A-Za-z_]\w*\.mean\s*\(/i.test(expr);
}
function guardBaselineEvidence(sourceText,recipe){
  const layout=guardLayout(recipe);
  if(!layout)return {status:'missing',reason:'guard-layout-not-proven'};
  const text=String(sourceText||'');const provenance=guardSampleProvenance(text,layout.leading);const baselineVars=new Set();const evidence=[];
  for(const item of provenance.assignments){
    if(!meanCall(item.rhs))continue;
    const direct=directGuardSliceKinds(item.rhs,provenance.tokens);
    let hasLeading=direct.has('leading'),hasTrailing=direct.has('trailing');
    for(const [name,kinds] of provenance.kinds){
      if(!new RegExp(`\\b${escapeRegex(name)}\\b`).test(item.rhs))continue;
      hasLeading=hasLeading||kinds.has('leading');hasTrailing=hasTrailing||kinds.has('trailing');
    }
    if(hasLeading&&hasTrailing){baselineVars.add(item.name);evidence.push(`guard-mean:${item.name}`);}
  }
  for(let round=0;round<4;round++){
    let changed=false;
    for(const item of provenance.assignments){
      if(baselineVars.has(item.name))continue;
      const parent=[...baselineVars].find((name)=>new RegExp(`\\b${escapeRegex(name)}\\b`).test(item.rhs));
      if(!parent)continue;
      if(!/^(?:float\s*\(|(?:np|numpy)\.float(?:32|64)?\s*\()?\s*[A-Za-z_]\w*\s*\)*$/i.test(item.rhs))continue;
      baselineVars.add(item.name);evidence.push(`guard-baseline-alias:${item.name}<-${parent}`);changed=true;
    }
    if(!changed)break;
  }
  if(!baselineVars.size)return {status:'missing',reason:'edge-guard-mean-not-proven',evidence};

  const centeredVars=new Set();
  for(const item of provenance.assignments){
    const baseline=[...baselineVars].find((name)=>new RegExp(`-\\s*${escapeRegex(name)}\\b`).test(item.rhs));
    if(!baseline)continue;
    centeredVars.add(item.name);evidence.push(`guard-centered:${item.name}<-${baseline}`);
  }
  const callRegex=/\b((?:np|numpy)\.(?:dot|inner|vdot)|torch\.(?:dot|inner))\s*\(([^\n]{1,500})\)/gi;
  for(const match of text.matchAll(callRegex)){
    const args=match[2];
    const centered=[...centeredVars].find((name)=>new RegExp(`\\b${escapeRegex(name)}\\b`).test(args));
    const inlineBaseline=[...baselineVars].find((name)=>new RegExp(`-\\s*${escapeRegex(name)}\\b`).test(args));
    if(centered||inlineBaseline){
      return {status:'ok',baselineGuard:{mode:'edge-mean',leading:layout.leading,trailing:layout.trailing,subtract:'feature-windows',source:'challenge-source',evidence:[...evidence,`baseline-linear-sink:${match[1].toLowerCase()}`]}};
    }
  }
  for(const raw of text.split(/\r?\n/)){
    if(!raw.includes('@'))continue;
    const centered=[...centeredVars].find((name)=>new RegExp(`\\b${escapeRegex(name)}\\b`).test(raw));
    const inlineBaseline=[...baselineVars].find((name)=>new RegExp(`-\\s*${escapeRegex(name)}\\b`).test(raw));
    if(centered||inlineBaseline)return {status:'ok',baselineGuard:{mode:'edge-mean',leading:layout.leading,trailing:layout.trailing,subtract:'feature-windows',source:'challenge-source',evidence:[...evidence,'baseline-linear-sink:@']}};
  }
  return {status:'missing',reason:'centered-value-does-not-feed-linear-sink',evidence};
}
function withGuardBaseline(sourceText,recipe){
  const result=guardBaselineEvidence(sourceText,recipe);
  if(result.status!=='ok')return recipe;
  return {...recipe,baselineGuard:result.baselineGuard,evidence:[...new Set([...list(recipe.evidence),'guard-baseline-edge-mean','guard-baseline-subtracted-before-hann',...list(result.baselineGuard.evidence)])]};
}
function resolveRealBundleFeatureRecipe(discovery,rawCols){
  const sourceText=discovery?.sourceText||'';
  const standard=resolveGroupedFeatureRecipe(discovery,rawCols);
  if(standard.status==='ok'&&standard.recipe?.metric==='hann-dot')return {...standard,sourceMode:'standard',recipe:withGuardBaseline(sourceText,standard.recipe)};
  const indirect=indirectHannDotEvidence(sourceText);
  if(indirect.status!=='ok')return standard;
  const structural=sourceRecipe(sourceText,rawCols);
  if(!structural)return standard.status==='gap'?standard:{status:'gap',code:'GROUP_FEATURE_RECIPE_GAP',detail:'indirect Hann kernel found but slot/window framing is not statically provable'};
  const windows=list(structural.windows).map((window)=>({...window,metric:'hann-dot',windowFunction:'hann'}));
  const evidence=[...new Set([...list(structural.evidence),'hann-dot-linear-amplitude','indirect-hann-kernel',...indirect.evidence])];
  const recipe=withGuardBaseline(sourceText,{...structural,metric:'hann-dot',windowFunction:'hann',windows,evidence});
  return {status:'ok',sourceMode:'indirect-hann-dataflow',recipe};
}
function baselineValue(row,baselineGuard){
  if(!baselineGuard||baselineGuard.mode!=='edge-mean')return 0;
  const leading=Number(baselineGuard.leading),trailing=Number(baselineGuard.trailing);
  if(!Number.isSafeInteger(leading)||!Number.isSafeInteger(trailing)||leading<=0||trailing<=0||leading+trailing>=row.length)throw new Error('guard baseline layout is invalid for row width');
  let sum=0,count=0;
  for(let index=0;index<leading;index+=1){const value=Number(row[index]);if(!Number.isFinite(value))throw new Error('feature source guard contains NaN/Inf');sum+=value;count+=1;}
  for(let index=row.length-trailing;index<row.length;index+=1){const value=Number(row[index]);if(!Number.isFinite(value))throw new Error('feature source guard contains NaN/Inf');sum+=value;count+=1;}
  return sum/count;
}
function transformRealBundleRow(row,recipe){
  if(!recipe?.baselineGuard)return transformRow(row,recipe);
  if(!Array.isArray(row)||row.length!==recipe.rawCols)throw new Error(`feature row width ${row?.length??0} != ${recipe.rawCols}`);
  const baseline=baselineValue(row,recipe.baselineGuard);
  return recipe.windows.map((window)=>{
    if(window.metric!=='hann-dot')throw new Error('guard baseline is only supported for proven hann-dot windows');
    let weighted=0;
    for(let index=0;index<window.length;index+=1){
      const value=Number(row[window.offset+index]);
      if(!Number.isFinite(value))throw new Error('feature source row contains NaN/Inf');
      weighted+=(value-baseline)*hannWeight(index,window.length);
    }
    return weighted;
  });
}
function wrapBudgetedStreamingFeatureSource(rowSource,recipe,options={}){
  if(!rowSource||typeof rowSource.readRows!=='function'||typeof rowSource.close!=='function')throw new Error('rowSource interface is invalid');
  if(Number(rowSource.cols)!==Number(recipe.rawCols))throw new Error(`feature recipe rawCols=${recipe.rawCols} does not match source cols=${rowSource.cols}`);
  const maxValues=Math.max(1,Math.min(MAX_RAW_VALUES_PER_READ,Number(options.maxRawReadValues)||MAX_RAW_VALUES_PER_READ));
  const rawChunkRows=Math.max(1,Math.floor(maxValues/Math.max(1,Number(rowSource.cols))));
  let closed=false;
  return {
    schema:'newcyber.sca-feature-row-source.v4',filePath:rowSource.filePath,fileName:rowSource.fileName,
    sourceKind:`${rowSource.sourceKind}+${recipe.windowFunction||'window'}-features`,rows:rowSource.rows,cols:recipe.windows.length,
    rawCols:rowSource.cols,segments:rowSource.segments,pickle:rowSource.pickle||null,recipe,
    readBudget:{maxRawValues:maxValues,rawChunkRows,rawCols:rowSource.cols,effectiveCols:recipe.windows.length},
    async readRows(start,count){
      start=Number(start);count=Number(count);
      if(!Number.isSafeInteger(start)||!Number.isSafeInteger(count)||start<0||count<0||start+count>rowSource.rows)throw new Error('feature readRows range invalid');
      const out=[];
      for(let offset=0;offset<count;){
        const take=Math.min(rawChunkRows,count-offset);
        const rows=await rowSource.readRows(start+offset,take);
        out.push(...rows.map((row)=>transformRealBundleRow(row,recipe)));offset+=take;
      }
      return out;
    },
    async close(){if(closed)return;closed=true;await rowSource.close();}
  };
}

module.exports={MAX_RAW_VALUES_PER_READ,DERIVED_CALL_ALLOWLIST,DOT_CALL_PATTERN,GUARD_AGGREGATE_CALLS,indirectHannDotEvidence,guardBaselineEvidence,baselineValue,transformRealBundleRow,resolveRealBundleFeatureRecipe,wrapBudgetedStreamingFeatureSource};