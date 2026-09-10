'use strict';

const {sourceRecipe,resolveGroupedFeatureRecipe,transformRow}=require('./sca_streaming_feature_source');

const MAX_RAW_VALUES_PER_READ=2_000_000;

function list(value){return Array.isArray(value)?value:[];}
function assignmentLines(sourceText){
  const out=[];
  for(const raw of String(sourceText||'').split(/\r?\n/)){
    const line=raw.replace(/#.*$/,'').trim();
    const match=line.match(/^([A-Za-z_]\w*)\s*=\s*(.+)$/);
    if(match&&match[2].length<=512)out.push({name:match[1],rhs:match[2]});
  }
  return out;
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
      const parent=[...tainted].find((name)=>new RegExp(`\\b${name}\\b`).test(item.rhs));
      if(!parent)continue;
      // Only propagate through simple numeric alias/normalization expressions.
      // Calls outside a tiny NumPy reduction allowlist are rejected so unrelated
      // dataflow cannot accidentally become a Hann recipe proof.
      const calls=[...item.rhs.matchAll(/\b([A-Za-z_]\w*(?:\.\w+)*)\s*\(/g)].map((m)=>m[1].toLowerCase());
      if(calls.some((name)=>!['np.sum','numpy.sum','sum','np.asarray','numpy.asarray'].includes(name)))continue;
      if(!/^[A-Za-z0-9_\.\s+\-*/(),\[\]]+$/.test(item.rhs))continue;
      tainted.add(item.name);evidence.push(`hann-derived:${item.name}<-${parent}`);changed=true;
    }
    if(!changed)break;
  }
  for(const match of text.matchAll(/(?:np\.)?dot\s*\(([^,\n]{1,240}),\s*([^\)\n]{1,240})\)/gi)){
    const args=`${match[1]} ${match[2]}`;
    const kernel=[...tainted].find((name)=>new RegExp(`\\b${name}\\b`).test(args));
    if(kernel)return {status:'ok',kernel,evidence:[...evidence,`dot-kernel:${kernel}`]};
  }
  return {status:'missing',kernel:null,evidence};
}
function resolveRealBundleFeatureRecipe(discovery,rawCols){
  const standard=resolveGroupedFeatureRecipe(discovery,rawCols);
  if(standard.status==='ok'&&standard.recipe?.metric==='hann-dot')return {...standard,sourceMode:'standard'};
  const indirect=indirectHannDotEvidence(discovery?.sourceText||'');
  if(indirect.status!=='ok')return standard;
  const structural=sourceRecipe(discovery?.sourceText||'',rawCols);
  if(!structural)return standard.status==='gap'?standard:{status:'gap',code:'GROUP_FEATURE_RECIPE_GAP',detail:'indirect Hann kernel found but slot/window framing is not statically provable'};
  const windows=list(structural.windows).map((window)=>({...window,metric:'hann-dot',windowFunction:'hann'}));
  const evidence=[...new Set([...list(structural.evidence),'hann-dot-linear-amplitude','indirect-hann-kernel',...indirect.evidence])];
  return {status:'ok',sourceMode:'indirect-hann-dataflow',recipe:{...structural,metric:'hann-dot',windowFunction:'hann',windows,evidence}};
}
function wrapBudgetedStreamingFeatureSource(rowSource,recipe,options={}){
  if(!rowSource||typeof rowSource.readRows!=='function'||typeof rowSource.close!=='function')throw new Error('rowSource interface is invalid');
  if(Number(rowSource.cols)!==Number(recipe.rawCols))throw new Error(`feature recipe rawCols=${recipe.rawCols} does not match source cols=${rowSource.cols}`);
  const maxValues=Math.max(1,Math.min(MAX_RAW_VALUES_PER_READ,Number(options.maxRawReadValues)||MAX_RAW_VALUES_PER_READ));
  const rawChunkRows=Math.max(1,Math.floor(maxValues/Math.max(1,Number(rowSource.cols))));
  let closed=false;
  return {
    schema:'newcyber.sca-feature-row-source.v3',filePath:rowSource.filePath,fileName:rowSource.fileName,
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
        out.push(...rows.map((row)=>transformRow(row,recipe)));offset+=take;
      }
      return out;
    },
    async close(){if(closed)return;closed=true;await rowSource.close();}
  };
}

module.exports={MAX_RAW_VALUES_PER_READ,indirectHannDotEvidence,resolveRealBundleFeatureRecipe,wrapBudgetedStreamingFeatureSource};
