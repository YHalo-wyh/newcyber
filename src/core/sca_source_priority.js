'use strict';

const fs=require('fs/promises');
const path=require('path');

const TEXT_EXT=new Set(['.py','.pyw','.json','.toml','.yaml','.yml','.txt','.md']);
const MAX_INTENT_BYTES=768*1024;
const MAX_INTENT_FILES=24;

function scoreSourcePath(value){
  const filePath=String(value||'');const base=path.basename(filePath).toLowerCase();const ext=path.extname(base).toLowerCase();
  if(!TEXT_EXT.has(ext))return 0;
  let score=100;
  if(ext==='.py'||ext==='.pyw')score+=220;
  else if(['.json','.toml','.yaml','.yml'].includes(ext))score+=100;
  if(/^(?:solve_template|solve|solver|solution|exploit)(?:[._-]|$)/.test(base))score+=900;
  if(/(?:challenge|task|problem|recipe|config)/.test(base))score+=360;
  if(/(?:sca|side[_ -]?channel|power|trace|leak|probe|oracle|hidden|model|token)/.test(base))score+=520;
  if(/(?:readme|writeup|wp|report|notes?|log)/.test(base))score-=90;
  return score;
}

function prioritizeScaPaths(values=[]){
  return values.map((value,index)=>({value,index,score:scoreSourcePath(value)}))
    .sort((a,b)=>b.score-a.score||a.index-b.index)
    .map((item)=>item.value);
}

function inspectText(text,state){
  const value=String(text||'');
  if(/(?:np\.(?:hanning|hann)|torch\.hann_window|windows\.hann|scipy\.signal\.windows\.hann)/i.test(value))state.hann=true;
  if(/\b(?:FEATURE_DIM|LEAKAGE_DIM|TRACE_DIM)\s*=\s*[1-9]\d*/.test(value))state.compactFeature=true;
  if(/\b(?:GROUP_SIZE|GROUP_WIDTH|HIDDEN_GROUP_SIZE|ROWS_PER_TOKEN|GROUPS_PER_TOKEN|SAMPLES_PER_TRACE|WINDOW_SIZE)\s*=\s*[1-9]\d*/.test(value))state.groupEvidence=true;
  if(/(?:groupedFeatureRecipe|grouped_feature_recipe|featureRecipe|windowFunction|window_function)/i.test(value))state.recipeManifest=true;
  if(/(?:recoverGroupedTargets|fitGroupedLeakage|hidden.*probe|probe.*hidden)/i.test(value))state.groupedSolver=true;
}

async function inspectQualityIntent(filePaths=[]){
  const prioritized=prioritizeScaPaths(filePaths);const state={hann:false,compactFeature:false,groupEvidence:false,recipeManifest:false,groupedSolver:false};
  const inspected=[];let bytes=0;
  for(const filePath of prioritized){
    if(inspected.length>=MAX_INTENT_FILES||bytes>=MAX_INTENT_BYTES)break;
    const ext=path.extname(String(filePath||'')).toLowerCase();if(!TEXT_EXT.has(ext))continue;
    let stat;try{stat=await fs.stat(filePath);}catch{continue;}
    if(!stat.isFile()||stat.size<=0||stat.size>2*1024*1024)continue;
    const allowance=Math.min(stat.size,MAX_INTENT_BYTES-bytes);if(allowance<=0)break;
    let text='';
    if(allowance===stat.size)text=await fs.readFile(filePath,'utf8');
    else {const handle=await fs.open(filePath,'r');try{const buffer=Buffer.alloc(allowance);const read=await handle.read(buffer,0,allowance,0);text=buffer.subarray(0,read.bytesRead).toString('utf8');}finally{await handle.close();}}
    bytes+=Buffer.byteLength(text);inspected.push(path.basename(filePath));inspectText(text,state);
  }
  const reasons=[];
  if(state.hann)reasons.push('hann-window');
  if(state.recipeManifest)reasons.push('feature-recipe');
  if(state.compactFeature)reasons.push('compact-feature-dimension');
  if(state.groupEvidence)reasons.push('group-layout');
  if(state.groupedSolver)reasons.push('grouped-solver');
  const strong=state.hann||state.recipeManifest||(state.compactFeature&&state.groupEvidence);
  return {schema:'newcyber.sca-quality-intent.v1',strong,reasons,state,inspectedFiles:inspected,inspectedBytes:bytes,priorityPreview:prioritized.slice(0,12).map((item)=>path.basename(item))};
}

module.exports={TEXT_EXT,MAX_INTENT_BYTES,scoreSourcePath,prioritizeScaPaths,inspectQualityIntent};
