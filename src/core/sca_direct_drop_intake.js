'use strict';

const fsp=require('fs/promises');
const path=require('path');
const base=require('./sca_autopilot');
const {TEXT_EXT,scoreSourcePath}=require('./sca_source_priority');

const MAX_SOURCE_FILES=24;
const MAX_SOURCE_BYTES=1024*1024;
const MAX_SINGLE_SOURCE_BYTES=512*1024;

function list(value){return Array.isArray(value)?value:[];}
function pathKey(value){
  const resolved=path.resolve(String(value||''));
  return process.platform==='win32'?resolved.toLowerCase():resolved;
}
function normalizedLiteral(value){return String(value||'').replace(/[\\/]+/g,path.sep);}
function quotedPathLiterals(text){
  const out=[];
  const source=String(text||'');
  for(const match of source.matchAll(/(["'])([^"'\r\n]{1,320})\1/g)){
    const value=match[2].trim();
    if(!value||/^(?:https?:|data:|[A-Za-z]+:\/\/)/i.test(value))continue;
    out.push(value);
    if(out.length>=4096)break;
  }
  return out;
}

function ambiguousCandidates(discovery,roleName){
  const role=discovery?.roles?.[roleName];
  if(role?.status!=='ambiguous')return [];
  const names=new Set(list(role.files).map((name)=>String(name)));
  return list(discovery.files).filter((file)=>names.has(String(file.fileName)));
}

async function readPrioritySources(discovery){
  const files=list(discovery?.files)
    .filter((file)=>TEXT_EXT.has(String(file.extension||'').toLowerCase())&&Number(file.size)>0&&Number(file.size)<=MAX_SINGLE_SOURCE_BYTES)
    .sort((a,b)=>scoreSourcePath(b.filePath)-scoreSourcePath(a.filePath)||String(a.filePath).localeCompare(String(b.filePath)));
  const out=[];let total=0;
  for(const file of files){
    if(out.length>=MAX_SOURCE_FILES||total>=MAX_SOURCE_BYTES)break;
    const allowance=Math.min(Number(file.size)||0,MAX_SOURCE_BYTES-total);
    if(allowance<=0)break;
    let text='';
    try{
      if(allowance===Number(file.size))text=await fsp.readFile(file.filePath,'utf8');
      else{
        const handle=await fsp.open(file.filePath,'r');
        try{const buffer=Buffer.alloc(allowance);const read=await handle.read(buffer,0,allowance,0);text=buffer.subarray(0,read.bytesRead).toString('utf8');}
        finally{await handle.close();}
      }
    }catch{continue;}
    total+=Buffer.byteLength(text);
    out.push({file,text,literals:quotedPathLiterals(text),score:scoreSourcePath(file.filePath)});
  }
  return out;
}

function literalResolvesTo(sourceFile,literal,candidate){
  const raw=normalizedLiteral(literal);
  if(!raw||raw.includes('\0'))return false;
  let resolved;
  try{resolved=path.resolve(path.dirname(sourceFile.filePath),raw);}
  catch{return false;}
  return pathKey(resolved)===pathKey(candidate.filePath);
}

function resolveRoleFromSources(discovery,roleName,sources){
  const candidates=ambiguousCandidates(discovery,roleName);
  if(candidates.length<2)return {status:'not-ambiguous',role:roleName};
  const evidence=[];
  for(const source of sources){
    for(const candidate of candidates){
      const matches=source.literals.filter((literal)=>literalResolvesTo(source.file,literal,candidate));
      if(!matches.length)continue;
      evidence.push({
        candidate,
        source:source.file,
        sourceScore:source.score,
        literal:matches[0],
        references:matches.length
      });
    }
  }
  if(!evidence.length)return {status:'unresolved',role:roleName,reason:'no exact source-relative literal reference',candidates:candidates.map((x)=>x.fileName)};
  const topScore=Math.max(...evidence.map((item)=>item.sourceScore));
  const top=evidence.filter((item)=>item.sourceScore===topScore);
  const candidateKeys=[...new Set(top.map((item)=>pathKey(item.candidate.filePath)))];
  if(candidateKeys.length!==1){
    return {
      status:'unresolved',role:roleName,reason:'highest-priority source evidence still selects multiple candidates',
      candidates:candidates.map((x)=>x.fileName),
      evidence:top.map((item)=>({candidate:item.candidate.filePath,source:item.source.filePath,literal:item.literal,sourceScore:item.sourceScore}))
    };
  }
  const chosen=top.find((item)=>pathKey(item.candidate.filePath)===candidateKeys[0]);
  return {
    status:'ok',role:roleName,file:chosen.candidate,
    evidence:{mode:'source-relative-literal',source:chosen.source.filePath,literal:chosen.literal,sourceScore:chosen.sourceScore,references:chosen.references},
    candidates
  };
}

function originalOkRoles(discovery){
  const out=[];
  for(const [role,value] of Object.entries(discovery?.roles||{}))if(value?.status==='ok'&&value.file?.filePath)out.push({role,file:value.file});
  return out;
}

async function resolveDirectDropScaIntake(filePaths,options={}){
  const original=list(filePaths).map((value)=>path.resolve(String(value)));
  let discovery;
  try{discovery=await base.discoverScaArtifacts(original,{...options,strict:false});}
  catch(error){return {status:'unavailable',paths:original,reason:error?.message||String(error),resolutions:[],dropped:[]};}
  if(discovery?.status!=='ok')return {status:'unavailable',paths:original,reason:discovery?.detail||discovery?.code||'discovery unavailable',resolutions:[],dropped:[],discovery};
  const ambiguous=Object.entries(discovery.roles||{}).filter(([,value])=>value?.status==='ambiguous').map(([role])=>role);
  if(!ambiguous.length)return {status:'unchanged',paths:original,resolutions:[],dropped:[],discovery};

  const sources=await readPrioritySources(discovery);
  const attempts=ambiguous.map((role)=>resolveRoleFromSources(discovery,role,sources));
  const resolved=attempts.filter((item)=>item.status==='ok');
  if(!resolved.length)return {status:'unresolved',paths:original,resolutions:attempts,dropped:[],discovery};

  const protectedPaths=new Set(originalOkRoles(discovery).map((item)=>pathKey(item.file.filePath)));
  for(const item of resolved)protectedPaths.add(pathKey(item.file.filePath));
  for(const item of attempts.filter((entry)=>entry.status!=='ok')){
    for(const candidate of ambiguousCandidates(discovery,item.role))protectedPaths.add(pathKey(candidate.filePath));
  }

  const drop=new Set();
  for(const item of resolved){
    for(const candidate of item.candidates){
      const key=pathKey(candidate.filePath);
      if(key===pathKey(item.file.filePath)||protectedPaths.has(key))continue;
      drop.add(key);
    }
  }
  if(!drop.size)return {status:'unresolved',paths:original,resolutions:attempts,dropped:[],discovery,reason:'resolved evidence could not remove candidates without affecting another role'};
  const filtered=original.filter((value)=>!drop.has(pathKey(value)));

  let preview;
  try{preview=await base.discoverScaArtifacts(filtered,{...options,strict:false});}
  catch(error){return {status:'unresolved',paths:original,resolutions:attempts,dropped:[],discovery,reason:`post-filter discovery failed: ${error?.message||String(error)}`};}
  if(preview?.status!=='ok')return {status:'unresolved',paths:original,resolutions:attempts,dropped:[],discovery,reason:`post-filter discovery: ${preview?.code||preview?.status}`};
  for(const item of originalOkRoles(discovery)){
    const after=preview.roles?.[item.role];
    if(after?.status!=='ok'||pathKey(after.file?.filePath)!==pathKey(item.file.filePath)){
      return {status:'unresolved',paths:original,resolutions:attempts,dropped:[],discovery,reason:`filter would change already-proven role ${item.role}`};
    }
  }
  for(const item of resolved){
    const after=preview.roles?.[item.role];
    if(after?.status!=='ok'||pathKey(after.file?.filePath)!==pathKey(item.file.filePath)){
      return {status:'unresolved',paths:original,resolutions:attempts,dropped:[],discovery,reason:`role ${item.role} remained ambiguous after evidence-bound filtering`};
    }
  }

  const dropped=original.filter((value)=>drop.has(pathKey(value)));
  return {
    schema:'newcyber.sca-direct-drop-intake.v1',status:'resolved',paths:filtered,
    resolutions:attempts,dropped,discovery:preview,
    sourceEvidence:{inspected:sources.map((item)=>path.basename(item.file.filePath)),bytes:sources.reduce((sum,item)=>sum+Buffer.byteLength(item.text),0)}
  };
}

module.exports={
  MAX_SOURCE_FILES,MAX_SOURCE_BYTES,quotedPathLiterals,ambiguousCandidates,
  resolveRoleFromSources,resolveDirectDropScaIntake
};
