'use strict';

const fs=require('fs/promises');
const path=require('path');
const {bufferFromArtifact,sanitizeName}=require('./artifacts');

const DEFAULT_LIMITS=Object.freeze({maxFiles:64,maxBytes:192*1024*1024,maxArtifactBytes:32*1024*1024});

function list(value){return Array.isArray(value)?value:[];}
function safeSegment(value,fallback='source'){
  return String(value||fallback).replace(/[^A-Za-z0-9._-]+/g,'_').replace(/^[.]+/,'').slice(0,120)||fallback;
}
function inside(root,target){const rel=path.relative(path.resolve(root),path.resolve(target));return rel===''||(!rel.startsWith(`..${path.sep}`)&&rel!=='..'&&!path.isAbsolute(rel));}

function artifactCandidates(analysis={}){
  const rows=[];const seen=new Set();
  const push=(artifact,source,kind)=>{
    if(!artifact||artifact.version!==1||artifact.completeness!=='complete'||!artifact.sha256||seen.has(String(artifact.sha256)))return;
    seen.add(String(artifact.sha256));rows.push({artifact,source,kind});
  };
  for(const file of list(analysis.files)){
    for(const artifact of list(file.artifacts))push(artifact,file.path,'file-artifact');
    for(const artifact of list(file.metadata?.recursiveArtifacts?.artifacts))push(artifact,file.path,'recursive-artifact');
    for(const item of list(file.metadata?.autoDecode?.candidates))push(item?.artifact,file.path,'auto-decode');
    for(const item of list(file.metadata?.contextCrypto?.bestCandidates))push(item?.artifact,file.path,'context-crypto');
    for(const artifact of list(file.metadata?.captureIntelligence?.video?.artifacts))push(artifact,file.path,'capture-video');
    for(const item of list(file.metadata?.captureIntelligence?.video?.sessions))push(item?.artifact,file.path,'capture-video-session');
  }
  return rows;
}

async function uniqueTarget(root,source,name,used){
  const dir=path.join(root,safeSegment(source.replace(/[\\/]+/g,'_')));await fs.mkdir(dir,{recursive:true});
  const clean=sanitizeName(name||'recovered.bin');const ext=path.extname(clean),stem=ext?clean.slice(0,-ext.length):clean;
  let candidate=clean,index=1;while(used.has(path.join(dir,candidate).toLowerCase()))candidate=`${stem}__${index++}${ext}`;
  const target=path.resolve(dir,candidate);if(!inside(root,target))throw new Error('materialized artifact path escapes recovery root');
  used.add(target.toLowerCase());return target;
}

async function materializeRecoveredArtifacts(sessionRoot,analysis,sessionState={},options={}){
  const limits={...DEFAULT_LIMITS,...options};
  limits.maxFiles=Math.max(1,Math.min(Number(limits.maxFiles)||DEFAULT_LIMITS.maxFiles,256));
  limits.maxBytes=Math.max(1024,Math.min(Number(limits.maxBytes)||DEFAULT_LIMITS.maxBytes,512*1024*1024));
  limits.maxArtifactBytes=Math.max(1024,Math.min(Number(limits.maxArtifactBytes)||DEFAULT_LIMITS.maxArtifactBytes,128*1024*1024));
  const root=path.resolve(String(sessionRoot||''));const pass=Math.max(1,Number(sessionState.materializationPass||0)+1);
  const outputRoot=path.join(root,'__recovered__',`pass-${pass}`);const existingHashes=new Set(list(analysis.files).map((file)=>String(file.sha256||'').toLowerCase()).filter((value)=>/^[0-9a-f]{64}$/.test(value)));
  const known=sessionState.materializedHashes instanceof Set?sessionState.materializedHashes:new Set(list(sessionState.materializedHashes).map(String));
  sessionState.materializedHashes=known;
  const used=new Set();const files=[];const skipped=[];let totalBytes=0;
  for(const row of artifactCandidates(analysis)){
    if(files.length>=limits.maxFiles)break;
    const digest=String(row.artifact.sha256||'').toLowerCase();
    if(existingHashes.has(digest)||known.has(digest))continue;
    if(!Number.isFinite(Number(row.artifact.size))||Number(row.artifact.size)<=0||Number(row.artifact.size)>limits.maxArtifactBytes){skipped.push({sha256:digest,source:row.source,reason:'artifact-size-limit'});continue;}
    if(totalBytes+Number(row.artifact.size)>limits.maxBytes){skipped.push({sha256:digest,source:row.source,reason:'pass-byte-budget'});break;}
    try{
      const decoded=bufferFromArtifact(row.artifact,{requireComplete:true});
      if(totalBytes+decoded.buffer.length>limits.maxBytes)break;
      const target=await uniqueTarget(outputRoot,row.source,decoded.name,used);await fs.writeFile(target,decoded.buffer,{flag:'wx'});
      known.add(decoded.sha256);totalBytes+=decoded.buffer.length;
      files.push({path:path.relative(root,target),name:path.basename(target),size:decoded.buffer.length,sha256:decoded.sha256,source:row.source,kind:row.kind,provenance:list(row.artifact.provenance).slice(0,12),metadata:row.artifact.metadata||{}});
    }catch(error){skipped.push({sha256:digest,source:row.source,reason:String(error?.message||error).slice(0,220)});}
  }
  if(files.length)sessionState.materializationPass=pass;
  return{schema:'newcyber.challenge-artifact-materialization.v1',pass,outputRoot:path.relative(root,outputRoot),files,totalBytes,skipped,limits};
}

module.exports={DEFAULT_LIMITS,artifactCandidates,materializeRecoveredArtifacts};
