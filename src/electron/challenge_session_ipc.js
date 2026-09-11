'use strict';

const {app,BrowserWindow,dialog,ipcMain}=require('electron');
const fs=require('fs/promises');
const path=require('path');
const {scanWorkspace,inspectFile}=require('../core/finals_analyzer_batch15');
const {buildChallengeSession}=require('../core/challenge_session');
const {expandChallengeArchive}=require('../core/challenge_archive_ingest');
const {materializeRecoveredArtifacts}=require('../core/challenge_artifact_materialize');

const MAX_INPUT_FILES=64;
const MAX_TOTAL_BYTES=2*1024*1024*1024;
const MAX_MATERIALIZATION_PASSES=2;
const sessions=new Map();

function activeWindow(){return BrowserWindow.getFocusedWindow()||BrowserWindow.getAllWindows()[0]||null;}
function safeName(value,fallback='challenge.bin'){
  const base=path.basename(String(value||fallback)).replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').replace(/[. ]+$/g,'').trim();
  return (base||fallback).slice(0,180);
}
function uniqueName(name,used){
  const safe=safeName(name);const ext=path.extname(safe);const stem=ext?safe.slice(0,-ext.length):safe;
  let out=safe;let index=1;while(used.has(out.toLowerCase()))out=`${stem}-${index++}${ext}`;used.add(out.toLowerCase());return out;
}
function requireSession(rootPath){
  const root=path.resolve(String(rootPath||''));const session=sessions.get(root);if(!session)throw new Error('当前 Challenge Session 已失效，请重新丢入题目文件');return {root,session};
}

async function validateInputPaths(paths){
  const resolved=[];let total=0;
  for(const raw of [...new Set((paths||[]).map((x)=>path.resolve(String(x||''))).filter(Boolean))].slice(0,MAX_INPUT_FILES)){
    const stat=await fs.stat(raw);if(!stat.isFile())continue;
    total+=stat.size;if(total>MAX_TOTAL_BYTES)throw new Error('补充附件总大小超过 2 GiB Session 上限');
    resolved.push({path:raw,size:stat.size,name:path.basename(raw)});
  }
  if(!resolved.length)throw new Error('没有获得可分析的题目文件');
  return resolved;
}

async function newSessionRoot(){
  const parent=path.join(app.getPath('temp'),'newcyber-challenge-sessions');
  await fs.mkdir(parent,{recursive:true});
  return fs.mkdtemp(path.join(parent,`${process.pid}-`));
}

function ingestSummary(session){
  const items=Array.isArray(session.archiveIngest)?session.archiveIngest:[];
  const applicable=items.filter((item)=>item?.applicable);
  const expandedFiles=applicable.reduce((sum,item)=>sum+(item.files?.length||0),0);
  const expandedBytes=applicable.reduce((sum,item)=>sum+(Number(item.totalBytes)||0),0);
  const skipped=applicable.reduce((sum,item)=>sum+(item.skipped?.length||0),0);
  const unsupported=applicable.reduce((sum,item)=>sum+(item.unsupported?.length||0),0);
  const errors=items.filter((item)=>item?.error).length;
  return {archives:applicable.length,expandedFiles,expandedBytes,skipped,unsupported,errors,items};
}

function recoverySummary(session){
  const passes=Array.isArray(session.materializations)?session.materializations:[];
  return {
    passes:passes.length,
    files:passes.reduce((sum,item)=>sum+(item.files?.length||0),0),
    bytes:passes.reduce((sum,item)=>sum+(Number(item.totalBytes)||0),0),
    skipped:passes.reduce((sum,item)=>sum+(item.skipped?.length||0),0),
    items:passes
  };
}

async function writeIngestManifest(root,session){
  const summary=ingestSummary(session);
  if(!summary.archives&&!summary.errors)return;
  const manifest={
    schema:'newcyber.challenge-archive-ingest.v1',
    generatedAt:new Date().toISOString(),
    summary:{archives:summary.archives,expandedFiles:summary.expandedFiles,expandedBytes:summary.expandedBytes,skipped:summary.skipped,unsupported:summary.unsupported,errors:summary.errors},
    archives:summary.items.map((item)=>({
      source:item.source||null,kind:item.kind||null,applicable:Boolean(item.applicable),outputRoot:item.outputRoot||null,totalBytes:Number(item.totalBytes)||0,
      files:(item.files||[]).map((file)=>({path:file.path,size:file.size,sha256:file.sha256,archive:file.archive,entry:file.entry,depth:file.depth,kind:file.kind})),
      archives:item.archives||[],skipped:item.skipped||[],unsupported:item.unsupported||[],error:item.error||null
    }))
  };
  await fs.writeFile(path.join(root,'newcyber_ingest_manifest.json'),`${JSON.stringify(manifest,null,2)}\n`,'utf8');
}

async function writeRecoveryManifest(root,session){
  const summary=recoverySummary(session);if(!summary.passes)return;
  const manifest={
    schema:'newcyber.challenge-recovered-artifacts.v1',generatedAt:new Date().toISOString(),
    summary:{passes:summary.passes,files:summary.files,bytes:summary.bytes,skipped:summary.skipped},
    passes:summary.items.map((item)=>({pass:item.pass,outputRoot:item.outputRoot,totalBytes:item.totalBytes,files:item.files,skipped:item.skipped}))
  };
  await fs.writeFile(path.join(root,'newcyber_recovered_manifest.json'),`${JSON.stringify(manifest,null,2)}\n`,'utf8');
}

async function stageFiles(inputFiles,root,session){
  const used=new Set(session.stagedNames.map((x)=>x.toLowerCase()));
  for(const file of inputFiles){
    const name=uniqueName(file.name,used);const target=path.join(root,name);
    await fs.copyFile(file.path,target);
    session.sources.push(file.path);session.stagedNames.push(name);
    try{
      const ingest=await expandChallengeArchive(target,root);
      if(ingest.applicable)session.archiveIngest.push(ingest);
    }catch(error){
      session.archiveIngest.push({applicable:true,source:name,kind:null,files:[],archives:[],skipped:[],unsupported:[],totalBytes:0,error:error?.message||String(error)});
    }
  }
  await writeIngestManifest(root,session);
}

function descriptor(root,session){
  const names=session.sources.map((x)=>path.basename(x));
  const ingest=ingestSummary(session);const recovery=recoverySummary(session);
  return {
    kind:'file-session',
    stagedRoot:root,
    displayName:names.length===1?names[0]:`${names[0]||'Challenge'} +${Math.max(0,names.length-1)}`,
    originalPaths:[...session.sources],
    fileCount:session.sources.length,
    archiveExpanded:ingest.archives>0,
    archiveCount:ingest.archives,
    expandedFileCount:ingest.expandedFiles,
    expandedBytes:ingest.expandedBytes,
    archiveSkipped:ingest.skipped,
    archiveUnsupported:ingest.unsupported,
    archiveErrors:ingest.errors,
    recoveredPasses:recovery.passes,
    recoveredFileCount:recovery.files,
    recoveredBytes:recovery.bytes
  };
}

function preserveChallengeRuntime(previous,next){
  if(!previous)return next;
  for(const key of ['solverPipeline','pipelineSummary','solverExecution','executorSummary','aiPreprocessingManifest'])if(previous[key]!==undefined)next[key]=previous[key];
  return next;
}

async function scanSession(root,session){
  let input=descriptor(root,session);
  let analysis=await scanWorkspace(root,{challengeInput:input});
  for(let index=0;index<MAX_MATERIALIZATION_PASSES;index+=1){
    const recovered=await materializeRecoveredArtifacts(root,analysis,session.materializationState);
    if(!recovered.files.length)break;
    session.materializations.push(recovered);await writeRecoveryManifest(root,session);
    input=descriptor(root,session);
    analysis=await scanWorkspace(root,{challengeInput:input});
  }

  input=descriptor(root,session);analysis.challengeInput=input;analysis.workspaceName=input.displayName;
  const ingest=ingestSummary(session);const recovery=recoverySummary(session);
  analysis.archiveIngest={schema:'newcyber.challenge-archive-ingest-summary.v1',archives:ingest.archives,expandedFiles:ingest.expandedFiles,expandedBytes:ingest.expandedBytes,skipped:ingest.skipped,unsupported:ingest.unsupported,errors:ingest.errors};
  analysis.recoveredArtifacts={schema:'newcyber.challenge-recovered-artifact-summary.v1',passes:recovery.passes,files:recovery.files,bytes:recovery.bytes,skipped:recovery.skipped};
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  if(ingest.archives>0){
    const check={id:'archive-ingest',title:'压缩包安全展开 / 递归入库',hits:ingest.expandedFiles};const existing=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(existing)Object.assign(existing,check);else analysis.autopilot.automaticChecks.push(check);
  }
  if(recovery.files>0){
    const check={id:'recovered-artifact-materialize',title:'恢复产物落盘 / 固定点复扫',hits:recovery.files};const existing=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(existing)Object.assign(existing,check);else analysis.autopilot.automaticChecks.push(check);
  }
  const previous=analysis.challengeSession;
  analysis.challengeSession=preserveChallengeRuntime(previous,buildChallengeSession(analysis));
  analysis.challengeSession.archiveIngest=analysis.archiveIngest;
  analysis.challengeSession.recoveredArtifacts=analysis.recoveredArtifacts;
  if(analysis.aiPreprocessingManifest)analysis.challengeSession.aiPreprocessingManifest=analysis.aiPreprocessingManifest;
  return analysis;
}

async function createFromPaths(paths){
  const inputs=await validateInputPaths(paths);const root=await newSessionRoot();
  const session={sources:[],stagedNames:[],archiveIngest:[],materializations:[],materializationState:{materializedHashes:new Set(),materializationPass:0},createdAt:new Date().toISOString()};sessions.set(root,session);
  try{await stageFiles(inputs,root,session);return await scanSession(root,session);}catch(error){sessions.delete(root);await fs.rm(root,{recursive:true,force:true}).catch(()=>{});throw error;}
}

async function chooseFiles(title='选择题目文件或压缩包'){
  const result=await dialog.showOpenDialog(activeWindow(),{title,properties:['openFile','multiSelections'],filters:[{name:'Challenge files / archives',extensions:['*']}]});
  if(result.canceled||!result.filePaths.length)return null;
  return result.filePaths;
}

function registerChallengeSessionIpc(){
  ipcMain.handle('challenge:choose-files',async()=>{const paths=await chooseFiles();return paths?createFromPaths(paths):null;});
  ipcMain.handle('challenge:analyze-dropped',async(_event,paths)=>createFromPaths(paths));
  ipcMain.handle('challenge:add-files',async(_event,rootPath)=>{
    const {root,session}=requireSession(rootPath);const paths=await chooseFiles('补充当前题目的附件或压缩包');if(!paths)return null;
    const inputs=await validateInputPaths(paths);await stageFiles(inputs,root,session);return scanSession(root,session);
  });
  ipcMain.handle('challenge:add-dropped',async(_event,rootPath,paths)=>{
    const {root,session}=requireSession(rootPath);const inputs=await validateInputPaths(paths);await stageFiles(inputs,root,session);return scanSession(root,session);
  });
  ipcMain.handle('challenge:rescan',async(_event,rootPath)=>{const {root,session}=requireSession(rootPath);return scanSession(root,session);});
  ipcMain.handle('challenge:inspect',async(_event,rootPath,relativePath)=>{const {root}=requireSession(rootPath);return inspectFile(root,relativePath);});
}

module.exports={registerChallengeSessionIpc,validateInputPaths,descriptor,ingestSummary,recoverySummary};
