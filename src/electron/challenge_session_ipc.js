'use strict';

const {app,BrowserWindow,dialog,ipcMain}=require('electron');
const fs=require('fs/promises');
const path=require('path');
const {scanWorkspace,inspectFile}=require('../core/finals_analyzer_batch15');
const {buildChallengeSession}=require('../core/challenge_session_batch51');
const {expandChallengeArchive}=require('../core/challenge_archive_ingest');
const {materializeRecoveredArtifacts}=require('../core/challenge_artifact_materialize');
const {runChallengeOnnxAutopilot}=require('../core/challenge_onnx_autopilot');
const {runAiDetectionBundleAutopilot}=require('../core/ai_detection_bundle_autopilot');
const {matchTrainingFamilies}=require('../core/ai_training_family_matcher');
const {decodeImageWithElectron}=require('./challenge_image_decoder');

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

async function writeOnnxAutopilotManifest(root,result){
  if(!result||result.status==='not-applicable')return;
  const safe={
    schema:'newcyber.challenge-onnx-autopilot-report.v1',generatedAt:new Date().toISOString(),status:result.status,mode:result.mode||null,model:result.model||null,runs:result.runs||0,
    runtime:result.runtime||null,gap:result.gap||null,errors:(result.errors||[]).slice(0,64),bridge:result.bridge||null,
    contest:result.contest?{status:result.contest.status,result:result.contest.result||null,next:result.contest.next,verifierMatches:(result.contest.verifierMatches||[]).slice(0,16),ranking:result.contest.ranking?{hints:result.contest.ranking.hints,candidates:result.contest.ranking.candidates,candidateSets:(result.contest.ranking.candidateSets||[]).slice(0,64)}:null}:null
  };
  await fs.writeFile(path.join(root,'newcyber_onnx_autopilot.json'),`${JSON.stringify(safe,null,2)}\n`,'utf8');
}

async function writeDetectionAutopilotManifest(root,result){
  if(!result||result.status==='not-applicable')return;
  const safe={
    schema:'newcyber.challenge-detection-autopilot-report.v1',generatedAt:new Date().toISOString(),status:result.status,summary:result.summary||null,
    evaluations:(result.evaluations||[]).slice(0,64),gaps:(result.gaps||[]).slice(0,64),next:result.next||null,notes:result.notes||[]
  };
  await fs.writeFile(path.join(root,'newcyber_detection_autopilot.json'),`${JSON.stringify(safe,null,2)}\n`,'utf8');
}

async function writeTrainingFamilyManifest(root,result){
  if(!result||result.status==='not-detected')return;
  const safe={
    schema:'newcyber.challenge-training-family-match.v1',generatedAt:new Date().toISOString(),status:result.status,summary:result.summary||null,
    directionRanking:(result.directionRanking||[]).slice(0,12),signals:(result.signals||[]).slice(0,32),matches:(result.matches||[]).slice(0,12),next:result.next||null,notes:result.notes||[]
  };
  await fs.writeFile(path.join(root,'newcyber_training_family_match.json'),`${JSON.stringify(safe,null,2)}\n`,'utf8');
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
  const ingest=ingestSummary(session);const recovery=recoverySummary(session);const onnx=session.onnxAutopilot||null;const detection=session.detectionAutopilot||null;
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
    recoveredBytes:recovery.bytes,
    onnxAutopilotStatus:onnx?.status||null,
    onnxAutopilotRuns:Number(onnx?.runs)||0,
    detectionAutopilotStatus:detection?.status||null,
    detectionAutopilotEvaluations:Number(detection?.summary?.evaluations)||0
  };
}

function preserveChallengeRuntime(previous,next){
  if(!previous)return next;
  for(const key of ['solverPipeline','pipelineSummary','solverExecution','executorSummary','aiPreprocessingManifest','aiContestAutopilot','onnxContestAutopilot','aiDetectionAutopilot','trainingFamilyMatch'])if(previous[key]!==undefined)next[key]=previous[key];
  return next;
}
function upsertCheck(analysis,check){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];const existing=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(existing)Object.assign(existing,check);else analysis.autopilot.automaticChecks.push(check);
}
function mergeFindings(analysis,findings){
  analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));
  for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}
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

  let onnxAuto;
  try{onnxAuto=await runChallengeOnnxAutopilot(root,analysis,{decodeImage:decodeImageWithElectron});}
  catch(error){onnxAuto={schema:'newcyber.challenge-onnx-autopilot.v1',status:'gap',mode:null,runs:0,errors:[],contest:null,gap:{code:'AUTOPILOT_EXCEPTION',detail:String(error?.message||error).slice(0,500)}};}
  session.onnxAutopilot=onnxAuto;analysis.onnxContestAutopilot=onnxAuto;await writeOnnxAutopilotManifest(root,onnxAuto);
  if(onnxAuto?.contest&&(onnxAuto.status==='verified'||onnxAuto.status==='ranked')){
    analysis.aiContestAutopilot=onnxAuto.contest;mergeFindings(analysis,onnxAuto.contest.findings);
  }

  let detectionAuto;
  try{detectionAuto=await runAiDetectionBundleAutopilot(root,analysis);}
  catch(error){detectionAuto={schema:'newcyber.ai-detection-bundle-autopilot.v1',status:'gap',summary:{structuredFiles:0,evaluations:0,binaryRuns:0,lossHistoryRuns:0,effectiveCandidates:0,gaps:1},evaluations:[],gaps:[{reason:'AUTOPILOT_EXCEPTION',detail:String(error?.message||error).slice(0,500)}],findings:[],next:'检测结果自动复算阶段异常，已降级为 GAP。',notes:[]};}
  session.detectionAutopilot=detectionAuto;analysis.aiDetectionAutopilot=detectionAuto;await writeDetectionAutopilotManifest(root,detectionAuto);mergeFindings(analysis,detectionAuto.findings);

  const familyMatch=matchTrainingFamilies(analysis,{limit:10});
  analysis.trainingFamilyMatch=familyMatch;await writeTrainingFamilyManifest(root,familyMatch);

  input=descriptor(root,session);analysis.challengeInput=input;analysis.workspaceName=input.displayName;
  const ingest=ingestSummary(session);const recovery=recoverySummary(session);
  analysis.archiveIngest={schema:'newcyber.challenge-archive-ingest-summary.v1',archives:ingest.archives,expandedFiles:ingest.expandedFiles,expandedBytes:ingest.expandedBytes,skipped:ingest.skipped,unsupported:ingest.unsupported,errors:ingest.errors};
  analysis.recoveredArtifacts={schema:'newcyber.challenge-recovered-artifact-summary.v1',passes:recovery.passes,files:recovery.files,bytes:recovery.bytes,skipped:recovery.skipped};
  if(ingest.archives>0)upsertCheck(analysis,{id:'archive-ingest',title:'压缩包安全展开 / 递归入库',hits:ingest.expandedFiles});
  if(recovery.files>0)upsertCheck(analysis,{id:'recovered-artifact-materialize',title:'恢复产物落盘 / 固定点复扫',hits:recovery.files});
  if(onnxAuto?.status&&onnxAuto.status!=='not-applicable')upsertCheck(analysis,{id:'challenge-onnx-autopilot',title:'本地 ONNX 候选批量推理 / 赛式排名',hits:Number(onnxAuto.runs)||0});
  if(detectionAuto?.status&&detectionAuto.status!=='not-applicable')upsertCheck(analysis,{id:'ai-detection-bundle-autopilot',title:'检测结果表自动复算 / loss-history 排名',hits:Number(detectionAuto.summary?.evaluations)||0,detail:detectionAuto.next});
  if(familyMatch.status!=='not-detected')upsertCheck(analysis,{id:'training-family-match',title:'历史赛题家族匹配 / 策略路由',hits:familyMatch.matches.length,detail:familyMatch.next});
  const previous=analysis.challengeSession;
  analysis.challengeSession=preserveChallengeRuntime(previous,buildChallengeSession(analysis));
  analysis.challengeSession.archiveIngest=analysis.archiveIngest;
  analysis.challengeSession.recoveredArtifacts=analysis.recoveredArtifacts;
  analysis.challengeSession.onnxContestAutopilot={status:onnxAuto?.status||'not-applicable',mode:onnxAuto?.mode||null,runs:Number(onnxAuto?.runs)||0,gap:onnxAuto?.gap||null};
  analysis.challengeSession.aiDetectionAutopilot={status:detectionAuto?.status||'not-applicable',summary:detectionAuto?.summary||null,next:detectionAuto?.next||null,gaps:(detectionAuto?.gaps||[]).slice(0,8)};
  analysis.challengeSession.trainingFamilyMatch={status:familyMatch.status,directionRanking:familyMatch.directionRanking.slice(0,5),matches:familyMatch.matches.slice(0,5),next:familyMatch.next};
  if(analysis.aiPreprocessingManifest)analysis.challengeSession.aiPreprocessingManifest=analysis.aiPreprocessingManifest;
  if(analysis.aiContestAutopilot)analysis.challengeSession.aiContestAutopilot={status:analysis.aiContestAutopilot.status,next:analysis.aiContestAutopilot.next,result:analysis.aiContestAutopilot.result||null};
  return analysis;
}

async function createFromPaths(paths){
  const inputs=await validateInputPaths(paths);const root=await newSessionRoot();
  const session={sources:[],stagedNames:[],archiveIngest:[],materializations:[],materializationState:{materializedHashes:new Set(),materializationPass:0},onnxAutopilot:null,detectionAutopilot:null,createdAt:new Date().toISOString()};sessions.set(root,session);
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