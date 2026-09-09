'use strict';

const {app,BrowserWindow,dialog,ipcMain}=require('electron');
const fs=require('fs/promises');
const path=require('path');
const {scanWorkspace,inspectFile}=require('../core/finals_analyzer_batch15');
const {buildChallengeSession}=require('../core/challenge_session');

const MAX_INPUT_FILES=64;
const MAX_TOTAL_BYTES=2*1024*1024*1024;
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
  const root=path.resolve(String(rootPath||''));const session=sessions.get(root);if(!session)throw new Error('当前单文件 Challenge Session 已失效，请重新丢入题目文件');return {root,session};
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

async function stageFiles(inputFiles,root,session){
  const used=new Set(session.stagedNames.map((x)=>x.toLowerCase()));
  for(const file of inputFiles){
    const name=uniqueName(file.name,used);const target=path.join(root,name);
    await fs.copyFile(file.path,target);
    session.sources.push(file.path);session.stagedNames.push(name);
  }
}

function descriptor(root,session){
  const names=session.sources.map((x)=>path.basename(x));
  return {
    kind:'file-session',
    stagedRoot:root,
    displayName:names.length===1?names[0]:`${names[0]||'Challenge'} +${Math.max(0,names.length-1)}`,
    originalPaths:[...session.sources],
    fileCount:session.sources.length
  };
}

async function scanSession(root,session){
  const input=descriptor(root,session);
  const analysis=await scanWorkspace(root,{challengeInput:input});
  analysis.challengeInput=input;
  analysis.workspaceName=input.displayName;
  analysis.challengeSession=buildChallengeSession(analysis);
  return analysis;
}

async function createFromPaths(paths){
  const inputs=await validateInputPaths(paths);const root=await newSessionRoot();
  const session={sources:[],stagedNames:[],createdAt:new Date().toISOString()};sessions.set(root,session);
  try{await stageFiles(inputs,root,session);return await scanSession(root,session);}catch(error){sessions.delete(root);await fs.rm(root,{recursive:true,force:true}).catch(()=>{});throw error;}
}

async function chooseFiles(title='选择题目文件'){
  const result=await dialog.showOpenDialog(activeWindow(),{title,properties:['openFile','multiSelections'],filters:[{name:'Challenge files',extensions:['*']}]});
  if(result.canceled||!result.filePaths.length)return null;
  return result.filePaths;
}

function registerChallengeSessionIpc(){
  ipcMain.handle('challenge:choose-files',async()=>{const paths=await chooseFiles();return paths?createFromPaths(paths):null;});
  ipcMain.handle('challenge:analyze-dropped',async(_event,paths)=>createFromPaths(paths));
  ipcMain.handle('challenge:add-files',async(_event,rootPath)=>{
    const {root,session}=requireSession(rootPath);const paths=await chooseFiles('补充当前题目的附件');if(!paths)return null;
    const inputs=await validateInputPaths(paths);await stageFiles(inputs,root,session);return scanSession(root,session);
  });
  ipcMain.handle('challenge:add-dropped',async(_event,rootPath,paths)=>{
    const {root,session}=requireSession(rootPath);const inputs=await validateInputPaths(paths);await stageFiles(inputs,root,session);return scanSession(root,session);
  });
  ipcMain.handle('challenge:rescan',async(_event,rootPath)=>{const {root,session}=requireSession(rootPath);return scanSession(root,session);});
  ipcMain.handle('challenge:inspect',async(_event,rootPath,relativePath)=>{const {root}=requireSession(rootPath);return inspectFile(root,relativePath);});
}

module.exports={registerChallengeSessionIpc,validateInputPaths,descriptor};