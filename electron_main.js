const {app,BrowserWindow,ipcMain,nativeTheme,shell,dialog}=require('electron');
const os=require('os');
const path=require('path');
const fs=require('fs/promises');
const {registerBinaryElfIpc}=require('./src/electron/binary_elf_ipc');
const {registerIdaSnapshotIpc}=require('./src/electron/ida_snapshot_ipc');
const {registerAiScaIpc}=require('./src/electron/ai_sca_ipc');
const {registerChallengeSessionIpc}=require('./src/electron/challenge_session_ipc');
const {resolveSubmissionArtifact,safeSuggestedName}=require('./src/core/challenge_submission_export');

let activeWindow=null;
const materialByWindow=new WeakMap();

function supportsWindowsBackdrop(){
  if(process.platform!=='win32')return false;
  const build=Number(String(os.release()).split('.').pop());
  return Number.isFinite(build)&&build>=22621;
}

function stateOf(win=activeWindow){
  if(!win||win.isDestroyed())return {available:false,platform:process.platform};
  return {
    available:true,
    platform:process.platform,
    maximized:win.isMaximized(),
    fullScreen:win.isFullScreen(),
    alwaysOnTop:win.isAlwaysOnTop(),
    focused:win.isFocused(),
    dark:nativeTheme.shouldUseDarkColors,
    material:materialByWindow.get(win)||'native'
  };
}

function emitState(win=activeWindow){
  if(!win||win.isDestroyed()||win.webContents.isDestroyed())return;
  win.webContents.send('window:state-changed',stateOf(win));
}

function applyNativeMaterial(win){
  let material='native';
  if(supportsWindowsBackdrop()&&typeof win.setBackgroundMaterial==='function'){
    try{win.setBackgroundMaterial('mica');material='mica';}
    catch{material='native';}
  }
  if(process.platform==='darwin'){
    try{win.setVibrancy('under-window');material='vibrancy';}catch{}
    try{win.setVisualEffectState('active');}catch{}
  }
  materialByWindow.set(win,material);
}

app.on('browser-window-created',(_event,win)=>{
  activeWindow=win;
  applyNativeMaterial(win);
  for(const name of ['maximize','unmaximize','enter-full-screen','leave-full-screen','focus','blur','always-on-top-changed'])win.on(name,()=>emitState(win));
  win.webContents.on('did-finish-load',()=>emitState(win));
  win.on('closed',()=>{if(activeWindow===win)activeWindow=BrowserWindow.getAllWindows()[0]||null;});
});

ipcMain.handle('window:state',()=>stateOf());
ipcMain.handle('window:toggle-always-on-top',()=>{
  const win=activeWindow;
  if(!win||win.isDestroyed())return stateOf(win);
  win.setAlwaysOnTop(!win.isAlwaysOnTop(),'floating');
  emitState(win);
  return stateOf(win);
});
ipcMain.handle('window:task-progress',(_event,value)=>{
  const win=activeWindow;
  if(!win||win.isDestroyed())return false;
  if(value==='indeterminate')win.setProgressBar(2);
  else if(value==='none'||value==null)win.setProgressBar(-1);
  else if(Number.isFinite(Number(value)))win.setProgressBar(Math.max(0,Math.min(1,Number(value))));
  return true;
});
ipcMain.handle('artifact:reveal-path',(_event,rootPath,relativePath)=>{
  const root=path.resolve(String(rootPath||''));const rel=String(relativePath||'');
  if(!root||!rel||path.isAbsolute(rel)||rel.includes('\0'))return false;
  const target=path.resolve(root,rel);const prefix=root.endsWith(path.sep)?root:`${root}${path.sep}`;
  if(target!==root&&!target.startsWith(prefix))return false;
  shell.showItemInFolder(target);return true;
});
ipcMain.handle('artifact:export-submission',async(_event,rootPath,relativePath,suggestedName)=>{
  const parent=path.resolve(path.join(app.getPath('temp'),'newcyber-challenge-sessions'));
  const root=path.resolve(String(rootPath||''));const parentPrefix=parent.endsWith(path.sep)?parent:`${parent}${path.sep}`;
  if(root===parent||!root.startsWith(parentPrefix))return{saved:false,reason:'UNAPPROVED_SESSION_ROOT'};
  const source=resolveSubmissionArtifact(root,relativePath);if(!source)return{saved:false,reason:'INVALID_SUBMISSION_ARTIFACT'};
  let stat;try{stat=await fs.stat(source);}catch{return{saved:false,reason:'ARTIFACT_NOT_FOUND'};}
  if(!stat.isFile()||stat.size<=0||stat.size>16*1024*1024)return{saved:false,reason:'ARTIFACT_SIZE_INVALID'};
  const name=safeSuggestedName(suggestedName||path.basename(source));const ext=path.extname(name).replace(/^\./,'')||'txt';
  const result=await dialog.showSaveDialog(activeWindow,{title:'保存 NewCyber 提交结果',defaultPath:name,filters:[{name:'Submission result',extensions:[ext]}]});
  if(result.canceled||!result.filePath)return{saved:false,canceled:true};
  await fs.copyFile(source,result.filePath);
  return{saved:true,path:result.filePath,bytes:stat.size};
});

nativeTheme.on('updated',()=>emitState());
app.setName('NewCyber');
if(process.platform==='win32')app.setAppUserModelId('NewCyber.SecurityWorkbench');

const pocIndexBase=require('./src/core/poc_reference_index');
const pocIndexV2=require('./src/core/poc_reference_index_v2');
pocIndexBase.buildPocIndexFromDirectory=pocIndexV2.buildPocIndexFromDirectory;

registerBinaryElfIpc();
registerIdaSnapshotIpc();
registerAiScaIpc();
registerChallengeSessionIpc();
require('./main');