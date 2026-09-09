const {app,BrowserWindow,ipcMain,nativeTheme}=require('electron');
const os=require('os');
const {registerBinaryElfIpc}=require('./src/electron/binary_elf_ipc');
const {registerIdaSnapshotIpc}=require('./src/electron/ida_snapshot_ipc');

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

nativeTheme.on('updated',()=>emitState());
app.setName('NewCyber');
if(process.platform==='win32')app.setAppUserModelId('NewCyber.SecurityWorkbench');

const pocIndexBase=require('./src/core/poc_reference_index');
const pocIndexV2=require('./src/core/poc_reference_index_v2');
pocIndexBase.buildPocIndexFromDirectory=pocIndexV2.buildPocIndexFromDirectory;

registerBinaryElfIpc();
registerIdaSnapshotIpc();
require('./main');