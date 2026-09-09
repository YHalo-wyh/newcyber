(() => {
  const api=window.newcyber;
  if(!api) return;
  let nativeState=null;
  let progressDepth=0;

  function materialLabel(state={}){
    if(state.material==='mica') return 'MICA';
    if(state.material==='vibrancy') return 'VIBRANCY';
    return 'NATIVE';
  }

  function applyState(state={}){
    nativeState=state;
    document.documentElement.dataset.platform=state.platform||'unknown';
    document.body.classList.toggle('electron-pinned',!!state.alwaysOnTop);
    document.body.classList.toggle('electron-maximized',!!state.maximized);
    document.body.classList.toggle('electron-unfocused',state.focused===false);
    const material=document.querySelector('[data-electron-material]');
    if(material) material.textContent=materialLabel(state);
    const pin=document.querySelector('[data-electron-action="pin"]');
    if(pin){
      pin.classList.toggle('active',!!state.alwaysOnTop);
      pin.setAttribute('aria-pressed',state.alwaysOnTop?'true':'false');
      pin.title=state.alwaysOnTop?'取消窗口置顶':'窗口置顶';
    }
  }

  function nativeCluster(){
    return `<div class="electron-native-cluster" data-electron-cluster>
      <span class="electron-material" data-electron-material>${materialLabel(nativeState||{})}</span>
      <button type="button" class="electron-native-button electron-pin" data-electron-action="pin" aria-pressed="false" title="窗口置顶"><span>PIN</span></button>
      <button type="button" class="electron-native-button electron-focus" data-electron-action="focus" aria-pressed="false" title="专注工作台"><span>FOCUS</span></button>
    </div>`;
  }

  function enhance(){
    document.body.classList.add('electron-native-shell');
    const topbar=document.querySelector('.topbar');
    if(!topbar) return;
    topbar.classList.add('electron-glass-topbar');
    const actions=topbar.querySelector('.top-actions');
    if(actions&&!actions.querySelector('[data-electron-cluster]')) actions.insertAdjacentHTML('afterbegin',nativeCluster());
    if(nativeState) applyState(nativeState);
  }

  async function beginNativeProgress(){
    progressDepth+=1;
    document.body.classList.add('electron-busy');
    if(progressDepth===1) await api.setTaskProgress?.('indeterminate').catch(()=>{});
  }

  async function endNativeProgress(){
    progressDepth=Math.max(0,progressDepth-1);
    if(progressDepth===0){
      document.body.classList.remove('electron-busy');
      await api.setTaskProgress?.('none').catch(()=>{});
    }
  }

  function wrapLongOperations(){
    if(typeof chooseWorkspace==='function'&&!chooseWorkspace.__electronWrapped){
      const base=chooseWorkspace;
      const wrapped=async function electronChooseWorkspace(...args){await beginNativeProgress();try{return await base.apply(this,args);}finally{await endNativeProgress();}};
      wrapped.__electronWrapped=true;
      chooseWorkspace=wrapped;
    }
    if(typeof runCurrentTool==='function'&&!runCurrentTool.__electronWrapped){
      const base=runCurrentTool;
      const wrapped=async function electronRunTool(...args){await beginNativeProgress();try{return await base.apply(this,args);}finally{await endNativeProgress();}};
      wrapped.__electronWrapped=true;
      runCurrentTool=wrapped;
    }
  }

  document.addEventListener('click',async(event)=>{
    const action=event.target.closest?.('[data-electron-action]')?.dataset.electronAction;
    if(action==='pin'){
      const button=event.target.closest('[data-electron-action="pin"]');
      if(button?.disabled) return;
      button.disabled=true;
      try{applyState(await api.toggleAlwaysOnTop());}finally{button.disabled=false;}
    }
    if(action==='focus'){
      const enabled=!document.body.classList.contains('electron-focus-mode');
      document.body.classList.toggle('electron-focus-mode',enabled);
      const button=event.target.closest('[data-electron-action="focus"]');
      button?.classList.toggle('active',enabled);
      button?.setAttribute('aria-pressed',enabled?'true':'false');
    }
  });

  const appRoot=document.querySelector('#app');
  if(appRoot) new MutationObserver(()=>requestAnimationFrame(enhance)).observe(appRoot,{childList:true,subtree:true});
  api.getWindowState?.().then(applyState).catch(()=>{});
  api.onWindowState?.(applyState);
  wrapLongOperations();
  enhance();
})();
