(() => {
  if (typeof toolView !== 'function') return;

  const TOOL='ai-skill-matrix';
  const previousToolView=toolView;
  const STAGES=[
    ['evidence','证据'],['skeleton','骨架'],['materialize','实体化'],['integration','集成门禁'],
    ['writer','写入计划'],['transaction','隔离事务'],['promotion','晋升'],['merge','合并授权']
  ];
  const ACTIONS={
    template:{route:'ai-training-evidence-template',label:'按下一轮生成模板'},
    intake:{route:'ai-training-evidence-intake',label:'校验证据'},
    skeleton:{route:'ai-training-regression-skeleton',label:'生成回归骨架'},
    materialize:{route:'ai-training-regression-materialize',label:'Dry-run 实体化'},
    integration:{route:'ai-training-integration-gate',label:'模拟集成收益'},
    inspect:{route:'ai-training-pipeline-status',label:'检查当前阶段'}
  };

  let draft='';
  let result=null;
  let status=null;
  let busy='';
  let error='';

  function h(value){
    if (typeof esc==='function') return esc(String(value??''));
    return String(value??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  function json(value){try{return JSON.stringify(value,null,2);}catch{return String(value??'');}}
  function parseDraft(){
    const source=draft.trim();
    if(!source)throw new Error('先生成模板或粘贴候选 JSON。');
    try{return JSON.parse(source);}catch(e){throw new Error(`JSON 无法解析：${e.message}`);}
  }
  function currentStage(){return status?.stage||null;}
  function currentState(){return status?.state||'idle';}
  function stateClass(value){return ['passed','prepared','draft'].includes(value)?'good':['blocked','rejected','stale'].includes(value)?'bad':value==='pending'?'pending':'idle';}
  function stageRail(){
    const states=new Map((status?.stages||[]).map((row)=>[row.id,row.state]));
    return `<div class="training-pipeline-rail">${STAGES.map(([id,label],index)=>{
      const s=states.get(id)||'pending';
      return `<div class="training-pipeline-stage ${stateClass(s)}"><i>${index+1}</i><span>${h(label)}</span><small>${h(s)}</small></div>`;
    }).join('')}</div>`;
  }
  function blockerPanel(){
    const blockers=status?.blockers||[];
    if(error)return `<div class="training-pipeline-alert bad"><b>执行失败</b><span>${h(error)}</span></div>`;
    if(!result)return `<div class="training-pipeline-alert neutral"><b>从当前 NEXT ROUND 开始</b><span>先生成 Work Order 对应的 Evidence Intake 模板，再补公开来源、成功条件、负对照与 synthetic verifier。这里不会自动编造赛题机制。</span></div>`;
    if(blockers.length)return `<div class="training-pipeline-alert bad"><b>${h(status.stageLabel||'Gate')} · ${h(currentState())}</b><span>${h(blockers.slice(0,6).join(' · '))}</span></div>`;
    return `<div class="training-pipeline-alert good"><b>${h(status?.stageLabel||'Pipeline')} · ${h(currentState())}</b><span>${status?.nextRoute?`下一步 ${h(status.nextRoute)}`:'当前阶段没有自动后继动作。仓库写入、隔离事务、CI 与 promotion 必须继续使用显式凭证。'}</span></div>`;
  }
  function editorPanel(){
    const schema=result?.schema||'';
    return `<div class="training-pipeline-editor-wrap">
      <div class="training-pipeline-editor-head"><div><span>CANDIDATE / ARTIFACT JSON</span><b>${h(schema||'尚未生成')}</b></div><em>${draft?`${draft.length} chars`:'empty'}</em></div>
      <textarea class="training-pipeline-editor" data-training-pipeline-editor spellcheck="false" placeholder="生成模板，或粘贴 Evidence Intake / Skeleton / Materializer JSON…">${h(draft)}</textarea>
      <div class="training-pipeline-editor-note">Skeleton 阶段需要你把 3 个 synthetic fixture 的 <code>payload</code>、<code>expected.predicate</code>、<code>expected.assertions</code> 填完整，Materializer 才会执行本地 evaluator。真实 Flag / 私钥 / Token 会被拒绝。</div>
    </div>`;
  }
  function actions(){
    return `<div class="training-pipeline-actions">
      ${Object.entries(ACTIONS).map(([id,meta])=>`<button class="button ${id==='template'?'':'ghost'}" data-training-pipeline-action="${id}" ${busy?'disabled':''}>${busy===id?'处理中…':h(meta.label)}</button>`).join('')}
      <button class="button ghost danger" data-training-pipeline-clear ${busy?'disabled':''}>清空</button>
    </div>`;
  }
  function repositoryBoundary(){
    return `<div class="training-pipeline-boundary"><div><span>REPOSITORY BOUNDARY</span><b>Writer → Transaction → Promotion 不允许被 UI 快捷跳过</b></div><p>Integration Gate 通过后，后续阶段必须携带 curriculum source SHA、base/head SHA、隔离分支、repository tests、full regression 与 CI proof。工作台只展示状态，不会把一次按钮点击当成 merge authorization。</p></div>`;
  }
  function pipelinePanel(){
    return `<section class="training-pipeline-panel">
      <div class="training-pipeline-head"><div><span>TRAINING PROMOTION PIPELINE</span><b>训练样本晋升流水线</b><small>Evidence → deterministic regression → structural gain → isolated integration → promotion</small></div><strong>${h(currentStage()||'IDLE')}</strong></div>
      ${stageRail()}
      ${blockerPanel()}
      <div class="training-pipeline-main">${editorPanel()}${actions()}</div>
      ${repositoryBoundary()}
    </section>`;
  }
  function inject(html){
    if(typeof html!=='string'||!html.includes('stage1-training-pane'))return html;
    const marker='<div class="stage1-training-note">';
    if(!html.includes(marker))return html;
    return html.replace(marker,`${pipelinePanel()}${marker}`);
  }
  async function refreshStatus(value){
    try{status=await window.newcyber.runTool('ai-training-pipeline-status',{input:value});}
    catch{status=null;}
  }
  async function execute(id){
    const meta=ACTIONS[id];
    if(!meta||busy)return;
    busy=id;error='';render();state.tool=TOOL;
    try{
      let input={};
      if(id!=='template')input=parseDraft();
      result=await window.newcyber.runTool(meta.route,id==='template'?{}:{input});
      draft=json(result);
      await refreshStatus(result);
    }catch(e){error=e?.message||String(e);}
    finally{
      busy='';render();state.tool=TOOL;
    }
  }

  toolView=function batch107TrainingPipelineToolView(tool){
    const html=previousToolView(tool);
    return tool===TOOL?inject(html):html;
  };

  document.addEventListener('input',(event)=>{
    const editor=event.target.closest?.('[data-training-pipeline-editor]');
    if(!editor||state.tool!==TOOL)return;
    draft=editor.value;
  });
  document.addEventListener('click',(event)=>{
    const action=event.target.closest?.('[data-training-pipeline-action]');
    if(action&&state.tool===TOOL){execute(action.dataset.trainingPipelineAction);return;}
    const clear=event.target.closest?.('[data-training-pipeline-clear]');
    if(clear&&state.tool===TOOL&&!busy){draft='';result=null;status=null;error='';render();state.tool=TOOL;}
  });
})();
