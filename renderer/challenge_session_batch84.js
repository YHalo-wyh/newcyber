(() => {
  if(typeof workspaceView!=='function'||typeof homeView!=='function'||typeof shell!=='function'||typeof render!=='function'||typeof esc!=='function')return;

  function currentSession(){return state.workspace?.challengeSession||{};}
  function currentInput(){return state.workspace?.challengeInput||{};}
  function isFileSession(){return currentInput().kind==='file-session'||currentSession()?.source?.kind==='file-session';}
  function challengeName(){return currentInput().displayName||state.workspace?.workspaceName||'自动解题';}
  function list(value){return Array.isArray(value)?value:[];}
  function text(value){return String(value??'').trim();}
  function shortened(value,limit=720){const v=text(value);return v.length>limit?`${v.slice(0,limit)} …`:v;}

  function effectiveResult(a,s){
    const sim=a?.aiSimAutopilot;
    if(sim?.answer?.flag&&(sim.status==='verified'||sim.status==='candidate'))return {value:sim.answer.flag,payload:sim.answer.candidate?JSON.stringify(sim.answer.candidate):'',source:`ai-ichunqiu-sim:${sim.answer.family}`};
    if(s?.result?.value||s?.result?.payload)return s.result;
    const membership=a?.aiMembershipAutopilot;
    if(membership?.status==='candidate'&&membership.result)return membership.result;
    const contest=a?.aiContestAutopilot;
    if(contest?.result)return contest.result;
    return null;
  }
  function resultPayload(a,s){const result=effectiveResult(a,s);return text(result?.payload||result?.value);}
  function resultDisplay(a,s){
    const result=effectiveResult(a,s);if(!result)return'';
    return text(result.displayValue||result.value||result.payload);
  }
  function isVerified(a,s){
    const result=effectiveResult(a,s);
    return s?.status==='solved'||result?.verified===true||text(result?.confidence).toLowerCase()==='verified'||a?.verifierContractAutopilot?.status==='verified';
  }

  function placement(){
    return isFileSession()
      ?'直接拖到这个卡片，或点“补充材料”。文件会加入当前隔离 Session，然后自动重跑。'
      :'把文件放进当前赛题目录（任意子目录都可以），然后点“重新分析”。';
  }
  function membershipNext(a){
    const auto=a?.aiMembershipAutopilot;if(!auto||auto.status==='not-detected')return null;
    if(auto.status==='candidate')return{code:'MEMBERSHIP_VERIFIER_OR_SCHEMA',title:'补题目提交格式或 checker',why:'Member ID 候选已经算出来，但缺题目自己的判定规则，所以现在只标记为候选。',provide:['checker.py / verifier.py / scorer.py','sample_submission.csv / submission.json','README / 题面评分规则'],format:'任意一种能说明“提交哪些字段、顺序、阈值或评分方式”的材料即可。',where:placement(),action:isFileSession()?'add':'rescan'};
    if(auto.status==='ambiguous')return{code:'MEMBERSHIP_PAIR_AMBIGUOUS',title:'说明哪份是 calibration，哪份是 query',why:auto.reason||'存在多个近似等价的数据配对，自动链不会按文件顺序猜。',provide:['calibration/reference 文件','query/challenge/test 文件','README / 题面说明'],format:'推荐命名 calibration.csv 与 query.csv；两边至少共享 loss / confidence / entropy / margin 中一个信号列。',where:placement(),action:isFileSession()?'add':'rescan'};
    if(auto.status==='gap'){
      const reason=text(auto.reason||auto.next);
      if(/calibration|reference|member\/non-member|真值/i.test(reason))return{code:'MEMBERSHIP_CALIBRATION_MISSING',title:'提供带成员真值的 calibration/reference 数据',why:reason,provide:['calibration.csv','reference.json / shadow.json'],format:'至少包含 id、member(0/1)，以及 loss / confidence / entropy / margin 中至少一列；同时要有 member 和 non-member。',where:placement(),action:isFileSession()?'add':'rescan'};
      return{code:'MEMBERSHIP_QUERY_MISSING',title:'提供待判定 query/challenge 数据',why:reason,provide:['query.csv','challenge.json / test.csv'],format:'包含 id，以及与 calibration 同名的 loss / confidence / entropy / margin 信号列；不要提供 challenge 真值。',where:placement(),action:isFileSession()?'add':'rescan'};
    }
    return null;
  }
  function genericNext(a,s){
    if(isVerified(a,s))return null;
    if(s?.nextInput?.title)return{...s.nextInput,where:s.nextInput.where||placement(),action:s.nextInput.action==='add-files'?'add':s.nextInput.action|| (isFileSession()?'add':'rescan')};
    const membership=membershipNext(a);if(membership)return membership;
    const onnx=a?.onnxContestAutopilot;
    if(onnx?.status==='gap'){
      const code=text(onnx.gap?.code).toUpperCase();const detail=text(onnx.gap?.detail)||'本地模型自动链还缺一个必要输入。';
      if(/MODEL/.test(code)||/模型|onnx/i.test(detail))return{code:code||'ONNX_MODEL_MISSING',title:'提供实际推理用的 ONNX 模型',why:detail,provide:['*.onnx','若有多个模型，再给 README / 配置说明'],format:'不要重命名模型内部输入；原始附件直接丢入即可。',where:placement(),action:isFileSession()?'add':'rescan'};
      if(/PREPROCESS|INPUT|IMAGE/.test(code)||/resize|normalize|preprocess|输入/i.test(detail))return{code:code||'ONNX_PREPROCESSING_MISSING',title:'提供模型预处理 / 输入配置',why:detail,provide:['infer.py / predict.py / preprocess.py','config.yaml / config.json','示例输入 .npy'],format:'最好明确 Resize、RGB/BGR、Normalize、NCHW/NHWC、dtype。NewCyber 不猜 ImageNet 默认参数。',where:placement(),action:isFileSession()?'add':'rescan'};
      return{code:code||'ONNX_GAP',title:'补齐模型自动链当前缺口',why:detail,provide:['题目 README / 配置','缺失的模型、label/hint、预处理或示例输入'],format:'优先继续丢题目原始附件，不要手工改内容。',where:placement(),action:isFileSession()?'add':'rescan'};
    }
    const need=s?.primaryNeed;
    if(need){
      const corpus=`${need.title||''}\n${need.why||''}\n${need.detail||''}`;let format=text(need.detail);
      if(/verifier|checker|scorer|submit/i.test(corpus))format='提供 checker/verifier/scorer、sample submission 或题面提交格式，任一种即可。';
      else if(/transcript|query|oracle/i.test(corpus))format='CSV/JSON 建议包含 query/step、prediction/success/score，以及 distance/epsilon 或题目预算。';
      else if(/preprocess|resize|normalize|rgb|nchw|nhwc/i.test(corpus))format='提供推理/预处理源码或配置，明确 Resize、颜色通道、Normalize、layout、dtype。';
      return{code:need.code||need.id||'PRIMARY_NEED',title:need.title||'补充当前缺失材料',why:need.why||need.detail||'补齐后自动链会继续。',provide:list(need.accepts),format,where:placement(),action:isFileSession()?'add':'rescan'};
    }
    return{code:'NO_EXPLICIT_GAP',title:'如果还有题面 / checker / 服务端交互文件，继续丢进来',why:'当前附件能自动跑的步骤已经执行完。没有证据时 NewCyber 不会猜参数或伪造最终结果。',provide:['README / 题面附件','checker / verifier / scorer','服务端返回 transcript / query 记录'],format:'保持原始文件即可。',where:placement(),action:isFileSession()?'add':'rescan'};
  }

  function statusInfo(a,s){
    if(isVerified(a,s))return{label:'已验证',cls:'solved'};
    if(effectiveResult(a,s))return{label:'候选结果',cls:'candidate'};
    if(genericNext(a,s)?.code!=='NO_EXPLICIT_GAP')return{label:'缺一项材料',cls:'need'};
    return{label:'分析完成',cls:'done'};
  }

  function emptyHome(){
    return `<div class="cs84-home"><section class="cs84-drop" data-session-drop data-session-open-file tabindex="0" title="点击选择文件，或直接把文件拖进来">
      <div class="cs84-drop-mark">＋</div>
      <span>自动解题</span><h1>把压缩包 / 附件拖进来</h1>
      <p>松手即自动分析：安全展开压缩包、识别题型、跑全部确定性分析、模型推理与 checker 复核。能出结果就直接显示；解不出来会给出可直接丢给其他 AI 的具体交接建议。</p>
      <small>点击卡片也可以选择文件 · ZIP / TAR / TGZ 安全展开 · 默认不执行不可信题目脚本</small>
    </section></div>`;
  }

  function resultCard(a,s){
    const result=effectiveResult(a,s);if(!result)return'';const verified=isVerified(a,s);const display=resultDisplay(a,s);const source=text(result.source||'workspace');
    return `<section class="cs84-result ${verified?'verified':'candidate'}">
      <div class="cs84-result-head"><span>${verified?'已验证结果':'候选结果'}</span><em>${verified?'可以进入提交/复核':'还差题目判定闭环'}</em></div>
      <code>${esc(shortened(display||'已生成候选'))}</code>
      <div class="cs84-result-foot"><small>${esc(source)}</small><button class="button primary" data-cs84-copy-result>复制结果</button></div>
    </section>`;
  }

  function nextCard(a,s){
    const next=genericNext(a,s);if(!next)return'';const provide=list(next.provide);
    const action=next.action==='rescan'
      ?'<button class="button primary" data-action="rescan-workspace">重新分析</button>'
      :'<button class="button primary" data-session-add-files>补充材料</button>';
    const drop=isFileSession()?'<div class="cs84-mini-drop" data-session-add-drop>文件也可以直接拖到这里</div>':'';
    return `<section class="cs84-next">
      <div class="cs84-next-title"><span>下一步只做这件事</span><b>${esc(next.title||'补充材料')}</b></div>
      <p>${esc(next.why||'补齐后继续自动分析。')}</p>
      ${provide.length?`<div class="cs84-next-row"><strong>提供</strong><div>${provide.map((item)=>`<span>${esc(item)}</span>`).join('')}</div></div>`:''}
      ${next.format?`<div class="cs84-next-row"><strong>格式</strong><p>${esc(next.format)}</p></div>`:''}
      <div class="cs84-next-row"><strong>放哪里</strong><p>${esc(next.where||placement())}</p></div>
      <div class="cs84-next-actions">${action}<button class="button ghost" data-cs84-copy-next>复制要求</button><button class="button primary" data-cs84-copy-ai>丢给其他 AI 解</button></div>${drop}
    </section>`;
  }

  function progressRow(a,s){
    const input=currentInput();const archive=Number(input.archiveCount||0);const recovered=Number(a?.recoveredArtifacts?.files||s?.recoveredArtifacts?.files||0);const templates=Number(s?.stats?.templatesRun||0);const findings=Number((a?.findings||[]).length||0);
    const verified=isVerified(a,s);const result=effectiveResult(a,s);
    return `<div class="cs84-progress">
      <span><b>附件</b>${archive?`${archive} 包已展开`:`${s?.stats?.files||input.fileCount||0} 文件`}</span>
      <span><b>自动分析</b>${templates} 项</span>
      <span><b>恢复产物</b>${recovered}</span>
      <span><b>结论</b>${verified?'已验证':result?'有候选':findings?'待闭环':'暂无结果'}</span>
    </div>`;
  }

  function stepToolFor(item){
    if(item.tool&&typeof TOOL_META!=='undefined'&&TOOL_META[item.tool])return item.tool;
    const hay=`${item.title||''} ${item.id||''} ${item.detail||''}`;
    const map=[
      [/模型算术|hidden[- ]?head/i,'ai-model-arithmetic-auto'],
      [/提示词攻击|提示词注入|prompt/i,'ai-prompt-injection-suite'],
      [/supply|供应链/i,'ai-supply-chain-audit'],
      [/onnx|对抗样本/i,'ai-adversarial-batch'],
      [/表格|tabular|candidate/i,'ai-tabular-candidate'],
      [/泄漏|leakage|功耗/i,'ai-leakage-solve'],
      [/pytorch|cuda|运行时/i,'local-torch-inspect']
    ];
    for(const [re,tool] of map){if(re.test(hay)&&typeof TOOL_META!=='undefined'&&TOOL_META[tool])return tool;}
    return null;
  }

  function writeupMarkdown(a,s){
    const ledger=list(s?.solverLedger);const findings=list(a?.findings);const result=effectiveResult(a,s);const verified=isVerified(a,s);
    const L=[];
    L.push(`# ${challengeName()} — WriteUp 素材`,'');
    L.push(`- 状态：${verified?'已验证':result?'有候选':'未闭环'}`);
    L.push(`- 附件：${Number(s?.stats?.files||0)} 文件 / ${Number(s?.stats?.templatesRun||ledger.length)||0} 项自动分析`,'');
    if(result){L.push('## 结果',`- ${verified?'VERIFIED':'CANDIDATE'}: ${result.value||result.display||''}`,`- 产出链路：${text(result.source||'workspace')}`,'');}
    L.push('## 分析过程');
    for(const [i,item] of ledger.entries()){
      L.push(`### ${i+1}. ${item.title||item.id||'步骤'} [${String(item.status||'ran').toUpperCase()}]`);
      if(item.detail)L.push(item.detail);
      if(item.result&&item.result!==item.detail)L.push(`- 输出：${item.result}`);
      if(item.tool)L.push(`- 工具：${item.tool}`);
      L.push('');
    }
    if(findings.length){L.push('## 关键 Finding');for(const f of findings)L.push(`- [${String(f.severity||'info').toUpperCase()}] ${f.title||f.id}${f.file?` (${f.file})`:''}\n  - ${f.evidence||f.detail||''}`);L.push('');}
    const next=genericNext(a,s);
    if(next){L.push('## 下一步',`- ${next.title||''}：${next.why||''}`,next.format?`- 期望格式：${next.format}`:'');}
    return L.join('\n');
  }

  function aiHandoffText(a,s){
    const existing=s?.aiHandoff?.markdown;
    if(existing)return existing;
    const ledger=list(s?.solverLedger);const findings=list(a?.findings);const result=effectiveResult(a,s);const next=genericNext(a,s);
    const L=[`我在用确定性分析工具链解一道 CTF 题，自动分析没有完全闭环，请你基于以下事实继续推理。`,'',
      `## 题目`, `- 名称：${challengeName()}`,`- 文件数：${list(a?.files).length}`,'',
      '## 已经跑过的分析（不要重复）'];
    for(const item of ledger)L.push(`- ${item.title||item.id}：${String(item.status||'ran').toUpperCase()}${item.detail?` · ${String(item.detail).slice(0,300)}`:''}`);
    L.push('','## 当前结果');
    if(result)L.push(`- ${isVerified(a,s)?'VERIFIED':'CANDIDATE'}: ${result.value||result.display||''}`);else L.push('- 尚无候选 Flag');
    if(findings.length){L.push('','## 关键 Finding');for(const f of findings.slice(0,12))L.push(`- [${String(f.severity||'info').toUpperCase()}] ${f.title||f.id}：${String(f.evidence||f.detail||'').slice(0,300)}`);}
    if(next){L.push('','## NewCyber 判断的下一步',`- ${next.title||''}：${next.why||''}`,next.provide?`- 需要提供：${list(next.provide).join(' / ')}`:'');}
    L.push('','## 请你做的事','1. 基于以上事实给出最可能的题型与解法路径，不要从零开始猜。','2. 给出我可以直接复制执行的具体步骤（命令 / 脚本 / 参数）。','3. 如果还缺材料，精确说明只缺什么、去哪里拿。','4. 得到 Flag 时说明验证方式。');
    return L.join('\n');
  }

  function detailPanel(a,s){
    const ledger=list(s?.solverLedger).slice(0,24);const tools=list(s?.toolFallbacks).slice(0,10);const findings=list(a?.findings).slice(0,12);
    const onnx=a?.onnxContestAutopilot;const membership=a?.aiMembershipAutopilot;
    const technical=[
      membership&&membership.status!=='not-detected'?`Membership: ${membership.status}${membership.selection?.signal?` · ${membership.selection.signal}`:''}`:null,
      onnx&&onnx.status!=='not-applicable'?`ONNX: ${onnx.status}${onnx.runs!=null?` · ${onnx.runs} runs`:''}`:null,
      a?.verifierContractAutopilot?.status&&a.verifierContractAutopilot.status!=='not-applicable'?`Verifier: ${a.verifierContractAutopilot.status}`:null
    ].filter(Boolean);
    return `<details class="cs84-details" open><summary><span>分析过程明细</span><small>${ledger.length} 个步骤 · ${findings.length} 个重点 finding</small></summary><div class="cs84-detail-body">
      ${technical.length?`<div class="cs84-tech">${technical.map((item)=>`<span>${esc(item)}</span>`).join('')}</div>`:''}
      ${(()=>{const sim=a?.aiSimAutopilot;if(!sim||sim.status==='not-applicable')return '';
        return `<div class="cs84-findings"><b>i春秋 AI 仿真题 · 命中 ${esc(sim.totalDetected)} 个家族 / 已验证 ${esc(sim.solvedCount)} 个</b>${sim.families.map(f=>`<p><strong>[${esc(f.id)}] ${esc(f.name)}</strong><span>${esc(f.flag||'未解出')}${f.verified?' · 已复刻 verifier 判定确认':''}</span></p>`).join('')}</div>
        <div class="cs84-ledger">${(sim.steps||[]).map((item)=>`<article><i class="${esc(item.status||'done')}"></i><div><b>${esc(item.title)}</b><pre class="cs84-step-detail">${esc(item.detail||'')}</pre></div><em>${esc(String(item.status||'done').toUpperCase())}</em></article>`).join('')}</div>`;})()}
      <div class="cs84-ledger">${ledger.map((item)=>{const tool=stepToolFor(item);
        return `<article><i class="${esc(item.status||'ran')}"></i><div><b>${esc(item.title||item.id||'自动步骤')}</b><pre class="cs84-step-detail">${esc(item.detail||item.result||'（本步骤没有产出细节）')}</pre>${item.result&&item.result!==item.detail?`<pre class="cs84-step-detail cs84-step-output">${esc(item.result)}</pre>`:''}</div><em>${esc(String(item.status||'ran').toUpperCase())}</em>${tool?`<button class="button ghost cs84-step-tool" data-tool="${esc(tool)}" title="在工具箱中打开并深入分析">打开 ${esc(String(tool))}</button>`:''}</article>`;}).join('')||'<p>暂无专项步骤记录。</p>'}</div>
      ${findings.length?`<div class="cs84-findings"><b>重点 Finding</b>${findings.map((item)=>`<p><strong>${esc(item.title||item.id||'Finding')}</strong><span>${esc(item.evidence||item.detail||'')}</span></p>`).join('')}</div>`:''}
      ${tools.length?`<div class="cs84-tools"><b>需要手工复核时再打开</b>${tools.map((item)=>`<button class="button ghost" data-tool="${esc(item.tool)}">${esc(item.title||'专业工具')}</button>`).join('')}</div>`:''}
      <div class="cs84-detail-actions"><button class="button ghost" data-action="export-report">导出完整报告</button><button class="button ghost" data-cs84-copy-wp>复制 WriteUp 素材（Markdown）</button><button class="button primary" data-cs84-copy-ai>复制给其他 AI 继续解</button></div>
    </div></details>`;
  }

  workspaceView=function batch84Workspace(){
    if(!state.workspace)return emptyHome();const a=state.workspace;const s=currentSession();const status=statusInfo(a,s);
    return `<div class="cs84-workspace">
      <header class="cs84-head"><div><span>自动解题</span><h1>${esc(challengeName())}</h1><p>${esc(s?.headline||'当前附件已完成自动分析')}</p></div><em class="${status.cls}">${status.label}</em></header>
      ${resultCard(a,s)}
      ${nextCard(a,s)}
      ${progressRow(a,s)}
      ${detailPanel(a,s)}
    </div>`;
  };
  homeView=function batch84Home(){return state.workspace?workspaceView():emptyHome();};

  shell=function batch84Shell(content){
    const toolTitle=state.tool?((typeof TOOL_META!=='undefined'&&TOOL_META[state.tool]?.title)||state.tool):null;const title=toolTitle||challengeName();
    let primary='';
    if(state.tool&&state.workspace)primary='<button class="button primary" data-session-return>返回结果</button>';
    else if(state.workspace&&isFileSession())primary='<button class="button primary" data-session-add-files>补充材料</button><button class="button ghost" data-session-open-file>新题目</button>';
    else if(state.workspace)primary='<button class="button primary" data-action="rescan-workspace">重新分析</button><button class="button ghost" data-session-open-file>新题目</button>';
    else if(state.tool)primary='';
    const aiNav=(()=>{
      const seen=new Set();const items=[];
      const push=(id,label)=>{if(!id||seen.has(id))return;seen.add(id);const title=String(label||id);items.push(`<button class="cs84-ai-item${state.tool===id?' active':''}" data-tool="${esc(id)}" title="${esc(title)}">${esc(title)}</button>`);};
      for(const row of ((typeof DOMAINS!=='undefined'&&DOMAINS.ai&&DOMAINS.ai.tools)||[]))push(row[0],row[1]);
      for(const [id,meta] of Object.entries(typeof TOOL_META!=='undefined'?TOOL_META:{})){if(meta&&meta.domain==='ai')push(id,meta.title);}
      return items.join('');
    })();
    return `<div class="shell challenge-shell cs84-shell">
      <aside class="sidebar cs84-sidebar"><button class="brand" data-view="home"><span class="brand-mark">N</span><span><strong>NewCyber</strong><small>DROP → RESULT</small></span></button>
        <button class="cs84-solve-nav active" data-session-return title="自动解题"><span>▶</span><div><b>自动解题</b><small>${state.workspace?esc(challengeName()):'丢进去就开始'}</small></div></button>
        <nav class="cs84-advanced cs84-ai-nav"><b class="cs84-ai-heading">AI 安全工具</b>${aiNav}<button data-view="knowledge">离线速查</button></nav>
      </aside>
      <main><header class="topbar cs84-topbar"><div><span>NewCyber</span><b>/</b><strong>${esc(title)}</strong></div><div class="top-actions">${primary}</div></header><section class="content cs84-content">${content}</section></main>
    </div><div id="toast"></div>`;
  };

  document.addEventListener('click',async(event)=>{
    const copyResult=event.target.closest?.('[data-cs84-copy-result]');
    const copyNext=event.target.closest?.('[data-cs84-copy-next]');
    const copyWp=event.target.closest?.('[data-cs84-copy-wp]');
    const copyAi=event.target.closest?.('[data-cs84-copy-ai]');
    if(copyResult){
      const value=resultPayload(state.workspace,currentSession());if(!value)return;
      try{await navigator.clipboard.writeText(value);toast('结果已复制');}catch{toast('复制失败',true);}return;
    }
    if(copyWp){
      try{await navigator.clipboard.writeText(writeupMarkdown(state.workspace,currentSession()));toast('WriteUp 素材已复制（Markdown）');}catch{toast('复制失败',true);}return;
    }
    if(copyAi){
      try{await navigator.clipboard.writeText(aiHandoffText(state.workspace,currentSession()));toast('交接包已复制：粘贴给其他 AI 即可继续');}catch{toast('复制失败',true);}return;
    }
    if(copyNext){
      const next=genericNext(state.workspace,currentSession());if(!next)return;
      const value=[`下一步：${next.title}`,next.why,list(next.provide).length?`提供：${list(next.provide).join(' / ')}`:'',next.format?`格式：${next.format}`:'',next.where?`放哪里：${next.where}`:''].filter(Boolean).join('\n');
      try{await navigator.clipboard.writeText(value);toast('补充要求已复制');}catch{toast('复制失败',true);}
    }
  });

  render();
})();
