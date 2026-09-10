'use strict';

function list(value){return Array.isArray(value)?value:[];}
function text(value){try{return JSON.stringify(value||{}).slice(0,240000);}catch{return String(value||'').slice(0,240000);}}
function has(re,value){return re.test(value);}
function globalVerified(analysis){
  const rows=[analysis?.challengeSession?.flags?.verified,analysis?.flags?.verified];
  return rows.some((items)=>list(items).length>0);
}
function scaState(analysis){return analysis?.scaAutopilot?.result||analysis?.scaAutopilot||null;}

function walkObjects(root,visit,maxNodes=4096){
  const queue=[root];const seen=new Set();let nodes=0;
  while(queue.length&&nodes<maxNodes){
    const value=queue.shift();
    if(!value||typeof value!=='object'||seen.has(value))continue;
    seen.add(value);nodes++;
    if(visit(value)===true)return true;
    if(Array.isArray(value)){for(const item of value)if(item&&typeof item==='object')queue.push(item);continue;}
    for(const child of Object.values(value))if(child&&typeof child==='object')queue.push(child);
  }
  return false;
}
function candidateDescriptor(value){
  if(!value||typeof value!=='object'||!value.candidateId)return'';
  return [value.kind,value.type,value.id,value.candidateId,value.verdict,value.templateId,value.category].filter(Boolean).join(' ');
}
function hasStructuredCandidate(analysis,re){
  return walkObjects({files:analysis?.files,candidates:analysis?.candidates,findings:analysis?.findings},(value)=>Boolean(value.candidateId)&&re.test(candidateDescriptor(value)));
}
function verifierObservationState(analysis,verifierRe){
  let waiting=false,verified=false,captured=false;
  const roots=[analysis?.observationHandoff,analysis?.challengeSession?.observationHandoff];
  for(const root of roots){
    walkObjects(root,(value)=>{
      if(!verifierRe.test(String(value?.verifier||'')))return false;
      const status=String(value?.status||value?.verdict||'').toLowerCase();
      const transitions=list(value?.transitions).map((x)=>String(x).toLowerCase());
      const resultVerified=value?.result?.verified===true||value?.verified===true;
      if(resultVerified||status.includes('verified')||transitions.includes('verified'))verified=true;
      if(status.includes('captured')||transitions.includes('captured'))captured=true;
      if(status.includes('waiting')||status.includes('captured')||transitions.includes('waiting'))waiting=true;
      return false;
    });
  }
  return {waiting,captured,verified};
}

function directionClosure(direction,analysis,context){
  if(globalVerified(analysis))return {stepsToFlag:0,closureStage:'flag-verified',readiness:'closed',blockers:[],nextBestAction:'已存在 Verified flag；停止扩展攻击面，保留证据并复核提交格式。',readyTools:[]};
  const id=direction.id;const blockers=[];let steps=5,stage='search',readiness='searching',next='继续从题面/附件提取该方向的确定性证据。';

  if(id==='privacy-leakage'){
    const sca=scaState(analysis);const status=String(sca?.status||'');const gap=String(sca?.gap?.code||'');
    if(status==='flag-recovered')return {stepsToFlag:0,closureStage:'flag-verified',readiness:'closed',blockers:[],nextBestAction:'SCA 已由 oracle 恢复 flag；复核提交格式。',readyTools:[]};
    if(status==='flag-candidate'){steps=1;stage='candidate-needs-verifier';readiness='verifier-ready';next='把 SCA flag candidate 送 Transformer/oracle 或 candidate-bound replay 完成最后验证。';}
    else if(status==='decoded-no-flag'){steps=2;stage='recovered-sequence-no-flag';readiness='solver-active';next='优先检查 calibrated/full-probe 与 unknown-prefix oracle，重新恢复 token sequence 并搜索 flag。';}
    else if(status==='gap'){
      steps=2;stage='solver-gap';readiness='blocked';blockers.push(gap||'SCA_GAP');next=`先关闭 SCA ${gap||'solver gap'}，不要切换到低质量 raw 猜测。`;
    }else if(has(/membership|model[_ -]?extraction|inversion|side[_ -]?channel|sca|power trace/i,context)){steps=3;stage='evidence-ready';readiness='analyzer-ready';next='运行隐私/SCA 本地恢复器，优先产出可绑定 verifier 的 candidate。';}
  }else if(id==='prompt-llm-security'){
    const observation=verifierObservationState(analysis,/^ai-transform-replay-verify$/i);
    const candidate=hasStructuredCandidate(analysis,/(?:transform-exfiltration|encoded-secret|prompt)/i)||observation.waiting||observation.captured||observation.verified;
    if(observation.verified){steps=1;stage='verified-observation-needs-flag';readiness='verifier-ready';next='从已验证响应执行 ASCII/hex/base64/URL/Unicode 解码并提取最终 flag。';}
    else if(candidate&&observation.waiting){steps=1;stage='candidate-awaiting-observation';readiness='remote-replay-ready';blockers.push('REAL_TARGET_OBSERVATION');next='使用推荐 Prompt replay contract 获取真实响应，回填 observation 后自动 verifier。';}
    else if(candidate){steps=2;stage='candidate-needs-replay';readiness='remote-replay-ready';blockers.push('REAL_TARGET_OBSERVATION');next='对 candidate 生成最小远程 replay，保存原始响应并立即回本地验证。';}
    else if(has(/prompt|system prompt|summari|rag|retriev|agent|tool_call/i,context)){steps=3;stage='probe-ready';readiness='remote-replay-ready';blockers.push('REAL_TARGET_RESPONSE');next='按题面排序 Prompt probe，先跑高信息增益的最小集合，命中后停止扩展。';}
  }else if(id==='adversarial-example'){
    const candidate=hasStructuredCandidate(analysis,/(?:adversarial|perturb|attack-sample)/i);
    const runtime=has(/runtime[^]{0,120}(?:verified|observation)|prediction[^]{0,100}changed/i,context);
    if(candidate&&runtime){steps=1;stage='candidate-needs-checker';readiness='verifier-ready';blockers.push('TARGET_CHECKER_CONFIRMATION');next='用与 checker 相同 preprocessing 复算 norm，再做一次最小目标查询确认并提取 flag。';}
    else if(candidate){steps=2;stage='candidate-needs-runtime';readiness='runtime-ready';blockers.push('MODEL_OR_TARGET_OBSERVATION');next='对 adversarial candidate 跑本地/靶机预测，严格验证 epsilon、clip、label goal。';}
    else if(has(/adversarial|fgsm|pgd|cifar|epsilon|linf|对抗样本/i,context)){steps=3;stage='attack-generation-ready';readiness='analyzer-ready';next='先固定 preprocessing 与 epsilon，再生成候选；不要先盲扫攻击算法。';}
  }else if(id==='backdoor-poisoning'){
    const trigger=hasStructuredCandidate(analysis,/(?:backdoor|trigger|patch|poison)/i);
    const triad=has(/clean[^]{0,200}trigger[^]{0,200}control|controlRate|control specificity/i,context);
    const verified=has(/backdoor[^]{0,200}verified|runtime closure[^]{0,200}verified/i,context);
    if(verified){steps=1;stage='behavior-verified-needs-flag';readiness='verifier-ready';next='利用已验证 trigger/target 行为进入 checker/提交链，提取最终 flag。';}
    else if(trigger&&triad){steps=1;stage='trigger-ready-for-verifier';readiness='verifier-ready';next='运行 clean/trigger/control verifier；ASR 高且 control rate 低时立即闭环。';}
    else if(trigger){steps=2;stage='trigger-needs-controls';readiness='runtime-ready';blockers.push('CLEAN_TRIGGER_CONTROL_OBSERVATIONS');next='构造 clean / trigger / control 三组最小观测，避免只看高 ASR 误报。';}
    else if(has(/backdoor|poison|trigger|patch|投毒|后门/i,context)){steps=3;stage='trigger-search';readiness='analyzer-ready';next='从数据/模型差异先定位 trigger candidate，再做 runtime 验证。';}
  }else if(id==='infra-supply-chain'){
    const sideEffectCandidate=hasStructuredCandidate(analysis,/(?:torchscript|file-side-effect|pickle|loader|supply)/i);
    const observation=verifierObservationState(analysis,/(?:torchscript|side-effect)/i);
    const sideEffect=sideEffectCandidate||has(/torchscript[^]{0,180}side.effect|file.side.effect|pickle[^]{0,120}(?:global|reduce)|unsafe[^]{0,100}load/i,context);
    if(observation.verified){steps=1;stage='side-effect-observed';readiness='verifier-ready';next='把已验证 side effect 与题目 checker/flag 路径绑定，提取结果而不是继续做泛化 SCA。';}
    else if(sideEffect){steps=2;stage='exploit-chain-candidate';readiness='observation-ready';blockers.push('CONTROLLED_OBSERVATION');next='生成最小受控 observation contract，验证 loader→side-effect 链，不执行未知模型。';}
    else if(has(/pickle|torch|jit|safetensors|onnx|huggingface|mlflow|ray|gradio|供应链/i,context)){steps=3;stage='static-evidence';readiness='analyzer-ready';next='先把静态发现收敛为可验证 loader/dependency chain，再进入 observation verifier。';}
  }

  if(direction.score<=0&&steps===5){stage='background';readiness='background';next='当前无直接证据，保留后台候选但不占用比赛时间。';}
  const readyTools=steps<=3?list(direction.localTools).slice(0,5):[];
  return {stepsToFlag:steps,closureStage:stage,readiness,blockers,nextBestAction:next,readyTools};
}

function buildFlagClosureScheduler(analysis={},autopilot=analysis.aiCompetitionAutopilot||{}){
  const context=text({files:analysis.files,findings:analysis.findings,candidates:analysis.candidates,scaAutopilot:analysis.scaAutopilot,observationHandoff:analysis.observationHandoff,challengeSession:analysis.challengeSession,autoSolve:analysis.autoSolve});
  const rows=list(autopilot.directions).map((direction)=>{
    const closure=directionClosure(direction,analysis,context);
    const evidenceScore=Number(direction.score)||0;
    // One fewer step to Verified must always dominate keyword/evidence tie-breakers.
    const priority=(6-closure.stepsToFlag)*100+Math.min(29,evidenceScore)+(closure.readiness==='verifier-ready'?15:closure.readiness==='remote-replay-ready'?8:0);
    return {...direction,...closure,priority};
  }).sort((a,b)=>a.stepsToFlag-b.stepsToFlag||b.priority-a.priority||b.score-a.score||a.id.localeCompare(b.id));
  const closed=globalVerified(analysis);
  return {
    schema:'newcyber.ai-flag-closure-scheduler.v1',version:55,goal:'minimum-steps-to-verified-flag',closed,
    primaryDirection:closed?null:rows[0]?.id||null,
    directions:rows,
    minStepsToFlag:closed?0:(rows[0]?.stepsToFlag??5),
    nextBestAction:closed?'Verified flag 已存在；停止攻击扩展并复核提交。':rows[0]?.nextBestAction||'继续收集确定性证据。',
    blockers:closed?[]:list(rows[0]?.blockers),
    policy:{optimizeFor:'flag-closure-distance',preserveAllFiveDirections:true,remoteExecution:'authorization-required',candidateEvidence:'structured-only'}
  };
}

module.exports={globalVerified,walkObjects,candidateDescriptor,hasStructuredCandidate,verifierObservationState,directionClosure,buildFlagClosureScheduler};
