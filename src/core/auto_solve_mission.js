'use strict';

const STAGE_IDS=Object.freeze(['ingest','classify','deterministic','deep-solve','verify']);

function flagValue(item){return typeof item==='string'?item:String(item?.value||item?.flag||'');}
function isVerifiedFlag(item){return Boolean(item&&typeof item==='object'&&(item.verified===true||String(item.confidence||'').toLowerCase()==='verified'));}

function uniqueFlags(analysis={}){
  const seen=new Set();const out=[];
  const sources=[...(analysis.candidates?.flags||[]),...(analysis.autopilot?.flags||[])];
  for(const raw of sources){
    const value=flagValue(raw);if(!value||seen.has(value))continue;seen.add(value);
    out.push(typeof raw==='string'?{value,confidence:'candidate',file:'workspace'}:{...raw,value});
  }
  return out;
}

function collectGaps(analysis={}){
  const gaps=[];
  const sca=analysis.scaAutopilot?.result;
  if(sca?.status==='gap'&&sca.gap?.code)gaps.push({source:'Power SCA / Transformer',code:String(sca.gap.code),detail:String(sca.gap.detail||''),tool:'ai-sca-autopilot'});
  if(analysis.scaAutopilot?.status==='error')gaps.push({source:'Power SCA / Transformer',code:'SCA_AUTOPILOT_ERROR',detail:String(analysis.scaAutopilot.error||'侧信道自动链执行失败'),tool:'ai-sca-autopilot'});

  const arithmetic=analysis.modelArithmeticAuto?.best?.result;
  if(arithmetic){
    const status=String(arithmetic.status||'');
    if(/(?:gap|incomplete|missing)/.test(status))gaps.push({source:'Model Arithmetic',code:status.toUpperCase().replace(/-/g,'_'),detail:`模型算术自动链状态：${status}`,tool:'ai-model-arithmetic-auto'});
    else if(arithmetic.solver?.status==='unique'&&!arithmetic.flag)gaps.push({source:'Model Arithmetic',code:'FLAG_DERIVATION_GAP',detail:'Hidden secret 已唯一恢复，但还没有形成可严格复现的 Flag 派生。',tool:'ai-model-arithmetic-auto'});
  }

  return gaps;
}

function gapAction(gap){
  const code=String(gap?.code||'');
  if(/RUNTIME|ORACLE_ARTIFACT|SAFETENSORS|MODEL/.test(code))return {kind:'tool',tool:'ai-local-model-runtime',title:'补齐本地模型运行环境',detail:gap?.detail||code};
  if(/PROBE|TRACE|PROFILE|TOKEN|SCA/.test(code))return {kind:'tool',tool:'ai-sca-autopilot',title:'继续模型侧信道自动链',detail:gap?.detail||code};
  if(/MODULAR|SOLVER|FEATURE|DERIVATION|ARITHMETIC/.test(code))return {kind:'tool',tool:'ai-model-arithmetic-auto',title:'继续模型算术自动恢复',detail:gap?.detail||code};
  return {kind:'rerun',title:'重新执行自动求解',detail:gap?.detail||code};
}

function stage(id,title,status,detail){return {id,title,status,detail};}

function buildStages({analysis,track,checks,flags,verified,gaps}){
  const fileCount=(analysis.files||[]).length;
  const solverApplicable=Boolean(analysis.modelArithmeticAuto?.attempts?.length)||(analysis.scaAutopilot&&analysis.scaAutopilot.status!=='not-applicable'&&analysis.scaAutopilot.status!=='disabled');
  const high=(analysis.findings||[]).filter((x)=>x.severity==='high').length;
  const artifactCount=analysis.autopilot?.artifacts?.length||0;
  return [
    stage('ingest','读取赛题',fileCount>0?'ok':'gap',fileCount>0?`已盘点 ${fileCount} 个工件`:'没有可分析工件'),
    stage('classify','判断方向',track?.score>0?'ok':'partial',track?.score>0?`${track.title} · score ${track.score}`:'方向证据不足，继续使用通用分析'),
    stage('deterministic','自动分析',checks.length?'ok':'partial',checks.length?`已运行 ${checks.length} 类确定性检查`:'当前附件没有命中专项自动检查'),
    stage('deep-solve','自动求解',verified.length?'ok':gaps.length?'gap':solverApplicable||flags.length||artifactCount||high?'partial':'pending',verified.length?'已有严格验证结果':gaps.length?`${gaps[0].code} · ${gaps[0].source}`:solverApplicable?'专项 solver 已运行，尚未形成最终结果':flags.length?'已找到候选结果':artifactCount?`恢复 ${artifactCount} 个可继续分析产物`:high?`存在 ${high} 个高价值线索`:'暂无可继续的自动 solver'),
    stage('verify','验证结果',verified.length?'ok':flags.length?'partial':'pending',verified.length?`${verified.length} 个结果通过严格验证`:flags.length?`${flags.length} 个 Flag 候选仍需验证`:'尚无可提交 Flag')
  ];
}

function buildFacts(analysis,track,flags,verified,gaps){
  const facts=[];
  if(track?.score>0)facts.push({label:'方向',value:track.title,detail:`score ${track.score}`});
  const checks=analysis.autopilot?.automaticChecks||[];
  if(checks.length)facts.push({label:'自动检查',value:`${checks.length} 类`,detail:`${checks.reduce((sum,x)=>sum+(Number(x.hits)||0),0)} 次命中`});
  if(verified.length)facts.push({label:'已验证结果',value:verified[0].value,detail:verified[0].source||verified[0].file||'verified'});
  else if(flags.length)facts.push({label:'Flag 候选',value:flags[0].value,detail:flags[0].file||'workspace'});
  const artifacts=analysis.autopilot?.artifacts||[];
  if(artifacts.length)facts.push({label:'恢复产物',value:`${artifacts.length} 个`,detail:artifacts[0].kind||artifacts[0].name||'artifact'});
  const high=(analysis.findings||[]).filter((x)=>x.severity==='high');
  if(high.length)facts.push({label:'高危线索',value:`${high.length} 个`,detail:high[0].title||high[0].id||'finding'});
  if(gaps.length)facts.push({label:'当前卡点',value:gaps[0].code,detail:gaps[0].detail});
  return facts.slice(0,5);
}

function primaryAction({analysis,verified,flags,gaps}){
  if(verified.length)return {kind:'copy-flag',title:'复制已验证 Flag',detail:verified[0].value,value:verified[0].value};
  if(flags.length)return {kind:'verify-flag',title:'先验证这个 Flag 候选',detail:`${flags[0].value} · ${flags[0].file||'workspace'}`,value:flags[0].value};
  if(gaps.length)return gapAction(gaps[0]);
  const first=(analysis.autopilot?.actions||[])[0];
  if(first?.tool)return {kind:'tool',tool:first.tool,title:first.title||'打开对应工具',detail:first.detail||''};
  if(first)return {kind:'rerun',title:first.title||'继续自动求解',detail:first.detail||''};
  return {kind:'rerun',title:'重新自动求解',detail:'当前没有高置信终点；重新扫描会继续使用最新 deterministic solver。'};
}

function buildAutoSolveMission(analysis={}){
  const flags=uniqueFlags(analysis);
  const verified=flags.filter(isVerifiedFlag);
  const gaps=collectGaps(analysis);
  const track=analysis.autopilot?.track||null;
  const checks=analysis.autopilot?.automaticChecks||[];
  const stages=buildStages({analysis,track,checks,flags,verified,gaps});
  let status='review';
  if(verified.length)status='solved';
  else if(flags.length)status='candidate';
  else if(gaps.length)status='blocked';
  else if(!(analysis.files||[]).length)status='empty';

  const completed=stages.filter((item)=>item.status==='ok').length;
  const headline={
    solved:'已自动解出并严格验证结果',
    candidate:'已经找到 Flag 候选，还差最后验证',
    blocked:`自动求解停在 ${gaps[0]?.code||'能力缺口'}`,
    empty:'还没有赛题工件',
    review:'自动分析已完成，暂未形成可直接提交结果'
  }[status];
  const explanation={
    solved:'你不需要再把各工具结果手工拼起来；下面的 Flag 已经由确定性证据链提升为 verified。',
    candidate:'NewCyber 已经把候选从附件里提出来，但当前证据还不足以把它当成可提交结果。',
    blocked:'前面的自动阶段已经完成。现在只显示第一个真正阻塞完整求解的 gap，补齐后重新自动求解即可。',
    empty:'选择完整赛题目录后，NewCyber 会自动扫描、路由、递归恢复并调用已支持的 solver。',
    review:'能自动完成的步骤已经跑过。NewCyber 会把分散证据合并，只保留一个主结论和一个下一步。'
  }[status];

  return {
    schema:'newcyber.auto-solve-mission.v1',
    version:1,
    generatedAt:new Date().toISOString(),
    status,
    headline,
    explanation,
    track,
    result:verified[0]||flags[0]||null,
    verifiedFlags:verified,
    flagCandidates:flags,
    gaps,
    facts:buildFacts(analysis,track,flags,verified,gaps),
    stages,
    progress:{completed,total:STAGE_IDS.length},
    primaryAction:primaryAction({analysis,verified,flags,gaps}),
    automaticChecks:checks,
    notes:[
      'Auto Solve 只整合和编排确定性结果，不会把 candidate 自动升级为 verified。',
      '后续专项 solver 应统一把 verified result / explicit gap 写回该 Mission，而不是要求使用者手工拼接多个工具页面。'
    ]
  };
}

module.exports={STAGE_IDS,uniqueFlags,collectGaps,buildAutoSolveMission};