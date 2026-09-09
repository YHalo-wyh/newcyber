'use strict';

const path=require('path');
const base=require('./finals_analyzer_batch31');
const {runScaAutopilotPaths}=require('./sca_autopilot_batch42');

const RELEVANT_EXT=new Set(['.npy','.onnx','.safetensors','.py','.pyw','.json','.txt','.md','.toml','.yaml','.yml']);
const MAX_SCA_FILES=256;

function inside(rootPath,relativePath){
  const root=path.resolve(rootPath);const target=path.resolve(root,relativePath);
  if(target!==root&&!target.startsWith(root+path.sep))throw new Error('SCA autopilot 文件超出赛题目录');
  return target;
}

function strongScaEvidence(files=[]){
  const names=files.map((file)=>String(file.path||file.name||'').toLowerCase());
  if(names.some((name)=>/(?:^|\/)(?:newcyber_sca|sca[_-]recipe)\.json$/.test(name)))return true;
  const hasTrace=names.some((name)=>/\.(?:npy)$/.test(name)&&/(profil|target|attack|trace|power|leak)/.test(name));
  const hasProbe=names.some((name)=>/\.npy$/.test(name)&&/(probe|lm[_-]?head|decoder.*weight)/.test(name));
  const hasSource=names.some((name)=>/\.(?:py|pyw|txt|md)$/.test(name)&&/(sca|side[_ -]?channel|power|hidden|probe)/.test(name));
  return hasTrace&&hasProbe&&hasSource;
}

function workspaceScaPaths(rootPath,files=[]){
  return files.filter((file)=>RELEVANT_EXT.has(String(file.extension||path.extname(file.path||'')).toLowerCase())&&Number(file.size||0)>=0)
    .slice(0,MAX_SCA_FILES).map((file)=>inside(rootPath,file.path));
}

async function analyzeWorkspaceSca(rootPath,analysis,options={}){
  if(options.enabled===false)return {schema:'newcyber.workspace-sca-autopilot.v1',enabled:false,status:'disabled',result:null};
  if(!strongScaEvidence(analysis.files||[]))return {schema:'newcyber.workspace-sca-autopilot.v1',enabled:true,status:'not-applicable',result:null};
  try{
    const result=await runScaAutopilotPaths(workspaceScaPaths(rootPath,analysis.files||[]),options);
    return {schema:'newcyber.workspace-sca-autopilot.v1',enabled:true,status:result.status,result};
  }catch(error){
    return {schema:'newcyber.workspace-sca-autopilot.v1',enabled:true,status:'error',error:error?.message||String(error),result:null};
  }
}

function addCheck(analysis,routed){
  analysis.autopilot||={automaticChecks:[],actions:[],summary:{}};
  analysis.autopilot.automaticChecks||=[];
  if(!analysis.autopilot.automaticChecks.some((item)=>item.id==='sca-autopilot'))analysis.autopilot.automaticChecks.push({
    id:'sca-autopilot',title:'功耗侧信道 → Transformer 自动恢复',hits:routed.result?.stages?.filter((item)=>item.status==='ok').length||1
  });
}

function promoteWorkspaceScaResult(analysis){
  const routed=analysis.scaAutopilot;
  if(!routed||routed.status==='not-applicable'||routed.status==='disabled')return;
  addCheck(analysis,routed);
  const result=routed.result;
  analysis.autopilot.actions||=[];
  analysis.autopilot.actions=analysis.autopilot.actions.filter((item)=>!String(item.id||'').startsWith('sca-autopilot'));

  if(result?.status==='flag-recovered'&&result.flag){
    analysis.candidates||={flags:[],urls:[],ips:[]};analysis.candidates.flags||=[];
    if(!analysis.candidates.flags.some((item)=>item.value===result.flag))analysis.candidates.flags.unshift({
      value:result.flag,file:result.discovery?.manifestFile?.fileName||'SCA bundle',source:'sca-autopilot',confidence:'verified',
      evidence:`trace/profile rows=${result.profile?.rows||0} · ${result.profile?.method||'ridge'} · probe candidates verified by Transformer oracle · oracle=${result.oracle?.status||'flag-recovered'}`
    });
    analysis.insights||=[];
    if(!analysis.insights.some((item)=>item.kind==='sca-autopilot-flag'&&item.flag===result.flag))analysis.insights.unshift({
      kind:'sca-autopilot-flag',title:'功耗侧信道链已由 Transformer Oracle 复核并恢复 Flag',flag:result.flag,
      evidence:`hidden=${result.profile?.hiddenDim||'?'} · leakage=${result.profile?.leakageDim||'?'} · target rows=${result.target?.rows||'?'} · ${result.oracle?.cacheUsed?'KV cache':'full replay'}`
    });
    analysis.autopilot.actions.unshift({id:'sca-autopilot-flag',priority:125,level:'win',title:'Flag 已自动恢复：Power SCA / Transformer',detail:`${result.flag} · leakage→hidden→probe→oracle verified`});
  }else if(result?.status==='flag-candidate'&&result.flagCandidate){
    analysis.candidates||={flags:[],urls:[],ips:[]};analysis.candidates.flags||=[];
    if(!analysis.candidates.flags.some((item)=>item.value===result.flagCandidate))analysis.candidates.flags.unshift({
      value:result.flagCandidate,file:result.discovery?.manifestFile?.fileName||'SCA bundle',source:'sca-free-probe',confidence:'candidate',
      evidence:`grouped leakage ${result.layout?.groupsPerToken||'?'} rows/token × hidden slice ${result.layout?.hiddenPerGroup||'?'} · free-probe direct decode · NOT Transformer-oracle verified`
    });
    analysis.insights||=[];
    if(!analysis.insights.some((item)=>item.kind==='sca-autopilot-candidate'&&item.flag===result.flagCandidate))analysis.insights.unshift({
      kind:'sca-autopilot-candidate',title:'功耗侧信道 free-probe 恢复 Flag candidate，仍需上下文/Oracle 复核',flag:result.flagCandidate,
      evidence:`hidden=${result.profile?.hiddenDim||'?'} · groups=${result.layout?.groupsPerToken||'?'} · target tokens=${result.target?.rows||'?'} · candidate-only`
    });
    analysis.autopilot.actions.unshift({id:'sca-autopilot-candidate',priority:96,level:'hot',title:'Flag candidate 已自动恢复：Power SCA free-probe',detail:`${result.flagCandidate} · 未经 Transformer oracle 复核，不提升为 verified`});
  }else if(result?.status==='gap'&&result.gap){
    analysis.autopilot.actions.unshift({id:'sca-autopilot-gap',priority:88,level:'normal',title:`模型侧信道自动链停在 ${result.gap.code}`,detail:result.gap.detail});
  }else if(routed.status==='error'){
    analysis.autopilot.actions.unshift({id:'sca-autopilot-error',priority:75,level:'normal',title:'模型侧信道自动链执行失败',detail:routed.error||'unknown error'});
  }else if(result){
    analysis.autopilot.actions.unshift({id:'sca-autopilot-review',priority:84,level:'hot',title:'侧信道 token 已恢复，Oracle 尚未形成 Flag',detail:`status=${result.status} · target=${result.target?.rows||0} rows`});
  }
  analysis.autopilot.actions.sort((a,b)=>(b.priority||0)-(a.priority||0));analysis.autopilot.actions=analysis.autopilot.actions.slice(0,6);
  analysis.autopilot.summary||={};
  analysis.autopilot.summary.scaAutopilotStages=result?.stages?.filter((item)=>item.status==='ok').length||0;
  analysis.autopilot.summary.scaAutopilotFlags=result?.flag?1:0;
  analysis.autopilot.summary.flagCandidates=analysis.candidates?.flags?.length||0;
  analysis.autopilot.summary.automaticCheckKinds=analysis.autopilot.automaticChecks.length;
  analysis.autopilot.summary.automaticCheckHits=analysis.autopilot.automaticChecks.reduce((sum,item)=>sum+(Number(item.hits)||0),0);
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  analysis.scaAutopilot=await analyzeWorkspaceSca(rootPath,analysis,options.scaAutopilot||{});
  promoteWorkspaceScaResult(analysis);
  const result=analysis.scaAutopilot?.result;
  analysis.recommendations=(analysis.recommendations||[]).filter((item)=>!/^模型侧信道：/.test(String(item)));
  if(result?.status==='flag-recovered'){
    analysis.recommendations.unshift(`模型侧信道：profiling → leakage inverse → probe → Transformer oracle 已自动恢复并复核 Flag ${result.flag}。`);
  }else if(result?.status==='flag-candidate'&&result.flagCandidate){
    analysis.recommendations.unshift(`模型侧信道：grouped leakage → hidden reassembly → free-probe 已恢复 candidate ${result.flagCandidate}；当前缺少可复核 prompt/context，不提升为 verified。`);
  }else if(result?.status==='gap'){
    analysis.recommendations.unshift(`模型侧信道：自动链停在 ${result.gap?.code||'GAP'}；${result.gap?.detail||'查看阶段证据。'}`);
  }
  analysis.version=Math.max(Number(analysis.version)||1,35);
  return analysis;
}

function buildBatch35Section(analysis){
  const routed=analysis.scaAutopilot;if(!routed||routed.status==='not-applicable'||routed.status==='disabled')return'';
  const result=routed.result;const lines=['## Batch 35/42 · Power SCA / Transformer Autopilot',''];
  if(!result){lines.push(`- ${routed.status}: ${routed.error||'no result'}`);return lines.join('\n');}
  lines.push(`- 状态：${result.status}${result.flag?` · Flag=\`${result.flag}\``:result.flagCandidate?` · Candidate=\`${result.flagCandidate}\``:''}`);
  for(const item of result.stages||[])lines.push(`  - ${item.id}: ${item.status} · ${item.detail||''}`);
  if(result.gap)lines.push(`- Gap：${result.gap.code} · ${result.gap.detail}`);
  if(result.profile?.status==='ok')lines.push(`- Profile：${result.profile.method} · rows=${result.profile.rows} · hidden=${result.profile.hiddenDim} · leakage=${result.profile.leakageDim} · R²=${result.profile.r2??'n/a'}`);
  if(result.layout?.groupsPerToken)lines.push(`- Group layout：rows/token=${result.layout.groupsPerToken} · hidden/group=${result.layout.hiddenPerGroup} · row feature=${result.layout.rowFeatureDim}`);
  lines.push('','> Flag 只有在功耗候选通过本地 Transformer oracle 复核后才会提升为 verified；未知 prompt 的 free-probe 结果只保留为 candidate。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=buildBatch35Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,strongScaEvidence,analyzeWorkspaceSca,promoteWorkspaceScaResult,buildBatch35Section};
