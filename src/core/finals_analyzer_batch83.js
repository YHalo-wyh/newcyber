'use strict';

const base=require('./finals_analyzer_batch82');
const {analyzeMembershipBundle}=require('./ai_membership_bundle_autopilot');
const {buildChallengeSession}=require('./challenge_session_batch83');

function upsertCheck(analysis,check){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);
  if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);
}
function mergeFindings(analysis,findings){
  analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));
  for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const files=await base.readCandidateFiles(rootPath,analysis);
  const membership=analyzeMembershipBundle(files,{targetFpr:0.1});
  analysis.aiMembershipAutopilot=membership;
  if(membership.status!=='not-detected'){
    mergeFindings(analysis,membership.findings);
    upsertCheck(analysis,{
      id:'ai-membership-bundle-autopilot',title:'Membership calibration/query 自动关联与候选生成',
      hits:Number(membership.summary?.memberCandidates)||0,
      detail:membership.status==='candidate'
        ?`candidate=${membership.summary?.memberCandidates||0}; signal=${membership.selection?.signal||'n/a'}; auc=${Number(membership.selection?.auc||0).toFixed(3)}`
        :`${membership.status}: ${membership.reason||membership.next||'等待材料'}`
    });
  }
  analysis.challengeSession=buildChallengeSession(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,83);
  return analysis;
}

function batch83Section(analysis){
  const auto=analysis.aiMembershipAutopilot;if(!auto||auto.status==='not-detected')return'';
  const lines=['## AI Batch83 · Membership Drop-to-Result',''];
  lines.push(`- 状态：${auto.status}`);
  if(auto.selection)lines.push(`- 自动配对：${auto.selection.calibration?.path||'?'} → ${auto.selection.query?.path||'?'} · signal=${auto.selection.signal} · AUC=${Number(auto.selection.auc||0).toFixed(4)} · TPR@FPR=${Number(auto.selection.tpr||0).toFixed(4)}`);
  if(auto.result)lines.push(`- Member 候选：${auto.result.memberIds?.length||0} 个 · source=${auto.result.source||'workspace'}`);
  if(auto.next||auto.reason)lines.push(`- 下一步：${auto.next||auto.reason}`);
  lines.push('','> Membership 阈值只允许从带真值 calibration/reference 数据确定；challenge/query 真值不会参与调参。候选必须经过题目 submission/checker/scorer 才能升级 solved。');
  return lines.join('\n');
}
function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=batch83Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch83Section};
