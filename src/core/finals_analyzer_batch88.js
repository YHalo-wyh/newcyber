'use strict';

const base=require('./finals_analyzer_batch87');
const {runVerifierContractAutopilot}=require('./challenge_verifier_contract_v3');
const {buildChallengeSession}=require('./challenge_session_batch88');

function upsertCheck(analysis,check){analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);}
function mergeFindings(analysis,findings){analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  let verifier;
  try{verifier=await runVerifierContractAutopilot(rootPath,analysis,options.verifier||{});}
  catch(error){verifier={schema:'newcyber.challenge-verifier-contract.v3',status:'gap',result:null,summary:{sourceFiles:0,contracts:0,exact:0,hash:0,format:0,candidates:0,extraCandidates:0,verifiedMatches:0,errors:1},contracts:[],verifiedMatches:[],findings:[],errors:[{error:String(error?.message||error).slice(0,500)}],next:'静态 verifier 结构化闭环阶段异常，已降级为 GAP。',notes:[]};}
  analysis.verifierContractAutopilot=verifier;
  mergeFindings(analysis,verifier.findings);
  if(verifier.status!=='not-applicable')upsertCheck(analysis,{id:'static-verifier-contract-v3',title:'静态 checker/verifier · 结构化候选闭环',hits:Number(verifier.summary?.verifiedMatches)||0,detail:`status=${verifier.status}; contracts=${Number(verifier.summary?.contracts)||0}; extraCandidates=${Number(verifier.summary?.extraCandidates??verifier.extraCandidates)||0}`});
  analysis.challengeSession=buildChallengeSession(analysis);
  analysis.version=Math.max(Number(analysis.version)||1,88);
  return analysis;
}

function batch88Section(analysis){
  const auto=analysis.verifierContractAutopilot;if(!auto||auto.status==='not-applicable')return'';
  const lines=['## Batch88 · Structured Verifier Closure','',`- 状态：${auto.status}`,
    `- contracts=${Number(auto.summary?.contracts)||0} · extraCandidates=${Number(auto.summary?.extraCandidates??auto.extraCandidates)||0} · verifiedMatches=${Number(auto.summary?.verifiedMatches)||0}`];
  if(auto.result)lines.push(`- RESULT：${auto.result.kind||'answer'} · verified=${Boolean(auto.result.verified)} · source=${auto.result.source||'static-verifier'}`);
  if(auto.next)lines.push(`- 下一步：${auto.next}`);
  lines.push('','> Membership / Universal Trigger / Model Fingerprint / Submission 等自动生成结果会重新进入静态 checker/verifier。结构化 payload 保留原始换行与尾部字节语义，不执行题目源码，也不会把未命中 contract 的候选升级为 solved。');
  return lines.join('\n');
}
function buildMarkdownReport(analysis,notes=''){const report=base.buildMarkdownReport(analysis,notes);const section=batch88Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch88Section};
