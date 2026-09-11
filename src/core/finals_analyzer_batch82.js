'use strict';

const base=require('./finals_analyzer_batch81');
const {analyzeBlackboxAdversarialTranscript}=require('./ai_blackbox_adversarial');
const {analyzeMcpSupplyChain}=require('./ai_mcp_supply_chain');
const {runStage1WorldwideHoldoutBatch82}=require('./ai_stage1_worldwide_holdout_batch82');
const {runRandom10Gate}=require('./ai_stage1_random10_gate');

function upsertCheck(analysis,check){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);
  if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);
}
function looksBlackboxTranscript(text){
  return/(?:query|iteration|step)/i.test(text)&&/(?:prediction|predicted_label|target_score|success|accepted|confidence|logit)/i.test(text)&&/(?:linf|l_inf|l2|distance|epsilon|eps|perturb)/i.test(text);
}
function looksMcpSupplyChain(text,path=''){
  return/(?:mcp|model context protocol)/i.test(`${path}\n${text}`)&&/(?:signature|signed|digest|sha256|provenance|attestation|allowlist|registry|revision|latest)/i.test(text);
}
function aggregate(results,schema){return results.length?{schema,files:results.length,results,findings:results.flatMap((x)=>x.result.findings||[])}:null;}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const files=await base.readCandidateFiles(rootPath,analysis);
  const blackbox=[];const mcp=[];
  for(const file of files){
    if(looksBlackboxTranscript(file.text)){
      try{const result=analyzeBlackboxAdversarialTranscript(file.text);if(result.status!=='gap')blackbox.push({file:file.path,result});}catch{}
    }
    if(looksMcpSupplyChain(file.text,file.path)){
      try{const result=analyzeMcpSupplyChain(file.text);mcp.push({file:file.path,result});}catch{}
    }
  }
  analysis.aiBlackboxAdversarial=aggregate(blackbox,'newcyber.batch82-blackbox-adversarial-aggregate.v1');
  analysis.aiMcpSupplyChain=aggregate(mcp,'newcyber.batch82-mcp-supply-chain-aggregate.v1');
  if(analysis.aiBlackboxAdversarial)upsertCheck(analysis,{id:'blackbox-adversarial-transcript',title:'黑盒对抗样本 Transcript 复算',hits:analysis.aiBlackboxAdversarial.findings.length,detail:`files=${blackbox.length}; candidates=${blackbox.filter((x)=>x.result.status==='candidate').length}`});
  if(analysis.aiMcpSupplyChain)upsertCheck(analysis,{id:'mcp-supply-chain-manifest',title:'MCP / Agent 供应链 Manifest 审计',hits:analysis.aiMcpSupplyChain.findings.length,detail:`files=${mcp.length}; admission-ready=${mcp.filter((x)=>x.result.admissionReady).length}`});

  const holdout=runStage1WorldwideHoldoutBatch82();
  const random10=runRandom10Gate({benchmark:holdout});
  analysis.aiStage1WorldwideHoldout={schema:holdout.schema,summary:holdout.summary,byDirection:holdout.byDirection,gaps:holdout.gaps};
  analysis.aiStage1Random10Gate=random10;
  upsertCheck(analysis,{id:'ai-stage1-worldwide-holdout-v2',title:'全网 AI 安全公开题 Holdout v2',hits:holdout.summary.closed,detail:`closed=${holdout.summary.closed}/${holdout.summary.cases}; partial=${holdout.summary.partial}; proxy=${(holdout.summary.solveProxyRate*100).toFixed(1)}%`});
  upsertCheck(analysis,{id:'ai-stage1-random10-gate',title:'随机 10 题 / 7 题闭环代理 Gate',hits:Math.round(random10.expectedSolved),detail:`E[closed]=${random10.expectedSolved.toFixed(2)}/10; P(>=7)=${(random10.probabilityAtLeast7*100).toFixed(1)}%; pass=${random10.pass}`});
  analysis.version=Math.max(Number(analysis.version)||1,82);
  return analysis;
}

function batch82Section(analysis){
  const gate=analysis.aiStage1Random10Gate;const holdout=analysis.aiStage1WorldwideHoldout;
  if(!gate&&!analysis.aiBlackboxAdversarial&&!analysis.aiMcpSupplyChain)return'';
  const lines=['## AI Batch82 · 全网 Holdout 与 Random-10 Gate',''];
  if(holdout)lines.push(`- Holdout v2：closed=${holdout.summary.closed}/${holdout.summary.cases} (${(holdout.summary.solveProxyRate*100).toFixed(1)}%) · partial=${holdout.summary.partial} · gap=${holdout.summary.gaps}`);
  if(gate)lines.push(`- Random-10 proxy：期望闭环 ${gate.expectedSolved.toFixed(2)}/10 · P(≥7)=${(gate.probabilityAtLeast7*100).toFixed(1)}% · median=${gate.median}/10 · gate=${gate.pass?'PASS':'FAIL'}`);
  if(gate?.weakestDirections?.length)lines.push(`- 当前最弱方向：${gate.weakestDirections.map((x)=>`${x.direction} ${(x.rate*100).toFixed(0)}%`).join(' · ')}`);
  if(analysis.aiBlackboxAdversarial)lines.push(`- 当前附件黑盒 adversarial transcript：files=${analysis.aiBlackboxAdversarial.files} · findings=${analysis.aiBlackboxAdversarial.findings.length}`);
  if(analysis.aiMcpSupplyChain)lines.push(`- 当前附件 MCP supply-chain：files=${analysis.aiMcpSupplyChain.files} · findings=${analysis.aiMcpSupplyChain.findings.length}`);
  lines.push('','> Random-10 是公开 source-derived holdout 的离线代理 Gate，不承诺未来随机比赛真实 7/10；最终题目仍以 challenge checker/verifier-backed solved 为准。');
  return lines.join('\n');
}
function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=batch82Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch82Section,looksBlackboxTranscript,looksMcpSupplyChain};
