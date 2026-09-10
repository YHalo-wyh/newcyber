'use strict';

const base=require('./finals_analyzer_batch41');
const {buildChallengeSession}=require('./challenge_session');
const {runObservationHandoff,observationNeeds}=require('./observation_orchestrator');

function list(value){return Array.isArray(value)?value:[];}
function oneLine(value){return String(value??'').replace(/\s+/g,' ').replace(/`/g,"'").trim();}

function attachObservationHandoff(analysis,handoff){
  analysis.observationHandoff=handoff;
  analysis.challengeSession=analysis.challengeSession||buildChallengeSession(analysis);
  const session=analysis.challengeSession;
  session.observationHandoff=handoff;
  session.observationSummary=handoff.summary;

  session.solverLedger=list(session.solverLedger);
  const old=session.solverLedger.findIndex((item)=>item.id==='observation-handoff');
  const ledger={
    id:'observation-handoff',
    template:'Candidate Observation Handoff',
    status:handoff.summary.verified?'verified-observation':handoff.summary.captured?'ran':'waiting',
    evidence:[
      `${handoff.summary.contracts} contracts`,
      `${handoff.summary.captured} captured`,
      `${handoff.summary.verified} observation-verified`,
      `${handoff.summary.waiting} waiting`
    ],
    detail:handoff.summary.verified
      ? '至少一个 Candidate 已由 candidate-bound verifier 在受信运行观测上闭环。'
      : handoff.summary.contracts
        ? '已有 Candidate capture contract；等待受信 observation sidecar 后自动送入 verifier。'
        : '当前 Workspace 没有可构造 observation contract 的受支持 Candidate。'
  };
  if(old>=0)session.solverLedger[old]=ledger;else session.solverLedger.push(ledger);

  const needs=observationNeeds(handoff);
  session.needs=list(session.needs);
  const known=new Set(session.needs.map((item)=>item.id));
  for(const need of needs)if(!known.has(need.id)){session.needs.push(need);known.add(need.id);}
  if(!session.primaryNeed&&needs.length)session.primaryNeed=needs[0];

  session.facts=list(session.facts);
  for(const contract of handoff.contracts.filter((item)=>item.status==='verified')){
    const fact=`Observation Verified · ${contract.candidateId} · ${contract.verifier}`;
    if(!session.facts.includes(fact))session.facts.push(fact);
  }
  return analysis;
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const handoff=await runObservationHandoff(rootPath,analysis);
  attachObservationHandoff(analysis,handoff);
  analysis.version=Math.max(Number(analysis.version)||1,53);
  return analysis;
}

function buildObservationHandoffSection(analysis){
  const handoff=analysis.observationHandoff||analysis.challengeSession?.observationHandoff;
  if(!handoff)return'';
  const s=handoff.summary||{};
  const lines=[
    '## Observation Handoff','',
    `- contracts：${Number(s.contracts)||0}`,
    `- captured attempts：${Number(s.captured)||0}`,
    `- observation-verified：${Number(s.verified)||0}`,
    `- rejected：${Number(s.rejected)||0}`,
    `- waiting：${Number(s.waiting)||0}`,
    `- blocked：${Number(s.blocked)||0}`,
    `- unmatched observations：${Number(s.unmatched)||0}`
  ];
  if(handoff.contracts?.length){
    lines.push('','### Capture Contracts','');
    for(const item of handoff.contracts.slice(0,20))lines.push(`- **${oneLine(item.kind)}** · \`${oneLine(item.candidateId)}\` · ${String(item.status||'waiting').toUpperCase()} · ${oneLine(item.verifier)}${item.originFile?` · \`${oneLine(item.originFile)}\``:''}`);
  }
  if(handoff.attempts?.length){
    lines.push('','### Verifier Handoffs','');
    for(const item of handoff.attempts.slice(0,20)){
      const chain=list(item.transitions).map((x)=>String(x).toUpperCase()).join(' → ');
      lines.push(`- \`${oneLine(item.candidateId)}\` · ${oneLine(item.verifier)} · ${chain} · ${oneLine(item.verdict)}${item.observationFile?` · \`${oneLine(item.observationFile)}\``:''}`);
    }
  }
  lines.push('','> Batch53 只消费 Workspace 已枚举的显式 observation sidecar；不执行赛题、不加载不可信模型、不联网。Observation Verified 不等于自动获得 flag。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=buildObservationHandoffSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildObservationHandoffSection,attachObservationHandoff};
