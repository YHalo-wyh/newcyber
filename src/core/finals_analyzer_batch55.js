'use strict';

const base=require('./finals_analyzer_batch54');
const {buildFlagClosureScheduler}=require('./ai_flag_closure_scheduler');
const {buildRemoteReplayPlan}=require('./ai_remote_replay_contract');

function list(value){return Array.isArray(value)?value:[];}
function oneLine(value){return String(value??'').replace(/\s+/g,' ').replace(/`/g,"'").trim();}

function attachFlagClosure(analysis,closure,replay){
  analysis.aiFlagClosure=closure;analysis.aiRemoteReplay=replay;
  const autopilot=analysis.aiCompetitionAutopilot;
  if(autopilot&&closure.primaryDirection)autopilot.primaryDirection=closure.primaryDirection;
  const session=analysis.challengeSession||(analysis.challengeSession={});
  session.aiFlagClosure=closure;session.aiRemoteReplay=replay;
  if(session.aiCompetitionAutopilot&&closure.primaryDirection)session.aiCompetitionAutopilot.primaryDirection=closure.primaryDirection;

  session.solverLedger=list(session.solverLedger);
  const old=session.solverLedger.findIndex((item)=>item.id==='ai-flag-closure-sprint');
  const primary=list(closure.directions).find((item)=>item.id===closure.primaryDirection)||closure.directions?.[0];
  const scaRoute=analysis.scaAutopilot?.result?.qualityRoute||null;
  const ledger={
    id:'ai-flag-closure-sprint',template:'AI-Only Flag Closure Sprint',
    status:closure.closed?'done':closure.minStepsToFlag<=1?'ready':closure.minStepsToFlag<=3?'running':'searching',
    evidence:[
      `primary=${primary?.title||'closed'}`,
      `steps-to-flag=${closure.minStepsToFlag}`,
      `closure-stage=${primary?.closureStage||'closed'}`,
      `remote-contracts=${replay.contractCount||0}`,
      ...(scaRoute?[`sca-engine=${scaRoute.selectedEngine}`,`sca-quality-intent=${scaRoute.qualityIntent?.strong?'strong':'normal'}`]:[])
    ],
    detail:closure.closed?'Verified flag 已存在；停止扩展攻击面。':closure.nextBestAction
  };
  if(old>=0)session.solverLedger[old]=ledger;else session.solverLedger.unshift(ledger);

  const prior=session.solverLedger.find((item)=>item.id==='ai-five-direction-autopilot');
  if(prior&&primary){
    prior.detail=`Batch55 已按 flag closure distance 重排；当前主方向 ${primary.title}，预计 ${primary.stepsToFlag} 步进入 Verified。`;
    prior.evidence=list(prior.evidence).filter((x)=>!String(x).startsWith('closure-'));
    prior.evidence.push(`closure-steps=${primary.stepsToFlag}`,`closure-stage=${primary.closureStage}`);
  }

  session.aiHandoff=session.aiHandoff||{};
  session.aiHandoff.flagClosure={
    primaryDirection:closure.primaryDirection,minStepsToFlag:closure.minStepsToFlag,nextBestAction:closure.nextBestAction,
    blockers:closure.blockers,replayContracts:replay.contracts?.slice(0,16)||[],scaQualityRoute:scaRoute
  };
  return analysis;
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const closure=buildFlagClosureScheduler(analysis,analysis.aiCompetitionAutopilot||{});
  const replay=buildRemoteReplayPlan(analysis.aiCompetitionAutopilot||{},closure,options);
  attachFlagClosure(analysis,closure,replay);
  analysis.version=Math.max(Number(analysis.version)||1,55);
  return analysis;
}

function buildFlagClosureSection(analysis){
  const c=analysis.aiFlagClosure||analysis.challengeSession?.aiFlagClosure;if(!c)return'';
  const replay=analysis.aiRemoteReplay||analysis.challengeSession?.aiRemoteReplay||{};
  const lines=['## AI-Only Flag Closure Sprint','',`- goal：minimum-steps-to-verified-flag`,`- closed：${c.closed?'yes':'no'}`,`- minimum steps：${c.minStepsToFlag}`,`- primary：${oneLine(c.primaryDirection||'closed')}`,`- next：${oneLine(c.nextBestAction)}`,`- remote replay contracts：${Number(replay.contractCount)||0}`,'','### Closure Ranking',''];
  for(const d of list(c.directions))lines.push(`- **${oneLine(d.title)}** · steps=${d.stepsToFlag} · ${oneLine(d.closureStage)} · priority=${d.priority} · next=${oneLine(d.nextBestAction)}`);
  const route=analysis.scaAutopilot?.result?.qualityRoute;
  if(route){
    lines.push('','### SCA Production Quality Route','',`- engine：${oneLine(route.engine)} → ${oneLine(route.selectedEngine)}`,`- quality intent：${route.qualityIntent?.strong?'strong':'normal'}${route.qualityIntent?.reasons?.length?` (${route.qualityIntent.reasons.join(', ')})`:''}`,`- raw downgrade blocked：${route.rawDowngradeBlocked?'yes':'no'}`);
    if(route.feature)lines.push(`- feature：${route.feature.rawDim??'?'} raw → ${route.feature.effectiveDim??'?'} effective · ${oneLine(route.feature.windowFunction||'window')}`);
    if(route.calibration)lines.push(`- calibration：${oneLine(route.calibration.mode||route.calibration.status)} · cosine gain=${Number(route.calibration.cosineGain||0).toFixed(6)}`);
    if(route.fullProbe)lines.push(`- full probe：${route.fullProbe.executed?'executed':'not-executed'} · rows=${route.fullProbe.fullScanRows||0}/${route.fullProbe.targetRows||0} · candidates=${route.fullProbe.candidateCount||0}`);
  }
  if(replay.contracts?.length){
    lines.push('','### Authorized Replay Contracts','');
    for(const item of replay.contracts.slice(0,16))lines.push(`- \`${oneLine(item.contractId)}\` · ${oneLine(item.direction)}${item.probeId?` · ${oneLine(item.probeId)}`:''} · authorization required · stop on verified flag`);
  }
  lines.push('','> Batch55 冻结非 AI 扩展。所有优先级按离 Verified flag 的距离计算；远程 replay 仅生成机器可读 contract，必须显式授权后执行。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=buildFlagClosureSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildFlagClosureSection,attachFlagClosure};
