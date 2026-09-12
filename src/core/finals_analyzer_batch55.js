'use strict';

const base=require('./finals_analyzer_batch54');
const {buildFlagClosureScheduler}=require('./ai_flag_closure_scheduler');
const {buildRemoteReplayPlan}=require('./ai_remote_replay_contract');
const {collectObservationInbox}=require('./observation_orchestrator');
const {buildReplayFeedback}=require('./ai_replay_feedback_scheduler');

function list(value){return Array.isArray(value)?value:[];}
function oneLine(value){return String(value??'').replace(/\s+/g,' ').replace(/`/g,"'").trim();}
function verifiedRecoverySummary(analysis){
  const value=analysis?.scaAutopilot?.result?.verifiedRecovery||analysis?.scaAutopilot?.verifiedRecovery||null;
  if(!value)return null;
  const finite=(x)=>Number.isFinite(Number(x))?Number(x):null;
  return {
    method:oneLine(value.method||'contextual-hidden-oracle'),tokens:Number(value.tokens)||0,
    threshold:finite(value.threshold),minCosine:finite(value.minCosine),meanCosine:finite(value.meanCosine),
    shortlistHits:Number(value.shortlistHits)||0,fallbackPositions:Number(value.fallbackPositions)||0,fullScanCandidates:Number(value.fullScanCandidates)||0,
    privacy:'raw-recovered-text-omitted'
  };
}

function attachFlagClosure(analysis,closure,replay,feedback=null){
  analysis.aiFlagClosure=closure;analysis.aiRemoteReplay=replay;
  if(feedback)analysis.aiReplayFeedback=feedback;
  const autopilot=analysis.aiCompetitionAutopilot;
  if(autopilot&&closure.primaryDirection)autopilot.primaryDirection=closure.primaryDirection;
  const session=analysis.challengeSession||(analysis.challengeSession={});
  session.aiFlagClosure=closure;session.aiRemoteReplay=replay;
  if(feedback)session.aiReplayFeedback=feedback;
  if(session.aiCompetitionAutopilot&&closure.primaryDirection)session.aiCompetitionAutopilot.primaryDirection=closure.primaryDirection;

  session.solverLedger=list(session.solverLedger);
  const old=session.solverLedger.findIndex((item)=>item.id==='ai-flag-closure-sprint');
  const primary=list(closure.directions).find((item)=>item.id===closure.primaryDirection)||closure.directions?.[0];
  const scaRoute=analysis.scaAutopilot?.result?.qualityRoute||null;
  const recovery=verifiedRecoverySummary(analysis);
  const feedbackActive=feedback&&feedback.status!=='no-observation';
  const effectiveNext=feedbackActive&&closure.primaryDirection==='prompt-llm-security'?feedback.nextBestAction:closure.nextBestAction;
  const ledger={
    id:'ai-flag-closure-sprint',template:'AI-Only Flag Closure Sprint',
    status:closure.closed?'done':feedback?.pauseForVerifier?'ready':closure.minStepsToFlag<=1?'ready':closure.minStepsToFlag<=3?'running':'searching',
    evidence:[
      `primary=${primary?.title||'closed'}`,
      `steps-to-flag=${closure.minStepsToFlag}`,
      `closure-stage=${primary?.closureStage||'closed'}`,
      `remote-contracts=${replay.contractCount||0}`,
      ...(feedback?[`replay-feedback=${feedback.status}`,`observed=${feedback.trustedMatched||0}`,`next-wave=${feedback.nextContractCount||0}`]:[]),
      ...(scaRoute?[`sca-engine=${scaRoute.selectedEngine}`,`sca-quality-intent=${scaRoute.qualityIntent?.strong?'strong':'normal'}`]:[]),
      ...(recovery?[`verified-recovery=${recovery.tokens} tokens`,`contextual-cos-min=${recovery.minCosine==null?'n/a':recovery.minCosine.toFixed(6)}`]:[])
    ],
    detail:closure.closed?'Verified flag 已存在；停止扩展攻击面。':effectiveNext
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
    primaryDirection:closure.primaryDirection,minStepsToFlag:closure.minStepsToFlag,nextBestAction:effectiveNext,
    blockers:closure.blockers,replayContracts:replay.contracts?.slice(0,16)||[],
    adaptiveReplayContracts:feedback?.nextContracts?.slice(0,16)||[],replayFeedback:feedback||null,scaQualityRoute:scaRoute,
    verifiedRecovery:recovery
  };
  return analysis;
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const closure=buildFlagClosureScheduler(analysis,analysis.aiCompetitionAutopilot||{});
  const replay=buildRemoteReplayPlan(analysis.aiCompetitionAutopilot||{},closure,options);
  let feedback=null;
  if(!closure.closed&&closure.primaryDirection==='prompt-llm-security'&&replay.contracts?.length){
    const rawInbox=await collectObservationInbox(rootPath,analysis);
    feedback=buildReplayFeedback(replay,analysis.aiCompetitionAutopilot?.promptPlan||{},rawInbox,options);
  }
  attachFlagClosure(analysis,closure,replay,feedback);
  analysis.version=Math.max(Number(analysis.version)||1,55);
  return analysis;
}

function buildFlagClosureSection(analysis){
  const c=analysis.aiFlagClosure||analysis.challengeSession?.aiFlagClosure;if(!c)return'';
  const replay=analysis.aiRemoteReplay||analysis.challengeSession?.aiRemoteReplay||{};
  const feedback=analysis.aiReplayFeedback||analysis.challengeSession?.aiReplayFeedback||null;
  const recovery=verifiedRecoverySummary(analysis);
  const lines=['## AI-Only Flag Closure Sprint','',`- goal：minimum-steps-to-verified-flag`,`- closed：${c.closed?'yes':'no'}`,`- minimum steps：${c.minStepsToFlag}`,`- primary：${oneLine(c.primaryDirection||'closed')}`,`- next：${oneLine(feedback?.status&&feedback.status!=='no-observation'?feedback.nextBestAction:c.nextBestAction)}`,`- remote replay contracts：${Number(replay.contractCount)||0}`,'','### Closure Ranking',''];
  for(const d of list(c.directions))lines.push(`- **${oneLine(d.title)}** · steps=${d.stepsToFlag} · ${oneLine(d.closureStage)} · priority=${d.priority} · next=${oneLine(d.nextBestAction)}`);
  const route=analysis.scaAutopilot?.result?.qualityRoute;
  if(route){
    lines.push('','### SCA Production Quality Route','',`- engine：${oneLine(route.engine)} → ${oneLine(route.selectedEngine)}`,`- quality intent：${route.qualityIntent?.strong?'strong':'normal'}${route.qualityIntent?.reasons?.length?` (${route.qualityIntent.reasons.join(', ')})`:''}`,`- raw downgrade blocked：${route.rawDowngradeBlocked?'yes':'no'}`);
    if(route.feature)lines.push(`- feature：${route.feature.rawDim??'?'} raw → ${route.feature.effectiveDim??'?'} effective · ${oneLine(route.feature.windowFunction||'window')}`);
    if(route.calibration)lines.push(`- calibration：${oneLine(route.calibration.mode||route.calibration.status)} · cosine gain=${Number(route.calibration.cosineGain||0).toFixed(6)}`);
    if(route.fullProbe){
      const fp=route.fullProbe;
      const mode=fp.actual?'actual':fp.estimated?'estimated':'unavailable';
      lines.push(`- full probe：${fp.executed?'executed':'not-executed'} · ${mode} · rows=${fp.fullScanSucceededRows??fp.fullScanRows??0}/${fp.targetRows||0} · expanded=${fp.fullProbeExpandedRows||0} · top1-changed=${fp.top1ChangedRows||0} · candidates=${fp.candidateCount||0}`);
    }
  }
  if(recovery){
    lines.push('','### Verified Recovery','',`- method：${oneLine(recovery.method)}`,`- tokens：${recovery.tokens}`,`- contextual cosine：min=${recovery.minCosine==null?'n/a':recovery.minCosine.toFixed(6)} · mean=${recovery.meanCosine==null?'n/a':recovery.meanCosine.toFixed(6)} · threshold=${recovery.threshold==null?'n/a':recovery.threshold.toFixed(6)}`,`- fallback positions：${recovery.fallbackPositions} · full-scan candidates=${recovery.fullScanCandidates}`,'- recovered text：omitted from report by default; inspect the explicit SCA result only when required for challenge submission.');
  }
  if(feedback){
    lines.push('','### Replay Feedback','',`- status：${oneLine(feedback.status)}`,`- trusted observations：${Number(feedback.trustedMatched)||0}/${Number(feedback.matchedObservations)||0}`,`- dominant class：${oneLine(feedback.dominantClass||'none')}`,`- pause for verifier：${feedback.pauseForVerifier?'yes':'no'}`,`- next wave：${Number(feedback.nextContractCount)||0}`,`- global budget：${Number(feedback.globalBudget?.attempted)||0}/${Number(feedback.globalBudget?.max)||32}`,`- next：${oneLine(feedback.nextBestAction)}`);
    const counts=Object.entries(feedback.classificationCounts||{});if(counts.length)lines.push(`- classes：${counts.map(([key,value])=>`${oneLine(key)}=${Number(value)||0}`).join(', ')}`);
    lines.push('- raw responses：not included (digest/length only)');
  }
  if(replay.contracts?.length){
    lines.push('','### Authorized Replay Contracts','');
    for(const item of replay.contracts.slice(0,16))lines.push(`- \`${oneLine(item.contractId)}\` · ${oneLine(item.direction)}${item.probeId?` · ${oneLine(item.probeId)}`:''} · authorization required · stop on verified flag`);
  }
  if(feedback?.nextContracts?.length){
    lines.push('','### Adaptive Next Wave','');
    for(const item of feedback.nextContracts.slice(0,16))lines.push(`- \`${oneLine(item.contractId)}\` · ${oneLine(item.probeId)} · ${oneLine(item.recipeId)} · authorization required`);
  }
  lines.push('','> Batch55 冻结非 AI 扩展。所有优先级按离 Verified flag 的距离计算；远程 replay 仅生成机器可读 contract，必须显式授权后执行。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=buildFlagClosureSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,buildFlagClosureSection,attachFlagClosure,verifiedRecoverySummary};
