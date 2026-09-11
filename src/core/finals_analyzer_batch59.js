'use strict';

const path=require('path');
const base=require('./finals_analyzer_batch55');
const {scanExistingScaRecovery}=require('./sca_existing_recovery');

function list(value){return Array.isArray(value)?value:[];}
function oneLine(value){return String(value??'').replace(/\s+/g,' ').replace(/`/g,"'").trim();}
function canonicalFindingId(finding){return String(finding?.originalId||finding?.id||'');}

function isPackagingManifestPath(value){
  const normalized=String(value||'').replace(/\\/g,'/').toLowerCase();
  const baseName=path.posix.basename(normalized);
  return /^requirements(?:[-_.].*)?\.txt$/.test(baseName)
    || /^constraints(?:[-_.].*)?\.txt$/.test(baseName)
    || ['pyproject.toml','poetry.lock','uv.lock','pipfile','pipfile.lock','setup.py','setup.cfg','package.json','package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','pnpm-lock.yml','pom.xml','build.gradle','build.gradle.kts','gradle.lockfile','go.mod','go.sum','cargo.toml','cargo.lock','composer.json','composer.lock','gemfile','gemfile.lock'].includes(baseName)
    || baseName==='dockerfile'||baseName.startsWith('dockerfile.')
    || /^(?:docker-)?compose(?:\.[^.]+)?\.ya?ml$/.test(baseName)
    || /^docker-compose\.ya?ml$/.test(baseName);
}

function isTokenizerArtifact(value){
  const baseName=path.posix.basename(String(value||'').replace(/\\/g,'/').toLowerCase());
  return [
    'vocab.json','tokenizer.json','tokenizer_config.json','special_tokens_map.json',
    'added_tokens.json','merges.txt','generation_config.json'
  ].includes(baseName)
    || /^vocab(?:[-_.].*)?\.(?:txt|json)$/.test(baseName)
    || /^merges(?:[-_.].*)?\.txt$/.test(baseName);
}

function isTokenizerCrossDomainFinding(finding){
  const id=canonicalFindingId(finding);
  return /^(?:regulatory:|gnss:|gnss-spectrum:|firmware-update:|web3-|lowalt-|uav-)/i.test(id)
    || /^(?:model-extraction:|model-inversion:)/i.test(id);
}

function summarizeSupplyChain(metadata){
  const supply=metadata?.aiSupplyChain;if(!supply)return;
  const findings=list(supply.findings);
  supply.summary={
    high:findings.filter((x)=>x.severity==='high').length,
    medium:findings.filter((x)=>x.severity==='medium').length,
    low:findings.filter((x)=>x.severity==='low').length,
    info:findings.filter((x)=>x.severity==='info').length
  };
}

function suppressDirectDropNoise(analysis){
  const stats={dependencyNotLocked:0,tokenizerCrossDomain:0,metadataAudits:0,total:0,files:0};
  for(const file of list(analysis?.files)){
    const before=list(file.findings);let changed=false;
    const packaging=isPackagingManifestPath(file.path||file.name);
    const tokenizer=isTokenizerArtifact(file.path||file.name);
    const kept=[];
    for(const finding of before){
      const id=canonicalFindingId(finding);
      if(!packaging&&/^dependency-not-locked(?:[:$]|$)/i.test(id)){
        stats.dependencyNotLocked+=1;stats.total+=1;changed=true;continue;
      }
      if(tokenizer&&isTokenizerCrossDomainFinding(finding)){
        stats.tokenizerCrossDomain+=1;stats.total+=1;changed=true;continue;
      }
      kept.push(finding);
    }
    if(changed)file.findings=kept;

    const metadata=file.metadata||{};
    if(metadata.aiSupplyChain&&!packaging){
      const prior=list(metadata.aiSupplyChain.findings);
      const filtered=prior.filter((finding)=>!/^dependency-not-locked(?:[:$]|$)/i.test(canonicalFindingId(finding)));
      if(filtered.length!==prior.length){
        stats.dependencyNotLocked+=prior.length-filtered.length;
        stats.total+=prior.length-filtered.length;
        metadata.aiSupplyChain={...metadata.aiSupplyChain,findings:filtered};
        summarizeSupplyChain(metadata);changed=true;
      }
    }
    if(tokenizer){
      for(const key of ['regulatoryAudit','gnssAudit','gnssSpectrumAudit','firmwareUpdateAudit','web3Audit','modelExtractionAudit','modelInversionAudit']){
        if(Object.prototype.hasOwnProperty.call(metadata,key)){
          delete metadata[key];stats.metadataAudits+=1;changed=true;
        }
      }
    }
    if(changed){file.metadata=metadata;stats.files+=1;}
  }

  const severityOrder={high:0,medium:1,low:2,info:3};
  analysis.findings=list(analysis.files).flatMap((file)=>list(file.findings)).sort((a,b)=>(severityOrder[a.severity]??9)-(severityOrder[b.severity]??9)||String(a.file||'').localeCompare(String(b.file||''))||(a.line||0)-(b.line||0));
  analysis.stats=analysis.stats||{};analysis.stats.findings=analysis.findings.length;

  if(analysis.examDirectionCounts){
    const files=list(analysis.files);
    analysis.examDirectionCounts={
      ...analysis.examDirectionCounts,
      gnss:files.filter((f)=>f.metadata?.gnssAudit).length,
      gnssSpectrum:files.filter((f)=>f.metadata?.gnssSpectrumAudit).length,
      regulatory:files.filter((f)=>f.metadata?.regulatoryAudit).length,
      update:files.filter((f)=>f.metadata?.firmwareUpdateAudit).length,
      extraction:files.filter((f)=>f.metadata?.modelExtractionAudit).length,
      inversion:files.filter((f)=>f.metadata?.modelInversionAudit).length
    };
    const c=analysis.examDirectionCounts;
    analysis.recommendations=list(analysis.recommendations).filter((item)=>{
      const text=String(item||'');
      if(!c.gnss&&/^GNSS：/.test(text))return false;
      if(!c.gnssSpectrum&&/^GNSS SDR：/.test(text))return false;
      if(!c.regulatory&&/^低空监管：/.test(text))return false;
      if(!c.update&&/^固件升级：/.test(text))return false;
      if(!c.extraction&&/^模型窃取：/.test(text))return false;
      if(!c.inversion&&/^模型反演：/.test(text))return false;
      return true;
    });
  }
  analysis.directDropNoiseSuppression={schema:'newcyber.direct-drop-noise-suppression.v1',...stats};
  return analysis.directDropNoiseSuppression;
}

function recoveryEvidence(recovery){
  const v=recovery?.verification||{};
  const count=Number.isFinite(Number(v.total))?`${Number(v.verified)||0}/${Number(v.total)}`:'n/a';
  const min=Number.isFinite(Number(v.minCosine))?Number(v.minCosine).toFixed(6):'n/a';
  const mean=Number.isFinite(Number(v.meanCosine))?Number(v.meanCosine).toFixed(6):'n/a';
  return `tokens=${count} · cosine min=${min} mean=${mean}`;
}

function attachExistingRecovery(analysis,recovery){
  analysis.scaExistingRecovery=recovery;
  if(!recovery||['missing'].includes(recovery.status))return analysis;
  analysis.insights=list(analysis.insights);
  analysis.autopilot=analysis.autopilot||{automaticChecks:[],actions:[],summary:{}};
  analysis.autopilot.actions=list(analysis.autopilot.actions).filter((item)=>item.id!=='sca-existing-recovery');
  const session=analysis.challengeSession||(analysis.challengeSession={});
  session.solverLedger=list(session.solverLedger).filter((item)=>item.id!=='sca-existing-recovery');
  session.aiHandoff=session.aiHandoff||{};

  if(recovery.status==='verified'){
    if(!analysis.insights.some((item)=>item.kind==='sca-existing-verified-recovery'))analysis.insights.unshift({
      kind:'sca-existing-verified-recovery',title:'已有 SCA 恢复文本被本地复核日志完整验证',
      file:recovery.sourcePath,evidence:`${recoveryEvidence(recovery)} · evidence=${recovery.evidencePath}`,
      recoveredText:recovery.recoveredText,confidence:'verified-recovery-text',promotesFlag:false
    });
    analysis.autopilot.actions.unshift({
      id:'sca-existing-recovery',priority:118,level:'hot',title:'接管已有 SCA Verified Recovery',
      detail:`${recoveryEvidence(recovery)} · 已恢复文本已进入 handoff；未伪装为 Flag。`
    });
    session.solverLedger.unshift({
      id:'sca-existing-recovery',template:'Existing SCA Recovery Intake',status:'done',
      evidence:[`source=${oneLine(recovery.sourcePath)}`,`evidence=${oneLine(recovery.evidencePath)}`,recoveryEvidence(recovery),'promotes-flag=no'],
      detail:`已验证恢复文本：${oneLine(recovery.recoveredText).slice(0,640)}`
    });
    session.aiHandoff.existingScaRecovery={status:'verified',sourcePath:recovery.sourcePath,evidencePath:recovery.evidencePath,recoveredText:recovery.recoveredText,verification:recovery.verification,promotesFlag:false};
    analysis.recommendations=list(analysis.recommendations).filter((x)=>!/^SCA 已有恢复产物：/.test(String(x)));
    analysis.recommendations.unshift(`SCA 已有恢复产物：${oneLine(recovery.sourcePath)} 已由配套日志完成 token/cosine 复核；恢复文本已接管，但不会在没有 flag 语义证据时提升为 Verified flag。`);
  }else{
    const ambiguous=recovery.status==='ambiguous';
    analysis.autopilot.actions.unshift({
      id:'sca-existing-recovery',priority:ambiguous?82:94,level:'normal',title:ambiguous?'已有 SCA 恢复产物仍不唯一':'发现已有 SCA 恢复产物',
      detail:ambiguous?`存在 ${recovery.candidateCount||0} 个等价候选；保持 fail-closed。`:`status=${recovery.status} · ${recoveryEvidence(recovery)}`
    });
    if(!ambiguous){
      session.solverLedger.unshift({
        id:'sca-existing-recovery',template:'Existing SCA Recovery Intake',status:'partial',
        evidence:[`source=${oneLine(recovery.sourcePath)}`,recoveryEvidence(recovery),'promotes-flag=no'],
        detail:`已有恢复文本存在，但证据尚未满足完整 token + cosine 验证门。`
      });
      session.aiHandoff.existingScaRecovery={status:recovery.status,sourcePath:recovery.sourcePath,evidencePath:recovery.evidencePath,recoveredText:recovery.recoveredText,verification:recovery.verification,promotesFlag:false};
    }
  }
  analysis.autopilot.actions.sort((a,b)=>(b.priority||0)-(a.priority||0));
  analysis.autopilot.actions=analysis.autopilot.actions.slice(0,8);
  return analysis;
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  suppressDirectDropNoise(analysis);
  let recovery;
  try{recovery=await scanExistingScaRecovery(rootPath,analysis,options.existingRecovery||{});}
  catch(error){recovery={schema:'newcyber.sca-existing-recovery.v1',status:'error',error:error?.message||String(error)};}
  attachExistingRecovery(analysis,recovery);
  analysis.version=Math.max(Number(analysis.version)||1,59);
  return analysis;
}

function buildExistingRecoverySection(analysis){
  const recovery=analysis.scaExistingRecovery;if(!recovery||recovery.status==='missing')return'';
  const lines=['## Batch59 · Direct-Drop SCA Intake','',`- existing recovery：${oneLine(recovery.status)}`];
  const noise=analysis.directDropNoiseSuppression;
  if(noise)lines.push(`- noise suppressed：${noise.total} findings · dependency=${noise.dependencyNotLocked} · tokenizer-cross-domain=${noise.tokenizerCrossDomain}`);
  if(recovery.sourcePath)lines.push(`- source：\`${oneLine(recovery.sourcePath)}\``);
  if(recovery.evidencePath)lines.push(`- verification evidence：\`${oneLine(recovery.evidencePath)}\``);
  if(recovery.verification)lines.push(`- ${recoveryEvidence(recovery)}`);
  lines.push('- promotes to flag：no');
  if(recovery.recoveredText){
    lines.push('','### Recovered text','');
    for(const line of String(recovery.recoveredText).split(/\r?\n/).slice(0,80))lines.push(`    ${line.replace(/\t/g,'    ')}`);
  }
  lines.push('','> Existing recovery 只有在完整 token 计数与 min/mean cosine 同时达到验证门时才标记为 verified recovery text；它不会凭文件名或文本内容自动升级为 Flag。');
  return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=buildExistingRecoverySection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={
  ...base,scanWorkspace,buildMarkdownReport,isPackagingManifestPath,isTokenizerArtifact,
  suppressDirectDropNoise,attachExistingRecovery,buildExistingRecoverySection
};
