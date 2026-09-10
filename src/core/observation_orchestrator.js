'use strict';

const fsp=require('fs/promises');
const path=require('path');
const crypto=require('crypto');
const {auditTorchScriptSideEffects}=require('./ai_torchscript_side_effect');
const {verifyTransformReplayObservation,verifyTorchScriptSideEffectObservation}=require('./ai_candidate_replay_verification');

const MAX_OBSERVATION_BYTES=1024*1024;
const MAX_SOURCE_BYTES=2*1024*1024;
const MAX_OBSERVATION_FILES=32;
const MAX_OBSERVATIONS=128;
const MAX_CONTRACTS=32;
const TRUSTED_PROVENANCE=new Set(['controlled-local-replay','challenge-runtime','explicit-user-verified']);
const SUPPORTED={
  'transform-exfiltration-replay':{
    verifier:'ai-transform-replay-verify',
    required:['response'],
    captureHint:'保存实际模型响应，并绑定 candidateId 与可信 provenance。'
  },
  'torchscript-file-side-effect-chain':{
    verifier:'ai-torchscript-side-effect-verify',
    required:['readBytesBase64','writeBeforeBase64','writeAfterBase64'],
    captureHint:'保存受控运行的 read bytes、write-before、write-after 与可信 provenance；无需把模型交给 NewCyber 执行。'
  }
};

function hashId(prefix,value){return `${prefix}-${crypto.createHash('sha256').update(String(value)).digest('hex').slice(0,20)}`;}
function safeRelative(rootPath,filePath){
  const root=path.resolve(rootPath);const full=path.resolve(root,filePath);const rel=path.relative(root,full);
  if(!rel||rel.startsWith('..')||path.isAbsolute(rel))return null;
  return {root,full,relative:rel.split(path.sep).join('/')};
}
function isObservationPath(filePath){
  const normalized=String(filePath||'').replace(/\\/g,'/').toLowerCase();
  const base=path.posix.basename(normalized);
  return base==='newcyber-observation.json'||base.endsWith('.newcyber-observation.json');
}
function uniqueBy(items,keyFn){const out=[];const seen=new Set();for(const item of items){const key=keyFn(item);if(seen.has(key))continue;seen.add(key);out.push(item);}return out;}

function walkCandidates(value,originFile,out,state,sourceHint=null,depth=0){
  if(!value||typeof value!=='object'||depth>8||state.nodes>5000||out.length>=MAX_CONTRACTS)return;
  state.nodes++;
  const inherited=typeof value.source==='string'&&value.source.length<=MAX_SOURCE_BYTES?value.source:sourceHint;
  if(value.kind&&value.candidateId&&SUPPORTED[value.kind])out.push({candidate:value,originFile,sourceHint:inherited});
  if(Array.isArray(value)){
    for(const child of value)walkCandidates(child,originFile,out,state,inherited,depth+1);
    return;
  }
  for(const [key,child] of Object.entries(value)){
    if(['decoded','response','output','raw','buffer','base64'].includes(key))continue;
    walkCandidates(child,originFile,out,state,inherited,depth+1);
  }
}

async function readBoundedContained(rootPath,filePath,limit){
  const safe=safeRelative(rootPath,filePath);if(!safe)throw new Error('path-outside-workspace');
  const [rootReal,lstat]=await Promise.all([fsp.realpath(safe.root),fsp.lstat(safe.full)]);
  if(lstat.isSymbolicLink())throw new Error('symlink-not-allowed');
  if(!lstat.isFile())throw new Error('not-a-regular-file');
  if(lstat.size>limit)throw new Error(`file-too-large:${lstat.size}`);
  const fullReal=await fsp.realpath(safe.full);const rel=path.relative(rootReal,fullReal);
  if(!rel||rel.startsWith('..')||path.isAbsolute(rel))throw new Error('realpath-outside-workspace');
  return {text:await fsp.readFile(fullReal,'utf8'),relative:safe.relative,size:lstat.size};
}

async function discoverCandidates(rootPath,analysis){
  const found=[];const state={nodes:0};
  for(const file of analysis.files||[]){
    walkCandidates(file.metadata||{},file.path,found,state,null,0);
    if(found.length>=MAX_CONTRACTS)break;
  }
  const existing=new Set(found.map((x)=>x.candidate.candidateId));
  for(const file of analysis.files||[]){
    if(found.length>=MAX_CONTRACTS)break;
    if(String(file.extension||path.extname(file.path)).toLowerCase()!=='.py')continue;
    try{
      const read=await readBoundedContained(rootPath,file.path,MAX_SOURCE_BYTES);
      if(!/torch\.(?:jit|from_file)/.test(read.text))continue;
      const audit=auditTorchScriptSideEffects(read.text);const candidate=audit.candidateObject;
      if(candidate&&SUPPORTED[candidate.kind]&&!existing.has(candidate.candidateId)){
        found.push({candidate,originFile:file.path,sourceHint:read.text,discoveredBy:'static-python'});existing.add(candidate.candidateId);
      }
    }catch{}
  }
  return uniqueBy(found,(x)=>x.candidate.candidateId).slice(0,MAX_CONTRACTS);
}

async function buildObservationContracts(rootPath,analysis){
  const candidates=await discoverCandidates(rootPath,analysis);const contracts=[];
  for(const item of candidates){
    const candidate=item.candidate;const spec=SUPPORTED[candidate.kind];let source=item.sourceHint||null;
    if(candidate.kind==='torchscript-file-side-effect-chain'&&!source&&item.originFile){
      try{source=(await readBoundedContained(rootPath,item.originFile,MAX_SOURCE_BYTES)).text;}catch{}
    }
    const contextReady=candidate.kind==='transform-exfiltration-replay'
      ? Boolean(candidate.prompt&&Array.isArray(candidate.protectedTerms)&&candidate.protectedTerms.length)
      : Boolean(source);
    contracts.push({
      schema:'newcyber.observation-contract.v1',
      contractId:hashId('obs-contract',`${candidate.candidateId}\0${spec.verifier}`),
      candidateId:candidate.candidateId,
      kind:candidate.kind,
      verifier:spec.verifier,
      originFile:item.originFile||null,
      candidate,
      context:{source:source||null},
      required:[...spec.required],
      captureHint:spec.captureHint,
      contextReady,
      status:contextReady?'waiting':'blocked',
      missing:contextReady?[]:['source-context']
    });
  }
  return contracts;
}

function normalizeObservationDocument(parsed,file){
  let list=[];
  if(Array.isArray(parsed))list=parsed;
  else if(Array.isArray(parsed?.observations))list=parsed.observations;
  else if(parsed&&typeof parsed==='object')list=[parsed];
  return list.slice(0,32).map((item,index)=>({
    ...(item&&typeof item==='object'?item:{}),
    _sourceFile:file,
    _index:index
  })).filter((item)=>item.schema==='newcyber.observation.v1'&&typeof item.candidateId==='string'&&item.candidateId);
}

async function collectObservationInbox(rootPath,analysis){
  const inbox=[];const files=(analysis.files||[]).filter((file)=>isObservationPath(file.path)).slice(0,MAX_OBSERVATION_FILES);
  for(const file of files){
    try{
      const read=await readBoundedContained(rootPath,file.path,MAX_OBSERVATION_BYTES);const parsed=JSON.parse(read.text);
      for(const observation of normalizeObservationDocument(parsed,read.relative)){
        inbox.push(observation);if(inbox.length>=MAX_OBSERVATIONS)break;
      }
    }catch(error){
      inbox.push({schema:'newcyber.observation-error.v1',candidateId:null,_sourceFile:file.path,error:error.message});
    }
    if(inbox.length>=MAX_OBSERVATIONS)break;
  }
  return inbox;
}

function publicInboxEntry(observation,matched){
  return {
    sourceFile:observation._sourceFile||null,
    index:observation._index??null,
    candidateId:observation.candidateId||null,
    provenance:observation.provenance||null,
    trusted:TRUSTED_PROVENANCE.has(String(observation.provenance||'')),
    matched:Boolean(matched),
    error:observation.error||null
  };
}

function invokeVerifier(contract,observation){
  if(contract.kind==='transform-exfiltration-replay'){
    return verifyTransformReplayObservation({
      candidate:contract.candidate,
      prompt:contract.candidate.prompt,
      protectedTerms:contract.candidate.protectedTerms,
      response:observation.response??observation.modelResponse??observation.output??''
    });
  }
  if(contract.kind==='torchscript-file-side-effect-chain'){
    return verifyTorchScriptSideEffectObservation({
      candidate:contract.candidate,
      source:contract.context.source,
      provenance:observation.provenance,
      readBytesBase64:observation.readBytesBase64,
      writeBeforeBase64:observation.writeBeforeBase64,
      writeAfterBase64:observation.writeAfterBase64,
      writeOffset:observation.writeOffset,
      copyLength:observation.copyLength
    });
  }
  throw new Error('unsupported-observation-contract');
}

async function runObservationHandoff(rootPath,analysis){
  const contracts=await buildObservationContracts(rootPath,analysis);const rawInbox=await collectObservationInbox(rootPath,analysis);
  const attempts=[];const matchedIndexes=new Set();
  for(const contract of contracts){
    if(!contract.contextReady)continue;
    const matches=rawInbox.map((item,index)=>({item,index})).filter(({item})=>item.candidateId===contract.candidateId).slice(0,3);
    let trustedAttempted=false;
    for(const {item,index} of matches){
      matchedIndexes.add(index);
      if(!TRUSTED_PROVENANCE.has(String(item.provenance||''))){
        attempts.push({candidateId:contract.candidateId,contractId:contract.contractId,verifier:contract.verifier,observationFile:item._sourceFile,status:'rejected',verified:false,verdict:'untrusted-observation-provenance',transitions:['waiting','captured','rejected']});
        continue;
      }
      trustedAttempted=true;
      try{
        const result=invokeVerifier(contract,item);const verified=result?.verified===true;
        attempts.push({candidateId:contract.candidateId,contractId:contract.contractId,verifier:contract.verifier,observationFile:item._sourceFile,status:verified?'verified':'rejected',verified,verdict:result?.verdict||'verification-rejected',observationId:result?.observationId||null,result,transitions:['waiting','captured',verified?'verified':'rejected']});
        if(verified){contract.status='verified';contract.observationFile=item._sourceFile;contract.observationId=result.observationId||null;break;}
      }catch(error){
        attempts.push({candidateId:contract.candidateId,contractId:contract.contractId,verifier:contract.verifier,observationFile:item._sourceFile,status:'rejected',verified:false,verdict:'verifier-error',error:error.message,transitions:['waiting','captured','rejected']});
      }
    }
    if(contract.status!=='verified'&&trustedAttempted)contract.status='rejected';
  }
  const inbox=rawInbox.map((item,index)=>publicInboxEntry(item,matchedIndexes.has(index)));
  const summary={
    contracts:contracts.length,
    captured:attempts.length,
    verified:contracts.filter((x)=>x.status==='verified').length,
    rejected:contracts.filter((x)=>x.status==='rejected').length,
    waiting:contracts.filter((x)=>x.status==='waiting').length,
    blocked:contracts.filter((x)=>x.status==='blocked').length,
    unmatched:inbox.filter((x)=>x.candidateId&&!x.matched).length,
    untrusted:inbox.filter((x)=>x.candidateId&&!x.trusted).length
  };
  return {
    schema:'newcyber.observation-handoff.v1',version:1,
    contracts, inbox, attempts, summary,
    notes:[
      '自动采集只消费 Workspace 已枚举到、名称明确的 *.newcyber-observation.json / newcyber-observation.json；不会主动执行赛题或联网。',
      'sidecar 必须使用 newcyber.observation.v1、精确 candidateId 和受信 provenance；任一条件不满足都不会升级 Verified。',
      'Observation Verified 只证明对应 Candidate 在给定观测中闭环；不会凭此伪造 flag，也不会改写真实 CTF 原题 Verified 账本。'
    ]
  };
}

function observationNeeds(handoff){
  return (handoff?.contracts||[]).filter((contract)=>['waiting','blocked','rejected'].includes(contract.status)).map((contract)=>({
    id:`observation:${contract.contractId}`,
    kind:'runtime-observation',
    title:contract.status==='blocked'?'缺少 Candidate 上下文':'等待 Candidate 运行观测',
    detail:contract.status==='blocked'
      ? `${contract.candidateId} 缺少 ${contract.missing.join(', ')}，无法构造安全 verifier handoff。`
      : `${contract.candidateId} → ${contract.verifier}：${contract.captureHint}`,
    action:'把受控运行结果保存为 newcyber-observation.json（schema=newcyber.observation.v1），重新扫描 Workspace 后自动验证。',
    requiredFields:contract.required
  }));
}

module.exports={
  MAX_OBSERVATION_BYTES,MAX_SOURCE_BYTES,TRUSTED_PROVENANCE,SUPPORTED,isObservationPath,safeRelative,
  discoverCandidates,buildObservationContracts,collectObservationInbox,runObservationHandoff,observationNeeds
};
