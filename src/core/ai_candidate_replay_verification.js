'use strict';

const crypto=require('crypto');
const {analyzeTransformExfiltration}=require('./ai_transform_exfiltration');
const {auditTorchScriptSideEffects}=require('./ai_torchscript_side_effect');

const MAX_OBSERVATION_BYTES=1024*1024;
const TRUSTED_PROVENANCE=new Set(['controlled-local-replay','challenge-runtime','explicit-user-verified']);

function hash(value){return crypto.createHash('sha256').update(value).digest('hex');}
function parseInput(input){
  if(input&&typeof input==='object')return input;
  const text=String(input||'').trim();
  if(!text)return {};
  try{return JSON.parse(text);}catch{return {};}
}
function termsFrom(data,candidate){
  const raw=data.protectedTerms??data.markers??candidate?.protectedTerms??[];
  return (Array.isArray(raw)?raw:[raw]).map((x)=>String(x||'').trim()).filter((x)=>x.length>=3);
}
function fail(schema,reason,extra={}){return {schema,verified:false,verdict:reason,...extra};}

function verifyTransformReplayObservation(input={}){
  const data=parseInput(input);const candidate=data.candidate||{};const candidateId=String(data.candidateId||candidate.candidateId||'');
  const prompt=String(data.prompt??candidate.prompt??'');const response=String(data.response??data.observation?.response??'');const protectedTerms=termsFrom(data,candidate);
  if(!candidateId||candidate.kind!=='transform-exfiltration-replay')return fail('newcyber.ai-transform-replay-verification.v1','REPLAY_CANDIDATE_REQUIRED');
  if(!prompt||!protectedTerms.length)return fail('newcyber.ai-transform-replay-verification.v1','REPLAY_CONTEXT_REQUIRED',{candidateId});
  const rebuilt=analyzeTransformExfiltration({prompt,protectedTerms});
  if(rebuilt.candidateObject?.candidateId!==candidateId)return fail('newcyber.ai-transform-replay-verification.v1','CANDIDATE_BINDING_MISMATCH',{candidateId,expectedCandidateId:rebuilt.candidateObject?.candidateId||null});
  if(!response)return fail('newcyber.ai-transform-replay-verification.v1','OBSERVATION_REQUIRED',{candidateId});
  const observed=analyzeTransformExfiltration({prompt,response,protectedTerms});
  const verified=observed.verified===true&&observed.directHits.length===0&&Boolean(observed.candidateObject?.markerHits?.length);
  const observationId=`replay-${hash(JSON.stringify({candidateId,prompt,protectedTerms,response})).slice(0,24)}`;
  return {
    schema:'newcyber.ai-transform-replay-verification.v1',candidateId,observationId,verified,
    verdict:verified?'verified-on-provided-observation':'observation-did-not-close-candidate',
    transformChain:observed.candidateObject?.transformChain||null,
    markerHits:observed.candidateObject?.markerHits||[],directHits:observed.directHits||[],
    decodedPreview:observed.candidateObject?.decodedPreview||null,
    evidence:{promptBound:true,protectedTermsBound:true,responseChars:response.length},
    notes:['Verified 只表示该 Candidate 在提供的实际响应观测上闭环；不会据此声称原赛事远端服务已被利用。','验证过程纯离线，不调用模型或网络。']
  };
}

function decodeBase64(value,label){
  const text=String(value||'').trim();if(!text)return {error:`${label}_REQUIRED`};
  if(text.length>MAX_OBSERVATION_BYTES*2)return {error:`${label}_TOO_LARGE`};
  if(!/^[A-Za-z0-9+/]*={0,2}$/.test(text)||text.length%4===1)return {error:`${label}_INVALID_BASE64`};
  const buffer=Buffer.from(text,'base64');if(buffer.length>MAX_OBSERVATION_BYTES)return {error:`${label}_TOO_LARGE`};
  return {buffer};
}
function outsideUnchanged(before,after,offset,length){
  if(before.length!==after.length)return false;
  for(let i=0;i<before.length;i++)if((i<offset||i>=offset+length)&&before[i]!==after[i])return false;
  return true;
}

function verifyTorchScriptSideEffectObservation(input={}){
  const data=parseInput(input);const source=String(data.source||'');const candidate=data.candidate||{};const candidateId=String(data.candidateId||candidate.candidateId||'');
  if(!source)return fail('newcyber.ai-torchscript-side-effect-verification.v1','SOURCE_REQUIRED');
  const rebuilt=auditTorchScriptSideEffects(source);const expected=rebuilt.candidateObject;
  if(!expected||expected.kind!=='torchscript-file-side-effect-chain')return fail('newcyber.ai-torchscript-side-effect-verification.v1','STATIC_CHAIN_REQUIRED');
  if(!candidateId||candidateId!==expected.candidateId)return fail('newcyber.ai-torchscript-side-effect-verification.v1','CANDIDATE_BINDING_MISMATCH',{candidateId,expectedCandidateId:expected.candidateId});
  const provenance=String(data.provenance??data.observation?.provenance??'');
  if(!TRUSTED_PROVENANCE.has(provenance))return fail('newcyber.ai-torchscript-side-effect-verification.v1','OBSERVATION_PROVENANCE_REQUIRED',{candidateId,provenance,allowedProvenance:[...TRUSTED_PROVENANCE]});
  const read=decodeBase64(data.readBytesBase64??data.observation?.readBytesBase64,'READ_BYTES');if(read.error)return fail('newcyber.ai-torchscript-side-effect-verification.v1',read.error,{candidateId});
  const before=decodeBase64(data.writeBeforeBase64??data.observation?.writeBeforeBase64,'WRITE_BEFORE');if(before.error)return fail('newcyber.ai-torchscript-side-effect-verification.v1',before.error,{candidateId});
  const after=decodeBase64(data.writeAfterBase64??data.observation?.writeAfterBase64,'WRITE_AFTER');if(after.error)return fail('newcyber.ai-torchscript-side-effect-verification.v1',after.error,{candidateId});
  const offset=Math.max(0,Number(data.writeOffset??data.observation?.writeOffset??0)|0);
  const requested=Number(data.copyLength??data.observation?.copyLength??read.buffer.length);
  const length=Math.max(0,Math.min(read.buffer.length,Number.isFinite(requested)?Math.floor(requested):read.buffer.length));
  if(!length||offset+length>before.buffer.length||offset+length>after.buffer.length)return fail('newcyber.ai-torchscript-side-effect-verification.v1','OBSERVATION_RANGE_INVALID',{candidateId,offset,length});
  const expectedSlice=read.buffer.subarray(0,length),beforeSlice=before.buffer.subarray(offset,offset+length),afterSlice=after.buffer.subarray(offset,offset+length);
  const copied=afterSlice.equals(expectedSlice);const changed=!beforeSlice.equals(afterSlice);const bounded=outsideUnchanged(before.buffer,after.buffer,offset,length);
  const verified=copied&&changed&&bounded;
  const observationId=`sidefx-${hash(Buffer.concat([Buffer.from(candidateId),read.buffer,before.buffer,after.buffer,Buffer.from(`${offset}:${length}:${provenance}`)])).slice(0,24)}`;
  return {
    schema:'newcyber.ai-torchscript-side-effect-verification.v1',candidateId,observationId,verified,
    verdict:verified?'verified-on-provided-observation':'observation-did-not-close-candidate',provenance,
    binding:{sourceCandidateId:expected.candidateId,readPath:expected.read.path,writePath:expected.write.path,mutation:expected.mutation.kind},
    checks:{copiedSourceBytes:copied,targetRegionChanged:changed,outsideRegionUnchanged:bounded},
    hashes:{read:hash(read.buffer),writeBefore:hash(before.buffer),writeAfter:hash(after.buffer)},
    range:{offset,length},
    notes:['本验证器不加载或执行 TorchScript；它只校验受控运行产生的 before/after/read 观测是否与静态 Candidate 严格绑定。','只有受信 provenance + candidateId/source 绑定 + 字节级副作用一致性同时成立才返回 Verified。']
  };
}

module.exports={MAX_OBSERVATION_BYTES,TRUSTED_PROVENANCE,verifyTransformReplayObservation,verifyTorchScriptSideEffectObservation};
