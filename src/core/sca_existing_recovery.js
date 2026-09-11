'use strict';

const fsp=require('fs/promises');
const path=require('path');

const MAX_RECOVERY_BYTES=256*1024;
const MAX_EVIDENCE_BYTES=512*1024;
const MAX_RECOVERY_TEXT=8192;
const TEXT_EXT=new Set(['.txt','.log','.json','.md']);

function list(value){return Array.isArray(value)?value:[];}
function rel(value){return String(value||'').replace(/\\/g,'/');}
function inside(root,value){
  const base=path.resolve(root),target=path.resolve(base,String(value||''));
  if(target!==base&&!target.startsWith(base+path.sep))throw new Error('recovery artifact path escaped workspace');
  return target;
}
function recoveryNameScore(file){
  const value=rel(file?.path||file?.name).toLowerCase();
  const base=path.basename(value);let score=0;
  if(/decoded[_-]?prompt|recovered[_-]?prompt|prompt[_-]?(?:decoded|recovered)/.test(base))score+=80;
  if(/decoded|recovered|recovery/.test(base))score+=35;
  if(/prompt|token|result|output/.test(base))score+=20;
  if(/(?:^|\/)(?:work|output|outputs|result|results|artifacts?)(?:\/|$)/.test(value))score+=20;
  if(/(?:verify|oracle|debug|trace)\.log$/.test(base)&&!/(?:decoded|recovered)/.test(base))score-=80;
  if(path.extname(base)==='.txt')score+=5;
  return score;
}
function isRecoveryCandidate(file){
  const ext=String(file?.extension||path.extname(file?.path||'')).toLowerCase();
  const size=Number(file?.size)||0;
  return TEXT_EXT.has(ext)&&size>0&&size<=MAX_RECOVERY_BYTES&&recoveryNameScore(file)>=55;
}
function isEvidenceFile(file,candidate){
  const ext=String(file?.extension||path.extname(file?.path||'')).toLowerCase();
  const size=Number(file?.size)||0;
  if(!TEXT_EXT.has(ext)||size<=0||size>MAX_EVIDENCE_BYTES)return false;
  const candidateDir=path.dirname(String(candidate?.path||''));
  if(path.dirname(String(file?.path||''))!==candidateDir)return false;
  if(String(file.path)===String(candidate.path))return true;
  return /(?:verify|verified|oracle|recover|decode|prompt|phase|solve|result|log)/i.test(path.basename(String(file.path)));
}
async function readBounded(root,file,maxBytes){
  const full=inside(root,file.path);
  const stat=await fsp.lstat(full);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>maxBytes)return null;
  const buffer=await fsp.readFile(full);
  if(buffer.includes(0))return null;
  return buffer.toString('utf8');
}
function numberMatch(text,patterns){
  for(const regex of patterns){
    const match=regex.exec(text);regex.lastIndex=0;
    if(match){const value=Number(match[1]);if(Number.isFinite(value))return value;}
  }
  return null;
}
function countEvidence(text){
  const source=String(text||'');
  const verifiedWord='(?:verified|passed|validated|复核(?:通过)?|验证(?:通过)?|全部通过)';
  let match=new RegExp(`${verifiedWord}[^\\r\\n]{0,80}?(\\d+)\\s*\\/\\s*(\\d+)`,'i').exec(source);
  if(match)return {verified:Number(match[1]),total:Number(match[2]),mode:'fraction'};
  match=new RegExp(`(\\d+)\\s*\\/\\s*(\\d+)[^\\r\\n]{0,80}?${verifiedWord}`,'i').exec(source);
  if(match)return {verified:Number(match[1]),total:Number(match[2]),mode:'fraction'};
  match=new RegExp(`(\\d+)\\s*(?:tokens?|positions?|个\\s*token)[^\\r\\n]{0,80}?(?:all|全部)[^\\r\\n]{0,30}?${verifiedWord}`,'i').exec(source);
  if(match){const total=Number(match[1]);return {verified:total,total,mode:'all-tokens'};}
  match=/(?:verified[_ -]?(?:positions?|tokens?)|通过位置数)\s*[:=]\s*(\d+)[^\r\n]{0,80}?(?:total[_ -]?(?:positions?|tokens?)|总数)\s*[:=]\s*(\d+)/i.exec(source);
  if(match)return {verified:Number(match[1]),total:Number(match[2]),mode:'named-counts'};
  return {verified:null,total:null,mode:null};
}
function cosineEvidence(text){
  const source=String(text||'');
  const value='([01](?:\\.\\d+)?)';
  const mean=numberMatch(source,[
    new RegExp(`(?:mean|avg|average|平均)[ _-]*(?:cos(?:ine)?(?:[ _-]*(?:similarity|相似度))?|余弦(?:相似度)?)?\\s*[:=]\\s*${value}`,'i'),
    new RegExp(`(?:cos(?:ine)?|余弦)[^\\r\\n]{0,30}?(?:mean|avg|average|平均)\\s*[:=]\\s*${value}`,'i')
  ]);
  const min=numberMatch(source,[
    new RegExp(`(?:min|minimum|最低)[ _-]*(?:cos(?:ine)?(?:[ _-]*(?:similarity|相似度))?|余弦(?:相似度)?)?\\s*[:=]\\s*${value}`,'i'),
    new RegExp(`(?:cos(?:ine)?|余弦)[^\\r\\n]{0,30}?(?:min|minimum|最低)\\s*[:=]\\s*${value}`,'i')
  ]);
  return {meanCosine:mean,minCosine:min};
}
function parseVerificationEvidence(text,threshold=0.99){
  const counts=countEvidence(text);const cosine=cosineEvidence(text);
  const complete=Number.isInteger(counts.verified)&&Number.isInteger(counts.total)&&counts.total>0&&counts.verified===counts.total;
  const cosineStrong=Number.isFinite(cosine.minCosine)&&Number.isFinite(cosine.meanCosine)&&cosine.minCosine>=threshold&&cosine.meanCosine>=threshold;
  return {...counts,...cosine,threshold,complete,cosineStrong,verified:complete&&cosineStrong};
}
function cleanRecoveryText(text){
  return String(text||'').replace(/\u0000/g,'').replace(/\r\n/g,'\n').trim().slice(0,MAX_RECOVERY_TEXT);
}
function evidenceScore(parsed){
  if(parsed.verified)return 1000+Number(parsed.total||0);
  if(parsed.complete)return 500+Number(parsed.total||0);
  if(Number.isFinite(parsed.minCosine)||Number.isFinite(parsed.meanCosine))return 100;
  return 0;
}

async function scanExistingScaRecovery(rootPath,analysis,options={}){
  const threshold=Number(options.threshold??0.99);
  const candidates=list(analysis?.files).filter(isRecoveryCandidate).sort((a,b)=>recoveryNameScore(b)-recoveryNameScore(a)||String(a.path).localeCompare(String(b.path)));
  if(!candidates.length)return {schema:'newcyber.sca-existing-recovery.v1',status:'missing',candidateCount:0};
  const evaluated=[];
  for(const candidate of candidates.slice(0,16)){
    let text;try{text=await readBounded(rootPath,candidate,MAX_RECOVERY_BYTES);}catch{continue;}
    if(!text?.trim())continue;
    const evidenceFiles=list(analysis.files).filter((file)=>isEvidenceFile(file,candidate)).slice(0,24);
    let best={parsed:parseVerificationEvidence(text,threshold),file:candidate};
    for(const file of evidenceFiles){
      let evidenceText;try{evidenceText=String(file.path)===String(candidate.path)?text:await readBounded(rootPath,file,MAX_EVIDENCE_BYTES);}catch{continue;}
      if(!evidenceText)continue;
      const parsed=parseVerificationEvidence(evidenceText,threshold);
      if(evidenceScore(parsed)>evidenceScore(best.parsed))best={parsed,file};
    }
    evaluated.push({candidate,text:cleanRecoveryText(text),verification:best.parsed,evidenceFile:best.file,score:recoveryNameScore(candidate)});
  }
  if(!evaluated.length)return {schema:'newcyber.sca-existing-recovery.v1',status:'missing',candidateCount:candidates.length};
  evaluated.sort((a,b)=>evidenceScore(b.verification)-evidenceScore(a.verification)||b.score-a.score||String(a.candidate.path).localeCompare(String(b.candidate.path)));
  const top=evaluated[0];const topRank=[evidenceScore(top.verification),top.score].join(':');
  const tied=evaluated.filter((item)=>[evidenceScore(item.verification),item.score].join(':')===topRank&&item.text!==top.text);
  if(tied.length)return {
    schema:'newcyber.sca-existing-recovery.v1',status:'ambiguous',candidateCount:evaluated.length,
    candidates:[top,...tied].map((item)=>({path:item.candidate.path,verification:item.verification,score:item.score}))
  };
  const status=top.verification.verified?'verified':top.verification.complete?'corroborated':'candidate';
  return {
    schema:'newcyber.sca-existing-recovery.v1',status,candidateCount:evaluated.length,
    sourcePath:top.candidate.path,evidencePath:top.evidenceFile?.path||top.candidate.path,
    recoveredText:top.text,verification:top.verification,
    provenance:'existing-workspace-artifact',promotesFlag:false
  };
}

module.exports={
  MAX_RECOVERY_BYTES,MAX_EVIDENCE_BYTES,recoveryNameScore,isRecoveryCandidate,
  parseVerificationEvidence,scanExistingScaRecovery
};
