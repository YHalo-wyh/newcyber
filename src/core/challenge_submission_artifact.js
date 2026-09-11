'use strict';

const crypto=require('crypto');
const fs=require('fs/promises');
const path=require('path');

const MAX_PAYLOAD_BYTES=16*1024*1024;
function text(value){return String(value??'');}
function safeExt(format){const value=String(format||'').toLowerCase();return value==='csv'?'.csv':value==='tsv'?'.tsv':value==='json'?'.json':'.txt';}
function sha256(buffer){return crypto.createHash('sha256').update(buffer).digest('hex');}
function verifierMatchesPayload(verifier,payload){
  if(!verifier||verifier.status!=='verified'||!verifier.result)return false;
  return String(verifier.result.value??verifier.result.payload??'')===payload;
}
async function materializeSubmissionArtifact(root,submission,verifier=null){
  if(!submission||submission.status!=='formatted'||!submission.result)return{status:'not-applicable',artifact:null};
  const payload=text(submission.result.payload);
  if(!payload)return{status:'gap',artifact:null,reason:'EMPTY_SUBMISSION_PAYLOAD'};
  const buffer=Buffer.from(payload,'utf8');
  if(buffer.length>MAX_PAYLOAD_BYTES)return{status:'gap',artifact:null,reason:'SUBMISSION_PAYLOAD_TOO_LARGE',bytes:buffer.length};
  const verified=verifierMatchesPayload(verifier,payload);
  const ext=safeExt(submission.result.format);
  const outputDir=path.join(path.resolve(root),'__newcyber_output__');
  await fs.mkdir(outputDir,{recursive:true});
  const filename=`newcyber_submission_${verified?'verified':'candidate'}${ext}`;
  const target=path.join(outputDir,filename);const tmp=`${target}.tmp-${process.pid}-${Date.now()}`;
  await fs.writeFile(tmp,buffer);await fs.rename(tmp,target);
  const artifact={
    kind:'submission-artifact',state:verified?'verified':'candidate',verified,
    path:path.relative(path.resolve(root),target).replace(/\\/g,'/'),absolutePath:target,
    filename,format:submission.result.format||ext.slice(1),bytes:buffer.length,sha256:sha256(buffer),
    template:submission.result.template||null,source:submission.result.source||'submission-autopilot'
  };
  submission.result.artifact=artifact;
  if(verified&&verifier?.result)verifier.result.artifact=artifact;
  return{status:verified?'verified':'candidate',artifact};
}

module.exports={MAX_PAYLOAD_BYTES,safeExt,sha256,verifierMatchesPayload,materializeSubmissionArtifact};
