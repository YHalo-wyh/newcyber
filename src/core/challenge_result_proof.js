'use strict';

const fs=require('fs/promises');
const path=require('path');
const crypto=require('crypto');

const OUTPUT_DIR='__newcyber_output__';
const PROOF_NAME='newcyber_result_proof.json';
function text(value){return String(value??'');}
function digest(value){const buffer=Buffer.from(text(value),'utf8');return{bytes:buffer.length,sha256:crypto.createHash('sha256').update(buffer).digest('hex')};}
function compactContract(contract={}){return{type:contract.type||null,file:contract.file||null,line:contract.line||null,expression:contract.expression||null,algorithm:contract.algorithm||null,confidence:contract.confidence||null};}
function buildResultProof(verifier={},submissionArtifact=null){
  if(verifier?.status!=='verified'||!verifier?.result)return null;
  const value=text(verifier.result.value??verifier.result.payload??'');if(!value)return null;
  const primary=verifier.proof||verifier.result.proof||null;
  const match=(verifier.verifiedMatches||[])[0]||null;
  const candidate=digest(value);
  const proof={
    schema:'newcyber.result-proof-manifest.v1',generatedAt:new Date().toISOString(),status:'verified',
    result:{kind:verifier.result.kind||'answer',source:verifier.result.source||'static-verifier',bytes:candidate.bytes,sha256:candidate.sha256},
    candidateSource:primary?.candidateSource||match?.candidateSource||null,
    verification:{method:primary?.method||match?.method||'static-verifier',sourceExecuted:false,contract:compactContract(primary?.contract||match?.contract||{}),checks:Array.isArray(primary?.checks)?primary.checks.slice(0,32):[]},
    artifact:submissionArtifact?{path:submissionArtifact.path||null,filename:submissionArtifact.filename||null,format:submissionArtifact.format||null,bytes:Number(submissionArtifact.bytes)||0,sha256:submissionArtifact.sha256||null,verified:Boolean(submissionArtifact.verified)}:null,
    guarantees:['题目 checker/verifier 源码未执行。','verified 仅来自静态恢复的强约束或完整受支持 return-predicate。','manifest 记录结果 SHA-256；大 payload 不重复写入 proof。']
  };
  if(proof.artifact?.sha256)proof.artifact.matchesResult=proof.artifact.sha256===proof.result.sha256;
  return proof;
}
async function materializeResultProof(rootPath,verifier={},submissionArtifact=null){
  const proof=buildResultProof(verifier,submissionArtifact);if(!proof)return{status:'not-applicable',proof:null,artifact:null};
  const root=path.resolve(String(rootPath||''));const outputDir=path.join(root,OUTPUT_DIR);await fs.mkdir(outputDir,{recursive:true});
  const target=path.join(outputDir,PROOF_NAME);const tmp=`${target}.tmp-${process.pid}-${Date.now()}`;const body=`${JSON.stringify(proof,null,2)}\n`;await fs.writeFile(tmp,body,'utf8');await fs.rename(tmp,target);
  const artifact={kind:'result-proof',path:path.relative(root,target).replace(/\\/g,'/'),absolutePath:target,filename:PROOF_NAME,format:'json',bytes:Buffer.byteLength(body,'utf8'),sha256:crypto.createHash('sha256').update(body,'utf8').digest('hex'),verified:true};
  return{status:'verified',proof,artifact};
}

module.exports={OUTPUT_DIR,PROOF_NAME,digest,buildResultProof,materializeResultProof};
