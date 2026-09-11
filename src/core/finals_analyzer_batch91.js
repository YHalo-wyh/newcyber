'use strict';

const base=require('./finals_analyzer_batch89');
const {runVerifierContractAutopilot}=require('./challenge_verifier_contract_v4');
const {materializeSubmissionArtifact}=require('./challenge_submission_artifact');
const {materializeResultProof}=require('./challenge_result_proof');
const {buildChallengeSession}=require('./challenge_session_batch89');

function upsertCheck(analysis,check){analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);}
function mergeFindings(analysis,findings){analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  let verifier;
  try{verifier=await runVerifierContractAutopilot(rootPath,analysis,options.verifier||{});}
  catch(error){verifier={schema:'newcyber.challenge-verifier-contract.v4',status:'gap',result:null,summary:{contracts:0,predicateContracts:0,predicateAttempts:0,predicateVerified:0,errors:1},contracts:[],predicateContracts:[],predicateAttempts:[],verifiedMatches:[],findings:[],errors:[{error:String(error?.message||error).slice(0,500)}],next:'受限 checker contract interpreter 异常，已降级为 GAP。',notes:[]};}
  analysis.verifierContractAutopilot=verifier;mergeFindings(analysis,verifier.findings);
  if(verifier.status!=='not-applicable')upsertCheck(analysis,{id:'bounded-checker-contract-v4',title:'受限 Checker Contract Interpreter',hits:Number(verifier.summary?.predicateVerified)||0,detail:`status=${verifier.status}; predicateContracts=${Number(verifier.summary?.predicateContracts)||0}; attempts=${Number(verifier.summary?.predicateAttempts)||0}`});

  let materialized=analysis.submissionArtifact||{status:'not-applicable',artifact:null};
  if(analysis.submissionAutopilot?.status==='formatted'){
    try{materialized=await materializeSubmissionArtifact(rootPath,analysis.submissionAutopilot,verifier);}
    catch(error){materialized={status:'gap',artifact:null,reason:'MATERIALIZE_EXCEPTION',error:String(error?.message||error).slice(0,500)};}
    analysis.submissionArtifact=materialized;
    if(materialized.artifact)upsertCheck(analysis,{id:'submission-artifact-materialize',title:'Submission 结果文件落盘',hits:1,detail:`${materialized.artifact.state} · ${materialized.artifact.path}`});
  }

  let proofAuto={status:'not-applicable',proof:null,artifact:null};
  try{proofAuto=await materializeResultProof(rootPath,verifier,materialized?.artifact||null);}
  catch(error){proofAuto={status:'gap',proof:null,artifact:null,error:String(error?.message||error).slice(0,500)};}
  analysis.resultProof=proofAuto;
  if(proofAuto.artifact){
    mergeFindings(analysis,[{id:'result-proof-materialized',severity:'high',title:'已生成 Verified Result Proof Manifest',file:proofAuto.artifact.path,evidence:`sha256=${proofAuto.proof?.result?.sha256||'n/a'} · method=${proofAuto.proof?.verification?.method||'static-verifier'}`,meaning:'该 manifest 记录候选来源、checker contract、逐项静态谓词结果和最终结果摘要；不执行题目源码。'}]);
    upsertCheck(analysis,{id:'result-proof-manifest',title:'Verified Result Proof Manifest',hits:1,detail:proofAuto.artifact.path});
  }
  analysis.challengeSession=buildChallengeSession(analysis);
  if(proofAuto.artifact){analysis.challengeSession.resultProof={status:proofAuto.status,artifact:proofAuto.artifact,proof:proofAuto.proof};}
  analysis.version=Math.max(Number(analysis.version)||1,91);return analysis;
}

function batch91Section(analysis){
  const verifier=analysis.verifierContractAutopilot;const proof=analysis.resultProof;if((!verifier||verifier.status==='not-applicable')&&(!proof||proof.status==='not-applicable'))return'';
  const lines=['## Batch91 · Checker Contract Interpreter / Result Proof',''];
  if(verifier){lines.push(`- verifier=${verifier.status} · predicateContracts=${Number(verifier.summary?.predicateContracts)||0} · predicateAttempts=${Number(verifier.summary?.predicateAttempts)||0} · predicateVerified=${Number(verifier.summary?.predicateVerified)||0}`);}
  if(proof?.artifact){lines.push(`- proof=${proof.artifact.path} · result_sha256=${proof.proof?.result?.sha256||'n/a'}`);}
  if(analysis.submissionArtifact?.artifact)lines.push(`- submission=${analysis.submissionArtifact.artifact.path} · state=${analysis.submissionArtifact.artifact.state}`);
  lines.push('','> 只解释 checker/verifier 中完整且受支持的 return conjunction：原始字符串长度/前后缀/包含/精确值，以及 JSON 字段标量和长度比较。表达式出现 OR、未知调用或任一未知原子时不会标 verified。题目源码始终不执行。');
  return lines.join('\n');
}
function buildMarkdownReport(analysis,notes=''){const report=base.buildMarkdownReport(analysis,notes);const section=batch91Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch91Section};
