'use strict';

const crypto=require('node:crypto');
const path=require('node:path');
const {signature}=require('./ai_training_quality');
const {metrics,computeDelta}=require('./ai_training_integration_gate');

function text(value){return value==null?'':String(value).trim();}
function clone(value){return value==null?value:JSON.parse(JSON.stringify(value));}
function sha256(value){return crypto.createHash('sha256').update(String(value??'')).digest('hex');}
function unique(values=[]){return [...new Set(values.filter(Boolean))];}

function stableKey(candidate={}){
  return sha256([text(candidate.event).toLowerCase(),text(candidate.challenge).toLowerCase(),text(candidate.family).toLowerCase()].join('|')).slice(0,10);
}

function validateCorpusPath(filePath){
  const raw=text(filePath).replace(/\\/g,'/');
  if(!raw)return{pass:false,error:'missing-corpus-artifact-path'};
  if(!raw.startsWith('src/core/')||!raw.endsWith('.js'))return{pass:false,error:'corpus-artifact-must-be-src-core-js'};
  if(raw.includes('\0'))return{pass:false,error:'unsafe-corpus-artifact-path'};
  const normalized=path.posix.normalize(raw);
  if(normalized!==raw||normalized.includes('..')||normalized.startsWith('/'))return{pass:false,error:'unsafe-corpus-artifact-path'};
  const relative=raw.slice('src/core/'.length,-3);
  if(!relative||relative.startsWith('.')||/[^A-Za-z0-9_./-]/.test(relative))return{pass:false,error:'unsafe-corpus-artifact-path'};
  return{pass:true,path:raw,requirePath:`./${relative}`};
}

function buildRegistryDescriptor(gate={}){
  const errors=[];
  if(gate?.schema!=='newcyber.ai-training-integration-gate.v1')errors.push('integration-gate-required');
  if(gate?.status!=='ready-to-integrate'||gate?.readyToIntegrate!==true)errors.push('integration-gate-not-ready');
  const candidate=gate?.candidate&&typeof gate.candidate==='object'?gate.candidate:null;
  if(!candidate)errors.push('integration-candidate-missing');
  const files=Array.isArray(gate?.patch?.files)?gate.patch.files:[];
  const coreFiles=files.filter((file)=>text(file?.path).replace(/\\/g,'/').startsWith('src/core/')&&text(file?.path).endsWith('.js'));
  if(coreFiles.length!==1)errors.push(`expected-one-corpus-artifact-found-${coreFiles.length}`);
  const pathCheck=coreFiles.length===1?validateCorpusPath(coreFiles[0].path):{pass:false,error:'missing-corpus-artifact-path'};
  if(!pathCheck.pass)errors.push(pathCheck.error);
  if(errors.length)return{pass:false,errors};
  const key=stableKey(candidate);
  return{
    pass:true,errors:[],
    descriptor:{
      key,
      registryId:`integration-${key}`,
      importSymbol:`getIntegratedTrainingCorpus_${key}`,
      modulePath:pathCheck.requirePath,
      corpusPath:pathCheck.path,
      title:`${text(candidate.event)} / ${text(candidate.challenge)}`,
      kind:'ctf-derived',
      signature:signature(candidate),
      candidate:clone(candidate)
    }
  };
}

function registryImportLine(descriptor={}){
  return `const {getTrainingCorpus:${descriptor.importSymbol}}=require(${JSON.stringify(descriptor.modulePath)});`;
}
function registryEntryLine(descriptor={}){
  return `{id:${JSON.stringify(descriptor.registryId)},title:${JSON.stringify(descriptor.title)},kind:${JSON.stringify(descriptor.kind)},get:${descriptor.importSymbol}}`;
}

function applyRegistryPatch(curriculumSource,descriptor={}){
  const source=String(curriculumSource??'');
  const errors=[];
  if(!source.includes("'use strict';"))errors.push('curriculum-source-not-recognized');
  if(!text(descriptor.importSymbol)||!text(descriptor.registryId)||!text(descriptor.modulePath))errors.push('registry-descriptor-incomplete');
  if(source.includes(descriptor.importSymbol))errors.push('registry-import-symbol-already-present');
  if(source.includes(`require('${descriptor.modulePath}')`)||source.includes(`require(\"${descriptor.modulePath}\")`))errors.push('registry-module-already-present');
  if(source.includes(`id:'${descriptor.registryId}'`)||source.includes(`id:\"${descriptor.registryId}\"`))errors.push('registry-id-already-present');
  const importMarker='\nconst TARGET_DIRECTIONS=Object.freeze([';
  const importIndex=source.indexOf(importMarker);
  if(importIndex<0)errors.push('curriculum-import-anchor-missing');
  const corporaStart=source.indexOf('const CORPORA=Object.freeze([');
  if(corporaStart<0)errors.push('curriculum-corpora-anchor-missing');
  const corporaClose=corporaStart>=0?source.indexOf('\n]);',corporaStart):-1;
  if(corporaStart>=0&&corporaClose<0)errors.push('curriculum-corpora-close-anchor-missing');
  if(errors.length)return{pass:false,errors,content:null};

  const importLine=registryImportLine(descriptor);
  let patched=source.slice(0,importIndex)+`\n${importLine}`+source.slice(importIndex);
  const patchedCorporaStart=patched.indexOf('const CORPORA=Object.freeze([');
  const patchedClose=patched.indexOf('\n]);',patchedCorporaStart);
  const beforeClose=patched.slice(0,patchedClose);
  const trimmedEnd=beforeClose.search(/\s*$/);
  const contentEnd=trimmedEnd<0?beforeClose.length:trimmedEnd;
  const trailing=beforeClose.slice(contentEnd);
  const last=beforeClose.slice(0,contentEnd).slice(-1);
  const separator=last===','?'\n  ':',\n  ';
  patched=beforeClose.slice(0,contentEnd)+separator+registryEntryLine(descriptor)+trailing+patched.slice(patchedClose);
  return{pass:true,errors:[],content:patched,importLine,registryEntry:registryEntryLine(descriptor)};
}

function buildIntegrationWritePlan({gate,curriculumSource,existingPaths=[]}={}){
  const descriptorResult=buildRegistryDescriptor(gate);
  if(!descriptorResult.pass)return{schema:'newcyber.ai-training-integration-writer.v1',status:'blocked',readyToWrite:false,errors:descriptorResult.errors,writes:[]};
  const descriptor=descriptorResult.descriptor;
  const artifacts=Array.isArray(gate?.patch?.files)?gate.patch.files:[];
  const collisions=artifacts.map((file)=>text(file?.path)).filter((filePath)=>filePath&&existingPaths.includes(filePath));
  if(collisions.length)return{schema:'newcyber.ai-training-integration-writer.v1',status:'blocked',readyToWrite:false,errors:collisions.map((filePath)=>`artifact-path-already-exists:${filePath}`),descriptor,writes:[]};
  const invalidArtifact=artifacts.find((file)=>!text(file?.path)||typeof file?.content!=='string'||file?.operation!=='create');
  if(invalidArtifact)return{schema:'newcyber.ai-training-integration-writer.v1',status:'blocked',readyToWrite:false,errors:['invalid-materialized-artifact'],descriptor,writes:[]};
  const patch=applyRegistryPatch(curriculumSource,descriptor);
  if(!patch.pass)return{schema:'newcyber.ai-training-integration-writer.v1',status:'blocked',readyToWrite:false,errors:patch.errors,descriptor,writes:[]};
  const writes=[...artifacts.map((file)=>({operation:'create',path:file.path,content:file.content})),{operation:'update',path:'src/core/ai_training_curriculum.js',content:patch.content}];
  return{
    schema:'newcyber.ai-training-integration-writer.v1',status:'ready-to-write',readyToWrite:true,errors:[],descriptor,writes,
    preconditions:{
      curriculumSourceSha256:sha256(curriculumSource),
      artifactsMustNotExist:artifacts.map((file)=>file.path),
      expectedCandidateSignature:descriptor.signature,
      integrationGateStatus:'ready-to-integrate'
    },
    expected:{delta:clone(gate.delta),candidate:clone(gate.candidate)},
    rollback:{delete:artifacts.map((file)=>file.path),restore:{path:'src/core/ai_training_curriculum.js',sha256:sha256(curriculumSource)}},
    completionGates:['apply all writes atomically or on an isolated branch','run npm test','run ai-training-full-regression','recompute actual curriculum delta','finalize only when actual delta exactly matches the integration-gate simulation'],
    note:'This writer produces deterministic repository writes but does not bypass repository/branch concurrency controls. The caller must preserve the curriculum source hash precondition and verify the post-write curriculum.'
  };
}

function comparableDelta(delta={}){
  return{
    direction:delta.direction||null,
    qualityScore:Number(delta.qualityScore)||0,
    effectiveCases:Number(delta.effectiveCases)||0,
    rawCases:Number(delta.rawCases)||0,
    events:Number(delta.events)||0,
    families:Number(delta.families)||0,
    challenges:Number(delta.challenges)||0,
    duplicateRatio:Number(delta.duplicateRatio)||0,
    provenanceAverage:Number(delta.provenanceAverage)||0,
    holdoutEligible:{before:Boolean(delta.holdoutEligible?.before),after:Boolean(delta.holdoutEligible?.after)},
    cleanPlans:Number(delta.cleanPlans)||0,
    unseenFamilyPlans:Number(delta.unseenFamilyPlans)||0,
    scheduleRank:{before:delta.scheduleRank?.before??null,after:delta.scheduleRank?.after??null,delta:delta.scheduleRank?.delta??null},
    scheduleScore:{before:delta.scheduleScore?.before??null,after:delta.scheduleScore?.after??null}
  };
}

function verifyIntegratedResult({gate,beforeCases=[],afterCurriculum,fullRegression,repositoryTests}={}){
  const errors=[];
  if(gate?.schema!=='newcyber.ai-training-integration-gate.v1'||gate?.readyToIntegrate!==true||gate?.status!=='ready-to-integrate')errors.push('integration-gate-not-ready');
  const afterCases=Array.isArray(afterCurriculum?.cases)?afterCurriculum.cases:null;
  if(afterCurriculum?.schema!=='newcyber.ai-training-curriculum.v1'||!afterCases)errors.push('post-integration-curriculum-required');
  const before=Array.isArray(beforeCases)?beforeCases:[];
  const candidate=gate?.candidate||{};
  if(afterCases){
    const matches=afterCases.filter((row)=>signature(row)===signature(candidate));
    if(matches.length!==1)errors.push(`candidate-signature-count-${matches.length}`);
    if(afterCases.length!==before.length+1)errors.push(`curriculum-case-count-drift:${before.length}->${afterCases.length}`);
    if(Array.isArray(afterCurriculum.sourceErrors)&&afterCurriculum.sourceErrors.length)errors.push('curriculum-source-errors');
  }
  let actualDelta=null;let expectedDelta=comparableDelta(gate?.delta||{});
  if(afterCases){
    const directions=unique([...before.map((row)=>row.direction),...afterCases.map((row)=>row.direction),candidate.direction]).sort();
    const beforeMetrics=metrics(before,directions);
    const afterMetrics=metrics(afterCases,directions);
    actualDelta=comparableDelta(computeDelta(beforeMetrics,afterMetrics,candidate.direction));
    if(JSON.stringify(actualDelta)!==JSON.stringify(expectedDelta))errors.push('simulated-vs-actual-delta-mismatch');
  }
  if(fullRegression?.schema!=='newcyber.ai-training-curriculum-regression.v1')errors.push('full-regression-result-required');
  else{
    if(Number(fullRegression?.summary?.suiteErrors)!==0)errors.push('full-regression-suite-errors');
    if(afterCases&&Number(fullRegression?.summary?.curriculumCases)!==afterCases.length)errors.push('full-regression-curriculum-count-mismatch');
  }
  if(repositoryTests?.passed!==true)errors.push('repository-tests-not-passed');
  const status=errors.length?(errors.includes('simulated-vs-actual-delta-mismatch')?'integration-drift':'verification-failed'):'verified-integrated';
  return{
    schema:'newcyber.ai-training-integration-verification.v1',status,verified:errors.length===0,errors,
    candidateSignature:signature(candidate),expectedDelta,actualDelta,
    checks:{
      candidatePresentExactlyOnce:!errors.some((x)=>x.startsWith('candidate-signature-count-')),
      isolatedCaseAddition:!errors.some((x)=>x.startsWith('curriculum-case-count-drift:')),
      deltaMatchesSimulation:!errors.includes('simulated-vs-actual-delta-mismatch'),
      fullRegressionPassed:!errors.includes('full-regression-result-required')&&!errors.includes('full-regression-suite-errors')&&!errors.includes('full-regression-curriculum-count-mismatch'),
      repositoryTestsPassed:repositoryTests?.passed===true
    },
    note:'verified-integrated is only emitted when the persisted curriculum reproduces the Batch103 simulated delta exactly, the deterministic full regression is clean, and repository tests are reported as passed.'
  };
}

module.exports={sha256,stableKey,validateCorpusPath,buildRegistryDescriptor,registryImportLine,registryEntryLine,applyRegistryPatch,buildIntegrationWritePlan,comparableDelta,verifyIntegratedResult};
