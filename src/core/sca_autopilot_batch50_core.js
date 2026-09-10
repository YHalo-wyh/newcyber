'use strict';

// Frozen Batch50 quality-first dispatcher. Batch55 wraps this implementation
// with source-priority, downgrade guards and production observability. The
// Batch55 result gate upgrades only fully contextual-verified recovery and
// blocks low-R2 exact linear-Hann decodes.
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const batch46=require('./sca_autopilot_batch46');
const quality=require('./sca_quality_grouped_core');
const {applyQualityResultGate}=require('./sca_quality_result_gate');

function list(value){return Array.isArray(value)?value:[];}
function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}
function missingProfileLabels(result){return result?.status==='not-applicable'&&/profileTokenIds/i.test(String(result?.reason||''));}
async function runQualityGroupedScaAutopilotPaths(filePaths,options={}){
  const result=await quality.runQualityGroupedScaAutopilotPaths(filePaths,options);
  return applyQualityResultGate(result,options);
}

async function replayResolvedLabels(filePaths,diagnostic,options={}){
  const labels=diagnostic?.profileLabels;
  if(labels?.status!=='ok')return null;
  if(diagnostic.discovery?.manifest)return null;
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-sca-b50-'));
  const labelPath=path.join(dir,'profiling_input_ids.npy');
  try{
    await batch46.writeInt32Npy(labelPath,labels.sequences);
    const result=await runQualityGroupedScaAutopilotPaths([...filePaths,labelPath],options);
    if(result?.status==='not-applicable')return null;
    return {...result,stages:[stage('profile-label','ok',`${labels.count} labels · ${labels.source} · Batch50 quality replay`),...list(result.stages)],profileLabelSource:{source:labels.source,count:labels.count,evidence:labels.evidence||null}};
  }finally{await fs.rm(dir,{recursive:true,force:true});}
}

async function runScaAutopilotPaths(filePaths,options={}){
  let qualityResult=null,qualityError=null;
  try{qualityResult=await runQualityGroupedScaAutopilotPaths(filePaths,options);}catch(error){qualityError=error;}
  if(qualityResult&&qualityResult.status!=='not-applicable')return qualityResult;

  if(missingProfileLabels(qualityResult)){
    try{
      const diagnostic=await batch46.diagnoseProfileLabelGap(filePaths,options);
      if(diagnostic.status==='profile-labels-resolved'){
        const replay=await replayResolvedLabels(filePaths,diagnostic,options);
        if(replay)return replay;
      }
    }catch{}
  }

  if(qualityError&&options.strictQuality===true)throw qualityError;
  return batch46.runScaAutopilotPaths(filePaths,options);
}

module.exports={...batch46,runScaAutopilotPaths,runQualityGroupedScaAutopilotPaths,replayResolvedLabels,applyQualityResultGate};
