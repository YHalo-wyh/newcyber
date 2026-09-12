'use strict';

const batch55=require('./sca_autopilot_batch55');
const real=require('./sca_real_bundle_quality_core');

function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}

async function runScaAutopilotPaths(filePaths,options={}){
  let result;
  try{result=await real.runRealBundleQualityPaths(filePaths,options);}
  catch(error){
    return {
      schema:'newcyber.sca-autopilot.v6',version:56,status:'gap',flag:null,
      gap:{code:'REAL_BUNDLE_PIPELINE_ERROR',stage:'batch56-dispatch',detail:error?.message||String(error)},
      stages:[stage('batch56-dispatch','gap',`contextual real-bundle pipeline error: ${error?.message||String(error)}`)],
      realBundleRoute:{mode:'error-no-legacy-fallback'}
    };
  }
  if(result?.status!=='not-applicable'){
    return {...result,version:56,stages:[stage('batch56-dispatch','ok','static profiling-boundary evidence -> contextual real-bundle quality core'),...(Array.isArray(result.stages)?result.stages:[])]};
  }
  const fallback=await batch55.runScaAutopilotPaths(filePaths,options);
  return {...fallback,version:56,stages:[stage('batch56-dispatch','skip',`real-bundle contextual path not applicable: ${result?.reason||'no boundary evidence'}; Batch55 fallback`),...(Array.isArray(fallback?.stages)?fallback.stages:[])]};
}

module.exports={...batch55,runScaAutopilotPaths,runRealBundleQualityPaths:real.runRealBundleQualityPaths};
