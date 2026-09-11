'use strict';

const path=require('path');
const batch56=require('./sca_autopilot_batch56');
const {resolveDirectDropScaIntake}=require('./sca_direct_drop_intake');

function list(value){return Array.isArray(value)?value:[];}
function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}
function compactIntake(intake){
  return {
    schema:'newcyber.sca-direct-drop-intake.v1',
    status:intake?.status||'unavailable',
    resolved:list(intake?.resolutions).filter((item)=>item.status==='ok').map((item)=>({
      role:item.role,
      file:path.basename(item.file?.filePath||item.file?.fileName||''),
      source:path.basename(item.evidence?.source||''),
      mode:item.evidence?.mode||null
    })),
    unresolved:list(intake?.resolutions).filter((item)=>item.status==='unresolved').map((item)=>({role:item.role,reason:item.reason,candidates:item.candidates||[]})),
    dropped:list(intake?.dropped).map((value)=>path.basename(value)),
    sourceEvidence:intake?.sourceEvidence||null,
    reason:intake?.reason||null
  };
}

async function runScaAutopilotPaths(filePaths,options={}){
  const intake=await resolveDirectDropScaIntake(filePaths,options);
  const selected=intake?.status==='resolved'?intake.paths:filePaths;
  const result=await batch56.runScaAutopilotPaths(selected,options);
  const compact=compactIntake(intake);
  let intakeStage;
  if(intake?.status==='resolved'){
    intakeStage=stage('direct-drop-intake','ok',`静态源码路径证据消歧 ${compact.resolved.length} 个角色，排除 ${compact.dropped.length} 个未引用副本`,compact);
  }else if(intake?.status==='unresolved'){
    intakeStage=stage('direct-drop-intake','skip',`检测到角色冲突，但静态源码证据不足以安全消歧；保持 fail-closed`,compact);
  }else{
    intakeStage=stage('direct-drop-intake','skip','未发现需要静态源码消歧的重复角色',compact);
  }
  if(!result||typeof result!=='object')return result;
  return {...result,directDropIntake:compact,stages:[intakeStage,...list(result.stages)]};
}

module.exports={...batch56,runScaAutopilotPaths,compactIntake};
