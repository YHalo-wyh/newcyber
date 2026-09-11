'use strict';

const {attachScaQualityDiagnostics}=require('./sca_quality_diagnostics');

function list(value){return Array.isArray(value)?value:[];}
function stage(id,status,detail,data){return {id,status,detail,...(data?{data}:{})};}

function exactLinearHannRecipe(recipe){
  const evidence=new Set(list(recipe?.evidence));
  return recipe?.metric==='hann-dot'
    && recipe?.windowFunction==='hann'
    && recipe?.source==='challenge-source'
    && evidence.has('hann-dot-linear-amplitude')
    && evidence.has('guard-framing')
    && Number.isSafeInteger(Number(recipe?.slots))
    && Number(recipe.slots)>0;
}

function contextualVerification(contextual,targetRows){
  const expected=Number(targetRows)||0;
  const recovered=list(contextual?.recoveredTokenIds);
  const positions=list(contextual?.positions);
  const threshold=Number(contextual?.threshold);
  if(contextual?.status!=='decoded'||!expected||recovered.length!==expected||positions.length!==expected||!Number.isFinite(threshold)){
    return {complete:false,expected,recovered:recovered.length,matched:0,threshold:Number.isFinite(threshold)?threshold:null,minCosine:null,meanCosine:null};
  }
  const cosines=[];
  for(const item of positions){
    const score=Number(item?.cosine);
    if(item?.status!=='matched'||!Number.isFinite(score)||score+1e-12<threshold)return {complete:false,expected,recovered:recovered.length,matched:cosines.length,threshold,minCosine:cosines.length?Math.min(...cosines):null,meanCosine:cosines.length?cosines.reduce((a,b)=>a+b,0)/cosines.length:null};
    cosines.push(score);
  }
  return {complete:true,expected,recovered:recovered.length,matched:positions.length,threshold,minCosine:Math.min(...cosines),meanCosine:cosines.reduce((a,b)=>a+b,0)/cosines.length};
}

function leakageQualityGate(result,options={}){
  if(!exactLinearHannRecipe(result?.featureRecipe)||result?.profile?.status!=='ok')return null;
  const threshold=Math.max(-1,Math.min(1,Number(options.minExactLinearHannR2??0.99)));
  const r2=Number(result.profile.r2);
  if(Number.isFinite(r2)&&r2>=threshold)return null;
  return {
    schema:'newcyber.sca-autopilot.v5',version:55,status:'gap',flag:null,flagCandidate:null,
    gap:{code:'LEAKAGE_QUALITY_GAP',stage:'leakage-fit',detail:`exact linear Hann recipe requires mean r2 >= ${threshold.toFixed(3)}, got ${Number.isFinite(r2)?r2.toFixed(6):'n/a'}; refusing garbage decode`},
    stages:[...list(result.stages),stage('leakage-quality','gap',`exact linear Hann · mean r2=${Number.isFinite(r2)?r2.toFixed(6):'n/a'} < ${threshold.toFixed(3)}`,{threshold,r2:Number.isFinite(r2)?r2:null})],
    discovery:result.discovery||null,runtime:result.runtime||null,layout:result.layout||null,profile:result.profile||null,featureRecipe:result.featureRecipe||null,
    blockedRecovery:{status:result.status||null,recoveredTokens:list(result.recoveredTokenIds).length},
    qualityGate:{kind:'exact-linear-hann-r2',threshold,r2:Number.isFinite(r2)?r2:null,blocked:true}
  };
}

function promoteContextualRecovery(result){
  const contextual=result?.contextualHiddenOracle;
  const verification=contextualVerification(contextual,result?.target?.rows);
  if(!verification.complete)return result;
  const verifiedRecovery={
    schema:'newcyber.sca-verified-recovery.v1',method:'contextual-hidden-oracle',tokens:verification.expected,
    threshold:verification.threshold,minCosine:verification.minCosine,meanCosine:verification.meanCosine,
    shortlistHits:Number(contextual.shortlistHits)||0,fallbackPositions:Number(contextual.fallbackPositions)||0,
    fullScanCandidates:Number(contextual.fullScanCandidates)||0
  };
  const stages=list(result.stages).filter((item)=>item?.id!=='flag-candidate'&&item?.id!=='verified-recovery'&&item?.id!=='flag');
  if(contextual.flag){
    stages.push(stage('flag','ok',contextual.flag,{verifiedBy:'contextual-hidden-oracle',tokens:verification.expected,minCosine:verification.minCosine,threshold:verification.threshold}));
    return {...result,schema:'newcyber.sca-autopilot.v5',version:55,status:'flag-recovered',flag:contextual.flag,flagCandidate:contextual.flag,gap:null,stages,verifiedRecovery,recoveredTokenIds:contextual.recoveredTokenIds,recoveredText:contextual.recoveredText};
  }
  stages.push(stage('verified-recovery','ok',`${verification.expected} tokens · contextual hidden cos min=${verification.minCosine.toFixed(6)} mean=${verification.meanCosine.toFixed(6)} · threshold=${verification.threshold.toFixed(6)}`,verifiedRecovery));
  return {...result,schema:'newcyber.sca-autopilot.v5',version:55,status:'verified-recovery',flag:null,flagCandidate:null,gap:null,stages,verifiedRecovery,recoveredTokenIds:contextual.recoveredTokenIds,recoveredText:contextual.recoveredText};
}

function applyQualityResultGate(result,options={}){
  if(!result||typeof result!=='object')return result;
  const leakageGap=leakageQualityGate(result,options);
  if(leakageGap)return attachScaQualityDiagnostics(leakageGap);
  return attachScaQualityDiagnostics(promoteContextualRecovery(result));
}

module.exports={exactLinearHannRecipe,contextualVerification,leakageQualityGate,promoteContextualRecovery,applyQualityResultGate};
