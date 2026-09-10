'use strict';

const {contextualVerification}=require('./sca_quality_result_gate');

const LONGCHENG_LEAKAGE_2026=Object.freeze({
  id:'longcheng-leakage-2026-real-shape',
  rawCols:528,effectiveDim:64,windowFunction:'hann',metric:'hann-dot',windowSize:8,offset:8,
  profileRows:287424,profileTokens:5988,groupsPerToken:48,hiddenPerGroup:16,hiddenDim:768,
  targetTokens:236,minR2:0.99,minCosine:0.99,
  calibrationMode:'sampled-global-ridge-hidden-to-wte',calibrationLambda:1,referenceStrategy:'phase2c-free'
});

function list(value){return Array.isArray(value)?value:[];}
function number(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function eq(actual,expected){return Number(actual)===Number(expected);}
function check(id,ok,expected,actual,detail){return {id,status:ok?'ok':'gap',expected,actual,detail};}
function recipeEvidence(recipe,name){return new Set(list(recipe?.evidence)).has(name);}

function observedShape(result){
  return {
    rawCols:number(result?.featureRecipe?.rawCols??result?.rawShape?.rawCols??result?.qualityRoute?.feature?.rawDim),
    profileRows:number(result?.layout?.profileRows??result?.profile?.rawRows??result?.rawShape?.profileRows),
    targetTokens:number(result?.target?.rows)
  };
}

function realShapeFingerprint(result,profile=LONGCHENG_LEAKAGE_2026){
  const observed=observedShape(result);
  const signals=[
    {id:'raw-cols',matched:eq(observed.rawCols,profile.rawCols),actual:observed.rawCols,expected:profile.rawCols},
    {id:'profile-rows',matched:eq(observed.profileRows,profile.profileRows),actual:observed.profileRows,expected:profile.profileRows},
    {id:'target-tokens',matched:eq(observed.targetTokens,profile.targetTokens),actual:observed.targetTokens,expected:profile.targetTokens}
  ];
  const matched=signals.filter((item)=>item.matched).length;
  return {profile:profile.id,matched,triggered:matched>=2,signals};
}

function evaluateRealShapeAcceptance(result,profile=LONGCHENG_LEAKAGE_2026){
  const fingerprint=realShapeFingerprint(result,profile);
  if(!fingerprint.triggered)return {schema:'newcyber.sca-real-shape-acceptance.v1',profile:profile.id,status:'not-applicable',fingerprint,checks:[]};

  const recipe=result?.featureRecipe||{};
  const layout=result?.layout||{};
  const leakage=result?.profile||{};
  const target=result?.target||{};
  const calibration=result?.probeCalibration||{};
  const contextual=result?.contextualHiddenOracle||{};
  const route=result?.qualityRoute||{};
  const verification=contextualVerification(contextual,target.rows);
  const checks=[];

  const recipeActual={rawCols:number(recipe.rawCols),slots:number(recipe.slots),windowSize:number(recipe.windowSize),offset:number(recipe.offset),windowFunction:recipe.windowFunction||null,metric:recipe.metric||null,source:recipe.source||null};
  checks.push(check('feature-recipe',
    eq(recipe.rawCols,profile.rawCols)&&eq(recipe.slots,profile.effectiveDim)&&eq(recipe.windowSize,profile.windowSize)&&eq(recipe.offset,profile.offset)
      &&recipe.windowFunction===profile.windowFunction&&recipe.metric===profile.metric&&recipe.source==='challenge-source'
      &&recipeEvidence(recipe,'guard-framing')&&recipeEvidence(recipe,'hann-dot-linear-amplitude'),
    `${profile.rawCols} raw -> ${profile.effectiveDim} ${profile.windowFunction}/${profile.metric}, window=${profile.windowSize}, offset=${profile.offset}, guarded linear source`,
    recipeActual,'raw trace must be reduced by the proven challenge Hann-dot recipe'));

  checks.push(check('profile-cardinality',
    eq(layout.profileRows,profile.profileRows)&&eq(layout.profileTokens,profile.profileTokens),
    `${profile.profileRows} rows / ${profile.profileTokens} tokens`,
    `${layout.profileRows??'n/a'} rows / ${layout.profileTokens??'n/a'} tokens`,
    'profiling row/token cardinality must match the real challenge shape'));

  checks.push(check('group-layout',
    eq(layout.groupsPerToken,profile.groupsPerToken)&&eq(layout.hiddenPerGroup,profile.hiddenPerGroup)&&eq(layout.hiddenDim,profile.hiddenDim)&&eq(layout.rowFeatureDim,profile.effectiveDim),
    `${profile.groupsPerToken} groups x ${profile.hiddenPerGroup} hidden = ${profile.hiddenDim}; row feature ${profile.effectiveDim}`,
    `${layout.groupsPerToken??'n/a'} groups x ${layout.hiddenPerGroup??'n/a'} hidden = ${layout.hiddenDim??'n/a'}; row feature ${layout.rowFeatureDim??'n/a'}`,
    'grouped leakage layout must preserve the 48-way hidden slicing'));

  const r2=number(leakage.r2);
  checks.push(check('streaming-leakage-fit',
    leakage.status==='ok'&&leakage.method==='streaming-ridge-token-groups'&&eq(leakage.rawRows,profile.profileRows)&&eq(leakage.rows,profile.profileTokens)
      &&eq(leakage.groupsPerToken,profile.groupsPerToken)&&eq(leakage.hiddenPerGroup,profile.hiddenPerGroup)&&eq(leakage.hiddenDim,profile.hiddenDim)
      &&eq(leakage.groupLeakageDim,profile.effectiveDim)&&r2!=null&&r2+1e-12>=profile.minR2,
    `streaming-ridge-token-groups, mean r2 >= ${profile.minR2}`,
    {status:leakage.status||null,method:leakage.method||null,rawRows:number(leakage.rawRows),rows:number(leakage.rows),r2},
    'the known linear leakage recipe must fit strongly; weak decodes are rejected'));

  checks.push(check('target-cardinality',eq(target.rows,profile.targetTokens),`${profile.targetTokens} target tokens`,number(target.rows),'target sequence length must match the real bundle'));

  const calibratedCosine=number(calibration?.evaluation?.calibratedCosine);
  checks.push(check('reference-probe-calibration',
    calibration.status==='accepted'&&calibration.mode===profile.calibrationMode&&calibration.referenceStrategy===profile.referenceStrategy
      &&eq(calibration.lambda,profile.calibrationLambda)&&eq(calibration.hiddenDim,profile.hiddenDim)&&calibratedCosine!=null,
    `${profile.calibrationMode}, lambda=${profile.calibrationLambda}, hidden=${profile.hiddenDim}, ${profile.referenceStrategy}`,
    {status:calibration.status||null,mode:calibration.mode||null,lambda:number(calibration.lambda),hiddenDim:number(calibration.hiddenDim),referenceStrategy:calibration.referenceStrategy||null,calibratedCosine},
    'candidate ranking must use the calibrated global hidden-to-WTE reference map'));

  checks.push(check('contextual-hidden-verification',
    verification.complete&&verification.expected===profile.targetTokens&&verification.matched===profile.targetTokens
      &&verification.minCosine!=null&&verification.minCosine+1e-12>=profile.minCosine,
    `${profile.targetTokens}/${profile.targetTokens} contextual matches, cosine min >= ${profile.minCosine}`,
    {expected:verification.expected,matched:verification.matched,threshold:verification.threshold,minCosine:verification.minCosine,meanCosine:verification.meanCosine},
    'every recovered token must be replay-verified against contextual model hidden state'));

  checks.push(check('recovery-maturity',
    result?.status==='verified-recovery'||result?.status==='flag-recovered',
    'verified-recovery or flag-recovered',result?.status||null,
    'free-probe or decoded text alone is not accepted'));

  const noRawFallback=!list(result?.stages).some((item)=>/raw(?:-|\s)?fallback|raw(?:-|\s)?downgrade/i.test(`${item?.id||''} ${item?.detail||''}`)&&item?.status==='ok');
  checks.push(check('production-quality-route',
    route.engine==='batch55-quality-first'&&route.selectedEngine==='quality-v4'&&route.rawDowngradeBlocked===false&&noRawFallback,
    'batch55-quality-first -> quality-v4; no raw fallback',
    {engine:route.engine||null,selectedEngine:route.selectedEngine||null,rawDowngradeBlocked:route.rawDowngradeBlocked??null,noRawFallback},
    'real-shape acceptance must come from the production quality path'));

  const failed=checks.filter((item)=>item.status!=='ok');
  return {
    schema:'newcyber.sca-real-shape-acceptance.v1',profile:profile.id,status:failed.length?'gap':'accepted',
    fingerprint,checks,passed:checks.length-failed.length,failed:failed.length,
    summary:failed.length?`${failed.length}/${checks.length} real-shape gates failed: ${failed.map((item)=>item.id).join(', ')}`:`${checks.length}/${checks.length} real-shape gates accepted`,
    metrics:{r2,contextualTokens:verification.matched,minCosine:verification.minCosine,meanCosine:verification.meanCosine}
  };
}

function enforceRealShapeAcceptance(result,profile=LONGCHENG_LEAKAGE_2026){
  const acceptance=evaluateRealShapeAcceptance(result,profile);
  if(acceptance.status==='not-applicable')return result;
  const stages=list(result?.stages).filter((item)=>item?.id!=='real-shape-acceptance');
  if(acceptance.status==='accepted'){
    stages.push({id:'real-shape-acceptance',status:'ok',detail:acceptance.summary,data:{profile:acceptance.profile,r2:acceptance.metrics.r2,contextualTokens:acceptance.metrics.contextualTokens,minCosine:acceptance.metrics.minCosine}});
    return {...result,stages,realShapeAcceptance:acceptance};
  }
  stages.push({id:'real-shape-acceptance',status:'gap',detail:acceptance.summary,data:{profile:acceptance.profile,failed:acceptance.checks.filter((item)=>item.status==='gap').map((item)=>item.id)}});
  return {
    ...result,status:'gap',flag:null,flagCandidate:null,
    gap:{code:'REAL_SHAPE_ACCEPTANCE_GAP',stage:'real-shape-acceptance',detail:acceptance.summary},
    stages,realShapeAcceptance:acceptance,
    blockedRecovery:{priorStatus:result?.status||null,recoveredTokens:list(result?.recoveredTokenIds).length}
  };
}

module.exports={LONGCHENG_LEAKAGE_2026,observedShape,realShapeFingerprint,evaluateRealShapeAcceptance,enforceRealShapeAcceptance};
