'use strict';

const ALLOWED_DIRECTIONS=Object.freeze([
  'prompt-llm-security','adversarial-example','privacy-leakage','model-extraction',
  'backdoor-poisoning','dataset-pipeline-security','infra-supply-chain'
]);
const EVIDENCE_LEVELS=Object.freeze(['official','challenge-source-specific','official-challenge-archive','writeup-specific','ctf-writeup','organizer-writeup','benchmark','paper','research','public-challenge','repository','archive','public']);
const SOURCE_KIND_HINTS=Object.freeze(['official','organizer','challenge','archive','writeup','benchmark','paper','repository','advisory']);
const FORBIDDEN_KEYS=Object.freeze(['flag','secret','password','privateKey','private_key','apiKey','api_key','token','exploitKey','answer']);

function text(value){return value==null?'':String(value).trim();}
function lower(value){return text(value).toLowerCase();}
function uniq(values=[]){return [...new Set(values.filter(Boolean))];}
function isPublicUrl(value){
  try{const url=new URL(text(value));return (url.protocol==='https:'||url.protocol==='http:')&&!/^(localhost|127\.|0\.0\.0\.0|\[?::1\]?$)/i.test(url.hostname);}
  catch{return false;}
}
function signatureOf(row={}){return [row.event,row.challenge,row.family].map((x)=>lower(x)).join('|');}
function findForbidden(value,path='input',hits=[]){
  if(value==null)return hits;
  if(Array.isArray(value)){value.forEach((item,index)=>findForbidden(item,`${path}[${index}]`,hits));return hits;}
  if(typeof value==='object'){
    for(const [key,item] of Object.entries(value)){
      if(FORBIDDEN_KEYS.some((blocked)=>lower(key)===lower(blocked))&&text(item))hits.push(`${path}.${key}`);
      findForbidden(item,`${path}.${key}`,hits);
    }
    return hits;
  }
  const s=text(value);
  if(/flag\s*\{|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(s))hits.push(path);
  return hits;
}
function normalizeList(value){return uniq(Array.isArray(value)?value.map(text):text(value).split(/[\n,;]+/).map(text));}

function normalizeCandidate(input={}){
  const source=input.source&&typeof input.source==='object'?input.source:{};
  const evidence=input.evidence&&typeof input.evidence==='object'?input.evidence:{};
  const verifier=input.verifier&&typeof input.verifier==='object'?input.verifier:{};
  return{
    event:text(input.event),challenge:text(input.challenge),direction:text(input.direction),family:text(input.family),
    mechanicsSummary:text(input.mechanicsSummary||input.mechanics),
    source:{url:text(source.url||input.sourceUrl),kind:text(source.kind||input.sourceKind),evidenceLevel:text(source.evidenceLevel||input.evidenceLevel),title:text(source.title)},
    evidence:{facts:normalizeList(evidence.facts||input.evidenceFacts),successCondition:text(evidence.successCondition||input.successCondition),negativeControl:text(evidence.negativeControl||input.negativeControl)},
    verifier:{plan:normalizeList(verifier.plan||input.verifierPlan),positive:text(verifier.positive||input.positiveCase),negative:text(verifier.negative||input.negativeCase),control:text(verifier.control||input.controlCase),synthetic:verifier.synthetic!==false&&input.synthetic!==false},
    workOrderId:text(input.workOrderId)
  };
}

function findWorkOrder(workOrders={},candidate={}){
  const orders=Array.isArray(workOrders?.orders)?workOrders.orders:[];
  if(candidate.workOrderId)return orders.find((row)=>row.id===candidate.workOrderId)||null;
  return orders.find((row)=>row.direction===candidate.direction)||null;
}

function checkCandidate(rawInput={},context={}){
  const candidate=normalizeCandidate(rawInput);
  const cases=Array.isArray(context.cases)?context.cases:[];
  const order=findWorkOrder(context.workOrders,candidate);
  const directionCases=cases.filter((row)=>row.direction===candidate.direction);
  const forbidden=findForbidden(rawInput);
  const duplicate=cases.find((row)=>signatureOf(row)===signatureOf(candidate));
  const eventExists=directionCases.some((row)=>lower(row.event)===lower(candidate.event));
  const familyExists=directionCases.some((row)=>lower(row.family)===lower(candidate.family));
  const sourceKindOk=SOURCE_KIND_HINTS.some((hint)=>lower(candidate.source.kind).includes(hint));
  const evidenceLevelOk=EVIDENCE_LEVELS.includes(lower(candidate.source.evidenceLevel));
  const requiredFields=['event','challenge','direction','family','mechanicsSummary'].filter((key)=>!text(candidate[key]));
  const missingEvidence=[];
  if(!isPublicUrl(candidate.source.url))missingEvidence.push('public-source-url');
  if(!sourceKindOk)missingEvidence.push('recognized-source-kind');
  if(!evidenceLevelOk)missingEvidence.push('evidence-level');
  if(candidate.evidence.facts.length<2)missingEvidence.push('at-least-two-evidence-facts');
  if(!candidate.evidence.successCondition)missingEvidence.push('public-success-condition');
  if(!candidate.evidence.negativeControl)missingEvidence.push('negative-control-evidence');
  if(candidate.verifier.plan.length<1)missingEvidence.push('verifier-plan');
  if(!candidate.verifier.positive)missingEvidence.push('synthetic-positive-case');
  if(!candidate.verifier.negative)missingEvidence.push('synthetic-negative-case');
  if(!candidate.verifier.control)missingEvidence.push('synthetic-control-case');
  if(!candidate.verifier.synthetic)missingEvidence.push('synthetic-only-verifier');
  if(!order)missingEvidence.push('matching-work-order');
  const orderFamilyMatch=Boolean(order&&(order.acquisition?.familyThemes||[]).some((theme)=>lower(candidate.family).includes(lower(theme))||lower(theme).includes(lower(candidate.family))));
  const orderEventDebt=Number(order?.objective?.targets?.newEvents)||0;
  const orderFamilyDebt=Number(order?.objective?.targets?.newFamilies)||0;
  const blockers=[];
  if(forbidden.length)blockers.push('forbidden-secret-material');
  if(duplicate)blockers.push('duplicate-event-challenge-family-signature');
  if(candidate.direction&&!ALLOWED_DIRECTIONS.includes(candidate.direction))blockers.push('unsupported-direction');
  if(order&&candidate.direction!==order.direction)blockers.push('work-order-direction-mismatch');
  if(requiredFields.length)missingEvidence.push(...requiredFields.map((field)=>`field:${field}`));
  const verdict=blockers.length?'reject':missingEvidence.length?'needs-evidence':'accept';
  const checks={
    provenance:{pass:isPublicUrl(candidate.source.url)&&sourceKindOk&&evidenceLevelOk,urlPublic:isPublicUrl(candidate.source.url),sourceKindOk,evidenceLevelOk},
    signature:{pass:!duplicate,duplicate:duplicate?{id:duplicate.id,event:duplicate.event,challenge:duplicate.challenge,family:duplicate.family}:null},
    novelty:{eventNew:!eventExists,familyNew:!familyExists,helpsEventDebt:orderEventDebt>0&&!eventExists,helpsFamilyDebt:orderFamilyDebt>0&&!familyExists,workOrderFamilyTheme:orderFamilyMatch},
    evidence:{pass:candidate.evidence.facts.length>=2&&Boolean(candidate.evidence.successCondition)&&Boolean(candidate.evidence.negativeControl),facts:candidate.evidence.facts.length,hasSuccessCondition:Boolean(candidate.evidence.successCondition),hasNegativeControl:Boolean(candidate.evidence.negativeControl)},
    verifier:{pass:candidate.verifier.synthetic&&candidate.verifier.plan.length>0&&Boolean(candidate.verifier.positive)&&Boolean(candidate.verifier.negative)&&Boolean(candidate.verifier.control),synthetic:candidate.verifier.synthetic,planSteps:candidate.verifier.plan.length,positive:Boolean(candidate.verifier.positive),negative:Boolean(candidate.verifier.negative),control:Boolean(candidate.verifier.control)},
    policy:{pass:forbidden.length===0,forbiddenHits:forbidden}
  };
  const corpusDraft=verdict==='accept'?{
    event:candidate.event,challenge:candidate.challenge,direction:candidate.direction,family:candidate.family,
    provenance:{title:candidate.source.title||candidate.challenge,url:candidate.source.url,kind:candidate.source.kind,evidenceLevel:candidate.source.evidenceLevel},
    trainingPolicy:'public-evidence-plus-synthetic-regression-only',
    limitation:'Mechanics must remain limited to facts supported by the cited public source; synthetic fixtures are not original challenge secrets.'
  }:null;
  return{
    schema:'newcyber.ai-training-evidence-intake.v1',
    verdict,
    candidate,
    workOrder:order?{id:order.id,direction:order.direction,priority:order.priority,score:order.score,nextAction:order.objective?.nextAction||null}:null,
    checks,
    blockers:uniq(blockers),
    missingEvidence:uniq(missingEvidence),
    corpusDraft,
    nextStep:verdict==='accept'?'build-synthetic-regression-and-rerun-quality-holdout-schedule':verdict==='needs-evidence'?'collect-missing-public-evidence':'do-not-admit-to-corpus',
    note:'Acceptance means the evidence package is structurally ready for a synthetic deterministic regression. It does not independently verify that the public URL content is true or that a challenge actually implements unstated mechanics.'
  };
}

function buildIntakeTemplate(workOrder={}){
  const family=workOrder?.acquisition?.familyThemes?.[0]||'';
  return{
    schema:'newcyber.ai-training-evidence-intake-template.v1',
    workOrderId:workOrder?.id||'',
    event:'',challenge:'',direction:workOrder?.direction||'',family,
    mechanicsSummary:'',
    source:{url:'',title:'',kind:'official challenge archive',evidenceLevel:'official-challenge-archive'},
    evidence:{facts:[],successCondition:'',negativeControl:''},
    verifier:{synthetic:true,plan:workOrder?.regressionDesign?.verifier||[],positive:'',negative:'',control:''}
  };
}

module.exports={ALLOWED_DIRECTIONS,EVIDENCE_LEVELS,SOURCE_KIND_HINTS,FORBIDDEN_KEYS,isPublicUrl,signatureOf,normalizeCandidate,findWorkOrder,checkCandidate,buildIntakeTemplate};
