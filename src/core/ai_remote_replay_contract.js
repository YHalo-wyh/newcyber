'use strict';

const crypto=require('crypto');

function list(value){return Array.isArray(value)?value:[];}
function clamp(value,min,max,fallback){const n=Number(value);return Number.isFinite(n)?Math.max(min,Math.min(max,Math.floor(n))):fallback;}
function idFor(value){return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0,20);}
function flagPattern(flagFormat='flag{...}'){
  const match=String(flagFormat).match(/^([A-Za-z0-9_-]+)\{/);
  return match?`${match[1].replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}\\{[^\\r\\n{}]{1,256}\\}`:'[A-Za-z0-9_-]+\\{[^\\r\\n{}]{1,256}\\}';
}

function promptContract(probe,options={}){
  const endpoint=String(options.endpoint||'{{ENDPOINT}}');
  const candidateId=`prompt-replay-${idFor(`${probe.id}|${endpoint}`)}`;
  return {
    schema:'newcyber.ai-remote-replay-contract.v1',contractId:candidateId,candidateId,
    direction:'prompt-llm-security',probeId:probe.id,templateId:probe.templateId,recipeId:probe.recipeId,category:probe.category,placement:probe.placement,
    purpose:'authorized-competition-replay',score:Number(probe.score)||0,
    request:{method:'POST',endpoint,headers:{'Content-Type':'application/json'},body:{prompt:probe.prompt}},
    observation:{schema:'newcyber.observation.v1',candidateId,provenance:'challenge-runtime',capture:['statusCode','response','toolCalls','latencyMs'],response:null,toolCalls:[]},
    successChecks:[
      {id:'flag-regex',kind:'regex',target:'response',pattern:flagPattern(options.flagFormat)},
      {id:'injection-failure-signals',kind:'contains-any',target:'response',values:list(probe.failureSignals)},
      {id:'encoded-secret-fallback',kind:'decode-search',target:'response',transforms:['ascii-decimal','hex','base64','url','unicode-escape']},
      {id:'tool-call-evidence',kind:'tool-call',target:'toolCalls',mode:'record-and-evaluate'}
    ],
    stopConditions:['verified-flag','explicit-secret-leak','request-budget-exhausted'],
    execution:{automatic:false,authorizationRequired:true,networkSideEffect:true,retryOnTransportError:false}
  };
}

function genericDirectionContract(direction,closure,options={}){
  const candidateId=`${direction.id}-replay-${idFor(`${direction.id}|${closure?.nextBestAction||''}|${options.endpoint||''}`)}`;
  return {
    schema:'newcyber.ai-remote-replay-contract.v1',contractId:candidateId,candidateId,direction:direction.id,purpose:'authorized-competition-observation',
    request:{method:'MANUAL_OR_CHALLENGE_DEFINED',endpoint:String(options.endpoint||'{{ENDPOINT}}'),template:direction.remoteTemplates?.[0]?.template||direction.remoteAdvice||closure?.nextBestAction||''},
    observation:{schema:'newcyber.observation.v1',candidateId,provenance:'challenge-runtime',capture:['rawResponse','prediction','score','checkerResult','artifactId'],rawResponse:null},
    successChecks:[{id:'flag-regex',kind:'regex',target:'rawResponse',pattern:flagPattern(options.flagFormat)},{id:'direction-verifier',kind:'local-verifier-handoff',tools:list(direction.localTools)}],
    stopConditions:['verified-flag','verifier-accepted','request-budget-exhausted'],
    execution:{automatic:false,authorizationRequired:true,networkSideEffect:true,retryOnTransportError:false}
  };
}

function buildRemoteReplayPlan(autopilot={},closure={},options={}){
  const maxRequests=clamp(options.maxRemoteRequests,1,32,16);
  if(closure.closed)return {schema:'newcyber.ai-remote-replay-plan.v1',version:55,status:'closed',primaryDirection:null,maxRequests:0,contracts:[],executionPolicy:{automatic:false,authorizationRequired:true,stopOnVerifiedFlag:true}};
  const primaryId=closure.primaryDirection||autopilot.primaryDirection;
  const direction=list(autopilot.directions).find((item)=>item.id===primaryId)||list(autopilot.directions)[0]||null;
  let contracts=[];
  if(primaryId==='prompt-llm-security'){
    contracts=list(autopilot.promptPlan?.recommended).slice(0,maxRequests).map((probe)=>promptContract(probe,options));
  }else if(direction){
    contracts=[genericDirectionContract(direction,list(closure.directions).find((item)=>item.id===primaryId),options)];
  }
  return {
    schema:'newcyber.ai-remote-replay-plan.v1',version:55,status:contracts.length?'ready':'not-applicable',primaryDirection:primaryId,maxRequests,contractCount:contracts.length,contracts,
    observationSchema:'newcyber.observation.v1',
    executionPolicy:{automatic:false,authorizationRequired:true,unknownEndpointAttack:false,stopOnVerifiedFlag:true,stopOnExplicitLeak:true,maxRequests},
    handoff:{onObservation:'保存为 candidate-bound observation sidecar → 本地 verifier/evaluator → flag closure scheduler 重新评分',onFailure:'保留原始响应，针对响应做二次 mutation；不要无界重复请求。'}
  };
}

module.exports={flagPattern,promptContract,genericDirectionContract,buildRemoteReplayPlan};
