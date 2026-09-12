'use strict';

const EVALUATOR_PROFILES=Object.freeze({
  'prompt-llm-security':{
    tool:'ai-prompt-injection-evaluate',module:'ai_prompt_injection',entrypoint:'evaluatePromptInjectionRun',
    contract:['positive fixture must satisfy the public success condition','negative fixture must stay non-finding','control fixture must prove the finding is specific rather than generic prompt failure']
  },
  'adversarial-example':{
    tool:'ai-adversarial-batch',module:'ai_adversarial',entrypoint:'analyzeAdversarialBatch',
    contract:['positive fixture must cross the public ranking/margin/misclassification criterion','negative fixture must preserve the clean ranking or class','control fixture must keep perturbation/constraint assumptions comparable']
  },
  'privacy-leakage':{
    tool:'ai-privacy-audit',module:'ai_privacy',entrypoint:'analyzePrivacyTranscript',
    contract:['positive fixture must exceed the documented leakage/member-separation criterion','negative fixture must remain below the criterion','control fixture must preserve a held-out or non-sensitive reference']
  },
  'model-extraction':{
    tool:'ai-model-extraction',module:'ai_model_extraction',entrypoint:'analyzeModelExtractionTranscript',
    contract:['positive fixture must meet the public fidelity/agreement notion','negative fixture must remain low-fidelity','control fixture must use a held-out evaluation slice']
  },
  'backdoor-poisoning':{
    tool:'ai-backdoor-behavior',module:'ai_poison_backdoor_validation',entrypoint:'analyzeBackdoorBehavior',
    contract:['positive fixture must show target-specific triggered behavior','negative fixture must preserve clean behavior','control fixture must reject generic corruption or non-specific activation']
  },
  'dataset-pipeline-security':{
    tool:'ai-dataset-security',module:'ai_dataset_security',entrypoint:'analyzeDatasetSecurity',
    contract:['positive fixture must violate the documented data/schema invariant','negative fixture must satisfy the invariant','control fixture must isolate the suspected pipeline transformation']
  },
  'infra-supply-chain':{
    tool:'ai-supply-chain',module:'ai_supply_chain',entrypoint:'auditAiSupplyChain',
    contract:['positive fixture must expose the public unsafe trust/loading/resolution condition','negative fixture must use the safe alternative','control fixture must isolate the specific artifact/dependency boundary']
  }
});

function text(value){return value==null?'':String(value).trim();}
function lower(value){return text(value).toLowerCase();}
function slug(value){return lower(value).replace(/[^a-z0-9\u4e00-\u9fff]+/g,'-').replace(/^-+|-+$/g,'').slice(0,96)||'case';}

function evaluatorFor(candidate={}){
  const direction=text(candidate.direction);
  const family=lower(candidate.family);
  if(direction==='privacy-leakage'&&/inversion|reconstruct/.test(family))return{
    tool:'ai-model-inversion',module:'ai_model_inversion',entrypoint:'analyzeModelInversion',
    contract:['positive fixture must reconstruct or expose the documented sensitive attribute beyond the public criterion','negative fixture must fail that reconstruction criterion','control fixture must use a non-sensitive or held-out reference']
  };
  if(direction==='backdoor-poisoning'&&/poison|label|loss|corrupt/.test(family))return{
    tool:'ai-poisoning-impact',module:'ai_poison_backdoor_validation',entrypoint:'analyzePoisoningImpact',
    contract:['positive fixture must show the documented poisoning impact','negative fixture must preserve the clean metric/labels','control fixture must distinguish poisoning from unrelated degradation']
  };
  return EVALUATOR_PROFILES[direction]||{
    tool:null,module:null,entrypoint:null,
    contract:['define a deterministic positive predicate from public evidence','define a deterministic negative predicate','define a specificity/control predicate']
  };
}

function fixture(role,candidate={},description=''){
  return{
    id:`${slug(candidate.event)}-${slug(candidate.challenge)}-${slug(candidate.family)}-${role}`,
    role,
    synthetic:true,
    description:text(description),
    payload:null,
    expected:{status:role==='positive'?'finding':'non-finding',predicate:'TODO: encode only the criterion supported by the cited public evidence'}
  };
}

function testSkeleton({candidate,evaluator,fixtures}){
  const title=`${candidate.event} / ${candidate.challenge} / ${candidate.family}`.replace(/'/g,"\\'");
  const tool=evaluator.tool||'TODO-evaluator-tool';
  return `'use strict';\n\nconst test=require('node:test');\nconst assert=require('node:assert/strict');\nconst {runTool}=require('../src/core/tool_router');\n\n// Generated skeleton only. Replace null payloads with synthetic fixtures derived from public evidence.\nconst FIXTURES=${JSON.stringify(fixtures,null,2)};\n\ntest.skip('${title} synthetic regression',()=>{\n  const positive=FIXTURES.find((row)=>row.role==='positive');\n  const negative=FIXTURES.find((row)=>row.role==='negative');\n  const control=FIXTURES.find((row)=>row.role==='control');\n  assert.ok(positive?.payload&&negative?.payload&&control?.payload,'fill synthetic positive/negative/control payloads first');\n  const positiveResult=runTool('${tool}',{input:positive.payload});\n  const negativeResult=runTool('${tool}',{input:negative.payload});\n  const controlResult=runTool('${tool}',{input:control.payload});\n  // TODO: assert the evidence-backed positive predicate.\n  assert.ok(positiveResult);\n  // TODO: assert negative/control stay non-finding and specificity holds.\n  assert.ok(negativeResult);\n  assert.ok(controlResult);\n});\n`;
}

function buildRegressionSkeleton(intakeResult={}){
  if(intakeResult?.schema!=='newcyber.ai-training-evidence-intake.v1')return{
    schema:'newcyber.ai-training-regression-skeleton.v1',status:'blocked',reason:'intake-result-required',skeleton:null
  };
  if(intakeResult.verdict!=='accept')return{
    schema:'newcyber.ai-training-regression-skeleton.v1',status:'blocked',reason:`intake-${intakeResult.verdict||'unknown'}`,missingEvidence:intakeResult.missingEvidence||[],blockers:intakeResult.blockers||[],skeleton:null
  };
  const candidate=intakeResult.candidate||{};
  const evaluator=evaluatorFor(candidate);
  const fixtures=[
    fixture('positive',candidate,candidate.verifier?.positive),
    fixture('negative',candidate,candidate.verifier?.negative),
    fixture('control',candidate,candidate.verifier?.control)
  ];
  const base=slug(`${candidate.event}-${candidate.challenge}-${candidate.family}`);
  const corpusEntry={
    id:`${base}-synthetic-regression`,
    event:candidate.event,
    challenge:candidate.challenge,
    direction:candidate.direction,
    family:candidate.family,
    evaluator:evaluator.tool,
    caseType:'public-training',
    provenance:{...(intakeResult.corpusDraft?.provenance||{})},
    coverage:candidate.mechanicsSummary,
    trainingPolicy:'public-evidence-plus-synthetic-regression-only',
    limitation:'Generated skeleton contains no original challenge secret, flag, hidden answer, unpublished trigger or private attachment. Fill fixtures only with synthetic values justified by cited public evidence.'
  };
  const artifactPlan={
    suggestedCorpusFile:`src/core/ai_training_${base.replace(/-/g,'_')}.js`,
    suggestedTestFile:`tests/${base}.test.js`,
    suggestedDocFile:`docs/${base}.md`
  };
  const completionGates=[
    'replace all three null fixture payloads with synthetic data only',
    'encode the positive predicate using only the cited public success condition',
    'prove negative and control remain non-finding',
    'remove test.skip before merge and make the generated regression deterministic',
    'retain provenance URL/evidence level separately from fixture values',
    'run the full repository test suite',
    'recompute curriculum quality, holdout and schedule and record the delta'
  ];
  return{
    schema:'newcyber.ai-training-regression-skeleton.v1',
    status:'ready',
    sourceIntake:{verdict:intakeResult.verdict,workOrder:intakeResult.workOrder||null},
    skeleton:{
      id:`sk-${base}`,
      candidate,
      evaluator,
      corpusEntry,
      fixtures,
      fixtureContract:{minimum:{positive:1,negative:1,control:1},syntheticOnly:true,contracts:[...evaluator.contract]},
      artifactPlan,
      testCode:testSkeleton({candidate,evaluator,fixtures}),
      completionGates
    },
    note:'This output is a scaffold, not a solved challenge or ready-to-merge corpus. Null fixture payloads are intentional so unsupported mechanics or real challenge secrets are never invented.'
  };
}

module.exports={EVALUATOR_PROFILES,evaluatorFor,fixture,testSkeleton,buildRegressionSkeleton};
