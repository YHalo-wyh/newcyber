'use strict';

const BLUEPRINTS=Object.freeze({
  'prompt-llm-security':{
    sourceKinds:['official challenge archive','organizer challenge page','public writeup with reproducible transcript'],
    familyThemes:['system-prompt-leakage','tool-policy-bypass','rag-context-exfiltration','false-premise-hallucination','multi-turn-auth-context-confusion'],
    requiredEvidence:['challenge objective or public task description','observable prompt/tool interaction shape','publicly described success condition','negative-control behavior or safe baseline'],
    verifier:['synthetic canary or judge predicate','authorized-vs-unauthorized tool-call comparison','negative prompt/control that must not trigger the same finding']
  },
  'adversarial-example':{
    sourceKinds:['official challenge archive','public writeup with scoring rule','public benchmark/challenge repository'],
    familyThemes:['top-k-ranking-perturbation','margin-collapse','targeted-misclassification','query-budget-search','transfer-attack-ranking'],
    requiredEvidence:['public scoring or ranking condition','input/output shape or logits-like evidence','perturbation or candidate constraints','clean control/baseline'],
    verifier:['deterministic synthetic logits or score matrix','ranking/margin predicate','clean-versus-adversarial control']
  },
  'privacy-leakage':{
    sourceKinds:['official challenge archive','organizer/public writeup','public privacy benchmark or paper artifact'],
    familyThemes:['membership-inference','sensitive-output-leakage','model-inversion','memorization-canary','confidence-leakage'],
    requiredEvidence:['public threat model','member/non-member or sensitive/non-sensitive distinction','observable model outputs or loss-like statistic','negative control or held-out reference'],
    verifier:['AUC/advantage/TPR threshold or exact leakage predicate','balanced synthetic positive/negative rows','control split that must remain below finding threshold']
  },
  'model-extraction':{
    sourceKinds:['official challenge archive','public model-stealing benchmark','public writeup with query/response protocol'],
    familyThemes:['label-only-extraction','probability-vector-extraction','active-query-stealing','decision-boundary-recovery','holdout-fidelity'],
    requiredEvidence:['public query interface shape','target response type','public success metric or fidelity notion','held-out evaluation concept'],
    verifier:['synthetic victim transcript','query-budget accounting','holdout fidelity or agreement threshold','negative low-fidelity control']
  },
  'backdoor-poisoning':{
    sourceKinds:['official challenge archive','organizer challenge repository','public writeup with trigger/poison behavior described'],
    familyThemes:['image-trigger-backdoor','label-swap-poisoning','loss-history-poison-ranking','feature-trigger-backdoor','clean-label-poisoning'],
    requiredEvidence:['public clean-versus-triggered or clean-versus-poisoned behavior','target-label or anomaly objective','specificity/control condition','publicly described detection or activation criterion'],
    verifier:['synthetic clean/triggered/control predictions','target ASR or poisoning-impact predicate','specificity control that rejects generic corruption']
  },
  'dataset-pipeline-security':{
    sourceKinds:['official challenge archive','public dataset-security benchmark','public writeup with dataset transformation mechanics'],
    familyThemes:['label-corruption','schema-tampering','train-test-leakage','feature-poisoning','sample-selection-bias'],
    requiredEvidence:['public dataset schema or transformation description','before/after label or feature relation','expected model/data impact','clean control dataset'],
    verifier:['synthetic CSV/JSON fixture','schema/label invariant checks','impact metric plus negative control']
  },
  'infra-supply-chain':{
    sourceKinds:['official challenge archive','public vulnerability advisory','organizer/public writeup with artifact loading flow'],
    familyThemes:['unsafe-deserialization','dependency-confusion','model-artifact-tampering','plugin-tool-supply-chain','untrusted-model-loader'],
    requiredEvidence:['public artifact/dependency loading path','unsafe trust boundary or resolution behavior','reproducible indicator in source/config/metadata','safe alternative or negative control'],
    verifier:['static source/config predicate','synthetic benign-versus-unsafe artifact metadata','negative control that uses safe loading/resolution']
  }
});

function text(value){return value==null?'':String(value).trim();}
function slug(value){return text(value).toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/g,'-').replace(/^-+|-+$/g,'').slice(0,100)||'item';}
function uniq(values=[]){return [...new Set(values.map(text).filter(Boolean))];}
function rowsFor(cases=[],direction){return (Array.isArray(cases)?cases:[]).filter((row)=>text(row?.direction)===direction);}
function existingValues(rows,key){return uniq(rows.map((row)=>row?.[key])).sort((a,b)=>a.localeCompare(b));}

function chooseFamilyThemes(direction,rows=[],count=3){
  const blueprint=BLUEPRINTS[direction]||{familyThemes:[`${direction}-new-family`]};
  const existing=existingValues(rows,'family').map((x)=>x.toLowerCase());
  const fresh=blueprint.familyThemes.filter((theme)=>!existing.some((family)=>family.includes(theme)||theme.includes(family)));
  const chosen=[...fresh,...blueprint.familyThemes.filter((theme)=>!fresh.includes(theme))];
  return chosen.slice(0,Math.max(1,count));
}

function acceptanceGates(task={}){
  const target=task.targets||{};
  const gates=[
    {id:'public-provenance',requirement:'Every accepted case has a public source URL and evidence tier; unsupported mechanics are rejected.'},
    {id:'synthetic-verifier',requirement:'Regression fixture uses synthetic canary/logits/labels/predictions instead of real flags, keys, hidden answers or private challenge data.'},
    {id:'negative-control',requirement:'Each new family has at least one deterministic negative/control case that must remain non-finding.'},
    {id:'dedupe-signature',requirement:'New event/challenge/family signature must not merely duplicate an existing signature.'}
  ];
  if((target.newEvents||0)>0)gates.push({id:'event-diversity',requirement:`Add at least ${target.newEvents} distinct event(s) for this direction before considering the event debt closed.`});
  if((target.newFamilies||0)>0)gates.push({id:'family-diversity',requirement:`Add at least ${target.newFamilies} distinct family/families not already represented in this direction.`});
  if((target.effectiveCaseDebt||0)>0)gates.push({id:'effective-coverage',requirement:`Raise provenance-weighted effective coverage by at least ${Number(target.effectiveCaseDebt).toFixed(3)} unless stronger diversity evidence closes readiness first.`});
  if((target.unseenFamilyHoldout||0)>0)gates.push({id:'unseen-family-holdout',requirement:'After integration, at least one clean leave-one-event-out plan must contain a family unseen in its training split.'});
  gates.push({id:'quality-recompute',requirement:'Recompute quality + holdout + schedule; the work order is complete only when the targeted debt decreases without new leakage.'});
  return gates;
}

function buildWorkOrder(task={},cases=[]){
  const direction=text(task.direction)||'ai-general';
  const rows=rowsFor(cases,direction);
  const blueprint=BLUEPRINTS[direction]||{
    sourceKinds:['official challenge archive','public benchmark or writeup'],
    familyThemes:[`${direction}-new-family`],
    requiredEvidence:['public problem statement','observable behavior','negative control'],
    verifier:['deterministic synthetic fixture','positive and negative predicate']
  };
  const familyCount=Math.max(1,Number(task.targets?.newFamilies)||1);
  const familyThemes=chooseFamilyThemes(direction,rows,Math.min(4,familyCount+1));
  const currentEvents=existingValues(rows,'event');
  const currentFamilies=existingValues(rows,'family');
  const order={
    id:`wo-${String(task.rank||0).padStart(2,'0')}-${slug(direction)}`,
    rank:Number(task.rank)||0,
    direction,
    priority:task.priority||'medium',
    score:Number(task.score)||0,
    objective:{
      nextAction:task.nextAction||null,
      acquisitionMode:task.acquisitionMode||null,
      targets:{...(task.targets||{})}
    },
    acquisition:{
      preferredSourceKinds:[...blueprint.sourceKinds],
      familyThemes,
      avoidExisting:{events:currentEvents.slice(0,32),families:currentFamilies.slice(0,32)},
      searchHints:[
        `${direction} CTF challenge writeup`,
        `${familyThemes[0]} challenge benchmark`,
        `${direction} official challenge archive`
      ],
      requiredEvidence:[...blueprint.requiredEvidence]
    },
    regressionDesign:{
      verifier:[...blueprint.verifier],
      fixturePolicy:['derive only structure/mechanics supported by public evidence','replace real secrets/flags/triggers with synthetic values','include positive, negative and specificity/control cases','keep provenance metadata separate from verifier fixture'],
      minimumCases:{positive:1,negative:1,control:1}
    },
    acceptanceGates:acceptanceGates(task),
    prohibited:['real flags or challenge secrets','private or leaked challenge attachments','unpublished exploit keys or hidden answers','invented challenge mechanics not supported by public evidence','copying a public answer as the regression oracle'],
    completionProof:['new normalized corpus entries','deterministic regression test','provenance metadata','quality delta','holdout delta','updated schedule rank']
  };
  return order;
}

function buildTrainingWorkOrders({schedule={},cases=[]}={},options={}){
  const queue=Array.isArray(schedule?.queue)?schedule.queue:[];
  const limit=Math.max(1,Math.min(16,Number(options.limit)||5));
  const onlyDirection=text(options.direction);
  const selected=queue.filter((item)=>!onlyDirection||item.direction===onlyDirection).slice(0,limit);
  const orders=selected.map((task)=>buildWorkOrder(task,cases));
  return{
    schema:'newcyber.ai-training-work-orders.v1',
    summary:{
      orders:orders.length,
      topOrder:orders[0]?.id||null,
      topDirection:orders[0]?.direction||null,
      priorities:orders.reduce((acc,row)=>{acc[row.priority]=(acc[row.priority]||0)+1;return acc;},{})
    },
    orders,
    gates:{
      publicEvidenceRequired:true,
      syntheticRegressionOnly:true,
      negativeControlRequired:true,
      dedupeBeforeAcceptance:true,
      recomputeQualityHoldoutScheduleAfterIntegration:true
    },
    note:'Work orders operationalize scheduler debt into evidence-acquisition and deterministic-regression tasks. They are planning artifacts, not claims that matching public challenges already exist.'
  };
}

module.exports={BLUEPRINTS,chooseFamilyThemes,acceptanceGates,buildWorkOrder,buildTrainingWorkOrders};
