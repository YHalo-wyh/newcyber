'use strict';

const SECRET_PATTERNS=Object.freeze([
  {id:'ctf-flag',re:/\b(?:flag|ctf)\s*\{[^}\n]{3,256}\}/i},
  {id:'private-key',re:/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i},
  {id:'jwt',re:/\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\b/},
  {id:'github-token',re:/\bgh[pousr]_[A-Za-z0-9]{20,}\b/},
  {id:'openai-key',re:/\bsk-[A-Za-z0-9_-]{20,}\b/},
  {id:'aws-access-key',re:/\bAKIA[0-9A-Z]{16}\b/}
]);
const OPS=Object.freeze(['eq','neq','truthy','falsy','exists','not-exists','gt','gte','lt','lte','includes','not-includes','length-eq']);

function text(value){return value==null?'':String(value).trim();}
function clone(value){return value==null?value:JSON.parse(JSON.stringify(value));}
function getPath(value,path){
  if(!text(path))return value;
  return text(path).split('.').reduce((cur,key)=>cur==null?undefined:cur[key],value);
}
function scanSecrets(value,path='payload',hits=[]){
  if(value==null)return hits;
  if(Array.isArray(value)){value.forEach((item,index)=>scanSecrets(item,`${path}[${index}]`,hits));return hits;}
  if(typeof value==='object'){
    for(const [key,item] of Object.entries(value))scanSecrets(item,`${path}.${key}`,hits);
    return hits;
  }
  const raw=String(value);
  for(const pattern of SECRET_PATTERNS)if(pattern.re.test(raw))hits.push({id:pattern.id,path});
  return hits;
}
function normalizeAssertion(assertion={}){
  return{path:text(assertion.path),op:text(assertion.op)||'eq',value:clone(assertion.value)};
}
function evaluateAssertion(result,assertion={}){
  const a=normalizeAssertion(assertion);const actual=getPath(result,a.path);let pass=false;
  switch(a.op){
    case'eq':pass=JSON.stringify(actual)===JSON.stringify(a.value);break;
    case'neq':pass=JSON.stringify(actual)!==JSON.stringify(a.value);break;
    case'truthy':pass=Boolean(actual);break;
    case'falsy':pass=!actual;break;
    case'exists':pass=actual!==undefined&&actual!==null;break;
    case'not-exists':pass=actual===undefined||actual===null;break;
    case'gt':pass=Number(actual)>Number(a.value);break;
    case'gte':pass=Number(actual)>=Number(a.value);break;
    case'lt':pass=Number(actual)<Number(a.value);break;
    case'lte':pass=Number(actual)<=Number(a.value);break;
    case'includes':pass=Array.isArray(actual)?actual.some((x)=>JSON.stringify(x)===JSON.stringify(a.value)):String(actual??'').includes(String(a.value??''));break;
    case'not-includes':pass=Array.isArray(actual)?!actual.some((x)=>JSON.stringify(x)===JSON.stringify(a.value)):!String(actual??'').includes(String(a.value??''));break;
    case'length-eq':pass=(actual?.length??-1)===Number(a.value);break;
    default:pass=false;
  }
  return{...a,actual:clone(actual),pass,supported:OPS.includes(a.op)};
}
function validateSkeleton(input={}){
  const errors=[];
  if(input?.schema!=='newcyber.ai-training-regression-skeleton.v1')errors.push('regression-skeleton-required');
  if(input?.status!=='ready')errors.push('skeleton-not-ready');
  const skeleton=input?.skeleton;
  if(!skeleton||typeof skeleton!=='object')errors.push('missing-skeleton');
  if(!text(skeleton?.evaluator?.tool))errors.push('missing-evaluator-tool');
  const fixtures=Array.isArray(skeleton?.fixtures)?skeleton.fixtures:[];
  for(const role of ['positive','negative','control']){
    const rows=fixtures.filter((row)=>row?.role===role);
    if(rows.length!==1)errors.push(`fixture-${role}-count-${rows.length}`);
  }
  return{pass:errors.length===0,errors};
}
function validateFixture(row={}){
  const errors=[];
  if(row.synthetic!==true)errors.push('fixture-not-marked-synthetic');
  if(row.payload==null)errors.push('fixture-payload-missing');
  const assertions=Array.isArray(row?.expected?.assertions)?row.expected.assertions:[];
  if(!assertions.length)errors.push('fixture-assertions-missing');
  for(const [index,a] of assertions.entries())if(!OPS.includes(text(a?.op)||'eq'))errors.push(`assertion-${index}-unsupported-op`);
  if(/TODO/i.test(text(row?.expected?.predicate)))errors.push('fixture-predicate-still-todo');
  const secretHits=scanSecrets(row.payload,`${row.role||'fixture'}.payload`);
  if(secretHits.length)errors.push('secret-pattern-detected');
  return{pass:errors.length===0,errors,secretHits,assertions:assertions.map(normalizeAssertion)};
}
function renderCorpusModule(corpusEntry={},fixtures=[]){
  const entry=JSON.stringify({...corpusEntry,fixtureIds:fixtures.map((row)=>row.id)},null,2);
  const fixtureText=JSON.stringify(fixtures.map((row)=>({id:row.id,role:row.role,synthetic:true,payload:row.payload,expected:row.expected})),null,2);
  return `'use strict';\n\nconst CORPUS_ENTRY=${entry};\nconst FIXTURES=${fixtureText};\n\nfunction getTrainingCorpus(){return [CORPUS_ENTRY];}\nfunction getSyntheticFixtures(){return FIXTURES;}\n\nmodule.exports={CORPUS_ENTRY,FIXTURES,getTrainingCorpus,getSyntheticFixtures};\n`;
}
function renderTestFile(skeleton={},fixtures=[]){
  const tool=skeleton.evaluator.tool;
  const title=`${skeleton.candidate?.event||''} / ${skeleton.candidate?.challenge||''} / ${skeleton.candidate?.family||''}`.replace(/'/g,"\\'");
  const fixtureText=JSON.stringify(fixtures,null,2);
  return `'use strict';\n\nconst test=require('node:test');\nconst assert=require('node:assert/strict');\nconst {runTool}=require('../src/core/tool_router');\n\nconst FIXTURES=${fixtureText};\n\nfunction getPath(value,path){return String(path||'').split('.').filter(Boolean).reduce((cur,key)=>cur==null?undefined:cur[key],value);}\nfunction check(result,a){const actual=getPath(result,a.path);switch(a.op||'eq'){case'eq':return JSON.stringify(actual)===JSON.stringify(a.value);case'neq':return JSON.stringify(actual)!==JSON.stringify(a.value);case'truthy':return Boolean(actual);case'falsy':return !actual;case'exists':return actual!==undefined&&actual!==null;case'not-exists':return actual===undefined||actual===null;case'gt':return Number(actual)>Number(a.value);case'gte':return Number(actual)>=Number(a.value);case'lt':return Number(actual)<Number(a.value);case'lte':return Number(actual)<=Number(a.value);case'includes':return Array.isArray(actual)?actual.some((x)=>JSON.stringify(x)===JSON.stringify(a.value)):String(actual??'').includes(String(a.value??''));case'not-includes':return Array.isArray(actual)?!actual.some((x)=>JSON.stringify(x)===JSON.stringify(a.value)):!String(actual??'').includes(String(a.value??''));case'length-eq':return (actual?.length??-1)===Number(a.value);default:return false;}}\n\ntest('${title} synthetic regression',()=>{\n  for(const fixture of FIXTURES){\n    assert.equal(fixture.synthetic,true);\n    const result=runTool('${tool}',{input:fixture.payload});\n    for(const a of fixture.expected.assertions||[])assert.ok(check(result,a),fixture.role+' assertion failed: '+JSON.stringify(a));\n  }\n});\n`;
}
function renderDoc(skeleton={},dryRuns=[]){
  const c=skeleton.candidate||{};const p=skeleton.corpusEntry?.provenance||{};
  return `# Synthetic regression: ${c.challenge||skeleton.id}\n\n- Event: ${c.event||''}\n- Direction: ${c.direction||''}\n- Family: ${c.family||''}\n- Evaluator: ${skeleton.evaluator?.tool||''}\n- Public source: ${p.url||''}\n- Evidence level: ${p.evidenceLevel||''}\n\nThis regression uses synthetic fixtures only. It must not contain original flags, private attachments, hidden answers, unpublished triggers or credentials.\n\n## Dry-run\n${dryRuns.map((row)=>`- ${row.role}: ${row.pass?'PASS':'FAIL'} (${row.assertions.filter((x)=>x.pass).length}/${row.assertions.length})`).join('\n')}\n`;
}

function materializeRegression(input={},executeTool){
  const validation=validateSkeleton(input);
  if(!validation.pass)return{schema:'newcyber.ai-training-regression-materializer.v1',status:'blocked',readyToCommit:false,checks:{skeleton:validation},errors:[...validation.errors],artifacts:null};
  const skeleton=clone(input.skeleton);const fixtures=skeleton.fixtures;
  const fixtureChecks=fixtures.map((row)=>({role:row.role,id:row.id,...validateFixture(row)}));
  const preflightErrors=fixtureChecks.flatMap((row)=>row.errors.map((error)=>`${row.role}:${error}`));
  if(preflightErrors.length)return{schema:'newcyber.ai-training-regression-materializer.v1',status:'blocked',readyToCommit:false,checks:{skeleton:validation,fixtures:fixtureChecks},errors:preflightErrors,artifacts:null};
  if(typeof executeTool!=='function')return{schema:'newcyber.ai-training-regression-materializer.v1',status:'blocked',readyToCommit:false,checks:{skeleton:validation,fixtures:fixtureChecks},errors:['evaluator-executor-required'],artifacts:null};
  const dryRuns=[];const runtimeErrors=[];
  for(const row of fixtures){
    let result;
    try{result=executeTool(skeleton.evaluator.tool,{input:clone(row.payload)});}catch(error){runtimeErrors.push(`${row.role}:evaluator-error:${text(error?.message||error)}`);dryRuns.push({role:row.role,id:row.id,pass:false,error:text(error?.message||error),assertions:[]});continue;}
    if(result&&typeof result.then==='function'){runtimeErrors.push(`${row.role}:async-evaluator-not-supported`);dryRuns.push({role:row.role,id:row.id,pass:false,error:'async-evaluator-not-supported',assertions:[]});continue;}
    const assertions=(row.expected.assertions||[]).map((a)=>evaluateAssertion(result,a));
    dryRuns.push({role:row.role,id:row.id,pass:assertions.length>0&&assertions.every((a)=>a.pass),assertions,result:clone(result)});
  }
  const failed=dryRuns.filter((row)=>!row.pass).map((row)=>`${row.role}:dry-run-failed`);
  const errors=[...runtimeErrors,...failed];
  if(errors.length)return{schema:'newcyber.ai-training-regression-materializer.v1',status:'dry-run-failed',readyToCommit:false,checks:{skeleton:validation,fixtures:fixtureChecks,dryRuns},errors,artifacts:null};
  const artifactPlan=skeleton.artifactPlan||{};
  const artifacts={
    corpus:{path:artifactPlan.suggestedCorpusFile||`src/core/ai_training_${skeleton.id||'materialized'}.js`,content:renderCorpusModule(skeleton.corpusEntry,fixtures)},
    test:{path:artifactPlan.suggestedTestFile||`tests/${skeleton.id||'materialized'}.test.js`,content:renderTestFile(skeleton,fixtures)},
    doc:{path:artifactPlan.suggestedDocFile||`docs/${skeleton.id||'materialized'}.md`,content:renderDoc(skeleton,dryRuns)}
  };
  return{
    schema:'newcyber.ai-training-regression-materializer.v1',status:'ready-to-commit',readyToCommit:true,
    checks:{skeleton:validation,fixtures:fixtureChecks,dryRuns},errors:[],artifacts,
    completionGates:['write artifacts without changing their validated fixture payloads','run npm test after writing artifacts','register the corpus only after repository tests pass','recompute curriculum quality, holdout and schedule after integration'],
    note:'ready-to-commit means the supplied synthetic fixtures passed the selected local evaluator and declared assertions. It does not prove public-source truth beyond the evidence intake gate.'
  };
}

module.exports={SECRET_PATTERNS,OPS,getPath,scanSecrets,normalizeAssertion,evaluateAssertion,validateSkeleton,validateFixture,renderCorpusModule,renderTestFile,renderDoc,materializeRegression};
