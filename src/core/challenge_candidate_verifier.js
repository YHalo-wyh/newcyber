'use strict';

const crypto=require('node:crypto');
const path=require('node:path');

const MAX_SOURCES=64;
const MAX_SOURCE_BYTES=2*1024*1024;
const MAX_SPECS=64;
const MAX_SETS=256;

function list(value){return Array.isArray(value)?value:[];}
function numericId(value){if(typeof value==='number'&&Number.isInteger(value))return value;const base=path.basename(String(value??''));const match=base.match(/^(\d+)(?:\.[^.]+)?$/);return match?Number(match[1]):null;}
function numericIds(ids){const out=list(ids).map(numericId);return out.some((x)=>x===null)?null:out;}
function digestLength(algorithm){return algorithm==='md5'?32:algorithm==='sha256'?64:null;}
function hash(algorithm,value){return crypto.createHash(algorithm).update(value).digest('hex');}
function unique(values){return[...new Set(values)];}

function serializeIds(ids,recipe){
  const numeric=numericIds(ids);if(!numeric)return null;const values=recipe.sorted===false?numeric.slice():numeric.slice().sort((a,b)=>a-b);
  switch(recipe.serialization){
    case'python-list':return`[${values.join(', ')}]`;
    case'json-compact':return`[${values.join(',')}]`;
    case'csv':return values.join(',');
    case'newline':return values.join('\n');
    case'concat':return values.join('');
    case'space':return values.join(' ');
    default:return null;
  }
}
function submissionValue(match){const base=match.spec.output==='digest'?match.digest:match.serialized;const wrapper=match.spec.wrapper;if(!wrapper)return base;return`${wrapper.prefix||''}${base}${wrapper.suffix||''}`;}

function serializationEvidence(body){
  const recipes=[];const add=(serialization,sorted,evidence)=>{if(!recipes.some((x)=>x.serialization===serialization&&x.sorted===sorted))recipes.push({serialization,sorted,evidence});};
  if(/(?:str|repr)\s*\(\s*sorted\s*\(/i.test(body))add('python-list',true,'str/repr(sorted(...))');
  if(/json\.dumps\s*\(\s*sorted\s*\([^)]*\)\s*(?:,\s*separators\s*=\s*\(\s*["']\s*,\s*["']\s*,\s*["']\s*:\s*["']\s*\))?/i.test(body)){
    if(/separators\s*=/.test(body))add('json-compact',true,'json.dumps(sorted(...), separators=...)');else add('python-list',true,'json.dumps(sorted(...)) default integer list');
  }
  const joinPatterns=[
    {re:/["']\s*,\s*["']\.join\s*\([^\n]{0,220}?sorted\s*\(/i,serialization:'csv',evidence:"','.join(...sorted(...))"},
    {re:/["']\\n["']\.join\s*\([^\n]{0,220}?sorted\s*\(/i,serialization:'newline',evidence:"'\\n'.join(...sorted(...))"},
    {re:/["']\s*["']\.join\s*\([^\n]{0,220}?sorted\s*\(/i,serialization:'concat',evidence:"''.join(...sorted(...))"},
    {re:/["']\s+["']\.join\s*\([^\n]{0,220}?sorted\s*\(/i,serialization:'space',evidence:"' '.join(...sorted(...))"}
  ];
  for(const item of joinPatterns)if(item.re.test(body))add(item.serialization,true,item.evidence);
  if(/(?:str|repr)\s*\(\s*(?:ids|indices|indexes|answer|result|candidates)\s*\)/i.test(body)&&!/sorted\s*\(/i.test(body))add('python-list',false,'str(ids-like variable) without sorted');
  return recipes;
}
function algorithmEvidence(body){const out=[];if(/(?:hashlib\.)?md5\s*\(/i.test(body))out.push({algorithm:'md5',evidence:'md5(...)'});if(/(?:hashlib\.)?sha256\s*\(/i.test(body)||/sha-?256/i.test(body))out.push({algorithm:'sha256',evidence:'sha256(...)'});return out;}
function digestLiterals(body,algorithm){const length=digestLength(algorithm);if(!length)return[];const re=new RegExp(`\\b[a-fA-F0-9]{${length}}\\b`,'g');return unique((body.match(re)||[]).map((x)=>x.toLowerCase()));}
function wrapperEvidence(body){
  const format=/([A-Za-z][A-Za-z0-9_-]{1,24}\{)\s*(?:\{\}|%s|[^}\n]{0,80}?(?:hexdigest|digest|hash|answer|result))\s*(\})/i.exec(body);if(format)return{prefix:format[1],suffix:format[2],evidence:format[0].slice(0,120)};
  if(/flag\s*=\s*f?["'][^"']*\{[^"']*(?:digest|hexdigest|hash)/i.test(body)){const m=/([A-Za-z][A-Za-z0-9_-]{1,24}\{)/.exec(body);if(m)return{prefix:m[1],suffix:'}',evidence:'flag f-string/hash wrapper'};}
  return null;
}
function hashOutputEvidence(body){return/(?:hexdigest\s*\(\)|\.digest\s*\(\)\.hex\s*\(\))/i.test(body)?'digest':'serialized';}

function discoverVerifierSpecs(sources){
  const specs=[];
  for(const source of list(sources).slice(0,MAX_SOURCES)){
    const file=String(source.file||source.path||'source');const body=String(source.text||source.content||'').slice(0,MAX_SOURCE_BYTES);if(!body)continue;
    const algorithms=algorithmEvidence(body),serializations=serializationEvidence(body);if(!algorithms.length||!serializations.length)continue;const wrapper=wrapperEvidence(body);const output=hashOutputEvidence(body);
    for(const algo of algorithms){const literals=digestLiterals(body,algo.algorithm);if(literals.length!==1)continue;for(const recipe of serializations){specs.push({file,algorithm:algo.algorithm,digest:literals[0],serialization:recipe.serialization,sorted:recipe.sorted,output,wrapper,evidence:{algorithm:algo.evidence,serialization:recipe.evidence,digest:'unique literal of matching length'}});if(specs.length>=MAX_SPECS)return specs;}}
  }
  return specs;
}

function verifyCandidateSets(candidateSets,sources){
  const specs=discoverVerifierSpecs(sources),matches=[],attempts=[];
  for(const set of list(candidateSets).slice(0,MAX_SETS))for(const spec of specs){const serialized=serializeIds(set.ids,spec);if(serialized===null)continue;const computed=hash(spec.algorithm,serialized);attempts.push({rank:set.rank,algorithm:spec.algorithm,serialization:spec.serialization,sorted:spec.sorted,computed,expected:spec.digest,file:spec.file});if(computed===spec.digest){const match={rank:set.rank,ids:set.ids,score:set.score,serialized,digest:computed,spec};match.submission=submissionValue(match);matches.push(match);}}
  matches.sort((a,b)=>a.rank-b.rank||String(a.spec.file).localeCompare(String(b.spec.file)));
  return{schema:'newcyber.challenge-candidate-verifier.v1',status:matches.length?'verified':specs.length?'checked':'not-detected',specs,matches:matches.slice(0,32),attempts:attempts.slice(0,512)};
}

module.exports={numericId,serializeIds,serializationEvidence,discoverVerifierSpecs,verifyCandidateSets};
