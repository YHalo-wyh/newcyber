'use strict';

const fs=require('fs/promises');
const crypto=require('crypto');
const v3=require('./challenge_verifier_contract_v3');

const MAX_PREDICATE_CONTRACTS=96;
const MAX_RETURN_EXPR=2048;

function text(value){return String(value??'');}
function stripOuterParens(value){
  let s=String(value||'').trim();
  while(s.startsWith('(')&&s.endsWith(')')){
    let depth=0,quote=null,escaped=false,wrap=true;
    for(let i=0;i<s.length;i+=1){
      const ch=s[i];
      if(quote){if(escaped)escaped=false;else if(ch==='\\')escaped=true;else if(ch===quote)quote=null;continue;}
      if(ch==='"'||ch==="'"||ch==='`'){quote=ch;continue;}
      if(ch==='(')depth+=1;else if(ch===')')depth-=1;
      if(depth===0&&i<s.length-1){wrap=false;break;}
    }
    if(!wrap)break;s=s.slice(1,-1).trim();
  }
  return s;
}
function splitConjunction(expr){
  const s=String(expr||'');const out=[];let start=0,depth=0,quote=null,escaped=false;
  for(let i=0;i<s.length;i+=1){
    const ch=s[i];
    if(quote){if(escaped)escaped=false;else if(ch==='\\')escaped=true;else if(ch===quote)quote=null;continue;}
    if(ch==='"'||ch==="'"||ch==='`'){quote=ch;continue;}
    if('([{'.includes(ch)){depth+=1;continue;}if(')]}'.includes(ch)){depth=Math.max(0,depth-1);continue;}
    if(depth!==0)continue;
    const rest=s.slice(i);
    const match=rest.match(/^(?:\s+and\s+|\s*&&\s*)/);
    if(!match)continue;
    out.push(s.slice(start,i).trim());i+=match[0].length-1;start=i+1;
  }
  out.push(s.slice(start).trim());return out.filter(Boolean);
}
function decodeStringLiteral(raw){
  const s=String(raw||'').trim();if(s.length<2)return null;const q=s[0];if(!['"',"'",'`'].includes(q)||s[s.length-1]!==q)return null;
  if(q==='"'){try{return JSON.parse(s);}catch{}}
  return s.slice(1,-1).replace(/\\([\\'"`nrt])/g,(_m,ch)=>({n:'\n',r:'\r',t:'\t'}[ch]??ch));
}
function parseScalar(raw){
  const s=String(raw||'').trim();
  const str=decodeStringLiteral(s);if(str!==null)return{kind:'string',value:str};
  if(/^(?:true|false)$/i.test(s))return{kind:'boolean',value:s.toLowerCase()==='true'};
  if(/^(?:none|null)$/i.test(s))return{kind:'null',value:null};
  if(/^-?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(s)){const n=Number(s);if(Number.isFinite(n))return{kind:'number',value:n};}
  return null;
}
function parseComparator(op){return {'===':'eq','==':'eq','!==':'ne','!=':'ne','>':'gt','>=':'gte','<':'lt','<=':'lte'}[op]||null;}
function pathFromAccessor(raw){
  const s=String(raw||'').trim();let m;
  if((m=s.match(/^([A-Za-z_$][\w$]*)\s*\[\s*(["'][^"']+["'])\s*\]$/)))return{root:m[1],path:[decodeStringLiteral(m[2])]};
  if((m=s.match(/^([A-Za-z_$][\w$]*)\.get\(\s*(["'][^"']+["'])\s*\)$/)))return{root:m[1],path:[decodeStringLiteral(m[2])]};
  if((m=s.match(/^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)$/)))return{root:m[1],path:[m[2]]};
  return null;
}
function parseAtom(raw){
  const atom=stripOuterParens(raw);let m;
  if((m=atom.match(/^len\(\s*([A-Za-z_$][\w$]*)\s*\)\s*(===|==|!==|!=|>=|<=|>|<)\s*(\d+)$/)))return{type:'raw-length',variable:m[1],op:parseComparator(m[2]),expected:Number(m[3])};
  if((m=atom.match(/^([A-Za-z_$][\w$]*)\.length\s*(===|==|!==|!=|>=|<=|>|<)\s*(\d+)$/)))return{type:'raw-length',variable:m[1],op:parseComparator(m[2]),expected:Number(m[3])};
  if((m=atom.match(/^([A-Za-z_$][\w$]*)\.(startswith|endswith|startsWith|endsWith|includes)\(\s*(["'`](?:\\.|[^\\])*?["'`])\s*\)$/))){
    const expected=decodeStringLiteral(m[3]);if(expected===null)return null;
    const kind=/starts/i.test(m[2])?'prefix':/ends/i.test(m[2])?'suffix':'contains';return{type:`raw-${kind}`,variable:m[1],expected};
  }
  if((m=atom.match(/^(["'`](?:\\.|[^\\])*?["'`])\s+in\s+([A-Za-z_$][\w$]*)$/))){const expected=decodeStringLiteral(m[1]);return expected===null?null:{type:'raw-contains',variable:m[2],expected};}
  if((m=atom.match(/^([A-Za-z_$][\w$]*)\s*(===|==|!==|!=)\s*(["'`](?:\\.|[^\\])*?["'`])$/))){const expected=decodeStringLiteral(m[3]);return expected===null?null:{type:'raw-scalar',variable:m[1],op:parseComparator(m[2]),expected};}

  if((m=atom.match(/^len\(\s*((?:[A-Za-z_$][\w$]*\s*\[\s*["'][^"']+["']\s*\])|(?:[A-Za-z_$][\w$]*\.get\(\s*["'][^"']+["']\s*\))|(?:[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*))\s*\)\s*(===|==|!==|!=|>=|<=|>|<)\s*(\d+)$/))){
    const access=pathFromAccessor(m[1]);return access?{type:'json-field-length',...access,op:parseComparator(m[2]),expected:Number(m[3])}:null;
  }
  if((m=atom.match(/^((?:[A-Za-z_$][\w$]*\s*\[\s*["'][^"']+["']\s*\])|(?:[A-Za-z_$][\w$]*\.get\(\s*["'][^"']+["']\s*\))|(?:[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*))\.length\s*(===|==|!==|!=|>=|<=|>|<)\s*(\d+)$/))){
    const access=pathFromAccessor(m[1]);return access?{type:'json-field-length',...access,op:parseComparator(m[2]),expected:Number(m[3])}:null;
  }
  if((m=atom.match(/^((?:[A-Za-z_$][\w$]*\s*\[\s*["'][^"']+["']\s*\])|(?:[A-Za-z_$][\w$]*\.get\(\s*["'][^"']+["']\s*\))|(?:[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*))\s*(===|==|!==|!=|>=|<=|>|<)\s*(.+)$/))){
    const access=pathFromAccessor(m[1]);const scalar=parseScalar(m[3]);return access&&scalar?{type:'json-field-scalar',...access,op:parseComparator(m[2]),expected:scalar.value,expectedKind:scalar.kind}:null;
  }
  return null;
}
function verifierNamed(file){return /(?:^|[_.-])(verif(?:y|ier)?|check(?:er)?|judge|scor(?:e|er)|validat(?:e|or)|submit)(?:[_.-]|$)/i.test(String(file||'').split('/').pop());}
function discoverPredicateContracts(file,body){
  if(!verifierNamed(file))return[];
  const out=[];const lines=String(body||'').split(/\r?\n/);
  for(let i=0;i<lines.length&&out.length<MAX_PREDICATE_CONTRACTS;i+=1){
    const line=lines[i];let match=line.match(/^\s*return\s+(.+?)\s*;?\s*$/);if(!match)continue;
    const expr=match[1].replace(/;\s*$/,'').trim();if(!expr||expr.length>MAX_RETURN_EXPR||/\bor\b|\|\|/.test(expr))continue;
    const rawAtoms=splitConjunction(expr);if(!rawAtoms.length||rawAtoms.length>16)continue;
    const atoms=rawAtoms.map(parseAtom);if(atoms.some((item)=>!item))continue;
    out.push({type:'predicate-return',file,line:i+1,confidence:'strong',expression:expr,atoms,evidence:line.trim().slice(0,MAX_RETURN_EXPR)});
  }
  return out;
}
function compare(actual,op,expected){
  if(op==='eq')return actual===expected;if(op==='ne')return actual!==expected;
  if(typeof actual!=='number'||typeof expected!=='number'||!Number.isFinite(actual)||!Number.isFinite(expected))return false;
  if(op==='gt')return actual>expected;if(op==='gte')return actual>=expected;if(op==='lt')return actual<expected;if(op==='lte')return actual<=expected;return false;
}
function parseJsonCandidate(value){try{return JSON.parse(value);}catch{return null;}}
function jsonField(root,path){let cur=root;for(const key of path||[]){if(cur===null||typeof cur!=='object'||!Object.prototype.hasOwnProperty.call(cur,key))return{found:false,value:undefined};cur=cur[key];}return{found:true,value:cur};}
function evaluateAtom(atom,value,jsonCache){
  if(atom.type==='raw-length')return{ok:compare(value.length,atom.op,atom.expected),actual:value.length};
  if(atom.type==='raw-prefix')return{ok:value.startsWith(atom.expected),actual:value.slice(0,Math.min(value.length,atom.expected.length))};
  if(atom.type==='raw-suffix')return{ok:value.endsWith(atom.expected),actual:value.slice(Math.max(0,value.length-atom.expected.length))};
  if(atom.type==='raw-contains')return{ok:value.includes(atom.expected),actual:value.includes(atom.expected)};
  if(atom.type==='raw-scalar')return{ok:compare(value,atom.op,atom.expected),actual:value};
  const parsed=jsonCache.value!==undefined?jsonCache.value:(jsonCache.value=parseJsonCandidate(value));if(parsed===null)return{ok:false,actual:'<invalid-json>',reason:'INVALID_JSON'};
  const field=jsonField(parsed,atom.path);if(!field.found)return{ok:false,actual:'<missing>',reason:'MISSING_FIELD'};
  if(atom.type==='json-field-length'){
    if(field.value==null||typeof field.value.length!=='number')return{ok:false,actual:'<no-length>',reason:'NO_LENGTH'};
    return{ok:compare(field.value.length,atom.op,atom.expected),actual:field.value.length};
  }
  if(atom.type==='json-field-scalar')return{ok:compare(field.value,atom.op,atom.expected),actual:field.value};
  return{ok:false,actual:'<unsupported>'};
}
function evaluatePredicateContracts(contracts,candidates){
  const verified=[];const attempts=[];
  for(const contract of contracts){
    for(const candidate of candidates){
      const value=text(candidate.value);if(!value||value.length>4*1024*1024)continue;
      const jsonCache={value:undefined};const checks=contract.atoms.map((atom)=>({...atom,...evaluateAtom(atom,value,jsonCache)}));
      const ok=checks.length>0&&checks.every((item)=>item.ok===true);
      attempts.push({contract:{file:contract.file,line:contract.line,type:contract.type},candidateSource:candidate.source,ok,checks:checks.map((item)=>({type:item.type,path:item.path||null,op:item.op||null,expected:item.expected,actual:item.actual,ok:item.ok}))});
      if(ok)verified.push({contract,value,candidateSource:candidate.source,method:'bounded-predicate-return',checks});
    }
  }
  return{verified,attempts:attempts.slice(0,128)};
}
function candidateDigest(value){const buffer=Buffer.from(text(value),'utf8');return{bytes:buffer.length,sha256:crypto.createHash('sha256').update(buffer).digest('hex')};}
function proofForMatch(match){
  if(!match)return null;const digest=candidateDigest(match.value);
  return{schema:'newcyber.result-proof.v1',method:match.method,candidateSource:match.candidateSource||match.source||'unknown',contract:{type:match.contract?.type||'unknown',file:match.contract?.file||null,line:match.contract?.line||null,expression:match.contract?.expression||null,confidence:match.contract?.confidence||null},candidate:digest,checks:(match.checks||[]).map((item)=>({type:item.type,path:item.path||null,op:item.op||null,expected:item.expected,actual:item.actual,ok:Boolean(item.ok)})),policy:{sourceExecuted:false,allPredicatesSupported:true,allPredicatesSatisfied:true}};
}

async function runVerifierContractAutopilot(root,analysis={},options={}){
  const first=await v3.runVerifierContractAutopilot(root,analysis,options);
  if(first.status==='verified'){
    const match=(first.verifiedMatches||[])[0]||null;const proof=match?proofForMatch(match):{schema:'newcyber.result-proof.v1',method:'static-exact-direct',candidateSource:'static-verifier',contract:{type:'exact',file:first.contracts?.[0]?.file||null,line:first.contracts?.[0]?.line||null},candidate:candidateDigest(first.result?.value||''),checks:[],policy:{sourceExecuted:false,allPredicatesSupported:true,allPredicatesSatisfied:true}};
    return{...first,schema:'newcyber.challenge-verifier-contract.v4',proof,summary:{...(first.summary||{}),predicateContracts:0,predicateAttempts:0,predicateVerified:0}};
  }
  const files=await v3.walkSources(root,options);const predicates=[];const errors=[];
  for(const file of files){let body;try{body=await fs.readFile(file.path,'utf8');}catch(error){errors.push({file:file.relative,error:String(error?.message||error).slice(0,240)});continue;}predicates.push(...discoverPredicateContracts(file.relative,body));if(predicates.length>=MAX_PREDICATE_CONTRACTS)break;}
  const seen=new Set();const candidates=[];for(const item of [...v3.extraCandidateValues(analysis),...v3.candidateValues(analysis)]){const key=`${item.source}\u0000${item.value}`;if(seen.has(key))continue;seen.add(key);candidates.push(item);if(candidates.length>=1024)break;}
  const evaluated=evaluatePredicateContracts(predicates,candidates);const verified=evaluated.verified[0]||null;
  const contracts=[...(first.contracts||[]),...predicates].slice(0,224);
  if(!verified)return{...first,schema:'newcyber.challenge-verifier-contract.v4',contracts,predicateContracts:predicates,predicateAttempts:evaluated.attempts,proof:null,errors:[...(first.errors||[]),...errors].slice(0,32),summary:{...(first.summary||{}),contracts:contracts.length,predicateContracts:predicates.length,predicateAttempts:evaluated.attempts.length,predicateVerified:0},next:predicates.length?'已恢复受限 return-predicate checker；现有候选尚未完整满足全部静态谓词。':'未发现可安全解释的完整 return-predicate checker。'};
  const proof=proofForMatch(verified);const result={value:verified.value,payload:verified.value,verified:true,confidence:'verified',kind:v3.flagLike(verified.value)?'flag':'answer',source:`bounded predicate @ ${verified.contract.file}:${verified.contract.line}`,proof};
  const finding={id:'bounded-checker-predicate-satisfied',severity:'high',title:'受限 Checker Contract Interpreter 已形成验证闭环',file:verified.contract.file,line:verified.contract.line,evidence:`return ${verified.contract.expression} <- ${verified.candidateSource}`,meaning:'checker 的 return 表达式只包含 NewCyber 明确支持的静态谓词，当前候选满足全部谓词；未执行题目源码，可升级为 verified。'};
  return{...first,schema:'newcyber.challenge-verifier-contract.v4',status:'verified',result,proof,contracts,predicateContracts:predicates,predicateAttempts:evaluated.attempts,verifiedMatches:[...(first.verifiedMatches||[]),verified].slice(0,32),findings:[...(first.findings||[]).filter((item)=>item.id!=='static-verifier-contract-discovered'),finding],errors:[...(first.errors||[]),...errors].slice(0,32),summary:{...(first.summary||{}),contracts:contracts.length,verifiedMatches:(first.summary?.verifiedMatches||0)+1,predicateContracts:predicates.length,predicateAttempts:evaluated.attempts.length,predicateVerified:1},next:'受限 checker return-predicate 已完整满足；结果具备静态 proof，可视为 verified。'};
}

module.exports={...v3,stripOuterParens,splitConjunction,decodeStringLiteral,parseScalar,parseAtom,discoverPredicateContracts,evaluateAtom,evaluatePredicateContracts,candidateDigest,proofForMatch,runVerifierContractAutopilot};
