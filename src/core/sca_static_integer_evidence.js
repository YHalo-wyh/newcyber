'use strict';

const MAX_STATIC_INTEGER=1_000_000_000;
const MAX_EXPR_LENGTH=256;
const MAX_ASSIGNMENTS=2048;
const MAX_RESOLVE_ROUNDS=32;

function stripComments(text){
  return String(text||'').split(/\r?\n/).map((line)=>line.replace(/#.*$/,'')).join('\n');
}
function normalizeIntegerLiteral(raw){
  const text=String(raw||'').replace(/_/g,'');
  let value;
  if(/^0[xX][0-9a-fA-F]+$/.test(text))value=Number.parseInt(text.slice(2),16);
  else if(/^0[bB][01]+$/.test(text))value=Number.parseInt(text.slice(2),2);
  else if(/^0[oO][0-7]+$/.test(text))value=Number.parseInt(text.slice(2),8);
  else if(/^\d+$/.test(text))value=Number(text);
  else return null;
  if(!Number.isSafeInteger(value)||Math.abs(value)>MAX_STATIC_INTEGER)return null;
  return value;
}
function tokenize(expr){
  const text=String(expr||'').trim();
  if(!text||text.length>MAX_EXPR_LENGTH)return null;
  const tokens=[];let index=0;
  while(index<text.length){
    const ws=text.slice(index).match(/^\s+/);if(ws){index+=ws[0].length;continue;}
    const num=text.slice(index).match(/^(?:0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*|\d(?:_?\d)*)/);
    if(num){tokens.push({type:'number',value:num[0]});index+=num[0].length;continue;}
    const ident=text.slice(index).match(/^[A-Za-z_]\w*/);
    if(ident){tokens.push({type:'ident',value:ident[0]});index+=ident[0].length;continue;}
    const op=['**','//','<<','>>','+','-','*','/','%','(',')'].find((candidate)=>text.startsWith(candidate,index));
    if(!op)return null;
    tokens.push({type:'op',value:op});index+=op.length;
  }
  return tokens;
}
function bounded(value){return Number.isSafeInteger(value)&&Math.abs(value)<=MAX_STATIC_INTEGER?value:null;}
function applyBinary(op,left,right){
  if(!Number.isSafeInteger(left)||!Number.isSafeInteger(right))return null;
  let value=null;
  if(op==='+')value=left+right;
  else if(op==='-')value=left-right;
  else if(op==='*')value=left*right;
  else if(op==='/'||op==='//'){
    if(right===0||left%right!==0)return null;
    value=left/right;
  }else if(op==='%'){
    if(right===0)return null;
    value=left%right;
  }else if(op==='<<'||op==='>>'){
    if(right<0||right>30||left<0||left>0x7fffffff)return null;
    value=op==='<<'?left*(2**right):Math.floor(left/(2**right));
  }else if(op==='**'){
    if(right<0||right>16||Math.abs(left)>100000)return null;
    value=left**right;
  }
  return bounded(value);
}
function parseStaticIntegerExpression(expr,env={}){
  const tokens=tokenize(expr);if(!tokens)return null;
  let pos=0;
  const peek=()=>tokens[pos]||null;
  const take=(value=null)=>{const token=tokens[pos];if(!token)return null;if(value!=null&&token.value!==value)return null;pos+=1;return token;};
  const primary=()=>{
    const token=peek();if(!token)return null;
    if(token.type==='number'){take();return normalizeIntegerLiteral(token.value);}
    if(token.type==='ident'){
      take();const name=token.value;
      const value=Object.prototype.hasOwnProperty.call(env,name)?env[name]:Object.prototype.hasOwnProperty.call(env,name.toUpperCase())?env[name.toUpperCase()]:null;
      return Number.isSafeInteger(value)?value:null;
    }
    if(token.value==='('){take('(');const value=shift();if(value==null||!take(')'))return null;return value;}
    return null;
  };
  const unary=()=>{
    const token=peek();
    if(token?.value==='+'||token?.value==='-'){
      take();const value=unary();if(value==null)return null;return bounded(token.value==='-'?-value:value);
    }
    return power();
  };
  const power=()=>{
    let left=primary();if(left==null)return null;
    if(peek()?.value==='**'){take('**');const right=unary();left=applyBinary('**',left,right);}
    return left;
  };
  const product=()=>{
    let left=unary();if(left==null)return null;
    while(['*','/','//','%'].includes(peek()?.value)){
      const op=take().value;const right=unary();left=applyBinary(op,left,right);if(left==null)return null;
    }
    return left;
  };
  const sum=()=>{
    let left=product();if(left==null)return null;
    while(['+','-'].includes(peek()?.value)){
      const op=take().value;const right=product();left=applyBinary(op,left,right);if(left==null)return null;
    }
    return left;
  };
  function shift(){
    let left=sum();if(left==null)return null;
    while(['<<','>>'].includes(peek()?.value)){
      const op=take().value;const right=sum();left=applyBinary(op,left,right);if(left==null)return null;
    }
    return left;
  }
  const value=shift();
  return value!=null&&pos===tokens.length?value:null;
}
function collectStaticAssignments(sourceText){
  const out=[];
  for(const raw of stripComments(sourceText).split(/\r?\n/)){
    const line=raw.trim();if(!line)continue;
    const match=line.match(/^([A-Za-z_]\w*)\s*=\s*([^;]+?)\s*$/);
    if(!match||match[2].length>MAX_EXPR_LENGTH)continue;
    out.push({name:match[1],rhs:match[2],text:line});
    if(out.length>=MAX_ASSIGNMENTS)break;
  }
  return out;
}
function resolveStaticIntegerAssignments(sourceText){
  const assignments=collectStaticAssignments(sourceText);const env={};const evidence=[];const conflicts=new Map();
  for(let round=0;round<MAX_RESOLVE_ROUNDS;round++){
    let changed=false;
    for(const item of assignments){
      const value=parseStaticIntegerExpression(item.rhs,env);if(value==null)continue;
      const key=item.name.toUpperCase();
      if(Object.prototype.hasOwnProperty.call(env,key)){
        if(env[key]!==value){const values=conflicts.get(key)||new Set([env[key]]);values.add(value);conflicts.set(key,values);}
        continue;
      }
      env[key]=value;env[item.name]=value;evidence.push({name:key,value,text:item.text,round});changed=true;
    }
    if(!changed)break;
  }
  return {env,evidence,conflicts,assignments};
}
function resolveNamedIntegerEvidence(sourceText,names){
  const resolved=resolveStaticIntegerAssignments(sourceText);const wanted=new Set((names||[]).map((name)=>String(name).toUpperCase()));const matches=[];
  for(const item of resolved.evidence)if(wanted.has(item.name))matches.push(item);
  for(const [name,values] of resolved.conflicts)if(wanted.has(name))for(const value of values)matches.push({name,value,text:'conflicting static assignments',conflict:true});
  const values=[...new Set(matches.map((item)=>item.value))];
  return {matches,values,env:resolved.env,conflicts:resolved.conflicts};
}

module.exports={
  MAX_STATIC_INTEGER,MAX_EXPR_LENGTH,
  stripComments,normalizeIntegerLiteral,tokenize,parseStaticIntegerExpression,
  collectStaticAssignments,resolveStaticIntegerAssignments,resolveNamedIntegerEvidence
};