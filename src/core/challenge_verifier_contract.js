'use strict';

const crypto=require('crypto');
const fs=require('fs/promises');
const path=require('path');

const SOURCE_EXTENSIONS=new Set(['.py','.js','.cjs','.mjs','.ts','.tsx','.jsx','.c','.cc','.cpp','.cxx','.h','.hpp','.java','.go','.rs','.php','.rb','.sh','.txt','.md']);
const MAX_FILES=3000;
const MAX_FILE_BYTES=2*1024*1024;
const MAX_TOTAL_BYTES=32*1024*1024;
const MAX_CONTRACTS=128;

function text(value){return String(value??'').trim();}
function list(value){return Array.isArray(value)?value:[];}
function lineAt(body,index){return body.slice(0,Math.max(0,index)).split(/\r?\n/).length;}
function context(body,index,radius=300){return body.slice(Math.max(0,index-radius),Math.min(body.length,index+radius)).replace(/\s+/g,' ').trim();}
function verifierNamed(file){return /(?:^|[_.-])(verif(?:y|ier)?|check(?:er)?|judge|scor(?:e|er)|validat(?:e|or)|submit)(?:[_.-]|$)/i.test(path.basename(file));}
function flagLike(value){return /(?:^|[^A-Za-z0-9])(?:flag|ctf|key|answer)?\{[^\r\n{}]{1,220}\}(?:$|[^A-Za-z0-9])/i.test(String(value||''))||/^(?:flag|ctf)[-_A-Za-z0-9]{4,220}$/i.test(String(value||''));}
function strongContext(file,near){return verifierNamed(file)||/(?:verify|verifier|checker|judge|submit|submission|expected[_ -]?answer|correct[_ -]?answer|flag)/i.test(near);}
function acceptanceContext(near){return /(?:correct|accepted|success|congrat|passed|valid\b|return\s+true|exit\s*\(\s*0\s*\)|print\s*\([^)]*(?:flag|correct|success)|status\s*[:=]\s*["']?(?:ok|pass|accepted|success))/i.test(String(near||''));}
function rejectionContext(near){return /(?:incorrect|wrong|invalid|failed|failure|reject|denied|return\s+false|exit\s*\(\s*1\s*\))/i.test(String(near||''));}
function safeLiteral(value){
  const s=String(value??'');if(s.length<1||s.length>512)return null;
  if(/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(s))return null;
  return s;
}
function decodeQuoted(raw){
  const quote=raw[0];if(!['"',"'",'`'].includes(quote)||raw[raw.length-1]!==quote)return null;
  const inner=raw.slice(1,-1);
  try{
    if(quote==='"')return JSON.parse(raw);
    return inner.replace(/\\([\\'"`nrt])/g,(_m,ch)=>({n:'\n',r:'\r',t:'\t'}[ch]??ch));
  }catch{return inner;}
}
function literalPattern(){return String.raw`((?:"(?:\\.|[^"\\\r\n]){1,512}")|(?:'(?:\\.|[^'\\\r\n]){1,512}')|(?:\x60(?:\\.|[^\x60\\\r\n]){1,512}\x60))`;}
function literalFromMatch(match,index){return safeLiteral(decodeQuoted(match[index]));}

async function walkSources(root,options={}){
  const maxFiles=Math.max(1,Math.min(10000,Number(options.maxFiles)||MAX_FILES));const out=[];let total=0;
  async function visit(dir){
    if(out.length>=maxFiles||total>=MAX_TOTAL_BYTES)return;
    let entries;try{entries=await fs.readdir(dir,{withFileTypes:true});}catch{return;}
    for(const entry of entries){
      if(out.length>=maxFiles||total>=MAX_TOTAL_BYTES)break;
      if(['.git','node_modules','__pycache__'].includes(entry.name))continue;
      const full=path.join(dir,entry.name);
      if(entry.isDirectory()){await visit(full);continue;}
      if(!entry.isFile()||/^newcyber_/i.test(entry.name))continue;
      const ext=path.extname(entry.name).toLowerCase();if(!SOURCE_EXTENSIONS.has(ext))continue;
      let stat;try{stat=await fs.stat(full);}catch{continue;}
      if(stat.size<=0||stat.size>MAX_FILE_BYTES||total+stat.size>MAX_TOTAL_BYTES)continue;
      total+=stat.size;out.push({path:full,relative:path.relative(root,full).replace(/\\/g,'/'),size:stat.size,ext});
    }
  }
  await visit(root);return out;
}

function discoverExactContracts(file,body){
  const out=[];const lit=literalPattern();
  const patterns=[
    new RegExp(String.raw`\b(flag|answer|submission|submitted|user[_-]?input|input_value|candidate|response|token)\b\s*(?:===|==)\s*${lit}`,'gi'),
    new RegExp(String.raw`${lit}\s*(?:===|==)\s*\b(flag|answer|submission|submitted|user[_-]?input|input_value|candidate|response|token)\b`,'gi'),
    new RegExp(String.raw`(?:compare_digest|timingSafeEqual|secure_compare)\s*\([^,\r\n]{1,180},\s*${lit}\s*\)`,'gi')
  ];
  for(let pIndex=0;pIndex<patterns.length;pIndex+=1){let match;while((match=patterns[pIndex].exec(body))&&out.length<MAX_CONTRACTS){
    let value,variable=null;
    if(pIndex===0){variable=match[1];value=literalFromMatch(match,2);}
    else if(pIndex===1){value=literalFromMatch(match,1);variable=match[2];}
    else value=literalFromMatch(match,1);
    if(!value)continue;const near=context(body,match.index);const strong=strongContext(file,near);
    if(!strong&&!flagLike(value))continue;
    out.push({type:'exact',file,line:lineAt(body,match.index),variable,expected:value,confidence:(verifierNamed(file)&&strong)||flagLike(value)?'strong':'medium',evidence:near.slice(0,500)});
  }}
  return out;
}

function discoverHashContracts(file,body){
  const out=[];const digestRe=/\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi;let match;
  while((match=digestRe.exec(body))&&out.length<MAX_CONTRACTS){
    const near=context(body,match.index,400);let algorithm=null;
    if(/\bmd5\b/i.test(near)&&match[1].length===32)algorithm='md5';
    else if(/\bsha1\b|sha-1/i.test(near)&&match[1].length===40)algorithm='sha1';
    else if(/\bsha256\b|sha-256/i.test(near)&&match[1].length===64)algorithm='sha256';
    if(!algorithm||!strongContext(file,near))continue;
    const inputBound=/(?:flag|answer|submission|submitted|user[_-]?input|candidate|response|stdin|request)/i.test(near);
    const compareBound=/(?:==|===|compare_digest|digest|hexdigest|check|verify)/i.test(near);
    if(!inputBound||!compareBound)continue;
    out.push({type:'hash',file,line:lineAt(body,match.index),algorithm,digest:match[1].toLowerCase(),confidence:verifierNamed(file)?'strong':'medium',evidence:near.slice(0,540)});
  }
  return out;
}

function discoverFormatContracts(file,body){
  const out=[];const re=/(?:fullmatch|match|search|regex|regexp|pattern)[^\r\n]{0,220}(["'])([^"'\r\n]{4,300})\1/gi;let match;
  while((match=re.exec(body))&&out.length<32){const pattern=match[2];if(!/(?:flag|ctf|\{|\\\{|\[A-Za-z)/i.test(pattern))continue;const near=context(body,match.index);if(!strongContext(file,near))continue;out.push({type:'format',file,line:lineAt(body,match.index),pattern,confidence:'medium',evidence:near.slice(0,440)});}
  return out;
}

function dedupeContracts(rows){
  const seen=new Set();const out=[];
  for(const row of rows){const key=row.type==='exact'?`exact:${row.expected}`:row.type==='hash'?`hash:${row.algorithm}:${row.digest}`:`format:${row.pattern}`;if(seen.has(key))continue;seen.add(key);out.push(row);if(out.length>=MAX_CONTRACTS)break;}
  return out;
}

function candidateValues(analysis={}){
  const out=[];const seen=new Set();
  function add(value,source){const s=text(value);if(!s||s.length>2048||seen.has(s))return;seen.add(s);out.push({value:s,source});}
  for(const value of list(analysis.candidates?.flags))add(typeof value==='string'?value:value?.value??value?.flag,'analysis.candidates.flags');
  add(analysis.aiContestAutopilot?.result?.value,'ai-contest-autopilot');
  add(analysis.challengeSession?.result?.value,'challenge-session');
  for(const finding of list(analysis.findings)){
    const evidence=text(finding?.evidence);const matches=evidence.match(/(?:flag|ctf)\{[^\r\n{}]{1,220}\}/gi)||[];for(const value of matches.slice(0,8))add(value,`finding:${finding.id||finding.title||'unknown'}`);
  }
  return out.slice(0,256);
}

function hashValue(algorithm,value){return crypto.createHash(algorithm).update(String(value),'utf8').digest('hex');}
function evaluateContracts(contracts,candidates){
  const verified=[];const direct=[];
  for(const contract of contracts){
    if(contract.type==='exact'){
      direct.push({contract,value:contract.expected,source:'static-exact-verifier'});
      for(const candidate of candidates)if(candidate.value===contract.expected)verified.push({contract,value:candidate.value,candidateSource:candidate.source,method:'exact-candidate-match'});
    }else if(contract.type==='hash'){
      for(const candidate of candidates){
        let digest;try{digest=hashValue(contract.algorithm,candidate.value);}catch{continue;}
        if(digest===contract.digest)verified.push({contract,value:candidate.value,candidateSource:candidate.source,method:`${contract.algorithm}-candidate-match`});
      }
    }
  }
  return{verified,direct};
}
function directEligible(item){
  const contract=item?.contract;if(!contract||contract.type!=='exact')return false;
  if(flagLike(item.value))return true;
  const evidence=text(contract.evidence);
  if(/(?:expected[_ -]?answer|correct[_ -]?answer|expected[_ -]?flag|correct[_ -]?flag)/i.test(evidence))return true;
  return acceptanceContext(evidence)&&!rejectionContext(evidence);
}

async function runVerifierContractAutopilot(root,analysis={},options={}){
  const files=await walkSources(root,options);const contracts=[];const errors=[];
  for(const file of files){
    let body;try{body=await fs.readFile(file.path,'utf8');}catch(error){errors.push({file:file.relative,error:String(error?.message||error).slice(0,240)});continue;}
    contracts.push(...discoverExactContracts(file.relative,body),...discoverHashContracts(file.relative,body),...discoverFormatContracts(file.relative,body));
    if(contracts.length>=MAX_CONTRACTS*2)break;
  }
  const unique=dedupeContracts(contracts);const candidates=candidateValues(analysis);const evaluated=evaluateContracts(unique,candidates);
  const exactStrong=evaluated.direct.find((item)=>item.contract.confidence==='strong'&&directEligible(item))||null;
  const verifiedMatch=evaluated.verified.find((item)=>item.contract.confidence==='strong')||evaluated.verified[0]||null;
  const result=verifiedMatch?{value:verifiedMatch.value,verified:true,confidence:'verified',kind:flagLike(verifiedMatch.value)?'flag':'answer',source:`${verifiedMatch.method} @ ${verifiedMatch.contract.file}:${verifiedMatch.contract.line}`}:
    exactStrong?{value:exactStrong.value,verified:true,confidence:'verified',kind:flagLike(exactStrong.value)?'flag':'answer',source:`static exact verifier @ ${exactStrong.contract.file}:${exactStrong.contract.line}`}:
    null;
  const status=result?'verified':unique.length?'contracts-found':'not-applicable';
  const findings=[];
  if(result)findings.push({id:'static-verifier-contract-satisfied',severity:'high',title:'静态 verifier contract 已形成强验证闭环',file:(verifiedMatch||exactStrong).contract.file,line:(verifiedMatch||exactStrong).contract.line,evidence:`${(verifiedMatch||exactStrong).contract.type} verifier -> ${result.kind}`,meaning:'题目 checker/verifier 源码中恢复到强约束，并已直接确定或验证当前候选；可升级为 verified result。'});
  else if(unique.length)findings.push({id:'static-verifier-contract-discovered',severity:'info',title:'发现可复用的 verifier contract',file:unique[0].file,line:unique[0].line,evidence:`contracts=${unique.length}; candidates=${candidates.length}`,meaning:'已恢复 exact/hash/format 约束，但当前没有候选满足强验证条件；保持候选/GAP。'});
  return{
    schema:'newcyber.challenge-verifier-contract.v2',status,result,
    summary:{sourceFiles:files.length,contracts:unique.length,exact:unique.filter((x)=>x.type==='exact').length,hash:unique.filter((x)=>x.type==='hash').length,format:unique.filter((x)=>x.type==='format').length,candidates:candidates.length,verifiedMatches:evaluated.verified.length,directEligible:evaluated.direct.filter(directEligible).length,errors:errors.length},
    contracts:unique,candidates:candidates.map((x)=>({source:x.source,valuePreview:flagLike(x.value)?x.value:x.value.slice(0,96)})),verifiedMatches:evaluated.verified.slice(0,32),findings,errors:errors.slice(0,32),
    next:result?'静态 verifier 已闭环，可把结果视为 verified。':unique.length?'已有 verifier contract；等待/生成满足 contract 的候选，不猜答案。':'未发现高置信静态 verifier contract。',
    notes:['仅解析文本，不执行 checker/verifier 源码。','exact literal 只有在 Flag-like、明确 expected/correct answer 语义或无拒绝信号的成功分支语境下才能直接形成 verified result。','hash contract 只验证已有候选；不会逆向哈希或枚举未知秘密。','安全展开与恢复目录中的 verifier 源码也会进入静态扫描，但不会执行。']
  };
}

module.exports={SOURCE_EXTENSIONS,flagLike,strongContext,acceptanceContext,rejectionContext,walkSources,discoverExactContracts,discoverHashContracts,discoverFormatContracts,dedupeContracts,candidateValues,evaluateContracts,directEligible,runVerifierContractAutopilot};