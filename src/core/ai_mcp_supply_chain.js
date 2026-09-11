'use strict';

function text(value){return String(value??'').trim();}
function bool(value){
  if(typeof value==='boolean')return value;
  if(typeof value==='number')return value!==0;
  const v=text(value).toLowerCase();
  if(['1','true','yes','verified','valid','allowed','trusted','pass','passed'].includes(v))return true;
  if(['0','false','no','unverified','invalid','denied','untrusted','fail','failed'].includes(v))return false;
  return null;
}
function parseInput(input){
  if(input&&typeof input==='object')return input;
  const raw=text(input);if(!raw)return{};
  try{return JSON.parse(raw);}catch{return{raw};}
}
function flattened(obj,prefix='',out={}){
  if(!obj||typeof obj!=='object'||Array.isArray(obj))return out;
  for(const [key,value] of Object.entries(obj)){
    const path=prefix?`${prefix}.${key}`:key;
    if(value&&typeof value==='object'&&!Array.isArray(value))flattened(value,path,out);
    else out[path.toLowerCase()]=value;
  }
  return out;
}
function first(flat,names){
  for(const name of names){
    const target=name.toLowerCase();
    if(Object.prototype.hasOwnProperty.call(flat,target))return flat[target];
    const suffix=Object.keys(flat).find((key)=>key.endsWith('.'+target));
    if(suffix)return flat[suffix];
  }
  return null;
}
function floatingRef(value){
  const v=text(value).toLowerCase();if(!v)return null;
  if(['latest','main','master','head','stable','dev','nightly','edge','*'].includes(v))return true;
  if(/^(?:\^|~|>=|>|<=|<)/.test(v))return true;
  if(/(?:^|[:/@-])latest$/.test(v))return true;
  if(/^[a-z][\w.-]*\/[^@]+$/.test(v))return true;
  if(/^[\w.-]+:[\w.-]+$/.test(v)&&!/@sha256:/i.test(v))return /:latest$/i.test(v);
  return false;
}
function digestPinned(flat){
  const digest=text(first(flat,['digest','sha256','checksum','artifact_digest','image_digest']));
  if(!digest)return{present:false,strong:false,value:null};
  const strong=/^(?:sha256:)?[a-f0-9]{64}$/i.test(digest)||/^sha512:[a-f0-9]{128}$/i.test(digest);
  return{present:true,strong,value:digest};
}
function normalizedRecord(input){
  const data=parseInput(input);const flat=flattened(data);
  const source=text(first(flat,['source','registry','repository','repo','origin','url','download_url','artifact_source']));
  const ref=text(first(flat,['revision','ref','reference','tag','version','commit','image','artifact']));
  const signatureVerified=bool(first(flat,['signature_verified','signatureverified','verified_signature','cosign_verified','signature.valid','signature.verified']));
  const signed=bool(first(flat,['signed','signature_present','has_signature'])) ?? Boolean(text(first(flat,['signature','sig','cosign_signature'])));
  const provenanceVerified=bool(first(flat,['provenance_verified','provenanceverified','attestation_verified','slsa_verified','provenance.valid','attestation.valid']));
  const provenancePresent=bool(first(flat,['provenance_present','has_provenance','attestation_present'])) ?? Boolean(text(first(flat,['provenance','attestation','slsa','builder_id','build_provenance'])));
  const sourceAllowed=bool(first(flat,['source_allowed','allowlisted','source_allowlisted','registry_allowed','trusted_source','source_trusted']));
  const name=text(first(flat,['name','server_name','artifact_name','package','model','tool_name','id']));
  const command=text(first(flat,['command','executable','entrypoint','cmd']));
  const digest=digestPinned(flat);
  return{data,flat,name,source,ref,command,digest,signed:Boolean(signed),signatureVerified,provenancePresent:Boolean(provenancePresent),provenanceVerified,sourceAllowed,floating:floatingRef(ref||source)};
}
function compareRecords(base,candidate){
  const fields=['name','source','ref','command'];const drift=[];
  for(const field of fields){if(text(base[field])&&text(candidate[field])&&text(base[field])!==text(candidate[field]))drift.push({field,before:base[field],after:candidate[field]});}
  if(base.digest.value&&candidate.digest.value&&base.digest.value!==candidate.digest.value)drift.push({field:'digest',before:base.digest.value,after:candidate.digest.value});
  return drift;
}

function analyzeMcpSupplyChain(input={}){
  const data=parseInput(input);
  const candidate=normalizedRecord(data.candidate||data.record||data.manifest||data);
  const baseline=(data.baseline&&typeof data.baseline==='object')?normalizedRecord(data.baseline):null;
  const findings=[];
  if(candidate.floating)findings.push({id:'mcp-floating-reference',severity:'medium',title:'MCP/Agent 组件使用浮动引用',evidence:candidate.ref||candidate.source||'floating reference',meaning:'latest/main/master/版本范围等引用无法保证下一次解析到相同组件；比赛供应链题中应优先要求不可变 commit 或 digest。'});
  if(!candidate.digest.present)findings.push({id:'mcp-digest-missing',severity:'medium',title:'组件缺少 digest pin',evidence:candidate.name||candidate.source||'artifact',meaning:'没有内容摘要无法把允许的名称/版本绑定到实际字节。'});
  else if(!candidate.digest.strong)findings.push({id:'mcp-digest-weak-or-unrecognized',severity:'info',title:'digest 格式不足以形成强 pin',evidence:candidate.digest.value,meaning:'发现摘要字段但未识别为完整 SHA-256/SHA-512 pin；需由题目 verifier 或可信实现进一步确认。'});
  if(candidate.signatureVerified!==true)findings.push({id:'mcp-signature-unverified',severity:candidate.signed?'medium':'high',title:candidate.signed?'签名存在但未验证':'组件未见签名验证证据',evidence:`signed=${candidate.signed}; verified=${candidate.signatureVerified}`,meaning:'仅存在 signature 字段不等于验签成功；需要独立的 signatureVerified/cosign verification 结果。'});
  if(candidate.provenanceVerified!==true)findings.push({id:'mcp-provenance-unverified',severity:'medium',title:'构建 provenance/attestation 未验证',evidence:`present=${candidate.provenancePresent}; verified=${candidate.provenanceVerified}`,meaning:'组件来源与构建过程未被可验证 provenance 绑定，无法确认 artifact 与声明来源一致。'});
  if(candidate.sourceAllowed===false)findings.push({id:'mcp-source-not-allowlisted',severity:'high',title:'组件来源不在允许范围',evidence:candidate.source||'sourceAllowed=false',meaning:'当前记录明确表明来源不受信或未通过 allowlist。'});
  if(candidate.sourceAllowed==null&&candidate.source)findings.push({id:'mcp-source-trust-unknown',severity:'info',title:'组件来源存在但 allowlist 状态未知',evidence:candidate.source,meaning:'不能仅凭仓库/registry 名称推断可信，应由独立 allowlist 规则验证。'});
  const drift=baseline?compareRecords(baseline,candidate):[];
  if(drift.length)findings.push({id:'mcp-artifact-drift',severity:'medium',title:'组件相对基线发生关键字段漂移',evidence:drift.map((x)=>`${x.field}:${x.before}->${x.after}`).join('; '),meaning:'名称、来源、引用、执行入口或 digest 发生变化；在没有重新验签/审批时不应继承旧信任。'});
  const admissionReady=candidate.sourceAllowed===true&&candidate.signatureVerified===true&&candidate.provenanceVerified===true&&candidate.digest.strong&&!candidate.floating;
  const rejected= candidate.sourceAllowed===false || candidate.signatureVerified===false || candidate.provenanceVerified===false;
  return{
    schema:'newcyber.ai-mcp-supply-chain.v1',status:admissionReady?'verified-record':rejected?'rejected-record':'guarded',
    candidate:{name:candidate.name,source:candidate.source,ref:candidate.ref,command:candidate.command,digest:candidate.digest,signed:candidate.signed,signatureVerified:candidate.signatureVerified,provenancePresent:candidate.provenancePresent,provenanceVerified:candidate.provenanceVerified,sourceAllowed:candidate.sourceAllowed,floating:candidate.floating},
    baseline:baseline?{name:baseline.name,source:baseline.source,ref:baseline.ref,command:baseline.command,digest:baseline.digest}:null,
    drift,admissionReady,findings,
    nextActions:admissionReady?["记录当前 digest/signature/provenance 证据并交给 challenge verifier；不要把 verified-record 等同于远端组件本身绝对安全。"]:["要求不可变 digest/commit pin。","把 allowlist、signature verification、provenance/attestation verification 作为彼此独立的门；任一缺失都不得从旧基线继承信任。","MCP server/tool schema 发生漂移时重新审批，不自动执行未知 server。"],
    notes:['本模块只静态验证 manifest/admission record 中的证据，不下载组件、不连接 MCP server，也不执行 command。','signature 字段存在不等于 cryptographic verification；只有明确 verified 证据才按通过处理。']
  };
}

module.exports={parseInput,flattened,floatingRef,digestPinned,normalizedRecord,compareRecords,analyzeMcpSupplyChain};
