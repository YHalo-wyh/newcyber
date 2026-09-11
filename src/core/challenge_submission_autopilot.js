'use strict';

const path=require('path');

const ID_ALIASES=['id','sample_id','record_id','uid','index','name','file','filename'];
const MEMBER_ALIASES=['member','is_member','membership','prediction','pred','label','target','in_training'];
const SCORE_ALIASES=['score','confidence','probability','prob','membership_score'];
const ANSWER_ALIASES=['answer','flag','result','submission','value'];

function text(value){return String(value??'').trim();}
function list(value){return Array.isArray(value)?value:[];}
function lowerMap(row){return new Map(Object.keys(row||{}).map((key)=>[key.toLowerCase(),key]));}
function firstKey(row,names){const map=lowerMap(row);for(const name of names){const key=map.get(name.toLowerCase());if(key!=null)return key;}return null;}
function quoteCsv(value,delimiter=','){const s=String(value??'');return /["\r\n]/.test(s)||s.includes(delimiter)?`"${s.replace(/"/g,'""')}"`:s;}
function splitDelimitedLine(line,delimiter){const out=[];let cell='';let quoted=false;for(let i=0;i<line.length;i++){const ch=line[i];if(ch==='"'){if(quoted&&line[i+1]==='"'){cell+='"';i++;continue;}quoted=!quoted;continue;}if(ch===delimiter&&!quoted){out.push(cell);cell='';continue;}cell+=ch;}out.push(cell);return out.map((x)=>x.trim());}
function parseDelimited(raw,delimiter){const lines=String(raw||'').split(/\r?\n/).filter((line)=>line.trim());if(lines.length<1)return null;const headers=splitDelimitedLine(lines.shift(),delimiter);if(!headers.length||headers.some((x)=>!x))return null;const rows=lines.slice(0,200000).map((line)=>{const values=splitDelimitedLine(line,delimiter);const row={};headers.forEach((header,index)=>row[header]=values[index]??'');return row;});return{format:delimiter==='\t'?'tsv':'csv',delimiter,headers,rows};}
function serializeDelimited(headers,rows,delimiter=','){return `${headers.map((x)=>quoteCsv(x,delimiter)).join(delimiter)}\n${rows.map((row)=>headers.map((header)=>quoteCsv(row[header]??'',delimiter)).join(delimiter)).join('\n')}${rows.length?'\n':''}`;}
function parseTemplate(file){
  const raw=String(file?.text??file?.content??'').trim();if(!raw)return null;const name=text(file?.path||file?.file||'submission');
  const ext=path.extname(name).toLowerCase();
  if(['.csv','.tsv'].includes(ext)||/submission|submit|answer|prediction|output/i.test(path.basename(name))){
    const first=raw.split(/\r?\n/,1)[0]||'';const delimiter=ext==='.tsv'||first.includes('\t')?'\t':first.includes(',')?',':null;
    if(delimiter){const parsed=parseDelimited(raw,delimiter);if(parsed)return{...parsed,file:name,raw};}
  }
  if(/^[\[{]/.test(raw))try{return{format:'json',file:name,raw,json:JSON.parse(raw)};}catch{}
  return null;
}
function templateScore(template){
  const base=path.basename(template.file||'').toLowerCase();let score=0;
  if(/sample[_ -]?submission|submission[_ -]?(?:sample|template|example)|submit[_ -]?(?:format|template)|answer[_ -]?template/.test(base))score+=8;
  else if(/submission|submit|prediction|answer|output/.test(base))score+=3;
  if(template.format==='csv'||template.format==='tsv')score+=2;
  if(template.format==='json')score+=1;
  return score;
}
function discoverTemplates(files=[]){return files.map(parseTemplate).filter(Boolean).sort((a,b)=>templateScore(b)-templateScore(a)||a.file.localeCompare(b.file));}
function resultCandidates(analysis={}){
  const out=[];const seen=new Set();
  const add=(kind,result,source)=>{if(!result)return;const payload=text(result.payload??result.value);const ids=list(result.memberIds??result.ids);const key=`${kind}:${payload}:${ids.join('|')}`;if(seen.has(key))return;seen.add(key);out.push({kind,result,source,payload,ids});};
  add('membership',analysis.aiMembershipAutopilot?.result,'ai-membership-autopilot');
  add('membership',analysis.challengeSession?.result?.kind==='membership-id-list'?analysis.challengeSession.result:null,'challenge-session');
  add('answer-set',analysis.aiContestAutopilot?.result,'ai-contest-autopilot');
  add('answer',analysis.challengeSession?.result,'challenge-session');
  return out;
}
function memberConfidenceMap(result){const map=new Map();for(const row of list(result?.candidates?.candidates??result?.candidates)){if(row?.id==null)continue;map.set(String(row.id),Number.isFinite(Number(row.confidence))?Number(row.confidence):(row.member?1:0));}return map;}
function formatMembershipDelimited(template,candidate){
  if(!template.headers?.length)return null;const exemplar=template.rows[0]||Object.fromEntries(template.headers.map((h)=>[h,'']));
  const idKey=firstKey(exemplar,ID_ALIASES)||template.headers.find((h)=>ID_ALIASES.includes(String(h).toLowerCase()));
  const memberKey=firstKey(exemplar,MEMBER_ALIASES)||template.headers.find((h)=>MEMBER_ALIASES.includes(String(h).toLowerCase()));
  const scoreKey=firstKey(exemplar,SCORE_ALIASES)||template.headers.find((h)=>SCORE_ALIASES.includes(String(h).toLowerCase()));
  if(!idKey||(!memberKey&&!scoreKey))return null;
  const ids=new Set(candidate.ids.map(String));const confidence=memberConfidenceMap(candidate.result);
  const rows=template.rows.length?template.rows.map((row)=>({...row})):[...ids].map((id)=>({[idKey]:id}));
  for(const row of rows){const id=String(row[idKey]??'');if(memberKey)row[memberKey]=ids.has(id)?1:0;if(scoreKey)row[scoreKey]=confidence.has(id)?confidence.get(id):(ids.has(id)?1:0);}
  const payload=serializeDelimited(template.headers,rows,template.delimiter);
  return{kind:'submission-table',format:template.format,payload,displayValue:`已按 ${path.basename(template.file)} 生成 ${rows.length} 行提交内容`,template:template.file,contract:{idColumn:idKey,memberColumn:memberKey||null,scoreColumn:scoreKey||null,rows:rows.length}};
}
function formatMembershipJson(template,candidate){
  const ids=candidate.ids;
  const root=template.json;
  if(Array.isArray(root)){
    if(!root.length||root.every((x)=>['string','number'].includes(typeof x)))return{kind:'submission-json',format:'json',payload:`${JSON.stringify(ids,null,2)}\n`,displayValue:`已按 ${path.basename(template.file)} 生成 ${ids.length} 个 member ID`,template:template.file,contract:{shape:'array-of-ids',count:ids.length}};
    return null;
  }
  if(!root||typeof root!=='object')return null;
  const key=Object.keys(root).find((k)=>/(?:member(?:_ids)?|members|predictions|ids|submission)/i.test(k));if(!key)return null;
  const out={...root,[key]:ids};return{kind:'submission-json',format:'json',payload:`${JSON.stringify(out,null,2)}\n`,displayValue:`已按 ${path.basename(template.file)} 填充 ${key} (${ids.length})`,template:template.file,contract:{shape:'object',field:key,count:ids.length}};
}
function formatGenericAnswer(template,candidate){
  if(!candidate.payload)return null;
  if(template.format==='json'&&template.json&&typeof template.json==='object'&&!Array.isArray(template.json)){
    const key=Object.keys(template.json).find((k)=>ANSWER_ALIASES.includes(k.toLowerCase()));if(!key)return null;const out={...template.json,[key]:candidate.payload};return{kind:'submission-json',format:'json',payload:`${JSON.stringify(out,null,2)}\n`,displayValue:`已按 ${path.basename(template.file)} 填充 ${key}`,template:template.file,contract:{shape:'object',field:key}};
  }
  if((template.format==='csv'||template.format==='tsv')&&template.headers?.length===1&&ANSWER_ALIASES.includes(template.headers[0].toLowerCase())){
    const row={[template.headers[0]]:candidate.payload};return{kind:'submission-table',format:template.format,payload:serializeDelimited(template.headers,[row],template.delimiter),displayValue:`已按 ${path.basename(template.file)} 生成提交内容`,template:template.file,contract:{answerColumn:template.headers[0],rows:1}};
  }
  return null;
}
function analyzeSubmissionBundle(files=[],analysis={}){
  const templates=discoverTemplates(files);const candidates=resultCandidates(analysis);
  if(!templates.length)return{schema:'newcyber.challenge-submission-autopilot.v1',status:'not-detected',templates:[],candidates:candidates.length,result:null,findings:[],next:null};
  if(!candidates.length)return{schema:'newcyber.challenge-submission-autopilot.v1',status:'needs-candidate',templates:templates.slice(0,8).map((x)=>({file:x.file,format:x.format,score:templateScore(x)})),candidates:0,result:null,findings:[],next:'已找到 submission 模板，但还没有可封装的题目候选。'};
  for(const template of templates){
    for(const candidate of candidates){
      let formatted=null;
      if(candidate.kind==='membership'&&candidate.ids.length)formatted=template.format==='json'?formatMembershipJson(template,candidate):formatMembershipDelimited(template,candidate);
      if(!formatted)formatted=formatGenericAnswer(template,candidate);
      if(!formatted)continue;
      const result={...formatted,verified:false,confidence:'candidate',source:`submission-autopilot:${template.file}`,candidateSource:candidate.source};
      return{schema:'newcyber.challenge-submission-autopilot.v1',status:'formatted',templates:templates.slice(0,8).map((x)=>({file:x.file,format:x.format,score:templateScore(x)})),candidates:candidates.length,result,findings:[{id:'submission-contract-formatted',severity:'info',title:'已按题目 submission 模板生成提交候选',file:template.file,evidence:`kind=${result.kind}; format=${result.format}; source=${candidate.source}`,meaning:'输出结构来自题目自带模板；内容仍是候选，只有题目 checker/verifier/scorer 命中后才能升级为 solved。'}],next:'已按题目模板生成提交内容；若同时存在 checker/verifier/scorer，继续自动验证。'};
    }
  }
  return{schema:'newcyber.challenge-submission-autopilot.v1',status:'unsupported-contract',templates:templates.slice(0,8).map((x)=>({file:x.file,format:x.format,score:templateScore(x)})),candidates:candidates.length,result:null,findings:[],next:'发现 submission 模板，但字段语义不足以安全映射当前候选；需要 README/checker/scorer 说明提交字段。'};
}

module.exports={ID_ALIASES,MEMBER_ALIASES,SCORE_ALIASES,ANSWER_ALIASES,splitDelimitedLine,parseDelimited,serializeDelimited,parseTemplate,discoverTemplates,resultCandidates,formatMembershipDelimited,formatMembershipJson,formatGenericAnswer,analyzeSubmissionBundle};
