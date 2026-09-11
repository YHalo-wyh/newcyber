'use strict';

const crypto=require('crypto');
const path=require('path');
const {rankAdversarialContestCandidates}=require('./ai_adversarial_ctf');

const MAX_JSON_NODES=4000;
const MAX_HINTS=256;
const MAX_CANDIDATES=100000;
const MAX_SOURCE_TEXT=2*1024*1024;

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'');}
function lower(value){return text(value).toLowerCase();}
function finiteArray(value){return Array.isArray(value)&&value.length>=2&&value.every((x)=>Number.isFinite(Number(x)));}
function labelOf(row){return row?.assignedLabel??row?.folderLabel??row?.bucketLabel??row?.classLabel??row?.label??row?.targetLabel??null;}
function candidateScores(row){return row?.scores??row?.logits??row?.output??row?.predictionScores;}
function candidateLike(row){return row&&typeof row==='object'&&!Array.isArray(row)&&finiteArray(candidateScores(row));}
function hintLike(row){
  if(Array.isArray(row)&&row.length>=2&&row.length<=4)return Number.isFinite(Number(row[0]))&&Number.isFinite(Number(row[1]));
  if(!row||typeof row!=='object'||Array.isArray(row))return false;
  const a=row.originLabel??row.origin??row.from,b=row.adversarialLabel??row.targetLabel??row.target??row.to;
  return a!==undefined&&b!==undefined;
}
function normalizedHint(row){
  if(Array.isArray(row))return[row[0],row[1]];
  return[row.originLabel??row.origin??row.from,row.adversarialLabel??row.targetLabel??row.target??row.to];
}

function walkObjects(value,visit,depth=0,state={count:0}){
  if(state.count>=MAX_JSON_NODES||depth>5||value===null||value===undefined)return;
  state.count+=1;visit(value,depth);
  if(Array.isArray(value)){for(const item of value.slice(0,MAX_JSON_NODES-state.count))walkObjects(item,visit,depth+1,state);return;}
  if(typeof value==='object')for(const child of Object.values(value))walkObjects(child,visit,depth+1,state);
}

function discoverJsonMaterial(file,body){
  let parsed;try{parsed=JSON.parse(body);}catch{return{hints:[],candidateSets:[],bundles:[]};}
  const hints=[];const candidateSets=[];const bundles=[];const seenHints=new Set();const seenCandidates=new Set();
  const addHints=(rows,source)=>{
    if(!Array.isArray(rows)||!rows.length||rows.length>MAX_HINTS||!rows.every(hintLike))return;
    const normalized=rows.map(normalizedHint);const key=JSON.stringify(normalized);if(seenHints.has(key))return;seenHints.add(key);hints.push({file,source,rows:normalized});
  };
  const addCandidates=(rows,source)=>{
    if(!Array.isArray(rows)||!rows.length||rows.length>MAX_CANDIDATES||!rows.every(candidateLike))return;
    const compact=rows.map((row,index)=>({id:row.id??row.index??row.file??row.name??row.path??index,assignedLabel:labelOf(row),scores:candidateScores(row).map(Number)}));
    const key=compact.slice(0,16).map((x)=>`${x.id}:${x.assignedLabel}:${x.scores.length}`).join('|')+`:${compact.length}`;if(seenCandidates.has(key))return;seenCandidates.add(key);candidateSets.push({file,source,rows:compact});
  };
  walkObjects(parsed,(value)=>{
    if(!value||typeof value!=='object'||Array.isArray(value))return;
    for(const key of ['hints','hintPairs','transitions','hint_pairs'])if(value[key]!==undefined)addHints(value[key],key);
    for(const key of ['candidates','samples','rows','predictions','results'])if(value[key]!==undefined)addCandidates(value[key],key);
    const h=value.hints??value.hintPairs??value.transitions??value.hint_pairs;
    const c=value.candidates??value.samples??value.rows??value.predictions??value.results;
    if(Array.isArray(h)&&Array.isArray(c)&&h.every(hintLike)&&c.every(candidateLike))bundles.push({file,hints:h.map(normalizedHint),candidates:c.map((row,index)=>({id:row.id??row.index??row.file??row.name??row.path??index,assignedLabel:labelOf(row),scores:candidateScores(row).map(Number)}))});
  });
  if(Array.isArray(parsed)){
    if(parsed.every(hintLike))addHints(parsed,'root-array');
    if(parsed.every(candidateLike))addCandidates(parsed,'root-array');
  }
  return{hints,candidateSets,bundles};
}

function discoverTextHints(file,body){
  const out=[];const assignment=/(?:^|\n)\s*(?:hint\w*|transitions?|pairs?)\s*=\s*\[([^\]]{3,12000})\]/gi;let match;
  while((match=assignment.exec(body))){
    const pairs=[];const pairRe=/[\[(]\s*(-?\d+)\s*,\s*(-?\d+)\s*[\])]/g;let pair;
    while((pair=pairRe.exec(match[1]))&&pairs.length<MAX_HINTS)pairs.push([Number(pair[1]),Number(pair[2])]);
    if(pairs.length)out.push({file,source:'python-like-hint-list',rows:pairs});
  }
  return out;
}

function splitCsvLine(line,delimiter){
  const out=[];let value='';let quote=false;
  for(let i=0;i<line.length;i+=1){const ch=line[i];if(ch==='"'){if(quote&&line[i+1]==='"'){value+='"';i+=1;}else quote=!quote;continue;}if(ch===delimiter&&!quote){out.push(value);value='';}else value+=ch;}out.push(value);return out;
}
function discoverDelimitedCandidates(file,body){
  const lines=body.split(/\r?\n/).filter((line)=>line.trim()).slice(0,MAX_CANDIDATES+1);if(lines.length<2)return[];
  const delimiter=lines[0].includes('\t')?'\t':',';const headers=splitCsvLine(lines[0],delimiter).map((x)=>x.trim());
  const scoreCols=headers.map((name,index)=>{const m=name.match(/^(?:score|logit|prob(?:ability)?)[_.-]?(\d+)$/i);return m?{index,label:Number(m[1])}:null;}).filter(Boolean).sort((a,b)=>a.label-b.label);
  if(scoreCols.length<2)return[];
  const idIndex=headers.findIndex((name)=>/^(?:id|index|sample|file|filename|name|path)$/i.test(name));
  const labelIndex=headers.findIndex((name)=>/^(?:assigned[_-]?label|folder[_-]?label|bucket[_-]?label|class[_-]?label|target[_-]?label|label)$/i.test(name));
  const rows=[];
  for(let rowIndex=1;rowIndex<lines.length;rowIndex+=1){
    const cells=splitCsvLine(lines[rowIndex],delimiter);const scores=scoreCols.map((col)=>Number(cells[col.index]));if(scores.some((x)=>!Number.isFinite(x)))continue;
    const rawLabel=labelIndex>=0?cells[labelIndex]:null;const numericLabel=rawLabel!==null&&rawLabel!==''&&Number.isFinite(Number(rawLabel))?Number(rawLabel):rawLabel;
    rows.push({id:idIndex>=0?cells[idIndex]:rowIndex-1,assignedLabel:numericLabel,scores});
  }
  return rows.length?[{file,source:'delimited-score-table',rows}]:[];
}

function discoverJsonlCandidates(file,body){
  const rows=[];const lines=body.split(/\r?\n/).filter((line)=>line.trim()).slice(0,MAX_CANDIDATES);
  if(lines.length<2)return[];
  for(const line of lines){let value;try{value=JSON.parse(line);}catch{return[];}if(!candidateLike(value))return[];rows.push({id:value.id??value.index??value.file??value.name??value.path??rows.length,assignedLabel:labelOf(value),scores:candidateScores(value).map(Number)});}
  return rows.length?[{file,source:'jsonl-score-rows',rows}]:[];
}

function discoverVerifierDigests(file,body){
  const out=[];const lines=body.split(/\r?\n/);
  for(let index=0;index<lines.length;index+=1){
    const line=lines[index];if(!/(?:md5|sha256|sha-256|digest|hash|hint\s*2|verif|check)/i.test(line))continue;
    const matches=line.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{64}\b/gi)||[];
    for(const digest of matches.slice(0,8))out.push({file,line:index+1,algorithm:digest.length===32?'md5':'sha256',digest:digest.toLowerCase(),evidence:line.trim().slice(0,300)});
  }
  return out;
}

function numericId(value){
  if(typeof value==='number'&&Number.isInteger(value))return value;
  const base=path.basename(String(value??''));const match=base.match(/^(\d+)(?:\.[^.]+)?$/);return match?Number(match[1]):null;
}
function canonicalIds(ids){const values=ids.map(numericId);if(values.some((x)=>x===null))return null;values.sort((a,b)=>a-b);return`[${values.join(', ')}]`;}
function digestsForIds(ids){const serialized=canonicalIds(ids);if(serialized===null)return null;return{serialized,md5:crypto.createHash('md5').update(serialized).digest('hex'),sha256:crypto.createHash('sha256').update(serialized).digest('hex')};}

function scoreReport(report){
  const resolved=report.groups.filter((group)=>group.shortlist?.length).length;const consensus=report.groups.filter((group)=>group.top?.consensusTop).length;
  return resolved*1000+consensus*20+Math.min(report.candidateSets.length,100);
}

function rankCombinations(hintSources,candidateSources,bundles){
  const attempts=[];const pairs=[];
  for(const bundle of bundles.slice(0,12))pairs.push({hints:bundle.hints,candidates:bundle.candidates,hintSource:bundle.file,candidateSource:bundle.file,source:'same-json-bundle'});
  for(const hints of hintSources.slice(0,12))for(const candidates of candidateSources.slice(0,12))pairs.push({hints:hints.rows,candidates:candidates.rows,hintSource:hints.file,candidateSource:candidates.file,source:'correlated-material'});
  const dedupe=new Set();
  for(const pair of pairs.slice(0,96)){
    const key=`${JSON.stringify(pair.hints)}:${pair.candidateSource}:${pair.candidates.length}`;if(dedupe.has(key))continue;dedupe.add(key);
    try{
      const report=rankAdversarialContestCandidates({hints:pair.hints,candidates:pair.candidates,shortlistSize:3,beamWidth:2,maxSets:128});
      attempts.push({...pair,report,score:scoreReport(report)});
    }catch(error){attempts.push({...pair,error:error?.message||String(error),score:-1});}
  }
  return attempts.sort((a,b)=>b.score-a.score).slice(0,24);
}

function verifyCandidateSets(report,verifiers){
  if(!report?.candidateSets?.length||!verifiers.length)return[];
  const matches=[];
  for(const set of report.candidateSets){const digest=digestsForIds(set.ids);if(!digest)continue;for(const verifier of verifiers){if(digest[verifier.algorithm]===verifier.digest)matches.push({rank:set.rank,ids:set.ids,score:set.score,serialized:digest.serialized,verifier});}}
  return matches.sort((a,b)=>a.rank-b.rank);
}

function detectAssets(analysis={}){
  const models=[],arrays=[],images=[];
  for(const file of list(analysis.files)){
    const ext=String(file.extension||path.extname(file.path||'')).toLowerCase();
    if(ext==='.onnx')models.push(file.path);else if(ext==='.npy'||ext==='.npz')arrays.push(file.path);else if(['.png','.jpg','.jpeg','.bmp','.webp'].includes(ext))images.push(file.path);
  }
  return{models:models.slice(0,32),arrays:arrays.slice(0,256),images:images.slice(0,1000)};
}

function analyzeAiContestBundle(sources,analysis={},preprocessing=null){
  const hintSources=[],candidateSources=[],bundles=[],verifiers=[];const scanned=[];
  for(const source of list(sources)){
    const file=String(source.file||source.path||'source');if(/^newcyber_.*manifest\.json$/i.test(path.basename(file)))continue;
    const body=String(source.text||source.content||'').slice(0,MAX_SOURCE_TEXT);if(!body)continue;
    const ext=path.extname(file).toLowerCase();const json=discoverJsonMaterial(file,body);
    hintSources.push(...json.hints,...discoverTextHints(file,body));candidateSources.push(...json.candidateSets);bundles.push(...json.bundles);verifiers.push(...discoverVerifierDigests(file,body));
    if(ext==='.csv'||ext==='.tsv')candidateSources.push(...discoverDelimitedCandidates(file,body));
    if(ext==='.jsonl'||ext==='.ndjson')candidateSources.push(...discoverJsonlCandidates(file,body));
    scanned.push(file);
  }
  const attempts=rankCombinations(hintSources,candidateSources,bundles);const best=attempts.find((item)=>item.report)||null;const matches=best?verifyCandidateSets(best.report,verifiers):[];
  const assets=detectAssets(analysis);let status='not-detected';
  if(matches.length)status='verified';else if(best?.report?.candidateSets?.length)status='ranked';else if(hintSources.length||candidateSources.length||bundles.length)status='partial';else if(assets.models.length&&(assets.images.length||assets.arrays.length))status=preprocessing?.executionReady?'model-assets-ready':'model-assets-detected';
  const topSet=best?.report?.candidateSets?.[0]||null;const verified=matches[0]||null;
  const findings=[];
  if(verified)findings.push({id:'ai-contest-verifier-match',severity:'high',title:'赛题 verifier 与候选组合精确匹配',file:verified.verifier.file,line:verified.verifier.line,evidence:`${verified.verifier.algorithm}(${verified.serialized}) = ${verified.verifier.digest}`,meaning:'候选组合通过题目材料中提取的 hash/verifier 证据，可作为已验证答案集合。'});
  else if(topSet)findings.push({id:'ai-contest-ranked-answer-set',severity:'medium',title:'AI 赛式候选组合已自动排名',file:best.candidateSource,evidence:`top ids=${JSON.stringify(topSet.ids)}; candidateSets=${best.report.candidateSets.length}`,meaning:'已有可解释候选组合，但未命中题目 verifier；保持 candidate，不冒充已验证答案。'});
  if(status==='model-assets-ready')findings.push({id:'ai-contest-model-assets-ready',severity:'info',title:'模型、样本与 preprocessing 证据已齐',evidence:`models=${assets.models.length}; images=${assets.images.length}; arrays=${assets.arrays.length}`,meaning:'下一执行阶段可以安全复用本地 ONNX runtime；不需要再人工整理 preprocessing。'});
  const result=verified?{value:verified.serialized,verified:true,confidence:'verified',source:`${verified.verifier.algorithm} verifier`,ids:verified.ids}:topSet?{value:canonicalIds(topSet.ids)||JSON.stringify(topSet.ids),verified:false,confidence:'candidate',source:'AI contest ranking',ids:topSet.ids}:null;
  return{
    schema:'newcyber.ai-contest-bundle-autopilot.v1',status,result,
    discovery:{scannedSources:scanned.length,hintSources:hintSources.map((x)=>({file:x.file,source:x.source,count:x.rows.length})).slice(0,24),candidateSources:candidateSources.map((x)=>({file:x.file,source:x.source,count:x.rows.length})).slice(0,24),verifiers:verifiers.slice(0,32),assets},
    ranking:best?{hintSource:best.hintSource,candidateSource:best.candidateSource,hints:best.report.hints,candidates:best.report.candidates,groups:best.report.groups,candidateSets:best.report.candidateSets.slice(0,64),findings:best.report.findings}:null,
    verifierMatches:matches.slice(0,16),attempts:attempts.map((item)=>({hintSource:item.hintSource,candidateSource:item.candidateSource,score:item.score,error:item.error||null,candidateSets:item.report?.candidateSets?.length||0})),findings,
    next:status==='verified'?'verified-answer-ready':status==='ranked'?'need-real-verifier-or-manual-check':status==='model-assets-ready'?'onnx-inference-bridge':status==='model-assets-detected'?'complete-preprocessing-evidence':'collect-hints-and-model-scores',
    notes:['只解析有界文本/JSON/CSV，不执行赛题 Python 或 pickle。','hash verifier 只有在候选 ID 能安全转换成整数列表且 digest 精确命中时才升级 verified。','没有 verifier 时，排名第一仍然只是 candidate。']
  };
}

module.exports={discoverJsonMaterial,discoverTextHints,discoverDelimitedCandidates,discoverVerifierDigests,digestsForIds,analyzeAiContestBundle};
