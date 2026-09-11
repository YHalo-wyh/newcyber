'use strict';

const fs=require('fs/promises');
const path=require('path');
const base=require('./finals_analyzer_batch41');
const {buildPreprocessingManifest}=require('./ai_preprocessing_manifest');
const {analyzeAiContestBundle}=require('./ai_contest_bundle_autopilot');
const {buildChallengeSession}=require('./challenge_session_batch51');

const SOURCE_EXTENSIONS=new Set(['.py','.pyw','.js','.mjs','.cjs','.ts','.tsx','.jsx','.json','.jsonl','.ndjson','.csv','.tsv','.yaml','.yml','.toml','.ini','.cfg','.md','.txt']);
const MAX_SOURCE_FILES=48;
const MAX_SOURCE_BYTES=2*1024*1024;
const MAX_TOTAL_SOURCE_BYTES=12*1024*1024;

function list(value){return Array.isArray(value)?value:[];}
function inside(root,target){const rel=path.relative(root,target);return rel===''||(!rel.startsWith(`..${path.sep}`)&&rel!=='..'&&!path.isAbsolute(rel));}

async function collectSources(rootPath,analysis){
  const root=await fs.realpath(path.resolve(String(rootPath||'')));const rows=[];let total=0;
  for(const file of list(analysis.files)){
    if(rows.length>=MAX_SOURCE_FILES||total>=MAX_TOTAL_SOURCE_BYTES)break;
    const ext=String(file.extension||path.extname(file.path||'')).toLowerCase();
    if(!SOURCE_EXTENSIONS.has(ext))continue;
    const lexical=path.resolve(root,String(file.path||''));if(!inside(root,lexical))continue;
    let stat;try{stat=await fs.lstat(lexical);}catch{continue;}
    if(!stat.isFile()||stat.isSymbolicLink()||stat.size<=0||stat.size>MAX_SOURCE_BYTES||total+stat.size>MAX_TOTAL_SOURCE_BYTES)continue;
    let body;try{body=await fs.readFile(lexical,'utf8');}catch{continue;}
    total+=Buffer.byteLength(body);rows.push({file:file.path,text:body});
  }
  return rows;
}

function preserveSessionRuntime(oldSession,newSession){
  if(!oldSession)return newSession;
  for(const key of ['solverPipeline','pipelineSummary','solverExecution','executorSummary','archiveIngest','recoveredArtifacts'])if(oldSession[key]!==undefined)newSession[key]=oldSession[key];
  return newSession;
}

function upsertAutomaticCheck(analysis,check){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  const existing=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(existing)Object.assign(existing,check);else analysis.autopilot.automaticChecks.push(check);
}

function mergeFindings(analysis,rows){
  analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.line||''}:${item.evidence||''}`));
  for(const item of list(rows)){const key=`${item.id||item.title}:${item.file||''}:${item.line||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const sources=await collectSources(rootPath,analysis);
  const manifest=buildPreprocessingManifest(sources);
  analysis.aiPreprocessingManifest=manifest;
  if(manifest.status!=='not-detected')upsertAutomaticCheck(analysis,{id:'ai-preprocessing-manifest',title:'AI 图像预处理证据恢复',hits:manifest.evidence.length});

  const contest=analyzeAiContestBundle(sources,analysis,manifest);
  analysis.aiContestAutopilot=contest;
  if(contest.status!=='not-detected'){
    const hits=contest.verifierMatches?.length||contest.ranking?.candidateSets?.length||contest.discovery?.hintSources?.length||contest.discovery?.assets?.models?.length||1;
    upsertAutomaticCheck(analysis,{id:'ai-contest-bundle-autopilot',title:'AI 赛题 Hint / Logits / Verifier 自动关联',hits});
    mergeFindings(analysis,contest.findings);
  }

  if(manifest.status!=='not-detected'||contest.status!=='not-detected'){
    const old=analysis.challengeSession;
    analysis.challengeSession=preserveSessionRuntime(old,buildChallengeSession(analysis));
    analysis.challengeSession.aiPreprocessingManifest=manifest;
    analysis.challengeSession.aiContestAutopilot={status:contest.status,next:contest.next,result:contest.result||null};
  }else if(analysis.challengeSession){analysis.challengeSession.aiPreprocessingManifest=manifest;analysis.challengeSession.aiContestAutopilot={status:contest.status,next:contest.next,result:null};}
  analysis.version=Math.max(Number(analysis.version)||1,51);
  return analysis;
}

function preprocessingSection(analysis){
  const m=analysis.aiPreprocessingManifest;if(!m||m.status==='not-detected')return'';
  const p=m.pipeline||{};const lines=['## AI Preprocessing Evidence','',`- status：${m.status}`,`- confidence：${m.confidence}`,`- executionReady：${m.executionReady?'true':'false'}`];
  for(const [key,value] of Object.entries(p))if(value!==null&&value!==undefined)lines.push(`- ${key}：\`${JSON.stringify(value)}\``);
  if(m.missing?.length)lines.push(`- missing：${m.missing.join(', ')}`);
  if(m.conflicts?.length)lines.push(`- conflicts：${m.conflicts.map((x)=>x.kind).join(', ')}`);
  lines.push('','### Evidence','');for(const item of (m.evidence||[]).slice(0,24))lines.push(`- \`${item.file}:${item.line}\` · ${item.kind}=${JSON.stringify(item.value)} · ${item.excerpt}`);
  lines.push('','> NewCyber 不凭模型名猜 preprocessing；冲突或缺字段时保持 partial/conflict。');return lines.join('\n');
}

function contestSection(analysis){
  const a=analysis.aiContestAutopilot;if(!a||a.status==='not-detected')return'';
  const lines=['## AI Contest Bundle Autopilot','',`- status：${a.status}`,`- next：${a.next}`];
  if(a.result)lines.push(`- result：\`${a.result.value}\``,`- confidence：${a.result.confidence||'candidate'}`);
  if(a.ranking)lines.push(`- hints：${a.ranking.hints}`,`- candidates：${a.ranking.candidates}`,`- candidateSets：${a.ranking.candidateSets?.length||0}`);
  if(a.discovery?.verifiers?.length)lines.push(`- verifier signals：${a.discovery.verifiers.length}`);
  for(const item of (a.findings||[]).slice(0,12))lines.push(`- ${item.title||item.id}：${item.evidence||''}`);
  lines.push('','> 只有题目 verifier/hash 精确命中才升级 verified；没有 verifier 时 Top-1 仍是 candidate。');return lines.join('\n');
}

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const sections=[preprocessingSection(analysis),contestSection(analysis)].filter(Boolean);
  return sections.length?`${report.trim()}\n\n${sections.join('\n\n')}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,collectSources,preprocessingSection,contestSection};
