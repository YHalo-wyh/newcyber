'use strict';

const fs=require('fs/promises');
const path=require('path');
const base=require('./finals_analyzer_batch41');
const {buildPreprocessingManifest}=require('./ai_preprocessing_manifest');
const {buildChallengeSession}=require('./challenge_session');

const SOURCE_EXTENSIONS=new Set(['.py','.pyw','.js','.mjs','.cjs','.ts','.tsx','.jsx','.json','.yaml','.yml','.toml','.ini','.cfg','.md','.txt']);
const MAX_SOURCE_FILES=32;
const MAX_SOURCE_BYTES=1024*1024;
const MAX_TOTAL_SOURCE_BYTES=8*1024*1024;

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
  for(const key of ['solverPipeline','pipelineSummary','solverExecution','executorSummary','archiveIngest'])if(oldSession[key]!==undefined)newSession[key]=oldSession[key];
  return newSession;
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const sources=await collectSources(rootPath,analysis);
  const manifest=buildPreprocessingManifest(sources);
  analysis.aiPreprocessingManifest=manifest;
  if(manifest.status!=='not-detected'){
    analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
    const check={id:'ai-preprocessing-manifest',title:'AI 图像预处理证据恢复',hits:manifest.evidence.length};
    const existing=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(existing)Object.assign(existing,check);else analysis.autopilot.automaticChecks.push(check);
    const old=analysis.challengeSession;
    analysis.challengeSession=preserveSessionRuntime(old,buildChallengeSession(analysis));
    analysis.challengeSession.aiPreprocessingManifest=manifest;
  }else if(analysis.challengeSession){analysis.challengeSession.aiPreprocessingManifest=manifest;}
  analysis.version=Math.max(Number(analysis.version)||1,49);
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

function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes),section=preprocessingSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,collectSources,preprocessingSection};
