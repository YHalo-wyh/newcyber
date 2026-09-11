'use strict';

const fs=require('fs/promises');
const path=require('path');
const base=require('./finals_analyzer_batch79');
const {buildPromptAttackArsenal}=require('./ai_prompt_attack_arsenal');
const {analyzePrivacyLeakage}=require('./ai_privacy_leakage');
const {analyzeBackdoorTriggerAssociations}=require('./ai_backdoor_trigger_search');

const TEXT_EXTS=new Set(['.csv','.tsv','.json','.jsonl','.ndjson','.txt','.log']);
const MAX_FILES=24;
const MAX_FILE_BYTES=2*1024*1024;
const MAX_TOTAL_BYTES=16*1024*1024;

function upsertCheck(analysis,check){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);
  if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);
}
function contained(root,target){const rel=path.relative(root,target);return rel===''||(!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel));}
function resolveFile(root,file){
  const raw=String(file?.path||file?.name||'');if(!raw)return null;
  const target=path.resolve(root,raw);return contained(path.resolve(root),target)?target:null;
}
async function readCandidateFiles(root,analysis){
  const out=[];let total=0;
  for(const file of analysis.files||[]){
    if(out.length>=MAX_FILES||total>=MAX_TOTAL_BYTES)break;
    const raw=String(file?.path||file?.name||'');if(/(?:^|[\\/])newcyber_/i.test(raw))continue;
    if(!TEXT_EXTS.has(path.extname(raw).toLowerCase()))continue;
    const target=resolveFile(root,file);if(!target)continue;
    try{
      const stat=await fs.stat(target);if(!stat.isFile()||stat.size>MAX_FILE_BYTES||total+stat.size>MAX_TOTAL_BYTES)continue;
      const text=await fs.readFile(target,'utf8');total+=stat.size;out.push({path:raw,text});
    }catch{}
  }
  return out;
}
function looksPrivacy(text){return/(?:response|output|answer|completion)/i.test(text)&&/(?:secret|canary|private_reference|hidden_context|system_prompt|private_value)/i.test(text);}
function looksBackdoor(text){return/(?:label|class|target_label)/i.test(text)&&/(?:trigger|pattern|patch|token|text|content|prompt|input)/i.test(text);}
function aggregate(results,key){
  if(!results.length)return null;
  const findings=results.flatMap((x)=>x.result.findings||[]);
  return{schema:`newcyber.batch80-${key}-aggregate.v1`,files:results.length,results,findings};
}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);
  const arsenal=buildPromptAttackArsenal({limit:512});
  analysis.promptAttackArsenal={schema:arsenal.schema,seeds:arsenal.seeds,mutations:arsenal.mutations,total:arsenal.total,coverage:arsenal.coverage};
  upsertCheck(analysis,{id:'prompt-attack-arsenal',title:'提示词攻击模板 Arsenal',hits:arsenal.total,detail:`${arsenal.seeds} families × ${arsenal.mutations} mutations = ${arsenal.total} safe competition templates`});

  const files=await readCandidateFiles(rootPath,analysis);
  const privacy=[];const backdoor=[];
  for(const file of files){
    if(looksPrivacy(file.text)){
      try{const result=analyzePrivacyLeakage(file.text);if(result.usableRows||result.findings?.length)privacy.push({file:file.path,result});}catch{}
    }
    if(looksBackdoor(file.text)){
      try{const result=analyzeBackdoorTriggerAssociations(file.text);if(result.status!=='gap')backdoor.push({file:file.path,result});}catch{}
    }
  }
  analysis.aiPrivacyLeakage=aggregate(privacy,'privacy-leakage');
  analysis.aiBackdoorTriggerSearch=aggregate(backdoor,'backdoor-trigger-search');
  if(analysis.aiPrivacyLeakage)upsertCheck(analysis,{id:'privacy-leakage-autopilot',title:'隐私 / 数据泄漏证据复算',hits:analysis.aiPrivacyLeakage.findings.length,detail:`files=${privacy.length}; explicit findings=${analysis.aiPrivacyLeakage.findings.length}`});
  if(analysis.aiBackdoorTriggerSearch)upsertCheck(analysis,{id:'backdoor-trigger-search',title:'后门 Trigger 关联搜索',hits:analysis.aiBackdoorTriggerSearch.findings.length,detail:`files=${backdoor.length}; candidate findings=${analysis.aiBackdoorTriggerSearch.findings.length}`});
  analysis.aiStage1OfficialDirections={
    schema:'newcyber.ai-stage1-five-directions.v1',
    directions:[
      {id:'prompt-llm-security',title:'提示词工程与大模型安全',reinforcement:'240-template safe attack arsenal + existing evaluator/source audit'},
      {id:'adversarial-example',title:'对抗样本攻击',reinforcement:'existing image/NPY preprocessing + ONNX + ranking + verifier closure'},
      {id:'privacy-leakage',title:'模型隐私与数据泄露',reinforcement:'membership metrics + explicit canary/private-reference leakage + memorization overlap'},
      {id:'backdoor-poisoning',title:'模型后门与数据投毒',reinforcement:'poison/backdoor behavior validation + rare trigger-label association search'},
      {id:'infra-supply-chain',title:'AI 基础设施与供应链安全',reinforcement:'existing static model/dependency/load-chain audit + deserialization guards'}
    ]
  };
  analysis.version=Math.max(Number(analysis.version)||1,80);
  return analysis;
}

function reinforcementSection(analysis){
  const arsenal=analysis.promptAttackArsenal;if(!arsenal)return'';
  const privacy=analysis.aiPrivacyLeakage;const backdoor=analysis.aiBackdoorTriggerSearch;
  return[
    '## AI 一阶段五方向强化',
    '',`- 提示词工程与大模型安全：${arsenal.total} 条比赛模板（${arsenal.seeds} families × ${arsenal.mutations} mutations）`,
    '- 对抗样本攻击：沿用 ONNX / NPY / 图像预处理 / Top-2 rank / verifier 闭环',
    `- 模型隐私与数据泄露：${privacy?`自动检查 ${privacy.files} 个 transcript，findings=${privacy.findings.length}`:'当前附件未命中可确定解析的 privacy transcript'}`,
    `- 模型后门与数据投毒：${backdoor?`自动检查 ${backdoor.files} 个数据表，findings=${backdoor.findings.length}`:'当前附件未命中可确定解析的 trigger-label 数据表'}`,
    '- AI 基础设施与供应链安全：沿用 SafeTensors/ONNX、Pickle/PyTorch 静态审计、revision/hash 与反序列化边界',
    '', '> Batch80 只强化题目附件的确定性分析与安全训练模板；不会为了提高“自动化率”去猜模型参数或执行不受信赛题脚本。'
  ].join('\n');
}
function buildMarkdownReport(analysis,notes=''){
  const report=base.buildMarkdownReport(analysis,notes);const section=reinforcementSection(analysis);
  return section?`${report.trim()}\n\n${section}\n`:report;
}

module.exports={...base,scanWorkspace,buildMarkdownReport,reinforcementSection,readCandidateFiles,looksPrivacy,looksBackdoor};
