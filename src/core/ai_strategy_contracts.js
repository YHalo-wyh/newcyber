'use strict';

const path=require('path');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function extOf(file){return String(file?.extension||path.extname(file?.path||file?.name||'')).toLowerCase();}
function fileFacts(analysis={}){
  const exts=new Map();const paths=[];
  for(const file of list(analysis.files)){
    const ext=extOf(file);if(ext)exts.set(ext,(exts.get(ext)||0)+1);paths.push(text(file.path||file.name));
  }
  const has=(...values)=>values.some((value)=>(exts.get(value)||0)>0);
  return{
    count:list(analysis.files).length,exts:Object.fromEntries(exts),paths,
    onnx:has('.onnx'),images:has('.png','.jpg','.jpeg','.bmp','.webp'),arrays:has('.npy','.npz'),tables:has('.csv','.tsv','.json','.jsonl','.ndjson'),
    unsafeModel:has('.pt','.pth','.pkl','.pickle'),safeModel:has('.onnx','.safetensors'),audio:has('.wav','.mp3','.flac'),pcap:has('.pcap','.pcapng')
  };
}
function topDirections(analysis={},familyMatch=null,limit=5){
  const match=familyMatch||analysis.trainingFamilyMatch||{};const rows=list(match.directionRanking).filter((x)=>text(x.direction));
  if(rows.length)return rows.slice(0,limit).map((x)=>({direction:x.direction,score:Number(x.score)||0,source:'training-family-match'}));
  return list(match.matches).slice(0,limit).map((x)=>({direction:x.direction,score:Number(x.score)||0,source:'training-family-match'})).filter((x)=>text(x.direction));
}
function step(id,title,status,detail,missing=[]){return{id,title,status,detail,missing:list(missing).filter(Boolean)};}

function adversarialPlan(analysis,facts){
  const onnx=analysis.onnxContestAutopilot||{};const prep=analysis.aiPreprocessingManifest||{};const contest=analysis.aiContestAutopilot||{};
  const steps=[];
  if(['verified','ranked'].includes(onnx.status))steps.push(step('onnx-run','本地 ONNX 候选推理','completed',`status=${onnx.status}; runs=${Number(onnx.runs)||0}`));
  else if(facts.onnx&&(facts.arrays||facts.images)){
    const missing=[];if(facts.images&&prep.executionReady!==true)missing.push('evidence-backed preprocessing');
    steps.push(step('onnx-run','本地 ONNX 候选推理',missing.length?'blocked':'ready',missing.length?'模型和样本已发现，但图像预处理证据尚未闭合。':'模型、输入与预处理条件已满足，可运行受控 ONNX runtime。',missing));
  }else steps.push(step('onnx-run','本地 ONNX 候选推理','needs-input','缺少 ONNX 模型或可绑定输入。',[!facts.onnx?'ONNX model':null,!(facts.arrays||facts.images)?'NPY/image candidates':null]));
  if(contest.status==='verified')steps.push(step('contest-rank','赛式候选 / verifier','completed','候选组合已由题目 verifier 闭环。'));
  else if(contest.status==='ranked')steps.push(step('contest-rank','赛式候选 / verifier','partial','已有排序候选，但仍缺题目级 verifier 命中。',['verifier/checker evidence']));
  else steps.push(step('contest-rank','赛式候选 / verifier','ready','等待 hints/logits/ONNX outputs 汇入统一 ranker。'));
  return steps;
}
function detectionPlan(analysis,facts){
  const auto=analysis.aiDetectionAutopilot||{};const steps=[];
  if(auto.status==='evaluated')steps.push(step('detector-score','检测结果独立复算','completed',`${Number(auto.summary?.evaluations)||0} evaluation(s) 已复算。`));
  else if(auto.status==='partial')steps.push(step('detector-score','检测结果独立复算','partial',auto.next||'部分结构化结果已复算，仍有 GAP。',list(auto.gaps).slice(0,4).map((x)=>x.reason)));
  else if(facts.tables)steps.push(step('detector-score','检测结果独立复算','ready','发现结构化结果表，可识别 truth/prediction/score/loss-history 并复算。'));
  else steps.push(step('detector-score','检测结果独立复算','needs-input','缺少可解释的结构化检测输出。',['CSV/TSV/JSON/JSONL result table']));
  if(facts.unsafeModel)steps.push(step('unsafe-model','未知 PyTorch/Pickle 模型','guarded','发现 .pt/.pth/.pkl；默认不反序列化不受信模型。',['trusted conversion or safe exported model']));
  return steps;
}
function promptPlan(analysis){
  const checks=list(analysis.autopilot?.automaticChecks);const findings=list(analysis.findings);const evidence=findings.filter((x)=>/prompt|rag|agent|system[- _]?prompt|tool[- _]?call/i.test([x.id,x.title,x.meaning,x.evidence].map(text).join(' '))).length;
  const steps=[step('prompt-static','Prompt/RAG/Agent 静态证据','completed',`${evidence} finding(s) 可用于策略选择。`)];
  const hasInteractive=checks.some((x)=>/endpoint|remote|http|oracle/i.test([x.id,x.title,x.detail].map(text).join(' ')));
  steps.push(step('interactive-probe','交互式 LLM/Agent 验证',hasInteractive?'needs-input':'needs-input','默认不根据附件中的 URL 擅自访问远端服务；需要明确目标与会话上下文。',['authorized endpoint/session context']));
  return steps;
}
function extractionPlan(analysis,facts){
  const transcript=list(analysis.findings).some((x)=>/oracle|confidence|logit|model extraction|steal/i.test([x.id,x.title,x.evidence,x.meaning].map(text).join(' ')));
  return[
    step('oracle-analysis','Oracle / 模型抽取证据分析',transcript?'ready':'needs-input',transcript?'已发现 oracle/confidence/logit 证据，可进入抽取策略。':'未发现可复用的 oracle 响应或查询记录。',transcript?[]:['oracle transcript or authorized endpoint']),
    ...(facts.tables?[step('query-table','查询结果表分析','ready','结构化响应表可进入模型抽取分析器。')]:[])
  ];
}
function privacyPlan(analysis,facts){
  const evidence=list(analysis.findings).some((x)=>/privacy|inversion|embedding|memor|sensitive|reconstruct/i.test([x.id,x.title,x.evidence,x.meaning].map(text).join(' ')));
  return[step('privacy-analysis','隐私泄漏 / 模型反演分析',evidence||facts.tables||facts.arrays?'ready':'needs-input',evidence?'已发现隐私/反演证据。':facts.tables||facts.arrays?'数据工件可进入隐私分析器。':'缺少 transcript、embedding、hidden state 或可比较数据。',evidence||facts.tables||facts.arrays?[]:['transcript/embedding/hidden-state evidence'])];
}
function supplyPlan(analysis,facts){
  const steps=[step('artifact-audit','模型供应链静态审计',facts.safeModel||facts.unsafeModel?'ready':'needs-input',facts.safeModel||facts.unsafeModel?'已发现模型工件，可进行格式/来源/危险加载路径审计。':'缺少模型工件。',facts.safeModel||facts.unsafeModel?[]:['model artifact'])];
  if(facts.unsafeModel)steps.push(step('deserialization-guard','不受信反序列化边界','guarded','PyTorch/Pickle 工件不会自动 torch.load/pickle.load。',['safe conversion/export path']));
  return steps;
}
function datasetPlan(analysis,facts){
  return[step('dataset-audit','数据集 / Tabular 安全分析',facts.tables||facts.arrays?'ready':'needs-input',facts.tables||facts.arrays?'发现结构化数据或 NPY/NPZ，可进入 schema、label、异常与 pipeline 分析。':'缺少结构化数据工件。',['CSV/JSONL/NPY/NPZ dataset'])];
}

function planForDirection(direction,analysis,facts){
  if(direction==='adversarial-example')return adversarialPlan(analysis,facts);
  if(direction==='backdoor-poisoning')return detectionPlan(analysis,facts);
  if(direction==='prompt-llm-security')return promptPlan(analysis,facts);
  if(direction==='model-extraction')return extractionPlan(analysis,facts);
  if(direction==='privacy-leakage')return privacyPlan(analysis,facts);
  if(direction==='infra-supply-chain')return supplyPlan(analysis,facts);
  if(direction==='dataset-pipeline-security')return datasetPlan(analysis,facts);
  return[step('generic-evidence','通用 AI 证据分析','ready','没有专用 contract，继续使用通用分析器。')];
}
function summarize(plans){
  const counts={completed:0,ready:0,partial:0,'needs-input':0,blocked:0,guarded:0};
  for(const plan of plans)for(const item of plan.steps)counts[item.status]=(counts[item.status]||0)+1;
  const actionable=counts.ready+counts.partial;const closed=counts.completed;const waiting=counts['needs-input']+counts.blocked+counts.guarded;
  return{directions:plans.length,steps:Object.values(counts).reduce((a,b)=>a+b,0),...counts,actionable,closed,waiting};
}
function buildAiStrategyPlan(analysis={},options={}){
  const facts=fileFacts(analysis);const directions=topDirections(analysis,options.familyMatch,Math.max(1,Math.min(7,Number(options.limit)||5)));
  const fallback=directions.length?directions:[{direction:'ai-general',score:0,source:'fallback'}];
  const plans=fallback.map((row)=>({direction:row.direction,score:row.score,source:row.source,steps:planForDirection(row.direction,analysis,facts)}));
  const summary=summarize(plans);let status='planned';
  if(summary.completed>0&&!summary.ready&&!summary.partial&&!summary.waiting)status='closed';
  else if(summary.completed>0||summary.ready>0||summary.partial>0)status=summary.waiting?'partial':'actionable';
  else if(summary.waiting)status='needs-input';
  return{
    schema:'newcyber.ai-strategy-contract-plan.v1',status,summary,facts,plans,
    next:plans.flatMap((x)=>x.steps.map((s)=>({...s,direction:x.direction}))).filter((x)=>['ready','partial'].includes(x.status)).slice(0,5),
    blockers:plans.flatMap((x)=>x.steps.map((s)=>({...s,direction:x.direction}))).filter((x)=>['needs-input','blocked','guarded'].includes(x.status)).slice(0,12),
    notes:['strategy contract 只决定下一步动作与输入契约，不会把历史赛题答案迁移到当前题目。','ready 表示确定性执行条件基本齐全；needs-input/blocked/guarded 会明确缺口，而不是猜参数。','远程 LLM/Agent 服务默认不会仅凭附件 URL 自动访问。']
  };
}

module.exports={fileFacts,topDirections,planForDirection,buildAiStrategyPlan};